#!/usr/bin/env bash
# End-to-end smoke test for a local barbacana build. Exercises what a
# user does from the command line: build, launch, hit endpoints,
# reload, shutdown. Intended to keep working for the life of the
# project, not tied to any particular WBS phase.
#
# Requires: go, curl, python3, lsof.
# Run from anywhere: ./scripts/minimal-test.sh
set -euo pipefail

HERE="$(cd "$(dirname "$0")/.." && pwd)"
cd "$HERE"

PORT_PROXY=${PORT_PROXY:-18080}
PORT_HEALTH=${PORT_HEALTH:-18081}
PORT_METRICS=${PORT_METRICS:-19090}
PORT_UPSTREAM=${PORT_UPSTREAM:-18500}

TMP="$(mktemp -d)"
BIN="$TMP/barbacana"
CONFIG="$TMP/config.yaml"
UPSTREAM_DIR="$TMP/upstream"
LOG="$TMP/barbacana.log"
mkdir -p "$UPSTREAM_DIR"

UPSTREAM_PID=""
BIN_PID=""

cleanup() {
  [ -n "$BIN_PID" ] && kill "$BIN_PID" 2>/dev/null || true
  [ -n "$UPSTREAM_PID" ] && kill "$UPSTREAM_PID" 2>/dev/null || true
  wait 2>/dev/null || true
  rm -rf "$TMP"
}
trap cleanup EXIT

fail() {
  echo "FAIL: $*" >&2
  if [ -f "$LOG" ]; then
    echo "--- barbacana log ---" >&2
    tail -40 "$LOG" >&2
  fi
  exit 1
}

step() { echo; echo "== $* =="; }

require_tool() { command -v "$1" >/dev/null || fail "missing required tool: $1"; }
for t in go curl python3 lsof; do require_tool "$t"; done

require_free_port() {
  if lsof -nP -iTCP:"$1" -sTCP:LISTEN >/dev/null 2>&1; then
    fail "port $1 is already in use. Override with PORT_* env vars."
  fi
}
for p in $PORT_PROXY $PORT_HEALTH $PORT_METRICS $PORT_UPSTREAM; do
  require_free_port "$p"
done

wait_for_port() {
  local port=$1
  for _ in $(seq 1 50); do
    if curl -fsS "http://127.0.0.1:$port/" >/dev/null 2>&1 \
      || curl -fsS "http://127.0.0.1:$port/healthz" >/dev/null 2>&1 \
      || curl -fsS "http://127.0.0.1:$port/metrics" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.1
  done
  return 1
}

wait_for_exit() {
  local pid=$1
  for _ in $(seq 1 50); do
    kill -0 "$pid" 2>/dev/null || return 0
    sleep 0.1
  done
  return 1
}

step "build barbacana"
go build -o "$BIN" ./ || fail "go build failed"

step "write minimal config"
cat > "$CONFIG" <<EOF
version: v1alpha1
listen: ":$PORT_PROXY"
health_listen: ":$PORT_HEALTH"
metrics_listen: ":$PORT_METRICS"

routes:
  - upstream: http://127.0.0.1:$PORT_UPSTREAM
EOF

step "start mock upstream on :$PORT_UPSTREAM"
echo "hello from upstream" > "$UPSTREAM_DIR/index.html"
(cd "$UPSTREAM_DIR" && python3 -m http.server "$PORT_UPSTREAM" --bind 127.0.0.1) \
  >/dev/null 2>&1 &
UPSTREAM_PID=$!
wait_for_port "$PORT_UPSTREAM" || fail "upstream did not start"

step "start barbacana"
"$BIN" serve --config "$CONFIG" > "$LOG" 2>&1 &
BIN_PID=$!
wait_for_port "$PORT_HEALTH" || fail "barbacana did not start"

step "GET /healthz returns 200 ok"
body=$(curl -fsS "http://127.0.0.1:$PORT_HEALTH/healthz")
[ "$(printf '%s' "$body")" = "ok" ] || fail "/healthz body = '$body', want 'ok'"

step "GET /readyz returns 200 ok"
body=$(curl -fsS "http://127.0.0.1:$PORT_HEALTH/readyz")
[ "$(printf '%s' "$body")" = "ok" ] || fail "/readyz body = '$body', want 'ok'"

step "GET /metrics includes waf_build_info"
metrics_body=$(curl -fsS "http://127.0.0.1:$PORT_METRICS/metrics")
echo "$metrics_body" | grep -q '^waf_build_info{' \
  || fail "waf_build_info not present in /metrics"
echo "$metrics_body" | grep -q '^go_goroutines ' \
  || fail "default Go process metrics missing from /metrics"

step "proxy forwards to upstream"
body=$(curl -fsS "http://127.0.0.1:$PORT_PROXY/index.html")
[ "$(printf '%s' "$body")" = "hello from upstream" ] \
  || fail "proxy body = '$body'"

step "SIGHUP triggers a config reload"
: > "$LOG.reload"
kill -HUP "$BIN_PID"
for _ in $(seq 1 30); do
  if grep -q "config reloaded" "$LOG"; then break; fi
  sleep 0.1
done
grep -q "config reloaded" "$LOG" || fail "no 'config reloaded' entry in log"

step "invalid reload keeps the running instance alive"
echo "not valid yaml: [" > "$CONFIG"
kill -HUP "$BIN_PID"
sleep 0.3
curl -fsS "http://127.0.0.1:$PORT_HEALTH/healthz" >/dev/null \
  || fail "instance died after a bad SIGHUP reload"

step "SIGTERM shuts barbacana down cleanly"
kill -TERM "$BIN_PID"
wait_for_exit "$BIN_PID" || fail "process still alive after SIGTERM"
BIN_PID=""

step "invalid config is rejected at startup"
echo "version: v2" > "$CONFIG"
if "$BIN" serve --config "$CONFIG" >/dev/null 2>&1; then
  fail "barbacana accepted a config with version: v2"
fi

step "missing --config is rejected"
if "$BIN" serve >/dev/null 2>&1; then
  fail "barbacana accepted a serve invocation without --config"
fi

echo
echo "minimal test passed"
