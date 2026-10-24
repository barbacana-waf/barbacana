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
version: v1beta1
port: $PORT_PROXY
health_port: $PORT_HEALTH
metrics_port: $PORT_METRICS
data_dir: $TMP/data

routes:
  - upstream: http://127.0.0.1:$PORT_UPSTREAM
EOF
GOOD_CONFIG="$(cat "$CONFIG")"

step "start mock upstream on :$PORT_UPSTREAM"
echo "hello from upstream" > "$UPSTREAM_DIR/index.html"
(cd "$UPSTREAM_DIR" && exec python3 -m http.server "$PORT_UPSTREAM" --bind 127.0.0.1) \
  >/dev/null 2>&1 &
UPSTREAM_PID=$!
wait_for_port "$PORT_UPSTREAM" || fail "upstream did not start"

step "start barbacana"
"$BIN" --config "$CONFIG" > "$LOG" 2>&1 &
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

# count_reloads prints how many "config reloaded" lines the log holds, so each
# reload step can wait for its own line rather than an earlier one.
count_reloads() { grep -c "config reloaded" "$LOG" || true; }

# wait_for_reload waits until the log holds more than $1 "config reloaded" lines.
wait_for_reload() {
  for _ in $(seq 1 50); do
    [ "$(count_reloads)" -gt "$1" ] && return 0
    sleep 0.1
  done
  return 1
}

# proxy_status METHOD prints the HTTP status the proxy answers to METHOD /index.html.
proxy_status() {
  if [ "$1" = POST ]; then
    curl -s -o /dev/null -w '%{http_code}' -H 'Content-Type: text/plain' --data 'hello' \
      "http://127.0.0.1:$PORT_PROXY/index.html"
  else
    curl -s -o /dev/null -w '%{http_code}' -X "$1" "http://127.0.0.1:$PORT_PROXY/index.html"
  fi
}

# python's http.server answers 501 to a POST it does not support, so 501 means
# "reached the upstream" and 405 means "stopped by the WAF's accept.methods".
step "POST reaches the upstream before any reload"
status=$(proxy_status POST)
[ "$status" = "501" ] || fail "POST status = $status, want 501 (from the upstream)"

step "SIGHUP triggers a config reload"
before=$(count_reloads)
kill -HUP "$BIN_PID"
wait_for_reload "$before" || fail "no new 'config reloaded' entry in log"

step "a reload applies a changed route policy"
cat > "$CONFIG" <<EOF
version: v1beta1
port: $PORT_PROXY
health_port: $PORT_HEALTH
metrics_port: $PORT_METRICS
data_dir: $TMP/data

routes:
  - upstream: http://127.0.0.1:$PORT_UPSTREAM
    accept:
      methods: [GET, HEAD]
EOF
before=$(count_reloads)
kill -HUP "$BIN_PID"
wait_for_reload "$before" || fail "no 'config reloaded' entry after the policy change"
status=$(proxy_status POST)
[ "$status" = "405" ] || fail "POST status after reload = $status, want 405 (new accept.methods not applied)"
status=$(proxy_status GET)
[ "$status" = "200" ] || fail "GET status after reload = $status, want 200"

step "invalid reload keeps the running instance and its policy"
echo "not valid yaml: [" > "$CONFIG"
kill -HUP "$BIN_PID"
sleep 0.5
curl -fsS "http://127.0.0.1:$PORT_HEALTH/healthz" >/dev/null \
  || fail "instance died after a bad SIGHUP reload"
grep -q "reload failed" "$LOG" || fail "no 'reload failed' entry in log"
status=$(proxy_status POST)
[ "$status" = "405" ] || fail "POST status after failed reload = $status, want 405 (running policy changed)"

step "a good config after a failed reload is applied"
printf '%s\n' "$GOOD_CONFIG" > "$CONFIG"
before=$(count_reloads)
kill -HUP "$BIN_PID"
wait_for_reload "$before" || fail "no 'config reloaded' entry after recovery"
status=$(proxy_status POST)
[ "$status" = "501" ] || fail "POST status after recovery = $status, want 501 (from the upstream)"

step "SIGTERM shuts barbacana down cleanly"
kill -TERM "$BIN_PID"
wait_for_exit "$BIN_PID" || fail "process still alive after SIGTERM"
BIN_PID=""

step "invalid config is rejected at startup"
echo "version: v2" > "$CONFIG"
if "$BIN" --config "$CONFIG" >/dev/null 2>&1; then
  fail "barbacana accepted a config with version: v2"
fi

step "missing default config path is rejected"
if "$BIN" --config /no/such/default.yaml >/dev/null 2>&1; then
  fail "barbacana accepted a missing config path"
fi

echo
echo "minimal test passed"
