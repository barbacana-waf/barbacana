package cmd

import (
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
	_ "github.com/caddyserver/caddy/v2/modules/standard"

	"github.com/barbacana-waf/barbacana/internal/config"
	"github.com/barbacana-waf/barbacana/internal/metrics"
	"github.com/barbacana-waf/barbacana/internal/pipeline"
	_ "github.com/barbacana-waf/barbacana/internal/protections/crs"
)

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port
}

// startServer brings the proxy up the way runServe does and returns a
// reloader for the running config.
func startServer(t *testing.T, path string, logger *slog.Logger) *reloader {
	t.Helper()
	metrics.Init()
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := config.Resolve(cfg)
	if err != nil {
		t.Fatal(err)
	}
	pipeline.RegisterConfigs(resolved)
	caddyJSON, err := config.Compile(cfg, resolved)
	if err != nil {
		t.Fatal(err)
	}
	if err := caddy.Load(caddyJSON, false); err != nil {
		t.Fatalf("start caddy: %v", err)
	}
	t.Cleanup(func() { _ = caddy.Stop() })
	return &reloader{path: path, logger: logger, cfg: cfg, resolved: resolved}
}

// noKeepAlive keeps the client from reusing a pooled connection that the
// previous server generation closes while draining after a reload, which
// surfaces as a spurious EOF unrelated to what is being tested.
var noKeepAlive = &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}

func post(t *testing.T, port int) int {
	t.Helper()
	resp, err := noKeepAlive.Post(fmt.Sprintf("http://127.0.0.1:%d/x", port), "application/json", strings.NewReader(`{"a":1}`))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

func TestReloadAppliesProtectionChanges(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	port := freePort(t)
	dir := t.TempDir()
	write := func(extra string) string {
		path := dir + "/waf.yaml"
		body := fmt.Sprintf("version: v1beta1\nport: %d\ndata_dir: %s\nroutes:\n  - id: app\n    upstream: %s\n%s",
			port, dir+"/data", upstream.URL, extra)
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	path := write("")
	rl := startServer(t, path, slog.New(slog.NewTextHandler(io.Discard, nil)))

	if got := post(t, port); got != http.StatusOK {
		t.Fatalf("before reload: POST = %d, want 200", got)
	}

	// A change that does not alter the Caddy JSON: only the route's accept
	// policy. An unforced caddy.Load would skip it as "unchanged".
	write("    accept:\n      methods: [GET, HEAD]\n")
	if err := rl.reload(); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if got := post(t, port); got != http.StatusMethodNotAllowed {
		t.Fatalf("after reload: POST = %d, want 405 (reload did not apply the new accept.methods)", got)
	}

	// A config that parses and compiles but fails when Caddy provisions the
	// handler (the OpenAPI spec file is read there). The running config must
	// keep serving and the registry must keep describing it.
	applied := &rl.resolved[0]
	write("    openapi:\n      spec: " + dir + "/missing-spec.yaml\n")
	if err := rl.reload(); err == nil {
		t.Fatal("reload with a missing OpenAPI spec: expected an error")
	}
	if got := post(t, port); got != http.StatusMethodNotAllowed {
		t.Fatalf("after failed reload: POST = %d, want 405 (running config changed)", got)
	}
	if rl.resolved[0].Accept.Methods[0] != "GET" || &rl.resolved[0] != applied {
		t.Error("reloader replaced its current config after a failed reload")
	}
	if pipeline.GetConfig("app") != applied {
		t.Error("route registry was left holding the config of the failed reload")
	}

	// And a later good reload still works.
	write("")
	if err := rl.reload(); err != nil {
		t.Fatalf("reload after a failed one: %v", err)
	}
	if got := post(t, port); got != http.StatusOK {
		t.Fatalf("after recovery reload: POST = %d, want 200", got)
	}
}

func TestStartupOnlyChanges(t *testing.T) {
	base := func() *config.Config { return &config.Config{HealthPort: 8081, MetricsPort: 9090} }

	if got := startupOnlyChanges(base(), base()); len(got) != 0 {
		t.Errorf("identical configs reported changes: %v", got)
	}

	changed := base()
	changed.HealthPort = 8082
	changed.MetricsPort = 0
	changed.Tracing.Enabled = true
	changed.AuditLog.Format = "ecs"
	got := strings.Join(startupOnlyChanges(base(), changed), ",")
	if want := "health_port,metrics_port,tracing,audit_log"; got != want {
		t.Errorf("startupOnlyChanges = %q, want %q", got, want)
	}

	// Settings Caddy applies on reload are not startup-only.
	moved := base()
	moved.Port = 8443
	moved.DataDir = "/elsewhere"
	if got := startupOnlyChanges(base(), moved); len(got) != 0 {
		t.Errorf("port/data_dir reported as startup-only: %v", got)
	}
}
