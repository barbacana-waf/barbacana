package headers

import (
	"net/http/httptest"
	"testing"

	"github.com/barbacana-waf/barbacana/internal/config"
)

func testCfg(preset string) config.Resolved {
	return config.Resolved{
		ID:      "test",
		Disable: map[string]bool{},
		ResponseHeaders: config.ResolvedHeaders{
			Preset: preset,
			Inject: map[string]string{},
		},
	}
}

func TestInjectModeratePreset(t *testing.T) {
	cfg := testCfg("moderate")
	inj := NewInjector(cfg)

	w := httptest.NewRecorder()
	inj.InjectHeaders(w, map[string]bool{})

	checks := map[string]string{
		"Strict-Transport-Security": "max-age=63072000; includeSubDomains",
		"X-Frame-Options":           "DENY",
		"X-Content-Type-Options":    "nosniff",
		"Referrer-Policy":           "strict-origin-when-cross-origin",
	}
	for hdr, want := range checks {
		got := w.Header().Get(hdr)
		if got != want {
			t.Errorf("%s = %q, want %q", hdr, got, want)
		}
	}
}

func TestInjectStrictPreset(t *testing.T) {
	cfg := testCfg("strict")
	inj := NewInjector(cfg)

	w := httptest.NewRecorder()
	inj.InjectHeaders(w, map[string]bool{})

	csp := w.Header().Get("Content-Security-Policy")
	if csp != "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'; upgrade-insecure-requests" {
		t.Errorf("CSP = %q", csp)
	}
	coep := w.Header().Get("Cross-Origin-Embedder-Policy")
	if coep != "require-corp" {
		t.Errorf("COEP = %q", coep)
	}
}

func TestInjectRouteOverride(t *testing.T) {
	cfg := testCfg("moderate")
	cfg.ResponseHeaders.Inject = map[string]string{
		"header-csp": "default-src 'self' https://cdn.example.com",
	}
	inj := NewInjector(cfg)

	w := httptest.NewRecorder()
	inj.InjectHeaders(w, map[string]bool{})

	csp := w.Header().Get("Content-Security-Policy")
	if csp != "default-src 'self' https://cdn.example.com" {
		t.Errorf("CSP = %q", csp)
	}
}

func TestInjectDisabled(t *testing.T) {
	cfg := testCfg("moderate")
	inj := NewInjector(cfg)

	w := httptest.NewRecorder()
	disabled := map[string]bool{"header-csp": true}
	inj.InjectHeaders(w, disabled)

	if w.Header().Get("Content-Security-Policy") != "" {
		t.Error("CSP should not be injected when disabled")
	}
	// Other headers should still be present.
	if w.Header().Get("X-Frame-Options") == "" {
		t.Error("X-Frame-Options should still be injected")
	}
}

func TestInjectAddOnly(t *testing.T) {
	cfg := testCfg("moderate")
	inj := NewInjector(cfg)

	w := httptest.NewRecorder()
	// Simulate backend setting CSP.
	w.Header().Set("Content-Security-Policy", "default-src 'self'")
	inj.InjectHeaders(w, map[string]bool{})

	csp := w.Header().Get("Content-Security-Policy")
	if csp != "default-src 'self'" {
		t.Errorf("should not override backend CSP, got: %q", csp)
	}
}

func TestStripHeaders(t *testing.T) {
	cfg := testCfg("moderate")
	s := NewStripper(cfg)

	w := httptest.NewRecorder()
	w.Header().Set("Server", "nginx/1.20")
	w.Header().Set("X-Powered-By", "Express")
	w.Header().Set("X-Custom", "keep")
	s.StripHeaders(w, map[string]bool{})

	if w.Header().Get("Server") != "" {
		t.Error("Server should be stripped")
	}
	if w.Header().Get("X-Powered-By") != "" {
		t.Error("X-Powered-By should be stripped")
	}
	if w.Header().Get("X-Custom") != "keep" {
		t.Error("X-Custom should not be stripped")
	}
}

func TestStripDisabled(t *testing.T) {
	cfg := testCfg("moderate")
	s := NewStripper(cfg)

	w := httptest.NewRecorder()
	w.Header().Set("Server", "nginx/1.20")
	disabled := map[string]bool{"strip-server": true}
	s.StripHeaders(w, disabled)

	if w.Header().Get("Server") == "" {
		t.Error("Server should be preserved when strip-server is disabled")
	}
}

func TestStripExtra(t *testing.T) {
	cfg := testCfg("moderate")
	cfg.ResponseHeaders.StripExtra = []string{"X-Custom-Backend-Id"}
	s := NewStripper(cfg)

	w := httptest.NewRecorder()
	w.Header().Set("X-Custom-Backend-Id", "abc123")
	s.StripHeaders(w, map[string]bool{})

	if w.Header().Get("X-Custom-Backend-Id") != "" {
		t.Error("X-Custom-Backend-Id should be stripped via strip_extra")
	}
}
