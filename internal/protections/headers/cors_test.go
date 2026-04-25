package headers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/barbacana-waf/barbacana/internal/config"
)

func corsCfg(origins []string, credentials bool) *config.CORSCfg {
	return &config.CORSCfg{
		AllowOrigins:     origins,
		AllowMethods:     []string{"GET", "POST"},
		AllowHeaders:     []string{"Authorization", "Content-Type"},
		AllowCredentials: &credentials,
	}
}

func TestPreflightAllowed(t *testing.T) {
	ch := NewCORSHandler(corsCfg([]string{"https://app.example.com"}, false))
	r := httptest.NewRequest("OPTIONS", "/api", nil)
	r.Header.Set("Origin", "https://app.example.com")
	r.Header.Set("Access-Control-Request-Method", "POST")
	w := httptest.NewRecorder()

	handled := ch.HandlePreflight(w, r)
	if !handled {
		t.Fatal("should handle preflight")
	}
	if w.Code != 204 {
		t.Errorf("status = %d, want 204", w.Code)
	}
	if w.Header().Get("Access-Control-Allow-Origin") != "https://app.example.com" {
		t.Errorf("ACAO = %q", w.Header().Get("Access-Control-Allow-Origin"))
	}
	if w.Header().Get("Access-Control-Allow-Methods") == "" {
		t.Error("missing ACAM header")
	}
}

func TestPreflightBlockedOrigin(t *testing.T) {
	ch := NewCORSHandler(corsCfg([]string{"https://app.example.com"}, false))
	r := httptest.NewRequest("OPTIONS", "/api", nil)
	r.Header.Set("Origin", "https://evil.com")
	r.Header.Set("Access-Control-Request-Method", "POST")
	w := httptest.NewRecorder()

	handled := ch.HandlePreflight(w, r)
	if !handled {
		t.Fatal("should handle preflight")
	}
	if w.Code != 403 {
		t.Errorf("status = %d, want 403", w.Code)
	}
}

func TestCORSResponseHeaders(t *testing.T) {
	ch := NewCORSHandler(corsCfg([]string{"https://app.example.com"}, false))
	r := httptest.NewRequest("GET", "/api", nil)
	r.Header.Set("Origin", "https://app.example.com")
	w := httptest.NewRecorder()

	ch.SetCORSHeaders(w, r)
	if w.Header().Get("Access-Control-Allow-Origin") != "https://app.example.com" {
		t.Errorf("ACAO = %q", w.Header().Get("Access-Control-Allow-Origin"))
	}
}

func TestCORSBlockedOriginNoHeaders(t *testing.T) {
	ch := NewCORSHandler(corsCfg([]string{"https://app.example.com"}, false))
	r := httptest.NewRequest("GET", "/api", nil)
	r.Header.Set("Origin", "https://evil.com")
	w := httptest.NewRecorder()

	ch.SetCORSHeaders(w, r)
	if w.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Error("should not set ACAO for blocked origin")
	}
}

func TestCORSCredentialsNoWildcard(t *testing.T) {
	ch := NewCORSHandler(corsCfg([]string{"https://app.example.com"}, true))
	r := httptest.NewRequest("GET", "/api", nil)
	r.Header.Set("Origin", "https://app.example.com")
	w := httptest.NewRecorder()

	ch.SetCORSHeaders(w, r)
	if w.Header().Get("Access-Control-Allow-Credentials") != "true" {
		t.Error("missing credentials header")
	}
	if w.Header().Get("Access-Control-Allow-Origin") == "*" {
		t.Error("should never reflect * with credentials")
	}
}

func TestNilCORSHandler(t *testing.T) {
	ch := NewCORSHandler(nil)
	if ch != nil {
		t.Error("nil config should produce nil handler")
	}
	// Nil handler methods should not panic.
	w := httptest.NewRecorder()
	r := httptest.NewRequest("OPTIONS", "/", nil)
	handled := (*CORSHandler)(nil).HandlePreflight(w, r)
	if handled {
		t.Error("nil should not handle")
	}
	(*CORSHandler)(nil).SetCORSHeaders(w, r)
	(*CORSHandler)(nil).InjectVary(http.Header{}, map[string]bool{})
}

func TestInjectVary_AddsAllThreeWhenAbsent(t *testing.T) {
	ch := NewCORSHandler(corsCfg([]string{"https://app.example.com"}, false))
	h := http.Header{}
	ch.InjectVary(h, map[string]bool{})

	v := h.Get("Vary")
	for _, want := range []string{"Origin", "Access-Control-Request-Method", "Access-Control-Request-Headers"} {
		if !strings.Contains(v, want) {
			t.Errorf("Vary missing %q: %q", want, v)
		}
	}
}

func TestInjectVary_AppendsWithoutDuplicates(t *testing.T) {
	ch := NewCORSHandler(corsCfg([]string{"https://app.example.com"}, false))
	h := http.Header{}
	h.Set("Vary", "Accept-Encoding, Origin")
	ch.InjectVary(h, map[string]bool{})

	v := h.Get("Vary")
	if !strings.Contains(v, "Accept-Encoding") {
		t.Errorf("existing value lost: %q", v)
	}
	// Origin should appear exactly once even though it was already present.
	if strings.Count(strings.ToLower(v), "origin") != 1 {
		t.Errorf("duplicate Origin in Vary: %q", v)
	}
	if !strings.Contains(v, "Access-Control-Request-Method") {
		t.Errorf("ACRM missing: %q", v)
	}
	if !strings.Contains(v, "Access-Control-Request-Headers") {
		t.Errorf("ACRH missing: %q", v)
	}
}

func TestInjectVary_Disabled(t *testing.T) {
	ch := NewCORSHandler(corsCfg([]string{"https://app.example.com"}, false))
	h := http.Header{}
	disabled := map[string]bool{CORSVaryInjection: true}
	ch.InjectVary(h, disabled)

	if h.Get("Vary") != "" {
		t.Errorf("Vary should not be set when cors-vary-injection disabled, got %q", h.Get("Vary"))
	}
}

func TestInjectVary_NilHandlerNoop(t *testing.T) {
	(*CORSHandler)(nil).InjectVary(http.Header{}, map[string]bool{})
}
