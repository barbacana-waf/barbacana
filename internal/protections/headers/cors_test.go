package headers

import (
	"net/http/httptest"
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
}
