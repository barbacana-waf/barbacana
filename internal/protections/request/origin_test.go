package request

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/barbacana-waf/barbacana/internal/config"
)

func originCfg(allowed []string, withCORS bool) config.Resolved {
	cfg := config.Resolved{
		ID:             "test",
		Disable:        map[string]bool{},
		AllowedOrigins: allowed,
	}
	if withCORS {
		cfg.CORS = &config.CORSCfg{AllowOrigins: allowed}
	}
	return cfg
}

func TestOrigin_SameOriginAllowed(t *testing.T) {
	v := NewOriginValidator(originCfg([]string{"http://localhost:18080"}, false))
	r := httptest.NewRequest("POST", "/api", nil)
	r.Header.Set("Origin", "http://localhost:18080")
	if d := v.Validate(context.Background(), r); d.Block {
		t.Errorf("same-origin POST should pass: %+v", d)
	}
}

func TestOrigin_CrossOriginBlocked(t *testing.T) {
	v := NewOriginValidator(originCfg([]string{"https://app.example.com"}, true))
	r := httptest.NewRequest("POST", "/api", nil)
	r.Header.Set("Origin", "https://evil.com")
	d := v.Validate(context.Background(), r)
	if !d.Block {
		t.Error("cross-origin POST should block")
	}
	if d.Protection != CSRFOriginCheck {
		t.Errorf("protection name = %q, want %q", d.Protection, CSRFOriginCheck)
	}
}

func TestOrigin_NoOriginNoCORS_Allowed(t *testing.T) {
	v := NewOriginValidator(originCfg([]string{"https://example.com"}, false))
	r := httptest.NewRequest("POST", "/api", nil)
	if d := v.Validate(context.Background(), r); d.Block {
		t.Errorf("non-browser POST without Origin should pass when no CORS: %+v", d)
	}
}

func TestOrigin_NoOriginWithCORS_Blocked(t *testing.T) {
	v := NewOriginValidator(originCfg([]string{"https://app.example.com"}, true))
	r := httptest.NewRequest("POST", "/api", nil)
	d := v.Validate(context.Background(), r)
	if !d.Block {
		t.Error("CORS-protected POST without Origin should block")
	}
}

func TestOrigin_RefererFallback(t *testing.T) {
	v := NewOriginValidator(originCfg([]string{"http://localhost:18080"}, false))
	r := httptest.NewRequest("POST", "/api", nil)
	r.Header.Set("Referer", "http://localhost:18080/some/page?q=1")
	if d := v.Validate(context.Background(), r); d.Block {
		t.Errorf("Referer fallback should pass: %+v", d)
	}
}

func TestOrigin_NullOrigin_FallsBackToReferer(t *testing.T) {
	v := NewOriginValidator(originCfg([]string{"http://localhost:18080"}, false))
	r := httptest.NewRequest("POST", "/api", nil)
	r.Header.Set("Origin", "null")
	r.Header.Set("Referer", "http://localhost:18080/foo")
	if d := v.Validate(context.Background(), r); d.Block {
		t.Errorf("Origin: null + matching Referer should pass: %+v", d)
	}
}

func TestOrigin_GETNotChecked(t *testing.T) {
	v := NewOriginValidator(originCfg([]string{"https://app.example.com"}, true))
	r := httptest.NewRequest("GET", "/api", nil)
	r.Header.Set("Origin", "https://evil.com")
	if d := v.Validate(context.Background(), r); d.Block {
		t.Errorf("GET should never be blocked by origin check: %+v", d)
	}
}

func TestOrigin_DELETEMatching_Allowed(t *testing.T) {
	v := NewOriginValidator(originCfg([]string{"https://app.example.com"}, true))
	r := httptest.NewRequest("DELETE", "/api/1", nil)
	r.Header.Set("Origin", "https://app.example.com")
	if d := v.Validate(context.Background(), r); d.Block {
		t.Errorf("DELETE with matching origin should pass: %+v", d)
	}
}

func TestOrigin_PortNormalization(t *testing.T) {
	// Allow list lacks explicit :443; request includes it. Should still match.
	v := NewOriginValidator(originCfg([]string{"https://example.com"}, true))
	r := httptest.NewRequest("POST", "/api", nil)
	r.Header.Set("Origin", "https://example.com:443")
	if d := v.Validate(context.Background(), r); d.Block {
		t.Errorf("default-port should normalize to bare host: %+v", d)
	}
}

func TestOrigin_NoAllowedOriginsNoCORS_SkipsCheck(t *testing.T) {
	// Mode 3 plain HTTP behind LB — no host info. Should let everything through.
	v := NewOriginValidator(originCfg(nil, false))
	r := httptest.NewRequest("POST", "/api", nil)
	r.Header.Set("Origin", "https://evil.com")
	if d := v.Validate(context.Background(), r); d.Block {
		t.Errorf("no allowed origins → check skipped: %+v", d)
	}
}

// TestOrigin_IPv6ZoneID_Encoded_FailsClosed documents that an Origin
// carrying a percent-encoded IPv6 zone identifier (RFC 6874 form,
// e.g. http://[::1%25eth0]) does not normalise to the plain-literal
// form (http://[::1]) and therefore fails to match an allow-list entry
// for the bare address. The check fails closed and blocks on a
// CORS-protected route.
//
// Per RFC 6454 §3 browsers MUST NOT include zone identifiers in Origin
// headers, so this path is only reachable via hand-crafted requests.
// The test exists to catch a future "fix" to splitHostPort that adds
// zone-ID awareness without thinking through the spoofing implication
// — treating [::1%eth0] as equivalent to [::1] would let a local
// attacker forge a same-origin header.
func TestOrigin_IPv6ZoneID_Encoded_FailsClosed(t *testing.T) {
	v := NewOriginValidator(originCfg([]string{"http://[::1]"}, true))
	r := httptest.NewRequest("POST", "/api", nil)
	r.Header.Set("Origin", "http://[::1%25eth0]")
	d := v.Validate(context.Background(), r)
	if !d.Block {
		t.Error("Origin with zone ID must not match plain [::1]")
	}
}

// TestOrigin_IPv6ZoneID_Unencoded_FailsClosed covers the non-conformant
// form (unescaped %) — url.Parse rejects this, the code falls back to a
// raw lowercased compare, and the result still does not match the
// allow-list entry. Same fail-closed guarantee.
func TestOrigin_IPv6ZoneID_Unencoded_FailsClosed(t *testing.T) {
	v := NewOriginValidator(originCfg([]string{"http://[::1]"}, true))
	r := httptest.NewRequest("POST", "/api", nil)
	r.Header.Set("Origin", "http://[fe80::1%eth0]")
	d := v.Validate(context.Background(), r)
	if !d.Block {
		t.Error("unparseable Origin with zone ID must fail closed")
	}
}

func TestOrigin_Disabled(t *testing.T) {
	cfg := originCfg([]string{"https://app.example.com"}, true)
	cfg.Disable = map[string]bool{CSRFOriginCheck: true}
	v := NewOriginValidator(cfg)
	r := httptest.NewRequest("POST", "/api", nil)
	r.Header.Set("Origin", "https://evil.com")
	if d := v.Validate(context.Background(), r); d.Block {
		t.Errorf("disabled origin check should pass: %+v", d)
	}
}
