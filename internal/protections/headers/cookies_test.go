package headers

import (
	"net/http"
	"strings"
	"testing"

	"github.com/barbacana-waf/barbacana/internal/config"
)

func cookieCfg(tlsMode bool) config.Resolved {
	return config.Resolved{
		ID:      "test",
		TLSMode: tlsMode,
		Disable: map[string]bool{},
	}
}

func TestCookieHardener_AddsBothInTLSMode(t *testing.T) {
	ch := NewCookieHardener(cookieCfg(true))
	h := http.Header{}
	h.Add("Set-Cookie", "session=abc123; Path=/")
	ch.HardenCookies(h, map[string]bool{})

	got := h.Get("Set-Cookie")
	if !strings.Contains(got, "SameSite=Lax") {
		t.Errorf("missing SameSite=Lax: %q", got)
	}
	if !strings.Contains(got, "Secure") {
		t.Errorf("missing Secure: %q", got)
	}
	if !strings.Contains(got, "session=abc123") {
		t.Errorf("value not preserved: %q", got)
	}
	if !strings.Contains(got, "Path=/") {
		t.Errorf("Path attribute not preserved: %q", got)
	}
}

func TestCookieHardener_PreservesExistingSameSite(t *testing.T) {
	ch := NewCookieHardener(cookieCfg(true))
	h := http.Header{}
	h.Add("Set-Cookie", "session=abc123; Path=/; SameSite=Strict")
	ch.HardenCookies(h, map[string]bool{})

	got := h.Get("Set-Cookie")
	if strings.Contains(got, "SameSite=Lax") {
		t.Errorf("should not add Lax when Strict already present: %q", got)
	}
	if !strings.Contains(got, "SameSite=Strict") {
		t.Errorf("Strict not preserved: %q", got)
	}
}

func TestCookieHardener_NoneWithSecurePreserved(t *testing.T) {
	ch := NewCookieHardener(cookieCfg(true))
	h := http.Header{}
	h.Add("Set-Cookie", "session=abc123; Path=/; SameSite=None; Secure")
	ch.HardenCookies(h, map[string]bool{})

	got := h.Get("Set-Cookie")
	if got != "session=abc123; Path=/; SameSite=None; Secure" {
		t.Errorf("cookie should be unchanged, got: %q", got)
	}
}

func TestCookieHardener_NoSecureInPlainHTTP(t *testing.T) {
	ch := NewCookieHardener(cookieCfg(false)) // plain HTTP
	h := http.Header{}
	h.Add("Set-Cookie", "session=abc123; Path=/")
	ch.HardenCookies(h, map[string]bool{})

	got := h.Get("Set-Cookie")
	if !strings.Contains(got, "SameSite=Lax") {
		t.Errorf("SameSite should still be added in plain HTTP: %q", got)
	}
	if strings.Contains(got, "Secure") {
		t.Errorf("Secure must NOT be added in plain HTTP: %q", got)
	}
}

func TestCookieHardener_MultipleCookies(t *testing.T) {
	ch := NewCookieHardener(cookieCfg(true))
	h := http.Header{}
	h.Add("Set-Cookie", "session=abc")
	h.Add("Set-Cookie", "tracking=xyz; SameSite=Lax")
	h.Add("Set-Cookie", "prefs=dark; Secure")
	ch.HardenCookies(h, map[string]bool{})

	cookies := h.Values("Set-Cookie")
	if len(cookies) != 3 {
		t.Fatalf("expected 3 cookies, got %d", len(cookies))
	}
	if !strings.Contains(cookies[0], "SameSite=Lax") || !strings.Contains(cookies[0], "Secure") {
		t.Errorf("session cookie not augmented: %q", cookies[0])
	}
	// tracking already had SameSite, should still get Secure but not double SameSite.
	if strings.Count(strings.ToLower(cookies[1]), "samesite=") != 1 {
		t.Errorf("tracking cookie has duplicate SameSite: %q", cookies[1])
	}
	if !strings.Contains(cookies[1], "Secure") {
		t.Errorf("tracking cookie missing Secure: %q", cookies[1])
	}
	// prefs already had Secure but no SameSite.
	if !strings.Contains(cookies[2], "SameSite=Lax") {
		t.Errorf("prefs cookie missing SameSite: %q", cookies[2])
	}
	if strings.Count(cookies[2], "Secure") != 1 {
		t.Errorf("prefs cookie has duplicate Secure: %q", cookies[2])
	}
}

func TestCookieHardener_UnusualFormatting(t *testing.T) {
	// Lowercase attribute names, weird spacing.
	ch := NewCookieHardener(cookieCfg(true))
	h := http.Header{}
	h.Add("Set-Cookie", "session=abc123;path=/;samesite=lax")
	ch.HardenCookies(h, map[string]bool{})

	got := h.Get("Set-Cookie")
	// SameSite was already there (lowercase). Should not be re-added.
	if strings.Count(strings.ToLower(got), "samesite=") != 1 {
		t.Errorf("duplicate samesite: %q", got)
	}
	// Secure was missing.
	if !strings.Contains(got, "Secure") {
		t.Errorf("Secure should be added: %q", got)
	}
}

func TestCookieHardener_DisableSameSite(t *testing.T) {
	ch := NewCookieHardener(cookieCfg(true))
	h := http.Header{}
	h.Add("Set-Cookie", "session=abc123")
	disabled := map[string]bool{CSRFSameSiteCookies: true}
	ch.HardenCookies(h, disabled)

	got := h.Get("Set-Cookie")
	if strings.Contains(got, "SameSite") {
		t.Errorf("SameSite should not be added when disabled: %q", got)
	}
	if !strings.Contains(got, "Secure") {
		t.Errorf("Secure still expected (TLS mode, csrf-secure-cookies enabled): %q", got)
	}
}

func TestCookieHardener_DisableSecure(t *testing.T) {
	ch := NewCookieHardener(cookieCfg(true))
	h := http.Header{}
	h.Add("Set-Cookie", "session=abc123")
	disabled := map[string]bool{CSRFSecureCookies: true}
	ch.HardenCookies(h, disabled)

	got := h.Get("Set-Cookie")
	if strings.Contains(got, "Secure") {
		t.Errorf("Secure should not be added when csrf-secure-cookies disabled: %q", got)
	}
	if !strings.Contains(got, "SameSite=Lax") {
		t.Errorf("SameSite still expected: %q", got)
	}
}

func TestCookieHardener_NoCookies(t *testing.T) {
	ch := NewCookieHardener(cookieCfg(true))
	h := http.Header{}
	// Should not panic and should not add any cookies.
	ch.HardenCookies(h, map[string]bool{})
	if len(h.Values("Set-Cookie")) != 0 {
		t.Errorf("unexpected cookies appeared")
	}
}
