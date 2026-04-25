package headers

import (
	"strings"

	"github.com/barbacana-waf/barbacana/internal/config"
	"github.com/barbacana-waf/barbacana/internal/protections"
)

const (
	CSRFSameSiteCookies = "csrf-samesite-cookies"
	CSRFSecureCookies   = "csrf-secure-cookies"
)

// CookieHardener augments Set-Cookie response headers with missing security
// attributes. It only ADDS attributes — cookie name, value, Path, Domain,
// Max-Age, Expires, and any attribute the upstream already set are
// preserved verbatim. Two sub-protections control behaviour independently:
// csrf-samesite-cookies (always available) and csrf-secure-cookies (only
// active when Barbacana terminates TLS — Secure cookies are inert over
// plain HTTP and would mislead operators if injected anyway).
type CookieHardener struct {
	cfg config.Resolved
}

func NewCookieHardener(cfg config.Resolved) *CookieHardener {
	return &CookieHardener{cfg: cfg}
}

// HardenCookies rewrites every Set-Cookie header on the response in place,
// adding SameSite=Lax and Secure when the corresponding sub-protection is
// enabled and the attribute is missing. No-op when the response carries no
// Set-Cookie header.
func (ch *CookieHardener) HardenCookies(headers headerSetter, disabled map[string]bool) {
	cookies := headers.Values("Set-Cookie")
	if len(cookies) == 0 {
		return
	}

	addSameSite := !protections.IsDisabled(CSRFSameSiteCookies, disabled)
	addSecure := ch.cfg.TLSMode && !protections.IsDisabled(CSRFSecureCookies, disabled)
	if !addSameSite && !addSecure {
		return
	}

	rewritten := make([]string, len(cookies))
	for i, c := range cookies {
		rewritten[i] = augmentCookie(c, addSameSite, addSecure)
	}
	headers.Del("Set-Cookie")
	for _, c := range rewritten {
		headers.Add("Set-Cookie", c)
	}
}

// headerSetter is the subset of http.Header used by HardenCookies and
// InjectVary. It is declared as an interface so a Caddy ResponseWriter
// and an httptest recorder can be passed in equally.
type headerSetter interface {
	Values(key string) []string
	Del(key string)
	Add(key, value string)
	Set(key, value string)
}

// augmentCookie appends missing SameSite and/or Secure attributes to a
// single Set-Cookie value. Detection is case-insensitive; presence is
// checked on the attribute name only — `SameSite=None` counts as set even
// though we would default to Lax.
func augmentCookie(cookie string, addSameSite, addSecure bool) string {
	hasSameSite := false
	hasSecure := false
	for _, part := range strings.Split(cookie, ";") {
		p := strings.ToLower(strings.TrimSpace(part))
		switch {
		case strings.HasPrefix(p, "samesite="):
			hasSameSite = true
		case p == "secure":
			hasSecure = true
		}
	}
	out := cookie
	if addSameSite && !hasSameSite {
		out += "; SameSite=Lax"
	}
	if addSecure && !hasSecure {
		out += "; Secure"
	}
	return out
}
