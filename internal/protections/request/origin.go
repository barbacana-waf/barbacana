package request

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/barbacana-waf/barbacana/internal/config"
	"github.com/barbacana-waf/barbacana/internal/protections"
)

// CSRFOriginCheck blocks state-changing requests whose Origin (or, as a
// fallback, Referer) header does not match the route's allowed origins.
// The check follows the OWASP CSRF cheat-sheet "verifying origin with
// standard headers" pattern: it complements but does not replace synchronizer
// tokens, and it never rejects safe HTTP methods.
const CSRFOriginCheck = "csrf-origin-check"

// OriginValidator owns the per-route origin allow-set computed at config
// resolution time so the per-request hot path is just two map/slice walks.
type OriginValidator struct {
	cfg     config.Resolved
	allowed map[string]bool
}

// NewOriginValidator captures the resolved allowed-origin list into a
// lookup map. AllowedOrigins is computed in internal/config/resolve.go from
// either the route's CORS allow_origins or the configured deployment hosts.
func NewOriginValidator(cfg config.Resolved) *OriginValidator {
	allowed := make(map[string]bool, len(cfg.AllowedOrigins))
	for _, o := range cfg.AllowedOrigins {
		allowed[o] = true
	}
	return &OriginValidator{cfg: cfg, allowed: allowed}
}

// Validate runs the origin check for the request. Returns Allow on safe
// methods, when the protection is disabled, or when the route has no
// allowed-origin information to compare against (plain HTTP behind a
// load balancer where no hosts are configured).
func (ov *OriginValidator) Validate(_ context.Context, r *http.Request) protections.Decision {
	if protections.IsDisabled(CSRFOriginCheck, ov.cfg.Disable) {
		return protections.Allow()
	}
	if !isStateChangingMethod(r.Method) {
		return protections.Allow()
	}

	hasCORS := ov.cfg.CORS != nil && len(ov.cfg.CORS.AllowOrigins) > 0
	if len(ov.allowed) == 0 && !hasCORS {
		// No host info available — typical for Mode 3 behind a TLS-terminating
		// load balancer where the WAF only knows the listen port. We can't
		// distinguish same-origin from cross-origin here; defer to other
		// CSRF defences (SameSite cookies, tokens).
		return protections.Allow()
	}

	origin := r.Header.Get("Origin")
	// Origin: null is sent by privacy-sensitive contexts (sandboxed iframes,
	// data: URIs, file://). Treat it as "no Origin" and try Referer next.
	if origin == "null" {
		origin = ""
	}

	if origin == "" {
		if ref := r.Header.Get("Referer"); ref != "" {
			origin = originFromReferer(ref)
		}
	}

	if origin == "" {
		// No Origin and no Referer.
		if hasCORS {
			return protections.Block(CSRFOriginCheck,
				"state-changing request without Origin or Referer on CORS-protected route")
		}
		// Non-browser clients (curl, webhooks, server-to-server) typically
		// omit both. The OWASP cheat-sheet is explicit that this branch
		// must allow the request to keep API integrations working.
		return protections.Allow()
	}

	normalized := normalizeOrigin(origin)
	if ov.allowed[normalized] {
		return protections.Allow()
	}
	return protections.Decision{
		Block:      true,
		Protection: CSRFOriginCheck,
		Reason:     fmt.Sprintf("origin %q not allowed for %s", normalized, r.Method),
	}
}

// isStateChangingMethod reports whether the method should be subjected to
// the origin check. Per RFC 9110 §9.2.1 GET/HEAD/OPTIONS are safe;
// TRACE/CONNECT are not relevant to browser CSRF in practice.
func isStateChangingMethod(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	}
	return false
}

// originFromReferer extracts the scheme://host[:port] portion of a Referer
// URL. Returns "" if the Referer is not a parseable absolute URL — the
// caller then treats it as missing.
func originFromReferer(ref string) string {
	u, err := url.Parse(ref)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

// normalizeOrigin strips the default port for the scheme so an Origin
// header sent as `https://example.com:443` matches a configured allow-list
// entry of `https://example.com` and vice versa.
func normalizeOrigin(o string) string {
	o = strings.TrimSpace(o)
	if o == "" {
		return ""
	}
	u, err := url.Parse(o)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return strings.ToLower(o)
	}
	host := u.Host
	if h, p, ok := splitHostPort(host); ok {
		if (u.Scheme == "http" && p == "80") || (u.Scheme == "https" && p == "443") {
			host = h
		}
	}
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(host)
}

func splitHostPort(hp string) (host, port string, ok bool) {
	if strings.HasPrefix(hp, "[") {
		end := strings.LastIndex(hp, "]")
		if end < 0 || end+1 >= len(hp) || hp[end+1] != ':' {
			return hp, "", false
		}
		return hp[:end+1], hp[end+2:], true
	}
	idx := strings.LastIndex(hp, ":")
	if idx < 0 {
		return hp, "", false
	}
	return hp[:idx], hp[idx+1:], true
}

// RegisterOrigin adds csrf-origin-check to the registry so disable-list
// validation accepts the canonical name.
func RegisterOrigin(reg *protections.Registry) {
	reg.Add(namedProtection{name: CSRFOriginCheck})
}
