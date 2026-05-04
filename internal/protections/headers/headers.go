// Package headers implements security header injection and stripping.
package headers

import (
	"net/http"

	"github.com/barbacana-waf/barbacana/internal/config"
	"github.com/barbacana-waf/barbacana/internal/metrics"
	"github.com/barbacana-waf/barbacana/internal/protections"
)

// Injection header canonical names → HTTP header → default value.
// Phase 2 of the taxonomy refactor: canonical names use the new
// response-headers-add-* form. Default-state flips (CSP, COOP, COEP,
// CORP, Permissions-Policy, Cache-Control going off-by-default per
// PLAN.md §3.4) land in phase 4 via internal/config/defaults.go; this
// map only changes name keys, not behavior.
var injectionDefaults = map[string]struct {
	Header  string
	Default string
}{
	"response-headers-add-hsts":              {"Strict-Transport-Security", "max-age=63072000; includeSubDomains"},
	"response-headers-add-csp":               {"Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; upgrade-insecure-requests"},
	"response-headers-add-frame-options":     {"X-Frame-Options", "DENY"},
	"response-headers-add-nosniff":           {"X-Content-Type-Options", "nosniff"},
	"response-headers-add-referrer-policy":   {"Referrer-Policy", "strict-origin-when-cross-origin"},
	"response-headers-add-dns-prefetch":      {"X-DNS-Prefetch-Control", "off"},
	"response-headers-add-coop":              {"Cross-Origin-Opener-Policy", "same-origin"},
	"response-headers-add-coep":              {"Cross-Origin-Embedder-Policy", "unsafe-none"},
	"response-headers-add-corp":              {"Cross-Origin-Resource-Policy", "same-origin"},
	"response-headers-add-permissions-policy": {"Permissions-Policy", "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=(), interest-cohort=()"},
	"response-headers-add-cache-control":     {"Cache-Control", "no-store, no-cache, must-revalidate, max-age=0"},
}

// Stripping header canonical names → HTTP headers to strip.
var strippingHeaders = map[string][]string{
	"response-headers-remove-server":         {"Server"},
	"response-headers-remove-powered-by":     {"X-Powered-By"},
	"response-headers-remove-aspnet-version": {"X-AspNet-Version", "X-AspNetMvc-Version"},
	"response-headers-remove-generator":      {"X-Generator"},
	"response-headers-remove-drupal":         {"X-Drupal-Dynamic-Cache", "X-Drupal-Cache"},
	"response-headers-remove-varnish":        {"X-Varnish"},
	"response-headers-remove-via":            {"Via"},
	"response-headers-remove-runtime":        {"X-Runtime"},
	"response-headers-remove-debug":          {"X-Debug-Token", "X-Debug-Token-Link"},
	"response-headers-remove-backend-server": {"X-Backend-Server"},
	"response-headers-remove-version":        {"X-Version"},
}

// Injector injects security response headers based on configured overrides.
type Injector struct {
	cfg config.Resolved
}

func NewInjector(cfg config.Resolved) *Injector {
	return &Injector{cfg: cfg}
}

// InjectHeaders adds security headers to the response. Called as a response
// modifier before the response is sent to the client.
func (inj *Injector) InjectHeaders(w http.ResponseWriter, disabled map[string]bool) {
	for canon, hdr := range injectionDefaults {
		if protections.IsDisabled(canon, disabled) {
			continue
		}
		// Determine value: inject > default.
		value := hdr.Default
		if rv, ok := inj.cfg.ResponseHeaders.Inject[canon]; ok {
			value = rv
		}
		// Add-only: don't override if backend already set it.
		if existing := w.Header().Get(hdr.Header); existing != "" {
			continue
		}
		w.Header().Set(hdr.Header, value)
		metrics.HeadersInjectedTotal.WithLabelValues(inj.cfg.ID, canon).Inc()
	}
}

// Stripper removes security-sensitive headers from backend responses.
type Stripper struct {
	cfg config.Resolved
}

func NewStripper(cfg config.Resolved) *Stripper {
	return &Stripper{cfg: cfg}
}

// StripHeaders removes configured headers from the response.
func (s *Stripper) StripHeaders(w http.ResponseWriter, disabled map[string]bool) {
	for canon, hdrs := range strippingHeaders {
		if protections.IsDisabled(canon, disabled) {
			continue
		}
		for _, h := range hdrs {
			w.Header().Del(h)
		}
	}
	// Strip extra headers from config.
	for _, h := range s.cfg.ResponseHeaders.StripExtra {
		w.Header().Del(h)
	}
}

