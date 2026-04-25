// Package headers implements security header injection and stripping.
package headers

import (
	"net/http"

	"github.com/barbacana-waf/barbacana/internal/config"
	"github.com/barbacana-waf/barbacana/internal/metrics"
	"github.com/barbacana-waf/barbacana/internal/protections"
)

// Injection header canonical names → HTTP header → default value.
var injectionDefaults = map[string]struct {
	Header  string
	Default string
}{
	"header-hsts":                  {"Strict-Transport-Security", "max-age=63072000; includeSubDomains"},
	"header-csp":                   {"Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; upgrade-insecure-requests"},
	"header-x-frame-options":       {"X-Frame-Options", "DENY"},
	"header-x-content-type-options": {"X-Content-Type-Options", "nosniff"},
	"header-referrer-policy":       {"Referrer-Policy", "strict-origin-when-cross-origin"},
	"header-x-dns-prefetch":        {"X-DNS-Prefetch-Control", "off"},
	"header-coop":                  {"Cross-Origin-Opener-Policy", "same-origin"},
	"header-coep":                  {"Cross-Origin-Embedder-Policy", "unsafe-none"},
	"header-corp":                  {"Cross-Origin-Resource-Policy", "same-origin"},
	"header-permissions-policy":    {"Permissions-Policy", "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=(), interest-cohort=()"},
	"header-cache-control":         {"Cache-Control", "no-store, no-cache, must-revalidate, max-age=0"},
}

// Preset overrides per preset name.
var presetOverrides = map[string]map[string]string{
	"strict": {
		"header-csp":  "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'; upgrade-insecure-requests",
		"header-coep": "require-corp",
	},
	"api-only": {
		"header-csp":           "default-src 'none'",
		"header-x-frame-options": "DENY",
		"header-cache-control": "no-store",
	},
	"moderate": {}, // uses all defaults
	"custom":   {}, // user provides everything via inject
}

// Stripping header canonical names → HTTP headers to strip.
var strippingHeaders = map[string][]string{
	"strip-server":         {"Server"},
	"strip-x-powered-by":   {"X-Powered-By"},
	"strip-aspnet-version": {"X-AspNet-Version", "X-AspNetMvc-Version"},
	"strip-generator":      {"X-Generator"},
	"strip-drupal":         {"X-Drupal-Dynamic-Cache", "X-Drupal-Cache"},
	"strip-varnish":        {"X-Varnish"},
	"strip-via":            {"Via"},
	"strip-runtime":        {"X-Runtime"},
	"strip-debug":          {"X-Debug-Token", "X-Debug-Token-Link"},
	"strip-backend-server": {"X-Backend-Server"},
	"strip-version":        {"X-Version"},
}

// Injector injects security response headers based on preset and overrides.
type Injector struct {
	cfg config.Resolved
}

func NewInjector(cfg config.Resolved) *Injector {
	return &Injector{cfg: cfg}
}

// InjectHeaders adds security headers to the response. Called as a response
// modifier before the response is sent to the client.
func (inj *Injector) InjectHeaders(w http.ResponseWriter, disabled map[string]bool) {
	preset := inj.cfg.ResponseHeaders.Preset
	overrides := presetOverrides[preset]

	for canon, hdr := range injectionDefaults {
		if protections.IsDisabled(canon, disabled) {
			continue
		}
		// Determine value: route inject > preset override > default.
		value := hdr.Default
		if pv, ok := overrides[canon]; ok {
			value = pv
		}
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

