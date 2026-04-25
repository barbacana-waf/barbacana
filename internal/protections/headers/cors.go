package headers

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/barbacana-waf/barbacana/internal/config"
	"github.com/barbacana-waf/barbacana/internal/protections"
)

// CORSVaryInjection is the canonical name for the protection that adds
// CORS-related values to the Vary response header on routes with CORS
// configured. Without it, a CDN may cache a response that includes CORS
// headers and serve it to a request from a different origin (CWE-525).
const CORSVaryInjection = "cors-vary-injection"

// corsVaryValues are the response-header names that influence the CORS
// negotiation outcome. Listing them in Vary tells caches that the response
// must not be reused for requests with different values of any of them.
var corsVaryValues = []string{
	"Origin",
	"Access-Control-Request-Method",
	"Access-Control-Request-Headers",
}

// CORSHandler implements CORS handling for a single route.
// CORS is disabled by default; this handler only exists when a route
// has a cors configuration block.
type CORSHandler struct {
	cfg *config.CORSCfg
}

func NewCORSHandler(cfg *config.CORSCfg) *CORSHandler {
	if cfg == nil {
		return nil
	}
	return &CORSHandler{cfg: cfg}
}

// HandlePreflight handles an OPTIONS preflight request. Returns true if
// it was a preflight and was handled (caller should not proceed further).
func (ch *CORSHandler) HandlePreflight(w http.ResponseWriter, r *http.Request) bool {
	if ch == nil || r.Method != "OPTIONS" {
		return false
	}
	acrm := r.Header.Get("Access-Control-Request-Method")
	if acrm == "" {
		return false // not a CORS preflight
	}

	origin := r.Header.Get("Origin")
	if !ch.isOriginAllowed(origin) {
		w.WriteHeader(http.StatusForbidden)
		return true
	}

	ch.setOriginHeader(w, origin)
	w.Header().Set("Access-Control-Allow-Methods", strings.Join(ch.allowMethods(), ", "))
	if len(ch.cfg.AllowHeaders) > 0 {
		w.Header().Set("Access-Control-Allow-Headers", strings.Join(ch.cfg.AllowHeaders, ", "))
	}
	if ch.cfg.AllowCredentials != nil && *ch.cfg.AllowCredentials {
		w.Header().Set("Access-Control-Allow-Credentials", "true")
	}
	maxAge := 600
	if ch.cfg.MaxAge != nil {
		maxAge = *ch.cfg.MaxAge
	}
	w.Header().Set("Access-Control-Max-Age", strconv.Itoa(maxAge))
	w.WriteHeader(http.StatusNoContent)
	return true
}

// SetCORSHeaders adds CORS response headers for non-preflight requests.
func (ch *CORSHandler) SetCORSHeaders(w http.ResponseWriter, r *http.Request) {
	if ch == nil {
		return
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		return
	}
	if !ch.isOriginAllowed(origin) {
		return
	}

	ch.setOriginHeader(w, origin)
	if len(ch.cfg.ExposeHeaders) > 0 {
		w.Header().Set("Access-Control-Expose-Headers", strings.Join(ch.cfg.ExposeHeaders, ", "))
	}
	if ch.cfg.AllowCredentials != nil && *ch.cfg.AllowCredentials {
		w.Header().Set("Access-Control-Allow-Credentials", "true")
	}
}

// InjectVary appends CORS-related values to the Vary response header so
// downstream caches (CDNs, browsers) keep separate cache entries per Origin
// and per CORS preflight request shape. Existing Vary values (e.g.
// `Accept-Encoding`) are preserved; CORS values already present are not
// duplicated. No-op when the route has no CORS configuration or when
// cors-vary-injection is disabled.
func (ch *CORSHandler) InjectVary(headers headerSetter, disabled map[string]bool) {
	if ch == nil {
		return
	}
	if protections.IsDisabled(CORSVaryInjection, disabled) {
		return
	}

	existing := headers.Values("Vary")
	present := map[string]bool{}
	out := make([]string, 0, len(existing)+len(corsVaryValues))
	for _, line := range existing {
		for _, raw := range strings.Split(line, ",") {
			v := strings.TrimSpace(raw)
			if v == "" {
				continue
			}
			key := strings.ToLower(v)
			if present[key] {
				continue
			}
			present[key] = true
			out = append(out, v)
		}
	}
	for _, v := range corsVaryValues {
		key := strings.ToLower(v)
		if present[key] {
			continue
		}
		present[key] = true
		out = append(out, v)
	}
	headers.Del("Vary")
	headers.Set("Vary", strings.Join(out, ", "))
}

func (ch *CORSHandler) isOriginAllowed(origin string) bool {
	if origin == "" {
		return false
	}
	for _, allowed := range ch.cfg.AllowOrigins {
		if allowed == "*" {
			return true
		}
		if strings.EqualFold(allowed, origin) {
			return true
		}
	}
	return false
}

func (ch *CORSHandler) setOriginHeader(w http.ResponseWriter, origin string) {
	// Never reflect * when credentials are involved.
	if ch.cfg.AllowCredentials != nil && *ch.cfg.AllowCredentials {
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Vary", "Origin")
		return
	}
	// Check if wildcard is in the allow list.
	for _, o := range ch.cfg.AllowOrigins {
		if o == "*" {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			return
		}
	}
	w.Header().Set("Access-Control-Allow-Origin", origin)
	w.Header().Set("Vary", "Origin")
}

func (ch *CORSHandler) allowMethods() []string {
	if len(ch.cfg.AllowMethods) > 0 {
		return ch.cfg.AllowMethods
	}
	return []string{"GET"}
}
