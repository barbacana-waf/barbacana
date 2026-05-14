package config

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// validateAuth validates the route's auth block: shape, mutual
// exclusion across the three mechanisms, and per-mechanism field
// constraints. Errors are accumulated rather than returned at the
// first failure so an operator sees every problem in one validation
// run.
func validateAuth(a *AuthCfg, prefix string, errs *[]string) {
	if a == nil {
		return
	}

	configured := authMechanismsSet(a)
	if len(configured) > 1 {
		*errs = append(*errs, fmt.Sprintf(
			"%s: auth has multiple mechanisms configured: %s. Exactly one of forward_auth, jwt, opaque_token may be set per route.",
			prefix, strings.Join(configured, ", ")))
		// Continue validating each block so the operator sees the
		// per-field issues as well — fixing the mutual-exclusion
		// error and resubmitting shouldn't immediately surface a
		// fresh wave of unrelated errors.
	}

	if a.ForwardAuth != nil {
		validateForwardAuth(a.ForwardAuth, prefix+".auth.forward_auth", errs)
	}
	if a.JWT != nil {
		validateJWT(a.JWT, prefix+".auth.jwt", errs)
	}
	if a.OpaqueToken != nil {
		validateOpaqueToken(a.OpaqueToken, prefix+".auth.opaque_token", errs)
	}
}

func authMechanismsSet(a *AuthCfg) []string {
	out := make([]string, 0, 3)
	if a.ForwardAuth != nil {
		out = append(out, "forward_auth")
	}
	if a.JWT != nil {
		out = append(out, "jwt")
	}
	if a.OpaqueToken != nil {
		out = append(out, "opaque_token")
	}
	return out
}

func validateForwardAuth(f *ForwardAuthCfg, prefix string, errs *[]string) {
	add := func(msg string) { *errs = append(*errs, fmt.Sprintf("%s: %s", prefix, msg)) }

	if f.Preset == "" {
		add("preset is required")
	} else if _, ok := ForwardAuthPresets[f.Preset]; !ok {
		add(fmt.Sprintf("preset %q is not one of: oauth2-proxy, authelia, authentik, tinyauth, custom", f.Preset))
	}

	if f.Endpoint == "" {
		add("endpoint is required")
	} else if !validHTTPURL(f.Endpoint) {
		add(fmt.Sprintf("endpoint must be a valid http or https URL, got %q", f.Endpoint))
	}

	if f.Preset == ForwardAuthPresetCustom {
		if f.VerifyEndpoint == "" {
			add("verify_endpoint is required when preset is \"custom\"")
		}
		if f.SigninRedirect == nil {
			add("signin_redirect is required when preset is \"custom\" (use empty string for sidecars that emit Location themselves)")
		}
		if f.SidecarPaths == nil {
			add("sidecar_paths is required when preset is \"custom\" (use [] for sidecars that live on a separate hostname)")
		}
		if len(f.IdentityHeaders) == 0 {
			add("identity_headers is required and must be non-empty when preset is \"custom\"")
		}
	}

	if f.VerifyEndpoint != "" && !strings.HasPrefix(f.VerifyEndpoint, "/") {
		add(fmt.Sprintf("verify_endpoint %q must start with /", f.VerifyEndpoint))
	}

	if f.SigninRedirect != nil && *f.SigninRedirect != "" {
		validateSigninRedirect(*f.SigninRedirect, prefix, errs)
	}

	for _, p := range f.SidecarPaths {
		if !strings.HasPrefix(p, "/") {
			add(fmt.Sprintf("sidecar_paths entry %q must start with /", p))
		}
		if !(strings.HasSuffix(p, "/") || strings.HasSuffix(p, "*")) {
			add(fmt.Sprintf("sidecar_paths entry %q must end with / or *", p))
		}
	}

	for _, h := range f.IdentityHeaders {
		if !validHTTPHeaderName(h) {
			add(fmt.Sprintf("identity_headers entry %q is not a valid HTTP header name", h))
		}
	}

	if f.Timeout != "" {
		d, err := time.ParseDuration(f.Timeout)
		if err != nil {
			add(fmt.Sprintf("timeout: %v", err))
		} else if d <= 0 || d >= MaxAuthSubrequestTimeout {
			add(fmt.Sprintf("timeout must be > 0 and < %s", MaxAuthSubrequestTimeout))
		}
	}
}

func validateSigninRedirect(s, prefix string, errs *[]string) {
	add := func(msg string) { *errs = append(*errs, fmt.Sprintf("%s: %s", prefix, msg)) }

	if u, err := url.Parse(s); err == nil && u.Scheme != "" && u.Host != "" {
		// Fully qualified URL — accepted as-is.
		return
	}
	if !strings.Contains(s, "{rd}") {
		add(fmt.Sprintf("signin_redirect %q must be empty, contain the {rd} placeholder, or be a fully qualified URL", s))
	}
}

func validateJWT(j *JWTCfg, prefix string, errs *[]string) {
	add := func(msg string) { *errs = append(*errs, fmt.Sprintf("%s: %s", prefix, msg)) }

	if j.JWKSURL == "" {
		add("jwks_url is required")
	} else if ok, msg := validateRemoteHTTPURL(j.JWKSURL); !ok {
		add("jwks_url: " + msg)
	}

	if j.Issuer == "" {
		add("issuer is required")
	}

	if len(j.Audience.Values) == 0 {
		add("audience is required")
	} else {
		for _, v := range j.Audience.Values {
			if v == "" {
				add("audience entries must be non-empty")
				break
			}
		}
	}

	// Distinguish absent (nil) from explicit empty (non-nil zero-length).
	// Absent falls through to the default [RS256] in resolve; explicit
	// empty is a footgun (no algorithms means no JWT can ever validate)
	// and must be a hard rejection so the operator notices and either
	// removes the field or names the algorithms they actually want.
	if j.Algorithms != nil && len(j.Algorithms) == 0 {
		add("algorithms: explicit empty list is not allowed; remove the field to use the default [RS256] or list the algorithms your IdP actually signs with")
	}
	for _, alg := range j.Algorithms {
		if strings.EqualFold(alg, "none") {
			add("algorithms must not include \"none\" — alg=none disables signature verification")
		}
	}

	if j.JWKSRefreshInterval != "" {
		d, err := time.ParseDuration(j.JWKSRefreshInterval)
		if err != nil {
			add(fmt.Sprintf("jwks_refresh_interval: %v", err))
		} else if d < MinJWKSRefreshInterval || d > MaxJWKSRefreshInterval {
			add(fmt.Sprintf("jwks_refresh_interval must be >= %s and <= %s", MinJWKSRefreshInterval, MaxJWKSRefreshInterval))
		}
	}

	if j.ClockSkew != "" {
		d, err := time.ParseDuration(j.ClockSkew)
		if err != nil {
			add(fmt.Sprintf("clock_skew: %v", err))
		} else if d < 0 || d > MaxJWTClockSkew {
			add(fmt.Sprintf("clock_skew must be >= 0 and <= %s", MaxJWTClockSkew))
		}
	}

	for claim, header := range j.ForwardClaims {
		if claim == "" {
			add("forward_claims keys must be non-empty")
		}
		if !validHTTPHeaderName(header) {
			add(fmt.Sprintf("forward_claims target %q is not a valid HTTP header name", header))
		}
	}

	validateTokenSource(j.TokenSource, prefix, errs)

	if j.HeaderName != "" && !validHTTPHeaderName(j.HeaderName) {
		add(fmt.Sprintf("header_name %q is not a valid HTTP header name", j.HeaderName))
	}
}

func validateOpaqueToken(o *OpaqueTokenCfg, prefix string, errs *[]string) {
	add := func(msg string) { *errs = append(*errs, fmt.Sprintf("%s: %s", prefix, msg)) }

	if o.IntrospectionEndpoint == "" {
		add("introspection_endpoint is required")
	} else if ok, msg := validateRemoteHTTPURL(o.IntrospectionEndpoint); !ok {
		add("introspection_endpoint: " + msg)
	}

	if o.ClientID == "" {
		add("client_id is required")
	}
	if o.ClientSecretEnv == "" {
		add("client_secret_env is required")
	} else if v, ok := os.LookupEnv(o.ClientSecretEnv); !ok || v == "" {
		add(fmt.Sprintf("client_secret_env: environment variable %q is unset or empty", o.ClientSecretEnv))
	}

	if o.CacheTTL != "" {
		d, err := time.ParseDuration(o.CacheTTL)
		if err != nil {
			add(fmt.Sprintf("cache_ttl: %v", err))
		} else if d < MinOpaqueTokenCacheTTL || d > MaxOpaqueTokenCacheTTL {
			add(fmt.Sprintf("cache_ttl must be >= %s and <= %s", MinOpaqueTokenCacheTTL, MaxOpaqueTokenCacheTTL))
		}
	}

	if o.CacheMaxSize != nil && (*o.CacheMaxSize < MinOpaqueTokenCacheMaxSize || *o.CacheMaxSize > MaxOpaqueTokenCacheMaxSize) {
		add(fmt.Sprintf("cache_max_size must be >= %d and <= %d", MinOpaqueTokenCacheMaxSize, MaxOpaqueTokenCacheMaxSize))
	}

	if o.Timeout != "" {
		d, err := time.ParseDuration(o.Timeout)
		if err != nil {
			add(fmt.Sprintf("timeout: %v", err))
		} else if d <= 0 || d >= MaxAuthSubrequestTimeout {
			add(fmt.Sprintf("timeout must be > 0 and < %s", MaxAuthSubrequestTimeout))
		}
	}

	for claim, header := range o.ForwardClaims {
		if claim == "" {
			add("forward_claims keys must be non-empty")
		}
		if !validHTTPHeaderName(header) {
			add(fmt.Sprintf("forward_claims target %q is not a valid HTTP header name", header))
		}
	}

	validateTokenSource(o.TokenSource, prefix, errs)

	if o.HeaderName != "" && !validHTTPHeaderName(o.HeaderName) {
		add(fmt.Sprintf("header_name %q is not a valid HTTP header name", o.HeaderName))
	}
}

func validateTokenSource(ts, prefix string, errs *[]string) {
	if ts == "" {
		return
	}
	if ts != TokenSourceHeader && ts != TokenSourceQuery && ts != TokenSourceBoth {
		*errs = append(*errs, fmt.Sprintf("%s: token_source must be one of: header, query, both. Got %q", prefix, ts))
	}
}

// validHTTPHeaderName returns true when s is a non-empty token per
// RFC 7230 §3.2.6. Used to reject bogus identity_headers /
// forward_claims targets at config-load time rather than at request
// time.
func validHTTPHeaderName(s string) bool {
	if s == "" {
		return false
	}
	return http.CanonicalHeaderKey(s) != "" && !strings.ContainsAny(s, " \t\r\n,;:")
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsLoopback()
}

// validHTTPURL reports whether s parses as a syntactically valid URL
// with scheme http or https and a non-empty host.
func validHTTPURL(s string) bool {
	u, err := url.Parse(s)
	if err != nil {
		return false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}
	return u.Host != ""
}

// validateRemoteHTTPURL parses s and reports it as one of three error
// shapes: empty (caller decides whether that is "required"), malformed
// (not parseable, wrong scheme, or no host), or non-loopback HTTP
// (HTTPS would have been required for any non-loopback host).
//
// Callers use the returned error message verbatim, prefixed with the
// field name. The named-loopback list ("localhost, 127.0.0.1, ::1") is
// hard-coded into the message because operators routinely try
// RFC 1918 ranges or cluster-internal hostnames and need to be told
// what does count.
func validateRemoteHTTPURL(s string) (ok bool, msg string) {
	u, err := url.Parse(s)
	if err != nil {
		return false, fmt.Sprintf("must be a valid http or https URL, got %q", s)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return false, fmt.Sprintf("must be a valid http or https URL, got %q", s)
	}
	if u.Host == "" {
		return false, fmt.Sprintf("must be a valid http or https URL with a host, got %q", s)
	}
	if u.Scheme == "http" && !isLoopbackHost(u.Hostname()) {
		return false, fmt.Sprintf(
			"http scheme is only allowed for loopback hosts (localhost, 127.0.0.1, ::1); got %q",
			u.Hostname())
	}
	return true, ""
}
