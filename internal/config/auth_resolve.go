package config

import (
	"fmt"
	"net/http"
	"sort"
	"time"
)

// resolveAuth merges preset defaults with the user's overrides and
// parses durations into typed values. Returns nil when no auth is
// configured for the route.
func resolveAuth(a *AuthCfg) (*ResolvedAuth, error) {
	if a == nil {
		return nil, nil
	}
	out := &ResolvedAuth{}
	if a.ForwardAuth != nil {
		fa, err := resolveForwardAuth(a.ForwardAuth)
		if err != nil {
			return nil, fmt.Errorf("auth.forward_auth: %w", err)
		}
		out.ForwardAuth = fa
	}
	if a.JWT != nil {
		j, err := resolveJWT(a.JWT)
		if err != nil {
			return nil, fmt.Errorf("auth.jwt: %w", err)
		}
		out.JWT = j
	}
	if a.OpaqueToken != nil {
		o, err := resolveOpaqueToken(a.OpaqueToken)
		if err != nil {
			return nil, fmt.Errorf("auth.opaque_token: %w", err)
		}
		out.OpaqueToken = o
	}
	return out, nil
}

func resolveForwardAuth(f *ForwardAuthCfg) (*ResolvedForwardAuth, error) {
	res := &ResolvedForwardAuth{
		Preset:   f.Preset,
		Endpoint: f.Endpoint,
		Timeout:  DefaultForwardAuthTimeout,
	}

	defaults, hasPreset := ForwardAuthPresets[f.Preset]
	if f.Preset == ForwardAuthPresetCustom {
		// All four override fields were validated as required for
		// custom; copy them straight through.
		res.VerifyEndpoint = f.VerifyEndpoint
		if f.SigninRedirect != nil {
			res.SigninRedirect = *f.SigninRedirect
		}
		res.SidecarPaths = append([]string{}, f.SidecarPaths...)
		res.IdentityHeaders = append([]string{}, f.IdentityHeaders...)
	} else if hasPreset {
		// First-set-wins. An explicit empty list (e.g. SidecarPaths:
		// []) is meaningful — the YAML decoder distinguishes nil
		// (absent) from len-zero slice (deliberately empty), and we
		// preserve that distinction so an Authelia user can
		// disable the bypass paths even if they switch to a preset
		// that has them.
		res.VerifyEndpoint = coalesceString(f.VerifyEndpoint, defaults.VerifyEndpoint)
		if f.SigninRedirect != nil {
			res.SigninRedirect = *f.SigninRedirect
		} else {
			res.SigninRedirect = defaults.SigninRedirect
		}
		if f.SidecarPaths != nil {
			res.SidecarPaths = append([]string{}, f.SidecarPaths...)
		} else {
			res.SidecarPaths = append([]string{}, defaults.SidecarPaths...)
		}
		if len(f.IdentityHeaders) > 0 {
			res.IdentityHeaders = append([]string{}, f.IdentityHeaders...)
		} else {
			res.IdentityHeaders = append([]string{}, defaults.IdentityHeaders...)
		}
	}

	if f.Timeout != "" {
		d, err := time.ParseDuration(f.Timeout)
		if err != nil {
			return nil, fmt.Errorf("timeout: %w", err)
		}
		res.Timeout = d
	}
	return res, nil
}

func resolveJWT(j *JWTCfg) (*ResolvedJWT, error) {
	res := &ResolvedJWT{
		JWKSURL:             j.JWKSURL,
		Issuer:              j.Issuer,
		Audience:            append([]string{}, j.Audience.Values...),
		Algorithms:          append([]string{}, j.Algorithms...),
		JWKSRefreshInterval: DefaultJWTRefreshInterval,
		ClockSkew:           DefaultJWTClockSkew,
		RequiredClaims:      append([]string{}, j.RequiredClaims...),
		ForwardClaims:       canonicalHeaderMap(j.ForwardClaims),
		TokenSource:         coalesceString(j.TokenSource, DefaultJWTTokenSource),
		HeaderName:          coalesceString(j.HeaderName, DefaultJWTHeaderName),
		QueryParam:          coalesceString(j.QueryParam, DefaultJWTQueryParam),
	}
	if len(res.Algorithms) == 0 {
		res.Algorithms = []string{DefaultJWTAlgorithm}
	}

	if j.JWKSRefreshInterval != "" {
		d, err := time.ParseDuration(j.JWKSRefreshInterval)
		if err != nil {
			return nil, fmt.Errorf("jwks_refresh_interval: %w", err)
		}
		res.JWKSRefreshInterval = d
	}
	if j.ClockSkew != "" {
		d, err := time.ParseDuration(j.ClockSkew)
		if err != nil {
			return nil, fmt.Errorf("clock_skew: %w", err)
		}
		res.ClockSkew = d
	}
	return res, nil
}

func resolveOpaqueToken(o *OpaqueTokenCfg) (*ResolvedOpaqueToken, error) {
	res := &ResolvedOpaqueToken{
		IntrospectionEndpoint: o.IntrospectionEndpoint,
		ClientID:              o.ClientID,
		ClientSecretEnv:       o.ClientSecretEnv,
		CacheTTL:              DefaultOpaqueTokenCacheTTL,
		CacheMaxSize:          DefaultOpaqueTokenCacheMaxSize,
		Timeout:               DefaultOpaqueTokenTimeout,
		ForwardClaims:         canonicalHeaderMap(o.ForwardClaims),
		TokenSource:           coalesceString(o.TokenSource, DefaultOpaqueTokenTokenSource),
		HeaderName:            coalesceString(o.HeaderName, DefaultOpaqueTokenHeaderName),
		QueryParam:            coalesceString(o.QueryParam, DefaultOpaqueTokenQueryParam),
	}
	if o.CacheTTL != "" {
		d, err := time.ParseDuration(o.CacheTTL)
		if err != nil {
			return nil, fmt.Errorf("cache_ttl: %w", err)
		}
		res.CacheTTL = d
	}
	if o.CacheMaxSize != nil {
		res.CacheMaxSize = *o.CacheMaxSize
	}
	if o.Timeout != "" {
		d, err := time.ParseDuration(o.Timeout)
		if err != nil {
			return nil, fmt.Errorf("timeout: %w", err)
		}
		res.Timeout = d
	}
	return res, nil
}

// AuthIdentityStripList returns the deduplicated, canonicalised set of
// identity-bearing header names that must be stripped from every
// inbound request before any handler runs (§5.1 of the auth design).
//
// The returned slice is sorted to make compile output stable across
// runs and to make the audit-friendly value deterministic. Computed
// once at config-load and emitted at the server level by compile.
//
// The strip list is the union of:
//   - every forward_auth identity_headers value across all routes
//     (presets resolve into the same slot)
//   - every forward_claims target header across all jwt and
//     opaque_token blocks
//
// Standard auth headers (Authorization, Cookie, WWW-Authenticate,
// Proxy-Authorization) are explicitly NOT in the strip list — they
// belong to the client.
func AuthIdentityStripList(resolved []Resolved) []string {
	seen := map[string]struct{}{}
	for _, r := range resolved {
		if r.Auth == nil {
			continue
		}
		if r.Auth.ForwardAuth != nil {
			for _, h := range r.Auth.ForwardAuth.IdentityHeaders {
				seen[http.CanonicalHeaderKey(h)] = struct{}{}
			}
		}
		if r.Auth.JWT != nil {
			for _, h := range r.Auth.JWT.ForwardClaims {
				seen[http.CanonicalHeaderKey(h)] = struct{}{}
			}
		}
		if r.Auth.OpaqueToken != nil {
			for _, h := range r.Auth.OpaqueToken.ForwardClaims {
				seen[http.CanonicalHeaderKey(h)] = struct{}{}
			}
		}
	}
	out := make([]string, 0, len(seen))
	for h := range seen {
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}

func canonicalHeaderMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = http.CanonicalHeaderKey(v)
	}
	return out
}

func coalesceString(s, fallback string) string {
	if s != "" {
		return s
	}
	return fallback
}
