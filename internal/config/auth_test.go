package config

import (
	"strings"
	"testing"
	"time"
)

// TestAuthForwardAuthValidPresets exercises every blessed preset name
// through Load (parse → defaults → validate). The body is intentionally
// minimal — just preset and endpoint — to assert that the preset alone
// is enough.
func TestAuthForwardAuthValidPresets(t *testing.T) {
	for _, preset := range []string{"oauth2-proxy", "authelia", "authentik", "tinyauth"} {
		preset := preset
		t.Run(preset, func(t *testing.T) {
			yaml := `
version: v1alpha1
routes:
  - id: api
    upstream: http://app:8000
    auth:
      forward_auth:
        preset: ` + preset + `
        endpoint: http://sidecar:4180
`
			if _, err := loadYAMLErr(yaml); err != nil {
				t.Fatalf("preset %s: load failed: %v", preset, err)
			}
		})
	}
}

func TestAuthForwardAuthInvalidPreset(t *testing.T) {
	yaml := `
version: v1alpha1
routes:
  - id: api
    upstream: http://app:8000
    auth:
      forward_auth:
        preset: bogus
        endpoint: http://sidecar:4180
`
	_, err := loadYAMLErr(yaml)
	if err == nil {
		t.Fatal("expected error for unknown preset")
	}
	if !strings.Contains(err.Error(), `preset "bogus"`) {
		t.Errorf("error did not name the preset: %v", err)
	}
}

func TestAuthForwardAuthMissingEndpoint(t *testing.T) {
	yaml := `
version: v1alpha1
routes:
  - id: api
    upstream: http://app:8000
    auth:
      forward_auth:
        preset: oauth2-proxy
`
	_, err := loadYAMLErr(yaml)
	if err == nil || !strings.Contains(err.Error(), "endpoint is required") {
		t.Errorf("expected endpoint-required error, got: %v", err)
	}
}

func TestAuthForwardAuthCustomRequiresAllOverrides(t *testing.T) {
	yaml := `
version: v1alpha1
routes:
  - id: api
    upstream: http://app:8000
    auth:
      forward_auth:
        preset: custom
        endpoint: http://sidecar:4180
`
	_, err := loadYAMLErr(yaml)
	if err == nil {
		t.Fatal("expected error for missing custom-preset overrides")
	}
	for _, want := range []string{"verify_endpoint", "signin_redirect", "sidecar_paths", "identity_headers"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error did not mention %q: %v", want, err)
		}
	}
}

func TestAuthForwardAuthCustomComplete(t *testing.T) {
	yaml := `
version: v1alpha1
routes:
  - id: api
    upstream: http://app:8000
    auth:
      forward_auth:
        preset: custom
        endpoint: http://sidecar:4180
        verify_endpoint: /verify
        signin_redirect: ""
        sidecar_paths: []
        identity_headers: [X-User]
`
	c, err := loadYAMLErr(yaml)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	resolved, err := Resolve(c)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	fa := resolved[0].Auth.ForwardAuth
	if fa.VerifyEndpoint != "/verify" {
		t.Errorf("verify_endpoint = %q", fa.VerifyEndpoint)
	}
	if fa.SigninRedirect != "" {
		t.Errorf("signin_redirect = %q, want empty", fa.SigninRedirect)
	}
	if len(fa.SidecarPaths) != 0 {
		t.Errorf("sidecar_paths = %v, want empty slice", fa.SidecarPaths)
	}
	if len(fa.IdentityHeaders) != 1 || fa.IdentityHeaders[0] != "X-User" {
		t.Errorf("identity_headers = %v", fa.IdentityHeaders)
	}
}

func TestAuthForwardAuthRejectsReservedField(t *testing.T) {
	// strict-mode YAML decoding rejects unknown fields, which is how
	// reserved names like provider/mode/options stop reaching the
	// validator. Each reserved name should fail at parse time.
	for _, name := range []string{"overrides", "options", "extra", "provider", "auth_options"} {
		name := name
		t.Run(name, func(t *testing.T) {
			yaml := `
version: v1alpha1
routes:
  - id: api
    upstream: http://app:8000
    auth:
      forward_auth:
        preset: oauth2-proxy
        endpoint: http://sidecar:4180
        ` + name + `: foo
`
			if _, err := loadYAMLErr(yaml); err == nil {
				t.Errorf("expected strict-mode decode error for reserved field %q", name)
			}
		})
	}
}

func TestAuthForwardAuthEmptySidecarPathsExplicit(t *testing.T) {
	// An explicit empty list is a deliberate override that suppresses
	// the preset's default — verified by checking the resolved value.
	yaml := `
version: v1alpha1
routes:
  - id: api
    upstream: http://app:8000
    auth:
      forward_auth:
        preset: oauth2-proxy
        endpoint: http://sidecar:4180
        sidecar_paths: []
`
	c, err := loadYAMLErr(yaml)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	resolved, err := Resolve(c)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got := resolved[0].Auth.ForwardAuth.SidecarPaths; len(got) != 0 {
		t.Errorf("sidecar_paths after explicit empty = %v; want empty", got)
	}
}

func TestAuthForwardAuthEmptySigninRedirectExplicit(t *testing.T) {
	yaml := `
version: v1alpha1
routes:
  - id: api
    upstream: http://app:8000
    auth:
      forward_auth:
        preset: oauth2-proxy
        endpoint: http://sidecar:4180
        signin_redirect: ""
`
	c, err := loadYAMLErr(yaml)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	resolved, err := Resolve(c)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got := resolved[0].Auth.ForwardAuth.SigninRedirect; got != "" {
		t.Errorf("signin_redirect after explicit empty = %q; want empty", got)
	}
}

func TestAuthForwardAuthAutheliaPresetDefaults(t *testing.T) {
	yaml := `
version: v1alpha1
routes:
  - id: api
    upstream: http://app:8000
    auth:
      forward_auth:
        preset: authelia
        endpoint: http://authelia:9091
`
	c, err := loadYAMLErr(yaml)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	resolved, err := Resolve(c)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	fa := resolved[0].Auth.ForwardAuth
	if fa.VerifyEndpoint != "/api/authz/forward-auth" {
		t.Errorf("Authelia VerifyEndpoint = %q", fa.VerifyEndpoint)
	}
	if fa.SigninRedirect != "" {
		t.Errorf("Authelia SigninRedirect = %q; want empty (sidecar emits Location)", fa.SigninRedirect)
	}
}

func TestAuthMutualExclusion(t *testing.T) {
	yaml := `
version: v1alpha1
routes:
  - id: api
    upstream: http://app:8000
    auth:
      forward_auth:
        preset: oauth2-proxy
        endpoint: http://sidecar:4180
      jwt:
        jwks_url: https://idp.example.com/.well-known/jwks.json
        issuer: https://idp.example.com
        audience: api
`
	_, err := loadYAMLErr(yaml)
	if err == nil {
		t.Fatal("expected mutual-exclusion error")
	}
	if !strings.Contains(err.Error(), "Exactly one of forward_auth, jwt, opaque_token") {
		t.Errorf("missing mutual-exclusion message in: %v", err)
	}
}

func TestAuthJWTValidMinimal(t *testing.T) {
	yaml := `
version: v1alpha1
routes:
  - id: api
    upstream: http://app:8000
    auth:
      jwt:
        jwks_url: https://idp.example.com/jwks
        issuer: https://idp.example.com
        audience: api.example.com
`
	c, err := loadYAMLErr(yaml)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	resolved, err := Resolve(c)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	j := resolved[0].Auth.JWT
	if j == nil {
		t.Fatal("resolved JWT was nil")
	}
	if len(j.Algorithms) != 1 || j.Algorithms[0] != "RS256" {
		t.Errorf("default algorithms = %v; want [RS256]", j.Algorithms)
	}
	if j.JWKSRefreshInterval != time.Hour {
		t.Errorf("default refresh = %s", j.JWKSRefreshInterval)
	}
	if j.ClockSkew != 30*time.Second {
		t.Errorf("default clock_skew = %s", j.ClockSkew)
	}
	if j.TokenSource != "header" || j.HeaderName != "Authorization" {
		t.Errorf("token_source/header defaults = %s/%s", j.TokenSource, j.HeaderName)
	}
	if len(j.Audience) != 1 || j.Audience[0] != "api.example.com" {
		t.Errorf("audience normalisation: %v", j.Audience)
	}
}

func TestAuthJWTAudienceList(t *testing.T) {
	yaml := `
version: v1alpha1
routes:
  - id: api
    upstream: http://app:8000
    auth:
      jwt:
        jwks_url: https://idp.example.com/jwks
        issuer: https://idp.example.com
        audience: [api.example.com, mobile.example.com]
`
	c, err := loadYAMLErr(yaml)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	resolved, err := Resolve(c)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got := resolved[0].Auth.JWT.Audience; len(got) != 2 {
		t.Errorf("audience list = %v", got)
	}
}

func TestAuthJWTRejectsNoneAlgorithm(t *testing.T) {
	for _, alg := range []string{"none", "None", "NONE"} {
		alg := alg
		t.Run(alg, func(t *testing.T) {
			yaml := `
version: v1alpha1
routes:
  - id: api
    upstream: http://app:8000
    auth:
      jwt:
        jwks_url: https://idp.example.com/jwks
        issuer: https://idp.example.com
        audience: api
        algorithms: [RS256, ` + alg + `]
`
			_, err := loadYAMLErr(yaml)
			if err == nil || !strings.Contains(err.Error(), "alg=none") {
				t.Errorf("expected alg=none rejection, got: %v", err)
			}
		})
	}
}

func TestAuthJWTHTTPLoopbackOnly(t *testing.T) {
	cases := []struct {
		name  string
		url   string
		ok    bool
	}{
		{"https remote", "https://idp.example.com/jwks", true},
		{"http localhost", "http://localhost:8080/jwks", true},
		{"http loopback ipv4", "http://127.0.0.1:8080/jwks", true},
		{"http loopback ipv6", "http://[::1]:8080/jwks", true},
		{"http remote rejected", "http://idp.example.com/jwks", false},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			yaml := `
version: v1alpha1
routes:
  - id: api
    upstream: http://app:8000
    auth:
      jwt:
        jwks_url: ` + c.url + `
        issuer: https://idp.example.com
        audience: api
`
			_, err := loadYAMLErr(yaml)
			if c.ok && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if !c.ok && err == nil {
				t.Errorf("expected error for non-loopback http jwks_url")
			}
		})
	}
}

func TestAuthJWTRejectsBadRefreshInterval(t *testing.T) {
	for _, interval := range []string{"30s", "48h"} {
		interval := interval
		t.Run(interval, func(t *testing.T) {
			yaml := `
version: v1alpha1
routes:
  - id: api
    upstream: http://app:8000
    auth:
      jwt:
        jwks_url: https://idp.example.com/jwks
        issuer: https://idp.example.com
        audience: api
        jwks_refresh_interval: ` + interval + `
`
			if _, err := loadYAMLErr(yaml); err == nil {
				t.Errorf("expected error for refresh_interval=%s", interval)
			}
		})
	}
}

func TestAuthJWTForwardClaims(t *testing.T) {
	yaml := `
version: v1alpha1
routes:
  - id: api
    upstream: http://app:8000
    auth:
      jwt:
        jwks_url: https://idp.example.com/jwks
        issuer: https://idp.example.com
        audience: api
        forward_claims:
          sub: x-jwt-subject
          email: X-JWT-Email
`
	c, err := loadYAMLErr(yaml)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	resolved, err := Resolve(c)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	fc := resolved[0].Auth.JWT.ForwardClaims
	if fc["sub"] != "X-Jwt-Subject" {
		t.Errorf("sub mapping = %q; want canonicalised X-Jwt-Subject", fc["sub"])
	}
	if fc["email"] != "X-Jwt-Email" {
		t.Errorf("email mapping = %q", fc["email"])
	}
}

func TestAuthOpaqueTokenValidMinimal(t *testing.T) {
	t.Setenv("IDP_CLIENT_SECRET", "secret-value")
	yaml := `
version: v1alpha1
routes:
  - id: api
    upstream: http://app:8000
    auth:
      opaque_token:
        introspection_endpoint: https://idp.example.com/introspect
        client_id: barbacana
        client_secret_env: IDP_CLIENT_SECRET
`
	c, err := loadYAMLErr(yaml)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	resolved, err := Resolve(c)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	o := resolved[0].Auth.OpaqueToken
	if o == nil {
		t.Fatal("resolved OpaqueToken was nil")
	}
	if o.CacheTTL != 5*time.Minute {
		t.Errorf("default cache_ttl = %s", o.CacheTTL)
	}
	if o.CacheMaxSize != 10000 {
		t.Errorf("default cache_max_size = %d", o.CacheMaxSize)
	}
}

func TestAuthOpaqueTokenMissingEnv(t *testing.T) {
	yaml := `
version: v1alpha1
routes:
  - id: api
    upstream: http://app:8000
    auth:
      opaque_token:
        introspection_endpoint: https://idp.example.com/introspect
        client_id: barbacana
        client_secret_env: NOT_SET_FOR_THIS_TEST_DEF45612
`
	_, err := loadYAMLErr(yaml)
	if err == nil || !strings.Contains(err.Error(), "client_secret_env") {
		t.Errorf("expected client_secret_env error, got: %v", err)
	}
}

func TestAuthOpaqueTokenHTTPLoopbackOnly(t *testing.T) {
	t.Setenv("IDP_CLIENT_SECRET", "x")
	yaml := `
version: v1alpha1
routes:
  - id: api
    upstream: http://app:8000
    auth:
      opaque_token:
        introspection_endpoint: http://idp.example.com/introspect
        client_id: barbacana
        client_secret_env: IDP_CLIENT_SECRET
`
	if _, err := loadYAMLErr(yaml); err == nil {
		t.Error("expected http-non-loopback rejection")
	}
}

func TestAuthOpaqueTokenCacheBounds(t *testing.T) {
	t.Setenv("IDP_CLIENT_SECRET", "x")
	for _, ttl := range []string{"30s", "2h"} {
		ttl := ttl
		t.Run(ttl, func(t *testing.T) {
			yaml := `
version: v1alpha1
routes:
  - id: api
    upstream: http://app:8000
    auth:
      opaque_token:
        introspection_endpoint: https://idp.example.com/introspect
        client_id: barbacana
        client_secret_env: IDP_CLIENT_SECRET
        cache_ttl: ` + ttl + `
`
			if _, err := loadYAMLErr(yaml); err == nil {
				t.Errorf("expected error for cache_ttl=%s", ttl)
			}
		})
	}
}

// TestAuthIdentityStripList verifies the union of forward_auth
// identity_headers and forward_claims targets is computed deterministically
// across the route set. The resulting list is what compile must emit at
// the server level so identity headers from the inbound request are
// stripped before any handler runs.
func TestAuthIdentityStripList(t *testing.T) {
	t.Setenv("IDP_CLIENT_SECRET", "x")
	yaml := `
version: v1alpha1
routes:
  - id: web
    upstream: http://app:8000
    auth:
      forward_auth:
        preset: oauth2-proxy
        endpoint: http://sidecar:4180
  - id: api
    upstream: http://app:8000
    match:
      paths: ["/api/*"]
    auth:
      jwt:
        jwks_url: https://idp.example.com/jwks
        issuer: https://idp.example.com
        audience: api
        forward_claims:
          sub: X-JWT-Subject
          email: X-JWT-Email
  - id: svc
    upstream: http://app:8000
    match:
      paths: ["/svc/*"]
    auth:
      opaque_token:
        introspection_endpoint: https://idp.example.com/introspect
        client_id: barbacana
        client_secret_env: IDP_CLIENT_SECRET
        forward_claims:
          username: X-User-Subject
  - id: public
    upstream: http://app:8000
    match:
      paths: ["/public/*"]
`
	c, err := loadYAMLErr(yaml)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	resolved, err := Resolve(c)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	got := AuthIdentityStripList(resolved)
	want := []string{
		"X-Auth-Request-Access-Token",
		"X-Auth-Request-Email",
		"X-Auth-Request-Groups",
		"X-Auth-Request-Preferred-Username",
		"X-Auth-Request-User",
		"X-Jwt-Email",
		"X-Jwt-Subject",
		"X-User-Subject",
	}
	if len(got) != len(want) {
		t.Fatalf("strip list = %v; want %v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("strip list[%d] = %q; want %q", i, got[i], want[i])
		}
	}
}

// TestAuthMechanism verifies the Mechanism() helper used by metrics
// and audit log labels.
func TestAuthMechanism(t *testing.T) {
	cases := []struct {
		name string
		auth *ResolvedAuth
		want string
	}{
		{"nil", nil, ""},
		{"empty", &ResolvedAuth{}, ""},
		{"forward_auth", &ResolvedAuth{ForwardAuth: &ResolvedForwardAuth{}}, "forward_auth"},
		{"jwt", &ResolvedAuth{JWT: &ResolvedJWT{}}, "jwt"},
		{"opaque_token", &ResolvedAuth{OpaqueToken: &ResolvedOpaqueToken{}}, "opaque_token"},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			if got := c.auth.Mechanism(); got != c.want {
				t.Errorf("Mechanism = %q; want %q", got, c.want)
			}
		})
	}
}

// TestAuthPresetsAreCovered guards against accidental preset deletions.
// The catalog of blessed presets is part of the public contract; an
// unintended rename or removal here is a breaking change.
func TestAuthPresetsAreCovered(t *testing.T) {
	want := []string{"oauth2-proxy", "authelia", "authentik", "tinyauth", "custom"}
	for _, p := range want {
		if _, ok := ForwardAuthPresets[p]; !ok {
			t.Errorf("preset %q missing from ForwardAuthPresets", p)
		}
	}
	if len(ForwardAuthPresets) != len(want) {
		t.Errorf("ForwardAuthPresets has %d entries, want %d", len(ForwardAuthPresets), len(want))
	}
}

// TestAuthPresetValues pins the full ForwardAuthPresetConfig for every
// blessed preset. These values are the public contract — silently
// changing verify_endpoint or sidecar_paths breaks every user's config
// in a way that's painful to debug. A change here is a deliberate
// schema-version bump.
func TestAuthPresetValues(t *testing.T) {
	cases := []struct {
		preset string
		want   ForwardAuthPresetConfig
	}{
		{
			preset: "oauth2-proxy",
			want: ForwardAuthPresetConfig{
				VerifyEndpoint: "/oauth2/auth",
				SigninRedirect: "/oauth2/start?rd={rd}",
				SidecarPaths:   []string{"/oauth2/*"},
				IdentityHeaders: []string{
					"X-Auth-Request-User",
					"X-Auth-Request-Email",
					"X-Auth-Request-Groups",
					"X-Auth-Request-Preferred-Username",
					"X-Auth-Request-Access-Token",
				},
			},
		},
		{
			preset: "authelia",
			want: ForwardAuthPresetConfig{
				VerifyEndpoint: "/api/authz/forward-auth",
				SigninRedirect: "",
				SidecarPaths:   []string{},
				IdentityHeaders: []string{
					"Remote-User",
					"Remote-Groups",
					"Remote-Email",
					"Remote-Name",
				},
			},
		},
		{
			preset: "authentik",
			want: ForwardAuthPresetConfig{
				VerifyEndpoint: "/outpost.goauthentik.io/auth/caddy",
				SigninRedirect: "/outpost.goauthentik.io/start?rd={rd}",
				SidecarPaths:   []string{"/outpost.goauthentik.io/*"},
				IdentityHeaders: []string{
					"X-authentik-username",
					"X-authentik-groups",
					"X-authentik-email",
					"X-authentik-name",
					"X-authentik-uid",
					"X-authentik-jwt",
					"X-authentik-entitlements",
				},
			},
		},
		{
			preset: "tinyauth",
			want: ForwardAuthPresetConfig{
				VerifyEndpoint: "/api/auth/caddy",
				SigninRedirect: "",
				SidecarPaths:   []string{},
				IdentityHeaders: []string{
					"Remote-User",
					"Remote-Email",
					"Remote-Name",
				},
			},
		},
		{
			preset: "custom",
			want:   ForwardAuthPresetConfig{},
		},
	}
	for _, c := range cases {
		c := c
		t.Run(c.preset, func(t *testing.T) {
			got, ok := ForwardAuthPresets[c.preset]
			if !ok {
				t.Fatalf("preset %q missing", c.preset)
			}
			if got.VerifyEndpoint != c.want.VerifyEndpoint {
				t.Errorf("VerifyEndpoint = %q; want %q", got.VerifyEndpoint, c.want.VerifyEndpoint)
			}
			if got.SigninRedirect != c.want.SigninRedirect {
				t.Errorf("SigninRedirect = %q; want %q", got.SigninRedirect, c.want.SigninRedirect)
			}
			if !equalStringSlices(got.SidecarPaths, c.want.SidecarPaths) {
				t.Errorf("SidecarPaths = %v; want %v", got.SidecarPaths, c.want.SidecarPaths)
			}
			if !equalStringSlices(got.IdentityHeaders, c.want.IdentityHeaders) {
				t.Errorf("IdentityHeaders = %v; want %v", got.IdentityHeaders, c.want.IdentityHeaders)
			}
		})
	}
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestAuthMutualExclusionAllPairs covers every two-mechanism combination.
// Catching only one pair and assuming the rule generalises is exactly
// the kind of test gap that ships broken config validators.
func TestAuthMutualExclusionAllPairs(t *testing.T) {
	t.Setenv("IDP_CLIENT_SECRET", "x")
	authBlock := map[string]string{
		"forward_auth": `      forward_auth:
        preset: oauth2-proxy
        endpoint: http://sidecar:4180
`,
		"jwt": `      jwt:
        jwks_url: https://idp.example.com/jwks
        issuer: https://idp.example.com
        audience: api
`,
		"opaque_token": `      opaque_token:
        introspection_endpoint: https://idp.example.com/introspect
        client_id: barbacana
        client_secret_env: IDP_CLIENT_SECRET
`,
	}
	pairs := [][2]string{
		{"forward_auth", "jwt"},
		{"forward_auth", "opaque_token"},
		{"jwt", "opaque_token"},
	}
	for _, p := range pairs {
		p := p
		t.Run(p[0]+"+"+p[1], func(t *testing.T) {
			yaml := `
version: v1alpha1
routes:
  - id: api
    upstream: http://app:8000
    auth:
` + authBlock[p[0]] + authBlock[p[1]]
			_, err := loadYAMLErr(yaml)
			if err == nil {
				t.Fatal("expected mutual-exclusion error")
			}
			if !strings.Contains(err.Error(), "Exactly one of forward_auth, jwt, opaque_token") {
				t.Errorf("missing mutual-exclusion message in: %v", err)
			}
		})
	}
}

// TestAuthJWTAudienceEdgeCases covers every shape of the audience union
// type. The shape carries credential-scope semantics — getting the
// "empty value rejected" cases wrong allows tokens with empty aud claims
// through.
func TestAuthJWTAudienceEdgeCases(t *testing.T) {
	cases := []struct {
		name      string
		audYAML   string
		shouldErr bool
		wantValue []string // when ok, the resolved Audience value
	}{
		{"string scalar", `audience: "https://api.example.com"`, false, []string{"https://api.example.com"}},
		{"list of one", `audience: ["https://api.example.com"]`, false, []string{"https://api.example.com"}},
		{"list of many", `audience: ["a", "b"]`, false, []string{"a", "b"}},
		{"empty list", `audience: []`, true, nil},
		{"empty string", `audience: ""`, true, nil},
		{"list with empty entry", `audience: ["valid", ""]`, true, nil},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			yaml := `
version: v1alpha1
routes:
  - id: api
    upstream: http://app:8000
    auth:
      jwt:
        jwks_url: https://idp.example.com/jwks
        issuer: https://idp.example.com
        ` + c.audYAML + "\n"
			cfg, err := loadYAMLErr(yaml)
			if c.shouldErr {
				if err == nil {
					t.Errorf("expected error for case %q", c.name)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			resolved, err := Resolve(cfg)
			if err != nil {
				t.Fatalf("resolve: %v", err)
			}
			got := resolved[0].Auth.JWT.Audience
			if !equalStringSlices(got, c.wantValue) {
				t.Errorf("Audience = %v; want %v", got, c.wantValue)
			}
		})
	}
}

// TestAuthLoopbackHTTPNonLoopbackRejected covers the URLs operators
// commonly try in dev — RFC 1918 ranges and cluster-internal hostnames —
// and confirms they get a clear error message that explicitly names what
// counts as loopback.
func TestAuthLoopbackHTTPNonLoopbackRejected(t *testing.T) {
	t.Setenv("IDP_CLIENT_SECRET", "x")
	negatives := []struct {
		name string
		host string // host portion only, http:// is prepended
	}{
		{"rfc1918 10.x", "10.0.0.5"},
		{"rfc1918 192.168.x", "192.168.1.10"},
		{"cluster.local hostname", "internal.cluster.local"},
		{"public hostname over http", "idp.example.com"},
	}
	for _, n := range negatives {
		n := n
		t.Run("jwks_url/"+n.name, func(t *testing.T) {
			yaml := `
version: v1alpha1
routes:
  - id: api
    upstream: http://app:8000
    auth:
      jwt:
        jwks_url: http://` + n.host + `/jwks
        issuer: https://idp.example.com
        audience: api
`
			_, err := loadYAMLErr(yaml)
			if err == nil {
				t.Fatalf("expected loopback rejection for %q", n.host)
			}
			if !strings.Contains(err.Error(), "loopback") {
				t.Errorf("error did not mention loopback: %v", err)
			}
			if !strings.Contains(err.Error(), "localhost, 127.0.0.1, ::1") {
				t.Errorf("error did not list the named loopback hosts: %v", err)
			}
		})
		t.Run("introspection_endpoint/"+n.name, func(t *testing.T) {
			yaml := `
version: v1alpha1
routes:
  - id: api
    upstream: http://app:8000
    auth:
      opaque_token:
        introspection_endpoint: http://` + n.host + `/introspect
        client_id: barbacana
        client_secret_env: IDP_CLIENT_SECRET
`
			_, err := loadYAMLErr(yaml)
			if err == nil {
				t.Fatalf("expected loopback rejection for %q", n.host)
			}
			if !strings.Contains(err.Error(), "loopback") {
				t.Errorf("error did not mention loopback: %v", err)
			}
		})
	}
}

// TestAuthForwardAuthEndpointMissingVsMalformed ensures the operator
// gets a different message for an empty endpoint (the field needs to
// be filled in) vs a malformed value (the value is wrong).
func TestAuthForwardAuthEndpointMissingVsMalformed(t *testing.T) {
	cases := []struct {
		name        string
		endpointVal string
		want        string
	}{
		{"missing", "", "endpoint is required"},
		{"missing scheme", "sidecar:4180", "endpoint must be a valid http or https URL"},
		{"ftp scheme", "ftp://sidecar/", "endpoint must be a valid http or https URL"},
		{"no host", "http://", "endpoint must be a valid http or https URL"},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			yaml := `
version: v1alpha1
routes:
  - id: api
    upstream: http://app:8000
    auth:
      forward_auth:
        preset: oauth2-proxy
`
			if c.endpointVal != "" {
				yaml += "        endpoint: " + c.endpointVal + "\n"
			}
			_, err := loadYAMLErr(yaml)
			if err == nil {
				t.Fatalf("expected error for %s", c.name)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("error %v\ndid not contain %q", err, c.want)
			}
		})
	}
}

// TestAuthJWTAlgorithmRejections covers the alg=none footgun across
// case variants and the explicit-empty-list variant. Default
// (algorithms unset) falls through to [RS256] and is exercised by
// TestAuthJWTValidMinimal.
func TestAuthJWTAlgorithmRejections(t *testing.T) {
	t.Run("none variants", func(t *testing.T) {
		// alg-name case sensitivity is the IdP's problem at runtime;
		// at config time we want to catch operator typos in any case.
		for _, variant := range []string{"none", "None", "NONE", "nOnE", "NoNe"} {
			variant := variant
			t.Run(variant, func(t *testing.T) {
				yaml := `
version: v1alpha1
routes:
  - id: api
    upstream: http://app:8000
    auth:
      jwt:
        jwks_url: https://idp.example.com/jwks
        issuer: https://idp.example.com
        audience: api
        algorithms: [RS256, ` + variant + `]
`
				_, err := loadYAMLErr(yaml)
				if err == nil || !strings.Contains(err.Error(), "alg=none") {
					t.Errorf("expected alg=none rejection for variant %q, got: %v", variant, err)
				}
			})
		}
	})
	t.Run("explicit empty list", func(t *testing.T) {
		yaml := `
version: v1alpha1
routes:
  - id: api
    upstream: http://app:8000
    auth:
      jwt:
        jwks_url: https://idp.example.com/jwks
        issuer: https://idp.example.com
        audience: api
        algorithms: []
`
		_, err := loadYAMLErr(yaml)
		if err == nil || !strings.Contains(err.Error(), "explicit empty list") {
			t.Errorf("expected explicit-empty-list rejection, got: %v", err)
		}
	})
	t.Run("absent uses default", func(t *testing.T) {
		// Confirm the no-algorithms case is distinct from the explicit-
		// empty case: it must succeed and resolve to [RS256].
		yaml := `
version: v1alpha1
routes:
  - id: api
    upstream: http://app:8000
    auth:
      jwt:
        jwks_url: https://idp.example.com/jwks
        issuer: https://idp.example.com
        audience: api
`
		c, err := loadYAMLErr(yaml)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		resolved, err := Resolve(c)
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
		if got := resolved[0].Auth.JWT.Algorithms; !equalStringSlices(got, []string{"RS256"}) {
			t.Errorf("default algorithms = %v; want [RS256]", got)
		}
	})
}

// TestAuthIdentityStripListDeterministic verifies that the same set of
// routes — fed in different orders — produces a byte-identical strip
// list. This matters for hot-reload: Caddy diffs config blobs to decide
// what to rebuild, and a non-deterministic strip list would force every
// reload to rebuild every server.
func TestAuthIdentityStripListDeterministic(t *testing.T) {
	t.Setenv("IDP_CLIENT_SECRET", "x")
	yamls := []string{
		// Order A
		`
version: v1alpha1
routes:
  - id: a
    upstream: http://app:8000
    match: { paths: ["/a/*"] }
    auth:
      forward_auth: { preset: oauth2-proxy, endpoint: http://sidecar:4180 }
  - id: b
    upstream: http://app:8000
    match: { paths: ["/b/*"] }
    auth:
      jwt:
        jwks_url: https://idp.example.com/jwks
        issuer: https://idp.example.com
        audience: api
        forward_claims: { sub: X-JWT-Subject }
  - id: c
    upstream: http://app:8000
    match: { paths: ["/c/*"] }
    auth:
      opaque_token:
        introspection_endpoint: https://idp.example.com/introspect
        client_id: barbacana
        client_secret_env: IDP_CLIENT_SECRET
        forward_claims: { username: X-User-Subject }
`,
		// Order B (c, a, b)
		`
version: v1alpha1
routes:
  - id: c
    upstream: http://app:8000
    match: { paths: ["/c/*"] }
    auth:
      opaque_token:
        introspection_endpoint: https://idp.example.com/introspect
        client_id: barbacana
        client_secret_env: IDP_CLIENT_SECRET
        forward_claims: { username: X-User-Subject }
  - id: a
    upstream: http://app:8000
    match: { paths: ["/a/*"] }
    auth:
      forward_auth: { preset: oauth2-proxy, endpoint: http://sidecar:4180 }
  - id: b
    upstream: http://app:8000
    match: { paths: ["/b/*"] }
    auth:
      jwt:
        jwks_url: https://idp.example.com/jwks
        issuer: https://idp.example.com
        audience: api
        forward_claims: { sub: X-JWT-Subject }
`,
	}
	var firstStripList []string
	for i, y := range yamls {
		c, err := loadYAMLErr(y)
		if err != nil {
			t.Fatalf("yaml %d load: %v", i, err)
		}
		resolved, err := Resolve(c)
		if err != nil {
			t.Fatalf("yaml %d resolve: %v", i, err)
		}
		got := AuthIdentityStripList(resolved)
		if i == 0 {
			firstStripList = got
			continue
		}
		if !equalStringSlices(got, firstStripList) {
			t.Errorf("strip list order-dependent: yaml %d = %v, yaml 0 = %v", i, got, firstStripList)
		}
	}
}

// TestAuthIdentityStripListCollisions verifies the union dedupes
// correctly when different routes / different mechanisms target the
// same upstream header name.
func TestAuthIdentityStripListCollisions(t *testing.T) {
	t.Setenv("IDP_CLIENT_SECRET", "x")
	yaml := `
version: v1alpha1
routes:
  - id: jwt-route
    upstream: http://app:8000
    match: { paths: ["/jwt/*"] }
    auth:
      jwt:
        jwks_url: https://idp.example.com/jwks
        issuer: https://idp.example.com
        audience: api
        forward_claims:
          sub: X-User-Id          # same header from different claim
          email: X-User-Id        # same upstream header
  - id: opaque-route
    upstream: http://app:8000
    match: { paths: ["/svc/*"] }
    auth:
      opaque_token:
        introspection_endpoint: https://idp.example.com/introspect
        client_id: barbacana
        client_secret_env: IDP_CLIENT_SECRET
        forward_claims:
          username: X-User-Id     # cross-mechanism collision
`
	c, err := loadYAMLErr(yaml)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	resolved, err := Resolve(c)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	got := AuthIdentityStripList(resolved)
	want := []string{"X-User-Id"}
	if !equalStringSlices(got, want) {
		t.Errorf("strip list with collisions = %v; want %v (single deduplicated entry)", got, want)
	}
}

// TestAuthJWTAudienceIsSlice asserts the resolved audience is always
// a []string, never a sum type — downstream consumers should not have
// to switch on the type when they iterate audiences.
func TestAuthJWTAudienceIsSlice(t *testing.T) {
	yaml := `
version: v1alpha1
routes:
  - id: api
    upstream: http://app:8000
    auth:
      jwt:
        jwks_url: https://idp.example.com/jwks
        issuer: https://idp.example.com
        audience: single-string
`
	c, err := loadYAMLErr(yaml)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	resolved, err := Resolve(c)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	// Compile-time check: the type assertion below would fail to
	// compile if Audience were a union type. Runtime: must be a
	// non-empty []string with the scalar normalised into a single
	// element.
	var aud []string = resolved[0].Auth.JWT.Audience
	if len(aud) != 1 || aud[0] != "single-string" {
		t.Errorf("Audience = %v; want []string{\"single-string\"}", aud)
	}
}
