package config

import "time"

// AuthCfg is the per-route authentication block. At most one of the three
// inner mechanisms may be set; mutual exclusion is enforced by the
// validator. Auth is per-route and never inherited from global config —
// inheriting auth across routes would silently apply credentials checks
// to routes the operator never chose to protect.
type AuthCfg struct {
	ForwardAuth  *ForwardAuthCfg  `yaml:"forward_auth,omitempty"`
	JWT          *JWTCfg          `yaml:"jwt,omitempty"`
	OpaqueToken  *OpaqueTokenCfg  `yaml:"opaque_token,omitempty"`
}

// Forward-auth presets. Adding or renaming a preset is a public-API
// change governed by semver (principle 14).
const (
	ForwardAuthPresetOAuth2Proxy = "oauth2-proxy"
	ForwardAuthPresetAuthelia    = "authelia"
	ForwardAuthPresetAuthentik   = "authentik"
	ForwardAuthPresetTinyauth    = "tinyauth"
	ForwardAuthPresetCustom      = "custom"
)

// ForwardAuthCfg configures browser-session OIDC delegated to a sidecar
// (oauth2-proxy, Authelia, Authentik, tinyauth, or a user-described
// custom sidecar). Optional fields default to the preset's bundled
// values; setting `preset: custom` disables defaults and requires every
// override field to be supplied.
type ForwardAuthCfg struct {
	Preset   string `yaml:"preset"`
	Endpoint string `yaml:"endpoint"`

	VerifyEndpoint  string   `yaml:"verify_endpoint,omitempty"`
	SigninRedirect  *string  `yaml:"signin_redirect,omitempty"`
	SidecarPaths    []string `yaml:"sidecar_paths,omitempty"`
	IdentityHeaders []string `yaml:"identity_headers,omitempty"`

	Timeout string `yaml:"timeout,omitempty"`
}

// JWTCfg validates bearer JWTs in-process against a remote JWKS. JWKS
// is fetched on startup and refreshed in the background; on-demand
// refresh handles unknown-kid cases between scheduled refreshes.
type JWTCfg struct {
	JWKSURL  string   `yaml:"jwks_url"`
	Issuer   string   `yaml:"issuer"`
	Audience Audience `yaml:"audience"`

	Algorithms          []string          `yaml:"algorithms,omitempty"`
	JWKSRefreshInterval string            `yaml:"jwks_refresh_interval,omitempty"`
	ClockSkew           string            `yaml:"clock_skew,omitempty"`
	RequiredClaims      []string          `yaml:"required_claims,omitempty"`
	ForwardClaims       map[string]string `yaml:"forward_claims,omitempty"`
	TokenSource         string            `yaml:"token_source,omitempty"`
	HeaderName          string            `yaml:"header_name,omitempty"`
	QueryParam          string            `yaml:"query_param,omitempty"`
}

// Audience accepts either a single string or a list of strings on the
// wire. Internally it is always stored as a list. Empty list is invalid;
// the validator rejects it.
type Audience struct {
	Values []string
}

// UnmarshalYAML lets the audience field be either a string or a list.
func (a *Audience) UnmarshalYAML(unmarshal func(any) error) error {
	var s string
	if err := unmarshal(&s); err == nil {
		if s != "" {
			a.Values = []string{s}
		}
		return nil
	}
	var list []string
	if err := unmarshal(&list); err != nil {
		return err
	}
	a.Values = list
	return nil
}

// OpaqueTokenCfg configures RFC 7662 introspection-based validation of
// IdP-issued opaque tokens. Positive results are cached per-process
// (see ResolvedOpaqueToken.CacheTTL); negative results are never
// cached.
type OpaqueTokenCfg struct {
	IntrospectionEndpoint string `yaml:"introspection_endpoint"`
	ClientID              string `yaml:"client_id"`
	ClientSecretEnv       string `yaml:"client_secret_env"`

	CacheTTL      string            `yaml:"cache_ttl,omitempty"`
	CacheMaxSize  *int              `yaml:"cache_max_size,omitempty"`
	Timeout       string            `yaml:"timeout,omitempty"`
	ForwardClaims map[string]string `yaml:"forward_claims,omitempty"`
	TokenSource   string            `yaml:"token_source,omitempty"`
	HeaderName    string            `yaml:"header_name,omitempty"`
	QueryParam    string            `yaml:"query_param,omitempty"`
}

// Token-source enum values shared by jwt and opaque_token blocks.
const (
	TokenSourceHeader = "header"
	TokenSourceQuery  = "query"
	TokenSourceBoth   = "both"
)

// Default values used by validate, resolve, and compile. Centralised so
// an audit of the auth defaults is one file read.
const (
	DefaultForwardAuthTimeout      = 2 * time.Second
	DefaultJWTRefreshInterval      = time.Hour
	DefaultJWTClockSkew            = 30 * time.Second
	DefaultJWTAlgorithm            = "RS256"
	DefaultJWTHeaderName           = "Authorization"
	DefaultJWTQueryParam           = "access_token"
	DefaultJWTTokenSource          = TokenSourceHeader
	DefaultOpaqueTokenCacheTTL     = 5 * time.Minute
	DefaultOpaqueTokenCacheMaxSize = 10000
	DefaultOpaqueTokenTimeout      = 2 * time.Second
	DefaultOpaqueTokenHeaderName   = "Authorization"
	DefaultOpaqueTokenQueryParam   = "access_token"
	DefaultOpaqueTokenTokenSource  = TokenSourceHeader

	MinJWKSRefreshInterval     = 5 * time.Minute
	MaxJWKSRefreshInterval     = 24 * time.Hour
	MaxJWTClockSkew            = 5 * time.Minute
	MinOpaqueTokenCacheTTL     = time.Minute
	MaxOpaqueTokenCacheTTL     = time.Hour
	MinOpaqueTokenCacheMaxSize = 100
	MaxOpaqueTokenCacheMaxSize = 1000000
	MaxAuthSubrequestTimeout   = time.Minute
)

// ForwardAuthPresetConfig is the per-preset bundle of defaults
// (verify endpoint, signin-redirect template, sidecar bypass paths,
// identity headers) that resolve fills in when the user does not
// override them. The custom preset has no defaults — all four fields
// must come from user config.
type ForwardAuthPresetConfig struct {
	VerifyEndpoint  string
	SigninRedirect  string
	SidecarPaths    []string
	IdentityHeaders []string
}

// ForwardAuthPresets bundles the blessed sidecar defaults. Verified
// against the upstream documentation linked from the auth design doc;
// regression tests in auth_test.go pin each preset.
var ForwardAuthPresets = map[string]ForwardAuthPresetConfig{
	ForwardAuthPresetOAuth2Proxy: {
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
	ForwardAuthPresetAuthelia: {
		VerifyEndpoint: "/api/authz/forward-auth",
		// Authelia returns a Location header itself; signin redirect
		// stays empty so compile emits copy_response_headers Location
		// rather than a redir directive.
		SigninRedirect: "",
		SidecarPaths:   []string{},
		IdentityHeaders: []string{
			"Remote-User",
			"Remote-Groups",
			"Remote-Email",
			"Remote-Name",
		},
	},
	ForwardAuthPresetAuthentik: {
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
	ForwardAuthPresetTinyauth: {
		VerifyEndpoint: "/api/auth/caddy",
		SigninRedirect: "",
		SidecarPaths:   []string{},
		IdentityHeaders: []string{
			"Remote-User",
			"Remote-Email",
			"Remote-Name",
		},
	},
	ForwardAuthPresetCustom: {
		// No defaults. Validator requires every override to be supplied.
	},
}

// ResolvedAuth is the post-defaults view of a route's auth block.
// Pipeline and compile read from Resolved values, never from the raw
// AuthCfg, so default-merging logic lives in one place.
type ResolvedAuth struct {
	ForwardAuth *ResolvedForwardAuth
	JWT         *ResolvedJWT
	OpaqueToken *ResolvedOpaqueToken
}

// Mechanism returns the canonical name of the configured auth
// mechanism, or "" when the route has no auth. Used in metrics and
// audit log labels.
func (r *ResolvedAuth) Mechanism() string {
	if r == nil {
		return ""
	}
	switch {
	case r.ForwardAuth != nil:
		return "forward_auth"
	case r.JWT != nil:
		return "jwt"
	case r.OpaqueToken != nil:
		return "opaque_token"
	}
	return ""
}

// ResolvedForwardAuth is a forward_auth block with preset defaults
// merged in. The preset name is preserved for metric labels and
// audit-log correlation.
type ResolvedForwardAuth struct {
	Preset          string
	Endpoint        string
	VerifyEndpoint  string
	SigninRedirect  string
	SidecarPaths    []string
	IdentityHeaders []string
	Timeout         time.Duration
}

// ResolvedJWT is a jwt block with optional fields filled in.
// Audience is always a non-empty slice post-validation.
type ResolvedJWT struct {
	JWKSURL             string
	Issuer              string
	Audience            []string
	Algorithms          []string
	JWKSRefreshInterval time.Duration
	ClockSkew           time.Duration
	RequiredClaims      []string
	ForwardClaims       map[string]string
	TokenSource         string
	HeaderName          string
	QueryParam          string
}

// ResolvedOpaqueToken is an opaque_token block with optional fields
// filled in.
type ResolvedOpaqueToken struct {
	IntrospectionEndpoint string
	ClientID              string
	ClientSecretEnv       string
	CacheTTL              time.Duration
	CacheMaxSize          int
	Timeout               time.Duration
	ForwardClaims         map[string]string
	TokenSource           string
	HeaderName            string
	QueryParam            string
}
