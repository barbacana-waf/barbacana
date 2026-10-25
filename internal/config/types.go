// Package config owns the YAML schema, defaulting, validation, and the
// compilation step that turns a Config into the JSON Caddy consumes.
package config

import (
	"fmt"
	"text/template"
	"time"

	"github.com/barbacana-waf/barbacana/internal/ratelimit"
	"gopkg.in/yaml.v3"
)

// Request-handling mode. ModeBlocking is the default (principle 11);
// ModeDetect is the opt-in escape hatch used to tune a route without
// breaking traffic — the wire value "detect_only" is explicit that
// malicious requests are observed but not blocked.
const (
	ModeBlocking = "blocking"
	ModeDetect   = "detect_only"
)

type Config struct {
	Version     string     `yaml:"version"`
	Hosts       HostList   `yaml:"host"`
	Port        int        `yaml:"port"`
	DataDir     string     `yaml:"data_dir"`
	MetricsPort int        `yaml:"metrics_port"`
	HealthPort  int        `yaml:"health_port"`
	RoutesDir   string     `yaml:"routes_dir"`
	Global      Global     `yaml:"global"`
	Tracing     TracingCfg `yaml:"tracing"`
	AuditLog    AuditCfg   `yaml:"audit_log"`
	Routes      []Route    `yaml:"routes"`
}

// HostList is the YAML type for the top-level `host` key (deployment
// Mode 1, auto-TLS). It accepts either a single hostname —
// `host: example.com` — or a list of hostnames —
// `host: [example.com, example.io]`. All routes serve every listed
// hostname; Caddy provisions one certificate per hostname.
//
// A bare empty scalar (`host: ""` or the key omitted) unmarshals to a
// nil list, preserving the existing "empty string means unset" signal
// consumed by applyDefaults and validateDeploymentMode. An explicitly
// empty sequence (`host: []`) is rejected — silently falling back to
// plain-HTTP mode 3 would be a security surprise for an operator who
// meant to list hostnames.
type HostList []string

func (h *HostList) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.ScalarNode:
		var s string
		if err := node.Decode(&s); err != nil {
			return fmt.Errorf("host: %w", err)
		}
		if s == "" {
			*h = nil
			return nil
		}
		*h = HostList{s}
		return nil
	case yaml.SequenceNode:
		var list []string
		if err := node.Decode(&list); err != nil {
			return fmt.Errorf("host: %w", err)
		}
		if len(list) == 0 {
			return fmt.Errorf(`host: must contain at least one hostname — remove "host" entirely (or use "port") for plain HTTP`)
		}
		*h = HostList(list)
		return nil
	default:
		return fmt.Errorf("host: must be a hostname string or a list of hostname strings, got %s", nodeKindName(node.Kind))
	}
}

// nodeKindName renders a yaml.Node.Kind as a short human-readable label
// for error messages.
func nodeKindName(k yaml.Kind) string {
	switch k {
	case yaml.MappingNode:
		return "a mapping"
	case yaml.AliasNode:
		return "an alias"
	case yaml.DocumentNode:
		return "a document"
	default:
		return "an unsupported YAML value"
	}
}

// TracingCfg is the YAML schema for the optional tracing block. Tracing
// is off by default; an absent block or `enabled: false` skips all
// exporter setup. When enabled, fields left unset fall through to the
// matching OTel env vars (OTEL_EXPORTER_OTLP_ENDPOINT, OTEL_SERVICE_NAME,
// ...). YAML wins over env when both are set.
type TracingCfg struct {
	Enabled  bool              `yaml:"enabled"`
	Protocol string            `yaml:"protocol"` // "grpc" (default) or "http"
	Endpoint string            `yaml:"endpoint"`
	Insecure *bool             `yaml:"insecure"` // default true
	Headers  map[string]string `yaml:"headers"`
	Timeout  string            `yaml:"timeout"`

	Service TracingService `yaml:"service"`
}

type TracingService struct {
	Name      string `yaml:"name"`
	Namespace string `yaml:"namespace"`
	Version   string `yaml:"version"`
}

// AuditCfg is the YAML schema for the audit log block. Stdout emission
// is unconditional — there is no off switch. The format field selects
// the wire schema for the unconditional stdout output and is the
// default for any sinks layered on top (sinks are Phase D, not yet
// implemented). Valid values: "ocsf" (default) and "ecs".
type AuditCfg struct {
	Format string `yaml:"format"`
}

type Global struct {
	Mode            string            `yaml:"mode"`
	Disable         []string          `yaml:"disable"`
	Enable          []string          `yaml:"enable"`
	Accept          AcceptCfg         `yaml:"accept"`
	Inspection      InspectionCfg     `yaml:"inspection"`
	Multipart       MultipartCfg      `yaml:"multipart"`
	Protocol        ProtocolCfg       `yaml:"protocol"`
	ResponseHeaders ResponseHeaderCfg `yaml:"response_headers"`
	OpenAPI         OpenAPIGlobal     `yaml:"openapi"`
	RateLimit       *RateLimitCfg     `yaml:"rate_limit,omitempty"`
}

// RateLimitCfg is the raw YAML schema for a rate_limit block. It may appear
// under global: (server-wide default) or under a route: (route-specific).
// A route-level block replaces the global entirely — no field-level merging.
type RateLimitCfg struct {
	Requests int         `yaml:"requests"`
	Window   string      `yaml:"window"`
	Source   SourceCfg   `yaml:"source"`
	Backend  *BackendCfg `yaml:"backend,omitempty"`
}

type SourceCfg struct {
	Type string `yaml:"type"`         // "ip" | "header"
	Key  string `yaml:"key,omitempty"` // required when type == "header"
}

type BackendCfg struct {
	Type    string `yaml:"type"`              // "memory"
	MaxKeys *int   `yaml:"max_keys,omitempty"`
	TTL     string `yaml:"ttl,omitempty"`
}

type AcceptCfg struct {
	Methods           []string `yaml:"methods"`
	ContentTypes      []string `yaml:"content_types"`
	MaxBodySize       string   `yaml:"max_body_size"`
	MaxURLLength      int      `yaml:"max_url_length"`
	MaxHeaderSize     string   `yaml:"max_header_size"`
	MaxHeaderCount    int      `yaml:"max_header_count"`
	RequireHostHeader *bool    `yaml:"require_host_header"`
}

type InspectionCfg struct {
	EvaluationTimeout       string `yaml:"evaluation_timeout"`
	MaxInspectSize          string `yaml:"max_inspect_size"`
	MaxMemoryBuffer         string `yaml:"max_memory_buffer"`
	DecompressionRatioLimit *int   `yaml:"decompression_ratio_limit"`
	JSONDepth               *int   `yaml:"json_depth"`
	JSONKeys                *int   `yaml:"json_keys"`
	XMLDepth                *int   `yaml:"xml_depth"`
	XMLEntities             *int   `yaml:"xml_entities"`
}

type MultipartCfg struct {
	FileLimit       *int     `yaml:"file_limit"`
	FileSize        string   `yaml:"file_size"`
	AllowedTypes    []string `yaml:"allowed_types"`
	DoubleExtension *bool    `yaml:"double_extension"`
}

type ProtocolCfg struct {
	SlowRequestHeaderTimeout   string `yaml:"slow_request_header_timeout"`
	SlowRequestMinRateBPS      *int   `yaml:"slow_request_min_rate_bps"`
	HTTP2MaxConcurrentStreams  *int   `yaml:"http2_max_concurrent_streams"`
	HTTP2MaxContinuationFrames *int   `yaml:"http2_max_continuation_frames"`
	HTTP2MaxDecodedHeaderBytes *int   `yaml:"http2_max_decoded_header_bytes"`
}

type ResponseHeaderCfg struct {
	Inject     map[string]string `yaml:"inject"`
	StripExtra []string          `yaml:"strip_extra"`
}

type OpenAPIGlobal struct {
	ShadowAPILogging *bool `yaml:"shadow_api_logging"`
}

type Route struct {
	ID              string             `yaml:"id"`
	Match           *Match             `yaml:"match,omitempty"`
	Upstream        string             `yaml:"upstream"`
	UpstreamTimeout string             `yaml:"upstream_timeout"`
	Rewrite         *RewriteCfg        `yaml:"rewrite,omitempty"`
	Mode            *string            `yaml:"mode,omitempty"`
	Disable         []string           `yaml:"disable"`
	Enable          []string           `yaml:"enable"`
	Accept          *AcceptCfg         `yaml:"accept,omitempty"`
	Inspection      *InspectionCfg     `yaml:"inspection,omitempty"`
	Multipart       *MultipartCfg      `yaml:"multipart,omitempty"`
	ResponseHeaders *ResponseHeaderCfg `yaml:"response_headers,omitempty"`
	OpenAPI         *OpenAPIRoute      `yaml:"openapi,omitempty"`
	CORS            *CORSCfg           `yaml:"cors,omitempty"`
	ErrorResponse   *ErrorResponseCfg  `yaml:"error_response,omitempty"`
	RateLimit       *RateLimitCfg      `yaml:"rate_limit,omitempty"`
}

type Match struct {
	Hosts []string `yaml:"hosts"`
	Paths []string `yaml:"paths"`
}

type RewriteCfg struct {
	StripPrefix string `yaml:"strip_prefix"`
	AddPrefix   string `yaml:"add_prefix"`
	Path        string `yaml:"path"`
}

type OpenAPIRoute struct {
	Spec    string   `yaml:"spec"`
	Strict  *bool    `yaml:"strict"`
	Disable []string `yaml:"disable"`
}

type CORSCfg struct {
	AllowOrigins     []string `yaml:"allow_origins"`
	AllowMethods     []string `yaml:"allow_methods"`
	AllowHeaders     []string `yaml:"allow_headers"`
	ExposeHeaders    []string `yaml:"expose_headers"`
	AllowCredentials *bool    `yaml:"allow_credentials"`
	MaxAge           *int     `yaml:"max_age"`
}

// ErrorResponseCfg configures the error response body sent to the client
// when a request is blocked. The Body is a Go text/template with only
// {{.RequestID}} and {{.Timestamp}} allowed.
type ErrorResponseCfg struct {
	Body string `yaml:"body"`
}

// Resolved is the route view after merging with the global defaults.
// Pipeline consumers read from Resolved rather than the raw Route — the
// resolver collapses inheritance and pointer fields into explicit values.
type Resolved struct {
	ID               string
	Match            *Match
	Upstream         string
	UpstreamTimeout  time.Duration
	Rewrite          *RewriteCfg
	Mode             string
	Disable          map[string]bool // expanded: categories expand to sub-protections
	Accept           ResolvedAccept
	Inspection       ResolvedInspection
	Multipart        ResolvedMultipart
	Protocol         ResolvedProtocol
	ResponseHeaders  ResolvedHeaders
	OpenAPI          *OpenAPIRoute
	CORS             *CORSCfg
	ShadowAPILogging bool
	ErrorTemplate    *template.Template // compiled custom error response, nil = default JSON
	RateLimit        *ratelimit.Config  // nil = no rate limiting on this route
	// ContentTypeGating reports whether a parser/protection should run.
	// Derived from Accept.ContentTypes.
	RunJSONParser      bool
	RunXMLParser       bool
	RunMultipartParser bool
	RunFormParser      bool
}

type ResolvedAccept struct {
	Methods           []string
	ContentTypes      []string
	MaxBodySize       int64
	MaxURLLength      int
	MaxHeaderSize     int64
	MaxHeaderCount    int
	RequireHostHeader bool
}

type ResolvedInspection struct {
	EvaluationTimeout       time.Duration
	MaxInspectSize          int64
	MaxMemoryBuffer         int64
	DecompressionRatioLimit int
	JSONDepth               int
	JSONKeys                int
	XMLDepth                int
	XMLEntities             int
}

type ResolvedMultipart struct {
	FileLimit       int
	FileSize        int64
	AllowedTypes    []string
	DoubleExtension bool
}

type ResolvedProtocol struct {
	SlowRequestHeaderTimeout   time.Duration
	SlowRequestMinRateBPS      int
	HTTP2MaxConcurrentStreams  int
	HTTP2MaxContinuationFrames int
	HTTP2MaxDecodedHeaderBytes int
}

type ResolvedHeaders struct {
	Inject     map[string]string
	StripExtra []string
}

// ResolvedTracing is the post-defaults view of the tracing block. The
// pipeline never sees pointers — Insecure is collapsed to a bool and
// Timeout is parsed once.
type ResolvedTracing struct {
	Enabled          bool
	Protocol         string
	Endpoint         string
	Insecure         bool
	Headers          map[string]string
	Timeout          time.Duration
	ServiceName      string
	ServiceNamespace string
	ServiceVersion   string
}

// ResolvedAudit is the post-defaults view of the audit_log block.
type ResolvedAudit struct {
	Format string
}

// AuditFormatOCSF and AuditFormatECS are the only valid audit log
// format values. OCSF is the default; ECS is the switchable
// alternative for Elastic stack users.
const (
	AuditFormatOCSF = "ocsf"
	AuditFormatECS  = "ecs"
)
