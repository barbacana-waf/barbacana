// Package config owns the YAML schema, defaulting, validation, and the
// compilation step that turns a Config into the JSON Caddy consumes.
package config

import (
	"text/template"
	"time"
)

// Request-handling mode. ModeBlocking is the default (principle 11);
// ModeDetect is the opt-in escape hatch used to tune a route without
// breaking traffic.
const (
	ModeBlocking = "blocking"
	ModeDetect   = "detect"
)

type Config struct {
	Version     string  `yaml:"version"`
	Host        string  `yaml:"host"`
	Port        int     `yaml:"port"`
	DataDir     string  `yaml:"data_dir"`
	MetricsPort int     `yaml:"metrics_port"`
	HealthPort  int     `yaml:"health_port"`
	RoutesDir   string  `yaml:"routes_dir"`
	Global      Global  `yaml:"global"`
	Routes      []Route `yaml:"routes"`
}

type Global struct {
	Mode            string            `yaml:"mode"`
	Disable         []string          `yaml:"disable"`
	Accept          AcceptCfg         `yaml:"accept"`
	Inspection      InspectionCfg     `yaml:"inspection"`
	Multipart       MultipartCfg      `yaml:"multipart"`
	Protocol        ProtocolCfg       `yaml:"protocol"`
	ResponseHeaders ResponseHeaderCfg `yaml:"response_headers"`
	OpenAPI         OpenAPIGlobal     `yaml:"openapi"`
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
	Sensitivity             *int    `yaml:"sensitivity"`
	AnomalyThreshold        *int    `yaml:"anomaly_threshold"`
	EvaluationTimeout       string  `yaml:"evaluation_timeout"`
	MaxInspectSize          string  `yaml:"max_inspect_size"`
	MaxMemoryBuffer         string  `yaml:"max_memory_buffer"`
	DecompressionRatioLimit *int    `yaml:"decompression_ratio_limit"`
	JSONDepth               *int    `yaml:"json_depth"`
	JSONKeys                *int    `yaml:"json_keys"`
	XMLDepth                *int    `yaml:"xml_depth"`
	XMLEntities             *int    `yaml:"xml_entities"`
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
	ParameterPollution         string `yaml:"parameter_pollution"`
}

type ResponseHeaderCfg struct {
	Preset     string            `yaml:"preset"`
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
	Accept          *AcceptCfg         `yaml:"accept,omitempty"`
	Inspection      *InspectionCfg     `yaml:"inspection,omitempty"`
	Multipart       *MultipartCfg      `yaml:"multipart,omitempty"`
	Protocol        *ProtocolCfg       `yaml:"protocol,omitempty"`
	ResponseHeaders *ResponseHeaderCfg `yaml:"response_headers,omitempty"`
	OpenAPI         *OpenAPIRoute      `yaml:"openapi,omitempty"`
	CORS            *CORSCfg           `yaml:"cors,omitempty"`
	ErrorResponse   *ErrorResponseCfg  `yaml:"error_response,omitempty"`
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
	Sensitivity             int
	AnomalyThreshold        int
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
	ParameterPollution         string
}

type ResolvedHeaders struct {
	Preset     string
	Inject     map[string]string
	StripExtra []string
}
