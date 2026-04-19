package config

// Default constants for the full schema. Every unset field is populated
// from this table — conventions.md §errors: "no implicit zero means
// default; the defaults pass writes the value explicitly."
const (
	defaultPort        = 8080
	defaultMetricsPort = 0
	defaultHealthPort  = 0
	defaultRoutesDir   = ""
	defaultDataDir     = "/data/barbacana"

	defaultMaxBodySize    = "10MB"
	defaultMaxURLLength   = 8192
	defaultMaxHeaderSize  = "16KB"
	defaultMaxHeaderCount = 100

	defaultSensitivity             = 1
	defaultAnomalyThreshold        = 5
	defaultEvaluationTimeout       = "50ms"
	defaultMaxInspectSize          = "128KB"
	defaultMaxMemoryBuffer         = "128KB"
	defaultDecompressionRatioLimit = 100
	defaultJSONDepth               = 20
	defaultJSONKeys                = 1000
	defaultXMLDepth                = 20
	defaultXMLEntities             = 100

	defaultMultipartFileLimit = 10
	defaultMultipartFileSize  = "10MB"

	defaultSlowRequestHeaderTimeout   = "10s"
	defaultSlowRequestMinRateBPS      = 1024
	defaultHTTP2MaxConcurrentStreams  = 100
	defaultHTTP2MaxContinuationFrames = 32
	defaultHTTP2MaxDecodedHeaderBytes = 65536
	defaultParameterPollution         = "reject"

	defaultResponseHeaderPreset = "moderate"

	defaultUpstreamTimeout = "30s"

	defaultMode = ModeBlocking
)

func defaultMethods() []string {
	return []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
}

// applyDefaults walks the parsed Config and writes defaults into every
// unset field. Route-level pointers stay nil when the route wants to
// inherit from global — resolveRoute fills those in later.
func applyDefaults(c *Config) {
	// Port defaults to 8080 only when mode 3 is unambiguous: no top-level
	// `host`, no explicit `port`, and no route uses `match.hosts`. Setting
	// `port` in modes 1/2 is a validation error handled by validate().
	if c.Host == "" && c.Port == 0 && !anyRouteHasHosts(c.Routes) {
		c.Port = defaultPort
	}
	// MetricsPort and HealthPort default to 0 (disabled). Operators opt in
	// by setting a non-zero port — see principles.md §10.
	if c.DataDir == "" {
		c.DataDir = defaultDataDir
	}
	applyGlobalDefaults(&c.Global)
	for i := range c.Routes {
		if c.Routes[i].UpstreamTimeout == "" {
			c.Routes[i].UpstreamTimeout = defaultUpstreamTimeout
		}
	}
}

func anyRouteHasHosts(routes []Route) bool {
	for _, r := range routes {
		if r.Match != nil && len(r.Match.Hosts) > 0 {
			return true
		}
	}
	return false
}

func applyGlobalDefaults(g *Global) {
	if g.Mode == "" {
		g.Mode = defaultMode
	}
	applyAcceptDefaults(&g.Accept)
	applyInspectionDefaults(&g.Inspection)
	applyMultipartDefaults(&g.Multipart)
	applyProtocolDefaults(&g.Protocol)
	applyResponseHeaderDefaults(&g.ResponseHeaders)
	if g.OpenAPI.ShadowAPILogging == nil {
		t := true
		g.OpenAPI.ShadowAPILogging = &t
	}
}

func applyAcceptDefaults(a *AcceptCfg) {
	if len(a.Methods) == 0 {
		a.Methods = defaultMethods()
	}
	if a.MaxBodySize == "" {
		a.MaxBodySize = defaultMaxBodySize
	}
	if a.MaxURLLength == 0 {
		a.MaxURLLength = defaultMaxURLLength
	}
	if a.MaxHeaderSize == "" {
		a.MaxHeaderSize = defaultMaxHeaderSize
	}
	if a.MaxHeaderCount == 0 {
		a.MaxHeaderCount = defaultMaxHeaderCount
	}
	if a.RequireHostHeader == nil {
		t := true
		a.RequireHostHeader = &t
	}
}

func applyInspectionDefaults(i *InspectionCfg) {
	if i.Sensitivity == nil {
		v := defaultSensitivity
		i.Sensitivity = &v
	}
	if i.AnomalyThreshold == nil {
		v := defaultAnomalyThreshold
		i.AnomalyThreshold = &v
	}
	if i.EvaluationTimeout == "" {
		i.EvaluationTimeout = defaultEvaluationTimeout
	}
	if i.MaxInspectSize == "" {
		i.MaxInspectSize = defaultMaxInspectSize
	}
	if i.MaxMemoryBuffer == "" {
		i.MaxMemoryBuffer = defaultMaxMemoryBuffer
	}
	if i.DecompressionRatioLimit == nil {
		v := defaultDecompressionRatioLimit
		i.DecompressionRatioLimit = &v
	}
	if i.JSONDepth == nil {
		v := defaultJSONDepth
		i.JSONDepth = &v
	}
	if i.JSONKeys == nil {
		v := defaultJSONKeys
		i.JSONKeys = &v
	}
	if i.XMLDepth == nil {
		v := defaultXMLDepth
		i.XMLDepth = &v
	}
	if i.XMLEntities == nil {
		v := defaultXMLEntities
		i.XMLEntities = &v
	}
}

func applyMultipartDefaults(m *MultipartCfg) {
	if m.FileLimit == nil {
		v := defaultMultipartFileLimit
		m.FileLimit = &v
	}
	if m.FileSize == "" {
		m.FileSize = defaultMultipartFileSize
	}
	if m.DoubleExtension == nil {
		t := true
		m.DoubleExtension = &t
	}
}

func applyProtocolDefaults(p *ProtocolCfg) {
	if p.SlowRequestHeaderTimeout == "" {
		p.SlowRequestHeaderTimeout = defaultSlowRequestHeaderTimeout
	}
	if p.SlowRequestMinRateBPS == nil {
		v := defaultSlowRequestMinRateBPS
		p.SlowRequestMinRateBPS = &v
	}
	if p.HTTP2MaxConcurrentStreams == nil {
		v := defaultHTTP2MaxConcurrentStreams
		p.HTTP2MaxConcurrentStreams = &v
	}
	if p.HTTP2MaxContinuationFrames == nil {
		v := defaultHTTP2MaxContinuationFrames
		p.HTTP2MaxContinuationFrames = &v
	}
	if p.HTTP2MaxDecodedHeaderBytes == nil {
		v := defaultHTTP2MaxDecodedHeaderBytes
		p.HTTP2MaxDecodedHeaderBytes = &v
	}
	if p.ParameterPollution == "" {
		p.ParameterPollution = defaultParameterPollution
	}
}

func applyResponseHeaderDefaults(r *ResponseHeaderCfg) {
	if r.Preset == "" {
		r.Preset = defaultResponseHeaderPreset
	}
	if r.Inject == nil {
		r.Inject = map[string]string{}
	}
}
