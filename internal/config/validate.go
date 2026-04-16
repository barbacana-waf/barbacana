package config

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/barbacana-waf/barbacana/internal/protections"
)

func validate(c *Config) error {
	var errs []string
	add := func(msg string) { errs = append(errs, msg) }

	if c.Version != "v1alpha1" {
		add(fmt.Sprintf("version: expected %q, got %q", "v1alpha1", c.Version))
	}
	if c.Listen == c.MetricsListen {
		add("listen and metrics_listen must differ")
	}
	if c.Listen == c.HealthListen {
		add("listen and health_listen must differ")
	}
	if c.MetricsListen == c.HealthListen {
		add("metrics_listen and health_listen must differ")
	}
	if len(c.Routes) == 0 {
		add("routes: at least one route is required")
	}

	allNames := protections.AllNames()
	validateDisableList(c.Global.Disable, "global", allNames, &errs)
	validateAccept(&c.Global.Accept, "global", &errs)
	validateInspection(&c.Global.Inspection, "global", &errs)
	validateMultipart(&c.Global.Multipart, "global", &errs)
	validateProtocol(&c.Global.Protocol, "global", &errs)
	validateResponseHeaders(&c.Global.ResponseHeaders, "global", allNames, &errs)

	seenIDs := map[string]bool{}
	for i, r := range c.Routes {
		prefix := fmt.Sprintf("routes[%d]", i)
		if r.ID != "" {
			prefix = fmt.Sprintf("route %q", r.ID)
		}
		validateRoute(i, r, prefix, allNames, seenIDs, &errs)
	}

	if len(errs) == 0 {
		return nil
	}
	return fmt.Errorf("%s", strings.Join(errs, "\n"))
}

func validateRoute(i int, r Route, prefix string, allNames map[string]bool, seenIDs map[string]bool, errs *[]string) {
	add := func(msg string) { *errs = append(*errs, fmt.Sprintf("%s: %s", prefix, msg)) }

	if r.ID != "" {
		if seenIDs[r.ID] {
			add("duplicate route id")
		}
		seenIDs[r.ID] = true
		for _, ch := range r.ID {
			if !((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-') {
				add("id must match ^[a-z0-9][a-z0-9-]*$")
				break
			}
		}
	}

	if r.Upstream == "" {
		add("upstream is required")
	} else {
		u, err := url.Parse(r.Upstream)
		if err != nil {
			add(fmt.Sprintf("upstream: %v", err))
		} else {
			if u.Scheme != "http" && u.Scheme != "https" {
				add(fmt.Sprintf("upstream: scheme must be http or https, got %q", u.Scheme))
			}
			if u.Host == "" {
				add("upstream: missing host")
			}
		}
	}

	if r.UpstreamTimeout != "" {
		d, err := time.ParseDuration(r.UpstreamTimeout)
		if err != nil {
			add(fmt.Sprintf("upstream_timeout: %v", err))
		} else if d < time.Second || d > 600*time.Second {
			add("upstream_timeout must be >= 1s and <= 600s")
		}
	}

	if r.Match != nil {
		if len(r.Match.Hosts) == 0 && len(r.Match.Paths) == 0 {
			add("match: at least one of hosts or paths must be set")
		}
		for _, p := range r.Match.Paths {
			if !strings.HasPrefix(p, "/") {
				add(fmt.Sprintf("match.paths: %q must start with /", p))
			}
		}
	}

	if r.Rewrite != nil {
		validateRewrite(r.Rewrite, prefix, errs)
	}

	validateDisableList(r.Disable, prefix, allNames, errs)

	if r.Accept != nil {
		validateAccept(r.Accept, prefix, errs)
	}
	if r.Inspection != nil {
		validateInspection(r.Inspection, prefix, errs)
	}
	if r.Multipart != nil {
		validateMultipart(r.Multipart, prefix, errs)
	}
	if r.Protocol != nil {
		validateProtocol(r.Protocol, prefix, errs)
	}
	if r.ResponseHeaders != nil {
		validateResponseHeaders(r.ResponseHeaders, prefix, allNames, errs)
	}
	if r.CORS != nil {
		validateCORS(r.CORS, prefix, errs)
	}
	if r.OpenAPI != nil {
		validateOpenAPI(r.OpenAPI, prefix, allNames, errs)
	}
}

func validateRewrite(rw *RewriteCfg, prefix string, errs *[]string) {
	add := func(msg string) { *errs = append(*errs, fmt.Sprintf("%s: rewrite.%s", prefix, msg)) }
	if rw.StripPrefix != "" && !strings.HasPrefix(rw.StripPrefix, "/") {
		add("strip_prefix must start with /")
	}
	if rw.AddPrefix != "" && !strings.HasPrefix(rw.AddPrefix, "/") {
		add("add_prefix must start with /")
	}
	if rw.Path != "" && !strings.HasPrefix(rw.Path, "/") {
		add("path must start with /")
	}
}

func validateAccept(a *AcceptCfg, prefix string, errs *[]string) {
	add := func(msg string) { *errs = append(*errs, fmt.Sprintf("%s: accept.%s", prefix, msg)) }

	for _, m := range a.Methods {
		if !isValidMethod(m) {
			add(fmt.Sprintf("invalid HTTP method %q", m))
		}
	}
	for _, ct := range a.ContentTypes {
		if !isValidMIME(ct) {
			add(fmt.Sprintf("invalid MIME type %q in content_types", ct))
		}
	}
	if a.MaxBodySize != "" {
		bs, err := parseByteSize(a.MaxBodySize)
		if err != nil {
			add(fmt.Sprintf("max_body_size: %v", err))
		} else if bs <= 0 || bs > 1024*1024*1024 {
			add("max_body_size must be > 0 and <= 1GB")
		}
	}
	if a.MaxURLLength != 0 && (a.MaxURLLength < 512 || a.MaxURLLength > 65536) {
		add("max_url_length must be >= 512 and <= 65536")
	}
	if a.MaxHeaderSize != "" {
		hs, err := parseByteSize(a.MaxHeaderSize)
		if err != nil {
			add(fmt.Sprintf("max_header_size: %v", err))
		} else if hs < 4*1024 || hs > 1024*1024 {
			add("max_header_size must be >= 4KB and <= 1MB")
		}
	}
	if a.MaxHeaderCount != 0 && (a.MaxHeaderCount < 10 || a.MaxHeaderCount > 1000) {
		add("max_header_count must be >= 10 and <= 1000")
	}
}

func validateInspection(ins *InspectionCfg, prefix string, errs *[]string) {
	add := func(msg string) { *errs = append(*errs, fmt.Sprintf("%s: inspection.%s", prefix, msg)) }

	if ins.Sensitivity != nil && (*ins.Sensitivity < 1 || *ins.Sensitivity > 4) {
		add("sensitivity must be >= 1 and <= 4")
	}
	if ins.AnomalyThreshold != nil && *ins.AnomalyThreshold < 1 {
		add("anomaly_threshold must be >= 1")
	}
	if ins.EvaluationTimeout != "" {
		d, err := time.ParseDuration(ins.EvaluationTimeout)
		if err != nil {
			add(fmt.Sprintf("evaluation_timeout: %v", err))
		} else if d < 10*time.Millisecond {
			add("evaluation_timeout must be >= 10ms")
		}
	}
	if ins.MaxInspectSize != "" {
		v, err := parseByteSize(ins.MaxInspectSize)
		if err != nil {
			add(fmt.Sprintf("max_inspect_size: %v", err))
		} else if v <= 0 || v > 10*1024*1024 {
			add("max_inspect_size must be > 0 and <= 10MB")
		}
	}
	if ins.MaxMemoryBuffer != "" {
		v, err := parseByteSize(ins.MaxMemoryBuffer)
		if err != nil {
			add(fmt.Sprintf("max_memory_buffer: %v", err))
		} else if v <= 0 || v > 10*1024*1024 {
			add("max_memory_buffer must be > 0 and <= 10MB")
		}
	}
	if ins.DecompressionRatioLimit != nil && *ins.DecompressionRatioLimit < 1 {
		add("decompression_ratio_limit must be >= 1")
	}
	if ins.JSONDepth != nil && (*ins.JSONDepth < 1 || *ins.JSONDepth > 1000) {
		add("json_depth must be >= 1 and <= 1000")
	}
	if ins.JSONKeys != nil && (*ins.JSONKeys < 1 || *ins.JSONKeys > 100000) {
		add("json_keys must be >= 1 and <= 100000")
	}
	if ins.XMLDepth != nil && (*ins.XMLDepth < 1 || *ins.XMLDepth > 1000) {
		add("xml_depth must be >= 1 and <= 1000")
	}
	if ins.XMLEntities != nil && (*ins.XMLEntities < 0 || *ins.XMLEntities > 10000) {
		add("xml_entities must be >= 0 and <= 10000")
	}
}

func validateMultipart(m *MultipartCfg, prefix string, errs *[]string) {
	add := func(msg string) { *errs = append(*errs, fmt.Sprintf("%s: multipart.%s", prefix, msg)) }
	if m.FileLimit != nil && *m.FileLimit < 1 {
		add("file_limit must be >= 1")
	}
	if m.FileSize != "" {
		v, err := parseByteSize(m.FileSize)
		if err != nil {
			add(fmt.Sprintf("file_size: %v", err))
		} else if v <= 0 {
			add("file_size must be > 0")
		}
	}
	for _, t := range m.AllowedTypes {
		if !isValidMIME(t) {
			add(fmt.Sprintf("invalid MIME type %q in allowed_types", t))
		}
	}
}

func validateProtocol(p *ProtocolCfg, prefix string, errs *[]string) {
	add := func(msg string) { *errs = append(*errs, fmt.Sprintf("%s: protocol.%s", prefix, msg)) }
	if p.SlowRequestHeaderTimeout != "" {
		d, err := time.ParseDuration(p.SlowRequestHeaderTimeout)
		if err != nil {
			add(fmt.Sprintf("slow_request_header_timeout: %v", err))
		} else if d < time.Second {
			add("slow_request_header_timeout must be >= 1s")
		}
	}
	if p.SlowRequestMinRateBPS != nil && *p.SlowRequestMinRateBPS < 0 {
		add("slow_request_min_rate_bps must be >= 0")
	}
	if p.HTTP2MaxConcurrentStreams != nil && *p.HTTP2MaxConcurrentStreams < 1 {
		add("http2_max_concurrent_streams must be >= 1")
	}
	if p.HTTP2MaxContinuationFrames != nil && *p.HTTP2MaxContinuationFrames < 1 {
		add("http2_max_continuation_frames must be >= 1")
	}
	if p.HTTP2MaxDecodedHeaderBytes != nil && *p.HTTP2MaxDecodedHeaderBytes < 4096 {
		add("http2_max_decoded_header_bytes must be >= 4096")
	}
	if p.ParameterPollution != "" {
		switch p.ParameterPollution {
		case "reject", "first", "last":
		default:
			add(fmt.Sprintf("parameter_pollution must be reject, first, or last; got %q", p.ParameterPollution))
		}
	}
}

func validateResponseHeaders(rh *ResponseHeaderCfg, prefix string, allNames map[string]bool, errs *[]string) {
	add := func(msg string) { *errs = append(*errs, fmt.Sprintf("%s: response_headers.%s", prefix, msg)) }
	if rh.Preset != "" {
		switch rh.Preset {
		case "strict", "moderate", "api-only", "custom":
		default:
			add(fmt.Sprintf("preset must be strict, moderate, api-only, or custom; got %q", rh.Preset))
		}
	}
	for k := range rh.Inject {
		if !strings.HasPrefix(k, "header-") {
			add(fmt.Sprintf("inject key %q must be a canonical header-* name", k))
		} else if !allNames[k] {
			add(fmt.Sprintf("inject key %q is not a known protection name", k))
		}
	}
}

func validateCORS(cors *CORSCfg, prefix string, errs *[]string) {
	add := func(msg string) { *errs = append(*errs, fmt.Sprintf("%s: cors.%s", prefix, msg)) }
	if len(cors.AllowOrigins) == 0 {
		add("allow_origins is required when cors is configured")
	}
	if cors.AllowCredentials != nil && *cors.AllowCredentials {
		for _, o := range cors.AllowOrigins {
			if o == "*" {
				add("allow_credentials is true but allow_origins contains \"*\"")
				break
			}
		}
	}
	for _, m := range cors.AllowMethods {
		if !isValidMethod(m) {
			add(fmt.Sprintf("invalid HTTP method %q in allow_methods", m))
		}
	}
	if cors.MaxAge != nil && (*cors.MaxAge < 0 || *cors.MaxAge > 86400) {
		add("max_age must be >= 0 and <= 86400")
	}
}

func validateOpenAPI(oa *OpenAPIRoute, prefix string, allNames map[string]bool, errs *[]string) {
	add := func(msg string) { *errs = append(*errs, fmt.Sprintf("%s: openapi.%s", prefix, msg)) }
	if oa.Spec == "" {
		add("spec is required when openapi is configured")
	}
	for _, d := range oa.Disable {
		if !strings.HasPrefix(d, "openapi-") {
			add(fmt.Sprintf("disable entry %q must be an openapi-* sub-protection name", d))
		} else if !allNames[d] {
			add(fmt.Sprintf("disable entry %q is not a known protection name", d))
		}
	}
}

func validateDisableList(disable []string, prefix string, allNames map[string]bool, errs *[]string) {
	for _, name := range disable {
		if !allNames[name] {
			suggestion := closestName(name, allNames)
			msg := fmt.Sprintf("%s: unknown protection %q in disable list", prefix, name)
			if suggestion != "" {
				msg += fmt.Sprintf(" (did you mean %q?)", suggestion)
			}
			*errs = append(*errs, msg)
		}
	}
}

// closestName returns the closest canonical name by Levenshtein distance
// (max 2) or "" if none is close enough.
func closestName(input string, names map[string]bool) string {
	best := ""
	bestDist := 3
	for n := range names {
		d := levenshtein(input, n)
		if d < bestDist {
			bestDist = d
			best = n
		}
	}
	return best
}

func levenshtein(a, b string) int {
	if len(a) == 0 {
		return len(b)
	}
	if len(b) == 0 {
		return len(a)
	}
	prev := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	curr := make([]int, len(b)+1)
	for i := 1; i <= len(a); i++ {
		curr[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			curr[j] = min(curr[j-1]+1, min(prev[j]+1, prev[j-1]+cost))
		}
		prev, curr = curr, prev
	}
	return prev[len(b)]
}

func isValidMethod(m string) bool {
	switch m {
	case "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE", "CONNECT":
		return true
	}
	return false
}

func isValidMIME(s string) bool {
	parts := strings.SplitN(s, "/", 2)
	if len(parts) != 2 {
		return false
	}
	return parts[0] != "" && parts[1] != ""
}
