package config

import (
	"fmt"
	"strings"
	"text/template"
	"time"

	"github.com/barbacana-waf/barbacana/internal/protections"
)

// Resolve converts the raw parsed Config into a slice of Resolved routes.
// Each route's fields are merged with the global section: route values win
// when set, global provides defaults. This is called after validation.
func Resolve(c *Config) ([]Resolved, error) {
	out := make([]Resolved, len(c.Routes))
	for i, r := range c.Routes {
		res, err := resolveRoute(r, &c.Global)
		if err != nil {
			return nil, fmt.Errorf("route %d (%s): %w", i, routeLabel(r), err)
		}
		out[i] = res
	}
	return out, nil
}

func resolveRoute(r Route, g *Global) (Resolved, error) {
	var res Resolved
	res.ID = r.ID
	if res.ID == "" && r.Match != nil && len(r.Match.Paths) > 0 {
		res.ID = sanitizeID(r.Match.Paths[0])
	}
	res.Match = r.Match
	res.Upstream = r.Upstream
	res.Rewrite = r.Rewrite

	ut, err := parseDuration(r.UpstreamTimeout)
	if err != nil {
		return res, fmt.Errorf("upstream_timeout: %w", err)
	}
	res.UpstreamTimeout = ut

	if r.Mode != nil {
		res.Mode = *r.Mode
	} else {
		res.Mode = g.Mode
	}

	// Merge disable lists: route is additive to global.
	combined := append([]string{}, g.Disable...)
	combined = append(combined, r.Disable...)
	res.Disable = protections.ExpandDisable(combined)

	// Accept
	acc := mergeAccept(r.Accept, &g.Accept)
	ra, err := resolveAccept(acc)
	if err != nil {
		return res, err
	}
	res.Accept = ra

	// Content-type gating
	res.RunJSONParser = true
	res.RunXMLParser = true
	res.RunMultipartParser = true
	res.RunFormParser = true
	if len(res.Accept.ContentTypes) > 0 {
		res.RunJSONParser = false
		res.RunXMLParser = false
		res.RunMultipartParser = false
		res.RunFormParser = false
		for _, ct := range res.Accept.ContentTypes {
			switch {
			case ct == "application/json" || strings.HasSuffix(ct, "+json"):
				res.RunJSONParser = true
			case ct == "application/xml" || ct == "text/xml" || strings.HasSuffix(ct, "+xml"):
				res.RunXMLParser = true
			case ct == "multipart/form-data":
				res.RunMultipartParser = true
			case ct == "application/x-www-form-urlencoded":
				res.RunFormParser = true
			}
		}
	}

	// Inspection
	ins := mergeInspection(r.Inspection, &g.Inspection)
	ri, err := resolveInspection(ins)
	if err != nil {
		return res, err
	}
	res.Inspection = ri

	// Multipart
	mp := mergeMultipart(r.Multipart, &g.Multipart)
	rm, err := resolveMultipart(mp)
	if err != nil {
		return res, err
	}
	res.Multipart = rm

	// Protocol
	proto := mergeProtocol(r.Protocol, &g.Protocol)
	rp, err := resolveProtocol(proto)
	if err != nil {
		return res, err
	}
	res.Protocol = rp

	// Response headers
	res.ResponseHeaders = resolveResponseHeaders(r.ResponseHeaders, &g.ResponseHeaders)

	// OpenAPI
	res.OpenAPI = r.OpenAPI
	res.ShadowAPILogging = *g.OpenAPI.ShadowAPILogging

	// CORS
	res.CORS = r.CORS

	// Custom error response template
	if r.ErrorResponse != nil && r.ErrorResponse.Body != "" {
		tmpl, err := compileErrorTemplate(r.ErrorResponse.Body)
		if err != nil {
			return res, fmt.Errorf("error_response.body: %w", err)
		}
		res.ErrorTemplate = tmpl
	}

	return res, nil
}

// compileErrorTemplate parses the error response body as a Go text/template.
// Only {{.RequestID}} and {{.Timestamp}} are allowed.
func compileErrorTemplate(body string) (*template.Template, error) {
	tmpl, err := template.New("error_response").Parse(body)
	if err != nil {
		return nil, fmt.Errorf("parse template: %w", err)
	}
	// Validate that only allowed fields are referenced by executing with
	// the known data structure. Any unknown field will cause an error.
	type errorData struct {
		RequestID string
		Timestamp string
	}
	var buf strings.Builder
	if err := tmpl.Execute(&buf, errorData{RequestID: "test", Timestamp: "test"}); err != nil {
		return nil, fmt.Errorf("template references disallowed fields (only .RequestID and .Timestamp are allowed): %w", err)
	}
	return tmpl, nil
}

func mergeAccept(route *AcceptCfg, global *AcceptCfg) AcceptCfg {
	if route == nil {
		return *global
	}
	out := *global
	if len(route.Methods) > 0 {
		out.Methods = route.Methods
	}
	if len(route.ContentTypes) > 0 {
		out.ContentTypes = route.ContentTypes
	}
	if route.MaxBodySize != "" {
		out.MaxBodySize = route.MaxBodySize
	}
	if route.MaxURLLength != 0 {
		out.MaxURLLength = route.MaxURLLength
	}
	if route.MaxHeaderSize != "" {
		out.MaxHeaderSize = route.MaxHeaderSize
	}
	if route.MaxHeaderCount != 0 {
		out.MaxHeaderCount = route.MaxHeaderCount
	}
	if route.RequireHostHeader != nil {
		out.RequireHostHeader = route.RequireHostHeader
	}
	return out
}

func mergeInspection(route *InspectionCfg, global *InspectionCfg) InspectionCfg {
	if route == nil {
		return *global
	}
	out := *global
	if route.EvaluationTimeout != "" {
		out.EvaluationTimeout = route.EvaluationTimeout
	}
	if route.MaxInspectSize != "" {
		out.MaxInspectSize = route.MaxInspectSize
	}
	if route.MaxMemoryBuffer != "" {
		out.MaxMemoryBuffer = route.MaxMemoryBuffer
	}
	if route.DecompressionRatioLimit != nil {
		out.DecompressionRatioLimit = route.DecompressionRatioLimit
	}
	if route.JSONDepth != nil {
		out.JSONDepth = route.JSONDepth
	}
	if route.JSONKeys != nil {
		out.JSONKeys = route.JSONKeys
	}
	if route.XMLDepth != nil {
		out.XMLDepth = route.XMLDepth
	}
	if route.XMLEntities != nil {
		out.XMLEntities = route.XMLEntities
	}
	return out
}

func mergeMultipart(route *MultipartCfg, global *MultipartCfg) MultipartCfg {
	if route == nil {
		return *global
	}
	out := *global
	if route.FileLimit != nil {
		out.FileLimit = route.FileLimit
	}
	if route.FileSize != "" {
		out.FileSize = route.FileSize
	}
	if len(route.AllowedTypes) > 0 {
		out.AllowedTypes = route.AllowedTypes
	}
	if route.DoubleExtension != nil {
		out.DoubleExtension = route.DoubleExtension
	}
	return out
}

func mergeProtocol(route *ProtocolCfg, global *ProtocolCfg) ProtocolCfg {
	if route == nil {
		return *global
	}
	out := *global
	if route.ParameterPollution != "" {
		out.ParameterPollution = route.ParameterPollution
	}
	return out
}

func resolveResponseHeaders(route *ResponseHeaderCfg, global *ResponseHeaderCfg) ResolvedHeaders {
	var rh ResolvedHeaders
	if route == nil {
		rh.Preset = global.Preset
		rh.Inject = copyMap(global.Inject)
		rh.StripExtra = global.StripExtra
		return rh
	}
	rh.Preset = route.Preset
	if rh.Preset == "" {
		rh.Preset = global.Preset
	}
	// Merge inject: global + route (route wins per key).
	rh.Inject = copyMap(global.Inject)
	for k, v := range route.Inject {
		rh.Inject[k] = v
	}
	rh.StripExtra = route.StripExtra
	if len(rh.StripExtra) == 0 {
		rh.StripExtra = global.StripExtra
	}
	return rh
}

func resolveAccept(a AcceptCfg) (ResolvedAccept, error) {
	var ra ResolvedAccept
	ra.Methods = a.Methods
	ra.ContentTypes = a.ContentTypes
	var err error
	ra.MaxBodySize, err = parseByteSize(a.MaxBodySize)
	if err != nil {
		return ra, fmt.Errorf("accept.max_body_size: %w", err)
	}
	ra.MaxURLLength = a.MaxURLLength
	ra.MaxHeaderSize, err = parseByteSize(a.MaxHeaderSize)
	if err != nil {
		return ra, fmt.Errorf("accept.max_header_size: %w", err)
	}
	ra.MaxHeaderCount = a.MaxHeaderCount
	if a.RequireHostHeader != nil {
		ra.RequireHostHeader = *a.RequireHostHeader
	}
	return ra, nil
}

func resolveInspection(ins InspectionCfg) (ResolvedInspection, error) {
	var ri ResolvedInspection
	d, err := parseDuration(ins.EvaluationTimeout)
	if err != nil {
		return ri, fmt.Errorf("inspection.evaluation_timeout: %w", err)
	}
	ri.EvaluationTimeout = d
	ri.MaxInspectSize, err = parseByteSize(ins.MaxInspectSize)
	if err != nil {
		return ri, fmt.Errorf("inspection.max_inspect_size: %w", err)
	}
	ri.MaxMemoryBuffer, err = parseByteSize(ins.MaxMemoryBuffer)
	if err != nil {
		return ri, fmt.Errorf("inspection.max_memory_buffer: %w", err)
	}
	ri.DecompressionRatioLimit = *ins.DecompressionRatioLimit
	ri.JSONDepth = *ins.JSONDepth
	ri.JSONKeys = *ins.JSONKeys
	ri.XMLDepth = *ins.XMLDepth
	ri.XMLEntities = *ins.XMLEntities
	return ri, nil
}

func resolveMultipart(m MultipartCfg) (ResolvedMultipart, error) {
	var rm ResolvedMultipart
	rm.FileLimit = *m.FileLimit
	bs, err := parseByteSize(m.FileSize)
	if err != nil {
		return rm, fmt.Errorf("multipart.file_size: %w", err)
	}
	rm.FileSize = bs
	rm.AllowedTypes = m.AllowedTypes
	rm.DoubleExtension = *m.DoubleExtension
	return rm, nil
}

func resolveProtocol(p ProtocolCfg) (ResolvedProtocol, error) {
	var rp ResolvedProtocol
	d, err := time.ParseDuration(p.SlowRequestHeaderTimeout)
	if err != nil {
		return rp, fmt.Errorf("protocol.slow_request_header_timeout: %w", err)
	}
	rp.SlowRequestHeaderTimeout = d
	rp.SlowRequestMinRateBPS = *p.SlowRequestMinRateBPS
	rp.HTTP2MaxConcurrentStreams = *p.HTTP2MaxConcurrentStreams
	rp.HTTP2MaxContinuationFrames = *p.HTTP2MaxContinuationFrames
	rp.HTTP2MaxDecodedHeaderBytes = *p.HTTP2MaxDecodedHeaderBytes
	rp.ParameterPollution = p.ParameterPollution
	return rp, nil
}

func sanitizeID(path string) string {
	s := strings.TrimPrefix(path, "/")
	s = strings.ReplaceAll(s, "/", "-")
	s = strings.ReplaceAll(s, "*", "")
	s = strings.TrimRight(s, "-")
	if s == "" {
		return "root"
	}
	return s
}

func routeLabel(r Route) string {
	if r.ID != "" {
		return r.ID
	}
	if r.Match != nil && len(r.Match.Paths) > 0 {
		return r.Match.Paths[0]
	}
	return "catch-all"
}

func copyMap(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
