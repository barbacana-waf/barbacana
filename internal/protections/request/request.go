// Package request implements request validation and body parsing protections.
package request

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/barbacana-waf/barbacana/internal/config"
	"github.com/barbacana-waf/barbacana/internal/protections"
)

const (
	MaxBodySize        = "max-body-size"
	MaxURLLength       = "max-url-length"
	MaxHeaderSize      = "max-header-size"
	MaxHeaderCount     = "max-header-count"
	AllowedMethods     = "allowed-methods"
	RequireHostHeader  = "require-host-header"
	RequireContentType = "require-content-type"
	JSONDepthLimit     = "json-depth-limit"
	JSONKeyLimit       = "json-key-limit"
	XMLDepthLimit      = "xml-depth-limit"
	XMLEntityExpansion = "xml-entity-expansion"
)

// Validator evaluates request-shape constraints against a resolved route config.
type Validator struct {
	cfg config.Resolved
}

// NewValidator creates a request validator for the given resolved route.
func NewValidator(cfg config.Resolved) *Validator {
	return &Validator{cfg: cfg}
}

// ValidateRequest runs all request validation checks. Returns the first
// blocking decision or Allow.
func (v *Validator) ValidateRequest(ctx context.Context, r *http.Request) protections.Decision {
	disabled := v.cfg.Disable

	// Method check.
	if !protections.IsDisabled(AllowedMethods, disabled) {
		if !v.isMethodAllowed(r.Method) {
			return protections.Decision{
				Block: true, Protection: AllowedMethods,
				Reason: fmt.Sprintf("method %s not allowed", r.Method),
			}
		}
	}

	// Host header check.
	if !protections.IsDisabled(RequireHostHeader, disabled) && v.cfg.Accept.RequireHostHeader {
		if r.Host == "" && r.Header.Get("Host") == "" {
			return protections.Block(RequireHostHeader, "missing Host header")
		}
	}

	// URL length check.
	if !protections.IsDisabled(MaxURLLength, disabled) {
		urlLen := len(r.URL.RequestURI())
		if urlLen > v.cfg.Accept.MaxURLLength {
			return protections.Decision{
				Block: true, Protection: MaxURLLength,
				Reason: fmt.Sprintf("URL length %d exceeds %d", urlLen, v.cfg.Accept.MaxURLLength),
			}
		}
	}

	// Header count check.
	if !protections.IsDisabled(MaxHeaderCount, disabled) {
		count := 0
		for _, vals := range r.Header {
			count += len(vals)
		}
		if count > v.cfg.Accept.MaxHeaderCount {
			return protections.Decision{
				Block: true, Protection: MaxHeaderCount,
				Reason: fmt.Sprintf("header count %d exceeds %d", count, v.cfg.Accept.MaxHeaderCount),
			}
		}
	}

	// Header size check.
	if !protections.IsDisabled(MaxHeaderSize, disabled) {
		totalSize := int64(0)
		for k, vals := range r.Header {
			for _, v := range vals {
				totalSize += int64(len(k) + len(v) + 4) // ": " + "\r\n"
			}
		}
		if totalSize > v.cfg.Accept.MaxHeaderSize {
			return protections.Decision{
				Block: true, Protection: MaxHeaderSize,
				Reason: fmt.Sprintf("header size %d exceeds %d", totalSize, v.cfg.Accept.MaxHeaderSize),
			}
		}
	}

	// Body size check.
	if !protections.IsDisabled(MaxBodySize, disabled) && r.ContentLength > 0 {
		if r.ContentLength > v.cfg.Accept.MaxBodySize {
			return protections.Decision{
				Block: true, Protection: MaxBodySize,
				Reason: fmt.Sprintf("body size %d exceeds %d", r.ContentLength, v.cfg.Accept.MaxBodySize),
			}
		}
	}

	// Content-type gating.
	if len(v.cfg.Accept.ContentTypes) > 0 && hasBody(r) {
		ct := r.Header.Get("Content-Type")
		if ct != "" && !v.isContentTypeAllowed(ct) {
			return protections.Decision{
				Block: true, Protection: RequireContentType,
				Reason: fmt.Sprintf("content type %q not allowed", ct),
			}
		}
	}

	// Require content type for methods with body.
	if !protections.IsDisabled(RequireContentType, disabled) {
		if hasBody(r) && r.Header.Get("Content-Type") == "" {
			return protections.Block(RequireContentType, "POST/PUT/PATCH without Content-Type")
		}
	}

	return protections.Allow()
}

// ValidateJSONBody checks JSON depth and key limits. Only called if the
// route accepts JSON and the request has a JSON body.
func (v *Validator) ValidateJSONBody(ctx context.Context, body []byte) protections.Decision {
	if !v.cfg.RunJSONParser {
		return protections.Allow()
	}

	disabled := v.cfg.Disable

	if !protections.IsDisabled(JSONDepthLimit, disabled) || !protections.IsDisabled(JSONKeyLimit, disabled) {
		depth, keys, err := analyzeJSON(body)
		if err != nil {
			return protections.Allow() // Not valid JSON — let CRS handle it.
		}
		if !protections.IsDisabled(JSONDepthLimit, disabled) && depth > v.cfg.Inspection.JSONDepth {
			return protections.Decision{
				Block: true, Protection: JSONDepthLimit,
				Reason: fmt.Sprintf("JSON depth %d exceeds %d", depth, v.cfg.Inspection.JSONDepth),
			}
		}
		if !protections.IsDisabled(JSONKeyLimit, disabled) && keys > v.cfg.Inspection.JSONKeys {
			return protections.Decision{
				Block: true, Protection: JSONKeyLimit,
				Reason: fmt.Sprintf("JSON key count %d exceeds %d", keys, v.cfg.Inspection.JSONKeys),
			}
		}
	}
	return protections.Allow()
}

// ValidateXMLBody checks XML depth and entity expansion limits.
func (v *Validator) ValidateXMLBody(ctx context.Context, body []byte) protections.Decision {
	if !v.cfg.RunXMLParser {
		return protections.Allow()
	}

	disabled := v.cfg.Disable
	if !protections.IsDisabled(XMLDepthLimit, disabled) || !protections.IsDisabled(XMLEntityExpansion, disabled) {
		depth, entities, err := analyzeXML(body)
		if err != nil {
			return protections.Allow()
		}
		if !protections.IsDisabled(XMLDepthLimit, disabled) && depth > v.cfg.Inspection.XMLDepth {
			return protections.Decision{
				Block: true, Protection: XMLDepthLimit,
				Reason: fmt.Sprintf("XML depth %d exceeds %d", depth, v.cfg.Inspection.XMLDepth),
			}
		}
		if !protections.IsDisabled(XMLEntityExpansion, disabled) && entities > v.cfg.Inspection.XMLEntities {
			return protections.Decision{
				Block: true, Protection: XMLEntityExpansion,
				Reason: fmt.Sprintf("XML entity count %d exceeds %d", entities, v.cfg.Inspection.XMLEntities),
			}
		}
	}
	return protections.Allow()
}

func (v *Validator) isMethodAllowed(method string) bool {
	for _, m := range v.cfg.Accept.Methods {
		if m == method {
			return true
		}
	}
	return false
}

func (v *Validator) isContentTypeAllowed(ct string) bool {
	// Normalize: strip parameters like charset.
	base := ct
	if idx := strings.IndexByte(ct, ';'); idx >= 0 {
		base = strings.TrimSpace(ct[:idx])
	}
	base = strings.ToLower(base)
	for _, allowed := range v.cfg.Accept.ContentTypes {
		if strings.ToLower(allowed) == base {
			return true
		}
	}
	return false
}

func hasBody(r *http.Request) bool {
	return r.Method == "POST" || r.Method == "PUT" || r.Method == "PATCH"
}

func analyzeJSON(data []byte) (maxDepth, keyCount int, err error) {
	dec := json.NewDecoder(strings.NewReader(string(data)))
	depth := 0
	for {
		t, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return 0, 0, err
		}
		switch t {
		case json.Delim('{'), json.Delim('['):
			depth++
			if depth > maxDepth {
				maxDepth = depth
			}
		case json.Delim('}'), json.Delim(']'):
			depth--
		default:
			// Count keys: strings that appear at the start of an object.
			if _, ok := t.(string); ok && depth > 0 {
				keyCount++
			}
		}
	}
	return maxDepth, keyCount / 2, nil // Keys appear as token + value pairs
}

func analyzeXML(data []byte) (maxDepth, entityCount int, err error) {
	dec := xml.NewDecoder(strings.NewReader(string(data)))
	// Disable entity expansion to prevent bombs.
	dec.Entity = map[string]string{}
	depth := 0
	for {
		t, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return maxDepth, entityCount, nil // Partial parse is fine.
		}
		switch t.(type) {
		case xml.StartElement:
			depth++
			if depth > maxDepth {
				maxDepth = depth
			}
		case xml.EndElement:
			depth--
		case xml.Directive:
			entityCount++
		}
	}
	return maxDepth, entityCount, nil
}

// Register adds request validation protections to the registry.
func Register(reg *protections.Registry) {
	// These are registered as named protections but evaluated via the
	// Validator rather than the Protection interface, since they need
	// route config context. The registry entries enable disable-list validation.
	reg.Add(namedProtection{name: MaxBodySize})
	reg.Add(namedProtection{name: MaxURLLength})
	reg.Add(namedProtection{name: MaxHeaderSize})
	reg.Add(namedProtection{name: MaxHeaderCount})
	reg.Add(namedProtection{name: AllowedMethods})
	reg.Add(namedProtection{name: RequireHostHeader})
	reg.Add(namedProtection{name: RequireContentType})
	reg.Add(namedProtection{name: JSONDepthLimit})
	reg.Add(namedProtection{name: JSONKeyLimit})
	reg.Add(namedProtection{name: XMLDepthLimit})
	reg.Add(namedProtection{name: XMLEntityExpansion})
}

// namedProtection is a placeholder for protections evaluated via Validator.
type namedProtection struct{ name string }

func (n namedProtection) Name() string     { return n.name }
func (n namedProtection) Category() string { return "" }
func (n namedProtection) CWE() string      { return protections.CWEForProtection(n.name) }
func (n namedProtection) Evaluate(_ context.Context, _ *http.Request) protections.Decision {
	return protections.Allow()
}
