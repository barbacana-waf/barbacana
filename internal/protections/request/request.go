// Package request implements request validation and body parsing protections.
package request

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/barbacana-waf/barbacana/internal/config"
	"github.com/barbacana-waf/barbacana/internal/protections"
)

// Canonical names. Phase 2 of the taxonomy refactor.
const (
	MaxBodySize        = "request-validation-max-body-size"
	MaxURLLength       = "request-validation-max-url-length"
	MaxHeaderSize      = "request-validation-max-header-size"
	MaxHeaderCount     = "request-validation-max-header-count"
	AllowedMethods     = "request-validation-allowed-methods"
	RequireHostHeader  = "request-validation-require-host-header"
	RequireContentType = "request-validation-require-content-type"
	JSONDepthLimit     = "json-parsing-max-depth"
	JSONKeyLimit       = "json-parsing-max-keys"
	XMLDepthLimit      = "xml-parsing-max-depth"
	XMLEntityExpansion = "xml-parsing-entity-expansion"
	XMLExternalEntity  = "xml-parsing-external-entities"
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
	if !protections.IsDisabled(XMLExternalEntity, disabled) && xmlExternalEntity.Match(body) {
		return protections.Decision{
			Block: true, Protection: XMLExternalEntity,
			Reason: "XML body declares an external DOCTYPE or SYSTEM/PUBLIC entity",
		}
	}
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

// xmlEntityDecl and xmlEntityRef find what an entity-expansion attack is made
// of: declarations of custom entities, and references to them. The five
// predefined entities and numeric character references are ordinary text.
var (
	xmlEntityDecl = regexp.MustCompile(`<!ENTITY\b`)
	xmlEntityRef  = regexp.MustCompile(`&([A-Za-z_:][A-Za-z0-9_.:-]*);`)
)

// xmlExternalEntity finds the two ways an XML body makes the parser read a
// local file or fetch a URL: a DOCTYPE with an external identifier
// (<!DOCTYPE x SYSTEM "..."> or PUBLIC) and an entity declared with SYSTEM or
// PUBLIC, parameter entities (<!ENTITY % x ...>) included.
var xmlExternalEntity = regexp.MustCompile(
	`(?i)<!(?:DOCTYPE\b[^>\[]*?\b(?:SYSTEM|PUBLIC)\b|ENTITY\s+(?:%\s*)?[^\s>]+\s+(?:SYSTEM|PUBLIC)\b)`)

// countXMLEntities counts custom entity declarations plus references to custom
// entities. It reads the raw bytes because Go's decoder cannot be used for it:
// it reports a whole DOCTYPE as one directive however many entities it declares,
// and it stops at the first reference to an entity it has no definition for,
// which is every reference in an expansion bomb.
func countXMLEntities(data []byte) int {
	n := len(xmlEntityDecl.FindAll(data, -1))
	for _, m := range xmlEntityRef.FindAllSubmatch(data, -1) {
		switch string(m[1]) {
		case "lt", "gt", "amp", "quot", "apos":
		default:
			n++
		}
	}
	return n
}

func analyzeXML(data []byte) (maxDepth, entityCount int, err error) {
	entityCount = countXMLEntities(data)
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
		}
	}
	return maxDepth, entityCount, nil
}

