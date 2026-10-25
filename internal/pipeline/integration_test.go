//go:build integration

package pipeline

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"

	"github.com/barbacana-waf/barbacana/internal/audit"
	"github.com/barbacana-waf/barbacana/internal/config"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/barbacana-waf/barbacana/internal/metrics"
	"github.com/barbacana-waf/barbacana/internal/protections"
	"github.com/barbacana-waf/barbacana/internal/protections/request"
)

func TestMain(m *testing.M) {
	metrics.Init()
	os.Exit(m.Run())
}

// expandLegacyDisableForTest builds a disable map equivalent to what
// resolveDisableEnable would produce for `disable: [id]` with no enable
// list. Tests that bypass the full config pipeline (constructing
// Resolved directly) use this to populate Resolved.Disable. Lives here
// rather than in the protections package because it's test-only glue.
func expandLegacyDisableForTest(id string) map[string]bool {
	leaves, ok := protections.LeafIDsUnder(id)
	if !ok {
		return nil
	}
	out := map[string]bool{id: true}
	for _, l := range leaves {
		out[l] = true
	}
	return out
}

// testResolved returns a basic resolved config for integration tests.
func testResolved(id string, detectOnly bool, disable []string) config.Resolved {
	disableMap := make(map[string]bool)
	for _, d := range disable {
		disableMap[d] = true
	}

	mode := config.ModeBlocking
	if detectOnly {
		mode = config.ModeDetect
	}

	return config.Resolved{
		ID:       id,
		Upstream: "http://localhost:9999", // not used directly in handler tests
		Mode:     mode,
		Disable:  disableMap,
		Accept: config.ResolvedAccept{
			Methods:           []string{"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"},
			MaxBodySize:       10 * 1024 * 1024,
			MaxURLLength:      8192,
			MaxHeaderSize:     16 * 1024,
			MaxHeaderCount:    100,
			RequireHostHeader: true,
		},
		Inspection: config.ResolvedInspection{
			EvaluationTimeout:       5 * time.Second,
			MaxInspectSize:          128 * 1024,
			MaxMemoryBuffer:         128 * 1024,
			DecompressionRatioLimit: 100,
			JSONDepth:               20,
			JSONKeys:                1000,
			XMLDepth:                20,
			XMLEntities:             100,
		},
		Multipart: config.ResolvedMultipart{
			FileLimit:       10,
			FileSize:        10 * 1024 * 1024,
			DoubleExtension: true,
		},
		Protocol: config.ResolvedProtocol{
			SlowRequestHeaderTimeout:   10 * time.Second,
			SlowRequestMinRateBPS:      1024,
			HTTP2MaxConcurrentStreams:  100,
			HTTP2MaxContinuationFrames: 10,
			HTTP2MaxDecodedHeaderBytes: 65536,
		},
		ResponseHeaders: config.ResolvedHeaders{
			Inject: map[string]string{},
		},
		RunJSONParser:      true,
		RunXMLParser:       true,
		RunMultipartParser: true,
		RunFormParser:      true,
	}
}

// provisionHandler creates a provisioned handler for testing.
func provisionHandler(t *testing.T, res config.Resolved) *Handler {
	t.Helper()
	RegisterConfigs([]config.Resolved{res})
	h := &Handler{RouteID: res.ID}
	if err := h.Provision(caddyCtx()); err != nil {
		t.Fatalf("provision handler: %v", err)
	}
	return h
}

// caddyCtx returns a minimal caddy.Context for testing.
// Handler.Provision ignores the context so a zero-value works.
func caddyCtx() caddy.Context {
	return caddy.Context{}
}

// upstreamHandler is a simple handler that simulates an upstream server.
var upstreamHandler = caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
	w.Header().Set("Server", "test-upstream")
	w.Header().Set("X-Powered-By", "go")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"ok":true}`))
	return nil
})

// captureAuditLogs redirects audit emission to a buffer. The audit
// package writes formatted OCSF/ECS lines to its own io.Writer
// (default os.Stdout) — bypassing slog — so capturing requires
// SetOutput, not slog redirection. The cleanup restores stdout when
// the subtest exits.
func captureAuditLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	audit.SetOutput(&buf)
	t.Cleanup(func() { audit.SetOutput(os.Stdout) })
	return &buf
}

// parseAuditEntries reads OCSF audit lines from buf and flattens each
// into the field shape these tests assert on (request_id,
// matched_protections, matched_rules, cwe, action, route_id, …). The
// translation lives here so individual test assertions stay format-
// agnostic — switching to ECS later only requires updating this helper.
func parseAuditEntries(buf *bytes.Buffer) []map[string]any {
	var entries []map[string]any
	for _, line := range strings.Split(buf.String(), "\n") {
		if line == "" {
			continue
		}
		var ocsf map[string]any
		if err := json.Unmarshal([]byte(line), &ocsf); err != nil {
			continue
		}
		entries = append(entries, flattenOCSFAudit(ocsf))
	}
	return entries
}

func flattenOCSFAudit(o map[string]any) map[string]any {
	flat := map[string]any{
		"timestamp":           o["time"],
		"response_code":       o["status_code"],
		"matched_protections": []any{},
		"matched_rules":       []any{},
		"cwe":                 []any{},
		"anomaly_score":       float64(0),
	}
	if hr, ok := o["http_request"].(map[string]any); ok {
		if uid, ok := hr["uid"]; ok {
			flat["request_id"] = uid
		}
		if m, ok := hr["http_method"]; ok {
			flat["method"] = m
		}
		if u, ok := hr["url"].(map[string]any); ok {
			flat["path"] = u["path"]
			flat["host"] = u["hostname"]
		}
	}
	if src, ok := o["src_endpoint"].(map[string]any); ok {
		flat["source_ip"] = src["ip"]
	}
	switch o["disposition"] {
	case "Blocked":
		flat["action"] = "blocked"
	case "Allowed":
		flat["action"] = "detected"
	}
	if rs, ok := o["risk_score"]; ok {
		flat["anomaly_score"] = rs
	}
	if md, ok := o["metadata"].(map[string]any); ok {
		if rid, ok := md["route_id"]; ok {
			flat["route_id"] = rid
		}
	}
	if bb, ok := o["barbacana"].(map[string]any); ok {
		if v, ok := bb["matched_protections"]; ok {
			flat["matched_protections"] = v
		}
		if v, ok := bb["matched_rules"]; ok {
			flat["matched_rules"] = v
		}
		if v, ok := bb["cwe"]; ok {
			flat["cwe"] = v
		}
	}
	return flat
}

// responseBody reads and returns the response body as a map.
func responseBody(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("parse response body: %v (raw: %s)", err, rec.Body.String())
	}
	return m
}

func TestIntegration_SQLiBlocked(t *testing.T) {
	buf := captureAuditLogs(t)
	res := testResolved("sqli-test", false, nil)
	h := provisionHandler(t, res)

	r := httptest.NewRequest("GET", "http://example.com/test?id=1%27+OR+%271%27%3D%271", nil)
	r.Header.Set("Host", "example.com")
	r.Header.Set("User-Agent", "Mozilla/5.0")
	r.Header.Set("Accept", "*/*")
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, r, upstreamHandler)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}

	entries := parseAuditEntries(buf)
	if len(entries) == 0 {
		t.Fatal("no audit entries emitted")
	}
	entry := entries[0]
	if entry["action"] != "blocked" {
		t.Errorf("action = %v, want blocked", entry["action"])
	}
	rules, ok := entry["matched_rules"].([]any)
	if !ok || len(rules) == 0 {
		t.Errorf("expected non-empty matched_rules, got %v", entry["matched_rules"])
	}
	cwes, ok := entry["cwe"].([]any)
	if !ok || len(cwes) == 0 {
		t.Errorf("expected non-empty cwe, got %v", entry["cwe"])
	}
	// Verify CWE-89 is in the list.
	foundCWE89 := false
	for _, c := range cwes {
		if c == "CWE-89" {
			foundCWE89 = true
		}
	}
	if !foundCWE89 {
		t.Errorf("expected CWE-89 in cwe list, got %v", cwes)
	}
}

func TestIntegration_CleanRequestPasses(t *testing.T) {
	res := testResolved("clean-test", false, nil)
	h := provisionHandler(t, res)

	r := httptest.NewRequest("GET", "http://example.com/api/users", nil)
	r.Header.Set("Host", "example.com")
	r.Header.Set("User-Agent", "Mozilla/5.0")
	r.Header.Set("Accept", "*/*")
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, r, upstreamHandler)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (body: %s)", rec.Code, rec.Body.String())
	}
}

func TestIntegration_NullByteRejection(t *testing.T) {
	buf := captureAuditLogs(t)
	res := testResolved("nullbyte-test", false, nil)
	h := provisionHandler(t, res)

	r := httptest.NewRequest("GET", "http://example.com/foo%00bar", nil)
	r.Header.Set("Host", "example.com")
	r.Header.Set("User-Agent", "Mozilla/5.0")
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, r, upstreamHandler)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}

	entries := parseAuditEntries(buf)
	if len(entries) == 0 {
		t.Fatal("no audit entries emitted")
	}
	entry := entries[0]

	// Native protection: matched_rules should be empty array.
	rules, ok := entry["matched_rules"].([]any)
	if !ok {
		t.Fatalf("matched_rules is not an array: %T", entry["matched_rules"])
	}
	if len(rules) != 0 {
		t.Errorf("expected empty matched_rules for native protection, got %v", rules)
	}

	// CWE should contain CWE-158.
	cwes, ok := entry["cwe"].([]any)
	if !ok || len(cwes) == 0 {
		t.Fatalf("expected non-empty cwe, got %v", entry["cwe"])
	}
	foundCWE := false
	for _, c := range cwes {
		if c == "CWE-158" {
			foundCWE = true
		}
	}
	if !foundCWE {
		t.Errorf("expected CWE-158 in cwe list, got %v", cwes)
	}
}

func TestIntegration_CRLFRejection(t *testing.T) {
	res := testResolved("crlf-test", false, nil)
	h := provisionHandler(t, res)

	r := httptest.NewRequest("GET", "http://example.com/foo%0d%0abar", nil)
	r.Header.Set("Host", "example.com")
	r.Header.Set("User-Agent", "Mozilla/5.0")
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, r, upstreamHandler)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
}

func TestIntegration_DetectModeGlobal(t *testing.T) {
	buf := captureAuditLogs(t)
	res := testResolved("detect-test", true, nil)
	h := provisionHandler(t, res)

	r := httptest.NewRequest("GET", "http://example.com/test?id=1%27+OR+%271%27%3D%271", nil)
	r.Header.Set("Host", "example.com")
	r.Header.Set("User-Agent", "Mozilla/5.0")
	r.Header.Set("Accept", "*/*")
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, r, upstreamHandler)

	// In detect-only, request passes through to upstream.
	if rec.Code != http.StatusOK {
		t.Fatalf("detect-only should pass through, got %d", rec.Code)
	}

	entries := parseAuditEntries(buf)
	if len(entries) == 0 {
		t.Fatal("no audit entries emitted in detect-only")
	}
	entry := entries[0]
	if entry["action"] != "detected" {
		t.Errorf("action = %v, want detected", entry["action"])
	}
}

func TestIntegration_ErrorResponseFormat(t *testing.T) {
	res := testResolved("err-format-test", false, nil)
	h := provisionHandler(t, res)

	r := httptest.NewRequest("GET", "http://example.com/test?id=1%27+OR+%271%27%3D%271", nil)
	r.Header.Set("Host", "example.com")
	r.Header.Set("User-Agent", "Mozilla/5.0")
	r.Header.Set("Accept", "*/*")
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, r, upstreamHandler)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}

	body := responseBody(t, rec)
	// Must only contain "error" and "request_id".
	for key := range body {
		switch key {
		case "error", "request_id":
			// allowed
		default:
			t.Errorf("unexpected field %q in error response", key)
		}
	}
	if body["error"] != "blocked" {
		t.Errorf("error = %v, want blocked", body["error"])
	}
	if _, ok := body["matched_rules"]; ok {
		t.Error("error response must not contain matched_rules")
	}
	if _, ok := body["cwe"]; ok {
		t.Error("error response must not contain cwe")
	}
}

func TestIntegration_SecurityHeadersInjected(t *testing.T) {
	res := testResolved("headers-test", false, nil)
	h := provisionHandler(t, res)

	r := httptest.NewRequest("GET", "http://example.com/api/ok", nil)
	r.Header.Set("Host", "example.com")
	r.Header.Set("User-Agent", "Mozilla/5.0")
	r.Header.Set("Accept", "*/*")
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, r, upstreamHandler)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	// Check that security headers are injected.
	expectedHeaders := []string{
		"Strict-Transport-Security",
		"Content-Security-Policy",
		"X-Content-Type-Options",
		"X-Frame-Options",
		"Referrer-Policy",
	}
	for _, hdr := range expectedHeaders {
		if rec.Header().Get(hdr) == "" {
			t.Errorf("expected header %s to be set", hdr)
		}
	}
}

func TestIntegration_SecurityHeadersStripped(t *testing.T) {
	res := testResolved("strip-test", false, nil)
	h := provisionHandler(t, res)

	r := httptest.NewRequest("GET", "http://example.com/api/ok", nil)
	r.Header.Set("Host", "example.com")
	r.Header.Set("User-Agent", "Mozilla/5.0")
	r.Header.Set("Accept", "*/*")
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, r, upstreamHandler)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	// Upstream sets Server and X-Powered-By — they should be stripped.
	if rec.Header().Get("Server") != "" {
		t.Error("Server header should be stripped")
	}
	if rec.Header().Get("X-Powered-By") != "" {
		t.Error("X-Powered-By header should be stripped")
	}
}

func TestIntegration_ContentTypeGating415(t *testing.T) {
	res := testResolved("ct-test", false, nil)
	res.Accept.ContentTypes = []string{"application/json"}
	res.RunJSONParser = true
	res.RunXMLParser = false
	res.RunMultipartParser = false
	res.RunFormParser = false
	h := provisionHandler(t, res)

	r := httptest.NewRequest("POST", "http://example.com/api/data", strings.NewReader("<xml/>"))
	r.Header.Set("Host", "example.com")
	r.Header.Set("Content-Type", "application/xml")
	r.Header.Set("User-Agent", "Mozilla/5.0")
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, r, upstreamHandler)

	if rec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("expected 415, got %d", rec.Code)
	}
}

func TestIntegration_OversizedBody413(t *testing.T) {
	res := testResolved("body-test", false, nil)
	res.Accept.MaxBodySize = 100 // 100 bytes
	h := provisionHandler(t, res)

	body := strings.Repeat("x", 200)
	r := httptest.NewRequest("POST", "http://example.com/api/data", strings.NewReader(body))
	r.Header.Set("Host", "example.com")
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("User-Agent", "Mozilla/5.0")
	r.ContentLength = 200
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, r, upstreamHandler)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d", rec.Code)
	}
}

// TestIntegration_OversizedChunkedBody413 covers the gap runRequestValidation
// cannot see: a body with no declared length (ContentLength == -1, as Go
// reports for chunked Transfer-Encoding) still gets capped and blocked,
// instead of being buffered without limit by readBody. Regression test for
// the CVE-2026-109618-class bug in Barbacana's own pipeline: an undeclared
// body length used to bypass the size check entirely, not just delay it.
func TestIntegration_OversizedChunkedBody413(t *testing.T) {
	res := testResolved("chunked-body-test", false, nil)
	res.Accept.MaxBodySize = 100 // 100 bytes
	h := provisionHandler(t, res)

	body := jsonBodyOfSize(200)
	r := httptest.NewRequest("POST", "http://example.com/api/data", strings.NewReader(body))
	r.Header.Set("Host", "example.com")
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("User-Agent", "Mozilla/5.0")
	r.ContentLength = -1 // undeclared length, as net/http reports for chunked bodies
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, r, upstreamHandler)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d", rec.Code)
	}
}

// jsonBodyOfSize returns a valid JSON document of exactly n bytes. These tests
// send application/json, and a body that is not JSON is blocked as malformed.
func jsonBodyOfSize(n int) string {
	const frame = `{"d":""}`
	return `{"d":"` + strings.Repeat("x", n-len(frame)) + `"}`
}

// TestIntegration_ChunkedBodyWithinLimitPasses proves the guard only fires
// on actual oversize, not on every undeclared-length request.
func TestIntegration_ChunkedBodyWithinLimitPasses(t *testing.T) {
	res := testResolved("chunked-body-ok-test", false, nil)
	res.Accept.MaxBodySize = 100 // 100 bytes
	h := provisionHandler(t, res)

	body := jsonBodyOfSize(50)
	r := httptest.NewRequest("POST", "http://example.com/api/data", strings.NewReader(body))
	r.Header.Set("Host", "example.com")
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("User-Agent", "Mozilla/5.0")
	r.ContentLength = -1
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, r, upstreamHandler)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestIntegration_OversizedChunkedBodyAlwaysRejected extends
// TestIntegration_OversizedChunkedBody413 to the configurations that would
// otherwise let a request through: detect-only, and
// request-validation-max-body-size disabled. The body was only read up to
// the cap, so letting it through would mean buffering an unbounded body or
// forwarding one nothing inspected.
func TestIntegration_OversizedChunkedBodyAlwaysRejected(t *testing.T) {
	tests := []struct {
		name       string
		detectOnly bool
		disable    []string
	}{
		{name: "detect-only", detectOnly: true},
		{name: "leaf disabled", disable: []string{request.MaxBodySize}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := captureAuditLogs(t)
			res := testResolved("chunked-body-always-test", tt.detectOnly, tt.disable)
			res.Accept.MaxBodySize = 100
			h := provisionHandler(t, res)
			blocked := metrics.RequestsBlockedTotal.WithLabelValues(res.ID, request.MaxBodySize)
			before := testutil.ToFloat64(blocked)

			r := httptest.NewRequest("POST", "http://example.com/api/data", strings.NewReader(strings.Repeat("x", 5000)))
			r.Header.Set("Host", "example.com")
			r.Header.Set("Content-Type", "text/plain")
			r.Header.Set("User-Agent", "Mozilla/5.0")
			r.ContentLength = -1
			rec := httptest.NewRecorder()

			reached := false
			upstream := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
				reached = true
				w.WriteHeader(http.StatusOK)
				return nil
			})
			h.ServeHTTP(rec, r, upstream)

			if rec.Code != http.StatusRequestEntityTooLarge {
				t.Fatalf("expected 413, got %d: %s", rec.Code, rec.Body.String())
			}
			if reached {
				t.Error("an oversized chunked body reached the upstream")
			}
			if got := testutil.ToFloat64(blocked); got != before+1 {
				t.Errorf("waf_requests_blocked_total{protection=%q} = %v, want %v", request.MaxBodySize, got, before+1)
			}

			entries := parseAuditEntries(buf)
			if len(entries) != 1 {
				t.Fatalf("got %d audit entries, want 1", len(entries))
			}
			if entries[0]["action"] != "blocked" {
				t.Errorf("action = %v, want blocked", entries[0]["action"])
			}
			prots, _ := entries[0]["matched_protections"].([]any)
			if len(prots) != 1 || prots[0] != request.MaxBodySize {
				t.Errorf("matched_protections = %v, want [%s]", prots, request.MaxBodySize)
			}
		})
	}
}

func TestIntegration_AuditLogAllFields(t *testing.T) {
	buf := captureAuditLogs(t)
	res := testResolved("audit-fields-test", false, nil)
	h := provisionHandler(t, res)

	r := httptest.NewRequest("GET", "http://example.com/test?id=1%27+OR+%271%27%3D%271", nil)
	r.Header.Set("Host", "example.com")
	r.Header.Set("User-Agent", "Mozilla/5.0")
	r.Header.Set("Accept", "*/*")
	r.Header.Set("X-Request-Id", "test-req-001")
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, r, upstreamHandler)

	entries := parseAuditEntries(buf)
	if len(entries) == 0 {
		t.Fatal("no audit entries")
	}
	entry := entries[0]

	requiredFields := []string{
		"timestamp", "request_id", "source_ip", "method", "host",
		"path", "route_id", "matched_protections", "matched_rules",
		"cwe", "anomaly_score", "action", "response_code",
	}
	for _, f := range requiredFields {
		if _, ok := entry[f]; !ok {
			t.Errorf("audit log missing field %q", f)
		}
	}

	if entry["route_id"] != "audit-fields-test" {
		t.Errorf("route_id = %v, want audit-fields-test", entry["route_id"])
	}
	if entry["request_id"] != "test-req-001" {
		t.Errorf("request_id = %v, want test-req-001", entry["request_id"])
	}
}

func TestIntegration_XSSBlocked(t *testing.T) {
	res := testResolved("xss-test", false, nil)
	h := provisionHandler(t, res)

	r := httptest.NewRequest("GET", "http://example.com/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E", nil)
	r.Header.Set("Host", "example.com")
	r.Header.Set("User-Agent", "Mozilla/5.0")
	r.Header.Set("Accept", "*/*")
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, r, upstreamHandler)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for XSS, got %d", rec.Code)
	}
}

func TestIntegration_DeepJSON413(t *testing.T) {
	res := testResolved("json-depth-test", false, nil)
	res.Inspection.JSONDepth = 3
	h := provisionHandler(t, res)

	// Deeply nested JSON (depth 5).
	body := `{"a":{"b":{"c":{"d":{"e":"deep"}}}}}`
	r := httptest.NewRequest("POST", "http://example.com/api/data", strings.NewReader(body))
	r.Header.Set("Host", "example.com")
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("User-Agent", "Mozilla/5.0")
	r.ContentLength = int64(len(body))
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, r, upstreamHandler)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for deep JSON, got %d (body: %s)", rec.Code, rec.Body.String())
	}
}

func TestIntegration_DisabledCategoryDisablesAll(t *testing.T) {
	// Disable the entire sql-injection L2 bucket.
	disableMap := expandLegacyDisableForTest("sql-injection")
	res := testResolved("disable-cat-test", false, nil)
	res.Disable = disableMap
	h := provisionHandler(t, res)

	r := httptest.NewRequest("GET", "http://example.com/test?id=1%27+OR+%271%27%3D%271", nil)
	r.Header.Set("Host", "example.com")
	r.Header.Set("User-Agent", "Mozilla/5.0")
	r.Header.Set("Accept", "*/*")
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, r, upstreamHandler)

	// SQLi should NOT be blocked because the category is disabled.
	if rec.Code == http.StatusForbidden {
		t.Fatalf("disabled sql-injection category should not block, got 403")
	}
}

func TestIntegration_DisabledSubProtection(t *testing.T) {
	// Disable only the libinjection-tokenizer leaf (renamed under phase 4).
	disableMap := expandLegacyDisableForTest("sql-injection-generic")
	res := testResolved("disable-sub-test", false, nil)
	res.Disable = disableMap
	h := provisionHandler(t, res)

	// This payload may still trigger other sql-injection sub-protections.
	r := httptest.NewRequest("GET", "http://example.com/test?id=1%27+OR+%271%27%3D%271", nil)
	r.Header.Set("Host", "example.com")
	r.Header.Set("User-Agent", "Mozilla/5.0")
	r.Header.Set("Accept", "*/*")
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, r, upstreamHandler)

	// May still be blocked by other sub-protections — this test verifies
	// that the disabled sub-protection itself is removed from CRS rules.
	// The key assertion is that it doesn't panic and processes correctly.
	t.Logf("status with sql-injection-libinjection disabled: %d", rec.Code)
}

func TestIntegration_CORSPreflightAllowed(t *testing.T) {
	res := testResolved("cors-test", false, nil)
	res.CORS = &config.CORSCfg{
		AllowOrigins: []string{"https://app.example.com"},
		AllowMethods: []string{"GET", "POST"},
		AllowHeaders: []string{"Content-Type", "Authorization"},
	}
	h := provisionHandler(t, res)

	r := httptest.NewRequest("OPTIONS", "http://example.com/api/data", nil)
	r.Header.Set("Host", "example.com")
	r.Header.Set("Origin", "https://app.example.com")
	r.Header.Set("Access-Control-Request-Method", "POST")
	r.Header.Set("Access-Control-Request-Headers", "Content-Type")
	r.Header.Set("User-Agent", "Mozilla/5.0")
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, r, upstreamHandler)

	// Preflight should return 204.
	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204 for CORS preflight, got %d", rec.Code)
	}
	if rec.Header().Get("Access-Control-Allow-Origin") != "https://app.example.com" {
		t.Errorf("ACAO = %q, want https://app.example.com", rec.Header().Get("Access-Control-Allow-Origin"))
	}
}

func TestIntegration_CORSUnlistedOriginBlocked(t *testing.T) {
	res := testResolved("cors-block-test", false, nil)
	res.CORS = &config.CORSCfg{
		AllowOrigins: []string{"https://app.example.com"},
		AllowMethods: []string{"GET"},
	}
	h := provisionHandler(t, res)

	r := httptest.NewRequest("OPTIONS", "http://example.com/api/data", nil)
	r.Header.Set("Host", "example.com")
	r.Header.Set("Origin", "https://evil.com")
	r.Header.Set("Access-Control-Request-Method", "GET")
	r.Header.Set("User-Agent", "Mozilla/5.0")
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, r, upstreamHandler)

	// Unlisted origin should not get CORS headers.
	if rec.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Errorf("unlisted origin should not get ACAO header, got %q", rec.Header().Get("Access-Control-Allow-Origin"))
	}
}

func TestIntegration_MultipartDoubleExtension(t *testing.T) {
	res := testResolved("multipart-ext-test", false, nil)
	res.Accept.ContentTypes = []string{"multipart/form-data"}
	res.RunMultipartParser = true
	res.RunJSONParser = false
	res.RunXMLParser = false
	res.Multipart.DoubleExtension = true
	h := provisionHandler(t, res)

	// Build a multipart body with a double-extension filename.
	var buf bytes.Buffer
	w := multipartWriter(&buf, "shell.php.jpg", "image/jpeg", []byte("fake image content"))
	r := httptest.NewRequest("POST", "http://example.com/upload", &buf)
	r.Header.Set("Host", "example.com")
	r.Header.Set("Content-Type", w)
	r.Header.Set("User-Agent", "Mozilla/5.0")
	r.ContentLength = int64(buf.Len())
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, r, upstreamHandler)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for double-extension, got %d", rec.Code)
	}
}

func TestIntegration_DecompressionBombRejected(t *testing.T) {
	res := testResolved("decomp-test", false, nil)
	res.Inspection.DecompressionRatioLimit = 10 // very low ratio limit
	h := provisionHandler(t, res)

	// Create a gzip body with high compression ratio.
	var compressed bytes.Buffer
	gz, _ := gzip.NewWriterLevel(&compressed, gzip.BestCompression)
	// 10KB of zeros — compresses to ~50 bytes → ratio ~200:1
	gz.Write(bytes.Repeat([]byte{0}, 10*1024))
	gz.Close()

	r := httptest.NewRequest("POST", "http://example.com/api/data", &compressed)
	r.Header.Set("Host", "example.com")
	r.Header.Set("Content-Encoding", "gzip")
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("User-Agent", "Mozilla/5.0")
	r.ContentLength = int64(compressed.Len())
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, r, upstreamHandler)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for decompression bomb, got %d", rec.Code)
	}
}

func TestIntegration_RequestSmuggling(t *testing.T) {
	res := testResolved("smuggling-test", false, nil)
	h := provisionHandler(t, res)

	r := httptest.NewRequest("POST", "http://example.com/api", strings.NewReader("x"))
	r.Header.Set("Host", "example.com")
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Content-Length", "1")
	r.Header.Set("Transfer-Encoding", "chunked")
	r.Header.Set("User-Agent", "Mozilla/5.0")
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, r, upstreamHandler)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for request smuggling, got %d", rec.Code)
	}
}

// TestIntegration_WebSocketUpgradePassesThrough drives a real TCP
// connection through Handler.ServeHTTP so the response goes through the
// actual responseModifier and a real net/http Hijack — a ResponseRecorder
// doesn't implement http.Hijacker, so this can't be verified with the
// rec := httptest.NewRecorder() pattern the other tests use. Regression
// test for a bug where WriteHeader unconditionally buffered the status
// line for response-phase inspection, so a 101 Switching Protocols never
// reached the wire before the upgrade handler hijacked the connection —
// breaking every Hijacker-based protocol upgrade (WebSocket, h2c). curl
// (and therefore Hurl) can't observe this: libcurl treats an unrecognized
// 1xx Upgrade as provisional and errors on the connection close that
// follows a real WS handshake, regardless of what the server sent, so
// this is a Go test rather than a blackbox scenario.
func TestIntegration_WebSocketUpgradePassesThrough(t *testing.T) {
	res := testResolved("ws-test", false, nil)
	h := provisionHandler(t, res)

	// RFC 6455 §1.3 worked example: this key always yields this accept.
	const wsKey = "dGhlIHNhbXBsZSBub25jZQ=="
	const wantAccept = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="

	upgradeNext := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Upgrade", "websocket")
		w.Header().Set("Connection", "Upgrade")
		w.Header().Set("Sec-WebSocket-Accept", wantAccept)
		w.WriteHeader(http.StatusSwitchingProtocols)
		conn, _, err := http.NewResponseController(w).Hijack()
		if err != nil {
			return err
		}
		return conn.Close()
	})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := h.ServeHTTP(w, r, upgradeNext); err != nil {
			t.Errorf("ServeHTTP: %v", err)
		}
	}))
	defer srv.Close()

	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	req := "GET /ws HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"Connection: Upgrade\r\n" +
		"Upgrade: websocket\r\n" +
		"Sec-WebSocket-Version: 13\r\n" +
		"Sec-WebSocket-Key: " + wsKey + "\r\n" +
		"User-Agent: Mozilla/5.0\r\n" +
		"\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("write request: %v", err)
	}

	br := bufio.NewReader(conn)
	statusLine, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read status line: %v", err)
	}
	if !strings.HasPrefix(statusLine, "HTTP/1.1 101") {
		t.Fatalf("status line = %q, want 101 Switching Protocols", statusLine)
	}

	headers := make(http.Header)
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("read headers: %v", err)
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			t.Fatalf("malformed header line %q", line)
		}
		headers.Add(strings.TrimSpace(k), strings.TrimSpace(v))
	}

	if got := headers.Get("Upgrade"); got != "websocket" {
		t.Errorf("Upgrade header = %q, want websocket", got)
	}
	if got := headers.Get("Connection"); !strings.EqualFold(got, "Upgrade") {
		t.Errorf("Connection header = %q, want Upgrade", got)
	}
	if got := headers.Get("Sec-WebSocket-Accept"); got != wantAccept {
		t.Errorf("Sec-WebSocket-Accept = %q, want %q", got, wantAccept)
	}
}

// TestIntegration_WebSocketUpgradeStripsFingerprintingHeaders is the
// sibling regression test for a defect found alongside the 1xx
// passthrough fix: the early-return branch in WriteHeader for 1xx
// codes skipped the header stripper entirely (it only ran in the
// final-response branch below), so an upstream that fingerprints
// itself on the 101 handshake — e.g. `Server:`, `X-Powered-By:` — leaked
// those headers straight through the WAF to the client. Stripping must
// run on the 1xx response too, while injection/CORS (meaningless on an
// informational response) must not.
func TestIntegration_WebSocketUpgradeStripsFingerprintingHeaders(t *testing.T) {
	res := testResolved("ws-strip-test", false, nil)
	h := provisionHandler(t, res)

	const wsKey = "dGhlIHNhbXBsZSBub25jZQ=="
	const wantAccept = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="

	upgradeNext := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		// Fingerprinting headers the default-enabled stripper removes
		// (see internal/protections/headers/headers.go
		// strippingHeaders["response-headers-remove-server"] and
		// ["response-headers-remove-powered-by"]).
		w.Header().Set("Server", "secretserver")
		w.Header().Set("X-Powered-By", "PHP/8.1")
		w.Header().Set("Upgrade", "websocket")
		w.Header().Set("Connection", "Upgrade")
		w.Header().Set("Sec-WebSocket-Accept", wantAccept)
		w.WriteHeader(http.StatusSwitchingProtocols)
		conn, _, err := http.NewResponseController(w).Hijack()
		if err != nil {
			return err
		}
		return conn.Close()
	})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := h.ServeHTTP(w, r, upgradeNext); err != nil {
			t.Errorf("ServeHTTP: %v", err)
		}
	}))
	defer srv.Close()

	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	req := "GET /ws HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"Connection: Upgrade\r\n" +
		"Upgrade: websocket\r\n" +
		"Sec-WebSocket-Version: 13\r\n" +
		"Sec-WebSocket-Key: " + wsKey + "\r\n" +
		"User-Agent: Mozilla/5.0\r\n" +
		"\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("write request: %v", err)
	}

	br := bufio.NewReader(conn)
	statusLine, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read status line: %v", err)
	}
	if !strings.HasPrefix(statusLine, "HTTP/1.1 101") {
		t.Fatalf("status line = %q, want 101 Switching Protocols", statusLine)
	}

	headers := make(http.Header)
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("read headers: %v", err)
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			t.Fatalf("malformed header line %q", line)
		}
		headers.Add(strings.TrimSpace(k), strings.TrimSpace(v))
	}

	if got := headers.Get("Server"); got != "" {
		t.Errorf("Server header = %q, want stripped", got)
	}
	if got := headers.Get("X-Powered-By"); got != "" {
		t.Errorf("X-Powered-By header = %q, want stripped", got)
	}
	if got := headers.Get("Upgrade"); got != "websocket" {
		t.Errorf("Upgrade header = %q, want websocket", got)
	}
	if got := headers.Get("Connection"); !strings.EqualFold(got, "Upgrade") {
		t.Errorf("Connection header = %q, want Upgrade", got)
	}
	if got := headers.Get("Sec-WebSocket-Accept"); got != wantAccept {
		t.Errorf("Sec-WebSocket-Accept = %q, want %q", got, wantAccept)
	}
}

// multipartWriter creates a multipart form body with a single file.
func multipartWriter(buf *bytes.Buffer, filename, contentType string, content []byte) string {
	w := multipart.NewWriter(buf)
	h := make(textproto.MIMEHeader)
	h.Set("Content-Disposition", `form-data; name="file"; filename="`+filename+`"`)
	h.Set("Content-Type", contentType)
	part, _ := w.CreatePart(h)
	part.Write(content)
	w.Close()
	return w.FormDataContentType()
}

// suppress unused import warning for io
var _ = io.Discard

// TestIntegration_ChunkedPHP2ShellMarkerBlocked proves the php2shell rule
// still sees a body with no declared length. Before CRS was fed the buffered
// body, a chunked multipart POST carrying the upload-progress marker reached
// the upstream un-inspected.
func TestIntegration_ChunkedPHP2ShellMarkerBlocked(t *testing.T) {
	res := testResolved("chunked-php2shell-test", false, nil)
	h := provisionHandler(t, res)

	const boundary = "AAABBBCCC"
	body := "--" + boundary + "\r\n" +
		"Content-Disposition: form-data; name=\"PHP_SESSION_UPLOAD_PROGRESS\"\r\n\r\n123\r\n" +
		"--" + boundary + "--\r\n"
	r := httptest.NewRequest("POST", "http://example.com/upload", strings.NewReader(body))
	r.Header.Set("Host", "example.com")
	r.Header.Set("Content-Type", "multipart/form-data; boundary="+boundary)
	r.Header.Set("User-Agent", "Mozilla/5.0")
	r.ContentLength = -1
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, r, upstreamHandler)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for chunked marker POST, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestIntegration_PHP2ShellBlockAuditAttribution checks the audit log and
// the response names the leaf that actually blocked a PHP2Shell request.
//
// Every multipart body also matches CRS 922140 — a severity-less `pass`
// helper that sets up state for 922110 and fires on clean uploads too —
// and it runs long before the Barbacana custom rules, which load last.
// While decisions came back in match order, the block was reported as
// file-upload-attacks-content-type-trick with CWE-444, so an operator
// reading the audit log (or a dashboard watching
// waf_requests_blocked_total{protection="php-php2shell-session-upload-progress"})
// never saw the protection that did the blocking.
func TestIntegration_PHP2ShellBlockAuditAttribution(t *testing.T) {
	buf := captureAuditLogs(t)
	res := testResolved("php2shell-attribution-test", false, nil)
	h := provisionHandler(t, res)

	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	if err := w.WriteField("PHP_SESSION_UPLOAD_PROGRESS", "123"); err != nil {
		t.Fatalf("write field: %v", err)
	}
	if err := w.WriteField("comment", "hello"); err != nil {
		t.Fatalf("write field: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close multipart writer: %v", err)
	}

	r := httptest.NewRequest("POST", "http://example.com/upload", bytes.NewReader(body.Bytes()))
	r.Header.Set("Host", "example.com")
	r.Header.Set("User-Agent", "Mozilla/5.0")
	r.Header.Set("Accept", "*/*")
	r.Header.Set("Content-Type", w.FormDataContentType())
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, r, upstreamHandler)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", rec.Code, rec.Body.String())
	}

	entries := parseAuditEntries(buf)
	if len(entries) == 0 {
		t.Fatal("no audit entries emitted")
	}
	entry := entries[0]
	if entry["action"] != "blocked" {
		t.Fatalf("action = %v, want blocked", entry["action"])
	}
	prots, ok := entry["matched_protections"].([]any)
	if !ok || len(prots) == 0 {
		t.Fatalf("expected non-empty matched_protections, got %v", entry["matched_protections"])
	}
	if prots[0] != "php-php2shell-session-upload-progress" {
		t.Errorf("matched_protections[0] = %v, want php-php2shell-session-upload-progress (entry=%v)", prots[0], entry)
	}
	cwes, _ := entry["cwe"].([]any)
	foundCWE94 := false
	for _, c := range cwes {
		if c == "CWE-94" {
			foundCWE94 = true
		}
	}
	if !foundCWE94 {
		t.Errorf("cwe = %v, want it to include CWE-94 (entry=%v)", cwes, entry)
	}
}

// shortThenErrReader yields a prefix and then fails, standing in for a
// client that disappears mid-upload or sends malformed chunked framing.
type shortThenErrReader struct {
	prefix []byte
	off    int
}

func (s *shortThenErrReader) Read(p []byte) (int, error) {
	if s.off < len(s.prefix) {
		n := copy(p, s.prefix[s.off:])
		s.off += n
		return n, nil
	}
	return 0, errors.New("connection reset by peer")
}

// TestIntegration_BodyBufferFailureIsCountedAndPreserved covers the
// fail-open path: when the body cannot be buffered there is nothing to
// inspect, so the request reaches the upstream with no body rule having
// run. That must not happen quietly — it is counted in
// waf_body_inspection_skipped_total — and the bytes already read off the
// wire must still reach the upstream rather than being dropped.
func TestIntegration_BodyBufferFailureIsCountedAndPreserved(t *testing.T) {
	const routeID = "body-buffer-failure-test"
	res := testResolved(routeID, false, nil)
	h := provisionHandler(t, res)

	before := testutil.ToFloat64(metrics.BodyInspectionSkippedTotal.WithLabelValues(routeID))

	r := httptest.NewRequest("POST", "http://example.com/api/data", nil)
	r.Header.Set("Host", "example.com")
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("User-Agent", "Mozilla/5.0")
	r.Body = io.NopCloser(&shortThenErrReader{prefix: []byte(`{"a":1}`)})
	r.ContentLength = -1
	rec := httptest.NewRecorder()

	var forwarded []byte
	upstream := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		forwarded, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		return nil
	})
	h.ServeHTTP(rec, r, upstream)

	if got := testutil.ToFloat64(metrics.BodyInspectionSkippedTotal.WithLabelValues(routeID)); got != before+1 {
		t.Errorf("waf_body_inspection_skipped_total = %v, want %v: a request forwarded without body inspection must be counted",
			got, before+1)
	}
	if string(forwarded) != `{"a":1}` {
		t.Errorf("upstream received %q, want the bytes already read off the wire to be preserved", forwarded)
	}
}

// A body over inspection.max_inspect_size is handled by the window rule, which
// answers 413 and is named in the audit log, not by an anonymous 403.
func TestIntegration_OversizedInspectionBody413(t *testing.T) {
	res := testResolved("window-test", false, nil)
	res.Inspection.MaxInspectSize = 1024
	res.Inspection.MaxMemoryBuffer = 1024
	audit := captureAuditLogs(t)
	h := provisionHandler(t, res)

	body := `{"data":"` + strings.Repeat("a", 4096) + `"}`
	r := httptest.NewRequest("POST", "http://example.com/api/data", strings.NewReader(body))
	r.Header.Set("Host", "example.com")
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("User-Agent", "Mozilla/5.0")
	r.ContentLength = int64(len(body))
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, r, upstreamHandler)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d", rec.Code)
	}
	entries := parseAuditEntries(audit)
	if len(entries) != 1 {
		t.Fatalf("expected one audit entry, got %d", len(entries))
	}
	if got := fmt.Sprint(entries[0]["matched_protections"]); !strings.Contains(got, "resource-limits-max-inspection-size") {
		t.Errorf("audit matched_protections = %s, want resource-limits-max-inspection-size", got)
	}
}

// An upload far larger than the window passes: the window counts what the
// rules read, and no rule reads file contents.
func TestIntegration_LargeUploadPasses(t *testing.T) {
	res := testResolved("upload-window-test", false, nil)
	res.Inspection.MaxInspectSize = 1024
	res.Inspection.MaxMemoryBuffer = 1024
	h := provisionHandler(t, res)

	var b strings.Builder
	b.WriteString("--XB\r\nContent-Disposition: form-data; name=\"title\"\r\n\r\nholiday\r\n")
	b.WriteString("--XB\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.bin\"\r\nContent-Type: application/octet-stream\r\n\r\n")
	b.WriteString(strings.Repeat("x", 1<<20))
	b.WriteString("\r\n--XB--\r\n")
	body := b.String()
	r := httptest.NewRequest("POST", "http://example.com/upload", strings.NewReader(body))
	r.Header.Set("Host", "example.com")
	r.Header.Set("Content-Type", "multipart/form-data; boundary=XB")
	r.Header.Set("User-Agent", "Mozilla/5.0")
	r.ContentLength = int64(len(body))
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, r, upstreamHandler)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}
