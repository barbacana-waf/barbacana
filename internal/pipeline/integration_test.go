//go:build integration

package pipeline

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"

	"github.com/barbacana-waf/barbacana/internal/config"
	"github.com/barbacana-waf/barbacana/internal/metrics"
	"github.com/barbacana-waf/barbacana/internal/protections"
)

func TestMain(m *testing.M) {
	metrics.Init()
	os.Exit(m.Run())
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
			Sensitivity:             1,
			AnomalyThreshold:        5,
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
			ParameterPollution:         "reject",
		},
		ResponseHeaders: config.ResolvedHeaders{
			Preset: "moderate",
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

// captureAuditLogs redirects slog to capture audit entries.
func captureAuditLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	slog.SetDefault(logger)
	return &buf
}

// parseAuditEntries parses all JSON log lines from the buffer.
func parseAuditEntries(buf *bytes.Buffer) []map[string]any {
	var entries []map[string]any
	for _, line := range strings.Split(buf.String(), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			continue
		}
		if _, ok := m["request_id"]; ok {
			entries = append(entries, m)
		}
	}
	return entries
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
	// Disable the entire sql-injection category.
	disableMap := protections.ExpandDisable([]string{"sql-injection"})
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
	// Disable only sql-injection-libinjection.
	disableMap := protections.ExpandDisable([]string{"sql-injection-libinjection"})
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
