package main

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

type echoResponse struct {
	Method   string            `json:"method"`
	Path     string            `json:"path"`
	Query    string            `json:"query"`
	Headers  map[string]string `json:"headers"`
	BodySize int               `json:"body_size"`
}

func handler(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	headers := make(map[string]string)
	for k, v := range r.Header {
		if len(v) > 0 {
			headers[k] = v[0]
		}
	}

	resp := echoResponse{
		Method:   r.Method,
		Path:     r.URL.Path,
		Query:    r.URL.RawQuery,
		Headers:  headers,
		BodySize: len(body),
	}

	// Set response headers that the WAF should strip.
	w.Header().Set("Server", "MockUpstream/1.0")
	w.Header().Set("X-Powered-By", "Go")

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

// onePixelPNG is a valid 67-byte 1x1 transparent PNG used by
// /conformance/binary to exercise binary passthrough.
var onePixelPNG = []byte{
	0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a,
	0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52,
	0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
	0x08, 0x06, 0x00, 0x00, 0x00, 0x1f, 0x15, 0xc4,
	0x89, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x44, 0x41,
	0x54, 0x78, 0x9c, 0x63, 0x00, 0x01, 0x00, 0x00,
	0x05, 0x00, 0x01, 0x0d, 0x0a, 0x2d, 0xb4, 0x00,
	0x00, 0x00, 0x00, 0x49, 0x45, 0x4e, 0x44, 0xae,
	0x42, 0x60, 0x82,
}

func conformanceGzip(w http.ResponseWriter, r *http.Request) {
	accepts := strings.Contains(r.Header.Get("Accept-Encoding"), "gzip")
	payload, _ := json.Marshal(map[string]any{
		"message":    "hello",
		"compressed": accepts,
	})
	w.Header().Set("Content-Type", "application/json")
	if accepts {
		w.Header().Set("Content-Encoding", "gzip")
		w.WriteHeader(http.StatusOK)
		gw := gzip.NewWriter(w)
		_, _ = gw.Write(payload)
		_ = gw.Close()
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(payload)
}

func conformanceChunked(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	flusher, _ := w.(http.Flusher)
	writeChunk := func(s string) {
		_, _ = w.Write([]byte(s))
		if flusher != nil {
			flusher.Flush()
		}
		time.Sleep(10 * time.Millisecond)
	}
	writeChunk(`{"chunks":[`)
	writeChunk(`"first"`)
	writeChunk(`,"second"`)
	writeChunk(`,"third"]}`)
}

func conformanceRedirectAbsolute(selfAddr string) http.HandlerFunc {
	location := "http://" + selfAddr + "/conformance/echo"
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", location)
		w.WriteHeader(http.StatusFound)
	}
}

func conformanceRedirectRelative(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Location", "/conformance/echo")
	w.WriteHeader(http.StatusFound)
}

type conformanceEcho struct {
	Method  string              `json:"method"`
	Path    string              `json:"path"`
	Headers map[string][]string `json:"headers"`
	Query   map[string][]string `json:"query"`
}

func conformanceEchoHandler(w http.ResponseWriter, r *http.Request) {
	headers := make(map[string][]string)
	for k, v := range r.Header {
		headers[k] = v
	}
	resp := conformanceEcho{
		Method:  r.Method,
		Path:    r.URL.Path,
		Headers: headers,
		Query:   r.URL.Query(),
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

func conformancePostEcho(w http.ResponseWriter, r *http.Request) {
	ct := r.Header.Get("Content-Type")
	body, _ := io.ReadAll(r.Body)
	if ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func conformanceEmpty(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}

func conformanceLargeBody(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	const filler = "lorem ipsum dolor sit amet consectetur adipiscing elit sed do eiusmod"
	_, _ = w.Write([]byte("["))
	for i := 0; i < 10000; i++ {
		if i > 0 {
			_, _ = w.Write([]byte(","))
		}
		_, _ = fmt.Fprintf(w, `{"id":%d,"filler":%q}`, i, filler)
	}
	_, _ = w.Write([]byte("]"))
}

func conformanceSlow(w http.ResponseWriter, r *http.Request) {
	time.Sleep(2 * time.Second)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"message":"slow but valid"}`))
}

func conformanceBinary(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Content-Length", fmt.Sprint(len(onePixelPNG)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(onePixelPNG)
}

func conformanceSetCookie(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Set-Cookie", "session=abc123; Path=/")
	w.Header().Add("Set-Cookie", "prefs=dark; Path=/; Max-Age=86400")
	w.Header().Add("Set-Cookie", "tracking=xyz; Path=/; Domain=.example.com")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"message":"cookies set"}`))
}

func conformanceCustomHeaders(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Custom-One", "value-one")
	w.Header().Set("X-Custom-Two", "value with spaces")
	w.Header().Add("X-Multi", "first")
	w.Header().Add("X-Multi", "second")
	// Emit Server and X-Powered-By so the stripped-headers conformance
	// test can verify Barbacana removes them on the way back to the client.
	w.Header().Set("Server", "MockUpstream/1.0")
	w.Header().Set("X-Powered-By", "Go")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"message":"custom headers set"}`))
}

func conformanceCache(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("ETag", `"abc123"`)
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.Header().Set("Vary", "Accept-Encoding, Accept-Language")
	w.Header().Set("Last-Modified", "Wed, 21 Oct 2025 07:28:00 GMT")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"message":"cacheable"}`))
}

func conformanceContentTypeJSON(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"type":"json"}`))
}

func conformanceContentTypeHTML(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`<!DOCTYPE html><html><head><title>Test</title></head><body>Hello</body></html>`))
}

func conformanceContentTypePlain(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("plain text body"))
}

func conformanceHead(w http.ResponseWriter, r *http.Request) {
	body := `{"message":"head-supported"}`
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", fmt.Sprint(len(body)))
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write([]byte(body))
	}
}

func conformanceSSE(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	flusher, _ := w.(http.Flusher)
	for i := 1; i <= 3; i++ {
		_, _ = fmt.Fprintf(w, "data: event%d\n\n", i)
		if flusher != nil {
			flusher.Flush()
		}
	}
}

// requestEnvelope is the standardised "_request" object attached to every
// new /conformance/* endpoint. It captures exactly what the upstream saw
// after Barbacana processed the request so Hurl tests can verify
// transparency. Legacy endpoints (01–23) are intentionally left alone.
type requestEnvelope struct {
	Method        string            `json:"method"`
	Path          string            `json:"path"`
	Query         string            `json:"query"`
	Headers       map[string]string `json:"headers"`
	Body          string            `json:"body"`
	ContentLength int64             `json:"content_length"`
	ContentType   string            `json:"content_type"`
	Host          string            `json:"host"`
	RemoteAddr    string            `json:"remote_addr"`
}

// newEnvelope reflects the request exactly as the upstream received it.
// bodyBytes is the already-read request body (nil for GET/HEAD/DELETE).
// Path/query are pulled from r.RequestURI so any re-encoding performed
// upstream of the mock is surfaced to the test.
func newEnvelope(r *http.Request, bodyBytes []byte) requestEnvelope {
	rawPath := r.RequestURI
	query := ""
	if idx := strings.IndexByte(rawPath, '?'); idx != -1 {
		query = rawPath[idx+1:]
		rawPath = rawPath[:idx]
	}
	headers := make(map[string]string, len(r.Header))
	for k, v := range r.Header {
		if len(v) > 0 {
			headers[k] = v[0]
		}
	}
	body := ""
	if bodyBytes != nil {
		body = string(bodyBytes)
	}
	return requestEnvelope{
		Method:        r.Method,
		Path:          rawPath,
		Query:         query,
		Headers:       headers,
		Body:          body,
		ContentLength: r.ContentLength,
		ContentType:   r.Header.Get("Content-Type"),
		Host:          r.Host,
		RemoteAddr:    r.RemoteAddr,
	}
}

func conformanceResource(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		bodyBytes, _ := io.ReadAll(r.Body)
		env := newEnvelope(r, bodyBytes)
		input := map[string]any{}
		if len(bodyBytes) > 0 {
			_ = json.Unmarshal(bodyBytes, &input)
		}
		input["id"] = 1
		input["_request"] = env
		w.Header().Set("Location", "/conformance/resource/1")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(input)
	case http.MethodOptions:
		w.Header().Set("Allow", "GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS")
		w.WriteHeader(http.StatusNoContent)
	default:
		w.Header().Set("Allow", "POST, OPTIONS")
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func conformanceResourceInstance(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		env := newEnvelope(r, nil)
		body, _ := json.Marshal(map[string]any{
			"id":       1,
			"name":     "example",
			"_request": env,
		})
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(http.StatusOK)
		if r.Method == http.MethodGet {
			_, _ = w.Write(body)
		}
	case http.MethodPut, http.MethodPatch:
		bodyBytes, _ := io.ReadAll(r.Body)
		env := newEnvelope(r, bodyBytes)
		input := map[string]any{}
		if len(bodyBytes) > 0 {
			_ = json.Unmarshal(bodyBytes, &input)
		}
		input["_request"] = env
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(input)
	case http.MethodDelete:
		w.WriteHeader(http.StatusNoContent)
	default:
		w.Header().Set("Allow", "GET, PUT, PATCH, DELETE, HEAD")
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func conformanceContentForm(w http.ResponseWriter, r *http.Request) {
	bodyBytes, _ := io.ReadAll(r.Body)
	// Restore the body so ParseForm can re-read it; newEnvelope uses the
	// already-captured bytes, not r.Body.
	r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	_ = r.ParseForm()
	fields := make(map[string]string)
	for k, v := range r.PostForm {
		if len(v) > 0 {
			fields[k] = v[0]
		}
	}
	resp := map[string]any{
		"fields":   fields,
		"_request": newEnvelope(r, bodyBytes),
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

func conformanceContentMultipart(w http.ResponseWriter, r *http.Request) {
	bodyBytes, _ := io.ReadAll(r.Body)
	r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	_ = r.ParseMultipartForm(10 << 20)
	fields := make(map[string]string)
	files := make(map[string]any)
	if r.MultipartForm != nil {
		for k, v := range r.MultipartForm.Value {
			if len(v) > 0 {
				fields[k] = v[0]
			}
		}
		for k, fhs := range r.MultipartForm.File {
			if len(fhs) > 0 {
				fh := fhs[0]
				files[k] = map[string]any{
					"filename": fh.Filename,
					"size":     fh.Size,
				}
			}
		}
	}
	resp := map[string]any{
		"fields":   fields,
		"files":    files,
		"_request": newEnvelope(r, bodyBytes),
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

// envelopeHeader JSON-encodes env into the X-Request-Echo response header
// for endpoints whose response body must be the verbatim request body
// (XML, plain text, echo/body) and therefore cannot carry _request.
func envelopeHeader(w http.ResponseWriter, env requestEnvelope) {
	b, _ := json.Marshal(env)
	w.Header().Set("X-Request-Echo", string(b))
}

func conformanceContentXML(w http.ResponseWriter, r *http.Request) {
	bodyBytes, _ := io.ReadAll(r.Body)
	envelopeHeader(w, newEnvelope(r, bodyBytes))
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(bodyBytes)
}

func conformanceContentPlain(w http.ResponseWriter, r *http.Request) {
	bodyBytes, _ := io.ReadAll(r.Body)
	envelopeHeader(w, newEnvelope(r, bodyBytes))
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(bodyBytes)
}

func conformanceEchoBody(w http.ResponseWriter, r *http.Request) {
	bodyBytes, _ := io.ReadAll(r.Body)
	envelopeHeader(w, newEnvelope(r, bodyBytes))
	if ct := r.Header.Get("Content-Type"); ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(bodyBytes)
}

func conformanceStatus(w http.ResponseWriter, r *http.Request) {
	codeStr := strings.TrimPrefix(r.URL.Path, "/conformance/status/")
	code, err := strconv.Atoi(codeStr)
	if err != nil {
		http.Error(w, "bad status code", http.StatusBadRequest)
		return
	}
	bodyBytes, _ := io.ReadAll(r.Body)
	env := newEnvelope(r, bodyBytes)
	switch code {
	case http.StatusCreated:
		w.Header().Set("Location", "/conformance/resource/1")
	case http.StatusMovedPermanently, http.StatusFound, http.StatusTemporaryRedirect:
		w.Header().Set("Location", "/conformance/status/200")
	case http.StatusUnauthorized:
		w.Header().Set("WWW-Authenticate", "Bearer")
	case http.StatusMethodNotAllowed:
		w.Header().Set("Allow", "GET, POST")
	case http.StatusTooManyRequests:
		w.Header().Set("Retry-After", "60")
	case http.StatusServiceUnavailable:
		w.Header().Set("Retry-After", "120")
	}
	// Bodiless responses per HTTP semantics (and per the spec).
	noBody := code == http.StatusNoContent || code == http.StatusNotModified ||
		code == http.StatusMovedPermanently || code == http.StatusFound ||
		code == http.StatusTemporaryRedirect
	if noBody {
		w.WriteHeader(code)
		return
	}
	var resp map[string]any
	if code >= 400 {
		resp = map[string]any{
			"error":    http.StatusText(code),
			"code":     code,
			"_request": env,
		}
	} else {
		resp = map[string]any{
			"ok":       true,
			"code":     code,
			"_request": env,
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(resp)
}

func conformanceHeadersEcho(w http.ResponseWriter, r *http.Request) {
	env := newEnvelope(r, nil)
	resp := make(map[string]any, len(r.Header)+1)
	for k, v := range r.Header {
		if len(v) > 0 {
			resp[strings.ToLower(k)] = v[0]
		}
	}
	resp["_request"] = env
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

func conformanceHeadersResponse(w http.ResponseWriter, r *http.Request) {
	env := newEnvelope(r, nil)
	w.Header().Set("Content-Language", "en-US")
	w.Header().Set("X-Request-Id", "req-12345")
	w.Header().Set("X-Correlation-Id", "corr-67890")
	w.Header().Set("Link", `<https://api.example.com/next>; rel="next"`)
	w.Header().Set("Retry-After", "30")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"message":  "headers set",
		"_request": env,
	})
}

func conformanceEncodingIdentity(w http.ResponseWriter, r *http.Request) {
	env := newEnvelope(r, nil)
	body, _ := json.Marshal(map[string]any{
		"encoding": "identity",
		"_request": env,
	})
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func conformanceEncodingChunked(w http.ResponseWriter, r *http.Request) {
	env := newEnvelope(r, nil)
	body, _ := json.Marshal(map[string]any{
		"encoding": "chunked",
		"_request": env,
	})
	// No Content-Length; Flush in the middle forces chunked transfer.
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	flusher, _ := w.(http.Flusher)
	half := len(body) / 2
	if half == 0 {
		half = len(body)
	}
	_, _ = w.Write(body[:half])
	if flusher != nil {
		flusher.Flush()
	}
	if half < len(body) {
		_, _ = w.Write(body[half:])
	}
}

func conformanceEncodingEmptyChunked(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}
}

func conformanceQueryEcho(w http.ResponseWriter, r *http.Request) {
	env := newEnvelope(r, nil)
	params := make(map[string][]string)
	for k, v := range r.URL.Query() {
		params[k] = v
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"params":   params,
		"_request": env,
	})
}

func conformancePath(w http.ResponseWriter, r *http.Request) {
	env := newEnvelope(r, nil)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"_request": env,
	})
}

func conformanceConnectionAlive(w http.ResponseWriter, r *http.Request) {
	env := newEnvelope(r, nil)
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"alive":    true,
		"_request": env,
	})
}

func main() {
	addr := ":19000"
	if v := os.Getenv("UPSTREAM_ADDR"); v != "" {
		addr = v
	}

	// Derive the upstream's own host:port for absolute-redirect responses.
	selfAddr := addr
	if strings.HasPrefix(selfAddr, ":") {
		selfAddr = "localhost" + selfAddr
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/conformance/gzip", conformanceGzip)
	mux.HandleFunc("/conformance/chunked", conformanceChunked)
	mux.HandleFunc("/conformance/redirect-absolute", conformanceRedirectAbsolute(selfAddr))
	mux.HandleFunc("/conformance/redirect-relative", conformanceRedirectRelative)
	mux.HandleFunc("/conformance/echo", conformanceEchoHandler)
	mux.HandleFunc("/conformance/post-echo", conformancePostEcho)
	mux.HandleFunc("/conformance/empty", conformanceEmpty)
	mux.HandleFunc("/conformance/large-body", conformanceLargeBody)
	mux.HandleFunc("/conformance/slow", conformanceSlow)
	mux.HandleFunc("/conformance/binary", conformanceBinary)
	mux.HandleFunc("/conformance/set-cookie", conformanceSetCookie)
	mux.HandleFunc("/conformance/custom-headers", conformanceCustomHeaders)
	mux.HandleFunc("/conformance/cache", conformanceCache)
	mux.HandleFunc("/conformance/content-types/json", conformanceContentTypeJSON)
	mux.HandleFunc("/conformance/content-types/html", conformanceContentTypeHTML)
	mux.HandleFunc("/conformance/content-types/plain", conformanceContentTypePlain)
	mux.HandleFunc("/conformance/head", conformanceHead)
	mux.HandleFunc("/conformance/sse", conformanceSSE)

	// ── Envelope-based conformance endpoints (see requestEnvelope). ──
	// Registered after the legacy handlers so longest-prefix-wins routing
	// still sends each specific path to the correct handler.
	mux.HandleFunc("/conformance/resource", conformanceResource)
	mux.HandleFunc("/conformance/resource/1", conformanceResourceInstance)
	mux.HandleFunc("/conformance/content/form", conformanceContentForm)
	mux.HandleFunc("/conformance/content/multipart", conformanceContentMultipart)
	mux.HandleFunc("/conformance/content/xml", conformanceContentXML)
	mux.HandleFunc("/conformance/content/plain", conformanceContentPlain)
	mux.HandleFunc("/conformance/echo/body", conformanceEchoBody)
	mux.HandleFunc("/conformance/status/", conformanceStatus)
	mux.HandleFunc("/conformance/headers/echo", conformanceHeadersEcho)
	mux.HandleFunc("/conformance/headers/response", conformanceHeadersResponse)
	mux.HandleFunc("/conformance/encoding/identity", conformanceEncodingIdentity)
	mux.HandleFunc("/conformance/encoding/chunked", conformanceEncodingChunked)
	mux.HandleFunc("/conformance/encoding/empty-chunked", conformanceEncodingEmptyChunked)
	mux.HandleFunc("/conformance/query/echo", conformanceQueryEcho)
	mux.HandleFunc("/conformance/path/", conformancePath)
	mux.HandleFunc("/conformance/connection/alive", conformanceConnectionAlive)

	// Legacy echo handler used by every scenario that does not rely on
	// conformance endpoints.
	mux.HandleFunc("/", handler)

	fmt.Fprintf(os.Stderr, "upstream listening on %s\n", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}
