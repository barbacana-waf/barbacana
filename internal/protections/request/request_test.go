package request

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/barbacana-waf/barbacana/internal/config"
)

func testCfg() config.Resolved {
	return config.Resolved{
		ID:      "test",
		Mode:    config.ModeBlocking,
		Disable: map[string]bool{},
		Accept: config.ResolvedAccept{
			Methods:           []string{"GET", "POST", "PUT", "DELETE"},
			ContentTypes:      []string{},
			MaxBodySize:       10 * 1024 * 1024,
			MaxURLLength:      8192,
			MaxHeaderSize:     16 * 1024,
			MaxHeaderCount:    100,
			RequireHostHeader: true,
		},
		Inspection: config.ResolvedInspection{
			JSONDepth:         20,
			JSONKeys:          1000,
			XMLDepth:          20,
			XMLEntities:       100,
			EvaluationTimeout: 50 * time.Millisecond,
		},
		Protocol:           config.ResolvedProtocol{},
		RunJSONParser:      true,
		RunXMLParser:       true,
		RunMultipartParser: true,
		RunFormParser:      true,
	}
}

func TestAllowedMethods(t *testing.T) {
	v := NewValidator(testCfg())
	r := httptest.NewRequest("TRACE", "/", nil)
	d := v.ValidateRequest(context.Background(), r)
	if !d.Block || d.Protection != AllowedMethods {
		t.Errorf("expected TRACE blocked, got: %+v", d)
	}
}

func TestAllowedMethodPass(t *testing.T) {
	v := NewValidator(testCfg())
	r := httptest.NewRequest("GET", "/api", nil)
	r.Header.Set("Host", "example.com")
	d := v.ValidateRequest(context.Background(), r)
	if d.Block {
		t.Errorf("GET should pass, got: %+v", d)
	}
}

func TestBodySize(t *testing.T) {
	cfg := testCfg()
	cfg.Accept.MaxBodySize = 100
	v := NewValidator(cfg)
	body := strings.NewReader(strings.Repeat("x", 200))
	r := httptest.NewRequest("POST", "/", body)
	r.Header.Set("Host", "example.com")
	r.Header.Set("Content-Type", "application/json")
	r.ContentLength = 200
	d := v.ValidateRequest(context.Background(), r)
	if !d.Block || d.Protection != MaxBodySize {
		t.Errorf("expected body size block, got: %+v", d)
	}
}

func TestURLLength(t *testing.T) {
	cfg := testCfg()
	cfg.Accept.MaxURLLength = 50
	v := NewValidator(cfg)
	r := httptest.NewRequest("GET", "/"+strings.Repeat("a", 100), nil)
	r.Header.Set("Host", "example.com")
	d := v.ValidateRequest(context.Background(), r)
	if !d.Block || d.Protection != MaxURLLength {
		t.Errorf("expected URL length block, got: %+v", d)
	}
}

func TestHeaderCount(t *testing.T) {
	cfg := testCfg()
	cfg.Accept.MaxHeaderCount = 5
	v := NewValidator(cfg)
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Host", "example.com")
	for i := 0; i < 10; i++ {
		r.Header.Add("X-Test", "value")
	}
	d := v.ValidateRequest(context.Background(), r)
	if !d.Block || d.Protection != MaxHeaderCount {
		t.Errorf("expected header count block, got: %+v", d)
	}
}

func TestContentTypeGating(t *testing.T) {
	cfg := testCfg()
	cfg.Accept.ContentTypes = []string{"application/json"}
	v := NewValidator(cfg)
	r := httptest.NewRequest("POST", "/", strings.NewReader("<xml/>"))
	r.Header.Set("Host", "example.com")
	r.Header.Set("Content-Type", "application/xml")
	r.ContentLength = 6
	d := v.ValidateRequest(context.Background(), r)
	if !d.Block {
		t.Error("expected XML content-type to be rejected for JSON-only route")
	}
}

func TestJSONDepthLimit(t *testing.T) {
	cfg := testCfg()
	cfg.Inspection.JSONDepth = 3
	v := NewValidator(cfg)
	deep := `{"a":{"b":{"c":{"d":"e"}}}}`
	d := v.ValidateJSONBody(context.Background(), []byte(deep))
	if !d.Block || d.Protection != JSONDepthLimit {
		t.Errorf("expected JSON depth block, got: %+v", d)
	}
}

func TestJSONDepthOK(t *testing.T) {
	v := NewValidator(testCfg())
	simple := `{"a":"b","c":"d"}`
	d := v.ValidateJSONBody(context.Background(), []byte(simple))
	if d.Block {
		t.Errorf("simple JSON should pass, got: %+v", d)
	}
}

func TestXMLDepthLimit(t *testing.T) {
	cfg := testCfg()
	cfg.Inspection.XMLDepth = 2
	v := NewValidator(cfg)
	deep := `<a><b><c><d>e</d></c></b></a>`
	d := v.ValidateXMLBody(context.Background(), []byte(deep))
	if !d.Block || d.Protection != XMLDepthLimit {
		t.Errorf("expected XML depth block, got: %+v", d)
	}
}

func TestJSONOnlyRouteSkipsXML(t *testing.T) {
	cfg := testCfg()
	cfg.RunXMLParser = false
	v := NewValidator(cfg)
	deep := `<a><b><c><d>e</d></c></b></a>`
	d := v.ValidateXMLBody(context.Background(), []byte(deep))
	if d.Block {
		t.Error("XML should not be parsed on JSON-only route")
	}
}
