package crs

import (
	"context"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/barbacana-waf/barbacana/internal/config"
)

// bodyResult runs one request through the engine and returns the protections
// that blocked it.
func bodyResult(t *testing.T, route config.Resolved, method, contentType, body string) []string {
	t.Helper()
	eng, err := NewEngine(route)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	r := httptest.NewRequest(method, "/x", strings.NewReader(body))
	r.Header.Set("Content-Type", contentType)
	r.Header.Set("User-Agent", "curl/8")
	r.Header.Set("Accept", "*/*")
	r.Header.Set("Content-Length", fmt.Sprint(len(body)))
	var blocked []string
	for _, d := range eng.Evaluate(context.Background(), r).Decisions {
		if d.Block {
			blocked = append(blocked, d.Protection)
		}
	}
	return blocked
}

func bodyRoute() config.Resolved {
	route := testRoute()
	route.Accept.Methods = []string{"GET", "POST", "PUT", "PROPFIND", "LOCK"}
	return route
}

// Without parser selection Coraza reads an XML body as URL-encoded form data,
// and `<?xml version="1.0"` becomes a field named `<?xml version` that XSS
// rule 941100 blocks. Every XML API failed for that reason.
func TestXMLBodiesParseAsXML(t *testing.T) {
	const propfind = `<?xml version="1.0" encoding="UTF-8"?>
<d:propfind xmlns:d="DAV:"><d:prop><d:getlastmodified/><d:resourcetype/></d:prop></d:propfind>`

	for _, tt := range []struct{ name, method, contentType, body string }{
		{"PROPFIND with declaration", "PROPFIND", "application/xml; charset=utf-8", propfind},
		{"text/xml", "POST", "text/xml", `<?xml version="1.0"?><a><b>hello world</b></a>`},
		{"+xml suffix", "POST", "application/atom+xml", `<?xml version="1.0"?><feed><title>x</title></feed>`},
		{"soap+xml", "POST", "application/soap+xml", `<?xml version="1.0"?><e><b>x</b></e>`},
		{"upper-case content type", "POST", "Application/XML", `<?xml version="1.0"?><a>x</a>`},
		{"HTML entity in text", "POST", "application/xml", `<a>hello&nbsp;world</a>`},
		{"empty body", "PROPFIND", "application/xml", ``},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if blocked := bodyResult(t, bodyRoute(), tt.method, tt.contentType, tt.body); len(blocked) > 0 {
				t.Errorf("clean XML blocked by %v", blocked)
			}
		})
	}
}

func TestJSONBodiesParseAsJSON(t *testing.T) {
	for _, tt := range []struct{ name, contentType, body string }{
		{"object", "application/json", `{"name":"alice","n":[1,2,{"k":"v"}]}`},
		{"charset", "application/json; charset=utf-8", `{"a":"b"}`},
		{"array", "application/json", `[1,2,3]`},
		{"scalar", "application/json", `"hello"`},
		{"empty object", "application/json", `{}`},
		{"+json suffix", "application/vnd.api+json", `{"data":{"id":"1"}}`},
		{"empty body", "application/json", ``},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if blocked := bodyResult(t, bodyRoute(), "POST", tt.contentType, tt.body); len(blocked) > 0 {
				t.Errorf("clean JSON blocked by %v", blocked)
			}
		})
	}
}

// Selecting the structured parsers must not cost detection: payloads in XML
// text, attributes, CDATA and in JSON keys and nested values stay blocked.
func TestAttacksInParsedBodiesStillBlocked(t *testing.T) {
	const sqli = "1 UNION SELECT password FROM users"
	for _, tt := range []struct{ name, contentType, body string }{
		{"xml text sqli", "application/xml", `<a><b>` + sqli + `</b></a>`},
		{"xml attribute sqli", "application/xml", `<a id="1' OR '1'='1' --"/>`},
		{"xml cdata sqli", "application/xml", `<a><![CDATA[` + sqli + `]]></a>`},
		{"xml xss", "application/xml", `<a><b><script>alert(1)</script></b></a>`},
		{"xml entity-encoded xss", "application/xml", `<a>&lt;script&gt;alert(1)&lt;/script&gt;</a>`},
		{"xml path traversal", "application/xml", `<a>../../../../etc/passwd</a>`},
		{"xml unclosed sqli", "application/xml", `<a><b>` + sqli},
		{"json value sqli", "application/json", `{"c":"` + sqli + `"}`},
		{"json key sqli", "application/json", `{"1' OR '1'='1' --":"x"}`},
		{"json nested sqli", "application/json", `{"a":{"b":["x",{"c":"` + sqli + `"}]}}`},
		{"json xss", "application/json", `{"c":"<script>alert(1)</script>"}`},
		{"json +json suffix sqli", "application/vnd.api+json", `{"c":"` + sqli + `"}`},
		{"urlencoded sqli", "application/x-www-form-urlencoded", `a=1+UNION+SELECT+password+FROM+users`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if blocked := bodyResult(t, bodyRoute(), "POST", tt.contentType, tt.body); len(blocked) == 0 {
				t.Error("attack was not blocked")
			}
		})
	}
}

// A body that does not parse as its declared type yields no variables under a
// structured parser, so the parse failure itself has to score. This is what
// keeps the parser selection from opening a way past the body rules.
func TestMalformedStructuredBodiesBlocked(t *testing.T) {
	for _, tt := range []struct{ name, contentType, body string }{
		{"json truncated", "application/json", `{"a":`},
		{"json plain text", "application/json", `not json`},
		{"json single quotes", "application/json", `{'a':1}`},
		{"json trailing comma", "application/json", `{"a":1,}`},
		{"json malformed with payload", "application/json", `{"c":"1 UNION SELECT password FROM users"`},
		{"xml mismatched tags", "application/xml", `<a></b>`},
		{"xml garbage with payload", "application/xml", `<<< 1 UNION SELECT password FROM users`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			blocked := bodyResult(t, bodyRoute(), "POST", tt.contentType, tt.body)
			found := false
			for _, p := range blocked {
				found = found || p == "http-compliance-malformed-body"
			}
			if !found {
				t.Errorf("blocked by %v, want http-compliance-malformed-body among them", blocked)
			}
		})
	}
}

// Only the declared JSON/XML types are held to a parse check. Bodies of other
// types behave as before.
func TestMalformedBodyCheckOnlyAppliesToJSONAndXML(t *testing.T) {
	for _, tt := range []struct{ name, contentType, body string }{
		{"plain text", "text/plain", `{"a":`},
		{"octet stream", "application/octet-stream", `<a></b>`},
		{"urlencoded", "application/x-www-form-urlencoded", `a=1&b=%zz`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if blocked := bodyResult(t, bodyRoute(), "POST", tt.contentType, tt.body); len(blocked) > 0 {
				t.Errorf("blocked by %v", blocked)
			}
		})
	}
}

func TestMalformedBodyLeafCanBeDisabled(t *testing.T) {
	route := bodyRoute()
	route.Disable["http-compliance-malformed-body"] = true
	if blocked := bodyResult(t, route, "POST", "application/json", `{"a":`); len(blocked) > 0 {
		t.Errorf("malformed JSON blocked by %v with the leaf disabled", blocked)
	}
}
