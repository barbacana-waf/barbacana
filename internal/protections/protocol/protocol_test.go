package protocol

import (
	"context"
	"net/http/httptest"
	"testing"
)

func TestSmuggling(t *testing.T) {
	cases := []struct {
		name      string
		headers   map[string]string
		wantBlock bool
	}{
		{"clean GET", nil, false},
		{"CL only", map[string]string{"Content-Length": "10"}, false},
		{"TE only", map[string]string{"Transfer-Encoding": "chunked"}, false},
		{"both CL and TE", map[string]string{
			"Content-Length":    "10",
			"Transfer-Encoding": "chunked",
		}, true},
	}
	p := Smuggling{}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", "/", nil)
			for k, v := range tc.headers {
				r.Header.Set(k, v)
			}
			d := p.Evaluate(context.Background(), r)
			if d.Block != tc.wantBlock {
				t.Errorf("Block = %v, want %v", d.Block, tc.wantBlock)
			}
		})
	}
}

func TestCRLF(t *testing.T) {
	cases := []struct {
		name      string
		url       string
		header    [2]string
		wantBlock bool
	}{
		{"clean", "/api/users", [2]string{}, false},
		{"crlf in query", "/api?x=a%0d%0ab", [2]string{}, true},
		{"cr in query", "/api?x=a%0db", [2]string{}, true},
		{"lf in query", "/api?x=a%0ab", [2]string{}, true},
		{"crlf in header", "/api", [2]string{"X-Foo", "bar\r\nbaz"}, true},
	}
	p := CRLF{}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", tc.url, nil)
			if tc.header[0] != "" {
				r.Header.Set(tc.header[0], tc.header[1])
			}
			d := p.Evaluate(context.Background(), r)
			if d.Block != tc.wantBlock {
				t.Errorf("Block = %v, want %v (reason=%q)", d.Block, tc.wantBlock, d.Reason)
			}
		})
	}
}

func TestNullByte(t *testing.T) {
	cases := []struct {
		name      string
		url       string
		header    [2]string
		wantBlock bool
	}{
		{"clean", "/api/users", [2]string{}, false},
		{"encoded null in query", "/api?id=1%00", [2]string{}, true},
		{"null in header", "/api", [2]string{"X-Foo", "bar\x00"}, true},
	}
	p := NullByte{}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", tc.url, nil)
			if tc.header[0] != "" {
				r.Header.Set(tc.header[0], tc.header[1])
			}
			d := p.Evaluate(context.Background(), r)
			if d.Block != tc.wantBlock {
				t.Errorf("Block = %v, want %v (reason=%q)", d.Block, tc.wantBlock, d.Reason)
			}
		})
	}
}

func TestMethodOverride(t *testing.T) {
	p := MethodOverrideStrip{}
	r := httptest.NewRequest("POST", "/api", nil)
	r.Header.Set("X-HTTP-Method-Override", "DELETE")
	r.Header.Set("X-Method-Override", "PUT")
	r.Header.Set("X-HTTP-Method", "PATCH")

	d := p.Evaluate(context.Background(), r)
	if d.Block {
		t.Error("method-override should not block")
	}
	if r.Header.Get("X-HTTP-Method-Override") != "" {
		t.Error("X-HTTP-Method-Override should be stripped")
	}
	if r.Header.Get("X-Method-Override") != "" {
		t.Error("X-Method-Override should be stripped")
	}
	if r.Header.Get("X-HTTP-Method") != "" {
		t.Error("X-HTTP-Method should be stripped")
	}
}
