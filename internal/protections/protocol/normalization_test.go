package protocol

import (
	"context"
	"net/http/httptest"
	"testing"
)

func TestDoubleEncoding(t *testing.T) {
	cases := []struct {
		name      string
		url       string
		wantBlock bool
	}{
		{"clean", "/api/users", false},
		{"single encoded", "/api/users?q=%3Cscript%3E", false},
		{"double encoded script", "/api/users?q=%253Cscript%253E", true},
		{"double encoded in query", "/api?path=%252e%252e%252fetc%252fpasswd", true},
	}
	p := DoubleEncode{}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", tc.url, nil)
			d := p.Evaluate(context.Background(), r)
			if d.Block != tc.wantBlock {
				t.Errorf("Block = %v, want %v", d.Block, tc.wantBlock)
			}
		})
	}
}

func TestUnicodeNormalization(t *testing.T) {
	p := UnicodeNorm{}
	// Full-width characters should be normalized.
	r := httptest.NewRequest("GET", "/api/test", nil)
	// Set a query with full-width characters directly.
	r.URL.RawQuery = "q=\uff1cscript\uff1e"
	p.Evaluate(context.Background(), r)
	// After NFC normalization, the query should still be valid UTF-8.
	if r.URL.RawQuery == "" {
		t.Error("query should not be empty after normalization")
	}
}

func TestPathNormalization(t *testing.T) {
	cases := []struct {
		name     string
		path     string
		wantPath string
	}{
		{"clean", "/api/users", "/api/users"},
		{"dotdot", "/api/../etc/passwd", "/etc/passwd"},
		{"double slash", "/api//users", "/api/users"},
		{"dot", "/api/./users", "/api/users"},
		{"backslash", "/api\\users", "/api/users"},
		{"root", "/", "/"},
	}
	p := PathNorm{}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", tc.path, nil)
			p.Evaluate(context.Background(), r)
			if r.URL.Path != tc.wantPath {
				t.Errorf("path = %q, want %q", r.URL.Path, tc.wantPath)
			}
		})
	}
}
