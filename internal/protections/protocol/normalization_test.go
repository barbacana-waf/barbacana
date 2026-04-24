package protocol

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/barbacana-waf/barbacana/internal/protections"
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
	r := httptest.NewRequest("GET", "/api/test", nil)
	// Full-width characters should be NFC-normalized in the inspection
	// path, not in r.URL — the upstream must still receive the original
	// bytes.
	r.URL.RawQuery = "q=＜script＞"
	originalQuery := r.URL.RawQuery

	ip := protections.NewInspectionPath(r)
	ctx := protections.WithInspectionPath(context.Background(), ip)

	p.Evaluate(ctx, r)

	if r.URL.RawQuery != originalQuery {
		t.Errorf("r.URL.RawQuery was mutated (%q → %q); normalization must stay out of the proxy path",
			originalQuery, r.URL.RawQuery)
	}
	if ip.RawQuery == "" {
		t.Error("inspection query should not be empty after normalization")
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
		// Detection-only: the trailing slash must stay on r.URL so the
		// upstream sees it, even though the canonical form does not
		// carry it.
		{"trailing slash", "/api/users/", "/api/users"},
	}
	p := PathNorm{}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", tc.path, nil)
			originalPath := r.URL.Path

			ip := protections.NewInspectionPath(r)
			ctx := protections.WithInspectionPath(context.Background(), ip)

			p.Evaluate(ctx, r)

			if ip.Path != tc.wantPath {
				t.Errorf("inspection path = %q, want %q", ip.Path, tc.wantPath)
			}
			if r.URL.Path != originalPath {
				t.Errorf("r.URL.Path was mutated (%q → %q); normalization is inspection-only",
					originalPath, r.URL.Path)
			}
		})
	}
}
