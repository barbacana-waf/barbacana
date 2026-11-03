package protections

import (
	"context"
	"net/http/httptest"
	"testing"
)

// The request target reaches Coraza as REQUEST_URI_RAW and inside
// REQUEST_LINE, so a fragment or a CONNECT authority must survive the
// trip through the inspection path instead of being rebuilt away.
func TestBuildInspectionURLKeepsRawTarget(t *testing.T) {
	cases := []struct {
		name   string
		method string
		target string
		want   string
	}{
		{"plain", "GET", "/a/b?x=1", "/a/b?x=1"},
		{"fragment in path", "GET", "/#fragment", "/#fragment"},
		{"empty fragment", "GET", "/a#", "/a#"},
		{"fragment after query", "GET", "/a?x=1#tag", "/a?x=1#tag"},
		{"query inside fragment", "GET", "/a#b?c=1", "/a#b?c=1"},
		{"encoded hash is not a fragment", "GET", "/a%23b", "/a%23b"},
		{"connect authority", "CONNECT", "www.coreruleset.org", "www.coreruleset.org"},
		{"connect authority with port", "CONNECT", "example.com:443", "example.com:443"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(tc.method, tc.target, nil)
			ctx := WithInspectionPath(context.Background(), NewInspectionPath(r))
			if got := BuildInspectionURL(ctx, r); got != tc.want {
				t.Errorf("BuildInspectionURL(%s %s) = %q, want %q", tc.method, tc.target, got, tc.want)
			}
		})
	}
}

// The fragment is kept out of Path and RawQuery so normalization stages
// work on the path the request actually names.
func TestNewInspectionPathSplitsFragment(t *testing.T) {
	r := httptest.NewRequest("GET", "/a/../b#c?d=1", nil)
	ip := NewInspectionPath(r)
	if ip.Path != "/a/../b" || ip.RawQuery != "" || ip.Fragment != "#c?d=1" {
		t.Errorf("got Path=%q RawQuery=%q Fragment=%q, want %q %q %q",
			ip.Path, ip.RawQuery, ip.Fragment, "/a/../b", "", "#c?d=1")
	}
}
