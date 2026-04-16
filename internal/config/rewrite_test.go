package config

import "testing"

func TestRewritePath(t *testing.T) {
	cases := []struct {
		name    string
		rw      *RewriteCfg
		path    string
		want    string
	}{
		{"nil rewrite", nil, "/api/users", "/api/users"},
		{"strip prefix", &RewriteCfg{StripPrefix: "/api/v1"}, "/api/v1/users", "/users"},
		{"strip and add", &RewriteCfg{StripPrefix: "/api", AddPrefix: "/v2"}, "/api/users", "/v2/users"},
		{"full path override", &RewriteCfg{Path: "/health", StripPrefix: "/api"}, "/api/anything", "/health"},
		{"strip to root", &RewriteCfg{StripPrefix: "/api"}, "/api", "/"},
		{"no match strip", &RewriteCfg{StripPrefix: "/other"}, "/api/users", "/api/users"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := RewritePath(tc.rw, tc.path)
			if got != tc.want {
				t.Errorf("RewritePath(%+v, %q) = %q, want %q", tc.rw, tc.path, got, tc.want)
			}
		})
	}
}
