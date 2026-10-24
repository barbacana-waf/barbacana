package crs

import (
	"context"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/barbacana-waf/barbacana/internal/config"
)

// crsRestrictedHeadersBasic mirrors CRS's own default. If a CRS upgrade
// changes rule 901165, this fails so the list is reviewed rather than
// silently pinned to the old one.
func TestCRSRestrictedHeadersBasicMatchesEmbeddedDefault(t *testing.T) {
	data, err := FS.ReadFile("rules/REQUEST-901-INITIALIZATION.conf")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`id:901165,[^"]*?setvar:'tx\.restricted_headers_basic=([^']+)'`).FindSubmatch(data)
	if m == nil {
		t.Fatal("rule 901165 not found in embedded CRS")
	}
	var want []string
	for _, h := range strings.Fields(string(m[1])) {
		want = append(want, strings.Trim(h, "/"))
	}
	if strings.Join(want, " ") != strings.Join(crsRestrictedHeadersBasic, " ") {
		t.Errorf("crsRestrictedHeadersBasic = %v, embedded CRS default = %v", crsRestrictedHeadersBasic, want)
	}
}

func TestRestrictedHeadersBasic(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*config.Resolved)
		wantIn  []string
		wantOut []string
	}{
		{
			name:    "default drops only expect",
			mutate:  func(*config.Resolved) {},
			wantIn:  []string{"/proxy/", "/if/", "/lock-token/", "/content-range/", "/x-middleware-subrequest/", "/x-http-method-override/"},
			wantOut: []string{"/expect/"},
		},
		{
			name: "method override disabled drops the override headers",
			mutate: func(r *config.Resolved) {
				r.Disable["http-compliance-method-override-param"] = true
			},
			wantIn:  []string{"/proxy/", "/if/"},
			wantOut: []string{"/expect/", "/x-http-method-override/", "/x-http-method/", "/x-method-override/"},
		},
		{
			name: "LOCK accepted drops if and lock-token",
			mutate: func(r *config.Resolved) {
				r.Accept.Methods = []string{"GET", "lock"}
			},
			wantIn:  []string{"/proxy/", "/content-range/", "/x-middleware-subrequest/"},
			wantOut: []string{"/expect/", "/if/", "/lock-token/"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			route := testRoute()
			tt.mutate(&route)
			got := " " + restrictedHeadersBasic(route) + " "
			for _, h := range tt.wantIn {
				if !strings.Contains(got, " "+h+" ") {
					t.Errorf("list %q is missing %s", got, h)
				}
			}
			for _, h := range tt.wantOut {
				if strings.Contains(got, " "+h+" ") {
					t.Errorf("list %q should not contain %s", got, h)
				}
			}
		})
	}
}

// evaluateHeader runs a small request carrying one extra header through the
// engine and reports whether the engine would block it.
func evaluateHeader(t *testing.T, route config.Resolved, method, name, value string) (blocked bool, protections []string) {
	t.Helper()
	eng, err := NewEngine(route)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	body := "a=1"
	r := httptest.NewRequest(method, "/x", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("User-Agent", "curl/8")
	r.Header.Set("Accept", "*/*")
	r.Header.Set("Content-Length", "3")
	r.Header.Set(name, value)
	res := eng.Evaluate(context.Background(), r)
	for _, d := range res.Decisions {
		if d.Block {
			blocked = true
			protections = append(protections, d.Protection)
		}
	}
	return blocked, protections
}

func TestExpectHeaderAllowed(t *testing.T) {
	route := testRoute()
	route.Accept.Methods = []string{"GET", "POST"}
	if blocked, p := evaluateHeader(t, route, "POST", "Expect", "100-continue"); blocked {
		t.Errorf("Expect: 100-continue was blocked by %v", p)
	}
}

func TestOtherRestrictedHeadersStillBlocked(t *testing.T) {
	route := testRoute()
	route.Accept.Methods = []string{"GET", "POST"}
	for _, h := range []struct{ name, value string }{
		{"Proxy", "http://evil.example:8080"},
		{"Content-Range", "bytes 0-1/2"},
		{"X-Middleware-Subrequest", "middleware"},
		{"If", "(<opaquelocktoken:x>)"},
		{"Lock-Token", "<opaquelocktoken:x>"},
		{"X-HTTP-Method-Override", "DELETE"},
	} {
		t.Run(h.name, func(t *testing.T) {
			if blocked, _ := evaluateHeader(t, route, "POST", h.name, h.value); !blocked {
				t.Errorf("%s was not blocked", h.name)
			}
		})
	}
}

func TestWebDAVLockHeadersAllowedWhenLockAccepted(t *testing.T) {
	route := testRoute()
	route.Accept.Methods = []string{"GET", "POST", "PUT", "LOCK", "UNLOCK"}
	for _, h := range []struct{ method, name, value string }{
		{"UNLOCK", "Lock-Token", "<opaquelocktoken:x>"},
		{"PUT", "If", "(<opaquelocktoken:x>)"},
	} {
		t.Run(h.name, func(t *testing.T) {
			if blocked, p := evaluateHeader(t, route, h.method, h.name, h.value); blocked {
				t.Errorf("%s %s was blocked by %v", h.method, h.name, p)
			}
		})
	}
	// The rest of the list stays in force on a WebDAV route.
	if blocked, _ := evaluateHeader(t, route, "PUT", "Proxy", "http://evil.example:8080"); !blocked {
		t.Error("Proxy header was not blocked on a WebDAV route")
	}
}
