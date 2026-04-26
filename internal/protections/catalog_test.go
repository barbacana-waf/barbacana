package protections

import (
	"net/http"
	"testing"
)

func TestCatalogResponseCategories(t *testing.T) {
	cat := Catalog()

	webShellSubs, ok := cat["web-shell"]
	if !ok {
		t.Fatal("catalog missing web-shell category")
	}
	if len(webShellSubs) != 1 || webShellSubs[0] != "web-shell-detection" {
		t.Errorf("web-shell subs = %v, want [web-shell-detection]", webShellSubs)
	}

	rubySubs, ok := cat["data-leakage-ruby"]
	if !ok {
		t.Fatal("catalog missing data-leakage-ruby category")
	}
	if len(rubySubs) != 1 || rubySubs[0] != "data-leakage-ruby" {
		t.Errorf("data-leakage-ruby subs = %v, want [data-leakage-ruby]", rubySubs)
	}
}

func TestCWEForNewCategories(t *testing.T) {
	cases := []struct {
		name string
		want string
	}{
		{"web-shell-detection", "CWE-506"},
		{"data-leakage-ruby", "CWE-209"},
	}
	for _, tc := range cases {
		if got := CWEForProtection(tc.name); got != tc.want {
			t.Errorf("CWEForProtection(%q) = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestAllNamesIncludesNewCategories(t *testing.T) {
	all := AllNames()
	for _, name := range []string{
		"web-shell",
		"web-shell-detection",
		"data-leakage-ruby",
	} {
		if !all[name] {
			t.Errorf("AllNames missing %q", name)
		}
	}
}

func TestExpandDisableWebShellCategory(t *testing.T) {
	disabled := ExpandDisable([]string{"web-shell"})
	if !disabled["web-shell"] {
		t.Error("web-shell category should be in disabled set")
	}
	if !disabled["web-shell-detection"] {
		t.Error("web-shell-detection sub-protection should be disabled via category")
	}
}

func TestExpandDisableDataLeakageRuby(t *testing.T) {
	disabled := ExpandDisable([]string{"data-leakage-ruby"})
	if !disabled["data-leakage-ruby"] {
		t.Error("data-leakage-ruby should be in disabled set")
	}
}

func TestExpandDisableSubOnlyDoesNotEnableCategory(t *testing.T) {
	disabled := ExpandDisable([]string{"sql-injection-union"})
	if !disabled["sql-injection-union"] {
		t.Error("directly disabled sub-protection should be in set")
	}
	if disabled["sql-injection"] {
		t.Error("parent category should NOT be disabled when only a sub is listed")
	}
	if disabled["sql-injection-blind"] {
		t.Error("sibling should NOT be disabled")
	}
}

func TestIsDisabled(t *testing.T) {
	disabled := map[string]bool{"null-byte-injection": true}
	if !IsDisabled("null-byte-injection", disabled) {
		t.Error("should be disabled")
	}
	if IsDisabled("crlf-injection", disabled) {
		t.Error("should not be disabled")
	}
}

func TestStatusFor(t *testing.T) {
	cases := []struct {
		name string
		want int
	}{
		// Default-403: any protection that does not declare a custom Status.
		{"sql-injection-union", http.StatusForbidden},
		{"crlf-injection", http.StatusForbidden},
		{"json-depth-limit", http.StatusForbidden},

		// Request-validation protections with custom status codes.
		{"max-body-size", http.StatusRequestEntityTooLarge},
		{"max-url-length", http.StatusRequestURITooLong},
		{"max-header-size", http.StatusRequestHeaderFieldsTooLarge},
		{"max-header-count", http.StatusRequestHeaderFieldsTooLarge},
		{"allowed-methods", http.StatusMethodNotAllowed},
		{"require-host-header", http.StatusBadRequest},
		{"require-content-type", http.StatusUnsupportedMediaType},

		// OpenAPI protections with custom status codes.
		{"openapi-path", http.StatusNotFound},
		{"openapi-method", http.StatusMethodNotAllowed},
		{"openapi-params", http.StatusUnprocessableEntity},
		{"openapi-body", http.StatusUnprocessableEntity},
		{"openapi-content-type", http.StatusUnsupportedMediaType},

		// Unknown name falls back to 403.
		{"not-a-real-protection", http.StatusForbidden},
		{"", http.StatusForbidden},
	}
	for _, tc := range cases {
		if got := StatusFor(tc.name); got != tc.want {
			t.Errorf("StatusFor(%q) = %d, want %d", tc.name, got, tc.want)
		}
	}
}
