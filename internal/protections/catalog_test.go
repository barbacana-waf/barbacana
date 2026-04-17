package protections

import "testing"

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
