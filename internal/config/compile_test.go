package config

import (
	"encoding/json"
	"testing"
)

func TestCompileRewriteStripPrefix(t *testing.T) {
	c := &Config{
		Version: "v1alpha1",
		Listen:  ":8080",
		Routes: []Route{{
			Upstream:        "http://app:8000",
			UpstreamTimeout: "30s",
			Rewrite:         &RewriteCfg{StripPrefix: "/api/v1"},
		}},
	}
	raw, err := Compile(c, nil)
	if err != nil {
		t.Fatal(err)
	}

	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}

	routes := extractRoutes(t, got)
	if len(routes) == 0 {
		t.Fatal("no routes")
	}
	handle := routes[0]["handle"].([]any)
	// First handler should be the rewrite with strip_path_prefix.
	first := handle[0].(map[string]any)
	if first["handler"] != "rewrite" {
		t.Errorf("first handler = %q, want rewrite", first["handler"])
	}
	if first["strip_path_prefix"] != "/api/v1" {
		t.Errorf("strip_path_prefix = %v", first["strip_path_prefix"])
	}
}

func TestCompileRewriteFullPath(t *testing.T) {
	c := &Config{
		Version: "v1alpha1",
		Listen:  ":8080",
		Routes: []Route{{
			Upstream:        "http://app:8000",
			UpstreamTimeout: "30s",
			Rewrite:         &RewriteCfg{Path: "/health"},
		}},
	}
	raw, err := Compile(c, nil)
	if err != nil {
		t.Fatal(err)
	}

	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}

	routes := extractRoutes(t, got)
	handle := routes[0]["handle"].([]any)
	first := handle[0].(map[string]any)
	if first["handler"] != "rewrite" {
		t.Errorf("first handler = %q, want rewrite", first["handler"])
	}
	if first["uri"] != "/health" {
		t.Errorf("uri = %v", first["uri"])
	}
}

func TestCompileRewriteStripAndAdd(t *testing.T) {
	c := &Config{
		Version: "v1alpha1",
		Listen:  ":8080",
		Routes: []Route{{
			Upstream:        "http://app:8000",
			UpstreamTimeout: "30s",
			Rewrite:         &RewriteCfg{StripPrefix: "/api", AddPrefix: "/v2"},
		}},
	}
	raw, err := Compile(c, nil)
	if err != nil {
		t.Fatal(err)
	}

	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}

	routes := extractRoutes(t, got)
	handle := routes[0]["handle"].([]any)
	// Should have two rewrite handlers (strip then add) + reverse_proxy.
	if len(handle) < 3 {
		t.Fatalf("expected at least 3 handlers, got %d", len(handle))
	}
}

func extractRoutes(t *testing.T, cfg map[string]any) []map[string]any {
	t.Helper()
	apps := cfg["apps"].(map[string]any)
	httpApp := apps["http"].(map[string]any)
	servers := httpApp["servers"].(map[string]any)
	proxy := servers["proxy"].(map[string]any)
	routes := proxy["routes"].([]any)
	result := make([]map[string]any, len(routes))
	for i, r := range routes {
		result[i] = r.(map[string]any)
	}
	return result
}
