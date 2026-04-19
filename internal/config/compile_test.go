package config

import (
	"encoding/json"
	"testing"
)

func TestCompileRewriteStripPrefix(t *testing.T) {
	c := &Config{
		Version: "v1alpha1",
		Port:    8080,
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
		Port:    8080,
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
		Port:    8080,
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

func TestCompileStorageDefault(t *testing.T) {
	c := &Config{Version: "v1alpha1"}
	c.Routes = []Route{{Upstream: "http://app:8000", UpstreamTimeout: "30s"}}
	applyDefaults(c)

	raw, err := Compile(c, nil)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	storage, ok := got["storage"].(map[string]any)
	if !ok {
		t.Fatal("storage block missing from compiled config")
	}
	if storage["module"] != "file_system" {
		t.Errorf("storage.module = %v, want file_system", storage["module"])
	}
	if storage["root"] != "/data/barbacana" {
		t.Errorf("storage.root = %v, want /data/barbacana", storage["root"])
	}
}

func TestCompileStorageOverride(t *testing.T) {
	c := &Config{Version: "v1alpha1", DataDir: "/var/lib/barbacana"}
	c.Routes = []Route{{Upstream: "http://app:8000", UpstreamTimeout: "30s"}}
	applyDefaults(c)

	raw, err := Compile(c, nil)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	storage := got["storage"].(map[string]any)
	if storage["root"] != "/var/lib/barbacana" {
		t.Errorf("storage.root = %v, want /var/lib/barbacana", storage["root"])
	}
}

func TestCompileMode1SingleHost(t *testing.T) {
	c := &Config{Version: "v1alpha1", Host: "api.example.com"}
	c.Routes = []Route{{Upstream: "http://app:8000", UpstreamTimeout: "30s"}}
	applyDefaults(c)

	raw, err := Compile(c, nil)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	server := got["apps"].(map[string]any)["http"].(map[string]any)["servers"].(map[string]any)["proxy"].(map[string]any)

	listen := server["listen"].([]any)
	want := map[string]bool{":443": true, ":80": true}
	if len(listen) != 2 || !want[listen[0].(string)] || !want[listen[1].(string)] {
		t.Errorf("mode 1 listen = %v, want [:443 :80]", listen)
	}
	if _, disabled := server["automatic_https"]; disabled {
		t.Error("mode 1 must not disable automatic_https")
	}

	routes := server["routes"].([]any)
	firstMatch := routes[0].(map[string]any)["match"].([]any)[0].(map[string]any)
	hosts, _ := firstMatch["host"].([]any)
	if len(hosts) != 1 || hosts[0] != "api.example.com" {
		t.Errorf("mode 1 should inject host matcher %q, got %v", "api.example.com", hosts)
	}
}

func TestCompileMode2MultiHost(t *testing.T) {
	c := &Config{Version: "v1alpha1"}
	c.Routes = []Route{
		{
			Upstream:        "http://api:8000",
			UpstreamTimeout: "30s",
			Match:           &Match{Hosts: []string{"api.example.com"}},
		},
		{
			Upstream:        "http://admin:8000",
			UpstreamTimeout: "30s",
			Match:           &Match{Hosts: []string{"admin.example.com"}},
		},
	}
	applyDefaults(c)

	raw, err := Compile(c, nil)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	server := got["apps"].(map[string]any)["http"].(map[string]any)["servers"].(map[string]any)["proxy"].(map[string]any)
	listen := server["listen"].([]any)
	if len(listen) != 2 {
		t.Errorf("mode 2 listen = %v, want [:443 :80]", listen)
	}
	if _, disabled := server["automatic_https"]; disabled {
		t.Error("mode 2 must not disable automatic_https")
	}
}

func TestCompileMode3PlainHTTP(t *testing.T) {
	c := &Config{Version: "v1alpha1", Port: 9000}
	c.Routes = []Route{{Upstream: "http://app:8000", UpstreamTimeout: "30s"}}
	applyDefaults(c)

	raw, err := Compile(c, nil)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	server := got["apps"].(map[string]any)["http"].(map[string]any)["servers"].(map[string]any)["proxy"].(map[string]any)
	listen := server["listen"].([]any)
	if len(listen) != 1 || listen[0] != ":9000" {
		t.Errorf("mode 3 listen = %v, want [:9000]", listen)
	}
	autoHTTPS, ok := server["automatic_https"].(map[string]any)
	if !ok || autoHTTPS["disable"] != true {
		t.Errorf("mode 3 must set automatic_https.disable=true, got %v", server["automatic_https"])
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
