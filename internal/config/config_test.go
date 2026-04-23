package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestLoadMinimal(t *testing.T) {
	c := loadYAML(t, "version: v1alpha1\nroutes:\n  - upstream: http://app:8000\n")

	if c.Host != "" {
		t.Errorf("Host = %q, want empty (mode 3)", c.Host)
	}
	if c.Port != 8080 {
		t.Errorf("Port = %d, want 8080 (mode 3 default)", c.Port)
	}
	if c.HealthPort != 0 {
		t.Errorf("HealthPort = %d, want 0 (disabled by default)", c.HealthPort)
	}
	if c.MetricsPort != 0 {
		t.Errorf("MetricsPort = %d, want 0 (disabled by default)", c.MetricsPort)
	}
	if c.Global.Mode != ModeBlocking {
		t.Errorf("global.mode = %q, want %q (default)", c.Global.Mode, ModeBlocking)
	}
	if len(c.Routes) != 1 || c.Routes[0].Upstream != "http://app:8000" {
		t.Errorf("Routes = %+v", c.Routes)
	}
	// Verify defaults were applied to global
	if *c.Global.Inspection.JSONDepth != 20 {
		t.Errorf("inspection.json_depth = %d, want 20", *c.Global.Inspection.JSONDepth)
	}
	if c.Global.Protocol.ParameterPollution != "reject" {
		t.Errorf("protocol.parameter_pollution = %q, want reject", c.Global.Protocol.ParameterPollution)
	}
	if c.Global.ResponseHeaders.Preset != "moderate" {
		t.Errorf("response_headers.preset = %q, want moderate", c.Global.ResponseHeaders.Preset)
	}
}

func TestLoadFullConfig(t *testing.T) {
	yaml := `
version: v1alpha1
host: api.example.com

global:
  mode: blocking
  disable:
    - scanner-detection
  accept:
    methods: [GET, POST, PUT, DELETE]
    max_body_size: 50MB
  inspection:
    json_depth: 15
  response_headers:
    preset: custom
    inject:
      header-csp: "default-src 'self'"
    strip_extra:
      - X-Custom-Backend-Id

routes:
  - id: uploads
    match:
      paths: ["/upload/*"]
    upstream: http://uploads:8000
    accept:
      content_types: [multipart/form-data]
      max_body_size: 500MB
    multipart:
      file_limit: 50
      file_size: 100MB
      allowed_types:
        - image/png
        - image/jpeg
      double_extension: true
    inspection:
      max_inspect_size: 256KB
    disable:
      - xss-script-tag

  - id: graphql
    match:
      paths: ["/graphql"]
    upstream: http://gql:4000
    accept:
      content_types: [application/json]
    inspection:
      json_depth: 40
      json_keys: 5000
`
	c := loadYAML(t, yaml)

	if c.Global.Mode != ModeBlocking {
		t.Errorf("global.mode = %q, want %q", c.Global.Mode, ModeBlocking)
	}
	if len(c.Routes) != 2 {
		t.Fatalf("want 2 routes, got %d", len(c.Routes))
	}
	if c.Routes[0].ID != "uploads" {
		t.Errorf("route 0 id = %q", c.Routes[0].ID)
	}
	if c.Routes[1].ID != "graphql" {
		t.Errorf("route 1 id = %q", c.Routes[1].ID)
	}
}

func TestLoadMultiRoute(t *testing.T) {
	yaml := `
version: v1alpha1

global:
  mode: blocking

routes:
  - id: public-api
    match:
      hosts: [api.example.com]
      paths: ["/v1/*"]
    upstream: http://api-backend:8000
    accept:
      content_types: [application/json]
      methods: [GET, POST, PUT, DELETE]
    rewrite:
      strip_prefix: /v1

  - id: admin
    match:
      hosts: [admin.example.com]
    upstream: http://admin-backend:8000
    cors:
      allow_origins: ["https://admin.example.com"]
      allow_credentials: true

  - id: legacy-php
    match:
      hosts: [legacy.example.com]
      paths: ["/legacy/*"]
    upstream: http://legacy:80
    rewrite:
      strip_prefix: /legacy
      add_prefix: /app
    disable:
      - php-injection
      - null-byte-injection
    mode: detect_only
`
	c := loadYAML(t, yaml)
	if len(c.Routes) != 3 {
		t.Fatalf("want 3 routes, got %d", len(c.Routes))
	}
	// Mode 2: no top-level host, port unset.
	if c.Host != "" {
		t.Errorf("Host = %q, want empty (mode 2)", c.Host)
	}
	if c.Port != 0 {
		t.Errorf("Port = %d, want 0 (mode 2)", c.Port)
	}
}

func TestValidateRejectsWrongVersion(t *testing.T) {
	_, err := loadYAMLErr("version: v2\nroutes:\n  - upstream: http://app:8000\n")
	if err == nil {
		t.Fatal("expected version validation error")
	}
}

func TestValidateRejectsUnknownProtection(t *testing.T) {
	_, err := loadYAMLErr("version: v1alpha1\nroutes:\n  - upstream: http://app:8000\n    disable:\n      - sql-injetcion\n")
	if err == nil {
		t.Fatal("expected unknown protection error")
	}
	if !strings.Contains(err.Error(), "sql-injetcion") {
		t.Errorf("error should mention the bad name, got: %v", err)
	}
	if !strings.Contains(err.Error(), "sql-injection") {
		t.Errorf("error should suggest sql-injection, got: %v", err)
	}
}

func TestValidateRejectsBadBodySize(t *testing.T) {
	_, err := loadYAMLErr("version: v1alpha1\nroutes:\n  - upstream: http://app:8000\nglobal:\n  accept:\n    max_body_size: 2GB\n")
	if err == nil {
		t.Fatal("expected body size validation error")
	}
	if !strings.Contains(err.Error(), "max_body_size") {
		t.Errorf("error should mention max_body_size, got: %v", err)
	}
}

func TestValidateRejectsCORSWildcardWithCredentials(t *testing.T) {
	yaml := `
version: v1alpha1
routes:
  - upstream: http://app:8000
    cors:
      allow_origins: ["*"]
      allow_credentials: true
`
	_, err := loadYAMLErr(yaml)
	if err == nil {
		t.Fatal("expected CORS validation error")
	}
	if !strings.Contains(err.Error(), "allow_credentials") {
		t.Errorf("error should mention credentials, got: %v", err)
	}
}

func TestValidateRejectsInvalidPreset(t *testing.T) {
	yaml := `
version: v1alpha1
global:
  response_headers:
    preset: invalid
routes:
  - upstream: http://app:8000
`
	_, err := loadYAMLErr(yaml)
	if err == nil {
		t.Fatal("expected preset validation error")
	}
}

func TestResolveMinimal(t *testing.T) {
	c := loadYAML(t, "version: v1alpha1\nroutes:\n  - upstream: http://app:8000\n")
	routes, err := Resolve(c)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(routes) != 1 {
		t.Fatalf("want 1 resolved route, got %d", len(routes))
	}
	r := routes[0]
	if r.Mode != ModeBlocking {
		t.Errorf("resolved route should inherit mode=%q from global, got %q", ModeBlocking, r.Mode)
	}
	if r.Accept.MaxBodySize != 10*1024*1024 {
		t.Errorf("MaxBodySize = %d, want 10MB", r.Accept.MaxBodySize)
	}
	if r.UpstreamTimeout != 30*time.Second {
		t.Errorf("UpstreamTimeout = %v, want 30s", r.UpstreamTimeout)
	}
	if r.Inspection.EvaluationTimeout != 50*time.Millisecond {
		t.Errorf("EvaluationTimeout = %v, want 50ms", r.Inspection.EvaluationTimeout)
	}
}

func TestResolveContentTypeGating(t *testing.T) {
	yaml := `
version: v1alpha1
routes:
  - upstream: http://app:8000
    accept:
      content_types: [application/json]
`
	c := loadYAML(t, yaml)
	routes, err := Resolve(c)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	r := routes[0]
	if !r.RunJSONParser {
		t.Error("JSON parser should be active for JSON-only route")
	}
	if r.RunXMLParser {
		t.Error("XML parser should be inactive for JSON-only route")
	}
	if r.RunMultipartParser {
		t.Error("Multipart parser should be inactive for JSON-only route")
	}
}

func TestResolveContentTypeGatingAllParsers(t *testing.T) {
	c := loadYAML(t, "version: v1alpha1\nroutes:\n  - upstream: http://app:8000\n")
	routes, err := Resolve(c)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	r := routes[0]
	if !r.RunJSONParser || !r.RunXMLParser || !r.RunMultipartParser || !r.RunFormParser {
		t.Error("all parsers should be active when content_types is empty")
	}
}

func TestResolveDisableExpansion(t *testing.T) {
	yaml := `
version: v1alpha1
global:
  disable:
    - sql-injection
routes:
  - upstream: http://app:8000
    disable:
      - null-byte-injection
`
	c := loadYAML(t, yaml)
	routes, err := Resolve(c)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	r := routes[0]
	if !r.Disable["sql-injection"] {
		t.Error("category sql-injection should be disabled")
	}
	if !r.Disable["sql-injection-union"] {
		t.Error("sub-protection sql-injection-union should be disabled via category")
	}
	if !r.Disable["null-byte-injection"] {
		t.Error("null-byte-injection should be disabled via route disable")
	}
}

func TestCompileHasProxyServer(t *testing.T) {
	c := &Config{Version: "v1alpha1"}
	applyDefaults(c)
	c.Routes = []Route{{Upstream: "http://app:8000", UpstreamTimeout: "30s"}}

	raw, err := Compile(c, nil)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Apps struct {
			HTTP struct {
				Servers map[string]json.RawMessage `json:"servers"`
			} `json:"http"`
		} `json:"apps"`
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if _, ok := got.Apps.HTTP.Servers["proxy"]; !ok {
		t.Errorf("missing proxy server in compiled config")
	}
}

func TestDataDirDefault(t *testing.T) {
	c := &Config{Version: "v1alpha1"}
	applyDefaults(c)
	if c.DataDir != "/data/barbacana" {
		t.Errorf("DataDir = %q, want /data/barbacana", c.DataDir)
	}
}

func TestDataDirExplicitOverride(t *testing.T) {
	c := loadYAML(t, "version: v1alpha1\ndata_dir: /tmp/foo\nroutes:\n  - upstream: http://app:8000\n")
	if c.DataDir != "/tmp/foo" {
		t.Errorf("DataDir = %q, want /tmp/foo", c.DataDir)
	}
}

func TestValidateDataDirWritable(t *testing.T) {
	dir := t.TempDir()
	var errs []string
	validateDataDir(dir, &errs)
	if len(errs) != 0 {
		t.Errorf("writable dir should produce no errors, got: %v", errs)
	}
}

func TestValidateDataDirMissing(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist")
	var errs []string
	validateDataDir(missing, &errs)
	if len(errs) != 0 {
		t.Errorf("missing dir should warn (no errors), got: %v", errs)
	}
}

func TestValidateDataDirIsFile(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "regular-file")
	if err := os.WriteFile(filePath, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	var errs []string
	validateDataDir(filePath, &errs)
	if len(errs) == 0 {
		t.Fatal("expected error for non-directory path")
	}
	if !strings.Contains(errs[0], "is not a directory") {
		t.Errorf("error should mention 'is not a directory', got: %v", errs[0])
	}
}

func TestValidateDataDirNotWritable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("chmod semantics differ on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("root bypasses permission checks")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	var errs []string
	validateDataDir(dir, &errs)
	if len(errs) == 0 {
		t.Fatal("expected error for non-writable dir")
	}
	if !strings.Contains(errs[0], "not writable") {
		t.Errorf("error should mention 'not writable', got: %v", errs[0])
	}
}

func TestLoadModeSingleHost(t *testing.T) {
	c := loadYAML(t, "version: v1alpha1\nhost: api.example.com\nroutes:\n  - upstream: http://app:8000\n")
	if c.Host != "api.example.com" {
		t.Errorf("Host = %q, want api.example.com", c.Host)
	}
	if c.Port != 0 {
		t.Errorf("Port = %d, want 0 (mode 1)", c.Port)
	}
}

func TestLoadModeMultiHost(t *testing.T) {
	yaml := `
version: v1alpha1
routes:
  - match:
      hosts: [api.example.com]
    upstream: http://api:8000
  - match:
      hosts: [admin.example.com]
    upstream: http://admin:8000
`
	c := loadYAML(t, yaml)
	if c.Host != "" || c.Port != 0 {
		t.Errorf("mode 2 should leave Host and Port empty, got Host=%q Port=%d", c.Host, c.Port)
	}
}

func TestLoadModePlainHTTPExplicit(t *testing.T) {
	c := loadYAML(t, "version: v1alpha1\nport: 9000\nroutes:\n  - upstream: http://app:8000\n")
	if c.Port != 9000 {
		t.Errorf("Port = %d, want 9000", c.Port)
	}
}

func TestValidateRejectsHostAndPort(t *testing.T) {
	yaml := `
version: v1alpha1
host: api.example.com
port: 8080
routes:
  - upstream: http://app:8000
`
	_, err := loadYAMLErr(yaml)
	if err == nil {
		t.Fatal("expected error: host and port are mutually exclusive")
	}
	if !strings.Contains(err.Error(), `"host" and "port" are mutually exclusive`) {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidateRejectsHostAndRouteHosts(t *testing.T) {
	yaml := `
version: v1alpha1
host: api.example.com
routes:
  - id: api
    match:
      hosts: [other.example.com]
    upstream: http://app:8000
`
	_, err := loadYAMLErr(yaml)
	if err == nil {
		t.Fatal("expected error: host and match.hosts are mutually exclusive")
	}
	if !strings.Contains(err.Error(), `"host" and "match.hosts" on route "api"`) {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidateRejectsPortAndRouteHosts(t *testing.T) {
	yaml := `
version: v1alpha1
port: 8080
routes:
  - id: api
    match:
      hosts: [api.example.com]
    upstream: http://app:8000
`
	_, err := loadYAMLErr(yaml)
	if err == nil {
		t.Fatal("expected error: port and match.hosts are mutually exclusive")
	}
	if !strings.Contains(err.Error(), `"port" and "match.hosts" on route "api"`) {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidateRejectsOutOfRangePort(t *testing.T) {
	_, err := loadYAMLErr("version: v1alpha1\nport: 70000\nroutes:\n  - upstream: http://app:8000\n")
	if err == nil {
		t.Fatal("expected port range error")
	}
	if !strings.Contains(err.Error(), "port must be between 1 and 65535") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidateRejectsDuplicatePorts(t *testing.T) {
	yaml := `
version: v1alpha1
port: 8080
metrics_port: 8080
routes:
  - upstream: http://app:8000
`
	_, err := loadYAMLErr(yaml)
	if err == nil {
		t.Fatal("expected duplicate-port error")
	}
	if !strings.Contains(err.Error(), "port and metrics_port must differ") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestLoadObservabilityPortsOptIn(t *testing.T) {
	yaml := `
version: v1alpha1
port: 8080
metrics_port: 9090
health_port: 8081
routes:
  - upstream: http://app:8000
`
	c := loadYAML(t, yaml)
	if c.MetricsPort != 9090 {
		t.Errorf("MetricsPort = %d, want 9090", c.MetricsPort)
	}
	if c.HealthPort != 8081 {
		t.Errorf("HealthPort = %d, want 8081", c.HealthPort)
	}
}

func TestValidateRejectsPartialRouteHosts(t *testing.T) {
	yaml := `
version: v1alpha1
routes:
  - id: api
    match:
      hosts: [api.example.com]
    upstream: http://api:8000
  - id: uploads
    match:
      paths: ["/uploads/*"]
    upstream: http://uploads:8000
`
	_, err := loadYAMLErr(yaml)
	if err == nil {
		t.Fatal("expected error: every route must have match.hosts when any route does")
	}
	if !strings.Contains(err.Error(), `add match.hosts to route "uploads"`) {
		t.Errorf("error should tell the user to add match.hosts to the bare route, got: %v", err)
	}
	if !strings.Contains(err.Error(), `add "host" at the top level`) {
		t.Errorf("error should suggest top-level host as an alternative, got: %v", err)
	}
	if !strings.Contains(err.Error(), `"api"`) {
		t.Errorf("error should name the route that already has match.hosts, got: %v", err)
	}
}

func TestParseByteSize(t *testing.T) {
	cases := []struct {
		input string
		want  int64
	}{
		{"10MB", 10 * 1024 * 1024},
		{"16KB", 16 * 1024},
		{"128KB", 128 * 1024},
		{"1GB", 1024 * 1024 * 1024},
		{"512", 512},
		{"100B", 100},
	}
	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			got, err := parseByteSize(tc.input)
			if err != nil {
				t.Fatalf("parseByteSize(%q): %v", tc.input, err)
			}
			if got != tc.want {
				t.Errorf("parseByteSize(%q) = %d, want %d", tc.input, got, tc.want)
			}
		})
	}
}

func TestLevenshtein(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"sql-injection", "sql-injetcion", 2},
		{"xss", "xss", 0},
		{"abc", "def", 3},
	}
	for _, tc := range cases {
		got := levenshtein(tc.a, tc.b)
		if got != tc.want {
			t.Errorf("levenshtein(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

// helpers

func loadYAML(t *testing.T, content string) *Config {
	t.Helper()
	c, err := loadYAMLErr(content)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return c
}

func loadYAMLErr(content string) (*Config, error) {
	dir, err := os.MkdirTemp("", "barbacana-test-*")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	path := filepath.Join(dir, "test.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		return nil, err
	}
	return Load(path)
}
