package cmd

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// captureStdout runs fn with os.Stdout redirected to an in-memory buffer,
// returning whatever fn wrote. Used by commands that print to stdout.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w
	defer func() { os.Stdout = orig }()

	done := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()

	fn()
	_ = w.Close()
	return <-done
}

// writeConfig writes content to a temp file and returns its path.
func writeConfig(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

const validConfig = `version: v1alpha1
routes:
  - upstream: http://localhost:8000
`

func TestRunValidateAcceptsValidConfig(t *testing.T) {
	path := writeConfig(t, validConfig)
	// Suppress stdout noise.
	captureStdout(t, func() {
		if err := runValidate(path); err != nil {
			t.Errorf("runValidate(%q) = %v, want nil", path, err)
		}
	})
}

func TestRunValidateRejectsMissingFile(t *testing.T) {
	err := runValidate("/no/such/file.yaml")
	if err == nil {
		t.Fatal("runValidate missing file: expected error, got nil")
	}
	if !strings.Contains(err.Error(), "load config") {
		t.Errorf("error = %q, want prefix mentioning load config", err.Error())
	}
}

func TestRunValidateRejectsInvalidYAML(t *testing.T) {
	path := writeConfig(t, "::not valid yaml::\n  - foo: [")
	err := runValidate(path)
	if err == nil {
		t.Fatal("runValidate invalid yaml: expected error, got nil")
	}
}

func TestRunValidateRejectsUnknownProtection(t *testing.T) {
	cfg := `version: v1alpha1
global:
  disable: [not-a-real-protection]
routes:
  - upstream: http://localhost:8000
`
	path := writeConfig(t, cfg)
	err := runValidate(path)
	if err == nil {
		t.Fatal("runValidate unknown protection: expected error, got nil")
	}
}

func TestRunValidateRejectsEmptyPath(t *testing.T) {
	err := runValidate("")
	if err == nil {
		t.Fatal("runValidate with empty path: expected error, got nil")
	}
}

func TestRunRenderConfigRendersConfig(t *testing.T) {
	path := writeConfig(t, validConfig)
	out := captureStdout(t, func() {
		if err := runRenderConfig(path); err != nil {
			t.Errorf("runRenderConfig = %v, want nil", err)
		}
	})
	// The output should be JSON containing Caddy's top-level apps key.
	if !strings.Contains(out, `"apps"`) {
		t.Errorf("render-config output missing Caddy JSON structure\n---\n%s", out)
	}
}

func TestRunVersionPrints(t *testing.T) {
	out := captureStdout(t, func() {
		runVersion()
	})
	// Must mention each of the three version lines.
	required := []string{"barbacana", "go", "crs"}
	for _, s := range required {
		if !strings.Contains(out, s) {
			t.Errorf("version output missing %q\n---\n%s", s, out)
		}
	}
}

func TestRunRejectsCombinedModeFlags(t *testing.T) {
	var stderr bytes.Buffer
	code := run([]string{"--validate", "--render-config"}, &stderr)
	if code != 2 {
		t.Errorf("run with two mode flags: exit code = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "mutually exclusive") {
		t.Errorf("stderr missing mutual-exclusion message\n---\n%s", stderr.String())
	}
}
