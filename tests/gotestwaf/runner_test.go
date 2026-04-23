//go:build gotestwaf

// Package gotestwaf runs Wallarm's gotestwaf attack suite against a live
// barbacana binary in its default configuration and emits a JSON + PDF
// report. The run is informational — the nightly security workflow
// uploads the reports as artifacts for review.
//
// Context and interpretation live in docs/design/security-evaluation.md.
//
// Run:
//
//	make test-gotestwaf
package gotestwaf

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	wafURL       = "http://localhost:8080"
	wafAddr      = "localhost:8080"
	upstreamAddr = "localhost:19000"
	reportName   = "default"
)

func waitForPort(ctx context.Context, addr string) error {
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timeout waiting for %s: %w", addr, ctx.Err())
		default:
		}
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func startProcess(ctx context.Context, t *testing.T, name string, args ...string) *exec.Cmd {
	t.Helper()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start %s: %v", name, err)
	}
	return cmd
}

func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolve repo root: %v", err)
	}
	return root
}

func requireBarbacana(t *testing.T, root string) string {
	t.Helper()
	bin := filepath.Join(root, "barbacana")
	if _, err := os.Stat(bin); err != nil {
		t.Fatalf("barbacana binary not found at %s — run 'make build' first", bin)
	}
	return bin
}

func requireGotestwaf(t *testing.T, root string) string {
	t.Helper()
	local := filepath.Join(root, "bin", "gotestwaf")
	if _, err := os.Stat(local); err == nil {
		return local
	}
	p, err := exec.LookPath("gotestwaf")
	if err != nil {
		t.Skip("gotestwaf not installed — run 'make tools-security'")
	}
	return p
}

// gotestwafSourceDir returns the pinned release path inside the Go
// module cache, where testcases/ and config.yaml live.
func gotestwafSourceDir(t *testing.T) string {
	t.Helper()
	version := os.Getenv("GOTESTWAF_VERSION")
	if version == "" {
		t.Skip("GOTESTWAF_VERSION env var not set — invoke via 'make test-gotestwaf'")
	}
	out, err := exec.Command("go", "env", "GOMODCACHE").Output()
	if err != nil {
		t.Fatalf("go env GOMODCACHE: %v", err)
	}
	modcache := strings.TrimSpace(string(out))
	dir := filepath.Join(modcache, "github.com", "wallarm", "gotestwaf@"+version)
	if _, err := os.Stat(filepath.Join(dir, "testcases")); err != nil {
		t.Fatalf("gotestwaf corpus missing at %s — run 'make tools-security' to populate module cache", dir)
	}
	return dir
}

// buildUpstream compiles the shared mock upstream to a temp binary.
func buildUpstream(t *testing.T, root string) string {
	t.Helper()
	src := filepath.Join(root, "tests", "blackbox", "upstream", "main.go")
	out := filepath.Join(t.TempDir(), "upstream")
	build := exec.Command("go", "build", "-o", out, src)
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		t.Fatalf("build upstream: %v", err)
	}
	return out
}

// TestGotestWAF runs gotestwaf once against the default Barbacana
// configuration. Since paranoia level and anomaly threshold are no
// longer user-configurable, there is no sensitivity sweep.
func TestGotestWAF(t *testing.T) {
	root := repoRoot(t)
	barbacana := requireBarbacana(t, root)
	gotestwaf := requireGotestwaf(t, root)
	sourceDir := gotestwafSourceDir(t)
	upstreamBin := buildUpstream(t, root)

	reportsDir := filepath.Join(root, "tests", "gotestwaf", "reports")
	if err := os.MkdirAll(reportsDir, 0o755); err != nil {
		t.Fatalf("mkdir reports: %v", err)
	}

	upstreamCtx, upstreamCancel := context.WithCancel(context.Background())
	defer upstreamCancel()
	upstreamCmd := startProcess(upstreamCtx, t, upstreamBin)
	defer func() {
		upstreamCancel()
		_ = upstreamCmd.Wait()
	}()

	readyCtx, readyCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer readyCancel()
	if err := waitForPort(readyCtx, upstreamAddr); err != nil {
		t.Fatalf("upstream not ready: %v", err)
	}

	configFile := filepath.Join(root, "tests", "gotestwaf", "config-default.yaml")
	if _, err := os.Stat(configFile); err != nil {
		t.Fatalf("missing config %s: %v", configFile, err)
	}

	wafCtx, wafCancel := context.WithCancel(context.Background())
	defer wafCancel()

	wafCmd := startProcess(wafCtx, t, barbacana, "--config", configFile)
	defer func() {
		wafCancel()
		_ = wafCmd.Wait()
	}()

	wafReadyCtx, wafReadyCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer wafReadyCancel()
	if err := waitForPort(wafReadyCtx, wafAddr); err != nil {
		t.Fatalf("WAF not ready: %v", err)
	}

	runCtx, runCancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer runCancel()

	cmd := exec.CommandContext(runCtx, gotestwaf,
		"--url", wafURL,
		"--reportPath", reportsDir,
		"--reportName", reportName,
		"--reportFormat", "pdf,json",
		"--noEmailReport",
		"--skipWAFBlockCheck",
		"--quiet",
	)
	cmd.Dir = sourceDir
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		t.Logf("gotestwaf exited non-zero (continuing): %v", err)
	}
}
