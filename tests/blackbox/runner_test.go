//go:build blackbox

// Package blackbox runs scenario-based functional tests against a compiled
// barbacana binary. Each scenario is a (config, Hurl tests) pair under
// scenarios/. The test boots a mock upstream once, then for every scenario
// starts the WAF, runs the Hurl files, and tears down the WAF.
//
// Run:
//
//	make test-blackbox            # builds the binary first
//	go test -tags=blackbox ./tests/blackbox/ -v -count=1
package blackbox

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

const (
	wafAddr      = "localhost:18080"
	upstreamAddr = "localhost:19000"
	hostURL      = "http://" + wafAddr
	upstreamURL  = "http://" + upstreamAddr
)

// waitForPort polls the address until it accepts a TCP connection or the
// context is cancelled. Returns nil on success.
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

// waitForPortDown polls until the address stops accepting connections or
// the context is cancelled.
func waitForPortDown(ctx context.Context, addr string) error {
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timeout waiting for %s to close: %w", addr, ctx.Err())
		default:
		}
		conn, err := net.DialTimeout("tcp", addr, 50*time.Millisecond)
		if err != nil {
			return nil // port is down
		}
		conn.Close()
		time.Sleep(50 * time.Millisecond)
	}
}

// startProcess launches a command tied to the context. When the context is
// cancelled, the process is killed. Returns after the command starts (but
// does NOT wait for it to exit).
func startProcess(ctx context.Context, t *testing.T, name string, args ...string) *exec.Cmd {
	t.Helper()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout = os.Stderr // route child stdout to test stderr so it's visible with -v
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start %s: %v", name, err)
	}
	return cmd
}

// scenarioDir returns the absolute path to the scenarios/ directory.
func scenarioDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs(filepath.Join("scenarios"))
	if err != nil {
		t.Fatalf("resolve scenarios dir: %v", err)
	}
	return dir
}

// listScenarios returns sorted scenario directory names.
func listScenarios(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read scenarios dir: %v", err)
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	return names
}

// hurlFiles returns sorted .hurl file paths under dir/tests/.
func hurlFiles(t *testing.T, scenarioPath string) []string {
	t.Helper()
	pattern := filepath.Join(scenarioPath, "tests", "*.hurl")
	files, err := filepath.Glob(pattern)
	if err != nil {
		t.Fatalf("glob %s: %v", pattern, err)
	}
	sort.Strings(files)
	return files
}

// requireHurl fails fast if hurl is not installed.
func requireHurl(t *testing.T) string {
	t.Helper()
	path, err := exec.LookPath("hurl")
	if err != nil {
		t.Skip("hurl not installed — see https://hurl.dev")
	}
	return path
}

// requireBarbacana fails fast if the binary is not built.
func requireBarbacana(t *testing.T) string {
	t.Helper()
	// Look in the repo root (two levels up from tests/blackbox/).
	bin, err := filepath.Abs(filepath.Join("..", "..", "barbacana"))
	if err != nil {
		t.Fatalf("resolve barbacana binary: %v", err)
	}
	if _, err := os.Stat(bin); err != nil {
		t.Fatalf("barbacana binary not found at %s — run 'make build' first", bin)
	}
	return bin
}

// repoRoot returns the absolute path to the repository root.
func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolve repo root: %v", err)
	}
	return root
}

func TestBlackbox(t *testing.T) {
	hurlBin := requireHurl(t)
	barbacana := requireBarbacana(t)
	scenariosRoot := scenarioDir(t)

	// Change to repo root so config-relative paths (e.g. OpenAPI spec paths)
	// resolve correctly — the barbacana binary is launched from here.
	root := repoRoot(t)
	if err := os.Chdir(root); err != nil {
		t.Fatalf("chdir to repo root %s: %v", root, err)
	}

	// ── Start mock upstream (lives for the whole test) ──────────────
	upstreamCtx, upstreamCancel := context.WithCancel(context.Background())
	defer upstreamCancel()

	upstreamMain := filepath.Join(scenariosRoot, "..", "upstream", "main.go")
	upstreamCmd := startProcess(upstreamCtx, t, "go", "run", upstreamMain)
	defer func() {
		upstreamCancel()
		_ = upstreamCmd.Wait()
	}()

	readyCtx, readyCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer readyCancel()
	if err := waitForPort(readyCtx, upstreamAddr); err != nil {
		t.Fatalf("upstream not ready: %v", err)
	}

	// ── Run each scenario as a subtest ──────────────────────────────
	for _, name := range listScenarios(t, scenariosRoot) {
		name := name // capture
		t.Run(name, func(t *testing.T) {
			scenarioPath := filepath.Join(scenariosRoot, name)
			configFile := filepath.Join(scenarioPath, "config.yaml")
			if _, err := os.Stat(configFile); err != nil {
				t.Skipf("no config.yaml")
			}

			// Run per-scenario setup if present.
			setupScript := filepath.Join(scenarioPath, "setup.sh")
			if _, err := os.Stat(setupScript); err == nil {
				cmd := exec.Command("bash", setupScript)
				cmd.Stderr = os.Stderr
				if err := cmd.Run(); err != nil {
					t.Fatalf("setup.sh: %v", err)
				}
			}

			// Start WAF.
			wafCtx, wafCancel := context.WithCancel(context.Background())
			defer wafCancel()

			wafCmd := startProcess(wafCtx, t, barbacana, "serve", "--config", configFile)
			defer func() {
				wafCancel()
				_ = wafCmd.Wait()
			}()

			readyCtx, readyCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer readyCancel()
			if err := waitForPort(readyCtx, wafAddr); err != nil {
				t.Fatalf("WAF not ready: %v", err)
			}

			// Collect Hurl files.
			files := hurlFiles(t, scenarioPath)
			if len(files) == 0 {
				t.Skipf("no .hurl files")
			}

			// Build hurl command.
			args := []string{
				"--test",
				"--variable", "host=" + hostURL,
				"--variable", "upstream=" + upstreamURL,
			}
			args = append(args, files...)

			cmd := exec.Command(hurlBin, args...)
			out, err := cmd.CombinedOutput()
			t.Log(strings.TrimSpace(string(out)))
			if err != nil {
				t.Fatalf("hurl failed:\n%s", out)
			}

			// Tear down WAF and wait for port to be released.
			wafCancel()
			_ = wafCmd.Wait()

			downCtx, downCancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer downCancel()
			if err := waitForPortDown(downCtx, wafAddr); err != nil {
				t.Logf("warning: WAF port did not release: %v", err)
			}
		})
	}
}
