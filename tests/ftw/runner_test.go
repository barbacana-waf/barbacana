//go:build ftw

// Package ftw runs the OWASP CRS FTW regression suite against a live
// barbacana binary and emits an informational report. It never fails —
// the nightly security workflow uploads the report as an artifact for
// review.
//
// Run:
//
//	make rules              # fetches CRS + FTW test corpus
//	make test-ftw           # builds barbacana, runs the suite
package ftw

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

const (
	wafAddr      = "localhost:8080"
	upstreamAddr = "localhost:19000"
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

func requireGoFtw(t *testing.T, root string) string {
	t.Helper()
	local := filepath.Join(root, "bin", "go-ftw")
	if _, err := os.Stat(local); err == nil {
		return local
	}
	p, err := exec.LookPath("go-ftw")
	if err != nil {
		t.Skip("go-ftw not installed — run 'make tools-security'")
	}
	return p
}

func requireCRSTests(t *testing.T, root string) string {
	t.Helper()
	dir := filepath.Join(root, "tests", "ftw", "crs-tests")
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) == 0 {
		t.Fatalf("CRS test corpus missing at %s — run 'make rules' first", dir)
	}
	return dir
}

// buildUpstream compiles the shared mock upstream to a temp binary so
// tests launch it directly (no `go run` grandchild that would hold stderr
// after the parent is killed).
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

// summarizeReport extracts the aggregate lines from a go-ftw report.
func summarizeReport(body string) string {
	totalRe := regexp.MustCompile(`run\s+\d+\s+total\s+tests`)
	skipRe := regexp.MustCompile(`skipped\s+\d+\s+tests?`)
	failRe := regexp.MustCompile(`\d+\s+test\(s\)\s+failed`)
	var lines []string
	scan := bufio.NewScanner(strings.NewReader(body))
	scan.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scan.Scan() {
		line := strings.TrimSpace(scan.Text())
		if totalRe.MatchString(line) || skipRe.MatchString(line) || failRe.MatchString(line) {
			lines = append(lines, line)
		}
	}
	if len(lines) == 0 {
		return "summary: could not parse go-ftw output; see ftw-report.txt"
	}
	return strings.Join(lines, "\n")
}

// TestFTW runs the full CRS regression suite and writes the raw output
// and a parsed summary to tests/ftw/reports/. It never fails — this is
// a report, not a gate.
func TestFTW(t *testing.T) {
	root := repoRoot(t)
	barbacana := requireBarbacana(t, root)
	goftw := requireGoFtw(t, root)
	testsDir := requireCRSTests(t, root)
	upstreamBin := buildUpstream(t, root)

	reportsDir := filepath.Join(root, "tests", "ftw", "reports")
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

	wafCtx, wafCancel := context.WithCancel(context.Background())
	defer wafCancel()

	configFile := filepath.Join(root, "tests", "ftw", "config.yaml")
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

	ftwConfig := filepath.Join(root, "tests", "ftw", "ftw.yaml")
	reportPath := filepath.Join(reportsDir, "ftw-report.txt")
	reportFile, err := os.Create(reportPath)
	if err != nil {
		t.Fatalf("create report: %v", err)
	}
	defer reportFile.Close()

	ftwCtx, ftwCancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer ftwCancel()

	// --cloud: rely only on HTTP status codes, do not process logs.
	// This is the documented go-ftw mode for WAFs whose audit log is not
	// a SecAuditLog drop-in.
	cmd := exec.CommandContext(ftwCtx, goftw,
		"--cloud",
		"--config", ftwConfig,
		"run",
		"--dir", testsDir,
	)
	cmd.Stdout = reportFile
	cmd.Stderr = reportFile

	runErr := cmd.Run()
	exitCode := 0
	if runErr != nil {
		if ee, ok := runErr.(*exec.ExitError); ok {
			exitCode = ee.ExitCode()
		} else {
			exitCode = -1
		}
	}

	body, _ := os.ReadFile(reportPath)
	summary := fmt.Sprintf(
		"go-ftw exit code: %d\n%s\ntest corpus: %s\nreport: %s\n",
		exitCode, summarizeReport(string(body)), testsDir, reportPath,
	)
	summaryPath := filepath.Join(reportsDir, "ftw-summary.txt")
	if err := os.WriteFile(summaryPath, []byte(summary), 0o644); err != nil {
		t.Logf("write summary: %v", err)
	}
	t.Logf("FTW complete —\n%s", summary)
}
