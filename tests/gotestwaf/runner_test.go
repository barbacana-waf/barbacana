//go:build gotestwaf

// Package gotestwaf runs Wallarm's gotestwaf attack suite against a live
// barbacana binary at four CRS paranoia levels (PL1–PL4) and emits a
// unified report. The run is informational — the nightly security
// workflow uploads the reports as artifacts for review.
//
// Why a sweep: attack-block rate and false-positive rate move in opposite
// directions as sensitivity rises. A single run at the default level
// (PL1) gives you one point on that curve; the sweep gives you all four.
// Context and interpretation live in docs/design/security-evaluation.md.
//
// Run:
//
//	make test-gotestwaf               # all 4 PLs (~7 min)
//	go test -tags=gotestwaf -run=TestGotestWAF/PL2 ./tests/gotestwaf/
package gotestwaf

import (
	"context"
	"encoding/json"
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
)

// paranoiaLevels lists the levels exercised. Thresholds are paired with
// the sensitivity per CRS community guidance — see the config files and
// docs/design/security-evaluation.md.
var paranoiaLevels = []int{1, 2, 3, 4}

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

func waitForPortDown(ctx context.Context, addr string) error {
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timeout waiting for %s to close: %w", addr, ctx.Err())
		default:
		}
		conn, err := net.DialTimeout("tcp", addr, 50*time.Millisecond)
		if err != nil {
			return nil
		}
		conn.Close()
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

// runOnePL runs gotestwaf against barbacana configured at the given
// paranoia level and writes the JSON + PDF reports.
func runOnePL(t *testing.T, pl int, barbacana, gotestwaf, sourceDir, reportsDir, root string) {
	configFile := filepath.Join(root, "tests", "gotestwaf", fmt.Sprintf("config-pl%d.yaml", pl))
	if _, err := os.Stat(configFile); err != nil {
		t.Fatalf("missing config %s: %v", configFile, err)
	}

	wafCtx, wafCancel := context.WithCancel(context.Background())
	defer wafCancel()

	wafCmd := startProcess(wafCtx, t, barbacana, "serve", "--config", configFile)
	defer func() {
		wafCancel()
		_ = wafCmd.Wait()
	}()

	readyCtx, readyCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer readyCancel()
	if err := waitForPort(readyCtx, wafAddr); err != nil {
		t.Fatalf("WAF not ready at PL%d: %v", pl, err)
	}

	runCtx, runCancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer runCancel()

	reportName := fmt.Sprintf("pl%d", pl)
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
		t.Logf("gotestwaf PL%d exited non-zero (continuing): %v", pl, err)
	}

	// Release :8080 before the next PL starts.
	wafCancel()
	_ = wafCmd.Wait()
	downCtx, downCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer downCancel()
	_ = waitForPortDown(downCtx, wafAddr)
}

// gotestwafSummary captures the fields we need from each JSON report.
// Additional fields in the file are ignored.
type gotestwafSummary struct {
	Score   float64 `json:"score"`
	Summary struct {
		TruePositive struct {
			Score  float64 `json:"score"`
			AppSec counts  `json:"app_sec"`
			APISec counts  `json:"api_sec"`
		} `json:"true_positive_tests"`
		TrueNegative struct {
			Score float64 `json:"score"`
		} `json:"true_negative_tests"`
	} `json:"summary"`
}

type counts struct {
	TotalSent     int `json:"total_sent"`
	ResolvedTests int `json:"resolved_tests"`
	BlockedTests  int `json:"blocked_tests"`
}

// pct renders a block-rate percentage, or "-" if no resolved tests.
func pct(c counts) string {
	if c.ResolvedTests == 0 {
		return "-"
	}
	return fmt.Sprintf("%.2f", float64(c.BlockedTests)/float64(c.ResolvedTests)*100)
}

// writeAggregate reads each PL's JSON and emits a markdown summary.
func writeAggregate(t *testing.T, reportsDir string, pls []int) {
	t.Helper()

	var rows []string
	rows = append(rows, "| PL | Anomaly threshold | Overall score | Attack-block % | Clean-pass % | App-sec block % | API-sec block % |")
	rows = append(rows, "|---|---:|---:|---:|---:|---:|---:|")

	thresholds := map[int]int{1: 5, 2: 7, 3: 9, 4: 12}

	for _, pl := range pls {
		path := filepath.Join(reportsDir, fmt.Sprintf("pl%d.json", pl))
		data, err := os.ReadFile(path)
		if err != nil {
			t.Logf("skipping PL%d in summary: %v", pl, err)
			continue
		}
		var s gotestwafSummary
		if err := json.Unmarshal(data, &s); err != nil {
			t.Logf("parse PL%d JSON: %v", pl, err)
			continue
		}
		rows = append(rows, fmt.Sprintf(
			"| PL%d | %d | %.2f | %.2f | %.2f | %s | %s |",
			pl, thresholds[pl],
			s.Score,
			s.Summary.TruePositive.Score,
			s.Summary.TrueNegative.Score,
			pct(s.Summary.TruePositive.AppSec),
			pct(s.Summary.TruePositive.APISec),
		))
	}

	body := strings.Join(rows, "\n") + "\n"
	summaryPath := filepath.Join(reportsDir, "summary.md")
	if err := os.WriteFile(summaryPath, []byte(body), 0o644); err != nil {
		t.Logf("write summary: %v", err)
		return
	}
	t.Logf("gotestwaf PL sweep summary →\n%s", body)
}

// TestGotestWAF runs the sensitivity sweep. Each PL is a subtest so
// filters like `-run=TestGotestWAF/PL2` exercise just one level.
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

	// Upstream lives for the entire sweep.
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

	var ranPLs []int
	for _, pl := range paranoiaLevels {
		pl := pl
		ok := t.Run(fmt.Sprintf("PL%d", pl), func(t *testing.T) {
			runOnePL(t, pl, barbacana, gotestwaf, sourceDir, reportsDir, root)
		})
		if ok {
			ranPLs = append(ranPLs, pl)
		}
	}

	if len(ranPLs) > 1 {
		writeAggregate(t, reportsDir, ranPLs)
	}
}
