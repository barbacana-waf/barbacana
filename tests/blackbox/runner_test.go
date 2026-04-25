//go:build blackbox && !windows

// Package blackbox runs scenario-based functional tests against a compiled
// barbacana binary. Each scenario is a (config, Hurl tests) pair under
// scenarios/. The test boots a mock upstream once, then for every scenario
// starts the WAF, runs the Hurl files, and tears down the WAF.
//
// Run:
//
//	make test-blackbox              # summary output only
//	make test-blackbox VERBOSE=1    # stream hurl + WAF logs live
//	go test -tags=blackbox ./tests/blackbox/ -count=1
package blackbox

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// syncBuffer is a concurrent-safe io.Writer that accumulates output. Used
// to capture a child process's stdout+stderr so it can be replayed into
// t.Log only when a scenario fails. Plain bytes.Buffer is not safe against
// concurrent writes from the process's stdio pipes.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

// runStats counts what happened across the scenario suite so TestMain can
// print a summary after all subtests finish. Without this, non-verbose
// go-test output is only "ok <pkg>" with no scenario/hurl counts.
var runStats struct {
	sync.Mutex
	scenarios, scenariosPassed int
	hurlFiles                  int
}

func recordScenario(passed bool, hurlFileCount int) {
	runStats.Lock()
	defer runStats.Unlock()
	runStats.scenarios++
	if passed {
		runStats.scenariosPassed++
	}
	runStats.hurlFiles += hurlFileCount
}

func TestMain(m *testing.M) {
	code := m.Run()
	// go-test buffers everything the test binary writes to stdout/stderr
	// and only flushes it with -v or on failure — which defeats "tell me
	// how many tests ran" on a passing quiet run. Write the summary to
	// BLACKBOX_SUMMARY_FILE (set by the Makefile) so it can be printed
	// out-of-band regardless of go-test's verbosity, and without
	// duplicating on failure when the buffered stderr also gets flushed.
	if path := os.Getenv("BLACKBOX_SUMMARY_FILE"); path != "" && runStats.scenarios > 0 {
		var head string
		if runStats.scenariosPassed == runStats.scenarios {
			head = fmt.Sprintf("blackbox: %d request files across %d scenarios — all passed",
				runStats.hurlFiles, runStats.scenarios)
		} else {
			head = fmt.Sprintf("blackbox: %d/%d scenarios passed, %d request files executed",
				runStats.scenariosPassed, runStats.scenarios, runStats.hurlFiles)
		}
		body := "each scenario boots barbacana with its own config.yaml and runs its .hurl request suite end-to-end"
		_ = os.WriteFile(path, []byte(head+"\n"+body+"\n"), 0o644)
	}
	os.Exit(code)
}

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

// startProcess launches a command tied to the context and directs its
// stdout+stderr to out. When the context is cancelled, the entire
// process group receives SIGTERM first; if the group is still alive
// after gracefulKillTimeout it gets SIGKILL. Group-targeted signals
// reap grandchildren too — e.g. the compiled binary spawned by
// `go run` — without which the orphaned grandchild keeps the test
// binary's inherited stderr pipe open, makes `go test` report
// "Test I/O incomplete", and (most painfully) holds the test ports
// past test exit so the next `make test-blackbox` fails to bind.
// WaitDelay bounds how long exec is willing to block on pipe draining
// after the cancel fires.
// Returns after the command starts (but does NOT wait for it to exit).
func startProcess(ctx context.Context, t *testing.T, out io.Writer, name string, args ...string) *exec.Cmd {
	t.Helper()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout = out
	cmd.Stderr = out
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return os.ErrProcessDone
		}
		return gracefulKillGroup(cmd.Process.Pid)
	}
	cmd.WaitDelay = gracefulKillTimeout + 2*time.Second
	if err := cmd.Start(); err != nil {
		t.Fatalf("start %s: %v", name, err)
	}
	return cmd
}

// gracefulKillTimeout is how long the runner waits between sending
// SIGTERM and escalating to SIGKILL. Long enough for an HTTP server
// to drain inflight requests, short enough that tearing down a
// scenario between subtests stays snappy.
const gracefulKillTimeout = 2 * time.Second

// gracefulKillGroup signals the process group leader's process group
// (note the negative PID), waits a short grace period for processes
// to exit cleanly, then SIGKILLs the group if anyone is still alive.
// Always returns nil on the first SIGTERM — exec.Cmd.Wait will report
// the actual exit reason; this function only escalates if needed.
func gracefulKillGroup(pid int) error {
	_ = syscall.Kill(-pid, syscall.SIGTERM)
	deadline := time.Now().Add(gracefulKillTimeout)
	for time.Now().Before(deadline) {
		// Signal 0 probes whether the group still exists without
		// affecting it. ESRCH means "no such process".
		if err := syscall.Kill(-pid, 0); err != nil {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return syscall.Kill(-pid, syscall.SIGKILL)
}

// requirePortFree fails the test fast if addr is already bound. The
// canonical cause is an orphan upstream/WAF left behind by a previous
// test run — the message tells the operator exactly what to do.
func requirePortFree(t *testing.T, addr string) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
	if err != nil {
		return
	}
	conn.Close()
	t.Fatalf("port %s already in use — kill the previous process with: lsof -ti:%s | xargs kill", addr, portOnly(addr))
}

func portOnly(addr string) string {
	if i := strings.LastIndex(addr, ":"); i >= 0 {
		return addr[i+1:]
	}
	return addr
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
	// Fail fast if a previous test run left an orphan on the upstream
	// or WAF port — without this preflight the next test silently
	// reuses the orphan and gives confusing assertion errors instead
	// of a clear "port already in use" message.
	requirePortFree(t, upstreamAddr)
	requirePortFree(t, wafAddr)

	upstreamCtx, upstreamCancel := context.WithCancel(context.Background())
	defer upstreamCancel()

	upstreamMain := filepath.Join(scenariosRoot, "..", "upstream", "main.go")
	upstreamCmd := startProcess(upstreamCtx, t, os.Stderr, "go", "run", upstreamMain)
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
		var scenarioFiles int
		var scenarioRan bool
		ok := t.Run(name, func(t *testing.T) {
			scenarioRan = true
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

			// Start WAF. Route its stdout+stderr into a per-scenario
			// buffer; replay via t.Log only if this subtest fails (or
			// -v is in effect), so a clean run stays quiet.
			wafCtx, wafCancel := context.WithCancel(context.Background())
			defer wafCancel()

			wafLog := &syncBuffer{}
			wafCmd := startProcess(wafCtx, t, wafLog, barbacana, "--config", configFile)
			defer func() {
				wafCancel()
				_ = wafCmd.Wait()
				if out := strings.TrimSpace(wafLog.String()); out != "" {
					t.Logf("barbacana output:\n%s", out)
				}
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
			scenarioFiles = len(files)

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
		// Filtered-out scenarios (go test -run TestBlackbox/X) never
		// executed the subtest body; skip them in the summary so the
		// count reflects what actually ran.
		if scenarioRan {
			recordScenario(ok, scenarioFiles)
		}
	}
}
