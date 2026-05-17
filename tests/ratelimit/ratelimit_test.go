//go:build ratelimit && !windows

// Package ratelimit runs end-to-end tests for the rate-limiting feature.
// Each sub-test boots a real barbacana binary with a purpose-built config,
// sends HTTP requests via net/http with precise timing or goroutine
// concurrency, and tears down the binary before the next sub-test starts.
//
// Run:
//
//	make test-ratelimit
//	make test-ratelimit VERBOSE=1
//	go test -tags=ratelimit -race ./tests/ratelimit/ -run TestRateLimit/sequential
package ratelimit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// ── process management (adapted from tests/blackbox/runner_test.go) ───────────

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

const wafAddr = "localhost:18080"

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

// requireBarbacana returns the path to the barbacana binary. It checks
// $BBPATH first, then falls back to ../../barbacana relative to this file.
func requireBarbacana(t *testing.T) string {
	t.Helper()
	if v := os.Getenv("BBPATH"); v != "" {
		if _, err := os.Stat(v); err == nil {
			return v
		}
		t.Fatalf("BBPATH=%q not found", v)
	}
	bin, err := filepath.Abs(filepath.Join("..", "..", "barbacana"))
	if err != nil {
		t.Fatalf("resolve barbacana binary: %v", err)
	}
	if _, err := os.Stat(bin); err != nil {
		t.Fatalf("barbacana binary not found at %s — run 'make build' first", bin)
	}
	return bin
}

func writeTempConfig(t *testing.T, yaml string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}
	return path
}

// startUpstream returns the URL of an inline httptest.Server that returns
// 200 OK for every request. Cleanup is registered on t.
func startUpstream(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

// startWAF launches barbacana with configPath, waits up to 5 s for it to
// bind on wafAddr, and registers a t.Cleanup that kills the process (using
// a process-group SIGKILL so grandchildren are reaped) and waits for the
// port to close. Subtests run sequentially so port 18080 is never double-booked.
func startWAF(t *testing.T, bbPath, configPath string) {
	t.Helper()
	wafLog := &syncBuffer{}
	ctx, cancel := context.WithCancel(context.Background())

	cmd := exec.CommandContext(ctx, bbPath, "--config", configPath)
	cmd.Stdout = wafLog
	cmd.Stderr = wafLog
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return os.ErrProcessDone
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	cmd.WaitDelay = 5 * time.Second

	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatalf("start barbacana: %v", err)
	}

	t.Cleanup(func() {
		cancel()
		_ = cmd.Wait()
		if out := strings.TrimSpace(wafLog.String()); out != "" {
			t.Logf("barbacana output:\n%s", out)
		}
		downCtx, downCancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer downCancel()
		if err := waitForPortDown(downCtx, wafAddr); err != nil {
			t.Logf("warning: WAF port did not release: %v", err)
		}
	})

	readyCtx, readyCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer readyCancel()
	if err := waitForPort(readyCtx, wafAddr); err != nil {
		t.Fatalf("WAF not ready: %v", err)
	}
}

// ── HTTP helpers ──────────────────────────────────────────────────────────────

var httpClient = &http.Client{
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// get sends GET wafURL+path with optional "Key", "Value" header pairs and
// returns the status code. Only safe to call from the test goroutine.
func get(t *testing.T, wafURL, path string, headers ...string) int {
	t.Helper()
	resp := doGet(t, wafURL, path, headers...)
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

// doGet is like get but returns the full *http.Response. Caller must close Body.
func doGet(t *testing.T, wafURL, path string, headers ...string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, wafURL+path, nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s%s: %v", wafURL, path, err)
	}
	return resp
}

// burstN releases n goroutines simultaneously via a channel barrier, each
// sending GET wafURL+path. Returns (allowed, blocked) counts for 200 and
// 429 responses respectively. Unexpected status codes are reported via
// t.Errorf. Safe to call from the test goroutine.
func burstN(t *testing.T, wafURL, path string, n int, headers ...string) (allowed, blocked int) {
	t.Helper()
	ready := make(chan struct{})
	var wg sync.WaitGroup
	var mu sync.Mutex
	codes := make([]int, 0, n)

	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-ready
			req, err := http.NewRequest(http.MethodGet, wafURL+path, nil)
			if err != nil {
				mu.Lock()
				codes = append(codes, -1)
				mu.Unlock()
				return
			}
			for i := 0; i+1 < len(headers); i += 2 {
				req.Header.Set(headers[i], headers[i+1])
			}
			resp, err := httpClient.Do(req)
			if err != nil {
				mu.Lock()
				codes = append(codes, -1)
				mu.Unlock()
				return
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			mu.Lock()
			codes = append(codes, resp.StatusCode)
			mu.Unlock()
		}()
	}
	close(ready)
	wg.Wait()

	for _, c := range codes {
		switch c {
		case http.StatusOK:
			allowed++
		case http.StatusTooManyRequests:
			blocked++
		default:
			t.Errorf("unexpected status %d in burst", c)
		}
	}
	return
}

// ── Config YAML templates ─────────────────────────────────────────────────────
// Each has a single %s placeholder for the upstream URL.

const cfgRouteIP = `
version: v1alpha1
port: 18080
global:
  mode: blocking
routes:
  - upstream: %s
    rate_limit:
      requests: 2
      window: 1s
      source:
        type: ip
`

const cfgDetectOnly = `
version: v1alpha1
port: 18080
global:
  mode: detect_only
routes:
  - upstream: %s
    rate_limit:
      requests: 2
      window: 1s
      source:
        type: ip
`

const cfgHeaderKey = `
version: v1alpha1
port: 18080
global:
  mode: blocking
routes:
  - upstream: %s
    rate_limit:
      requests: 2
      window: 1s
      source:
        type: header
        key: X-Client-ID
`

const cfgGlobalOnly = `
version: v1alpha1
port: 18080
global:
  mode: blocking
  rate_limit:
    requests: 2
    window: 1s
    source:
      type: ip
routes:
  - upstream: %s
`

const cfgRouteWins = `
version: v1alpha1
port: 18080
global:
  mode: blocking
  rate_limit:
    requests: 10
    window: 1s
    source:
      type: ip
routes:
  - upstream: %s
    rate_limit:
      requests: 2
      window: 1s
      source:
        type: ip
`

const cfgHighRate = `
version: v1alpha1
port: 18080
global:
  mode: blocking
routes:
  - upstream: %s
    rate_limit:
      requests: 5
      window: 1s
      source:
        type: ip
`

// ── Tests ─────────────────────────────────────────────────────────────────────

func TestRateLimit(t *testing.T) {
	bb := requireBarbacana(t)
	const wafURL = "http://" + wafAddr

	// sequential: each sub-test boots its own barbacana so rate-limit state
	// does not bleed between runs. The t.Cleanup registered by startWAF
	// kills the process and waits for the port to close before the next
	// sub-test calls startWAF.
	t.Run("sequential", func(t *testing.T) {
		t.Run("budget_respected", func(t *testing.T) {
			startWAF(t, bb, writeTempConfig(t, fmt.Sprintf(cfgRouteIP, startUpstream(t))))

			if code := get(t, wafURL, "/hello"); code != http.StatusOK {
				t.Errorf("request 1: got %d, want 200", code)
			}
			if code := get(t, wafURL, "/hello"); code != http.StatusOK {
				t.Errorf("request 2: got %d, want 200", code)
			}
			if code := get(t, wafURL, "/hello"); code != http.StatusTooManyRequests {
				t.Errorf("request 3: got %d, want 429", code)
			}
		})

		t.Run("retry_after_header", func(t *testing.T) {
			startWAF(t, bb, writeTempConfig(t, fmt.Sprintf(cfgRouteIP, startUpstream(t))))

			get(t, wafURL, "/hello") // consume budget
			get(t, wafURL, "/hello")
			resp := doGet(t, wafURL, "/hello")
			defer resp.Body.Close()
			_, _ = io.Copy(io.Discard, resp.Body)
			if resp.StatusCode != http.StatusTooManyRequests {
				t.Fatalf("got %d, want 429", resp.StatusCode)
			}
			if v := resp.Header.Get("Retry-After"); v != "1" {
				t.Errorf("Retry-After: got %q, want %q", v, "1")
			}
		})

		t.Run("blocked_body_shape", func(t *testing.T) {
			startWAF(t, bb, writeTempConfig(t, fmt.Sprintf(cfgRouteIP, startUpstream(t))))

			get(t, wafURL, "/hello") // consume budget
			get(t, wafURL, "/hello")
			resp := doGet(t, wafURL, "/hello")
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusTooManyRequests {
				t.Fatalf("got %d, want 429", resp.StatusCode)
			}
			var body struct {
				Error     string `json:"error"`
				RequestID string `json:"request_id"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
				t.Fatalf("decode body: %v", err)
			}
			if body.Error != "blocked" {
				t.Errorf("body.error: got %q, want %q", body.Error, "blocked")
			}
			if body.RequestID == "" {
				t.Error("body.request_id is empty")
			}
		})

		t.Run("window_reset", func(t *testing.T) {
			startWAF(t, bb, writeTempConfig(t, fmt.Sprintf(cfgRouteIP, startUpstream(t))))

			get(t, wafURL, "/hello") // consume budget
			get(t, wafURL, "/hello")
			if code := get(t, wafURL, "/hello"); code != http.StatusTooManyRequests {
				t.Fatalf("before reset: got %d, want 429", code)
			}

			// The sliding window is 1 second. Sleep 1100 ms to let all
			// timestamps expire; 100 ms headroom avoids clock edge cases.
			time.Sleep(1100 * time.Millisecond)

			if code := get(t, wafURL, "/hello"); code != http.StatusOK {
				t.Errorf("after reset (req 1): got %d, want 200", code)
			}
			if code := get(t, wafURL, "/hello"); code != http.StatusOK {
				t.Errorf("after reset (req 2): got %d, want 200", code)
			}
		})
	})

	// concurrent: verifies the MemoryLimiter's global mutex serialises
	// concurrent Allow calls so exactly `requests` calls pass — no more,
	// no less.
	t.Run("concurrent", func(t *testing.T) {
		t.Run("exactly_budget_pass", func(t *testing.T) {
			startWAF(t, bb, writeTempConfig(t, fmt.Sprintf(cfgHighRate, startUpstream(t))))

			const requests = 5
			allowed, blocked := burstN(t, wafURL, "/test", requests*2)
			if allowed != requests {
				t.Errorf("allowed: got %d, want %d", allowed, requests)
			}
			if blocked != requests {
				t.Errorf("blocked: got %d, want %d", blocked, requests)
			}
		})
	})

	// detect_only: rate-limit detection is active but no request is blocked.
	t.Run("detect_only", func(t *testing.T) {
		t.Run("passes_all", func(t *testing.T) {
			startWAF(t, bb, writeTempConfig(t, fmt.Sprintf(cfgDetectOnly, startUpstream(t))))

			for i := range 5 {
				if code := get(t, wafURL, "/hello"); code != http.StatusOK {
					t.Errorf("request %d: got %d, want 200", i+1, code)
				}
			}
		})
	})

	// header_key: requests are bucketed by a header value, not by IP,
	// so different header values are rate-limited independently.
	t.Run("header_key", func(t *testing.T) {
		t.Run("same_key_shares_bucket", func(t *testing.T) {
			startWAF(t, bb, writeTempConfig(t, fmt.Sprintf(cfgHeaderKey, startUpstream(t))))

			if code := get(t, wafURL, "/hello", "X-Client-ID", "alice"); code != http.StatusOK {
				t.Errorf("alice req 1: got %d, want 200", code)
			}
			if code := get(t, wafURL, "/hello", "X-Client-ID", "alice"); code != http.StatusOK {
				t.Errorf("alice req 2: got %d, want 200", code)
			}
			if code := get(t, wafURL, "/hello", "X-Client-ID", "alice"); code != http.StatusTooManyRequests {
				t.Errorf("alice req 3: got %d, want 429", code)
			}
		})

		t.Run("different_keys_independent", func(t *testing.T) {
			startWAF(t, bb, writeTempConfig(t, fmt.Sprintf(cfgHeaderKey, startUpstream(t))))

			// Exhaust alice's budget.
			get(t, wafURL, "/hello", "X-Client-ID", "alice")
			get(t, wafURL, "/hello", "X-Client-ID", "alice")
			if code := get(t, wafURL, "/hello", "X-Client-ID", "alice"); code != http.StatusTooManyRequests {
				t.Fatalf("alice req 3: got %d, want 429", code)
			}
			// Bob has an independent bucket and must not be affected.
			if code := get(t, wafURL, "/hello", "X-Client-ID", "bob"); code != http.StatusOK {
				t.Errorf("bob req 1: got %d, want 200", code)
			}
		})
	})

	// global_vs_route: route-level config wins over global when both are set;
	// when a route has no rate_limit block the global config applies.
	t.Run("global_vs_route", func(t *testing.T) {
		t.Run("route_wins", func(t *testing.T) {
			// global requests=10 but route requests=2; limiter must enforce route budget.
			startWAF(t, bb, writeTempConfig(t, fmt.Sprintf(cfgRouteWins, startUpstream(t))))

			get(t, wafURL, "/hello")
			get(t, wafURL, "/hello")
			if code := get(t, wafURL, "/hello"); code != http.StatusTooManyRequests {
				t.Errorf("req 3: got %d, want 429", code)
			}
		})

		t.Run("global_applies_to_route", func(t *testing.T) {
			// Route has no rate_limit block; global requests=2 must apply.
			startWAF(t, bb, writeTempConfig(t, fmt.Sprintf(cfgGlobalOnly, startUpstream(t))))

			get(t, wafURL, "/hello")
			get(t, wafURL, "/hello")
			if code := get(t, wafURL, "/hello"); code != http.StatusTooManyRequests {
				t.Errorf("req 3: got %d, want 429", code)
			}
		})
	})
}
