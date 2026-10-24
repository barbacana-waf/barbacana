package crs

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/barbacana-waf/barbacana/internal/config"
	"github.com/barbacana-waf/barbacana/internal/protections"
)

// Tests for the inspection window: what happens to a request body larger than
// inspection.max_inspect_size. The window counts what the rules read, so the
// contents of uploaded files do not use it up.

func windowRoute(limit int64, onOversize string) config.Resolved {
	route := testRoute()
	route.Accept.Methods = []string{"GET", "POST", "PUT"}
	route.Inspection.MaxInspectSize = limit
	route.Inspection.MaxMemoryBuffer = limit
	route.Inspection.OnOversize = onOversize
	return route
}

func windowRequest(contentType string, body []byte) *http.Request {
	r := httptest.NewRequest("POST", "/upload", bytes.NewReader(body))
	r.Header.Set("Host", "example.com")
	r.Header.Set("User-Agent", "Mozilla/5.0")
	r.Header.Set("Accept", "*/*")
	r.Header.Set("Content-Type", contentType)
	r.Header.Set("Content-Length", strconv.Itoa(len(body)))
	return r
}

func evaluateWindow(t *testing.T, route config.Resolved, contentType string, body []byte) EvaluationResult {
	t.Helper()
	eng, err := NewEngine(route)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return eng.Evaluate(context.Background(), windowRequest(contentType, body))
}

func blockingLeaves(res EvaluationResult) []string {
	var out []string
	for _, d := range res.Decisions {
		if d.Block {
			out = append(out, d.Protection)
		}
	}
	return out
}

func hasDecision(res EvaluationResult, leaf string) (found, blocking bool) {
	for _, d := range res.Decisions {
		if d.Protection == leaf {
			return true, d.Block
		}
	}
	return false, false
}

func multipartType() string { return "multipart/form-data; boundary=" + shapeBoundary }

// bigFile is an upload of n bytes whose content is as hostile-looking as text
// gets: the rules do not read it, and neither should the window count it.
func bigFile(name string, n int) rawPart {
	const hostile = "' OR '1'='1' -- <script>alert(1)</script> ../../etc/passwd; cat /etc/passwd\n"
	return filePart(name, name+".txt", strings.Repeat(hostile, n/len(hostile)+1)[:n])
}

func TestLargeUploadPassesTheWindow(t *testing.T) {
	for _, size := range []int{200 * 1024, 5 * 1024 * 1024, 32 * 1024 * 1024} {
		t.Run(fmt.Sprintf("%dKB", size/1024), func(t *testing.T) {
			body := rawMultipart([]rawPart{
				fieldPart("title", "holiday photos"),
				bigFile("upload", size),
				fieldPart("note", "see attached"),
			})
			res := evaluateWindow(t, windowRoute(128*1024, config.OnOversizeReject), multipartType(), body)
			if b := blockingLeaves(res); len(b) > 0 {
				t.Errorf("%d byte upload blocked by %v", len(body), b)
			}
			if found, _ := hasDecision(res, maxInspectSizeLeaf); found {
				t.Error("upload was reported as exceeding the window; file contents must not count")
			}
		})
	}
}

// The window still sees every field: an attack in the form around a large file
// is blocked, wherever in the body it sits.
func TestAttackInFormAroundLargeUploadStillBlocked(t *testing.T) {
	const sqli = "1 UNION SELECT password FROM users"
	for _, tt := range []struct {
		name  string
		parts []rawPart
	}{
		{"field before the file", []rawPart{fieldPart("q", sqli), bigFile("f", 1<<20)}},
		{"field after the file", []rawPart{bigFile("f", 1<<20), fieldPart("q", sqli)}},
		{"field between two files", []rawPart{bigFile("a", 1<<20), fieldPart("q", sqli), bigFile("b", 1<<20)}},
		{"php2shell marker after the file", []rawPart{bigFile("f", 1<<20), fieldPart("PHP_SESSION_UPLOAD_PROGRESS", "x")}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			res := evaluateWindow(t, windowRoute(128*1024, config.OnOversizeReject), multipartType(), rawMultipart(tt.parts))
			if len(blockingLeaves(res)) == 0 {
				t.Error("attack was not blocked")
			}
		})
	}
}

// A part that carries a filename parameter Coraza does not treat as a file is a
// form field to it, and its content is scanned. The projection must not hide
// that content by guessing the other way.
func TestFieldContentNotMistakenForFileContent(t *testing.T) {
	const sqli = "1 UNION SELECT password FROM users"
	for _, tt := range []struct {
		name    string
		headers []string
	}{
		{"empty filename", []string{`Content-Disposition: form-data; name="q"; filename=""`}},
		{"no filename", []string{`Content-Disposition: form-data; name="q"`}},
		{"filename star empty", []string{`Content-Disposition: form-data; name="q"; filename*=utf-8''`}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			parts := []rawPart{{headers: tt.headers, value: sqli}, bigFile("f", 1<<20)}
			small := evaluateWindow(t, windowRoute(128*1024, config.OnOversizeReject), multipartType(), rawMultipart(parts))
			whole := evaluateWindow(t, windowRoute(8*1024*1024, config.OnOversizeReject), multipartType(), rawMultipart(parts))
			if got, want := strings.Join(blockingLeaves(small), ","), strings.Join(blockingLeaves(whole), ","); got != want {
				t.Errorf("projected body blocked by [%s], the whole body by [%s]", got, want)
			}
		})
	}
}

// The php2shell shapes are counted from the part headers. Hiding them behind a
// large upload must not work: the headers are kept whatever the upload weighs.
func TestPHP2ShellShapesBehindLargeUploadStillBlocked(t *testing.T) {
	for _, tt := range []struct {
		name  string
		parts []rawPart
		leaf  string
	}{
		{
			"4001 part header lines", append([]rawPart{bigFile("f", 1<<20)},
				fieldPart("x", "v", padHeaders(4001)...)), "php-php2shell-part-headers",
		},
		{
			"header block past the parser limit", append([]rawPart{bigFile("f", 1<<20)},
				fieldPart("x", "v", padHeaders(20000)...)), "php-php2shell-part-headers",
		},
		{
			"21 empty file controls", append([]rawPart{bigFile("f", 1<<20)}, emptyFileControls(21)...),
			"php-php2shell-empty-file-controls",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			res := evaluateWindow(t, windowRoute(128*1024, config.OnOversizeReject), multipartType(), rawMultipart(tt.parts))
			if found, blocking := hasDecision(res, tt.leaf); !found || !blocking {
				t.Errorf("expected %s to block, got blocking leaves %v", tt.leaf, blockingLeaves(res))
			}
		})
	}
}

func TestLargeBodyWithPHP2ShellLeafDisabledFallsBackToWindowRule(t *testing.T) {
	route := windowRoute(128*1024, config.OnOversizeReject)
	route.Disable["php-php2shell-part-headers"] = true
	parts := append([]rawPart{bigFile("f", 1<<20)}, fieldPart("x", "v", padHeaders(20000)...))
	res := evaluateWindow(t, route, multipartType(), rawMultipart(parts))
	if found, blocking := hasDecision(res, maxInspectSizeLeaf); !found || !blocking {
		t.Errorf("expected the window rule to block once the leaf is off, got %v", blockingLeaves(res))
	}
}

func TestNonFileContentOverflowingTheWindowIsRejected(t *testing.T) {
	body := rawMultipart([]rawPart{fieldPart("essay", strings.Repeat("word ", 60*1024))})
	res := evaluateWindow(t, windowRoute(128*1024, config.OnOversizeReject), multipartType(), body)
	found, blocking := hasDecision(res, maxInspectSizeLeaf)
	if !found || !blocking {
		t.Fatalf("expected %s to block, got %v", maxInspectSizeLeaf, blockingLeaves(res))
	}
	if got := protections.StatusFor(maxInspectSizeLeaf); got != http.StatusRequestEntityTooLarge {
		t.Errorf("status for %s = %d, want 413", maxInspectSizeLeaf, got)
	}
}

func TestOversizedNonMultipartBodyRejected(t *testing.T) {
	body := []byte(`{"data":"` + strings.Repeat("a", 200*1024) + `"}`)
	res := evaluateWindow(t, windowRoute(128*1024, config.OnOversizeReject), "application/json", body)
	found, blocking := hasDecision(res, maxInspectSizeLeaf)
	if !found || !blocking {
		t.Fatalf("expected %s to block, got %v", maxInspectSizeLeaf, blockingLeaves(res))
	}
	for _, d := range res.Decisions {
		if d.Protection == "crs-unknown" {
			t.Errorf("oversized body surfaced as an anonymous block: %+v", d)
		}
	}
}

func TestBodyAtExactlyTheLimitFits(t *testing.T) {
	const limit = 128 * 1024
	at := []byte(`{"data":"` + strings.Repeat("a", limit-len(`{"data":""}`)) + `"}`)
	if len(at) != limit {
		t.Fatalf("test body is %d bytes, want %d", len(at), limit)
	}
	if b := blockingLeaves(evaluateWindow(t, windowRoute(limit, config.OnOversizeReject), "application/json", at)); len(b) > 0 {
		t.Errorf("body of exactly max_inspect_size bytes blocked by %v", b)
	}
	over := append(append([]byte{}, at[:len(at)-2]...), []byte(`a"}`)...)
	if len(over) != limit+1 {
		t.Fatalf("test body is %d bytes, want %d", len(over), limit+1)
	}
	if found, blocking := hasDecision(evaluateWindow(t, windowRoute(limit, config.OnOversizeReject), "application/json", over), maxInspectSizeLeaf); !found || !blocking {
		t.Error("body one byte over max_inspect_size was not rejected")
	}
}

func TestInspectPrefixInspectsTheStartAndReportsTheRest(t *testing.T) {
	const sqli = "1 UNION SELECT password FROM users"
	pad := strings.Repeat("a", 190*1024)
	route := windowRoute(128*1024, config.OnOversizeInspectPrefix)

	t.Run("attack inside the window is blocked", func(t *testing.T) {
		body := []byte(`{"q":"` + sqli + `","pad":"` + pad + `"}`)
		res := evaluateWindow(t, route, "application/json", body)
		sawSQLi := false
		for _, l := range blockingLeaves(res) {
			sawSQLi = sawSQLi || strings.HasPrefix(l, "sql-injection")
		}
		if !sawSQLi {
			t.Errorf("attack at the start of the body was not blocked as SQL injection; blocked by %v", blockingLeaves(res))
		}
		if found, blocking := hasDecision(res, "http-compliance-malformed-body"); found && blocking {
			t.Error("a body cut at the window was flagged as malformed")
		}
	})

	t.Run("attack past the window is not seen, and that is recorded", func(t *testing.T) {
		body := []byte(`{"pad":"` + pad + `","q":"` + sqli + `"}`)
		res := evaluateWindow(t, route, "application/json", body)
		if b := blockingLeaves(res); len(b) > 0 {
			t.Errorf("blocked by %v; the attack lies past the window", b)
		}
		found, blocking := hasDecision(res, maxInspectSizeLeaf)
		if !found || blocking {
			t.Errorf("expected a non-blocking %s decision, found=%v blocking=%v", maxInspectSizeLeaf, found, blocking)
		}
	})

	t.Run("a large upload is not reported", func(t *testing.T) {
		body := rawMultipart([]rawPart{fieldPart("t", "x"), bigFile("f", 1<<20)})
		res := evaluateWindow(t, route, multipartType(), body)
		if found, _ := hasDecision(res, maxInspectSizeLeaf); found {
			t.Error("upload reported as exceeding the window")
		}
	})

	t.Run("multipart whose form overflows is inspected from the start", func(t *testing.T) {
		body := rawMultipart([]rawPart{fieldPart("q", sqli), fieldPart("essay", strings.Repeat("word ", 60*1024))})
		res := evaluateWindow(t, route, multipartType(), body)
		if len(blockingLeaves(res)) == 0 {
			t.Error("attack at the start of the form was not blocked")
		}
		if found, blocking := hasDecision(res, maxInspectSizeLeaf); !found || blocking {
			t.Errorf("expected a non-blocking %s decision, found=%v blocking=%v", maxInspectSizeLeaf, found, blocking)
		}
	})
}

func TestWindowLeafDisabledForwardsQuietly(t *testing.T) {
	route := windowRoute(128*1024, config.OnOversizeReject)
	route.Disable[maxInspectSizeLeaf] = true
	body := []byte(`{"data":"` + strings.Repeat("a", 200*1024) + `"}`)
	res := evaluateWindow(t, route, "application/json", body)
	if b := blockingLeaves(res); len(b) > 0 {
		t.Errorf("blocked by %v with the leaf disabled", b)
	}
	if found, _ := hasDecision(res, maxInspectSizeLeaf); found {
		t.Error("disabled leaf still produced a decision")
	}
}

func TestDetectOnlyReportsOversizeAndKeepsInspecting(t *testing.T) {
	const sqli = "1 UNION SELECT password FROM users"
	route := windowRoute(128*1024, config.OnOversizeReject)
	route.Mode = config.ModeDetect
	body := []byte(`{"q":"` + sqli + `","pad":"` + strings.Repeat("a", 200*1024) + `"}`)
	res := evaluateWindow(t, route, "application/json", body)
	if found, _ := hasDecision(res, maxInspectSizeLeaf); !found {
		t.Error("detect-only did not report the oversized body")
	}
	sawAttack := false
	for _, d := range res.Decisions {
		if strings.HasPrefix(d.Protection, "sql-injection") {
			sawAttack = true
		}
	}
	if !sawAttack {
		t.Error("detect-only stopped inspecting at the oversize decision; the attack in the window was not reported")
	}
}

// The projection is only worth anything if Coraza reaches the same verdict on
// it as on the real body. Run bodies through two engines: one whose window
// holds the whole body, one whose window forces the projection, and compare.
func TestProjectionReachesTheVerdictOfTheWholeBody(t *testing.T) {
	const sqli = "1 UNION SELECT password FROM users"
	upload := bigFile("big", 64*1024)

	cases := []struct {
		name  string
		parts []rawPart
	}{
		{"plain form", []rawPart{fieldPart("a", "1"), fieldPart("b", "two")}},
		{"sqli field", []rawPart{fieldPart("q", sqli)}},
		{"xss field", []rawPart{fieldPart("q", "<script>alert(1)</script>")}},
		{"sqli in file content", []rawPart{filePart("f", "a.txt", sqli)}},
		{"sqli under empty filename", []rawPart{{headers: []string{`Content-Disposition: form-data; name="q"; filename=""`}, value: sqli}}},
		{"sqli under filename star", []rawPart{{headers: []string{`Content-Disposition: form-data; name="q"; filename*=utf-8''a.txt`}, value: sqli}}},
		{"sqli under both filenames", []rawPart{{headers: []string{`Content-Disposition: form-data; name="q"; filename=""; filename*=utf-8''a.txt`}, value: sqli}}},
		{"duplicate filename params", []rawPart{{headers: []string{`Content-Disposition: form-data; name="q"; filename="a.txt"; filename="b.txt"`}, value: sqli}}},
		{"duplicate disposition headers", []rawPart{{headers: []string{`Content-Disposition: form-data; name="q"`, `Content-Disposition: form-data; name="q"; filename="a.txt"`}, value: sqli}}},
		{"quoted-printable field", []rawPart{{headers: []string{`Content-Disposition: form-data; name="q"`, "Content-Transfer-Encoding: quoted-printable"}, value: "1 UNION=20SELECT=20password FROM users"}}},
		{"php upload", []rawPart{filePart("f", "shell.php", "<?php system($_GET['c']); ?>")}},
		{"double extension", []rawPart{filePart("f", "photo.jpg.php", "x")}},
		{"traversal filename", []rawPart{filePart("f", "../../etc/passwd", "x")}},
		{"several files one name", []rawPart{filePart("f", "a.txt", "1"), filePart("f", "b.txt", "2")}},
		{"empty file controls over the cap", emptyFileControls(25)},
		{"empty file controls under the cap", emptyFileControls(5)},
		{"part header flood", []rawPart{fieldPart("x", "v", padHeaders(4100)...)}},
		{"upload marker", []rawPart{fieldPart("PHP_SESSION_UPLOAD_PROGRESS", "x")}},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			// A large upload is appended so the whole body overflows the small
			// window while its projection fits.
			body := rawMultipart(append(append([]rawPart{}, tt.parts...), upload))
			whole := evaluateWindow(t, windowRoute(8*1024*1024, config.OnOversizeReject), multipartType(), body)
			// The small window is the body divided by this. The flood's headers
			// alone are most of what the projection keeps, so it needs more room.
			div := 4
			if tt.name == "part header flood" {
				div = 2
			}
			small := evaluateWindow(t, windowRoute(int64(len(body)/div), config.OnOversizeReject), multipartType(), body)

			if found, _ := hasDecision(small, maxInspectSizeLeaf); found {
				t.Fatalf("projection did not fit a window 1/%d of the body (%d bytes)", div, len(body)/div)
			}
			if got, want := verdict(small), verdict(whole); got != want {
				t.Errorf("projected body: %s\nwhole body:     %s", got, want)
			}
		})
	}
}

// verdict is the part of a result that two evaluations of the same request
// must agree on: which protections blocked, and which rules matched.
func verdict(res EvaluationResult) string {
	blocked := map[string]bool{}
	rules := map[int]bool{}
	for _, d := range res.Decisions {
		if d.Protection == maxInspectSizeLeaf {
			continue
		}
		if d.Block {
			blocked[d.Protection] = true
		}
		for _, id := range d.MatchedRules {
			rules[id] = true
		}
	}
	var b []string
	for k := range blocked {
		b = append(b, k)
	}
	sort.Strings(b)
	var r []int
	for id := range rules {
		r = append(r, id)
	}
	sort.Ints(r)
	return fmt.Sprintf("blocked=%v rules=%v", b, r)
}
