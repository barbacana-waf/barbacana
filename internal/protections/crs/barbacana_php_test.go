package crs

import (
	"bytes"
	"context"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const (
	php2ShellLeaf   = "php-php2shell-session-upload-progress"
	php2ShellRuleID = 211001
	php2ShellField  = "PHP_SESSION_UPLOAD_PROGRESS"
)

// multipartPart is one part of a test multipart body. A non-empty
// filename makes it a file part.
type multipartPart struct {
	name, filename, value string
}

func multipartBody(t *testing.T, parts []multipartPart) (contentType string, body []byte) {
	t.Helper()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	for _, p := range parts {
		var err error
		if p.filename != "" {
			fw, ferr := w.CreateFormFile(p.name, p.filename)
			if ferr == nil {
				_, err = fw.Write([]byte(p.value))
			} else {
				err = ferr
			}
		} else {
			err = w.WriteField(p.name, p.value)
		}
		if err != nil {
			t.Fatalf("build multipart part %q: %v", p.name, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close multipart writer: %v", err)
	}
	return w.FormDataContentType(), buf.Bytes()
}

func php2ShellRequest(method, target, contentType string, body []byte) *http.Request {
	var r *http.Request
	if body != nil {
		r = httptest.NewRequest(method, target, bytes.NewReader(body))
	} else {
		r = httptest.NewRequest(method, target, nil)
	}
	r.Header.Set("Host", "example.com")
	r.Header.Set("User-Agent", "Mozilla/5.0")
	r.Header.Set("Accept", "*/*")
	if contentType != "" {
		r.Header.Set("Content-Type", contentType)
	}
	return r
}

// php2ShellOutcome summarises an evaluation: whether any decision blocked,
// whether the php2shell leaf produced a decision, and whether rule 211001
// appears in any decision's matched rules.
func php2ShellOutcome(res EvaluationResult) (blocked, leafHit, ruleFired bool) {
	for _, d := range res.Decisions {
		if d.Block {
			blocked = true
		}
		if d.Protection == php2ShellLeaf {
			leafHit = true
		}
		for _, id := range d.MatchedRules {
			if id == php2ShellRuleID {
				ruleFired = true
			}
		}
	}
	return blocked, leafHit, ruleFired
}

// TestBarbacanaPHP2ShellRuleBlocksUploadProgressField verifies the custom
// rule 211001 fires on POST requests carrying PHP's upload-progress marker
// field — the CVE-2026-109619 ("PHP2Shell") request vector — across every
// body surface the rule inspects, and that the block is attributed to the
// php-php2shell-session-upload-progress leaf through the catalog's RuleIDs mapping.
//
// This is a WAF-rule test only: no PHP backend is involved, and the
// field value is an arbitrary inert token.
func TestBarbacanaPHP2ShellRuleBlocksUploadProgressField(t *testing.T) {
	eng, err := NewEngine(testRoute())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	multipartCT, multipartField := multipartBody(t, []multipartPart{
		{name: php2ShellField, value: "123"},
		{name: "comment", value: "hello"},
	})
	fileCT, filePart := multipartBody(t, []multipartPart{
		{name: php2ShellField, filename: "progress.txt", value: "123"},
	})

	cases := []struct {
		name        string
		contentType string
		body        []byte
	}{
		{"multipart field", multipartCT, multipartField},
		{"urlencoded field", "application/x-www-form-urlencoded", []byte(php2ShellField + "=123&comment=hello")},
		// Coraza files a part with a filename as an upload (FILES_NAMES /
		// MULTIPART_NAME), not an ARG; the rule must still see it.
		{"multipart file part", fileCT, filePart},
		// A Content-Type Coraza does not parse leaves the raw body in
		// REQUEST_BODY (CRS 901340 forces it); the fallback must catch it.
		{"unparsed body", "text/plain", multipartField},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := php2ShellRequest("POST", "/upload", c.contentType, c.body)
			res := eng.Evaluate(context.Background(), r)

			blocked, leafHit, ruleFired := php2ShellOutcome(res)
			if !blocked {
				t.Errorf("expected request to be blocked; decisions=%+v", res.Decisions)
			}
			if !leafHit {
				t.Errorf("expected a %q decision; decisions=%+v", php2ShellLeaf, res.Decisions)
			}
			if !ruleFired {
				t.Errorf("expected rule %d in matched rules; decisions=%+v", php2ShellRuleID, res.Decisions)
			}
		})
	}
}

// TestBarbacanaPHP2ShellRuleDoesNotFire verifies the rule stays quiet on
// traffic that is not the PHP2Shell request shape.
//
// GET is deliberately not blocked: PHP's upload-progress hook only runs
// while parsing a multipart POST body, so a GET carrying the token cannot
// reach it. This case locks in that the REQUEST_METHOD gate works and the
// rule is not a bare string match on the whole request.
func TestBarbacanaPHP2ShellRuleDoesNotFire(t *testing.T) {
	eng, err := NewEngine(testRoute())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	cleanCT, cleanBody := multipartBody(t, []multipartPart{
		{name: "comment", value: "profile picture update"},
		{name: "avatar", filename: "avatar.png", value: "not really a png"},
	})

	cases := []struct {
		name        string
		method      string
		target      string
		contentType string
		body        []byte
	}{
		{"GET query param", "GET", "/upload?" + php2ShellField + "=123", "", nil},
		{"clean multipart upload", "POST", "/upload", cleanCT, cleanBody},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := php2ShellRequest(c.method, c.target, c.contentType, c.body)
			res := eng.Evaluate(context.Background(), r)

			blocked, leafHit, ruleFired := php2ShellOutcome(res)
			if blocked {
				t.Errorf("expected request to pass; decisions=%+v", res.Decisions)
			}
			if leafHit || ruleFired {
				t.Errorf("rule %d fired unexpectedly; decisions=%+v", php2ShellRuleID, res.Decisions)
			}
		})
	}
}

// TestBarbacanaPHP2ShellRuleDisable verifies that disabling the leaf
// removes rule 211001 (via SecRuleRemoveById from DisabledRuleIDs) so
// the same attack-shaped request passes.
func TestBarbacanaPHP2ShellRuleDisable(t *testing.T) {
	ids := DisabledRuleIDs(map[string]bool{php2ShellLeaf: true})
	if len(ids) != 1 || ids[0] != php2ShellRuleID {
		t.Fatalf("DisabledRuleIDs(%q) = %v, want [%d]", php2ShellLeaf, ids, php2ShellRuleID)
	}

	route := testRoute()
	route.Disable = map[string]bool{php2ShellLeaf: true}
	eng, err := NewEngine(route)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	ct, body := multipartBody(t, []multipartPart{
		{name: php2ShellField, value: "123"},
		{name: "comment", value: "hello"},
	})
	res := eng.Evaluate(context.Background(), php2ShellRequest("POST", "/upload", ct, body))

	blocked, leafHit, ruleFired := php2ShellOutcome(res)
	if blocked {
		t.Errorf("expected request to pass with %q disabled; decisions=%+v", php2ShellLeaf, res.Decisions)
	}
	if leafHit || ruleFired {
		t.Errorf("disabled leaf still produced a decision; decisions=%+v", res.Decisions)
	}
}

// TestBarbacanaPHP2ShellRuleIDResolvesToLeaf pins the rule-ID → leaf
// mapping derived from the catalog.
func TestBarbacanaPHP2ShellRuleIDResolvesToLeaf(t *testing.T) {
	if got := RuleIDToSubProtection(php2ShellRuleID); got != php2ShellLeaf {
		t.Errorf("RuleIDToSubProtection(%d) = %q, want %q", php2ShellRuleID, got, php2ShellLeaf)
	}
	if !strings.Contains(barbacanaPHP2ShellRules, "id:211001,") {
		t.Errorf("barbacanaPHP2ShellRules does not declare id:%d", php2ShellRuleID)
	}
}

// TestBarbacanaPHP2ShellRuleBlocksChunkedBody covers the undeclared-length
// path: net/http reports a chunked body as ContentLength == -1, and the
// engine must still hand the (already buffered and size-capped) body to
// Coraza. Without that the multipart processor never runs and none of the
// php2shell rules can fire on a chunked request.
func TestBarbacanaPHP2ShellRuleBlocksChunkedBody(t *testing.T) {
	eng, err := NewEngine(testRoute())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	ct, body := multipartBody(t, []multipartPart{
		{name: php2ShellField, value: "123"},
		{name: "comment", value: "hello"},
	})
	r := php2ShellRequest("POST", "/upload", ct, body)
	r.ContentLength = -1
	r.TransferEncoding = []string{"chunked"}

	res := eng.Evaluate(context.Background(), r)
	blocked, leafHit, ruleFired := php2ShellOutcome(res)
	if !blocked || !leafHit || !ruleFired {
		t.Errorf("chunked marker POST must be blocked by %q (blocked=%v leaf=%v rule=%v); decisions=%+v",
			php2ShellLeaf, blocked, leafHit, ruleFired, res.Decisions)
	}
}

// TestChunkedBenignBodyNotBlocked guards the side effect of feeding chunked
// bodies to Coraza: a plain chunked POST must not be blocked, and CRS 920180
// (POST without Content-Length/Transfer-Encoding) must not fire, because
// net/http hides Transfer-Encoding from r.Header and the engine re-adds it.
func TestChunkedBenignBodyNotBlocked(t *testing.T) {
	eng, err := NewEngine(testRoute())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	r := php2ShellRequest("POST", "/test", "text/plain", []byte("hello"))
	r.ContentLength = -1
	r.TransferEncoding = []string{"chunked"}

	res := eng.Evaluate(context.Background(), r)
	for _, d := range res.Decisions {
		if d.Block {
			t.Errorf("benign chunked POST blocked: %+v", d)
		}
		for _, id := range d.MatchedRules {
			if id == 920180 {
				t.Errorf("920180 fired on a chunked request: %+v", d)
			}
		}
	}
}
