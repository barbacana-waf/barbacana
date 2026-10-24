package crs

import (
	"bytes"
	"context"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strconv"
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

const (
	partHeadersLeaf      = "php-php2shell-part-headers"
	emptyFileControlLeaf = "php-php2shell-empty-file-controls"
	partHeaderCountRule  = 212001
	partHeaderParseRule  = 212002
	emptyFileControlRule = 212003
	shapeBoundary        = "BarbacanaShapeBoundary"
)

// rawPart is one part of a hand-built multipart body. Hand-building (rather
// than mime/multipart.Writer) is needed to control extra part headers and to
// emit filename="" exactly as browsers do for an empty file input.
type rawPart struct {
	headers []string // full header lines, without CRLF
	value   string
}

func rawMultipart(parts []rawPart) []byte {
	var b strings.Builder
	for _, p := range parts {
		fmt.Fprintf(&b, "--%s\r\n", shapeBoundary)
		for _, h := range p.headers {
			b.WriteString(h)
			b.WriteString("\r\n")
		}
		b.WriteString("\r\n")
		b.WriteString(p.value)
		b.WriteString("\r\n")
	}
	fmt.Fprintf(&b, "--%s--\r\n", shapeBoundary)
	return []byte(b.String())
}

func fieldPart(name, value string, extra ...string) rawPart {
	h := append([]string{fmt.Sprintf(`Content-Disposition: form-data; name="%s"`, name)}, extra...)
	return rawPart{headers: h, value: value}
}

func filePart(name, filename, value string) rawPart {
	return rawPart{headers: []string{
		fmt.Sprintf(`Content-Disposition: form-data; name="%s"; filename="%s"`, name, filename),
		"Content-Type: text/plain",
	}, value: value}
}

// emptyFileControl is what a browser sends for a file input left empty.
func emptyFileControl(name string) rawPart {
	return rawPart{headers: []string{
		fmt.Sprintf(`Content-Disposition: form-data; name="%s"; filename=""`, name),
		"Content-Type: application/octet-stream",
	}}
}

// padHeaders returns n extra part header lines with distinct names.
func padHeaders(n int) []string {
	h := make([]string, n)
	for i := range h {
		h[i] = "X-P" + strconv.Itoa(i) + ": a"
	}
	return h
}

func emptyFileControls(n int) []rawPart {
	parts := make([]rawPart, n)
	for i := range parts {
		parts[i] = emptyFileControl(fmt.Sprintf("doc%d[a][b]", i))
	}
	return parts
}

// shapeRequest builds a multipart POST with a declared Content-Length, as a
// real client sends it (and as Barbacana's handler presents it to CRS).
func shapeRequest(body []byte) *http.Request {
	r := httptest.NewRequest("POST", "/upload", bytes.NewReader(body))
	r.Header.Set("Host", "example.com")
	r.Header.Set("User-Agent", "Mozilla/5.0")
	r.Header.Set("Accept", "*/*")
	r.Header.Set("Content-Type", "multipart/form-data; boundary="+shapeBoundary)
	r.Header.Set("Content-Length", strconv.Itoa(len(body)))
	return r
}

// shapeOutcome reports whether any decision blocked, whether the given leaf
// produced a decision, and whether ruleID is among the matched rules.
func shapeOutcome(res EvaluationResult, leaf string, ruleID int) (blocked, leafHit, ruleFired bool) {
	for _, d := range res.Decisions {
		if d.Block {
			blocked = true
		}
		if d.Protection == leaf {
			leafHit = true
		}
		for _, id := range d.MatchedRules {
			if id == ruleID {
				ruleFired = true
			}
		}
	}
	return blocked, leafHit, ruleFired
}

// anyShapeRuleFired reports whether any of the 212xxx rules matched.
func anyShapeRuleFired(res EvaluationResult) bool {
	for _, d := range res.Decisions {
		for _, id := range d.MatchedRules {
			if id == partHeaderCountRule || id == partHeaderParseRule || id == emptyFileControlRule {
				return true
			}
		}
	}
	return false
}

// TestBarbacanaMultipartShapeRulesBlockAttackShapes verifies the custom
// 212xxx rules fire on the CVE-2026-109618 request shapes and attribute the
// block to the right catalog leaf. Every body stays under the test route's
// 128KB max_inspect_size so Coraza parses it in full.
//
// WAF-rule test only: no PHP backend is involved.
func TestBarbacanaMultipartShapeRulesBlockAttackShapes(t *testing.T) {
	eng, err := NewEngine(testRoute())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	spread := make([]rawPart, 0, 10)
	for i := 0; i < 10; i++ {
		// 10 parts x (1 Content-Disposition + 400 padding) = 4010 lines.
		spread = append(spread, fieldPart(fmt.Sprintf("f%d", i), "v", padHeaders(400)...))
	}

	unquoted := emptyFileControls(21)
	for i := range unquoted {
		unquoted[i].headers[0] = fmt.Sprintf(`Content-Disposition: form-data; name="u%d"; filename=`, i)
	}

	cases := []struct {
		name   string
		body   []byte
		leaf   string
		ruleID int
	}{
		// 1 Content-Disposition + 4000 padding = 4001 lines in one part.
		{"one part over header cap", rawMultipart([]rawPart{fieldPart("x", "v", padHeaders(4000)...)}), partHeadersLeaf, partHeaderCountRule},
		{"header cap spread across parts", rawMultipart(spread), partHeadersLeaf, partHeaderCountRule},
		// More than Go's 10,000-entry per-part limit: Coraza's parser
		// aborts, MULTIPART_PART_HEADERS stays empty, so only the
		// parser-error rule can see it.
		{"one part over parser header limit", rawMultipart([]rawPart{fieldPart("x", "v", padHeaders(10001)...)}), partHeadersLeaf, partHeaderParseRule},
		{"21 empty file controls with nested names", rawMultipart(append([]rawPart{fieldPart("title", "hello")}, emptyFileControls(21)...)), emptyFileControlLeaf, emptyFileControlRule},
		{"21 empty file controls, unquoted empty filename", rawMultipart(unquoted), emptyFileControlLeaf, emptyFileControlRule},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if len(c.body) >= 128*1024 {
				t.Fatalf("test body is %d bytes; must stay under max_inspect_size", len(c.body))
			}
			res := eng.Evaluate(context.Background(), shapeRequest(c.body))
			blocked, leafHit, ruleFired := shapeOutcome(res, c.leaf, c.ruleID)
			if !blocked {
				t.Errorf("expected request to be blocked; decisions=%+v", res.Decisions)
			}
			if !leafHit {
				t.Errorf("expected a %q decision; decisions=%+v", c.leaf, res.Decisions)
			}
			if !ruleFired {
				t.Errorf("expected rule %d in matched rules; decisions=%+v", c.ruleID, res.Decisions)
			}
		})
	}
}

// TestBarbacanaMultipartShapeRulesDoNotFire verifies the rules stay quiet
// on ordinary multipart traffic, including bodies exactly at each limit and
// header-like text inside part content (which is not a part header).
func TestBarbacanaMultipartShapeRulesDoNotFire(t *testing.T) {
	eng, err := NewEngine(testRoute())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	// A large but legitimate form: 1000 fields + 20 files = 1040 header
	// lines, PHP's default input ceiling.
	bigForm := make([]rawPart, 0, 1020)
	for i := 0; i < 1000; i++ {
		bigForm = append(bigForm, fieldPart(fmt.Sprintf("f%d", i), "v"))
	}
	for i := 0; i < 20; i++ {
		bigForm = append(bigForm, filePart(fmt.Sprintf("file%d", i), fmt.Sprintf("doc%d.txt", i), "notes"))
	}

	headerLikeContent := strings.Repeat("Content-Disposition: form-data; name=\"x\"; filename=\"\"\r\n", 30)

	cases := []struct {
		name string
		body []byte
	}{
		{"ordinary upload", rawMultipart([]rawPart{
			fieldPart("comment", "profile picture update"),
			filePart("avatar", "avatar.txt", "not really an image"),
			emptyFileControl("optional_attachment"),
		})},
		{"exactly 4000 header lines", rawMultipart([]rawPart{fieldPart("x", "v", padHeaders(3999)...)})},
		{"exactly 20 empty file controls", rawMultipart(append([]rawPart{fieldPart("title", "hello")}, emptyFileControls(20)...))},
		{"1000 fields and 20 files", rawMultipart(bigForm)},
		{"header-like text in part content", rawMultipart([]rawPart{filePart("upload", "headers.txt", headerLikeContent)})},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := eng.Evaluate(context.Background(), shapeRequest(c.body))
			if anyShapeRuleFired(res) {
				t.Errorf("multipart-shape rule fired unexpectedly; decisions=%+v", res.Decisions)
			}
			for _, d := range res.Decisions {
				if d.Block {
					t.Errorf("expected request to pass; decisions=%+v", res.Decisions)
					break
				}
			}
		})
	}
}

// TestBarbacanaMultipartShapeRulesDisable verifies that disabling each leaf
// removes exactly its rules (via SecRuleRemoveById from DisabledRuleIDs), so
// its attack shape passes while the sibling leaf still blocks.
func TestBarbacanaMultipartShapeRulesDisable(t *testing.T) {
	headerFlood := rawMultipart([]rawPart{fieldPart("x", "v", padHeaders(4000)...)})
	emptyFlood := rawMultipart(emptyFileControls(21))

	cases := []struct {
		leaf        string
		wantIDs     []int
		attack      []byte
		sibling     []byte
		siblingLeaf string
	}{
		{partHeadersLeaf, []int{partHeaderCountRule, partHeaderParseRule}, headerFlood, emptyFlood, emptyFileControlLeaf},
		{emptyFileControlLeaf, []int{emptyFileControlRule}, emptyFlood, headerFlood, partHeadersLeaf},
	}

	for _, c := range cases {
		t.Run(c.leaf, func(t *testing.T) {
			ids := DisabledRuleIDs(map[string]bool{c.leaf: true})
			got := map[int]bool{}
			for _, id := range ids {
				got[id] = true
			}
			if len(ids) != len(c.wantIDs) {
				t.Fatalf("DisabledRuleIDs(%q) = %v, want %v", c.leaf, ids, c.wantIDs)
			}
			for _, id := range c.wantIDs {
				if !got[id] {
					t.Fatalf("DisabledRuleIDs(%q) = %v, missing %d", c.leaf, ids, id)
				}
			}

			route := testRoute()
			route.Disable = map[string]bool{c.leaf: true}
			eng, err := NewEngine(route)
			if err != nil {
				t.Fatalf("NewEngine: %v", err)
			}

			res := eng.Evaluate(context.Background(), shapeRequest(c.attack))
			for _, d := range res.Decisions {
				if d.Block {
					t.Errorf("expected attack shape to pass with %q disabled; decisions=%+v", c.leaf, res.Decisions)
					break
				}
			}
			if anyShapeRuleFired(res) {
				t.Errorf("disabled leaf's rule still matched; decisions=%+v", res.Decisions)
			}

			res = eng.Evaluate(context.Background(), shapeRequest(c.sibling))
			if blocked, leafHit, _ := shapeOutcome(res, c.siblingLeaf, 0); !blocked || !leafHit {
				t.Errorf("sibling leaf %q should still block; decisions=%+v", c.siblingLeaf, res.Decisions)
			}
		})
	}
}

// TestBarbacanaMultipartShapeOversizedBodyRejected locks in the scope claim
// in barbacana_php2shell.go: in blocking mode, a declared-length body
// at or above max_inspect_size never reaches these rules because Coraza's
// default SecRequestBodyLimitAction (Reject) turns it away first. If this
// test starts failing, the body-limit action changed and the rule file's
// scope notes must be revisited.
func TestBarbacanaMultipartShapeOversizedBodyRejected(t *testing.T) {
	eng, err := NewEngine(testRoute())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	body := rawMultipart([]rawPart{fieldPart("x", "v", padHeaders(20000)...)})
	if len(body) < 128*1024 {
		t.Fatalf("test body is %d bytes; must exceed max_inspect_size", len(body))
	}
	res := eng.Evaluate(context.Background(), shapeRequest(body))
	blocked := false
	for _, d := range res.Decisions {
		if d.Block {
			blocked = true
		}
	}
	if !blocked {
		t.Errorf("expected oversized body to be rejected in blocking mode; decisions=%+v", res.Decisions)
	}
}

// TestBarbacanaMultipartShapeRuleIDsResolveToLeaves pins the rule-ID → leaf
// mapping derived from the catalog.
func TestBarbacanaMultipartShapeRuleIDsResolveToLeaves(t *testing.T) {
	want := map[int]string{
		partHeaderCountRule:  partHeadersLeaf,
		partHeaderParseRule:  partHeadersLeaf,
		emptyFileControlRule: emptyFileControlLeaf,
	}
	for id, leaf := range want {
		if got := RuleIDToSubProtection(id); got != leaf {
			t.Errorf("RuleIDToSubProtection(%d) = %q, want %q", id, got, leaf)
		}
		if !strings.Contains(barbacanaPHP2ShellMultipartRules, "id:"+strconv.Itoa(id)+",") {
			t.Errorf("barbacanaPHP2ShellMultipartRules does not declare id:%d", id)
		}
	}
}
