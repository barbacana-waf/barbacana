package base64decode

import (
	"encoding/base64"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/barbacana-waf/barbacana/internal/protections"
)

// jsEscape writes every character of s as a \uXXXX escape, as scanners that
// try to hide a payload inside a JSON body do.
func jsEscape(s string) string {
	var b strings.Builder
	for _, r := range s {
		fmt.Fprintf(&b, `\u%04x`, r)
	}
	return b.String()
}

// evaluateBody runs the stage over a POST body of the given Content-Type and
// returns what it added to the inspection args.
func evaluateBody(t *testing.T, contentType, body string) []protections.ArgPair {
	t.Helper()
	ctx, ia := stageCtx()
	r := httptest.NewRequest("POST", "/", strings.NewReader(body))
	r.Header.Set("Content-Type", contentType)
	if d := New(map[string]bool{}).Evaluate(ctx, r, []byte(body)); d.Block {
		t.Fatalf("unexpected block: %+v", d)
	}
	return ia.POST
}

func hasValue(args []protections.ArgPair, prefix, value string) bool {
	for _, a := range args {
		if strings.HasPrefix(a.Name, prefix) && a.Value == value {
			return true
		}
	}
	return false
}

func TestJSONBodyFindsBase64HiddenBehindEscapes(t *testing.T) {
	enc := base64.StdEncoding.EncodeToString([]byte(sqli))
	body := `{"test": true, "k": "` + jsEscape(enc) + `"}`

	// The bytes of this body hold no run of base64 for the flat scan to find.
	_, flat := stageCtx()
	scanBody([]byte(body), flat, newBudget(maxDecodedValues, true))
	if len(flat.POST) != 0 {
		t.Fatalf("flat scan found %v in an all-escaped body; the test premise is wrong", flat.POST)
	}

	if got := evaluateBody(t, "application/json", body); !hasValue(got, "body.b64decoded.", sqli) {
		t.Errorf("stage args = %v, want the decoded payload under body.b64decoded.*", got)
	}
}

func TestJSONBodyBase64IsNotCountedTwice(t *testing.T) {
	enc := base64.StdEncoding.EncodeToString([]byte(sqli))
	got := evaluateBody(t, "application/json", `{"payload":"`+enc+`"}`)
	n := 0
	for _, a := range got {
		if strings.HasPrefix(a.Name, "body.b64decoded.") {
			n++
		}
	}
	if n != 1 {
		t.Errorf("found %d decodes of one blob: %v", n, got)
	}
}

func TestJSONBodyEmitsURLDecodedStrings(t *testing.T) {
	got := evaluateBody(t, "application/json", `{"q": "%27+OR+1%3D1--", "n": "no escapes here"}`)
	if !hasValue(got, "body.urldecoded.", sqli) {
		t.Errorf("stage args = %v, want the URL-decoded value under body.urldecoded.*", got)
	}
	for _, a := range got {
		if a.Value == "no escapes here" {
			t.Errorf("a string with nothing to decode was emitted: %v", a)
		}
	}
}

func TestInvalidJSONFallsBackToFlatScan(t *testing.T) {
	enc := base64.StdEncoding.EncodeToString([]byte(sqli))
	got := evaluateBody(t, "application/json", `{"payload":"`+enc+`"`)
	if !hasValue(got, "body.b64decoded.", sqli) {
		t.Errorf("stage args = %v, want the flat scan to find the blob in malformed JSON", got)
	}
}

func TestNonJSONBodyIsScannedFlat(t *testing.T) {
	enc := base64.StdEncoding.EncodeToString([]byte(sqli))
	got := evaluateBody(t, "text/plain", "note: "+enc+" and 100%25 sure")
	if !hasValue(got, "body.b64decoded.", sqli) {
		t.Errorf("stage args = %v, want the blob found", got)
	}
	for _, a := range got {
		if strings.HasPrefix(a.Name, "body.urldecoded.") {
			t.Errorf("URL-decoded copy produced for a non-JSON body: %v", a)
		}
	}
}

func TestJSONURLDecodedCopiesAreCapped(t *testing.T) {
	var parts []string
	for i := 0; i < 80; i++ {
		parts = append(parts, fmt.Sprintf(`"k%d":"%%41%d"`, i, i))
	}
	got := evaluateBody(t, "application/json", "{"+strings.Join(parts, ",")+"}")
	n := 0
	for _, a := range got {
		if strings.HasPrefix(a.Name, "body.urldecoded.") {
			n++
		}
	}
	if n != maxURLDecodedValues {
		t.Errorf("got %d URL-decoded copies, want the cap of %d", n, maxURLDecodedValues)
	}
}
