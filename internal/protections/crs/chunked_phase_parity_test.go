package crs

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const (
	postWithoutLengthLeaf   = "http-compliance-post-without-length"
	postWithoutLengthRuleID = 920180
)

// chunkedPOST builds a POST with no declared length, the way net/http
// presents a Transfer-Encoding: chunked request to a handler: ContentLength
// is -1, the Content-Length header is gone, and the transfer encoding lives
// on r.TransferEncoding rather than in r.Header.
func chunkedPOST(headers map[string]string) *http.Request {
	r := httptest.NewRequest("POST", "/x", strings.NewReader("a=1"))
	r.Header.Set("Host", "example.com")
	r.Header.Set("User-Agent", "Mozilla/5.0")
	r.Header.Set("Accept", "*/*")
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	r.Header.Del("Content-Length")
	r.ContentLength = -1
	r.TransferEncoding = []string{"chunked"}
	return r
}

func anyBlocked(res EvaluationResult) bool {
	for _, d := range res.Decisions {
		if d.Block {
			return true
		}
	}
	return false
}

func firedRule(res EvaluationResult, ruleID int) bool {
	for _, d := range res.Decisions {
		for _, id := range d.MatchedRules {
			if id == ruleID {
				return true
			}
		}
	}
	return false
}

// TestChunkedRequestPhasesAgree pins the parity between the request phase
// (Evaluate) and the request-context replay the response phase does
// (EvaluateResponse). Both go through addRequestHeaders, so both see the
// re-added Transfer-Encoding and neither trips CRS 920180.
//
// When only Evaluate re-added the header, the response phase scored every
// chunked request 3 points (920180, warning) higher than the request phase
// had. For a request whose other matches sat just under the threshold that
// flipped the outcome: runResponsePhase discards the buffered upstream
// response and serves a block instead, so the client got a 403 for a
// request the request phase had allowed — after the upstream had already
// run it and committed whatever it does.
func TestChunkedRequestPhasesAgree(t *testing.T) {
	eng, err := NewEngine(testRoute())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	cases := []struct {
		name    string
		headers map[string]string
	}{
		{"clean", nil},
		// Each of these matches exactly one warning-severity PL1 rule, so
		// the request phase stays below the blocking threshold and the
		// stray 920180 would be enough to push the response phase over it.
		{"obsolete request-range", map[string]string{"Request-Range": "bytes=0-10"}},
		{"conflicting connection", map[string]string{"Connection": "keep-alive, close"}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			reqRes := eng.Evaluate(context.Background(), chunkedPOST(c.headers))
			respRes := eng.EvaluateResponse(context.Background(), chunkedPOST(c.headers), 200,
				http.Header{"Content-Type": []string{"text/html"}}, []byte("<html>ok</html>"))

			if got, want := anyBlocked(respRes), anyBlocked(reqRes); got != want {
				t.Errorf("response phase blocked=%v, request phase blocked=%v: the two phases must agree on the same request\nrequest=%+v\nresponse=%+v",
					got, want, reqRes.Decisions, respRes.Decisions)
			}
			for _, p := range []struct {
				phase string
				res   EvaluationResult
			}{{"request", reqRes}, {"response", respRes}} {
				if firedRule(p.res, postWithoutLengthRuleID) {
					t.Errorf("%s phase: rule %d fired on a chunked request; Transfer-Encoding was not replayed into the transaction; decisions=%+v",
						p.phase, postWithoutLengthRuleID, p.res.Decisions)
				}
			}
		})
	}
}

// TestChunkedRequestStillBlocksOnItsOwnMerits guards the other direction:
// replaying Transfer-Encoding silences 920180, it does not make a chunked
// request unblockable.
func TestChunkedRequestStillBlocksOnItsOwnMerits(t *testing.T) {
	eng, err := NewEngine(testRoute())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	r := chunkedPOST(nil)
	r.URL.RawQuery = "code=%3C%3Fphp+echo+1%3B+%3F%3E"

	res := eng.Evaluate(context.Background(), r)
	if !anyBlocked(res) {
		t.Errorf("expected an inline PHP open tag to be blocked on a chunked request; decisions=%+v", res.Decisions)
	}
}
