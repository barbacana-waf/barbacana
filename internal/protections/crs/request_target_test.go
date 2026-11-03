package crs

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/barbacana-waf/barbacana/internal/protections"
)

// Coraza must see the request target as the client sent it. Rebuilding it
// from the parsed URL escaped a raw '#' in the path to %23 and turned a
// CONNECT authority into "/", so both checks below were silently skipped.
func TestRequestTargetReachesCRSRaw(t *testing.T) {
	eng, err := NewEngine(testRoute())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	cases := []struct {
		method, target, protection string
	}{
		{"GET", "/#fragment", "http-compliance-uri-fragments"},
		{"CONNECT", "www.coreruleset.org", "http-compliance-malformed-request-line"},
	}
	for _, tc := range cases {
		t.Run(tc.method+" "+tc.target, func(t *testing.T) {
			r := httptest.NewRequest(tc.method, tc.target, nil)
			r.Header.Set("User-Agent", "curl/8")
			r.Header.Set("Accept", "*/*")
			ctx := protections.WithInspectionPath(context.Background(), protections.NewInspectionPath(r))

			res := eng.Evaluate(ctx, r)
			for _, d := range res.Decisions {
				if d.Protection == tc.protection {
					return
				}
			}
			t.Errorf("expected a %s decision; got %+v", tc.protection, res.Decisions)
		})
	}
}
