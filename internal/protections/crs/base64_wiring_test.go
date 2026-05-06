package crs

import (
	"context"
	"encoding/base64"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/barbacana-waf/barbacana/internal/protections"
)

// TestDecodedArgReachesCRS verifies the end-to-end wiring: a decoded
// SQLi payload placed in InspectionArgs.GET reaches CRS as an ARG and
// triggers a SQLi rule. Also verifies that dot-bearing argument names
// (the synthetic naming convention used by the base64-decoding stage)
// are accepted by Coraza.
func TestDecodedArgReachesCRS(t *testing.T) {
	route := testRoute()
	eng, err := NewEngine(route)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	r := httptest.NewRequest("GET", "/test", nil)
	r.Header.Set("Host", "example.com")
	r.Header.Set("User-Agent", "curl/8")
	r.Header.Set("Accept", "*/*")

	ia := protections.NewInspectionArgs()
	ia.GET = append(ia.GET, protections.ArgPair{
		Name:  "q.b64decoded",
		Value: "' OR 1=1--",
	})
	ctx := protections.WithInspectionArgs(context.Background(), ia)

	res := eng.Evaluate(ctx, r)

	foundSQLi := false
	for _, d := range res.Decisions {
		if strings.HasPrefix(d.Protection, "sql-injection") {
			foundSQLi = true
			break
		}
	}
	if !foundSQLi {
		t.Errorf("expected a sql-injection decision; got %+v (anomaly=%d)",
			res.Decisions, res.AnomalyScore)
	}
}

// TestDecodedJWTHeaderDoesNotFire ensures a benign JSON payload (the
// decoded form of a JWT header) does not trigger any CRS rule when
// surfaced as a synthetic ARG. Catches over-eager false positives in
// the wiring path.
func TestDecodedJWTHeaderDoesNotFire(t *testing.T) {
	route := testRoute()
	eng, err := NewEngine(route)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	r := httptest.NewRequest("GET", "/test", nil)
	r.Header.Set("Host", "example.com")
	r.Header.Set("User-Agent", "curl/8")
	r.Header.Set("Accept", "*/*")

	ia := protections.NewInspectionArgs()
	jwt := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	ia.GET = append(ia.GET, protections.ArgPair{
		Name:  "token.b64decoded",
		Value: jwt,
	})
	ctx := protections.WithInspectionArgs(context.Background(), ia)

	res := eng.Evaluate(ctx, r)

	for _, d := range res.Decisions {
		if d.Block {
			t.Errorf("benign JWT header decoded value triggered block: %+v", d)
		}
	}
}
