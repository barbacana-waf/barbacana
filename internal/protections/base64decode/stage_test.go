package base64decode

import (
	"context"
	"encoding/base64"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/barbacana-waf/barbacana/internal/protections"
)

const sqli = "' OR 1=1--"

// stageCtx returns a context with an empty InspectionArgs ready for the
// stage to populate. Mirrors how the pipeline wires the stage.
func stageCtx() (context.Context, *protections.InspectionArgs) {
	ia := protections.NewInspectionArgs()
	ctx := protections.WithInspectionArgs(context.Background(), ia)
	return ctx, ia
}

func TestStageEmitsQueryParam(t *testing.T) {
	ctx, ia := stageCtx()
	enc := base64.StdEncoding.EncodeToString([]byte(sqli))
	r := httptest.NewRequest("GET", "/?q="+enc, nil)
	st := New(map[string]bool{})
	if d := st.Evaluate(ctx, r, nil); d.Block {
		t.Fatalf("unexpected block: %+v", d)
	}
	if len(ia.GET) != 1 {
		t.Fatalf("ia.GET = %v; want one entry", ia.GET)
	}
	if ia.GET[0].Name != "q.b64decoded" {
		t.Errorf("name = %q; want %q", ia.GET[0].Name, "q.b64decoded")
	}
	if ia.GET[0].Value != sqli {
		t.Errorf("value = %q; want %q", ia.GET[0].Value, sqli)
	}
}

func TestStageEmitsRepeatedQueryKey(t *testing.T) {
	ctx, ia := stageCtx()
	enc1 := base64.StdEncoding.EncodeToString([]byte(sqli))
	enc2 := base64.RawURLEncoding.EncodeToString([]byte("UNION SELECT * FROM users"))
	r := httptest.NewRequest("GET", "/?key="+enc1+"&key="+enc2, nil)
	st := New(map[string]bool{})
	if d := st.Evaluate(ctx, r, nil); d.Block {
		t.Fatalf("unexpected block: %+v", d)
	}
	if len(ia.GET) != 2 {
		t.Fatalf("ia.GET = %v; want two entries", ia.GET)
	}
	for _, p := range ia.GET {
		if p.Name != "key.b64decoded" {
			t.Errorf("name = %q; want %q", p.Name, "key.b64decoded")
		}
	}
}

func TestStageEmitsPathSegment(t *testing.T) {
	ctx, ia := stageCtx()
	seg := base64.StdEncoding.EncodeToString([]byte(sqli))
	r := httptest.NewRequest("GET", "/"+seg+"/users", nil)
	st := New(map[string]bool{})
	if d := st.Evaluate(ctx, r, nil); d.Block {
		t.Fatalf("unexpected block: %+v", d)
	}
	if len(ia.PATH) == 0 {
		t.Fatalf("ia.PATH = %v; want at least one entry", ia.PATH)
	}
	found := false
	for _, p := range ia.PATH {
		if p.Value == sqli {
			found = true
		}
	}
	if !found {
		t.Errorf("expected sqli decoded value in ia.PATH; got %v", ia.PATH)
	}
}

func TestStageEmitsBodySubstring(t *testing.T) {
	ctx, ia := stageCtx()
	enc := base64.StdEncoding.EncodeToString([]byte(sqli))
	body := []byte(`{"payload":"` + enc + `"}`)
	r := httptest.NewRequest("POST", "/api", nil)
	st := New(map[string]bool{})
	if d := st.Evaluate(ctx, r, body); d.Block {
		t.Fatalf("unexpected block: %+v", d)
	}
	found := false
	for _, p := range ia.POST {
		if p.Value == sqli {
			found = true
		}
	}
	if !found {
		t.Errorf("expected sqli decoded value in ia.POST; got %v", ia.POST)
	}
}

func TestStageDisabledLeafSkipsSurface(t *testing.T) {
	ctx, ia := stageCtx()
	enc := base64.StdEncoding.EncodeToString([]byte(sqli))
	r := httptest.NewRequest("GET", "/?q="+enc, nil)
	st := New(map[string]bool{LeafQuery: true})
	if d := st.Evaluate(ctx, r, nil); d.Block {
		t.Fatalf("unexpected block: %+v", d)
	}
	if len(ia.GET) != 0 {
		t.Errorf("ia.GET = %v; want empty when query leaf disabled", ia.GET)
	}
}

func TestStageFloodBlocks(t *testing.T) {
	ctx, ia := stageCtx()
	// Build a query string with maxDecodedValues+1 distinct base64-shaped
	// values, each of which decodes successfully.
	enc := base64.StdEncoding.EncodeToString([]byte(sqli))
	var sb strings.Builder
	sb.WriteString("/?")
	for i := 0; i < maxDecodedValues+5; i++ {
		if i > 0 {
			sb.WriteByte('&')
		}
		sb.WriteByte('k')
		sb.WriteByte(byte('a' + (i % 26)))
		sb.WriteByte(byte('a' + (i / 26)))
		sb.WriteByte('=')
		sb.WriteString(enc)
	}
	r := httptest.NewRequest("GET", sb.String(), nil)
	st := New(map[string]bool{})
	d := st.Evaluate(ctx, r, nil)
	if !d.Block {
		t.Fatalf("expected block; got %+v with %d ia.GET entries", d, len(ia.GET))
	}
	if d.Protection != LeafFlood {
		t.Errorf("d.Protection = %q; want %q", d.Protection, LeafFlood)
	}
}

func TestStageManyShortNonBase64Passes(t *testing.T) {
	ctx, ia := stageCtx()
	// 60 short non-base64 fields. Decoder rejects each (below minLen or
	// printable-ratio gate), so the budget never trips.
	var sb strings.Builder
	sb.WriteString("/?")
	for i := 0; i < 60; i++ {
		if i > 0 {
			sb.WriteByte('&')
		}
		sb.WriteByte('k')
		sb.WriteByte(byte('a' + (i % 26)))
		sb.WriteByte(byte('a' + (i / 26)))
		sb.WriteString("=hi")
	}
	r := httptest.NewRequest("GET", sb.String(), nil)
	st := New(map[string]bool{})
	if d := st.Evaluate(ctx, r, nil); d.Block {
		t.Fatalf("unexpected block: %+v (ia.GET len=%d)", d, len(ia.GET))
	}
}

func TestStageWithoutContextNoOps(t *testing.T) {
	r := httptest.NewRequest("GET", "/?q="+base64.StdEncoding.EncodeToString([]byte(sqli)), nil)
	st := New(map[string]bool{})
	if d := st.Evaluate(context.Background(), r, nil); d.Block {
		t.Fatalf("unexpected block in no-context path: %+v", d)
	}
}

func TestStageFloodLeafDisabledDoesNotBlock(t *testing.T) {
	ctx, _ := stageCtx()
	enc := base64.StdEncoding.EncodeToString([]byte(sqli))
	var sb strings.Builder
	sb.WriteString("/?")
	for i := 0; i < maxDecodedValues+5; i++ {
		if i > 0 {
			sb.WriteByte('&')
		}
		sb.WriteByte('k')
		sb.WriteByte(byte('a' + (i % 26)))
		sb.WriteByte(byte('a' + (i / 26)))
		sb.WriteByte('=')
		sb.WriteString(enc)
	}
	r := httptest.NewRequest("GET", sb.String(), nil)
	st := New(map[string]bool{LeafFlood: true})
	if d := st.Evaluate(ctx, r, nil); d.Block {
		t.Errorf("flood leaf disabled but stage blocked: %+v", d)
	}
}
