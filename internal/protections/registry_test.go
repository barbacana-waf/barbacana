package protections

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// stubProtection is a minimal Protection for testing.
type stubProtection struct {
	name     string
	category string
	block    bool
}

func (s stubProtection) Name() string     { return s.name }
func (s stubProtection) Category() string { return s.category }
func (s stubProtection) Evaluate(_ context.Context, _ *http.Request) Decision {
	if s.block {
		return Block(s.name, "test block")
	}
	return Allow()
}

func TestRegistryAddAndGet(t *testing.T) {
	reg := NewRegistry()
	p := stubProtection{name: "null-byte-injection"}
	reg.Add(p)

	got := reg.Get("null-byte-injection")
	if got == nil {
		t.Fatal("Get returned nil for registered protection")
	}
	if got.Name() != "null-byte-injection" {
		t.Errorf("Name() = %q", got.Name())
	}
}

func TestRegistryDuplicatePanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic on duplicate registration")
		}
	}()
	reg := NewRegistry()
	reg.Add(stubProtection{name: "test"})
	reg.Add(stubProtection{name: "test"})
}

func TestRegistryCategory(t *testing.T) {
	reg := NewRegistry()
	reg.Add(stubProtection{name: "sql-injection-union", category: "sql-injection"})
	reg.Add(stubProtection{name: "sql-injection-blind", category: "sql-injection"})

	subs := reg.SubProtections("sql-injection")
	if len(subs) != 2 {
		t.Fatalf("want 2 sub-protections, got %d", len(subs))
	}
}

func TestExpandDisable(t *testing.T) {
	disabled := ExpandDisable([]string{"sql-injection"})
	if !disabled["sql-injection"] {
		t.Error("category should be disabled")
	}
	if !disabled["sql-injection-union"] {
		t.Error("sub-protection should be disabled via category")
	}
	if disabled["xss-script-tag"] {
		t.Error("unrelated protection should not be disabled")
	}
}

func TestExpandDisableSubOnly(t *testing.T) {
	disabled := ExpandDisable([]string{"sql-injection-union"})
	if !disabled["sql-injection-union"] {
		t.Error("directly disabled sub-protection should be in set")
	}
	if disabled["sql-injection"] {
		t.Error("parent category should NOT be disabled when only a sub is listed")
	}
	if disabled["sql-injection-blind"] {
		t.Error("sibling should NOT be disabled")
	}
}

func TestIsDisabled(t *testing.T) {
	disabled := map[string]bool{"null-byte-injection": true}
	if !IsDisabled("null-byte-injection", disabled) {
		t.Error("should be disabled")
	}
	if IsDisabled("crlf-injection", disabled) {
		t.Error("should not be disabled")
	}
}

func TestDecisionBlockAllow(t *testing.T) {
	d := Allow()
	if d.Block {
		t.Error("Allow() should not block")
	}
	d = Block("test", "reason")
	if !d.Block || d.Protection != "test" || d.Reason != "reason" {
		t.Errorf("unexpected decision: %+v", d)
	}
}

func TestWriteBlockResponse(t *testing.T) {
	w := httptest.NewRecorder()
	WriteBlockResponse(w, "req-123", http.StatusForbidden)
	if w.Code != 403 {
		t.Errorf("status = %d, want 403", w.Code)
	}
	body := w.Body.String()
	if !contains(body, `"error":"blocked"`) {
		t.Errorf("body = %s", body)
	}
	if !contains(body, `"request_id":"req-123"`) {
		t.Errorf("body missing request_id: %s", body)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && containsInner(s, sub)
}

func containsInner(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
