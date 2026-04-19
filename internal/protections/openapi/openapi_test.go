package openapi

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/barbacana-waf/barbacana/internal/config"
)

func testCfg() config.Resolved {
	strict := true
	return config.Resolved{
		ID:      "test",
		Mode:    config.ModeBlocking,
		Disable: map[string]bool{},
		OpenAPI: &config.OpenAPIRoute{
			Spec:    "testdata/specs/petstore.yaml",
			Strict:  &strict,
			Disable: nil,
		},
		ShadowAPILogging: true,
		Inspection: config.ResolvedInspection{
			EvaluationTimeout: 50 * time.Millisecond,
		},
	}
}

func TestValidateUndeclaredPath(t *testing.T) {
	cfg := testCfg()
	v, err := NewValidator("testdata/specs/petstore.yaml", cfg)
	if err != nil {
		t.Fatalf("NewValidator: %v", err)
	}

	r := httptest.NewRequest("GET", "/unknown", nil)
	d := v.Validate(context.Background(), r)
	if !d.Block || d.Protection != OpenAPIPath {
		t.Errorf("expected path block, got: %+v", d)
	}
}

func TestValidateDeclaredPath(t *testing.T) {
	cfg := testCfg()
	v, err := NewValidator("testdata/specs/petstore.yaml", cfg)
	if err != nil {
		t.Fatalf("NewValidator: %v", err)
	}

	r := httptest.NewRequest("GET", "/pets", nil)
	d := v.Validate(context.Background(), r)
	if d.Block {
		t.Errorf("valid path should pass, got: %+v", d)
	}
}

func TestValidateInvalidBody(t *testing.T) {
	cfg := testCfg()
	v, err := NewValidator("testdata/specs/petstore.yaml", cfg)
	if err != nil {
		t.Fatalf("NewValidator: %v", err)
	}

	// POST without required "name" field.
	body := `{"age": 5}`
	r := httptest.NewRequest("POST", "/pets", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	d := v.Validate(context.Background(), r)
	if !d.Block {
		t.Errorf("invalid body should be blocked, got: %+v", d)
	}
}

func TestValidateValidBody(t *testing.T) {
	cfg := testCfg()
	v, err := NewValidator("testdata/specs/petstore.yaml", cfg)
	if err != nil {
		t.Fatalf("NewValidator: %v", err)
	}

	body := `{"name": "Fluffy", "age": 3}`
	r := httptest.NewRequest("POST", "/pets", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	d := v.Validate(context.Background(), r)
	if d.Block {
		t.Errorf("valid body should pass, got: %+v", d)
	}
}

func TestValidatePathDisabled(t *testing.T) {
	cfg := testCfg()
	cfg.OpenAPI.Disable = []string{"openapi-path"}
	v, err := NewValidator("testdata/specs/petstore.yaml", cfg)
	if err != nil {
		t.Fatalf("NewValidator: %v", err)
	}

	r := httptest.NewRequest("GET", "/unknown", nil)
	d := v.Validate(context.Background(), r)
	if d.Block {
		t.Error("should pass when openapi-path is disabled")
	}
}
