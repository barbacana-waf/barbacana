package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"testing"
	"time"
)

func TestEmitProducesAllFields(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	slog.SetDefault(logger)

	entry := Entry{
		Timestamp:          time.Date(2026, 1, 15, 10, 30, 0, 0, time.UTC),
		RequestID:          "req-123",
		SourceIP:           "10.0.0.1",
		Method:             "GET",
		Host:               "example.com",
		Path:               "/api/users",
		RouteID:            "api-users",
		MatchedProtections: []string{"sql-injection-auth-bypass"},
		MatchedRules:       []int{942100},
		CWE:                []string{"CWE-89"},
		AnomalyScore:       5,
		Action:             "blocked",
		ResponseCode:       403,
	}
	Emit(context.Background(), entry)

	var parsed map[string]any
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("failed to parse audit JSON: %v\nraw: %s", err, buf.String())
	}

	requiredFields := []string{
		"timestamp", "request_id", "source_ip", "method", "host",
		"path", "route_id", "matched_protections", "matched_rules",
		"cwe", "anomaly_score", "action", "response_code",
	}
	for _, f := range requiredFields {
		if _, ok := parsed[f]; !ok {
			t.Errorf("missing required field %q in audit log: %s", f, buf.String())
		}
	}

	if parsed["action"] != "blocked" {
		t.Errorf("action = %v, want blocked", parsed["action"])
	}
	if parsed["request_id"] != "req-123" {
		t.Errorf("request_id = %v, want req-123", parsed["request_id"])
	}
	if parsed["route_id"] != "api-users" {
		t.Errorf("route_id = %v, want api-users", parsed["route_id"])
	}
}

func TestEmitEmptyArraysNotNull(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	slog.SetDefault(logger)

	entry := Entry{
		Timestamp:          time.Now(),
		RequestID:          "req-456",
		SourceIP:           "10.0.0.2",
		Method:             "POST",
		Host:               "example.com",
		Path:               "/login",
		RouteID:            "login",
		MatchedProtections: []string{"null-byte-injection"},
		MatchedRules:       []int{},
		CWE:                []string{"CWE-158"},
		Action:             "blocked",
		ResponseCode:       403,
	}
	Emit(context.Background(), entry)

	var parsed map[string]any
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("failed to parse audit JSON: %v", err)
	}

	// matched_rules should be an empty array, not null
	rules, ok := parsed["matched_rules"]
	if !ok {
		t.Fatal("matched_rules missing from audit log")
	}
	arr, ok := rules.([]any)
	if !ok {
		t.Fatalf("matched_rules is not an array: %T", rules)
	}
	if len(arr) != 0 {
		t.Errorf("matched_rules should be empty, got %v", arr)
	}
}

func TestEmitDetectedAction(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	slog.SetDefault(logger)

	entry := Entry{
		Timestamp:          time.Now(),
		RequestID:          "req-789",
		SourceIP:           "10.0.0.3",
		Method:             "GET",
		Host:               "example.com",
		Path:               "/search",
		RouteID:            "search",
		MatchedProtections: []string{"xss-script-tag", "sql-injection-auth-bypass"},
		MatchedRules:       []int{941110, 942100},
		CWE:                []string{"CWE-79", "CWE-89"},
		AnomalyScore:       10,
		Action:             "detected",
		ResponseCode:       200,
	}
	Emit(context.Background(), entry)

	var parsed map[string]any
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("failed to parse audit JSON: %v", err)
	}

	if parsed["action"] != "detected" {
		t.Errorf("action = %v, want detected", parsed["action"])
	}
	if parsed["response_code"] != float64(200) {
		t.Errorf("response_code = %v, want 200", parsed["response_code"])
	}

	protections := parsed["matched_protections"].([]any)
	if len(protections) != 2 {
		t.Errorf("matched_protections length = %d, want 2", len(protections))
	}
}
