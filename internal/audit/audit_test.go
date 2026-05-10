package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/otel/trace"
)

// resetForTest restores the package defaults between tests so format
// selection or output redirection in one case does not leak into the
// next. Fail-loud: callers register a t.Cleanup so a panic mid-test
// still resets state.
func resetForTest(t *testing.T, format Format, w *bytes.Buffer) {
	t.Helper()
	SetOutput(w)
	SetFormat(string(format))
	t.Cleanup(func() {
		SetFormat(string(FormatOCSF))
	})
}

func sampleEvent() Event {
	return Event{
		Timestamp:    time.Date(2026, 1, 15, 10, 30, 0, 0, time.UTC),
		RequestID:    "req-123",
		SourceIP:     "10.0.0.1",
		SourcePort:   54321,
		Method:       "POST",
		Host:         "api.example.com",
		Path:         "/login",
		URLFull:      "https://api.example.com/login?next=/admin",
		UserAgent:    "curl/8.0",
		RouteID:      "api-login",
		Protections:  []string{"sql-injection-auth-bypass"},
		RuleIDs:      []int{942100, 942110},
		CWE:          []string{"CWE-89"},
		AnomalyScore: 12,
		Action:       "blocked",
		ResponseCode: 403,
	}
}

func TestEmitOCSFRequiredFields(t *testing.T) {
	var buf bytes.Buffer
	resetForTest(t, FormatOCSF, &buf)

	Emit(context.Background(), sampleEvent())

	var parsed map[string]any
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("parse OCSF JSON: %v\nraw: %s", err, buf.String())
	}

	if got := parsed["class_uid"]; got != float64(ocsfClassHTTPActivity) {
		t.Errorf("class_uid = %v, want %d", got, ocsfClassHTTPActivity)
	}
	if got := parsed["activity_id"]; got != float64(ocsfActivityHTTPTrace) {
		t.Errorf("activity_id = %v, want %d (HTTP Trace for blocked)", got, ocsfActivityHTTPTrace)
	}
	if got := parsed["disposition"]; got != "Blocked" {
		t.Errorf("disposition = %v, want Blocked", got)
	}
	if got := parsed["status_code"]; got != float64(403) {
		t.Errorf("status_code = %v, want 403", got)
	}

	attacks, ok := parsed["attacks"].([]any)
	if !ok || len(attacks) == 0 {
		t.Fatalf("attacks missing or empty: %v", parsed["attacks"])
	}
	first, _ := attacks[0].(map[string]any)
	if first["name"] != "sql-injection-auth-bypass" {
		t.Errorf("attacks[0].name = %v, want sql-injection-auth-bypass", first["name"])
	}
	if first["category"] != "sql-injection" {
		t.Errorf("attacks[0].category = %v, want sql-injection", first["category"])
	}

	rule, ok := parsed["firewall_rule"].(map[string]any)
	if !ok {
		t.Fatalf("firewall_rule missing or wrong type: %v", parsed["firewall_rule"])
	}
	if rule["uid"] != "942100" {
		t.Errorf("firewall_rule.uid = %v, want 942100", rule["uid"])
	}
}

func TestEmitOCSFAllowedActivity(t *testing.T) {
	var buf bytes.Buffer
	resetForTest(t, FormatOCSF, &buf)

	ev := sampleEvent()
	ev.Action = "detected"
	ev.ResponseCode = 200
	Emit(context.Background(), ev)

	var parsed map[string]any
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("parse OCSF JSON: %v", err)
	}

	if got := parsed["activity_id"]; got != float64(ocsfActivityHTTPRequest) {
		t.Errorf("activity_id = %v, want %d (HTTP Request for detected)", got, ocsfActivityHTTPRequest)
	}
	if got := parsed["disposition"]; got != "Allowed" {
		t.Errorf("disposition = %v, want Allowed", got)
	}
}

func TestEmitECSRequiredFields(t *testing.T) {
	var buf bytes.Buffer
	resetForTest(t, FormatECS, &buf)

	Emit(context.Background(), sampleEvent())

	var parsed map[string]any
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("parse ECS JSON: %v\nraw: %s", err, buf.String())
	}

	if _, ok := parsed["@timestamp"]; !ok {
		t.Errorf("@timestamp missing")
	}

	event, ok := parsed["event"].(map[string]any)
	if !ok {
		t.Fatalf("event missing or wrong type")
	}
	if event["kind"] != "alert" {
		t.Errorf("event.kind = %v, want alert", event["kind"])
	}
	if event["action"] != "block" {
		t.Errorf("event.action = %v, want block", event["action"])
	}
	if event["outcome"] != "failure" {
		t.Errorf("event.outcome = %v, want failure", event["outcome"])
	}

	rule, _ := parsed["rule"].(map[string]any)
	if rule["category"] != "sql-injection-auth-bypass" {
		t.Errorf("rule.category = %v, want sql-injection-auth-bypass", rule["category"])
	}

	vuln, _ := parsed["vulnerability"].(map[string]any)
	classification, _ := vuln["classification"].([]any)
	if len(classification) != 1 || classification[0] != "CWE-89" {
		t.Errorf("vulnerability.classification = %v, want [CWE-89]", classification)
	}

	client, _ := parsed["client"].(map[string]any)
	if client["ip"] != "10.0.0.1" {
		t.Errorf("client.ip = %v, want 10.0.0.1", client["ip"])
	}
	if client["port"] != float64(54321) {
		t.Errorf("client.port = %v, want 54321", client["port"])
	}

	url, _ := parsed["url"].(map[string]any)
	if url["path"] != "/login" {
		t.Errorf("url.path = %v, want /login", url["path"])
	}
}

func TestEmitECSDetectedOutcome(t *testing.T) {
	var buf bytes.Buffer
	resetForTest(t, FormatECS, &buf)

	ev := sampleEvent()
	ev.Action = "detected"
	ev.ResponseCode = 200
	Emit(context.Background(), ev)

	var parsed map[string]any
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("parse ECS JSON: %v", err)
	}

	event, _ := parsed["event"].(map[string]any)
	if event["action"] != "allow" {
		t.Errorf("event.action = %v, want allow", event["action"])
	}
	if event["outcome"] != "success" {
		t.Errorf("event.outcome = %v, want success", event["outcome"])
	}
}

func TestEmitOCSFRouteID(t *testing.T) {
	var buf bytes.Buffer
	resetForTest(t, FormatOCSF, &buf)

	Emit(context.Background(), sampleEvent())

	var parsed map[string]any
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("parse OCSF JSON: %v", err)
	}
	md, _ := parsed["metadata"].(map[string]any)
	if md["route_id"] != "api-login" {
		t.Errorf("metadata.route_id = %v, want api-login", md["route_id"])
	}
}

func TestEmitOCSFRouteIDAbsentWhenEmpty(t *testing.T) {
	var buf bytes.Buffer
	resetForTest(t, FormatOCSF, &buf)

	ev := sampleEvent()
	ev.RouteID = ""
	Emit(context.Background(), ev)

	var parsed map[string]any
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("parse OCSF JSON: %v", err)
	}
	md, _ := parsed["metadata"].(map[string]any)
	if _, ok := md["route_id"]; ok {
		t.Errorf("metadata.route_id should be absent when empty, got %v", md["route_id"])
	}
}

func TestEmitTraceCorrelationFromContext(t *testing.T) {
	var buf bytes.Buffer
	resetForTest(t, FormatOCSF, &buf)

	tid, _ := trace.TraceIDFromHex("0102030405060708090a0b0c0d0e0f10")
	sid, _ := trace.SpanIDFromHex("1112131415161718")
	sc := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    tid,
		SpanID:     sid,
		TraceFlags: trace.FlagsSampled,
	})
	ctx := trace.ContextWithSpanContext(context.Background(), sc)

	Emit(ctx, sampleEvent())

	var parsed map[string]any
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("parse OCSF JSON: %v", err)
	}
	md, _ := parsed["metadata"].(map[string]any)
	if md["trace_id"] != tid.String() {
		t.Errorf("metadata.trace_id = %v, want %s", md["trace_id"], tid.String())
	}
	if md["span_id"] != sid.String() {
		t.Errorf("metadata.span_id = %v, want %s", md["span_id"], sid.String())
	}
}

func TestEmitTraceCorrelationECS(t *testing.T) {
	var buf bytes.Buffer
	resetForTest(t, FormatECS, &buf)

	tid, _ := trace.TraceIDFromHex("0102030405060708090a0b0c0d0e0f10")
	sid, _ := trace.SpanIDFromHex("1112131415161718")
	sc := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    tid,
		SpanID:     sid,
		TraceFlags: trace.FlagsSampled,
	})
	ctx := trace.ContextWithSpanContext(context.Background(), sc)

	Emit(ctx, sampleEvent())

	var parsed map[string]any
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("parse ECS JSON: %v", err)
	}

	traceObj, _ := parsed["trace"].(map[string]any)
	if traceObj["id"] != tid.String() {
		t.Errorf("trace.id = %v, want %s", traceObj["id"], tid.String())
	}
	span, _ := parsed["span"].(map[string]any)
	if span["id"] != sid.String() {
		t.Errorf("span.id = %v, want %s", span["id"], sid.String())
	}
}

func TestTraceFieldsAbsentWhenTracingDisabled(t *testing.T) {
	var buf bytes.Buffer
	resetForTest(t, FormatOCSF, &buf)

	Emit(context.Background(), sampleEvent())

	var parsed map[string]any
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("parse OCSF JSON: %v", err)
	}
	md, _ := parsed["metadata"].(map[string]any)
	if _, ok := md["trace_id"]; ok {
		t.Errorf("metadata.trace_id should be absent when no span context, got %v", md["trace_id"])
	}
	if _, ok := md["span_id"]; ok {
		t.Errorf("metadata.span_id should be absent when no span context, got %v", md["span_id"])
	}
}

func TestSetFormatUnknownFallsBackToOCSF(t *testing.T) {
	var buf bytes.Buffer
	resetForTest(t, FormatOCSF, &buf)

	SetFormat("not-a-real-format")
	Emit(context.Background(), sampleEvent())

	if !strings.Contains(buf.String(), `"class_uid":4002`) {
		t.Errorf("expected OCSF fallback, got: %s", buf.String())
	}
}

func TestEmitTrailingNewline(t *testing.T) {
	var buf bytes.Buffer
	resetForTest(t, FormatOCSF, &buf)

	Emit(context.Background(), sampleEvent())
	if !strings.HasSuffix(buf.String(), "\n") {
		t.Errorf("audit line missing trailing newline")
	}
}

func TestBarbacanaNamespaceOCSF(t *testing.T) {
	var buf bytes.Buffer
	resetForTest(t, FormatOCSF, &buf)

	Emit(context.Background(), sampleEvent())

	var parsed map[string]any
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("parse OCSF JSON: %v", err)
	}
	bb, ok := parsed["barbacana"].(map[string]any)
	if !ok {
		t.Fatalf("barbacana namespace missing or wrong type: %v", parsed["barbacana"])
	}

	prots, _ := bb["matched_protections"].([]any)
	if len(prots) != 1 || prots[0] != "sql-injection-auth-bypass" {
		t.Errorf("barbacana.matched_protections = %v, want [sql-injection-auth-bypass]", prots)
	}
	rules, _ := bb["matched_rules"].([]any)
	if len(rules) != 2 || rules[0] != "942100" || rules[1] != "942110" {
		t.Errorf("barbacana.matched_rules = %v, want [942100 942110]", rules)
	}
	cwes, _ := bb["cwe"].([]any)
	if len(cwes) != 1 || cwes[0] != "CWE-89" {
		t.Errorf("barbacana.cwe = %v, want [CWE-89]", cwes)
	}
}

func TestBarbacanaNamespaceECS(t *testing.T) {
	var buf bytes.Buffer
	resetForTest(t, FormatECS, &buf)

	Emit(context.Background(), sampleEvent())

	var parsed map[string]any
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("parse ECS JSON: %v", err)
	}
	bb, ok := parsed["barbacana"].(map[string]any)
	if !ok {
		t.Fatalf("barbacana namespace missing or wrong type: %v", parsed["barbacana"])
	}

	prots, _ := bb["matched_protections"].([]any)
	if len(prots) != 1 || prots[0] != "sql-injection-auth-bypass" {
		t.Errorf("barbacana.matched_protections = %v, want [sql-injection-auth-bypass]", prots)
	}
	rules, _ := bb["matched_rules"].([]any)
	if len(rules) != 2 || rules[0] != "942100" || rules[1] != "942110" {
		t.Errorf("barbacana.matched_rules = %v, want [942100 942110]", rules)
	}
	cwes, _ := bb["cwe"].([]any)
	if len(cwes) != 1 || cwes[0] != "CWE-89" {
		t.Errorf("barbacana.cwe = %v, want [CWE-89]", cwes)
	}
}

func TestBarbacanaNamespaceAbsentWhenNoSignals(t *testing.T) {
	var buf bytes.Buffer
	resetForTest(t, FormatOCSF, &buf)

	ev := sampleEvent()
	ev.Protections = nil
	ev.RuleIDs = nil
	ev.CWE = nil
	Emit(context.Background(), ev)

	var parsed map[string]any
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("parse OCSF JSON: %v", err)
	}
	if _, ok := parsed["barbacana"]; ok {
		t.Errorf("barbacana namespace should be absent when no protection/rule/cwe data, got %v", parsed["barbacana"])
	}
}

func TestEmitEmptyArraysHandledGracefully(t *testing.T) {
	var buf bytes.Buffer
	resetForTest(t, FormatOCSF, &buf)

	ev := sampleEvent()
	ev.RuleIDs = []int{}
	ev.Protections = []string{}
	ev.CWE = []string{}
	Emit(context.Background(), ev)

	if !json.Valid(buf.Bytes()) {
		t.Errorf("OCSF emission with empty slices produced invalid JSON: %s", buf.String())
	}
}
