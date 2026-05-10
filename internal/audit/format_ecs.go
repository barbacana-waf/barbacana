package audit

// ECS 8.x formatter. Emits the JSON shape Elastic's stack expects for
// security events. Field choices follow
// https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html
// for ECS 8.x — only the fields a WAF actually populates are emitted;
// the schema permits absent optional fields.
//
// ECS was donated to OpenTelemetry SemConv in April 2023 and the
// merger is in progress; if the OTel side renames or restructures
// fields, this formatter freezes on ECS 8.x semantics rather than
// chasing a moving target.

import (
	"net"
	"strconv"
	"time"
)

type ecsFormatter struct{}

func (ecsFormatter) Name() Format { return FormatECS }

func (f ecsFormatter) Format(e Event) ([]byte, error) {
	out := map[string]any{
		"@timestamp": e.Timestamp.UTC().Format(time.RFC3339Nano),
		"ecs":        map[string]any{"version": "8.11.0"},
		"event": map[string]any{
			"kind":     "alert",
			"category": []string{"intrusion_detection"},
			"action":   ecsAction(e.Action),
			"outcome":  ecsOutcome(e.Action),
			"dataset":  "barbacana.audit",
			"module":   "barbacana",
		},
	}

	if r := ecsRule(e); r != nil {
		out["rule"] = r
	}
	if v := ecsVulnerability(e); v != nil {
		out["vulnerability"] = v
	}
	if c := ecsClient(e); c != nil {
		out["client"] = c
	}
	out["url"] = ecsURL(e)
	out["http"] = ecsHTTP(e)
	if e.UserAgent != "" {
		out["user_agent"] = map[string]any{"original": e.UserAgent}
	}
	if e.AnomalyScore > 0 {
		out["risk"] = map[string]any{"static_score": e.AnomalyScore}
	}
	if e.RequestID != "" {
		out["labels"] = map[string]any{"request_id": e.RequestID, "route_id": e.RouteID}
	} else if e.RouteID != "" {
		out["labels"] = map[string]any{"route_id": e.RouteID}
	}

	// Native ECS trace.id / span.id when tracing is on; absent
	// otherwise. ECS uses dotted keys, not nested objects, for these
	// two — the JSON encoder sees them as standalone fields.
	if e.TraceID != "" {
		out["trace"] = map[string]any{"id": e.TraceID}
	}
	if e.SpanID != "" {
		out["span"] = map[string]any{"id": e.SpanID}
	}

	if bb := barbacanaNamespace(e); bb != nil {
		out["barbacana"] = bb
	}

	return MarshalLine(out)
}

func ecsAction(action string) string {
	switch action {
	case "blocked":
		return "block"
	case "detected":
		return "allow"
	default:
		return action
	}
}

func ecsOutcome(action string) string {
	if action == "blocked" {
		return "failure"
	}
	return "success"
}

func ecsRule(e Event) map[string]any {
	if len(e.Protections) == 0 && len(e.RuleIDs) == 0 {
		return nil
	}
	r := map[string]any{
		"ruleset": "owasp-crs",
	}
	if len(e.Protections) > 0 {
		r["name"] = e.Protections[0]
		r["category"] = e.Protections[0]
	}
	if len(e.RuleIDs) > 0 {
		r["id"] = strconv.Itoa(e.RuleIDs[0])
		ids := make([]string, 0, len(e.RuleIDs))
		for _, rid := range e.RuleIDs {
			ids = append(ids, strconv.Itoa(rid))
		}
		r["reference"] = ids
	}
	return r
}

func ecsVulnerability(e Event) map[string]any {
	if len(e.CWE) == 0 {
		return nil
	}
	return map[string]any{
		"classification": e.CWE,
	}
}

func ecsClient(e Event) map[string]any {
	if e.SourceIP == "" {
		return nil
	}
	c := map[string]any{
		"ip":      e.SourceIP,
		"address": e.SourceIP,
	}
	if e.SourcePort > 0 {
		c["port"] = e.SourcePort
	}
	// ECS encourages parallel client.geo when available; we don't do
	// geo lookups, so the field stays absent rather than guessed.
	if parsed := net.ParseIP(e.SourceIP); parsed == nil {
		// IP didn't parse; emit only address so SIEMs that index .ip
		// strictly don't reject the document.
		delete(c, "ip")
	}
	return c
}

func ecsURL(e Event) map[string]any {
	u := map[string]any{
		"path": e.Path,
	}
	if e.URLFull != "" {
		u["full"] = e.URLFull
	}
	if e.Host != "" {
		u["domain"] = e.Host
	}
	return u
}

func ecsHTTP(e Event) map[string]any {
	h := map[string]any{
		"request": map[string]any{
			"method": e.Method,
		},
	}
	if e.ResponseCode > 0 {
		h["response"] = map[string]any{
			"status_code": e.ResponseCode,
		}
	}
	return h
}

// Ensure ecsFormatter satisfies Formatter.
var _ Formatter = ecsFormatter{}
