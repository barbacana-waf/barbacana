package audit

// OCSF v1.2.0 formatter. Renders one Event into the JSON shape the
// Open Cybersecurity Schema Framework defines for the HTTP Activity
// event class (class_uid 4002). Field choices follow the schema at
// https://schema.ocsf.io/1.2.0/classes/http_activity, restricted to
// what a WAF actually knows about — there is no enrichment of fields
// the engine never produces (e.g. attack.tactic mapping is left to
// the SIEM if its dashboards want it).
//
// The OCSF library `github.com/valllabh/ocsf-schema-golang` exposes
// proto-generated structs but their JSON marshaling does not emit the
// flat OCSF wire format SIEMs expect — the proto field names use
// snake_case-with-underscored-numerals which OCSF rejects. So we
// build a hand-rolled map directly. This is intentional and matches
// what Coraza's internal formatter does on the same library.

import (
	"strconv"
	"strings"
)

type ocsfFormatter struct{}

func (ocsfFormatter) Name() Format { return FormatOCSF }

const (
	ocsfClassHTTPActivity   = 4002
	ocsfCategoryNetwork     = 4
	ocsfActivityHTTPRequest = 1
	ocsfActivityHTTPTrace   = 6 // OCSF "Trace" activity used for blocked WAF events.

	ocsfTypeUIDHTTPRequest = ocsfClassHTTPActivity*100 + ocsfActivityHTTPRequest
	ocsfTypeUIDHTTPTrace   = ocsfClassHTTPActivity*100 + ocsfActivityHTTPTrace

	ocsfSeverityInformational = 1
	ocsfSeverityHigh          = 4

	ocsfDispositionAllowed = 1
	ocsfDispositionBlocked = 2
)

func (f ocsfFormatter) Format(e Event) ([]byte, error) {
	activityID, typeUID := ocsfActivityHTTPRequest, ocsfTypeUIDHTTPRequest
	disposition, dispositionID := "Allowed", ocsfDispositionAllowed
	severityID := ocsfSeverityInformational

	if e.Action == "blocked" {
		activityID, typeUID = ocsfActivityHTTPTrace, ocsfTypeUIDHTTPTrace
		disposition, dispositionID = "Blocked", ocsfDispositionBlocked
		severityID = ocsfSeverityHigh
	}

	out := map[string]any{
		"class_uid":      ocsfClassHTTPActivity,
		"class_name":     "HTTP Activity",
		"category_uid":   ocsfCategoryNetwork,
		"category_name":  "Network Activity",
		"activity_id":    activityID,
		"type_uid":       typeUID,
		"severity_id":    severityID,
		"time":           e.Timestamp.UTC().UnixMilli(),
		"disposition":    disposition,
		"disposition_id": dispositionID,
		"status":         actionToStatus(e.Action),
		"status_code":    e.ResponseCode,
		"http_request":   ocsfHTTPRequest(e),
		"src_endpoint":   ocsfSrcEndpoint(e),
		"metadata":       ocsfMetadata(e),
	}

	if e.AnomalyScore > 0 {
		out["risk_score"] = e.AnomalyScore
	}
	if attacks := ocsfAttacks(e); len(attacks) > 0 {
		out["attacks"] = attacks
	}
	if rule := ocsfFirewallRule(e); rule != nil {
		out["firewall_rule"] = rule
	}
	if bb := barbacanaNamespace(e); bb != nil {
		out["barbacana"] = bb
	}

	return MarshalLine(out)
}

func ocsfHTTPRequest(e Event) map[string]any {
	r := map[string]any{
		"http_method": e.Method,
		"url":         map[string]any{"path": e.Path, "url_string": e.URLFull, "hostname": e.Host},
	}
	if e.UserAgent != "" {
		r["user_agent"] = e.UserAgent
	}
	if e.RequestID != "" {
		r["uid"] = e.RequestID
	}
	return r
}

func ocsfSrcEndpoint(e Event) map[string]any {
	ep := map[string]any{}
	if e.SourceIP != "" {
		ep["ip"] = e.SourceIP
	}
	if e.SourcePort > 0 {
		ep["port"] = e.SourcePort
	}
	return ep
}

func ocsfMetadata(e Event) map[string]any {
	md := map[string]any{
		"version": "1.2.0",
		"product": map[string]any{
			"name":   "barbacana",
			"vendor_name": "barbacana",
		},
	}
	if e.RouteID != "" {
		md["route_id"] = e.RouteID
	}
	// Trace correlation. Both fields stay absent when tracing is off
	// rather than emitting all-zero IDs that look like real spans to
	// SIEM correlation rules.
	if e.TraceID != "" {
		md["trace_id"] = e.TraceID
	}
	if e.SpanID != "" {
		md["span_id"] = e.SpanID
	}
	return md
}

func ocsfAttacks(e Event) []map[string]any {
	if len(e.Protections) == 0 {
		return nil
	}
	attacks := make([]map[string]any, 0, len(e.Protections))
	for _, p := range e.Protections {
		a := map[string]any{
			"name":     p,
			"category": ocsfAttackCategory(p),
		}
		if cwes := ocsfClassifications(e.CWE); len(cwes) > 0 {
			a["classification"] = cwes
		}
		attacks = append(attacks, a)
	}
	return attacks
}

func ocsfAttackCategory(protectionName string) string {
	// Map the L1 family from the canonical name (e.g.
	// "sql-injection-auth-bypass" → "sql-injection") to a readable
	// attack category. Splitting on the first hyphen pair holds for
	// every leaf in the catalog because the hierarchy is flat at
	// emission time.
	parts := strings.SplitN(protectionName, "-", 3)
	if len(parts) >= 2 {
		return parts[0] + "-" + parts[1]
	}
	return protectionName
}

func ocsfClassifications(cwes []string) []map[string]any {
	if len(cwes) == 0 {
		return nil
	}
	out := make([]map[string]any, 0, len(cwes))
	for _, cwe := range cwes {
		out = append(out, map[string]any{
			"taxonomy":    "CWE",
			"category":    cwe,
			"category_id": cwe,
		})
	}
	return out
}

func ocsfFirewallRule(e Event) map[string]any {
	if len(e.RuleIDs) == 0 && len(e.Protections) == 0 {
		return nil
	}
	r := map[string]any{}
	if len(e.RuleIDs) > 0 {
		// `uid` is the canonical OCSF firewall_rule identifier; we
		// use the first matched rule. Full list is preserved in
		// match_details for SIEMs that want it.
		r["uid"] = strconv.Itoa(e.RuleIDs[0])
		ids := make([]string, 0, len(e.RuleIDs))
		for _, rid := range e.RuleIDs {
			ids = append(ids, strconv.Itoa(rid))
		}
		r["match_details"] = ids
	}
	if len(e.Protections) > 0 {
		r["category"] = e.Protections[0]
	}
	return r
}

func actionToStatus(action string) string {
	switch action {
	case "blocked":
		return "Failure"
	case "detected":
		return "Success"
	default:
		return "Success"
	}
}

// Ensure ocsfFormatter satisfies Formatter.
var _ Formatter = ocsfFormatter{}
