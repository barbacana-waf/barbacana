// Package audit emits structured JSON audit log entries for blocked or
// detected requests. One entry per request, never one per protection.
package audit

import (
	"context"
	"log/slog"
	"time"
)

// Entry represents a single audit log event for a request.
type Entry struct {
	Timestamp          time.Time `json:"timestamp"`
	RequestID          string    `json:"request_id"`
	SourceIP           string    `json:"source_ip"`
	Method             string    `json:"method"`
	Host               string    `json:"host"`
	Path               string    `json:"path"`
	RouteID            string    `json:"route_id"`
	MatchedProtections []string  `json:"matched_protections"`
	MatchedRules       []int     `json:"matched_rules"`
	CWE                []string  `json:"cwe"`
	AnomalyScore       int       `json:"anomaly_score,omitempty"`
	Action             string    `json:"action"`
	ResponseCode       int       `json:"response_code"`
}

// Emit writes the audit entry as a structured slog.Info message.
func Emit(ctx context.Context, e Entry) {
	slog.InfoContext(ctx, "audit",
		"timestamp", e.Timestamp.UTC().Format(time.RFC3339Nano),
		"request_id", e.RequestID,
		"source_ip", e.SourceIP,
		"method", e.Method,
		"host", e.Host,
		"path", e.Path,
		"route_id", e.RouteID,
		"matched_protections", e.MatchedProtections,
		"matched_rules", e.MatchedRules,
		"cwe", e.CWE,
		"anomaly_score", e.AnomalyScore,
		"action", e.Action,
		"response_code", e.ResponseCode,
	)
}
