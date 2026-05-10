// Package audit emits structured audit log entries for blocked or
// detected requests. One entry per request, never one per protection.
//
// Stdout emission is unconditional: there is no off switch and no
// route-level toggle. Operators choose between the OCSF v1.2.0 and
// ECS 8.x wire schemas via the audit_log.format config key (default
// OCSF). The format choice is process-wide; rotating between formats
// requires a config reload.
//
// audit-log section for field mappings.
package audit

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"time"

	"go.opentelemetry.io/otel/trace"
)

// Format is one of the supported audit log wire schemas. Mirrors the
// constants in the config package so callers don't need to import both.
type Format string

const (
	FormatOCSF Format = "ocsf"
	FormatECS  Format = "ecs"
)

// Event is the neutral, format-independent representation of one audit
// log record. Formatters render this struct into OCSF, ECS, or (later)
// CEF wire JSON. Adding a field here makes it available to every
// formatter; format-specific shaping happens at the formatter, not at
// the call site.
type Event struct {
	Timestamp    time.Time
	RequestID    string
	SourceIP     string
	SourcePort   int
	Method       string
	Host         string
	Path         string
	URLFull      string
	UserAgent    string
	RouteID      string
	Protections  []string
	RuleIDs      []int
	CWE          []string
	AnomalyScore int
	Action       string // "blocked" | "detected"
	ResponseCode int

	// Trace correlation fields. Empty when tracing is disabled — the
	// span context lookup returns the zero value and formatters omit
	// the fields rather than emitting all-zero IDs.
	TraceID string
	SpanID  string
}

// Formatter renders one Event into the bytes written to stdout. The
// returned slice must include a trailing newline; no formatter is
// permitted to share a line with another. Formatters are pure
// functions; concurrent calls share no state.
type Formatter interface {
	Format(Event) ([]byte, error)
	Name() Format
}

var (
	mu        sync.RWMutex
	formatter Formatter = ocsfFormatter{}
	out       io.Writer = os.Stdout
)

// SetFormat selects the active audit log wire schema for stdout
// emission. Unknown values fall through to OCSF — validation in the
// config package guarantees only "ocsf" or "ecs" reach here, so the
// fallback is defensive, not load-bearing. Safe to call at startup
// and on config reload.
func SetFormat(name string) {
	mu.Lock()
	defer mu.Unlock()
	switch Format(name) {
	case FormatECS:
		formatter = ecsFormatter{}
	case FormatOCSF, "":
		formatter = ocsfFormatter{}
	default:
		formatter = ocsfFormatter{}
	}
}

// SetOutput swaps the destination writer. Tests use this to capture
// audit lines without spawning a process; production never calls it —
// stdout is the only sanctioned destination per the design (Phase D
// adds extra sinks but stdout stays unconditional).
func SetOutput(w io.Writer) {
	mu.Lock()
	defer mu.Unlock()
	out = w
}

// Emit writes one audit event to stdout in the active format. Trace
// correlation IDs are pulled from the active span context if the
// caller did not set them explicitly — tracing-disabled paths leave
// them empty.
func Emit(ctx context.Context, e Event) {
	if e.TraceID == "" || e.SpanID == "" {
		sc := trace.SpanContextFromContext(ctx)
		if sc.IsValid() {
			if e.TraceID == "" {
				e.TraceID = sc.TraceID().String()
			}
			if e.SpanID == "" {
				e.SpanID = sc.SpanID().String()
			}
		}
	}

	mu.RLock()
	f := formatter
	w := out
	mu.RUnlock()

	line, err := f.Format(e)
	if err != nil {
		// Audit emission failures are reported via slog so operators
		// see them in their normal log stream. The audit line itself
		// is dropped — emitting a half-formed record into the SIEM
		// would confuse downstream parsers worse than a missed event.
		slog.ErrorContext(ctx, "audit format failed", "format", f.Name(), "err", err.Error())
		return
	}
	bw := bufio.NewWriter(w)
	if _, err := bw.Write(line); err != nil {
		slog.ErrorContext(ctx, "audit write failed", "err", err.Error())
		return
	}
	if err := bw.Flush(); err != nil {
		slog.ErrorContext(ctx, "audit flush failed", "err", err.Error())
	}
}

// EventFromRequest pre-fills the network/HTTP fields of an Event from
// a request. Stage-specific fields (protections, rule IDs, CWE,
// anomaly score, action, response code) are populated by the caller
// before passing to Emit.
func EventFromRequest(r *http.Request, routeID, requestID string, ts time.Time) Event {
	return Event{
		Timestamp: ts,
		RequestID: requestID,
		Method:    r.Method,
		Host:      r.Host,
		Path:      r.URL.Path,
		URLFull:   urlFull(r),
		UserAgent: r.Header.Get("User-Agent"),
		RouteID:   routeID,
	}
}

// MarshalLine is exported for formatters that emit raw JSON: each
// formatter's Format method ends with a newline; this helper appends
// it consistently.
func MarshalLine(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

func urlFull(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if r.URL.RawQuery != "" {
		return scheme + "://" + r.Host + r.URL.Path + "?" + r.URL.RawQuery
	}
	return scheme + "://" + r.Host + r.URL.Path
}
