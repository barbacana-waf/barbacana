package pipeline

import (
	"context"
	"net/http"
	"sync/atomic"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/barbacana-waf/barbacana/internal/protections"
)

// tracerName is the instrumentation library identifier emitted on every
// span Barbacana creates. Stable across versions so dashboards can pin
// service.name + tracer name.
const tracerName = "github.com/barbacana-waf/barbacana"

// tracingEnabled gates every per-request OTel call site in the
// pipeline. The OTel SDK's no-op providers are cheap but not free —
// `propagation.HeaderCarrier(r.Header)`, `tracer.Start` with its
// attribute slice, and `r.WithContext` all allocate per request. The
// fast path skips them entirely when tracing is disabled, leaving a
// production deployment with no `tracing:` block paying nothing for
// instrumentation.
var tracingEnabled atomic.Bool

// noopTracer produces span values for the disabled-tracing fast path.
// Every method on the returned span is a no-op; the deferred End() at
// each call site stays well-formed regardless of whether the span was
// real or noop.
var noopTracer = noop.NewTracerProvider().Tracer("")

// SetTracingEnabled toggles the per-request tracing fast path. Called
// by cmd/serve.go after observability.Setup decides whether to install
// a real TracerProvider. Safe to call from any goroutine; the atomic
// store is sufficient — readers do not need to see writes in any
// particular order.
func SetTracingEnabled(b bool) { tracingEnabled.Store(b) }

// startRequestSpan extracts trace context from incoming headers, opens
// the per-request parent span, and injects the active context back into
// r.Header so Caddy's reverse_proxy forwards `traceparent` / `tracestate`
// to the upstream. When tracing is disabled this returns the original
// request unchanged plus a no-op span — no propagator calls, no
// attribute allocation, no context.WithValue. A `traceparent` the
// client sent still reaches the upstream because nothing in the
// pipeline strips headers; we just don't pay to re-derive it.
func startRequestSpan(r *http.Request) (context.Context, trace.Span, *http.Request) {
	if !tracingEnabled.Load() {
		_, span := noopTracer.Start(r.Context(), "")
		return r.Context(), span, r
	}

	propagator := otel.GetTextMapPropagator()
	ctx := propagator.Extract(r.Context(), propagation.HeaderCarrier(r.Header))

	tracer := otel.Tracer(tracerName)
	ctx, span := tracer.Start(ctx, "barbacana.evaluate",
		trace.WithSpanKind(trace.SpanKindServer),
		trace.WithAttributes(
			attribute.String("http.request.method", r.Method),
			attribute.String("url.path", r.URL.Path),
			attribute.String("server.address", r.Host),
		),
	)

	// Re-inject so the child request the reverse_proxy makes carries
	// our span as the parent. Mutating r.Header in place is fine —
	// reverse_proxy reads from this map; clients downstream never see
	// the original headers anyway because they read from the response.
	propagator.Inject(ctx, propagation.HeaderCarrier(r.Header))

	r = r.WithContext(ctx)
	return ctx, span, r
}

// startCorazaSpan opens the child span around the rule-engine
// evaluation when tracing is enabled, otherwise returns the original
// ctx and a no-op span. The span name is generic ("waf.evaluate") on
// purpose — `coraza.*` and `crs.*` would leak the engine vocabulary
// into user-facing telemetry, which violates the "CRS is wrapped"
// principle (CLAUDE.md). Engine swaps don't break dashboards built on
// this span name.
func startCorazaSpan(ctx context.Context) (context.Context, trace.Span) {
	if !tracingEnabled.Load() {
		_, span := noopTracer.Start(ctx, "")
		return ctx, span
	}
	return otel.Tracer(tracerName).Start(ctx, "waf.evaluate")
}

// startUpstreamSpan opens a child span around the reverse_proxy call
// to the configured upstream. Caddy's reverse_proxy is not OTel-aware,
// so without this span the trace tree shows a gap between the WAF
// pipeline and any spans the upstream itself emits — operators
// looking for "where did the latency go?" see no edge for the proxy
// hop. The span's elapsed time is the same value reflected in the
// upstream-elapsed metric subtraction in handler.go.
//
// Attributes are passed in by the caller (rather than derived here)
// so the per-request HTTP semconv set — http.request.method, url.full,
// server.address, server.port — stays close to the request object it
// reads from. The kind is Client because Barbacana is the originator
// of the upstream call, and the OTLP semantic-convention render in
// Jaeger expects Client kind for outgoing HTTP work.
func startUpstreamSpan(ctx context.Context, attrs ...attribute.KeyValue) (context.Context, trace.Span) {
	if !tracingEnabled.Load() {
		_, span := noopTracer.Start(ctx, "")
		return ctx, span
	}
	return otel.Tracer(tracerName).Start(ctx, "waf.upstream",
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(attrs...),
	)
}

// startStageSpan opens a child span for one pipeline stage. Span name
// is "waf.stage.<name>" so dashboards filter and aggregate by span.name
// without parsing attributes; the leaf stage names match the catalog
// IDs already documented in handler.go's stages table. Skips entirely
// when tracing is disabled (no allocation, no propagator calls).
//
// The CRS stage gets both a stage span (waf.stage.crs) and the
// existing waf.evaluate child — the nest documents "stage took N ms,
// rule engine portion took M ms" without changing existing span names
// dashboards may already reference.
func startStageSpan(ctx context.Context, name string) (context.Context, trace.Span) {
	if !tracingEnabled.Load() {
		_, span := noopTracer.Start(ctx, "")
		return ctx, span
	}
	return otel.Tracer(tracerName).Start(ctx, "waf.stage."+name,
		trace.WithAttributes(attribute.String("waf.stage", name)),
	)
}

// recordBlockOnSpan tags a parent or child span with the WAF decision
// that ended the request. Action and protection are pulled straight from
// the decision; status code is what was actually written. The function
// is safe to call when the span is the no-op (tracing disabled).
func recordBlockOnSpan(span trace.Span, d protections.Decision, status int) {
	if !span.IsRecording() {
		return
	}
	span.SetAttributes(
		attribute.String("waf.action", "block"),
		attribute.String("waf.protection", d.Protection),
		attribute.Int("http.response.status_code", status),
	)
	span.SetStatus(codes.Error, d.Reason)
}

// recordDetectedOnSpan tags a span when detect-only mode observed at
// least one match. The action is "log" — OTel semantic conventions for
// firewall events use this verb when an event is recorded but not
// enforced. waf.protections lists every protection that matched; this
// expands cardinality only when a request actually triggered a stack
// of detections, which is uncommon.
func recordDetectedOnSpan(span trace.Span, protectionsList []string) {
	if !span.IsRecording() || len(protectionsList) == 0 {
		return
	}
	span.SetAttributes(
		attribute.String("waf.action", "log"),
		attribute.StringSlice("waf.protections", protectionsList),
	)
}
