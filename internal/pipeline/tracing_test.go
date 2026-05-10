package pipeline

import (
	"context"
	"net/http/httptest"
	"testing"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
)

// TestStartRequestSpanFastPathWhenDisabled locks in the contract that
// production deployments without `tracing:` pay nothing for
// instrumentation: with the gate off, no span is recorded, no
// propagator runs, the request and context come back untouched, and
// the returned span is the no-op variant.
func TestStartRequestSpanFastPathWhenDisabled(t *testing.T) {
	prevEnabled := tracingEnabled.Load()
	t.Cleanup(func() { tracingEnabled.Store(prevEnabled) })
	tracingEnabled.Store(false)

	// Install a recording exporter so any leaked Start would show up
	// here. The noop fast path must produce zero spans on this
	// exporter regardless of how many requests pass through.
	prevTP := otel.GetTracerProvider()
	t.Cleanup(func() { otel.SetTracerProvider(prevTP) })

	rec := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(rec))
	otel.SetTracerProvider(tp)

	r := httptest.NewRequest("GET", "/whatever", nil)
	r.Header.Set("traceparent", "00-0102030405060708090a0b0c0d0e0f10-1112131415161718-01")
	origCtx := r.Context()

	ctx, span, out := startRequestSpan(r)

	if ctx != origCtx {
		t.Errorf("disabled path mutated context — request would carry trace state for free")
	}
	if out != r {
		t.Errorf("disabled path replaced *http.Request — extra alloc on the hot path")
	}
	if span.IsRecording() {
		t.Errorf("disabled path returned a recording span; should be no-op")
	}
	if got := len(rec.Started()); got != 0 {
		t.Errorf("disabled path started %d span(s); want 0", got)
	}
}

// TestStartRequestSpanRecordsWhenEnabled confirms the slow path still
// works: with the gate on, a span is recorded and the W3C trace
// context is re-injected into the outgoing headers (so reverse_proxy
// forwards a continued trace).
func TestStartRequestSpanRecordsWhenEnabled(t *testing.T) {
	prevEnabled := tracingEnabled.Load()
	t.Cleanup(func() { tracingEnabled.Store(prevEnabled) })
	tracingEnabled.Store(true)

	prevTP := otel.GetTracerProvider()
	prevProp := otel.GetTextMapPropagator()
	t.Cleanup(func() {
		otel.SetTracerProvider(prevTP)
		otel.SetTextMapPropagator(prevProp)
	})

	rec := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(rec))
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{}, propagation.Baggage{},
	))

	r := httptest.NewRequest("GET", "/login", nil)
	r.Header.Set("traceparent", "00-0102030405060708090a0b0c0d0e0f10-1112131415161718-01")

	_, span, out := startRequestSpan(r)
	span.End()

	started := rec.Started()
	if len(started) != 1 {
		t.Fatalf("enabled path started %d span(s); want 1", len(started))
	}
	if !started[0].SpanContext().TraceID().IsValid() {
		t.Errorf("started span has invalid trace id")
	}

	tp2 := out.Header.Get("traceparent")
	if tp2 == "" {
		t.Errorf("traceparent missing on outgoing request — upstream loses trace context")
	}
	// The trace ID must survive — that is the point of propagation.
	if !contains(tp2, "0102030405060708090a0b0c0d0e0f10") {
		t.Errorf("outgoing traceparent did not preserve trace id: %q", tp2)
	}
}

// TestStartCorazaSpanFastPathWhenDisabled mirrors the parent-span
// guarantee for the child span path inside runCRS.
func TestStartCorazaSpanFastPathWhenDisabled(t *testing.T) {
	prevEnabled := tracingEnabled.Load()
	t.Cleanup(func() { tracingEnabled.Store(prevEnabled) })
	tracingEnabled.Store(false)

	prevTP := otel.GetTracerProvider()
	t.Cleanup(func() { otel.SetTracerProvider(prevTP) })

	rec := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(rec))
	otel.SetTracerProvider(tp)

	ctx := context.Background()
	gotCtx, span := startCorazaSpan(ctx)
	if gotCtx != ctx {
		t.Errorf("disabled path mutated ctx — extra alloc per request")
	}
	if span.IsRecording() {
		t.Errorf("disabled path returned recording coraza span")
	}
	if got := len(rec.Started()); got != 0 {
		t.Errorf("disabled path started %d coraza span(s); want 0", got)
	}
}

// BenchmarkStartRequestSpanDisabled measures the cost of the
// disabled-tracing fast path on the hot pipeline entry point. This is
// the baseline a production deployment without `tracing:` pays per
// request for the instrumentation layer.
func BenchmarkStartRequestSpanDisabled(b *testing.B) {
	tracingEnabled.Store(false)

	r := httptest.NewRequest("GET", "/some/path", nil)
	r.Header.Set("traceparent", "00-0102030405060708090a0b0c0d0e0f10-1112131415161718-01")

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, span, _ := startRequestSpan(r)
		span.End()
	}
}

// BenchmarkStartRequestSpanEnabled exposes the cost of the slow path
// for comparison. Run side by side with the disabled benchmark to
// quantify the gate's payoff.
func BenchmarkStartRequestSpanEnabled(b *testing.B) {
	tracingEnabled.Store(true)
	defer tracingEnabled.Store(false)

	prevTP := otel.GetTracerProvider()
	prevProp := otel.GetTextMapPropagator()
	defer func() {
		otel.SetTracerProvider(prevTP)
		otel.SetTextMapPropagator(prevProp)
	}()

	tp := sdktrace.NewTracerProvider() // dropping spans is fine; Start cost still incurs
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{}, propagation.Baggage{},
	))

	r := httptest.NewRequest("GET", "/some/path", nil)
	r.Header.Set("traceparent", "00-0102030405060708090a0b0c0d0e0f10-1112131415161718-01")

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, span, _ := startRequestSpan(r)
		span.SetAttributes(attribute.String("noop.attr", "x"))
		span.End()
	}
	_ = trace.SpanFromContext(context.Background())
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
