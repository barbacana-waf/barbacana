// Package observability owns the lifecycle of OpenTelemetry providers
// (TracerProvider today; LoggerProvider follows in Phase C). All providers
// are off by default — Setup is a no-op when the corresponding feature
// block is absent or disabled, so a Barbacana running without an OTel
// collector makes zero exporter calls.
//
// Caddy's bundled http.handlers.tracing module owns its own private
// global TracerProvider with no injection hook (caddy v2.11 source:
// modules/caddyhttp/tracing/tracerprovider.go), so a metrics-style
// per-context-registry bridge is not available for traces. Instead this
// package installs a TracerProvider as the OTel global and the pipeline
// handler instruments spans against it directly. Caddy's tracing module
// is intentionally unused — running both would double-export every span.
package observability

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"

	"github.com/barbacana-waf/barbacana/internal/version"
)

// TracingConfig describes the resolved tracing block. The zero value
// (Enabled=false) is a no-op: Setup returns a noop provider and never
// dials an exporter. Standard OTEL_EXPORTER_OTLP_* env vars fill in
// fields the YAML leaves empty when Enabled=true.
type TracingConfig struct {
	Enabled  bool
	Protocol string // "grpc" (default) or "http"
	Endpoint string
	Insecure bool
	Headers  map[string]string
	Timeout  time.Duration

	ServiceName      string
	ServiceNamespace string
	ServiceVersion   string
}

// Provider holds the state needed to shut traces down cleanly. The
// caller obtains it from Setup and calls Shutdown during process exit;
// missing this drops in-flight spans on SIGTERM.
type Provider struct {
	tp       *sdktrace.TracerProvider
	shutdown []func(context.Context) error
}

var (
	mu     sync.Mutex
	active *Provider
)

// Setup installs OTel providers based on cfg. When tracing is disabled
// the function is a no-op: no exporter is created, no global provider
// is replaced, and Shutdown does nothing. Safe to call repeatedly —
// each call replaces the previous provider, draining the old one
// synchronously to avoid leaking exporter goroutines.
func Setup(ctx context.Context, cfg TracingConfig) (*Provider, error) {
	if !cfg.Enabled {
		return &Provider{}, nil
	}

	res, err := buildResource(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("build trace resource: %w", err)
	}

	exporter, err := buildExporter(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("build trace exporter: %w", err)
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
	)

	mu.Lock()
	prev := active
	p := &Provider{
		tp:       tp,
		shutdown: []func(context.Context) error{tp.Shutdown},
	}
	active = p
	mu.Unlock()

	if prev != nil {
		_ = prev.Shutdown(ctx)
	}

	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	return p, nil
}

// Shutdown drains all installed providers. Idempotent: repeated calls
// after the first are no-ops.
func (p *Provider) Shutdown(ctx context.Context) error {
	if p == nil {
		return nil
	}
	var errs []error
	for _, fn := range p.shutdown {
		if err := fn(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	p.shutdown = nil
	return errors.Join(errs...)
}

// Tracer returns the named tracer from the active TracerProvider. When
// tracing is disabled the global provider is the OTel no-op, so callers
// can use this unconditionally — span starts become free.
func Tracer(name string) trace.Tracer {
	return otel.Tracer(name)
}

func buildResource(ctx context.Context, cfg TracingConfig) (*resource.Resource, error) {
	name := cfg.ServiceName
	if name == "" {
		name = "barbacana"
	}
	ver := cfg.ServiceVersion
	if ver == "" {
		ver = version.Version
	}

	attrs := []resource.Option{
		resource.WithFromEnv(),
		resource.WithProcess(),
		resource.WithTelemetrySDK(),
		resource.WithAttributes(
			semconv.ServiceName(name),
			semconv.ServiceVersion(ver),
		),
	}
	if cfg.ServiceNamespace != "" {
		attrs = append(attrs, resource.WithAttributes(semconv.ServiceNamespace(cfg.ServiceNamespace)))
	}
	return resource.New(ctx, attrs...)
}

func buildExporter(ctx context.Context, cfg TracingConfig) (sdktrace.SpanExporter, error) {
	switch cfg.Protocol {
	case "", "grpc":
		return buildGRPCExporter(ctx, cfg)
	case "http", "http/protobuf":
		return buildHTTPExporter(ctx, cfg)
	default:
		return nil, fmt.Errorf("unsupported tracing protocol %q (expected grpc or http)", cfg.Protocol)
	}
}

func buildGRPCExporter(ctx context.Context, cfg TracingConfig) (sdktrace.SpanExporter, error) {
	opts := []otlptracegrpc.Option{}
	if cfg.Endpoint != "" {
		opts = append(opts, otlptracegrpc.WithEndpoint(cfg.Endpoint))
	}
	if cfg.Insecure {
		opts = append(opts, otlptracegrpc.WithInsecure())
	} else {
		opts = append(opts, otlptracegrpc.WithTLSCredentials(grpcCreds()))
	}
	if len(cfg.Headers) > 0 {
		opts = append(opts, otlptracegrpc.WithHeaders(cfg.Headers))
	}
	if cfg.Timeout > 0 {
		opts = append(opts, otlptracegrpc.WithTimeout(cfg.Timeout))
	}
	return otlptrace.New(ctx, otlptracegrpc.NewClient(opts...))
}

func buildHTTPExporter(ctx context.Context, cfg TracingConfig) (sdktrace.SpanExporter, error) {
	opts := []otlptracehttp.Option{}
	if cfg.Endpoint != "" {
		opts = append(opts, otlptracehttp.WithEndpoint(cfg.Endpoint))
	}
	if cfg.Insecure {
		opts = append(opts, otlptracehttp.WithInsecure())
	} else {
		opts = append(opts, otlptracehttp.WithTLSClientConfig(&tls.Config{MinVersion: tls.VersionTLS12}))
	}
	if len(cfg.Headers) > 0 {
		opts = append(opts, otlptracehttp.WithHeaders(cfg.Headers))
	}
	if cfg.Timeout > 0 {
		opts = append(opts, otlptracehttp.WithTimeout(cfg.Timeout))
	}
	return otlptrace.New(ctx, otlptracehttp.NewClient(opts...))
}
