package cmd

// Composition root for the observability runtime — turns the parsed
// config into installed OTel state. Lives in cmd/ (not config/ or
// observability/) because it has side effects: starting exporter
// goroutines, mutating the OTel global TracerProvider, flipping the
// pipeline's per-request fast-path gate. config/ stays pure data;
// observability/ stays YAML-agnostic.

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/barbacana-waf/barbacana/internal/config"
	"github.com/barbacana-waf/barbacana/internal/observability"
	"github.com/barbacana-waf/barbacana/internal/pipeline"
)

// tracingShutdownTimeout caps the time the deferred drain waits for
// the batch span processor to flush. Long enough that a healthy
// collector receives the tail of in-flight spans, short enough that
// an unreachable collector cannot wedge process exit.
const tracingShutdownTimeout = 5 * time.Second

// setupTracing reads the resolved tracing config and installs the OTel
// providers. With tracing disabled the returned Provider is a no-op
// shell — calling Shutdown on it is harmless. The pipeline fast-path
// gate is flipped here so the handler skips per-request OTel calls
// entirely when the operator never configured `tracing:`.
func setupTracing(cfg *config.Config) (*observability.Provider, error) {
	rt, err := config.ResolveTracing(cfg)
	if err != nil {
		return nil, fmt.Errorf("resolve tracing config: %w", err)
	}
	provider, err := observability.Setup(context.Background(), observability.TracingConfig{
		Enabled:          rt.Enabled,
		Protocol:         rt.Protocol,
		Endpoint:         rt.Endpoint,
		Insecure:         rt.Insecure,
		Headers:          rt.Headers,
		Timeout:          rt.Timeout,
		ServiceName:      rt.ServiceName,
		ServiceNamespace: rt.ServiceNamespace,
		ServiceVersion:   rt.ServiceVersion,
	})
	if err != nil {
		return nil, fmt.Errorf("setup tracing: %w", err)
	}
	pipeline.SetTracingEnabled(rt.Enabled)
	return provider, nil
}

// drainTracing flushes the batch span processor on shutdown. Without
// this the SDK drops every span currently buffered (default ~5s of
// traffic) when the process exits. The drain runs against a fresh
// context because the caller's context is typically the one the
// shutdown signal just cancelled.
func drainTracing(provider *observability.Provider, logger *slog.Logger) {
	ctx, cancel := context.WithTimeout(context.Background(), tracingShutdownTimeout)
	defer cancel()
	if err := provider.Shutdown(ctx); err != nil {
		logger.Error("tracing shutdown", "err", err.Error())
	}
}
