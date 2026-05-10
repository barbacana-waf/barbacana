package observability

import (
	"context"
	"testing"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace/noop"
)

// TestSetupDisabledIsNoop locks in the contract that an absent or
// disabled tracing block does not touch the OTel global. The acceptance
// criterion in the design is "no observability config = no exporter
// calls" — the simplest enforcement is to prove the global remains
// whatever the test set it to before the call.
func TestSetupDisabledIsNoop(t *testing.T) {
	// Stash and restore the global so other tests in the package see a
	// clean state.
	prev := otel.GetTracerProvider()
	t.Cleanup(func() { otel.SetTracerProvider(prev) })

	noopTP := noop.NewTracerProvider()
	otel.SetTracerProvider(noopTP)

	p, err := Setup(context.Background(), TracingConfig{Enabled: false})
	if err != nil {
		t.Fatalf("Setup(disabled): %v", err)
	}
	if p == nil {
		t.Fatal("Setup returned nil Provider")
	}

	if otel.GetTracerProvider() != noopTP {
		t.Errorf("disabled Setup mutated the global TracerProvider")
	}

	if err := p.Shutdown(context.Background()); err != nil {
		t.Errorf("Shutdown(disabled) returned error: %v", err)
	}
}

// TestSetupEnabledRejectsBadProtocol surfaces config errors at Setup
// rather than at request time, so a bad config makes the daemon fail
// fast on startup.
func TestSetupEnabledRejectsBadProtocol(t *testing.T) {
	_, err := Setup(context.Background(), TracingConfig{
		Enabled:  true,
		Protocol: "smoke-signals",
		Endpoint: "localhost:1",
		Insecure: true,
		Timeout:  100 * time.Millisecond,
	})
	if err == nil {
		t.Fatal("Setup with bad protocol should have failed")
	}
}

// TestProviderShutdownIdempotent: calling Shutdown twice on the same
// Provider is allowed — operators wiring this into both a defer in
// main and a SIGTERM handler should not get a panic on the second
// call.
func TestProviderShutdownIdempotent(t *testing.T) {
	p := &Provider{}
	if err := p.Shutdown(context.Background()); err != nil {
		t.Errorf("first Shutdown: %v", err)
	}
	if err := p.Shutdown(context.Background()); err != nil {
		t.Errorf("second Shutdown: %v", err)
	}
}
