package protocol

import (
	"context"
	"net/http"

	"github.com/barbacana-waf/barbacana/internal/protections"
)

const (
	SlowRequest             = "slow-request"
	HTTP2ContinuationFlood = "http2-continuation-flood"
	HTTP2HPACKBomb          = "http2-hpack-bomb"
	HTTP2StreamLimit         = "http2-stream-limit"
)

// RegisterSlowRequest adds slow-request and HTTP/2 protections to the registry.
// These are implemented as Caddy configuration parameters, not as request-time
// evaluations. The registry entries enable disable-list validation.
func RegisterSlowRequest(reg *protections.Registry) {
	reg.Add(caddyConfigProtection{name: SlowRequest})
	reg.Add(caddyConfigProtection{name: HTTP2ContinuationFlood})
	reg.Add(caddyConfigProtection{name: HTTP2HPACKBomb})
	reg.Add(caddyConfigProtection{name: HTTP2StreamLimit})
}

type caddyConfigProtection struct{ name string }

func (c caddyConfigProtection) Name() string     { return c.name }
func (c caddyConfigProtection) Category() string { return "" }
func (c caddyConfigProtection) Evaluate(_ context.Context, _ *http.Request) protections.Decision {
	return protections.Allow()
}
