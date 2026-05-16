package ratelimit

import (
	"fmt"
	"log/slog"
	"net"
	"net/http"
)

// KeyExtractor derives the rate-limit key from an incoming request.
type KeyExtractor interface {
	Extract(r *http.Request) (string, error)
}

// IPExtractor uses the client IP from r.RemoteAddr, stripping the port.
// Correct when barbacana terminates TLS directly (edge deployment).
type IPExtractor struct{}

func (e IPExtractor) Extract(r *http.Request) (string, error) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		// RemoteAddr has no port (e.g. a Unix socket path); use it as-is.
		return r.RemoteAddr, nil
	}
	return host, nil
}

// HeaderExtractor reads the key from a specific HTTP header. When the header
// is absent, it falls back to the client IP and logs a warning — the proxy
// is responsible for supplying a trustworthy value.
type HeaderExtractor struct {
	Header string
}

func (e HeaderExtractor) Extract(r *http.Request) (string, error) {
	val := r.Header.Get(e.Header)
	if val == "" {
		slog.WarnContext(r.Context(),
			"rate-limit: configured header absent, falling back to RemoteAddr",
			"header", e.Header,
			"remote_addr", r.RemoteAddr,
		)
		return IPExtractor{}.Extract(r)
	}
	return val, nil
}

// NewExtractor constructs the KeyExtractor described by cfg.
func NewExtractor(cfg SourceConfig) (KeyExtractor, error) {
	switch cfg.Type {
	case SourceTypeIP:
		return IPExtractor{}, nil
	case SourceTypeHeader:
		return HeaderExtractor{Header: cfg.Key}, nil
	default:
		return nil, fmt.Errorf("unknown source type %q", cfg.Type)
	}
}
