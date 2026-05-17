package ratelimit

import (
	"fmt"
	"time"
)

const (
	DefaultBackendMaxKeys = 100000
	DefaultBackendTTL     = 10 * time.Minute

	SourceTypeIP      = "ip"
	SourceTypeHeader  = "header"
	BackendTypeMemory = "memory"
)

// Config is the post-defaults, resolved rate limit configuration consumed by
// the pipeline. All pointer and string defaults are already applied; the
// pipeline never reads the raw YAML types.
type Config struct {
	Requests int
	Window   time.Duration
	Source   SourceConfig
	Backend  BackendConfig
}

type SourceConfig struct {
	Type string // "ip" | "header"
	Key  string // required when Type == "header"
}

type BackendConfig struct {
	Type    string
	MaxKeys int
	TTL     time.Duration
}

// Validate checks the invariants of a resolved Config. Called by tests and
// as a defence-in-depth check in resolve.
func (c *Config) Validate() error {
	if c.Requests < 1 {
		return fmt.Errorf("rate_limit.requests must be >= 1")
	}
	if c.Window < time.Second {
		return fmt.Errorf("rate_limit.window must be >= 1s")
	}
	switch c.Source.Type {
	case SourceTypeIP:
	case SourceTypeHeader:
		if c.Source.Key == "" {
			return fmt.Errorf("rate_limit.source.key is required when source.type is %q", SourceTypeHeader)
		}
	default:
		return fmt.Errorf("rate_limit.source.type must be %q or %q, got %q", SourceTypeIP, SourceTypeHeader, c.Source.Type)
	}
	if c.Backend.Type != BackendTypeMemory {
		return fmt.Errorf("rate_limit.backend.type must be %q, got %q", BackendTypeMemory, c.Backend.Type)
	}
	if c.Backend.MaxKeys < 1 {
		return fmt.Errorf("rate_limit.backend.max_keys must be >= 1")
	}
	if c.Backend.TTL < time.Second {
		return fmt.Errorf("rate_limit.backend.ttl must be >= 1s")
	}
	return nil
}
