package config

import (
	"fmt"
	"time"

	"github.com/barbacana-waf/barbacana/internal/ratelimit"
)

// resolveRateLimit converts the raw YAML rate limit blocks into a ratelimit.Config
// with defaults applied. Route-level config wins entirely over global — no merging.
// Returns nil when neither layer has a rate_limit block.
func resolveRateLimit(routeRL, globalRL *RateLimitCfg) (*ratelimit.Config, error) {
	raw := routeRL
	if raw == nil {
		raw = globalRL
	}
	if raw == nil {
		return nil, nil
	}

	cfg := &ratelimit.Config{
		RPS: raw.RPS,
		Source: ratelimit.SourceConfig{
			Type: raw.Source.Type,
			Key:  raw.Source.Key,
		},
		Backend: ratelimit.BackendConfig{
			Type:    ratelimit.BackendTypeMemory,
			MaxKeys: ratelimit.DefaultBackendMaxKeys,
			TTL:     ratelimit.DefaultBackendTTL,
		},
	}

	if raw.Backend != nil {
		if raw.Backend.Type != "" {
			cfg.Backend.Type = raw.Backend.Type
		}
		if raw.Backend.MaxKeys != nil {
			cfg.Backend.MaxKeys = *raw.Backend.MaxKeys
		}
		if raw.Backend.TTL != "" {
			d, err := time.ParseDuration(raw.Backend.TTL)
			if err != nil {
				return nil, fmt.Errorf("rate_limit.backend.ttl: %w", err)
			}
			cfg.Backend.TTL = d
		}
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}
