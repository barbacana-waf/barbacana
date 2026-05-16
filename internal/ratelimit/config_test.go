package ratelimit

import (
	"testing"
	"time"
)

func TestConfig_Validate_HeaderNoKey(t *testing.T) {
	cfg := Config{
		RPS:    10,
		Source: SourceConfig{Type: SourceTypeHeader, Key: ""},
		Backend: BackendConfig{
			Type:    BackendTypeMemory,
			MaxKeys: DefaultBackendMaxKeys,
			TTL:     DefaultBackendTTL,
		},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for header source with no key, got nil")
	}
}

func TestConfig_Validate_IPSourceNoKeyRequired(t *testing.T) {
	cfg := Config{
		RPS:    10,
		Source: SourceConfig{Type: SourceTypeIP},
		Backend: BackendConfig{
			Type:    BackendTypeMemory,
			MaxKeys: DefaultBackendMaxKeys,
			TTL:     DefaultBackendTTL,
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("IP source should not require a key: %v", err)
	}
}

func TestConfig_Validate_ZeroRPS(t *testing.T) {
	cfg := Config{
		RPS:    0,
		Source: SourceConfig{Type: SourceTypeIP},
		Backend: BackendConfig{
			Type:    BackendTypeMemory,
			MaxKeys: DefaultBackendMaxKeys,
			TTL:     DefaultBackendTTL,
		},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for rps=0, got nil")
	}
}

func TestConfig_Validate_TTLTooShort(t *testing.T) {
	cfg := Config{
		RPS:    5,
		Source: SourceConfig{Type: SourceTypeIP},
		Backend: BackendConfig{
			Type:    BackendTypeMemory,
			MaxKeys: DefaultBackendMaxKeys,
			TTL:     500 * time.Millisecond,
		},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for ttl < 1s, got nil")
	}
}

func TestConfig_Validate_Valid(t *testing.T) {
	cfg := Config{
		RPS:    100,
		Source: SourceConfig{Type: SourceTypeHeader, Key: "X-Real-IP"},
		Backend: BackendConfig{
			Type:    BackendTypeMemory,
			MaxKeys: 50000,
			TTL:     5 * time.Minute,
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected error for valid config: %v", err)
	}
}
