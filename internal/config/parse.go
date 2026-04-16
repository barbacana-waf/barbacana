package config

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// parseByteSize accepts "10MB", "16KB", "128KB", "1GB", or bare integers
// (bytes). Powers of 1024 per config-schema.md. Empty string returns 0.
func parseByteSize(s string) (int64, error) {
	if s == "" {
		return 0, nil
	}
	orig := s
	s = strings.TrimSpace(s)
	mul := int64(1)
	switch {
	case strings.HasSuffix(s, "GB"):
		mul = 1024 * 1024 * 1024
		s = strings.TrimSuffix(s, "GB")
	case strings.HasSuffix(s, "MB"):
		mul = 1024 * 1024
		s = strings.TrimSuffix(s, "MB")
	case strings.HasSuffix(s, "KB"):
		mul = 1024
		s = strings.TrimSuffix(s, "KB")
	case strings.HasSuffix(s, "B"):
		s = strings.TrimSuffix(s, "B")
	}
	s = strings.TrimSpace(s)
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid byte size %q", orig)
	}
	return n * mul, nil
}

// parseDuration wraps time.ParseDuration and returns the zero duration on
// empty input. Used in resolvers where "" means "inherit default".
func parseDuration(s string) (time.Duration, error) {
	if s == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("invalid duration %q", s)
	}
	return d, nil
}
