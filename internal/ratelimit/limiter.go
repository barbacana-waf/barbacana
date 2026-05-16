// Package ratelimit implements the in-process sliding-window rate limiter
// used by the barbacana pipeline. The Limiter interface is intentionally
// narrow so a future Redis backend can be wired in without touching the
// call site.
package ratelimit

import "context"

// Limiter is the interface implemented by each backend.
type Limiter interface {
	Allow(ctx context.Context, key string) (bool, error)
}
