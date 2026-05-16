package ratelimit

import (
	"context"
	"sync"
	"time"

	"github.com/jellydator/ttlcache/v3"
)

// entry holds the sliding-window state for one rate-limit key.
type entry struct {
	mu         sync.Mutex
	timestamps []time.Time
}

// allow reports whether the request at `now` is within the rps budget.
// It drops timestamps older than (now − 1s) before checking, maintaining
// a rolling 1-second window.
func (e *entry) allow(now time.Time, rps int) bool {
	e.mu.Lock()
	defer e.mu.Unlock()

	cutoff := now.Add(-time.Second)
	j := 0
	for _, t := range e.timestamps {
		if t.After(cutoff) {
			e.timestamps[j] = t
			j++
		}
	}
	e.timestamps = e.timestamps[:j]

	if len(e.timestamps) >= rps {
		return false
	}
	e.timestamps = append(e.timestamps, now)
	return true
}

// MemoryLimiter is the in-process sliding-window rate limiter. It uses
// jellydator/ttlcache for per-key LRU eviction (max_keys) and idle-TTL
// eviction. Each key's sliding window is stored in an *entry whose own
// mutex serialises timestamp mutations independently of the cache lock.
type MemoryLimiter struct {
	mu    sync.Mutex
	cache *ttlcache.Cache[string, *entry]
	rps   int
	now   func() time.Time // injectable for testing; defaults to time.Now
}

// NewMemoryLimiter creates a MemoryLimiter from a resolved Config.
func NewMemoryLimiter(cfg Config) (*MemoryLimiter, error) {
	c := ttlcache.New[string, *entry](
		ttlcache.WithTTL[string, *entry](cfg.Backend.TTL),
		ttlcache.WithCapacity[string, *entry](uint64(cfg.Backend.MaxKeys)),
	)
	return &MemoryLimiter{
		cache: c,
		rps:   cfg.RPS,
		now:   time.Now,
	}, nil
}

// Allow returns true when the request is within the rps budget for key.
// The global mutex serialises cache.Get + cache.Set so that exactly one
// *entry is created per key; the per-entry mutex serialises the timestamp
// mutations independently.
func (l *MemoryLimiter) Allow(ctx context.Context, key string) (bool, error) {
	now := l.now()

	l.mu.Lock()
	item := l.cache.Get(key)
	var e *entry
	if item == nil {
		e = &entry{timestamps: make([]time.Time, 0, l.rps)}
		l.cache.Set(key, e, ttlcache.DefaultTTL)
	} else {
		e = item.Value()
	}
	l.mu.Unlock()

	return e.allow(now, l.rps), nil
}
