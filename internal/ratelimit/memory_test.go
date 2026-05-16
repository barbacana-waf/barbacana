package ratelimit

import (
	"context"
	"testing"
	"time"
)

func newTestLimiter(rps, maxKeys int, ttl time.Duration) *MemoryLimiter {
	cfg := Config{
		RPS: rps,
		Source: SourceConfig{Type: SourceTypeIP},
		Backend: BackendConfig{
			Type:    BackendTypeMemory,
			MaxKeys: maxKeys,
			TTL:     ttl,
		},
	}
	l, err := NewMemoryLimiter(cfg)
	if err != nil {
		panic(err)
	}
	return l
}

func TestSlidingWindow_ExactLimit(t *testing.T) {
	rps := 3
	l := newTestLimiter(rps, 100, time.Minute)
	ctx := context.Background()
	now := time.Now()
	l.now = func() time.Time { return now }

	for i := 0; i < rps; i++ {
		ok, err := l.Allow(ctx, "key")
		if err != nil || !ok {
			t.Fatalf("request %d/%d should be allowed, got ok=%v err=%v", i+1, rps, ok, err)
		}
	}

	ok, err := l.Allow(ctx, "key")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Fatalf("request %d should be rejected (rps=%d)", rps+1, rps)
	}
}

func TestSlidingWindow_OldTimestampsNotCounted(t *testing.T) {
	rps := 2
	l := newTestLimiter(rps, 100, time.Minute)
	ctx := context.Background()

	t0 := time.Now()

	// Fill up the window at t0.
	l.now = func() time.Time { return t0 }
	for i := 0; i < rps; i++ {
		ok, _ := l.Allow(ctx, "key")
		if !ok {
			t.Fatalf("request %d should be allowed", i+1)
		}
	}
	ok, _ := l.Allow(ctx, "key")
	if ok {
		t.Fatal("window should be full at t0")
	}

	// Advance past the 1-second window; old timestamps must not count.
	t1 := t0.Add(time.Second + time.Millisecond)
	l.now = func() time.Time { return t1 }

	for i := 0; i < rps; i++ {
		ok, err := l.Allow(ctx, "key")
		if err != nil || !ok {
			t.Fatalf("request %d should be allowed after window reset, got ok=%v err=%v", i+1, ok, err)
		}
	}
}

func TestLRUEviction(t *testing.T) {
	maxKeys := 3
	l := newTestLimiter(10, maxKeys, time.Minute)
	ctx := context.Background()

	// Fill to capacity.
	for i := 0; i < maxKeys; i++ {
		key := string(rune('a' + i))
		l.Allow(ctx, key) //nolint:errcheck
	}

	// Insert one more key — the oldest (least-recently-used) must be evicted.
	l.Allow(ctx, "new") //nolint:errcheck

	// Cache size must not exceed maxKeys.
	if got := l.cache.Len(); got > maxKeys {
		t.Fatalf("cache size %d exceeds max_keys %d after LRU eviction", got, maxKeys)
	}
}

func TestTTLEviction(t *testing.T) {
	ttl := 50 * time.Millisecond
	l := newTestLimiter(10, 100, ttl)
	ctx := context.Background()

	l.Allow(ctx, "idle-key") //nolint:errcheck

	// ttlcache evicts lazily on Get even without Start(); sleeping past TTL
	// guarantees the next Get sees an expired item and returns nil.
	time.Sleep(ttl * 3)

	if item := l.cache.Get("idle-key"); item != nil {
		t.Fatal("idle key should have been evicted after TTL")
	}
}
