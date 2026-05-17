package ratelimit

import (
	"context"
	"testing"
	"time"
)

func newTestLimiter(requests int, window time.Duration, maxKeys int, ttl time.Duration) *MemoryLimiter {
	cfg := Config{
		Requests: requests,
		Window:   window,
		Source:   SourceConfig{Type: SourceTypeIP},
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
	requests := 3
	l := newTestLimiter(requests, time.Second, 100, time.Minute)
	ctx := context.Background()
	now := time.Now()
	l.now = func() time.Time { return now }

	for i := 0; i < requests; i++ {
		ok, err := l.Allow(ctx, "key")
		if err != nil || !ok {
			t.Fatalf("request %d/%d should be allowed, got ok=%v err=%v", i+1, requests, ok, err)
		}
	}

	ok, err := l.Allow(ctx, "key")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Fatalf("request %d should be rejected (requests=%d)", requests+1, requests)
	}
}

func TestSlidingWindow_OldTimestampsNotCounted(t *testing.T) {
	requests := 2
	window := time.Second
	l := newTestLimiter(requests, window, 100, time.Minute)
	ctx := context.Background()

	t0 := time.Now()

	// Fill up the window at t0.
	l.now = func() time.Time { return t0 }
	for i := 0; i < requests; i++ {
		ok, _ := l.Allow(ctx, "key")
		if !ok {
			t.Fatalf("request %d should be allowed", i+1)
		}
	}
	ok, _ := l.Allow(ctx, "key")
	if ok {
		t.Fatal("window should be full at t0")
	}

	// Advance past the configured window; old timestamps must not count.
	t1 := t0.Add(window + time.Millisecond)
	l.now = func() time.Time { return t1 }

	for i := 0; i < requests; i++ {
		ok, err := l.Allow(ctx, "key")
		if err != nil || !ok {
			t.Fatalf("request %d should be allowed after window reset, got ok=%v err=%v", i+1, ok, err)
		}
	}
}

func TestSlidingWindow_CustomWindow(t *testing.T) {
	// 3 requests per minute: at t0 the first 3 pass and the 4th is rejected;
	// 30 s later (still inside the window) all are still rejected; past the
	// full minute they are allowed again.
	requests := 3
	window := time.Minute
	l := newTestLimiter(requests, window, 100, time.Hour)
	ctx := context.Background()

	t0 := time.Now()
	l.now = func() time.Time { return t0 }
	for i := 0; i < requests; i++ {
		if ok, _ := l.Allow(ctx, "key"); !ok {
			t.Fatalf("request %d/%d should be allowed", i+1, requests)
		}
	}
	if ok, _ := l.Allow(ctx, "key"); ok {
		t.Fatal("4th request inside window should be rejected")
	}

	// Half-way through the window: still over budget.
	l.now = func() time.Time { return t0.Add(window / 2) }
	if ok, _ := l.Allow(ctx, "key"); ok {
		t.Fatal("request at window/2 should still be rejected")
	}

	// Past the window: all 3 timestamps expire.
	l.now = func() time.Time { return t0.Add(window + time.Millisecond) }
	for i := 0; i < requests; i++ {
		if ok, _ := l.Allow(ctx, "key"); !ok {
			t.Fatalf("request %d after window expiry should be allowed", i+1)
		}
	}
}

// TestSlidingWindow_LongWindow_PartialExpiry exercises true sliding-window
// behavior over a window longer than 1 s. Timestamps fired at different
// instants must expire independently — not all at once at the end of a
// fixed bucket. With window=2s and requests=2, a request at t0 expires
// before a request at t0+1s does, so a fresh request at t0+2.001s should
// be allowed while the t0+1s timestamp is still in the window.
func TestSlidingWindow_LongWindow_PartialExpiry(t *testing.T) {
	window := 2 * time.Second
	l := newTestLimiter(2, window, 100, time.Minute)
	ctx := context.Background()

	t0 := time.Now()
	l.now = func() time.Time { return t0 }
	if ok, _ := l.Allow(ctx, "key"); !ok {
		t.Fatal("req at t0 should be allowed")
	}

	t1 := t0.Add(time.Second)
	l.now = func() time.Time { return t1 }
	if ok, _ := l.Allow(ctx, "key"); !ok {
		t.Fatal("req at t0+1s should be allowed (2nd in window)")
	}
	if ok, _ := l.Allow(ctx, "key"); ok {
		t.Fatal("req at t0+1s (3rd) should be rejected — at limit")
	}

	// Past the window from t0 but still inside the window from t0+1s:
	// the t0 timestamp expires, the t0+1s timestamp survives, so the
	// budget recovers by exactly one slot.
	t2 := t0.Add(window + time.Millisecond)
	l.now = func() time.Time { return t2 }
	if ok, _ := l.Allow(ctx, "key"); !ok {
		t.Fatal("req after t0 expires should be allowed (only t0+1s still counts)")
	}
	if ok, _ := l.Allow(ctx, "key"); ok {
		t.Fatal("immediate follow-up should be rejected — back at limit")
	}
}

// TestSlidingWindow_MinuteWindow_HoldsAcrossSubSecondTicks verifies the
// limiter does not reset at 1-second boundaries when configured with a
// minute-scale window: a single bucket fills at t0 and stays full as the
// clock advances second-by-second up to (but not past) the minute mark.
func TestSlidingWindow_MinuteWindow_HoldsAcrossSubSecondTicks(t *testing.T) {
	window := time.Minute
	requests := 5
	l := newTestLimiter(requests, window, 100, time.Hour)
	ctx := context.Background()

	t0 := time.Now()
	l.now = func() time.Time { return t0 }
	for i := 0; i < requests; i++ {
		if ok, _ := l.Allow(ctx, "key"); !ok {
			t.Fatalf("req %d/%d at t0 should be allowed", i+1, requests)
		}
	}

	// Tick once per second for the duration of the window minus 1 s.
	// Every Allow call must be rejected — the window has not advanced
	// enough for any timestamp from t0 to expire.
	for sec := 1; sec < int(window/time.Second); sec++ {
		ts := t0.Add(time.Duration(sec) * time.Second)
		l.now = func() time.Time { return ts }
		if ok, _ := l.Allow(ctx, "key"); ok {
			t.Fatalf("req at t0+%ds should be rejected — minute window still full", sec)
		}
	}

	// One tick past the window: all 5 t0 timestamps expire together.
	l.now = func() time.Time { return t0.Add(window + time.Millisecond) }
	if ok, _ := l.Allow(ctx, "key"); !ok {
		t.Fatal("req past the minute window should be allowed")
	}
}

func TestLRUEviction(t *testing.T) {
	maxKeys := 3
	l := newTestLimiter(10, time.Second, maxKeys, time.Minute)
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
	l := newTestLimiter(10, time.Second, 100, ttl)
	ctx := context.Background()

	l.Allow(ctx, "idle-key") //nolint:errcheck

	// ttlcache evicts lazily on Get even without Start(); sleeping past TTL
	// guarantees the next Get sees an expired item and returns nil.
	time.Sleep(ttl * 3)

	if item := l.cache.Get("idle-key"); item != nil {
		t.Fatal("idle key should have been evicted after TTL")
	}
}
