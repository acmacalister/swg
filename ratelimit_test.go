package swg

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRateLimiter_Allow_Basic(t *testing.T) {
	rl := NewRateLimiter(10, 5)
	defer rl.Close()

	for range 5 {
		if !rl.Allow("192.168.1.1:1234") {
			t.Fatal("first 5 requests should be allowed (burst)")
		}
	}

	if rl.Allow("192.168.1.1:1234") {
		t.Fatal("6th request should be denied (burst exhausted)")
	}
}

func TestRateLimiter_Allow_Refill(t *testing.T) {
	rl := NewRateLimiter(100, 2)
	defer rl.Close()

	rl.Allow("10.0.0.1:5000")
	rl.Allow("10.0.0.1:5000")

	if rl.Allow("10.0.0.1:5000") {
		t.Fatal("bucket should be empty")
	}

	time.Sleep(25 * time.Millisecond)

	if !rl.Allow("10.0.0.1:5000") {
		t.Fatal("should be allowed after refill")
	}
}

func TestRateLimiter_Allow_PerClient(t *testing.T) {
	rl := NewRateLimiter(1, 1)
	defer rl.Close()

	if !rl.Allow("client-a:1") {
		t.Fatal("client A first request should be allowed")
	}

	if !rl.Allow("client-b:1") {
		t.Fatal("client B first request should be allowed (independent bucket)")
	}

	if rl.Allow("client-a:2") {
		t.Fatal("client A second request should be denied")
	}
}

func TestRateLimiter_Allow_NoPort(t *testing.T) {
	rl := NewRateLimiter(10, 1)
	defer rl.Close()

	if !rl.Allow("192.168.1.1") {
		t.Fatal("address without port should work")
	}
}

func TestRateLimiter_AllowHTTP(t *testing.T) {
	rl := NewRateLimiter(10, 1)
	defer rl.Close()

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.168.1.1:9999"

	w := httptest.NewRecorder()
	if !rl.AllowHTTP(w, req) {
		t.Fatal("first request should be allowed")
	}

	w2 := httptest.NewRecorder()
	if rl.AllowHTTP(w2, req) {
		t.Fatal("second request should be denied")
	}

	resp := w2.Result()
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("status = %d, want 429", resp.StatusCode)
	}
	if resp.Header.Get("Retry-After") != "1" {
		t.Error("missing Retry-After header")
	}
}

func TestRateLimiter_BurstCap(t *testing.T) {
	rl := NewRateLimiter(1000, 3)
	defer rl.Close()

	rl.Allow("x:1")
	rl.Allow("x:1")
	rl.Allow("x:1")

	time.Sleep(100 * time.Millisecond)

	allowed := 0
	for range 10 {
		if rl.Allow("x:1") {
			allowed++
		}
	}

	if allowed > 3 {
		t.Errorf("allowed %d > burst cap 3", allowed)
	}
}

func TestRateLimiter_ClientCount(t *testing.T) {
	rl := NewRateLimiter(10, 5)
	defer rl.Close()

	rl.Allow("a:1")
	rl.Allow("b:1")
	rl.Allow("c:1")

	if n := rl.ClientCount(); n != 3 {
		t.Errorf("ClientCount = %d, want 3", n)
	}
}

func TestRateLimiter_Close_Idempotent(t *testing.T) {
	rl := NewRateLimiter(10, 5)
	rl.Close()
	rl.Close()
}

func TestRateLimiter_Cleanup(t *testing.T) {
	rl := &RateLimiter{
		buckets:         make(map[string]*tokenBucket),
		Rate:            10,
		Burst:           5,
		CleanupInterval: 500 * time.Millisecond,
		done:            make(chan struct{}),
	}

	now := time.Now()
	rl.mu.Lock()
	rl.buckets["stale"] = &tokenBucket{
		tokens:   5,
		lastTime: now.Add(-5 * time.Minute),
	}
	rl.buckets["fresh"] = &tokenBucket{
		tokens:   5,
		lastTime: now,
	}
	rl.mu.Unlock()

	go rl.cleanup()
	defer rl.Close()

	time.Sleep(700 * time.Millisecond)

	rl.mu.Lock()
	_, hasStale := rl.buckets["stale"]
	_, hasFresh := rl.buckets["fresh"]
	rl.mu.Unlock()

	if hasStale {
		t.Error("stale bucket should have been cleaned up")
	}
	if !hasFresh {
		t.Error("fresh bucket should still exist")
	}
}
