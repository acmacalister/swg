package swg

import (
	"net"
	"net/http"
	"sync"
	"time"
)

// RateLimiter provides per-client request throttling using a token-bucket
// algorithm. Each client IP gets an independent bucket that refills at a
// steady rate up to a configurable burst size.
type RateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*tokenBucket

	// Rate is the number of requests permitted per second per client.
	Rate float64

	// Burst is the maximum number of requests a client can make in a
	// single burst before being throttled.
	Burst int

	// CleanupInterval controls how often stale buckets are removed.
	// Defaults to 1 minute.
	CleanupInterval time.Duration

	done chan struct{}
}

type tokenBucket struct {
	tokens   float64
	lastTime time.Time
}

// NewRateLimiter creates a new per-client rate limiter.
// rate is requests/second, burst is the max tokens a client can accumulate.
func NewRateLimiter(rate float64, burst int) *RateLimiter {
	rl := &RateLimiter{
		buckets:         make(map[string]*tokenBucket),
		Rate:            rate,
		Burst:           burst,
		CleanupInterval: time.Minute,
		done:            make(chan struct{}),
	}
	go rl.cleanup()
	return rl
}

// Allow returns true if the request from the given client address is
// permitted under the rate limit.
func (rl *RateLimiter) Allow(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()

	b, ok := rl.buckets[host]
	if !ok {
		b = &tokenBucket{
			tokens:   float64(rl.Burst) - 1,
			lastTime: now,
		}
		rl.buckets[host] = b
		return true
	}

	elapsed := now.Sub(b.lastTime).Seconds()
	b.tokens += elapsed * rl.Rate
	if b.tokens > float64(rl.Burst) {
		b.tokens = float64(rl.Burst)
	}
	b.lastTime = now

	if b.tokens >= 1 {
		b.tokens--
		return true
	}

	return false
}

// AllowHTTP checks the rate limit for the given HTTP request and writes
// a 429 Too Many Requests response if the client is throttled. Returns
// true if the request is allowed.
func (rl *RateLimiter) AllowHTTP(w http.ResponseWriter, r *http.Request) bool {
	if rl.Allow(r.RemoteAddr) {
		return true
	}

	w.Header().Set("Retry-After", "1")
	http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
	return false
}

// Close stops the background cleanup goroutine.
func (rl *RateLimiter) Close() {
	select {
	case <-rl.done:
	default:
		close(rl.done)
	}
}

// ClientCount returns the number of tracked clients.
func (rl *RateLimiter) ClientCount() int {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	return len(rl.buckets)
}

func (rl *RateLimiter) cleanup() {
	interval := rl.CleanupInterval
	if interval == 0 {
		interval = time.Minute
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-rl.done:
			return
		case now := <-ticker.C:
			rl.mu.Lock()
			staleThreshold := now.Add(-2 * interval)
			for key, b := range rl.buckets {
				if b.lastTime.Before(staleThreshold) {
					delete(rl.buckets, key)
				}
			}
			rl.mu.Unlock()
		}
	}
}
