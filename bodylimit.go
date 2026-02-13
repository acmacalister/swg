package swg

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
)

// Common body size constants for convenience.
const (
	KB = 1024
	MB = 1024 * KB
	GB = 1024 * MB
)

// ErrBodyTooLarge is returned when the request body exceeds the configured limit.
var ErrBodyTooLarge = errors.New("request body too large")

// BodyLimitConfig configures request body size limits.
type BodyLimitConfig struct {
	// MaxSize is the maximum allowed request body size in bytes.
	// Zero means no limit.
	MaxSize int64

	// StreamCheck enables early rejection by checking Content-Length header
	// before reading the body. If Content-Length exceeds MaxSize, the request
	// is rejected immediately without buffering.
	StreamCheck bool

	// RejectResponse is an optional custom response to send when the limit is
	// exceeded. If nil, a default 413 Payload Too Large response is sent.
	RejectResponse *http.Response

	// SkipPaths is a list of URL path prefixes to skip body limit checks.
	// Useful for upload endpoints that need larger limits.
	SkipPaths []string

	// SkipMethods is a list of HTTP methods to skip body limit checks.
	// By default, GET, HEAD, OPTIONS, and TRACE are skipped as they
	// typically don't have request bodies.
	SkipMethods []string
}

// DefaultBodyLimitConfig returns a configuration with sensible defaults.
func DefaultBodyLimitConfig() BodyLimitConfig {
	return BodyLimitConfig{
		MaxSize:     10 * MB, // 10 MB default
		StreamCheck: true,
		SkipMethods: []string{"GET", "HEAD", "OPTIONS", "TRACE"},
	}
}

// BodyLimiter enforces request body size limits.
type BodyLimiter struct {
	Config BodyLimitConfig

	mu          sync.RWMutex
	pathLimits  map[string]int64 // path prefix -> max size
	methodSkips map[string]bool
}

// NewBodyLimiter creates a new BodyLimiter with the given maximum size.
func NewBodyLimiter(maxSize int64) *BodyLimiter {
	cfg := DefaultBodyLimitConfig()
	cfg.MaxSize = maxSize
	return NewBodyLimiterWithConfig(cfg)
}

// NewBodyLimiterWithConfig creates a BodyLimiter with custom configuration.
func NewBodyLimiterWithConfig(cfg BodyLimitConfig) *BodyLimiter {
	bl := &BodyLimiter{
		Config:      cfg,
		pathLimits:  make(map[string]int64),
		methodSkips: make(map[string]bool),
	}

	// Initialize method skips
	for _, m := range cfg.SkipMethods {
		bl.methodSkips[m] = true
	}

	return bl
}

// SetPathLimit sets a custom body size limit for a specific path prefix.
// This overrides the global MaxSize for requests matching the prefix.
// Set limit to 0 to disable limits for this path, or -1 to use the global limit.
func (bl *BodyLimiter) SetPathLimit(pathPrefix string, limit int64) {
	bl.mu.Lock()
	defer bl.mu.Unlock()
	if limit < 0 {
		delete(bl.pathLimits, pathPrefix)
	} else {
		bl.pathLimits[pathPrefix] = limit
	}
}

// GetPathLimit returns the effective limit for a given path.
// Returns the path-specific limit if set, otherwise the global MaxSize.
func (bl *BodyLimiter) GetPathLimit(path string) int64 {
	bl.mu.RLock()
	defer bl.mu.RUnlock()

	// Check path-specific limits (longest prefix match)
	var matchedPrefix string
	var matchedLimit int64 = -1

	for prefix, limit := range bl.pathLimits {
		if len(prefix) > len(matchedPrefix) && hasPathPrefix(path, prefix) {
			matchedPrefix = prefix
			matchedLimit = limit
		}
	}

	if matchedLimit >= 0 {
		return matchedLimit
	}

	return bl.Config.MaxSize
}

// Check validates the request body size against configured limits.
// Returns ErrBodyTooLarge if the body exceeds the limit.
// If StreamCheck is enabled and Content-Length is set, validation happens
// without reading the body. Otherwise, the body is wrapped with a limiting reader.
func (bl *BodyLimiter) Check(req *http.Request) error {
	// Skip configured methods
	if bl.methodSkips[req.Method] {
		return nil
	}

	// Skip configured paths
	for _, prefix := range bl.Config.SkipPaths {
		if hasPathPrefix(req.URL.Path, prefix) {
			return nil
		}
	}

	limit := bl.GetPathLimit(req.URL.Path)
	if limit == 0 {
		return nil // No limit for this path
	}

	// Early rejection via Content-Length header
	if bl.Config.StreamCheck && req.ContentLength > 0 {
		if req.ContentLength > limit {
			return fmt.Errorf("%w: content-length %d exceeds limit %d", ErrBodyTooLarge, req.ContentLength, limit)
		}
	}

	// Wrap body with limiting reader for streaming validation
	if req.Body != nil && req.Body != http.NoBody {
		req.Body = &limitedReadCloser{
			ReadCloser: req.Body,
			remaining:  limit,
			limit:      limit,
		}
	}

	return nil
}

// HandleRequest implements RequestHook for integration with PolicyEngine.
// Returns a 413 response if the body size limit is exceeded.
func (bl *BodyLimiter) HandleRequest(ctx context.Context, req *http.Request, rc *RequestContext) *http.Response {
	if err := bl.Check(req); err != nil {
		if errors.Is(err, ErrBodyTooLarge) {
			if bl.Config.RejectResponse != nil {
				return bl.Config.RejectResponse
			}
			return &http.Response{
				StatusCode: http.StatusRequestEntityTooLarge,
				Status:     "413 Payload Too Large",
				Proto:      req.Proto,
				ProtoMajor: req.ProtoMajor,
				ProtoMinor: req.ProtoMinor,
				Header:     http.Header{"Content-Type": []string{"text/plain; charset=utf-8"}},
				Body:       io.NopCloser(errReader{err: err}),
			}
		}
	}
	return nil
}

// Middleware returns an http.Handler middleware that enforces body size limits.
func (bl *BodyLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := bl.Check(r); err != nil {
			if errors.Is(err, ErrBodyTooLarge) {
				http.Error(w, err.Error(), http.StatusRequestEntityTooLarge)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// limitedReadCloser wraps an io.ReadCloser with a size limit.
type limitedReadCloser struct {
	io.ReadCloser
	remaining int64
	limit     int64
}

func (l *limitedReadCloser) Read(p []byte) (n int, err error) {
	if l.remaining <= 0 {
		return 0, fmt.Errorf("%w: exceeded limit of %d bytes", ErrBodyTooLarge, l.limit)
	}

	// Limit read size to remaining bytes
	if int64(len(p)) > l.remaining {
		p = p[:l.remaining]
	}

	n, err = l.ReadCloser.Read(p)
	l.remaining -= int64(n)

	// Check if we've hit the limit exactly and there's more data
	if l.remaining == 0 && err == nil {
		// Peek to see if there's more data
		var peek [1]byte
		pn, perr := l.ReadCloser.Read(peek[:])
		if pn > 0 {
			return n, fmt.Errorf("%w: exceeded limit of %d bytes", ErrBodyTooLarge, l.limit)
		}
		if perr == io.EOF {
			err = io.EOF
		}
	}

	return n, err
}

// errReader returns an error message as its content.
type errReader struct {
	err error
}

func (e errReader) Read(p []byte) (n int, err error) {
	msg := e.err.Error()
	n = copy(p, msg)
	return n, io.EOF
}

// hasPathPrefix checks if path starts with prefix, handling trailing slashes.
func hasPathPrefix(path, prefix string) bool {
	if prefix == "/" {
		return true // Root matches everything
	}
	if len(path) < len(prefix) {
		return false
	}
	if path[:len(prefix)] != prefix {
		return false
	}
	// Exact match or path continues with /
	return len(path) == len(prefix) || path[len(prefix)] == '/'
}

// LimitRequestBody is a convenience function that wraps an http.Handler
// with body size limiting middleware.
func LimitRequestBody(maxSize int64, next http.Handler) http.Handler {
	bl := NewBodyLimiter(maxSize)
	return bl.Middleware(next)
}
