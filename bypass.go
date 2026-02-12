package swg

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"log/slog"
	"net/http"
	"sync"
)

// DefaultBypassHeader is the default HTTP header used to carry a bypass token.
const DefaultBypassHeader = "X-SWG-Bypass"

// Bypass allows authorized clients to skip content filtering. Clients
// present a secret token via an HTTP header or are identified by their
// [RequestContext] identity. When a request is granted bypass, filtering
// and policy hooks are skipped and the request is forwarded directly.
//
// Tokens are compared using constant-time comparison to prevent timing
// side-channels.
//
// Usage:
//
//	b := swg.NewBypass()
//	b.AddToken("debug-token-abc123")
//	proxy.Bypass = b
//
// Clients then set the header:
//
//	curl -H "X-SWG-Bypass: debug-token-abc123" -x http://proxy:8080 http://example.com
type Bypass struct {
	// Header is the HTTP header name that carries the bypass token.
	// Defaults to [DefaultBypassHeader] ("X-SWG-Bypass").
	Header string

	// Identities is a set of [RequestContext] identity values (e.g.
	// usernames from mTLS certificates) that are granted bypass.
	// Identity matching is case-sensitive and checked after token
	// matching.
	Identities map[string]bool

	// Logger for bypass events. If nil, bypass is silent.
	Logger *slog.Logger

	mu     sync.RWMutex
	tokens map[string]bool
}

// NewBypass creates a [Bypass] with the default header name and no tokens.
// Use [Bypass.AddToken] or [Bypass.GenerateToken] to register tokens.
func NewBypass() *Bypass {
	return &Bypass{
		Header:     DefaultBypassHeader,
		Identities: make(map[string]bool),
		tokens:     make(map[string]bool),
	}
}

// AddToken registers a bypass token. Duplicate tokens are ignored.
// AddToken is safe for concurrent use.
func (b *Bypass) AddToken(token string) {
	b.mu.Lock()
	b.tokens[token] = true
	b.mu.Unlock()
}

// RemoveToken revokes a previously registered bypass token.
// RemoveToken is safe for concurrent use.
func (b *Bypass) RemoveToken(token string) {
	b.mu.Lock()
	delete(b.tokens, token)
	b.mu.Unlock()
}

// RevokeAll removes all registered bypass tokens.
// RevokeAll is safe for concurrent use.
func (b *Bypass) RevokeAll() {
	b.mu.Lock()
	b.tokens = make(map[string]bool)
	b.mu.Unlock()
}

// TokenCount returns the number of registered bypass tokens.
// TokenCount is safe for concurrent use.
func (b *Bypass) TokenCount() int {
	b.mu.RLock()
	n := len(b.tokens)
	b.mu.RUnlock()
	return n
}

// GenerateToken creates a cryptographically random 32-byte hex token,
// registers it, and returns the token string. The returned token is
// suitable for use in HTTP headers.
func (b *Bypass) GenerateToken() (string, error) {
	var buf [32]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", err
	}
	token := hex.EncodeToString(buf[:])
	b.AddToken(token)
	return token, nil
}

// ShouldBypass reports whether the request should skip content filtering.
// It checks the bypass header for a valid token using constant-time
// comparison, then falls back to identity matching via [RequestContext].
// Returns true if bypass is granted.
func (b *Bypass) ShouldBypass(req *http.Request) bool {
	header := b.Header
	if header == "" {
		header = DefaultBypassHeader
	}

	if token := req.Header.Get(header); token != "" {
		if b.matchToken(token) {
			if b.Logger != nil {
				b.Logger.Info("bypass granted",
					"method", "token",
					"host", req.Host,
					"path", req.URL.Path,
					"remote", req.RemoteAddr,
				)
			}
			req.Header.Del(header)
			return true
		}
	}

	if len(b.Identities) > 0 {
		if rc := GetRequestContext(req.Context()); rc != nil && rc.Identity != "" {
			if b.Identities[rc.Identity] {
				if b.Logger != nil {
					b.Logger.Info("bypass granted",
						"method", "identity",
						"identity", rc.Identity,
						"host", req.Host,
						"path", req.URL.Path,
					)
				}
				return true
			}
		}
	}

	return false
}

// matchToken checks whether the given token matches any registered
// token using constant-time comparison.
func (b *Bypass) matchToken(candidate string) bool {
	b.mu.RLock()
	defer b.mu.RUnlock()

	for token := range b.tokens {
		if len(token) == len(candidate) && subtle.ConstantTimeCompare([]byte(token), []byte(candidate)) == 1 {
			return true
		}
	}
	return false
}
