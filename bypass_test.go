package swg

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// ---------------------------------------------------------------------------
// Constructor
// ---------------------------------------------------------------------------

func TestNewBypass(t *testing.T) {
	b := NewBypass()
	if b.Header != DefaultBypassHeader {
		t.Errorf("want header %q, got %q", DefaultBypassHeader, b.Header)
	}
	if b.tokens == nil {
		t.Fatal("tokens map should be initialized")
	}
	if b.Identities == nil {
		t.Fatal("identities map should be initialized")
	}
	if b.TokenCount() != 0 {
		t.Errorf("want 0 tokens, got %d", b.TokenCount())
	}
}

// ---------------------------------------------------------------------------
// Token management
// ---------------------------------------------------------------------------

func TestBypass_AddToken(t *testing.T) {
	b := NewBypass()
	b.AddToken("tok1")
	b.AddToken("tok2")
	if b.TokenCount() != 2 {
		t.Errorf("want 2 tokens, got %d", b.TokenCount())
	}
	b.AddToken("tok1")
	if b.TokenCount() != 2 {
		t.Errorf("duplicate add should not increase count, got %d", b.TokenCount())
	}
}

func TestBypass_RemoveToken(t *testing.T) {
	b := NewBypass()
	b.AddToken("tok1")
	b.AddToken("tok2")
	b.RemoveToken("tok1")
	if b.TokenCount() != 1 {
		t.Errorf("want 1 token after remove, got %d", b.TokenCount())
	}
	b.RemoveToken("nonexistent")
	if b.TokenCount() != 1 {
		t.Errorf("removing nonexistent should be no-op, got %d", b.TokenCount())
	}
}

func TestBypass_RevokeAll(t *testing.T) {
	b := NewBypass()
	b.AddToken("a")
	b.AddToken("b")
	b.AddToken("c")
	b.RevokeAll()
	if b.TokenCount() != 0 {
		t.Errorf("want 0 tokens after revoke all, got %d", b.TokenCount())
	}
}

func TestBypass_GenerateToken(t *testing.T) {
	b := NewBypass()
	tok, err := b.GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	if len(tok) != 64 {
		t.Errorf("want 64-char hex token, got %d chars", len(tok))
	}
	if b.TokenCount() != 1 {
		t.Errorf("want 1 token after generate, got %d", b.TokenCount())
	}

	tok2, err := b.GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	if tok == tok2 {
		t.Error("generated tokens should be unique")
	}
}

// ---------------------------------------------------------------------------
// ShouldBypass — token matching
// ---------------------------------------------------------------------------

func TestBypass_ShouldBypass_ValidToken(t *testing.T) {
	b := NewBypass()
	b.AddToken("secret123")

	req := httptest.NewRequest(http.MethodGet, "http://example.com/path", nil)
	req.Header.Set(DefaultBypassHeader, "secret123")

	if !b.ShouldBypass(req) {
		t.Error("valid token should grant bypass")
	}
	if req.Header.Get(DefaultBypassHeader) != "" {
		t.Error("bypass header should be stripped after match")
	}
}

func TestBypass_ShouldBypass_InvalidToken(t *testing.T) {
	b := NewBypass()
	b.AddToken("secret123")

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.Header.Set(DefaultBypassHeader, "wrong-token")

	if b.ShouldBypass(req) {
		t.Error("invalid token should not grant bypass")
	}
}

func TestBypass_ShouldBypass_NoHeader(t *testing.T) {
	b := NewBypass()
	b.AddToken("secret123")

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	if b.ShouldBypass(req) {
		t.Error("missing header should not grant bypass")
	}
}

func TestBypass_ShouldBypass_EmptyToken(t *testing.T) {
	b := NewBypass()
	b.AddToken("secret123")

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.Header.Set(DefaultBypassHeader, "")

	if b.ShouldBypass(req) {
		t.Error("empty token header should not grant bypass")
	}
}

func TestBypass_ShouldBypass_NoTokensRegistered(t *testing.T) {
	b := NewBypass()

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.Header.Set(DefaultBypassHeader, "anything")

	if b.ShouldBypass(req) {
		t.Error("no tokens registered should not grant bypass")
	}
}

func TestBypass_ShouldBypass_CustomHeader(t *testing.T) {
	b := NewBypass()
	b.Header = "X-Debug-Token"
	b.AddToken("debug")

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.Header.Set("X-Debug-Token", "debug")

	if !b.ShouldBypass(req) {
		t.Error("valid token with custom header should grant bypass")
	}
}

func TestBypass_ShouldBypass_MultipleTokens(t *testing.T) {
	b := NewBypass()
	b.AddToken("tok-alpha")
	b.AddToken("tok-beta")
	b.AddToken("tok-gamma")

	for _, tok := range []string{"tok-alpha", "tok-beta", "tok-gamma"} {
		req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
		req.Header.Set(DefaultBypassHeader, tok)
		if !b.ShouldBypass(req) {
			t.Errorf("token %q should grant bypass", tok)
		}
	}
}

func TestBypass_ShouldBypass_RevokedToken(t *testing.T) {
	b := NewBypass()
	b.AddToken("ephemeral")

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.Header.Set(DefaultBypassHeader, "ephemeral")
	if !b.ShouldBypass(req) {
		t.Fatal("token should grant bypass before revocation")
	}

	b.RemoveToken("ephemeral")
	req2 := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req2.Header.Set(DefaultBypassHeader, "ephemeral")
	if b.ShouldBypass(req2) {
		t.Error("revoked token should not grant bypass")
	}
}

// ---------------------------------------------------------------------------
// ShouldBypass — identity matching
// ---------------------------------------------------------------------------

func TestBypass_ShouldBypass_Identity(t *testing.T) {
	b := NewBypass()
	b.Identities["alice"] = true

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	ctx := WithRequestContext(req.Context(), &RequestContext{Identity: "alice"})
	req = req.WithContext(ctx)

	if !b.ShouldBypass(req) {
		t.Error("whitelisted identity should grant bypass")
	}
}

func TestBypass_ShouldBypass_IdentityNotWhitelisted(t *testing.T) {
	b := NewBypass()
	b.Identities["alice"] = true

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	ctx := WithRequestContext(req.Context(), &RequestContext{Identity: "bob"})
	req = req.WithContext(ctx)

	if b.ShouldBypass(req) {
		t.Error("non-whitelisted identity should not grant bypass")
	}
}

func TestBypass_ShouldBypass_IdentityNoContext(t *testing.T) {
	b := NewBypass()
	b.Identities["alice"] = true

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	if b.ShouldBypass(req) {
		t.Error("no request context should not grant identity bypass")
	}
}

func TestBypass_ShouldBypass_IdentityEmptyString(t *testing.T) {
	b := NewBypass()
	b.Identities["alice"] = true

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	ctx := WithRequestContext(req.Context(), &RequestContext{Identity: ""})
	req = req.WithContext(ctx)

	if b.ShouldBypass(req) {
		t.Error("empty identity should not grant bypass")
	}
}

func TestBypass_ShouldBypass_TokenBeforeIdentity(t *testing.T) {
	b := NewBypass()
	b.AddToken("tok")
	b.Identities["alice"] = true

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.Header.Set(DefaultBypassHeader, "tok")
	ctx := WithRequestContext(req.Context(), &RequestContext{Identity: "alice"})
	req = req.WithContext(ctx)

	if !b.ShouldBypass(req) {
		t.Error("token should grant bypass")
	}
	if req.Header.Get(DefaultBypassHeader) != "" {
		t.Error("header should be stripped (token path)")
	}
}

// ---------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------

func TestBypass_ShouldBypass_LogsTokenBypass(t *testing.T) {
	var buf strings.Builder
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	b := NewBypass()
	b.Logger = logger
	b.AddToken("secret")

	req := httptest.NewRequest(http.MethodGet, "http://example.com/test", nil)
	req.Header.Set(DefaultBypassHeader, "secret")
	b.ShouldBypass(req)

	if !strings.Contains(buf.String(), "bypass granted") {
		t.Error("expected 'bypass granted' log entry")
	}
	if !strings.Contains(buf.String(), "method=token") {
		t.Error("expected method=token in log entry")
	}
}

func TestBypass_ShouldBypass_LogsIdentityBypass(t *testing.T) {
	var buf strings.Builder
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	b := NewBypass()
	b.Logger = logger
	b.Identities["alice"] = true

	req := httptest.NewRequest(http.MethodGet, "http://example.com/test", nil)
	ctx := WithRequestContext(req.Context(), &RequestContext{Identity: "alice"})
	req = req.WithContext(ctx)
	b.ShouldBypass(req)

	if !strings.Contains(buf.String(), "bypass granted") {
		t.Error("expected 'bypass granted' log entry")
	}
	if !strings.Contains(buf.String(), "method=identity") {
		t.Error("expected method=identity in log entry")
	}
}

// ---------------------------------------------------------------------------
// Concurrency
// ---------------------------------------------------------------------------

func TestBypass_ConcurrentAccess(t *testing.T) {
	b := NewBypass()
	var wg sync.WaitGroup

	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tok, _ := b.GenerateToken()
			req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
			req.Header.Set(DefaultBypassHeader, tok)
			b.ShouldBypass(req)
		}()
	}

	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			b.AddToken("shared")
			b.RemoveToken("shared")
			_ = b.TokenCount()
		}()
	}

	wg.Wait()
}

// ---------------------------------------------------------------------------
// Proxy integration — handleHTTP bypass
// ---------------------------------------------------------------------------

func TestProxy_BypassSkipsFilter(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	}))
	defer backend.Close()

	certPEM, keyPEM, err := GenerateCA("Test CA", 1)
	if err != nil {
		t.Fatal(err)
	}
	cm, err := NewCertManagerFromPEM(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}

	blockAll := FilterFunc(func(_ *http.Request) (bool, string) {
		return true, "blocked"
	})

	bypass := NewBypass()
	bypass.AddToken("letmein")

	proxy := NewProxy(":0", cm)
	proxy.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	proxy.Filter = blockAll
	proxy.Bypass = bypass

	// Without bypass token — should be blocked (403).
	req1 := httptest.NewRequest(http.MethodGet, backend.URL, nil)
	rec1 := httptest.NewRecorder()
	proxy.handleHTTP(rec1, req1)
	if rec1.Code != http.StatusForbidden {
		t.Errorf("without bypass: want 403, got %d", rec1.Code)
	}

	// With bypass token — should reach backend (200).
	req2 := httptest.NewRequest(http.MethodGet, backend.URL, nil)
	req2.Header.Set(DefaultBypassHeader, "letmein")
	rec2 := httptest.NewRecorder()
	proxy.handleHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Errorf("with bypass: want 200, got %d", rec2.Code)
	}
}

func TestProxy_BypassIdentitySkipsFilter(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	certPEM, keyPEM, err := GenerateCA("Test CA", 1)
	if err != nil {
		t.Fatal(err)
	}
	cm, err := NewCertManagerFromPEM(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}

	blockAll := FilterFunc(func(_ *http.Request) (bool, string) {
		return true, "blocked"
	})

	bypass := NewBypass()
	bypass.Identities["admin"] = true

	proxy := NewProxy(":0", cm)
	proxy.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	proxy.Filter = blockAll
	proxy.Bypass = bypass

	// Non-admin identity — blocked.
	req1 := httptest.NewRequest(http.MethodGet, backend.URL, nil)
	ctx1 := WithRequestContext(req1.Context(), &RequestContext{Identity: "user"})
	req1 = req1.WithContext(ctx1)
	rec1 := httptest.NewRecorder()
	proxy.handleHTTP(rec1, req1)
	if rec1.Code != http.StatusForbidden {
		t.Errorf("non-admin: want 403, got %d", rec1.Code)
	}

	// Admin identity — bypassed.
	req2 := httptest.NewRequest(http.MethodGet, backend.URL, nil)
	ctx2 := WithRequestContext(req2.Context(), &RequestContext{Identity: "admin"})
	req2 = req2.WithContext(ctx2)
	rec2 := httptest.NewRecorder()
	proxy.handleHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Errorf("admin: want 200, got %d", rec2.Code)
	}
}

func TestProxy_NoBypassFilterStillWorks(t *testing.T) {
	certPEM, keyPEM, err := GenerateCA("Test CA", 1)
	if err != nil {
		t.Fatal(err)
	}
	cm, err := NewCertManagerFromPEM(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}

	blockAll := FilterFunc(func(_ *http.Request) (bool, string) {
		return true, "blocked"
	})

	proxy := NewProxy(":0", cm)
	proxy.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	proxy.Filter = blockAll

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	rec := httptest.NewRecorder()
	proxy.handleHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("want 403, got %d", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// Constant-time comparison
// ---------------------------------------------------------------------------

func TestBypass_ConstantTimeComparison(t *testing.T) {
	b := NewBypass()
	b.AddToken("correct-token-value")

	tests := []struct {
		name  string
		token string
		want  bool
	}{
		{"exact match", "correct-token-value", true},
		{"wrong value", "incorrect-token-valu", false},
		{"different length", "short", false},
		{"empty", "", false},
		{"prefix", "correct-token", false},
		{"suffix", "token-value", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
			if tt.token != "" {
				req.Header.Set(DefaultBypassHeader, tt.token)
			}
			got := b.ShouldBypass(req)
			if got != tt.want {
				t.Errorf("ShouldBypass(%q) = %v, want %v", tt.token, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Header fallback when Header field is empty
// ---------------------------------------------------------------------------

func TestBypass_ShouldBypass_EmptyHeaderFieldUsesDefault(t *testing.T) {
	b := NewBypass()
	b.Header = ""
	b.AddToken("tok")

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.Header.Set(DefaultBypassHeader, "tok")

	if !b.ShouldBypass(req) {
		t.Error("empty Header field should fall back to default")
	}
}

// ---------------------------------------------------------------------------
// Bypass with context helper
// ---------------------------------------------------------------------------

func TestBypass_ShouldBypass_ContextWithoutRequestContext(t *testing.T) {
	b := NewBypass()
	b.Identities["admin"] = true

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req = req.WithContext(context.Background())

	if b.ShouldBypass(req) {
		t.Error("context without RequestContext should not grant identity bypass")
	}
}
