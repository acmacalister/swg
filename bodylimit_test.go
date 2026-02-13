package swg

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDefaultBodyLimitConfig(t *testing.T) {
	cfg := DefaultBodyLimitConfig()

	if cfg.MaxSize != 10*MB {
		t.Errorf("MaxSize = %d, want %d", cfg.MaxSize, 10*MB)
	}

	if !cfg.StreamCheck {
		t.Error("StreamCheck should be true by default")
	}

	expectedSkips := map[string]bool{"GET": true, "HEAD": true, "OPTIONS": true, "TRACE": true}
	for _, m := range cfg.SkipMethods {
		if !expectedSkips[m] {
			t.Errorf("unexpected skip method: %s", m)
		}
	}
}

func TestNewBodyLimiter(t *testing.T) {
	bl := NewBodyLimiter(5 * MB)

	if bl.Config.MaxSize != 5*MB {
		t.Errorf("MaxSize = %d, want %d", bl.Config.MaxSize, 5*MB)
	}
}

func TestBodyLimiter_Check_SkipMethods(t *testing.T) {
	bl := NewBodyLimiter(100)

	skipMethods := []string{"GET", "HEAD", "OPTIONS", "TRACE"}
	for _, method := range skipMethods {
		req := httptest.NewRequest(method, "/", strings.NewReader(strings.Repeat("x", 200)))
		req.ContentLength = 200

		if err := bl.Check(req); err != nil {
			t.Errorf("Check(%s) returned error, expected skip: %v", method, err)
		}
	}
}

func TestBodyLimiter_Check_ContentLength(t *testing.T) {
	bl := NewBodyLimiter(100)

	// Body exceeds limit via Content-Length
	req := httptest.NewRequest("POST", "/", strings.NewReader(strings.Repeat("x", 200)))
	req.ContentLength = 200

	err := bl.Check(req)
	if !errors.Is(err, ErrBodyTooLarge) {
		t.Errorf("Check() = %v, want ErrBodyTooLarge", err)
	}
}

func TestBodyLimiter_Check_StreamingLimit(t *testing.T) {
	bl := NewBodyLimiterWithConfig(BodyLimitConfig{
		MaxSize:     100,
		StreamCheck: false, // Don't check Content-Length, use streaming
		SkipMethods: []string{"GET", "HEAD"},
	})

	body := strings.NewReader(strings.Repeat("x", 200))
	req := httptest.NewRequest("POST", "/", body)
	req.ContentLength = -1 // Unknown content length

	// Check wraps the body
	if err := bl.Check(req); err != nil {
		t.Fatalf("Check() returned error: %v", err)
	}

	// Now try to read all - should fail
	_, err := io.ReadAll(req.Body)
	if !errors.Is(err, ErrBodyTooLarge) {
		t.Errorf("ReadAll() = %v, want ErrBodyTooLarge", err)
	}
}

func TestBodyLimiter_Check_WithinLimit(t *testing.T) {
	bl := NewBodyLimiter(100)

	req := httptest.NewRequest("POST", "/", strings.NewReader("hello"))
	req.ContentLength = 5

	if err := bl.Check(req); err != nil {
		t.Errorf("Check() = %v, want nil", err)
	}
}

func TestBodyLimiter_SetPathLimit(t *testing.T) {
	bl := NewBodyLimiter(100)

	// Set custom limit for /upload
	bl.SetPathLimit("/upload", 10*MB)

	// /upload should have 10MB limit
	if limit := bl.GetPathLimit("/upload"); limit != 10*MB {
		t.Errorf("GetPathLimit(/upload) = %d, want %d", limit, 10*MB)
	}

	// /upload/file should match /upload prefix
	if limit := bl.GetPathLimit("/upload/file"); limit != 10*MB {
		t.Errorf("GetPathLimit(/upload/file) = %d, want %d", limit, 10*MB)
	}

	// /other should use global limit
	if limit := bl.GetPathLimit("/other"); limit != 100 {
		t.Errorf("GetPathLimit(/other) = %d, want 100", limit)
	}

	// Remove the path limit
	bl.SetPathLimit("/upload", -1)
	if limit := bl.GetPathLimit("/upload"); limit != 100 {
		t.Errorf("GetPathLimit(/upload) after removal = %d, want 100", limit)
	}
}

func TestBodyLimiter_SkipPaths(t *testing.T) {
	bl := NewBodyLimiterWithConfig(BodyLimitConfig{
		MaxSize:     100,
		StreamCheck: true,
		SkipPaths:   []string{"/upload", "/api/files"},
		SkipMethods: []string{"GET"},
	})

	tests := []struct {
		path    string
		size    int64
		wantErr bool
	}{
		{"/upload", 200, false},           // skip path
		{"/upload/big", 200, false},       // skip path prefix
		{"/api/files", 200, false},        // skip path
		{"/api/files/large", 200, false},  // skip path prefix
		{"/api/other", 200, true},         // not a skip path
		{"/other", 200, true},             // not a skip path
		{"/other", 50, false},             // within limit
	}

	for _, tt := range tests {
		req := httptest.NewRequest("POST", tt.path, strings.NewReader(strings.Repeat("x", int(tt.size))))
		req.ContentLength = tt.size

		err := bl.Check(req)
		if tt.wantErr && !errors.Is(err, ErrBodyTooLarge) {
			t.Errorf("Check(%s, %d) = %v, want ErrBodyTooLarge", tt.path, tt.size, err)
		}
		if !tt.wantErr && err != nil {
			t.Errorf("Check(%s, %d) = %v, want nil", tt.path, tt.size, err)
		}
	}
}

func TestBodyLimiter_HandleRequest(t *testing.T) {
	bl := NewBodyLimiter(100)

	// Request that exceeds limit
	req := httptest.NewRequest("POST", "/", strings.NewReader(strings.Repeat("x", 200)))
	req.ContentLength = 200

	rc := &RequestContext{}
	resp := bl.HandleRequest(context.Background(), req, rc)

	if resp == nil {
		t.Fatal("HandleRequest() returned nil, want 413 response")
	}

	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("StatusCode = %d, want %d", resp.StatusCode, http.StatusRequestEntityTooLarge)
	}
}

func TestBodyLimiter_HandleRequest_WithinLimit(t *testing.T) {
	bl := NewBodyLimiter(100)

	req := httptest.NewRequest("POST", "/", strings.NewReader("hello"))
	req.ContentLength = 5

	rc := &RequestContext{}
	resp := bl.HandleRequest(context.Background(), req, rc)

	if resp != nil {
		t.Errorf("HandleRequest() = %v, want nil (should pass)", resp)
	}
}

func TestBodyLimiter_Middleware(t *testing.T) {
	bl := NewBodyLimiter(100)

	// Handler that reads the body
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	})

	wrapped := bl.Middleware(handler)

	// Request exceeds limit
	req := httptest.NewRequest("POST", "/", strings.NewReader(strings.Repeat("x", 200)))
	req.ContentLength = 200
	rec := httptest.NewRecorder()

	wrapped.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("StatusCode = %d, want %d", rec.Code, http.StatusRequestEntityTooLarge)
	}
}

func TestBodyLimiter_Middleware_Pass(t *testing.T) {
	bl := NewBodyLimiter(100)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_, _ = w.Write(body)
	})

	wrapped := bl.Middleware(handler)

	req := httptest.NewRequest("POST", "/", strings.NewReader("hello"))
	req.ContentLength = 5
	rec := httptest.NewRecorder()

	wrapped.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("StatusCode = %d, want %d", rec.Code, http.StatusOK)
	}

	if rec.Body.String() != "hello" {
		t.Errorf("Body = %q, want %q", rec.Body.String(), "hello")
	}
}

func TestLimitRequestBody(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrapped := LimitRequestBody(100, handler)

	// Exceeds limit
	req := httptest.NewRequest("POST", "/", strings.NewReader(strings.Repeat("x", 200)))
	req.ContentLength = 200
	rec := httptest.NewRecorder()

	wrapped.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("StatusCode = %d, want %d", rec.Code, http.StatusRequestEntityTooLarge)
	}
}

func TestLimitedReadCloser_ExactLimit(t *testing.T) {
	// Body exactly at limit
	body := strings.NewReader(strings.Repeat("x", 100))
	lrc := &limitedReadCloser{
		ReadCloser: io.NopCloser(body),
		remaining:  100,
		limit:      100,
	}

	data, err := io.ReadAll(lrc)
	if err != nil {
		t.Errorf("ReadAll() error = %v, want nil", err)
	}

	if len(data) != 100 {
		t.Errorf("len(data) = %d, want 100", len(data))
	}
}

func TestLimitedReadCloser_ExceedsLimit(t *testing.T) {
	// Body exceeds limit
	body := strings.NewReader(strings.Repeat("x", 150))
	lrc := &limitedReadCloser{
		ReadCloser: io.NopCloser(body),
		remaining:  100,
		limit:      100,
	}

	_, err := io.ReadAll(lrc)
	if !errors.Is(err, ErrBodyTooLarge) {
		t.Errorf("ReadAll() error = %v, want ErrBodyTooLarge", err)
	}
}

func TestBodyLimiter_ZeroLimit(t *testing.T) {
	bl := NewBodyLimiter(0) // No limit

	req := httptest.NewRequest("POST", "/", strings.NewReader(strings.Repeat("x", 10000)))
	req.ContentLength = 10000

	if err := bl.Check(req); err != nil {
		t.Errorf("Check() with zero limit = %v, want nil", err)
	}
}

func TestBodyLimiter_PathLimitZero(t *testing.T) {
	bl := NewBodyLimiter(100)
	bl.SetPathLimit("/unlimited", 0) // No limit for this path

	req := httptest.NewRequest("POST", "/unlimited", strings.NewReader(strings.Repeat("x", 10000)))
	req.ContentLength = 10000

	if err := bl.Check(req); err != nil {
		t.Errorf("Check(/unlimited) = %v, want nil (unlimited path)", err)
	}
}

func TestHasPathPrefix(t *testing.T) {
	tests := []struct {
		path   string
		prefix string
		want   bool
	}{
		{"/upload", "/upload", true},
		{"/upload/file", "/upload", true},
		{"/upload/file/deep", "/upload", true},
		{"/uploadx", "/upload", false}, // Not a path boundary
		{"/up", "/upload", false},
		{"/other", "/upload", false},
		{"/", "/", true},
		{"/foo", "/", true},
	}

	for _, tt := range tests {
		if got := hasPathPrefix(tt.path, tt.prefix); got != tt.want {
			t.Errorf("hasPathPrefix(%q, %q) = %v, want %v", tt.path, tt.prefix, got, tt.want)
		}
	}
}

func TestBodyLimiter_CustomRejectResponse(t *testing.T) {
	customBody := "Custom error: body too large"
	bl := NewBodyLimiterWithConfig(BodyLimitConfig{
		MaxSize:     100,
		StreamCheck: true,
		SkipMethods: []string{"GET"},
		RejectResponse: &http.Response{
			StatusCode: http.StatusRequestEntityTooLarge,
			Status:     "413 Payload Too Large",
			Header:     http.Header{"Content-Type": []string{"text/plain"}},
			Body:       io.NopCloser(bytes.NewReader([]byte(customBody))),
		},
	})

	req := httptest.NewRequest("POST", "/", strings.NewReader(strings.Repeat("x", 200)))
	req.ContentLength = 200

	rc := &RequestContext{}
	resp := bl.HandleRequest(context.Background(), req, rc)

	if resp == nil {
		t.Fatal("HandleRequest() returned nil, want custom response")
	}

	body, _ := io.ReadAll(resp.Body)
	if string(body) != customBody {
		t.Errorf("response body = %q, want %q", string(body), customBody)
	}
}

func TestSizeConstants(t *testing.T) {
	if KB != 1024 {
		t.Errorf("KB = %d, want 1024", KB)
	}
	if MB != 1024*1024 {
		t.Errorf("MB = %d, want %d", MB, 1024*1024)
	}
	if GB != 1024*1024*1024 {
		t.Errorf("GB = %d, want %d", GB, 1024*1024*1024)
	}
}

func BenchmarkBodyLimiter_Check(b *testing.B) {
	bl := NewBodyLimiter(10 * MB)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("POST", "/api/data", nil)
		req.ContentLength = 1024
		_ = bl.Check(req)
	}
}

func BenchmarkBodyLimiter_WithPathLimits(b *testing.B) {
	bl := NewBodyLimiter(10 * MB)
	bl.SetPathLimit("/upload", 100*MB)
	bl.SetPathLimit("/api/files", 50*MB)
	bl.SetPathLimit("/small", 1*KB)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("POST", "/api/files/upload", nil)
		req.ContentLength = 1024
		_ = bl.Check(req)
	}
}
