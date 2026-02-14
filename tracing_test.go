package swg

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"go.opentelemetry.io/otel/trace"
)

func TestDefaultTracingConfig(t *testing.T) {
	cfg := DefaultTracingConfig()

	if !cfg.Enabled {
		t.Error("default config should be enabled")
	}
	if cfg.ServiceName != "swg-proxy" {
		t.Errorf("expected service name 'swg-proxy', got %q", cfg.ServiceName)
	}
	if cfg.Exporter != ExporterOTLPHTTP {
		t.Errorf("expected exporter OTLP HTTP, got %q", cfg.Exporter)
	}
	if cfg.SampleRate != 1.0 {
		t.Errorf("expected sample rate 1.0, got %f", cfg.SampleRate)
	}
	if cfg.BatchTimeout != 5*time.Second {
		t.Errorf("expected batch timeout 5s, got %v", cfg.BatchTimeout)
	}
	if cfg.MaxExportBatchSize != 512 {
		t.Errorf("expected max export batch size 512, got %d", cfg.MaxExportBatchSize)
	}
	if cfg.MaxQueueSize != 2048 {
		t.Errorf("expected max queue size 2048, got %d", cfg.MaxQueueSize)
	}
}

func TestNewTracer_Disabled(t *testing.T) {
	cfg := TracingConfig{Enabled: false}
	tracer, err := NewTracer(cfg)
	if err != nil {
		t.Fatalf("NewTracer() error: %v", err)
	}
	defer func() {
		if err := tracer.Shutdown(context.Background()); err != nil {
			t.Errorf("Shutdown error: %v", err)
		}
	}()

	if tracer.Enabled() {
		t.Error("tracer should be disabled")
	}
	if tracer.TracerProvider() != nil {
		t.Error("provider should be nil when disabled")
	}

	// StartSpan should return the same context when disabled
	ctx := context.Background()
	newCtx, span := tracer.StartSpan(ctx, "test")
	if newCtx != ctx {
		t.Error("context should be unchanged when disabled")
	}
	// Span should be a no-op span
	span.End()
}

func TestNewTracer_InvalidExporter(t *testing.T) {
	cfg := TracingConfig{
		Enabled:  true,
		Exporter: ExporterType("invalid"),
	}
	_, err := NewTracer(cfg)
	if err == nil {
		t.Error("expected error for invalid exporter")
	}
}

func TestNewTracer_AppliesDefaults(t *testing.T) {
	// Use a disabled config to avoid actually connecting
	cfg := TracingConfig{Enabled: false}
	tracer, err := NewTracer(cfg)
	if err != nil {
		t.Fatalf("NewTracer() error: %v", err)
	}
	defer func() {
		if err := tracer.Shutdown(context.Background()); err != nil {
			t.Errorf("Shutdown error: %v", err)
		}
	}()

	// Even disabled tracer should work without panicking
	ctx := context.Background()
	_, span := tracer.StartSpan(ctx, "test")
	span.End()
}

func TestTracer_ExtractInject(t *testing.T) {
	// Test with disabled tracer - should not panic
	tracer := &Tracer{}

	ctx := context.Background()
	headers := http.Header{}
	headers.Set("traceparent", "00-12345678901234567890123456789012-1234567890123456-01")

	// Extract should return context unchanged when disabled
	newCtx := tracer.Extract(ctx, headers)
	if newCtx != ctx {
		t.Error("Extract should return same context when disabled")
	}

	// Inject should not panic when disabled
	tracer.Inject(ctx, headers)
}

func TestTracingMiddleware_Disabled(t *testing.T) {
	tracer := &Tracer{} // disabled tracer

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middleware := NewTracingMiddleware(tracer, handler, TracingMiddlewareOptions{})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()

	middleware.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
}

func TestTracingMiddleware_SkipPaths(t *testing.T) {
	tracer := &Tracer{} // disabled for this test

	called := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	middleware := NewTracingMiddleware(tracer, handler, TracingMiddlewareOptions{
		SkipPaths: []string{"/health", "/metrics"},
	})

	tests := []struct {
		path     string
		expected bool
	}{
		{"/health", true},
		{"/metrics", true},
		{"/api/v1", true},
	}

	for _, tt := range tests {
		called = false
		req := httptest.NewRequest(http.MethodGet, tt.path, nil)
		rec := httptest.NewRecorder()

		middleware.ServeHTTP(rec, req)

		if called != tt.expected {
			t.Errorf("path %s: expected called=%v, got %v", tt.path, tt.expected, called)
		}
	}
}

func TestTracingMiddleware_CapturesStatusCode(t *testing.T) {
	tracer := &Tracer{} // disabled

	tests := []struct {
		name       string
		statusCode int
	}{
		{"OK", http.StatusOK},
		{"Created", http.StatusCreated},
		{"BadRequest", http.StatusBadRequest},
		{"NotFound", http.StatusNotFound},
		{"InternalError", http.StatusInternalServerError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
			})

			middleware := NewTracingMiddleware(tracer, handler, TracingMiddlewareOptions{})

			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			rec := httptest.NewRecorder()

			middleware.ServeHTTP(rec, req)

			if rec.Code != tt.statusCode {
				t.Errorf("expected status %d, got %d", tt.statusCode, rec.Code)
			}
		})
	}
}

func TestTracingResponseWriter(t *testing.T) {
	rec := httptest.NewRecorder()
	wrapped := &tracingResponseWriter{ResponseWriter: rec, statusCode: http.StatusOK}

	// Test WriteHeader
	wrapped.WriteHeader(http.StatusCreated)
	if wrapped.statusCode != http.StatusCreated {
		t.Errorf("expected status %d, got %d", http.StatusCreated, wrapped.statusCode)
	}

	// Test WriteHeader is only captured once
	wrapped.WriteHeader(http.StatusBadRequest)
	if wrapped.statusCode != http.StatusCreated {
		t.Errorf("status should not change after first WriteHeader, got %d", wrapped.statusCode)
	}
}

func TestTracingResponseWriter_Write(t *testing.T) {
	rec := httptest.NewRecorder()
	wrapped := &tracingResponseWriter{ResponseWriter: rec, statusCode: http.StatusOK}

	// Write without WriteHeader should set status to 200
	n, err := wrapped.Write([]byte("test"))
	if err != nil {
		t.Fatalf("Write error: %v", err)
	}
	if n != 4 {
		t.Errorf("expected 4 bytes written, got %d", n)
	}
	if wrapped.statusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", wrapped.statusCode)
	}
	if !wrapped.written {
		t.Error("written should be true")
	}
}

func TestNewProxyTracer(t *testing.T) {
	tracer := &Tracer{}
	pt := NewProxyTracer(tracer)

	if pt.tracer != tracer {
		t.Error("tracer not set correctly")
	}
}

func TestProxyTracer_Enabled(t *testing.T) {
	tests := []struct {
		name     string
		tracer   *ProxyTracer
		expected bool
	}{
		{"nil tracer", &ProxyTracer{tracer: nil}, false},
		{"disabled tracer", &ProxyTracer{tracer: &Tracer{}}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.tracer.Enabled(); got != tt.expected {
				t.Errorf("Enabled() = %v, expected %v", got, tt.expected)
			}
		})
	}
}

func TestProxyTracer_StartRequest_Disabled(t *testing.T) {
	pt := NewProxyTracer(&Tracer{})
	ctx := context.Background()
	req := httptest.NewRequest(http.MethodGet, "https://example.com/path", nil)

	newCtx, span := pt.StartRequest(ctx, req)
	defer span.End()

	if newCtx != ctx {
		t.Error("context should be unchanged when disabled")
	}
}

func TestProxyTracer_StartConnect_Disabled(t *testing.T) {
	pt := NewProxyTracer(&Tracer{})
	ctx := context.Background()

	newCtx, span := pt.StartConnect(ctx, "example.com:443", "192.168.1.1:12345")
	defer span.End()

	if newCtx != ctx {
		t.Error("context should be unchanged when disabled")
	}
}

func TestProxyTracer_StartTLSHandshake_Disabled(t *testing.T) {
	pt := NewProxyTracer(&Tracer{})
	ctx := context.Background()

	newCtx, span := pt.StartTLSHandshake(ctx, "example.com")
	defer span.End()

	if newCtx != ctx {
		t.Error("context should be unchanged when disabled")
	}
}

func TestProxyTracer_StartCertGeneration_Disabled(t *testing.T) {
	pt := NewProxyTracer(&Tracer{})
	ctx := context.Background()

	newCtx, span := pt.StartCertGeneration(ctx, "example.com")
	defer span.End()

	if newCtx != ctx {
		t.Error("context should be unchanged when disabled")
	}
}

func TestProxyTracer_StartFilter_Disabled(t *testing.T) {
	pt := NewProxyTracer(&Tracer{})
	ctx := context.Background()

	newCtx, span := pt.StartFilter(ctx, "example.com")
	defer span.End()

	if newCtx != ctx {
		t.Error("context should be unchanged when disabled")
	}
}

func TestProxyTracer_StartUpstream_Disabled(t *testing.T) {
	pt := NewProxyTracer(&Tracer{})
	ctx := context.Background()
	req := httptest.NewRequest(http.MethodGet, "https://example.com/path", nil)

	newCtx, span := pt.StartUpstream(ctx, req)
	defer span.End()

	if newCtx != ctx {
		t.Error("context should be unchanged when disabled")
	}
}

func TestProxyTracer_StartBodyScan_Disabled(t *testing.T) {
	pt := NewProxyTracer(&Tracer{})
	ctx := context.Background()

	newCtx, span := pt.StartBodyScan(ctx, "application/json", 1024)
	defer span.End()

	if newCtx != ctx {
		t.Error("context should be unchanged when disabled")
	}
}

func TestProxyTracer_RecordError_Disabled(t *testing.T) {
	pt := NewProxyTracer(&Tracer{})
	ctx := context.Background()

	// Should not panic
	pt.RecordError(ctx, context.DeadlineExceeded)
}

func TestProxyTracer_SetBlocked_Disabled(t *testing.T) {
	pt := NewProxyTracer(&Tracer{})
	ctx := context.Background()

	// Should not panic
	pt.SetBlocked(ctx, "blocked for testing")
}

func TestProxyTracer_SetAllowed_Disabled(t *testing.T) {
	pt := NewProxyTracer(&Tracer{})
	ctx := context.Background()

	// Should not panic
	pt.SetAllowed(ctx)
}

func TestProxyTracer_SetIdentity_Disabled(t *testing.T) {
	pt := NewProxyTracer(&Tracer{})
	ctx := context.Background()

	// Should not panic
	pt.SetIdentity(ctx, "user@example.com", []string{"admin", "users"})
}

func TestProxyTracer_SetUpstreamResponse_Disabled(t *testing.T) {
	pt := NewProxyTracer(&Tracer{})
	ctx := context.Background()

	// Should not panic
	pt.SetUpstreamResponse(ctx, 200, 4096)
}

func TestProxyTracer_AddEvent_Disabled(t *testing.T) {
	pt := NewProxyTracer(&Tracer{})
	ctx := context.Background()

	// Should not panic
	pt.AddEvent(ctx, "test event")
}

func TestExporterTypes(t *testing.T) {
	if ExporterOTLPHTTP != "otlp-http" {
		t.Errorf("expected 'otlp-http', got %q", ExporterOTLPHTTP)
	}
	if ExporterOTLPGRPC != "otlp-grpc" {
		t.Errorf("expected 'otlp-grpc', got %q", ExporterOTLPGRPC)
	}
}

func TestTracer_SpanFromContext(t *testing.T) {
	tracer := &Tracer{}
	ctx := context.Background()

	span := tracer.SpanFromContext(ctx)
	// Should return a no-op span from empty context
	if span == nil {
		t.Error("SpanFromContext should never return nil")
	}
}

func TestTracingMiddlewareOptions(t *testing.T) {
	opts := TracingMiddlewareOptions{
		IncludeHeaders:   true,
		HeadersToCapture: []string{"X-Request-ID", "Authorization"},
		IncludeQuery:     true,
		SkipPaths:        []string{"/health", "/metrics"},
	}

	if !opts.IncludeHeaders {
		t.Error("IncludeHeaders should be true")
	}
	if len(opts.HeadersToCapture) != 2 {
		t.Errorf("expected 2 headers to capture, got %d", len(opts.HeadersToCapture))
	}
	if !opts.IncludeQuery {
		t.Error("IncludeQuery should be true")
	}
	if len(opts.SkipPaths) != 2 {
		t.Errorf("expected 2 skip paths, got %d", len(opts.SkipPaths))
	}
}

func TestTracingMiddleware_CaptureHeaders(t *testing.T) {
	tracer := &Tracer{} // disabled

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middleware := NewTracingMiddleware(tracer, handler, TracingMiddlewareOptions{
		IncludeHeaders:   true,
		HeadersToCapture: []string{"X-Request-ID"},
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("X-Request-ID", "test-123")
	rec := httptest.NewRecorder()

	middleware.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
}

func TestTracingConfig_ResourceAttributes(t *testing.T) {
	cfg := TracingConfig{
		Enabled:     false,
		ServiceName: "test-service",
		ResourceAttributes: map[string]string{
			"deployment.environment": "production",
			"service.namespace":      "swg",
		},
	}

	if len(cfg.ResourceAttributes) != 2 {
		t.Errorf("expected 2 resource attributes, got %d", len(cfg.ResourceAttributes))
	}
	if cfg.ResourceAttributes["deployment.environment"] != "production" {
		t.Error("deployment.environment attribute incorrect")
	}
}

func TestTracingConfig_Headers(t *testing.T) {
	cfg := TracingConfig{
		Enabled:  false,
		Exporter: ExporterOTLPHTTP,
		Headers: map[string]string{
			"Authorization": "Bearer token123",
			"X-Custom":      "value",
		},
	}

	if len(cfg.Headers) != 2 {
		t.Errorf("expected 2 headers, got %d", len(cfg.Headers))
	}
}

func TestProxyTracer_NilTracer(t *testing.T) {
	pt := &ProxyTracer{tracer: nil}

	if pt.Enabled() {
		t.Error("should not be enabled with nil tracer")
	}

	ctx := context.Background()

	// All methods should handle nil gracefully
	pt.RecordError(ctx, context.Canceled)
	pt.SetBlocked(ctx, "reason")
	pt.SetAllowed(ctx)
	pt.SetIdentity(ctx, "id", nil)
	pt.SetUpstreamResponse(ctx, 200, 0)
	pt.AddEvent(ctx, "event")

	req := httptest.NewRequest(http.MethodGet, "/", nil)

	newCtx, span := pt.StartRequest(ctx, req)
	span.End()
	if newCtx != ctx {
		t.Error("context should be unchanged")
	}

	newCtx, span = pt.StartConnect(ctx, "host", "addr")
	span.End()
	if newCtx != ctx {
		t.Error("context should be unchanged")
	}

	newCtx, span = pt.StartTLSHandshake(ctx, "host")
	span.End()
	if newCtx != ctx {
		t.Error("context should be unchanged")
	}

	newCtx, span = pt.StartCertGeneration(ctx, "host")
	span.End()
	if newCtx != ctx {
		t.Error("context should be unchanged")
	}

	newCtx, span = pt.StartFilter(ctx, "host")
	span.End()
	if newCtx != ctx {
		t.Error("context should be unchanged")
	}

	newCtx, span = pt.StartUpstream(ctx, req)
	span.End()
	if newCtx != ctx {
		t.Error("context should be unchanged")
	}

	newCtx, span = pt.StartBodyScan(ctx, "text/html", 100)
	span.End()
	if newCtx != ctx {
		t.Error("context should be unchanged")
	}
}

// TestTracer_IntegrationDisabled tests that all tracer methods work when disabled
func TestTracer_IntegrationDisabled(t *testing.T) {
	cfg := TracingConfig{Enabled: false}
	tracer, err := NewTracer(cfg)
	if err != nil {
		t.Fatalf("NewTracer() error: %v", err)
	}
	defer func() {
		if err := tracer.Shutdown(context.Background()); err != nil {
			t.Errorf("Shutdown error: %v", err)
		}
	}()

	ctx := context.Background()

	// All operations should be no-ops
	ctx, span := tracer.StartSpan(ctx, "test-span")
	span.End()

	span = tracer.SpanFromContext(ctx)
	if span == nil {
		t.Error("SpanFromContext should never return nil")
	}

	headers := http.Header{}
	tracer.Inject(ctx, headers)
	_ = tracer.Extract(ctx, headers)
}

// TestTracingMiddleware_shouldSkip tests the path skipping logic
func TestTracingMiddleware_shouldSkip(t *testing.T) {
	middleware := &TracingMiddleware{
		options: TracingMiddlewareOptions{
			SkipPaths: []string{"/health", "/metrics", "/ready"},
		},
	}

	tests := []struct {
		path     string
		expected bool
	}{
		{"/health", true},
		{"/metrics", true},
		{"/ready", true},
		{"/api/v1", false},
		{"/healthz", false},
		{"/health/deep", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			if got := middleware.shouldSkip(tt.path); got != tt.expected {
				t.Errorf("shouldSkip(%q) = %v, want %v", tt.path, got, tt.expected)
			}
		})
	}
}

// BenchmarkTracingMiddleware_Disabled benchmarks middleware when tracing is disabled
func BenchmarkTracingMiddleware_Disabled(b *testing.B) {
	tracer := &Tracer{}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	middleware := NewTracingMiddleware(tracer, handler, TracingMiddlewareOptions{})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rec := httptest.NewRecorder()
		middleware.ServeHTTP(rec, req)
	}
}

// BenchmarkProxyTracer_StartRequest_Disabled benchmarks disabled proxy tracer
func BenchmarkProxyTracer_StartRequest_Disabled(b *testing.B) {
	pt := NewProxyTracer(&Tracer{})
	ctx := context.Background()
	req := httptest.NewRequest(http.MethodGet, "https://example.com/path", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, span := pt.StartRequest(ctx, req)
		span.End()
	}
}

// TestSpanInterface verifies that returned spans implement the trace.Span interface
func TestSpanInterface(t *testing.T) {
	pt := NewProxyTracer(&Tracer{})
	ctx := context.Background()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	_, span := pt.StartRequest(ctx, req)
	defer span.End()

	// Verify span implements trace.Span (compile-time check)
	_ = trace.Span(span)
}
