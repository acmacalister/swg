package swg

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
)

// ExporterType defines the type of trace exporter to use.
type ExporterType string

const (
	// ExporterOTLPHTTP exports traces via OTLP over HTTP.
	ExporterOTLPHTTP ExporterType = "otlp-http"
	// ExporterOTLPGRPC exports traces via OTLP over gRPC.
	ExporterOTLPGRPC ExporterType = "otlp-grpc"
)

// TracingConfig configures OpenTelemetry tracing for the proxy.
type TracingConfig struct {
	// Enabled enables or disables tracing.
	Enabled bool

	// ServiceName is the name of the service reported in traces.
	// Defaults to "swg-proxy".
	ServiceName string

	// ServiceVersion is the version of the service reported in traces.
	ServiceVersion string

	// Exporter specifies which exporter to use.
	// Defaults to ExporterOTLPHTTP.
	Exporter ExporterType

	// Endpoint is the OTLP collector endpoint.
	// For OTLP HTTP: defaults to "localhost:4318"
	// For OTLP gRPC: defaults to "localhost:4317"
	Endpoint string

	// Insecure disables TLS for the exporter connection.
	Insecure bool

	// Headers are additional headers to send with OTLP requests.
	Headers map[string]string

	// SampleRate is the sampling rate (0.0 to 1.0).
	// 1.0 means sample everything, 0.0 means sample nothing.
	// Defaults to 1.0.
	SampleRate float64

	// BatchTimeout is the maximum time to wait before exporting a batch.
	// Defaults to 5 seconds.
	BatchTimeout time.Duration

	// MaxExportBatchSize is the maximum number of spans per batch.
	// Defaults to 512.
	MaxExportBatchSize int

	// MaxQueueSize is the maximum number of spans to queue.
	// Defaults to 2048.
	MaxQueueSize int

	// ResourceAttributes are additional attributes to add to the resource.
	ResourceAttributes map[string]string
}

// DefaultTracingConfig returns a TracingConfig with sensible defaults.
func DefaultTracingConfig() TracingConfig {
	return TracingConfig{
		Enabled:            true,
		ServiceName:        "swg-proxy",
		Exporter:           ExporterOTLPHTTP,
		SampleRate:         1.0,
		BatchTimeout:       5 * time.Second,
		MaxExportBatchSize: 512,
		MaxQueueSize:       2048,
		Insecure:           true,
	}
}

// Tracer provides OpenTelemetry tracing for the proxy.
type Tracer struct {
	provider   *sdktrace.TracerProvider
	tracer     trace.Tracer
	propagator propagation.TextMapPropagator
	config     TracingConfig
}

// NewTracer creates a new Tracer with the given configuration.
func NewTracer(cfg TracingConfig) (*Tracer, error) {
	if !cfg.Enabled {
		return &Tracer{config: cfg}, nil
	}

	// Apply defaults
	if cfg.ServiceName == "" {
		cfg.ServiceName = "swg-proxy"
	}
	if cfg.SampleRate == 0 {
		cfg.SampleRate = 1.0
	}
	if cfg.BatchTimeout == 0 {
		cfg.BatchTimeout = 5 * time.Second
	}
	if cfg.MaxExportBatchSize == 0 {
		cfg.MaxExportBatchSize = 512
	}
	if cfg.MaxQueueSize == 0 {
		cfg.MaxQueueSize = 2048
	}

	ctx := context.Background()

	// Create exporter
	exporter, err := createExporter(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("create exporter: %w", err)
	}

	// Create resource with service info
	res, err := createResource(cfg)
	if err != nil {
		return nil, fmt.Errorf("create resource: %w", err)
	}

	// Create sampler
	var sampler sdktrace.Sampler
	if cfg.SampleRate >= 1.0 {
		sampler = sdktrace.AlwaysSample()
	} else if cfg.SampleRate <= 0 {
		sampler = sdktrace.NeverSample()
	} else {
		sampler = sdktrace.TraceIDRatioBased(cfg.SampleRate)
	}

	// Create trace provider
	provider := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter,
			sdktrace.WithBatchTimeout(cfg.BatchTimeout),
			sdktrace.WithMaxExportBatchSize(cfg.MaxExportBatchSize),
			sdktrace.WithMaxQueueSize(cfg.MaxQueueSize),
		),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sampler),
	)

	// Set global provider and propagator
	otel.SetTracerProvider(provider)
	propagator := propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	)
	otel.SetTextMapPropagator(propagator)

	tracer := provider.Tracer(cfg.ServiceName)

	return &Tracer{
		provider:   provider,
		tracer:     tracer,
		propagator: propagator,
		config:     cfg,
	}, nil
}

// createExporter creates the appropriate span exporter based on config.
func createExporter(ctx context.Context, cfg TracingConfig) (sdktrace.SpanExporter, error) {
	switch cfg.Exporter {
	case ExporterOTLPGRPC:
		endpoint := cfg.Endpoint
		if endpoint == "" {
			endpoint = "localhost:4317"
		}
		opts := []otlptracegrpc.Option{
			otlptracegrpc.WithEndpoint(endpoint),
		}
		if cfg.Insecure {
			opts = append(opts, otlptracegrpc.WithInsecure())
		}
		if len(cfg.Headers) > 0 {
			opts = append(opts, otlptracegrpc.WithHeaders(cfg.Headers))
		}
		return otlptracegrpc.New(ctx, opts...)

	case ExporterOTLPHTTP, "":
		endpoint := cfg.Endpoint
		if endpoint == "" {
			endpoint = "localhost:4318"
		}
		opts := []otlptracehttp.Option{
			otlptracehttp.WithEndpoint(endpoint),
		}
		if cfg.Insecure {
			opts = append(opts, otlptracehttp.WithInsecure())
		}
		if len(cfg.Headers) > 0 {
			opts = append(opts, otlptracehttp.WithHeaders(cfg.Headers))
		}
		return otlptracehttp.New(ctx, opts...)

	default:
		return nil, fmt.Errorf("unknown exporter type: %s", cfg.Exporter)
	}
}

// createResource creates a resource with service attributes.
func createResource(cfg TracingConfig) (*resource.Resource, error) {
	attrs := []attribute.KeyValue{
		semconv.ServiceName(cfg.ServiceName),
	}
	if cfg.ServiceVersion != "" {
		attrs = append(attrs, semconv.ServiceVersion(cfg.ServiceVersion))
	}

	// Add custom resource attributes
	for k, v := range cfg.ResourceAttributes {
		attrs = append(attrs, attribute.String(k, v))
	}

	return resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(semconv.SchemaURL, attrs...),
	)
}

// Shutdown gracefully shuts down the tracer provider.
func (t *Tracer) Shutdown(ctx context.Context) error {
	if t.provider == nil {
		return nil
	}
	return t.provider.Shutdown(ctx)
}

// StartSpan starts a new span with the given name.
func (t *Tracer) StartSpan(ctx context.Context, name string, opts ...trace.SpanStartOption) (context.Context, trace.Span) {
	if t.tracer == nil {
		return ctx, trace.SpanFromContext(ctx)
	}
	return t.tracer.Start(ctx, name, opts...)
}

// SpanFromContext returns the current span from the context.
func (t *Tracer) SpanFromContext(ctx context.Context) trace.Span {
	return trace.SpanFromContext(ctx)
}

// Extract extracts trace context from HTTP headers.
func (t *Tracer) Extract(ctx context.Context, headers http.Header) context.Context {
	if t.propagator == nil {
		return ctx
	}
	return t.propagator.Extract(ctx, propagation.HeaderCarrier(headers))
}

// Inject injects trace context into HTTP headers.
func (t *Tracer) Inject(ctx context.Context, headers http.Header) {
	if t.propagator == nil {
		return
	}
	t.propagator.Inject(ctx, propagation.HeaderCarrier(headers))
}

// TracerProvider returns the underlying TracerProvider.
func (t *Tracer) TracerProvider() *sdktrace.TracerProvider {
	return t.provider
}

// Enabled returns whether tracing is enabled.
func (t *Tracer) Enabled() bool {
	return t.config.Enabled && t.tracer != nil
}

// TracingMiddleware wraps an http.Handler with tracing.
type TracingMiddleware struct {
	tracer  *Tracer
	next    http.Handler
	options TracingMiddlewareOptions
}

// TracingMiddlewareOptions configures the tracing middleware.
type TracingMiddlewareOptions struct {
	// IncludeHeaders includes request/response headers in span attributes.
	IncludeHeaders bool

	// HeadersToCapture specifies which headers to capture (if IncludeHeaders is true).
	// If empty, captures all headers.
	HeadersToCapture []string

	// IncludeQuery includes the query string in span attributes.
	IncludeQuery bool

	// SkipPaths are URL paths to skip tracing for.
	SkipPaths []string
}

// NewTracingMiddleware creates a new tracing middleware.
func NewTracingMiddleware(tracer *Tracer, next http.Handler, opts TracingMiddlewareOptions) *TracingMiddleware {
	return &TracingMiddleware{
		tracer:  tracer,
		next:    next,
		options: opts,
	}
}

// ServeHTTP implements http.Handler.
func (m *TracingMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Skip if tracing disabled or path should be skipped
	if !m.tracer.Enabled() || m.shouldSkip(r.URL.Path) {
		m.next.ServeHTTP(w, r)
		return
	}

	// Extract trace context from incoming request
	ctx := m.tracer.Extract(r.Context(), r.Header)

	// Start span for this request
	spanName := fmt.Sprintf("%s %s", r.Method, r.URL.Path)
	ctx, span := m.tracer.StartSpan(ctx, spanName,
		trace.WithSpanKind(trace.SpanKindServer),
	)
	defer span.End()

	// Add standard HTTP attributes
	span.SetAttributes(
		semconv.HTTPRequestMethodKey.String(r.Method),
		semconv.URLScheme(r.URL.Scheme),
		semconv.URLPath(r.URL.Path),
		semconv.ServerAddress(r.Host),
		semconv.UserAgentOriginal(r.UserAgent()),
		semconv.NetworkPeerAddress(r.RemoteAddr),
	)

	if m.options.IncludeQuery && r.URL.RawQuery != "" {
		span.SetAttributes(semconv.URLQuery(r.URL.RawQuery))
	}

	// Capture request headers
	if m.options.IncludeHeaders {
		m.captureHeaders(span, "http.request.header.", r.Header)
	}

	// Wrap response writer to capture status code
	wrapped := &tracingResponseWriter{ResponseWriter: w, statusCode: http.StatusOK}

	// Process request
	m.next.ServeHTTP(wrapped, r.WithContext(ctx))

	// Add response attributes
	span.SetAttributes(semconv.HTTPResponseStatusCode(wrapped.statusCode))

	// Set span status based on HTTP status code
	if wrapped.statusCode >= 400 {
		span.SetStatus(codes.Error, http.StatusText(wrapped.statusCode))
	} else {
		span.SetStatus(codes.Ok, "")
	}
}

// shouldSkip returns true if the path should skip tracing.
func (m *TracingMiddleware) shouldSkip(path string) bool {
	for _, skip := range m.options.SkipPaths {
		if path == skip {
			return true
		}
	}
	return false
}

// captureHeaders adds headers as span attributes.
func (m *TracingMiddleware) captureHeaders(span trace.Span, prefix string, headers http.Header) {
	if len(m.options.HeadersToCapture) > 0 {
		// Only capture specified headers
		for _, name := range m.options.HeadersToCapture {
			if values := headers.Values(name); len(values) > 0 {
				span.SetAttributes(attribute.StringSlice(prefix+name, values))
			}
		}
	} else {
		// Capture all headers
		for name, values := range headers {
			span.SetAttributes(attribute.StringSlice(prefix+name, values))
		}
	}
}

// tracingResponseWriter wraps http.ResponseWriter to capture the status code.
type tracingResponseWriter struct {
	http.ResponseWriter
	statusCode int
	written    bool
}

// WriteHeader captures the status code.
func (w *tracingResponseWriter) WriteHeader(code int) {
	if !w.written {
		w.statusCode = code
		w.written = true
	}
	w.ResponseWriter.WriteHeader(code)
}

// Write implements io.Writer.
func (w *tracingResponseWriter) Write(b []byte) (int, error) {
	if !w.written {
		w.statusCode = http.StatusOK
		w.written = true
	}
	return w.ResponseWriter.Write(b)
}

// ProxyTracer provides tracing specifically for proxy operations.
type ProxyTracer struct {
	tracer *Tracer
}

// NewProxyTracer creates a ProxyTracer wrapping a Tracer.
func NewProxyTracer(t *Tracer) *ProxyTracer {
	return &ProxyTracer{tracer: t}
}

// Enabled returns whether tracing is enabled.
func (pt *ProxyTracer) Enabled() bool {
	return pt.tracer != nil && pt.tracer.Enabled()
}

// StartRequest starts a span for an incoming proxy request.
func (pt *ProxyTracer) StartRequest(ctx context.Context, r *http.Request) (context.Context, trace.Span) {
	if !pt.Enabled() {
		return ctx, trace.SpanFromContext(ctx)
	}

	// Extract trace context from incoming request
	ctx = pt.tracer.Extract(ctx, r.Header)

	spanName := fmt.Sprintf("proxy %s %s", r.Method, r.Host)
	ctx, span := pt.tracer.StartSpan(ctx, spanName,
		trace.WithSpanKind(trace.SpanKindServer),
		trace.WithAttributes(
			semconv.HTTPRequestMethodKey.String(r.Method),
			attribute.String("proxy.target.host", r.Host),
			attribute.String("proxy.target.path", r.URL.Path),
			semconv.NetworkPeerAddress(r.RemoteAddr),
		),
	)

	return ctx, span
}

// StartConnect starts a span for a CONNECT tunnel establishment.
func (pt *ProxyTracer) StartConnect(ctx context.Context, host string, clientAddr string) (context.Context, trace.Span) {
	if !pt.Enabled() {
		return ctx, trace.SpanFromContext(ctx)
	}

	ctx, span := pt.tracer.StartSpan(ctx, "proxy CONNECT "+host,
		trace.WithSpanKind(trace.SpanKindServer),
		trace.WithAttributes(
			attribute.String("proxy.connect.host", host),
			semconv.NetworkPeerAddress(clientAddr),
		),
	)

	return ctx, span
}

// StartTLSHandshake starts a span for TLS handshake with client.
func (pt *ProxyTracer) StartTLSHandshake(ctx context.Context, host string) (context.Context, trace.Span) {
	if !pt.Enabled() {
		return ctx, trace.SpanFromContext(ctx)
	}

	return pt.tracer.StartSpan(ctx, "tls.handshake.client",
		trace.WithAttributes(
			attribute.String("tls.server_name", host),
		),
	)
}

// StartCertGeneration starts a span for certificate generation.
func (pt *ProxyTracer) StartCertGeneration(ctx context.Context, host string) (context.Context, trace.Span) {
	if !pt.Enabled() {
		return ctx, trace.SpanFromContext(ctx)
	}

	return pt.tracer.StartSpan(ctx, "cert.generate",
		trace.WithAttributes(
			attribute.String("cert.host", host),
		),
	)
}

// StartFilter starts a span for filter evaluation.
func (pt *ProxyTracer) StartFilter(ctx context.Context, host string) (context.Context, trace.Span) {
	if !pt.Enabled() {
		return ctx, trace.SpanFromContext(ctx)
	}

	return pt.tracer.StartSpan(ctx, "filter.evaluate",
		trace.WithAttributes(
			attribute.String("filter.host", host),
		),
	)
}

// StartUpstream starts a span for upstream request.
func (pt *ProxyTracer) StartUpstream(ctx context.Context, r *http.Request) (context.Context, trace.Span) {
	if !pt.Enabled() {
		return ctx, trace.SpanFromContext(ctx)
	}

	ctx, span := pt.tracer.StartSpan(ctx, fmt.Sprintf("upstream %s %s", r.Method, r.Host),
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(
			semconv.HTTPRequestMethodKey.String(r.Method),
			semconv.ServerAddress(r.Host),
			semconv.URLPath(r.URL.Path),
		),
	)

	// Inject trace context into outgoing request
	pt.tracer.Inject(ctx, r.Header)

	return ctx, span
}

// StartBodyScan starts a span for response body scanning.
func (pt *ProxyTracer) StartBodyScan(ctx context.Context, contentType string, size int64) (context.Context, trace.Span) {
	if !pt.Enabled() {
		return ctx, trace.SpanFromContext(ctx)
	}

	return pt.tracer.StartSpan(ctx, "body.scan",
		trace.WithAttributes(
			attribute.String("body.content_type", contentType),
			attribute.Int64("body.size", size),
		),
	)
}

// RecordError records an error on the current span.
func (pt *ProxyTracer) RecordError(ctx context.Context, err error) {
	if !pt.Enabled() {
		return
	}
	span := trace.SpanFromContext(ctx)
	span.RecordError(err)
	span.SetStatus(codes.Error, err.Error())
}

// SetBlocked marks the request as blocked by the filter.
func (pt *ProxyTracer) SetBlocked(ctx context.Context, reason string) {
	if !pt.Enabled() {
		return
	}
	span := trace.SpanFromContext(ctx)
	span.SetAttributes(
		attribute.Bool("proxy.blocked", true),
		attribute.String("proxy.block_reason", reason),
	)
}

// SetAllowed marks the request as allowed through the filter.
func (pt *ProxyTracer) SetAllowed(ctx context.Context) {
	if !pt.Enabled() {
		return
	}
	span := trace.SpanFromContext(ctx)
	span.SetAttributes(attribute.Bool("proxy.blocked", false))
}

// SetIdentity sets identity information on the span.
func (pt *ProxyTracer) SetIdentity(ctx context.Context, identity string, groups []string) {
	if !pt.Enabled() {
		return
	}
	span := trace.SpanFromContext(ctx)
	span.SetAttributes(
		attribute.String("proxy.identity", identity),
		attribute.StringSlice("proxy.groups", groups),
	)
}

// SetUpstreamResponse records upstream response details.
func (pt *ProxyTracer) SetUpstreamResponse(ctx context.Context, statusCode int, contentLength int64) {
	if !pt.Enabled() {
		return
	}
	span := trace.SpanFromContext(ctx)
	span.SetAttributes(
		semconv.HTTPResponseStatusCode(statusCode),
		attribute.Int64("http.response.body.size", contentLength),
	)
}

// AddEvent adds an event to the current span.
func (pt *ProxyTracer) AddEvent(ctx context.Context, name string, attrs ...attribute.KeyValue) {
	if !pt.Enabled() {
		return
	}
	span := trace.SpanFromContext(ctx)
	span.AddEvent(name, trace.WithAttributes(attrs...))
}
