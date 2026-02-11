package swg

import (
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics holds all Prometheus metrics for the proxy.
type Metrics struct {
	requestsTotal    *prometheus.CounterVec
	requestsBlocked  *prometheus.CounterVec
	requestDuration  *prometheus.HistogramVec
	activeConns      prometheus.Gauge
	certCacheSize    prometheus.Gauge
	certCacheHits    prometheus.Counter
	certCacheMisses  prometheus.Counter
	filterRuleCount  prometheus.Gauge
	filterReloads    prometheus.Counter
	filterReloadErrs prometheus.Counter
	upstreamErrors   *prometheus.CounterVec
	tlsHandshakeErrs prometheus.Counter

	registry *prometheus.Registry
}

// NewMetrics creates a new Metrics instance with all collectors registered.
func NewMetrics() *Metrics {
	reg := prometheus.NewRegistry()
	reg.MustRegister(collectors.NewGoCollector())
	reg.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))

	m := &Metrics{
		requestsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "swg",
			Name:      "requests_total",
			Help:      "Total number of requests processed.",
		}, []string{"method", "scheme"}),

		requestsBlocked: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "swg",
			Name:      "requests_blocked_total",
			Help:      "Total number of requests blocked by filter.",
		}, []string{"reason"}),

		requestDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: "swg",
			Name:      "request_duration_seconds",
			Help:      "Request duration in seconds.",
			Buckets:   []float64{.001, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10},
		}, []string{"method", "status"}),

		activeConns: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "swg",
			Name:      "active_connections",
			Help:      "Number of active proxy connections.",
		}),

		certCacheSize: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "swg",
			Name:      "cert_cache_size",
			Help:      "Number of cached TLS certificates.",
		}),

		certCacheHits: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "swg",
			Name:      "cert_cache_hits_total",
			Help:      "Number of certificate cache hits.",
		}),

		certCacheMisses: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "swg",
			Name:      "cert_cache_misses_total",
			Help:      "Number of certificate cache misses.",
		}),

		filterRuleCount: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "swg",
			Name:      "filter_rule_count",
			Help:      "Number of active filter rules.",
		}),

		filterReloads: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "swg",
			Name:      "filter_reloads_total",
			Help:      "Number of successful filter reloads.",
		}),

		filterReloadErrs: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "swg",
			Name:      "filter_reload_errors_total",
			Help:      "Number of failed filter reloads.",
		}),

		upstreamErrors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "swg",
			Name:      "upstream_errors_total",
			Help:      "Number of upstream connection errors.",
		}, []string{"host"}),

		tlsHandshakeErrs: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "swg",
			Name:      "tls_handshake_errors_total",
			Help:      "Number of TLS handshake failures with clients.",
		}),

		registry: reg,
	}

	reg.MustRegister(
		m.requestsTotal,
		m.requestsBlocked,
		m.requestDuration,
		m.activeConns,
		m.certCacheSize,
		m.certCacheHits,
		m.certCacheMisses,
		m.filterRuleCount,
		m.filterReloads,
		m.filterReloadErrs,
		m.upstreamErrors,
		m.tlsHandshakeErrs,
	)

	return m
}

// Handler returns an http.Handler that serves the /metrics endpoint.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
}

// RecordRequest records a processed request.
func (m *Metrics) RecordRequest(method, scheme string) {
	m.requestsTotal.WithLabelValues(method, scheme).Inc()
}

// RecordBlocked records a blocked request.
func (m *Metrics) RecordBlocked(reason string) {
	m.requestsBlocked.WithLabelValues(reason).Inc()
}

// RecordRequestDuration records the duration of a request.
func (m *Metrics) RecordRequestDuration(method string, statusCode int, duration time.Duration) {
	m.requestDuration.WithLabelValues(method, strconv.Itoa(statusCode)).Observe(duration.Seconds())
}

// IncActiveConns increments the active connection gauge.
func (m *Metrics) IncActiveConns() {
	m.activeConns.Inc()
}

// DecActiveConns decrements the active connection gauge.
func (m *Metrics) DecActiveConns() {
	m.activeConns.Dec()
}

// SetCertCacheSize sets the certificate cache size gauge.
func (m *Metrics) SetCertCacheSize(size int) {
	m.certCacheSize.Set(float64(size))
}

// RecordCertCacheHit records a certificate cache hit.
func (m *Metrics) RecordCertCacheHit() {
	m.certCacheHits.Inc()
}

// RecordCertCacheMiss records a certificate cache miss.
func (m *Metrics) RecordCertCacheMiss() {
	m.certCacheMisses.Inc()
}

// SetFilterRuleCount sets the current filter rule count.
func (m *Metrics) SetFilterRuleCount(count int) {
	m.filterRuleCount.Set(float64(count))
}

// RecordFilterReload records a successful filter reload.
func (m *Metrics) RecordFilterReload() {
	m.filterReloads.Inc()
}

// RecordFilterReloadError records a failed filter reload.
func (m *Metrics) RecordFilterReloadError() {
	m.filterReloadErrs.Inc()
}

// RecordUpstreamError records an upstream connection error.
func (m *Metrics) RecordUpstreamError(host string) {
	m.upstreamErrors.WithLabelValues(host).Inc()
}

// RecordTLSHandshakeError records a TLS handshake failure.
func (m *Metrics) RecordTLSHandshakeError() {
	m.tlsHandshakeErrs.Inc()
}
