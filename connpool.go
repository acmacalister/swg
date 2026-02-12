package swg

import (
	"crypto/tls"
	"net"
	"net/http"
	"sync/atomic"
	"time"
)

// TransportPool provides a configurable HTTP transport with connection
// pooling and optional HTTP/2 support. It wraps [http.Transport] with
// sensible defaults for a forward proxy workload and exposes connection
// pool statistics for monitoring.
type TransportPool struct {
	// MaxIdleConns is the total maximum number of idle connections
	// across all hosts. Zero means the default (100).
	MaxIdleConns int

	// MaxIdleConnsPerHost is the maximum number of idle connections
	// per host. Zero means the default (2 per host).
	MaxIdleConnsPerHost int

	// MaxConnsPerHost limits the total number of connections per host,
	// including connections in the dialing, active, and idle states.
	// Zero means no limit.
	MaxConnsPerHost int

	// IdleConnTimeout is how long an idle connection remains in the
	// pool before being closed. Zero means the default (90 seconds).
	IdleConnTimeout time.Duration

	// DialTimeout is the maximum time to wait for a TCP dial to complete.
	// Zero means the default (30 seconds).
	DialTimeout time.Duration

	// TLSHandshakeTimeout is the maximum time to wait for a TLS
	// handshake. Zero means the default (10 seconds).
	TLSHandshakeTimeout time.Duration

	// ResponseHeaderTimeout is the maximum time to wait for a server's
	// response headers after the request has been fully written.
	// Zero means no timeout.
	ResponseHeaderTimeout time.Duration

	// EnableHTTP2 enables HTTP/2 negotiation with upstream servers.
	// When true, the transport will attempt h2 via ALPN during TLS.
	EnableHTTP2 bool

	// TLSConfig provides custom TLS settings for upstream connections.
	// If nil, a default configuration is used.
	TLSConfig *tls.Config

	// DisableKeepAlives disables HTTP keep-alives; each request will
	// use a fresh connection. This overrides connection pool settings.
	DisableKeepAlives bool

	// WriteBufferSize specifies the size of the write buffer used
	// when writing to the transport. Zero uses the default.
	WriteBufferSize int

	// ReadBufferSize specifies the size of the read buffer used
	// when reading from the transport. Zero uses the default.
	ReadBufferSize int

	transport atomic.Pointer[http.Transport]

	// stats tracks connection pool metrics.
	stats transportStats
}

type transportStats struct {
	totalRequests  atomic.Int64
	activeRequests atomic.Int64
}

// NewTransportPool creates a TransportPool with sensible proxy defaults.
func NewTransportPool() *TransportPool {
	return &TransportPool{
		MaxIdleConns:          200,
		MaxIdleConnsPerHost:   10,
		MaxConnsPerHost:       0,
		IdleConnTimeout:       90 * time.Second,
		DialTimeout:           30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 60 * time.Second,
		EnableHTTP2:           true,
	}
}

// Build creates the underlying [http.Transport]. Call this after setting
// all configuration fields. It is safe to call multiple times; each call
// creates a fresh transport and closes idle connections on the previous one.
func (tp *TransportPool) Build() *http.Transport {
	tlsCfg := tp.TLSConfig
	if tlsCfg == nil {
		tlsCfg = &tls.Config{}
	} else {
		tlsCfg = tlsCfg.Clone()
	}

	if tp.EnableHTTP2 {
		if tlsCfg.NextProtos == nil {
			tlsCfg.NextProtos = []string{"h2", "http/1.1"}
		}
	}

	dialTimeout := tp.DialTimeout
	if dialTimeout == 0 {
		dialTimeout = 30 * time.Second
	}

	t := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   dialTimeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSClientConfig:       tlsCfg,
		MaxIdleConns:          tp.MaxIdleConns,
		MaxIdleConnsPerHost:   tp.MaxIdleConnsPerHost,
		MaxConnsPerHost:       tp.MaxConnsPerHost,
		IdleConnTimeout:       tp.IdleConnTimeout,
		TLSHandshakeTimeout:   tp.TLSHandshakeTimeout,
		ResponseHeaderTimeout: tp.ResponseHeaderTimeout,
		ForceAttemptHTTP2:     tp.EnableHTTP2,
		DisableKeepAlives:     tp.DisableKeepAlives,
		WriteBufferSize:       tp.WriteBufferSize,
		ReadBufferSize:        tp.ReadBufferSize,
	}

	if old := tp.transport.Swap(t); old != nil {
		old.CloseIdleConnections()
	}

	return t
}

// Transport returns an [http.RoundTripper] that wraps the pooled transport
// with request counting. If [Build] has not been called, it is called
// automatically.
func (tp *TransportPool) Transport() http.RoundTripper {
	if tp.transport.Load() == nil {
		tp.Build()
	}
	return &pooledRoundTripper{pool: tp}
}

// CloseIdleConnections closes all idle connections in the pool.
func (tp *TransportPool) CloseIdleConnections() {
	if t := tp.transport.Load(); t != nil {
		t.CloseIdleConnections()
	}
}

// Stats returns a snapshot of transport statistics.
func (tp *TransportPool) Stats() TransportPoolStats {
	return TransportPoolStats{
		TotalRequests:  tp.stats.totalRequests.Load(),
		ActiveRequests: tp.stats.activeRequests.Load(),
	}
}

// TransportPoolStats holds a snapshot of connection pool statistics.
type TransportPoolStats struct {
	TotalRequests  int64
	ActiveRequests int64
}

// pooledRoundTripper wraps the underlying transport with stats tracking.
type pooledRoundTripper struct {
	pool *TransportPool
}

func (rt *pooledRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	rt.pool.stats.totalRequests.Add(1)
	rt.pool.stats.activeRequests.Add(1)
	defer rt.pool.stats.activeRequests.Add(-1)

	t := rt.pool.transport.Load()
	if t == nil {
		t = rt.pool.Build()
	}

	return t.RoundTrip(req)
}
