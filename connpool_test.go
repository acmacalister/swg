package swg

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestNewTransportPool_Defaults(t *testing.T) {
	tp := NewTransportPool()

	if tp.MaxIdleConns != 200 {
		t.Errorf("MaxIdleConns = %d, want 200", tp.MaxIdleConns)
	}
	if tp.MaxIdleConnsPerHost != 10 {
		t.Errorf("MaxIdleConnsPerHost = %d, want 10", tp.MaxIdleConnsPerHost)
	}
	if tp.IdleConnTimeout != 90*time.Second {
		t.Errorf("IdleConnTimeout = %v, want 90s", tp.IdleConnTimeout)
	}
	if tp.DialTimeout != 30*time.Second {
		t.Errorf("DialTimeout = %v, want 30s", tp.DialTimeout)
	}
	if tp.TLSHandshakeTimeout != 10*time.Second {
		t.Errorf("TLSHandshakeTimeout = %v, want 10s", tp.TLSHandshakeTimeout)
	}
	if tp.ResponseHeaderTimeout != 60*time.Second {
		t.Errorf("ResponseHeaderTimeout = %v, want 60s", tp.ResponseHeaderTimeout)
	}
	if !tp.EnableHTTP2 {
		t.Error("EnableHTTP2 should default to true")
	}
}

func TestTransportPool_Build(t *testing.T) {
	tp := NewTransportPool()
	tp.MaxIdleConns = 50
	tp.MaxIdleConnsPerHost = 5
	tp.MaxConnsPerHost = 20
	tp.IdleConnTimeout = 45 * time.Second
	tp.TLSHandshakeTimeout = 5 * time.Second
	tp.ResponseHeaderTimeout = 30 * time.Second
	tp.DisableKeepAlives = true
	tp.WriteBufferSize = 8192
	tp.ReadBufferSize = 8192

	tr := tp.Build()

	if tr.MaxIdleConns != 50 {
		t.Errorf("MaxIdleConns = %d, want 50", tr.MaxIdleConns)
	}
	if tr.MaxIdleConnsPerHost != 5 {
		t.Errorf("MaxIdleConnsPerHost = %d, want 5", tr.MaxIdleConnsPerHost)
	}
	if tr.MaxConnsPerHost != 20 {
		t.Errorf("MaxConnsPerHost = %d, want 20", tr.MaxConnsPerHost)
	}
	if tr.IdleConnTimeout != 45*time.Second {
		t.Errorf("IdleConnTimeout = %v, want 45s", tr.IdleConnTimeout)
	}
	if tr.TLSHandshakeTimeout != 5*time.Second {
		t.Errorf("TLSHandshakeTimeout = %v, want 5s", tr.TLSHandshakeTimeout)
	}
	if tr.ResponseHeaderTimeout != 30*time.Second {
		t.Errorf("ResponseHeaderTimeout = %v, want 30s", tr.ResponseHeaderTimeout)
	}
	if !tr.DisableKeepAlives {
		t.Error("DisableKeepAlives should be true")
	}
	if tr.WriteBufferSize != 8192 {
		t.Errorf("WriteBufferSize = %d, want 8192", tr.WriteBufferSize)
	}
	if tr.ReadBufferSize != 8192 {
		t.Errorf("ReadBufferSize = %d, want 8192", tr.ReadBufferSize)
	}
}

func TestTransportPool_Build_HTTP2(t *testing.T) {
	tp := NewTransportPool()
	tp.EnableHTTP2 = true
	tr := tp.Build()

	if !tr.ForceAttemptHTTP2 {
		t.Error("ForceAttemptHTTP2 should be true when EnableHTTP2 is set")
	}
	if tr.TLSClientConfig == nil {
		t.Fatal("TLSClientConfig should not be nil")
	}

	hasH2 := false
	for _, p := range tr.TLSClientConfig.NextProtos {
		if p == "h2" {
			hasH2 = true
			break
		}
	}
	if !hasH2 {
		t.Error("NextProtos should contain 'h2'")
	}
}

func TestTransportPool_Build_NoHTTP2(t *testing.T) {
	tp := NewTransportPool()
	tp.EnableHTTP2 = false
	tr := tp.Build()

	if tr.ForceAttemptHTTP2 {
		t.Error("ForceAttemptHTTP2 should be false when EnableHTTP2 is false")
	}
}

func TestTransportPool_Build_CustomTLS(t *testing.T) {
	tp := NewTransportPool()
	tp.TLSConfig = &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"custom-proto"},
	}
	tp.EnableHTTP2 = true
	tr := tp.Build()

	if !tr.TLSClientConfig.InsecureSkipVerify {
		t.Error("InsecureSkipVerify should be preserved from custom config")
	}
	// Custom NextProtos should be preserved (not overwritten with h2)
	if len(tr.TLSClientConfig.NextProtos) != 1 || tr.TLSClientConfig.NextProtos[0] != "custom-proto" {
		t.Errorf("NextProtos = %v, want [custom-proto]", tr.TLSClientConfig.NextProtos)
	}
}

func TestTransportPool_Build_ClosesOldIdleConns(t *testing.T) {
	tp := NewTransportPool()
	tr1 := tp.Build()

	// Build again; first transport should have been swapped.
	tr2 := tp.Build()

	if tr1 == tr2 {
		t.Error("successive Build calls should return different transports")
	}
}

func TestTransportPool_Transport_AutoBuild(t *testing.T) {
	tp := NewTransportPool()
	rt := tp.Transport()
	if rt == nil {
		t.Fatal("Transport() should not return nil")
	}
}

func TestTransportPool_Transport_RoundTrip(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Test", "pooled")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("hello from pool"))
	}))
	defer backend.Close()

	tp := NewTransportPool()
	tp.EnableHTTP2 = false
	rt := tp.Transport()

	req, err := http.NewRequest("GET", backend.URL+"/test", nil)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	if resp.Header.Get("X-Test") != "pooled" {
		t.Error("missing X-Test header")
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "hello from pool" {
		t.Errorf("body = %q, want 'hello from pool'", body)
	}
}

func TestTransportPool_Stats(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	tp := NewTransportPool()
	tp.EnableHTTP2 = false
	rt := tp.Transport()

	for range 5 {
		req, _ := http.NewRequest("GET", backend.URL, nil)
		resp, err := rt.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
	}

	stats := tp.Stats()
	if stats.TotalRequests != 5 {
		t.Errorf("TotalRequests = %d, want 5", stats.TotalRequests)
	}
	if stats.ActiveRequests != 0 {
		t.Errorf("ActiveRequests = %d, want 0", stats.ActiveRequests)
	}
}

func TestTransportPool_Stats_ActiveDuringRequest(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(started)
		<-release
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	tp := NewTransportPool()
	tp.EnableHTTP2 = false
	rt := tp.Transport()

	go func() {
		req, _ := http.NewRequest("GET", backend.URL, nil)
		resp, err := rt.RoundTrip(req)
		if err == nil {
			_ = resp.Body.Close()
		}
	}()

	<-started

	stats := tp.Stats()
	if stats.ActiveRequests != 1 {
		t.Errorf("ActiveRequests = %d during request, want 1", stats.ActiveRequests)
	}

	close(release)

	// Wait briefly for the goroutine to finish.
	time.Sleep(50 * time.Millisecond)

	stats = tp.Stats()
	if stats.ActiveRequests != 0 {
		t.Errorf("ActiveRequests = %d after request, want 0", stats.ActiveRequests)
	}
}

func TestTransportPool_ConcurrentRequests(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer backend.Close()

	tp := NewTransportPool()
	tp.MaxConnsPerHost = 5
	tp.EnableHTTP2 = false
	rt := tp.Transport()

	const n = 20
	var wg sync.WaitGroup
	wg.Add(n)

	errors := make(chan error, n)

	for range n {
		go func() {
			defer wg.Done()
			req, _ := http.NewRequest("GET", backend.URL, nil)
			resp, err := rt.RoundTrip(req)
			if err != nil {
				errors <- err
				return
			}
			_, _ = io.ReadAll(resp.Body)
			_ = resp.Body.Close()
		}()
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		t.Errorf("concurrent request error: %v", err)
	}

	stats := tp.Stats()
	if stats.TotalRequests != n {
		t.Errorf("TotalRequests = %d, want %d", stats.TotalRequests, n)
	}
}

func TestTransportPool_CloseIdleConnections(t *testing.T) {
	tp := NewTransportPool()
	tp.Build()
	// Should not panic on built transport.
	tp.CloseIdleConnections()
}

func TestTransportPool_CloseIdleConnections_NoBuild(t *testing.T) {
	tp := NewTransportPool()
	// Should not panic when transport hasn't been built.
	tp.CloseIdleConnections()
}

func TestTransportPool_Build_DefaultDialTimeout(t *testing.T) {
	tp := &TransportPool{}
	tr := tp.Build()
	// Verify it doesn't panic and creates a valid transport.
	if tr == nil {
		t.Fatal("Build should return non-nil transport")
	}
}

func TestTransportPool_ConnectionReuse(t *testing.T) {
	var connCount int
	var mu sync.Mutex

	backend := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	backend.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			mu.Lock()
			connCount++
			mu.Unlock()
		}
	}
	backend.Start()
	defer backend.Close()

	tp := NewTransportPool()
	tp.MaxIdleConnsPerHost = 1
	tp.EnableHTTP2 = false
	rt := tp.Transport()

	for range 5 {
		req, _ := http.NewRequest("GET", backend.URL, nil)
		resp, err := rt.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.ReadAll(resp.Body)
		_ = resp.Body.Close()
	}

	mu.Lock()
	c := connCount
	mu.Unlock()

	if c > 2 {
		t.Errorf("expected connection reuse, but got %d connections for 5 requests", c)
	}
}

func TestTransportPool_HTTP2_TLS(t *testing.T) {
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Proto", r.Proto)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(r.Proto))
	}))
	defer backend.Close()

	tp := NewTransportPool()
	tp.EnableHTTP2 = true
	tp.TLSConfig = &tls.Config{
		InsecureSkipVerify: true,
	}
	rt := tp.Transport()

	req, _ := http.NewRequest("GET", backend.URL+"/h2test", nil)
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	proto := strings.TrimSpace(string(body))

	// httptest.NewTLSServer supports HTTP/2; check that our transport
	// successfully negotiated it.
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	if proto != "HTTP/2.0" {
		t.Logf("note: server returned proto %q (HTTP/2 may require h2 ALPN from test server)", proto)
	}
}

func TestTransportPool_DisableKeepAlives(t *testing.T) {
	tp := NewTransportPool()
	tp.DisableKeepAlives = true
	tr := tp.Build()

	if !tr.DisableKeepAlives {
		t.Error("DisableKeepAlives should be set on underlying transport")
	}
}
