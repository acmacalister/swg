package swg

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Proxy is an HTTPS MITM proxy that intercepts TLS traffic for content filtering.
type Proxy struct {
	// Addr is the address to listen on (e.g., ":8080")
	Addr string

	// CertManager handles dynamic certificate generation
	CertManager *CertManager

	// Filter determines whether requests should be blocked
	Filter Filter

	// BlockPageURL is the URL to redirect blocked requests to (optional)
	BlockPageURL string

	// BlockPage is a custom block page template (optional, uses default if nil)
	BlockPage *BlockPage

	// Logger for proxy events
	Logger *slog.Logger

	// Transport for outbound requests (optional, uses default if nil)
	Transport http.RoundTripper

	// Metrics collects Prometheus metrics (optional)
	Metrics *Metrics

	// PACHandler serves PAC files at /proxy.pac (optional)
	PACHandler *PACGenerator

	// HealthChecker provides /healthz and /readyz endpoints (optional)
	HealthChecker *HealthChecker

	// AccessLog writes structured access log entries for each request (optional)
	AccessLog *AccessLogger

	// UpstreamProxy forwards requests through a parent proxy (optional).
	// When set, CONNECT tunnels are established via the upstream proxy
	// and plain HTTP requests are forwarded through it.
	UpstreamProxy *UpstreamProxy

	// RateLimiter provides per-client request throttling (optional).
	// When set, requests exceeding the rate limit receive 429 responses.
	RateLimiter *RateLimiter

	// TransportPool provides a connection-pooled transport with HTTP/2
	// support (optional). When set, its Transport() is used as the base
	// transport instead of the Transport field.
	TransportPool *TransportPool

	// Policy provides lifecycle hooks, identity resolution, and response
	// body scanning (optional). When set, request hooks run before
	// filtering and response hooks run after the upstream response is
	// received. This enables pluggable AV scanning, DLP, content-type
	// blocking, per-group policies, and more.
	Policy *PolicyEngine

	// Admin provides REST endpoints for runtime rule management,
	// status inspection, and filter reloads (optional). When set,
	// requests matching the AdminAPI.PathPrefix are routed to the
	// admin handler instead of being proxied.
	Admin *AdminAPI

	// ClientAuth enables mutual TLS (mTLS) on the proxy listener.
	// When set, clients must present a valid certificate signed by
	// a trusted CA to connect. See [ClientAuth] for configuration.
	ClientAuth *ClientAuth

	// Bypass allows authorized clients to skip content filtering.
	// When set, requests carrying a valid bypass token in an HTTP
	// header or originating from a whitelisted identity skip the
	// filter and policy hooks. See [Bypass] for configuration.
	Bypass *Bypass

	listener net.Listener
	srv      *http.Server
}

// Filter determines whether a request should be blocked.
type Filter interface {
	// ShouldBlock returns true if the request should be blocked, along with a reason.
	ShouldBlock(req *http.Request) (blocked bool, reason string)
}

// FilterFunc is a function adapter for Filter.
type FilterFunc func(req *http.Request) (blocked bool, reason string)

// ShouldBlock calls the underlying function to determine if a request should be blocked.
func (f FilterFunc) ShouldBlock(req *http.Request) (bool, string) {
	return f(req)
}

// NewProxy creates a new HTTPS MITM proxy.
func NewProxy(addr string, cm *CertManager) *Proxy {
	return &Proxy{
		Addr:        addr,
		CertManager: cm,
		Logger:      slog.Default(),
		Transport:   http.DefaultTransport,
	}
}

// ListenAndServe starts the proxy server.
// When [Proxy.ClientAuth] is set, the listener is wrapped with TLS to
// enforce mutual TLS authentication before any HTTP traffic.
func (p *Proxy) ListenAndServe() error {
	listener, err := net.Listen("tcp", p.Addr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}

	if p.ClientAuth != nil {
		serverCert, certErr := p.CertManager.GetCertificateForHost("proxy.local")
		if certErr != nil {
			_ = listener.Close()
			return fmt.Errorf("mtls server cert: %w", certErr)
		}
		listener = p.ClientAuth.WrapListener(listener, *serverCert)
		p.Logger.Info("mTLS enabled on proxy listener")
	}

	p.listener = listener

	p.srv = &http.Server{
		Handler: p,
	}

	p.Logger.Info("proxy listening", "addr", p.Addr)
	return p.srv.Serve(listener)
}

// Shutdown gracefully stops the proxy.
func (p *Proxy) Shutdown(ctx context.Context) error {
	if p.srv != nil {
		return p.srv.Shutdown(ctx)
	}
	return nil
}

// ServeHTTP handles incoming proxy requests.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if p.ClientAuth != nil && p.ClientAuth.IdentityFromCert && r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		cert := r.TLS.PeerCertificates[0]
		ctx := WithRequestContext(r.Context(), &RequestContext{
			Identity:  cert.Subject.CommonName,
			Groups:    cert.Subject.Organization,
			ClientIP:  r.RemoteAddr,
			StartTime: time.Now(),
			Tags:      map[string]string{"auth": "mtls"},
		})
		r = r.WithContext(ctx)
	}

	if p.PACHandler != nil && r.URL.Path == "/proxy.pac" && r.Method != http.MethodConnect {
		p.PACHandler.ServeHTTP(w, r)
		return
	}
	if p.Metrics != nil && r.URL.Path == "/metrics" && r.Method != http.MethodConnect {
		p.Metrics.Handler().ServeHTTP(w, r)
		return
	}
	if p.HealthChecker != nil && r.Method != http.MethodConnect {
		switch r.URL.Path {
		case "/healthz":
			p.HealthChecker.HandleHealthz(w, r)
			return
		case "/readyz":
			p.HealthChecker.HandleReadyz(w, r)
			return
		}
	}
	if p.Admin != nil && strings.HasPrefix(r.URL.Path, p.Admin.PathPrefix) && r.Method != http.MethodConnect {
		p.Admin.ServeHTTP(w, r)
		return
	}

	// Rate limiting
	if p.RateLimiter != nil {
		if !p.RateLimiter.AllowHTTP(w, r) {
			if p.Metrics != nil {
				p.Metrics.RecordRequest(r.Method, "rate_limited")
			}
			return
		}
	}

	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
	} else {
		p.handleHTTP(w, r)
	}
}

// handleConnect handles HTTPS CONNECT requests (MITM interception).
func (p *Proxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	if p.Metrics != nil {
		p.Metrics.RecordRequest(r.Method, "https")
		p.Metrics.IncActiveConns()
		defer p.Metrics.DecActiveConns()
	}
	p.Logger.Debug("CONNECT", "host", r.Host)

	// Hijack the connection
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		p.Logger.Error("hijack failed", "error", err)
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	// Send 200 Connection Established to client
	_, err = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	if err != nil {
		p.Logger.Error("write connect response", "error", err)
		_ = clientConn.Close()
		return
	}

	// Get hostname for certificate generation
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}

	// Create TLS config with dynamic cert generation
	tlsConfig := &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			// Use SNI if available, otherwise use the CONNECT host
			h := hello.ServerName
			if h == "" {
				h = host
			}
			return p.CertManager.GetCertificateForHost(h)
		},
	}

	// Wrap client connection with TLS (server side - we're pretending to be the target)
	tlsClientConn := tls.Server(clientConn, tlsConfig)
	if err := tlsClientConn.Handshake(); err != nil {
		p.Logger.Error("TLS handshake with client", "error", err, "host", host)
		if p.Metrics != nil {
			p.Metrics.RecordTLSHandshakeError()
		}
		_ = clientConn.Close()
		return
	}

	// Handle HTTP requests over the TLS connection
	p.handleTLSConnection(tlsClientConn, host)
}

// handleTLSConnection reads HTTP requests from the TLS connection and processes them.
func (p *Proxy) handleTLSConnection(conn *tls.Conn, defaultHost string) {
	defer func() { _ = conn.Close() }()

	reader := bufio.NewReader(conn)

	for {
		// Set read deadline
		_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))

		req, err := http.ReadRequest(reader)
		if err != nil {
			if err != io.EOF {
				p.Logger.Debug("read request", "error", err)
			}
			return
		}

		// Ensure the request has the proper host/URL
		if req.URL.Host == "" {
			req.URL.Host = defaultHost
		}
		if req.URL.Scheme == "" {
			req.URL.Scheme = "https"
		}
		if req.Host == "" {
			req.Host = defaultHost
		}

		// Run policy request hooks (identity resolution, access control).
		var rc *RequestContext
		if p.Policy != nil {
			var policyResp *http.Response
			rc, policyResp = p.Policy.ProcessRequest(req.Context(), req)
			if policyResp != nil {
				_ = policyResp.Write(conn)
				_ = policyResp.Body.Close()
				continue
			}
			req = req.WithContext(WithRequestContext(req.Context(), rc))
		}

		// Check bypass before filter
		bypassed := p.Bypass != nil && p.Bypass.ShouldBypass(req)

		// Check filter
		if !bypassed && p.Filter != nil {
			if blocked, reason := p.Filter.ShouldBlock(req); blocked {
				p.Logger.Info("blocked", "host", req.Host, "path", req.URL.Path, "reason", reason)
				if p.Metrics != nil {
					p.Metrics.RecordBlocked(reason)
				}
				p.writeBlockResponse(conn, req, reason)
				if p.AccessLog != nil {
					p.AccessLog.Log(AccessLogEntry{
						Timestamp:   time.Now(),
						Method:      req.Method,
						Host:        req.Host,
						Path:        req.URL.Path,
						Scheme:      req.URL.Scheme,
						Blocked:     true,
						BlockReason: reason,
						ClientAddr:  conn.RemoteAddr().String(),
						UserAgent:   req.UserAgent(),
					})
				}
				continue
			}
		}

		// Forward the request
		start := time.Now()
		resp, err := p.forwardRequest(req)
		if err != nil {
			p.Logger.Error("forward request", "error", err, "url", req.URL)
			if p.Metrics != nil {
				p.Metrics.RecordUpstreamError(req.Host)
			}
			p.writeErrorResponse(conn, err)
			if p.AccessLog != nil {
				p.AccessLog.Log(AccessLogEntry{
					Timestamp:  time.Now(),
					Method:     req.Method,
					Host:       req.Host,
					Path:       req.URL.Path,
					Scheme:     req.URL.Scheme,
					Duration:   time.Since(start),
					ClientAddr: conn.RemoteAddr().String(),
					UserAgent:  req.UserAgent(),
					Error:      err.Error(),
				})
			}
			continue
		}
		if p.Metrics != nil {
			p.Metrics.RecordRequestDuration(req.Method, resp.StatusCode, time.Since(start))
		}

		// Run policy response hooks (content-type filter, body scanning).
		if p.Policy != nil {
			processed, err := p.Policy.ProcessResponse(req.Context(), req, resp, rc)
			if err != nil {
				_ = resp.Body.Close()
				p.writeErrorResponse(conn, err)
				continue
			}
			resp = processed
		}

		// Write response back to client
		err = resp.Write(conn)
		_ = resp.Body.Close()
		if p.AccessLog != nil {
			e := AccessLogEntry{
				Timestamp:    time.Now(),
				Method:       req.Method,
				Host:         req.Host,
				Path:         req.URL.Path,
				Scheme:       req.URL.Scheme,
				StatusCode:   resp.StatusCode,
				Duration:     time.Since(start),
				BytesWritten: resp.ContentLength,
				ClientAddr:   conn.RemoteAddr().String(),
				UserAgent:    req.UserAgent(),
			}
			if err != nil {
				e.Error = err.Error()
			}
			p.AccessLog.Log(e)
		}
		if err != nil {
			p.Logger.Debug("write response", "error", err)
			return
		}
	}
}

// forwardRequest sends the request to the actual server.
func (p *Proxy) forwardRequest(req *http.Request) (*http.Response, error) {
	// Clone the request for forwarding
	outReq := req.Clone(req.Context())

	// Remove hop-by-hop headers
	removeHopByHopHeaders(outReq.Header)

	transport := p.transport()

	return transport.RoundTrip(outReq)
}

// transport returns the effective http.RoundTripper, wrapping the base
// transport with the upstream proxy transport when configured.
func (p *Proxy) transport() http.RoundTripper {
	var base http.RoundTripper
	switch {
	case p.TransportPool != nil:
		base = p.TransportPool.Transport()
	case p.Transport != nil:
		base = p.Transport
	default:
		base = http.DefaultTransport
	}
	if p.UpstreamProxy != nil {
		return p.UpstreamProxy.Transport(base)
	}
	return base
}

// writeBlockResponse writes a block page response.
func (p *Proxy) writeBlockResponse(w io.Writer, req *http.Request, reason string) {
	var resp *http.Response

	if p.BlockPageURL != "" {
		// Redirect to block page
		blockURL, _ := url.Parse(p.BlockPageURL)
		q := blockURL.Query()
		q.Set("url", req.URL.String())
		q.Set("reason", reason)
		blockURL.RawQuery = q.Encode()

		resp = &http.Response{
			StatusCode: http.StatusFound,
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header: http.Header{
				"Location":     {blockURL.String()},
				"Content-Type": {"text/html"},
			},
			Body: io.NopCloser(strings.NewReader(
				fmt.Sprintf(`<html><body>Redirecting to <a href="%s">block page</a>...</body></html>`, blockURL.String()),
			)),
		}
	} else {
		// Use custom block page or default
		blockPage := p.BlockPage
		if blockPage == nil {
			blockPage = NewBlockPage()
		}

		host := req.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}

		data := BlockPageData{
			URL:       req.URL.String(),
			Host:      host,
			Path:      req.URL.Path,
			Reason:    reason,
			Timestamp: time.Now().Format(time.RFC1123),
		}

		body, _ := blockPage.RenderString(data)

		resp = &http.Response{
			StatusCode:    http.StatusForbidden,
			ProtoMajor:    1,
			ProtoMinor:    1,
			Header:        http.Header{"Content-Type": {"text/html; charset=utf-8"}},
			Body:          io.NopCloser(strings.NewReader(body)),
			ContentLength: int64(len(body)),
		}
	}

	_ = resp.Write(w)
}

// writeErrorResponse writes an error response.
func (p *Proxy) writeErrorResponse(w io.Writer, err error) {
	body := fmt.Sprintf("Proxy Error: %v", err)
	resp := &http.Response{
		StatusCode:    http.StatusBadGateway,
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        http.Header{"Content-Type": {"text/plain"}},
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
	}
	_ = resp.Write(w)
}

// handleHTTP handles plain HTTP requests (non-CONNECT).
func (p *Proxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	if p.Metrics != nil {
		p.Metrics.RecordRequest(r.Method, "http")
	}
	p.Logger.Debug("HTTP", "method", r.Method, "url", r.URL)

	// Run policy request hooks (identity resolution, access control).
	var rc *RequestContext
	if p.Policy != nil {
		var policyResp *http.Response
		rc, policyResp = p.Policy.ProcessRequest(r.Context(), r)
		if policyResp != nil {
			for k, vv := range policyResp.Header {
				for _, v := range vv {
					w.Header().Add(k, v)
				}
			}
			w.WriteHeader(policyResp.StatusCode)
			_, _ = io.Copy(w, policyResp.Body)
			_ = policyResp.Body.Close()
			return
		}
		r = r.WithContext(WithRequestContext(r.Context(), rc))
	}

	// Check bypass before filter
	bypassed := p.Bypass != nil && p.Bypass.ShouldBypass(r)

	// Check filter
	if !bypassed && p.Filter != nil {
		if blocked, reason := p.Filter.ShouldBlock(r); blocked {
			p.Logger.Info("blocked", "url", r.URL, "reason", reason)
			if p.Metrics != nil {
				p.Metrics.RecordBlocked(reason)
			}
			if p.BlockPageURL != "" {
				blockURL, _ := url.Parse(p.BlockPageURL)
				q := blockURL.Query()
				q.Set("url", r.URL.String())
				q.Set("reason", reason)
				blockURL.RawQuery = q.Encode()
				http.Redirect(w, r, blockURL.String(), http.StatusFound)
			} else {
				// Use custom block page or default
				blockPage := p.BlockPage
				if blockPage == nil {
					blockPage = NewBlockPage()
				}

				host := r.Host
				if h, _, err := net.SplitHostPort(host); err == nil {
					host = h
				}

				data := BlockPageData{
					URL:       r.URL.String(),
					Host:      host,
					Path:      r.URL.Path,
					Reason:    reason,
					Timestamp: time.Now().Format(time.RFC1123),
				}

				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.WriteHeader(http.StatusForbidden)
				blockPage.Render(w, data) //nolint:errcheck
			}
			if p.AccessLog != nil {
				p.AccessLog.Log(AccessLogEntry{
					Timestamp:   time.Now(),
					Method:      r.Method,
					Host:        r.Host,
					Path:        r.URL.Path,
					Scheme:      r.URL.Scheme,
					Blocked:     true,
					BlockReason: reason,
					ClientAddr:  r.RemoteAddr,
					UserAgent:   r.UserAgent(),
				})
			}
			return
		}
	}

	// Forward the request
	outReq := r.Clone(r.Context())
	removeHopByHopHeaders(outReq.Header)

	transport := p.transport()

	start := time.Now()
	resp, err := transport.RoundTrip(outReq)
	if err != nil {
		p.Logger.Error("forward request", "error", err, "url", r.URL)
		if p.Metrics != nil {
			p.Metrics.RecordUpstreamError(r.Host)
		}
		http.Error(w, err.Error(), http.StatusBadGateway)
		if p.AccessLog != nil {
			p.AccessLog.Log(AccessLogEntry{
				Timestamp:  time.Now(),
				Method:     r.Method,
				Host:       r.Host,
				Path:       r.URL.Path,
				Scheme:     r.URL.Scheme,
				Duration:   time.Since(start),
				ClientAddr: r.RemoteAddr,
				UserAgent:  r.UserAgent(),
				Error:      err.Error(),
			})
		}
		return
	}
	defer func() { _ = resp.Body.Close() }()
	if p.Metrics != nil {
		p.Metrics.RecordRequestDuration(r.Method, resp.StatusCode, time.Since(start))
	}

	// Run policy response hooks (content-type filter, body scanning).
	if p.Policy != nil {
		processed, pErr := p.Policy.ProcessResponse(r.Context(), r, resp, rc)
		if pErr != nil {
			_ = resp.Body.Close()
			http.Error(w, pErr.Error(), http.StatusBadGateway)
			return
		}
		resp = processed
	}

	// Copy response headers
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	written, _ := io.Copy(w, resp.Body)
	if p.AccessLog != nil {
		p.AccessLog.Log(AccessLogEntry{
			Timestamp:    time.Now(),
			Method:       r.Method,
			Host:         r.Host,
			Path:         r.URL.Path,
			Scheme:       r.URL.Scheme,
			StatusCode:   resp.StatusCode,
			Duration:     time.Since(start),
			BytesWritten: written,
			ClientAddr:   r.RemoteAddr,
			UserAgent:    r.UserAgent(),
		})
	}
}

// Hop-by-hop headers that should not be forwarded
var hopByHopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailers",
	"Transfer-Encoding",
	"Upgrade",
}

func removeHopByHopHeaders(h http.Header) {
	for _, header := range hopByHopHeaders {
		h.Del(header)
	}
}

// DomainFilter is a simple filter that blocks requests to specific domains.
type DomainFilter struct {
	mu       sync.RWMutex
	blocked  map[string]bool
	patterns []string // wildcard patterns like "*.ads.com"
}

// NewDomainFilter creates a new domain-based filter.
func NewDomainFilter() *DomainFilter {
	return &DomainFilter{
		blocked: make(map[string]bool),
	}
}

// AddDomain adds a domain to the blocklist.
// Supports wildcards: "*.example.com" blocks all subdomains.
func (f *DomainFilter) AddDomain(domain string) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if strings.HasPrefix(domain, "*.") {
		f.patterns = append(f.patterns, domain[2:]) // Store without "*."
	} else {
		f.blocked[strings.ToLower(domain)] = true
	}
}

// AddDomains adds multiple domains to the blocklist.
func (f *DomainFilter) AddDomains(domains []string) {
	for _, d := range domains {
		f.AddDomain(d)
	}
}

// ShouldBlock implements Filter.
func (f *DomainFilter) ShouldBlock(req *http.Request) (bool, string) {
	host := req.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.ToLower(host)

	f.mu.RLock()
	defer f.mu.RUnlock()

	// Check exact match
	if f.blocked[host] {
		return true, "domain blocked"
	}

	// Check wildcard patterns
	for _, pattern := range f.patterns {
		if host == pattern || strings.HasSuffix(host, "."+pattern) {
			return true, "domain blocked (wildcard)"
		}
	}

	return false, ""
}
