//nolint:errcheck // Benchmarks intentionally ignore errors for performance measurement
package swg

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"sync"
	"testing"
)

// =============================================================================
// Certificate Generation Benchmarks
// =============================================================================

func BenchmarkCertGeneration(b *testing.B) {
	certPEM, keyPEM, err := GenerateCA("Benchmark CA", 1)
	if err != nil {
		b.Fatalf("GenerateCA failed: %v", err)
	}

	cm, err := NewCertManagerFromPEM(certPEM, keyPEM)
	if err != nil {
		b.Fatalf("NewCertManagerFromPEM failed: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		host := fmt.Sprintf("bench%d.example.com", i)
		_, err := cm.GetCertificateForHost(host)
		if err != nil {
			b.Fatalf("GetCertificateForHost failed: %v", err)
		}
	}
}

func BenchmarkCertGeneration_Cached(b *testing.B) {
	certPEM, keyPEM, err := GenerateCA("Benchmark CA", 1)
	if err != nil {
		b.Fatalf("GenerateCA failed: %v", err)
	}

	cm, err := NewCertManagerFromPEM(certPEM, keyPEM)
	if err != nil {
		b.Fatalf("NewCertManagerFromPEM failed: %v", err)
	}

	// Pre-populate cache
	_, err = cm.GetCertificateForHost("cached.example.com")
	if err != nil {
		b.Fatalf("GetCertificateForHost failed: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := cm.GetCertificateForHost("cached.example.com")
		if err != nil {
			b.Fatalf("GetCertificateForHost failed: %v", err)
		}
	}
}

func BenchmarkCertGeneration_Parallel(b *testing.B) {
	certPEM, keyPEM, err := GenerateCA("Benchmark CA", 1)
	if err != nil {
		b.Fatalf("GenerateCA failed: %v", err)
	}

	cm, err := NewCertManagerFromPEM(certPEM, keyPEM)
	if err != nil {
		b.Fatalf("NewCertManagerFromPEM failed: %v", err)
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			host := fmt.Sprintf("parallel%d.example.com", i)
			_, err := cm.GetCertificateForHost(host)
			if err != nil {
				b.Errorf("GetCertificateForHost failed: %v", err)
			}
			i++
		}
	})
}

// =============================================================================
// RuleSet Matching Benchmarks
// =============================================================================

func BenchmarkRuleSetMatch_Domain_1K(b *testing.B) {
	benchmarkRuleSetMatchDomain(b, 1000)
}

func BenchmarkRuleSetMatch_Domain_10K(b *testing.B) {
	benchmarkRuleSetMatchDomain(b, 10000)
}

func BenchmarkRuleSetMatch_Domain_100K(b *testing.B) {
	benchmarkRuleSetMatchDomain(b, 100000)
}

func benchmarkRuleSetMatchDomain(b *testing.B, ruleCount int) {
	rs := NewRuleSet()

	// Add rules
	for i := 0; i < ruleCount; i++ {
		rs.AddDomain(fmt.Sprintf("blocked%d.example.com", i))
	}

	// Create request for a blocked domain (worst case - checks all rules)
	req := httptest.NewRequest("GET", fmt.Sprintf("http://blocked%d.example.com/", ruleCount/2), nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rs.ShouldBlock(req)
	}
}

func BenchmarkRuleSetMatch_Domain_Miss(b *testing.B) {
	rs := NewRuleSet()

	// Add 10K rules
	for i := 0; i < 10000; i++ {
		rs.AddDomain(fmt.Sprintf("blocked%d.example.com", i))
	}

	// Request for non-blocked domain
	req := httptest.NewRequest("GET", "http://allowed.example.com/", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rs.ShouldBlock(req)
	}
}

func BenchmarkRuleSetMatch_Wildcard_1K(b *testing.B) {
	benchmarkRuleSetMatchWildcard(b, 1000)
}

func BenchmarkRuleSetMatch_Wildcard_10K(b *testing.B) {
	benchmarkRuleSetMatchWildcard(b, 10000)
}

func benchmarkRuleSetMatchWildcard(b *testing.B, ruleCount int) {
	rs := NewRuleSet()

	// Add wildcard rules
	for i := 0; i < ruleCount; i++ {
		rs.AddDomain(fmt.Sprintf("*.domain%d.com", i))
	}

	// Create request that matches middle wildcard
	req := httptest.NewRequest("GET", fmt.Sprintf("http://sub.domain%d.com/", ruleCount/2), nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rs.ShouldBlock(req)
	}
}

func BenchmarkRuleSetMatch_Regex_100(b *testing.B) {
	benchmarkRuleSetMatchRegex(b, 100)
}

func BenchmarkRuleSetMatch_Regex_1K(b *testing.B) {
	benchmarkRuleSetMatchRegex(b, 1000)
}

func benchmarkRuleSetMatchRegex(b *testing.B, ruleCount int) {
	rs := NewRuleSet()

	// Add regex rules
	for i := 0; i < ruleCount; i++ {
		rs.AddRegex(fmt.Sprintf(`.*pattern%d.*`, i))
	}

	// Create request with URL that matches
	req := httptest.NewRequest("GET", fmt.Sprintf("http://example.com/path/pattern%d/page", ruleCount/2), nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rs.ShouldBlock(req)
	}
}

func BenchmarkRuleSetMatch_URL_1K(b *testing.B) {
	benchmarkRuleSetMatchURL(b, 1000)
}

func BenchmarkRuleSetMatch_URL_10K(b *testing.B) {
	benchmarkRuleSetMatchURL(b, 10000)
}

func benchmarkRuleSetMatchURL(b *testing.B, ruleCount int) {
	rs := NewRuleSet()

	// Add URL prefix rules
	for i := 0; i < ruleCount; i++ {
		rs.AddURL(fmt.Sprintf("http://blocked%d.example.com/path", i))
	}

	// Create request that matches
	req := httptest.NewRequest("GET", fmt.Sprintf("http://blocked%d.example.com/path/page", ruleCount/2), nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rs.ShouldBlock(req)
	}
}

func BenchmarkRuleSetMatch_Mixed(b *testing.B) {
	rs := NewRuleSet()

	// Add mixed rules (realistic scenario)
	for i := 0; i < 1000; i++ {
		rs.AddDomain(fmt.Sprintf("blocked%d.example.com", i))
	}
	for i := 0; i < 500; i++ {
		rs.AddDomain(fmt.Sprintf("*.ads%d.com", i))
	}
	for i := 0; i < 100; i++ {
		rs.AddURL(fmt.Sprintf("http://tracking%d.com/pixel", i))
	}
	for i := 0; i < 50; i++ {
		rs.AddRegex(fmt.Sprintf(`.*analytics%d.*`, i))
	}

	req := httptest.NewRequest("GET", "http://allowed.example.com/", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rs.ShouldBlock(req)
	}
}

func BenchmarkRuleSetMatch_Parallel(b *testing.B) {
	rs := NewRuleSet()

	for i := 0; i < 10000; i++ {
		rs.AddDomain(fmt.Sprintf("blocked%d.example.com", i))
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		req := httptest.NewRequest("GET", "http://blocked5000.example.com/", nil)
		for pb.Next() {
			rs.ShouldBlock(req)
		}
	})
}

// =============================================================================
// Rate Limiter Benchmarks
// =============================================================================

func BenchmarkRateLimiter_Allow(b *testing.B) {
	rl := NewRateLimiter(1000000, 1000) // High rate to avoid rejections
	defer rl.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rl.Allow("192.168.1.1:1234")
	}
}

func BenchmarkRateLimiter_Allow_MultiClient(b *testing.B) {
	rl := NewRateLimiter(1000000, 1000)
	defer rl.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rl.Allow(fmt.Sprintf("192.168.1.%d:%d", i%256, i%65536))
	}
}

func BenchmarkRateLimiter_Parallel(b *testing.B) {
	rl := NewRateLimiter(1000000, 1000)
	defer rl.Close()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			rl.Allow(fmt.Sprintf("10.0.%d.%d:1234", (i/256)%256, i%256))
			i++
		}
	})
}

// =============================================================================
// Proxy HTTP Benchmarks
// =============================================================================

func BenchmarkProxyHTTP(b *testing.B) {
	// Create backend server
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer backend.Close()

	// Create proxy
	certPEM, keyPEM, _ := GenerateCA("Benchmark CA", 1)
	cm, _ := NewCertManagerFromPEM(certPEM, keyPEM)

	proxy := NewProxy(":0", cm)

	// Start proxy
	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		b.Fatalf("Listen failed: %v", err)
	}
	defer ln.Close()

	go http.Serve(ln, proxy)

	// Create client that uses proxy
	proxyURL := "http://" + ln.Addr().String()
	transport := &http.Transport{
		Proxy: func(*http.Request) (*url.URL, error) {
			return url.Parse(proxyURL)
		},
	}
	client := &http.Client{Transport: transport}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp, err := client.Get(backend.URL)
		if err != nil {
			b.Fatalf("GET failed: %v", err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
}

func BenchmarkProxyHTTP_Parallel(b *testing.B) {
	// Create backend server
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer backend.Close()

	// Create proxy
	certPEM, keyPEM, _ := GenerateCA("Benchmark CA", 1)
	cm, _ := NewCertManagerFromPEM(certPEM, keyPEM)

	proxy := NewProxy(":0", cm)

	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		b.Fatalf("Listen failed: %v", err)
	}
	defer ln.Close()

	go http.Serve(ln, proxy)

	proxyURL := "http://" + ln.Addr().String()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		transport := &http.Transport{
			Proxy: func(*http.Request) (*url.URL, error) {
				return url.Parse(proxyURL)
			},
		}
		client := &http.Client{Transport: transport}

		for pb.Next() {
			resp, err := client.Get(backend.URL)
			if err != nil {
				b.Errorf("GET failed: %v", err)
				continue
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
	})
}

func BenchmarkProxyHTTP_WithFilter(b *testing.B) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer backend.Close()

	certPEM, keyPEM, _ := GenerateCA("Benchmark CA", 1)
	cm, _ := NewCertManagerFromPEM(certPEM, keyPEM)

	proxy := NewProxy(":0", cm)

	// Add filter with 10K rules
	rs := NewRuleSet()
	for i := 0; i < 10000; i++ {
		rs.AddDomain(fmt.Sprintf("blocked%d.example.com", i))
	}
	proxy.Filter = rs

	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		b.Fatalf("Listen failed: %v", err)
	}
	defer ln.Close()

	go http.Serve(ln, proxy)

	proxyURL := "http://" + ln.Addr().String()
	transport := &http.Transport{
		Proxy: func(*http.Request) (*url.URL, error) {
			return url.Parse(proxyURL)
		},
	}
	client := &http.Client{Transport: transport}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp, err := client.Get(backend.URL)
		if err != nil {
			b.Fatalf("GET failed: %v", err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
}

// =============================================================================
// Proxy HTTPS (CONNECT) Benchmarks
// =============================================================================

func BenchmarkProxyHTTPS(b *testing.B) {
	// Create TLS backend server
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer backend.Close()

	// Create proxy with CA
	certPEM, keyPEM, _ := GenerateCA("Benchmark CA", 1)
	cm, _ := NewCertManagerFromPEM(certPEM, keyPEM)

	proxy := NewProxy(":0", cm)

	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		b.Fatalf("Listen failed: %v", err)
	}
	defer ln.Close()

	go http.Serve(ln, proxy)

	// Create CA pool for client
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(certPEM)
	// Also add backend's cert
	caPool.AddCert(backend.Certificate())

	proxyURL := "http://" + ln.Addr().String()
	transport := &http.Transport{
		Proxy: func(*http.Request) (*url.URL, error) {
			return url.Parse(proxyURL)
		},
		TLSClientConfig: &tls.Config{
			RootCAs:            caPool,
			InsecureSkipVerify: true, // For benchmark only
		},
	}
	client := &http.Client{Transport: transport}

	// Warm up - establish connection
	resp, err := client.Get(backend.URL)
	if err != nil {
		b.Skipf("HTTPS proxy setup failed (expected in some environments): %v", err)
	}
	resp.Body.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp, err := client.Get(backend.URL)
		if err != nil {
			b.Fatalf("GET failed: %v", err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
}

// =============================================================================
// Concurrent Connections Benchmarks
// =============================================================================

func BenchmarkConcurrentConnections_10(b *testing.B) {
	benchmarkConcurrentConnections(b, 10)
}

func BenchmarkConcurrentConnections_100(b *testing.B) {
	benchmarkConcurrentConnections(b, 100)
}

func BenchmarkConcurrentConnections_1000(b *testing.B) {
	benchmarkConcurrentConnections(b, 1000)
}

func benchmarkConcurrentConnections(b *testing.B, concurrency int) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer backend.Close()

	certPEM, keyPEM, _ := GenerateCA("Benchmark CA", 1)
	cm, _ := NewCertManagerFromPEM(certPEM, keyPEM)

	proxy := NewProxy(":0", cm)

	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		b.Fatalf("Listen failed: %v", err)
	}
	defer ln.Close()

	go http.Serve(ln, proxy)

	proxyURL := "http://" + ln.Addr().String()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var wg sync.WaitGroup
		wg.Add(concurrency)

		for j := 0; j < concurrency; j++ {
			go func() {
				defer wg.Done()

				transport := &http.Transport{
					Proxy: func(*http.Request) (*url.URL, error) {
						return url.Parse(proxyURL)
					},
					DisableKeepAlives: true, // Force new connections
				}
				client := &http.Client{Transport: transport}

				resp, err := client.Get(backend.URL)
				if err != nil {
					return
				}
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}()
		}

		wg.Wait()
	}
}

// =============================================================================
// Connection Pool Benchmarks
// =============================================================================

func BenchmarkTransportPool_Build(b *testing.B) {
	for i := 0; i < b.N; i++ {
		pool := NewTransportPool()
		_ = pool.Transport()
	}
}

func BenchmarkTransportPool_Request(b *testing.B) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer backend.Close()

	pool := NewTransportPool()
	client := &http.Client{Transport: pool.Transport()}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp, err := client.Get(backend.URL)
		if err != nil {
			b.Fatalf("GET failed: %v", err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
}

func BenchmarkTransportPool_Parallel(b *testing.B) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer backend.Close()

	pool := NewTransportPool()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		client := &http.Client{Transport: pool.Transport()}
		for pb.Next() {
			resp, err := client.Get(backend.URL)
			if err != nil {
				b.Errorf("GET failed: %v", err)
				continue
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
	})
}

// =============================================================================
// Body Limiter Benchmarks
// =============================================================================

func BenchmarkBodyLimiter_Check_Pass(b *testing.B) {
	limiter := NewBodyLimiter(10 * MB)

	body := bytes.NewReader(make([]byte, 1*MB))
	req := httptest.NewRequest("POST", "http://example.com/upload", body)
	req.ContentLength = 1 * MB

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		body.Reset(make([]byte, 1*MB))
		req.Body = io.NopCloser(body)
		limiter.Check(req)
	}
}

func BenchmarkBodyLimiter_Check_Reject(b *testing.B) {
	limiter := NewBodyLimiter(1 * MB)

	body := bytes.NewReader(make([]byte, 10*MB))
	req := httptest.NewRequest("POST", "http://example.com/upload", body)
	req.ContentLength = 10 * MB

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		limiter.Check(req)
	}
}

func BenchmarkBodyLimiter_PathLimit(b *testing.B) {
	limiter := NewBodyLimiter(10 * MB)
	limiter.SetPathLimit("/api/", 1*MB)
	limiter.SetPathLimit("/upload/", 100*MB)
	limiter.SetPathLimit("/small/", 100*KB)

	paths := []string{"/api/data", "/upload/file", "/small/item", "/other/path"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		limiter.GetPathLimit(paths[i%len(paths)])
	}
}

// =============================================================================
// Compression Benchmarks
// =============================================================================

func BenchmarkCompress_Gzip(b *testing.B) {
	data := bytes.Repeat([]byte("Hello, World! This is test data for compression. "), 1000)

	b.ResetTimer()
	b.SetBytes(int64(len(data)))
	for i := 0; i < b.N; i++ {
		_, err := CompressBytes(data, "gzip")
		if err != nil {
			b.Fatalf("CompressBytes failed: %v", err)
		}
	}
}

func BenchmarkCompress_Zstd(b *testing.B) {
	data := bytes.Repeat([]byte("Hello, World! This is test data for compression. "), 1000)

	b.ResetTimer()
	b.SetBytes(int64(len(data)))
	for i := 0; i < b.N; i++ {
		_, err := CompressBytes(data, "zstd")
		if err != nil {
			b.Fatalf("CompressBytes failed: %v", err)
		}
	}
}

func BenchmarkCompress_Brotli(b *testing.B) {
	data := bytes.Repeat([]byte("Hello, World! This is test data for compression. "), 1000)

	b.ResetTimer()
	b.SetBytes(int64(len(data)))
	for i := 0; i < b.N; i++ {
		_, err := CompressBytes(data, "br")
		if err != nil {
			b.Fatalf("CompressBytes failed: %v", err)
		}
	}
}

// =============================================================================
// Baseline Comparisons (for reference)
// =============================================================================

func BenchmarkBaseline_RegexpMatch(b *testing.B) {
	// Baseline for regex performance comparison
	patterns := make([]*regexp.Regexp, 100)
	for i := 0; i < 100; i++ {
		patterns[i] = regexp.MustCompile(fmt.Sprintf(`.*pattern%d.*`, i))
	}

	url := "http://example.com/path/pattern50/page"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, p := range patterns {
			if p.MatchString(url) {
				break
			}
		}
	}
}

func BenchmarkBaseline_MapLookup(b *testing.B) {
	// Baseline for map lookup performance
	m := make(map[string]bool)
	for i := 0; i < 100000; i++ {
		m[fmt.Sprintf("key%d", i)] = true
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = m["key50000"]
	}
}

func BenchmarkBaseline_TLSHandshake(b *testing.B) {
	// Baseline TLS handshake without proxy
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		DisableKeepAlives: true, // Force new TLS handshake each time
	}
	client := &http.Client{Transport: transport}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp, err := client.Get(server.URL)
		if err != nil {
			b.Fatalf("GET failed: %v", err)
		}
		resp.Body.Close()
	}
}

// =============================================================================
// Memory Allocation Benchmarks
// =============================================================================

func BenchmarkCertGeneration_Allocs(b *testing.B) {
	certPEM, keyPEM, _ := GenerateCA("Benchmark CA", 1)
	cm, _ := NewCertManagerFromPEM(certPEM, keyPEM)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		host := fmt.Sprintf("alloc%d.example.com", i)
		cm.GetCertificateForHost(host)
	}
}

func BenchmarkRuleSetMatch_Allocs(b *testing.B) {
	rs := NewRuleSet()
	for i := 0; i < 10000; i++ {
		rs.AddDomain(fmt.Sprintf("blocked%d.example.com", i))
	}

	req := &http.Request{Host: "blocked5000.example.com"}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rs.ShouldBlock(req)
	}
}

// =============================================================================
// ReloadableFilter Benchmarks
// =============================================================================

func BenchmarkReloadableFilter_Load(b *testing.B) {
	rules := make([]Rule, 10000)
	for i := 0; i < 10000; i++ {
		rules[i] = Rule{
			Type:    "domain",
			Pattern: fmt.Sprintf("blocked%d.example.com", i),
			Reason:  "benchmark",
		}
	}

	loader := NewStaticLoader(rules...)
	rf := NewReloadableFilter(loader)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rf.Load(context.Background())
	}
}

func BenchmarkReloadableFilter_ShouldBlock(b *testing.B) {
	rules := make([]Rule, 10000)
	for i := 0; i < 10000; i++ {
		rules[i] = Rule{
			Type:    "domain",
			Pattern: fmt.Sprintf("blocked%d.example.com", i),
			Reason:  "benchmark",
		}
	}

	loader := NewStaticLoader(rules...)
	rf := NewReloadableFilter(loader)
	rf.Load(context.Background())

	req := httptest.NewRequest("GET", "http://blocked5000.example.com/", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rf.ShouldBlock(req)
	}
}
