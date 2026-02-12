package swg

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestNewUpstreamProxy(t *testing.T) {
	tests := []struct {
		name    string
		rawURL  string
		wantErr bool
		auth    bool
	}{
		{"http proxy", "http://proxy:3128", false, false},
		{"https proxy", "https://proxy.corp:443", false, false},
		{"with auth in URL", "http://user:pass@proxy:3128", false, true},
		{"invalid scheme", "socks5://proxy:1080", true, false},
		{"bad URL", "://bad", true, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			up, err := NewUpstreamProxy(tt.rawURL)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if up.DialTimeout != 10*time.Second {
				t.Errorf("DialTimeout = %v, want 10s", up.DialTimeout)
			}
			if tt.auth {
				if up.Auth == nil {
					t.Fatal("expected auth")
				}
				if up.Auth.Username != "user" || up.Auth.Password != "pass" {
					t.Errorf("auth = %+v", up.Auth)
				}
			}
		})
	}
}

func TestUpstreamProxy_DialConnect(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, "hello from backend")
	}))
	defer backend.Close()

	_, backendPort, _ := net.SplitHostPort(backend.Listener.Addr().String())
	targetAddr := "backend.test:" + backendPort

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "expected CONNECT", http.StatusBadRequest)
			return
		}

		if r.Host != targetAddr {
			http.Error(w, "wrong target", http.StatusBadRequest)
			return
		}

		hijacker, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "hijack not supported", http.StatusInternalServerError)
			return
		}

		targetConn, err := net.Dial("tcp", backend.Listener.Addr().String())
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}

		conn, _, err := hijacker.Hijack()
		if err != nil {
			_ = targetConn.Close()
			return
		}

		_, _ = conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

		go func() { _, _ = io.Copy(targetConn, conn) }()
		_, _ = io.Copy(conn, targetConn)
		_ = conn.Close()
		_ = targetConn.Close()
	}))
	defer upstream.Close()

	up, err := NewUpstreamProxy(upstream.URL)
	if err != nil {
		t.Fatalf("NewUpstreamProxy: %v", err)
	}

	clientAddr := &net.TCPAddr{IP: net.ParseIP("192.168.1.100"), Port: 12345}
	conn, err := up.DialConnect(context.Background(), "tcp", targetAddr, clientAddr)
	if err != nil {
		t.Fatalf("DialConnect: %v", err)
	}
	defer func() { _ = conn.Close() }()

	req, _ := http.NewRequest("GET", "http://"+targetAddr+"/test", nil)
	if err := req.Write(conn); err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "hello from backend" {
		t.Errorf("body = %q, want %q", body, "hello from backend")
	}
}

func TestUpstreamProxy_DialConnect_AuthHeader(t *testing.T) {
	var mu sync.Mutex
	var gotAuth string

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotAuth = r.Header.Get("Proxy-Authorization")
		mu.Unlock()

		if r.Method == http.MethodConnect {
			hijacker, ok := w.(http.Hijacker)
			if !ok {
				http.Error(w, "no hijack", http.StatusInternalServerError)
				return
			}
			conn, _, err := hijacker.Hijack()
			if err != nil {
				return
			}
			_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
			_ = conn.Close()
			return
		}
	}))
	defer upstream.Close()

	up, _ := NewUpstreamProxy(upstream.URL)
	up.Auth = &UpstreamAuth{Username: "testuser", Password: "testpass"}

	conn, err := up.DialConnect(context.Background(), "tcp", "example.com:443", nil)
	if err != nil {
		t.Fatalf("DialConnect: %v", err)
	}
	_ = conn.Close()

	mu.Lock()
	auth := gotAuth
	mu.Unlock()

	if auth == "" {
		t.Fatal("expected Proxy-Authorization header")
	}
	if !strings.HasPrefix(auth, "Basic ") {
		t.Errorf("auth = %q, want Basic prefix", auth)
	}
}

func TestUpstreamProxy_DialConnect_Rejected(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer upstream.Close()

	up, _ := NewUpstreamProxy(upstream.URL)

	_, err := up.DialConnect(context.Background(), "tcp", "blocked.com:443", nil)
	if err == nil {
		t.Fatal("expected error for rejected CONNECT")
	}
	if !strings.Contains(err.Error(), "403") {
		t.Errorf("error = %q, want 403", err)
	}
}

func TestUpstreamProxy_Transport_HTTP(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, "ok")
	}))
	defer backend.Close()

	up, _ := NewUpstreamProxy(backend.URL)

	transport := up.Transport(nil)
	req, _ := http.NewRequest("GET", "http://example.com/test", nil)

	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

func TestWriteProxyProtocolV1_IPv4(t *testing.T) {
	var buf bytes.Buffer
	src := &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 12345}
	dst := &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 8080}

	if err := writeProxyProtocolV1(&buf, src, dst); err != nil {
		t.Fatalf("writeProxyProtocolV1: %v", err)
	}

	got := buf.String()
	want := "PROXY TCP4 192.168.1.1 10.0.0.1 12345 8080\r\n"
	if got != want {
		t.Errorf("header = %q, want %q", got, want)
	}
}

func TestWriteProxyProtocolV1_IPv6(t *testing.T) {
	var buf bytes.Buffer
	src := &net.TCPAddr{IP: net.ParseIP("::1"), Port: 1234}
	dst := &net.TCPAddr{IP: net.ParseIP("::1"), Port: 5678}

	if err := writeProxyProtocolV1(&buf, src, dst); err != nil {
		t.Fatalf("writeProxyProtocolV1: %v", err)
	}

	got := buf.String()
	if !strings.HasPrefix(got, "PROXY TCP6 ") {
		t.Errorf("expected TCP6, got %q", got)
	}
	if !strings.HasSuffix(got, "\r\n") {
		t.Error("missing CRLF")
	}
}

func TestWriteProxyProtocolV2_IPv4(t *testing.T) {
	var buf bytes.Buffer
	src := &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 12345}
	dst := &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 8080}

	if err := writeProxyProtocolV2(&buf, src, dst); err != nil {
		t.Fatalf("writeProxyProtocolV2: %v", err)
	}

	data := buf.Bytes()

	// Check v2 signature
	sig := []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}
	if !bytes.HasPrefix(data, sig) {
		t.Error("missing v2 signature")
	}

	// Version+command byte
	if data[12] != 0x21 {
		t.Errorf("ver_cmd = %02x, want 0x21", data[12])
	}

	// AF_INET + STREAM
	if data[13] != 0x11 {
		t.Errorf("family_proto = %02x, want 0x11", data[13])
	}

	// Address length for IPv4: 12 bytes
	addrLen := binary.BigEndian.Uint16(data[14:16])
	if addrLen != 12 {
		t.Errorf("addr_len = %d, want 12", addrLen)
	}

	// Source IP
	srcIP := net.IP(data[16:20])
	if !srcIP.Equal(net.ParseIP("192.168.1.1")) {
		t.Errorf("src IP = %s, want 192.168.1.1", srcIP)
	}

	// Destination IP
	dstIP := net.IP(data[20:24])
	if !dstIP.Equal(net.ParseIP("10.0.0.1")) {
		t.Errorf("dst IP = %s, want 10.0.0.1", dstIP)
	}

	// Ports
	srcPort := binary.BigEndian.Uint16(data[24:26])
	dstPort := binary.BigEndian.Uint16(data[26:28])
	if srcPort != 12345 {
		t.Errorf("src port = %d, want 12345", srcPort)
	}
	if dstPort != 8080 {
		t.Errorf("dst port = %d, want 8080", dstPort)
	}
}

func TestWriteProxyProtocolV2_IPv6(t *testing.T) {
	var buf bytes.Buffer
	src := &net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 1234}
	dst := &net.TCPAddr{IP: net.ParseIP("2001:db8::2"), Port: 5678}

	if err := writeProxyProtocolV2(&buf, src, dst); err != nil {
		t.Fatalf("writeProxyProtocolV2: %v", err)
	}

	data := buf.Bytes()

	// AF_INET6 + STREAM
	if data[13] != 0x21 {
		t.Errorf("family_proto = %02x, want 0x21", data[13])
	}

	// Address length for IPv6: 36 bytes
	addrLen := binary.BigEndian.Uint16(data[14:16])
	if addrLen != 36 {
		t.Errorf("addr_len = %d, want 36", addrLen)
	}
}

func TestWriteProxyProtocolHeader_InvalidVersion(t *testing.T) {
	var buf bytes.Buffer
	src := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1}
	dst := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 2}

	err := writeProxyProtocolHeader(&buf, 3, src, dst)
	if err == nil {
		t.Fatal("expected error for unsupported version")
	}
}

func TestUpstreamProxy_DialConnect_WithProxyProtocolV1(t *testing.T) {
	var receivedHeader string

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = listener.Close() }()

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()

		reader := bufio.NewReader(conn)
		line, _ := reader.ReadString('\n')
		receivedHeader = line

		req, err := http.ReadRequest(reader)
		if err != nil {
			return
		}

		resp := &http.Response{
			StatusCode: http.StatusOK,
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header:     http.Header{},
			Body:       io.NopCloser(strings.NewReader("")),
		}
		if req.Method == http.MethodConnect {
			_, _ = fmt.Fprintf(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
		} else {
			_ = resp.Write(conn)
		}
	}()

	up := &UpstreamProxy{
		URL:           mustParseURL("http://" + listener.Addr().String()),
		DialTimeout:   5 * time.Second,
		ProxyProtocol: 1,
	}

	clientAddr := &net.TCPAddr{IP: net.ParseIP("10.0.0.50"), Port: 54321}
	conn, err := up.DialConnect(context.Background(), "tcp", "target.com:443", clientAddr)
	if err != nil {
		t.Fatalf("DialConnect: %v", err)
	}
	_ = conn.Close()

	if !strings.HasPrefix(receivedHeader, "PROXY TCP4 10.0.0.50 ") {
		t.Errorf("header = %q, expected PROXY protocol v1", receivedHeader)
	}
}

func TestBufferedConn_Read(t *testing.T) {
	data := "hello world"
	reader := bufio.NewReader(strings.NewReader(data))

	conn := &bufferedConn{
		Conn:   nil,
		reader: reader,
	}

	buf := make([]byte, 5)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if string(buf[:n]) != "hello" {
		t.Errorf("Read = %q, want %q", buf[:n], "hello")
	}
}

func TestExtractHostPort_TCPAddr(t *testing.T) {
	addr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080}
	host, port, err := extractHostPort(addr)
	if err != nil {
		t.Fatalf("extractHostPort: %v", err)
	}
	if host != "127.0.0.1" || port != "8080" {
		t.Errorf("got %s:%s, want 127.0.0.1:8080", host, port)
	}
}

func TestExtractHostPort_StringAddr(t *testing.T) {
	addr := stringAddr("192.168.1.1:9090")
	host, port, err := extractHostPort(addr)
	if err != nil {
		t.Fatalf("extractHostPort: %v", err)
	}
	if host != "192.168.1.1" || port != "9090" {
		t.Errorf("got %s:%s, want 192.168.1.1:9090", host, port)
	}
}

func TestParsePort(t *testing.T) {
	tests := []struct {
		input string
		want  uint16
	}{
		{"0", 0},
		{"80", 80},
		{"443", 443},
		{"65535", 65535},
	}
	for _, tt := range tests {
		if got := parsePort(tt.input); got != tt.want {
			t.Errorf("parsePort(%q) = %d, want %d", tt.input, got, tt.want)
		}
	}
}

type stringAddr string

func (s stringAddr) Network() string { return "tcp" }
func (s stringAddr) String() string  { return string(s) }

func mustParseURL(raw string) *url.URL {
	u, err := url.Parse(raw)
	if err != nil {
		panic(err)
	}
	return u
}
