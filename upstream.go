package swg

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"
)

// UpstreamProxy configures forwarding through a parent proxy.
// Both HTTP CONNECT proxies and SOCKS-style chaining are supported via
// the standard CONNECT tunnel method.
type UpstreamProxy struct {
	// URL is the upstream proxy address (e.g., "http://proxy.corp:3128").
	URL *url.URL

	// Auth is optional basic-auth credentials for the upstream proxy.
	Auth *UpstreamAuth

	// TLSConfig for connecting to TLS-enabled upstream proxies (optional).
	TLSConfig *tls.Config

	// DialTimeout is the timeout for establishing a connection to the upstream proxy.
	// Defaults to 10 seconds.
	DialTimeout time.Duration

	// ProxyProtocol enables sending a PROXY protocol header (v1 or v2) when
	// connecting to the upstream proxy. This preserves the original client address.
	// 0 = disabled, 1 = v1 (text), 2 = v2 (binary).
	ProxyProtocol int
}

// UpstreamAuth holds basic-auth credentials for an upstream proxy.
type UpstreamAuth struct {
	Username string
	Password string
}

// NewUpstreamProxy creates an UpstreamProxy from a URL string.
func NewUpstreamProxy(rawURL string) (*UpstreamProxy, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("parse upstream proxy URL: %w", err)
	}

	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("unsupported upstream proxy scheme: %s", u.Scheme)
	}

	up := &UpstreamProxy{
		URL:         u,
		DialTimeout: 10 * time.Second,
	}

	if u.User != nil {
		pass, _ := u.User.Password()
		up.Auth = &UpstreamAuth{
			Username: u.User.Username(),
			Password: pass,
		}
	}

	return up, nil
}

// Transport returns an http.RoundTripper that forwards requests through
// the upstream proxy. For HTTPS requests, it establishes a CONNECT tunnel.
func (up *UpstreamProxy) Transport(base http.RoundTripper) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	return &upstreamTransport{
		upstream: up,
		base:     base,
	}
}

// DialConnect establishes a CONNECT tunnel through the upstream proxy to
// the given target address. This is used for HTTPS proxy chaining where
// the downstream proxy needs a raw TCP tunnel to the target.
func (up *UpstreamProxy) DialConnect(ctx context.Context, network, addr string, clientAddr net.Addr) (net.Conn, error) {
	timeout := up.DialTimeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}

	dialer := &net.Dialer{Timeout: timeout}

	host := up.URL.Host
	if _, _, err := net.SplitHostPort(host); err != nil {
		if up.URL.Scheme == "https" {
			host = host + ":443"
		} else {
			host = host + ":3128"
		}
	}

	var conn net.Conn
	var err error

	if up.URL.Scheme == "https" {
		tlsCfg := up.TLSConfig
		if tlsCfg == nil {
			tlsCfg = &tls.Config{}
		}
		if tlsCfg.ServerName == "" {
			h, _, _ := net.SplitHostPort(host)
			tlsCfg = tlsCfg.Clone()
			tlsCfg.ServerName = h
		}
		conn, err = tls.DialWithDialer(&net.Dialer{Timeout: timeout}, network, host, tlsCfg)
	} else {
		conn, err = dialer.DialContext(ctx, network, host)
	}
	if err != nil {
		return nil, fmt.Errorf("dial upstream proxy: %w", err)
	}

	if up.ProxyProtocol > 0 && clientAddr != nil {
		if err := writeProxyProtocolHeader(conn, up.ProxyProtocol, clientAddr, conn.LocalAddr()); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("write PROXY protocol header: %w", err)
		}
	}

	connectReq := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: addr},
		Host:   addr,
		Header: make(http.Header),
	}

	if up.Auth != nil {
		connectReq.Header.Set("Proxy-Authorization", basicAuth(up.Auth.Username, up.Auth.Password))
	}

	if err := connectReq.Write(conn); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("write CONNECT request: %w", err)
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, connectReq)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("read CONNECT response: %w", err)
	}
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_ = conn.Close()
		return nil, fmt.Errorf("upstream CONNECT returned %d", resp.StatusCode)
	}

	if br.Buffered() > 0 {
		return &bufferedConn{Conn: conn, reader: br}, nil
	}
	return conn, nil
}

type upstreamTransport struct {
	upstream *UpstreamProxy
	base     http.RoundTripper
}

func (t *upstreamTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme == "http" {
		proxyReq := req.Clone(req.Context())
		proxyReq.URL = &url.URL{
			Scheme:   t.upstream.URL.Scheme,
			Host:     t.upstream.URL.Host,
			Path:     req.URL.String(),
			RawQuery: "",
		}
		proxyReq.RequestURI = req.URL.String()
		proxyReq.Host = req.Host

		if t.upstream.Auth != nil {
			proxyReq.Header.Set("Proxy-Authorization", basicAuth(t.upstream.Auth.Username, t.upstream.Auth.Password))
		}

		return t.base.RoundTrip(proxyReq)
	}

	return t.base.RoundTrip(req)
}

// bufferedConn wraps a net.Conn with buffered data that was read during
// the CONNECT handshake but not yet consumed.
type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(b []byte) (int, error) {
	return c.reader.Read(b)
}

// writeProxyProtocolHeader writes a PROXY protocol header (v1 or v2) to the connection.
func writeProxyProtocolHeader(w io.Writer, version int, srcAddr, dstAddr net.Addr) error {
	switch version {
	case 1:
		return writeProxyProtocolV1(w, srcAddr, dstAddr)
	case 2:
		return writeProxyProtocolV2(w, srcAddr, dstAddr)
	default:
		return fmt.Errorf("unsupported PROXY protocol version: %d", version)
	}
}

// writeProxyProtocolV1 writes a PROXY protocol v1 (text) header.
// Format: "PROXY TCP4 <srcIP> <dstIP> <srcPort> <dstPort>\r\n"
func writeProxyProtocolV1(w io.Writer, srcAddr, dstAddr net.Addr) error {
	srcHost, srcPort, err := extractHostPort(srcAddr)
	if err != nil {
		return fmt.Errorf("parse source address: %w", err)
	}

	dstHost, dstPort, err := extractHostPort(dstAddr)
	if err != nil {
		return fmt.Errorf("parse destination address: %w", err)
	}

	srcIP := net.ParseIP(srcHost)
	family := "TCP4"
	if srcIP != nil && srcIP.To4() == nil {
		family = "TCP6"
	}

	header := fmt.Sprintf("PROXY %s %s %s %s %s\r\n", family, srcHost, dstHost, srcPort, dstPort)
	_, err = io.WriteString(w, header)
	return err
}

// writeProxyProtocolV2 writes a PROXY protocol v2 (binary) header.
func writeProxyProtocolV2(w io.Writer, srcAddr, dstAddr net.Addr) error {
	srcHost, srcPort, err := extractHostPort(srcAddr)
	if err != nil {
		return fmt.Errorf("parse source address: %w", err)
	}

	dstHost, dstPort, err := extractHostPort(dstAddr)
	if err != nil {
		return fmt.Errorf("parse destination address: %w", err)
	}

	srcIP := net.ParseIP(srcHost)
	dstIP := net.ParseIP(dstHost)
	if srcIP == nil || dstIP == nil {
		return fmt.Errorf("invalid IP addresses: src=%s dst=%s", srcHost, dstHost)
	}

	// v2 signature
	sig := []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}

	// Version (2) + command (PROXY = 1)
	verCmd := byte(0x21)

	var familyProto byte
	var addrBlock []byte

	srcPortInt := parsePort(srcPort)
	dstPortInt := parsePort(dstPort)

	if srcIP.To4() != nil && dstIP.To4() != nil {
		familyProto = 0x11 // AF_INET + STREAM
		addrBlock = make([]byte, 12)
		copy(addrBlock[0:4], srcIP.To4())
		copy(addrBlock[4:8], dstIP.To4())
		binary.BigEndian.PutUint16(addrBlock[8:10], srcPortInt)
		binary.BigEndian.PutUint16(addrBlock[10:12], dstPortInt)
	} else {
		familyProto = 0x21 // AF_INET6 + STREAM
		addrBlock = make([]byte, 36)
		copy(addrBlock[0:16], srcIP.To16())
		copy(addrBlock[16:32], dstIP.To16())
		binary.BigEndian.PutUint16(addrBlock[32:34], srcPortInt)
		binary.BigEndian.PutUint16(addrBlock[34:36], dstPortInt)
	}

	addrLen := make([]byte, 2)
	binary.BigEndian.PutUint16(addrLen, uint16(len(addrBlock)))

	buf := make([]byte, 0, len(sig)+4+len(addrBlock))
	buf = append(buf, sig...)
	buf = append(buf, verCmd, familyProto)
	buf = append(buf, addrLen...)
	buf = append(buf, addrBlock...)

	_, err = w.Write(buf)
	return err
}

func extractHostPort(addr net.Addr) (string, string, error) {
	switch a := addr.(type) {
	case *net.TCPAddr:
		return a.IP.String(), fmt.Sprintf("%d", a.Port), nil
	default:
		host, port, err := net.SplitHostPort(addr.String())
		if err != nil {
			return "", "", err
		}
		return host, port, nil
	}
}

func parsePort(s string) uint16 {
	var port uint16
	for _, c := range s {
		port = port*10 + uint16(c-'0')
	}
	return port
}

func basicAuth(username, password string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(username+":"+password))
}
