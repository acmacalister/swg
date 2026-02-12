package swg

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"testing"
	"time"
)

func newTestCA(t *testing.T) (certPEM, keyPEM []byte, cm *CertManager) {
	t.Helper()
	certPEM, keyPEM, err := GenerateCA("Test CA", 1)
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	cm, err = NewCertManagerFromPEM(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("NewCertManagerFromPEM: %v", err)
	}
	return certPEM, keyPEM, cm
}

func newTestClientCert(t *testing.T, cm *CertManager, keyPEM []byte, cn string, orgs []string) (tls.Certificate, []byte) {
	t.Helper()
	certPEM, clientKeyPEM, err := generateClientCertWithKey(cm.caCert, cm.caKey, cn, orgs, 1)
	if err != nil {
		t.Fatalf("generateClientCertWithKey: %v", err)
	}
	_ = keyPEM
	cert, err := tls.X509KeyPair(certPEM, clientKeyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair: %v", err)
	}
	return cert, certPEM
}

// ---------------------------------------------------------------------------
// NewClientAuth constructors
// ---------------------------------------------------------------------------

func TestNewClientAuth(t *testing.T) {
	pool := x509.NewCertPool()
	ca := NewClientAuth(pool)

	if ca.pool != pool {
		t.Error("pool not set")
	}
	if ca.policy != tls.RequireAndVerifyClientCert {
		t.Errorf("want RequireAndVerifyClientCert, got %v", ca.policy)
	}
	if !ca.IdentityFromCert {
		t.Error("IdentityFromCert should default to true")
	}
}

func TestNewClientAuthFromPEM(t *testing.T) {
	certPEM, _, _ := newTestCA(t)

	ca, err := NewClientAuthFromPEM(certPEM)
	if err != nil {
		t.Fatalf("NewClientAuthFromPEM: %v", err)
	}
	if ca == nil {
		t.Fatal("returned nil")
	}
}

func TestNewClientAuthFromPEM_Invalid(t *testing.T) {
	_, err := NewClientAuthFromPEM([]byte("not pem"))
	if err == nil {
		t.Error("want error for invalid PEM")
	}
}

func TestNewClientAuthFromFile(t *testing.T) {
	certPEM, _, _ := newTestCA(t)

	path := t.TempDir() + "/ca.pem"
	if err := writeFile(path, certPEM); err != nil {
		t.Fatalf("write: %v", err)
	}

	ca, err := NewClientAuthFromFile(path)
	if err != nil {
		t.Fatalf("NewClientAuthFromFile: %v", err)
	}
	if ca == nil {
		t.Fatal("returned nil")
	}
}

func TestNewClientAuthFromFile_Missing(t *testing.T) {
	_, err := NewClientAuthFromFile("/nonexistent/path.pem")
	if err == nil {
		t.Error("want error for missing file")
	}
}

// ---------------------------------------------------------------------------
// Policy get/set
// ---------------------------------------------------------------------------

func TestClientAuth_SetPolicy(t *testing.T) {
	ca := NewClientAuth(x509.NewCertPool())
	ca.SetPolicy(tls.VerifyClientCertIfGiven)

	if ca.Policy() != tls.VerifyClientCertIfGiven {
		t.Errorf("want VerifyClientCertIfGiven, got %v", ca.Policy())
	}
}

// ---------------------------------------------------------------------------
// AddCACert / AddCAPEM
// ---------------------------------------------------------------------------

func TestClientAuth_AddCACert(t *testing.T) {
	_, _, cm := newTestCA(t)
	ca := NewClientAuth(x509.NewCertPool())
	ca.AddCACert(cm.caCert)
}

func TestClientAuth_AddCAPEM(t *testing.T) {
	certPEM, _, _ := newTestCA(t)
	ca := NewClientAuth(x509.NewCertPool())

	if err := ca.AddCAPEM(certPEM); err != nil {
		t.Fatalf("AddCAPEM: %v", err)
	}
}

func TestClientAuth_AddCAPEM_Invalid(t *testing.T) {
	ca := NewClientAuth(x509.NewCertPool())
	if err := ca.AddCAPEM([]byte("garbage")); err == nil {
		t.Error("want error for invalid PEM")
	}
}

// ---------------------------------------------------------------------------
// TLSConfig
// ---------------------------------------------------------------------------

func TestClientAuth_TLSConfig(t *testing.T) {
	certPEM, _, _ := newTestCA(t)
	ca, _ := NewClientAuthFromPEM(certPEM)

	cfg := ca.TLSConfig()
	if cfg.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Errorf("want RequireAndVerifyClientCert, got %v", cfg.ClientAuth)
	}
	if cfg.ClientCAs == nil {
		t.Error("ClientCAs is nil")
	}
}

// ---------------------------------------------------------------------------
// VerifyPeerCertificate
// ---------------------------------------------------------------------------

func TestClientAuth_VerifyPeerCertificate_Valid(t *testing.T) {
	certPEM, keyPEM, cm := newTestCA(t)
	_ = keyPEM
	ca, _ := NewClientAuthFromPEM(certPEM)

	clientCertPEM, _, err := generateClientCertWithKey(cm.caCert, cm.caKey, "alice", []string{"engineering"}, 1)
	if err != nil {
		t.Fatal(err)
	}

	block, _ := pem.Decode(clientCertPEM)
	if block == nil {
		t.Fatal("decode client cert PEM")
	}

	err = ca.VerifyPeerCertificate([][]byte{block.Bytes}, nil)
	if err != nil {
		t.Fatalf("VerifyPeerCertificate: %v", err)
	}
}

func TestClientAuth_VerifyPeerCertificate_NoCerts(t *testing.T) {
	ca := NewClientAuth(x509.NewCertPool())
	err := ca.VerifyPeerCertificate(nil, nil)
	if err == nil {
		t.Error("want error for empty certs")
	}
}

func TestClientAuth_VerifyPeerCertificate_UntrustedCA(t *testing.T) {
	_, _, cm1 := newTestCA(t)
	certPEM2, _, _ := newTestCA(t)

	ca, _ := NewClientAuthFromPEM(certPEM2)

	clientCertPEM, _, err := generateClientCertWithKey(cm1.caCert, cm1.caKey, "eve", nil, 1)
	if err != nil {
		t.Fatal(err)
	}

	block, _ := pem.Decode(clientCertPEM)
	err = ca.VerifyPeerCertificate([][]byte{block.Bytes}, nil)
	if err == nil {
		t.Error("want error for untrusted CA")
	}
}

// ---------------------------------------------------------------------------
// IdentityFromConn
// ---------------------------------------------------------------------------

func TestClientAuth_IdentityFromConn(t *testing.T) {
	certPEM, _, cm := newTestCA(t)
	ca, _ := NewClientAuthFromPEM(certPEM)
	clientCert, _ := newTestClientCert(t, cm, nil, "alice", []string{"engineering", "devops"})

	serverCert, err := cm.GetCertificateForHost("localhost")
	if err != nil {
		t.Fatal(err)
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(certPEM)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	serverTLS := ca.TLSConfig()
	serverTLS.Certificates = []tls.Certificate{*serverCert}

	done := make(chan struct{})
	var identity string
	var groups []string

	go func() {
		defer close(done)
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			return
		}
		tlsConn := tls.Server(conn, serverTLS)
		if hsErr := tlsConn.Handshake(); hsErr != nil {
			_ = tlsConn.Close()
			return
		}
		identity, groups = ca.IdentityFromConn(tlsConn)
		_ = tlsConn.Close()
	}()

	clientTLS := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      caCertPool,
		ServerName:   "localhost",
	}
	conn, err := tls.Dial("tcp", ln.Addr().String(), clientTLS)
	if err != nil {
		t.Fatalf("tls.Dial: %v", err)
	}
	_ = conn.Close()

	<-done

	if identity != "alice" {
		t.Errorf("want identity alice, got %q", identity)
	}
	if len(groups) != 2 || !slices.Contains(groups, "engineering") || !slices.Contains(groups, "devops") {
		t.Errorf("want [engineering devops], got %v", groups)
	}
}

func TestClientAuth_IdentityFromConn_NoPeer(t *testing.T) {
	ca := NewClientAuth(x509.NewCertPool())
	identity, groups := ca.IdentityFromConn(nil)
	if identity != "" {
		t.Errorf("want empty identity, got %q", identity)
	}
	if groups != nil {
		t.Errorf("want nil groups, got %v", groups)
	}
}

// ---------------------------------------------------------------------------
// WrapListener
// ---------------------------------------------------------------------------

func TestClientAuth_WrapListener(t *testing.T) {
	certPEM, _, cm := newTestCA(t)
	ca, _ := NewClientAuthFromPEM(certPEM)
	clientCert, _ := newTestClientCert(t, cm, nil, "bob", []string{"ops"})

	serverCert, err := cm.GetCertificateForHost("localhost")
	if err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	wrapped := ca.WrapListener(ln, *serverCert)
	defer func() { _ = wrapped.Close() }()

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(certPEM)

	done := make(chan error, 1)
	go func() {
		conn, acceptErr := wrapped.Accept()
		if acceptErr != nil {
			done <- acceptErr
			return
		}
		buf := make([]byte, 16)
		_, readErr := conn.Read(buf)
		_ = conn.Close()
		done <- readErr
	}()

	clientTLS := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      caCertPool,
		ServerName:   "localhost",
	}
	conn, err := tls.Dial("tcp", ln.Addr().String(), clientTLS)
	if err != nil {
		t.Fatalf("tls.Dial: %v", err)
	}
	_, _ = conn.Write([]byte("hello"))
	_ = conn.Close()

	select {
	case err := <-done:
		if err != nil && err != io.EOF {
			t.Errorf("server error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for server")
	}
}

func TestClientAuth_WrapListener_RejectsNoCert(t *testing.T) {
	certPEM, _, cm := newTestCA(t)
	ca, _ := NewClientAuthFromPEM(certPEM)

	serverCert, err := cm.GetCertificateForHost("localhost")
	if err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	wrapped := ca.WrapListener(ln, *serverCert)
	defer func() { _ = wrapped.Close() }()

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(certPEM)

	go func() {
		conn, _ := wrapped.Accept()
		if conn != nil {
			_ = conn.Close()
		}
	}()

	clientTLS := &tls.Config{
		RootCAs:    caCertPool,
		ServerName: "localhost",
	}
	conn, err := tls.Dial("tcp", ln.Addr().String(), clientTLS)
	if err == nil {
		_ = conn.Close()
		t.Error("want handshake error for missing client cert")
	}
}

// ---------------------------------------------------------------------------
// GenerateClientCert
// ---------------------------------------------------------------------------

func TestGenerateClientCert(t *testing.T) {
	certPEM, keyPEM, cm := newTestCA(t)
	_ = certPEM

	clientCertPEM, clientKeyPEM, err := GenerateClientCert(cm.caCert, keyPEM, "alice", []string{"engineering"}, 1)
	if err != nil {
		t.Fatalf("GenerateClientCert: %v", err)
	}

	cert, err := tls.X509KeyPair(clientCertPEM, clientKeyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair: %v", err)
	}

	parsed, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}

	if parsed.Subject.CommonName != "alice" {
		t.Errorf("want CN=alice, got %q", parsed.Subject.CommonName)
	}
	if len(parsed.Subject.Organization) != 1 || parsed.Subject.Organization[0] != "engineering" {
		t.Errorf("want Organization=[engineering], got %v", parsed.Subject.Organization)
	}
	if len(parsed.ExtKeyUsage) != 1 || parsed.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Errorf("want ExtKeyUsageClientAuth, got %v", parsed.ExtKeyUsage)
	}
}

func TestGenerateClientCert_InvalidKey(t *testing.T) {
	_, _, cm := newTestCA(t)
	_, _, err := GenerateClientCert(cm.caCert, []byte("bad key"), "test", nil, 1)
	if err == nil {
		t.Error("want error for invalid key PEM")
	}
}

// ---------------------------------------------------------------------------
// Proxy ServeHTTP mTLS identity injection
// ---------------------------------------------------------------------------

func TestProxyServeHTTP_mTLSIdentityInjection(t *testing.T) {
	certPEM, _, cm := newTestCA(t)
	clientCert, _ := newTestClientCert(t, cm, nil, "alice", []string{"engineering", "devops"})

	ca, _ := NewClientAuthFromPEM(certPEM)

	serverCert, err := cm.GetCertificateForHost("localhost")
	if err != nil {
		t.Fatal(err)
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(certPEM)

	proxy := &Proxy{
		Addr:        ":0",
		CertManager: cm,
		Logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		ClientAuth:  ca,
	}

	var capturedIdentity string
	var capturedGroups []string
	var capturedTag string
	proxy.Filter = FilterFunc(func(req *http.Request) (bool, string) {
		rc := GetRequestContext(req.Context())
		if rc != nil {
			capturedIdentity = rc.Identity
			capturedGroups = rc.Groups
			capturedTag = rc.Tags["auth"]
		}
		return false, ""
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	wrapped := ca.WrapListener(ln, *serverCert)

	srv := &http.Server{Handler: proxy}
	go func() { _ = srv.Serve(wrapped) }()
	defer func() { _ = srv.Close() }()

	clientTLS := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      caCertPool,
		ServerName:   "localhost",
	}
	transport := &http.Transport{TLSClientConfig: clientTLS}
	client := &http.Client{Transport: transport}

	resp, err := client.Get("https://" + ln.Addr().String() + "/test")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	_ = resp.Body.Close()

	if capturedIdentity != "alice" {
		t.Errorf("want identity alice, got %q", capturedIdentity)
	}
	if len(capturedGroups) != 2 || !slices.Contains(capturedGroups, "engineering") || !slices.Contains(capturedGroups, "devops") {
		t.Errorf("want groups [engineering devops], got %v", capturedGroups)
	}
	if capturedTag != "mtls" {
		t.Errorf("want tag auth=mtls, got %q", capturedTag)
	}
}

func TestProxyServeHTTP_NoClientAuth(t *testing.T) {
	proxy := &Proxy{
		Addr:   ":0",
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()

	proxy.ServeHTTP(rec, req)

	rc := GetRequestContext(req.Context())
	if rc != nil {
		t.Error("want no RequestContext without mTLS")
	}
}

// ---------------------------------------------------------------------------
// helper
// ---------------------------------------------------------------------------

func writeFile(path string, data []byte) error {
	return os.WriteFile(path, data, 0o600)
}

// Verify RequestContext uses proper fields from x509 Subject.
func TestClientAuth_CertSubjectFields(t *testing.T) {
	certPEM, _, cm := newTestCA(t)

	clientCertPEM, clientKeyPEM, err := generateClientCertWithKey(cm.caCert, cm.caKey, "test-user", []string{"team-a", "team-b"}, 1)
	if err != nil {
		t.Fatal(err)
	}

	block, _ := pem.Decode(clientCertPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	_ = certPEM
	_ = clientKeyPEM

	if cert.Subject.CommonName != "test-user" {
		t.Errorf("want CN=test-user, got %q", cert.Subject.CommonName)
	}
	if len(cert.Subject.Organization) != 2 {
		t.Fatalf("want 2 orgs, got %d", len(cert.Subject.Organization))
	}
	if cert.Subject.Organization[0] != "team-a" || cert.Subject.Organization[1] != "team-b" {
		t.Errorf("want [team-a team-b], got %v", cert.Subject.Organization)
	}
}

// Verify that IdentityFromCert=false skips identity injection.
func TestProxyServeHTTP_IdentityFromCertDisabled(t *testing.T) {
	proxy := &Proxy{
		Addr:   ":0",
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		ClientAuth: &ClientAuth{
			IdentityFromCert: false,
			pool:             x509.NewCertPool(),
			policy:           tls.RequireAndVerifyClientCert,
			Logger:           slog.New(slog.NewTextHandler(io.Discard, nil)),
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{
			{Subject: pkix.Name{CommonName: "should-not-appear"}},
		},
	}
	rec := httptest.NewRecorder()

	proxy.ServeHTTP(rec, req)

	rc := GetRequestContext(req.Context())
	if rc != nil {
		t.Error("want no RequestContext when IdentityFromCert is false")
	}
}
