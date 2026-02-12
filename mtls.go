package swg

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"os"
	"sync"
	"time"
)

// ClientAuth configures mutual TLS (mTLS) client certificate authentication
// for the proxy listener. When enabled, clients must present a valid TLS
// certificate signed by one of the trusted client CAs to use the proxy.
//
// The proxy listener is wrapped with TLS so that the initial connection
// requires a client certificate. The mTLS handshake happens before any
// HTTP traffic, meaning unauthenticated clients cannot even send a
// CONNECT request.
//
// ClientAuth integrates with the [PolicyEngine] identity system: when
// [ClientAuth.IdentityFromCert] is true, the certificate's Common Name
// is injected as the client identity and the certificate's Organization
// fields are used as group memberships. This populates
// [RequestContext.Identity] and [RequestContext.Groups] for downstream
// policy decisions.
type ClientAuth struct {
	mu     sync.RWMutex
	pool   *x509.CertPool
	policy tls.ClientAuthType

	// IdentityFromCert controls whether the client certificate's subject
	// is used for identity resolution. When true, the certificate's
	// CommonName populates [RequestContext.Identity] and the Organization
	// fields populate [RequestContext.Groups]. This overrides the
	// PolicyEngine's IdentityResolver for mTLS-authenticated clients.
	IdentityFromCert bool

	// Logger for client auth events.
	Logger *slog.Logger
}

// NewClientAuth creates a ClientAuth that requires and verifies client
// certificates against the provided CA certificate pool.
func NewClientAuth(pool *x509.CertPool) *ClientAuth {
	return &ClientAuth{
		pool:             pool,
		policy:           tls.RequireAndVerifyClientCert,
		IdentityFromCert: true,
		Logger:           slog.Default(),
	}
}

// NewClientAuthFromFile creates a ClientAuth by loading a PEM-encoded CA
// certificate bundle from the given file path.
func NewClientAuthFromFile(path string) (*ClientAuth, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read client CA: %w", err)
	}
	return NewClientAuthFromPEM(data)
}

// NewClientAuthFromPEM creates a ClientAuth from PEM-encoded CA certificates.
// Multiple certificates may be concatenated in the PEM data.
func NewClientAuthFromPEM(pemData []byte) (*ClientAuth, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemData) {
		return nil, fmt.Errorf("no valid certificates found in PEM data")
	}
	return NewClientAuth(pool), nil
}

// SetPolicy sets the TLS client auth policy. The default is
// [tls.RequireAndVerifyClientCert]. Use [tls.VerifyClientCertIfGiven]
// for optional mTLS where unauthenticated clients are still allowed.
func (ca *ClientAuth) SetPolicy(policy tls.ClientAuthType) {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	ca.policy = policy
}

// Policy returns the current TLS client auth policy.
func (ca *ClientAuth) Policy() tls.ClientAuthType {
	ca.mu.RLock()
	defer ca.mu.RUnlock()
	return ca.policy
}

// AddCACert adds a CA certificate to the trusted pool.
// This is safe for concurrent use.
func (ca *ClientAuth) AddCACert(cert *x509.Certificate) {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	ca.pool.AddCert(cert)
}

// AddCAPEM appends PEM-encoded CA certificates to the trusted pool.
// Returns an error if no valid certificates are found.
func (ca *ClientAuth) AddCAPEM(pemData []byte) error {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	if !ca.pool.AppendCertsFromPEM(pemData) {
		return fmt.Errorf("no valid certificates found in PEM data")
	}
	return nil
}

// TLSConfig returns a [tls.Config] suitable for wrapping the proxy listener.
// The returned config requires client certificates verified against the
// trusted CA pool.
func (ca *ClientAuth) TLSConfig() *tls.Config {
	ca.mu.RLock()
	defer ca.mu.RUnlock()
	return &tls.Config{
		ClientAuth: ca.policy,
		ClientCAs:  ca.pool,
	}
}

// WrapListener wraps a [net.Listener] with TLS using the ClientAuth
// configuration. The returned listener performs TLS handshakes with
// client certificate verification on every accepted connection.
//
// The serverCert is the proxy's own TLS certificate presented to clients.
// For self-signed proxy deployments, generate one with [GenerateCA] or use
// the proxy's existing [CertManager] CA.
func (ca *ClientAuth) WrapListener(inner net.Listener, serverCert tls.Certificate) net.Listener {
	tlsCfg := ca.TLSConfig()
	tlsCfg.Certificates = []tls.Certificate{serverCert}
	return tls.NewListener(inner, tlsCfg)
}

// VerifyPeerCertificate returns a function suitable for
// [tls.Config.VerifyPeerCertificate] that checks the raw client
// certificate against the trusted CA pool. This is useful when
// integrating with custom TLS configurations.
func (ca *ClientAuth) VerifyPeerCertificate(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	if len(rawCerts) == 0 {
		return fmt.Errorf("mtls: no client certificate provided")
	}

	ca.mu.RLock()
	pool := ca.pool
	ca.mu.RUnlock()

	cert, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return fmt.Errorf("mtls: parse client certificate: %w", err)
	}

	opts := x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	if _, err := cert.Verify(opts); err != nil {
		return fmt.Errorf("mtls: verify client certificate: %w", err)
	}

	return nil
}

// IdentityFromConn extracts client identity from a TLS connection's
// peer certificate. Returns the CommonName as identity and the
// Organization fields as groups. If the connection has no verified
// peer certificates, returns empty strings.
func (ca *ClientAuth) IdentityFromConn(conn *tls.Conn) (identity string, groups []string) {
	if conn == nil {
		return "", nil
	}
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return "", nil
	}
	cert := state.PeerCertificates[0]
	return cert.Subject.CommonName, cert.Subject.Organization
}

// GenerateClientCert generates a client certificate signed by the given CA.
// The certificate includes the [x509.ExtKeyUsageClientAuth] extended key
// usage and is valid for the specified number of years.
//
// This is a convenience function for testing and development. Production
// deployments should use a proper PKI or certificate authority.
func GenerateClientCert(caCert *x509.Certificate, caKeyPEM []byte, cn string, orgs []string, validYears int) (certPEM, keyPEM []byte, err error) {
	keyBlock, _ := pem.Decode(caKeyPEM)
	if keyBlock == nil {
		return nil, nil, fmt.Errorf("failed to decode CA key PEM")
	}

	caKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		key, err2 := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if err2 != nil {
			return nil, nil, fmt.Errorf("parse CA key: %w (also tried PKCS8: %v)", err, err2)
		}
		var ok bool
		caKey, ok = key.(*rsa.PrivateKey)
		if !ok {
			return nil, nil, fmt.Errorf("CA key is not RSA")
		}
	}

	return generateClientCertWithKey(caCert, caKey, cn, orgs, validYears)
}

// generateClientCertWithKey creates a client certificate using parsed key.
func generateClientCertWithKey(caCert *x509.Certificate, caKey *rsa.PrivateKey, cn string, orgs []string, validYears int) (certPEM, keyPEM []byte, err error) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("generate client key: %w", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("generate serial: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: orgs,
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Duration(validYears) * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &privKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, fmt.Errorf("create client certificate: %w", err)
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privKey)})

	return certPEM, keyPEM, nil
}
