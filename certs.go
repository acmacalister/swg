package swg

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"sync"
	"time"
)

// CertManager manages CA and per-host certificate generation for MITM proxying.
type CertManager struct {
	caCert *x509.Certificate
	caKey  *rsa.PrivateKey

	// Cache generated certs to avoid regenerating for same host
	mu    sync.RWMutex
	cache map[string]*tls.Certificate
}

// NewCertManager creates a CertManager from existing CA certificate and key files.
func NewCertManager(caCertPath, caKeyPath string) (*CertManager, error) {
	caCertPEM, err := os.ReadFile(caCertPath)
	if err != nil {
		return nil, fmt.Errorf("read CA cert: %w", err)
	}

	caKeyPEM, err := os.ReadFile(caKeyPath)
	if err != nil {
		return nil, fmt.Errorf("read CA key: %w", err)
	}

	return NewCertManagerFromPEM(caCertPEM, caKeyPEM)
}

// NewCertManagerFromPEM creates a CertManager from PEM-encoded CA cert and key.
func NewCertManagerFromPEM(caCertPEM, caKeyPEM []byte) (*CertManager, error) {
	certBlock, _ := pem.Decode(caCertPEM)
	if certBlock == nil {
		return nil, fmt.Errorf("failed to decode CA certificate PEM")
	}

	caCert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA cert: %w", err)
	}

	keyBlock, _ := pem.Decode(caKeyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("failed to decode CA key PEM")
	}

	caKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		// Try PKCS8 format
		key, err2 := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if err2 != nil {
			return nil, fmt.Errorf("parse CA key: %w (also tried PKCS8: %v)", err, err2)
		}
		var ok bool
		caKey, ok = key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("CA key is not RSA")
		}
	}

	return &CertManager{
		caCert: caCert,
		caKey:  caKey,
		cache:  make(map[string]*tls.Certificate),
	}, nil
}

// GetCertificate returns a TLS certificate for the given host, generating one if needed.
// This is suitable for use as tls.Config.GetCertificate.
func (cm *CertManager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	host := hello.ServerName
	if host == "" {
		return nil, fmt.Errorf("no SNI provided")
	}
	return cm.GetCertificateForHost(host)
}

// GetCertificateForHost returns a TLS certificate for the given hostname.
func (cm *CertManager) GetCertificateForHost(host string) (*tls.Certificate, error) {
	// Check cache first
	cm.mu.RLock()
	cert, ok := cm.cache[host]
	cm.mu.RUnlock()
	if ok {
		return cert, nil
	}

	// Generate new cert
	cm.mu.Lock()
	defer cm.mu.Unlock()

	// Double-check after acquiring write lock
	if cert, ok := cm.cache[host]; ok {
		return cert, nil
	}

	cert, err := cm.generateCert(host)
	if err != nil {
		return nil, err
	}

	cm.cache[host] = cert
	return cert, nil
}

func (cm *CertManager) generateCert(host string) (*tls.Certificate, error) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate serial: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   host,
			Organization: []string{"SWG Proxy"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour * 365), // 1 year
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Add host as SAN
	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{host}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, cm.caCert, &privKey.PublicKey, cm.caKey)
	if err != nil {
		return nil, fmt.Errorf("create certificate: %w", err)
	}

	return &tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  privKey,
	}, nil
}

// GenerateCA generates a new CA certificate and private key.
// Returns PEM-encoded certificate and key.
func GenerateCA(org string, validYears int) (certPEM, keyPEM []byte, err error) {
	privKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, fmt.Errorf("generate CA key: %w", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("generate serial: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   org + " Root CA",
			Organization: []string{org},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Duration(validYears) * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	if err != nil {
		return nil, nil, fmt.Errorf("create CA certificate: %w", err)
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privKey)})

	return certPEM, keyPEM, nil
}
