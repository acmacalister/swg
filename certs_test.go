package swg

import (
	"crypto/tls"
	"crypto/x509"
	"testing"
)

func TestGenerateCA(t *testing.T) {
	certPEM, keyPEM, err := GenerateCA("Test Org", 1)
	if err != nil {
		t.Fatalf("GenerateCA failed: %v", err)
	}

	if len(certPEM) == 0 {
		t.Error("certPEM is empty")
	}
	if len(keyPEM) == 0 {
		t.Error("keyPEM is empty")
	}

	// Verify the cert is valid PEM and parses correctly
	cm, err := NewCertManagerFromPEM(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("NewCertManagerFromPEM failed: %v", err)
	}

	if cm.caCert == nil {
		t.Error("caCert is nil")
	}
	if cm.caKey == nil {
		t.Error("caKey is nil")
	}

	// Verify CA properties
	if !cm.caCert.IsCA {
		t.Error("certificate is not marked as CA")
	}
	if cm.caCert.Subject.Organization[0] != "Test Org" {
		t.Errorf("unexpected organization: %v", cm.caCert.Subject.Organization)
	}
}

func TestCertManagerGetCertificateForHost(t *testing.T) {
	// Generate test CA
	certPEM, keyPEM, err := GenerateCA("Test CA", 1)
	if err != nil {
		t.Fatalf("GenerateCA failed: %v", err)
	}

	cm, err := NewCertManagerFromPEM(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("NewCertManagerFromPEM failed: %v", err)
	}

	tests := []struct {
		name string
		host string
	}{
		{"simple domain", "example.com"},
		{"subdomain", "www.example.com"},
		{"ip address", "192.168.1.1"},
		{"localhost", "localhost"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert, err := cm.GetCertificateForHost(tt.host)
			if err != nil {
				t.Fatalf("GetCertificateForHost(%q) failed: %v", tt.host, err)
			}

			if cert == nil {
				t.Fatal("returned certificate is nil")
			}

			if len(cert.Certificate) == 0 {
				t.Error("certificate chain is empty")
			}

			// Parse and verify the certificate
			parsed, err := x509.ParseCertificate(cert.Certificate[0])
			if err != nil {
				t.Fatalf("failed to parse generated certificate: %v", err)
			}

			// Verify it's signed by our CA
			roots := x509.NewCertPool()
			roots.AddCert(cm.caCert)

			_, err = parsed.Verify(x509.VerifyOptions{
				Roots: roots,
			})
			if err != nil {
				t.Errorf("certificate verification failed: %v", err)
			}
		})
	}
}

func TestCertManagerCaching(t *testing.T) {
	certPEM, keyPEM, err := GenerateCA("Test CA", 1)
	if err != nil {
		t.Fatalf("GenerateCA failed: %v", err)
	}

	cm, err := NewCertManagerFromPEM(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("NewCertManagerFromPEM failed: %v", err)
	}

	host := "cached.example.com"

	// Get certificate first time
	cert1, err := cm.GetCertificateForHost(host)
	if err != nil {
		t.Fatalf("first GetCertificateForHost failed: %v", err)
	}

	// Get certificate second time - should be cached
	cert2, err := cm.GetCertificateForHost(host)
	if err != nil {
		t.Fatalf("second GetCertificateForHost failed: %v", err)
	}

	// Should be the exact same pointer (cached)
	if cert1 != cert2 {
		t.Error("certificate was not cached - got different pointers")
	}
}

func TestCertManagerGetCertificate(t *testing.T) {
	certPEM, keyPEM, err := GenerateCA("Test CA", 1)
	if err != nil {
		t.Fatalf("GenerateCA failed: %v", err)
	}

	cm, err := NewCertManagerFromPEM(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("NewCertManagerFromPEM failed: %v", err)
	}

	// Test with SNI
	hello := &tls.ClientHelloInfo{
		ServerName: "sni.example.com",
	}

	cert, err := cm.GetCertificate(hello)
	if err != nil {
		t.Fatalf("GetCertificate failed: %v", err)
	}

	if cert == nil {
		t.Fatal("returned certificate is nil")
	}

	// Test without SNI - should fail
	helloNoSNI := &tls.ClientHelloInfo{}
	_, err = cm.GetCertificate(helloNoSNI)
	if err == nil {
		t.Error("expected error when no SNI provided")
	}
}

func TestNewCertManagerFromPEM_InvalidCert(t *testing.T) {
	validCert, validKey, _ := GenerateCA("Test", 1)

	tests := []struct {
		name    string
		cert    []byte
		key     []byte
		wantErr bool
	}{
		{"invalid cert PEM", []byte("not a cert"), validKey, true},
		{"invalid key PEM", validCert, []byte("not a key"), true},
		{"empty cert", []byte{}, validKey, true},
		{"empty key", validCert, []byte{}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewCertManagerFromPEM(tt.cert, tt.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewCertManagerFromPEM() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
