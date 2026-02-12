package swg

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"sync"
	"time"
)

// CertRotator wraps a CertManager and adds the ability to atomically swap
// the underlying CA certificate and key at runtime, e.g. from a SIGHUP
// handler or periodic refresh. All in-flight TLS handshakes continue using
// the old CA; new connections pick up the rotated CA immediately.
//
// Host-certificate caches are flushed on every rotation because the old
// certs were signed by the previous CA.
type CertRotator struct {
	mu sync.RWMutex
	cm *CertManager

	certPath string
	keyPath  string

	// OnRotate is called after a successful rotation with the new CA subject.
	OnRotate func(subject string)

	// OnError is called when a rotation attempt fails.
	OnError func(err error)
}

// NewCertRotator creates a CertRotator that can reload the CA from disk.
func NewCertRotator(cm *CertManager, certPath, keyPath string) *CertRotator {
	return &CertRotator{
		cm:       cm,
		certPath: certPath,
		keyPath:  keyPath,
	}
}

// CertManager returns the current CertManager. The caller must not hold a
// reference across a rotation boundary — call this each time you need it.
func (cr *CertRotator) CertManager() *CertManager {
	cr.mu.RLock()
	defer cr.mu.RUnlock()
	return cr.cm
}

// Rotate reloads the CA certificate and key from the paths configured at
// creation time. On success the internal CertManager is swapped atomically
// and the host-cert cache is cleared. Returns the new CertManager.
func (cr *CertRotator) Rotate() (*CertManager, error) {
	newCM, err := NewCertManager(cr.certPath, cr.keyPath)
	if err != nil {
		if cr.OnError != nil {
			cr.OnError(err)
		}
		return nil, fmt.Errorf("rotate CA: %w", err)
	}

	cr.mu.Lock()
	cr.cm = newCM
	cr.mu.Unlock()

	if cr.OnRotate != nil {
		cr.OnRotate(newCM.caCert.Subject.CommonName)
	}

	return newCM, nil
}

// RotateFromPEM reloads the CA from in-memory PEM bytes.
func (cr *CertRotator) RotateFromPEM(certPEM, keyPEM []byte) (*CertManager, error) {
	newCM, err := NewCertManagerFromPEM(certPEM, keyPEM)
	if err != nil {
		if cr.OnError != nil {
			cr.OnError(err)
		}
		return nil, fmt.Errorf("rotate CA from PEM: %w", err)
	}

	cr.mu.Lock()
	cr.cm = newCM
	cr.mu.Unlock()

	if cr.OnRotate != nil {
		cr.OnRotate(newCM.caCert.Subject.CommonName)
	}

	return newCM, nil
}

// GetCertificate implements the tls.Config.GetCertificate callback, delegating
// to the current CertManager. This should be used instead of cm.GetCertificate
// when certificate rotation is enabled.
func (cr *CertRotator) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	cr.mu.RLock()
	cm := cr.cm
	cr.mu.RUnlock()
	return cm.GetCertificate(hello)
}

// GetCertificateForHost generates (or retrieves from cache) a host certificate
// signed by the current CA.
func (cr *CertRotator) GetCertificateForHost(host string) (*tls.Certificate, error) {
	cr.mu.RLock()
	cm := cr.cm
	cr.mu.RUnlock()
	return cm.GetCertificateForHost(host)
}

// CACert returns the current CA certificate.
func (cr *CertRotator) CACert() *x509.Certificate {
	cr.mu.RLock()
	defer cr.mu.RUnlock()
	return cr.cm.caCert
}

// CAKey returns the current CA private key.
func (cr *CertRotator) CAKey() *rsa.PrivateKey {
	cr.mu.RLock()
	defer cr.mu.RUnlock()
	return cr.cm.caKey
}

// CacheSize returns the number of cached host certificates.
func (cr *CertRotator) CacheSize() int {
	cr.mu.RLock()
	cm := cr.cm
	cr.mu.RUnlock()
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return len(cm.cache)
}

// WatchCAFiles watches the CA cert and key files for changes and
// automatically rotates when they are modified. Returns a cancel function.
// This uses a simple polling approach; for production use consider
// fsnotify or similar.
func (cr *CertRotator) WatchCAFiles(interval func() <-chan time.Time) func() {
	done := make(chan struct{})

	var lastCertMod, lastKeyMod time.Time
	if info, err := os.Stat(cr.certPath); err == nil {
		lastCertMod = info.ModTime()
	}
	if info, err := os.Stat(cr.keyPath); err == nil {
		lastKeyMod = info.ModTime()
	}

	go func() {
		for {
			select {
			case <-done:
				return
			case <-interval():
				changed := false

				if info, err := os.Stat(cr.certPath); err == nil {
					if info.ModTime().After(lastCertMod) {
						lastCertMod = info.ModTime()
						changed = true
					}
				}

				if info, err := os.Stat(cr.keyPath); err == nil {
					if info.ModTime().After(lastKeyMod) {
						lastKeyMod = info.ModTime()
						changed = true
					}
				}

				if changed {
					_, _ = cr.Rotate()
				}
			}
		}
	}()

	return func() { close(done) }
}
