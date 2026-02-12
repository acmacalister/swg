package swg

import (
	"crypto/tls"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestCertRotator_Rotate(t *testing.T) {
	certPEM, keyPEM, err := GenerateCA("OrigCA", 1)
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}

	cm, err := NewCertManagerFromPEM(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("NewCertManagerFromPEM: %v", err)
	}

	dir := t.TempDir()
	certPath := dir + "/ca.crt"
	keyPath := dir + "/ca.key"
	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		t.Fatal(err)
	}

	cr := NewCertRotator(cm, certPath, keyPath)

	origSubject := cr.CACert().Subject.CommonName

	newCertPEM, newKeyPEM, _ := GenerateCA("NewCA", 1)
	if err := os.WriteFile(certPath, newCertPEM, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, newKeyPEM, 0600); err != nil {
		t.Fatal(err)
	}

	newCM, err := cr.Rotate()
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}

	if newCM == cm {
		t.Error("expected new CertManager")
	}

	newSubject := cr.CACert().Subject.CommonName
	if newSubject == origSubject {
		t.Errorf("subject should have changed, got %q", newSubject)
	}
	if newSubject != "NewCA Root CA" {
		t.Errorf("subject = %q, want %q", newSubject, "NewCA Root CA")
	}
}

func TestCertRotator_RotateFromPEM(t *testing.T) {
	certPEM, keyPEM, _ := GenerateCA("OrigCA", 1)
	cm, _ := NewCertManagerFromPEM(certPEM, keyPEM)

	cr := NewCertRotator(cm, "", "")

	newCertPEM, newKeyPEM, _ := GenerateCA("PEMRotated", 1)
	newCM, err := cr.RotateFromPEM(newCertPEM, newKeyPEM)
	if err != nil {
		t.Fatalf("RotateFromPEM: %v", err)
	}

	if newCM.caCert.Subject.CommonName != "PEMRotated Root CA" {
		t.Errorf("subject = %q", newCM.caCert.Subject.CommonName)
	}

	got := cr.CertManager()
	if got != newCM {
		t.Error("CertManager() should return new CM")
	}
}

func TestCertRotator_RotateError(t *testing.T) {
	certPEM, keyPEM, _ := GenerateCA("Orig", 1)
	cm, _ := NewCertManagerFromPEM(certPEM, keyPEM)

	cr := NewCertRotator(cm, "/nonexistent/ca.crt", "/nonexistent/ca.key")

	var gotErr error
	cr.OnError = func(err error) { gotErr = err }

	_, err := cr.Rotate()
	if err == nil {
		t.Fatal("expected error")
	}
	if gotErr == nil {
		t.Fatal("OnError not called")
	}
}

func TestCertRotator_OnRotateCallback(t *testing.T) {
	certPEM, keyPEM, _ := GenerateCA("CallbackTest", 1)
	cm, _ := NewCertManagerFromPEM(certPEM, keyPEM)

	dir := t.TempDir()
	certPath := dir + "/ca.crt"
	keyPath := dir + "/ca.key"
	_ = os.WriteFile(certPath, certPEM, 0644)
	_ = os.WriteFile(keyPath, keyPEM, 0600)

	cr := NewCertRotator(cm, certPath, keyPath)

	var gotSubject string
	cr.OnRotate = func(subject string) { gotSubject = subject }

	_, err := cr.Rotate()
	if err != nil {
		t.Fatal(err)
	}

	if gotSubject != "CallbackTest Root CA" {
		t.Errorf("OnRotate subject = %q", gotSubject)
	}
}

func TestCertRotator_GetCertificate(t *testing.T) {
	certPEM, keyPEM, _ := GenerateCA("CertTest", 1)
	cm, _ := NewCertManagerFromPEM(certPEM, keyPEM)

	cr := NewCertRotator(cm, "", "")

	cert, err := cr.GetCertificateForHost("example.com")
	if err != nil {
		t.Fatalf("GetCertificateForHost: %v", err)
	}
	if cert == nil {
		t.Fatal("expected certificate")
	}

	hello := &tls.ClientHelloInfo{ServerName: "test.com"}
	cert2, err := cr.GetCertificate(hello)
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if cert2 == nil {
		t.Fatal("expected certificate")
	}
}

func TestCertRotator_CacheCleared(t *testing.T) {
	certPEM, keyPEM, _ := GenerateCA("Cache1", 1)
	cm, _ := NewCertManagerFromPEM(certPEM, keyPEM)

	dir := t.TempDir()
	certPath := dir + "/ca.crt"
	keyPath := dir + "/ca.key"
	_ = os.WriteFile(certPath, certPEM, 0644)
	_ = os.WriteFile(keyPath, keyPEM, 0600)

	cr := NewCertRotator(cm, certPath, keyPath)

	_, _ = cr.GetCertificateForHost("cached.com")
	if cr.CacheSize() != 1 {
		t.Errorf("cache size = %d, want 1", cr.CacheSize())
	}

	_, _ = cr.Rotate()

	if cr.CacheSize() != 0 {
		t.Errorf("cache size = %d after rotation, want 0", cr.CacheSize())
	}
}

func TestCertRotator_CAKey(t *testing.T) {
	certPEM, keyPEM, _ := GenerateCA("KeyTest", 1)
	cm, _ := NewCertManagerFromPEM(certPEM, keyPEM)

	cr := NewCertRotator(cm, "", "")

	key := cr.CAKey()
	if key == nil {
		t.Fatal("expected CA key")
	}
}

func TestCertRotator_ConcurrentAccess(t *testing.T) {
	certPEM, keyPEM, _ := GenerateCA("Concurrent", 1)
	cm, _ := NewCertManagerFromPEM(certPEM, keyPEM)

	dir := t.TempDir()
	certPath := dir + "/ca.crt"
	keyPath := dir + "/ca.key"
	_ = os.WriteFile(certPath, certPEM, 0644)
	_ = os.WriteFile(keyPath, keyPEM, 0600)

	cr := NewCertRotator(cm, certPath, keyPath)

	var wg sync.WaitGroup
	for range 10 {
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, _ = cr.GetCertificateForHost("test.com")
		}()
		go func() {
			defer wg.Done()
			_, _ = cr.Rotate()
		}()
	}
	wg.Wait()
}

func TestCertRotator_WatchCAFiles(t *testing.T) {
	certPEM, keyPEM, _ := GenerateCA("Watch1", 1)
	cm, _ := NewCertManagerFromPEM(certPEM, keyPEM)

	dir := t.TempDir()
	certPath := dir + "/ca.crt"
	keyPath := dir + "/ca.key"
	_ = os.WriteFile(certPath, certPEM, 0644)
	_ = os.WriteFile(keyPath, keyPEM, 0600)

	cr := NewCertRotator(cm, certPath, keyPath)

	var rotated atomic.Bool
	cr.OnRotate = func(_ string) { rotated.Store(true) }

	ch := make(chan time.Time, 1)
	cancel := cr.WatchCAFiles(func() <-chan time.Time { return ch })
	defer cancel()

	newCertPEM, newKeyPEM, _ := GenerateCA("Watch2", 1)
	time.Sleep(10 * time.Millisecond)
	_ = os.WriteFile(certPath, newCertPEM, 0644)
	_ = os.WriteFile(keyPath, newKeyPEM, 0600)

	ch <- time.Now()
	time.Sleep(50 * time.Millisecond)

	if !rotated.Load() {
		t.Error("expected rotation after file change")
	}

	if cr.CACert().Subject.CommonName != "Watch2 Root CA" {
		t.Errorf("subject = %q after watch", cr.CACert().Subject.CommonName)
	}
}

func TestCertRotator_WatchCAFiles_NoChange(t *testing.T) {
	certPEM, keyPEM, _ := GenerateCA("NoChange", 1)
	cm, _ := NewCertManagerFromPEM(certPEM, keyPEM)

	dir := t.TempDir()
	certPath := dir + "/ca.crt"
	keyPath := dir + "/ca.key"
	_ = os.WriteFile(certPath, certPEM, 0644)
	_ = os.WriteFile(keyPath, keyPEM, 0600)

	cr := NewCertRotator(cm, certPath, keyPath)

	var rotated atomic.Bool
	cr.OnRotate = func(_ string) { rotated.Store(true) }

	ch := make(chan time.Time, 1)
	cancel := cr.WatchCAFiles(func() <-chan time.Time { return ch })
	defer cancel()

	ch <- time.Now()
	time.Sleep(50 * time.Millisecond)

	if rotated.Load() {
		t.Error("should not rotate when files unchanged")
	}
}
