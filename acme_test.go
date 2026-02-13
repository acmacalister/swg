package swg

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDefaultACMEConfig(t *testing.T) {
	cfg := DefaultACMEConfig()

	if cfg.CA != LetsEncryptProduction {
		t.Errorf("CA = %q, want %q", cfg.CA, LetsEncryptProduction)
	}
	if cfg.KeyType != "ec256" {
		t.Errorf("KeyType = %q, want %q", cfg.KeyType, "ec256")
	}
	if cfg.StoragePath != "./acme" {
		t.Errorf("StoragePath = %q, want %q", cfg.StoragePath, "./acme")
	}
	if cfg.HTTPPort != 80 {
		t.Errorf("HTTPPort = %d, want %d", cfg.HTTPPort, 80)
	}
	if cfg.TLSPort != 443 {
		t.Errorf("TLSPort = %d, want %d", cfg.TLSPort, 443)
	}
	if cfg.RenewBefore != 30*24*time.Hour {
		t.Errorf("RenewBefore = %v, want %v", cfg.RenewBefore, 30*24*time.Hour)
	}
	if cfg.AcceptTOS {
		t.Error("AcceptTOS should default to false")
	}
}

func TestNewACMECertManager_Validation(t *testing.T) {
	tests := []struct {
		name    string
		cfg     ACMEConfig
		wantErr string
	}{
		{
			name: "missing email",
			cfg: ACMEConfig{
				Domains:   []string{"example.com"},
				AcceptTOS: true,
			},
			wantErr: "email is required",
		},
		{
			name: "missing domains",
			cfg: ACMEConfig{
				Email:     "admin@example.com",
				AcceptTOS: true,
			},
			wantErr: "at least one domain is required",
		},
		{
			name: "TOS not accepted",
			cfg: ACMEConfig{
				Email:     "admin@example.com",
				Domains:   []string{"example.com"},
				AcceptTOS: false,
			},
			wantErr: "must accept Terms of Service",
		},
		{
			name: "valid config",
			cfg: ACMEConfig{
				Email:       "admin@example.com",
				Domains:     []string{"example.com"},
				AcceptTOS:   true,
				StoragePath: t.TempDir(),
			},
			wantErr: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			acm, err := NewACMECertManager(tt.cfg)
			if tt.wantErr != "" {
				if err == nil {
					t.Errorf("expected error containing %q, got nil", tt.wantErr)
				} else if !contains(err.Error(), tt.wantErr) {
					t.Errorf("error = %q, want containing %q", err.Error(), tt.wantErr)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if acm != nil {
					_ = acm.Close()
				}
			}
		})
	}
}

func TestACMECertManager_StorageDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	storagePath := filepath.Join(tmpDir, "nested", "acme")

	cfg := ACMEConfig{
		Email:       "admin@example.com",
		Domains:     []string{"example.com"},
		AcceptTOS:   true,
		StoragePath: storagePath,
	}

	acm, err := NewACMECertManager(cfg)
	if err != nil {
		t.Fatalf("NewACMECertManager() error = %v", err)
	}
	defer func() { _ = acm.Close() }()

	// Check directory was created
	info, err := os.Stat(storagePath)
	if err != nil {
		t.Errorf("storage directory not created: %v", err)
	} else if !info.IsDir() {
		t.Error("storage path is not a directory")
	}
}

func TestACMECertManager_ParseKeyType(t *testing.T) {
	tmpDir := t.TempDir()

	tests := []struct {
		keyType  string
		wantType string // We can't easily check certcrypto.KeyType, just ensure no crash
	}{
		{"ec256", "ec256"},
		{"ec384", "ec384"},
		{"rsa2048", "rsa2048"},
		{"rsa4096", "rsa4096"},
		{"rsa8192", "rsa8192"},
		{"", "ec256"},        // default
		{"unknown", "ec256"}, // fallback to default
	}

	for _, tt := range tests {
		t.Run(tt.keyType, func(t *testing.T) {
			cfg := ACMEConfig{
				Email:       "admin@example.com",
				Domains:     []string{"example.com"},
				AcceptTOS:   true,
				StoragePath: filepath.Join(tmpDir, tt.keyType),
				KeyType:     tt.keyType,
			}

			acm, err := NewACMECertManager(cfg)
			if err != nil {
				t.Fatalf("NewACMECertManager() error = %v", err)
			}
			defer func() { _ = acm.Close() }()

			// Just verify it parses without error
			_ = acm.parseKeyType()
		})
	}
}

func TestACMECertManager_UserPath(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := ACMEConfig{
		Email:       "admin@example.com",
		Domains:     []string{"example.com"},
		AcceptTOS:   true,
		StoragePath: tmpDir,
	}

	acm, err := NewACMECertManager(cfg)
	if err != nil {
		t.Fatalf("NewACMECertManager() error = %v", err)
	}
	defer func() { _ = acm.Close() }()

	expectedPath := filepath.Join(tmpDir, "account.json")
	if got := acm.userPath(); got != expectedPath {
		t.Errorf("userPath() = %q, want %q", got, expectedPath)
	}
}

func TestACMECertManager_CertPath(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := ACMEConfig{
		Email:       "admin@example.com",
		Domains:     []string{"example.com"},
		AcceptTOS:   true,
		StoragePath: tmpDir,
	}

	acm, err := NewACMECertManager(cfg)
	if err != nil {
		t.Fatalf("NewACMECertManager() error = %v", err)
	}
	defer func() { _ = acm.Close() }()

	expectedPath := filepath.Join(tmpDir, "certificates", "example.com")
	if got := acm.certPath("example.com"); got != expectedPath {
		t.Errorf("certPath() = %q, want %q", got, expectedPath)
	}
}

func TestACMECertManager_CacheSize(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := ACMEConfig{
		Email:       "admin@example.com",
		Domains:     []string{"example.com"},
		AcceptTOS:   true,
		StoragePath: tmpDir,
	}

	acm, err := NewACMECertManager(cfg)
	if err != nil {
		t.Fatalf("NewACMECertManager() error = %v", err)
	}
	defer func() { _ = acm.Close() }()

	if got := acm.CacheSize(); got != 0 {
		t.Errorf("CacheSize() = %d, want 0", got)
	}
}

func TestACMECertManager_GetCertificateForHost_NotConfigured(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := ACMEConfig{
		Email:       "admin@example.com",
		Domains:     []string{"example.com"},
		AcceptTOS:   true,
		StoragePath: tmpDir,
	}

	acm, err := NewACMECertManager(cfg)
	if err != nil {
		t.Fatalf("NewACMECertManager() error = %v", err)
	}
	defer func() { _ = acm.Close() }()

	// Request cert for unconfigured domain
	_, err = acm.GetCertificateForHost("other.com")
	if err == nil {
		t.Error("expected error for unconfigured domain")
	}
}

func TestACMEUser_Interface(t *testing.T) {
	user := &acmeUser{
		Email: "test@example.com",
	}

	if got := user.GetEmail(); got != "test@example.com" {
		t.Errorf("GetEmail() = %q, want %q", got, "test@example.com")
	}
	if got := user.GetRegistration(); got != nil {
		t.Errorf("GetRegistration() = %v, want nil", got)
	}
	if got := user.GetPrivateKey(); got != nil {
		t.Errorf("GetPrivateKey() = %v, want nil", got)
	}
}

func TestACMECertManager_Close(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := ACMEConfig{
		Email:       "admin@example.com",
		Domains:     []string{"example.com"},
		AcceptTOS:   true,
		StoragePath: tmpDir,
	}

	acm, err := NewACMECertManager(cfg)
	if err != nil {
		t.Fatalf("NewACMECertManager() error = %v", err)
	}

	// Close should not error
	if err := acm.Close(); err != nil {
		t.Errorf("Close() error = %v", err)
	}

	// Double close should also be safe
	if err := acm.Close(); err != nil {
		t.Errorf("second Close() error = %v", err)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && findSubstring(s, substr)))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
