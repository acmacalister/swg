package swg

import (
	"errors"
	"testing"
	"time"
)

func TestDefaultDNS01Config(t *testing.T) {
	cfg := DefaultDNS01Config()

	if cfg.PropagationTimeout != 120*time.Second {
		t.Errorf("expected propagation timeout 120s, got %v", cfg.PropagationTimeout)
	}
	if cfg.PollingInterval != 5*time.Second {
		t.Errorf("expected polling interval 5s, got %v", cfg.PollingInterval)
	}
}

func TestNewDNS01ChallengeProvider_Manual(t *testing.T) {
	cfg := DNS01Config{
		Provider: "manual",
	}

	provider, err := NewDNS01ChallengeProvider(cfg)
	if err != nil {
		t.Fatalf("NewDNS01ChallengeProvider() error: %v", err)
	}

	if provider == nil {
		t.Fatal("provider should not be nil")
	}

	// Check defaults were applied
	timeout, interval := provider.Timeout()
	if timeout != 120*time.Second {
		t.Errorf("expected timeout 120s, got %v", timeout)
	}
	if interval != 5*time.Second {
		t.Errorf("expected interval 5s, got %v", interval)
	}
}

func TestNewDNS01ChallengeProvider_Custom(t *testing.T) {
	mock := NewMockDNSProvider()
	cfg := DNS01Config{
		Provider:       "custom",
		CustomProvider: mock,
	}

	provider, err := NewDNS01ChallengeProvider(cfg)
	if err != nil {
		t.Fatalf("NewDNS01ChallengeProvider() error: %v", err)
	}

	if provider == nil {
		t.Fatal("provider should not be nil")
	}
}

func TestNewDNS01ChallengeProvider_CustomNil(t *testing.T) {
	cfg := DNS01Config{
		Provider: "custom",
	}

	_, err := NewDNS01ChallengeProvider(cfg)
	if err == nil {
		t.Error("expected error for custom provider with nil CustomProvider")
	}
}

func TestNewDNS01ChallengeProvider_EmptyProvider(t *testing.T) {
	cfg := DNS01Config{}

	_, err := NewDNS01ChallengeProvider(cfg)
	if err == nil {
		t.Error("expected error for empty provider")
	}
}

func TestNewDNS01ChallengeProvider_UnsupportedProvider(t *testing.T) {
	cfg := DNS01Config{
		Provider: "unsupported",
	}

	_, err := NewDNS01ChallengeProvider(cfg)
	if err == nil {
		t.Error("expected error for unsupported provider")
	}
}

func TestNewDNS01ChallengeProvider_AppliesTimeouts(t *testing.T) {
	cfg := DNS01Config{
		Provider:           "manual",
		PropagationTimeout: 300 * time.Second,
		PollingInterval:    10 * time.Second,
	}

	provider, err := NewDNS01ChallengeProvider(cfg)
	if err != nil {
		t.Fatalf("NewDNS01ChallengeProvider() error: %v", err)
	}

	timeout, interval := provider.Timeout()
	if timeout != 300*time.Second {
		t.Errorf("expected timeout 300s, got %v", timeout)
	}
	if interval != 10*time.Second {
		t.Errorf("expected interval 10s, got %v", interval)
	}
}

func TestDNS01ChallengeProvider_ChallengeOptions(t *testing.T) {
	tests := []struct {
		name                    string
		config                  DNS01Config
		expectNameserverOpt     bool
		expectPropagationDisable bool
	}{
		{
			name: "no options",
			config: DNS01Config{
				Provider: "manual",
			},
			expectNameserverOpt:     false,
			expectPropagationDisable: false,
		},
		{
			name: "with nameservers",
			config: DNS01Config{
				Provider:    "manual",
				Nameservers: []string{"8.8.8.8", "8.8.4.4"},
			},
			expectNameserverOpt:     true,
			expectPropagationDisable: false,
		},
		{
			name: "disable propagation check",
			config: DNS01Config{
				Provider:                "manual",
				DisablePropagationCheck: true,
			},
			expectNameserverOpt:     false,
			expectPropagationDisable: true,
		},
		{
			name: "both options",
			config: DNS01Config{
				Provider:                "manual",
				Nameservers:             []string{"1.1.1.1"},
				DisablePropagationCheck: true,
			},
			expectNameserverOpt:     true,
			expectPropagationDisable: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider, err := NewDNS01ChallengeProvider(tt.config)
			if err != nil {
				t.Fatalf("NewDNS01ChallengeProvider() error: %v", err)
			}

			opts := provider.ChallengeOptions()

			expectedCount := 0
			if tt.expectNameserverOpt {
				expectedCount++
			}
			if tt.expectPropagationDisable {
				expectedCount++
			}

			if len(opts) != expectedCount {
				t.Errorf("expected %d options, got %d", expectedCount, len(opts))
			}
		})
	}
}

func TestMemoryDNSProvider(t *testing.T) {
	p := NewMemoryDNSProvider()

	if p.RecordCount() != 0 {
		t.Errorf("expected 0 records initially, got %d", p.RecordCount())
	}

	// Present a record
	err := p.Present("example.com", "token123", "keyAuth456")
	if err != nil {
		t.Fatalf("Present() error: %v", err)
	}

	if p.RecordCount() != 1 {
		t.Errorf("expected 1 record after Present, got %d", p.RecordCount())
	}

	// CleanUp the record
	err = p.CleanUp("example.com", "token123", "keyAuth456")
	if err != nil {
		t.Fatalf("CleanUp() error: %v", err)
	}

	if p.RecordCount() != 0 {
		t.Errorf("expected 0 records after CleanUp, got %d", p.RecordCount())
	}
}

func TestMemoryDNSProvider_GetRecord(t *testing.T) {
	p := NewMemoryDNSProvider()

	// Record not present
	_, ok := p.GetRecord("_acme-challenge.example.com.")
	if ok {
		t.Error("expected record not found before Present")
	}

	// Present a record
	_ = p.Present("example.com", "token123", "keyAuth456")

	// The FQDN is computed by dns01.GetRecord, so we need to check
	// that something was stored
	if p.RecordCount() != 1 {
		t.Error("expected record to be stored")
	}
}

func TestMockDNSProvider(t *testing.T) {
	p := NewMockDNSProvider()

	// Test Present with default (nil) func
	err := p.Present("example.com", "token", "keyAuth")
	if err != nil {
		t.Fatalf("Present() error: %v", err)
	}

	if len(p.PresentCalls) != 1 {
		t.Errorf("expected 1 Present call, got %d", len(p.PresentCalls))
	}
	if p.PresentCalls[0].Domain != "example.com" {
		t.Errorf("expected domain 'example.com', got %s", p.PresentCalls[0].Domain)
	}

	// Test CleanUp with default (nil) func
	err = p.CleanUp("example.com", "token", "keyAuth")
	if err != nil {
		t.Fatalf("CleanUp() error: %v", err)
	}

	if len(p.CleanUpCalls) != 1 {
		t.Errorf("expected 1 CleanUp call, got %d", len(p.CleanUpCalls))
	}
}

func TestMockDNSProvider_CustomFuncs(t *testing.T) {
	expectedErr := errors.New("test error")
	p := NewMockDNSProvider()
	p.PresentFunc = func(domain, token, keyAuth string) error {
		return expectedErr
	}

	err := p.Present("example.com", "token", "keyAuth")
	if err != expectedErr {
		t.Errorf("expected error %v, got %v", expectedErr, err)
	}

	// CleanUp should still work
	err = p.CleanUp("example.com", "token", "keyAuth")
	if err != nil {
		t.Fatalf("CleanUp() error: %v", err)
	}
}

func TestDNS01ProviderNames(t *testing.T) {
	names := DNS01ProviderNames()

	expectedNames := []string{"cloudflare", "route53", "gcloud", "digitalocean", "manual", "custom"}
	if len(names) != len(expectedNames) {
		t.Errorf("expected %d providers, got %d", len(expectedNames), len(names))
	}

	for _, expected := range expectedNames {
		found := false
		for _, name := range names {
			if name == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected provider %q not found in list", expected)
		}
	}
}

func TestValidateDNS01Provider(t *testing.T) {
	tests := []struct {
		name        string
		provider    string
		expectError bool
	}{
		{"cloudflare", "cloudflare", false},
		{"cloudflare uppercase", "CLOUDFLARE", false},
		{"route53", "route53", false},
		{"gcloud", "gcloud", false},
		{"digitalocean", "digitalocean", false},
		{"manual", "manual", false},
		{"custom", "custom", false},
		{"unsupported", "unsupported", true},
		{"empty", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateDNS01Provider(tt.provider)
			if tt.expectError && err == nil {
				t.Error("expected error, got nil")
			}
			if !tt.expectError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestWildcardDomain(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"example.com", "*.example.com"},
		{"sub.example.com", "*.sub.example.com"},
		{"*.example.com", "*.example.com"}, // already wildcard
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := WildcardDomain(tt.input)
			if result != tt.expected {
				t.Errorf("WildcardDomain(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestIsWildcardDomain(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"example.com", false},
		{"sub.example.com", false},
		{"*.example.com", true},
		{"*.sub.example.com", true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := IsWildcardDomain(tt.input)
			if result != tt.expected {
				t.Errorf("IsWildcardDomain(%q) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestBaseDomain(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"*.example.com", "example.com"},
		{"*.sub.example.com", "sub.example.com"},
		{"example.com", "example.com"}, // not wildcard
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := BaseDomain(tt.input)
			if result != tt.expected {
				t.Errorf("BaseDomain(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestGetDNS01ChallengeInfo(t *testing.T) {
	info := GetDNS01ChallengeInfo("example.com", "keyAuth123")

	if info.Domain != "example.com" {
		t.Errorf("expected domain 'example.com', got %q", info.Domain)
	}
	if info.KeyAuth != "keyAuth123" {
		t.Errorf("expected keyAuth 'keyAuth123', got %q", info.KeyAuth)
	}
	if info.FQDN == "" {
		t.Error("expected FQDN to be set")
	}
	if info.Value == "" {
		t.Error("expected Value to be set")
	}
	if info.Obtained.IsZero() {
		t.Error("expected Obtained timestamp to be set")
	}
}

func TestDNS01Validator(t *testing.T) {
	v := NewDNS01Validator()

	if v.Timeout != 30*time.Second {
		t.Errorf("expected timeout 30s, got %v", v.Timeout)
	}

	// Test CheckRecord
	fqdn, value := v.CheckRecord("example.com", "keyAuth123")
	if fqdn == "" {
		t.Error("expected FQDN to be returned")
	}
	if value == "" {
		t.Error("expected value to be returned")
	}
}

func TestDNS01ChallengeProvider_Provider(t *testing.T) {
	cfg := DNS01Config{
		Provider: "manual",
	}

	provider, err := NewDNS01ChallengeProvider(cfg)
	if err != nil {
		t.Fatalf("NewDNS01ChallengeProvider() error: %v", err)
	}

	underlying := provider.Provider()
	if underlying == nil {
		t.Error("Provider() should not return nil")
	}
}

func TestDNS01ChallengeProvider_PresentCleanUp(t *testing.T) {
	mock := NewMockDNSProvider()
	cfg := DNS01Config{
		Provider:       "custom",
		CustomProvider: mock,
	}

	provider, err := NewDNS01ChallengeProvider(cfg)
	if err != nil {
		t.Fatalf("NewDNS01ChallengeProvider() error: %v", err)
	}

	// Test Present
	err = provider.Present("example.com", "token", "keyAuth")
	if err != nil {
		t.Fatalf("Present() error: %v", err)
	}

	if len(mock.PresentCalls) != 1 {
		t.Errorf("expected 1 Present call, got %d", len(mock.PresentCalls))
	}

	// Test CleanUp
	err = provider.CleanUp("example.com", "token", "keyAuth")
	if err != nil {
		t.Fatalf("CleanUp() error: %v", err)
	}

	if len(mock.CleanUpCalls) != 1 {
		t.Errorf("expected 1 CleanUp call, got %d", len(mock.CleanUpCalls))
	}
}

// TestNewDNS01ChallengeProvider_CloudflareNoEnv tests Cloudflare provider
// without environment variables (will fail but tests the code path)
func TestNewDNS01ChallengeProvider_CloudflareNoEnv(t *testing.T) {
	cfg := DNS01Config{
		Provider: "cloudflare",
	}

	// This will fail without CLOUDFLARE_* env vars, which is expected
	_, err := NewDNS01ChallengeProvider(cfg)
	if err == nil {
		t.Log("Cloudflare provider created (env vars must be set)")
	} else {
		t.Logf("Cloudflare provider creation failed (expected): %v", err)
	}
}

// TestNewDNS01ChallengeProvider_CloudflareWithToken tests Cloudflare with API token
func TestNewDNS01ChallengeProvider_CloudflareWithToken(t *testing.T) {
	cfg := DNS01Config{
		Provider:           "cloudflare",
		CloudflareAPIToken: "test-token",
	}

	// This will create the provider but fail on actual use
	provider, err := NewDNS01ChallengeProvider(cfg)
	if err != nil {
		t.Fatalf("NewDNS01ChallengeProvider() error: %v", err)
	}

	if provider == nil {
		t.Fatal("provider should not be nil")
	}
}

// TestNewDNS01ChallengeProvider_CloudflareWithKeyEmail tests Cloudflare with API key + email
func TestNewDNS01ChallengeProvider_CloudflareWithKeyEmail(t *testing.T) {
	cfg := DNS01Config{
		Provider:        "cloudflare",
		CloudflareAPIKey: "test-key",
		CloudflareEmail:  "test@example.com",
	}

	provider, err := NewDNS01ChallengeProvider(cfg)
	if err != nil {
		t.Fatalf("NewDNS01ChallengeProvider() error: %v", err)
	}

	if provider == nil {
		t.Fatal("provider should not be nil")
	}
}

// TestNewDNS01ChallengeProvider_DigitalOceanWithToken tests DigitalOcean with token
func TestNewDNS01ChallengeProvider_DigitalOceanWithToken(t *testing.T) {
	cfg := DNS01Config{
		Provider:          "digitalocean",
		DigitalOceanToken: "test-token",
	}

	provider, err := NewDNS01ChallengeProvider(cfg)
	if err != nil {
		t.Fatalf("NewDNS01ChallengeProvider() error: %v", err)
	}

	if provider == nil {
		t.Fatal("provider should not be nil")
	}
}

// BenchmarkMemoryDNSProvider benchmarks the in-memory provider
func BenchmarkMemoryDNSProvider(b *testing.B) {
	p := NewMemoryDNSProvider()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = p.Present("example.com", "token", "keyAuth")
		_ = p.CleanUp("example.com", "token", "keyAuth")
	}
}

// BenchmarkMockDNSProvider benchmarks the mock provider
func BenchmarkMockDNSProvider(b *testing.B) {
	p := NewMockDNSProvider()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = p.Present("example.com", "token", "keyAuth")
		_ = p.CleanUp("example.com", "token", "keyAuth")
	}
}
