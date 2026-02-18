package swg

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/providers/dns/cloudflare"
	"github.com/go-acme/lego/v4/providers/dns/digitalocean"
	"github.com/go-acme/lego/v4/providers/dns/gcloud"
	"github.com/go-acme/lego/v4/providers/dns/manual"
	"github.com/go-acme/lego/v4/providers/dns/route53"
)

// DNS01Provider is the interface for DNS-01 challenge providers.
// It matches lego's challenge.Provider interface.
type DNS01Provider interface {
	challenge.Provider
}

// DNS01Config holds the configuration for DNS-01 ACME challenges.
// DNS-01 is required for wildcard certificates and environments where
// ports 80/443 are not publicly accessible.
type DNS01Config struct {
	// Provider specifies the DNS provider to use. Supported values:
	//   - "cloudflare"    — Cloudflare DNS
	//   - "route53"       — AWS Route 53
	//   - "gcloud"        — Google Cloud DNS
	//   - "digitalocean"  — DigitalOcean DNS
	//   - "manual"        — Manual DNS record creation (for testing)
	//   - "custom"        — Use CustomProvider field
	//
	// Each provider requires specific environment variables for authentication.
	// See the documentation for each provider for required variables.
	Provider string `mapstructure:"provider"`

	// CustomProvider allows using a custom DNS01Provider implementation.
	// This is used when Provider is set to "custom".
	CustomProvider DNS01Provider `mapstructure:"-"`

	// PropagationTimeout is the maximum time to wait for DNS propagation.
	// Defaults to 120 seconds.
	PropagationTimeout time.Duration `mapstructure:"propagation_timeout"`

	// PollingInterval is how often to check for DNS propagation.
	// Defaults to 5 seconds.
	PollingInterval time.Duration `mapstructure:"polling_interval"`

	// Nameservers specifies custom nameservers for DNS propagation checks.
	// If empty, the default system resolver is used.
	Nameservers []string `mapstructure:"nameservers"`

	// DisablePropagationCheck skips waiting for DNS propagation.
	// Use with caution — the CA may fail to verify if records haven't propagated.
	DisablePropagationCheck bool `mapstructure:"disable_propagation_check"`

	// Cloudflare-specific configuration
	CloudflareAPIToken string `mapstructure:"cloudflare_api_token"`
	CloudflareAPIKey   string `mapstructure:"cloudflare_api_key"`
	CloudflareEmail    string `mapstructure:"cloudflare_email"`
	CloudflareZoneID   string `mapstructure:"cloudflare_zone_id"`

	// Route53-specific configuration
	Route53AccessKeyID     string `mapstructure:"route53_access_key_id"`
	Route53SecretAccessKey string `mapstructure:"route53_secret_access_key"`
	Route53Region          string `mapstructure:"route53_region"`
	Route53HostedZoneID    string `mapstructure:"route53_hosted_zone_id"`

	// Google Cloud DNS-specific configuration
	GCloudProject     string `mapstructure:"gcloud_project"`
	GCloudServiceFile string `mapstructure:"gcloud_service_file"`

	// DigitalOcean-specific configuration
	DigitalOceanToken string `mapstructure:"digitalocean_token"`
}

// DefaultDNS01Config returns a DNS01Config with sensible defaults.
func DefaultDNS01Config() DNS01Config {
	return DNS01Config{
		PropagationTimeout: 120 * time.Second,
		PollingInterval:    5 * time.Second,
	}
}

// DNS01ChallengeProvider wraps a lego DNS provider with additional
// configuration options like custom propagation settings.
type DNS01ChallengeProvider struct {
	provider challenge.Provider
	config   DNS01Config
}

// NewDNS01ChallengeProvider creates a new DNS-01 challenge provider
// based on the provided configuration.
func NewDNS01ChallengeProvider(cfg DNS01Config) (*DNS01ChallengeProvider, error) {
	if cfg.PropagationTimeout == 0 {
		cfg.PropagationTimeout = 120 * time.Second
	}
	if cfg.PollingInterval == 0 {
		cfg.PollingInterval = 5 * time.Second
	}

	var provider challenge.Provider
	var err error

	switch strings.ToLower(cfg.Provider) {
	case "cloudflare":
		provider, err = newCloudflareProvider(cfg)
	case "route53":
		provider, err = newRoute53Provider(cfg)
	case "gcloud":
		provider, err = newGCloudProvider(cfg)
	case "digitalocean":
		provider, err = newDigitalOceanProvider(cfg)
	case "manual":
		provider, err = manual.NewDNSProvider()
	case "custom":
		if cfg.CustomProvider == nil {
			return nil, errors.New("dns01: custom provider specified but CustomProvider is nil")
		}
		provider = cfg.CustomProvider
	case "":
		return nil, errors.New("dns01: provider is required")
	default:
		return nil, fmt.Errorf("dns01: unsupported provider %q", cfg.Provider)
	}

	if err != nil {
		return nil, fmt.Errorf("dns01: create %s provider: %w", cfg.Provider, err)
	}

	return &DNS01ChallengeProvider{
		provider: provider,
		config:   cfg,
	}, nil
}

// Present creates the DNS TXT record for the ACME challenge.
func (p *DNS01ChallengeProvider) Present(domain, token, keyAuth string) error {
	return p.provider.Present(domain, token, keyAuth)
}

// CleanUp removes the DNS TXT record after the challenge completes.
func (p *DNS01ChallengeProvider) CleanUp(domain, token, keyAuth string) error {
	return p.provider.CleanUp(domain, token, keyAuth)
}

// Timeout returns the propagation timeout and polling interval.
// This implements challenge.ProviderTimeout for custom timeout handling.
func (p *DNS01ChallengeProvider) Timeout() (timeout, interval time.Duration) {
	return p.config.PropagationTimeout, p.config.PollingInterval
}

// ChallengeOptions returns dns01.ChallengeOption values based on config.
func (p *DNS01ChallengeProvider) ChallengeOptions() []dns01.ChallengeOption {
	var opts []dns01.ChallengeOption

	if len(p.config.Nameservers) > 0 {
		opts = append(opts, dns01.AddRecursiveNameservers(p.config.Nameservers))
	}

	if p.config.DisablePropagationCheck {
		opts = append(opts, dns01.DisableAuthoritativeNssPropagationRequirement())
	}

	return opts
}

// Provider returns the underlying challenge.Provider.
func (p *DNS01ChallengeProvider) Provider() challenge.Provider {
	return p.provider
}

// newCloudflareProvider creates a Cloudflare DNS provider.
// Supports API token (preferred) or API key + email authentication.
func newCloudflareProvider(cfg DNS01Config) (challenge.Provider, error) {
	// Cloudflare provider reads from environment by default.
	// We can override with config values.
	if cfg.CloudflareAPIToken != "" {
		config := cloudflare.NewDefaultConfig()
		config.AuthToken = cfg.CloudflareAPIToken
		if cfg.CloudflareZoneID != "" {
			config.ZoneToken = cfg.CloudflareAPIToken
		}
		config.PropagationTimeout = cfg.PropagationTimeout
		config.PollingInterval = cfg.PollingInterval
		return cloudflare.NewDNSProviderConfig(config)
	}

	if cfg.CloudflareAPIKey != "" && cfg.CloudflareEmail != "" {
		config := cloudflare.NewDefaultConfig()
		config.AuthKey = cfg.CloudflareAPIKey
		config.AuthEmail = cfg.CloudflareEmail
		config.PropagationTimeout = cfg.PropagationTimeout
		config.PollingInterval = cfg.PollingInterval
		return cloudflare.NewDNSProviderConfig(config)
	}

	// Fall back to environment variables
	return cloudflare.NewDNSProvider()
}

// newRoute53Provider creates an AWS Route 53 DNS provider.
func newRoute53Provider(cfg DNS01Config) (challenge.Provider, error) {
	config := route53.NewDefaultConfig()
	config.PropagationTimeout = cfg.PropagationTimeout
	config.PollingInterval = cfg.PollingInterval

	if cfg.Route53AccessKeyID != "" {
		config.AccessKeyID = cfg.Route53AccessKeyID
	}
	if cfg.Route53SecretAccessKey != "" {
		config.SecretAccessKey = cfg.Route53SecretAccessKey
	}
	if cfg.Route53Region != "" {
		config.Region = cfg.Route53Region
	}
	if cfg.Route53HostedZoneID != "" {
		config.HostedZoneID = cfg.Route53HostedZoneID
	}

	// If we have explicit credentials, use config
	if cfg.Route53AccessKeyID != "" && cfg.Route53SecretAccessKey != "" {
		return route53.NewDNSProviderConfig(config)
	}

	// Fall back to environment/IAM
	return route53.NewDNSProvider()
}

// newGCloudProvider creates a Google Cloud DNS provider.
func newGCloudProvider(cfg DNS01Config) (challenge.Provider, error) {
	config := gcloud.NewDefaultConfig()
	config.PropagationTimeout = cfg.PropagationTimeout
	config.PollingInterval = cfg.PollingInterval

	if cfg.GCloudProject != "" {
		config.Project = cfg.GCloudProject
	}

	// If we have a service account file, use config
	if cfg.GCloudServiceFile != "" {
		// gcloud provider reads GOOGLE_APPLICATION_CREDENTIALS or uses ADC
		// For explicit file, we need to use the config
		return gcloud.NewDNSProviderConfig(config)
	}

	// Fall back to ADC/environment
	return gcloud.NewDNSProvider()
}

// newDigitalOceanProvider creates a DigitalOcean DNS provider.
func newDigitalOceanProvider(cfg DNS01Config) (challenge.Provider, error) {
	if cfg.DigitalOceanToken != "" {
		config := digitalocean.NewDefaultConfig()
		config.AuthToken = cfg.DigitalOceanToken
		config.PropagationTimeout = cfg.PropagationTimeout
		config.PollingInterval = cfg.PollingInterval
		return digitalocean.NewDNSProviderConfig(config)
	}

	// Fall back to environment
	return digitalocean.NewDNSProvider()
}

// MemoryDNSProvider is an in-memory DNS provider for testing.
// It stores TXT records but doesn't interact with real DNS.
type MemoryDNSProvider struct {
	records map[string]string
}

// NewMemoryDNSProvider creates a new in-memory DNS provider for testing.
func NewMemoryDNSProvider() *MemoryDNSProvider {
	return &MemoryDNSProvider{
		records: make(map[string]string),
	}
}

// Present stores the TXT record in memory.
func (p *MemoryDNSProvider) Present(domain, token, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)
	p.records[info.FQDN] = info.Value
	return nil
}

// CleanUp removes the TXT record from memory.
func (p *MemoryDNSProvider) CleanUp(domain, token, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)
	delete(p.records, info.FQDN)
	return nil
}

// GetRecord returns the stored TXT record for a domain.
func (p *MemoryDNSProvider) GetRecord(fqdn string) (string, bool) {
	val, ok := p.records[fqdn]
	return val, ok
}

// RecordCount returns the number of stored records.
func (p *MemoryDNSProvider) RecordCount() int {
	return len(p.records)
}

// MockDNSProvider is a configurable mock DNS provider for testing.
// It allows simulating errors and tracking method calls.
type MockDNSProvider struct {
	PresentFunc func(domain, token, keyAuth string) error
	CleanUpFunc func(domain, token, keyAuth string) error

	PresentCalls []mockDNSCall
	CleanUpCalls []mockDNSCall
}

type mockDNSCall struct {
	Domain  string
	Token   string
	KeyAuth string
}

// NewMockDNSProvider creates a new mock DNS provider.
func NewMockDNSProvider() *MockDNSProvider {
	return &MockDNSProvider{
		PresentCalls: make([]mockDNSCall, 0),
		CleanUpCalls: make([]mockDNSCall, 0),
	}
}

// Present records the call and optionally runs PresentFunc.
func (p *MockDNSProvider) Present(domain, token, keyAuth string) error {
	p.PresentCalls = append(p.PresentCalls, mockDNSCall{domain, token, keyAuth})
	if p.PresentFunc != nil {
		return p.PresentFunc(domain, token, keyAuth)
	}
	return nil
}

// CleanUp records the call and optionally runs CleanUpFunc.
func (p *MockDNSProvider) CleanUp(domain, token, keyAuth string) error {
	p.CleanUpCalls = append(p.CleanUpCalls, mockDNSCall{domain, token, keyAuth})
	if p.CleanUpFunc != nil {
		return p.CleanUpFunc(domain, token, keyAuth)
	}
	return nil
}

// SetDNS01Provider configures the ACMECertManager to use DNS-01 challenges
// instead of HTTP-01/TLS-ALPN-01. This must be called after Initialize()
// but before ObtainCertificates().
//
// DNS-01 is required for:
//   - Wildcard certificates (*.example.com)
//   - Environments where ports 80/443 are not publicly accessible
//
// Example:
//
//	acm, _ := swg.NewACMECertManager(cfg)
//	acm.Initialize(ctx)
//
//	dns01Provider, _ := swg.NewDNS01ChallengeProvider(swg.DNS01Config{
//	    Provider:           "cloudflare",
//	    CloudflareAPIToken: os.Getenv("CF_API_TOKEN"),
//	})
//	acm.SetDNS01Provider(dns01Provider)
//
//	acm.ObtainCertificates(ctx) // Uses DNS-01 challenge
func (acm *ACMECertManager) SetDNS01Provider(provider *DNS01ChallengeProvider) error {
	if acm.client == nil {
		return errors.New("acme: must call Initialize() before SetDNS01Provider()")
	}

	opts := provider.ChallengeOptions()
	err := acm.client.Challenge.SetDNS01Provider(provider, opts...)
	if err != nil {
		return fmt.Errorf("acme: set DNS-01 provider: %w", err)
	}

	acm.logger.Info("configured DNS-01 challenge provider",
		"provider", provider.config.Provider,
		"propagation_timeout", provider.config.PropagationTimeout,
	)

	return nil
}

// SetDNS01ProviderWithConfig is a convenience method that creates and sets
// a DNS-01 provider from configuration. It combines NewDNS01ChallengeProvider
// and SetDNS01Provider into a single call.
func (acm *ACMECertManager) SetDNS01ProviderWithConfig(cfg DNS01Config) error {
	provider, err := NewDNS01ChallengeProvider(cfg)
	if err != nil {
		return err
	}
	return acm.SetDNS01Provider(provider)
}

// DNS01ProviderNames returns the list of supported DNS provider names.
func DNS01ProviderNames() []string {
	return []string{
		"cloudflare",
		"route53",
		"gcloud",
		"digitalocean",
		"manual",
		"custom",
	}
}

// ValidateDNS01Provider checks if the provider name is supported.
func ValidateDNS01Provider(name string) error {
	switch strings.ToLower(name) {
	case "cloudflare", "route53", "gcloud", "digitalocean", "manual", "custom":
		return nil
	default:
		return fmt.Errorf("unsupported DNS-01 provider: %q (supported: %s)",
			name, strings.Join(DNS01ProviderNames(), ", "))
	}
}

// WildcardDomain returns the wildcard version of a domain.
// Example: "example.com" -> "*.example.com"
func WildcardDomain(domain string) string {
	if strings.HasPrefix(domain, "*.") {
		return domain
	}
	return "*." + domain
}

// IsWildcardDomain checks if a domain is a wildcard domain.
func IsWildcardDomain(domain string) bool {
	return strings.HasPrefix(domain, "*.")
}

// BaseDomain extracts the base domain from a wildcard domain.
// Example: "*.example.com" -> "example.com"
func BaseDomain(domain string) string {
	return strings.TrimPrefix(domain, "*.")
}

// DNS01ChallengeInfo contains information about a DNS-01 challenge.
type DNS01ChallengeInfo struct {
	Domain   string
	FQDN     string
	Value    string
	KeyAuth  string
	Token    string
	Obtained time.Time
}

// GetDNS01ChallengeInfo returns the DNS record information for a domain.
// This is useful for manual DNS-01 challenges or debugging.
func GetDNS01ChallengeInfo(domain, keyAuth string) DNS01ChallengeInfo {
	info := dns01.GetChallengeInfo(domain, keyAuth)
	return DNS01ChallengeInfo{
		Domain:   domain,
		FQDN:     info.FQDN,
		Value:    info.Value,
		KeyAuth:  keyAuth,
		Obtained: time.Now(),
	}
}

// DNS01Validator provides utilities for validating DNS-01 challenges.
type DNS01Validator struct {
	Nameservers []string
	Timeout     time.Duration
}

// NewDNS01Validator creates a new DNS-01 validator with defaults.
func NewDNS01Validator() *DNS01Validator {
	return &DNS01Validator{
		Timeout: 30 * time.Second,
	}
}

// CheckRecord uses lego's dns01 package to get the expected record info.
// This is useful for debugging DNS-01 challenges.
func (v *DNS01Validator) CheckRecord(domain, keyAuth string) (fqdn, value string) {
	info := dns01.GetChallengeInfo(domain, keyAuth)
	return info.FQDN, info.Value
}
