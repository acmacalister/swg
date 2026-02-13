package swg

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/http01"
	"github.com/go-acme/lego/v4/challenge/tlsalpn01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
)

// ACME CA directory URLs.
const (
	LetsEncryptProduction = lego.LEDirectoryProduction
	LetsEncryptStaging    = lego.LEDirectoryStaging
)

// ACMEConfig contains ACME/Let's Encrypt configuration.
// Configuration style follows Caddy server patterns.
type ACMEConfig struct {
	// Email is used for ACME account registration and certificate notifications.
	// Highly recommended to set this for certificate expiration warnings.
	Email string `mapstructure:"email"`

	// CA is the ACME CA directory URL.
	// Defaults to Let's Encrypt production.
	// For testing, use LetsEncryptStaging to avoid rate limits.
	CA string `mapstructure:"ca"`

	// KeyType is the type of key to generate for certificates.
	// Supported: "ec256", "ec384", "rsa2048", "rsa4096", "rsa8192"
	// Defaults to "ec256" (recommended).
	KeyType string `mapstructure:"key_type"`

	// StoragePath is where certificates and account data are stored.
	// Defaults to "./acme" in the current directory.
	StoragePath string `mapstructure:"storage_path"`

	// HTTPPort is the port to use for HTTP-01 challenges.
	// Defaults to 80. Set to 0 to disable HTTP-01 challenge.
	HTTPPort int `mapstructure:"http_port"`

	// TLSPort is the port to use for TLS-ALPN-01 challenges.
	// Defaults to 443. Set to 0 to disable TLS-ALPN-01 challenge.
	TLSPort int `mapstructure:"tls_port"`

	// RenewBefore specifies how long before expiration to renew certificates.
	// Defaults to 30 days.
	RenewBefore time.Duration `mapstructure:"renew_before"`

	// Domains is the list of domains to obtain certificates for.
	// At least one domain is required.
	Domains []string `mapstructure:"domains"`

	// AcceptTOS indicates acceptance of the CA's Terms of Service.
	// Must be true to obtain certificates.
	AcceptTOS bool `mapstructure:"accept_tos"`

	// EABKeyID is the External Account Binding key ID (optional).
	// Required by some CAs like ZeroSSL.
	EABKeyID string `mapstructure:"eab_key_id"`

	// EABMACKey is the External Account Binding MAC key (optional).
	// Required by some CAs like ZeroSSL.
	EABMACKey string `mapstructure:"eab_mac_key"`
}

// DefaultACMEConfig returns an ACMEConfig with sensible defaults.
func DefaultACMEConfig() ACMEConfig {
	return ACMEConfig{
		CA:          LetsEncryptProduction,
		KeyType:     "ec256",
		StoragePath: "./acme",
		HTTPPort:    80,
		TLSPort:     443,
		RenewBefore: 30 * 24 * time.Hour,
		AcceptTOS:   false,
	}
}

// acmeUser implements registration.User for lego.
type acmeUser struct {
	Email        string                 `json:"email"`
	Registration *registration.Resource `json:"registration"`
	key          crypto.PrivateKey
	keyPEM       []byte `json:"key_pem"`
}

func (u *acmeUser) GetEmail() string {
	return u.Email
}

func (u *acmeUser) GetRegistration() *registration.Resource {
	return u.Registration
}

func (u *acmeUser) GetPrivateKey() crypto.PrivateKey {
	return u.key
}

// ACMECertManager manages Let's Encrypt certificates for MITM proxying.
type ACMECertManager struct {
	config ACMEConfig
	user   *acmeUser
	client *lego.Client
	logger *slog.Logger

	// Certificate storage
	mu    sync.RWMutex
	certs map[string]*tls.Certificate

	// Background renewal
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// Callbacks
	OnCertObtained func(domain string)
	OnCertRenewed  func(domain string)
	OnError        func(domain string, err error)
}

// NewACMECertManager creates a new ACMECertManager with the given configuration.
func NewACMECertManager(cfg ACMEConfig) (*ACMECertManager, error) {
	if cfg.Email == "" {
		return nil, errors.New("acme: email is required")
	}
	if len(cfg.Domains) == 0 {
		return nil, errors.New("acme: at least one domain is required")
	}
	if !cfg.AcceptTOS {
		return nil, errors.New("acme: must accept Terms of Service (set accept_tos: true)")
	}

	// Apply defaults
	if cfg.CA == "" {
		cfg.CA = LetsEncryptProduction
	}
	if cfg.KeyType == "" {
		cfg.KeyType = "ec256"
	}
	if cfg.StoragePath == "" {
		cfg.StoragePath = "./acme"
	}
	if cfg.RenewBefore == 0 {
		cfg.RenewBefore = 30 * 24 * time.Hour
	}

	// Create storage directory
	if err := os.MkdirAll(cfg.StoragePath, 0700); err != nil {
		return nil, fmt.Errorf("acme: create storage directory: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	acm := &ACMECertManager{
		config: cfg,
		certs:  make(map[string]*tls.Certificate),
		logger: slog.Default(),
		ctx:    ctx,
		cancel: cancel,
	}

	return acm, nil
}

// SetLogger sets the logger for the ACMECertManager.
func (acm *ACMECertManager) SetLogger(logger *slog.Logger) {
	acm.logger = logger
}

// Initialize sets up the ACME client and loads/registers the account.
func (acm *ACMECertManager) Initialize(ctx context.Context) error {
	// Load or create user
	user, err := acm.loadOrCreateUser()
	if err != nil {
		return fmt.Errorf("acme: load/create user: %w", err)
	}
	acm.user = user

	// Create lego config
	legoCfg := lego.NewConfig(user)
	legoCfg.CADirURL = acm.config.CA
	legoCfg.Certificate.KeyType = acm.parseKeyType()

	// Create client
	client, err := lego.NewClient(legoCfg)
	if err != nil {
		return fmt.Errorf("acme: create client: %w", err)
	}
	acm.client = client

	// Configure challenges
	if acm.config.HTTPPort > 0 {
		err = client.Challenge.SetHTTP01Provider(http01.NewProviderServer("", fmt.Sprintf("%d", acm.config.HTTPPort)))
		if err != nil {
			return fmt.Errorf("acme: set HTTP-01 provider: %w", err)
		}
	}
	if acm.config.TLSPort > 0 {
		err = client.Challenge.SetTLSALPN01Provider(tlsalpn01.NewProviderServer("", fmt.Sprintf("%d", acm.config.TLSPort)))
		if err != nil {
			return fmt.Errorf("acme: set TLS-ALPN-01 provider: %w", err)
		}
	}

	// Register if needed
	if user.Registration == nil {
		acm.logger.Info("registering ACME account", "email", user.Email, "ca", acm.config.CA)

		var reg *registration.Resource
		if acm.config.EABKeyID != "" && acm.config.EABMACKey != "" {
			reg, err = client.Registration.RegisterWithExternalAccountBinding(registration.RegisterEABOptions{
				TermsOfServiceAgreed: true,
				Kid:                  acm.config.EABKeyID,
				HmacEncoded:          acm.config.EABMACKey,
			})
		} else {
			reg, err = client.Registration.Register(registration.RegisterOptions{
				TermsOfServiceAgreed: true,
			})
		}
		if err != nil {
			return fmt.Errorf("acme: register account: %w", err)
		}
		user.Registration = reg
		if err := acm.saveUser(user); err != nil {
			return fmt.Errorf("acme: save user after registration: %w", err)
		}
		acm.logger.Info("ACME account registered", "email", user.Email)
	}

	// Load existing certificates
	if err := acm.loadCertificates(); err != nil {
		acm.logger.Warn("failed to load existing certificates", "error", err)
	}

	return nil
}

// ObtainCertificates obtains certificates for all configured domains.
func (acm *ACMECertManager) ObtainCertificates(ctx context.Context) error {
	for _, domain := range acm.config.Domains {
		if err := acm.obtainCertificate(ctx, domain); err != nil {
			if acm.OnError != nil {
				acm.OnError(domain, err)
			}
			return fmt.Errorf("acme: obtain certificate for %s: %w", domain, err)
		}
	}
	return nil
}

func (acm *ACMECertManager) obtainCertificate(ctx context.Context, domain string) error {
	// Check if we already have a valid certificate
	acm.mu.RLock()
	cert, exists := acm.certs[domain]
	acm.mu.RUnlock()

	if exists && cert != nil {
		// Check if renewal is needed
		x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
		if err == nil && time.Until(x509Cert.NotAfter) > acm.config.RenewBefore {
			acm.logger.Debug("certificate still valid", "domain", domain, "expires", x509Cert.NotAfter)
			return nil
		}
	}

	acm.logger.Info("obtaining certificate", "domain", domain)

	request := certificate.ObtainRequest{
		Domains: []string{domain},
		Bundle:  true,
	}

	certificates, err := acm.client.Certificate.Obtain(request)
	if err != nil {
		return fmt.Errorf("obtain: %w", err)
	}

	// Parse and store certificate
	tlsCert, err := tls.X509KeyPair(certificates.Certificate, certificates.PrivateKey)
	if err != nil {
		return fmt.Errorf("parse certificate: %w", err)
	}

	acm.mu.Lock()
	acm.certs[domain] = &tlsCert
	acm.mu.Unlock()

	// Save to disk
	if err := acm.saveCertificate(domain, certificates); err != nil {
		acm.logger.Warn("failed to save certificate", "domain", domain, "error", err)
	}

	if acm.OnCertObtained != nil {
		acm.OnCertObtained(domain)
	}

	acm.logger.Info("certificate obtained", "domain", domain)
	return nil
}

// GetCertificate returns a TLS certificate for the given host.
// This is suitable for use as tls.Config.GetCertificate.
func (acm *ACMECertManager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	host := hello.ServerName
	if host == "" {
		return nil, errors.New("acme: no SNI provided")
	}
	return acm.GetCertificateForHost(host)
}

// GetCertificateForHost returns a TLS certificate for the given hostname.
func (acm *ACMECertManager) GetCertificateForHost(host string) (*tls.Certificate, error) {
	acm.mu.RLock()
	cert, ok := acm.certs[host]
	acm.mu.RUnlock()

	if ok && cert != nil {
		return cert, nil
	}

	// Check if this host is in our configured domains
	for _, domain := range acm.config.Domains {
		if domain == host {
			// Try to obtain on-demand
			if err := acm.obtainCertificate(acm.ctx, host); err != nil {
				return nil, fmt.Errorf("acme: obtain certificate: %w", err)
			}
			acm.mu.RLock()
			cert = acm.certs[host]
			acm.mu.RUnlock()
			if cert != nil {
				return cert, nil
			}
		}
	}

	return nil, fmt.Errorf("acme: no certificate for host %s", host)
}

// StartAutoRenewal starts a background goroutine that renews certificates
// before they expire.
func (acm *ACMECertManager) StartAutoRenewal(checkInterval time.Duration) {
	if checkInterval == 0 {
		checkInterval = 12 * time.Hour
	}

	acm.wg.Add(1)
	go func() {
		defer acm.wg.Done()
		ticker := time.NewTicker(checkInterval)
		defer ticker.Stop()

		for {
			select {
			case <-acm.ctx.Done():
				return
			case <-ticker.C:
				acm.renewExpiring()
			}
		}
	}()

	acm.logger.Info("started certificate auto-renewal", "interval", checkInterval)
}

func (acm *ACMECertManager) renewExpiring() {
	acm.mu.RLock()
	domains := make([]string, 0, len(acm.certs))
	for domain := range acm.certs {
		domains = append(domains, domain)
	}
	acm.mu.RUnlock()

	for _, domain := range domains {
		acm.mu.RLock()
		cert := acm.certs[domain]
		acm.mu.RUnlock()

		if cert == nil {
			continue
		}

		x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			acm.logger.Warn("failed to parse certificate for renewal check", "domain", domain, "error", err)
			continue
		}

		if time.Until(x509Cert.NotAfter) <= acm.config.RenewBefore {
			acm.logger.Info("renewing certificate", "domain", domain, "expires", x509Cert.NotAfter)
			if err := acm.obtainCertificate(acm.ctx, domain); err != nil {
				acm.logger.Error("failed to renew certificate", "domain", domain, "error", err)
				if acm.OnError != nil {
					acm.OnError(domain, err)
				}
			} else if acm.OnCertRenewed != nil {
				acm.OnCertRenewed(domain)
			}
		}
	}
}

// Close stops background renewal and releases resources.
func (acm *ACMECertManager) Close() error {
	acm.cancel()
	acm.wg.Wait()
	return nil
}

// CacheSize returns the number of cached certificates.
func (acm *ACMECertManager) CacheSize() int {
	acm.mu.RLock()
	defer acm.mu.RUnlock()
	return len(acm.certs)
}

func (acm *ACMECertManager) parseKeyType() certcrypto.KeyType {
	switch acm.config.KeyType {
	case "ec256":
		return certcrypto.EC256
	case "ec384":
		return certcrypto.EC384
	case "rsa2048":
		return certcrypto.RSA2048
	case "rsa4096":
		return certcrypto.RSA4096
	case "rsa8192":
		return certcrypto.RSA8192
	default:
		return certcrypto.EC256
	}
}

func (acm *ACMECertManager) userPath() string {
	return filepath.Join(acm.config.StoragePath, "account.json")
}

func (acm *ACMECertManager) certPath(domain string) string {
	return filepath.Join(acm.config.StoragePath, "certificates", domain)
}

func (acm *ACMECertManager) loadOrCreateUser() (*acmeUser, error) {
	userPath := acm.userPath()

	// Try to load existing user
	data, err := os.ReadFile(userPath)
	if err == nil {
		var user acmeUser
		if err := json.Unmarshal(data, &user); err != nil {
			return nil, fmt.Errorf("parse user data: %w", err)
		}

		// Parse the key
		if len(user.keyPEM) > 0 {
			block, _ := pem.Decode(user.keyPEM)
			if block != nil {
				key, err := x509.ParseECPrivateKey(block.Bytes)
				if err != nil {
					// Try PKCS8
					pkcs8Key, err2 := x509.ParsePKCS8PrivateKey(block.Bytes)
					if err2 != nil {
						return nil, fmt.Errorf("parse user key: %w (also tried PKCS8: %v)", err, err2)
					}
					user.key = pkcs8Key
				} else {
					user.key = key
				}
			}
		}

		return &user, nil
	}

	// Create new user
	acm.logger.Info("creating new ACME account")

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}

	keyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("marshal key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})

	user := &acmeUser{
		Email:  acm.config.Email,
		key:    privateKey,
		keyPEM: keyPEM,
	}

	return user, nil
}

func (acm *ACMECertManager) saveUser(user *acmeUser) error {
	data, err := json.MarshalIndent(user, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal user: %w", err)
	}

	if err := os.WriteFile(acm.userPath(), data, 0600); err != nil {
		return fmt.Errorf("write user file: %w", err)
	}

	return nil
}

func (acm *ACMECertManager) loadCertificates() error {
	certsDir := filepath.Join(acm.config.StoragePath, "certificates")
	entries, err := os.ReadDir(certsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		domain := entry.Name()
		certPath := filepath.Join(certsDir, domain, "certificate.pem")
		keyPath := filepath.Join(certsDir, domain, "private_key.pem")

		certPEM, err := os.ReadFile(certPath)
		if err != nil {
			acm.logger.Warn("failed to read certificate", "domain", domain, "error", err)
			continue
		}

		keyPEM, err := os.ReadFile(keyPath)
		if err != nil {
			acm.logger.Warn("failed to read private key", "domain", domain, "error", err)
			continue
		}

		tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			acm.logger.Warn("failed to parse certificate", "domain", domain, "error", err)
			continue
		}

		// Check expiration
		x509Cert, err := x509.ParseCertificate(tlsCert.Certificate[0])
		if err != nil {
			acm.logger.Warn("failed to parse x509 certificate", "domain", domain, "error", err)
			continue
		}

		if time.Now().After(x509Cert.NotAfter) {
			acm.logger.Warn("certificate expired", "domain", domain, "expired", x509Cert.NotAfter)
			continue
		}

		acm.mu.Lock()
		acm.certs[domain] = &tlsCert
		acm.mu.Unlock()

		acm.logger.Debug("loaded certificate", "domain", domain, "expires", x509Cert.NotAfter)
	}

	return nil
}

func (acm *ACMECertManager) saveCertificate(domain string, cert *certificate.Resource) error {
	certDir := acm.certPath(domain)
	if err := os.MkdirAll(certDir, 0700); err != nil {
		return fmt.Errorf("create certificate directory: %w", err)
	}

	if err := os.WriteFile(filepath.Join(certDir, "certificate.pem"), cert.Certificate, 0600); err != nil {
		return fmt.Errorf("write certificate: %w", err)
	}

	if err := os.WriteFile(filepath.Join(certDir, "private_key.pem"), cert.PrivateKey, 0600); err != nil {
		return fmt.Errorf("write private key: %w", err)
	}

	if cert.IssuerCertificate != nil {
		if err := os.WriteFile(filepath.Join(certDir, "issuer.pem"), cert.IssuerCertificate, 0600); err != nil {
			return fmt.Errorf("write issuer certificate: %w", err)
		}
	}

	// Save metadata
	meta := map[string]any{
		"domain":    cert.Domain,
		"stable_url": cert.CertStableURL,
		"obtained":  time.Now().Format(time.RFC3339),
	}
	metaData, _ := json.MarshalIndent(meta, "", "  ")
	if err := os.WriteFile(filepath.Join(certDir, "metadata.json"), metaData, 0600); err != nil {
		return fmt.Errorf("write metadata: %w", err)
	}

	return nil
}
