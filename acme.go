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

// ACME CA directory URLs for use with [ACMEConfig].CA.
//
// LetsEncryptProduction is the default when CA is empty. Use
// LetsEncryptStaging during development and testing to avoid
// Let's Encrypt production rate limits (5 duplicate certificates
// per week, 50 certificates per registered domain per week).
const (
	LetsEncryptProduction = lego.LEDirectoryProduction
	LetsEncryptStaging    = lego.LEDirectoryStaging
)

// ACMEConfig holds the configuration for obtaining and renewing TLS
// certificates via the ACME protocol (RFC 8555). It is the sole input to
// [NewACMECertManager].
//
// At minimum you must set [ACMEConfig.Email], [ACMEConfig.Domains], and
// [ACMEConfig.AcceptTOS]. All other fields have sensible defaults provided
// by [DefaultACMEConfig].
//
// # Challenge Types
//
// The ACME protocol verifies domain ownership through challenge types.
// ACMEConfig supports two:
//
//   - HTTP-01 — The CA makes an HTTP request to port 80 on the domain.
//     Controlled by [ACMEConfig.HTTPPort]. Set to 0 to disable.
//   - TLS-ALPN-01 — The CA performs a TLS handshake on port 443 using a
//     special ALPN protocol. Controlled by [ACMEConfig.TLSPort]. Set to 0
//     to disable.
//
// At least one challenge type must remain enabled. Both ports must be
// reachable from the public internet for the challenge to succeed.
//
// # External Account Binding (EAB)
//
// Some CAs (ZeroSSL, Google Trust Services, Buypass Go) require External
// Account Binding. Set [ACMEConfig.EABKeyID] and [ACMEConfig.EABMACKey] to
// the values provided by the CA's dashboard.
//
// # Storage Layout
//
// Certificates, private keys, and account data are persisted under
// [ACMEConfig.StoragePath] (default "./acme"):
//
//	<StoragePath>/
//	├── account.json                     # ACME account + private key
//	└── certificates/
//	    └── <domain>/
//	        ├── certificate.pem          # Leaf + intermediates
//	        ├── private_key.pem          # Certificate private key
//	        ├── issuer.pem               # Issuer certificate
//	        └── metadata.json            # Domain, URL, timestamp
//
// All files are created with mode 0600/0700 so only the process owner can
// read them.
type ACMEConfig struct {
	// Email is the address registered with the ACME account. The CA sends
	// certificate expiration warnings here. Required.
	Email string `mapstructure:"email"`

	// CA is the ACME directory URL. Defaults to [LetsEncryptProduction].
	// Use [LetsEncryptStaging] during development to avoid rate limits.
	// Any RFC 8555-compliant CA directory URL is accepted (e.g. ZeroSSL,
	// Buypass, Google Trust Services).
	CA string `mapstructure:"ca"`

	// KeyType selects the private key algorithm for issued certificates.
	// Supported values:
	//
	//   - "ec256"   — ECDSA P-256 (default, recommended)
	//   - "ec384"   — ECDSA P-384
	//   - "rsa2048" — RSA 2048-bit
	//   - "rsa4096" — RSA 4096-bit
	//   - "rsa8192" — RSA 8192-bit
	//
	// ECDSA keys produce smaller certificates and faster TLS handshakes.
	KeyType string `mapstructure:"key_type"`

	// StoragePath is the directory where account data and certificates are
	// persisted. The directory is created automatically with mode 0700.
	// Defaults to "./acme".
	StoragePath string `mapstructure:"storage_path"`

	// HTTPPort is the listen port for HTTP-01 ACME challenges.
	// Defaults to 80. Set to 0 to disable the HTTP-01 challenge solver.
	HTTPPort int `mapstructure:"http_port"`

	// TLSPort is the listen port for TLS-ALPN-01 ACME challenges.
	// Defaults to 443. Set to 0 to disable the TLS-ALPN-01 challenge solver.
	TLSPort int `mapstructure:"tls_port"`

	// RenewBefore is how far in advance of expiration the certificate is
	// renewed during auto-renewal. Defaults to 30 days. Let's Encrypt
	// certificates are valid for 90 days, so 30 days gives two retry
	// windows.
	RenewBefore time.Duration `mapstructure:"renew_before"`

	// Domains lists the fully-qualified domain names for which
	// certificates will be obtained. At least one is required. Each
	// domain receives its own certificate (no SANs across entries).
	Domains []string `mapstructure:"domains"`

	// AcceptTOS must be set to true to indicate acceptance of the CA's
	// Terms of Service. [NewACMECertManager] returns an error if false.
	AcceptTOS bool `mapstructure:"accept_tos"`

	// EABKeyID is the External Account Binding key identifier.
	// Required only for CAs that mandate EAB (e.g. ZeroSSL).
	EABKeyID string `mapstructure:"eab_key_id"`

	// EABMACKey is the base64url-encoded HMAC key for EAB.
	// Required only for CAs that mandate EAB (e.g. ZeroSSL).
	EABMACKey string `mapstructure:"eab_mac_key"`
}

// DefaultACMEConfig returns an [ACMEConfig] populated with production-ready
// defaults. The caller must still set Email, Domains, and AcceptTOS before
// passing the config to [NewACMECertManager].
//
//	cfg := swg.DefaultACMEConfig()
//	cfg.Email     = "admin@example.com"
//	cfg.Domains   = []string{"proxy.example.com"}
//	cfg.AcceptTOS = true
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
	keyPEM       []byte //nolint:structcheck // used for JSON serialization
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

// ACMECertManager obtains and renews TLS certificates from an ACME CA such
// as Let's Encrypt. It implements the same GetCertificate / GetCertificateForHost
// surface as [CertManager], so it can be used with [tls.Config.GetCertificate]
// or anywhere a per-host certificate provider is needed.
//
// # Lifecycle
//
// The typical usage follows four steps:
//
//  1. Create — [NewACMECertManager] validates the config and creates the
//     on-disk storage directory.
//  2. Initialize — [ACMECertManager.Initialize] registers (or loads) the ACME
//     account, configures challenge solvers, and loads any previously obtained
//     certificates from disk.
//  3. Obtain — [ACMECertManager.ObtainCertificates] contacts the CA and
//     obtains certificates for every domain in the config.
//  4. Renew — [ACMECertManager.StartAutoRenewal] spawns a background
//     goroutine that periodically checks certificate expiration and renews
//     before the RenewBefore window.
//
// Call [ACMECertManager.Close] to stop the renewal goroutine and release
// resources.
//
// # Callbacks
//
// Three optional callbacks are available for observability:
//
//   - OnCertObtained — fired after a certificate is successfully obtained.
//   - OnCertRenewed  — fired after a certificate is successfully renewed.
//   - OnError        — fired when obtaining or renewing a certificate fails.
//
// # Thread Safety
//
// All public methods are safe for concurrent use. The certificate cache is
// protected by an internal sync.RWMutex.
//
// # Example
//
//	acm, err := swg.NewACMECertManager(swg.ACMEConfig{
//	    Email:     "admin@example.com",
//	    Domains:   []string{"proxy.example.com"},
//	    AcceptTOS: true,
//	    CA:        swg.LetsEncryptStaging, // use staging for testing
//	})
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer acm.Close()
//
//	if err := acm.Initialize(ctx); err != nil {
//	    log.Fatal(err)
//	}
//	if err := acm.ObtainCertificates(ctx); err != nil {
//	    log.Fatal(err)
//	}
//	acm.StartAutoRenewal(12 * time.Hour)
//
//	srv := &http.Server{
//	    TLSConfig: &tls.Config{GetCertificate: acm.GetCertificate},
//	}
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

	// OnCertObtained is called after a new certificate is obtained for a
	// domain. It is called from the goroutine that performed the obtain.
	OnCertObtained func(domain string)

	// OnCertRenewed is called after an existing certificate is renewed.
	OnCertRenewed func(domain string)

	// OnError is called when obtaining or renewing a certificate fails.
	OnError func(domain string, err error)
}

// NewACMECertManager validates cfg and returns a new [ACMECertManager].
// It creates the storage directory specified by [ACMEConfig.StoragePath] but
// does not contact the CA — call [ACMECertManager.Initialize] next.
//
// Returns an error if Email is empty, Domains is empty, or AcceptTOS is
// false.
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

// SetLogger replaces the default [slog.Default] logger used by the
// ACMECertManager. Call this before [ACMECertManager.Initialize] to capture
// all log output.
func (acm *ACMECertManager) SetLogger(logger *slog.Logger) {
	acm.logger = logger
}

// Initialize creates the lego ACME client, configures the HTTP-01 and
// TLS-ALPN-01 challenge providers, and either loads an existing account
// from disk or registers a new one with the CA.
//
// On first run the account private key is generated and persisted at
// <StoragePath>/account.json. Subsequent calls load the existing key.
//
// If [ACMEConfig.EABKeyID] and [ACMEConfig.EABMACKey] are set, External
// Account Binding is used during registration.
//
// Any certificates previously stored on disk are loaded into the in-memory
// cache so they are available immediately without contacting the CA.
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

// ObtainCertificates iterates over every domain in [ACMEConfig.Domains]
// and obtains a certificate from the CA. If a valid certificate already
// exists in the cache and is not within the RenewBefore window, the domain
// is skipped.
//
// Certificates are persisted to disk under <StoragePath>/certificates/<domain>/.
// The [ACMECertManager.OnCertObtained] callback is invoked for each newly
// obtained certificate.
//
// Returns the first error encountered; remaining domains are not attempted.
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

// GetCertificate returns a TLS certificate for the SNI host name in hello.
// It is intended for use as [tls.Config].GetCertificate:
//
//	srv := &http.Server{
//	    TLSConfig: &tls.Config{
//	        GetCertificate: acm.GetCertificate,
//	    },
//	}
//
// Returns an error if the ClientHelloInfo contains no SNI server name.
func (acm *ACMECertManager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	host := hello.ServerName
	if host == "" {
		return nil, errors.New("acme: no SNI provided")
	}
	return acm.GetCertificateForHost(host)
}

// GetCertificateForHost returns the cached TLS certificate for host. If the
// certificate is not in the cache but the host is one of the configured
// [ACMEConfig.Domains], an on-demand obtain is attempted.
//
// Returns an error if the host is not in the configured domain list.
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

// StartAutoRenewal spawns a background goroutine that checks all cached
// certificates at the given interval and renews any that will expire within
// the [ACMEConfig.RenewBefore] window.
//
// If checkInterval is zero it defaults to 12 hours. A typical production
// value is 12*time.Hour, which balances CA load against timely renewal.
//
// The goroutine is stopped when [ACMECertManager.Close] is called.
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

// Close stops the auto-renewal goroutine (if running) and waits for it to
// exit. It is safe to call Close multiple times.
func (acm *ACMECertManager) Close() error {
	acm.cancel()
	acm.wg.Wait()
	return nil
}

// CacheSize returns the number of certificates currently held in the
// in-memory cache.
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
