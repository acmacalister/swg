// Example: SWG proxy with DNS-01 ACME challenge for wildcard certificates
//
// This example demonstrates how to use DNS-01 challenges to obtain wildcard
// certificates (*.example.com) from Let's Encrypt. DNS-01 is required for:
//   - Wildcard certificates
//   - Environments where ports 80/443 are not publicly accessible
//   - Internal/private domains
//
// The example uses Cloudflare DNS, but Route53, Google Cloud DNS, and
// DigitalOcean are also supported. Set -provider to switch.
//
// Prerequisites:
//   - A domain with DNS managed by a supported provider
//   - API credentials for the DNS provider
//   - A self-signed CA cert/key pair (generate with: go run ../../cmd -gen-ca)
//
// Usage:
//
//	# Cloudflare (using API token):
//	export CF_API_TOKEN="your-cloudflare-api-token"
//	go run . -email admin@example.com -domain "*.example.com" -provider cloudflare
//
//	# AWS Route 53:
//	export AWS_ACCESS_KEY_ID="your-access-key"
//	export AWS_SECRET_ACCESS_KEY="your-secret-key"
//	go run . -email admin@example.com -domain "*.example.com" -provider route53
//
//	# Google Cloud DNS:
//	export GOOGLE_APPLICATION_CREDENTIALS="/path/to/service-account.json"
//	go run . -email admin@example.com -domain "*.example.com" -provider gcloud \
//	    -gcloud-project your-project-id
//
//	# DigitalOcean:
//	export DO_AUTH_TOKEN="your-digitalocean-token"
//	go run . -email admin@example.com -domain "*.example.com" -provider digitalocean
//
//	# Staging mode (recommended for testing):
//	go run . -email admin@example.com -domain "*.example.com" -provider cloudflare -staging
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/acmacalister/swg"
)

func main() {
	// ACME configuration
	email := flag.String("email", "", "ACME account email (required)")
	domain := flag.String("domain", "", "domain to obtain certificate for, e.g. *.example.com (required)")
	staging := flag.Bool("staging", false, "use Let's Encrypt staging environment")
	storagePath := flag.String("storage", "./acme", "certificate storage directory")

	// DNS-01 provider configuration
	provider := flag.String("provider", "cloudflare", "DNS provider: cloudflare, route53, gcloud, digitalocean")
	propagationTimeout := flag.Duration("propagation-timeout", 2*time.Minute, "DNS propagation timeout")
	pollingInterval := flag.Duration("polling-interval", 5*time.Second, "DNS propagation polling interval")
	disablePropCheck := flag.Bool("disable-propagation-check", false, "skip DNS propagation verification")

	// Provider-specific flags
	cfAPIToken := flag.String("cf-api-token", "", "Cloudflare API token (or set CF_API_TOKEN env)")
	cfZoneID := flag.String("cf-zone-id", "", "Cloudflare zone ID (optional, auto-detected)")
	gcloudProject := flag.String("gcloud-project", "", "Google Cloud project ID")
	gcloudServiceFile := flag.String("gcloud-service-file", "", "Google Cloud service account JSON file")
	r53Region := flag.String("r53-region", "us-east-1", "AWS Route 53 region")
	r53HostedZone := flag.String("r53-hosted-zone", "", "AWS Route 53 hosted zone ID (optional)")
	doToken := flag.String("do-token", "", "DigitalOcean API token (or set DO_AUTH_TOKEN env)")

	// Proxy configuration
	proxyAddr := flag.String("addr", ":8443", "proxy listen address")
	caCert := flag.String("ca-cert", "ca.crt", "path to MITM CA certificate")
	caKey := flag.String("ca-key", "ca.key", "path to MITM CA private key")
	blockDomains := flag.String("block", "", "comma-separated domains to block")
	verbose := flag.Bool("v", false, "verbose logging")
	flag.Parse()

	if *email == "" || *domain == "" {
		flag.Usage()
		log.Fatal("email and domain are required")
	}

	logLevel := slog.LevelInfo
	if *verbose {
		logLevel = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel}))

	// ---------------------------------------------------------------
	// 1. Create the DNS-01 challenge provider
	// ---------------------------------------------------------------
	dns01Cfg := swg.DNS01Config{
		Provider:                *provider,
		PropagationTimeout:      *propagationTimeout,
		PollingInterval:         *pollingInterval,
		DisablePropagationCheck: *disablePropCheck,
	}

	// Set provider-specific credentials
	switch *provider {
	case "cloudflare":
		if *cfAPIToken != "" {
			dns01Cfg.CloudflareAPIToken = *cfAPIToken
		} else if token := os.Getenv("CF_API_TOKEN"); token != "" {
			dns01Cfg.CloudflareAPIToken = token
		} else if key := os.Getenv("CF_API_KEY"); key != "" {
			dns01Cfg.CloudflareAPIKey = key
			dns01Cfg.CloudflareEmail = os.Getenv("CF_API_EMAIL")
		}
		dns01Cfg.CloudflareZoneID = *cfZoneID

	case "route53":
		if key := os.Getenv("AWS_ACCESS_KEY_ID"); key != "" {
			dns01Cfg.Route53AccessKeyID = key
			dns01Cfg.Route53SecretAccessKey = os.Getenv("AWS_SECRET_ACCESS_KEY")
		}
		dns01Cfg.Route53Region = *r53Region
		dns01Cfg.Route53HostedZoneID = *r53HostedZone

	case "gcloud":
		dns01Cfg.GCloudProject = *gcloudProject
		dns01Cfg.GCloudServiceFile = *gcloudServiceFile

	case "digitalocean":
		if *doToken != "" {
			dns01Cfg.DigitalOceanToken = *doToken
		} else if token := os.Getenv("DO_AUTH_TOKEN"); token != "" {
			dns01Cfg.DigitalOceanToken = token
		}
	}

	dns01Provider, err := swg.NewDNS01ChallengeProvider(dns01Cfg)
	if err != nil {
		log.Fatalf("create DNS-01 provider: %v", err)
	}
	logger.Info("DNS-01 provider configured",
		"provider", *provider,
		"propagation_timeout", *propagationTimeout,
		"polling_interval", *pollingInterval,
	)

	// ---------------------------------------------------------------
	// 2. Set up the ACME certificate manager
	// ---------------------------------------------------------------
	// For wildcard certs, we need both the wildcard and base domain
	domains := []string{*domain}
	if swg.IsWildcardDomain(*domain) {
		baseDomain := swg.BaseDomain(*domain)
		domains = append(domains, baseDomain)
		logger.Info("requesting wildcard certificate", "domains", domains)
	}

	acmeCfg := swg.ACMEConfig{
		Email:       *email,
		Domains:     domains,
		AcceptTOS:   true,
		StoragePath: *storagePath,
		HTTPPort:    0, // Disable HTTP-01 (we're using DNS-01)
		TLSPort:     0, // Disable TLS-ALPN-01 (we're using DNS-01)
		RenewBefore: 30 * 24 * time.Hour,
	}
	if *staging {
		acmeCfg.CA = swg.LetsEncryptStaging
		logger.Info("using Let's Encrypt staging environment")
	}

	acm, err := swg.NewACMECertManager(acmeCfg)
	if err != nil {
		log.Fatalf("create ACME cert manager: %v", err)
	}
	acm.SetLogger(logger)

	acm.OnCertObtained = func(d string) { logger.Info("certificate obtained", "domain", d) }
	acm.OnCertRenewed = func(d string) { logger.Info("certificate renewed", "domain", d) }
	acm.OnError = func(d string, e error) { logger.Error("certificate error", "domain", d, "error", e) }

	// ---------------------------------------------------------------
	// 3. Initialize ACME and configure DNS-01 challenge
	// ---------------------------------------------------------------
	ctx := context.Background()

	if err := acm.Initialize(ctx); err != nil {
		log.Fatalf("ACME initialize: %v", err)
	}

	// Set DNS-01 provider AFTER Initialize but BEFORE ObtainCertificates
	if err := acm.SetDNS01Provider(dns01Provider); err != nil {
		log.Fatalf("set DNS-01 provider: %v", err)
	}
	logger.Info("DNS-01 challenge configured")

	// Obtain certificates using DNS-01
	logger.Info("obtaining certificates via DNS-01 challenge...")
	if err := acm.ObtainCertificates(ctx); err != nil {
		log.Fatalf("ACME obtain certificates: %v", err)
	}
	logger.Info("certificates obtained successfully", "count", acm.CacheSize())

	// Start auto-renewal
	acm.StartAutoRenewal(12 * time.Hour)

	// ---------------------------------------------------------------
	// 4. Set up the self-signed CA CertManager for MITM per-host certs
	// ---------------------------------------------------------------
	cm, err := swg.NewCertManager(*caCert, *caKey)
	if err != nil {
		log.Fatalf("load CA: %v", err)
	}

	// ---------------------------------------------------------------
	// 5. Create the proxy with optional domain filtering
	// ---------------------------------------------------------------
	proxy := swg.NewProxy(*proxyAddr, cm)
	proxy.Logger = logger
	proxy.BlockPage = swg.NewBlockPage()

	if *blockDomains != "" {
		filter := swg.NewDomainFilter()
		for _, d := range splitDomains(*blockDomains) {
			filter.AddDomain(d)
		}
		proxy.Filter = filter
	}

	// ---------------------------------------------------------------
	// 6. Wrap the proxy listener with ACME-managed TLS
	// ---------------------------------------------------------------
	ln, err := net.Listen("tcp", *proxyAddr)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	tlsLn := tls.NewListener(ln, &tls.Config{
		GetCertificate: acm.GetCertificate,
		MinVersion:     tls.VersionTLS12,
	})

	// ---------------------------------------------------------------
	// 7. Graceful shutdown on SIGINT / SIGTERM
	// ---------------------------------------------------------------
	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-done
		logger.Info("shutting down")
		shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := proxy.Shutdown(shutCtx); err != nil {
			logger.Error("shutdown error", "error", err)
		}
		if err := acm.Close(); err != nil {
			logger.Error("ACME close error", "error", err)
		}
	}()

	logger.Info("starting proxy with DNS-01 ACME certificates",
		"addr", *proxyAddr,
		"domains", domains,
		"provider", *provider,
		"staging", *staging,
	)

	srv := &http.Server{Handler: proxy}
	if err := srv.Serve(tlsLn); err != nil && err != http.ErrServerClosed {
		log.Fatalf("serve: %v", err)
	}
}

func splitDomains(s string) []string {
	var out []string
	start := 0
	for i := range len(s) {
		if s[i] == ',' {
			d := trim(s[start:i])
			if d != "" {
				out = append(out, d)
			}
			start = i + 1
		}
	}
	if d := trim(s[start:]); d != "" {
		out = append(out, d)
	}
	return out
}

func trim(s string) string {
	for len(s) > 0 && s[0] == ' ' {
		s = s[1:]
	}
	for len(s) > 0 && s[len(s)-1] == ' ' {
		s = s[:len(s)-1]
	}
	return s
}

func init() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: dns01 [flags]\n\n")
		fmt.Fprintf(os.Stderr, "Run an SWG MITM proxy with DNS-01 ACME challenge for wildcard certificates.\n\n")
		fmt.Fprintf(os.Stderr, "This example uses Cloudflare by default. Set -provider to use a different\n")
		fmt.Fprintf(os.Stderr, "DNS provider (route53, gcloud, digitalocean).\n\n")
		fmt.Fprintf(os.Stderr, "Environment variables:\n")
		fmt.Fprintf(os.Stderr, "  CF_API_TOKEN           Cloudflare API token\n")
		fmt.Fprintf(os.Stderr, "  CF_API_KEY/EMAIL       Cloudflare API key (legacy)\n")
		fmt.Fprintf(os.Stderr, "  AWS_ACCESS_KEY_ID      AWS access key for Route 53\n")
		fmt.Fprintf(os.Stderr, "  AWS_SECRET_ACCESS_KEY  AWS secret key for Route 53\n")
		fmt.Fprintf(os.Stderr, "  GOOGLE_APPLICATION_CREDENTIALS  GCP service account JSON path\n")
		fmt.Fprintf(os.Stderr, "  DO_AUTH_TOKEN          DigitalOcean API token\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
	}
}
