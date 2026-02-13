// Example: Using SWG with Let's Encrypt (ACME) certificates
//
// This example demonstrates obtaining and auto-renewing certificates from
// Let's Encrypt using the ACME protocol. No self-signed CA required!
//
// Prerequisites:
//   - Domain name pointing to this server
//   - Ports 80 and 443 accessible from the internet (for ACME challenges)
//
// Usage:
//
//	# For testing, use staging to avoid rate limits
//	go run . -email admin@example.com -domain proxy.example.com -staging
//
//	# For production
//	go run . -email admin@example.com -domain proxy.example.com
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/acmacalister/swg"
)

func main() {
	email := flag.String("email", "", "email for ACME account (required)")
	domain := flag.String("domain", "", "domain to obtain certificate for (required)")
	staging := flag.Bool("staging", false, "use Let's Encrypt staging environment")
	storagePath := flag.String("storage", "./acme", "path to store certificates")
	httpPort := flag.Int("http-port", 80, "port for HTTP-01 challenge (0 to disable)")
	tlsPort := flag.Int("tls-port", 443, "port for TLS-ALPN-01 challenge (0 to disable)")
	proxyAddr := flag.String("addr", ":8443", "proxy listen address")
	verbose := flag.Bool("v", false, "verbose logging")
	flag.Parse()

	if *email == "" || *domain == "" {
		flag.Usage()
		log.Fatal("email and domain are required")
	}

	// Configure logger
	logLevel := slog.LevelInfo
	if *verbose {
		logLevel = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel}))

	// Configure ACME
	acmeCfg := swg.ACMEConfig{
		Email:       *email,
		Domains:     []string{*domain},
		AcceptTOS:   true,
		StoragePath: *storagePath,
		HTTPPort:    *httpPort,
		TLSPort:     *tlsPort,
		RenewBefore: 30 * 24 * time.Hour, // 30 days
	}

	if *staging {
		acmeCfg.CA = swg.LetsEncryptStaging
		logger.Info("using Let's Encrypt staging environment")
	}

	// Create ACME certificate manager
	acm, err := swg.NewACMECertManager(acmeCfg)
	if err != nil {
		log.Fatalf("Failed to create ACME cert manager: %v", err)
	}
	defer acm.Close()

	acm.SetLogger(logger)

	// Set up callbacks
	acm.OnCertObtained = func(domain string) {
		logger.Info("certificate obtained", "domain", domain)
	}
	acm.OnCertRenewed = func(domain string) {
		logger.Info("certificate renewed", "domain", domain)
	}
	acm.OnError = func(domain string, err error) {
		logger.Error("certificate error", "domain", domain, "error", err)
	}

	// Initialize ACME client and register account
	ctx := context.Background()
	logger.Info("initializing ACME client", "email", *email, "domain", *domain)
	if err := acm.Initialize(ctx); err != nil {
		log.Fatalf("Failed to initialize ACME: %v", err)
	}

	// Obtain initial certificates
	logger.Info("obtaining certificates")
	if err := acm.ObtainCertificates(ctx); err != nil {
		log.Fatalf("Failed to obtain certificates: %v", err)
	}

	// Start auto-renewal (checks every 12 hours)
	acm.StartAutoRenewal(12 * time.Hour)

	// Create proxy - Note: ACMECertManager implements the same interface as CertManager
	// For MITM proxying, you may still want to use a self-signed CA for per-host certs.
	// This example shows how to use ACME for the proxy's own TLS certificate.

	// For this example, we'll create a simple HTTPS server that uses ACME certs
	// In a real scenario, you'd combine this with a CertManager for MITM certs.

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("SWG Proxy with Let's Encrypt!\n"))
		w.Write([]byte("Domain: " + *domain + "\n"))
	})

	server := &http.Server{
		Addr:    *proxyAddr,
		Handler: mux,
		TLSConfig: &tls.Config{
			GetCertificate: acm.GetCertificate,
			MinVersion:     tls.VersionTLS12,
		},
	}

	// Graceful shutdown
	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-done
		logger.Info("shutting down")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		server.Shutdown(ctx)
	}()

	// Start server
	logger.Info("starting server", "addr", *proxyAddr, "domain", *domain)
	if err := server.ListenAndServeTLS("", ""); err != http.ErrServerClosed {
		log.Fatalf("Server error: %v", err)
	}
}
