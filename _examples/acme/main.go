// Example: SWG proxy with ACME / Let's Encrypt certificates
//
// This example shows how to combine an ACME-managed listener certificate
// (for the proxy's own TLS) with a self-signed CA CertManager (for MITM
// per-host certificate generation). The result is a proxy whose clients
// see a valid, publicly-trusted certificate when connecting, while
// intercepted upstream connections use dynamically generated certificates
// signed by the local CA.
//
// Prerequisites:
//   - A public DNS A/AAAA record pointing to this server.
//   - Ports 80 and 443 reachable from the internet (ACME challenges).
//   - A self-signed CA cert/key pair (generate with: go run ../../cmd -gen-ca).
//
// Usage:
//
//	# Staging (recommended for testing — avoids Let's Encrypt rate limits):
//	go run . -email admin@example.com -domain proxy.example.com -staging
//
//	# Production:
//	go run . -email admin@example.com -domain proxy.example.com
//
//	# With ZeroSSL (requires External Account Binding):
//	go run . -email admin@example.com -domain proxy.example.com \
//	    -eab-kid <key-id> -eab-hmac <hmac-key>
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
	email := flag.String("email", "", "ACME account email (required)")
	domain := flag.String("domain", "", "domain to obtain certificate for (required)")
	staging := flag.Bool("staging", false, "use Let's Encrypt staging environment")
	storagePath := flag.String("storage", "./acme", "certificate storage directory")
	httpPort := flag.Int("http-port", 80, "HTTP-01 challenge port (0 to disable)")
	tlsPort := flag.Int("tls-port", 443, "TLS-ALPN-01 challenge port (0 to disable)")
	proxyAddr := flag.String("addr", ":8443", "proxy listen address")
	caCert := flag.String("ca-cert", "ca.crt", "path to MITM CA certificate")
	caKey := flag.String("ca-key", "ca.key", "path to MITM CA private key")
	blockDomains := flag.String("block", "", "comma-separated domains to block")
	eabKID := flag.String("eab-kid", "", "External Account Binding key ID (ZeroSSL)")
	eabHMAC := flag.String("eab-hmac", "", "External Account Binding HMAC key (ZeroSSL)")
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
	// 1. Set up the ACME certificate manager for the proxy listener.
	// ---------------------------------------------------------------
	acmeCfg := swg.ACMEConfig{
		Email:       *email,
		Domains:     []string{*domain},
		AcceptTOS:   true,
		StoragePath: *storagePath,
		HTTPPort:    *httpPort,
		TLSPort:     *tlsPort,
		RenewBefore: 30 * 24 * time.Hour,
	}
	if *staging {
		acmeCfg.CA = swg.LetsEncryptStaging
		logger.Info("using Let's Encrypt staging environment")
	}
	if *eabKID != "" {
		acmeCfg.EABKeyID = *eabKID
		acmeCfg.EABMACKey = *eabHMAC
	}

	acm, err := swg.NewACMECertManager(acmeCfg)
	if err != nil {
		log.Fatalf("create ACME cert manager: %v", err)
	}
	acm.SetLogger(logger)

	acm.OnCertObtained = func(d string) { logger.Info("certificate obtained", "domain", d) }
	acm.OnCertRenewed = func(d string) { logger.Info("certificate renewed", "domain", d) }
	acm.OnError = func(d string, e error) { logger.Error("certificate error", "domain", d, "error", e) }

	ctx := context.Background()

	if err := acm.Initialize(ctx); err != nil {
		log.Fatalf("ACME initialize: %v", err)
	}
	if err := acm.ObtainCertificates(ctx); err != nil {
		log.Fatalf("ACME obtain: %v", err)
	}
	acm.StartAutoRenewal(12 * time.Hour)

	// ---------------------------------------------------------------
	// 2. Set up the self-signed CA CertManager for MITM per-host certs.
	// ---------------------------------------------------------------
	cm, err := swg.NewCertManager(*caCert, *caKey)
	if err != nil {
		log.Fatalf("load CA: %v", err)
	}

	// ---------------------------------------------------------------
	// 3. Create the proxy with optional domain filtering.
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
	// 4. Wrap the proxy listener with ACME-managed TLS so clients see
	//    a publicly trusted certificate for the proxy host itself.
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
	// 5. Graceful shutdown on SIGINT / SIGTERM.
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

	logger.Info("starting proxy",
		"addr", *proxyAddr,
		"domain", *domain,
		"staging", *staging,
		"cached_certs", acm.CacheSize(),
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
		fmt.Fprintf(os.Stderr, "Usage: acme [flags]\n\n")
		fmt.Fprintf(os.Stderr, "Run an SWG MITM proxy with an ACME/Let's Encrypt listener certificate.\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
	}
}
