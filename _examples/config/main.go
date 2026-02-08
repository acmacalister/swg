// Example: Using SWG with a configuration file
//
// This example demonstrates loading proxy configuration from a YAML file
// and starting the proxy with those settings.
//
// Usage:
//
//	# Generate CA certificate first
//	go run . -gen-ca
//
//	# Start proxy with config file
//	go run . -config swg.yaml
//
//	# Or use default search paths (./swg.yaml, ~/.swg/config.yaml, /etc/swg/config.yaml)
//	go run .
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
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
	configPath := flag.String("config", "", "path to config file (default: search ./swg.yaml, ~/.swg/config.yaml, /etc/swg/config.yaml)")
	genCA := flag.Bool("gen-ca", false, "generate CA certificate and exit")
	genConfig := flag.Bool("gen-config", false, "generate example config file and exit")
	verbose := flag.Bool("v", false, "verbose logging")
	flag.Parse()

	// Generate example config
	if *genConfig {
		if err := swg.WriteExampleConfig("swg.yaml"); err != nil {
			log.Fatalf("Failed to generate config: %v", err)
		}
		fmt.Println("Generated swg.yaml")
		return
	}

	// Load configuration
	cfg, err := swg.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Generate CA certificate
	if *genCA {
		certPEM, keyPEM, err := swg.GenerateCA(cfg.TLS.Organization, cfg.TLS.CertValidityDays)
		if err != nil {
			log.Fatalf("Failed to generate CA: %v", err)
		}
		if err := os.WriteFile(cfg.TLS.CACert, certPEM, 0644); err != nil {
			log.Fatalf("Failed to write CA cert: %v", err)
		}
		if err := os.WriteFile(cfg.TLS.CAKey, keyPEM, 0600); err != nil {
			log.Fatalf("Failed to write CA key: %v", err)
		}
		fmt.Printf("Generated %s and %s\n", cfg.TLS.CACert, cfg.TLS.CAKey)
		fmt.Println("Install the CA certificate in your browser/system to trust generated certificates.")
		return
	}

	// Load CA certificate
	cm, err := swg.NewCertManager(cfg.TLS.CACert, cfg.TLS.CAKey)
	if err != nil {
		log.Fatalf("Failed to load CA certificate: %v\nRun with -gen-ca to generate one.", err)
	}

	// Build filter from config
	var filter swg.Filter
	if cfg.Filter.Enabled {
		loader, err := cfg.BuildRuleLoader()
		if err != nil {
			log.Fatalf("Failed to build rule loader: %v", err)
		}

		// Use reloadable filter for dynamic updates
		reloadable := swg.NewReloadableFilter(loader)
		ctx := context.Background()

		// Initial load
		if err := reloadable.Load(ctx); err != nil {
			log.Printf("Warning: initial rule load failed: %v", err)
		}

		// Start auto-reload if interval is set
		if cfg.Filter.ReloadInterval > 0 {
			cancel := reloadable.StartAutoReload(ctx, cfg.Filter.ReloadInterval)
			defer cancel()

			if *verbose {
				log.Printf("Filter enabled with %v reload interval", cfg.Filter.ReloadInterval)
			}
		}

		filter = reloadable
	}

	// Create block page handler
	var blockPage *swg.BlockPage
	if cfg.BlockPage.Enabled {
		if cfg.BlockPage.TemplatePath != "" {
			var err error
			blockPage, err = swg.NewBlockPageFromFile(cfg.BlockPage.TemplatePath)
			if err != nil {
				log.Fatalf("Failed to load block page template: %v", err)
			}
		} else {
			blockPage = swg.NewBlockPage()
		}
	}

	// Create proxy
	proxy := swg.NewProxy(cfg.Server.Addr, cm)
	proxy.Filter = filter
	proxy.BlockPage = blockPage
	if cfg.BlockPage.RedirectURL != "" {
		proxy.BlockPageURL = cfg.BlockPage.RedirectURL
	}
	if *verbose {
		proxy.Logger = slog.Default()
	}

	// Create server
	server := &http.Server{
		Addr:         cfg.Server.Addr,
		Handler:      proxy,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
		IdleTimeout:  cfg.Server.IdleTimeout,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}

	// Graceful shutdown
	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-done
		log.Println("Shutting down...")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		server.Shutdown(ctx)
	}()

	// Start server
	log.Printf("Starting SWG proxy on %s", cfg.Server.Addr)
	if cfg.Filter.Enabled {
		log.Printf("Filtering enabled")
	}

	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatalf("Server error: %v", err)
	}
}
