// Example: Loading blocklist rules from a CSV file
//
// This example demonstrates how to use the CSVLoader to load
// blocking rules from a CSV file and set up auto-reload.
//
// CSV Format:
// type,pattern,reason,category
// domain,ads.example.com,advertising,ads
// domain,*.tracking.com,tracking,analytics
// url,https://evil.com/malware,malware distribution,security
// regex,.*\.doubleclick\.net.*,advertising tracker,ads
package main

import (
	"context"
	"log/slog"
	"os"
	"time"

	"github.com/acmacalister/swg"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	// Generate or load CA certificate
	certPEM, keyPEM, err := swg.GenerateCA("Example Proxy", 1)
	if err != nil {
		logger.Error("generate CA", "error", err)
		os.Exit(1)
	}

	cm, err := swg.NewCertManagerFromPEM(certPEM, keyPEM)
	if err != nil {
		logger.Error("create cert manager", "error", err)
		os.Exit(1)
	}

	// Create CSV loader
	csvLoader := swg.NewCSVLoader("blocklist.csv")
	csvLoader.HasHeader = true
	csvLoader.DefaultReason = "blocked by corporate policy"
	csvLoader.DefaultCategory = "general"

	// Create reloadable filter
	filter := swg.NewReloadableFilter(csvLoader)

	// Set up callbacks for monitoring
	filter.OnReload = func(count int) {
		logger.Info("blocklist reloaded", "rules", count)
	}
	filter.OnError = func(err error) {
		logger.Error("blocklist reload failed", "error", err)
	}

	// Initial load
	ctx := context.Background()
	if err := filter.Load(ctx); err != nil {
		logger.Error("initial load failed", "error", err)
		// Continue anyway - will retry on next reload
	}

	// Start auto-reload every 5 minutes
	cancel := filter.StartAutoReload(ctx, 5*time.Minute)
	defer cancel()

	// Create and configure proxy
	proxy := swg.NewProxy(":8080", cm)
	proxy.Logger = logger
	proxy.Filter = filter

	logger.Info("starting proxy with CSV blocklist", "addr", ":8080")
	if err := proxy.ListenAndServe(); err != nil {
		logger.Error("proxy error", "error", err)
	}
}
