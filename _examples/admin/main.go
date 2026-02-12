// Example: Admin API for runtime rule management
//
// This example demonstrates the Admin API with a ReloadableFilter
// backed by a CSV blocklist. The proxy exposes REST endpoints at
// /api for listing, adding, and removing rules, checking status,
// and triggering reloads.
//
// Endpoints:
//
//	GET  /api/status  - Proxy status and rule count
//	GET  /api/rules   - List all active rules
//	POST /api/rules   - Add a rule   {"type":"domain","pattern":"evil.com"}
//	DELETE /api/rules - Remove a rule {"type":"domain","pattern":"evil.com"}
//	POST /api/reload  - Reload rules from source
//
// Try it:
//
//	curl http://localhost:8080/api/status
//	curl http://localhost:8080/api/rules
//	curl -X POST http://localhost:8080/api/rules -d '{"type":"domain","pattern":"ads.com","reason":"ads"}'
//	curl -X DELETE http://localhost:8080/api/rules -d '{"type":"domain","pattern":"ads.com"}'
//	curl -X POST http://localhost:8080/api/reload
package main

import (
	"context"
	"log/slog"
	"os"
	"time"

	"github.com/acmacalister/swg"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))

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

	// Set up a reloadable filter with a static loader for demonstration.
	loader := &swg.StaticLoader{
		Rules: []swg.Rule{
			{Type: "domain", Pattern: "ads.example.com", Reason: "advertising", Category: "ads"},
			{Type: "domain", Pattern: "*.tracking.com", Reason: "user tracking", Category: "analytics"},
		},
	}

	filter := swg.NewReloadableFilter(loader)
	filter.OnReload = func(count int) {
		logger.Info("blocklist reloaded", "rules", count)
	}
	filter.OnError = func(err error) {
		logger.Error("blocklist reload failed", "error", err)
	}

	ctx := context.Background()
	if err := filter.Load(ctx); err != nil {
		logger.Error("initial load", "error", err)
		os.Exit(1)
	}

	// Start auto-reload every 5 minutes.
	cancel := filter.StartAutoReload(ctx, 5*time.Minute)
	defer cancel()

	// Create proxy with the filter.
	proxy := swg.NewProxy(":8080", cm)
	proxy.Logger = logger
	proxy.Filter = filter
	proxy.HealthChecker = swg.NewHealthChecker()

	// Create and wire the Admin API.
	admin := swg.NewAdminAPI(proxy)
	admin.Logger = logger

	// ReloadFunc reloads from the configured loader.
	admin.ReloadFunc = func(ctx context.Context) error {
		return filter.Load(ctx)
	}

	proxy.Admin = admin

	logger.Info("starting proxy with admin API",
		"addr", ":8080",
		"admin", admin.PathPrefix,
	)
	if err := proxy.ListenAndServe(); err != nil {
		logger.Error("proxy error", "error", err)
	}
}
