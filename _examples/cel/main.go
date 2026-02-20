// Example: CEL Expression Matchers
//
// This example demonstrates using CEL (Common Expression Language) for
// advanced request filtering with complex boolean logic, custom functions,
// and access to request context.
//
// CEL provides a powerful, type-safe expression language that goes beyond
// simple domain or regex matching, enabling rules like:
//   - Block non-GET requests to API endpoints
//   - Allow only internal users to access admin paths
//   - Block requests from public IPs to internal services
//   - Complex header and content-type based filtering
//
// Run with: go run main.go
// Test with: curl -x localhost:8080 http://example.com/
package main

import (
	"context"
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
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))

	// Generate or load CA certificate
	var cm *swg.CertManager
	if _, err := os.Stat("ca.crt"); os.IsNotExist(err) {
		logger.Info("generating CA certificate")
		certPEM, keyPEM, err := swg.GenerateCA("SWG CEL Example", 1)
		if err != nil {
			log.Fatalf("generate CA: %v", err)
		}
		cm, err = swg.NewCertManagerFromPEM(certPEM, keyPEM)
		if err != nil {
			log.Fatalf("create cert manager: %v", err)
		}
	} else {
		var err error
		cm, err = swg.NewCertManager("ca.crt", "ca.key")
		if err != nil {
			log.Fatalf("load CA: %v", err)
		}
	}

	// Create a CELRuleSet that combines standard rules with CEL expressions
	ruleSet := swg.NewCELRuleSet()

	// Standard domain blocking (fast O(1) lookup)
	ruleSet.AddDomain("blocked.example.com")
	ruleSet.AddDomain("*.ads.example.com")

	// CEL expression: Block all DELETE requests
	err := ruleSet.AddRule(swg.Rule{
		Type:     "cel",
		Pattern:  `request["method"] == "DELETE"`,
		Reason:   "DELETE requests are not allowed",
		Category: "security",
	})
	if err != nil {
		log.Fatalf("add CEL rule: %v", err)
	}

	// CEL expression: Block non-GET/HEAD requests to /api/ endpoints
	err = ruleSet.AddRule(swg.Rule{
		Type:     "cel",
		Pattern:  `!(request["method"] in ["GET", "HEAD"]) && request["path"].startsWith("/api/")`,
		Reason:   "only GET/HEAD allowed on API endpoints",
		Category: "api-security",
	})
	if err != nil {
		log.Fatalf("add CEL rule: %v", err)
	}

	// CEL expression: Block requests without User-Agent header
	err = ruleSet.AddRule(swg.Rule{
		Type:     "cel",
		Pattern:  `request["headers"]["user-agent"] == ""`,
		Reason:   "User-Agent header required",
		Category: "bot-protection",
	})
	if err != nil {
		log.Fatalf("add CEL rule: %v", err)
	}

	// CEL expression: Block internal domains from public IPs
	err = ruleSet.AddRule(swg.Rule{
		Type:     "cel",
		Pattern:  `request["host"].matchesDomain("internal.corp") && !client["ip"].isPrivate()`,
		Reason:   "internal domains require private network",
		Category: "access-control",
	})
	if err != nil {
		log.Fatalf("add CEL rule: %v", err)
	}

	// CEL expression: Block large uploads (>10MB)
	err = ruleSet.AddRule(swg.Rule{
		Type:     "cel",
		Pattern:  `request["content_length"] > 10485760`,
		Reason:   "request body too large (max 10MB)",
		Category: "resource-limits",
	})
	if err != nil {
		log.Fatalf("add CEL rule: %v", err)
	}

	logger.Info("loaded rules",
		"total", ruleSet.Count(),
		"cel", ruleSet.CELCount(),
		"domain", ruleSet.Count()-ruleSet.CELCount(),
	)

	// Create proxy with CEL-enabled rule set
	proxy := &swg.Proxy{
		Addr:        ":8080",
		CertManager: cm,
		Filter:      ruleSet,
		Logger:      logger,
	}

	// Graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		logger.Info("shutting down")

		shutdownCtx, shutdownCancel := context.WithTimeout(ctx, 5*time.Second)
		defer shutdownCancel()

		if err := proxy.Shutdown(shutdownCtx); err != nil {
			logger.Error("shutdown error", "error", err)
		}
		cancel()
	}()

	logger.Info("starting proxy", "addr", proxy.Addr)
	logger.Info("CEL expressions available:",
		"example1", `request["method"] == "POST"`,
		"example2", `request["host"].matchesDomain("example.com")`,
		"example3", `client["ip"].inCIDR("10.0.0.0/8")`,
		"example4", `"admin" in client["groups"]`,
	)

	if err := proxy.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("proxy error: %v", err)
	}
}
