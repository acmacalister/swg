// Example: Bypass token for debugging
//
// This example demonstrates the bypass feature that allows authorized
// clients to skip content filtering. The proxy blocks "blocked.example.com"
// but clients with a valid bypass token can reach it anyway.
//
// Try it:
//
//	# Blocked without token
//	curl -x http://localhost:8080 http://blocked.example.com
//
//	# Bypassed with token
//	curl -H "X-SWG-Bypass: <token>" -x http://localhost:8080 http://blocked.example.com
//
// The token is printed to stderr on startup.
package main

import (
	"fmt"
	"log/slog"
	"os"

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

	rs := &swg.RuleSet{}
	rs.AddDomain("blocked.example.com")

	bypass := swg.NewBypass()
	bypass.Logger = logger

	tok, err := bypass.GenerateToken()
	if err != nil {
		logger.Error("generate bypass token", "error", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "\nBypass token: %s\n\n", tok)
	fmt.Fprintf(os.Stderr, "Test with:\n")
	fmt.Fprintf(os.Stderr, "  curl -x http://localhost:8080 http://blocked.example.com       # blocked\n")
	fmt.Fprintf(os.Stderr, "  curl -H \"X-SWG-Bypass: %s\" -x http://localhost:8080 http://blocked.example.com  # bypassed\n\n", tok)

	proxy := swg.NewProxy(":8080", cm)
	proxy.Logger = logger
	proxy.Filter = rs
	proxy.Bypass = bypass

	logger.Info("starting proxy with bypass", "addr", ":8080")
	if err := proxy.ListenAndServe(); err != nil {
		logger.Error("proxy error", "error", err)
	}
}
