// Example: mTLS client certificate authentication
//
// This example demonstrates mutual TLS authentication where clients
// must present a valid certificate to connect to the proxy. The cert's
// Subject.CommonName becomes the client identity and Subject.Organization
// becomes the group membership.
//
// The example generates a CA, creates a client certificate, then starts
// the proxy with mTLS enabled. In production, use a real PKI instead of
// GenerateCA/GenerateClientCert.
//
// Try it:
//
//	# The example writes client.crt, client.key, and ca.crt to /tmp
//	curl --proxy-cacert /tmp/ca.crt \
//	     --proxy-cert /tmp/client.crt --proxy-key /tmp/client.key \
//	     -x https://localhost:8080 \
//	     http://example.com
package main

import (
	"crypto/x509"
	"encoding/pem"
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

	// Parse the CA cert for client cert generation.
	block, _ := pem.Decode(certPEM)
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		logger.Error("parse CA cert", "error", err)
		os.Exit(1)
	}

	// Generate a client certificate signed by the proxy CA.
	clientCert, clientKey, err := swg.GenerateClientCert(
		caCert, keyPEM,
		"alice",
		[]string{"engineering", "ops"},
		1,
	)
	if err != nil {
		logger.Error("generate client cert", "error", err)
		os.Exit(1)
	}

	// Write client credentials and CA cert for curl/testing.
	if err := os.WriteFile("/tmp/client.crt", clientCert, 0o600); err != nil {
		logger.Error("write client cert", "error", err)
		os.Exit(1)
	}
	if err := os.WriteFile("/tmp/client.key", clientKey, 0o600); err != nil {
		logger.Error("write client key", "error", err)
		os.Exit(1)
	}
	if err := os.WriteFile("/tmp/ca.crt", certPEM, 0o644); err != nil {
		logger.Error("write CA cert", "error", err)
		os.Exit(1)
	}

	logger.Info("wrote client credentials",
		"cert", "/tmp/client.crt",
		"key", "/tmp/client.key",
		"ca", "/tmp/ca.crt",
	)

	// Create mTLS client auth using the same CA.
	clientAuth, err := swg.NewClientAuthFromPEM(certPEM)
	if err != nil {
		logger.Error("create client auth", "error", err)
		os.Exit(1)
	}

	// Create proxy with mTLS enabled.
	proxy := swg.NewProxy(":8080", cm)
	proxy.Logger = logger
	proxy.ClientAuth = clientAuth

	logger.Info("starting proxy with mTLS", "addr", ":8080")
	if err := proxy.ListenAndServe(); err != nil {
		logger.Error("proxy error", "error", err)
	}
}
