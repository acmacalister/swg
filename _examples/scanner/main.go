// Example: Response body scanning with a pluggable AV scanner
//
// This example demonstrates how to implement the ResponseBodyScanner
// interface to integrate an external antivirus engine. The scanner
// receives the full response body as a byte slice and returns a
// verdict (allow, block, or replace).
//
// In production, replace the stub scanner with a real AV SDK call
// (e.g. ClamAV via clamd, or a commercial API).
//
// Usage:
//
//	go run .
package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"github.com/acmacalister/swg"
)

// ClamAVScanner wraps a ClamAV daemon connection.
// In production, this would open a TCP/Unix socket to clamd.
type ClamAVScanner struct {
	ClamdAddr string
}

// Scan sends the body to ClamAV and returns a verdict.
func (s *ClamAVScanner) Scan(_ context.Context, body []byte, _ *http.Request, resp *http.Response) (swg.ScanResult, error) {
	// Stub: in production, connect to clamd and send INSTREAM.
	// Here we just check for the EICAR test string.
	if strings.Contains(string(body), "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR") {
		return swg.ScanResult{
			Verdict: swg.VerdictBlock,
			Reason:  fmt.Sprintf("malware detected in %s response", resp.Header.Get("Content-Type")),
		}, nil
	}
	return swg.ScanResult{Verdict: swg.VerdictAllow}, nil
}

// DLPScanner checks for sensitive data patterns and redacts them.
type DLPScanner struct {
	Patterns []string
}

// Scan checks the body for sensitive patterns and redacts matches.
func (s *DLPScanner) Scan(_ context.Context, body []byte, _ *http.Request, _ *http.Response) (swg.ScanResult, error) {
	content := string(body)
	redacted := false

	for _, pattern := range s.Patterns {
		if strings.Contains(content, pattern) {
			content = strings.ReplaceAll(content, pattern, "[REDACTED]")
			redacted = true
		}
	}

	if redacted {
		return swg.ScanResult{
			Verdict:                swg.VerdictReplace,
			ReplacementBody:        io.NopCloser(strings.NewReader(content)),
			ReplacementContentType: "text/html; charset=utf-8",
		}, nil
	}

	return swg.ScanResult{Verdict: swg.VerdictAllow}, nil
}

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

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

	// --- Build policy with scanners ---
	policy := swg.NewPolicyEngine()

	// AV scanner runs first
	policy.BodyScanners = append(policy.BodyScanners, &ClamAVScanner{
		ClamdAddr: "localhost:3310",
	})

	// DLP scanner runs second
	policy.BodyScanners = append(policy.BodyScanners, &DLPScanner{
		Patterns: []string{
			"SSN: 123-45-6789",
			"4111-1111-1111-1111",
		},
	})

	// Only scan text responses (skip images, video, etc.)
	policy.ScanContentTypes = []string{
		"text/html",
		"text/plain",
		"application/json",
		"application/xml",
	}

	// Cap scan buffer at 10 MiB (default)
	policy.MaxScanSize = 10 << 20

	// --- Block executable content-types via ResponseHook ---
	ctFilter := swg.NewContentTypeFilter()
	ctFilter.Block("application/x-executable", "executable downloads blocked")
	ctFilter.Block("application/x-msdownload", "Windows PE blocked")
	ctFilter.Block("application/x-dosexec", "DOS executable blocked")
	ctFilter.Block("application/x-mach-binary", "macOS binary blocked")
	policy.ResponseHooks = append(policy.ResponseHooks, ctFilter)

	// --- Proxy setup ---
	proxy := swg.NewProxy(":8080", cm)
	proxy.Logger = logger
	proxy.Policy = policy

	logger.Info("starting proxy with AV + DLP scanning",
		"addr", ":8080",
		"scan_types", policy.ScanContentTypes,
	)
	if err := proxy.ListenAndServe(); err != nil {
		logger.Error("proxy error", "error", err)
	}
}
