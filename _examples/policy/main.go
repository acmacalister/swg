// Example: Policy engine with lifecycle hooks, identity, and body scanning
//
// This example demonstrates the full PolicyEngine pipeline:
//   - IP-based identity resolution
//   - Request hooks for early access control and tagging
//   - Group-based filtering with per-group policies
//   - Content-type blocking via ResponseHook
//   - Response body scanning (e.g. AV / DLP)
//
// Usage:
//
//	go run . -v
package main

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"github.com/acmacalister/swg"
)

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

	// --- Identity resolver: map client IPs to users/groups ---
	resolver := swg.NewIPIdentityResolver()
	resolver.AddIP("10.0.0.50", "alice", []string{"engineering"})
	resolver.AddIP("10.0.0.51", "bob", []string{"marketing"})
	if err := resolver.AddCIDR("192.168.1.0/24", "guest", []string{"guests"}); err != nil {
		logger.Error("add CIDR", "error", err)
		os.Exit(1)
	}

	// --- Per-group filter policies ---
	groupFilter := swg.NewGroupPolicyFilter()

	// Engineering: only block known-malware domains
	engFilter := swg.NewDomainFilter()
	engFilter.AddDomain("malware.example.com")
	groupFilter.SetPolicy("engineering", engFilter)

	// Marketing: block social media during work hours (see time-rule example)
	mktFilter := swg.NewDomainFilter()
	mktFilter.AddDomains([]string{"twitter.com", "facebook.com", "reddit.com"})
	groupFilter.SetPolicy("marketing", mktFilter)

	// Guests: allow-list mode (deny by default)
	guestFilter := swg.NewAllowListFilter()
	guestFilter.AddDomains([]string{"docs.google.com", "*.wikipedia.org"})
	groupFilter.SetPolicy("guests", guestFilter)

	// Default policy for unknown identities
	groupFilter.Default = swg.NewDomainFilter()

	// --- Content-type filter (ResponseHook) ---
	ctFilter := swg.NewContentTypeFilter()
	ctFilter.Block("application/x-executable", "executable downloads blocked")
	ctFilter.Block("application/x-msdownload", "Windows executables blocked")
	ctFilter.Block("application/x-dosexec", "DOS executables blocked")

	// --- Simple keyword body scanner ---
	keywordScanner := swg.ResponseBodyScannerFunc(
		func(_ context.Context, body []byte, _ *http.Request, _ *http.Response) (swg.ScanResult, error) {
			if strings.Contains(string(body), "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR") {
				return swg.ScanResult{
					Verdict: swg.VerdictBlock,
					Reason:  "EICAR test signature detected",
				}, nil
			}
			return swg.ScanResult{Verdict: swg.VerdictAllow}, nil
		},
	)

	// --- DLP scanner: redact credit card patterns ---
	dlpScanner := swg.ResponseBodyScannerFunc(
		func(_ context.Context, body []byte, _ *http.Request, _ *http.Response) (swg.ScanResult, error) {
			content := string(body)
			if strings.Contains(content, "4111-1111-1111-1111") {
				redacted := strings.ReplaceAll(content, "4111-1111-1111-1111", "XXXX-XXXX-XXXX-XXXX")
				return swg.ScanResult{
					Verdict:                swg.VerdictReplace,
					ReplacementBody:        io.NopCloser(strings.NewReader(redacted)),
					ReplacementContentType: "text/html; charset=utf-8",
				}, nil
			}
			return swg.ScanResult{Verdict: swg.VerdictAllow}, nil
		},
	)

	// --- Assemble the policy engine ---
	policy := swg.NewPolicyEngine()
	policy.IdentityResolver = resolver
	policy.ResponseHooks = []swg.ResponseHook{ctFilter}
	policy.BodyScanners = []swg.ResponseBodyScanner{keywordScanner, dlpScanner}
	policy.ScanContentTypes = []string{"text/html", "application/json", "text/plain"}
	policy.MaxScanSize = 5 << 20 // 5 MiB

	// --- Request hook: log identity and tag requests ---
	policy.RequestHooks = []swg.RequestHook{
		swg.RequestHookFunc(func(_ context.Context, req *http.Request, rc *swg.RequestContext) *http.Response {
			logger.Info("request",
				"client_ip", rc.ClientIP,
				"identity", rc.Identity,
				"groups", rc.Groups,
				"host", req.Host,
			)
			rc.Tags["inspected"] = "true"
			return nil
		}),
	}

	// --- Build proxy ---
	proxy := swg.NewProxy(":8080", cm)
	proxy.Logger = logger
	proxy.Filter = groupFilter
	proxy.Policy = policy

	logger.Info("starting proxy with policy engine", "addr", ":8080")
	if err := proxy.ListenAndServe(); err != nil {
		logger.Error("proxy error", "error", err)
	}
}
