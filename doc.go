// Package swg provides an HTTPS man-in-the-middle (MITM) proxy for content
// filtering. It intercepts HTTPS connections by dynamically generating TLS
// certificates signed by a trusted CA, allowing inspection and filtering of
// encrypted traffic.
//
// # Architecture
//
// The proxy handles both HTTP and HTTPS (CONNECT) requests. For HTTPS, it
// performs a TLS handshake with the client using a dynamically generated
// certificate for the requested host, then forwards the decrypted request
// to the origin server. Filters can inspect and block requests at any point.
//
// # Basic Proxy
//
// Create a proxy with certificate management and start serving:
//
//	cm, err := swg.NewCertManager("ca.crt", "ca.key")
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	proxy := swg.NewProxy(":8080", cm)
//	log.Fatal(proxy.ListenAndServe())
//
// # Domain Filtering
//
// Block requests by domain name with optional wildcard support:
//
//	filter := swg.NewDomainFilter()
//	filter.AddDomain("blocked.com")
//	filter.AddDomain("*.ads.example.com")
//	proxy.Filter = filter
//
// # Advanced Filtering with RuleSet
//
// RuleSet supports domain, URL prefix, and regex pattern matching with
// metadata such as reason and category:
//
//	rs := swg.NewRuleSet()
//	rs.AddDomain("ads.example.com")
//	rs.AddURL("https://evil.com/malware")
//	rs.AddRegex(`.*\.tracking\..*`)
//
//	rs.AddRule(swg.Rule{
//	    Type:     "domain",
//	    Pattern:  "malware.com",
//	    Reason:   "known malware host",
//	    Category: "security",
//	})
//
//	proxy.Filter = rs
//
// # Reloadable Filters
//
// Load rules from external sources (CSV files, HTTP endpoints, databases)
// with automatic periodic reloading:
//
//	loader := swg.NewCSVLoader("blocklist.csv")
//	loader.HasHeader = true
//
//	filter := swg.NewReloadableFilter(loader)
//	filter.OnReload = func(count int) {
//	    log.Printf("Loaded %d rules", count)
//	}
//
//	ctx := context.Background()
//	filter.Load(ctx)
//
//	cancel := filter.StartAutoReload(ctx, 5*time.Minute)
//	defer cancel()
//
//	proxy.Filter = filter
//
// Multiple sources can be combined:
//
//	multi := swg.NewMultiLoader(
//	    swg.NewCSVLoader("local.csv"),
//	    swg.NewURLLoader("https://blocklist.example.com/rules.csv"),
//	    swg.NewStaticLoader(swg.Rule{Type: "domain", Pattern: "always-blocked.com"}),
//	)
//	filter := swg.NewReloadableFilter(multi)
//
// # Custom Filters
//
// Implement the [Filter] interface or use [FilterFunc] for simple cases:
//
//	proxy.Filter = swg.FilterFunc(func(req *http.Request) (bool, string) {
//	    if req.Host == "blocked.com" {
//	        return true, "domain blocked"
//	    }
//	    return false, ""
//	})
//
// # Block Pages
//
// Display a customizable HTML page when requests are blocked:
//
//	proxy.BlockPage = swg.NewBlockPage()
//
//	// Or from a custom template file
//	bp, err := swg.NewBlockPageFromFile("block.html")
//	proxy.BlockPage = bp
//
// Template variables available in block pages: {{.URL}}, {{.Host}},
// {{.Path}}, {{.Reason}}, and {{.Timestamp}}.
//
// # PAC File Generation
//
// Generate Proxy Auto-Configuration files for client setup:
//
//	pac := swg.NewPACGenerator("proxy.example.com:8080")
//	pac.AddBypassDomain("internal.company.com")
//	pac.AddBypassNetwork("10.0.0.0/8")
//
//	// Serve as HTTP handler
//	http.Handle("/proxy.pac", pac)
//
//	// Or write to file
//	pac.WriteFile("proxy.pac")
//
// # Prometheus Metrics
//
// Instrument the proxy with Prometheus metrics for monitoring:
//
//	metrics := swg.NewMetrics()
//	http.Handle("/metrics", metrics.Handler())
//
// The Metrics type provides methods for recording requests, blocked
// connections, certificate cache statistics, filter reloads, and more.
//
// # Health Check Endpoints
//
// Expose /healthz and /readyz endpoints for Kubernetes and load balancers:
//
//	health := swg.NewHealthChecker()
//	proxy.HealthChecker = health
//
//	health.SetAlive(true)
//	health.SetReady(true)
//
// Custom readiness checks verify downstream dependencies:
//
//	health.ReadinessChecks = append(health.ReadinessChecks, func() error {
//	    if !dbPing() {
//	        return errors.New("database unreachable")
//	    }
//	    return nil
//	})
//
// # Structured Access Log
//
// Write JSON access log entries for every proxied request:
//
//	f, _ := os.OpenFile("access.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
//	alLogger := slog.New(slog.NewJSONHandler(f, nil))
//	proxy.AccessLog = swg.NewAccessLogger(alLogger)
//
// Each entry includes method, host, path, scheme, status code, duration,
// bytes written, client address, blocked/reason, and user agent.
//
// # SIGHUP Reload
//
// Reload filter rules on SIGHUP without restarting the proxy:
//
//	reloader := swg.WatchSIGHUP(proxy, func(ctx context.Context) (swg.Filter, error) {
//	    cfg, _ := swg.LoadConfig("swg.yaml")
//	    loader, _ := cfg.BuildRuleLoader()
//	    filter := swg.NewReloadableFilter(loader)
//	    filter.Load(ctx)
//	    return filter, nil
//	}, logger)
//	defer reloader.Cancel()
//
// # Configuration
//
// Load configuration from YAML, JSON, or TOML files with environment
// variable overrides (SWG_ prefix):
//
//	cfg, err := swg.LoadConfig("swg.yaml")
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	rs, err := cfg.BuildRuleSet()
//	proxy.Filter = rs
//
// # CA Certificate Generation
//
// Generate a new CA certificate and key pair programmatically:
//
//	certPEM, keyPEM, err := swg.GenerateCA("My Organization", 10)
//	cm, err := swg.NewCertManagerFromPEM(certPEM, keyPEM)
//
// # Graceful Shutdown
//
//	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
//	defer cancel()
//	if err := proxy.Shutdown(ctx); err != nil {
//	    log.Printf("shutdown error: %v", err)
//	}
package swg
