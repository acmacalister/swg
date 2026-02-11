package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/acmacalister/swg"
)

func main() {
	var (
		// Config file (takes precedence over individual flags)
		configPath = flag.String("config", "", "path to config file (default: search ./swg.yaml, ~/.swg/config.yaml, /etc/swg/config.yaml)")
		genConfig  = flag.Bool("gen-config", false, "generate example config file and exit")

		// Individual flags (used when no config file)
		addr           = flag.String("addr", ":8080", "proxy listen address")
		caCertPath     = flag.String("ca-cert", "ca.crt", "path to CA certificate")
		caKeyPath      = flag.String("ca-key", "ca.key", "path to CA private key")
		blockDomains   = flag.String("block", "", "comma-separated list of domains to block")
		blockPageURL   = flag.String("block-page-url", "", "URL to redirect blocked requests to")
		blockPageFile  = flag.String("block-page-file", "", "path to custom block page HTML template")
		genCA          = flag.Bool("gen-ca", false, "generate a new CA certificate and exit")
		caOrg          = flag.String("ca-org", "SWG Proxy", "organization name for generated CA")
		verbose        = flag.Bool("v", false, "verbose logging")
		printBlockPage = flag.Bool("print-block-page", false, "print default block page template and exit")
		genPAC         = flag.String("gen-pac", "", "generate PAC file at path and exit")
		pacBypass      = flag.String("pac-bypass", "", "comma-separated domains to bypass proxy in PAC file")
		metricsEnabled = flag.Bool("metrics", false, "enable Prometheus /metrics endpoint")
	)
	flag.Parse()

	// Set up logging
	logLevel := slog.LevelInfo
	if *verbose {
		logLevel = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel}))
	slog.SetDefault(logger)

	// Print block page template mode
	if *printBlockPage {
		fmt.Println(swg.DefaultBlockPageHTML)
		return
	}

	// Generate PAC file mode
	if *genPAC != "" {
		pac := swg.NewPACGenerator(*addr)
		if *pacBypass != "" {
			for d := range strings.SplitSeq(*pacBypass, ",") {
				d = strings.TrimSpace(d)
				if d != "" {
					pac.AddBypassDomain(d)
				}
			}
		}
		if err := pac.WriteFile(*genPAC); err != nil {
			logger.Error("generate PAC file", "error", err)
			os.Exit(1)
		}
		fmt.Printf("Generated %s\n", *genPAC)
		return
	}

	// Generate example config mode
	if *genConfig {
		if err := swg.WriteExampleConfig("swg.yaml"); err != nil {
			logger.Error("generate config", "error", err)
			os.Exit(1)
		}
		fmt.Println("Generated swg.yaml")
		return
	}

	// Try to load config file
	cfg, err := swg.LoadConfig(*configPath)
	if err != nil && *configPath != "" {
		logger.Error("load config", "error", err)
		os.Exit(1)
	}

	// Determine effective settings (config file overrides flags if present)
	effectiveAddr := *addr
	effectiveCACert := *caCertPath
	effectiveCAKey := *caKeyPath
	effectiveOrg := *caOrg
	effectiveBlockPageURL := *blockPageURL
	effectiveBlockPageFile := *blockPageFile

	if cfg != nil {
		if cfg.Server.Addr != "" {
			effectiveAddr = cfg.Server.Addr
		}
		if cfg.TLS.CACert != "" {
			effectiveCACert = cfg.TLS.CACert
		}
		if cfg.TLS.CAKey != "" {
			effectiveCAKey = cfg.TLS.CAKey
		}
		if cfg.TLS.Organization != "" {
			effectiveOrg = cfg.TLS.Organization
		}
		if cfg.BlockPage.RedirectURL != "" {
			effectiveBlockPageURL = cfg.BlockPage.RedirectURL
		}
		if cfg.BlockPage.TemplatePath != "" {
			effectiveBlockPageFile = cfg.BlockPage.TemplatePath
		}
	}

	// Generate CA mode
	if *genCA {
		if err := generateCA(effectiveCACert, effectiveCAKey, effectiveOrg); err != nil {
			logger.Error("generate CA", "error", err)
			os.Exit(1)
		}
		return
	}

	// Load CA certificate
	cm, err := swg.NewCertManager(effectiveCACert, effectiveCAKey)
	if err != nil {
		logger.Error("load CA certificate", "error", err)
		logger.Info("hint: run with -gen-ca to generate a new CA certificate")
		os.Exit(1)
	}

	// Create proxy
	proxy := swg.NewProxy(effectiveAddr, cm)
	proxy.Logger = logger
	proxy.BlockPageURL = effectiveBlockPageURL

	// Set up PAC handler (serves /proxy.pac)
	pac := swg.NewPACGenerator(effectiveAddr)
	if *pacBypass != "" {
		for d := range strings.SplitSeq(*pacBypass, ",") {
			d = strings.TrimSpace(d)
			if d != "" {
				pac.AddBypassDomain(d)
			}
		}
	}
	proxy.PACHandler = pac

	// Set up metrics
	if *metricsEnabled {
		proxy.Metrics = swg.NewMetrics()
		logger.Info("prometheus metrics enabled at /metrics")
	}

	// Load custom block page if specified
	if effectiveBlockPageFile != "" {
		blockPage, err := swg.NewBlockPageFromFile(effectiveBlockPageFile)
		if err != nil {
			logger.Error("load block page template", "error", err, "file", effectiveBlockPageFile)
			os.Exit(1)
		}
		proxy.BlockPage = blockPage
		logger.Info("loaded custom block page", "file", effectiveBlockPageFile)
	}

	// Set up filter
	if cfg != nil && cfg.Filter.Enabled {
		// Use config-based filtering
		loader, err := cfg.BuildRuleLoader()
		if err != nil {
			logger.Error("build rule loader", "error", err)
			os.Exit(1)
		}

		filter := swg.NewReloadableFilter(loader)

		// Initial load
		if err := filter.Load(context.Background()); err != nil {
			logger.Warn("initial rule load failed", "error", err)
		} else {
			logger.Info("loaded filter rules", "count", filter.Count())
		}

		// Start auto-reload if configured
		if cfg.Filter.ReloadInterval > 0 {
			cancel := filter.StartAutoReload(context.Background(), cfg.Filter.ReloadInterval)
			defer cancel()
			logger.Info("filter auto-reload enabled", "interval", cfg.Filter.ReloadInterval)
		}

		proxy.Filter = filter
	} else if *blockDomains != "" {
		// Fall back to simple domain filtering from flags
		filter := swg.NewDomainFilter()
		for d := range strings.SplitSeq(*blockDomains, ",") {
			d = strings.TrimSpace(d)
			if d != "" {
				filter.AddDomain(d)
				logger.Info("blocking domain", "domain", d)
			}
		}
		proxy.Filter = filter
	}

	// Handle shutdown
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		<-ctx.Done()
		logger.Info("shutting down...")
		_ = proxy.Shutdown(context.Background())
	}()

	// Start proxy
	logger.Info("starting proxy", "addr", effectiveAddr)
	logger.Info("configure your system proxy to use this address")
	logger.Info("ensure the CA certificate is trusted by your system/browser")

	if err := proxy.ListenAndServe(); err != nil {
		logger.Error("proxy error", "error", err)
		os.Exit(1)
	}
}

func generateCA(certPath, keyPath, org string) error {
	// Check if files already exist
	if _, err := os.Stat(certPath); err == nil {
		return fmt.Errorf("CA certificate already exists at %s", certPath)
	}
	if _, err := os.Stat(keyPath); err == nil {
		return fmt.Errorf("CA key already exists at %s", keyPath)
	}

	slog.Info("generating CA certificate", "org", org)

	certPEM, keyPEM, err := swg.GenerateCA(org, 10) // 10 year validity
	if err != nil {
		return err
	}

	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		return fmt.Errorf("write CA cert: %w", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return fmt.Errorf("write CA key: %w", err)
	}

	slog.Info("CA certificate generated", "cert", certPath, "key", keyPath)
	slog.Info("add the CA certificate to your system/browser trust store")

	return nil
}
