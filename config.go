package swg

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// Config represents the complete proxy configuration.
type Config struct {
	// Server configuration
	Server ServerConfig `mapstructure:"server"`

	// TLS/CA configuration
	TLS TLSConfig `mapstructure:"tls"`

	// Filtering configuration
	Filter FilterConfig `mapstructure:"filter"`

	// Block page configuration
	BlockPage BlockPageConfig `mapstructure:"block_page"`

	// Logging configuration
	Logging LoggingConfig `mapstructure:"logging"`
}

// ServerConfig contains server-related settings.
type ServerConfig struct {
	// Address to listen on (e.g., ":8080", "0.0.0.0:8080")
	Addr string `mapstructure:"addr"`

	// ReadTimeout for incoming connections
	ReadTimeout time.Duration `mapstructure:"read_timeout"`

	// WriteTimeout for outgoing responses
	WriteTimeout time.Duration `mapstructure:"write_timeout"`

	// IdleTimeout for keep-alive connections
	IdleTimeout time.Duration `mapstructure:"idle_timeout"`
}

// TLSConfig contains TLS/certificate settings.
type TLSConfig struct {
	// CACert is the path to the CA certificate file
	CACert string `mapstructure:"ca_cert"`

	// CAKey is the path to the CA private key file
	CAKey string `mapstructure:"ca_key"`

	// Organization name for generated certificates
	Organization string `mapstructure:"organization"`

	// CertValidityDays for generated host certificates
	CertValidityDays int `mapstructure:"cert_validity_days"`
}

// FilterConfig contains filtering settings.
type FilterConfig struct {
	// Enabled determines if filtering is active
	Enabled bool `mapstructure:"enabled"`

	// Domains is a list of domains to block
	Domains []string `mapstructure:"domains"`

	// URLs is a list of URL prefixes to block
	URLs []string `mapstructure:"urls"`

	// Regex is a list of regex patterns to block
	Regex []string `mapstructure:"regex"`

	// Rules is a list of full rule definitions
	Rules []RuleConfig `mapstructure:"rules"`

	// Sources defines external rule sources
	Sources []SourceConfig `mapstructure:"sources"`

	// ReloadInterval for external sources (0 = no auto-reload)
	ReloadInterval time.Duration `mapstructure:"reload_interval"`
}

// RuleConfig represents a single blocking rule in config.
type RuleConfig struct {
	Type     string `mapstructure:"type"`
	Pattern  string `mapstructure:"pattern"`
	Reason   string `mapstructure:"reason"`
	Category string `mapstructure:"category"`
}

// SourceConfig defines an external rule source.
type SourceConfig struct {
	// Type of source: "csv", "url"
	Type string `mapstructure:"type"`

	// Path for file-based sources
	Path string `mapstructure:"path"`

	// URL for remote sources
	URL string `mapstructure:"url"`

	// HasHeader indicates if CSV has a header row
	HasHeader bool `mapstructure:"has_header"`
}

// BlockPageConfig contains block page settings.
type BlockPageConfig struct {
	// Enabled determines if custom block page is used
	Enabled bool `mapstructure:"enabled"`

	// RedirectURL to redirect blocked requests (optional)
	RedirectURL string `mapstructure:"redirect_url"`

	// TemplatePath to custom block page template
	TemplatePath string `mapstructure:"template_path"`

	// TemplateInline is inline template content
	TemplateInline string `mapstructure:"template_inline"`
}

// LoggingConfig contains logging settings.
type LoggingConfig struct {
	// Level is the log level: debug, info, warn, error
	Level string `mapstructure:"level"`

	// Format is the log format: text, json
	Format string `mapstructure:"format"`

	// Output is where to write logs: stdout, stderr, or file path
	Output string `mapstructure:"output"`
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		Server: ServerConfig{
			Addr:         ":8080",
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 30 * time.Second,
			IdleTimeout:  60 * time.Second,
		},
		TLS: TLSConfig{
			CACert:           "ca.crt",
			CAKey:            "ca.key",
			Organization:     "SWG Proxy",
			CertValidityDays: 365,
		},
		Filter: FilterConfig{
			Enabled:        true,
			ReloadInterval: 5 * time.Minute,
		},
		BlockPage: BlockPageConfig{
			Enabled: true,
		},
		Logging: LoggingConfig{
			Level:  "info",
			Format: "text",
			Output: "stderr",
		},
	}
}

// LoadConfig loads configuration from file, environment, and defaults.
// It searches for config files in the following order:
// 1. Explicit path (if provided)
// 2. ./swg.yaml, ./swg.yml, ./swg.json, ./swg.toml
// 3. $HOME/.swg/config.yaml
// 4. /etc/swg/config.yaml
func LoadConfig(configPath string) (*Config, error) {
	v := viper.New()

	// Set defaults
	setDefaults(v)

	// Configure viper
	v.SetConfigName("swg")
	v.SetConfigType("yaml")

	// Add search paths
	v.AddConfigPath(".")
	v.AddConfigPath("$HOME/.swg")
	v.AddConfigPath("/etc/swg")

	// Environment variables
	v.SetEnvPrefix("SWG")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	// Load explicit config file if provided
	if configPath != "" {
		v.SetConfigFile(configPath)
	}

	// Read config file
	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("read config: %w", err)
		}
		// Config file not found is OK - use defaults
	}

	// Unmarshal config
	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("unmarshal config: %w", err)
	}

	return &cfg, nil
}

// LoadConfigFromReader loads configuration from a reader.
// Useful for testing or embedded configs.
func LoadConfigFromReader(configType string, data []byte) (*Config, error) {
	v := viper.New()

	setDefaults(v)
	v.SetConfigType(configType)

	if err := v.ReadConfig(strings.NewReader(string(data))); err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("unmarshal config: %w", err)
	}

	return &cfg, nil
}

func setDefaults(v *viper.Viper) {
	defaults := DefaultConfig()

	// Server defaults
	v.SetDefault("server.addr", defaults.Server.Addr)
	v.SetDefault("server.read_timeout", defaults.Server.ReadTimeout)
	v.SetDefault("server.write_timeout", defaults.Server.WriteTimeout)
	v.SetDefault("server.idle_timeout", defaults.Server.IdleTimeout)

	// TLS defaults
	v.SetDefault("tls.ca_cert", defaults.TLS.CACert)
	v.SetDefault("tls.ca_key", defaults.TLS.CAKey)
	v.SetDefault("tls.organization", defaults.TLS.Organization)
	v.SetDefault("tls.cert_validity_days", defaults.TLS.CertValidityDays)

	// Filter defaults
	v.SetDefault("filter.enabled", defaults.Filter.Enabled)
	v.SetDefault("filter.reload_interval", defaults.Filter.ReloadInterval)

	// Block page defaults
	v.SetDefault("block_page.enabled", defaults.BlockPage.Enabled)

	// Logging defaults
	v.SetDefault("logging.level", defaults.Logging.Level)
	v.SetDefault("logging.format", defaults.Logging.Format)
	v.SetDefault("logging.output", defaults.Logging.Output)
}

// BuildRuleSet creates a RuleSet from the filter configuration.
func (c *Config) BuildRuleSet() (*RuleSet, error) {
	rs := NewRuleSet()

	// Add domains
	for _, domain := range c.Filter.Domains {
		rs.AddDomain(domain)
	}

	// Add URLs
	for _, url := range c.Filter.URLs {
		rs.AddURL(url)
	}

	// Add regex patterns
	for _, pattern := range c.Filter.Regex {
		if err := rs.AddRegex(pattern); err != nil {
			return nil, fmt.Errorf("invalid regex %q: %w", pattern, err)
		}
	}

	// Add full rules
	for _, rule := range c.Filter.Rules {
		if err := rs.AddRule(Rule{
			Type:     rule.Type,
			Pattern:  rule.Pattern,
			Reason:   rule.Reason,
			Category: rule.Category,
		}); err != nil {
			return nil, fmt.Errorf("invalid rule %+v: %w", rule, err)
		}
	}

	return rs, nil
}

// BuildRuleLoader creates a RuleLoader from the filter sources configuration.
func (c *Config) BuildRuleLoader() (RuleLoader, error) {
	var loaders []RuleLoader

	// Add static rules from config
	if len(c.Filter.Domains) > 0 || len(c.Filter.URLs) > 0 ||
		len(c.Filter.Regex) > 0 || len(c.Filter.Rules) > 0 {

		var staticRules []Rule

		for _, domain := range c.Filter.Domains {
			staticRules = append(staticRules, Rule{
				Type:    "domain",
				Pattern: domain,
				Reason:  "blocked by policy",
			})
		}

		for _, url := range c.Filter.URLs {
			staticRules = append(staticRules, Rule{
				Type:    "url",
				Pattern: url,
				Reason:  "blocked by policy",
			})
		}

		for _, pattern := range c.Filter.Regex {
			staticRules = append(staticRules, Rule{
				Type:    "regex",
				Pattern: pattern,
				Reason:  "blocked by policy",
			})
		}

		for _, rule := range c.Filter.Rules {
			staticRules = append(staticRules, Rule{
				Type:     rule.Type,
				Pattern:  rule.Pattern,
				Reason:   rule.Reason,
				Category: rule.Category,
			})
		}

		loaders = append(loaders, NewStaticLoader(staticRules...))
	}

	// Add external sources
	for _, source := range c.Filter.Sources {
		switch source.Type {
		case "csv":
			loader := NewCSVLoader(source.Path)
			loader.HasHeader = source.HasHeader
			loaders = append(loaders, loader)

		case "url":
			loader := NewURLLoader(source.URL)
			loader.HasHeader = source.HasHeader
			loaders = append(loaders, loader)

		default:
			return nil, fmt.Errorf("unknown source type: %s", source.Type)
		}
	}

	if len(loaders) == 0 {
		return NewStaticLoader(), nil
	}

	if len(loaders) == 1 {
		return loaders[0], nil
	}

	return NewMultiLoader(loaders...), nil
}

// WriteExampleConfig writes an example configuration file.
func WriteExampleConfig(path string) error {
	example := `# SWG - Secure Web Gateway Configuration
# See https://github.com/acmacalister/swg for documentation

server:
  # Address to listen on
  addr: ":8080"
  
  # Timeouts
  read_timeout: 30s
  write_timeout: 30s
  idle_timeout: 60s

tls:
  # CA certificate and key paths
  ca_cert: "ca.crt"
  ca_key: "ca.key"
  
  # Organization name for generated certificates
  organization: "SWG Proxy"
  
  # Validity period for generated host certificates
  cert_validity_days: 365

filter:
  # Enable/disable filtering
  enabled: true
  
  # Simple domain blocklist
  domains:
    - "ads.example.com"
    - "*.tracking.com"
    - "malware.bad.com"
  
  # URL prefix blocklist
  urls:
    - "https://phishing.example.com/login"
    - "http://spam.com/offers"
  
  # Regex patterns
  regex:
    - ".*\\.doubleclick\\.net.*"
    - ".*analytics.*\\.js$"
  
  # Full rule definitions with metadata
  rules:
    - type: domain
      pattern: "suspicious.com"
      reason: "suspicious activity detected"
      category: security
    
    - type: url
      pattern: "https://untrusted.com/download"
      reason: "untrusted download source"
      category: security
  
  # External rule sources
  sources:
    - type: csv
      path: "/etc/swg/blocklist.csv"
      has_header: true
    
    # - type: url
    #   url: "https://blocklist.example.com/rules.csv"
    #   has_header: true
  
  # Auto-reload interval for external sources
  reload_interval: 5m

block_page:
  # Enable custom block page
  enabled: true
  
  # Redirect to external block page (optional)
  # redirect_url: "https://internal.company.com/blocked"
  
  # Custom template file (optional)
  # template_path: "/etc/swg/block.html"

logging:
  # Log level: debug, info, warn, error
  level: "info"
  
  # Log format: text, json
  format: "text"
  
  # Output: stdout, stderr, or file path
  output: "stderr"
`

	dir := filepath.Dir(path)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("create directory: %w", err)
		}
	}

	return os.WriteFile(path, []byte(example), 0644)
}
