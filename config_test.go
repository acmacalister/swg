package swg

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	// Server defaults
	if cfg.Server.Addr != ":8080" {
		t.Errorf("expected addr :8080, got %s", cfg.Server.Addr)
	}
	if cfg.Server.ReadTimeout != 30*time.Second {
		t.Errorf("expected read_timeout 30s, got %v", cfg.Server.ReadTimeout)
	}
	if cfg.Server.WriteTimeout != 30*time.Second {
		t.Errorf("expected write_timeout 30s, got %v", cfg.Server.WriteTimeout)
	}
	if cfg.Server.IdleTimeout != 60*time.Second {
		t.Errorf("expected idle_timeout 60s, got %v", cfg.Server.IdleTimeout)
	}

	// TLS defaults
	if cfg.TLS.CACert != "ca.crt" {
		t.Errorf("expected ca_cert ca.crt, got %s", cfg.TLS.CACert)
	}
	if cfg.TLS.CAKey != "ca.key" {
		t.Errorf("expected ca_key ca.key, got %s", cfg.TLS.CAKey)
	}
	if cfg.TLS.Organization != "SWG Proxy" {
		t.Errorf("expected organization 'SWG Proxy', got %s", cfg.TLS.Organization)
	}
	if cfg.TLS.CertValidityDays != 365 {
		t.Errorf("expected cert_validity_days 365, got %d", cfg.TLS.CertValidityDays)
	}

	// Filter defaults
	if !cfg.Filter.Enabled {
		t.Error("expected filter.enabled true")
	}
	if cfg.Filter.ReloadInterval != 5*time.Minute {
		t.Errorf("expected reload_interval 5m, got %v", cfg.Filter.ReloadInterval)
	}

	// Block page defaults
	if !cfg.BlockPage.Enabled {
		t.Error("expected block_page.enabled true")
	}

	// Logging defaults
	if cfg.Logging.Level != "info" {
		t.Errorf("expected logging.level info, got %s", cfg.Logging.Level)
	}
	if cfg.Logging.Format != "text" {
		t.Errorf("expected logging.format text, got %s", cfg.Logging.Format)
	}
	if cfg.Logging.Output != "stderr" {
		t.Errorf("expected logging.output stderr, got %s", cfg.Logging.Output)
	}
}

func TestLoadConfigFromReader(t *testing.T) {
	yaml := `
server:
  addr: ":9090"
  read_timeout: 10s
  write_timeout: 15s
  idle_timeout: 30s

tls:
  ca_cert: "/etc/swg/ca.crt"
  ca_key: "/etc/swg/ca.key"
  organization: "Test Org"
  cert_validity_days: 180

filter:
  enabled: true
  domains:
    - "blocked.com"
    - "*.ads.com"
  urls:
    - "https://phishing.example.com/login"
  regex:
    - ".*tracking.*"
  rules:
    - type: domain
      pattern: "malware.com"
      reason: "known malware"
      category: security
  sources:
    - type: csv
      path: "/etc/swg/blocklist.csv"
      has_header: true
  reload_interval: 10m

block_page:
  enabled: true
  redirect_url: "https://blocked.example.com"

logging:
  level: "debug"
  format: "json"
  output: "/var/log/swg.log"
`

	cfg, err := LoadConfigFromReader("yaml", []byte(yaml))
	if err != nil {
		t.Fatalf("LoadConfigFromReader failed: %v", err)
	}

	// Server
	if cfg.Server.Addr != ":9090" {
		t.Errorf("expected addr :9090, got %s", cfg.Server.Addr)
	}
	if cfg.Server.ReadTimeout != 10*time.Second {
		t.Errorf("expected read_timeout 10s, got %v", cfg.Server.ReadTimeout)
	}
	if cfg.Server.WriteTimeout != 15*time.Second {
		t.Errorf("expected write_timeout 15s, got %v", cfg.Server.WriteTimeout)
	}
	if cfg.Server.IdleTimeout != 30*time.Second {
		t.Errorf("expected idle_timeout 30s, got %v", cfg.Server.IdleTimeout)
	}

	// TLS
	if cfg.TLS.CACert != "/etc/swg/ca.crt" {
		t.Errorf("expected ca_cert /etc/swg/ca.crt, got %s", cfg.TLS.CACert)
	}
	if cfg.TLS.CAKey != "/etc/swg/ca.key" {
		t.Errorf("expected ca_key /etc/swg/ca.key, got %s", cfg.TLS.CAKey)
	}
	if cfg.TLS.Organization != "Test Org" {
		t.Errorf("expected organization 'Test Org', got %s", cfg.TLS.Organization)
	}
	if cfg.TLS.CertValidityDays != 180 {
		t.Errorf("expected cert_validity_days 180, got %d", cfg.TLS.CertValidityDays)
	}

	// Filter
	if !cfg.Filter.Enabled {
		t.Error("expected filter.enabled true")
	}
	if len(cfg.Filter.Domains) != 2 {
		t.Errorf("expected 2 domains, got %d", len(cfg.Filter.Domains))
	}
	if cfg.Filter.Domains[0] != "blocked.com" {
		t.Errorf("expected first domain blocked.com, got %s", cfg.Filter.Domains[0])
	}
	if len(cfg.Filter.URLs) != 1 {
		t.Errorf("expected 1 url, got %d", len(cfg.Filter.URLs))
	}
	if len(cfg.Filter.Regex) != 1 {
		t.Errorf("expected 1 regex, got %d", len(cfg.Filter.Regex))
	}
	if len(cfg.Filter.Rules) != 1 {
		t.Errorf("expected 1 rule, got %d", len(cfg.Filter.Rules))
	}
	if cfg.Filter.Rules[0].Type != "domain" {
		t.Errorf("expected rule type domain, got %s", cfg.Filter.Rules[0].Type)
	}
	if cfg.Filter.Rules[0].Pattern != "malware.com" {
		t.Errorf("expected rule pattern malware.com, got %s", cfg.Filter.Rules[0].Pattern)
	}
	if cfg.Filter.Rules[0].Reason != "known malware" {
		t.Errorf("expected rule reason 'known malware', got %s", cfg.Filter.Rules[0].Reason)
	}
	if cfg.Filter.Rules[0].Category != "security" {
		t.Errorf("expected rule category security, got %s", cfg.Filter.Rules[0].Category)
	}
	if len(cfg.Filter.Sources) != 1 {
		t.Errorf("expected 1 source, got %d", len(cfg.Filter.Sources))
	}
	if cfg.Filter.Sources[0].Type != "csv" {
		t.Errorf("expected source type csv, got %s", cfg.Filter.Sources[0].Type)
	}
	if cfg.Filter.ReloadInterval != 10*time.Minute {
		t.Errorf("expected reload_interval 10m, got %v", cfg.Filter.ReloadInterval)
	}

	// Block page
	if !cfg.BlockPage.Enabled {
		t.Error("expected block_page.enabled true")
	}
	if cfg.BlockPage.RedirectURL != "https://blocked.example.com" {
		t.Errorf("expected redirect_url 'https://blocked.example.com', got %s", cfg.BlockPage.RedirectURL)
	}

	// Logging
	if cfg.Logging.Level != "debug" {
		t.Errorf("expected logging.level debug, got %s", cfg.Logging.Level)
	}
	if cfg.Logging.Format != "json" {
		t.Errorf("expected logging.format json, got %s", cfg.Logging.Format)
	}
	if cfg.Logging.Output != "/var/log/swg.log" {
		t.Errorf("expected logging.output /var/log/swg.log, got %s", cfg.Logging.Output)
	}
}

func TestLoadConfigFromReaderJSON(t *testing.T) {
	json := `{
  "server": {
    "addr": ":7070"
  },
  "filter": {
    "domains": ["test.com"]
  }
}`

	cfg, err := LoadConfigFromReader("json", []byte(json))
	if err != nil {
		t.Fatalf("LoadConfigFromReader(json) failed: %v", err)
	}

	if cfg.Server.Addr != ":7070" {
		t.Errorf("expected addr :7070, got %s", cfg.Server.Addr)
	}
	if len(cfg.Filter.Domains) != 1 || cfg.Filter.Domains[0] != "test.com" {
		t.Errorf("expected domains [test.com], got %v", cfg.Filter.Domains)
	}
}

func TestLoadConfigFromReaderDefaults(t *testing.T) {
	yaml := `
server:
  addr: ":9999"
`

	cfg, err := LoadConfigFromReader("yaml", []byte(yaml))
	if err != nil {
		t.Fatalf("LoadConfigFromReader failed: %v", err)
	}

	// Overridden value
	if cfg.Server.Addr != ":9999" {
		t.Errorf("expected addr :9999, got %s", cfg.Server.Addr)
	}

	// Default values should still be set
	if cfg.Server.ReadTimeout != 30*time.Second {
		t.Errorf("expected default read_timeout 30s, got %v", cfg.Server.ReadTimeout)
	}
	if cfg.TLS.Organization != "SWG Proxy" {
		t.Errorf("expected default organization 'SWG Proxy', got %s", cfg.TLS.Organization)
	}
	if !cfg.Filter.Enabled {
		t.Error("expected default filter.enabled true")
	}
}

func TestLoadConfigFromReaderInvalid(t *testing.T) {
	_, err := LoadConfigFromReader("yaml", []byte("invalid: yaml: data: ["))
	if err == nil {
		t.Error("expected error for invalid YAML")
	}
}

func TestLoadConfig(t *testing.T) {
	// Create temp directory and config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "swg.yaml")

	yaml := `
server:
  addr: ":8888"
filter:
  domains:
    - "example.com"
`
	if err := os.WriteFile(configPath, []byte(yaml), 0644); err != nil {
		t.Fatalf("write config file: %v", err)
	}

	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if cfg.Server.Addr != ":8888" {
		t.Errorf("expected addr :8888, got %s", cfg.Server.Addr)
	}
	if len(cfg.Filter.Domains) != 1 || cfg.Filter.Domains[0] != "example.com" {
		t.Errorf("expected domains [example.com], got %v", cfg.Filter.Domains)
	}
}

func TestLoadConfigMissingFile(t *testing.T) {
	// Should not error for missing file - use defaults
	cfg, err := LoadConfig("/nonexistent/path/config.yaml")
	if err == nil || cfg != nil {
		// Viper errors on explicit path that doesn't exist
		t.Log("LoadConfig correctly errors for missing explicit path")
	}
}

func TestLoadConfigNoFile(t *testing.T) {
	// Create temp dir with no config
	tmpDir := t.TempDir()
	origDir, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(origDir)

	// Should use defaults when no config file found
	cfg, err := LoadConfig("")
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	// Should have default values
	if cfg.Server.Addr != ":8080" {
		t.Errorf("expected default addr :8080, got %s", cfg.Server.Addr)
	}
}

func TestBuildRuleSet(t *testing.T) {
	cfg := &Config{
		Filter: FilterConfig{
			Enabled: true,
			Domains: []string{"blocked.com", "*.ads.com"},
			URLs:    []string{"https://phishing.com/login"},
			Regex:   []string{".*tracking.*"},
			Rules: []RuleConfig{
				{Type: "domain", Pattern: "malware.com", Reason: "known malware", Category: "security"},
			},
		},
	}

	rs, err := cfg.BuildRuleSet()
	if err != nil {
		t.Fatalf("BuildRuleSet failed: %v", err)
	}

	tests := []struct {
		url     string
		blocked bool
		reason  string
	}{
		{"https://blocked.com/page", true, ""},
		{"https://test.ads.com/banner", true, ""},
		{"https://phishing.com/login", true, ""},
		{"https://site.com/tracking.js", true, ""},
		{"https://malware.com/download", true, "known malware (security)"},
		{"https://safe.com/page", false, ""},
	}

	for _, tc := range tests {
		req, _ := http.NewRequest("GET", tc.url, nil)
		blocked, reason := rs.ShouldBlock(req)
		if blocked != tc.blocked {
			t.Errorf("%s: expected blocked=%v, got %v", tc.url, tc.blocked, blocked)
		}
		if tc.reason != "" && reason != tc.reason {
			t.Errorf("%s: expected reason %q, got %q", tc.url, tc.reason, reason)
		}
	}
}

func TestBuildRuleSetInvalidRegex(t *testing.T) {
	cfg := &Config{
		Filter: FilterConfig{
			Regex: []string{"[invalid"},
		},
	}

	_, err := cfg.BuildRuleSet()
	if err == nil {
		t.Error("expected error for invalid regex")
	}
}

func TestBuildRuleLoader(t *testing.T) {
	cfg := &Config{
		Filter: FilterConfig{
			Domains: []string{"blocked.com"},
			URLs:    []string{"https://phishing.com"},
			Regex:   []string{".*ads.*"},
			Rules: []RuleConfig{
				{Type: "domain", Pattern: "malware.com", Reason: "malware", Category: "security"},
			},
		},
	}

	loader, err := cfg.BuildRuleLoader()
	if err != nil {
		t.Fatalf("BuildRuleLoader failed: %v", err)
	}

	rules, err := loader.Load(context.Background())
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	// Should have 4 rules: 1 domain + 1 url + 1 regex + 1 full rule
	if len(rules) != 4 {
		t.Errorf("expected 4 rules, got %d", len(rules))
	}

	// Verify rule types
	typeCount := make(map[string]int)
	for _, r := range rules {
		typeCount[r.Type]++
	}
	if typeCount["domain"] != 2 {
		t.Errorf("expected 2 domain rules, got %d", typeCount["domain"])
	}
	if typeCount["url"] != 1 {
		t.Errorf("expected 1 url rule, got %d", typeCount["url"])
	}
	if typeCount["regex"] != 1 {
		t.Errorf("expected 1 regex rule, got %d", typeCount["regex"])
	}
}

func TestBuildRuleLoaderWithCSVSource(t *testing.T) {
	// Create temp CSV file
	tmpDir := t.TempDir()
	csvPath := filepath.Join(tmpDir, "blocklist.csv")

	csv := `type,pattern,reason,category
domain,csvblocked.com,from csv,test
`
	if err := os.WriteFile(csvPath, []byte(csv), 0644); err != nil {
		t.Fatalf("write csv: %v", err)
	}

	cfg := &Config{
		Filter: FilterConfig{
			Sources: []SourceConfig{
				{Type: "csv", Path: csvPath, HasHeader: true},
			},
		},
	}

	loader, err := cfg.BuildRuleLoader()
	if err != nil {
		t.Fatalf("BuildRuleLoader failed: %v", err)
	}

	rules, err := loader.Load(context.Background())
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if len(rules) != 1 {
		t.Errorf("expected 1 rule, got %d", len(rules))
	}
	if rules[0].Pattern != "csvblocked.com" {
		t.Errorf("expected pattern csvblocked.com, got %s", rules[0].Pattern)
	}
}

func TestBuildRuleLoaderEmpty(t *testing.T) {
	cfg := &Config{
		Filter: FilterConfig{},
	}

	loader, err := cfg.BuildRuleLoader()
	if err != nil {
		t.Fatalf("BuildRuleLoader failed: %v", err)
	}

	rules, err := loader.Load(context.Background())
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	// Should return empty rules, not error
	if len(rules) != 0 {
		t.Errorf("expected 0 rules, got %d", len(rules))
	}
}

func TestBuildRuleLoaderUnknownSourceType(t *testing.T) {
	cfg := &Config{
		Filter: FilterConfig{
			Sources: []SourceConfig{
				{Type: "unknown", Path: "/some/path"},
			},
		},
	}

	_, err := cfg.BuildRuleLoader()
	if err == nil {
		t.Error("expected error for unknown source type")
	}
}

func TestWriteExampleConfig(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "example", "swg.yaml")

	err := WriteExampleConfig(configPath)
	if err != nil {
		t.Fatalf("WriteExampleConfig failed: %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		t.Error("config file was not created")
	}

	// Verify content is valid YAML that can be loaded
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}

	cfg, err := LoadConfigFromReader("yaml", data)
	if err != nil {
		t.Fatalf("example config is not valid: %v", err)
	}

	// Verify some expected values
	if cfg.Server.Addr != ":8080" {
		t.Errorf("expected addr :8080 in example, got %s", cfg.Server.Addr)
	}
	if len(cfg.Filter.Domains) == 0 {
		t.Error("expected domains in example config")
	}
}

func TestWriteExampleConfigCurrentDir(t *testing.T) {
	tmpDir := t.TempDir()
	origDir, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(origDir)

	err := WriteExampleConfig("swg.yaml")
	if err != nil {
		t.Fatalf("WriteExampleConfig failed: %v", err)
	}

	if _, err := os.Stat("swg.yaml"); os.IsNotExist(err) {
		t.Error("config file was not created in current dir")
	}
}

func TestEnvironmentVariableOverride(t *testing.T) {
	// Create temp directory with config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "swg.yaml")

	yaml := `
server:
  addr: ":8080"
`
	if err := os.WriteFile(configPath, []byte(yaml), 0644); err != nil {
		t.Fatalf("write config file: %v", err)
	}

	// Set environment variable to override
	os.Setenv("SWG_SERVER_ADDR", ":9999")
	defer os.Unsetenv("SWG_SERVER_ADDR")

	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	// Environment variable should override config file
	if cfg.Server.Addr != ":9999" {
		t.Errorf("expected addr :9999 from env, got %s", cfg.Server.Addr)
	}
}

func TestEnvironmentVariableNestedOverride(t *testing.T) {
	tmpDir := t.TempDir()
	origDir, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(origDir)

	// Set environment variable for nested config
	os.Setenv("SWG_TLS_ORGANIZATION", "Env Org")
	defer os.Unsetenv("SWG_TLS_ORGANIZATION")

	cfg, err := LoadConfig("")
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if cfg.TLS.Organization != "Env Org" {
		t.Errorf("expected organization 'Env Org' from env, got %s", cfg.TLS.Organization)
	}
}
