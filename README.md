# SWG - Secure Web Gateway

[![Go Reference](https://pkg.go.dev/badge/github.com/acmacalister/swg.svg)](https://pkg.go.dev/github.com/acmacalister/swg)
[![CI](https://github.com/acmacalister/swg/actions/workflows/ci.yml/badge.svg)](https://github.com/acmacalister/swg/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/acmacalister/swg/branch/master/graph/badge.svg)](https://codecov.io/gh/acmacalister/swg)
[![Go Report Card](https://goreportcard.com/badge/github.com/acmacalister/swg)](https://goreportcard.com/report/github.com/acmacalister/swg)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

An HTTPS man-in-the-middle (MITM) proxy for content filtering written in Go. SWG intercepts HTTPS traffic by dynamically generating certificates, allowing inspection and filtering of encrypted connections.

## Features

- **SSL/TLS Interception**: Decrypt HTTPS traffic using dynamically generated certificates
- **Content Filtering**: Block requests based on domain names, URL prefixes, and regex patterns
- **Custom Block Pages**: Fully customizable HTML block pages with template support
- **PAC File Generation**: Generate Proxy Auto-Configuration files for client setup
- **Prometheus Metrics**: Built-in instrumentation for monitoring and alerting
- **Auto-Reloading Rules**: Load blocklists from CSV, HTTP endpoints, or databases with periodic refresh
- **Configuration Files**: YAML/JSON/TOML config with environment variable overrides
- **Cross-Platform**: Runs on Linux, macOS, and Windows

## Installation

### Homebrew (macOS/Linux)

```bash
brew install acmacalister/tap/swg
```

### APT (Debian/Ubuntu)

```bash
echo "deb [trusted=yes] https://apt.fury.io/acmacalister/ /" | sudo tee /etc/apt/sources.list.d/swg.list
sudo apt update
sudo apt install swg
```

### APK (Alpine Linux)

```bash
# Download the latest .apk from releases
sudo apk add --allow-untrusted swg_*.apk
```

### Pacman (Arch Linux)

```bash
# Using yay
yay -S swg-bin

# Or download from releases
sudo pacman -U swg_*.pkg.tar.zst
```

### RPM (Fedora/RHEL/CentOS)

```bash
sudo rpm -i swg_*.rpm
```

### Go Install

```bash
go install github.com/acmacalister/swg/cmd@latest
```

### From Source

```bash
git clone https://github.com/acmacalister/swg.git
cd swg
go build -o swg ./cmd
```

### Docker

```bash
docker pull ghcr.io/acmacalister/swg:latest
docker run -p 8080:8080 -v $(pwd)/certs:/certs ghcr.io/acmacalister/swg:latest \
  -ca-cert /certs/ca.crt -ca-key /certs/ca.key
```

## Quick Start

### 1. Generate CA Certificate

```bash
swg -gen-ca
```

This creates `ca.crt` and `ca.key` in the current directory.

### 2. Trust the CA Certificate

**macOS:**
```bash
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ca.crt
```

**Linux (Debian/Ubuntu):**
```bash
sudo cp ca.crt /usr/local/share/ca-certificates/swg-ca.crt
sudo update-ca-certificates
```

**Windows:**
```powershell
Import-Certificate -FilePath ca.crt -CertStoreLocation Cert:\LocalMachine\Root
```

### 3. Start the Proxy

```bash
swg -addr :8080 -block "ads.example.com,*.tracking.com" -v
```

### 4. Configure System Proxy

Set your system or browser to use `localhost:8080` as the HTTP/HTTPS proxy.

## CLI Usage

```
Usage of swg:
  -addr string
        proxy listen address (default ":8080")
  -block string
        comma-separated list of domains to block
  -block-page-file string
        path to custom block page HTML template
  -block-page-url string
        URL to redirect blocked requests to
  -ca-cert string
        path to CA certificate (default "ca.crt")
  -ca-key string
        path to CA private key (default "ca.key")
  -ca-org string
        organization name for generated CA (default "SWG Proxy")
  -config string
        path to config file (default: search ./swg.yaml, ~/.swg/config.yaml, /etc/swg/config.yaml)
  -gen-ca
        generate a new CA certificate and exit
  -gen-config
        generate example config file and exit
  -gen-pac
        generate a PAC file and exit
  -metrics
        enable Prometheus metrics endpoint
  -pac-bypass string
        comma-separated domains to bypass proxy in PAC file
  -print-block-page
        print default block page template and exit
  -v    verbose logging
```

### Examples

```bash
# Basic usage with domain blocking
swg -block "facebook.com,twitter.com,*.ads.com"

# Using a config file
swg -config /etc/swg/swg.yaml

# Generate example config file
swg -gen-config

# Custom block page redirect
swg -block "malware.com" -block-page-url "https://internal.company.com/blocked"

# Custom block page template
swg -block "restricted.com" -block-page-file ./my-block-page.html

# Export default block page template for customization
swg -print-block-page > custom-block.html

# Generate a PAC file for client auto-configuration
swg -gen-pac -pac-bypass "internal.company.com,*.local"

# Enable Prometheus metrics on /metrics
swg -block "ads.com" -metrics -v
```

### Configuration File

SWG supports YAML, JSON, and TOML configuration files. Generate an example config:

```bash
swg -gen-config
```

Example `swg.yaml`:

```yaml
server:
  addr: ":8080"
  read_timeout: 30s
  write_timeout: 30s

tls:
  ca_cert: "ca.crt"
  ca_key: "ca.key"
  organization: "SWG Proxy"

filter:
  enabled: true
  domains:
    - "ads.example.com"
    - "*.tracking.com"
  reload_interval: 5m

logging:
  level: "info"
  format: "json"
```

Config file search paths (in order):
1. Explicit path via `-config`
2. `./swg.yaml`
3. `$HOME/.swg/config.yaml`
4. `/etc/swg/config.yaml`

Environment variables override config file values with `SWG_` prefix:
- `SWG_SERVER_ADDR=:9090`
- `SWG_TLS_ORGANIZATION="My Org"`
- `SWG_FILTER_ENABLED=false`

## Library API

SWG can be used as a Go library for building custom proxy solutions.

### Basic Proxy

```go
package main

import (
    "log"
    "github.com/acmacalister/swg"
)

func main() {
    // Load CA certificate
    cm, err := swg.NewCertManager("ca.crt", "ca.key")
    if err != nil {
        log.Fatal(err)
    }

    // Create proxy
    proxy := swg.NewProxy(":8080", cm)

    // Start proxy
    log.Fatal(proxy.ListenAndServe())
}
```

### Domain Filtering

```go
// Create domain filter
filter := swg.NewDomainFilter()
filter.AddDomain("blocked.com")
filter.AddDomain("*.ads.example.com")  // Wildcard support
filter.AddDomains([]string{"evil.com", "malware.org"})

proxy.Filter = filter
```

### Advanced Filtering with RuleSet

RuleSet supports domains, URLs, and regex patterns with categories:

```go
// Create a rule set
rs := swg.NewRuleSet()

// Add domain rules
rs.AddDomain("blocked.com")
rs.AddDomain("*.ads.example.com")

// Add URL prefix rules
rs.AddURL("https://evil.com/malware")

// Add regex patterns
rs.AddRegex(`.*\.tracking\..*`)

// Add rules with full metadata
rs.AddRule(swg.Rule{
    Type:     "domain",
    Pattern:  "malware.com",
    Reason:   "known malware host",
    Category: "security",
})

proxy.Filter = rs
```

### Loading Rules from CSV

```go
// Create CSV loader
loader := swg.NewCSVLoader("blocklist.csv")
loader.HasHeader = true
loader.DefaultReason = "blocked by policy"

// Create reloadable filter
filter := swg.NewReloadableFilter(loader)

// Set up callbacks
filter.OnReload = func(count int) {
    log.Printf("Loaded %d rules", count)
}
filter.OnError = func(err error) {
    log.Printf("Reload error: %v", err)
}

// Initial load
ctx := context.Background()
filter.Load(ctx)

// Start auto-reload every 5 minutes
cancel := filter.StartAutoReload(ctx, 5*time.Minute)
defer cancel()

proxy.Filter = filter
```

CSV format: `type,pattern,reason,category`

```csv
type,pattern,reason,category
domain,ads.example.com,advertising,ads
domain,*.tracking.com,user tracking,analytics
url,https://phishing.com/login,phishing attempt,security
regex,.*\.doubleclick\.net.*,ad tracker,ads
```

### Loading Rules from PostgreSQL

See `_examples/postgres/` for a complete example using sqlx:

```go
// Implement RuleLoader interface
type PostgresLoader struct {
    DB *sqlx.DB
}

func (l *PostgresLoader) Load(ctx context.Context) ([]swg.Rule, error) {
    var rules []swg.Rule
    err := l.DB.SelectContext(ctx, &rules, 
        `SELECT rule_type as type, pattern, reason, category 
         FROM blocklist WHERE enabled = true`)
    return rules, err
}

// Use with ReloadableFilter
loader := &PostgresLoader{DB: db}
filter := swg.NewReloadableFilter(loader)
filter.Load(ctx)
```

### Combining Multiple Sources

```go
// Load from multiple sources
csvLoader := swg.NewCSVLoader("local-rules.csv")
urlLoader := swg.NewURLLoader("https://blocklist.example.com/rules.csv")
staticLoader := swg.NewStaticLoader(
    swg.Rule{Type: "domain", Pattern: "always-blocked.com"},
)

multiLoader := swg.NewMultiLoader(csvLoader, urlLoader, staticLoader)
filter := swg.NewReloadableFilter(multiLoader)
```

### Custom Filter

```go
// Implement the Filter interface
type MyFilter struct{}

func (f *MyFilter) ShouldBlock(req *http.Request) (bool, string) {
    // Block requests with specific paths
    if strings.Contains(req.URL.Path, "/api/tracking") {
        return true, "tracking endpoint blocked"
    }
    return false, ""
}

proxy.Filter = &MyFilter{}

// Or use FilterFunc for simple cases
proxy.Filter = swg.FilterFunc(func(req *http.Request) (bool, string) {
    if req.Host == "blocked.com" {
        return true, "domain blocked"
    }
    return false, ""
})
```

### Custom Block Page

```go
// Use built-in styled block page
proxy.BlockPage = swg.NewBlockPage()

// Or load from file
blockPage, err := swg.NewBlockPageFromFile("block.html")
if err != nil {
    log.Fatal(err)
}
proxy.BlockPage = blockPage

// Or from template string
tmpl := `<html><body>Blocked: {{.URL}} - {{.Reason}}</body></html>`
blockPage, err := swg.NewBlockPageFromTemplate(tmpl)
proxy.BlockPage = blockPage
```

### Block Page Template Variables

| Variable | Description |
|----------|-------------|
| `{{.URL}}` | Full blocked URL |
| `{{.Host}}` | Hostname of blocked request |
| `{{.Path}}` | Path of blocked request |
| `{{.Reason}}` | Reason for blocking |
| `{{.Timestamp}}` | Time of block (RFC1123 format) |

### Generate CA Programmatically

```go
certPEM, keyPEM, err := swg.GenerateCA("My Organization", 10) // 10 year validity
if err != nil {
    log.Fatal(err)
}

// Save to files
os.WriteFile("ca.crt", certPEM, 0644)
os.WriteFile("ca.key", keyPEM, 0600)

// Or use directly
cm, err := swg.NewCertManagerFromPEM(certPEM, keyPEM)
```

### Graceful Shutdown

```go
ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()

if err := proxy.Shutdown(ctx); err != nil {
    log.Printf("shutdown error: %v", err)
}
```

### PAC File Generation

```go
pac := swg.NewPACGenerator("proxy.example.com:8080")
pac.AddBypassDomain("internal.company.com")
pac.AddBypassNetwork("10.0.0.0/8")

// Serve as HTTP handler
http.Handle("/proxy.pac", pac)

// Or generate to file
pac.WriteFile("proxy.pac")
```

### Prometheus Metrics

```go
metrics := swg.NewMetrics()
http.Handle("/metrics", metrics.Handler())

// Record proxy events
metrics.RecordRequest("GET", "https")
metrics.RecordBlocked("ads")
metrics.RecordRequestDuration("GET", 200, duration)
```

## Architecture

```
┌─────────┐     ┌───────────────┐     ┌──────────────┐
│ Client  │────▶│   SWG Proxy   │────▶│ Origin Server│
└─────────┘     └───────────────┘     └──────────────┘
                       │
                       ▼
               ┌───────────────┐
               │ CertManager   │
               │ (Dynamic TLS) │
               └───────────────┘
                       │
                       ▼
               ┌───────────────┐
               │    Filter     │
               │ (Block/Allow) │
               └───────────────┘
```

1. Client sends CONNECT request to proxy
2. Proxy responds with 200 Connection Established
3. Proxy performs TLS handshake with client using dynamically generated certificate
4. Proxy inspects decrypted request and applies filters
5. If allowed, proxy forwards request to origin server
6. Response is returned to client through the TLS tunnel

## Security Considerations

- **CA Private Key**: The CA private key (`ca.key`) should be kept secure. Anyone with access can intercept traffic.
- **Trust Scope**: Only install the CA certificate on systems you control.
- **Network Position**: The proxy must be in the network path to intercept traffic.
- **Certificate Pinning**: Applications using certificate pinning will fail through this proxy.

## Kubernetes Deployment

SWG includes Kubernetes manifests and a Helm chart for cluster deployment.

### Using kubectl

```bash
# Create CA secret first
kubectl create namespace swg
kubectl create secret generic swg-ca-cert \
  --from-file=ca.crt=ca.crt \
  --from-file=ca.key=ca.key \
  -n swg

# Apply manifests
kubectl apply -f deploy/kubernetes/
```

See [deploy/kubernetes/README.md](deploy/kubernetes/README.md) for details.

### Using Helm

```bash
helm install swg ./deploy/helm/swg -n swg
```

See [deploy/helm/swg/README.md](deploy/helm/swg/README.md) for configuration options.

## License

MIT License - see [LICENSE](LICENSE) for details.
