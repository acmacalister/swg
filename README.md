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
- **Health Check Endpoints**: `/healthz` and `/readyz` probes for Kubernetes and load balancers
- **Structured Access Log**: JSON access log with request metadata, timing, and filter decisions
- **SIGHUP Reload**: Reload config and filter rules without restarting (`kill -HUP <pid>`)
- **Policy Engine**: Lifecycle hooks for request/response interception with pluggable identity, group policies, and scanning
- **Allow-List Mode**: Deny-by-default filtering for kiosk and restricted environments
- **Time-Based Rules**: Schedule filter activation by hour-of-day and day-of-week with timezone support
- **Per-User/Group Policies**: Apply different filters based on client identity resolved from IP, CIDR, or custom resolvers
- **Content-Type Filtering**: Block responses by MIME type (e.g. executable downloads)
- **Response Body Scanning**: Pluggable AV/DLP scanners with allow, block, and replace verdicts
- **Upstream Proxy Chaining**: Forward through a parent proxy with CONNECT tunnel and PROXY protocol support
- **Connection Pooling**: Configurable transport pool with HTTP/2 support and connection statistics
- **Rate Limiting**: Per-client token-bucket rate limiter with automatic stale bucket cleanup
- **Admin API**: REST endpoints for runtime rule CRUD, status inspection, and filter reloads via [chi](https://github.com/go-chi/chi)
- **mTLS Client Auth**: Mutual TLS authentication requiring client certificates with identity/group extraction
- **Bypass Token**: Allow authorized clients to skip filtering for debugging via header token or identity
- **Certificate Rotation**: Hot-swap CA certificates at runtime without proxy restart
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
  -access-log string
        access log output: stdout, stderr, or file path (disabled if empty)
  -healthz
        enable /healthz and /readyz health endpoints
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

# Enable health check endpoints
swg -block "ads.com" -healthz

# Enable structured JSON access log to file
swg -block "ads.com" -access-log /var/log/swg/access.log

# Access log to stdout (useful in containers)
swg -block "ads.com" -access-log stdout

# Reload config/rules without restart
kill -HUP $(pidof swg)
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

### Health Check Endpoints

```go
health := swg.NewHealthChecker()
proxy.HealthChecker = health

// Mark alive/ready at appropriate lifecycle points
health.SetAlive(true)
health.SetReady(true)

// Add custom readiness checks
health.ReadinessChecks = append(health.ReadinessChecks, func() error {
    if !databaseIsReachable() {
        return errors.New("database unavailable")
    }
    return nil
})
```

Endpoints return JSON:
- `GET /healthz` — `{"status":"ok","uptime":"1h30m0s"}`
- `GET /readyz` — `{"status":"ok","uptime":"1h30m0s"}` or `{"status":"not ready","details":[...]}`

### Structured Access Log

```go
// Create a JSON access logger writing to a file
f, _ := os.OpenFile("access.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
alLogger := slog.New(slog.NewJSONHandler(f, nil))
proxy.AccessLog = swg.NewAccessLogger(alLogger)
```

Each request produces a JSON log entry with method, host, path, scheme, status code, duration, bytes written, client address, blocked/reason, and user agent.

### SIGHUP Reload

```go
reloader := swg.WatchSIGHUP(proxy, func(ctx context.Context) (swg.Filter, error) {
    // Rebuild filter from config, database, etc.
    cfg, err := swg.LoadConfig("swg.yaml")
    if err != nil {
        return nil, err
    }
    loader, _ := cfg.BuildRuleLoader()
    filter := swg.NewReloadableFilter(loader)
    filter.Load(ctx)
    return filter, nil
}, logger)
defer reloader.Cancel()
```

Send `SIGHUP` to the process to trigger a filter reload without downtime.

### Policy Engine

The policy engine provides lifecycle hooks for the full request/response pipeline:

```go
policy := swg.NewPolicyEngine()

// Resolve client identity from IP ranges
resolver := swg.NewIPIdentityResolver()
resolver.AddIP("10.0.0.50", "alice", []string{"engineering"})
resolver.AddCIDR("192.168.1.0/24", "guest", []string{"guests"})
policy.IdentityResolver = resolver

// Add request hooks (run before filtering)
policy.RequestHooks = []swg.RequestHook{
    swg.RequestHookFunc(func(ctx context.Context, req *http.Request, rc *swg.RequestContext) *http.Response {
        log.Printf("request from %s (%s)", rc.Identity, rc.ClientIP)
        rc.Tags["inspected"] = "true"
        return nil // return non-nil *http.Response to short-circuit
    }),
}

proxy.Policy = policy
```

### Per-User/Group Policies

```go
groupFilter := swg.NewGroupPolicyFilter()

// Engineering: minimal blocking
engFilter := swg.NewDomainFilter()
engFilter.AddDomain("malware.example.com")
groupFilter.SetPolicy("engineering", engFilter)

// Guests: allow-list mode (deny everything not explicitly permitted)
guestFilter := swg.NewAllowListFilter()
guestFilter.AddDomains([]string{"docs.google.com", "*.wikipedia.org"})
groupFilter.SetPolicy("guests", guestFilter)

// Fallback for unrecognized users
groupFilter.Default = swg.NewDomainFilter()

proxy.Filter = groupFilter
```

### Allow-List Mode

```go
// Deny-by-default: only listed domains are allowed
allow := swg.NewAllowListFilter()
allow.AddDomains([]string{
    "docs.google.com",
    "*.golang.org",
    "pkg.go.dev",
})
allow.Reason = "domain not on approved list"

proxy.Filter = allow
```

### Time-Based Rules

```go
// Block social media Mon-Fri 9am-5pm US Eastern
eastern, _ := time.LoadLocation("America/New_York")
socialBlock := swg.NewDomainFilter()
socialBlock.AddDomains([]string{"twitter.com", "facebook.com", "reddit.com"})

proxy.Filter = &swg.TimeRule{
    Inner:     socialBlock,
    StartHour: 9,
    EndHour:   17,
    Weekdays:  []time.Weekday{time.Monday, time.Tuesday, time.Wednesday, time.Thursday, time.Friday},
    Location:  eastern,
}
```

### Composing Filters

```go
// Chain multiple filters — first block wins
proxy.Filter = &swg.ChainFilter{
    Filters: []swg.Filter{socialTimeRule, afterHoursBlock, malwareFilter},
}
```

### Content-Type Filtering

```go
// Block executable downloads via ResponseHook
ctFilter := swg.NewContentTypeFilter()
ctFilter.Block("application/x-executable", "executable downloads blocked")
ctFilter.Block("application/x-msdownload", "Windows executables blocked")

policy := swg.NewPolicyEngine()
policy.ResponseHooks = []swg.ResponseHook{ctFilter}
proxy.Policy = policy
```

### Response Body Scanning

```go
// Implement ResponseBodyScanner for AV/DLP integration
type AVScanner struct{}

func (s *AVScanner) Scan(ctx context.Context, body []byte, req *http.Request, resp *http.Response) (swg.ScanResult, error) {
    if isMalware(body) {
        return swg.ScanResult{Verdict: swg.VerdictBlock, Reason: "malware detected"}, nil
    }
    return swg.ScanResult{Verdict: swg.VerdictAllow}, nil
}

policy := swg.NewPolicyEngine()
policy.BodyScanners = []swg.ResponseBodyScanner{&AVScanner{}}
policy.ScanContentTypes = []string{"text/html", "application/json"} // empty = scan all
policy.MaxScanSize = 10 << 20 // 10 MiB (default)
proxy.Policy = policy
```

Scanners return one of three verdicts:

| Verdict | Behavior |
|---------|----------|
| `VerdictAllow` | Content passes through unmodified |
| `VerdictBlock` | Client receives 403 with the reason |
| `VerdictReplace` | Scanner provides a replacement body (e.g. DLP redaction) |

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

### Admin API

The Admin API provides REST endpoints for runtime rule management:

```go
admin := swg.NewAdminAPI(proxy)
admin.Logger = logger

// Optional: configure reload from your source
admin.ReloadFunc = func(ctx context.Context) error {
    return filter.Load(ctx)
}

proxy.Admin = admin
```

Endpoints (default prefix `/api`):

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/status` | Proxy status, rule count, uptime, filter type |
| `GET` | `/api/rules` | List all active rules |
| `POST` | `/api/rules` | Add a rule (`{"type":"domain","pattern":"evil.com"}`) |
| `DELETE` | `/api/rules` | Remove a rule (`{"type":"domain","pattern":"evil.com"}`) |
| `POST` | `/api/reload` | Reload rules from source |

```bash
# Check status
curl http://localhost:8080/api/status

# List rules
curl http://localhost:8080/api/rules

# Add a rule
curl -X POST http://localhost:8080/api/rules \
  -d '{"type":"domain","pattern":"ads.com","reason":"advertising"}'

# Remove a rule
curl -X DELETE http://localhost:8080/api/rules \
  -d '{"type":"domain","pattern":"ads.com"}'

# Trigger reload
curl -X POST http://localhost:8080/api/reload
```

Rule mutations require the filter to be a `*RuleSet` or `*ReloadableFilter`. Other filter types report status and rules as read-only.

### mTLS Client Authentication

Require client certificates to connect to the proxy, limiting access to managed devices:

```go
// Load CA that signed client certificates
clientAuth, err := swg.NewClientAuthFromFile("client-ca.pem")
if err != nil {
    log.Fatal(err)
}

// Optional: allow unauthenticated clients (gradual rollout)
// clientAuth.SetPolicy(tls.VerifyClientCertIfGiven)

proxy.ClientAuth = clientAuth
```

When enabled, the proxy listener is wrapped with TLS requiring client certificates. The cert's Subject fields are automatically mapped to identity:

- **CommonName** → `RequestContext.Identity`
- **Organization** → `RequestContext.Groups`
- Tag `auth=mtls` is set on the request context

Generate client certificates for testing (same package or using the CA PEM directly):

```go
// Parse CA cert from PEM for signing
block, _ := pem.Decode(caCertPEM)
caCert, _ := x509.ParseCertificate(block.Bytes)

certPEM, keyPEM, err := swg.GenerateClientCert(
    caCert, caKeyPEM,
    "alice",                       // CommonName (identity)
    []string{"engineering", "ops"}, // Organizations (groups)
    1,                              // Valid for 1 year
)
```

### Bypass Token

Allow authorized clients to skip content filtering for debugging:

```go
bypass := swg.NewBypass()
bypass.AddToken("debug-token-abc123")

// Or generate a cryptographically random token
tok, _ := bypass.GenerateToken()
fmt.Println("Generated token:", tok)

// Grant bypass by identity (e.g. from mTLS cert CN)
bypass.Identities["admin-user"] = true

proxy.Bypass = bypass
```

Clients set the bypass header to skip filtering:

```bash
curl -H "X-SWG-Bypass: debug-token-abc123" -x http://proxy:8080 http://blocked-site.com
```

Tokens are compared using constant-time comparison. The bypass header is stripped before forwarding to upstream.

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
                ┌──────┴──────┐
                ▼             ▼
         ┌────────────┐ ┌──────────────┐
         │CertManager │ │ PolicyEngine │
         │(Dynamic TLS)│ │  (Lifecycle) │
         └────────────┘ └──────┬───────┘
                               │
           ┌───────────────────┼───────────────────┐
           ▼                   ▼                   ▼
    ┌──────────────┐   ┌──────────────┐   ┌──────────────┐
    │  Identity    │   │   Filter     │   │ Body Scanner │
    │  Resolver    │   │ (Block/Allow)│   │  (AV / DLP)  │
    └──────────────┘   └──────────────┘   └──────────────┘
```

### Request Lifecycle

1. Client sends CONNECT request to proxy
2. Proxy responds with 200 Connection Established
3. Proxy performs TLS handshake with client using dynamically generated certificate
4. **Policy request hooks** run: identity resolution, access control, tagging
5. **Filter** checks: domain, URL, regex, allow-list, time-based, group-based
6. If allowed, proxy forwards request to origin server
7. **Policy response hooks** run: content-type filtering
8. **Body scanners** run: AV, DLP, keyword detection
9. Response is returned to client through the TLS tunnel

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

## Performance

SWG is designed for high throughput with minimal overhead. Benchmarks run on Apple M4 Pro:

| Operation | Performance | Notes |
|-----------|-------------|-------|
| HTTP proxy throughput | ~14,000 req/s | Plain HTTP forwarding |
| Certificate generation | ~43ms | Per-host, first request only |
| Certificate cache hit | ~6ns | Subsequent requests |
| Domain filter (100K rules) | ~40ns | O(1) map lookup |
| Wildcard filter (10K rules) | ~71µs | Linear scan |
| Rate limiter check | ~47ns | Per-client token bucket |
| Gzip compression | 4 GB/s | ~50KB response body |
| Brotli compression | 292 MB/s | Better ratio, slower |

### Comparison with Other Proxies

Direct benchmarking across MITM proxies is difficult due to differing test methodologies, hardware, and feature sets. For rough reference:

| Proxy | Language | Approx. Throughput | Notes |
|-------|----------|-------------------|-------|
| **SWG** | Go | ~14,000 req/s | This project |
| mitmproxy | Python | ~1,400 req/s | Single-threaded |
| Traefik | Go | ~26,000 req/s | Reverse proxy (not MITM) |
| Caddy | Go | ~18,000 req/s | Reverse proxy (not MITM) |

*Note: mitmproxy numbers from [Fluxzy benchmarks](https://www.fluxzy.io/resources/blogs/performance-benchmark-fluxzy-mitmproxy-mitmdump-squid). Traefik/Caddy are reverse proxies without MITM interception, included for Go baseline reference.*

Run benchmarks locally:

```bash
go test -bench=. -benchmem ./...
```

## License

MIT License - see [LICENSE](LICENSE) for details.
