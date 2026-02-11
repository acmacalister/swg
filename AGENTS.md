# AGENTS.md

Agent instructions for the `swg` Go project - a Secure Web Gateway / HTTPS MITM proxy.

## Project Overview

This is a Go module (`github.com/acmacalister/swg`) that provides an HTTPS man-in-the-middle proxy for content filtering. The proxy:

- Intercepts HTTPS traffic via SSL/TLS decryption
- Generates per-host certificates signed by a trusted CA
- Filters requests based on configurable rules (domains, URLs, regex patterns)
- Supports loading blocklists from CSV, HTTP endpoints, databases, or custom sources
- Displays customizable block pages using Go templates
- Ships as both a library and CLI tool

## Commands

### Build

```bash
go build ./...
```

### Run CLI

```bash
# Generate CA certificate (first time)
go run ./cmd -gen-ca

# Start proxy with domain blocking
go run ./cmd -addr :8080 -block "ads.example.com,*.tracking.com" -v

# With custom block page
go run ./cmd -block "blocked.com" -block-page-file ./custom.html
```

### Test

```bash
go test ./...

# With coverage
go test -cover ./...

# Run benchmarks
go test -bench=. ./...
```

### Format & Lint

```bash
go fmt ./...
go vet ./...
```

### Release (goreleaser)

```bash
# Snapshot build (local testing)
goreleaser release --snapshot --clean

# Full release (requires GITHUB_TOKEN)
goreleaser release --clean
```

## Project Structure

```
swg/
├── go.mod              # Module definition (Go 1.25.3)
├── swg.go              # Package documentation
├── certs.go            # CA and certificate management
├── certs_test.go       # Tests for certificate functions
├── proxy.go            # HTTPS MITM proxy implementation
├── proxy_test.go       # Tests for proxy functions
├── filter.go           # Rule-based filtering system (RuleSet, loaders)
├── filter_test.go      # Tests for filter functions
├── metrics.go          # Prometheus metrics instrumentation
├── metrics_test.go     # Tests for metrics functions
├── pac.go              # PAC file generator
├── pac_test.go         # Tests for PAC functions
├── blockpage.go        # Custom block page templates
├── blockpage_test.go   # Tests for block page functions
├── config.go           # Viper-based configuration loading
├── config_test.go      # Tests for config functions
├── .goreleaser.yaml    # GoReleaser configuration
├── Dockerfile          # Container image definition
├── README.md           # User documentation
├── _examples/          # Example implementations
│   ├── csv/            # CSV-based blocklist example
│   ├── config/         # Config file example
│   └── postgres/       # PostgreSQL blocklist example
├── deploy/
│   ├── kubernetes/     # Raw K8s manifests
│   └── helm/swg/       # Helm chart
└── cmd/
    └── main.go         # CLI entry point
```

## Key Components

### `CertManager` (certs.go)
- `NewCertManager(certPath, keyPath)` - Load CA from files
- `NewCertManagerFromPEM(certPEM, keyPEM)` - Load CA from PEM bytes
- `GetCertificate(hello)` - For `tls.Config.GetCertificate`
- `GetCertificateForHost(host)` - Generate/cache cert for hostname
- `GenerateCA(org, validYears)` - Create new CA cert/key pair

### `Proxy` (proxy.go)
- `NewProxy(addr, certManager)` - Create new proxy instance
- `ListenAndServe()` - Start the proxy server
- `Shutdown(ctx)` - Graceful shutdown
- `ServeHTTP(w, r)` - HTTP handler (implements `http.Handler`)

**Proxy Fields:**
- `Addr` - Listen address (e.g., `:8080`)
- `CertManager` - Certificate manager for TLS
- `Filter` - Request filter (optional)
- `BlockPageURL` - Redirect URL for blocked requests (optional)
- `BlockPage` - Custom block page template (optional)
- `Metrics` - `*Metrics` for Prometheus instrumentation (optional)
- `PACHandler` - `*PACGenerator` serves `/proxy.pac` (optional)
- `Logger` - `*slog.Logger` for logging
- `Transport` - `http.RoundTripper` for outbound requests

### `Filter` interface (proxy.go)
```go
type Filter interface {
    ShouldBlock(req *http.Request) (blocked bool, reason string)
}
```

- `FilterFunc` - Function adapter for simple filters
- `DomainFilter` - Simple domain blocklist with wildcard support

### `RuleSet` (filter.go)
Advanced filtering with multiple rule types:
- `AddDomain(domain)` - Block exact domain or wildcard (`*.ads.com`)
- `AddURL(prefix)` - Block URL prefixes
- `AddRegex(pattern)` - Block by regex pattern
- `AddRule(Rule)` - Add rule with full metadata (type, pattern, reason, category)
- `Match(req)` - Returns matching rule
- `ShouldBlock(req)` - Implements `Filter` interface

### `RuleLoader` interface (filter.go)
```go
type RuleLoader interface {
    Load(ctx context.Context) ([]Rule, error)
}
```

Built-in loaders:
- `CSVLoader` - Load from CSV file
- `URLLoader` - Load from HTTP endpoint (CSV format)
- `StaticLoader` - Fixed set of rules
- `MultiLoader` - Combine multiple loaders

### `ReloadableFilter` (filter.go)
- `NewReloadableFilter(loader)` - Create with a `RuleLoader`
- `Load(ctx)` - Load/reload rules from source
- `StartAutoReload(ctx, interval)` - Background reload goroutine
- `OnReload` - Callback after successful reload
- `OnError` - Callback on reload error

### `PACGenerator` (pac.go)
- `NewPACGenerator(proxyAddr)` - Create PAC generator with defaults
- `AddBypassDomain(domain)` - Add domain to bypass list
- `AddBypassNetwork(cidr)` - Add CIDR network to bypass list
- `Generate(w)` - Write PAC content to writer
- `GenerateString()` - Return PAC as string
- `WriteFile(path)` - Write PAC to disk
- `ServeHTTP(w, r)` - HTTP handler (implements `http.Handler`)

**Fields:**
- `ProxyAddr` - Proxy address in host:port format
- `BypassDomains` - Domains that should connect directly
- `BypassNetworks` - CIDR networks that should connect directly
- `FallbackDirect` - Fall back to direct if proxy unreachable (default: true)

### `Metrics` (metrics.go)
- `NewMetrics()` - Create metrics instance with Prometheus registry
- `Handler()` - Returns `http.Handler` for `/metrics` endpoint
- `RecordRequest(method, scheme)` - Count requests
- `RecordBlocked(reason)` - Count blocked requests
- `RecordRequestDuration(method, statusCode, duration)` - Histogram of latency
- `IncActiveConns()` / `DecActiveConns()` - Active connection gauge
- `SetCertCacheSize(size)` - Certificate cache gauge
- `RecordCertCacheHit()` / `RecordCertCacheMiss()` - Cache metrics
- `SetFilterRuleCount(count)` - Rule count gauge
- `RecordFilterReload()` / `RecordFilterReloadError()` - Reload counters
- `RecordUpstreamError(host)` - Upstream error counter
- `RecordTLSHandshakeError()` - TLS handshake failure counter

### `BlockPage` (blockpage.go)
- `NewBlockPage()` - Default styled block page
- `NewBlockPageFromTemplate(tmpl)` - Custom template string
- `NewBlockPageFromFile(path)` - Load template from file

**Template Variables (`BlockPageData`):**
- `{{.URL}}` - Full blocked URL
- `{{.Host}}` - Hostname
- `{{.Path}}` - URL path
- `{{.Reason}}` - Block reason
- `{{.Timestamp}}` - RFC1123 timestamp

### `Config` (config.go)
Configuration loading via [viper](https://github.com/spf13/viper):
- `LoadConfig(path)` - Load from file/env/defaults
- `LoadConfigFromReader(type, data)` - Load from bytes
- `DefaultConfig()` - Sensible defaults
- `WriteExampleConfig(path)` - Generate example YAML

**Config Struct Fields:**
- `Server` - Addr, timeouts
- `TLS` - CA cert/key paths, organization, validity
- `Filter` - Enabled, domains, urls, regex, rules, sources, reload interval
- `BlockPage` - Enabled, redirect URL, template path
- `Logging` - Level, format, output

**Methods:**
- `cfg.BuildRuleSet()` - Create `*RuleSet` from config
- `cfg.BuildRuleLoader()` - Create `RuleLoader` from config

**Environment Variables:**
Config values can be overridden via `SWG_` prefixed env vars:
- `SWG_SERVER_ADDR=:9090`
- `SWG_TLS_ORGANIZATION=MyOrg`
- `SWG_FILTER_ENABLED=false`

## Rule Types

| Type | Pattern Example | Description |
|------|-----------------|-------------|
| `domain` | `blocked.com` | Exact domain match |
| `domain` | `*.ads.com` | Wildcard subdomain match |
| `url` | `https://evil.com/path` | URL prefix match |
| `regex` | `.*tracking.*` | Regex pattern on full URL |

## CSV Format

```csv
type,pattern,reason,category
domain,ads.example.com,advertising,ads
domain,*.tracking.com,user tracking,analytics
url,https://phishing.com/login,phishing attempt,security
regex,.*\.doubleclick\.net.*,ad tracker,ads
```

## CLI Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-addr` | `:8080` | Proxy listen address |
| `-ca-cert` | `ca.crt` | Path to CA certificate |
| `-ca-key` | `ca.key` | Path to CA private key |
| `-config` | (none) | Path to config file |
| `-gen-config` | false | Generate example config and exit |
| `-block` | (none) | Comma-separated domains to block |
| `-block-page-url` | (none) | URL to redirect blocked requests |
| `-block-page-file` | (none) | Path to custom block page template |
| `-gen-ca` | false | Generate new CA and exit |
| `-ca-org` | `SWG Proxy` | Organization for generated CA |
| `-print-block-page` | false | Print default block page template |
| `-gen-pac` | (none) | Generate PAC file at path and exit |
| `-pac-bypass` | (none) | Comma-separated domains to bypass in PAC |
| `-metrics` | false | Enable Prometheus /metrics endpoint |
| `-v` | false | Verbose (debug) logging |

## Testing Patterns

Tests use table-driven patterns and subtests:

```go
tests := []struct {
    name string
    // ... test case fields
}{
    {"case 1", ...},
    {"case 2", ...},
}

for _, tt := range tests {
    t.Run(tt.name, func(t *testing.T) {
        // test logic
    })
}
```

Integration tests create real TCP listeners and test the full proxy flow.

## Conventions

- **Module path**: `github.com/acmacalister/swg`
- **Go version**: 1.25.3
- **Logging**: Uses `log/slog` structured logging
- **Error handling**: Wrap errors with `fmt.Errorf("context: %w", err)`
- **Tab indentation**: Standard Go formatting (use `go fmt`)
- **Interfaces**: Keep interfaces small (single method preferred)

## Examples

See `_examples/` directory:
- `csv/` - Loading blocklist from CSV file with auto-reload
- `config/` - Using viper config file with auto-reload
- `postgres/` - Loading blocklist from PostgreSQL using sqlx

## Kubernetes Deployment

See `deploy/` directory:
- `kubernetes/` - Raw manifests (namespace, configmap, secret, deployment, service)
- `helm/swg/` - Helm chart with values.yaml customization

**Note:** GoReleaser does NOT support Helm charts natively. Use [chart-releaser-action](https://github.com/helm/chart-releaser-action) separately.

## Release Process

1. Tag the release: `git tag v1.0.0`
2. Push tag: `git push origin v1.0.0`
3. GoReleaser builds binaries for Linux/macOS/Windows (amd64/arm64)
4. Creates packages: `.deb`, `.rpm`, `.apk`, `.pkg.tar.zst`
5. Publishes to:
   - GitHub Releases
   - Homebrew tap (`acmacalister/homebrew-tap`)
   - Docker (`ghcr.io/acmacalister/swg`)
   - AUR (`swg-bin`)

## Development Notes

- Linter warnings about unchecked error returns on `Close()` calls are acceptable
- The proxy handles both HTTP (plain) and HTTPS (CONNECT) requests
- Certificate caching is thread-safe using `sync.RWMutex`
- RuleSet uses maps for O(1) domain lookups, linear scan for wildcards/regex
- ReloadableFilter swaps entire RuleSet atomically on reload

## Security Considerations

- CA private key must be protected - grants traffic interception capability
- Generated host certificates are cached in memory only
- No persistent storage of intercepted data
- Certificate pinning in clients will cause failures (expected)
