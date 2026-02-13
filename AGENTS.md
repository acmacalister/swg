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
├── swg.go              # Package declaration
├── doc.go              # Package documentation
├── certs.go            # CA and certificate management
├── certs_test.go       # Tests for certificate functions
├── proxy.go            # HTTPS MITM proxy implementation
├── proxy_test.go       # Tests for proxy functions
├── filter.go           # Rule-based filtering system (RuleSet, loaders)
├── filter_test.go      # Tests for filter functions
├── health.go           # Health check endpoints (/healthz, /readyz)
├── health_test.go      # Tests for health check functions
├── accesslog.go        # Structured access log with slog
├── accesslog_test.go   # Tests for access log functions
├── reload.go           # SIGHUP signal reload support
├── metrics.go          # Prometheus metrics instrumentation
├── metrics_test.go     # Tests for metrics functions
├── pac.go              # PAC file generator
├── pac_test.go         # Tests for PAC functions
├── blockpage.go        # Custom block page templates
├── blockpage_test.go   # Tests for block page functions
├── upstream.go         # Upstream proxy chaining + PROXY protocol v1/v2
├── upstream_test.go    # Tests for upstream proxy functions
├── connpool.go         # Connection pooling & HTTP/2 transport
├── connpool_test.go    # Tests for connection pool functions
├── ratelimit.go        # Per-client token-bucket rate limiter
├── ratelimit_test.go   # Tests for rate limiter functions
├── certrotate.go       # Graceful CA certificate rotation
├── certrotate_test.go  # Tests for cert rotation functions
├── policy.go           # Policy engine, lifecycle hooks, identity, scanning
├── policy_test.go      # Tests for policy engine functions
├── admin.go            # Admin REST API (chi router) for runtime management
├── admin_test.go       # Tests for admin API functions
├── mtls.go             # mTLS client certificate authentication
├── mtls_test.go        # Tests for mTLS functions
├── bypass.go           # Bypass header/token for authorized filter skipping
├── bypass_test.go      # Tests for bypass functions
├── acme.go             # ACME/Let's Encrypt certificate management (lego)
├── acme_test.go        # Tests for ACME functions
├── config.go           # Viper-based configuration loading
├── config_test.go      # Tests for config functions
├── .goreleaser.yaml    # GoReleaser configuration
├── Dockerfile          # Container image definition
├── README.md           # User documentation
├── FEATURES.md         # Feature roadmap and status
├── _examples/          # Example implementations
│   ├── csv/            # CSV-based blocklist example
│   ├── config/         # Config file example
│   ├── postgres/       # PostgreSQL blocklist example
│   ├── policy/         # Policy engine with identity, groups, scanning
│   ├── allowlist/      # Allow-list mode with time-based rules
│   ├── scanner/        # Response body scanning (AV/DLP)
│   ├── admin/          # Admin API with runtime rule management
│   ├── mtls/           # mTLS client certificate authentication
│   ├── bypass/         # Bypass token for debugging
│   └── acme/           # ACME/Let's Encrypt certificates
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

### `ACMECertManager` (acme.go)
ACME/Let's Encrypt certificate management using [lego](https://github.com/go-acme/lego):
- `NewACMECertManager(cfg)` - Create from ACMEConfig
- `Initialize(ctx)` - Set up ACME client and register account
- `ObtainCertificates(ctx)` - Obtain certificates for configured domains
- `GetCertificate(hello)` - For `tls.Config.GetCertificate`
- `GetCertificateForHost(host)` - Get certificate for hostname
- `StartAutoRenewal(interval)` - Background renewal goroutine
- `Close()` - Stop background renewal
- `CacheSize()` - Number of cached certificates

**ACMEConfig Fields:**
- `Email` - ACME account email (required, for expiration warnings)
- `Domains` - Domains to obtain certificates for (required)
- `AcceptTOS` - Accept CA Terms of Service (required, must be true)
- `CA` - ACME CA directory URL (default: Let's Encrypt production)
- `KeyType` - Key type: ec256, ec384, rsa2048, rsa4096, rsa8192 (default: ec256)
- `StoragePath` - Certificate storage directory (default: ./acme)
- `HTTPPort` - HTTP-01 challenge port (default: 80, 0 to disable)
- `TLSPort` - TLS-ALPN-01 challenge port (default: 443, 0 to disable)
- `RenewBefore` - Renew this long before expiration (default: 30 days)
- `EABKeyID` / `EABMACKey` - External Account Binding (optional, for ZeroSSL)

**Callbacks:**
- `OnCertObtained func(domain string)` - Called when certificate obtained
- `OnCertRenewed func(domain string)` - Called when certificate renewed
- `OnError func(domain string, err error)` - Called on errors

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
- `HealthChecker` - `*HealthChecker` serves `/healthz` and `/readyz` (optional)
- `AccessLog` - `*AccessLogger` structured access log (optional)
- `UpstreamProxy` - `*UpstreamProxy` parent proxy chaining (optional)
- `RateLimiter` - `*RateLimiter` per-client request throttling (optional)
- `TransportPool` - `*TransportPool` connection-pooled HTTP/2 transport (optional)
- `Policy` - `*PolicyEngine` lifecycle hooks, identity, and body scanning (optional)
- `Admin` - `*AdminAPI` REST endpoints for runtime rule management (optional)
- `ClientAuth` - `*ClientAuth` mTLS client certificate authentication (optional)
- `Bypass` - `*Bypass` allows authorized clients to skip filtering (optional)
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
- `RemoveRule(type, pattern)` - Remove first matching rule by type and pattern
- `Rules()` - Returns a snapshot of all rules as `[]Rule`
- `Count()` - Returns total number of rules
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
- `RuleSet()` - Returns the underlying `*RuleSet` for direct rule manipulation
- `Load(ctx)` - Load/reload rules from source
- `StartAutoReload(ctx, interval)` - Background reload goroutine
- `OnReload` - Callback after successful reload
- `OnError` - Callback on reload error

### `AdminAPI` (admin.go)
REST API for runtime proxy management using [chi](https://github.com/go-chi/chi) router:
- `NewAdminAPI(proxy)` - Create admin API wired to a proxy
- `Handler()` - Returns `http.Handler` with path prefix stripped
- `ServeHTTP(w, r)` - Implements `http.Handler`

**Fields:**
- `Proxy` - The proxy instance to manage
- `Logger` - `*slog.Logger` for admin API events
- `PathPrefix` - URL path prefix (default `/api`)
- `ReloadFunc` - Called on `POST /reload`; if nil, returns 501

**Endpoints (under PathPrefix):**
- `GET /status` - Proxy status, rule count, uptime, filter type
- `GET /rules` - List all active rules
- `POST /rules` - Add a rule (JSON body: type, pattern, reason, category)
- `DELETE /rules` - Remove a rule (JSON body: type, pattern)
- `POST /reload` - Trigger filter reload via ReloadFunc

**Response types:** `StatusResponse`, `RulesResponse`, `RuleRequest`, `ErrorResponse`, `MessageResponse`

### `ClientAuth` (mtls.go)
mTLS client certificate authentication at the proxy listener level:
- `NewClientAuth(pool)` - Create with existing cert pool
- `NewClientAuthFromPEM(pemData)` - Create from PEM-encoded CA certificates
- `NewClientAuthFromFile(path)` - Load CA from PEM file
- `SetPolicy(policy)` / `Policy()` - Get/set client auth policy (thread-safe)
- `AddCACert(cert)` - Add CA certificate to pool
- `AddCAPEM(pemData)` - Append PEM certificates to pool
- `TLSConfig()` - Returns `*tls.Config` with client auth settings
- `WrapListener(inner, serverCert)` - Wrap TCP listener with TLS + mTLS
- `VerifyPeerCertificate(rawCerts, _)` - Manual peer certificate verification
- `IdentityFromConn(conn)` - Extract CN (identity) and Organization (groups) from peer cert
- `GenerateClientCert(caCert, caKeyPEM, cn, orgs, validYears)` - Generate signed client certificate

**Fields:**
- `IdentityFromCert` - Map cert subject to RequestContext identity/groups (default: true)

### `Bypass` (bypass.go)
Allows authorized clients to skip content filtering via header token or identity:
- `NewBypass()` - Create with default header and no tokens
- `AddToken(token)` - Register a bypass token (thread-safe)
- `RemoveToken(token)` - Revoke a bypass token (thread-safe)
- `RevokeAll()` - Remove all bypass tokens (thread-safe)
- `TokenCount()` - Number of registered tokens
- `GenerateToken()` - Generate cryptographically random 32-byte hex token
- `ShouldBypass(req)` - Check header token or identity for bypass

**Fields:**
- `Header` - HTTP header name (default `X-SWG-Bypass`)
- `Identities` - Set of identity values granted bypass
- `Logger` - `*slog.Logger` for bypass events

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

### `HealthChecker` (health.go)
- `NewHealthChecker()` - Create health checker with start time
- `SetAlive(bool)` - Mark proxy as alive/not alive
- `SetReady(bool)` - Mark proxy as ready/not ready
- `IsAlive()` / `IsReady()` - Check liveness/readiness
- `HandleHealthz(w, r)` - HTTP handler for `/healthz`
- `HandleReadyz(w, r)` - HTTP handler for `/readyz`
- `ReadinessChecks []ReadinessCheck` - Pluggable readiness checks

### `AccessLogger` (accesslog.go)
- `NewAccessLogger(logger)` - Create access logger wrapping `*slog.Logger`
- `Log(entry)` - Write an `AccessLogEntry` using `slog.LogAttrs`

**`AccessLogEntry` Fields:**
- `Timestamp`, `Method`, `Host`, `Path`, `Scheme`
- `StatusCode`, `Duration`, `BytesWritten`
- `ClientAddr`, `Blocked`, `BlockReason`
- `Error`, `UserAgent`

### `SIGHUPReloader` (reload.go)
- `WatchSIGHUP(proxy, reloadFunc, logger)` - Start goroutine watching SIGHUP
- `Cancel()` - Stop the watcher
- `ReloadFunc` - Callback `func(ctx) (Filter, error)` called on each SIGHUP

### `UpstreamProxy` (upstream.go)
Upstream proxy chaining with PROXY protocol v1/v2 support:
- `NewUpstreamProxy(rawURL)` - Create from URL string (extracts auth from userinfo)
- `DialConnect(ctx, network, addr, clientAddr)` - CONNECT tunnel through upstream proxy
- `Transport(base)` - Returns `http.RoundTripper` for plain HTTP forwarding
- `ProxyProtocol` field: 0=disabled, 1=v1 (text), 2=v2 (binary)
- `writeProxyProtocolV1()` / `writeProxyProtocolV2()` - PROXY protocol header writers
- `bufferedConn` - Wraps `net.Conn` with leftover data from CONNECT handshake

### `TransportPool` (connpool.go)
Connection pooling & HTTP/2 transport:
- `NewTransportPool()` - Create with sensible proxy defaults (200 idle conns, HTTP/2 enabled)
- `Build()` - Create underlying `http.Transport` from config fields
- `Transport()` - Returns stats-tracking `http.RoundTripper` (auto-builds if needed)
- `CloseIdleConnections()` - Close idle connections in the pool
- `Stats()` - Returns `TransportPoolStats` (TotalRequests, ActiveRequests)

**Key Fields:**
- `MaxIdleConns`, `MaxIdleConnsPerHost`, `MaxConnsPerHost` - Pool sizing
- `IdleConnTimeout`, `DialTimeout`, `TLSHandshakeTimeout` - Timeouts
- `EnableHTTP2` - HTTP/2 via ALPN negotiation
- `TLSConfig` - Custom TLS settings
- `DisableKeepAlives` - Force fresh connections

### `RateLimiter` (ratelimit.go)
Per-client token-bucket rate limiter:
- `NewRateLimiter(rate, burst)` - Create with background cleanup goroutine
- `Allow(addr)` - Check if request from client IP is allowed
- `AllowHTTP(w, r)` - HTTP handler wrapper, writes 429 with `Retry-After: 1` if denied
- `Close()` - Stop cleanup goroutine (idempotent)
- `ClientCount()` - Number of tracked clients
- `CleanupInterval` - How often stale buckets are removed (default 1 minute)

### `CertRotator` (certrotate.go)
Graceful CA certificate rotation:
- `NewCertRotator(cm, certPath, keyPath)` - Wrap existing CertManager
- `Rotate()` - Reload CA from disk, swap CertManager atomically
- `RotateFromPEM(certPEM, keyPEM)` - Rotate from in-memory PEM
- `GetCertificate(hello)` / `GetCertificateForHost(host)` - Thread-safe delegation
- `WatchCAFiles(interval)` - Poll file mtimes, auto-rotate on change
- `OnRotate` / `OnError` - Callbacks for rotation events
- `CACert()`, `CAKey()`, `CacheSize()` - Thread-safe accessors

### `PolicyEngine` (policy.go)
Request/response lifecycle hooks with identity resolution and body scanning:
- `NewPolicyEngine()` - Create with defaults (10 MiB max scan size)
- `ProcessRequest(ctx, req)` - Resolve identity, run request hooks
- `ProcessResponse(ctx, req, resp, rc)` - Run response hooks, then body scanners

**Fields:**
- `RequestHooks []RequestHook` - Pre-filter hooks (identity, access control, tagging)
- `ResponseHooks []ResponseHook` - Post-upstream hooks (content-type filtering)
- `IdentityResolver` - Resolves client identity from request
- `BodyScanners []ResponseBodyScanner` - AV/DLP content inspection
- `ScanContentTypes []string` - Limit scanning to these MIME prefixes (empty = all)
- `MaxScanSize int64` - Max bytes to buffer for scanning (default 10 MiB)

**Interfaces:**
- `RequestHook` / `RequestHookFunc` - `HandleRequest(ctx, req, rc) *http.Response`
- `ResponseHook` / `ResponseHookFunc` - `HandleResponse(ctx, req, resp, rc) *http.Response`
- `IdentityResolver` / `IdentityResolverFunc` - `Resolve(req) (identity, groups, error)`
- `ResponseBodyScanner` / `ResponseBodyScannerFunc` - `Scan(ctx, body, req, resp) (ScanResult, error)`

**Built-in implementations:**
- `IPIdentityResolver` - Maps IPs/CIDRs to identity/groups (`AddIP`, `AddCIDR`, `Resolve`)
- `AllowListFilter` - Deny-by-default filter (`AddDomain`, `AddDomains`, `ShouldBlock`)
- `TimeRule` - Time-windowed filter wrapper (`StartHour`, `EndHour`, `Weekdays`, `Location`)
- `GroupPolicyFilter` - Per-group filter dispatch (`SetPolicy`, `Default`)
- `ContentTypeFilter` - Block responses by MIME type (`Block`, `HandleResponse`)
- `ChainFilter` - Compose multiple filters (`Filters []Filter`, first block wins)
- `RequestContext` - Carries identity, groups, tags through `context.Context`
- `ScanVerdict` - `VerdictAllow`, `VerdictBlock`, `VerdictReplace`
- `ScanResult` - Verdict + optional replacement body and content-type

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
| `-access-log` | (none) | Access log output: stdout, stderr, or file path |
| `-healthz` | false | Enable /healthz and /readyz health endpoints |
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
- `policy/` - Full policy engine: identity resolution, group policies, content-type blocking, body scanning
- `allowlist/` - Allow-list mode with time-based rules and ChainFilter composition
- `scanner/` - Response body scanning with AV and DLP scanner implementations

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
