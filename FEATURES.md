# Feature Roadmap

Planned features for `swg`. Items marked with ✅ are complete.

---

## Completed ✅

### PAC File Generator ✅
Generate [Proxy Auto-Configuration](https://developer.mozilla.org/en-US/docs/Web/HTTP/Proxy_servers_and_tunneling/Proxy_Auto-Configuration_PAC_file) files for pointing clients at the proxy.

- Serve a `/proxy.pac` endpoint from the proxy itself
- Write PAC files to disk via CLI (`-gen-pac`)
- Configurable bypass list for internal/trusted domains (e.g. `*.local`, `10.0.0.0/8`)
- Support direct-connect fallback when proxy is unreachable

### Prometheus Metrics ✅
Expose a `/metrics` endpoint for Prometheus scraping.

- Request counts (total, blocked, allowed) by domain/category
- Request latency histograms
- Block rate by filter rule type
- Certificate cache size and hit ratio
- Upstream connection errors
- Active connection gauge
- Filter reload counts and last-reload timestamp

### Health Check Endpoints ✅
Kubernetes-compatible health probes for load balancers and orchestrators.

- `/healthz` — liveness probe (is the process running?)
- `/readyz` — readiness probe (is the proxy ready to serve traffic?)
- JSON responses with status, uptime, and failure details
- Pluggable readiness checks via `ReadinessCheck` functions
- Enabled via `-healthz` CLI flag

### Structured Access Log ✅
JSON access log (separate from operational logs) with request/response metadata, timing, and filter decisions.

- Per-request log entries with method, host, path, scheme, status code, duration, bytes written
- Blocked request tracking with block reason
- Error logging for upstream failures
- Client address and User-Agent capture
- Configurable output: stdout, stderr, or file path via `-access-log` flag
- Uses `slog.LogAttrs` with pre-sized attribute slices for low-allocation logging

### SIGHUP Reload ✅
Reload config and filter rules without restarting the proxy.

- Send `SIGHUP` to reload config file and rebuild filter rules
- Works with both config-file filtering and `-block` domain filtering
- Logs reload success/failure with rule count
- Library API: `WatchSIGHUP(proxy, reloadFunc, logger)` with cancellation support

### Upstream Proxy Chaining ✅
Forward traffic through a parent proxy for enterprise network topologies.

- HTTP and HTTPS upstream proxy support via `NewUpstreamProxy(rawURL)`
- CONNECT tunnel for HTTPS traffic through upstream
- Basic authentication (inline in URL or via `UpstreamAuth`)
- TLS-to-upstream with configurable `tls.Config`
- PROXY protocol v1 (text) and v2 (binary) header injection to preserve original client addresses
- Transparent integration: set `Proxy.UpstreamProxy` and all traffic routes through the parent

### Connection Pooling ✅
Configurable HTTP transport pool with connection reuse and statistics.

- `TransportPool` with tunable idle connections, per-host limits, and timeouts
- HTTP/2 upstream support (enabled by default)
- Custom TLS configuration for upstream connections
- Connection statistics: total requests, active requests
- Automatic idle connection cleanup
- Thread-safe `Build()` rebuilds the underlying transport without restart

### Rate Limiting ✅
Per-client token-bucket rate limiter to prevent abuse.

- Configurable rate (requests/second) and burst size
- Per-client-IP tracking with automatic stale bucket cleanup
- HTTP-aware check: writes 429 with `Retry-After` header when throttled
- `ClientCount()` for monitoring tracked IPs
- Background goroutine cleans up inactive clients

### Certificate Rotation ✅
Hot-swap CA certificates at runtime without proxy restart.

- `CertRotator` wraps `CertManager` for atomic cert/key reload
- `Rotate()` reloads from disk, `RotateFromPEM()` from memory
- Flushes host certificate cache on rotation
- `WatchCAFiles(interval)` polls cert/key files for changes and auto-rotates
- `OnRotate` / `OnError` callbacks for monitoring
- Thread-safe: serves traffic continuously during rotation

### Policy Engine ✅
Lifecycle hooks for the full request/response pipeline with pluggable identity, group policies, and content inspection.

- **RequestHook** interface: inspect, modify, or block requests before filtering. Return a non-nil `*http.Response` to short-circuit the pipeline.
- **ResponseHook** interface: inspect or replace responses after upstream. Content-type filtering is a built-in ResponseHook.
- **IdentityResolver** interface: resolve client identity from requests. Built-in `IPIdentityResolver` maps IPs and CIDRs to identity/group pairs.
- **RequestContext**: carries identity, groups, tags, and block status through `context.Context` for all lifecycle stages.
- **PolicyEngine** orchestrator: composes identity resolution → request hooks → filtering → upstream → response hooks → body scanning.

### Allow-List Mode ✅
Deny-by-default filtering for kiosk and restricted environments.

- `AllowListFilter` blocks all domains not explicitly permitted
- Wildcard support: `*.example.com` allows all subdomains
- `AddDomain()` / `AddDomains()` for single and batch operations
- Custom block reason via `Reason` field
- Implements `Filter` interface — composable with `ChainFilter` and `TimeRule`

### Time-Based Rules ✅
Schedule filter activation by hour-of-day and day-of-week.

- `TimeRule` wraps any `Filter` and activates it only during the specified window
- `StartHour` / `EndHour` with midnight wrap support (e.g. 22–06)
- `Weekdays` filter: limit to specific days of the week
- `Location` for timezone-aware evaluation
- `NowFunc` for deterministic testing

### Per-User/Group Policies ✅
Apply different filters based on client identity.

- `GroupPolicyFilter` maps group names to `Filter` implementations
- Reads groups from `RequestContext` (populated by `IdentityResolver`)
- First matching group's policy applies
- `Default` filter for unrecognized users
- `IPIdentityResolver`: exact IP takes priority over CIDR range matches

### Content-Type Filtering ✅
Block responses by MIME type to prevent unwanted downloads.

- `ContentTypeFilter` implements `ResponseHook`
- `Block(prefix, reason)` for prefix-based matching (e.g. `"application/"` blocks all `application/*`)
- Runs before body scanners — rejects content without buffering
- Thread-safe: add rules at runtime

### Response Body Scanning ✅
Pluggable scanner interface for AV, DLP, keyword detection, and content sanitization.

- `ResponseBodyScanner` interface: receives `[]byte` body plus request/response context
- Three verdicts: `VerdictAllow` (pass through), `VerdictBlock` (403 with reason), `VerdictReplace` (substitute body)
- `ScanContentTypes` limits scanning to specific MIME type prefixes (empty = scan all)
- `MaxScanSize` (default 10 MiB): bodies exceeding this pass through without scanning
- Multiple scanners run in order; first block/replace wins
- Function adapter `ResponseBodyScannerFunc` for inline scanners

### Filter Composition ✅
Combine multiple filter strategies into a single pipeline.

- `ChainFilter` composes `[]Filter` — first block wins
- All filter types (`DomainFilter`, `RuleSet`, `AllowListFilter`, `TimeRule`, `GroupPolicyFilter`, `ReloadableFilter`) implement the same `Filter` interface
- Filters and policy hooks coexist: `PolicyEngine` runs first, then `Proxy.Filter`

### Admin API ✅
REST endpoints for runtime rule management via [chi](https://github.com/go-chi/chi) router.

- `GET /api/status` — proxy status, rule count, uptime, filter type
- `GET /api/rules` — list all active rules
- `POST /api/rules` — add a rule (domain, URL, or regex)
- `DELETE /api/rules` — remove a rule
- `POST /api/reload` — trigger filter reload via user-provided `ReloadFunc`
- Configurable path prefix (default `/api`)
- Supports `*RuleSet` and `*ReloadableFilter` for full CRUD; other filter types are read-only
- `RuleSet.RemoveRule()` and `RuleSet.Rules()` for programmatic rule management
- `ReloadableFilter.RuleSet()` exposes underlying rule set

### mTLS Client Authentication

Mutual TLS authentication at the proxy listener level, requiring client certificates to connect.

- `ClientAuth` struct manages CA pool and auth policy (thread-safe)
- Constructors: `NewClientAuth`, `NewClientAuthFromPEM`, `NewClientAuthFromFile`
- `WrapListener` wraps a TCP listener with TLS + client cert verification
- `IdentityFromConn` extracts CN (identity) and Organization (groups) from peer cert
- `GenerateClientCert` convenience function for creating signed client certificates
- Configurable policy: `RequireAndVerifyClientCert` (default) or `VerifyClientCertIfGiven` for optional mode
- Cert identity injected into `RequestContext` (CN → Identity, Orgs → Groups, tag `auth=mtls`)
- Integrates with `Proxy.ClientAuth` field for automatic listener wrapping and identity injection

### Bypass Header/Token

Allow authorized clients to skip content filtering for debugging and operational use.

- `Bypass` struct with configurable HTTP header name (default `X-SWG-Bypass`)
- Token-based bypass with constant-time comparison to prevent timing attacks
- Identity-based bypass via `RequestContext` (e.g. mTLS cert CN)
- `GenerateToken()` creates cryptographically random 32-byte hex tokens
- Thread-safe token management: `AddToken`, `RemoveToken`, `RevokeAll`
- Bypass header stripped from forwarded requests to prevent leaking to upstream
- Checked before `Filter.ShouldBlock` in both HTTPS (handleTLSConnection) and HTTP (handleHTTP) paths
- Integrates with `Proxy.Bypass` field

### ACME/Let's Encrypt Certificates ✅

Automatic certificate provisioning from Let's Encrypt using the ACME protocol via [lego](https://github.com/go-acme/lego).

- `ACMECertManager` for automatic certificate obtain and renewal
- Caddy-style configuration with email-based setup
- HTTP-01 and TLS-ALPN-01 challenge support
- Automatic renewal with configurable interval (default: 30 days before expiry)
- Persistent storage of certificates and account data
- External Account Binding (EAB) support for ZeroSSL and other CAs
- Staging environment support for testing without rate limits
- Key type selection: EC256, EC384, RSA2048, RSA4096, RSA8192
- Callbacks for certificate events: `OnCertObtained`, `OnCertRenewed`, `OnError`

### Response Compression ✅
On-the-fly compression for responses using modern algorithms.

- `CompressHandler` wraps `http.Handler` with transparent compression
- Gzip, Zstandard (zstd), and Brotli encoding support
- `Accept-Encoding` header negotiation with preference order: br > zstd > gzip
- Automatic content-type detection (compresses text/*, application/json, application/xml, etc.)
- Configurable minimum size threshold (default: 256 bytes)
- Adds `Vary: Accept-Encoding` header for cache correctness
- Skips already-encoded responses (Content-Encoding present)
- `CompressBytes(data, encoding)` utility for one-off compression
- Admin API includes chi's compression middleware

### Request Body Size Limits ✅
Restrict request body size to prevent abuse via large uploads.

- `BodyLimiter` enforces configurable max body size globally or per-path
- Returns 413 Payload Too Large when exceeded
- Streaming validation via wrapped `io.ReadCloser` (rejects during read)
- Optional Content-Length header check for early rejection
- Per-path limit overrides with `SetPathLimit(prefix, limit)`
- Configurable skip paths and methods (GET, HEAD, OPTIONS, TRACE skipped by default)
- Size constants: `KB`, `MB`, `GB` for convenience
- Integrates with `PolicyEngine` via `RequestHook` interface
- Standard `http.Handler` middleware via `Middleware()` or `LimitRequestBody()`

### Benchmarks ✅
Comprehensive performance benchmarks and load testing.

- `BenchmarkProxyHTTP` — plain HTTP throughput (~71µs/op)
- `BenchmarkProxyHTTPS` — HTTPS with cert generation
- `BenchmarkCertGeneration` — per-host certificate generation (~43ms new, ~6ns cached)
- `BenchmarkRuleSetMatch` — filter matching at scale (1K, 10K, 100K rules) — O(1) domain lookup (~40ns)
- `BenchmarkRateLimiter` — token bucket performance (~47ns/op single client)
- `BenchmarkConcurrentConnections` — parallel connection handling
- `BenchmarkCompress` — gzip/zstd/brotli throughput (gzip: 4GB/s, brotli: 292MB/s)
- `BenchmarkBodyLimiter` — request body size validation (~40ns path lookup)
- `BenchmarkTransportPool` — connection pool request handling
- Baseline comparisons: TLS handshake (~1.2ms), map lookup (~5ns), regex match (~2.9µs)

---

## Planned

### OpenTelemetry Tracing
Distributed tracing for request flows beyond Prometheus metrics.

- Trace context propagation (W3C Trace Context)
- Span creation for proxy lifecycle stages
- Integration with Jaeger, Zipkin, OTLP exporters
- Configurable sampling rates
- Request/response attribute capture

### DNS-01 ACME Challenge
DNS-based ACME challenge for environments without exposed ports 80/443.

- DNS provider integrations via `libdns` ecosystem
- Support for Cloudflare, Route53, Google Cloud DNS, DigitalOcean, etc.
- Wildcard certificate support (requires DNS-01)
- Configurable propagation timeout and polling interval

### HTTP/3 Listener
QUIC/HTTP3 support for the proxy's client-facing listener.

- Faster connection establishment (0-RTT)
- Better multiplexing without head-of-line blocking
- Connection migration for mobile clients
- Falls back to HTTP/2 for incompatible clients
- Note: MITM interception of HTTP/3 traffic not planned (falls back to HTTP/2)

### CEL Expression Matchers
Common Expression Language for advanced rule evaluation.

- Powerful boolean expressions beyond regex
- Access to request headers, path, method, client IP, identity
- Examples: `request.header["X-Custom"] == "value" && request.path.startsWith("/api")`
- Composable with existing filter types
- Precompiled expressions for performance
