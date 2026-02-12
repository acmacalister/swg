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

---

## Planned

### Client Configuration
- **mTLS client auth** — require client certificates to use the proxy, limiting access to managed devices

### Operational
- **Bypass header/token** — allow authorized clients to skip filtering for debugging
