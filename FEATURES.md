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

---

## Planned

### Client Configuration
- **mTLS client auth** — require client certificates to use the proxy, limiting access to managed devices

### Filtering & Policy
- **Allow-list mode** — invert filtering to only permit explicitly allowed domains (kiosk/restricted environments)
- **Time-based rules** — block certain categories only during specific hours
- **Per-user/group policies** — tie rules to client IP ranges or proxy-auth credentials
- **Content-type filtering** — block responses by MIME type (e.g. block executable downloads)
- **Response body inspection** — scan response bodies for patterns (malware signatures, DLP keywords)

### Resilience & Performance
- **Upstream proxy chaining** — forward through a parent proxy for enterprise network topologies
- **Connection pooling & HTTP/2 upstream** — reuse connections to frequently-hit origins
- **Rate limiting** — per-client or per-domain request rate limits
- **Graceful certificate rotation** — reload CA cert/key without restart

### Operational
- **Admin API** — REST endpoints to add/remove rules, view stats, and trigger reloads at runtime
- **Bypass header/token** — allow authorized clients to skip filtering for debugging
