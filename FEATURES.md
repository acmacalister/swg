# Feature Roadmap

Planned features for `swg`. Items marked with ✅ are complete.

---

## In Progress

### PAC File Generator
Generate [Proxy Auto-Configuration](https://developer.mozilla.org/en-US/docs/Web/HTTP/Proxy_servers_and_tunneling/Proxy_Auto-Configuration_PAC_file) files for pointing clients at the proxy.

- Serve a `/proxy.pac` endpoint from the proxy itself
- Write PAC files to disk via CLI (`-gen-pac`)
- Configurable bypass list for internal/trusted domains (e.g. `*.local`, `10.0.0.0/8`)
- Support direct-connect fallback when proxy is unreachable

### Prometheus Metrics
Expose a `/metrics` endpoint for Prometheus scraping.

- Request counts (total, blocked, allowed) by domain/category
- Request latency histograms
- Block rate by filter rule type
- Certificate cache size and hit ratio
- Upstream connection errors
- Active connection gauge
- Filter reload counts and last-reload timestamp

---

## Planned

### Client Configuration
- **mTLS client auth** — require client certificates to use the proxy, limiting access to managed devices

### Observability
- **Structured access log** — JSON access log (separate from operational logs) with request/response metadata, timing, and filter decisions
- **Health check endpoints** — `/healthz` and `/readyz` for load balancers and Kubernetes probes

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
- **SIGHUP reload** — reload config and rules on signal
- **Bypass header/token** — allow authorized clients to skip filtering for debugging
