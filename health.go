package swg

import (
	"encoding/json"
	"net/http"
	"sync/atomic"
	"time"
)

// HealthChecker provides liveness and readiness probes for the proxy.
// It tracks whether the proxy has started successfully and can optionally
// run custom readiness checks (e.g., verifying filter rules are loaded).
type HealthChecker struct {
	alive atomic.Bool
	ready atomic.Bool

	startTime time.Time

	// ReadinessChecks are optional functions that must all return nil
	// for the readiness probe to pass. If empty, readiness follows liveness.
	ReadinessChecks []ReadinessCheck
}

// ReadinessCheck is a function that returns nil if the component is ready,
// or an error describing why it is not.
type ReadinessCheck func() error

// HealthResponse is the JSON body returned by health endpoints.
type HealthResponse struct {
	Status  string `json:"status"`
	Uptime  string `json:"uptime,omitempty"`
	Reason  string `json:"reason,omitempty"`
	Details []string `json:"details,omitempty"`
}

// NewHealthChecker creates a new HealthChecker.
func NewHealthChecker() *HealthChecker {
	return &HealthChecker{
		startTime: time.Now(),
	}
}

// SetAlive marks the proxy as alive (liveness probe passes).
func (h *HealthChecker) SetAlive(alive bool) {
	h.alive.Store(alive)
}

// SetReady marks the proxy as ready (readiness probe passes).
func (h *HealthChecker) SetReady(ready bool) {
	h.ready.Store(ready)
}

// IsAlive returns true if the proxy is alive.
func (h *HealthChecker) IsAlive() bool {
	return h.alive.Load()
}

// IsReady returns true if the proxy is ready to serve traffic.
// If ReadinessChecks are configured, all must pass. Otherwise, readiness
// follows the explicitly set ready state.
func (h *HealthChecker) IsReady() bool {
	if !h.ready.Load() {
		return false
	}

	for _, check := range h.ReadinessChecks {
		if err := check(); err != nil {
			return false
		}
	}

	return true
}

// HandleHealthz handles the /healthz liveness probe endpoint.
func (h *HealthChecker) HandleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	resp := HealthResponse{
		Uptime: time.Since(h.startTime).Truncate(time.Second).String(),
	}

	if h.IsAlive() {
		resp.Status = "ok"
		w.WriteHeader(http.StatusOK)
	} else {
		resp.Status = "unavailable"
		w.WriteHeader(http.StatusServiceUnavailable)
	}

	_ = json.NewEncoder(w).Encode(resp)
}

// HandleReadyz handles the /readyz readiness probe endpoint.
func (h *HealthChecker) HandleReadyz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	resp := HealthResponse{
		Uptime: time.Since(h.startTime).Truncate(time.Second).String(),
	}

	if !h.ready.Load() {
		resp.Status = "not ready"
		resp.Reason = "proxy not yet ready"
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(resp)
		return
	}

	var failures []string
	for _, check := range h.ReadinessChecks {
		if err := check(); err != nil {
			failures = append(failures, err.Error())
		}
	}

	if len(failures) > 0 {
		resp.Status = "not ready"
		resp.Details = failures
		w.WriteHeader(http.StatusServiceUnavailable)
	} else {
		resp.Status = "ok"
		w.WriteHeader(http.StatusOK)
	}

	_ = json.NewEncoder(w).Encode(resp)
}
