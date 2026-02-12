package swg

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHealthChecker_Liveness(t *testing.T) {
	h := NewHealthChecker()

	t.Run("not alive by default", func(t *testing.T) {
		if h.IsAlive() {
			t.Error("expected not alive by default")
		}
	})

	t.Run("alive after SetAlive", func(t *testing.T) {
		h.SetAlive(true)
		if !h.IsAlive() {
			t.Error("expected alive after SetAlive(true)")
		}
	})

	t.Run("not alive after SetAlive false", func(t *testing.T) {
		h.SetAlive(false)
		if h.IsAlive() {
			t.Error("expected not alive after SetAlive(false)")
		}
	})
}

func TestHealthChecker_Readiness(t *testing.T) {
	h := NewHealthChecker()

	t.Run("not ready by default", func(t *testing.T) {
		if h.IsReady() {
			t.Error("expected not ready by default")
		}
	})

	t.Run("ready after SetReady", func(t *testing.T) {
		h.SetReady(true)
		if !h.IsReady() {
			t.Error("expected ready after SetReady(true)")
		}
	})

	t.Run("not ready when check fails", func(t *testing.T) {
		h.SetReady(true)
		h.ReadinessChecks = []ReadinessCheck{
			func() error { return errors.New("filter not loaded") },
		}
		if h.IsReady() {
			t.Error("expected not ready when check fails")
		}
	})

	t.Run("ready when all checks pass", func(t *testing.T) {
		h.SetReady(true)
		h.ReadinessChecks = []ReadinessCheck{
			func() error { return nil },
			func() error { return nil },
		}
		if !h.IsReady() {
			t.Error("expected ready when all checks pass")
		}
	})

	t.Run("not ready when one check fails", func(t *testing.T) {
		h.SetReady(true)
		h.ReadinessChecks = []ReadinessCheck{
			func() error { return nil },
			func() error { return errors.New("db down") },
		}
		if h.IsReady() {
			t.Error("expected not ready when one check fails")
		}
	})
}

func TestHealthChecker_HandleHealthz(t *testing.T) {
	tests := []struct {
		name       string
		alive      bool
		wantStatus int
		wantBody   string
	}{
		{"alive", true, http.StatusOK, "ok"},
		{"not alive", false, http.StatusServiceUnavailable, "unavailable"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := NewHealthChecker()
			h.SetAlive(tt.alive)

			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "/healthz", nil)
			h.HandleHealthz(w, r)

			if w.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", w.Code, tt.wantStatus)
			}

			var resp HealthResponse
			if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if resp.Status != tt.wantBody {
				t.Errorf("status = %q, want %q", resp.Status, tt.wantBody)
			}
			if resp.Uptime == "" {
				t.Error("expected uptime in response")
			}
		})
	}
}

func TestHealthChecker_HandleReadyz(t *testing.T) {
	t.Run("ready no checks", func(t *testing.T) {
		h := NewHealthChecker()
		h.SetReady(true)

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/readyz", nil)
		h.HandleReadyz(w, r)

		if w.Code != http.StatusOK {
			t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
		}

		var resp HealthResponse
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if resp.Status != "ok" {
			t.Errorf("status = %q, want %q", resp.Status, "ok")
		}
	})

	t.Run("not ready explicitly", func(t *testing.T) {
		h := NewHealthChecker()

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/readyz", nil)
		h.HandleReadyz(w, r)

		if w.Code != http.StatusServiceUnavailable {
			t.Errorf("status = %d, want %d", w.Code, http.StatusServiceUnavailable)
		}

		var resp HealthResponse
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if resp.Reason != "proxy not yet ready" {
			t.Errorf("reason = %q, want 'proxy not yet ready'", resp.Reason)
		}
	})

	t.Run("not ready with failing checks", func(t *testing.T) {
		h := NewHealthChecker()
		h.SetReady(true)
		h.ReadinessChecks = []ReadinessCheck{
			func() error { return errors.New("rules not loaded") },
			func() error { return errors.New("upstream unreachable") },
		}

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/readyz", nil)
		h.HandleReadyz(w, r)

		if w.Code != http.StatusServiceUnavailable {
			t.Errorf("status = %d, want %d", w.Code, http.StatusServiceUnavailable)
		}

		var resp HealthResponse
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if len(resp.Details) != 2 {
			t.Errorf("details = %d items, want 2", len(resp.Details))
		}
	})

	t.Run("content type is json", func(t *testing.T) {
		h := NewHealthChecker()
		h.SetAlive(true)

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/healthz", nil)
		h.HandleHealthz(w, r)

		ct := w.Header().Get("Content-Type")
		if ct != "application/json" {
			t.Errorf("Content-Type = %q, want application/json", ct)
		}
	})
}
