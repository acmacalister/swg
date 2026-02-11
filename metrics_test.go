package swg

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNewMetrics(t *testing.T) {
	m := NewMetrics()
	if m == nil {
		t.Fatal("NewMetrics() returned nil")
	}
	if m.registry == nil {
		t.Fatal("registry should not be nil")
	}
}

func TestMetrics_RecordRequest(t *testing.T) {
	m := NewMetrics()
	m.RecordRequest("GET", "https")
	m.RecordRequest("POST", "http")
	m.RecordRequest("GET", "https")
}

func TestMetrics_RecordBlocked(t *testing.T) {
	m := NewMetrics()
	m.RecordBlocked("domain blocked")
	m.RecordBlocked("pattern blocked")
}

func TestMetrics_RecordRequestDuration(t *testing.T) {
	m := NewMetrics()
	m.RecordRequestDuration("GET", 200, 50*time.Millisecond)
	m.RecordRequestDuration("POST", 403, 10*time.Millisecond)
}

func TestMetrics_ActiveConns(t *testing.T) {
	m := NewMetrics()
	m.IncActiveConns()
	m.IncActiveConns()
	m.DecActiveConns()
}

func TestMetrics_CertCache(t *testing.T) {
	m := NewMetrics()
	m.SetCertCacheSize(42)
	m.RecordCertCacheHit()
	m.RecordCertCacheMiss()
}

func TestMetrics_FilterReload(t *testing.T) {
	m := NewMetrics()
	m.SetFilterRuleCount(100)
	m.RecordFilterReload()
	m.RecordFilterReloadError()
}

func TestMetrics_UpstreamErrors(t *testing.T) {
	m := NewMetrics()
	m.RecordUpstreamError("example.com")
	m.RecordTLSHandshakeError()
}

func TestMetrics_Handler(t *testing.T) {
	m := NewMetrics()
	m.RecordRequest("GET", "https")
	m.RecordBlocked("test reason")
	m.SetFilterRuleCount(5)
	m.RecordRequestDuration("GET", 200, 50*time.Millisecond)

	handler := m.Handler()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	body := rec.Body.String()

	checks := []string{
		"swg_requests_total",
		"swg_requests_blocked_total",
		"swg_filter_rule_count",
		"swg_active_connections",
		"swg_cert_cache_size",
		"swg_request_duration_seconds",
	}

	for _, check := range checks {
		if !strings.Contains(body, check) {
			t.Errorf("metrics output missing %q", check)
		}
	}
}
