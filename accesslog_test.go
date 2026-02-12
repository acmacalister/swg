package swg

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"testing"
	"time"
)

func TestAccessLogger_Log(t *testing.T) {
	tests := []struct {
		name  string
		entry AccessLogEntry
		check func(t *testing.T, m map[string]any)
	}{
		{
			name: "normal request",
			entry: AccessLogEntry{
				Timestamp:    time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC),
				Method:       "GET",
				Host:         "example.com",
				Path:         "/index.html",
				Scheme:       "https",
				StatusCode:   200,
				Duration:     150 * time.Millisecond,
				BytesWritten: 4096,
				ClientAddr:   "192.168.1.1:54321",
			},
			check: func(t *testing.T, m map[string]any) {
				if m["method"] != "GET" {
					t.Errorf("method = %v, want GET", m["method"])
				}
				if m["host"] != "example.com" {
					t.Errorf("host = %v, want example.com", m["host"])
				}
				if m["path"] != "/index.html" {
					t.Errorf("path = %v, want /index.html", m["path"])
				}
				if m["scheme"] != "https" {
					t.Errorf("scheme = %v, want https", m["scheme"])
				}
				if m["status"] != float64(200) {
					t.Errorf("status = %v, want 200", m["status"])
				}
				if m["bytes"] != float64(4096) {
					t.Errorf("bytes = %v, want 4096", m["bytes"])
				}
				if m["client"] != "192.168.1.1:54321" {
					t.Errorf("client = %v, want 192.168.1.1:54321", m["client"])
				}
				if _, ok := m["blocked"]; ok {
					t.Error("blocked should not be present for normal request")
				}
				if _, ok := m["error"]; ok {
					t.Error("error should not be present for normal request")
				}
			},
		},
		{
			name: "blocked request",
			entry: AccessLogEntry{
				Timestamp:   time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC),
				Method:      "GET",
				Host:        "blocked.com",
				Path:        "/",
				Scheme:      "https",
				Blocked:     true,
				BlockReason: "domain blocked",
				Duration:    1 * time.Millisecond,
				ClientAddr:  "10.0.0.1:12345",
			},
			check: func(t *testing.T, m map[string]any) {
				if m["blocked"] != true {
					t.Errorf("blocked = %v, want true", m["blocked"])
				}
				if m["block_reason"] != "domain blocked" {
					t.Errorf("block_reason = %v, want domain blocked", m["block_reason"])
				}
				if _, ok := m["status"]; ok {
					t.Error("status should not be present for blocked request")
				}
			},
		},
		{
			name: "error request",
			entry: AccessLogEntry{
				Timestamp:  time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC),
				Method:     "GET",
				Host:       "timeout.com",
				Path:       "/slow",
				Scheme:     "https",
				StatusCode: 502,
				Duration:   30 * time.Second,
				ClientAddr: "10.0.0.2:22222",
				Error:      "upstream timeout",
			},
			check: func(t *testing.T, m map[string]any) {
				if m["error"] != "upstream timeout" {
					t.Errorf("error = %v, want upstream timeout", m["error"])
				}
				if m["status"] != float64(502) {
					t.Errorf("status = %v, want 502", m["status"])
				}
			},
		},
		{
			name: "request with user agent",
			entry: AccessLogEntry{
				Timestamp:    time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC),
				Method:       "POST",
				Host:         "api.example.com",
				Path:         "/data",
				Scheme:       "https",
				StatusCode:   201,
				Duration:     50 * time.Millisecond,
				BytesWritten: 256,
				ClientAddr:   "10.0.0.3:33333",
				UserAgent:    "Mozilla/5.0",
			},
			check: func(t *testing.T, m map[string]any) {
				if m["user_agent"] != "Mozilla/5.0" {
					t.Errorf("user_agent = %v, want Mozilla/5.0", m["user_agent"])
				}
				if m["method"] != "POST" {
					t.Errorf("method = %v, want POST", m["method"])
				}
			},
		},
		{
			name: "empty user agent omitted",
			entry: AccessLogEntry{
				Timestamp:  time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC),
				Method:     "GET",
				Host:       "example.com",
				Path:       "/",
				Scheme:     "http",
				StatusCode: 200,
				Duration:   10 * time.Millisecond,
				ClientAddr: "10.0.0.4:44444",
			},
			check: func(t *testing.T, m map[string]any) {
				if _, ok := m["user_agent"]; ok {
					t.Error("user_agent should not be present when empty")
				}
				if m["scheme"] != "http" {
					t.Errorf("scheme = %v, want http", m["scheme"])
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			handler := slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})
			logger := slog.New(handler)
			al := NewAccessLogger(logger)

			al.Log(tt.entry)

			var m map[string]any
			if err := json.Unmarshal(buf.Bytes(), &m); err != nil {
				t.Fatalf("failed to parse JSON: %v\nraw: %s", err, buf.String())
			}

			if m["msg"] != "access" {
				t.Errorf("msg = %v, want access", m["msg"])
			}

			tt.check(t, m)
		})
	}
}

func TestNewAccessLogger(t *testing.T) {
	logger := slog.Default()
	al := NewAccessLogger(logger)
	if al == nil {
		t.Fatal("NewAccessLogger returned nil")
	}
	if al.logger != logger {
		t.Error("logger not set correctly")
	}
}

func BenchmarkAccessLogger_Log(b *testing.B) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})
	logger := slog.New(handler)
	al := NewAccessLogger(logger)

	entry := AccessLogEntry{
		Timestamp:    time.Now(),
		Method:       "GET",
		Host:         "example.com",
		Path:         "/index.html",
		Scheme:       "https",
		StatusCode:   200,
		Duration:     150 * time.Millisecond,
		BytesWritten: 4096,
		ClientAddr:   "192.168.1.1:54321",
		UserAgent:    "Mozilla/5.0",
	}

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		buf.Reset()
		al.Log(entry)
	}
}
