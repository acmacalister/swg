package swg

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestNewBlockPage(t *testing.T) {
	bp := NewBlockPage()
	if bp == nil {
		t.Fatal("NewBlockPage returned nil")
	}
	if bp.template == nil {
		t.Fatal("template is nil")
	}
}

func TestNewBlockPageFromTemplate(t *testing.T) {
	tmpl := `<html><body>{{.URL}} blocked: {{.Reason}}</body></html>`
	bp, err := NewBlockPageFromTemplate(tmpl)
	if err != nil {
		t.Fatalf("NewBlockPageFromTemplate failed: %v", err)
	}
	if bp == nil {
		t.Fatal("returned nil")
	}

	data := BlockPageData{URL: "https://example.com", Reason: "test"}
	result, err := bp.RenderString(data)
	if err != nil {
		t.Fatalf("RenderString failed: %v", err)
	}

	if !strings.Contains(result, "https://example.com") {
		t.Error("missing URL in output")
	}
	if !strings.Contains(result, "test") {
		t.Error("missing reason in output")
	}
}

func TestNewBlockPageFromTemplate_Invalid(t *testing.T) {
	_, err := NewBlockPageFromTemplate("{{.Invalid")
	if err == nil {
		t.Error("expected error for invalid template")
	}
}

func TestBlockPage_Render(t *testing.T) {
	bp := NewBlockPage()
	data := BlockPageData{
		URL:       "https://blocked.example.com/path",
		Host:      "blocked.example.com",
		Path:      "/path",
		Reason:    "domain blocked",
		Timestamp: "Mon, 01 Jan 2024 12:00:00 UTC",
	}

	var sb strings.Builder
	err := bp.Render(&sb, data)
	if err != nil {
		t.Fatalf("Render failed: %v", err)
	}

	result := sb.String()

	// Check all data is present
	checks := []string{
		data.URL,
		data.Host,
		data.Reason,
		data.Timestamp,
		"Access Blocked",
		"<!DOCTYPE html>",
	}

	for _, check := range checks {
		if !strings.Contains(result, check) {
			t.Errorf("missing %q in output", check)
		}
	}
}

func TestBlockPage_RenderString(t *testing.T) {
	bp := NewBlockPage()
	data := BlockPageData{
		URL:    "https://test.com",
		Reason: "test reason",
	}

	result, err := bp.RenderString(data)
	if err != nil {
		t.Fatalf("RenderString failed: %v", err)
	}

	if !strings.Contains(result, "test.com") {
		t.Error("missing URL")
	}
	if !strings.Contains(result, "test reason") {
		t.Error("missing reason")
	}
}

func TestBlockPage_ServeHTTP(t *testing.T) {
	bp := NewBlockPage()

	req := httptest.NewRequest(http.MethodGet, "/blocked?url=https://evil.com&reason=malware&host=evil.com", nil)
	rec := httptest.NewRecorder()

	bp.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rec.Code)
	}

	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Errorf("unexpected content-type: %s", ct)
	}

	body := rec.Body.String()
	if !strings.Contains(body, "evil.com") {
		t.Error("missing URL in body")
	}
	if !strings.Contains(body, "malware") {
		t.Error("missing reason in body")
	}
}

func TestBlockPageData(t *testing.T) {
	data := BlockPageData{
		URL:       "https://example.com/page",
		Host:      "example.com",
		Path:      "/page",
		Reason:    "blocked",
		Timestamp: "now",
	}

	if data.URL != "https://example.com/page" {
		t.Error("URL mismatch")
	}
	if data.Host != "example.com" {
		t.Error("Host mismatch")
	}
	if data.Path != "/page" {
		t.Error("Path mismatch")
	}
	if data.Reason != "blocked" {
		t.Error("Reason mismatch")
	}
	if data.Timestamp != "now" {
		t.Error("Timestamp mismatch")
	}
}

func TestDefaultBlockPageHTML(t *testing.T) {
	if DefaultBlockPageHTML == "" {
		t.Error("DefaultBlockPageHTML is empty")
	}

	// Verify it's valid HTML
	if !strings.Contains(DefaultBlockPageHTML, "<!DOCTYPE html>") {
		t.Error("missing DOCTYPE")
	}
	if !strings.Contains(DefaultBlockPageHTML, "{{.URL}}") {
		t.Error("missing URL template variable")
	}
	if !strings.Contains(DefaultBlockPageHTML, "{{.Reason}}") {
		t.Error("missing Reason template variable")
	}
}

func BenchmarkBlockPage_RenderString(b *testing.B) {
	bp := NewBlockPage()
	data := BlockPageData{
		URL:       "https://blocked.example.com/path/to/resource",
		Host:      "blocked.example.com",
		Path:      "/path/to/resource",
		Reason:    "domain blocked",
		Timestamp: "Mon, 01 Jan 2024 12:00:00 UTC",
	}

	b.ResetTimer()
	for b.Loop() {
		_, _ = bp.RenderString(data)
	}
}

func TestNewBlockPageFromFile(t *testing.T) {
	tmplContent := `<html><body>Blocked: {{.URL}} - {{.Reason}}</body></html>`
	dir := t.TempDir()
	path := dir + "/block.html"

	if err := os.WriteFile(path, []byte(tmplContent), 0o644); err != nil {
		t.Fatalf("write template: %v", err)
	}

	bp, err := NewBlockPageFromFile(path)
	if err != nil {
		t.Fatalf("NewBlockPageFromFile failed: %v", err)
	}

	data := BlockPageData{URL: "https://evil.com", Reason: "malware"}
	result, err := bp.RenderString(data)
	if err != nil {
		t.Fatalf("RenderString failed: %v", err)
	}

	if !strings.Contains(result, "https://evil.com") {
		t.Error("missing URL in output")
	}
	if !strings.Contains(result, "malware") {
		t.Error("missing reason in output")
	}
}

func TestNewBlockPageFromFile_Error(t *testing.T) {
	_, err := NewBlockPageFromFile("/nonexistent/path/block.html")
	if err == nil {
		t.Error("expected error for missing file")
	}
}
