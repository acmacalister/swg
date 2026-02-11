package swg

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewPACGenerator(t *testing.T) {
	g := NewPACGenerator("proxy.local:8080")

	if g.ProxyAddr != "proxy.local:8080" {
		t.Errorf("ProxyAddr = %q, want %q", g.ProxyAddr, "proxy.local:8080")
	}
	if !g.FallbackDirect {
		t.Error("FallbackDirect should default to true")
	}
	if len(g.BypassDomains) == 0 {
		t.Error("BypassDomains should have defaults")
	}
	if len(g.BypassNetworks) == 0 {
		t.Error("BypassNetworks should have defaults")
	}
}

func TestPACGenerator_GenerateString(t *testing.T) {
	g := NewPACGenerator("proxy.local:8080")

	pac, err := g.GenerateString()
	if err != nil {
		t.Fatalf("GenerateString() error: %v", err)
	}

	if !strings.Contains(pac, "FindProxyForURL") {
		t.Error("PAC should contain FindProxyForURL function")
	}
	if !strings.Contains(pac, "proxy.local:8080") {
		t.Error("PAC should contain proxy address")
	}
	if !strings.Contains(pac, "PROXY proxy.local:8080; DIRECT") {
		t.Error("PAC should contain fallback DIRECT when FallbackDirect is true")
	}
	if !strings.Contains(pac, "isPlainHostName") {
		t.Error("PAC should check for plain hostnames")
	}
}

func TestPACGenerator_NoFallback(t *testing.T) {
	g := NewPACGenerator("proxy.local:8080")
	g.FallbackDirect = false

	pac, err := g.GenerateString()
	if err != nil {
		t.Fatalf("GenerateString() error: %v", err)
	}

	if strings.Contains(pac, "PROXY proxy.local:8080; DIRECT") {
		t.Error("PAC should NOT contain DIRECT fallback")
	}
	if !strings.Contains(pac, "PROXY proxy.local:8080") {
		t.Error("PAC should contain proxy address without DIRECT")
	}
}

func TestPACGenerator_BypassDomains(t *testing.T) {
	g := NewPACGenerator("proxy.local:8080")
	g.BypassDomains = []string{"internal.corp"}
	g.BypassNetworks = nil

	pac, err := g.GenerateString()
	if err != nil {
		t.Fatalf("GenerateString() error: %v", err)
	}

	if !strings.Contains(pac, `dnsDomainIs(host, "internal.corp")`) {
		t.Error("PAC should contain bypass domain check")
	}
}

func TestPACGenerator_BypassNetworks(t *testing.T) {
	g := NewPACGenerator("proxy.local:8080")
	g.BypassDomains = nil
	g.BypassNetworks = []string{"10.0.0.0/8", "192.168.0.0/16"}

	pac, err := g.GenerateString()
	if err != nil {
		t.Fatalf("GenerateString() error: %v", err)
	}

	if !strings.Contains(pac, `isInNet(host, "10.0.0.0", "255.0.0.0")`) {
		t.Error("PAC should contain 10.0.0.0/8 bypass")
	}
	if !strings.Contains(pac, `isInNet(host, "192.168.0.0", "255.255.0.0")`) {
		t.Error("PAC should contain 192.168.0.0/16 bypass")
	}
}

func TestPACGenerator_WriteFile(t *testing.T) {
	g := NewPACGenerator("proxy.local:8080")
	path := filepath.Join(t.TempDir(), "proxy.pac")

	if err := g.WriteFile(path); err != nil {
		t.Fatalf("WriteFile() error: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error: %v", err)
	}

	if !strings.Contains(string(data), "FindProxyForURL") {
		t.Error("written file should contain PAC function")
	}
}

func TestPACGenerator_ServeHTTP(t *testing.T) {
	g := NewPACGenerator("proxy.local:8080")

	req := httptest.NewRequest(http.MethodGet, "/proxy.pac", nil)
	rec := httptest.NewRecorder()

	g.ServeHTTP(rec, req)

	if ct := rec.Header().Get("Content-Type"); ct != "application/x-ns-proxy-autoconfig" {
		t.Errorf("Content-Type = %q, want %q", ct, "application/x-ns-proxy-autoconfig")
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "max-age=300" {
		t.Errorf("Cache-Control = %q, want %q", cc, "max-age=300")
	}
	if !strings.Contains(rec.Body.String(), "FindProxyForURL") {
		t.Error("response body should contain PAC function")
	}
}

func TestPACGenerator_AddBypassDomain(t *testing.T) {
	g := NewPACGenerator("proxy.local:8080")
	initial := len(g.BypassDomains)

	g.AddBypassDomain(".internal.corp")

	if len(g.BypassDomains) != initial+1 {
		t.Error("AddBypassDomain should append to bypass list")
	}
}

func TestPACGenerator_AddBypassNetwork(t *testing.T) {
	g := NewPACGenerator("proxy.local:8080")
	initial := len(g.BypassNetworks)

	g.AddBypassNetwork("172.20.0.0/16")

	if len(g.BypassNetworks) != initial+1 {
		t.Error("AddBypassNetwork should append to network list")
	}
}

func TestCIDRToMask(t *testing.T) {
	tests := []struct {
		prefix string
		want   string
	}{
		{"8", "255.0.0.0"},
		{"12", "255.240.0.0"},
		{"16", "255.255.0.0"},
		{"24", "255.255.255.0"},
		{"32", "255.255.255.255"},
		{"0", "0.0.0.0"},
		{"1", "128.0.0.0"},
		{"17", "255.255.128.0"},
		{"invalid", ""},
		{"-1", ""},
		{"33", ""},
	}

	for _, tt := range tests {
		t.Run(tt.prefix, func(t *testing.T) {
			got := cidrToMask(tt.prefix)
			if got != tt.want {
				t.Errorf("cidrToMask(%q) = %q, want %q", tt.prefix, got, tt.want)
			}
		})
	}
}
