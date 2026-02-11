package swg

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestRule(t *testing.T) {
	rule := Rule{
		Type:     "domain",
		Pattern:  "blocked.com",
		Reason:   "test reason",
		Category: "test",
	}

	if rule.Type != "domain" {
		t.Errorf("unexpected type: %s", rule.Type)
	}
	if rule.Pattern != "blocked.com" {
		t.Errorf("unexpected pattern: %s", rule.Pattern)
	}
	if rule.Reason != "test reason" {
		t.Errorf("unexpected reason: %s", rule.Reason)
	}
	if rule.Category != "test" {
		t.Errorf("unexpected category: %s", rule.Category)
	}
}

func TestNewRuleSet(t *testing.T) {
	rs := NewRuleSet()
	if rs == nil {
		t.Fatal("NewRuleSet returned nil")
	}
	if rs.domains == nil {
		t.Error("domains map is nil")
	}
	if rs.wildcardDomains == nil {
		t.Error("wildcardDomains map is nil")
	}
	if rs.Count() != 0 {
		t.Errorf("expected empty ruleset, got %d rules", rs.Count())
	}
}

func TestRuleSet_AddRule_Domain(t *testing.T) {
	rs := NewRuleSet()

	err := rs.AddRule(Rule{
		Type:    "domain",
		Pattern: "blocked.com",
		Reason:  "test",
	})
	if err != nil {
		t.Fatalf("AddRule failed: %v", err)
	}

	if rs.Count() != 1 {
		t.Errorf("expected 1 rule, got %d", rs.Count())
	}
}

func TestRuleSet_AddRule_WildcardDomain(t *testing.T) {
	rs := NewRuleSet()

	err := rs.AddRule(Rule{
		Type:    "domain",
		Pattern: "*.ads.com",
		Reason:  "ads",
	})
	if err != nil {
		t.Fatalf("AddRule failed: %v", err)
	}

	if rs.Count() != 1 {
		t.Errorf("expected 1 rule, got %d", rs.Count())
	}

	// Check it's stored as wildcard
	if len(rs.wildcardDomains) != 1 {
		t.Error("expected wildcard domain to be stored")
	}
}

func TestRuleSet_AddRule_URL(t *testing.T) {
	rs := NewRuleSet()

	err := rs.AddRule(Rule{
		Type:    "url",
		Pattern: "https://evil.com/malware",
		Reason:  "malware",
	})
	if err != nil {
		t.Fatalf("AddRule failed: %v", err)
	}

	if len(rs.urlPrefixes) != 1 {
		t.Error("expected URL prefix to be stored")
	}
}

func TestRuleSet_AddRule_Regex(t *testing.T) {
	rs := NewRuleSet()

	err := rs.AddRule(Rule{
		Type:    "regex",
		Pattern: `.*\.tracking\..*`,
		Reason:  "tracking",
	})
	if err != nil {
		t.Fatalf("AddRule failed: %v", err)
	}

	if len(rs.regexPatterns) != 1 {
		t.Error("expected regex pattern to be stored")
	}
}

func TestRuleSet_AddRule_InvalidRegex(t *testing.T) {
	rs := NewRuleSet()

	err := rs.AddRule(Rule{
		Type:    "regex",
		Pattern: `[invalid`,
		Reason:  "test",
	})
	if err == nil {
		t.Error("expected error for invalid regex")
	}
}

func TestRuleSet_AddRule_UnknownType(t *testing.T) {
	rs := NewRuleSet()

	err := rs.AddRule(Rule{
		Type:    "unknown",
		Pattern: "test",
		Reason:  "test",
	})
	if err == nil {
		t.Error("expected error for unknown type")
	}
}

func TestRuleSet_AddDomain(t *testing.T) {
	rs := NewRuleSet()
	rs.AddDomain("blocked.com")

	if rs.Count() != 1 {
		t.Errorf("expected 1 rule, got %d", rs.Count())
	}
}

func TestRuleSet_AddURL(t *testing.T) {
	rs := NewRuleSet()
	rs.AddURL("https://evil.com/path")

	if rs.Count() != 1 {
		t.Errorf("expected 1 rule, got %d", rs.Count())
	}
}

func TestRuleSet_AddRegex(t *testing.T) {
	rs := NewRuleSet()
	err := rs.AddRegex(`.*test.*`)

	if err != nil {
		t.Errorf("AddRegex failed: %v", err)
	}
	if rs.Count() != 1 {
		t.Errorf("expected 1 rule, got %d", rs.Count())
	}
}

func TestRuleSet_Match_Domain(t *testing.T) {
	rs := NewRuleSet()
	rs.AddDomain("blocked.com")

	tests := []struct {
		name    string
		host    string
		blocked bool
	}{
		{"exact match", "blocked.com", true},
		{"with port", "blocked.com:443", true},
		{"case insensitive", "BLOCKED.COM", true},
		{"subdomain not matched", "sub.blocked.com", false},
		{"different domain", "allowed.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &http.Request{Host: tt.host, URL: &url.URL{Path: "/"}}
			_, blocked := rs.Match(req)
			if blocked != tt.blocked {
				t.Errorf("Match(%q) = %v, want %v", tt.host, blocked, tt.blocked)
			}
		})
	}
}

func TestRuleSet_Match_WildcardDomain(t *testing.T) {
	rs := NewRuleSet()
	rs.AddDomain("*.ads.com")

	tests := []struct {
		name    string
		host    string
		blocked bool
	}{
		{"exact wildcard domain", "ads.com", true},
		{"subdomain", "tracker.ads.com", true},
		{"deep subdomain", "a.b.c.ads.com", true},
		{"different domain", "notads.com", false},
		{"similar domain", "myads.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &http.Request{Host: tt.host, URL: &url.URL{Path: "/"}}
			_, blocked := rs.Match(req)
			if blocked != tt.blocked {
				t.Errorf("Match(%q) = %v, want %v", tt.host, blocked, tt.blocked)
			}
		})
	}
}

func TestRuleSet_Match_URL(t *testing.T) {
	rs := NewRuleSet()
	rs.AddURL("http://evil.com/malware")

	tests := []struct {
		name    string
		host    string
		path    string
		blocked bool
	}{
		{"exact URL", "evil.com", "/malware", true},
		{"URL prefix", "evil.com", "/malware/payload.exe", true},
		{"different path", "evil.com", "/safe", false},
		{"different host", "good.com", "/malware", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &http.Request{
				Host: tt.host,
				URL:  &url.URL{Path: tt.path},
			}
			_, blocked := rs.Match(req)
			if blocked != tt.blocked {
				t.Errorf("Match(%s%s) = %v, want %v", tt.host, tt.path, blocked, tt.blocked)
			}
		})
	}
}

func TestRuleSet_Match_Regex(t *testing.T) {
	rs := NewRuleSet()
	_ = rs.AddRegex(`.*\.doubleclick\.net.*`)

	tests := []struct {
		name    string
		host    string
		blocked bool
	}{
		{"matching host", "ad.doubleclick.net", true},
		{"subdomain match", "tracker.ad.doubleclick.net", true},
		{"non-matching", "google.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &http.Request{Host: tt.host, URL: &url.URL{Path: "/"}}
			_, blocked := rs.Match(req)
			if blocked != tt.blocked {
				t.Errorf("Match(%q) = %v, want %v", tt.host, blocked, tt.blocked)
			}
		})
	}
}

func TestRuleSet_ShouldBlock(t *testing.T) {
	rs := NewRuleSet()
	_ = rs.AddRule(Rule{
		Type:     "domain",
		Pattern:  "blocked.com",
		Reason:   "test reason",
		Category: "test category",
	})

	req := &http.Request{Host: "blocked.com", URL: &url.URL{Path: "/"}}
	blocked, reason := rs.ShouldBlock(req)

	if !blocked {
		t.Error("expected request to be blocked")
	}
	if !strings.Contains(reason, "test reason") {
		t.Errorf("unexpected reason: %s", reason)
	}
	if !strings.Contains(reason, "test category") {
		t.Errorf("reason should contain category: %s", reason)
	}
}

func TestRuleSet_Clear(t *testing.T) {
	rs := NewRuleSet()
	rs.AddDomain("a.com")
	rs.AddDomain("*.b.com")
	rs.AddURL("http://c.com")
	_ = rs.AddRegex(`.*d\.com.*`)

	if rs.Count() != 4 {
		t.Errorf("expected 4 rules, got %d", rs.Count())
	}

	rs.Clear()

	if rs.Count() != 0 {
		t.Errorf("expected 0 rules after clear, got %d", rs.Count())
	}
}

func TestCSVLoader_LoadFromReader(t *testing.T) {
	csv := `type,pattern,reason,category
domain,blocked.com,test reason,test category
domain,*.ads.com,advertising,ads
url,https://evil.com/path,malware,security
regex,.*tracking.*,tracking,analytics`

	loader := &CSVLoader{
		HasHeader:     true,
		DefaultReason: "default",
	}

	rules, err := loader.LoadFromReader(context.Background(), strings.NewReader(csv))
	if err != nil {
		t.Fatalf("LoadFromReader failed: %v", err)
	}

	if len(rules) != 4 {
		t.Errorf("expected 4 rules, got %d", len(rules))
	}

	// Check first rule
	if rules[0].Type != "domain" || rules[0].Pattern != "blocked.com" {
		t.Errorf("unexpected first rule: %+v", rules[0])
	}
	if rules[0].Reason != "test reason" {
		t.Errorf("unexpected reason: %s", rules[0].Reason)
	}
	if rules[0].Category != "test category" {
		t.Errorf("unexpected category: %s", rules[0].Category)
	}
}

func TestCSVLoader_LoadFromReader_NoHeader(t *testing.T) {
	csv := `domain,blocked.com,reason,category`

	loader := &CSVLoader{
		HasHeader:     false,
		DefaultReason: "default",
	}

	rules, err := loader.LoadFromReader(context.Background(), strings.NewReader(csv))
	if err != nil {
		t.Fatalf("LoadFromReader failed: %v", err)
	}

	if len(rules) != 1 {
		t.Errorf("expected 1 rule, got %d", len(rules))
	}
}

func TestCSVLoader_LoadFromReader_DefaultValues(t *testing.T) {
	csv := `type,pattern
domain,blocked.com`

	loader := &CSVLoader{
		HasHeader:       true,
		DefaultReason:   "default reason",
		DefaultCategory: "default category",
	}

	rules, err := loader.LoadFromReader(context.Background(), strings.NewReader(csv))
	if err != nil {
		t.Fatalf("LoadFromReader failed: %v", err)
	}

	if rules[0].Reason != "default reason" {
		t.Errorf("expected default reason, got: %s", rules[0].Reason)
	}
	if rules[0].Category != "default category" {
		t.Errorf("expected default category, got: %s", rules[0].Category)
	}
}

func TestCSVLoader_LoadFromReader_InvalidType(t *testing.T) {
	csv := `type,pattern
invalid,test.com`

	loader := &CSVLoader{HasHeader: true}

	_, err := loader.LoadFromReader(context.Background(), strings.NewReader(csv))
	if err == nil {
		t.Error("expected error for invalid type")
	}
}

func TestCSVLoader_LoadFromReader_TooFewFields(t *testing.T) {
	csv := `type,pattern
domain`

	loader := &CSVLoader{HasHeader: true}

	_, err := loader.LoadFromReader(context.Background(), strings.NewReader(csv))
	if err == nil {
		t.Error("expected error for too few fields")
	}
}

func TestCSVLoader_LoadFromReader_EmptyFields(t *testing.T) {
	csv := `type,pattern
,blocked.com`

	loader := &CSVLoader{HasHeader: true}

	_, err := loader.LoadFromReader(context.Background(), strings.NewReader(csv))
	if err == nil {
		t.Error("expected error for empty type")
	}
}

func TestCSVLoader_LoadFromReader_ContextCanceled(t *testing.T) {
	csv := `type,pattern
domain,a.com
domain,b.com`

	loader := &CSVLoader{HasHeader: true}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := loader.LoadFromReader(ctx, strings.NewReader(csv))
	if err == nil {
		t.Error("expected error for canceled context")
	}
}

func TestNewCSVLoader(t *testing.T) {
	loader := NewCSVLoader("/path/to/file.csv")

	if loader.Path != "/path/to/file.csv" {
		t.Errorf("unexpected path: %s", loader.Path)
	}
	if !loader.HasHeader {
		t.Error("expected HasHeader to be true by default")
	}
	if loader.DefaultReason == "" {
		t.Error("expected default reason to be set")
	}
}

func TestStaticLoader(t *testing.T) {
	rules := []Rule{
		{Type: "domain", Pattern: "a.com"},
		{Type: "domain", Pattern: "b.com"},
	}

	loader := NewStaticLoader(rules...)
	loaded, err := loader.Load(context.Background())

	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if len(loaded) != 2 {
		t.Errorf("expected 2 rules, got %d", len(loaded))
	}
}

func TestMultiLoader(t *testing.T) {
	loader1 := NewStaticLoader(Rule{Type: "domain", Pattern: "a.com"})
	loader2 := NewStaticLoader(Rule{Type: "domain", Pattern: "b.com"})

	multi := NewMultiLoader(loader1, loader2)
	rules, err := multi.Load(context.Background())

	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if len(rules) != 2 {
		t.Errorf("expected 2 rules, got %d", len(rules))
	}
}

func TestURLLoader(t *testing.T) {
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`type,pattern
domain,blocked.com`))
	}))
	defer server.Close()

	loader := NewURLLoader(server.URL)
	rules, err := loader.Load(context.Background())

	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if len(rules) != 1 {
		t.Errorf("expected 1 rule, got %d", len(rules))
	}
	if rules[0].Pattern != "blocked.com" {
		t.Errorf("unexpected pattern: %s", rules[0].Pattern)
	}
}

func TestURLLoader_Error(t *testing.T) {
	loader := NewURLLoader("http://nonexistent.invalid")
	_, err := loader.Load(context.Background())

	if err == nil {
		t.Error("expected error for invalid URL")
	}
}

func TestURLLoader_BadStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	loader := NewURLLoader(server.URL)
	_, err := loader.Load(context.Background())

	if err == nil {
		t.Error("expected error for bad status")
	}
}

func TestReloadableFilter(t *testing.T) {
	rules := []Rule{
		{Type: "domain", Pattern: "blocked.com", Reason: "test"},
	}
	loader := NewStaticLoader(rules...)

	filter := NewReloadableFilter(loader)

	// Should not block before loading
	req := &http.Request{Host: "blocked.com", URL: &url.URL{Path: "/"}}
	blocked, _ := filter.ShouldBlock(req)
	if blocked {
		t.Error("should not block before loading")
	}

	// Load rules
	err := filter.Load(context.Background())
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	// Should block after loading
	blocked, _ = filter.ShouldBlock(req)
	if !blocked {
		t.Error("should block after loading")
	}

	if filter.Count() != 1 {
		t.Errorf("expected 1 rule, got %d", filter.Count())
	}
}

func TestReloadableFilter_Callbacks(t *testing.T) {
	loader := NewStaticLoader(Rule{Type: "domain", Pattern: "a.com"})
	filter := NewReloadableFilter(loader)

	reloadCalled := false
	filter.OnReload = func(count int) {
		reloadCalled = true
		if count != 1 {
			t.Errorf("expected count 1, got %d", count)
		}
	}

	_ = filter.Load(context.Background())

	if !reloadCalled {
		t.Error("OnReload callback not called")
	}
}

func TestReloadableFilter_ErrorCallback(t *testing.T) {
	loader := RuleLoaderFunc(func(ctx context.Context) ([]Rule, error) {
		return nil, context.DeadlineExceeded
	})

	filter := NewReloadableFilter(loader)

	errorCalled := false
	filter.OnError = func(err error) {
		errorCalled = true
	}

	_ = filter.Load(context.Background())

	if !errorCalled {
		t.Error("OnError callback not called")
	}
}

func TestReloadableFilter_AutoReload(t *testing.T) {
	var loadCount atomic.Int32
	loader := RuleLoaderFunc(func(ctx context.Context) ([]Rule, error) {
		loadCount.Add(1)
		return []Rule{{Type: "domain", Pattern: "test.com"}}, nil
	})

	filter := NewReloadableFilter(loader)

	ctx := context.Background()
	cancel := filter.StartAutoReload(ctx, 50*time.Millisecond)
	defer cancel()

	// Wait for a few reloads
	time.Sleep(200 * time.Millisecond)

	if loadCount.Load() < 2 {
		t.Errorf("expected multiple loads, got %d", loadCount.Load())
	}
}

func TestParseDomainList(t *testing.T) {
	input := `# Comment line
blocked.com
ads.example.com

# Another comment
*.tracking.com`

	rules, err := ParseDomainList(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseDomainList failed: %v", err)
	}

	if len(rules) != 3 {
		t.Errorf("expected 3 rules, got %d", len(rules))
	}

	expected := []string{"blocked.com", "ads.example.com", "*.tracking.com"}
	for i, rule := range rules {
		if rule.Type != "domain" {
			t.Errorf("rule %d: expected type domain, got %s", i, rule.Type)
		}
		if rule.Pattern != expected[i] {
			t.Errorf("rule %d: expected pattern %q, got %q", i, expected[i], rule.Pattern)
		}
	}
}

func TestRuleLoaderFunc(t *testing.T) {
	called := false
	loader := RuleLoaderFunc(func(ctx context.Context) ([]Rule, error) {
		called = true
		return []Rule{{Type: "domain", Pattern: "test.com"}}, nil
	})

	rules, err := loader.Load(context.Background())
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if !called {
		t.Error("function not called")
	}
	if len(rules) != 1 {
		t.Errorf("expected 1 rule, got %d", len(rules))
	}
}

// Benchmarks

func BenchmarkRuleSet_Match_Domain(b *testing.B) {
	rs := NewRuleSet()
	for i := range 100 {
		rs.AddDomain(strings.Repeat("a", i) + ".com")
	}

	req := &http.Request{Host: "notblocked.com", URL: &url.URL{Path: "/"}}

	b.ResetTimer()
	for b.Loop() {
		rs.Match(req)
	}
}

func BenchmarkRuleSet_Match_Wildcard(b *testing.B) {
	rs := NewRuleSet()
	for i := range 50 {
		rs.AddDomain("*." + strings.Repeat("a", i) + ".com")
	}

	req := &http.Request{Host: "sub.notblocked.com", URL: &url.URL{Path: "/"}}

	b.ResetTimer()
	for b.Loop() {
		rs.Match(req)
	}
}

func BenchmarkRuleSet_Match_Regex(b *testing.B) {
	rs := NewRuleSet()
	_ = rs.AddRegex(`.*tracking.*`)
	_ = rs.AddRegex(`.*analytics.*`)
	_ = rs.AddRegex(`.*\.doubleclick\..*`)

	req := &http.Request{Host: "safe.com", URL: &url.URL{Path: "/"}}

	b.ResetTimer()
	for b.Loop() {
		rs.Match(req)
	}
}

func BenchmarkCSVLoader_Parse(b *testing.B) {
	csv := `type,pattern,reason,category
domain,a.com,reason,cat
domain,b.com,reason,cat
domain,c.com,reason,cat
url,http://d.com,reason,cat
regex,.*e.*,reason,cat`

	loader := &CSVLoader{HasHeader: true, DefaultReason: "default"}

	b.ResetTimer()
	for b.Loop() {
		_, _ = loader.LoadFromReader(context.Background(), strings.NewReader(csv))
	}
}
