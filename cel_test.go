package swg

import (
	"context"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNewCELMatcher(t *testing.T) {
	tests := []struct {
		name       string
		expression string
		wantErr    bool
		errContain string
	}{
		{
			name:       "valid simple expression",
			expression: `request["method"] == "GET"`,
			wantErr:    false,
		},
		{
			name:       "valid complex expression",
			expression: `request["host"].matchesDomain("example.com") && request["method"] == "POST"`,
			wantErr:    false,
		},
		{
			name:       "empty expression",
			expression: "",
			wantErr:    true,
			errContain: "cannot be empty",
		},
		{
			name:       "syntax error",
			expression: `request["method" ==`,
			wantErr:    true,
			errContain: "compile CEL expression",
		},
		{
			name:       "non-boolean return",
			expression: `request["method"]`,
			wantErr:    true,
			errContain: "must return bool",
		},
		{
			name:       "undefined variable",
			expression: `undefined_var == "test"`,
			wantErr:    true,
			errContain: "compile CEL expression",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matcher, err := NewCELMatcher(tt.expression)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tt.errContain != "" && !celContains(err.Error(), tt.errContain) {
					t.Errorf("error %q should contain %q", err.Error(), tt.errContain)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if matcher == nil {
				t.Fatal("expected matcher, got nil")
			}
			if matcher.Expression() != tt.expression {
				t.Errorf("Expression() = %q, want %q", matcher.Expression(), tt.expression)
			}
		})
	}
}

func TestCELMatcherWithConfig(t *testing.T) {
	cfg := CELMatcherConfig{
		Expression: `request["method"] == "GET"`,
		Reason:     "GET not allowed",
		Category:   "security",
	}

	matcher, err := NewCELMatcherWithConfig(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if matcher.Reason() != "GET not allowed" {
		t.Errorf("Reason() = %q, want %q", matcher.Reason(), "GET not allowed")
	}
	if matcher.Category() != "security" {
		t.Errorf("Category() = %q, want %q", matcher.Category(), "security")
	}
}

func TestCELMatcher_Match(t *testing.T) {
	tests := []struct {
		name       string
		expression string
		method     string
		host       string
		path       string
		headers    map[string]string
		wantMatch  bool
	}{
		{
			name:       "method match",
			expression: `request["method"] == "POST"`,
			method:     "POST",
			host:       "example.com",
			wantMatch:  true,
		},
		{
			name:       "method no match",
			expression: `request["method"] == "POST"`,
			method:     "GET",
			host:       "example.com",
			wantMatch:  false,
		},
		{
			name:       "host exact match",
			expression: `request["host"].isDomain("example.com")`,
			method:     "GET",
			host:       "example.com",
			wantMatch:  true,
		},
		{
			name:       "host exact no match subdomain",
			expression: `request["host"].isDomain("example.com")`,
			method:     "GET",
			host:       "www.example.com",
			wantMatch:  false,
		},
		{
			name:       "host matches domain with subdomain",
			expression: `request["host"].matchesDomain("example.com")`,
			method:     "GET",
			host:       "www.example.com",
			wantMatch:  true,
		},
		{
			name:       "host matches domain exact",
			expression: `request["host"].matchesDomain("example.com")`,
			method:     "GET",
			host:       "example.com",
			wantMatch:  true,
		},
		{
			name:       "host matches domain no match",
			expression: `request["host"].matchesDomain("example.com")`,
			method:     "GET",
			host:       "notexample.com",
			wantMatch:  false,
		},
		{
			name:       "path startsWith",
			expression: `request["path"].startsWith("/api/")`,
			method:     "GET",
			host:       "example.com",
			path:       "/api/users",
			wantMatch:  true,
		},
		{
			name:       "path no match",
			expression: `request["path"].startsWith("/api/")`,
			method:     "GET",
			host:       "example.com",
			path:       "/web/users",
			wantMatch:  false,
		},
		{
			name:       "header match",
			expression: `request["headers"]["x-api-key"] == "secret"`,
			method:     "GET",
			host:       "example.com",
			headers:    map[string]string{"X-API-Key": "secret"},
			wantMatch:  true,
		},
		{
			name:       "header present but empty",
			expression: `request["headers"]["x-custom"] == ""`,
			method:     "GET",
			host:       "example.com",
			headers:    map[string]string{"X-Custom": ""},
			wantMatch:  true,
		},
		{
			name:       "complex expression",
			expression: `request["method"] == "POST" && request["path"].startsWith("/admin")`,
			method:     "POST",
			host:       "example.com",
			path:       "/admin/users",
			wantMatch:  true,
		},
		{
			name:       "complex expression partial match",
			expression: `request["method"] == "POST" && request["path"].startsWith("/admin")`,
			method:     "GET",
			host:       "example.com",
			path:       "/admin/users",
			wantMatch:  false,
		},
		{
			name:       "regex match",
			expression: `request["path"].matches("^/api/v[0-9]+/")`,
			method:     "GET",
			host:       "example.com",
			path:       "/api/v2/users",
			wantMatch:  true,
		},
		{
			name:       "content type check",
			expression: `request["content_type"].contains("json")`,
			method:     "POST",
			host:       "example.com",
			headers:    map[string]string{"Content-Type": "application/json"},
			wantMatch:  true,
		},
		{
			name:       "scheme check https",
			expression: `request["scheme"] == "http"`,
			method:     "GET",
			host:       "example.com",
			wantMatch:  true, // httptest creates http requests by default
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matcher, err := NewCELMatcher(tt.expression)
			if err != nil {
				t.Fatalf("failed to create matcher: %v", err)
			}

			path := tt.path
			if path == "" {
				path = "/"
			}

			req := httptest.NewRequest(tt.method, "http://"+tt.host+path, nil)
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			matched, err := matcher.Match(req)
			if err != nil {
				t.Fatalf("Match() error: %v", err)
			}

			if matched != tt.wantMatch {
				t.Errorf("Match() = %v, want %v", matched, tt.wantMatch)
			}
		})
	}
}

func TestCELMatcher_MatchWithContext(t *testing.T) {
	tests := []struct {
		name       string
		expression string
		rc         *RequestContext
		wantMatch  bool
	}{
		{
			name:       "client IP match",
			expression: `client["ip"] == "192.168.1.100"`,
			rc:         &RequestContext{ClientIP: "192.168.1.100"},
			wantMatch:  true,
		},
		{
			name:       "client IP no match",
			expression: `client["ip"] == "192.168.1.100"`,
			rc:         &RequestContext{ClientIP: "10.0.0.1"},
			wantMatch:  false,
		},
		{
			name:       "client IP in CIDR",
			expression: `client["ip"].inCIDR("192.168.0.0/16")`,
			rc:         &RequestContext{ClientIP: "192.168.1.100"},
			wantMatch:  true,
		},
		{
			name:       "client IP not in CIDR",
			expression: `client["ip"].inCIDR("192.168.0.0/16")`,
			rc:         &RequestContext{ClientIP: "10.0.0.1"},
			wantMatch:  false,
		},
		{
			name:       "client IP is private",
			expression: `client["ip"].isPrivate()`,
			rc:         &RequestContext{ClientIP: "192.168.1.100"},
			wantMatch:  true,
		},
		{
			name:       "client IP is not private",
			expression: `client["ip"].isPrivate()`,
			rc:         &RequestContext{ClientIP: "8.8.8.8"},
			wantMatch:  false,
		},
		{
			name:       "identity match",
			expression: `client["identity"] == "admin"`,
			rc:         &RequestContext{Identity: "admin"},
			wantMatch:  true,
		},
		{
			name:       "group membership with in",
			expression: `"admin" in client["groups"]`,
			rc:         &RequestContext{Groups: []string{"users", "admin"}},
			wantMatch:  true,
		},
		{
			name:       "group membership not found",
			expression: `"admin" in client["groups"]`,
			rc:         &RequestContext{Groups: []string{"users", "guests"}},
			wantMatch:  false,
		},
		{
			name:       "tag match",
			expression: `client["tags"]["department"] == "engineering"`,
			rc:         &RequestContext{Tags: map[string]string{"department": "engineering"}},
			wantMatch:  true,
		},
		{
			name:       "nil context - uses remote addr",
			expression: `client["ip"] != ""`,
			rc:         nil,
			wantMatch:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matcher, err := NewCELMatcher(tt.expression)
			if err != nil {
				t.Fatalf("failed to create matcher: %v", err)
			}

			req := httptest.NewRequest("GET", "http://example.com/", nil)

			matched, err := matcher.MatchWithContext(req, tt.rc)
			if err != nil {
				t.Fatalf("MatchWithContext() error: %v", err)
			}

			if matched != tt.wantMatch {
				t.Errorf("MatchWithContext() = %v, want %v", matched, tt.wantMatch)
			}
		})
	}
}

func TestCELMatcher_ShouldBlock(t *testing.T) {
	cfg := CELMatcherConfig{
		Expression: `request["method"] == "DELETE"`,
		Reason:     "DELETE not allowed",
		Category:   "security",
	}

	matcher, err := NewCELMatcherWithConfig(cfg)
	if err != nil {
		t.Fatalf("failed to create matcher: %v", err)
	}

	// Test blocking
	req := httptest.NewRequest("DELETE", "http://example.com/resource", nil)
	blocked, reason := matcher.ShouldBlock(req)
	if !blocked {
		t.Error("expected request to be blocked")
	}
	if reason != "DELETE not allowed (security)" {
		t.Errorf("reason = %q, want %q", reason, "DELETE not allowed (security)")
	}

	// Test not blocking
	req = httptest.NewRequest("GET", "http://example.com/resource", nil)
	blocked, reason = matcher.ShouldBlock(req)
	if blocked {
		t.Error("expected request to not be blocked")
	}
	if reason != "" {
		t.Errorf("reason = %q, want empty", reason)
	}
}

func TestCELMatcher_ShouldBlockWithRequestContext(t *testing.T) {
	matcher, err := NewCELMatcherWithConfig(CELMatcherConfig{
		Expression: `!("admin" in client["groups"]) && request["path"].startsWith("/admin")`,
		Reason:     "admin access denied",
	})
	if err != nil {
		t.Fatalf("failed to create matcher: %v", err)
	}

	// Non-admin accessing /admin should be blocked
	rc := &RequestContext{Groups: []string{"users"}}
	ctx := WithRequestContext(context.Background(), rc)
	req := httptest.NewRequest("GET", "http://example.com/admin/users", nil)
	req = req.WithContext(ctx)

	blocked, _ := matcher.ShouldBlock(req)
	if !blocked {
		t.Error("expected non-admin to be blocked from /admin")
	}

	// Admin accessing /admin should not be blocked
	rc = &RequestContext{Groups: []string{"users", "admin"}}
	ctx = WithRequestContext(context.Background(), rc)
	req = httptest.NewRequest("GET", "http://example.com/admin/users", nil)
	req = req.WithContext(ctx)

	blocked, _ = matcher.ShouldBlock(req)
	if blocked {
		t.Error("expected admin to not be blocked from /admin")
	}
}

func TestCELFilter(t *testing.T) {
	filter := NewCELFilter()

	// Add expressions
	err := filter.AddExpression(`request["method"] == "DELETE"`)
	if err != nil {
		t.Fatalf("AddExpression() error: %v", err)
	}

	err = filter.AddExpressionWithConfig(CELMatcherConfig{
		Expression: `request["path"].startsWith("/internal/")`,
		Reason:     "internal path blocked",
		Category:   "access",
	})
	if err != nil {
		t.Fatalf("AddExpressionWithConfig() error: %v", err)
	}

	if filter.Count() != 2 {
		t.Errorf("Count() = %d, want 2", filter.Count())
	}

	// Test first expression matches
	req := httptest.NewRequest("DELETE", "http://example.com/resource", nil)
	blocked, _ := filter.ShouldBlock(req)
	if !blocked {
		t.Error("expected DELETE to be blocked")
	}

	// Test second expression matches
	req = httptest.NewRequest("GET", "http://example.com/internal/config", nil)
	blocked, reason := filter.ShouldBlock(req)
	if !blocked {
		t.Error("expected /internal/ to be blocked")
	}
	if reason != "internal path blocked (access)" {
		t.Errorf("reason = %q, want %q", reason, "internal path blocked (access)")
	}

	// Test no match
	req = httptest.NewRequest("GET", "http://example.com/public", nil)
	blocked, _ = filter.ShouldBlock(req)
	if blocked {
		t.Error("expected /public GET to not be blocked")
	}

	// Test remove
	if !filter.RemoveExpression(`request["method"] == "DELETE"`) {
		t.Error("RemoveExpression() returned false")
	}
	if filter.Count() != 1 {
		t.Errorf("Count() = %d, want 1", filter.Count())
	}

	// DELETE should now pass
	req = httptest.NewRequest("DELETE", "http://example.com/resource", nil)
	blocked, _ = filter.ShouldBlock(req)
	if blocked {
		t.Error("expected DELETE to pass after removal")
	}

	// Test clear
	filter.Clear()
	if filter.Count() != 0 {
		t.Errorf("Count() = %d after Clear(), want 0", filter.Count())
	}
}

func TestCELFilter_Expressions(t *testing.T) {
	filter := NewCELFilter()

	exprs := []string{
		`request["method"] == "DELETE"`,
		`request["path"].startsWith("/admin")`,
		`request["host"].matchesDomain("blocked.com")`,
	}

	for _, expr := range exprs {
		if err := filter.AddExpression(expr); err != nil {
			t.Fatalf("AddExpression() error: %v", err)
		}
	}

	got := filter.Expressions()
	if len(got) != len(exprs) {
		t.Errorf("len(Expressions()) = %d, want %d", len(got), len(exprs))
	}

	for i, expr := range exprs {
		if got[i] != expr {
			t.Errorf("Expressions()[%d] = %q, want %q", i, got[i], expr)
		}
	}
}

func TestCELRuleSet(t *testing.T) {
	rs := NewCELRuleSet()

	// Add standard domain rule
	err := rs.AddRule(Rule{
		Type:    "domain",
		Pattern: "blocked.com",
		Reason:  "domain blocked",
	})
	if err != nil {
		t.Fatalf("AddRule(domain) error: %v", err)
	}

	// Add CEL rule
	err = rs.AddRule(Rule{
		Type:     "cel",
		Pattern:  `request["method"] == "DELETE"`,
		Reason:   "DELETE blocked",
		Category: "security",
	})
	if err != nil {
		t.Fatalf("AddRule(cel) error: %v", err)
	}

	// Add CEL using convenience method
	err = rs.AddCEL(`request["path"].startsWith("/internal/")`)
	if err != nil {
		t.Fatalf("AddCEL() error: %v", err)
	}

	// Check counts
	if rs.Count() != 3 {
		t.Errorf("Count() = %d, want 3", rs.Count())
	}
	if rs.CELCount() != 2 {
		t.Errorf("CELCount() = %d, want 2", rs.CELCount())
	}

	// Test domain match
	req := httptest.NewRequest("GET", "http://blocked.com/", nil)
	rule, blocked := rs.Match(req)
	if !blocked {
		t.Error("expected blocked.com to be blocked")
	}
	if rule.Type != "domain" {
		t.Errorf("rule.Type = %q, want %q", rule.Type, "domain")
	}

	// Test CEL match (DELETE)
	req = httptest.NewRequest("DELETE", "http://example.com/resource", nil)
	rule, blocked = rs.Match(req)
	if !blocked {
		t.Error("expected DELETE to be blocked")
	}
	if rule.Type != "cel" {
		t.Errorf("rule.Type = %q, want %q", rule.Type, "cel")
	}

	// Test CEL match (internal path)
	req = httptest.NewRequest("GET", "http://example.com/internal/config", nil)
	blocked, _ = rs.ShouldBlock(req)
	if !blocked {
		t.Error("expected /internal/ to be blocked")
	}

	// Test no match
	req = httptest.NewRequest("GET", "http://example.com/public", nil)
	blocked, _ = rs.ShouldBlock(req)
	if blocked {
		t.Error("expected /public GET to not be blocked")
	}

	// Test Rules() returns all
	rules := rs.Rules()
	if len(rules) != 3 {
		t.Errorf("len(Rules()) = %d, want 3", len(rules))
	}

	// Test remove CEL rule
	if !rs.RemoveRule("cel", `request["method"] == "DELETE"`) {
		t.Error("RemoveRule(cel) returned false")
	}
	if rs.CELCount() != 1 {
		t.Errorf("CELCount() = %d after remove, want 1", rs.CELCount())
	}

	// Test Clear
	rs.Clear()
	if rs.Count() != 0 {
		t.Errorf("Count() = %d after Clear(), want 0", rs.Count())
	}
	if rs.CELCount() != 0 {
		t.Errorf("CELCount() = %d after Clear(), want 0", rs.CELCount())
	}
}

func TestCELRuleSet_InvalidExpression(t *testing.T) {
	rs := NewCELRuleSet()

	err := rs.AddRule(Rule{
		Type:    "cel",
		Pattern: `invalid syntax [[[`,
		Reason:  "test",
	})
	if err == nil {
		t.Error("expected error for invalid CEL expression")
	}
}

func TestCELMatcher_CustomFunctions(t *testing.T) {
	tests := []struct {
		name       string
		expression string
		host       string
		clientIP   string
		wantMatch  bool
	}{
		{
			name:       "isDomain exact match",
			expression: `request["host"].isDomain("example.com")`,
			host:       "example.com",
			wantMatch:  true,
		},
		{
			name:       "isDomain case insensitive",
			expression: `request["host"].isDomain("EXAMPLE.COM")`,
			host:       "example.com",
			wantMatch:  true,
		},
		{
			name:       "matchesDomain subdomain",
			expression: `request["host"].matchesDomain("example.com")`,
			host:       "api.example.com",
			wantMatch:  true,
		},
		{
			name:       "matchesDomain deep subdomain",
			expression: `request["host"].matchesDomain("example.com")`,
			host:       "a.b.c.example.com",
			wantMatch:  true,
		},
		{
			name:       "inCIDR IPv4",
			expression: `client["ip"].inCIDR("10.0.0.0/8")`,
			clientIP:   "10.255.255.255",
			wantMatch:  true,
		},
		{
			name:       "inCIDR IPv4 no match",
			expression: `client["ip"].inCIDR("10.0.0.0/8")`,
			clientIP:   "192.168.1.1",
			wantMatch:  false,
		},
		{
			name:       "inCIDR invalid CIDR returns false",
			expression: `client["ip"].inCIDR("invalid")`,
			clientIP:   "10.0.0.1",
			wantMatch:  false,
		},
		{
			name:       "inCIDR invalid IP returns false",
			expression: `client["ip"].inCIDR("10.0.0.0/8")`,
			clientIP:   "invalid",
			wantMatch:  false,
		},
		{
			name:       "isPrivate RFC1918 class A",
			expression: `client["ip"].isPrivate()`,
			clientIP:   "10.0.0.1",
			wantMatch:  true,
		},
		{
			name:       "isPrivate RFC1918 class B",
			expression: `client["ip"].isPrivate()`,
			clientIP:   "172.16.0.1",
			wantMatch:  true,
		},
		{
			name:       "isPrivate RFC1918 class C",
			expression: `client["ip"].isPrivate()`,
			clientIP:   "192.168.1.1",
			wantMatch:  true,
		},
		{
			name:       "isPrivate public IP",
			expression: `client["ip"].isPrivate()`,
			clientIP:   "1.1.1.1",
			wantMatch:  false,
		},
		{
			name:       "isPrivate invalid IP returns false",
			expression: `client["ip"].isPrivate()`,
			clientIP:   "not-an-ip",
			wantMatch:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matcher, err := NewCELMatcher(tt.expression)
			if err != nil {
				t.Fatalf("failed to create matcher: %v", err)
			}

			host := tt.host
			if host == "" {
				host = "example.com"
			}

			req := httptest.NewRequest("GET", "http://"+host+"/", nil)

			var rc *RequestContext
			if tt.clientIP != "" {
				rc = &RequestContext{ClientIP: tt.clientIP}
			}

			matched, err := matcher.MatchWithContext(req, rc)
			if err != nil {
				t.Fatalf("MatchWithContext() error: %v", err)
			}

			if matched != tt.wantMatch {
				t.Errorf("MatchWithContext() = %v, want %v", matched, tt.wantMatch)
			}
		})
	}
}

func TestCELFilter_AddMatcher(t *testing.T) {
	filter := NewCELFilter()

	matcher, err := NewCELMatcherWithConfig(CELMatcherConfig{
		Expression: `request["method"] == "PUT"`,
		Reason:     "PUT blocked",
	})
	if err != nil {
		t.Fatalf("NewCELMatcherWithConfig() error: %v", err)
	}

	filter.AddMatcher(matcher)

	if filter.Count() != 1 {
		t.Errorf("Count() = %d, want 1", filter.Count())
	}

	req := httptest.NewRequest("PUT", "http://example.com/resource", nil)
	blocked, reason := filter.ShouldBlock(req)
	if !blocked {
		t.Error("expected PUT to be blocked")
	}
	if reason != "PUT blocked" {
		t.Errorf("reason = %q, want %q", reason, "PUT blocked")
	}
}

func TestCELMatcher_HostWithPort(t *testing.T) {
	matcher, err := NewCELMatcher(`request["host"] == "example.com"`)
	if err != nil {
		t.Fatalf("failed to create matcher: %v", err)
	}

	// Host with port should be stripped
	req := httptest.NewRequest("GET", "http://example.com:8080/", nil)
	req.Host = "example.com:8080"

	matched, err := matcher.Match(req)
	if err != nil {
		t.Fatalf("Match() error: %v", err)
	}
	if !matched {
		t.Error("expected host with port to match after stripping port")
	}
}

func BenchmarkCELMatcher_Simple(b *testing.B) {
	matcher, err := NewCELMatcher(`request["method"] == "GET"`)
	if err != nil {
		b.Fatalf("failed to create matcher: %v", err)
	}

	req := httptest.NewRequest("GET", "http://example.com/", nil)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _ = matcher.Match(req)
	}
}

func BenchmarkCELMatcher_Complex(b *testing.B) {
	matcher, err := NewCELMatcher(`
		request["method"] == "POST" && 
		request["path"].startsWith("/api/") && 
		request["host"].matchesDomain("example.com")
	`)
	if err != nil {
		b.Fatalf("failed to create matcher: %v", err)
	}

	req := httptest.NewRequest("POST", "http://api.example.com/api/users", nil)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _ = matcher.Match(req)
	}
}

func BenchmarkCELMatcher_WithContext(b *testing.B) {
	matcher, err := NewCELMatcher(`
		client["ip"].inCIDR("10.0.0.0/8") && 
		"admin" in client["groups"]
	`)
	if err != nil {
		b.Fatalf("failed to create matcher: %v", err)
	}

	req := httptest.NewRequest("GET", "http://example.com/", nil)
	rc := &RequestContext{
		ClientIP: "10.0.0.1",
		Groups:   []string{"users", "admin"},
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _ = matcher.MatchWithContext(req, rc)
	}
}

func BenchmarkCELFilter_Multiple(b *testing.B) {
	filter := NewCELFilter()

	expressions := []string{
		`request["method"] == "DELETE"`,
		`request["path"].startsWith("/admin/")`,
		`request["host"].matchesDomain("blocked.com")`,
		`request["headers"]["x-blocked"] == "true"`,
	}

	for _, expr := range expressions {
		if err := filter.AddExpression(expr); err != nil {
			b.Fatalf("AddExpression() error: %v", err)
		}
	}

	req := httptest.NewRequest("GET", "http://example.com/public", nil)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		filter.ShouldBlock(req)
	}
}

func BenchmarkCELRuleSet_Mixed(b *testing.B) {
	rs := NewCELRuleSet()

	// Add domain rules
	for i := 0; i < 100; i++ {
		rs.AddDomain(fmt.Sprintf("blocked%d.com", i))
	}

	// Add CEL rules
	_ = rs.AddCEL(`request["method"] == "DELETE"`)
	_ = rs.AddCEL(`request["path"].startsWith("/admin/")`)

	req := httptest.NewRequest("GET", "http://example.com/public", nil)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		rs.ShouldBlock(req)
	}
}

// celContains is a helper function for string containment checks
func celContains(s, substr string) bool {
	return strings.Contains(s, substr)
}
