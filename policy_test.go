package swg

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// RequestContext
// ---------------------------------------------------------------------------

func TestRequestContext_RoundTrip(t *testing.T) {
	rc := &RequestContext{
		ClientIP: "10.0.0.1",
		Identity: "alice",
		Groups:   []string{"admins"},
		Tags:     map[string]string{"env": "prod"},
	}
	ctx := WithRequestContext(context.Background(), rc)
	got := GetRequestContext(ctx)
	if got != rc {
		t.Fatal("round-trip through context failed")
	}
}

func TestGetRequestContext_Missing(t *testing.T) {
	if rc := GetRequestContext(context.Background()); rc != nil {
		t.Fatal("expected nil for empty context")
	}
}

// ---------------------------------------------------------------------------
// AllowListFilter
// ---------------------------------------------------------------------------

func TestAllowListFilter_Allowed(t *testing.T) {
	f := NewAllowListFilter()
	f.AddDomain("safe.com")
	f.AddDomain("*.internal.co")

	tests := []struct {
		host    string
		blocked bool
	}{
		{"safe.com", false},
		{"app.internal.co", false},
		{"internal.co", false},
		{"evil.com", true},
		{"notsafe.com", true},
	}

	for _, tt := range tests {
		req := httptest.NewRequest("GET", "http://"+tt.host+"/", nil)
		blocked, _ := f.ShouldBlock(req)
		if blocked != tt.blocked {
			t.Errorf("host=%s: blocked=%v, want %v", tt.host, blocked, tt.blocked)
		}
	}
}

func TestAllowListFilter_AddDomains(t *testing.T) {
	f := NewAllowListFilter()
	f.AddDomains([]string{"a.com", "b.com"})

	req := httptest.NewRequest("GET", "http://a.com/", nil)
	if blocked, _ := f.ShouldBlock(req); blocked {
		t.Error("a.com should be allowed")
	}

	req = httptest.NewRequest("GET", "http://c.com/", nil)
	if blocked, _ := f.ShouldBlock(req); !blocked {
		t.Error("c.com should be blocked")
	}
}

func TestAllowListFilter_CustomReason(t *testing.T) {
	f := NewAllowListFilter()
	f.Reason = "not on the whitelist"

	req := httptest.NewRequest("GET", "http://blocked.com/", nil)
	_, reason := f.ShouldBlock(req)
	if reason != "not on the whitelist" {
		t.Errorf("reason = %q, want 'not on the whitelist'", reason)
	}
}

func TestAllowListFilter_HostWithPort(t *testing.T) {
	f := NewAllowListFilter()
	f.AddDomain("api.local")

	req := httptest.NewRequest("GET", "http://api.local:8080/v1", nil)
	if blocked, _ := f.ShouldBlock(req); blocked {
		t.Error("api.local:8080 should be allowed")
	}
}

// ---------------------------------------------------------------------------
// TimeRule
// ---------------------------------------------------------------------------

func TestTimeRule_ActiveDuringWindow(t *testing.T) {
	inner := NewDomainFilter()
	inner.AddDomain("blocked.com")

	tr := &TimeRule{
		Inner:     inner,
		StartHour: 9,
		EndHour:   17,
		Location:  time.UTC,
		NowFunc:   func() time.Time { return time.Date(2025, 6, 10, 12, 0, 0, 0, time.UTC) },
	}

	req := httptest.NewRequest("GET", "http://blocked.com/", nil)
	blocked, _ := tr.ShouldBlock(req)
	if !blocked {
		t.Error("should be blocked during active window")
	}
}

func TestTimeRule_InactiveOutsideWindow(t *testing.T) {
	inner := NewDomainFilter()
	inner.AddDomain("blocked.com")

	tr := &TimeRule{
		Inner:     inner,
		StartHour: 9,
		EndHour:   17,
		Location:  time.UTC,
		NowFunc:   func() time.Time { return time.Date(2025, 6, 10, 20, 0, 0, 0, time.UTC) },
	}

	req := httptest.NewRequest("GET", "http://blocked.com/", nil)
	blocked, _ := tr.ShouldBlock(req)
	if blocked {
		t.Error("should NOT be blocked outside window")
	}
}

func TestTimeRule_WrapsMidnight(t *testing.T) {
	inner := NewDomainFilter()
	inner.AddDomain("late.com")

	tr := &TimeRule{
		Inner:     inner,
		StartHour: 22,
		EndHour:   6,
		Location:  time.UTC,
	}

	tests := []struct {
		hour    int
		blocked bool
	}{
		{23, true},
		{0, true},
		{3, true},
		{5, true},
		{6, false},
		{12, false},
		{21, false},
		{22, true},
	}

	for _, tt := range tests {
		tr.NowFunc = func() time.Time { return time.Date(2025, 6, 10, tt.hour, 0, 0, 0, time.UTC) }
		req := httptest.NewRequest("GET", "http://late.com/", nil)
		blocked, _ := tr.ShouldBlock(req)
		if blocked != tt.blocked {
			t.Errorf("hour=%d: blocked=%v, want %v", tt.hour, blocked, tt.blocked)
		}
	}
}

func TestTimeRule_WeekdayFilter(t *testing.T) {
	inner := NewDomainFilter()
	inner.AddDomain("work.com")

	tr := &TimeRule{
		Inner:     inner,
		StartHour: 0,
		EndHour:   24,
		Weekdays:  []time.Weekday{time.Monday, time.Tuesday},
		Location:  time.UTC,
	}

	// Tuesday
	tr.NowFunc = func() time.Time { return time.Date(2025, 6, 10, 12, 0, 0, 0, time.UTC) }
	req := httptest.NewRequest("GET", "http://work.com/", nil)
	if blocked, _ := tr.ShouldBlock(req); !blocked {
		t.Error("should be blocked on Tuesday")
	}

	// Sunday
	tr.NowFunc = func() time.Time { return time.Date(2025, 6, 8, 12, 0, 0, 0, time.UTC) }
	if blocked, _ := tr.ShouldBlock(req); blocked {
		t.Error("should NOT be blocked on Sunday")
	}
}

func TestTimeRule_DefaultLocation(t *testing.T) {
	inner := FilterFunc(func(req *http.Request) (bool, string) { return true, "test" })
	tr := &TimeRule{
		Inner:     inner,
		StartHour: 0,
		EndHour:   24,
	}

	req := httptest.NewRequest("GET", "http://any.com/", nil)
	blocked, _ := tr.ShouldBlock(req)
	if !blocked {
		t.Error("should be blocked with 0-24 window")
	}
}

// ---------------------------------------------------------------------------
// IPIdentityResolver
// ---------------------------------------------------------------------------

func TestIPIdentityResolver_ExactIP(t *testing.T) {
	r := NewIPIdentityResolver()
	r.AddIP("10.0.0.5", "alice", []string{"admins", "engineering"})

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.5:4321"

	identity, groups, err := r.Resolve(req)
	if err != nil {
		t.Fatal(err)
	}
	if identity != "alice" {
		t.Errorf("identity = %q, want alice", identity)
	}
	if len(groups) != 2 || groups[0] != "admins" {
		t.Errorf("groups = %v, want [admins engineering]", groups)
	}
}

func TestIPIdentityResolver_CIDR(t *testing.T) {
	r := NewIPIdentityResolver()
	if err := r.AddCIDR("192.168.1.0/24", "office", []string{"corp"}); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.168.1.42:9999"

	identity, groups, err := r.Resolve(req)
	if err != nil {
		t.Fatal(err)
	}
	if identity != "office" {
		t.Errorf("identity = %q, want office", identity)
	}
	if len(groups) != 1 || groups[0] != "corp" {
		t.Errorf("groups = %v, want [corp]", groups)
	}
}

func TestIPIdentityResolver_NoMatch(t *testing.T) {
	r := NewIPIdentityResolver()
	r.AddIP("10.0.0.1", "known", nil)

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.99:1234"

	identity, groups, err := r.Resolve(req)
	if err != nil {
		t.Fatal(err)
	}
	if identity != "" || groups != nil {
		t.Errorf("expected empty identity for unknown IP, got %q %v", identity, groups)
	}
}

func TestIPIdentityResolver_InvalidCIDR(t *testing.T) {
	r := NewIPIdentityResolver()
	if err := r.AddCIDR("not-a-cidr", "x", nil); err == nil {
		t.Fatal("expected error for invalid CIDR")
	}
}

func TestIPIdentityResolver_NoPort(t *testing.T) {
	r := NewIPIdentityResolver()
	r.AddIP("10.0.0.1", "alice", nil)

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1"

	identity, _, err := r.Resolve(req)
	if err != nil {
		t.Fatal(err)
	}
	if identity != "alice" {
		t.Errorf("identity = %q, want alice", identity)
	}
}

func TestIPIdentityResolver_ExactTakesPriority(t *testing.T) {
	r := NewIPIdentityResolver()
	_ = r.AddCIDR("10.0.0.0/8", "network", []string{"net"})
	r.AddIP("10.0.0.5", "specific", []string{"vip"})

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.5:1234"

	identity, groups, _ := r.Resolve(req)
	if identity != "specific" {
		t.Errorf("identity = %q, want specific (exact match priority)", identity)
	}
	if len(groups) != 1 || groups[0] != "vip" {
		t.Errorf("groups = %v, want [vip]", groups)
	}
}

// ---------------------------------------------------------------------------
// GroupPolicyFilter
// ---------------------------------------------------------------------------

func TestGroupPolicyFilter_MatchesGroup(t *testing.T) {
	admins := NewAllowListFilter()
	admins.AddDomain("admin-only.com")

	gf := NewGroupPolicyFilter()
	gf.SetPolicy("admins", admins)

	rc := &RequestContext{Groups: []string{"admins"}}
	ctx := WithRequestContext(context.Background(), rc)
	req := httptest.NewRequest("GET", "http://admin-only.com/", nil)
	req = req.WithContext(ctx)

	blocked, _ := gf.ShouldBlock(req)
	if blocked {
		t.Error("admins group should allow admin-only.com")
	}
}

func TestGroupPolicyFilter_BlockedByGroup(t *testing.T) {
	restricted := NewDomainFilter()
	restricted.AddDomain("social.com")

	gf := NewGroupPolicyFilter()
	gf.SetPolicy("employees", restricted)

	rc := &RequestContext{Groups: []string{"employees"}}
	ctx := WithRequestContext(context.Background(), rc)
	req := httptest.NewRequest("GET", "http://social.com/", nil)
	req = req.WithContext(ctx)

	blocked, _ := gf.ShouldBlock(req)
	if !blocked {
		t.Error("employees should be blocked from social.com")
	}
}

func TestGroupPolicyFilter_DefaultPolicy(t *testing.T) {
	block := NewDomainFilter()
	block.AddDomain("blocked.com")

	gf := NewGroupPolicyFilter()
	gf.Default = block

	rc := &RequestContext{Groups: []string{"unknown-group"}}
	ctx := WithRequestContext(context.Background(), rc)
	req := httptest.NewRequest("GET", "http://blocked.com/", nil)
	req = req.WithContext(ctx)

	blocked, _ := gf.ShouldBlock(req)
	if !blocked {
		t.Error("default policy should block blocked.com")
	}
}

func TestGroupPolicyFilter_NoContext(t *testing.T) {
	gf := NewGroupPolicyFilter()
	gf.Default = FilterFunc(func(req *http.Request) (bool, string) {
		return true, "default"
	})

	req := httptest.NewRequest("GET", "http://any.com/", nil)
	blocked, reason := gf.ShouldBlock(req)
	if !blocked || reason != "default" {
		t.Errorf("blocked=%v reason=%q, want true/default", blocked, reason)
	}
}

func TestGroupPolicyFilter_NoMatchNoDefault(t *testing.T) {
	gf := NewGroupPolicyFilter()

	req := httptest.NewRequest("GET", "http://any.com/", nil)
	blocked, _ := gf.ShouldBlock(req)
	if blocked {
		t.Error("should not block with no policies and no default")
	}
}

// ---------------------------------------------------------------------------
// ContentTypeFilter (ResponseHook)
// ---------------------------------------------------------------------------

func TestContentTypeFilter_BlocksMatching(t *testing.T) {
	f := NewContentTypeFilter()
	f.Block("application/x-executable", "executable blocked")
	f.Block("application/zip", "archives blocked")

	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": {"application/x-executable"}},
		Body:       io.NopCloser(strings.NewReader("ELF...")),
	}

	result := f.HandleResponse(context.Background(), nil, resp, nil)
	if result == nil {
		t.Fatal("expected blocked response")
	}

	body, _ := io.ReadAll(result.Body)
	_ = result.Body.Close()

	if result.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", result.StatusCode)
	}
	if !strings.Contains(string(body), "executable blocked") {
		t.Errorf("body = %q, want reason in body", body)
	}
}

func TestContentTypeFilter_AllowsClean(t *testing.T) {
	f := NewContentTypeFilter()
	f.Block("application/x-executable", "blocked")

	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": {"text/html"}},
		Body:       io.NopCloser(strings.NewReader("<html>")),
	}

	result := f.HandleResponse(context.Background(), nil, resp, nil)
	if result != nil {
		t.Error("should not replace clean response")
	}
}

func TestContentTypeFilter_PrefixMatch(t *testing.T) {
	f := NewContentTypeFilter()
	f.Block("application/", "all application types blocked")

	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": {"application/json; charset=utf-8"}},
		Body:       io.NopCloser(strings.NewReader(`{}`)),
	}

	result := f.HandleResponse(context.Background(), nil, resp, nil)
	if result == nil {
		t.Fatal("expected blocked response for application/json")
	}
}

// ---------------------------------------------------------------------------
// ChainFilter
// ---------------------------------------------------------------------------

func TestChainFilter_FirstBlockWins(t *testing.T) {
	f1 := FilterFunc(func(req *http.Request) (bool, string) { return false, "" })
	f2 := FilterFunc(func(req *http.Request) (bool, string) { return true, "f2 blocked" })
	f3 := FilterFunc(func(req *http.Request) (bool, string) { return true, "f3 blocked" })

	cf := &ChainFilter{Filters: []Filter{f1, f2, f3}}
	req := httptest.NewRequest("GET", "http://any.com/", nil)
	blocked, reason := cf.ShouldBlock(req)
	if !blocked || reason != "f2 blocked" {
		t.Errorf("blocked=%v reason=%q, want true/f2 blocked", blocked, reason)
	}
}

func TestChainFilter_NoneBlock(t *testing.T) {
	f1 := FilterFunc(func(req *http.Request) (bool, string) { return false, "" })
	f2 := FilterFunc(func(req *http.Request) (bool, string) { return false, "" })

	cf := &ChainFilter{Filters: []Filter{f1, f2}}
	req := httptest.NewRequest("GET", "http://any.com/", nil)
	blocked, _ := cf.ShouldBlock(req)
	if blocked {
		t.Error("should not block")
	}
}

// ---------------------------------------------------------------------------
// PolicyEngine — ProcessRequest
// ---------------------------------------------------------------------------

func TestPolicyEngine_ProcessRequest_IdentityResolved(t *testing.T) {
	pe := NewPolicyEngine()
	pe.IdentityResolver = IdentityResolverFunc(func(req *http.Request) (string, []string, error) {
		return "bob", []string{"staff"}, nil
	})

	req := httptest.NewRequest("GET", "http://example.com/", nil)
	req.RemoteAddr = "10.0.0.1:9999"

	rc, resp := pe.ProcessRequest(context.Background(), req)
	if resp != nil {
		t.Fatal("should not short-circuit")
	}
	if rc.Identity != "bob" {
		t.Errorf("Identity = %q, want bob", rc.Identity)
	}
	if len(rc.Groups) != 1 || rc.Groups[0] != "staff" {
		t.Errorf("Groups = %v, want [staff]", rc.Groups)
	}
	if rc.ClientIP != "10.0.0.1" {
		t.Errorf("ClientIP = %q, want 10.0.0.1", rc.ClientIP)
	}
}

func TestPolicyEngine_ProcessRequest_HookShortCircuits(t *testing.T) {
	pe := NewPolicyEngine()
	pe.RequestHooks = []RequestHook{
		RequestHookFunc(func(_ context.Context, _ *http.Request, rc *RequestContext) *http.Response {
			return &http.Response{
				StatusCode: http.StatusForbidden,
				Header:     http.Header{"Content-Type": {"text/plain"}},
				Body:       io.NopCloser(strings.NewReader("denied by hook")),
			}
		}),
	}

	req := httptest.NewRequest("GET", "http://example.com/", nil)
	_, resp := pe.ProcessRequest(context.Background(), req)
	if resp == nil {
		t.Fatal("expected short-circuit response")
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func TestPolicyEngine_ProcessRequest_MultipleHooks(t *testing.T) {
	var order []string

	pe := NewPolicyEngine()
	pe.RequestHooks = []RequestHook{
		RequestHookFunc(func(_ context.Context, _ *http.Request, rc *RequestContext) *http.Response {
			order = append(order, "first")
			rc.Tags["first"] = "ran"
			return nil
		}),
		RequestHookFunc(func(_ context.Context, _ *http.Request, rc *RequestContext) *http.Response {
			order = append(order, "second")
			rc.Tags["second"] = "ran"
			return nil
		}),
	}

	req := httptest.NewRequest("GET", "http://example.com/", nil)
	rc, resp := pe.ProcessRequest(context.Background(), req)
	if resp != nil {
		t.Fatal("should not short-circuit")
	}
	if len(order) != 2 || order[0] != "first" || order[1] != "second" {
		t.Errorf("order = %v, want [first second]", order)
	}
	if rc.Tags["first"] != "ran" || rc.Tags["second"] != "ran" {
		t.Error("hooks should set tags")
	}
}

func TestPolicyEngine_ProcessRequest_SecondHookShortCircuits(t *testing.T) {
	pe := NewPolicyEngine()
	pe.RequestHooks = []RequestHook{
		RequestHookFunc(func(_ context.Context, _ *http.Request, _ *RequestContext) *http.Response {
			return nil
		}),
		RequestHookFunc(func(_ context.Context, _ *http.Request, _ *RequestContext) *http.Response {
			return blockedResponse("hook2")
		}),
		RequestHookFunc(func(_ context.Context, _ *http.Request, _ *RequestContext) *http.Response {
			t.Error("third hook should not run")
			return nil
		}),
	}

	req := httptest.NewRequest("GET", "http://example.com/", nil)
	_, resp := pe.ProcessRequest(context.Background(), req)
	if resp == nil {
		t.Fatal("expected short-circuit")
	}
	_ = resp.Body.Close()
}

// ---------------------------------------------------------------------------
// PolicyEngine — ProcessResponse
// ---------------------------------------------------------------------------

func TestPolicyEngine_ProcessResponse_HookReplaces(t *testing.T) {
	pe := NewPolicyEngine()
	pe.ResponseHooks = []ResponseHook{
		ResponseHookFunc(func(_ context.Context, _ *http.Request, resp *http.Response, _ *RequestContext) *http.Response {
			_ = resp.Body.Close()
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"X-Modified": {"true"}},
				Body:       io.NopCloser(strings.NewReader("modified")),
			}
		}),
	}

	req := httptest.NewRequest("GET", "http://example.com/", nil)
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{},
		Body:       io.NopCloser(strings.NewReader("original")),
	}

	result, err := pe.ProcessResponse(context.Background(), req, resp, &RequestContext{})
	if err != nil {
		t.Fatal(err)
	}
	if result.Header.Get("X-Modified") != "true" {
		t.Error("response should be replaced")
	}
	body, _ := io.ReadAll(result.Body)
	_ = result.Body.Close()
	if string(body) != "modified" {
		t.Errorf("body = %q, want modified", body)
	}
}

func TestPolicyEngine_ProcessResponse_NoHooksPassthrough(t *testing.T) {
	pe := NewPolicyEngine()

	req := httptest.NewRequest("GET", "http://example.com/", nil)
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"X-Original": {"true"}},
		Body:       io.NopCloser(strings.NewReader("original")),
	}

	result, err := pe.ProcessResponse(context.Background(), req, resp, &RequestContext{})
	if err != nil {
		t.Fatal(err)
	}
	if result != resp {
		t.Error("should return original response")
	}
}

// ---------------------------------------------------------------------------
// ResponseBodyScanner
// ---------------------------------------------------------------------------

func TestPolicyEngine_BodyScanner_Block(t *testing.T) {
	pe := NewPolicyEngine()
	pe.BodyScanners = []ResponseBodyScanner{
		ResponseBodyScannerFunc(func(_ context.Context, body []byte, _ *http.Request, _ *http.Response) (ScanResult, error) {
			if bytes.Contains(body, []byte("EICAR")) {
				return ScanResult{Verdict: VerdictBlock, Reason: "malware detected"}, nil
			}
			return ScanResult{Verdict: VerdictAllow}, nil
		}),
	}

	req := httptest.NewRequest("GET", "http://example.com/file", nil)
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": {"application/octet-stream"}},
		Body:       io.NopCloser(strings.NewReader("this is EICAR test data")),
	}

	result, err := pe.ProcessResponse(context.Background(), req, resp, &RequestContext{})
	if err != nil {
		t.Fatal(err)
	}
	if result.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", result.StatusCode)
	}
	body, _ := io.ReadAll(result.Body)
	_ = result.Body.Close()
	if !strings.Contains(string(body), "malware detected") {
		t.Errorf("body = %q, want malware reason", body)
	}
}

func TestPolicyEngine_BodyScanner_Allow(t *testing.T) {
	pe := NewPolicyEngine()
	pe.BodyScanners = []ResponseBodyScanner{
		ResponseBodyScannerFunc(func(_ context.Context, _ []byte, _ *http.Request, _ *http.Response) (ScanResult, error) {
			return ScanResult{Verdict: VerdictAllow}, nil
		}),
	}

	original := "clean content"
	req := httptest.NewRequest("GET", "http://example.com/", nil)
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": {"text/plain"}},
		Body:       io.NopCloser(strings.NewReader(original)),
	}

	result, err := pe.ProcessResponse(context.Background(), req, resp, &RequestContext{})
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(result.Body)
	_ = result.Body.Close()
	if string(body) != original {
		t.Errorf("body = %q, want %q", body, original)
	}
}

func TestPolicyEngine_BodyScanner_Replace(t *testing.T) {
	pe := NewPolicyEngine()
	pe.BodyScanners = []ResponseBodyScanner{
		ResponseBodyScannerFunc(func(_ context.Context, body []byte, _ *http.Request, _ *http.Response) (ScanResult, error) {
			sanitized := bytes.ReplaceAll(body, []byte("secret"), []byte("REDACTED"))
			return ScanResult{
				Verdict:                VerdictReplace,
				ReplacementBody:        io.NopCloser(bytes.NewReader(sanitized)),
				ReplacementContentType: "text/plain",
			}, nil
		}),
	}

	req := httptest.NewRequest("GET", "http://example.com/", nil)
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": {"text/html"}},
		Body:       io.NopCloser(strings.NewReader("contains secret data")),
	}

	result, err := pe.ProcessResponse(context.Background(), req, resp, &RequestContext{})
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(result.Body)
	_ = result.Body.Close()
	if string(body) != "contains REDACTED data" {
		t.Errorf("body = %q, want redacted", body)
	}
	if result.Header.Get("Content-Type") != "text/plain" {
		t.Errorf("Content-Type = %q, want text/plain", result.Header.Get("Content-Type"))
	}
}

func TestPolicyEngine_BodyScanner_ContentTypeFilter(t *testing.T) {
	pe := NewPolicyEngine()
	pe.ScanContentTypes = []string{"application/octet-stream", "application/zip"}
	pe.BodyScanners = []ResponseBodyScanner{
		ResponseBodyScannerFunc(func(_ context.Context, _ []byte, _ *http.Request, _ *http.Response) (ScanResult, error) {
			return ScanResult{Verdict: VerdictBlock, Reason: "scanned"}, nil
		}),
	}

	// text/html should NOT be scanned.
	req := httptest.NewRequest("GET", "http://example.com/", nil)
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": {"text/html"}},
		Body:       io.NopCloser(strings.NewReader("safe")),
	}
	result, err := pe.ProcessResponse(context.Background(), req, resp, &RequestContext{})
	if err != nil {
		t.Fatal(err)
	}
	if result.StatusCode == http.StatusForbidden {
		t.Error("text/html should not be scanned")
	}

	// application/octet-stream SHOULD be scanned.
	resp2 := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": {"application/octet-stream"}},
		Body:       io.NopCloser(strings.NewReader("binary data")),
	}
	result2, err := pe.ProcessResponse(context.Background(), req, resp2, &RequestContext{})
	if err != nil {
		t.Fatal(err)
	}
	if result2.StatusCode != http.StatusForbidden {
		t.Error("application/octet-stream should be scanned and blocked")
	}
	_ = result2.Body.Close()
}

func TestPolicyEngine_BodyScanner_MaxSizeSkip(t *testing.T) {
	pe := NewPolicyEngine()
	pe.MaxScanSize = 10
	scanned := false
	pe.BodyScanners = []ResponseBodyScanner{
		ResponseBodyScannerFunc(func(_ context.Context, _ []byte, _ *http.Request, _ *http.Response) (ScanResult, error) {
			scanned = true
			return ScanResult{Verdict: VerdictAllow}, nil
		}),
	}

	req := httptest.NewRequest("GET", "http://example.com/", nil)
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": {"application/octet-stream"}},
		Body:       io.NopCloser(strings.NewReader("this body is definitely larger than 10 bytes")),
	}

	result, err := pe.ProcessResponse(context.Background(), req, resp, &RequestContext{})
	if err != nil {
		t.Fatal(err)
	}
	if scanned {
		t.Error("body scanner should not run on oversized bodies")
	}
	_ = result.Body.Close()
}

func TestPolicyEngine_BodyScanner_NilBody(t *testing.T) {
	pe := NewPolicyEngine()
	pe.BodyScanners = []ResponseBodyScanner{
		ResponseBodyScannerFunc(func(_ context.Context, _ []byte, _ *http.Request, _ *http.Response) (ScanResult, error) {
			t.Error("should not scan nil body")
			return ScanResult{}, nil
		}),
	}

	req := httptest.NewRequest("GET", "http://example.com/", nil)
	resp := &http.Response{
		StatusCode: 204,
		Header:     http.Header{},
		Body:       nil,
	}

	result, err := pe.ProcessResponse(context.Background(), req, resp, &RequestContext{})
	if err != nil {
		t.Fatal(err)
	}
	if result.StatusCode != 204 {
		t.Errorf("status = %d, want 204", result.StatusCode)
	}
}

func TestPolicyEngine_BodyScanner_MultipleScanners(t *testing.T) {
	pe := NewPolicyEngine()
	pe.BodyScanners = []ResponseBodyScanner{
		ResponseBodyScannerFunc(func(_ context.Context, _ []byte, _ *http.Request, _ *http.Response) (ScanResult, error) {
			return ScanResult{Verdict: VerdictAllow}, nil
		}),
		ResponseBodyScannerFunc(func(_ context.Context, body []byte, _ *http.Request, _ *http.Response) (ScanResult, error) {
			if bytes.Contains(body, []byte("virus")) {
				return ScanResult{Verdict: VerdictBlock, Reason: "scanner2 found virus"}, nil
			}
			return ScanResult{Verdict: VerdictAllow}, nil
		}),
	}

	req := httptest.NewRequest("GET", "http://example.com/", nil)
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": {"text/plain"}},
		Body:       io.NopCloser(strings.NewReader("contains virus")),
	}

	result, err := pe.ProcessResponse(context.Background(), req, resp, &RequestContext{})
	if err != nil {
		t.Fatal(err)
	}
	if result.StatusCode != http.StatusForbidden {
		t.Error("second scanner should block")
	}
	body, _ := io.ReadAll(result.Body)
	_ = result.Body.Close()
	if !strings.Contains(string(body), "scanner2") {
		t.Errorf("body = %q, want scanner2 reason", body)
	}
}

func TestPolicyEngine_BodyScanner_Error(t *testing.T) {
	pe := NewPolicyEngine()
	pe.BodyScanners = []ResponseBodyScanner{
		ResponseBodyScannerFunc(func(_ context.Context, _ []byte, _ *http.Request, _ *http.Response) (ScanResult, error) {
			return ScanResult{}, io.ErrUnexpectedEOF
		}),
	}

	req := httptest.NewRequest("GET", "http://example.com/", nil)
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": {"text/plain"}},
		Body:       io.NopCloser(strings.NewReader("data")),
	}

	_, err := pe.ProcessResponse(context.Background(), req, resp, &RequestContext{})
	if err == nil {
		t.Fatal("expected error from scanner")
	}
}

// ---------------------------------------------------------------------------
// IdentityResolverFunc adapter
// ---------------------------------------------------------------------------

func TestIdentityResolverFunc(t *testing.T) {
	f := IdentityResolverFunc(func(req *http.Request) (string, []string, error) {
		return "func-user", []string{"func-group"}, nil
	})

	req := httptest.NewRequest("GET", "/", nil)
	identity, groups, err := f.Resolve(req)
	if err != nil || identity != "func-user" || len(groups) != 1 {
		t.Errorf("IdentityResolverFunc failed: %q %v %v", identity, groups, err)
	}
}

// ---------------------------------------------------------------------------
// Function adapters
// ---------------------------------------------------------------------------

func TestRequestHookFunc(t *testing.T) {
	called := false
	f := RequestHookFunc(func(_ context.Context, _ *http.Request, _ *RequestContext) *http.Response {
		called = true
		return nil
	})
	f.HandleRequest(context.Background(), httptest.NewRequest("GET", "/", nil), &RequestContext{})
	if !called {
		t.Error("RequestHookFunc not called")
	}
}

func TestResponseHookFunc(t *testing.T) {
	called := false
	f := ResponseHookFunc(func(_ context.Context, _ *http.Request, _ *http.Response, _ *RequestContext) *http.Response {
		called = true
		return nil
	})
	resp := &http.Response{Body: io.NopCloser(strings.NewReader(""))}
	f.HandleResponse(context.Background(), httptest.NewRequest("GET", "/", nil), resp, &RequestContext{})
	if !called {
		t.Error("ResponseHookFunc not called")
	}
}

func TestResponseBodyScannerFunc(t *testing.T) {
	f := ResponseBodyScannerFunc(func(_ context.Context, body []byte, _ *http.Request, _ *http.Response) (ScanResult, error) {
		return ScanResult{Verdict: VerdictAllow}, nil
	})
	result, err := f.Scan(context.Background(), []byte("test"), nil, nil)
	if err != nil || result.Verdict != VerdictAllow {
		t.Error("ResponseBodyScannerFunc failed")
	}
}

// ---------------------------------------------------------------------------
// End-to-end: PolicyEngine with ContentTypeFilter + BodyScanner
// ---------------------------------------------------------------------------

func TestPolicyEngine_EndToEnd_ContentTypeBlockPlusAV(t *testing.T) {
	pe := NewPolicyEngine()

	// Response hook: block executables by content-type.
	ctFilter := NewContentTypeFilter()
	ctFilter.Block("application/x-executable", "executables blocked")
	pe.ResponseHooks = []ResponseHook{ctFilter}

	// Body scanner: block EICAR patterns.
	pe.BodyScanners = []ResponseBodyScanner{
		ResponseBodyScannerFunc(func(_ context.Context, body []byte, _ *http.Request, _ *http.Response) (ScanResult, error) {
			if bytes.Contains(body, []byte("X5O!P%@AP")) {
				return ScanResult{Verdict: VerdictBlock, Reason: "EICAR test string"}, nil
			}
			return ScanResult{Verdict: VerdictAllow}, nil
		}),
	}

	// Case 1: executable content-type → blocked by response hook (never reaches scanner).
	req := httptest.NewRequest("GET", "http://example.com/malware.exe", nil)
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": {"application/x-executable"}},
		Body:       io.NopCloser(strings.NewReader("MZ...")),
	}
	result, err := pe.ProcessResponse(context.Background(), req, resp, &RequestContext{})
	if err != nil {
		t.Fatal(err)
	}
	if result.StatusCode != http.StatusForbidden {
		t.Error("executable should be blocked by content-type hook")
	}
	_ = result.Body.Close()

	// Case 2: text/plain with EICAR → passes hook, blocked by scanner.
	resp2 := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": {"text/plain"}},
		Body:       io.NopCloser(strings.NewReader("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR")),
	}
	result2, err := pe.ProcessResponse(context.Background(), req, resp2, &RequestContext{})
	if err != nil {
		t.Fatal(err)
	}
	if result2.StatusCode != http.StatusForbidden {
		t.Error("EICAR should be blocked by body scanner")
	}
	_ = result2.Body.Close()

	// Case 3: clean text → passes everything.
	resp3 := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": {"text/plain"}},
		Body:       io.NopCloser(strings.NewReader("Hello, World!")),
	}
	result3, err := pe.ProcessResponse(context.Background(), req, resp3, &RequestContext{})
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(result3.Body)
	_ = result3.Body.Close()
	if string(body) != "Hello, World!" {
		t.Errorf("clean body = %q, want Hello, World!", body)
	}
}
