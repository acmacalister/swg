package swg

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newTestAdminAPI(filter Filter) *AdminAPI {
	p := &Proxy{
		Addr:   ":0",
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Filter: filter,
	}
	a := NewAdminAPI(p)
	a.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	return a
}

func doAdmin(t *testing.T, a *AdminAPI, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		r = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, r)
	rec := httptest.NewRecorder()
	a.ServeHTTP(rec, req)
	return rec
}

func decodeJSON[T any](t *testing.T, rec *httptest.ResponseRecorder) T {
	t.Helper()
	var v T
	if err := json.NewDecoder(rec.Body).Decode(&v); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}
	return v
}

// ---------------------------------------------------------------------------
// GET /api/status
// ---------------------------------------------------------------------------

func TestAdminStatus_NoFilter(t *testing.T) {
	a := newTestAdminAPI(nil)
	rec := doAdmin(t, a, http.MethodGet, "/api/status", nil)

	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}

	resp := decodeJSON[StatusResponse](t, rec)
	if resp.Status != "ok" {
		t.Errorf("want status ok, got %q", resp.Status)
	}
	if resp.Filter != "none" {
		t.Errorf("want filter_type none, got %q", resp.Filter)
	}
	if resp.RuleCount != 0 {
		t.Errorf("want rule_count 0, got %d", resp.RuleCount)
	}
}

func TestAdminStatus_RuleSet(t *testing.T) {
	rs := NewRuleSet()
	rs.AddDomain("blocked.com")

	a := newTestAdminAPI(rs)
	rec := doAdmin(t, a, http.MethodGet, "/api/status", nil)

	resp := decodeJSON[StatusResponse](t, rec)
	if resp.Filter != "ruleset" {
		t.Errorf("want filter_type ruleset, got %q", resp.Filter)
	}
	if resp.RuleCount != 1 {
		t.Errorf("want rule_count 1, got %d", resp.RuleCount)
	}
}

func TestAdminStatus_ReloadableFilter(t *testing.T) {
	loader := StaticLoader{
		Rules: []Rule{{Type: "domain", Pattern: "a.com", Reason: "test"}},
	}
	rf := NewReloadableFilter(&loader)
	if err := rf.Load(context.Background()); err != nil {
		t.Fatal(err)
	}

	a := newTestAdminAPI(rf)
	rec := doAdmin(t, a, http.MethodGet, "/api/status", nil)

	resp := decodeJSON[StatusResponse](t, rec)
	if resp.Filter != "reloadable" {
		t.Errorf("want filter_type reloadable, got %q", resp.Filter)
	}
	if resp.RuleCount != 1 {
		t.Errorf("want rule_count 1, got %d", resp.RuleCount)
	}
}

func TestAdminStatus_DomainFilter(t *testing.T) {
	df := NewDomainFilter()
	df.AddDomain("blocked.com")

	a := newTestAdminAPI(df)
	rec := doAdmin(t, a, http.MethodGet, "/api/status", nil)

	resp := decodeJSON[StatusResponse](t, rec)
	if resp.Filter != "domain" {
		t.Errorf("want filter_type domain, got %q", resp.Filter)
	}
	if resp.RuleCount != 0 {
		t.Errorf("want rule_count 0 for DomainFilter, got %d", resp.RuleCount)
	}
}

func TestAdminStatus_Uptime(t *testing.T) {
	a := newTestAdminAPI(nil)
	a.Proxy.HealthChecker = NewHealthChecker()

	rec := doAdmin(t, a, http.MethodGet, "/api/status", nil)
	resp := decodeJSON[StatusResponse](t, rec)

	if resp.Uptime == "" {
		t.Error("want non-empty uptime with HealthChecker")
	}
}

// ---------------------------------------------------------------------------
// Filter type detection
// ---------------------------------------------------------------------------

func TestAdminFilterType(t *testing.T) {
	tests := []struct {
		name   string
		filter Filter
		want   string
	}{
		{"nil", nil, "none"},
		{"ruleset", NewRuleSet(), "ruleset"},
		{"reloadable", NewReloadableFilter(&StaticLoader{}), "reloadable"},
		{"domain", NewDomainFilter(), "domain"},
		{"allowlist", NewAllowListFilter(), "allowlist"},
		{"group", NewGroupPolicyFilter(), "group"},
		{"chain", &ChainFilter{}, "chain"},
		{"custom", FilterFunc(func(*http.Request) (bool, string) { return false, "" }), "custom"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := newTestAdminAPI(tt.filter)
			rec := doAdmin(t, a, http.MethodGet, "/api/status", nil)
			resp := decodeJSON[StatusResponse](t, rec)
			if resp.Filter != tt.want {
				t.Errorf("want %q, got %q", tt.want, resp.Filter)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// GET /api/rules
// ---------------------------------------------------------------------------

func TestAdminListRules_Empty(t *testing.T) {
	a := newTestAdminAPI(NewRuleSet())
	rec := doAdmin(t, a, http.MethodGet, "/api/rules", nil)

	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}

	resp := decodeJSON[RulesResponse](t, rec)
	if resp.Count != 0 {
		t.Errorf("want count 0, got %d", resp.Count)
	}
	if len(resp.Rules) != 0 {
		t.Errorf("want 0 rules, got %d", len(resp.Rules))
	}
}

func TestAdminListRules_Populated(t *testing.T) {
	rs := NewRuleSet()
	rs.AddDomain("a.com")
	rs.AddDomain("*.b.com")
	rs.AddURL("https://c.com/path")
	if err := rs.AddRegex(".*tracking.*"); err != nil {
		t.Fatal(err)
	}

	a := newTestAdminAPI(rs)
	rec := doAdmin(t, a, http.MethodGet, "/api/rules", nil)

	resp := decodeJSON[RulesResponse](t, rec)
	if resp.Count != 4 {
		t.Errorf("want count 4, got %d", resp.Count)
	}
	if len(resp.Rules) != 4 {
		t.Errorf("want 4 rules, got %d", len(resp.Rules))
	}
}

func TestAdminListRules_NonRuleSetFilter(t *testing.T) {
	df := NewDomainFilter()
	df.AddDomain("test.com")

	a := newTestAdminAPI(df)
	rec := doAdmin(t, a, http.MethodGet, "/api/rules", nil)

	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}

	resp := decodeJSON[RulesResponse](t, rec)
	if resp.Count != 0 {
		t.Errorf("want count 0 for DomainFilter, got %d", resp.Count)
	}
}

func TestAdminListRules_ReloadableFilter(t *testing.T) {
	loader := StaticLoader{
		Rules: []Rule{
			{Type: "domain", Pattern: "x.com", Reason: "test"},
			{Type: "domain", Pattern: "y.com", Reason: "test"},
		},
	}
	rf := NewReloadableFilter(&loader)
	if err := rf.Load(context.Background()); err != nil {
		t.Fatal(err)
	}

	a := newTestAdminAPI(rf)
	rec := doAdmin(t, a, http.MethodGet, "/api/rules", nil)

	resp := decodeJSON[RulesResponse](t, rec)
	if resp.Count != 2 {
		t.Errorf("want count 2, got %d", resp.Count)
	}
}

// ---------------------------------------------------------------------------
// POST /api/rules
// ---------------------------------------------------------------------------

func TestAdminAddRule_Domain(t *testing.T) {
	a := newTestAdminAPI(NewRuleSet())
	rec := doAdmin(t, a, http.MethodPost, "/api/rules", RuleRequest{
		Type:    "domain",
		Pattern: "evil.com",
		Reason:  "malware",
	})

	if rec.Code != http.StatusCreated {
		t.Fatalf("want 201, got %d: %s", rec.Code, rec.Body.String())
	}

	rec = doAdmin(t, a, http.MethodGet, "/api/rules", nil)
	resp := decodeJSON[RulesResponse](t, rec)
	if resp.Count != 1 {
		t.Errorf("want 1 rule after add, got %d", resp.Count)
	}
}

func TestAdminAddRule_URL(t *testing.T) {
	a := newTestAdminAPI(NewRuleSet())
	rec := doAdmin(t, a, http.MethodPost, "/api/rules", RuleRequest{
		Type:    "url",
		Pattern: "https://bad.com/path",
	})

	if rec.Code != http.StatusCreated {
		t.Fatalf("want 201, got %d", rec.Code)
	}
}

func TestAdminAddRule_Regex(t *testing.T) {
	a := newTestAdminAPI(NewRuleSet())
	rec := doAdmin(t, a, http.MethodPost, "/api/rules", RuleRequest{
		Type:    "regex",
		Pattern: ".*ads.*",
	})

	if rec.Code != http.StatusCreated {
		t.Fatalf("want 201, got %d", rec.Code)
	}
}

func TestAdminAddRule_InvalidJSON(t *testing.T) {
	a := newTestAdminAPI(NewRuleSet())
	req := httptest.NewRequest(http.MethodPost, "/api/rules", bytes.NewReader([]byte("not json")))
	rec := httptest.NewRecorder()
	a.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", rec.Code)
	}
}

func TestAdminAddRule_MissingFields(t *testing.T) {
	a := newTestAdminAPI(NewRuleSet())

	tests := []struct {
		name string
		body RuleRequest
	}{
		{"missing type", RuleRequest{Pattern: "foo.com"}},
		{"missing pattern", RuleRequest{Type: "domain"}},
		{"missing both", RuleRequest{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := doAdmin(t, a, http.MethodPost, "/api/rules", tt.body)
			if rec.Code != http.StatusBadRequest {
				t.Errorf("want 400, got %d", rec.Code)
			}
		})
	}
}

func TestAdminAddRule_InvalidType(t *testing.T) {
	a := newTestAdminAPI(NewRuleSet())
	rec := doAdmin(t, a, http.MethodPost, "/api/rules", RuleRequest{
		Type:    "invalid",
		Pattern: "something",
	})

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for invalid type, got %d", rec.Code)
	}
}

func TestAdminAddRule_InvalidRegex(t *testing.T) {
	a := newTestAdminAPI(NewRuleSet())
	rec := doAdmin(t, a, http.MethodPost, "/api/rules", RuleRequest{
		Type:    "regex",
		Pattern: "[invalid",
	})

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for invalid regex, got %d", rec.Code)
	}
}

func TestAdminAddRule_DefaultReason(t *testing.T) {
	rs := NewRuleSet()
	a := newTestAdminAPI(rs)
	doAdmin(t, a, http.MethodPost, "/api/rules", RuleRequest{
		Type:    "domain",
		Pattern: "test.com",
	})

	rules := rs.Rules()
	if len(rules) != 1 {
		t.Fatalf("want 1 rule, got %d", len(rules))
	}
	if rules[0].Reason != "added via admin API" {
		t.Errorf("want default reason, got %q", rules[0].Reason)
	}
}

func TestAdminAddRule_NoRuleSet(t *testing.T) {
	a := newTestAdminAPI(NewDomainFilter())
	rec := doAdmin(t, a, http.MethodPost, "/api/rules", RuleRequest{
		Type:    "domain",
		Pattern: "test.com",
	})

	if rec.Code != http.StatusConflict {
		t.Fatalf("want 409, got %d", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// DELETE /api/rules
// ---------------------------------------------------------------------------

func TestAdminDeleteRule_Existing(t *testing.T) {
	rs := NewRuleSet()
	rs.AddDomain("evil.com")

	a := newTestAdminAPI(rs)
	rec := doAdmin(t, a, http.MethodDelete, "/api/rules", RuleRequest{
		Type:    "domain",
		Pattern: "evil.com",
	})

	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body.String())
	}

	if rs.Count() != 0 {
		t.Errorf("want 0 rules after delete, got %d", rs.Count())
	}
}

func TestAdminDeleteRule_NotFound(t *testing.T) {
	a := newTestAdminAPI(NewRuleSet())
	rec := doAdmin(t, a, http.MethodDelete, "/api/rules", RuleRequest{
		Type:    "domain",
		Pattern: "nonexistent.com",
	})

	if rec.Code != http.StatusNotFound {
		t.Fatalf("want 404, got %d", rec.Code)
	}
}

func TestAdminDeleteRule_InvalidJSON(t *testing.T) {
	a := newTestAdminAPI(NewRuleSet())
	req := httptest.NewRequest(http.MethodDelete, "/api/rules", bytes.NewReader([]byte("{bad")))
	rec := httptest.NewRecorder()
	a.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", rec.Code)
	}
}

func TestAdminDeleteRule_MissingFields(t *testing.T) {
	a := newTestAdminAPI(NewRuleSet())
	rec := doAdmin(t, a, http.MethodDelete, "/api/rules", RuleRequest{
		Type: "domain",
	})

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", rec.Code)
	}
}

func TestAdminDeleteRule_NoRuleSet(t *testing.T) {
	a := newTestAdminAPI(NewDomainFilter())
	rec := doAdmin(t, a, http.MethodDelete, "/api/rules", RuleRequest{
		Type:    "domain",
		Pattern: "test.com",
	})

	if rec.Code != http.StatusConflict {
		t.Fatalf("want 409, got %d", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// POST /api/reload
// ---------------------------------------------------------------------------

func TestAdminReload_Success(t *testing.T) {
	a := newTestAdminAPI(NewRuleSet())
	called := false
	a.ReloadFunc = func(_ context.Context) error {
		called = true
		return nil
	}

	rec := doAdmin(t, a, http.MethodPost, "/api/reload", nil)

	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	if !called {
		t.Error("ReloadFunc not called")
	}
}

func TestAdminReload_Error(t *testing.T) {
	a := newTestAdminAPI(NewRuleSet())
	a.ReloadFunc = func(_ context.Context) error {
		return errors.New("db unavailable")
	}

	rec := doAdmin(t, a, http.MethodPost, "/api/reload", nil)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("want 500, got %d", rec.Code)
	}

	resp := decodeJSON[ErrorResponse](t, rec)
	if resp.Error != "reload failed: db unavailable" {
		t.Errorf("unexpected error: %q", resp.Error)
	}
}

func TestAdminReload_NotConfigured(t *testing.T) {
	a := newTestAdminAPI(NewRuleSet())

	rec := doAdmin(t, a, http.MethodPost, "/api/reload", nil)

	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("want 501, got %d", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// JSON content-type header
// ---------------------------------------------------------------------------

func TestAdminContentType(t *testing.T) {
	a := newTestAdminAPI(nil)
	rec := doAdmin(t, a, http.MethodGet, "/api/status", nil)

	ct := rec.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("want application/json, got %q", ct)
	}
}

// ---------------------------------------------------------------------------
// ServeHTTP dispatch via proxy
// ---------------------------------------------------------------------------

func TestProxyServeHTTP_AdminDispatch(t *testing.T) {
	p := &Proxy{
		Addr:   ":0",
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Filter: NewRuleSet(),
	}
	p.Admin = NewAdminAPI(p)
	p.Admin.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))

	req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}

	resp := decodeJSON[StatusResponse](t, rec)
	if resp.Status != "ok" {
		t.Errorf("want status ok, got %q", resp.Status)
	}
}

func TestProxyServeHTTP_AdminNotTriggeredForCONNECT(t *testing.T) {
	p := &Proxy{
		Addr:   ":0",
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Filter: NewRuleSet(),
	}
	p.Admin = NewAdminAPI(p)
	p.Admin.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))

	req := httptest.NewRequest(http.MethodConnect, "/api/status", nil)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)

	// CONNECT should not route to admin — it goes to handleConnect which will
	// fail without a real connection, but should NOT return 200 status JSON
	if rec.Code == http.StatusOK {
		var resp StatusResponse
		if json.NewDecoder(rec.Body).Decode(&resp) == nil && resp.Status == "ok" {
			t.Error("CONNECT should not dispatch to admin API")
		}
	}
}

// ---------------------------------------------------------------------------
// RuleSet.Rules() and RuleSet.RemoveRule()
// ---------------------------------------------------------------------------

func TestRuleSetRules_Snapshot(t *testing.T) {
	rs := NewRuleSet()
	rs.AddDomain("a.com")
	rs.AddDomain("*.b.com")
	rs.AddURL("https://c.com/path")
	if err := rs.AddRegex(".*d.*"); err != nil {
		t.Fatal(err)
	}

	rules := rs.Rules()
	if len(rules) != 4 {
		t.Fatalf("want 4 rules, got %d", len(rules))
	}

	types := map[string]int{}
	for _, r := range rules {
		types[r.Type]++
	}
	if types["domain"] != 2 {
		t.Errorf("want 2 domain rules, got %d", types["domain"])
	}
	if types["url"] != 1 {
		t.Errorf("want 1 url rule, got %d", types["url"])
	}
	if types["regex"] != 1 {
		t.Errorf("want 1 regex rule, got %d", types["regex"])
	}
}

func TestRuleSetRemoveRule(t *testing.T) {
	tests := []struct {
		name      string
		setup     func(rs *RuleSet)
		ruleType  string
		pattern   string
		wantFound bool
		wantCount int
	}{
		{
			name:      "remove exact domain",
			setup:     func(rs *RuleSet) { rs.AddDomain("evil.com") },
			ruleType:  "domain",
			pattern:   "evil.com",
			wantFound: true,
			wantCount: 0,
		},
		{
			name:      "remove wildcard domain",
			setup:     func(rs *RuleSet) { rs.AddDomain("*.ads.com") },
			ruleType:  "domain",
			pattern:   "*.ads.com",
			wantFound: true,
			wantCount: 0,
		},
		{
			name:      "remove url prefix",
			setup:     func(rs *RuleSet) { rs.AddURL("https://bad.com/path") },
			ruleType:  "url",
			pattern:   "https://bad.com/path",
			wantFound: true,
			wantCount: 0,
		},
		{
			name: "remove regex",
			setup: func(rs *RuleSet) {
				if err := rs.AddRegex(".*track.*"); err != nil {
					panic(err)
				}
			},
			ruleType:  "regex",
			pattern:   ".*track.*",
			wantFound: true,
			wantCount: 0,
		},
		{
			name:      "remove nonexistent domain",
			setup:     func(rs *RuleSet) { rs.AddDomain("other.com") },
			ruleType:  "domain",
			pattern:   "nope.com",
			wantFound: false,
			wantCount: 1,
		},
		{
			name:      "remove nonexistent type",
			setup:     func(rs *RuleSet) { rs.AddDomain("test.com") },
			ruleType:  "unknown",
			pattern:   "test.com",
			wantFound: false,
			wantCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rs := NewRuleSet()
			tt.setup(rs)
			got := rs.RemoveRule(tt.ruleType, tt.pattern)
			if got != tt.wantFound {
				t.Errorf("RemoveRule returned %v, want %v", got, tt.wantFound)
			}
			if rs.Count() != tt.wantCount {
				t.Errorf("count after remove: got %d, want %d", rs.Count(), tt.wantCount)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// ReloadableFilter.RuleSet()
// ---------------------------------------------------------------------------

func TestReloadableFilterRuleSet(t *testing.T) {
	loader := StaticLoader{
		Rules: []Rule{
			{Type: "domain", Pattern: "a.com", Reason: "test"},
		},
	}
	rf := NewReloadableFilter(&loader)
	if err := rf.Load(context.Background()); err != nil {
		t.Fatal(err)
	}

	rs := rf.RuleSet()
	if rs == nil {
		t.Fatal("RuleSet() returned nil")
	}
	if rs.Count() != 1 {
		t.Errorf("want count 1, got %d", rs.Count())
	}

	rs.AddDomain("b.com")
	if rf.Count() != 2 {
		t.Errorf("mutations through RuleSet() should be visible: want 2, got %d", rf.Count())
	}
}

// ---------------------------------------------------------------------------
// Custom path prefix
// ---------------------------------------------------------------------------

func TestAdminCustomPrefix(t *testing.T) {
	p := &Proxy{
		Addr:   ":0",
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	a := NewAdminAPI(p)
	a.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	a.PathPrefix = "/admin"
	a.buildRouter()

	req := httptest.NewRequest(http.MethodGet, "/admin/status", nil)
	rec := httptest.NewRecorder()
	a.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// Full CRUD round-trip
// ---------------------------------------------------------------------------

func TestAdminCRUDRoundTrip(t *testing.T) {
	a := newTestAdminAPI(NewRuleSet())

	rec := doAdmin(t, a, http.MethodPost, "/api/rules", RuleRequest{
		Type:     "domain",
		Pattern:  "evil.com",
		Reason:   "malware",
		Category: "security",
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("add: want 201, got %d", rec.Code)
	}

	rec = doAdmin(t, a, http.MethodGet, "/api/rules", nil)
	rules := decodeJSON[RulesResponse](t, rec)
	if rules.Count != 1 {
		t.Fatalf("list after add: want 1, got %d", rules.Count)
	}
	if rules.Rules[0].Pattern != "evil.com" {
		t.Errorf("want pattern evil.com, got %q", rules.Rules[0].Pattern)
	}
	if rules.Rules[0].Reason != "malware" {
		t.Errorf("want reason malware, got %q", rules.Rules[0].Reason)
	}
	if rules.Rules[0].Category != "security" {
		t.Errorf("want category security, got %q", rules.Rules[0].Category)
	}

	rec = doAdmin(t, a, http.MethodDelete, "/api/rules", RuleRequest{
		Type:    "domain",
		Pattern: "evil.com",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("delete: want 200, got %d", rec.Code)
	}

	rec = doAdmin(t, a, http.MethodGet, "/api/rules", nil)
	rules = decodeJSON[RulesResponse](t, rec)
	if rules.Count != 0 {
		t.Fatalf("list after delete: want 0, got %d", rules.Count)
	}
}
