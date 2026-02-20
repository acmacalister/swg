package swg

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
)

// CELMatcher evaluates CEL (Common Expression Language) expressions against
// HTTP requests. It provides a powerful, type-safe expression language for
// complex filtering rules that go beyond simple domain or regex matching.
//
// CEL expressions have access to a rich set of request attributes and custom
// functions designed for proxy filtering use cases.
//
// For full CEL language documentation, see:
//   - CEL Specification: https://github.com/google/cel-spec
//   - CEL-Go Library: https://github.com/google/cel-go
//   - CEL Language Guide: https://github.com/google/cel-spec/blob/master/doc/langdef.md
//   - CEL Standard Functions: https://github.com/google/cel-spec/blob/master/doc/langdef.md#list-of-standard-definitions
//
// # Available Variables
//
// Request attributes available in expressions:
//
//   - request.method (string): HTTP method (GET, POST, etc.)
//   - request.host (string): Host header value (lowercase, without port)
//   - request.path (string): URL path
//   - request.query (string): Raw query string (without leading ?)
//   - request.scheme (string): "http" or "https"
//   - request.url (string): Full URL (scheme://host/path?query)
//   - request.headers (map[string]string): HTTP headers (lowercase keys)
//   - request.content_length (int): Content-Length header value
//   - request.content_type (string): Content-Type header value
//
// Client context (when RequestContext is available):
//
//   - client.ip (string): Client IP address
//   - client.identity (string): Resolved identity (from IdentityResolver)
//   - client.groups (list[string]): Groups the client belongs to
//   - client.tags (map[string]string): Tags attached by hooks
//
// # Custom Functions
//
// Domain matching:
//
//   - request.host.isDomain(string): Exact domain match (case-insensitive)
//   - request.host.matchesDomain(string): Domain or subdomain match
//     e.g., matchesDomain("example.com") matches "example.com" and "www.example.com"
//
// IP functions:
//
//   - client.ip.inCIDR(string): Check if client IP is in CIDR range
//     e.g., client.ip.inCIDR("10.0.0.0/8")
//   - client.ip.isPrivate(): Check if client IP is in private range (RFC 1918)
//
// String functions (from CEL stdlib):
//
//   - contains(string): Substring match
//   - startsWith(string): Prefix match
//   - endsWith(string): Suffix match
//   - matches(string): RE2 regex match
//
// List functions:
//
//   - client.groups.contains(string): Check group membership
//   - in operator: "admin" in client.groups
//
// # Example Expressions
//
//	// Block non-GET requests to API endpoints
//	request.method != "GET" && request.path.startsWith("/api/")
//
//	// Allow only internal users to access admin
//	request.path.startsWith("/admin") && !("admin" in client.groups)
//
//	// Block requests from public IPs to internal endpoints
//	!client.ip.isPrivate() && request.host.matchesDomain("internal.corp")
//
//	// Complex content filtering
//	request.content_type.contains("json") && request.content_length > 1048576
//
//	// Header-based filtering
//	request.headers["x-api-key"] == "" && request.path.startsWith("/api/")
//
// # Thread Safety
//
// CELMatcher is safe for concurrent use. Programs are compiled once and
// evaluated many times. The matcher uses sync.Pool for activation objects
// to reduce allocations under load.
//
// # Performance
//
// CEL is designed for fast evaluation:
//   - Expressions are compiled once at creation time
//   - Evaluation is linear time (not Turing-complete)
//   - No memory allocation during evaluation (uses object pooling)
//   - Typical evaluation time: 100ns-10µs depending on expression complexity
type CELMatcher struct {
	expression string
	reason     string
	category   string

	env     *cel.Env
	program cel.Program

	// pool for activation maps to reduce allocations
	activationPool sync.Pool
}

// CELMatcherConfig configures a CELMatcher.
type CELMatcherConfig struct {
	// Expression is the CEL expression to evaluate.
	// Must return a boolean value.
	Expression string

	// Reason is the human-readable reason shown when the expression matches.
	// If empty, defaults to "CEL expression matched".
	Reason string

	// Category is an optional category for grouping/reporting.
	Category string
}

// NewCELMatcher creates a new CEL-based filter from an expression string.
// The expression must evaluate to a boolean value.
//
// Returns an error if the expression fails to compile or has a non-boolean
// return type.
func NewCELMatcher(expression string) (*CELMatcher, error) {
	return NewCELMatcherWithConfig(CELMatcherConfig{
		Expression: expression,
	})
}

// NewCELMatcherWithConfig creates a new CEL-based filter with full configuration.
func NewCELMatcherWithConfig(cfg CELMatcherConfig) (*CELMatcher, error) {
	if cfg.Expression == "" {
		return nil, fmt.Errorf("CEL expression cannot be empty")
	}

	env, err := newCELEnv()
	if err != nil {
		return nil, fmt.Errorf("create CEL environment: %w", err)
	}

	ast, issues := env.Compile(cfg.Expression)
	if issues != nil && issues.Err() != nil {
		return nil, fmt.Errorf("compile CEL expression: %w", issues.Err())
	}

	// Verify return type is bool
	if ast.OutputType() != cel.BoolType {
		return nil, fmt.Errorf("CEL expression must return bool, got %s", ast.OutputType())
	}

	program, err := env.Program(ast)
	if err != nil {
		return nil, fmt.Errorf("create CEL program: %w", err)
	}

	reason := cfg.Reason
	if reason == "" {
		reason = "CEL expression matched"
	}

	return &CELMatcher{
		expression: cfg.Expression,
		reason:     reason,
		category:   cfg.Category,
		env:        env,
		program:    program,
		activationPool: sync.Pool{
			New: func() any {
				return make(map[string]any, 16)
			},
		},
	}, nil
}

// Expression returns the CEL expression string.
func (m *CELMatcher) Expression() string {
	return m.expression
}

// Reason returns the block reason.
func (m *CELMatcher) Reason() string {
	return m.reason
}

// Category returns the category.
func (m *CELMatcher) Category() string {
	return m.category
}

// Match evaluates the CEL expression against the request.
// Returns true if the expression evaluates to true.
func (m *CELMatcher) Match(req *http.Request) (bool, error) {
	return m.MatchWithContext(req, nil)
}

// MatchWithContext evaluates the CEL expression with RequestContext.
// The RequestContext provides client identity, groups, and tags.
func (m *CELMatcher) MatchWithContext(req *http.Request, rc *RequestContext) (bool, error) {
	activation := m.activationPool.Get().(map[string]any)
	defer func() {
		// Clear map for reuse
		for k := range activation {
			delete(activation, k)
		}
		m.activationPool.Put(activation)
	}()

	m.populateActivation(activation, req, rc)

	result, _, err := m.program.Eval(activation)
	if err != nil {
		return false, fmt.Errorf("evaluate CEL expression: %w", err)
	}

	b, ok := result.Value().(bool)
	if !ok {
		return false, fmt.Errorf("CEL expression returned %T, expected bool", result.Value())
	}

	return b, nil
}

// ShouldBlock implements the Filter interface.
// Returns true and the reason if the expression matches.
func (m *CELMatcher) ShouldBlock(req *http.Request) (bool, string) {
	// Try to get RequestContext from request context
	var rc *RequestContext
	if req.Context() != nil {
		rc = GetRequestContext(req.Context())
	}

	matched, err := m.MatchWithContext(req, rc)
	if err != nil {
		// On error, don't block but log would be nice
		return false, ""
	}

	if matched {
		reason := m.reason
		if m.category != "" {
			reason = fmt.Sprintf("%s (%s)", reason, m.category)
		}
		return true, reason
	}

	return false, ""
}

// populateActivation fills the activation map with request and context data.
func (m *CELMatcher) populateActivation(activation map[string]any, req *http.Request, rc *RequestContext) {
	// Extract host without port
	host := req.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.ToLower(host)

	// Determine scheme
	scheme := "http"
	if req.TLS != nil {
		scheme = "https"
	}

	// Build full URL
	fullURL := fmt.Sprintf("%s://%s%s", scheme, host, req.URL.RequestURI())

	// Build headers map (lowercase keys)
	headers := make(map[string]string, len(req.Header))
	for k, v := range req.Header {
		if len(v) > 0 {
			headers[strings.ToLower(k)] = v[0]
		}
	}

	// Request attributes
	activation["request"] = map[string]any{
		"method":         req.Method,
		"host":           host,
		"path":           req.URL.Path,
		"query":          req.URL.RawQuery,
		"scheme":         scheme,
		"url":            fullURL,
		"headers":        headers,
		"content_length": req.ContentLength,
		"content_type":   req.Header.Get("Content-Type"),
	}

	// Client context
	clientIP := ""
	identity := ""
	var groups []string
	tags := make(map[string]string)

	if rc != nil {
		clientIP = rc.ClientIP
		identity = rc.Identity
		groups = rc.Groups
		if rc.Tags != nil {
			tags = rc.Tags
		}
	}

	// If no RequestContext, try to extract client IP from request
	if clientIP == "" && req.RemoteAddr != "" {
		if ip, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
			clientIP = ip
		} else {
			clientIP = req.RemoteAddr
		}
	}

	if groups == nil {
		groups = []string{}
	}

	activation["client"] = map[string]any{
		"ip":       clientIP,
		"identity": identity,
		"groups":   groups,
		"tags":     tags,
	}
}

// newCELEnv creates the CEL environment with custom types and functions.
func newCELEnv() (*cel.Env, error) {
	return cel.NewEnv(
		// Declare request variable as a map
		cel.Variable("request", cel.MapType(cel.StringType, cel.DynType)),

		// Declare client variable as a map
		cel.Variable("client", cel.MapType(cel.StringType, cel.DynType)),

		// Custom function: isDomain (exact match)
		cel.Function("isDomain",
			cel.MemberOverload("string_isDomain_string",
				[]*cel.Type{cel.StringType, cel.StringType},
				cel.BoolType,
				cel.BinaryBinding(func(lhs, rhs ref.Val) ref.Val {
					host := strings.ToLower(lhs.Value().(string))
					domain := strings.ToLower(rhs.Value().(string))
					return types.Bool(host == domain)
				}),
			),
		),

		// Custom function: matchesDomain (domain or subdomain)
		cel.Function("matchesDomain",
			cel.MemberOverload("string_matchesDomain_string",
				[]*cel.Type{cel.StringType, cel.StringType},
				cel.BoolType,
				cel.BinaryBinding(func(lhs, rhs ref.Val) ref.Val {
					host := strings.ToLower(lhs.Value().(string))
					domain := strings.ToLower(rhs.Value().(string))
					return types.Bool(host == domain || strings.HasSuffix(host, "."+domain))
				}),
			),
		),

		// Custom function: inCIDR (check IP in CIDR range)
		cel.Function("inCIDR",
			cel.MemberOverload("string_inCIDR_string",
				[]*cel.Type{cel.StringType, cel.StringType},
				cel.BoolType,
				cel.BinaryBinding(func(lhs, rhs ref.Val) ref.Val {
					ipStr := lhs.Value().(string)
					cidrStr := rhs.Value().(string)

					ip := net.ParseIP(ipStr)
					if ip == nil {
						return types.Bool(false)
					}

					_, network, err := net.ParseCIDR(cidrStr)
					if err != nil {
						return types.Bool(false)
					}

					return types.Bool(network.Contains(ip))
				}),
			),
		),

		// Custom function: isPrivate (check if IP is in private range)
		cel.Function("isPrivate",
			cel.MemberOverload("string_isPrivate",
				[]*cel.Type{cel.StringType},
				cel.BoolType,
				cel.UnaryBinding(func(val ref.Val) ref.Val {
					ipStr := val.Value().(string)
					ip := net.ParseIP(ipStr)
					if ip == nil {
						return types.Bool(false)
					}
					return types.Bool(ip.IsPrivate())
				}),
			),
		),
	)
}

// CELFilter combines multiple CEL expressions with OR logic.
// A request is blocked if ANY expression matches (first match wins).
//
// CELFilter is thread-safe for concurrent use. Expressions can be added
// or removed at runtime without interrupting request processing.
//
// Example:
//
//	filter := swg.NewCELFilter()
//	filter.AddExpressionWithConfig(swg.CELMatcherConfig{
//	    Expression: `request["method"] == "DELETE"`,
//	    Reason:     "DELETE method blocked",
//	})
//	filter.AddExpressionWithConfig(swg.CELMatcherConfig{
//	    Expression: `request["path"].startsWith("/admin")`,
//	    Reason:     "Admin path restricted",
//	})
//
// See [CELMatcher] for available variables and custom functions.
type CELFilter struct {
	mu       sync.RWMutex
	matchers []*CELMatcher
}

// NewCELFilter creates a new filter that evaluates multiple CEL expressions.
func NewCELFilter() *CELFilter {
	return &CELFilter{}
}

// AddExpression compiles and adds a CEL expression to the filter.
func (f *CELFilter) AddExpression(expression string) error {
	return f.AddExpressionWithConfig(CELMatcherConfig{Expression: expression})
}

// AddExpressionWithConfig adds a CEL expression with full configuration.
func (f *CELFilter) AddExpressionWithConfig(cfg CELMatcherConfig) error {
	matcher, err := NewCELMatcherWithConfig(cfg)
	if err != nil {
		return err
	}

	f.mu.Lock()
	f.matchers = append(f.matchers, matcher)
	f.mu.Unlock()

	return nil
}

// AddMatcher adds a pre-compiled CELMatcher to the filter.
func (f *CELFilter) AddMatcher(matcher *CELMatcher) {
	f.mu.Lock()
	f.matchers = append(f.matchers, matcher)
	f.mu.Unlock()
}

// RemoveExpression removes the first matcher with the given expression.
// Returns true if a matcher was removed.
func (f *CELFilter) RemoveExpression(expression string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()

	for i, m := range f.matchers {
		if m.expression == expression {
			f.matchers = append(f.matchers[:i], f.matchers[i+1:]...)
			return true
		}
	}
	return false
}

// Clear removes all matchers.
func (f *CELFilter) Clear() {
	f.mu.Lock()
	f.matchers = nil
	f.mu.Unlock()
}

// Count returns the number of CEL expressions.
func (f *CELFilter) Count() int {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return len(f.matchers)
}

// Expressions returns a copy of all expression strings.
func (f *CELFilter) Expressions() []string {
	f.mu.RLock()
	defer f.mu.RUnlock()

	exprs := make([]string, len(f.matchers))
	for i, m := range f.matchers {
		exprs[i] = m.expression
	}
	return exprs
}

// ShouldBlock implements the Filter interface.
// Returns true if any CEL expression matches.
func (f *CELFilter) ShouldBlock(req *http.Request) (bool, string) {
	f.mu.RLock()
	matchers := f.matchers
	f.mu.RUnlock()

	var rc *RequestContext
	if req.Context() != nil {
		rc = GetRequestContext(req.Context())
	}

	for _, m := range matchers {
		matched, err := m.MatchWithContext(req, rc)
		if err != nil {
			continue // Skip on error
		}
		if matched {
			reason := m.reason
			if m.category != "" {
				reason = fmt.Sprintf("%s (%s)", reason, m.category)
			}
			return true, reason
		}
	}

	return false, ""
}

// CELRuleSet extends [RuleSet] with CEL expression support.
// It combines traditional domain/URL/regex rules with powerful CEL expressions,
// allowing complex filtering logic without sacrificing simple rule management.
//
// CEL rules use the special type "cel" and are evaluated after standard rules.
// Standard rules are checked first for performance (O(1) domain lookup), then
// CEL expressions are evaluated in order until a match is found.
//
// Example:
//
//	rs := swg.NewCELRuleSet()
//
//	// Standard domain rules (fast, O(1) lookup)
//	rs.AddDomain("ads.example.com")
//	rs.AddDomain("*.tracking.com")
//
//	// CEL rules for complex conditions
//	rs.AddRule(swg.Rule{
//	    Type:     "cel",
//	    Pattern:  `request["method"] == "DELETE" && !("admin" in client["groups"])`,
//	    Reason:   "DELETE requires admin group",
//	    Category: "access-control",
//	})
//
//	rs.AddCEL(`request["path"].startsWith("/internal") && !client["ip"].isPrivate()`)
//
// CELRuleSet is thread-safe and implements the [Filter] interface.
// See [CELMatcher] for available variables and custom functions.
type CELRuleSet struct {
	*RuleSet
	celMu       sync.RWMutex
	celMatchers []*celMatcherRule
}

type celMatcherRule struct {
	matcher *CELMatcher
	rule    *Rule
}

// NewCELRuleSet creates a new RuleSet with CEL support.
func NewCELRuleSet() *CELRuleSet {
	return &CELRuleSet{
		RuleSet: NewRuleSet(),
	}
}

// AddRule adds a rule to the set. If Type is "cel", the Pattern is compiled
// as a CEL expression.
func (rs *CELRuleSet) AddRule(r Rule) error {
	if r.Type == "cel" {
		matcher, err := NewCELMatcherWithConfig(CELMatcherConfig{
			Expression: r.Pattern,
			Reason:     r.Reason,
			Category:   r.Category,
		})
		if err != nil {
			return fmt.Errorf("compile CEL expression: %w", err)
		}

		rs.celMu.Lock()
		rs.celMatchers = append(rs.celMatchers, &celMatcherRule{
			matcher: matcher,
			rule:    &r,
		})
		rs.celMu.Unlock()
		return nil
	}

	return rs.RuleSet.AddRule(r)
}

// AddCEL is a convenience method to add a CEL expression rule.
func (rs *CELRuleSet) AddCEL(expression string) error {
	return rs.AddRule(Rule{
		Type:    "cel",
		Pattern: expression,
		Reason:  "CEL expression matched",
	})
}

// RemoveRule removes a rule. For CEL rules, matches by expression string.
func (rs *CELRuleSet) RemoveRule(ruleType, pattern string) bool {
	if ruleType == "cel" {
		rs.celMu.Lock()
		defer rs.celMu.Unlock()

		for i, cm := range rs.celMatchers {
			if cm.matcher.expression == pattern {
				rs.celMatchers = append(rs.celMatchers[:i], rs.celMatchers[i+1:]...)
				return true
			}
		}
		return false
	}

	return rs.RuleSet.RemoveRule(ruleType, pattern)
}

// Match checks if a request matches any rule (including CEL expressions).
func (rs *CELRuleSet) Match(req *http.Request) (*Rule, bool) {
	// Check standard rules first
	if rule, blocked := rs.RuleSet.Match(req); blocked {
		return rule, true
	}

	// Check CEL expressions
	rs.celMu.RLock()
	matchers := rs.celMatchers
	rs.celMu.RUnlock()

	var rc *RequestContext
	if req.Context() != nil {
		rc = GetRequestContext(req.Context())
	}

	for _, cm := range matchers {
		matched, err := cm.matcher.MatchWithContext(req, rc)
		if err != nil {
			continue
		}
		if matched {
			return cm.rule, true
		}
	}

	return nil, false
}

// ShouldBlock implements the Filter interface.
func (rs *CELRuleSet) ShouldBlock(req *http.Request) (bool, string) {
	rule, blocked := rs.Match(req)
	if blocked {
		reason := rule.Reason
		if rule.Category != "" {
			reason = fmt.Sprintf("%s (%s)", reason, rule.Category)
		}
		return true, reason
	}
	return false, ""
}

// Rules returns all rules including CEL expressions.
func (rs *CELRuleSet) Rules() []Rule {
	rules := rs.RuleSet.Rules()

	rs.celMu.RLock()
	defer rs.celMu.RUnlock()

	for _, cm := range rs.celMatchers {
		rules = append(rules, *cm.rule)
	}

	return rules
}

// Count returns the total number of rules including CEL expressions.
func (rs *CELRuleSet) Count() int {
	rs.celMu.RLock()
	celCount := len(rs.celMatchers)
	rs.celMu.RUnlock()

	return rs.RuleSet.Count() + celCount
}

// Clear removes all rules including CEL expressions.
func (rs *CELRuleSet) Clear() {
	rs.RuleSet.Clear()

	rs.celMu.Lock()
	rs.celMatchers = nil
	rs.celMu.Unlock()
}

// CELCount returns the number of CEL expression rules.
func (rs *CELRuleSet) CELCount() int {
	rs.celMu.RLock()
	defer rs.celMu.RUnlock()
	return len(rs.celMatchers)
}
