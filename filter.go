package swg

import (
	"bufio"
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Rule represents a blocking rule that can match domains, URLs, or patterns.
type Rule struct {
	// Type of rule: "domain", "url", "regex"
	Type string

	// Pattern is the matching pattern (domain, URL prefix, or regex)
	Pattern string

	// Reason for blocking (shown to user)
	Reason string

	// Category for grouping/reporting (optional)
	Category string

	// compiled regex for Type="regex"
	compiledRegex *regexp.Regexp
}

// RuleSet is a collection of blocking rules with efficient lookup.
type RuleSet struct {
	mu sync.RWMutex

	// Exact domain matches
	domains map[string]*Rule

	// Wildcard domain patterns (stored without "*.")
	wildcardDomains map[string]*Rule

	// URL prefix matches
	urlPrefixes []*urlPrefixRule

	// Regex patterns
	regexPatterns []*Rule
}

type urlPrefixRule struct {
	prefix string
	rule   *Rule
}

// NewRuleSet creates a new empty RuleSet.
func NewRuleSet() *RuleSet {
	return &RuleSet{
		domains:         make(map[string]*Rule),
		wildcardDomains: make(map[string]*Rule),
	}
}

// AddRule adds a rule to the set.
func (rs *RuleSet) AddRule(r Rule) error {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	rule := &r

	switch r.Type {
	case "domain":
		pattern := strings.ToLower(r.Pattern)
		if strings.HasPrefix(pattern, "*.") {
			rs.wildcardDomains[pattern[2:]] = rule
		} else {
			rs.domains[pattern] = rule
		}

	case "url":
		rs.urlPrefixes = append(rs.urlPrefixes, &urlPrefixRule{
			prefix: strings.ToLower(r.Pattern),
			rule:   rule,
		})

	case "regex":
		compiled, err := regexp.Compile(r.Pattern)
		if err != nil {
			return fmt.Errorf("invalid regex pattern %q: %w", r.Pattern, err)
		}
		rule.compiledRegex = compiled
		rs.regexPatterns = append(rs.regexPatterns, rule)

	default:
		return fmt.Errorf("unknown rule type: %s", r.Type)
	}

	return nil
}

// AddDomain is a convenience method to add a domain blocking rule.
func (rs *RuleSet) AddDomain(domain string) {
	_ = rs.AddRule(Rule{
		Type:    "domain",
		Pattern: domain,
		Reason:  "domain blocked",
	})
}

// AddURL is a convenience method to add a URL prefix blocking rule.
func (rs *RuleSet) AddURL(urlPrefix string) {
	_ = rs.AddRule(Rule{
		Type:    "url",
		Pattern: urlPrefix,
		Reason:  "URL blocked",
	})
}

// AddRegex is a convenience method to add a regex blocking rule.
func (rs *RuleSet) AddRegex(pattern string) error {
	return rs.AddRule(Rule{
		Type:    "regex",
		Pattern: pattern,
		Reason:  "pattern blocked",
	})
}

// Match checks if a request matches any rule in the set.
// Returns the matching rule and true if blocked, nil and false otherwise.
func (rs *RuleSet) Match(req *http.Request) (*Rule, bool) {
	rs.mu.RLock()
	defer rs.mu.RUnlock()

	// Extract host
	host := req.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.ToLower(host)

	// Check exact domain match
	if rule, ok := rs.domains[host]; ok {
		return rule, true
	}

	// Check wildcard domain match
	for pattern, rule := range rs.wildcardDomains {
		if host == pattern || strings.HasSuffix(host, "."+pattern) {
			return rule, true
		}
	}

	// Build full URL for URL and regex matching
	fullURL := strings.ToLower(req.URL.String())
	if !strings.HasPrefix(fullURL, "http") {
		scheme := "http"
		if req.TLS != nil {
			scheme = "https"
		}
		fullURL = scheme + "://" + host + req.URL.RequestURI()
	}

	// Check URL prefix match
	for _, pr := range rs.urlPrefixes {
		if strings.HasPrefix(fullURL, pr.prefix) {
			return pr.rule, true
		}
	}

	// Check regex patterns
	for _, rule := range rs.regexPatterns {
		if rule.compiledRegex.MatchString(fullURL) {
			return rule, true
		}
	}

	return nil, false
}

// ShouldBlock implements the Filter interface.
func (rs *RuleSet) ShouldBlock(req *http.Request) (bool, string) {
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

// Clear removes all rules from the set.
func (rs *RuleSet) Clear() {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	rs.domains = make(map[string]*Rule)
	rs.wildcardDomains = make(map[string]*Rule)
	rs.urlPrefixes = nil
	rs.regexPatterns = nil
}

// Count returns the total number of rules in the set.
func (rs *RuleSet) Count() int {
	rs.mu.RLock()
	defer rs.mu.RUnlock()

	return len(rs.domains) + len(rs.wildcardDomains) + len(rs.urlPrefixes) + len(rs.regexPatterns)
}

// RuleLoader defines the interface for loading rules from various sources.
type RuleLoader interface {
	// Load reads rules from the source and returns them.
	Load(ctx context.Context) ([]Rule, error)
}

// RuleLoaderFunc is a function adapter for RuleLoader.
type RuleLoaderFunc func(ctx context.Context) ([]Rule, error)

// Load calls the underlying function to load rules.
func (f RuleLoaderFunc) Load(ctx context.Context) ([]Rule, error) {
	return f(ctx)
}

// ReloadableFilter wraps a RuleSet with automatic reloading from a RuleLoader.
type ReloadableFilter struct {
	ruleSet *RuleSet
	loader  RuleLoader
	mu      sync.RWMutex

	// OnReload is called after successful reload with the rule count
	OnReload func(count int)

	// OnError is called when reload fails
	OnError func(err error)
}

// NewReloadableFilter creates a new filter that can reload rules from a loader.
func NewReloadableFilter(loader RuleLoader) *ReloadableFilter {
	return &ReloadableFilter{
		ruleSet: NewRuleSet(),
		loader:  loader,
	}
}

// Load loads rules from the configured loader, replacing existing rules.
func (rf *ReloadableFilter) Load(ctx context.Context) error {
	rules, err := rf.loader.Load(ctx)
	if err != nil {
		if rf.OnError != nil {
			rf.OnError(err)
		}
		return err
	}

	newRuleSet := NewRuleSet()
	for _, rule := range rules {
		if err := newRuleSet.AddRule(rule); err != nil {
			if rf.OnError != nil {
				rf.OnError(err)
			}
			return err
		}
	}

	rf.mu.Lock()
	rf.ruleSet = newRuleSet
	rf.mu.Unlock()

	if rf.OnReload != nil {
		rf.OnReload(newRuleSet.Count())
	}

	return nil
}

// StartAutoReload starts a goroutine that reloads rules at the specified interval.
// Returns a cancel function to stop the reload goroutine.
func (rf *ReloadableFilter) StartAutoReload(ctx context.Context, interval time.Duration) context.CancelFunc {
	ctx, cancel := context.WithCancel(ctx)

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				_ = rf.Load(ctx)
			}
		}
	}()

	return cancel
}

// ShouldBlock implements the Filter interface.
func (rf *ReloadableFilter) ShouldBlock(req *http.Request) (bool, string) {
	rf.mu.RLock()
	rs := rf.ruleSet
	rf.mu.RUnlock()

	return rs.ShouldBlock(req)
}

// Count returns the current number of rules.
func (rf *ReloadableFilter) Count() int {
	rf.mu.RLock()
	defer rf.mu.RUnlock()
	return rf.ruleSet.Count()
}

// CSVLoader loads rules from a CSV file.
// Expected CSV format: type,pattern,reason,category
// Where type is one of: domain, url, regex
type CSVLoader struct {
	// Path to the CSV file
	Path string

	// HasHeader indicates if the first row is a header (skipped)
	HasHeader bool

	// DefaultReason is used when the reason column is empty
	DefaultReason string

	// DefaultCategory is used when the category column is empty
	DefaultCategory string
}

// NewCSVLoader creates a new CSV loader for the given file path.
func NewCSVLoader(path string) *CSVLoader {
	return &CSVLoader{
		Path:          path,
		HasHeader:     true,
		DefaultReason: "blocked by policy",
	}
}

// Load implements RuleLoader.
func (l *CSVLoader) Load(ctx context.Context) ([]Rule, error) {
	file, err := os.Open(l.Path)
	if err != nil {
		return nil, fmt.Errorf("open CSV file: %w", err)
	}
	defer func() { _ = file.Close() }()

	return l.LoadFromReader(ctx, file)
}

// LoadFromReader loads rules from an io.Reader (useful for testing).
func (l *CSVLoader) LoadFromReader(ctx context.Context, r io.Reader) ([]Rule, error) {
	reader := csv.NewReader(r)
	reader.FieldsPerRecord = -1 // Allow variable number of fields
	reader.TrimLeadingSpace = true

	var rules []Rule
	lineNum := 0

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read CSV line %d: %w", lineNum+1, err)
		}

		lineNum++

		// Skip header
		if lineNum == 1 && l.HasHeader {
			continue
		}

		// Skip empty lines
		if len(record) == 0 || (len(record) == 1 && record[0] == "") {
			continue
		}

		// Parse rule
		rule, err := l.parseRecord(record, lineNum)
		if err != nil {
			return nil, err
		}

		rules = append(rules, rule)
	}

	return rules, nil
}

func (l *CSVLoader) parseRecord(record []string, lineNum int) (Rule, error) {
	if len(record) < 2 {
		return Rule{}, fmt.Errorf("line %d: expected at least 2 fields (type, pattern)", lineNum)
	}

	ruleType := strings.ToLower(strings.TrimSpace(record[0]))
	pattern := strings.TrimSpace(record[1])

	if ruleType == "" || pattern == "" {
		return Rule{}, fmt.Errorf("line %d: type and pattern cannot be empty", lineNum)
	}

	// Validate rule type
	switch ruleType {
	case "domain", "url", "regex":
		// valid
	default:
		return Rule{}, fmt.Errorf("line %d: invalid rule type %q (expected domain, url, or regex)", lineNum, ruleType)
	}

	rule := Rule{
		Type:     ruleType,
		Pattern:  pattern,
		Reason:   l.DefaultReason,
		Category: l.DefaultCategory,
	}

	// Optional reason
	if len(record) > 2 && record[2] != "" {
		rule.Reason = strings.TrimSpace(record[2])
	}

	// Optional category
	if len(record) > 3 && record[3] != "" {
		rule.Category = strings.TrimSpace(record[3])
	}

	return rule, nil
}

// MultiLoader combines multiple loaders into one.
type MultiLoader struct {
	Loaders []RuleLoader
}

// NewMultiLoader creates a loader that combines rules from multiple sources.
func NewMultiLoader(loaders ...RuleLoader) *MultiLoader {
	return &MultiLoader{Loaders: loaders}
}

// Load implements RuleLoader by loading from all configured loaders.
func (m *MultiLoader) Load(ctx context.Context) ([]Rule, error) {
	var allRules []Rule

	for i, loader := range m.Loaders {
		rules, err := loader.Load(ctx)
		if err != nil {
			return nil, fmt.Errorf("loader %d: %w", i, err)
		}
		allRules = append(allRules, rules...)
	}

	return allRules, nil
}

// URLLoader loads rules from an HTTP endpoint.
// Expects the same CSV format as CSVLoader.
type URLLoader struct {
	// URL to fetch rules from
	URL string

	// Client for HTTP requests (uses http.DefaultClient if nil)
	Client *http.Client

	// HasHeader indicates if the first row is a header
	HasHeader bool

	// DefaultReason is used when the reason column is empty
	DefaultReason string
}

// NewURLLoader creates a loader that fetches rules from a URL.
func NewURLLoader(endpoint string) *URLLoader {
	return &URLLoader{
		URL:           endpoint,
		HasHeader:     true,
		DefaultReason: "blocked by policy",
	}
}

// Load implements RuleLoader.
func (l *URLLoader) Load(ctx context.Context) ([]Rule, error) {
	client := l.Client
	if client == nil {
		client = http.DefaultClient
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, l.URL, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch rules: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	csvLoader := &CSVLoader{
		HasHeader:     l.HasHeader,
		DefaultReason: l.DefaultReason,
	}

	return csvLoader.LoadFromReader(ctx, resp.Body)
}

// StaticLoader returns a fixed set of rules.
// Useful for testing or combining with other loaders.
type StaticLoader struct {
	Rules []Rule
}

// NewStaticLoader creates a loader with a fixed set of rules.
func NewStaticLoader(rules ...Rule) *StaticLoader {
	return &StaticLoader{Rules: rules}
}

// Load implements RuleLoader.
func (l *StaticLoader) Load(ctx context.Context) ([]Rule, error) {
	return l.Rules, nil
}

// ParseDomainList parses a list of domains (one per line) into rules.
// Supports comments (lines starting with #) and empty lines.
func ParseDomainList(r io.Reader) ([]Rule, error) {
	var rules []Rule
	scanner := bufio.NewScanner(r)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		rules = append(rules, Rule{
			Type:    "domain",
			Pattern: line,
			Reason:  "domain blocked",
		})
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return rules, nil
}
