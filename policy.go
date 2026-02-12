package swg

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// RequestContext carries metadata through the proxy request lifecycle.
// Hooks and middleware attach information here for downstream stages.
type RequestContext struct {
	// ClientIP is the connecting client's IP (without port).
	ClientIP string

	// Identity is resolved by an IdentityResolver (optional).
	// May represent a username, group, device ID, or any string.
	Identity string

	// Groups the client belongs to (resolved by IdentityResolver).
	Groups []string

	// Tags are arbitrary key-value metadata set by hooks.
	Tags map[string]string

	// Blocked is set to true when any stage decides to block the request.
	Blocked bool

	// BlockReason is the human-readable reason for blocking.
	BlockReason string

	// StartTime is when the request was first received.
	StartTime time.Time
}

type requestContextKey struct{}

// WithRequestContext attaches a RequestContext to the given context.
func WithRequestContext(ctx context.Context, rc *RequestContext) context.Context {
	return context.WithValue(ctx, requestContextKey{}, rc)
}

// GetRequestContext retrieves the RequestContext from the context, or nil.
func GetRequestContext(ctx context.Context) *RequestContext {
	rc, _ := ctx.Value(requestContextKey{}).(*RequestContext)
	return rc
}

// --------------------------------------------------------------------------
// Lifecycle hook interfaces
// --------------------------------------------------------------------------

// RequestHook is called when a request is first received, before any
// filtering. Hooks may inspect, modify, or block the request. They may
// also resolve identity, attach tags, or perform early access control.
//
// Returning a non-nil *http.Response short-circuits the pipeline: that
// response is sent to the client and no further hooks or forwarding occur.
type RequestHook interface {
	HandleRequest(ctx context.Context, req *http.Request, rc *RequestContext) *http.Response
}

// RequestHookFunc is a function adapter for RequestHook.
type RequestHookFunc func(ctx context.Context, req *http.Request, rc *RequestContext) *http.Response

func (f RequestHookFunc) HandleRequest(ctx context.Context, req *http.Request, rc *RequestContext) *http.Response {
	return f(ctx, req, rc)
}

// ResponseHook is called after the upstream response is received but
// before it is sent back to the client. Hooks may inspect headers,
// content-type, or the response body. They may replace the response
// entirely (e.g. with a block page) by returning a non-nil *http.Response.
//
// The original response body is readable (and should be closed by the
// hook if it replaces the response). For body inspection, use
// ResponseBodyScanner which handles buffering and streaming.
type ResponseHook interface {
	HandleResponse(ctx context.Context, req *http.Request, resp *http.Response, rc *RequestContext) *http.Response
}

// ResponseHookFunc is a function adapter for ResponseHook.
type ResponseHookFunc func(ctx context.Context, req *http.Request, resp *http.Response, rc *RequestContext) *http.Response

func (f ResponseHookFunc) HandleResponse(ctx context.Context, req *http.Request, resp *http.Response, rc *RequestContext) *http.Response {
	return f(ctx, req, resp, rc)
}

// --------------------------------------------------------------------------
// Identity resolution
// --------------------------------------------------------------------------

// IdentityResolver determines who a client is from the request. This
// drives per-user/group policy decisions. Implementations might use
// client certificates, Proxy-Authorization headers, IP-to-user mappings,
// or external auth services.
type IdentityResolver interface {
	Resolve(req *http.Request) (identity string, groups []string, err error)
}

// IdentityResolverFunc is a function adapter for IdentityResolver.
type IdentityResolverFunc func(req *http.Request) (string, []string, error)

func (f IdentityResolverFunc) Resolve(req *http.Request) (string, []string, error) {
	return f(req)
}

// IPIdentityResolver maps client IPs to identity/groups.
type IPIdentityResolver struct {
	mu       sync.RWMutex
	ipMap    map[string]ipIdentity
	cidrMap  []cidrIdentity
}

type ipIdentity struct {
	Identity string
	Groups   []string
}

type cidrIdentity struct {
	Network  *net.IPNet
	Identity string
	Groups   []string
}

// NewIPIdentityResolver creates an empty IP-based identity resolver.
func NewIPIdentityResolver() *IPIdentityResolver {
	return &IPIdentityResolver{
		ipMap: make(map[string]ipIdentity),
	}
}

// AddIP maps a single IP to an identity and groups.
func (r *IPIdentityResolver) AddIP(ip, identity string, groups []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ipMap[ip] = ipIdentity{Identity: identity, Groups: groups}
}

// AddCIDR maps a CIDR range to an identity and groups.
func (r *IPIdentityResolver) AddCIDR(cidr, identity string, groups []string) error {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cidrMap = append(r.cidrMap, cidrIdentity{
		Network:  network,
		Identity: identity,
		Groups:   groups,
	})
	return nil
}

// Resolve implements IdentityResolver.
func (r *IPIdentityResolver) Resolve(req *http.Request) (string, []string, error) {
	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		host = req.RemoteAddr
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	if id, ok := r.ipMap[host]; ok {
		return id.Identity, id.Groups, nil
	}

	ip := net.ParseIP(host)
	if ip != nil {
		for _, entry := range r.cidrMap {
			if entry.Network.Contains(ip) {
				return entry.Identity, entry.Groups, nil
			}
		}
	}

	return "", nil, nil
}

// --------------------------------------------------------------------------
// Response body scanning
// --------------------------------------------------------------------------

// ScanVerdict is the result of a ResponseBodyScanner inspection.
type ScanVerdict int

const (
	// VerdictAllow means the content is clean.
	VerdictAllow ScanVerdict = iota

	// VerdictBlock means the content should be blocked.
	VerdictBlock

	// VerdictReplace means the scanner is providing a replacement body.
	VerdictReplace
)

// ScanResult holds the outcome of a body scan.
type ScanResult struct {
	Verdict ScanVerdict

	// Reason is set when Verdict is VerdictBlock.
	Reason string

	// ReplacementBody is set when Verdict is VerdictReplace. The caller
	// is responsible for closing it.
	ReplacementBody io.ReadCloser

	// ReplacementContentType overrides Content-Type when replacing.
	ReplacementContentType string
}

// ResponseBodyScanner inspects response bodies for threats or policy
// violations. Implementations can wrap AV engines, DLP scanners,
// keyword detectors, or any content analysis tool.
//
// Scan receives the full body as a byte slice (up to the configured
// MaxScanSize) plus the request and response for context. Returning
// an error causes the proxy to serve a 502 error to the client.
type ResponseBodyScanner interface {
	Scan(ctx context.Context, body []byte, req *http.Request, resp *http.Response) (ScanResult, error)
}

// ResponseBodyScannerFunc is a function adapter for ResponseBodyScanner.
type ResponseBodyScannerFunc func(ctx context.Context, body []byte, req *http.Request, resp *http.Response) (ScanResult, error)

func (f ResponseBodyScannerFunc) Scan(ctx context.Context, body []byte, req *http.Request, resp *http.Response) (ScanResult, error) {
	return f(ctx, body, req, resp)
}

// --------------------------------------------------------------------------
// PolicyEngine — orchestrates the full lifecycle
// --------------------------------------------------------------------------

// PolicyEngine manages the request/response pipeline with hooks,
// identity resolution, and body scanning. It is set on Proxy.Policy.
type PolicyEngine struct {
	// RequestHooks are called in order when a request arrives.
	// Any hook may short-circuit by returning a response.
	RequestHooks []RequestHook

	// ResponseHooks are called in order after the upstream response
	// is received. Any hook may replace the response.
	ResponseHooks []ResponseHook

	// IdentityResolver resolves client identity before hooks run.
	IdentityResolver IdentityResolver

	// BodyScanners inspect response bodies. They run after
	// ResponseHooks, only for responses whose Content-Type matches
	// ScanContentTypes (or all responses if ScanContentTypes is empty).
	BodyScanners []ResponseBodyScanner

	// ScanContentTypes limits body scanning to responses with matching
	// Content-Type prefixes (e.g. "application/octet-stream",
	// "application/zip"). Empty means scan all responses.
	ScanContentTypes []string

	// MaxScanSize is the maximum number of bytes to buffer for body
	// scanning. Responses larger than this are passed through without
	// scanning. Default is 10 MiB.
	MaxScanSize int64
}

// NewPolicyEngine creates a PolicyEngine with sensible defaults.
func NewPolicyEngine() *PolicyEngine {
	return &PolicyEngine{
		MaxScanSize: 10 << 20, // 10 MiB
	}
}

// ProcessRequest runs the request-side pipeline: identity resolution
// then request hooks. Returns a non-nil response to short-circuit.
func (pe *PolicyEngine) ProcessRequest(ctx context.Context, req *http.Request) (*RequestContext, *http.Response) {
	rc := &RequestContext{
		StartTime: time.Now(),
		Tags:      make(map[string]string),
	}

	if host, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
		rc.ClientIP = host
	} else {
		rc.ClientIP = req.RemoteAddr
	}

	if pe.IdentityResolver != nil {
		identity, groups, _ := pe.IdentityResolver.Resolve(req)
		rc.Identity = identity
		rc.Groups = groups
	}

	ctx = WithRequestContext(ctx, rc)

	for _, hook := range pe.RequestHooks {
		if resp := hook.HandleRequest(ctx, req, rc); resp != nil {
			return rc, resp
		}
	}

	return rc, nil
}

// ProcessResponse runs the response-side pipeline: response hooks then
// body scanners. Returns the (possibly replaced) response.
func (pe *PolicyEngine) ProcessResponse(ctx context.Context, req *http.Request, resp *http.Response, rc *RequestContext) (*http.Response, error) {
	for _, hook := range pe.ResponseHooks {
		if replacement := hook.HandleResponse(ctx, req, resp, rc); replacement != nil {
			resp = replacement
		}
	}

	if len(pe.BodyScanners) > 0 && pe.shouldScanBody(resp) {
		scanned, err := pe.scanBody(ctx, req, resp)
		if err != nil {
			return nil, err
		}
		resp = scanned
	}

	return resp, nil
}

func (pe *PolicyEngine) shouldScanBody(resp *http.Response) bool {
	if resp.Body == nil {
		return false
	}

	if len(pe.ScanContentTypes) == 0 {
		return true
	}

	ct := resp.Header.Get("Content-Type")
	ct = strings.ToLower(ct)
	for _, prefix := range pe.ScanContentTypes {
		if strings.HasPrefix(ct, strings.ToLower(prefix)) {
			return true
		}
	}
	return false
}

func (pe *PolicyEngine) scanBody(ctx context.Context, req *http.Request, resp *http.Response) (*http.Response, error) {
	maxSize := pe.MaxScanSize
	if maxSize <= 0 {
		maxSize = 10 << 20
	}

	limited := io.LimitReader(resp.Body, maxSize+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		_ = resp.Body.Close()
		return nil, err
	}
	_ = resp.Body.Close()

	if int64(len(body)) > maxSize {
		resp.Body = io.NopCloser(io.MultiReader(
			bytes.NewReader(body[:maxSize]),
			resp.Body,
		))
		return resp, nil
	}

	for _, scanner := range pe.BodyScanners {
		result, err := scanner.Scan(ctx, body, req, resp)
		if err != nil {
			return nil, err
		}

		switch result.Verdict {
		case VerdictBlock:
			return blockedResponse(result.Reason), nil
		case VerdictReplace:
			newResp := &http.Response{
				StatusCode: resp.StatusCode,
				Header:     resp.Header.Clone(),
				ProtoMajor: 1,
				ProtoMinor: 1,
			}
			if result.ReplacementContentType != "" {
				newResp.Header.Set("Content-Type", result.ReplacementContentType)
			}
			newResp.Body = result.ReplacementBody
			return newResp, nil
		}
	}

	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
	return resp, nil
}

func blockedResponse(reason string) *http.Response {
	body := "Blocked: " + reason
	return &http.Response{
		StatusCode:    http.StatusForbidden,
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        http.Header{"Content-Type": {"text/plain; charset=utf-8"}},
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
	}
}

// --------------------------------------------------------------------------
// Built-in policy implementations
// --------------------------------------------------------------------------

// AllowListFilter implements Filter with a deny-by-default policy.
// Only requests matching allowed domains pass through; everything else
// is blocked.
type AllowListFilter struct {
	mu       sync.RWMutex
	allowed  map[string]bool
	patterns []string // wildcard patterns stored without "*."
	Reason   string   // block reason for denied requests
}

// NewAllowListFilter creates a deny-by-default filter.
func NewAllowListFilter() *AllowListFilter {
	return &AllowListFilter{
		allowed: make(map[string]bool),
		Reason:  "domain not in allow list",
	}
}

// AddDomain adds a domain to the allow list.
// Supports wildcards: "*.example.com" allows all subdomains.
func (f *AllowListFilter) AddDomain(domain string) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if strings.HasPrefix(domain, "*.") {
		f.patterns = append(f.patterns, strings.ToLower(domain[2:]))
	} else {
		f.allowed[strings.ToLower(domain)] = true
	}
}

// AddDomains adds multiple domains to the allow list.
func (f *AllowListFilter) AddDomains(domains []string) {
	for _, d := range domains {
		f.AddDomain(d)
	}
}

// ShouldBlock implements Filter. Returns true for domains NOT in the
// allow list.
func (f *AllowListFilter) ShouldBlock(req *http.Request) (bool, string) {
	host := req.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.ToLower(host)

	f.mu.RLock()
	defer f.mu.RUnlock()

	if f.allowed[host] {
		return false, ""
	}

	for _, pattern := range f.patterns {
		if host == pattern || strings.HasSuffix(host, "."+pattern) {
			return false, ""
		}
	}

	return true, f.Reason
}

// TimeRule wraps a Filter and only activates it during specific time
// windows. Outside the window, the inner filter is bypassed.
type TimeRule struct {
	// Inner is the filter to apply during the active window.
	Inner Filter

	// StartHour is the hour (0-23) when the rule becomes active.
	StartHour int

	// EndHour is the hour (0-23) when the rule becomes inactive.
	// If EndHour < StartHour, the window wraps past midnight.
	EndHour int

	// Weekdays limits the rule to specific days. Empty means every day.
	Weekdays []time.Weekday

	// Location for time evaluation. Defaults to UTC.
	Location *time.Location

	// NowFunc returns the current time. Defaults to time.Now.
	// Exposed for testing.
	NowFunc func() time.Time
}

// ShouldBlock implements Filter. Delegates to Inner only during the
// active time window.
func (tr *TimeRule) ShouldBlock(req *http.Request) (bool, string) {
	now := tr.now()
	if !tr.isActive(now) {
		return false, ""
	}
	return tr.Inner.ShouldBlock(req)
}

func (tr *TimeRule) now() time.Time {
	if tr.NowFunc != nil {
		return tr.NowFunc()
	}
	return time.Now()
}

func (tr *TimeRule) isActive(now time.Time) bool {
	loc := tr.Location
	if loc == nil {
		loc = time.UTC
	}
	now = now.In(loc)

	if len(tr.Weekdays) > 0 {
		day := now.Weekday()
		found := false
		for _, wd := range tr.Weekdays {
			if wd == day {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	hour := now.Hour()

	if tr.StartHour <= tr.EndHour {
		return hour >= tr.StartHour && hour < tr.EndHour
	}
	// Wraps midnight: e.g. 22-06 means 22,23,0,1,2,3,4,5
	return hour >= tr.StartHour || hour < tr.EndHour
}

// GroupPolicyFilter applies different filters based on the client's
// resolved group membership. It reads groups from the RequestContext.
type GroupPolicyFilter struct {
	mu       sync.RWMutex
	policies map[string]Filter // group name -> filter
	Default  Filter            // applied when no group matches
}

// NewGroupPolicyFilter creates a group-based policy filter.
func NewGroupPolicyFilter() *GroupPolicyFilter {
	return &GroupPolicyFilter{
		policies: make(map[string]Filter),
	}
}

// SetPolicy assigns a filter to a group name.
func (gf *GroupPolicyFilter) SetPolicy(group string, filter Filter) {
	gf.mu.Lock()
	defer gf.mu.Unlock()
	gf.policies[group] = filter
}

// ShouldBlock implements Filter. Checks the RequestContext for group
// membership and applies the first matching group policy.
func (gf *GroupPolicyFilter) ShouldBlock(req *http.Request) (bool, string) {
	rc := GetRequestContext(req.Context())

	gf.mu.RLock()
	defer gf.mu.RUnlock()

	if rc != nil {
		for _, group := range rc.Groups {
			if filter, ok := gf.policies[group]; ok {
				return filter.ShouldBlock(req)
			}
		}
	}

	if gf.Default != nil {
		return gf.Default.ShouldBlock(req)
	}

	return false, ""
}

// ContentTypeFilter blocks responses based on Content-Type. It is used
// as a ResponseHook to inspect the upstream response headers.
type ContentTypeFilter struct {
	mu      sync.RWMutex
	blocked map[string]string // content-type prefix -> reason
}

// NewContentTypeFilter creates a content-type response filter.
func NewContentTypeFilter() *ContentTypeFilter {
	return &ContentTypeFilter{
		blocked: make(map[string]string),
	}
}

// Block adds a content-type prefix to the block list. For example,
// "application/x-executable" blocks that exact type, while
// "application/" blocks all application/* types.
func (f *ContentTypeFilter) Block(contentTypePrefix, reason string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.blocked[strings.ToLower(contentTypePrefix)] = reason
}

// HandleResponse implements ResponseHook.
func (f *ContentTypeFilter) HandleResponse(_ context.Context, _ *http.Request, resp *http.Response, _ *RequestContext) *http.Response {
	ct := strings.ToLower(resp.Header.Get("Content-Type"))

	f.mu.RLock()
	defer f.mu.RUnlock()

	for prefix, reason := range f.blocked {
		if strings.HasPrefix(ct, prefix) {
			_ = resp.Body.Close()
			return blockedResponse(reason)
		}
	}

	return nil
}

// ChainFilter composes multiple Filters into one. Filters are checked
// in order; the first one that blocks wins.
type ChainFilter struct {
	Filters []Filter
}

// ShouldBlock implements Filter.
func (cf *ChainFilter) ShouldBlock(req *http.Request) (bool, string) {
	for _, f := range cf.Filters {
		if blocked, reason := f.ShouldBlock(req); blocked {
			return true, reason
		}
	}
	return false, ""
}
