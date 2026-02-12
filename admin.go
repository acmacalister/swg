package swg

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

// AdminAPI provides REST endpoints for managing the proxy at runtime.
// It exposes routes for listing, adding, and removing filter rules,
// viewing proxy status, and triggering filter reloads.
//
// The API is mounted at a configurable path prefix (default "/api") and
// uses [chi] for routing.
//
// All endpoints return JSON responses with appropriate status codes.
// Mutations require the filter to be a *RuleSet or a *ReloadableFilter
// that exposes a RuleSet.
type AdminAPI struct {
	// Proxy is the proxy instance to manage.
	Proxy *Proxy

	// Logger for admin API events.
	Logger *slog.Logger

	// PathPrefix is the URL path prefix for admin routes (default "/api").
	PathPrefix string

	// ReloadFunc is called when POST /api/reload is invoked. It should
	// rebuild the filter from its source (e.g. config file, database).
	// If nil, the reload endpoint returns 501 Not Implemented.
	ReloadFunc func(ctx context.Context) error

	router chi.Router
}

// NewAdminAPI creates an AdminAPI wired to the given proxy.
func NewAdminAPI(proxy *Proxy) *AdminAPI {
	a := &AdminAPI{
		Proxy:      proxy,
		Logger:     slog.Default(),
		PathPrefix: "/api",
	}
	a.buildRouter()
	return a
}

func (a *AdminAPI) buildRouter() {
	r := chi.NewRouter()
	r.Use(middleware.SetHeader("Content-Type", "application/json"))

	r.Get("/status", a.handleStatus)
	r.Get("/rules", a.handleListRules)
	r.Post("/rules", a.handleAddRule)
	r.Delete("/rules", a.handleDeleteRule)
	r.Post("/reload", a.handleReload)

	a.router = r
}

// Handler returns an http.Handler for the admin API routes.
// Mount this on the proxy or a separate listener.
func (a *AdminAPI) Handler() http.Handler {
	return http.StripPrefix(a.PathPrefix, a.router)
}

// ServeHTTP implements http.Handler by delegating to the internal chi router
// after stripping the path prefix.
func (a *AdminAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.Handler().ServeHTTP(w, r)
}

// --------------------------------------------------------------------------
// Response types
// --------------------------------------------------------------------------

// StatusResponse is returned by GET /api/status.
type StatusResponse struct {
	Status    string `json:"status"`
	RuleCount int    `json:"rule_count"`
	Uptime    string `json:"uptime,omitempty"`
	Filter    string `json:"filter_type"`
}

// RulesResponse is returned by GET /api/rules.
type RulesResponse struct {
	Count int    `json:"count"`
	Rules []Rule `json:"rules"`
}

// RuleRequest is the body for POST /api/rules and DELETE /api/rules.
type RuleRequest struct {
	Type     string `json:"type"`
	Pattern  string `json:"pattern"`
	Reason   string `json:"reason,omitempty"`
	Category string `json:"category,omitempty"`
}

// ErrorResponse is returned for error conditions.
type ErrorResponse struct {
	Error string `json:"error"`
}

// MessageResponse is returned for successful mutations.
type MessageResponse struct {
	Message string `json:"message"`
}

// --------------------------------------------------------------------------
// Handlers
// --------------------------------------------------------------------------

func (a *AdminAPI) handleStatus(w http.ResponseWriter, _ *http.Request) {
	resp := StatusResponse{
		Status:    "ok",
		RuleCount: a.ruleCount(),
		Filter:    a.filterType(),
	}

	if a.Proxy.HealthChecker != nil {
		resp.Uptime = time.Since(a.Proxy.HealthChecker.startTime).Truncate(time.Second).String()
	}

	a.writeJSON(w, http.StatusOK, resp)
}

func (a *AdminAPI) handleListRules(w http.ResponseWriter, _ *http.Request) {
	rs := a.resolveRuleSet()
	if rs == nil {
		a.writeJSON(w, http.StatusOK, RulesResponse{Count: 0, Rules: []Rule{}})
		return
	}

	rules := rs.Rules()
	a.writeJSON(w, http.StatusOK, RulesResponse{Count: len(rules), Rules: rules})
}

func (a *AdminAPI) handleAddRule(w http.ResponseWriter, r *http.Request) {
	rs := a.resolveRuleSet()
	if rs == nil {
		a.writeJSON(w, http.StatusConflict, ErrorResponse{Error: "filter does not support rule management"})
		return
	}

	var req RuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "invalid JSON: " + err.Error()})
		return
	}

	if req.Type == "" || req.Pattern == "" {
		a.writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "type and pattern are required"})
		return
	}

	rule := Rule{
		Type:     req.Type,
		Pattern:  req.Pattern,
		Reason:   req.Reason,
		Category: req.Category,
	}
	if rule.Reason == "" {
		rule.Reason = "added via admin API"
	}

	if err := rs.AddRule(rule); err != nil {
		a.writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: err.Error()})
		return
	}

	a.Logger.Info("rule added via admin API", "type", req.Type, "pattern", req.Pattern)
	a.writeJSON(w, http.StatusCreated, MessageResponse{Message: "rule added"})
}

func (a *AdminAPI) handleDeleteRule(w http.ResponseWriter, r *http.Request) {
	rs := a.resolveRuleSet()
	if rs == nil {
		a.writeJSON(w, http.StatusConflict, ErrorResponse{Error: "filter does not support rule management"})
		return
	}

	var req RuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "invalid JSON: " + err.Error()})
		return
	}

	if req.Type == "" || req.Pattern == "" {
		a.writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "type and pattern are required"})
		return
	}

	if !rs.RemoveRule(req.Type, req.Pattern) {
		a.writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "rule not found"})
		return
	}

	a.Logger.Info("rule removed via admin API", "type", req.Type, "pattern", req.Pattern)
	a.writeJSON(w, http.StatusOK, MessageResponse{Message: "rule removed"})
}

func (a *AdminAPI) handleReload(w http.ResponseWriter, r *http.Request) {
	if a.ReloadFunc == nil {
		a.writeJSON(w, http.StatusNotImplemented, ErrorResponse{Error: "reload not configured"})
		return
	}

	if err := a.ReloadFunc(r.Context()); err != nil {
		a.Logger.Error("admin API reload failed", "error", err)
		a.writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "reload failed: " + err.Error()})
		return
	}

	a.Logger.Info("filter reloaded via admin API")
	a.writeJSON(w, http.StatusOK, MessageResponse{Message: "reload successful"})
}

// --------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------

// resolveRuleSet extracts a *RuleSet from the proxy's filter, supporting
// both *RuleSet directly and *ReloadableFilter which wraps one.
func (a *AdminAPI) resolveRuleSet() *RuleSet {
	switch f := a.Proxy.Filter.(type) {
	case *RuleSet:
		return f
	case *ReloadableFilter:
		return f.RuleSet()
	default:
		return nil
	}
}

func (a *AdminAPI) ruleCount() int {
	rs := a.resolveRuleSet()
	if rs != nil {
		return rs.Count()
	}
	return 0
}

func (a *AdminAPI) filterType() string {
	if a.Proxy.Filter == nil {
		return "none"
	}
	switch a.Proxy.Filter.(type) {
	case *RuleSet:
		return "ruleset"
	case *ReloadableFilter:
		return "reloadable"
	case *DomainFilter:
		return "domain"
	case *AllowListFilter:
		return "allowlist"
	case *GroupPolicyFilter:
		return "group"
	case *ChainFilter:
		return "chain"
	default:
		return "custom"
	}
}

func (a *AdminAPI) writeJSON(w http.ResponseWriter, status int, v any) {
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		a.Logger.Error("admin API write error", "error", err)
	}
}
