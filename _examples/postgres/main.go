// Example: Loading blocklist rules from PostgreSQL using sqlx
//
// This example demonstrates how to implement a custom RuleLoader
// that fetches blocking rules from a PostgreSQL database using sqlx.
//
// Required table schema:
//
//	CREATE TABLE blocklist (
//	    id SERIAL PRIMARY KEY,
//	    rule_type VARCHAR(10) NOT NULL CHECK (rule_type IN ('domain', 'url', 'regex')),
//	    pattern VARCHAR(500) NOT NULL,
//	    reason VARCHAR(255) DEFAULT 'blocked by policy',
//	    category VARCHAR(100),
//	    enabled BOOLEAN DEFAULT true,
//	    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
//	    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
//	);
//
//	CREATE INDEX idx_blocklist_enabled ON blocklist(enabled) WHERE enabled = true;
//
// To run this example:
//
//	go get github.com/jmoiron/sqlx
//	go get github.com/lib/pq
//	DATABASE_URL="postgres://user:pass@localhost/dbname?sslmode=disable" go run main.go
package main

import (
	"context"
	"log/slog"
	"os"
	"time"

	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"

	"github.com/acmacalister/swg"
)

// PostgresLoader loads rules from a PostgreSQL database.
type PostgresLoader struct {
	DB *sqlx.DB

	// Query to fetch rules (must return type, pattern, reason, category columns)
	Query string
}

// BlocklistRow represents a row from the blocklist table.
type BlocklistRow struct {
	RuleType string  `db:"rule_type"`
	Pattern  string  `db:"pattern"`
	Reason   *string `db:"reason"`
	Category *string `db:"category"`
}

// NewPostgresLoader creates a new PostgreSQL rule loader.
func NewPostgresLoader(db *sqlx.DB) *PostgresLoader {
	return &PostgresLoader{
		DB: db,
		Query: `
			SELECT rule_type, pattern, reason, category
			FROM blocklist
			WHERE enabled = true
			ORDER BY id
		`,
	}
}

// Load implements swg.RuleLoader.
func (l *PostgresLoader) Load(ctx context.Context) ([]swg.Rule, error) {
	var rows []BlocklistRow
	if err := l.DB.SelectContext(ctx, &rows, l.Query); err != nil {
		return nil, err
	}

	rules := make([]swg.Rule, 0, len(rows))
	for _, row := range rows {
		rule := swg.Rule{
			Type:    row.RuleType,
			Pattern: row.Pattern,
			Reason:  "blocked by policy",
		}

		if row.Reason != nil {
			rule.Reason = *row.Reason
		}
		if row.Category != nil {
			rule.Category = *row.Category
		}

		rules = append(rules, rule)
	}

	return rules, nil
}

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	// Connect to database
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		databaseURL = "postgres://localhost/swg?sslmode=disable"
	}

	db, err := sqlx.Connect("postgres", databaseURL)
	if err != nil {
		logger.Error("connect to database", "error", err)
		os.Exit(1)
	}
	defer db.Close()

	// Test connection
	if err := db.Ping(); err != nil {
		logger.Error("ping database", "error", err)
		os.Exit(1)
	}
	logger.Info("connected to database")

	// Generate CA certificate
	certPEM, keyPEM, err := swg.GenerateCA("Example Proxy", 1)
	if err != nil {
		logger.Error("generate CA", "error", err)
		os.Exit(1)
	}

	cm, err := swg.NewCertManagerFromPEM(certPEM, keyPEM)
	if err != nil {
		logger.Error("create cert manager", "error", err)
		os.Exit(1)
	}

	// Create PostgreSQL loader
	pgLoader := NewPostgresLoader(db)

	// Optionally use a custom query
	// pgLoader.Query = `SELECT rule_type, pattern, reason, category FROM blocklist WHERE enabled = true AND category = 'security'`

	// Create reloadable filter
	filter := swg.NewReloadableFilter(pgLoader)

	filter.OnReload = func(count int) {
		logger.Info("blocklist reloaded from database", "rules", count)
	}
	filter.OnError = func(err error) {
		logger.Error("blocklist reload failed", "error", err)
	}

	// Initial load
	ctx := context.Background()
	if err := filter.Load(ctx); err != nil {
		logger.Error("initial load failed", "error", err)
		os.Exit(1)
	}

	// Start auto-reload every minute
	cancel := filter.StartAutoReload(ctx, 1*time.Minute)
	defer cancel()

	// Create and configure proxy
	proxy := swg.NewProxy(":8080", cm)
	proxy.Logger = logger
	proxy.Filter = filter

	logger.Info("starting proxy with PostgreSQL blocklist", "addr", ":8080")
	if err := proxy.ListenAndServe(); err != nil {
		logger.Error("proxy error", "error", err)
	}
}
