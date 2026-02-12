// Example: Allow-list mode with time-based rules
//
// This example shows how to combine AllowListFilter with TimeRule
// to create a kiosk-style proxy that only allows certain sites
// during business hours and blocks everything outside that window.
//
// Usage:
//
//	go run .
package main

import (
	"log/slog"
	"os"
	"time"

	"github.com/acmacalister/swg"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

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

	// --- Allow-list: only these domains are permitted ---
	allow := swg.NewAllowListFilter()
	allow.AddDomains([]string{
		"docs.google.com",
		"*.wikipedia.org",
		"stackoverflow.com",
		"*.golang.org",
		"pkg.go.dev",
	})

	// --- Time-based social media block ---
	// Block social media Mon-Fri 9am-5pm US Eastern
	eastern, _ := time.LoadLocation("America/New_York")
	socialBlock := swg.NewDomainFilter()
	socialBlock.AddDomains([]string{
		"twitter.com",
		"facebook.com",
		"instagram.com",
		"reddit.com",
		"tiktok.com",
	})

	socialTimeRule := &swg.TimeRule{
		Inner:     socialBlock,
		StartHour: 9,
		EndHour:   17,
		Weekdays: []time.Weekday{
			time.Monday, time.Tuesday, time.Wednesday,
			time.Thursday, time.Friday,
		},
		Location: eastern,
	}

	// --- After-hours total block ---
	// Block everything except allowed sites from 10pm-6am every day
	afterHoursBlock := &swg.TimeRule{
		Inner:     allow, // allow-list filter blocks everything NOT on the list
		StartHour: 22,
		EndHour:   6,
	}

	// --- Combine filters ---
	proxy := swg.NewProxy(":8080", cm)
	proxy.Logger = logger
	proxy.Filter = &swg.ChainFilter{
		Filters: []swg.Filter{
			socialTimeRule,
			afterHoursBlock,
		},
	}

	logger.Info("starting proxy with time-based rules", "addr", ":8080")
	if err := proxy.ListenAndServe(); err != nil {
		logger.Error("proxy error", "error", err)
	}
}
