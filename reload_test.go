package swg

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func TestWatchSIGHUP_Reload(t *testing.T) {
	certPEM, keyPEM, _ := GenerateCA("Test", 1)
	cm, _ := NewCertManagerFromPEM(certPEM, keyPEM)

	proxy := NewProxy(":0", cm)
	proxy.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))

	oldFilter := NewDomainFilter()
	oldFilter.AddDomain("old.com")
	proxy.Filter = oldFilter

	newFilter := NewDomainFilter()
	newFilter.AddDomain("new.com")

	var called atomic.Int32
	reload := func(_ context.Context) (Filter, error) {
		called.Add(1)
		return newFilter, nil
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	reloader := WatchSIGHUP(proxy, reload, logger)

	_ = syscall.Kill(syscall.Getpid(), syscall.SIGHUP)

	deadline := time.After(2 * time.Second)
	for called.Load() == 0 {
		select {
		case <-deadline:
			t.Fatal("timed out waiting for reload")
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}

	reloader.Cancel()

	req := &http.Request{Host: "new.com"}
	blocked, _ := proxy.Filter.ShouldBlock(req)
	if !blocked {
		t.Error("new filter should block new.com")
	}

	req2 := &http.Request{Host: "old.com"}
	blocked2, _ := proxy.Filter.ShouldBlock(req2)
	if blocked2 {
		t.Error("new filter should not block old.com")
	}
}

func TestWatchSIGHUP_ReloadError(t *testing.T) {
	certPEM, keyPEM, _ := GenerateCA("Test", 1)
	cm, _ := NewCertManagerFromPEM(certPEM, keyPEM)

	proxy := NewProxy(":0", cm)
	proxy.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))

	origFilter := NewDomainFilter()
	origFilter.AddDomain("keep.com")
	proxy.Filter = origFilter

	var called atomic.Int32
	reload := func(_ context.Context) (Filter, error) {
		called.Add(1)
		return nil, fmt.Errorf("config load failed")
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	reloader := WatchSIGHUP(proxy, reload, logger)
	defer reloader.Cancel()

	_ = syscall.Kill(syscall.Getpid(), syscall.SIGHUP)

	deadline := time.After(2 * time.Second)
	for called.Load() == 0 {
		select {
		case <-deadline:
			t.Fatal("timed out waiting for reload")
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}

	if proxy.Filter != origFilter {
		t.Error("proxy.Filter should not change on error")
	}
}

func TestWatchSIGHUP_NilFilter(t *testing.T) {
	certPEM, keyPEM, _ := GenerateCA("Test", 1)
	cm, _ := NewCertManagerFromPEM(certPEM, keyPEM)

	proxy := NewProxy(":0", cm)
	proxy.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))

	origFilter := NewDomainFilter()
	origFilter.AddDomain("keep.com")
	proxy.Filter = origFilter

	var called atomic.Int32
	reload := func(_ context.Context) (Filter, error) {
		called.Add(1)
		return nil, nil
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	reloader := WatchSIGHUP(proxy, reload, logger)
	defer reloader.Cancel()

	_ = syscall.Kill(syscall.Getpid(), syscall.SIGHUP)

	deadline := time.After(2 * time.Second)
	for called.Load() == 0 {
		select {
		case <-deadline:
			t.Fatal("timed out waiting for reload")
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}

	if proxy.Filter != origFilter {
		t.Error("proxy.Filter should not change when reload returns nil")
	}
}

func TestSIGHUPReloader_Cancel(t *testing.T) {
	certPEM, keyPEM, _ := GenerateCA("Test", 1)
	cm, _ := NewCertManagerFromPEM(certPEM, keyPEM)

	proxy := NewProxy(":0", cm)
	proxy.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))

	reload := func(_ context.Context) (Filter, error) {
		return nil, nil
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	reloader := WatchSIGHUP(proxy, reload, logger)

	done := make(chan struct{})
	go func() {
		reloader.Cancel()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Cancel did not return in time")
	}
}
