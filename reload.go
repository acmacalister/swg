package swg

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
)

// SIGHUPReloader watches for SIGHUP signals and reloads the proxy filter.
// Call Cancel to stop watching.
type SIGHUPReloader struct {
	cancel context.CancelFunc
	done   chan struct{}
}

// Cancel stops the SIGHUP watcher.
func (r *SIGHUPReloader) Cancel() {
	r.cancel()
	<-r.done
}

// ReloadFunc is called on each SIGHUP. It should reload configuration and
// return the new Filter (or nil to keep the current one) and any error.
type ReloadFunc func(ctx context.Context) (Filter, error)

// WatchSIGHUP starts a goroutine that listens for SIGHUP signals and calls
// the reload function. If reload returns a non-nil Filter, it is assigned to
// the proxy. The returned SIGHUPReloader can be used to stop watching.
func WatchSIGHUP(proxy *Proxy, reload ReloadFunc, logger *slog.Logger) *SIGHUPReloader {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGHUP)

	go func() {
		defer close(done)
		defer signal.Stop(sigCh)

		for {
			select {
			case <-ctx.Done():
				return
			case <-sigCh:
				logger.Info("received SIGHUP, reloading...")
				f, err := reload(ctx)
				if err != nil {
					logger.Error("reload failed", "error", err)
					continue
				}
				if f != nil {
					proxy.Filter = f
					logger.Info("filter reloaded successfully")
				}
			}
		}
	}()

	return &SIGHUPReloader{cancel: cancel, done: done}
}
