package swg

import (
	"context"
	"log/slog"
	"time"
)

// AccessLogger writes structured access log entries for each proxied request.
// It uses slog.LogAttrs for low-allocation logging on the hot path.
type AccessLogger struct {
	logger *slog.Logger
}

// AccessLogEntry contains all fields for a single access log record.
type AccessLogEntry struct {
	// Timestamp when the request was received.
	Timestamp time.Time

	// Method is the HTTP method (GET, POST, CONNECT, etc.).
	Method string

	// Host is the target hostname.
	Host string

	// Path is the request URL path.
	Path string

	// Scheme is "http" or "https".
	Scheme string

	// StatusCode is the upstream response status code. Zero if blocked or errored.
	StatusCode int

	// Duration is the time to process the request.
	Duration time.Duration

	// BytesWritten is the response body size.
	BytesWritten int64

	// ClientAddr is the client's remote address.
	ClientAddr string

	// Blocked is true if the request was blocked by a filter.
	Blocked bool

	// BlockReason is the reason the request was blocked (if Blocked is true).
	BlockReason string

	// Error is a description of any error that occurred.
	Error string

	// UserAgent is the client's User-Agent header.
	UserAgent string
}

// NewAccessLogger creates a new AccessLogger that writes to the given slog.Logger.
// For best performance, pass a logger configured with slog.NewJSONHandler.
func NewAccessLogger(logger *slog.Logger) *AccessLogger {
	return &AccessLogger{logger: logger}
}

// Log writes an access log entry using slog.LogAttrs to minimize allocations.
func (al *AccessLogger) Log(e AccessLogEntry) {
	attrs := make([]slog.Attr, 0, 12)

	attrs = append(attrs,
		slog.Time("timestamp", e.Timestamp),
		slog.String("method", e.Method),
		slog.String("host", e.Host),
		slog.String("path", e.Path),
		slog.String("scheme", e.Scheme),
		slog.String("client", e.ClientAddr),
	)

	if e.Blocked {
		attrs = append(attrs,
			slog.Bool("blocked", true),
			slog.String("block_reason", e.BlockReason),
		)
	} else {
		attrs = append(attrs,
			slog.Int("status", e.StatusCode),
			slog.Int64("bytes", e.BytesWritten),
		)
	}

	attrs = append(attrs,
		slog.Duration("duration", e.Duration),
	)

	if e.Error != "" {
		attrs = append(attrs, slog.String("error", e.Error))
	}

	if e.UserAgent != "" {
		attrs = append(attrs, slog.String("user_agent", e.UserAgent))
	}

	al.logger.LogAttrs(context.Background(), slog.LevelInfo, "access", attrs...)
}
