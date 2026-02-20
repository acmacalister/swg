// Example: WebSocket interception
//
// This example demonstrates WebSocket message interception and filtering.
// The proxy intercepts WebSocket frames and can:
// - Log all messages (direction, type, size)
// - Block messages containing specific content
// - Modify messages before forwarding
//
// Test with any WebSocket echo server, for example:
//
//	# Configure browser/client to use proxy at localhost:8080
//	# Connect to wss://echo.websocket.org or similar
//
// The proxy will log all WebSocket messages passing through.
package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"github.com/acmacalister/swg"
)

// LoggingWebSocketHandler logs all WebSocket messages and can optionally
// block messages containing specific content.
type LoggingWebSocketHandler struct {
	Logger       *slog.Logger
	BlockedWords []string
}

func (h *LoggingWebSocketHandler) OnConnect(ctx context.Context, req *http.Request, resp *http.Response) error {
	h.Logger.Info("websocket connected",
		"host", req.Host,
		"path", req.URL.Path,
		"status", resp.StatusCode)
	return nil
}

func (h *LoggingWebSocketHandler) OnMessage(ctx context.Context, msg *swg.WebSocketMessage) (*swg.WebSocketMessage, error) {
	// Log the message
	attrs := []any{
		"direction", msg.Direction.String(),
		"opcode", opcodeToString(msg.Opcode),
		"size", len(msg.Payload),
	}

	// For text messages, log a preview
	if msg.IsText() && len(msg.Payload) > 0 {
		preview := string(msg.Payload)
		if len(preview) > 100 {
			preview = preview[:100] + "..."
		}
		attrs = append(attrs, "preview", preview)
	}

	// For close frames, log the code and reason
	if msg.Opcode == swg.OpcodeClose {
		attrs = append(attrs, "close_code", msg.CloseCode())
		if reason := msg.CloseReason(); reason != "" {
			attrs = append(attrs, "close_reason", reason)
		}
	}

	h.Logger.Debug("websocket message", attrs...)

	// Check for blocked content in text messages
	if msg.IsText() && len(h.BlockedWords) > 0 {
		content := strings.ToLower(string(msg.Payload))
		for _, word := range h.BlockedWords {
			if strings.Contains(content, strings.ToLower(word)) {
				h.Logger.Warn("blocked websocket message",
					"direction", msg.Direction.String(),
					"blocked_word", word)
				return nil, nil // Drop the message
			}
		}
	}

	return msg, nil
}

func (h *LoggingWebSocketHandler) OnClose(ctx context.Context, code uint16, reason string) {
	h.Logger.Info("websocket closed",
		"code", code,
		"code_desc", swg.CloseCodeString(code),
		"reason", reason)
}

func opcodeToString(opcode byte) string {
	switch opcode {
	case swg.OpcodeContinuation:
		return "continuation"
	case swg.OpcodeText:
		return "text"
	case swg.OpcodeBinary:
		return "binary"
	case swg.OpcodeClose:
		return "close"
	case swg.OpcodePing:
		return "ping"
	case swg.OpcodePong:
		return "pong"
	default:
		return "unknown"
	}
}

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))

	// Generate CA certificate
	certPEM, keyPEM, err := swg.GenerateCA("WebSocket Proxy", 1)
	if err != nil {
		logger.Error("generate CA", "error", err)
		os.Exit(1)
	}

	cm, err := swg.NewCertManagerFromPEM(certPEM, keyPEM)
	if err != nil {
		logger.Error("create cert manager", "error", err)
		os.Exit(1)
	}

	// Create WebSocket handler
	wsHandler := &LoggingWebSocketHandler{
		Logger: logger,
		// Example: block messages containing these words
		BlockedWords: []string{"blocked", "forbidden"},
	}

	proxy := swg.NewProxy(":8080", cm)
	proxy.Logger = logger
	proxy.WebSocketHandler = wsHandler
	proxy.WebSocketConfig = swg.DefaultWebSocketConfig()

	logger.Info("starting websocket proxy",
		"addr", ":8080",
		"blocked_words", wsHandler.BlockedWords)
	logger.Info("configure your client to use this proxy and connect to any WebSocket server")
	logger.Info("messages containing blocked words will be dropped silently")

	if err := proxy.ListenAndServe(); err != nil {
		logger.Error("proxy error", "error", err)
	}
}
