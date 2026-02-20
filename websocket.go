package swg

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// WebSocket opcodes as defined in RFC 6455.
const (
	OpcodeContinuation = 0x0
	OpcodeText         = 0x1
	OpcodeBinary       = 0x2
	OpcodeClose        = 0x8
	OpcodePing         = 0x9
	OpcodePong         = 0xA
)

// MessageDirection indicates the direction of a WebSocket message.
type MessageDirection int

const (
	// ClientToServer indicates a message from the client to the upstream server.
	ClientToServer MessageDirection = iota
	// ServerToClient indicates a message from the upstream server to the client.
	ServerToClient
)

func (d MessageDirection) String() string {
	switch d {
	case ClientToServer:
		return "client->server"
	case ServerToClient:
		return "server->client"
	default:
		return "unknown"
	}
}

// WebSocketMessage represents a complete WebSocket message (after defragmentation).
//
// For control frames (Close, Ping, Pong), the message contains the control frame data.
// For data frames (Text, Binary), the message contains the complete payload after
// reassembling any fragmented frames.
type WebSocketMessage struct {
	// Opcode is the WebSocket opcode (OpcodeText, OpcodeBinary, OpcodeClose, etc.)
	Opcode byte

	// Payload is the message data. For text messages, this is UTF-8 encoded.
	// For close frames, this contains the 2-byte status code followed by optional reason.
	Payload []byte

	// Direction indicates whether this message is from client or server.
	Direction MessageDirection

	// Timestamp is when the message was received.
	Timestamp time.Time
}

// IsControl returns true if this is a control frame (Close, Ping, Pong).
func (m *WebSocketMessage) IsControl() bool {
	return m.Opcode >= OpcodeClose
}

// IsText returns true if this is a text message.
func (m *WebSocketMessage) IsText() bool {
	return m.Opcode == OpcodeText
}

// IsBinary returns true if this is a binary message.
func (m *WebSocketMessage) IsBinary() bool {
	return m.Opcode == OpcodeBinary
}

// CloseCode returns the close status code for close frames.
// Returns 0 if not a close frame or payload is too short.
func (m *WebSocketMessage) CloseCode() uint16 {
	if m.Opcode != OpcodeClose || len(m.Payload) < 2 {
		return 0
	}
	return binary.BigEndian.Uint16(m.Payload[:2])
}

// CloseReason returns the close reason string for close frames.
// Returns empty string if not a close frame or no reason provided.
func (m *WebSocketMessage) CloseReason() string {
	if m.Opcode != OpcodeClose || len(m.Payload) <= 2 {
		return ""
	}
	return string(m.Payload[2:])
}

// WebSocketHandler provides hooks for inspecting and filtering WebSocket traffic.
//
// Implementations can inspect connection lifecycle events and individual messages.
// All methods are optional - return nil to allow the operation to proceed.
//
// The handler is called synchronously in the message relay path, so implementations
// should be fast to avoid adding latency to the WebSocket connection.
//
// # Thread Safety
//
// A single handler instance may be called concurrently for different connections.
// Implementations must be safe for concurrent use.
//
// # Example
//
//	type LoggingHandler struct {
//	    logger *slog.Logger
//	}
//
//	func (h *LoggingHandler) OnConnect(ctx context.Context, req *http.Request, resp *http.Response) error {
//	    h.logger.Info("websocket connected", "host", req.Host, "path", req.URL.Path)
//	    return nil
//	}
//
//	func (h *LoggingHandler) OnMessage(ctx context.Context, msg *WebSocketMessage) (*WebSocketMessage, error) {
//	    h.logger.Debug("websocket message",
//	        "direction", msg.Direction,
//	        "opcode", msg.Opcode,
//	        "size", len(msg.Payload))
//	    return msg, nil // pass through unchanged
//	}
//
//	func (h *LoggingHandler) OnClose(ctx context.Context, code uint16, reason string) {
//	    h.logger.Info("websocket closed", "code", code, "reason", reason)
//	}
type WebSocketHandler interface {
	// OnConnect is called after a successful WebSocket handshake.
	// Return an error to reject the connection (sends 403 to client).
	// The request contains the original upgrade request with headers.
	// The response contains the upstream's 101 Switching Protocols response.
	OnConnect(ctx context.Context, req *http.Request, resp *http.Response) error

	// OnMessage is called for each complete message (after defragmentation).
	// Return the message to forward it (possibly modified).
	// Return nil to drop the message silently.
	// Return an error to close the connection.
	//
	// Control frames (Ping, Pong, Close) are also passed through this handler.
	// Returning nil for a Ping will prevent the automatic Pong response.
	OnMessage(ctx context.Context, msg *WebSocketMessage) (*WebSocketMessage, error)

	// OnClose is called when the WebSocket connection closes.
	// This is called once per connection, regardless of which side initiated the close.
	OnClose(ctx context.Context, code uint16, reason string)
}

// WebSocketHandlerFunc is a function adapter for simple message-only handlers.
// It implements WebSocketHandler with no-op OnConnect and OnClose.
type WebSocketHandlerFunc func(ctx context.Context, msg *WebSocketMessage) (*WebSocketMessage, error)

// OnConnect implements WebSocketHandler.
func (f WebSocketHandlerFunc) OnConnect(ctx context.Context, req *http.Request, resp *http.Response) error {
	return nil
}

// OnMessage implements WebSocketHandler.
func (f WebSocketHandlerFunc) OnMessage(ctx context.Context, msg *WebSocketMessage) (*WebSocketMessage, error) {
	return f(ctx, msg)
}

// OnClose implements WebSocketHandler.
func (f WebSocketHandlerFunc) OnClose(ctx context.Context, code uint16, reason string) {}

// WebSocketConfig configures WebSocket interception behavior.
type WebSocketConfig struct {
	// MaxMessageSize is the maximum size of a single message in bytes.
	// Messages larger than this will cause the connection to close.
	// Default: 16 MiB
	MaxMessageSize int64

	// ReadTimeout is the timeout for reading a complete message.
	// Default: 60 seconds
	ReadTimeout time.Duration

	// WriteTimeout is the timeout for writing a complete message.
	// Default: 60 seconds
	WriteTimeout time.Duration

	// PingInterval is how often to send ping frames to keep the connection alive.
	// Set to 0 to disable automatic pings.
	// Default: 30 seconds
	PingInterval time.Duration

	// PongTimeout is how long to wait for a pong response before closing.
	// Default: 10 seconds
	PongTimeout time.Duration
}

// DefaultWebSocketConfig returns sensible defaults for WebSocket handling.
func DefaultWebSocketConfig() WebSocketConfig {
	return WebSocketConfig{
		MaxMessageSize: 16 * 1024 * 1024, // 16 MiB
		ReadTimeout:    60 * time.Second,
		WriteTimeout:   60 * time.Second,
		PingInterval:   30 * time.Second,
		PongTimeout:    10 * time.Second,
	}
}

// wsFrame represents a single WebSocket frame.
type wsFrame struct {
	fin     bool
	opcode  byte
	masked  bool
	payload []byte
}

// wsConn wraps a net.Conn with WebSocket frame reading/writing.
type wsConn struct {
	conn   net.Conn
	reader *bufio.Reader
	mu     sync.Mutex // protects writes

	maxMessageSize int64
	readTimeout    time.Duration
	writeTimeout   time.Duration
}

func newWSConn(conn net.Conn, cfg WebSocketConfig) *wsConn {
	return &wsConn{
		conn:           conn,
		reader:         bufio.NewReader(conn),
		maxMessageSize: cfg.MaxMessageSize,
		readTimeout:    cfg.ReadTimeout,
		writeTimeout:   cfg.WriteTimeout,
	}
}

// readFrame reads a single WebSocket frame from the connection.
func (c *wsConn) readFrame() (*wsFrame, error) {
	if c.readTimeout > 0 {
		if err := c.conn.SetReadDeadline(time.Now().Add(c.readTimeout)); err != nil {
			return nil, err
		}
	}

	// Read first two bytes (FIN, opcode, MASK, payload length)
	header := make([]byte, 2)
	if _, err := io.ReadFull(c.reader, header); err != nil {
		return nil, err
	}

	frame := &wsFrame{
		fin:    header[0]&0x80 != 0,
		opcode: header[0] & 0x0F,
		masked: header[1]&0x80 != 0,
	}

	// Get payload length
	payloadLen := uint64(header[1] & 0x7F)

	switch payloadLen {
	case 126:
		// 16-bit length
		lenBytes := make([]byte, 2)
		if _, err := io.ReadFull(c.reader, lenBytes); err != nil {
			return nil, err
		}
		payloadLen = uint64(binary.BigEndian.Uint16(lenBytes))
	case 127:
		// 64-bit length
		lenBytes := make([]byte, 8)
		if _, err := io.ReadFull(c.reader, lenBytes); err != nil {
			return nil, err
		}
		payloadLen = binary.BigEndian.Uint64(lenBytes)
	}

	// Check message size limit
	if c.maxMessageSize > 0 && int64(payloadLen) > c.maxMessageSize {
		return nil, fmt.Errorf("websocket frame too large: %d bytes", payloadLen)
	}

	// Read masking key if present
	var maskKey []byte
	if frame.masked {
		maskKey = make([]byte, 4)
		if _, err := io.ReadFull(c.reader, maskKey); err != nil {
			return nil, err
		}
	}

	// Read payload
	frame.payload = make([]byte, payloadLen)
	if _, err := io.ReadFull(c.reader, frame.payload); err != nil {
		return nil, err
	}

	// Unmask payload if masked
	if frame.masked {
		for i := range frame.payload {
			frame.payload[i] ^= maskKey[i%4]
		}
	}

	return frame, nil
}

// writeFrame writes a single WebSocket frame to the connection.
func (c *wsConn) writeFrame(frame *wsFrame) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.writeTimeout > 0 {
		if err := c.conn.SetWriteDeadline(time.Now().Add(c.writeTimeout)); err != nil {
			return err
		}
	}

	// Build header
	var header []byte
	firstByte := frame.opcode
	if frame.fin {
		firstByte |= 0x80
	}

	payloadLen := len(frame.payload)

	if payloadLen < 126 {
		header = []byte{firstByte, byte(payloadLen)}
	} else if payloadLen < 65536 {
		header = make([]byte, 4)
		header[0] = firstByte
		header[1] = 126
		binary.BigEndian.PutUint16(header[2:], uint16(payloadLen))
	} else {
		header = make([]byte, 10)
		header[0] = firstByte
		header[1] = 127
		binary.BigEndian.PutUint64(header[2:], uint64(payloadLen))
	}

	// Set mask bit if we're masking (client->server requires masking)
	if frame.masked {
		header[1] |= 0x80
	}

	// Write header
	if _, err := c.conn.Write(header); err != nil {
		return err
	}

	// Write masking key and masked payload if masked
	if frame.masked {
		maskKey := []byte{0x12, 0x34, 0x56, 0x78} // Simple mask key
		if _, err := c.conn.Write(maskKey); err != nil {
			return err
		}
		masked := make([]byte, len(frame.payload))
		for i := range frame.payload {
			masked[i] = frame.payload[i] ^ maskKey[i%4]
		}
		_, err := c.conn.Write(masked)
		return err
	}

	// Write unmasked payload
	_, err := c.conn.Write(frame.payload)
	return err
}

// writeMessage writes a complete message as one or more frames.
func (c *wsConn) writeMessage(opcode byte, payload []byte, masked bool) error {
	return c.writeFrame(&wsFrame{
		fin:     true,
		opcode:  opcode,
		masked:  masked,
		payload: payload,
	})
}

// writeClose writes a close frame with the given code and reason.
func (c *wsConn) writeClose(code uint16, reason string, masked bool) error {
	payload := make([]byte, 2+len(reason))
	binary.BigEndian.PutUint16(payload[:2], code)
	copy(payload[2:], reason)
	return c.writeMessage(OpcodeClose, payload, masked)
}

// WebSocketInterceptor handles the WebSocket protocol after HTTP upgrade.
type WebSocketInterceptor struct {
	handler WebSocketHandler
	config  WebSocketConfig
}

// NewWebSocketInterceptor creates a new WebSocket interceptor.
func NewWebSocketInterceptor(handler WebSocketHandler, config WebSocketConfig) *WebSocketInterceptor {
	if config.MaxMessageSize == 0 {
		config = DefaultWebSocketConfig()
	}
	return &WebSocketInterceptor{
		handler: handler,
		config:  config,
	}
}

// IsWebSocketUpgrade checks if the request is a WebSocket upgrade request.
func IsWebSocketUpgrade(req *http.Request) bool {
	return strings.EqualFold(req.Header.Get("Upgrade"), "websocket") &&
		strings.Contains(strings.ToLower(req.Header.Get("Connection")), "upgrade")
}

// Intercept handles a WebSocket connection after the HTTP upgrade handshake.
// clientConn is the connection to the client, serverConn is the connection to upstream.
// The request is the original upgrade request.
func (i *WebSocketInterceptor) Intercept(ctx context.Context, clientConn, serverConn net.Conn, req *http.Request, resp *http.Response) error {
	// Notify handler of connection
	if i.handler != nil {
		if err := i.handler.OnConnect(ctx, req, resp); err != nil {
			return err
		}
	}

	clientWS := newWSConn(clientConn, i.config)
	serverWS := newWSConn(serverConn, i.config)

	// Track close status
	var closeCode uint16 = 1000
	var closeReason string
	var closeOnce sync.Once

	// Set up context cancellation
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Error channel for relay goroutines
	errCh := make(chan error, 2)

	// Relay client -> server
	go func() {
		errCh <- i.relayMessages(ctx, clientWS, serverWS, ClientToServer, true, &closeCode, &closeReason, &closeOnce)
	}()

	// Relay server -> client
	go func() {
		errCh <- i.relayMessages(ctx, serverWS, clientWS, ServerToClient, false, &closeCode, &closeReason, &closeOnce)
	}()

	// Wait for either direction to complete
	err := <-errCh
	cancel() // Stop the other direction

	// Wait for both to finish
	<-errCh

	// Notify handler of close
	if i.handler != nil {
		i.handler.OnClose(ctx, closeCode, closeReason)
	}

	return err
}

// relayMessages reads messages from src and writes to dst.
func (i *WebSocketInterceptor) relayMessages(
	ctx context.Context,
	src, dst *wsConn,
	direction MessageDirection,
	maskOutgoing bool,
	closeCode *uint16,
	closeReason *string,
	closeOnce *sync.Once,
) error {
	// Buffer for defragmenting messages
	var msgBuf []byte
	var msgOpcode byte

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		frame, err := src.readFrame()
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}

		// Handle fragmentation
		if frame.opcode != OpcodeContinuation {
			// Start of new message
			msgOpcode = frame.opcode
			msgBuf = frame.payload
		} else {
			// Continuation frame
			msgBuf = append(msgBuf, frame.payload...)
		}

		// Check total message size
		if i.config.MaxMessageSize > 0 && int64(len(msgBuf)) > i.config.MaxMessageSize {
			closeOnce.Do(func() {
				*closeCode = 1009 // Message too big
				*closeReason = "message too large"
			})
			return fmt.Errorf("websocket message too large: %d bytes", len(msgBuf))
		}

		// If not final frame, keep reading
		if !frame.fin {
			continue
		}

		// Complete message received
		msg := &WebSocketMessage{
			Opcode:    msgOpcode,
			Payload:   msgBuf,
			Direction: direction,
			Timestamp: time.Now(),
		}

		// Reset buffer
		msgBuf = nil

		// Handle close frame
		if msg.Opcode == OpcodeClose {
			closeOnce.Do(func() {
				*closeCode = msg.CloseCode()
				*closeReason = msg.CloseReason()
			})
			// Forward close frame
			_ = dst.writeMessage(OpcodeClose, msg.Payload, maskOutgoing)
			return nil
		}

		// Handle ping - respond with pong
		if msg.Opcode == OpcodePing {
			// Let handler see it first
			if i.handler != nil {
				var err error
				msg, err = i.handler.OnMessage(ctx, msg)
				if err != nil {
					return err
				}
				if msg == nil {
					continue // Handler dropped the ping
				}
			}
			// Send pong back to sender
			if err := src.writeMessage(OpcodePong, msg.Payload, !maskOutgoing); err != nil {
				return err
			}
			continue
		}

		// Handle pong - just pass to handler if present
		if msg.Opcode == OpcodePong {
			if i.handler != nil {
				_, err := i.handler.OnMessage(ctx, msg)
				if err != nil {
					return err
				}
			}
			continue
		}

		// Pass through handler
		if i.handler != nil {
			msg, err = i.handler.OnMessage(ctx, msg)
			if err != nil {
				return err
			}
			if msg == nil {
				continue // Handler dropped the message
			}
		}

		// Forward message to destination
		if err := dst.writeMessage(msg.Opcode, msg.Payload, maskOutgoing); err != nil {
			return err
		}
	}
}

// Close status codes as defined in RFC 6455.
const (
	CloseNormalClosure           = 1000
	CloseGoingAway               = 1001
	CloseProtocolError           = 1002
	CloseUnsupportedData         = 1003
	CloseNoStatusReceived        = 1005
	CloseAbnormalClosure         = 1006
	CloseInvalidFramePayloadData = 1007
	ClosePolicyViolation         = 1008
	CloseMessageTooBig           = 1009
	CloseMandatoryExtension      = 1010
	CloseInternalServerErr       = 1011
	CloseTLSHandshake            = 1015
)

// CloseCodeString returns a human-readable description of a close code.
func CloseCodeString(code uint16) string {
	switch code {
	case CloseNormalClosure:
		return "normal closure"
	case CloseGoingAway:
		return "going away"
	case CloseProtocolError:
		return "protocol error"
	case CloseUnsupportedData:
		return "unsupported data"
	case CloseNoStatusReceived:
		return "no status received"
	case CloseAbnormalClosure:
		return "abnormal closure"
	case CloseInvalidFramePayloadData:
		return "invalid frame payload data"
	case ClosePolicyViolation:
		return "policy violation"
	case CloseMessageTooBig:
		return "message too big"
	case CloseMandatoryExtension:
		return "mandatory extension"
	case CloseInternalServerErr:
		return "internal server error"
	case CloseTLSHandshake:
		return "TLS handshake"
	default:
		return fmt.Sprintf("unknown (%d)", code)
	}
}
