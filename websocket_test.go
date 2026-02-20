package swg

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"
)

func TestIsWebSocketUpgrade(t *testing.T) {
	tests := []struct {
		name    string
		headers map[string]string
		want    bool
	}{
		{
			name: "valid upgrade",
			headers: map[string]string{
				"Upgrade":    "websocket",
				"Connection": "Upgrade",
			},
			want: true,
		},
		{
			name: "valid upgrade lowercase",
			headers: map[string]string{
				"Upgrade":    "WebSocket",
				"Connection": "upgrade",
			},
			want: true,
		},
		{
			name: "valid with keep-alive",
			headers: map[string]string{
				"Upgrade":    "websocket",
				"Connection": "keep-alive, Upgrade",
			},
			want: true,
		},
		{
			name: "missing upgrade header",
			headers: map[string]string{
				"Connection": "Upgrade",
			},
			want: false,
		},
		{
			name: "missing connection header",
			headers: map[string]string{
				"Upgrade": "websocket",
			},
			want: false,
		},
		{
			name: "wrong upgrade value",
			headers: map[string]string{
				"Upgrade":    "h2c",
				"Connection": "Upgrade",
			},
			want: false,
		},
		{
			name:    "empty headers",
			headers: map[string]string{},
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &http.Request{Header: make(http.Header)}
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}
			if got := IsWebSocketUpgrade(req); got != tt.want {
				t.Errorf("IsWebSocketUpgrade() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestWebSocketMessage_Methods(t *testing.T) {
	t.Run("IsControl", func(t *testing.T) {
		tests := []struct {
			opcode byte
			want   bool
		}{
			{OpcodeContinuation, false},
			{OpcodeText, false},
			{OpcodeBinary, false},
			{OpcodeClose, true},
			{OpcodePing, true},
			{OpcodePong, true},
		}
		for _, tt := range tests {
			msg := &WebSocketMessage{Opcode: tt.opcode}
			if got := msg.IsControl(); got != tt.want {
				t.Errorf("IsControl() for opcode %d = %v, want %v", tt.opcode, got, tt.want)
			}
		}
	})

	t.Run("IsText", func(t *testing.T) {
		msg := &WebSocketMessage{Opcode: OpcodeText}
		if !msg.IsText() {
			t.Error("IsText() = false, want true")
		}
		msg.Opcode = OpcodeBinary
		if msg.IsText() {
			t.Error("IsText() = true for binary, want false")
		}
	})

	t.Run("IsBinary", func(t *testing.T) {
		msg := &WebSocketMessage{Opcode: OpcodeBinary}
		if !msg.IsBinary() {
			t.Error("IsBinary() = false, want true")
		}
		msg.Opcode = OpcodeText
		if msg.IsBinary() {
			t.Error("IsBinary() = true for text, want false")
		}
	})

	t.Run("CloseCode", func(t *testing.T) {
		payload := make([]byte, 2)
		binary.BigEndian.PutUint16(payload, CloseNormalClosure)

		msg := &WebSocketMessage{Opcode: OpcodeClose, Payload: payload}
		if got := msg.CloseCode(); got != CloseNormalClosure {
			t.Errorf("CloseCode() = %d, want %d", got, CloseNormalClosure)
		}

		// Not a close frame
		msg.Opcode = OpcodeText
		if got := msg.CloseCode(); got != 0 {
			t.Errorf("CloseCode() for text = %d, want 0", got)
		}

		// Payload too short
		msg.Opcode = OpcodeClose
		msg.Payload = []byte{0x03}
		if got := msg.CloseCode(); got != 0 {
			t.Errorf("CloseCode() for short payload = %d, want 0", got)
		}
	})

	t.Run("CloseReason", func(t *testing.T) {
		payload := make([]byte, 2+len("goodbye"))
		binary.BigEndian.PutUint16(payload, CloseNormalClosure)
		copy(payload[2:], "goodbye")

		msg := &WebSocketMessage{Opcode: OpcodeClose, Payload: payload}
		if got := msg.CloseReason(); got != "goodbye" {
			t.Errorf("CloseReason() = %q, want %q", got, "goodbye")
		}

		// No reason
		msg.Payload = payload[:2]
		if got := msg.CloseReason(); got != "" {
			t.Errorf("CloseReason() for no reason = %q, want empty", got)
		}
	})
}

func TestMessageDirection_String(t *testing.T) {
	tests := []struct {
		dir  MessageDirection
		want string
	}{
		{ClientToServer, "client->server"},
		{ServerToClient, "server->client"},
		{MessageDirection(99), "unknown"},
	}

	for _, tt := range tests {
		if got := tt.dir.String(); got != tt.want {
			t.Errorf("%d.String() = %q, want %q", tt.dir, got, tt.want)
		}
	}
}

func TestCloseCodeString(t *testing.T) {
	tests := []struct {
		code uint16
		want string
	}{
		{CloseNormalClosure, "normal closure"},
		{CloseGoingAway, "going away"},
		{CloseProtocolError, "protocol error"},
		{CloseUnsupportedData, "unsupported data"},
		{CloseNoStatusReceived, "no status received"},
		{CloseAbnormalClosure, "abnormal closure"},
		{CloseInvalidFramePayloadData, "invalid frame payload data"},
		{ClosePolicyViolation, "policy violation"},
		{CloseMessageTooBig, "message too big"},
		{CloseMandatoryExtension, "mandatory extension"},
		{CloseInternalServerErr, "internal server error"},
		{CloseTLSHandshake, "TLS handshake"},
		{9999, "unknown (9999)"},
	}

	for _, tt := range tests {
		if got := CloseCodeString(tt.code); got != tt.want {
			t.Errorf("CloseCodeString(%d) = %q, want %q", tt.code, got, tt.want)
		}
	}
}

func TestDefaultWebSocketConfig(t *testing.T) {
	cfg := DefaultWebSocketConfig()

	if cfg.MaxMessageSize != 16*1024*1024 {
		t.Errorf("MaxMessageSize = %d, want %d", cfg.MaxMessageSize, 16*1024*1024)
	}
	if cfg.ReadTimeout != 60*time.Second {
		t.Errorf("ReadTimeout = %v, want %v", cfg.ReadTimeout, 60*time.Second)
	}
	if cfg.WriteTimeout != 60*time.Second {
		t.Errorf("WriteTimeout = %v, want %v", cfg.WriteTimeout, 60*time.Second)
	}
	if cfg.PingInterval != 30*time.Second {
		t.Errorf("PingInterval = %v, want %v", cfg.PingInterval, 30*time.Second)
	}
	if cfg.PongTimeout != 10*time.Second {
		t.Errorf("PongTimeout = %v, want %v", cfg.PongTimeout, 10*time.Second)
	}
}

func TestWebSocketHandlerFunc(t *testing.T) {
	called := false
	handler := WebSocketHandlerFunc(func(ctx context.Context, msg *WebSocketMessage) (*WebSocketMessage, error) {
		called = true
		return msg, nil
	})

	// OnConnect should be no-op
	if err := handler.OnConnect(context.Background(), nil, nil); err != nil {
		t.Errorf("OnConnect() error = %v", err)
	}

	// OnMessage should call the function
	msg := &WebSocketMessage{Opcode: OpcodeText, Payload: []byte("hello")}
	result, err := handler.OnMessage(context.Background(), msg)
	if err != nil {
		t.Errorf("OnMessage() error = %v", err)
	}
	if result != msg {
		t.Error("OnMessage() did not return original message")
	}
	if !called {
		t.Error("OnMessage() did not call handler function")
	}

	// OnClose should be no-op (no panic)
	handler.OnClose(context.Background(), 1000, "test")
}

// testPipe creates a pair of connected net.Conn for testing
func testPipe() (client, server net.Conn) {
	client, server = net.Pipe()
	return
}

func TestWSConn_ReadWriteFrame(t *testing.T) {
	client, server := testPipe()
	defer func() {
		_ = client.Close()
		_ = server.Close()
	}()

	cfg := WebSocketConfig{
		MaxMessageSize: 1024,
		ReadTimeout:    time.Second,
		WriteTimeout:   time.Second,
	}

	clientWS := newWSConn(client, cfg)
	serverWS := newWSConn(server, cfg)

	t.Run("text frame unmasked", func(t *testing.T) {
		go func() {
			err := clientWS.writeFrame(&wsFrame{
				fin:     true,
				opcode:  OpcodeText,
				masked:  false,
				payload: []byte("hello"),
			})
			if err != nil {
				t.Errorf("writeFrame error: %v", err)
			}
		}()

		frame, err := serverWS.readFrame()
		if err != nil {
			t.Fatalf("readFrame error: %v", err)
		}
		if !frame.fin {
			t.Error("frame.fin = false, want true")
		}
		if frame.opcode != OpcodeText {
			t.Errorf("frame.opcode = %d, want %d", frame.opcode, OpcodeText)
		}
		if string(frame.payload) != "hello" {
			t.Errorf("frame.payload = %q, want %q", frame.payload, "hello")
		}
	})

	t.Run("binary frame masked", func(t *testing.T) {
		go func() {
			err := clientWS.writeFrame(&wsFrame{
				fin:     true,
				opcode:  OpcodeBinary,
				masked:  true,
				payload: []byte{0x01, 0x02, 0x03, 0x04},
			})
			if err != nil {
				t.Errorf("writeFrame error: %v", err)
			}
		}()

		frame, err := serverWS.readFrame()
		if err != nil {
			t.Fatalf("readFrame error: %v", err)
		}
		if frame.opcode != OpcodeBinary {
			t.Errorf("frame.opcode = %d, want %d", frame.opcode, OpcodeBinary)
		}
		if !bytes.Equal(frame.payload, []byte{0x01, 0x02, 0x03, 0x04}) {
			t.Errorf("frame.payload = %v, want [1,2,3,4]", frame.payload)
		}
	})
}

func TestWSConn_WriteMessage(t *testing.T) {
	client, server := testPipe()
	defer func() {
		_ = client.Close()
		_ = server.Close()
	}()

	cfg := WebSocketConfig{
		MaxMessageSize: 1024,
		ReadTimeout:    time.Second,
		WriteTimeout:   time.Second,
	}

	clientWS := newWSConn(client, cfg)
	serverWS := newWSConn(server, cfg)

	go func() {
		_ = clientWS.writeMessage(OpcodeText, []byte("world"), false)
	}()

	frame, err := serverWS.readFrame()
	if err != nil {
		t.Fatalf("readFrame error: %v", err)
	}
	if !frame.fin {
		t.Error("message frame not final")
	}
	if string(frame.payload) != "world" {
		t.Errorf("payload = %q, want %q", frame.payload, "world")
	}
}

func TestWSConn_WriteClose(t *testing.T) {
	client, server := testPipe()
	defer func() {
		_ = client.Close()
		_ = server.Close()
	}()

	cfg := WebSocketConfig{
		MaxMessageSize: 1024,
		ReadTimeout:    time.Second,
		WriteTimeout:   time.Second,
	}

	clientWS := newWSConn(client, cfg)
	serverWS := newWSConn(server, cfg)

	go func() {
		_ = clientWS.writeClose(CloseNormalClosure, "bye", false)
	}()

	frame, err := serverWS.readFrame()
	if err != nil {
		t.Fatalf("readFrame error: %v", err)
	}
	if frame.opcode != OpcodeClose {
		t.Errorf("opcode = %d, want %d", frame.opcode, OpcodeClose)
	}

	// Check close code and reason
	if len(frame.payload) < 2 {
		t.Fatal("close frame payload too short")
	}
	code := binary.BigEndian.Uint16(frame.payload[:2])
	if code != CloseNormalClosure {
		t.Errorf("close code = %d, want %d", code, CloseNormalClosure)
	}
	reason := string(frame.payload[2:])
	if reason != "bye" {
		t.Errorf("close reason = %q, want %q", reason, "bye")
	}
}

func TestWSConn_ReadFrame_PayloadSizes(t *testing.T) {
	tests := []struct {
		name string
		size int
	}{
		{"small payload (< 126)", 100},
		{"medium payload (126-65535)", 1000},
		{"large payload (> 65535)", 70000},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, server := testPipe()
			defer func() {
				_ = client.Close()
				_ = server.Close()
			}()

			cfg := WebSocketConfig{
				MaxMessageSize: 100000,
				ReadTimeout:    5 * time.Second,
				WriteTimeout:   5 * time.Second,
			}

			clientWS := newWSConn(client, cfg)
			serverWS := newWSConn(server, cfg)

			payload := make([]byte, tt.size)
			for i := range payload {
				payload[i] = byte(i % 256)
			}

			go func() {
				_ = clientWS.writeMessage(OpcodeBinary, payload, false)
			}()

			frame, err := serverWS.readFrame()
			if err != nil {
				t.Fatalf("readFrame error: %v", err)
			}
			if len(frame.payload) != tt.size {
				t.Errorf("payload size = %d, want %d", len(frame.payload), tt.size)
			}
			if !bytes.Equal(frame.payload, payload) {
				t.Error("payload mismatch")
			}
		})
	}
}

func TestWSConn_ReadFrame_MessageTooLarge(t *testing.T) {
	client, server := testPipe()
	defer func() {
		_ = client.Close()
		_ = server.Close()
	}()

	cfg := WebSocketConfig{
		MaxMessageSize: 100, // Very small limit
		ReadTimeout:    time.Second,
		WriteTimeout:   time.Second,
	}

	_ = cfg // cfg used below
	serverWS := newWSConn(server, cfg)

	// Write a message larger than the limit
	go func() {
		largeCfg := WebSocketConfig{MaxMessageSize: 1000}
		largeClientWS := newWSConn(client, largeCfg)
		_ = largeClientWS.writeMessage(OpcodeText, make([]byte, 200), false)
	}()

	_, err := serverWS.readFrame()
	if err == nil {
		t.Error("expected error for oversized message")
	}
}

// mockHandler is a test implementation of WebSocketHandler
type mockHandler struct {
	mu           sync.Mutex
	connectCalls int
	messageCalls int
	closeCalls   int
	lastMessage  *WebSocketMessage
	blockMessage bool
	connectError error
	messageError error
}

func (m *mockHandler) OnConnect(ctx context.Context, req *http.Request, resp *http.Response) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.connectCalls++
	return m.connectError
}

func (m *mockHandler) OnMessage(ctx context.Context, msg *WebSocketMessage) (*WebSocketMessage, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.messageCalls++
	m.lastMessage = msg
	if m.messageError != nil {
		return nil, m.messageError
	}
	if m.blockMessage {
		return nil, nil
	}
	return msg, nil
}

func (m *mockHandler) OnClose(ctx context.Context, code uint16, reason string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closeCalls++
}

func TestWebSocketInterceptor_Intercept(t *testing.T) {
	t.Run("message relay", func(t *testing.T) {
		handler := &mockHandler{}
		cfg := DefaultWebSocketConfig()
		cfg.ReadTimeout = 500 * time.Millisecond
		cfg.WriteTimeout = 500 * time.Millisecond
		interceptor := NewWebSocketInterceptor(handler, cfg)

		// Create two pipe pairs: one for client-proxy, one for proxy-server
		clientToProxy, proxyFromClient := testPipe()
		proxyToServer, serverFromProxy := testPipe()
		defer func() {
			_ = clientToProxy.Close()
			_ = proxyFromClient.Close()
			_ = proxyToServer.Close()
			_ = serverFromProxy.Close()
		}()

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		// Start interceptor in background
		errCh := make(chan error, 1)
		go func() {
			errCh <- interceptor.Intercept(ctx, proxyFromClient, proxyToServer,
				&http.Request{}, &http.Response{StatusCode: 101})
		}()

		// Create WebSocket connections for client and server ends
		clientWS := newWSConn(clientToProxy, cfg)
		serverWS := newWSConn(serverFromProxy, cfg)

		// Send a text message from client side in goroutine
		done := make(chan struct{})
		go func() {
			defer close(done)
			// Client sends message
			if err := clientWS.writeMessage(OpcodeText, []byte("hello from client"), true); err != nil {
				t.Errorf("client write error: %v", err)
				return
			}

			// Wait a bit then send close
			time.Sleep(50 * time.Millisecond)
			_ = clientWS.writeClose(CloseNormalClosure, "done", true)
		}()

		// Server should receive the message
		frame, err := serverWS.readFrame()
		if err != nil {
			t.Fatalf("server readFrame error: %v", err)
		}
		if string(frame.payload) != "hello from client" {
			t.Errorf("server received = %q, want %q", frame.payload, "hello from client")
		}

		// Server reads close frame
		closeFrame, err := serverWS.readFrame()
		if err != nil {
			t.Fatalf("server read close error: %v", err)
		}
		if closeFrame.opcode != OpcodeClose {
			t.Errorf("expected close frame, got opcode %d", closeFrame.opcode)
		}

		<-done

		// Wait for interceptor to finish
		select {
		case <-errCh:
			// OK
		case <-time.After(2 * time.Second):
			t.Error("interceptor did not finish")
		}

		// Verify handler was called
		handler.mu.Lock()
		if handler.connectCalls != 1 {
			t.Errorf("OnConnect calls = %d, want 1", handler.connectCalls)
		}
		if handler.messageCalls < 1 {
			t.Errorf("OnMessage calls = %d, want >= 1", handler.messageCalls)
		}
		handler.mu.Unlock()
	})

	t.Run("nil handler passthrough", func(t *testing.T) {
		cfg := DefaultWebSocketConfig()
		cfg.ReadTimeout = 500 * time.Millisecond
		cfg.WriteTimeout = 500 * time.Millisecond
		interceptor := NewWebSocketInterceptor(nil, cfg)

		clientToProxy, proxyFromClient := testPipe()
		proxyToServer, serverFromProxy := testPipe()
		defer func() {
			_ = clientToProxy.Close()
			_ = proxyFromClient.Close()
			_ = proxyToServer.Close()
			_ = serverFromProxy.Close()
		}()

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		errCh := make(chan error, 1)
		go func() {
			errCh <- interceptor.Intercept(ctx, proxyFromClient, proxyToServer,
				&http.Request{}, &http.Response{StatusCode: 101})
		}()

		clientWS := newWSConn(clientToProxy, cfg)
		serverWS := newWSConn(serverFromProxy, cfg)

		// Message should still be relayed even without handler
		done := make(chan struct{})
		go func() {
			defer close(done)
			_ = clientWS.writeMessage(OpcodeBinary, []byte{0xDE, 0xAD}, true)
			time.Sleep(50 * time.Millisecond)
			_ = clientWS.writeClose(CloseNormalClosure, "", true)
		}()

		frame, err := serverWS.readFrame()
		if err != nil {
			t.Fatalf("readFrame error: %v", err)
		}
		if !bytes.Equal(frame.payload, []byte{0xDE, 0xAD}) {
			t.Errorf("payload = %v, want [0xDE, 0xAD]", frame.payload)
		}

		// Read close
		_, _ = serverWS.readFrame()
		<-done

		select {
		case <-errCh:
		case <-time.After(2 * time.Second):
			t.Error("interceptor did not finish")
		}
	})
}

func TestWebSocketInterceptor_PingPong(t *testing.T) {
	handler := &mockHandler{}
	cfg := DefaultWebSocketConfig()
	cfg.ReadTimeout = 500 * time.Millisecond
	cfg.WriteTimeout = 500 * time.Millisecond
	interceptor := NewWebSocketInterceptor(handler, cfg)

	clientToProxy, proxyFromClient := testPipe()
	proxyToServer, serverFromProxy := testPipe()
	defer func() {
		_ = clientToProxy.Close()
		_ = proxyFromClient.Close()
		_ = proxyToServer.Close()
		_ = serverFromProxy.Close()
	}()
	_ = serverFromProxy // server end unused in this test

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- interceptor.Intercept(ctx, proxyFromClient, proxyToServer,
			&http.Request{}, &http.Response{StatusCode: 101})
	}()

	clientWS := newWSConn(clientToProxy, cfg)

	// Send ping frame
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := clientWS.writeMessage(OpcodePing, []byte("ping-data"), true); err != nil {
			t.Errorf("write ping error: %v", err)
			return
		}
	}()

	// Should receive pong back (ping handler sends pong back to sender)
	frame, err := clientWS.readFrame()
	if err != nil {
		t.Fatalf("readFrame error: %v", err)
	}
	if frame.opcode != OpcodePong {
		t.Errorf("opcode = %d, want %d (pong)", frame.opcode, OpcodePong)
	}
	if string(frame.payload) != "ping-data" {
		t.Errorf("pong payload = %q, want %q", frame.payload, "ping-data")
	}

	<-done

	// Close to end test
	go func() {
		_ = clientWS.writeClose(CloseNormalClosure, "", true)
	}()

	select {
	case <-errCh:
	case <-time.After(2 * time.Second):
		// Cancel context to unblock
		cancel()
	}
}

func TestWebSocketInterceptor_MessageBlocking(t *testing.T) {
	handler := &mockHandler{blockMessage: true}
	cfg := DefaultWebSocketConfig()
	cfg.ReadTimeout = 500 * time.Millisecond
	cfg.WriteTimeout = 500 * time.Millisecond
	interceptor := NewWebSocketInterceptor(handler, cfg)

	clientToProxy, proxyFromClient := testPipe()
	proxyToServer, serverFromProxy := testPipe()
	defer func() {
		_ = clientToProxy.Close()
		_ = proxyFromClient.Close()
		_ = proxyToServer.Close()
		_ = serverFromProxy.Close()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- interceptor.Intercept(ctx, proxyFromClient, proxyToServer,
			&http.Request{}, &http.Response{StatusCode: 101})
	}()

	clientWS := newWSConn(clientToProxy, cfg)
	serverWS := newWSConn(serverFromProxy, cfg)

	// Send blocked message then close
	go func() {
		_ = clientWS.writeMessage(OpcodeText, []byte("blocked"), true)
		time.Sleep(50 * time.Millisecond)
		_ = clientWS.writeClose(CloseNormalClosure, "", true)
	}()

	// Server should NOT receive the blocked message, only the close
	frame, err := serverWS.readFrame()
	if err != nil {
		t.Fatalf("readFrame error: %v", err)
	}
	// Should get close frame (blocked message was dropped)
	if frame.opcode != OpcodeClose {
		t.Errorf("expected close frame after blocked message, got opcode %d", frame.opcode)
	}

	select {
	case <-errCh:
	case <-time.After(2 * time.Second):
		cancel()
	}
}

func TestBufferedReaderConn(t *testing.T) {
	// Create a pipe and write some data
	client, server := testPipe()
	defer func() {
		_ = client.Close()
		_ = server.Close()
	}()

	// Write data to server side
	go func() {
		_, _ = server.Write([]byte("hello world"))
	}()

	// Create buffered reader and read some data
	reader := bufio.NewReader(client)
	buf := make([]byte, 5)
	_, _ = io.ReadFull(reader, buf)
	if string(buf) != "hello" {
		t.Errorf("first read = %q, want %q", buf, "hello")
	}

	// Wrap in bufferedReaderConn
	wrapped := &bufferedReaderConn{
		Conn:   client,
		reader: reader,
	}

	// Read remaining data through the wrapped conn
	remaining := make([]byte, 6)
	n, err := wrapped.Read(remaining)
	if err != nil {
		t.Fatalf("Read error: %v", err)
	}
	if n != 6 || string(remaining) != " world" {
		t.Errorf("Read() = %d, %q, want 6, %q", n, remaining[:n], " world")
	}
}
