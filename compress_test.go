package swg

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

func TestDefaultCompressionConfig(t *testing.T) {
	cfg := DefaultCompressionConfig()

	if cfg.MinSize != 256 {
		t.Errorf("MinSize = %d, want 256", cfg.MinSize)
	}
	if cfg.Level != 0 {
		t.Errorf("Level = %d, want 0", cfg.Level)
	}
	if len(cfg.PreferOrder) != 3 {
		t.Errorf("PreferOrder length = %d, want 3", len(cfg.PreferOrder))
	}
}

func TestParseAcceptEncoding(t *testing.T) {
	tests := []struct {
		header string
		want   map[string]struct{}
	}{
		{
			header: "gzip, deflate",
			want:   map[string]struct{}{"gzip": {}, "deflate": {}},
		},
		{
			header: "gzip;q=0.8, br;q=1.0",
			want:   map[string]struct{}{"gzip": {}, "br": {}},
		},
		{
			header: "br",
			want:   map[string]struct{}{"br": {}},
		},
		{
			header: "identity",
			want:   map[string]struct{}{},
		},
		{
			header: "",
			want:   map[string]struct{}{},
		},
		{
			header: "gzip, br, zstd",
			want:   map[string]struct{}{"gzip": {}, "br": {}, "zstd": {}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.header, func(t *testing.T) {
			got := parseAcceptEncoding(tt.header)
			if len(got) != len(tt.want) {
				t.Errorf("parseAcceptEncoding(%q) = %v, want %v", tt.header, got, tt.want)
			}
			for k := range tt.want {
				if _, ok := got[k]; !ok {
					t.Errorf("parseAcceptEncoding(%q) missing key %q", tt.header, k)
				}
			}
		})
	}
}

func TestCompressHandler_NoAcceptEncoding(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(strings.Repeat("hello world ", 100)))
	})

	ch := NewCompressHandler(handler)
	req := httptest.NewRequest("GET", "/", nil)
	// No Accept-Encoding header
	rec := httptest.NewRecorder()

	ch.ServeHTTP(rec, req)

	if rec.Header().Get("Content-Encoding") != "" {
		t.Error("expected no Content-Encoding when client doesn't accept compression")
	}
}

func TestCompressHandler_Gzip(t *testing.T) {
	originalData := strings.Repeat("hello world ", 100)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(originalData))
	})

	ch := NewCompressHandler(handler)
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	rec := httptest.NewRecorder()

	ch.ServeHTTP(rec, req)

	if rec.Header().Get("Content-Encoding") != "gzip" {
		t.Errorf("Content-Encoding = %q, want gzip", rec.Header().Get("Content-Encoding"))
	}

	// Decompress and verify
	gr, err := gzip.NewReader(rec.Body)
	if err != nil {
		t.Fatalf("failed to create gzip reader: %v", err)
	}
	defer func() { _ = gr.Close() }()

	decompressed, err := io.ReadAll(gr)
	if err != nil {
		t.Fatalf("failed to decompress: %v", err)
	}

	if string(decompressed) != originalData {
		t.Errorf("decompressed data mismatch")
	}
}

func TestCompressHandler_Brotli(t *testing.T) {
	originalData := strings.Repeat("hello world ", 100)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(originalData))
	})

	ch := NewCompressHandler(handler)
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Accept-Encoding", "br")
	rec := httptest.NewRecorder()

	ch.ServeHTTP(rec, req)

	if rec.Header().Get("Content-Encoding") != "br" {
		t.Errorf("Content-Encoding = %q, want br", rec.Header().Get("Content-Encoding"))
	}

	// Decompress and verify
	br := brotli.NewReader(rec.Body)
	decompressed, err := io.ReadAll(br)
	if err != nil {
		t.Fatalf("failed to decompress brotli: %v", err)
	}

	if string(decompressed) != originalData {
		t.Errorf("decompressed data mismatch")
	}
}

func TestCompressHandler_Zstd(t *testing.T) {
	originalData := strings.Repeat("hello world ", 100)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(originalData))
	})

	ch := NewCompressHandler(handler)
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Accept-Encoding", "zstd")
	rec := httptest.NewRecorder()

	ch.ServeHTTP(rec, req)

	if rec.Header().Get("Content-Encoding") != "zstd" {
		t.Errorf("Content-Encoding = %q, want zstd", rec.Header().Get("Content-Encoding"))
	}

	// Decompress and verify
	zr, err := zstd.NewReader(rec.Body)
	if err != nil {
		t.Fatalf("failed to create zstd reader: %v", err)
	}
	defer zr.Close()

	decompressed, err := io.ReadAll(zr)
	if err != nil {
		t.Fatalf("failed to decompress zstd: %v", err)
	}

	if string(decompressed) != originalData {
		t.Errorf("decompressed data mismatch")
	}
}

func TestCompressHandler_MinSize(t *testing.T) {
	smallData := "hello" // Less than 256 bytes
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(smallData))
	})

	ch := NewCompressHandler(handler)
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	rec := httptest.NewRecorder()

	ch.ServeHTTP(rec, req)

	// Should not be compressed due to MinSize
	if rec.Header().Get("Content-Encoding") != "" {
		t.Errorf("expected no compression for small response, got %q", rec.Header().Get("Content-Encoding"))
	}

	if rec.Body.String() != smallData {
		t.Errorf("body = %q, want %q", rec.Body.String(), smallData)
	}
}

func TestCompressHandler_NonCompressibleContentType(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		_, _ = w.Write([]byte(strings.Repeat("x", 1000)))
	})

	ch := NewCompressHandler(handler)
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	rec := httptest.NewRecorder()

	ch.ServeHTTP(rec, req)

	// Should not be compressed - image/png is not compressible
	if rec.Header().Get("Content-Encoding") != "" {
		t.Errorf("expected no compression for image/png, got %q", rec.Header().Get("Content-Encoding"))
	}
}

func TestCompressHandler_AlreadyEncoded(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = w.Write([]byte(strings.Repeat("x", 1000)))
	})

	ch := NewCompressHandler(handler)
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	rec := httptest.NewRecorder()

	ch.ServeHTTP(rec, req)

	// Should remain gzip (from handler), not double-compressed
	if rec.Header().Get("Content-Encoding") != "gzip" {
		t.Errorf("Content-Encoding = %q, want gzip", rec.Header().Get("Content-Encoding"))
	}
}

func TestCompressHandler_PreferOrder(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(strings.Repeat("hello world ", 100)))
	})

	ch := NewCompressHandler(handler)
	// Default order: br > zstd > gzip

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Accept-Encoding", "gzip, br, zstd")
	rec := httptest.NewRecorder()

	ch.ServeHTTP(rec, req)

	// Should prefer brotli
	if rec.Header().Get("Content-Encoding") != "br" {
		t.Errorf("Content-Encoding = %q, want br (preferred)", rec.Header().Get("Content-Encoding"))
	}
}

func TestCompressHandler_VaryHeader(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(strings.Repeat("hello world ", 100)))
	})

	ch := NewCompressHandler(handler)
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	rec := httptest.NewRecorder()

	ch.ServeHTTP(rec, req)

	vary := rec.Header().Get("Vary")
	if !strings.Contains(vary, "Accept-Encoding") {
		t.Errorf("Vary header = %q, should contain Accept-Encoding", vary)
	}
}

func TestCompressBytes(t *testing.T) {
	data := []byte(strings.Repeat("hello world ", 100))

	tests := []struct {
		encoding string
	}{
		{EncodingGzip},
		{EncodingZstd},
		{EncodingBrotli},
	}

	for _, tt := range tests {
		t.Run(tt.encoding, func(t *testing.T) {
			compressed, err := CompressBytes(data, tt.encoding)
			if err != nil {
				t.Fatalf("CompressBytes(%s) error = %v", tt.encoding, err)
			}

			if len(compressed) >= len(data) {
				t.Logf("warning: compressed size (%d) >= original (%d)", len(compressed), len(data))
			}

			// Verify by decompressing
			var decompressed []byte
			switch tt.encoding {
			case EncodingGzip:
				gr, _ := gzip.NewReader(bytes.NewReader(compressed))
				decompressed, _ = io.ReadAll(gr)
				_ = gr.Close()
			case EncodingZstd:
				zr, _ := zstd.NewReader(bytes.NewReader(compressed))
				decompressed, _ = io.ReadAll(zr)
				zr.Close()
			case EncodingBrotli:
				br := brotli.NewReader(bytes.NewReader(compressed))
				decompressed, _ = io.ReadAll(br)
			}

			if !bytes.Equal(decompressed, data) {
				t.Errorf("decompressed data mismatch for %s", tt.encoding)
			}
		})
	}
}

func TestCompressBytes_Unknown(t *testing.T) {
	data := []byte("hello")
	result, err := CompressBytes(data, "unknown")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !bytes.Equal(result, data) {
		t.Error("unknown encoding should return data unchanged")
	}
}

func TestCompressHandler_JSON(t *testing.T) {
	jsonData := `{"message":"` + strings.Repeat("hello world ", 50) + `"}`
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(jsonData))
	})

	ch := NewCompressHandler(handler)
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	rec := httptest.NewRecorder()

	ch.ServeHTTP(rec, req)

	if rec.Header().Get("Content-Encoding") != "gzip" {
		t.Errorf("expected gzip for application/json, got %q", rec.Header().Get("Content-Encoding"))
	}
}

func BenchmarkCompressHandler_Gzip(b *testing.B) {
	data := []byte(strings.Repeat("hello world ", 1000))
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write(data)
	})

	ch := NewCompressHandler(handler)
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Accept-Encoding", "gzip")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rec := httptest.NewRecorder()
		ch.ServeHTTP(rec, req)
	}
}

func BenchmarkCompressHandler_Brotli(b *testing.B) {
	data := []byte(strings.Repeat("hello world ", 1000))
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write(data)
	})

	ch := NewCompressHandler(handler)
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Accept-Encoding", "br")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rec := httptest.NewRecorder()
		ch.ServeHTTP(rec, req)
	}
}

func BenchmarkCompressHandler_Zstd(b *testing.B) {
	data := []byte(strings.Repeat("hello world ", 1000))
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write(data)
	})

	ch := NewCompressHandler(handler)
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Accept-Encoding", "zstd")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rec := httptest.NewRecorder()
		ch.ServeHTTP(rec, req)
	}
}
