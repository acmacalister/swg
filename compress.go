package swg

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/gzip"
	"github.com/klauspost/compress/zstd"
)

// Compression encoding constants.
const (
	EncodingGzip    = "gzip"
	EncodingZstd    = "zstd"
	EncodingBrotli  = "br"
	EncodingDeflate = "deflate"
)

// CompressionConfig controls response compression behavior.
type CompressionConfig struct {
	// MinSize is the minimum response size to compress (default: 256 bytes).
	// Responses smaller than this are sent uncompressed.
	MinSize int

	// Level is the compression level (1-9 for gzip, 1-22 for brotli, 1-4 for zstd).
	// 0 uses the default level for each algorithm.
	Level int

	// ContentTypes is a list of content-type prefixes to compress.
	// Empty means compress common text types (text/*, application/json, etc.).
	ContentTypes []string

	// PreferOrder is the preferred encoding order when client accepts multiple.
	// Default: ["br", "zstd", "gzip"]
	PreferOrder []string
}

// DefaultCompressionConfig returns a CompressionConfig with sensible defaults.
func DefaultCompressionConfig() CompressionConfig {
	return CompressionConfig{
		MinSize:     256,
		Level:       0, // Use default levels
		PreferOrder: []string{EncodingBrotli, EncodingZstd, EncodingGzip},
	}
}

// defaultCompressibleTypes are content-type prefixes that should be compressed.
var defaultCompressibleTypes = []string{
	"text/",
	"application/json",
	"application/javascript",
	"application/xml",
	"application/xhtml+xml",
	"application/rss+xml",
	"application/atom+xml",
	"image/svg+xml",
}

// CompressHandler wraps an http.Handler with response compression.
type CompressHandler struct {
	Handler http.Handler
	Config  CompressionConfig
}

// NewCompressHandler creates a compression middleware with default config.
func NewCompressHandler(h http.Handler) *CompressHandler {
	return &CompressHandler{
		Handler: h,
		Config:  DefaultCompressionConfig(),
	}
}

// ServeHTTP implements http.Handler with transparent response compression.
func (c *CompressHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Check Accept-Encoding header
	acceptEncoding := r.Header.Get("Accept-Encoding")
	if acceptEncoding == "" {
		c.Handler.ServeHTTP(w, r)
		return
	}

	// Select best encoding
	encoding := c.selectEncoding(acceptEncoding)
	if encoding == "" {
		c.Handler.ServeHTTP(w, r)
		return
	}

	// Create compressed response writer
	cw := &compressResponseWriter{
		ResponseWriter: w,
		encoding:       encoding,
		config:         c.Config,
		request:        r,
	}
	defer func() { _ = cw.Close() }()

	c.Handler.ServeHTTP(cw, r)
}

// selectEncoding chooses the best encoding based on client preferences and server config.
func (c *CompressHandler) selectEncoding(acceptEncoding string) string {
	accepted := parseAcceptEncoding(acceptEncoding)

	// Check preferred order
	preferOrder := c.Config.PreferOrder
	if len(preferOrder) == 0 {
		preferOrder = []string{EncodingBrotli, EncodingZstd, EncodingGzip}
	}

	for _, enc := range preferOrder {
		if _, ok := accepted[enc]; ok {
			return enc
		}
	}

	return ""
}

// parseAcceptEncoding parses Accept-Encoding header into a set of accepted encodings.
func parseAcceptEncoding(header string) map[string]struct{} {
	result := make(map[string]struct{})
	for _, part := range strings.Split(header, ",") {
		part = strings.TrimSpace(part)
		// Handle quality values (e.g., "gzip;q=0.8")
		if idx := strings.Index(part, ";"); idx != -1 {
			part = part[:idx]
		}
		part = strings.TrimSpace(part)
		if part != "" && part != "identity" {
			result[part] = struct{}{}
		}
	}
	return result
}

// compressResponseWriter wraps http.ResponseWriter with compression.
type compressResponseWriter struct {
	http.ResponseWriter
	encoding    string
	config      CompressionConfig
	request     *http.Request
	writer      io.WriteCloser
	buffer      []byte
	wroteHeader bool
	compressed  bool
}

// WriteHeader captures the status code and checks if compression should be applied.
func (cw *compressResponseWriter) WriteHeader(statusCode int) {
	if cw.wroteHeader {
		return
	}
	cw.wroteHeader = true

	// Don't compress certain status codes
	if statusCode == http.StatusNoContent || statusCode == http.StatusNotModified {
		cw.ResponseWriter.WriteHeader(statusCode)
		return
	}

	// Check if already encoded
	if cw.Header().Get("Content-Encoding") != "" {
		cw.ResponseWriter.WriteHeader(statusCode)
		return
	}

	// Check content type
	contentType := cw.Header().Get("Content-Type")
	if !cw.shouldCompress(contentType) {
		cw.ResponseWriter.WriteHeader(statusCode)
		return
	}

	// We'll set compression headers after we know the size (in Write)
	cw.ResponseWriter.WriteHeader(statusCode)
}

// Write compresses and writes data.
func (cw *compressResponseWriter) Write(b []byte) (int, error) {
	if !cw.wroteHeader {
		cw.WriteHeader(http.StatusOK)
	}

	// If compression already decided against, write directly
	if cw.writer == nil && cw.compressed {
		return cw.ResponseWriter.Write(b)
	}

	// Buffer small writes to check min size
	if cw.writer == nil && !cw.compressed {
		cw.buffer = append(cw.buffer, b...)

		minSize := cw.config.MinSize
		if minSize == 0 {
			minSize = 256
		}

		if len(cw.buffer) < minSize {
			return len(b), nil
		}

		// Check content type again (might have been set after WriteHeader)
		contentType := cw.Header().Get("Content-Type")
		if cw.Header().Get("Content-Encoding") != "" || !cw.shouldCompress(contentType) {
			cw.compressed = true
			return cw.ResponseWriter.Write(cw.buffer)
		}

		// Initialize compression
		if err := cw.initCompression(); err != nil {
			cw.compressed = true
			return cw.ResponseWriter.Write(cw.buffer)
		}

		// Write buffered data
		if _, err := cw.writer.Write(cw.buffer); err != nil {
			return 0, err
		}
		cw.buffer = nil
		return len(b), nil
	}

	return cw.writer.Write(b)
}

// Close flushes any remaining data and closes the compression writer.
func (cw *compressResponseWriter) Close() error {
	// Flush any buffered data that didn't meet min size
	if len(cw.buffer) > 0 {
		_, _ = cw.ResponseWriter.Write(cw.buffer)
		cw.buffer = nil
	}

	if cw.writer != nil {
		return cw.writer.Close()
	}
	return nil
}

// initCompression sets up the compression writer and headers.
func (cw *compressResponseWriter) initCompression() error {
	cw.compressed = true

	// Remove Content-Length since we're compressing
	cw.Header().Del("Content-Length")
	cw.Header().Set("Content-Encoding", cw.encoding)
	cw.Header().Add("Vary", "Accept-Encoding")

	var err error
	switch cw.encoding {
	case EncodingGzip:
		level := cw.config.Level
		if level == 0 {
			level = gzip.DefaultCompression
		}
		cw.writer, err = gzip.NewWriterLevel(cw.ResponseWriter, level)

	case EncodingZstd:
		level := zstd.EncoderLevelFromZstd(cw.config.Level)
		if cw.config.Level == 0 {
			level = zstd.SpeedDefault
		}
		cw.writer, err = zstd.NewWriter(cw.ResponseWriter, zstd.WithEncoderLevel(level))

	case EncodingBrotli:
		level := cw.config.Level
		if level == 0 {
			level = brotli.DefaultCompression
		}
		cw.writer = brotli.NewWriterLevel(cw.ResponseWriter, level)
	}

	return err
}

// shouldCompress checks if the content type should be compressed.
func (cw *compressResponseWriter) shouldCompress(contentType string) bool {
	if contentType == "" {
		return false
	}

	// Use configured types or defaults
	types := cw.config.ContentTypes
	if len(types) == 0 {
		types = defaultCompressibleTypes
	}

	contentType = strings.ToLower(contentType)
	for _, t := range types {
		if strings.HasPrefix(contentType, strings.ToLower(t)) {
			return true
		}
	}
	return false
}

// Flush implements http.Flusher.
func (cw *compressResponseWriter) Flush() {
	// Flush buffer first
	if len(cw.buffer) > 0 {
		if cw.writer != nil {
			_, _ = cw.writer.Write(cw.buffer)
		} else {
			_, _ = cw.ResponseWriter.Write(cw.buffer)
		}
		cw.buffer = nil
	}

	// Flush compression writer if it supports it
	if f, ok := cw.writer.(interface{ Flush() error }); ok {
		_ = f.Flush()
	}

	// Flush underlying writer
	if f, ok := cw.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Hijack implements http.Hijacker.
func (cw *compressResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hj, ok := cw.ResponseWriter.(http.Hijacker); ok {
		return hj.Hijack()
	}
	return nil, nil, http.ErrNotSupported
}

// Writer pool for reusing compression writers.
var (
	gzipWriterPool = sync.Pool{
		New: func() any {
			w, _ := gzip.NewWriterLevel(io.Discard, gzip.DefaultCompression)
			return w
		},
	}
)

// CompressBytes compresses data with the specified encoding.
func CompressBytes(data []byte, encoding string) ([]byte, error) {
	switch encoding {
	case EncodingGzip:
		return compressGzip(data)
	case EncodingZstd:
		return compressZstd(data)
	case EncodingBrotli:
		return compressBrotli(data)
	default:
		return data, nil
	}
}

func compressGzip(data []byte) ([]byte, error) {
	var buf strings.Builder
	w := gzipWriterPool.Get().(*gzip.Writer)
	w.Reset(&buf)
	defer func() {
		w.Reset(io.Discard)
		gzipWriterPool.Put(w)
	}()

	if _, err := w.Write(data); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return []byte(buf.String()), nil
}

func compressZstd(data []byte) ([]byte, error) {
	w, err := zstd.NewWriter(nil)
	if err != nil {
		return nil, err
	}
	return w.EncodeAll(data, nil), nil
}

func compressBrotli(data []byte) ([]byte, error) {
	var buf strings.Builder
	w := brotli.NewWriter(&buf)
	if _, err := w.Write(data); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return []byte(buf.String()), nil
}
