package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/net/idna"
)

// --- 1. Pointer & Map Safety Utilities ---

// DerefOrDefault safely dereferences ptr if it is non-nil; otherwise it returns fallback.
func DerefOrDefault[T any](ptr *T, fallback T) T {
	if ptr == nil {
		return fallback
	}
	return *ptr
}

// InitMap initializes *m with make(map[K]V) if *m is nil, and returns *m.
// If m is nil, it returns a new empty map without mutating m.
func InitMap[K comparable, V any](m *map[K]V) map[K]V {
	if m == nil {
		return make(map[K]V)
	}
	if *m == nil {
		*m = make(map[K]V)
	}
	return *m
}

// CopyMap returns a shallow copy of src using maps.Clone. If src is nil, it returns an initialized empty map.
func CopyMap[K comparable, V any](src map[K]V) map[K]V {
	if src == nil {
		return make(map[K]V)
	}
	return maps.Clone(src)
}

// --- 2. Domain & String Normalization Utilities ---

// NormalizeDomain normalizes a domain or hostname by trimming whitespace,
// stripping trailing dots, and converting to lowercase.
func NormalizeDomain(domain string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
}

// NormalizeDomainToASCIIText normalizes a domain name and converts internationalized
// domain names (IDN/Punycode) to ASCII using idna.ToASCII. If conversion fails,
// it falls back to NormalizeDomain(domain).
func NormalizeDomainToASCIIText(domain string) string {
	cleaned := NormalizeDomain(domain)
	if ascii, err := idna.ToASCII(cleaned); err == nil && ascii != "" {
		return ascii
	}
	return cleaned
}

// DeduplicateSlice returns a new slice containing unique elements from items,
// preserving the original insertion order.
func DeduplicateSlice[T comparable](items []T) []T {
	if len(items) == 0 {
		return nil
	}
	seen := make(map[T]struct{}, len(items))
	result := make([]T, 0, len(items))
	for _, item := range items {
		if _, exists := seen[item]; !exists {
			seen[item] = struct{}{}
			result = append(result, item)
		}
	}
	return result
}

// DeduplicateNonEmptyStrings trims each string in items, filters out empty strings,
// and deduplicates the remainder while preserving order.
func DeduplicateNonEmptyStrings(items []string) []string {
	if len(items) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(items))
	result := make([]string, 0, len(items))
	for _, item := range items {
		cleaned := strings.TrimSpace(item)
		if cleaned == "" {
			continue
		}
		if _, exists := seen[cleaned]; !exists {
			seen[cleaned] = struct{}{}
			result = append(result, cleaned)
		}
	}
	return result
}

// --- 3. Concurrency, Panic Recovery & Error Safety ---

// RecoverAndLogPanic captures any active panic, logs it with context, and allows
// the enclosing function/goroutine to terminate gracefully.
func RecoverAndLogPanic(op string) {
	if r := recover(); r != nil {
		LogError("Recovered from unexpected panic", "operation", op, "panic", r)
	}
}

// TruncateRunes safely truncates s to maxRunes runes without splitting multi-byte UTF-8 sequences.
func TruncateRunes(s string, maxRunes int) string {
	if maxRunes <= 0 {
		return ""
	}
	if utf8.RuneCountInString(s) <= maxRunes {
		return s
	}
	runes := []rune(s)
	return string(runes[:maxRunes])
}

// --- 4. HTTP Resiliency & Connection Management ---

// DefaultHTTPClient provides a safe fallback HTTP client with a 10-second timeout.
var DefaultHTTPClient = &http.Client{Timeout: 10 * time.Second}

// ResolveHTTPClient returns client if non-nil; otherwise it returns DefaultHTTPClient.
func ResolveHTTPClient(client *http.Client) *http.Client {
	if client == nil {
		return DefaultHTTPClient
	}
	return client
}

// DrainAndClose reads remaining bytes from rc up to maxBytes (defaulting to 4KB if <= 0)
// and closes rc. Draining before closing allows Go's underlying HTTP Transport to
// reuse the established TCP/TLS connection.
func DrainAndClose(rc io.ReadCloser, maxBytes int64) {
	if rc == nil {
		return
	}
	if maxBytes <= 0 {
		maxBytes = 4096
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(rc, maxBytes))
	_ = rc.Close()
}

// --- 5. Network, Token & Filesystem Safety Utilities ---

// DefaultPort ensures addr has a port component. If addr does not have a port,
// defaultPort is appended. It correctly handles IPv4 and IPv6 addresses.
func DefaultPort(addr, defaultPort string) string {
	cleanAddr := strings.TrimSpace(addr)
	if _, _, err := net.SplitHostPort(cleanAddr); err != nil {
		cleanAddr = strings.Trim(cleanAddr, "[]")
		return net.JoinHostPort(cleanAddr, defaultPort)
	}
	return cleanAddr
}

// NormalizeStatusToken cleans and standardizes status tokens by removing spaces,
// hyphens, and underscores, and converting to lowercase using single-pass allocation-free mapping.
func NormalizeStatusToken(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	return strings.Map(func(r rune) rune {
		if r == ' ' || r == '-' || r == '_' {
			return -1
		}
		return unicode.ToLower(r)
	}, s)
}

// IsRestrictedIP reports whether ip is a private, loopback, link-local, multicast,
// unspecified, or CGNAT IP address, suitable for SSRF and rebinding prevention.
func IsRestrictedIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast() || ip.IsUnspecified() {
		return true
	}
	if ip4 := ip.To4(); ip4 != nil {
		// RFC 6598: Carrier Grade NAT (100.64.0.0/10)
		if ip4[0] == 100 && (ip4[1]&0xc0) == 64 {
			return true
		}
		// RFC 1122: "This network" (0.0.0.0/8)
		if ip4[0] == 0 {
			return true
		}
	}
	return false
}

// IsSafeSubpath reports whether targetPath is safely located strictly within baseDir,
// preventing directory traversal attacks.
func IsSafeSubpath(baseDir, targetPath string) bool {
	cleanBase := filepath.Clean(baseDir)
	cleanTarget := filepath.Clean(targetPath)
	if cleanTarget == cleanBase {
		return false
	}
	rel, err := filepath.Rel(cleanBase, cleanTarget)
	if err != nil {
		return false
	}
	return !strings.HasPrefix(rel, "..") && !filepath.IsAbs(rel)
}

// AtomicWriteFile writes data to a temporary file in the destination directory and
// atomically renames it into place, preventing partial file corruption on process termination.
func AtomicWriteFile(path string, data []byte, perm os.FileMode) (err error) {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		if err != nil {
			_ = tmp.Close()
			_ = os.Remove(tmpName)
		}
	}()

	if err = os.Chmod(tmpName, perm); err != nil {
		return err
	}
	if _, err = tmp.Write(data); err != nil {
		return err
	}
	if err = tmp.Sync(); err != nil {
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	if err = os.Rename(tmpName, path); err != nil {
		return err
	}
	return nil
}

// --- 6. Standardized Logging Utilities with Localized Timezone (No k=v syntax, No Source) ---

// CleanTextHandler formats log records into human-readable lines without key=value syntax or source annotations.
type CleanTextHandler struct {
	w     io.Writer
	mu    *sync.Mutex
	attrs []string
}

// NewCleanTextHandler creates a new CleanTextHandler writing to w.
func NewCleanTextHandler(w io.Writer) *CleanTextHandler {
	return &CleanTextHandler{
		w:  w,
		mu: &sync.Mutex{},
	}
}

func (h *CleanTextHandler) Enabled(_ context.Context, _ slog.Level) bool {
	return true
}

func (h *CleanTextHandler) Handle(_ context.Context, r slog.Record) error {
	timestamp := r.Time.In(time.Local).Format("2006-01-02 15:04:05 MST")
	levelStr := r.Level.String()

	var attrs []string
	if len(h.attrs) > 0 {
		attrs = append(attrs, h.attrs...)
	}
	r.Attrs(func(a slog.Attr) bool {
		if a.Key != "" {
			attrs = append(attrs, fmt.Sprintf("%s: %v", a.Key, a.Value.Any()))
		}
		return true
	})

	var line string
	if len(attrs) > 0 {
		line = fmt.Sprintf("%s [%s] %s (%s)\n", timestamp, levelStr, r.Message, strings.Join(attrs, ", "))
	} else {
		line = fmt.Sprintf("%s [%s] %s\n", timestamp, levelStr, r.Message)
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	_, err := io.WriteString(h.w, line)
	return err
}

func (h *CleanTextHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	var formatted []string
	for _, a := range attrs {
		if a.Key != "" {
			formatted = append(formatted, fmt.Sprintf("%s: %v", a.Key, a.Value.Any()))
		}
	}
	newAttrs := make([]string, 0, len(h.attrs)+len(formatted))
	newAttrs = append(newAttrs, h.attrs...)
	newAttrs = append(newAttrs, formatted...)
	return &CleanTextHandler{
		w:     h.w,
		mu:    h.mu,
		attrs: newAttrs,
	}
}

func (h *CleanTextHandler) WithGroup(_ string) slog.Handler {
	return h
}

func init() {
	InitLocalizedLogger()
}

// InitLocalizedLogger initializes the default slog logger to format timestamps
// with the localized system timezone and clean human-readable output without key=value syntax or source annotations.
func InitLocalizedLogger() {
	slog.SetDefault(slog.New(NewCleanTextHandler(os.Stderr)))
}

// logWithLevel logs a message at the specified level without source annotations.
func logWithLevel(ctx context.Context, level slog.Level, msg string, args ...any) {
	logger := slog.Default()
	if !logger.Enabled(ctx, level) {
		return
	}
	r := slog.NewRecord(time.Now().In(time.Local), level, msg, 0)
	r.Add(args...)
	_ = logger.Handler().Handle(ctx, r)
}

// LogInfo logs an informational message with structured key-value attributes.
func LogInfo(msg string, args ...any) {
	logWithLevel(context.Background(), slog.LevelInfo, msg, args...)
}

// LogInfof formats and logs an informational message.
func LogInfof(format string, args ...any) {
	logWithLevel(context.Background(), slog.LevelInfo, fmt.Sprintf(format, args...))
}

// LogWarn logs a warning message with structured key-value attributes.
func LogWarn(msg string, args ...any) {
	logWithLevel(context.Background(), slog.LevelWarn, msg, args...)
}

// LogWarnf formats and logs a warning message.
func LogWarnf(format string, args ...any) {
	logWithLevel(context.Background(), slog.LevelWarn, fmt.Sprintf(format, args...))
}

// LogError logs an error message with structured key-value attributes.
func LogError(msg string, args ...any) {
	logWithLevel(context.Background(), slog.LevelError, msg, args...)
}

// LogErrorf formats and logs an error message.
func LogErrorf(format string, args ...any) {
	logWithLevel(context.Background(), slog.LevelError, fmt.Sprintf(format, args...))
}

// LogDebug logs a debug message with structured key-value attributes.
func LogDebug(msg string, args ...any) {
	logWithLevel(context.Background(), slog.LevelDebug, msg, args...)
}

// LogDebugf formats and logs a debug message.
func LogDebugf(format string, args ...any) {
	logWithLevel(context.Background(), slog.LevelDebug, fmt.Sprintf(format, args...))
}
