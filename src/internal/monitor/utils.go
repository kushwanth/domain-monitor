package monitor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"golang.org/x/net/idna"
)

// --- 1. Value Safety Utilities ---

// WrapError wraps an underlying error with a descriptive prefix message while preserving the error chain for errors.Is and errors.As.
func WrapError(prefix string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf(MsgErr, prefix, err)
}

// AnyToString converts any value or panic object into a string representation safely.
func AnyToString(v any) string {
	if v == nil {
		return StrEmpty
	}
	switch val := v.(type) {
	case string:
		return val
	case error:
		return val.Error()
	case fmt.Stringer:
		return val.String()
	default:
		return fmt.Sprint(v)
	}
}

// DerefOrDefault safely dereferences ptr if it is non-nil; otherwise it returns fallback.
func DerefOrDefault[T any](ptr *T, fallback T) T {
	if ptr == nil {
		return fallback
	}
	return *ptr
}

// readBounded reads at most limit bytes and rejects input that exceeds it.
func readBounded(r io.Reader, limit int64) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, ErrReadLimitExceeded
	}
	return body, nil
}

// --- 2. Domain & String Normalization Utilities ---

// NormalizeDomain normalizes a domain or hostname by trimming whitespace,
// stripping trailing dots, and converting to lowercase.
func NormalizeDomain(domain string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), SymDot))
}

// NormalizeDomainToASCIIText normalizes a domain name and converts internationalized
// domain names (IDN/Punycode) to ASCII using idna.ToASCII. If conversion fails,
// it falls back to NormalizeDomain(domain).
func NormalizeDomainToASCIIText(domain string) string {
	cleaned := NormalizeDomain(domain)
	if ascii, err := idna.ToASCII(cleaned); err == nil && ascii != StrEmpty {
		return ascii
	}
	return cleaned
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
		if cleaned == StrEmpty {
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
		LogError(MsgLogRecoveredPanic, StrOperation, op, StrPanic, r)
	}
}

// TruncateRunes safely truncates s to maxRunes runes without splitting multi-byte UTF-8 sequences.
func TruncateRunes(s string, maxRunes int) string {
	if maxRunes <= 0 {
		return StrEmpty
	}
	count := 0
	for i := range s {
		if count == maxRunes {
			return s[:i]
		}
		count++
	}
	return s
}

// --- 4. HTTP Resiliency & Connection Management ---

// ResolveHTTPClient returns the injected client, or nil when it is absent.
func ResolveHTTPClient(client HTTPDoer) HTTPDoer {
	if client == nil {
		return nil
	}
	if c, ok := client.(*http.Client); ok && c == nil {
		return nil
	}
	return client
}

func retryBackoff(attempt int, base time.Duration) time.Duration {
	delay := base << max(attempt-1, 0)
	jitter := delay / 4
	if jitter == 0 {
		return delay
	}
	return delay + time.Duration(rand.Int64N(int64(jitter)+1)) // #nosec G404 -- timing jitter does not require cryptographic randomness.
}

func retryWithBackoff[T any](ctx context.Context, operation string, baseDelay time.Duration, attemptFn func(int) (T, bool, time.Duration, error)) (T, error) {
	var zero T
	for attempt := 1; attempt <= MaxNetworkAttempts; attempt++ {
		value, retry, serverDelay, err := attemptFn(attempt)
		if !retry || attempt == MaxNetworkAttempts {
			return value, err
		}
		if ctx.Err() != nil {
			return zero, ctx.Err()
		}
		delay := retryBackoff(attempt, baseDelay)
		if serverDelay > delay {
			delay = serverDelay
		}
		if delay > MaxRetryDelay {
			return value, err
		}
		if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) <= delay {
			return value, err
		}
		LogWarn(MsgLogNetworkRetry, StrOperation, operation, FieldAttempt, attempt, FieldRetryIn, delay, FieldError, err)
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return zero, ctx.Err()
		case <-timer.C:
		}
	}
	return zero, ctx.Err()
}

func retryableHTTPStatus(status int) bool {
	return status == http.StatusRequestTimeout || status == http.StatusTooEarly || status == http.StatusTooManyRequests ||
		status == http.StatusInternalServerError || status == http.StatusBadGateway || status == http.StatusServiceUnavailable || status == http.StatusGatewayTimeout
}

func responseRetryAfter(response *http.Response, now time.Time) time.Duration {
	if response == nil {
		return 0
	}
	raw := strings.TrimSpace(response.Header.Get(HeaderRetryAfter))
	if seconds, err := strconv.Atoi(raw); err == nil && seconds > 0 {
		return time.Duration(seconds) * time.Second
	}
	if when, err := http.ParseTime(raw); err == nil && when.After(now) {
		return when.Sub(now)
	}
	return 0
}

func transientNetworkError(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	var networkError net.Error
	return errors.As(err, &networkError)
}

func doHTTPRequest(client HTTPDoer, request *http.Request) (*http.Response, error) {
	client = ResolveHTTPClient(client)
	if client == nil {
		return nil, ErrHTTPClientNil
	}
	response, err := client.Do(request)
	if err == nil && response == nil {
		return nil, ErrEmptyHTTPResponse
	}
	return response, err
}

func doHTTPWithRetry(ctx context.Context, operation string, client HTTPDoer, policy HTTPRetryPolicy, requestFn func() (*http.Request, error)) (*http.Response, error) {
	client = ResolveHTTPClient(client)
	if client == nil {
		return nil, ErrHTTPClientNil
	}
	return retryWithBackoff(ctx, operation, HTTPRetryBaseDelay, func(attempt int) (*http.Response, bool, time.Duration, error) {
		request, err := requestFn()
		if err != nil {
			return nil, false, 0, err
		}
		response, err := doHTTPRequest(client, request)
		if err != nil {
			if response != nil {
				DrainAndClose(response.Body, MaxBodyDrainSize)
			}
			return nil, policy == RetryHTTPTransient && transientNetworkError(err), 0, err
		}
		if !retryableHTTPStatus(response.StatusCode) || attempt == MaxNetworkAttempts {
			return response, false, 0, nil
		}
		delay := responseRetryAfter(response, time.Now())
		statusErr := fmt.Errorf(MsgErrTemporaryHTTPStatus, response.StatusCode)
		DrainAndClose(response.Body, MaxBodyDrainSize)
		return nil, true, delay, statusErr
	})
}

// DrainAndClose reads remaining bytes from rc up to maxBytes (defaulting to 4KB if <= 0)
// and closes rc. Draining before closing allows Go's underlying HTTP Transport to
// reuse the established TCP/TLS connection.
func DrainAndClose(rc io.ReadCloser, maxBytes int64) {
	if rc == nil {
		return
	}
	if maxBytes <= 0 {
		maxBytes = MaxBodyDrainSize
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(rc, maxBytes))
	_ = rc.Close()
}

// --- 5. Network & Token Safety Utilities ---

// DefaultPort ensures addr has a port component. If addr does not have a port,
// defaultPort is appended. It correctly handles IPv4 and IPv6 addresses.
func DefaultPort(addr, defaultPort string) string {
	cleanAddr := strings.TrimSpace(addr)
	if _, _, err := net.SplitHostPort(cleanAddr); err != nil {
		cleanAddr = strings.Trim(cleanAddr, SymBrackets)
		return net.JoinHostPort(cleanAddr, defaultPort)
	}
	return cleanAddr
}

// NormalizeStatusToken cleans and standardizes status tokens by removing spaces,
// hyphens, and underscores, and converting to lowercase using a single mapping pass.
func NormalizeStatusToken(s string) string {
	s = strings.TrimSpace(s)
	if s == StrEmpty {
		return StrEmpty
	}
	return strings.Map(func(r rune) rune {
		if r == ' ' || r == '-' || r == '_' {
			return -1
		}
		return unicode.ToLower(r)
	}, s)
}

// --- 6. Standardized Logging Utilities with Localized Timezone (No k=v syntax, No Source) ---

// NewConsoleHandler creates a new ConsoleHandler writing to w.
func NewConsoleHandler(w io.Writer) *ConsoleHandler {
	return &ConsoleHandler{
		w:  w,
		mu: &sync.Mutex{},
	}
}

// Enabled accepts all log levels.
func (h *ConsoleHandler) Enabled(_ context.Context, _ slog.Level) bool {
	return true
}

// Handle formats a record and serializes writes to the shared output.
func (h *ConsoleHandler) Handle(_ context.Context, r slog.Record) error {
	timestamp := r.Time.In(time.Local).Format(DefaultLogTimeFormat)
	levelStr := r.Level.String()

	var attrs []string
	if len(h.attrs) > 0 {
		attrs = append(attrs, h.attrs...)
	}
	r.Attrs(func(a slog.Attr) bool {
		if a.Key != StrEmpty {
			attrs = append(attrs, fmt.Sprintf(LogFormatAttr, a.Key, a.Value.Any()))
		}
		return true
	})

	var line string
	if len(attrs) > 0 {
		line = fmt.Sprintf(LogFormatLineWithAttrs, timestamp, levelStr, r.Message, strings.Join(attrs, SymCommaSpace))
	} else {
		line = fmt.Sprintf(LogFormatLineNoAttrs, timestamp, levelStr, r.Message)
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	_, err := io.WriteString(h.w, line)
	return err
}

// WithAttrs returns a handler with independently owned formatted attributes.
func (h *ConsoleHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	var formatted []string
	for _, a := range attrs {
		if a.Key != StrEmpty {
			formatted = append(formatted, fmt.Sprintf(LogFormatAttr, a.Key, a.Value.Any()))
		}
	}
	newAttrs := make([]string, 0, len(h.attrs)+len(formatted))
	newAttrs = append(newAttrs, h.attrs...)
	newAttrs = append(newAttrs, formatted...)
	return &ConsoleHandler{
		w:     h.w,
		mu:    h.mu,
		attrs: newAttrs,
	}
}

// WithGroup preserves the flat attribute format used by this handler.
func (h *ConsoleHandler) WithGroup(_ string) slog.Handler {
	return h
}

func init() {
	InitLocalizedLogger()
}

// InitLocalizedLogger initializes the default slog logger to format timestamps
// with the localized system timezone and clean human-readable output without key=value syntax or source annotations.
func InitLocalizedLogger() {
	slog.SetDefault(slog.New(NewConsoleHandler(os.Stderr)))
}

// logWithLevel logs a message at the specified level without source annotations.
func logWithLevel(ctx context.Context, level slog.Level, msg string, args ...any) {
	logger := slog.Default()
	if !logger.Enabled(ctx, level) {
		return
	}
	r := slog.NewRecord(time.Now().In(time.Local), level, msg, 0)
	r.Add(args...)
	_ = logger.Handler().Handle(ctx, r) // Logging failures must not interrupt monitoring.
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
