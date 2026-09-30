package main

import (
	"bytes"
	"context"
	jsonv2 "encoding/json/v2"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDerefOrDefault(t *testing.T) {
	t.Parallel()

	val := "custom"
	if got := DerefOrDefault(&val, "fallback"); got != "custom" {
		t.Errorf("DerefOrDefault(&val) = %q, expected 'custom'", got)
	}

	var nilPtr *string
	if got := DerefOrDefault(nilPtr, "fallback"); got != "fallback" {
		t.Errorf("DerefOrDefault(nil) = %q, expected 'fallback'", got)
	}
}

func TestReadBounded(t *testing.T) {
	t.Parallel()

	body, err := readBounded(strings.NewReader("1234"), 4)
	require.NoError(t, err)
	assert.Equal(t, []byte("1234"), body)

	body, err = readBounded(strings.NewReader("12345"), 4)
	assert.Nil(t, body)
	assert.ErrorIs(t, err, ErrReadLimitExceeded)
}

func TestRetryWithBackoffAttemptLimitAndCancellation(t *testing.T) {
	attempts := 0
	_, err := retryWithBackoff(context.Background(), "test", 0, func(int) (string, bool, time.Duration, error) {
		attempts++
		return "", true, 0, errors.New("temporary")
	})
	require.Error(t, err)
	assert.Equal(t, MaxNetworkAttempts, attempts)

	ctx, cancel := context.WithCancel(context.Background())
	attempts = 0
	_, err = retryWithBackoff(ctx, "test", time.Second, func(int) (string, bool, time.Duration, error) {
		attempts++
		cancel()
		return "", true, 0, errors.New("temporary")
	})
	assert.ErrorIs(t, err, context.Canceled)
	assert.Equal(t, 1, attempts)

	attempts = 0
	_, err = retryWithBackoff(context.Background(), "test", 0, func(int) (string, bool, time.Duration, error) {
		attempts++
		return "", true, MaxRetryDelay + time.Second, errors.New("rate limited")
	})
	require.Error(t, err)
	assert.Equal(t, 1, attempts, "a long Retry-After must defer work to a later cycle")
}

func TestHTTPRetryPolicy(t *testing.T) {
	for _, status := range []int{http.StatusRequestTimeout, http.StatusTooEarly, http.StatusTooManyRequests, http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout} {
		assert.True(t, retryableHTTPStatus(status), "status %d", status)
	}
	for _, status := range []int{http.StatusBadRequest, http.StatusNotFound, http.StatusNotImplemented, http.StatusHTTPVersionNotSupported} {
		assert.False(t, retryableHTTPStatus(status), "status %d", status)
	}

	now := time.Now().UTC().Truncate(time.Second)
	response := &http.Response{Header: make(http.Header)}
	response.Header.Set("Retry-After", "7")
	assert.Equal(t, 7*time.Second, responseRetryAfter(response, now))
	response.Header.Set("Retry-After", now.Add(5*time.Second).Format(http.TimeFormat))
	assert.Equal(t, 5*time.Second, responseRetryAfter(response, now))
}

func TestNormalizeDomain(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input    string
		expected string
	}{
		{"  Example.COM.  ", "example.com"},
		{"sub.DOMAIN.org.", "sub.domain.org"},
		{"domain.com", "domain.com"},
		{"", ""},
		{".", ""},
	}

	for _, tt := range tests {
		if got := NormalizeDomain(tt.input); got != tt.expected {
			t.Errorf("NormalizeDomain(%q) = %q, expected %q", tt.input, got, tt.expected)
		}
	}
}

func TestNormalizeDomainToASCIIText(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input    string
		expected string
	}{
		{"example.com", "example.com"},
		{"münchen.de", "xn--mnchen-3ya.de"},
		{"  EXAMPLE.com.  ", "example.com"},
	}

	for _, tt := range tests {
		if got := NormalizeDomainToASCIIText(tt.input); got != tt.expected {
			t.Errorf("NormalizeDomainToASCIIText(%q) = %q, expected %q", tt.input, got, tt.expected)
		}
	}
}

func TestDeduplicateNonEmptyStrings(t *testing.T) {
	t.Parallel()

	if got := DeduplicateNonEmptyStrings(nil); got != nil {
		t.Errorf("DeduplicateNonEmptyStrings(nil) expected nil, got %v", got)
	}

	items := []string{"  a  ", "", "   ", "b", "a", "b  "}
	expected := []string{"a", "b"}
	got := DeduplicateNonEmptyStrings(items)
	if len(got) != len(expected) {
		t.Fatalf("DeduplicateNonEmptyStrings len = %d, expected %d", len(got), len(expected))
	}
	for i := range expected {
		if got[i] != expected[i] {
			t.Errorf("DeduplicateNonEmptyStrings[%d] = %q, expected %q", i, got[i], expected[i])
		}
	}
}

func TestNormalizeStatusToken(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input    string
		expected string
	}{
		{"clientTransferProhibited", "clienttransferprohibited"},
		{"client-transfer-prohibited", "clienttransferprohibited"},
		{"client_transfer_prohibited", "clienttransferprohibited"},
		{"Client Transfer Prohibited", "clienttransferprohibited"},
		{"  SERVER-HOLD  ", "serverhold"},
		{"", ""},
	}

	for _, tt := range tests {
		if got := NormalizeStatusToken(tt.input); got != tt.expected {
			t.Errorf("NormalizeStatusToken(%q) = %q, expected %q", tt.input, got, tt.expected)
		}
	}
}

func TestDefaultPort(t *testing.T) {
	t.Parallel()

	tests := []struct {
		addr        string
		defaultPort string
		expected    string
	}{
		{"1.1.1.1", "53", "1.1.1.1:53"},
		{"1.1.1.1:5353", "53", "1.1.1.1:5353"},
		{"example.com", "443", "example.com:443"},
		{"example.com:8443", "443", "example.com:8443"},
		{"2606:4700:4700::1111", "53", "[2606:4700:4700::1111]:53"},
		{"[2606:4700:4700::1111]", "53", "[2606:4700:4700::1111]:53"},
		{"[2606:4700:4700::1111]:5353", "53", "[2606:4700:4700::1111]:5353"},
	}

	for _, tt := range tests {
		if got := DefaultPort(tt.addr, tt.defaultPort); got != tt.expected {
			t.Errorf("DefaultPort(%q, %q) = %q, expected %q", tt.addr, tt.defaultPort, got, tt.expected)
		}
	}
}

func TestTruncateRunes(t *testing.T) {
	t.Parallel()

	if got := TruncateRunes("hello", 0); got != "" {
		t.Errorf("TruncateRunes maxRunes<=0 expected empty, got %q", got)
	}
	if got := TruncateRunes("hello", 10); got != "hello" {
		t.Errorf("TruncateRunes within bounds expected 'hello', got %q", got)
	}
	if got := TruncateRunes("hello world", 5); got != "hello" {
		t.Errorf("TruncateRunes truncated expected 'hello', got %q", got)
	}
	// Multi-byte Unicode runes
	unicodeStr := "🚀🎉✨💡"
	if got := TruncateRunes(unicodeStr, 2); got != "🚀🎉" {
		t.Errorf("TruncateRunes multi-byte expected '🚀🎉', got %q", got)
	}
}

func TestResolveHTTPClient(t *testing.T) {
	t.Parallel()

	assert.Nil(t, ResolveHTTPClient(nil))
	var typedNil *http.Client
	assert.Nil(t, ResolveHTTPClient(typedNil))

	custom := &http.Client{Timeout: 3 * time.Second}
	if got := ResolveHTTPClient(custom); got != custom {
		t.Errorf("ResolveHTTPClient(custom) expected custom client")
	}
}

func TestDrainAndClose(t *testing.T) {
	t.Parallel()

	// Should not panic on nil
	DrainAndClose(nil, 0)

	body := io.NopCloser(bytes.NewBufferString("sample response payload"))
	DrainAndClose(body, 10)
}

func TestRecoverAndLogPanic(t *testing.T) {
	t.Parallel()

	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()
		defer RecoverAndLogPanic("test background operation")
		panic("deliberate panic in test goroutine")
	}()

	wg.Wait()
}

func TestLoggingUtilities(_ *testing.T) {
	// Ensure standardized logging helpers execute without issue
	LogInfo(MsgLogTestInfoMessage, "key", "value")
	LogInfof(MsgLogTestInfof, "formatted")
	LogWarn(MsgLogTestWarnMessage, "code", 123)
	LogWarnf(MsgLogTestWarnf, 456)
	LogError(MsgLogTestErrorMessage, "error", "mock error")
	LogErrorf(MsgLogTestErrorf, "detailed error")
	LogDebug(MsgLogTestDebugMessage, "trace", "id-789")
	LogDebugf(MsgLogTestDebugf, "debug detail")
}

func TestLogUtil_CleanFormattingAndNoSource(t *testing.T) {
	var buf bytes.Buffer
	handler := NewConsoleHandler(&buf)
	oldLogger := slog.Default()
	defer slog.SetDefault(oldLogger)
	slog.SetDefault(slog.New(handler))

	LogInfo(MsgLogSampleLocalizedMessage, "test_attr", 42)

	output := buf.String()
	zone, _ := time.Now().In(time.Local).Zone()
	if !strings.Contains(output, zone) {
		t.Errorf("expected log output to contain local timezone abbreviation %q, got: %s", zone, output)
	}
	if !strings.Contains(output, "[INFO] Sample localized message (test_attr: 42)") {
		t.Errorf("expected clean format without k=v, got: %s", output)
	}
	if strings.Contains(output, "source=") || strings.Contains(output, "utils_test.go") {
		t.Errorf("expected log output NOT to contain source annotations, got: %s", output)
	}
	if strings.Contains(output, "level=") || strings.Contains(output, "msg=") || strings.Contains(output, "time=") {
		t.Errorf("expected log output NOT to contain k=v syntax, got: %s", output)
	}
}

func TestWrapError(t *testing.T) {
	if WrapError("prefix", nil) != nil {
		t.Errorf("expected WrapError on nil to return nil")
	}

	root := errors.New(MsgErrRootCause)
	wrapped := WrapError("operation failed", root)
	if wrapped == nil {
		t.Fatalf("expected wrapped error, got nil")
	}
	if !errors.Is(wrapped, root) {
		t.Errorf("expected errors.Is(wrapped, root) to be true")
	}
	expectedMsg := "operation failed: root cause"
	if wrapped.Error() != expectedMsg {
		t.Errorf("expected message %q, got %q", expectedMsg, wrapped.Error())
	}
}

func TestAnyToString(t *testing.T) {
	t.Parallel()

	if got := AnyToString(nil); got != "" {
		t.Errorf("AnyToString(nil) = %q, expected empty string", got)
	}
	if got := AnyToString("hello"); got != "hello" {
		t.Errorf("AnyToString(string) = %q, expected %q", got, "hello")
	}
	if got := AnyToString(errors.New(MsgErrCustomError)); got != "custom error" {
		t.Errorf("AnyToString(error) = %q, expected %q", got, "custom error")
	}
	if got := AnyToString(dummyStringer{}); got != "dummy-string" {
		t.Errorf("AnyToString(Stringer) = %q, expected %q", got, "dummy-string")
	}
	if got := AnyToString(12345); got != "12345" {
		t.Errorf("AnyToString(int) = %q, expected %q", got, "12345")
	}
}

func TestIsRestrictedIP(t *testing.T) {
	assert.True(t, IsRestrictedIP(net.ParseIP("127.0.0.1")))
	assert.True(t, IsRestrictedIP(net.ParseIP("10.0.0.1")))
	assert.True(t, IsRestrictedIP(net.ParseIP("192.168.1.1")))
	assert.True(t, IsRestrictedIP(net.ParseIP("224.0.0.1")))
	assert.True(t, IsRestrictedIP(net.ParseIP("ff02::1")))
	assert.False(t, IsRestrictedIP(net.ParseIP("93.184.216.34")))
}

func TestCustomLoggerMethods(t *testing.T) {
	handler := NewConsoleHandler(os.Stdout)

	h2 := handler.WithAttrs([]slog.Attr{slog.String("foo", "bar")})
	assert.NotNil(t, h2)

	h3 := handler.WithGroup("test_group")
	assert.NotNil(t, h3)
}

func TestLogStateTransitions(_ *testing.T) {
	prev := make(map[string]CheckStatus)
	current := map[string]RDAPState{
		"example.com": {Status: StatusFailed},
	}

	logStateTransitions(CheckTypeRDAP, TargetKeyDomain, current, func(s RDAPState) CheckStatus { return s.Status }, prev)

	tmp := current["example.com"]
	tmp.Status = StatusOK
	current["example.com"] = tmp
	logStateTransitions(CheckTypeRDAP, TargetKeyDomain, current, func(s RDAPState) CheckStatus { return s.Status }, prev)
}

func TestNewAppStateWiresWHOISTransport(t *testing.T) {
	app := NewAppState(AppConfig{Resolvers: []string{"1.1.1.1"}})
	require.NotNil(t, app.WHOISDial)
	assert.Equal(t, []string{"1.1.1.1"}, app.Resolvers())
}

func TestStringListUnmarshalShapes(t *testing.T) {
	for _, tt := range []struct {
		name  string
		input string
		want  StringList
		bad   bool
	}{
		{"single", `"a"`, StringList{"a"}, false},
		{"array", `["a","b"]`, StringList{"a", "b"}, false},
		{"empty", `[]`, StringList{}, false},
		{"number", `7`, nil, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var got StringList
			err := got.UnmarshalJSON([]byte(tt.input))
			if tt.bad {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestResultCodeString(t *testing.T) {
	for _, tt := range []struct {
		code ResultCode
		want string
	}{
		{CodeCAAVerified, "caaVerified"},
		{CodeCTCoverageIncomplete, "ctCoverageIncomplete"},
		{ResultCode(-1), ""},
		{ResultCode(10000), ""},
	} {
		assert.Equal(t, tt.want, tt.code.String())
	}
}

func TestDefaultResolversReturnsIndependentSlices(t *testing.T) {
	first := DefaultResolvers()
	second := DefaultResolvers()
	if assert.NotEmpty(t, first) {
		first[0] = "192.0.2.1"
		assert.NotEqual(t, first[0], second[0])
	}
}

func TestStateEnumWireCompatibility(t *testing.T) {
	for _, status := range []CheckStatus{StatusPending, StatusOK, StatusFailed, StatusMismatch, StatusWarning, StatusHijacked} {
		encoded, err := jsonv2.Marshal(DNSState{Status: status})
		require.NoError(t, err)
		var decoded DNSState
		require.NoError(t, jsonv2.Unmarshal(encoded, &decoded))
		assert.Equal(t, status, decoded.Status)
		var wire map[string]any
		require.NoError(t, jsonv2.Unmarshal(encoded, &wire))
		assert.IsType(t, "", wire["status"], "API statuses must remain strings")
	}
	_, err := jsonv2.Marshal(DNSState{Status: CheckStatus(255)})
	require.Error(t, err, "invalid statuses must still fail encoding")
}

func TestRuntimeViewsAvoidAllocations(t *testing.T) {
	app := NewAppState(AppConfig{Resolvers: []string{"1.1.1.1"}})
	var cfg AppConfig
	var resolvers []string
	allocations := testing.AllocsPerRun(100, func() {
		cfg = app.configuration()
		resolvers = app.resolvers()
	})
	assert.Zero(t, allocations)
	assert.Equal(t, "1.1.1.1", cfg.Resolvers[0])
	assert.Equal(t, "1.1.1.1", resolvers[0])
}
