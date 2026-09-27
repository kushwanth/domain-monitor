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

	"github.com/miekg/dns"
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

func TestInitMap(t *testing.T) {
	t.Parallel()

	// 1. Nil pointer
	m1 := InitMap[string, int](nil)
	if m1 == nil {
		t.Fatalf("InitMap(nil) returned nil map")
	}

	// 2. Pointer to nil map
	var m2 map[string]int
	InitMap(&m2)
	if m2 == nil {
		t.Fatalf("InitMap(&nilMap) did not initialize map")
	}
	m2["key"] = 100
	if m2["key"] != 100 {
		t.Errorf("failed to write to initialized map")
	}

	// 3. Pointer to existing map
	m3 := map[string]int{"orig": 1}
	res := InitMap(&m3)
	if res["orig"] != 1 {
		t.Errorf("InitMap mutated existing map contents")
	}
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

type dummyStringer struct{}

func (dummyStringer) String() string { return "dummy-string" }

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

func TestLogStateTransitions(t *testing.T) {
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

// MockHTTPClient implements HTTPDoer for tests.
type MockHTTPClient struct {
	MockDo func(req *http.Request) (*http.Response, error)
}

func (m *MockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	if m.MockDo != nil {
		return m.MockDo(req)
	}
	return nil, nil
}

// MockDNSResolver implements DNSResolver for tests.
type MockDNSResolver struct {
	MockExchangeContext func(ctx context.Context, m *dns.Msg, a string) (*dns.Msg, time.Duration, error)
}

func (m *MockDNSResolver) ExchangeContext(ctx context.Context, msg *dns.Msg, a string) (*dns.Msg, time.Duration, error) {
	if m.MockExchangeContext != nil {
		return m.MockExchangeContext(ctx, msg, a)
	}
	return nil, 0, nil
}

// MockWHOISClient implements WHOISClient for tests.
type MockWHOISClient struct {
	MockQuery func(ctx context.Context, domain, server string) (string, error)
}

func (m *MockWHOISClient) Query(ctx context.Context, domain, server string) (string, error) {
	if m.MockQuery != nil {
		return m.MockQuery(ctx, domain, server)
	}
	return "", nil
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

type recordingNotifier struct {
	*NotificationManager
	alerts []Alert
}

func newRecordingNotifier() *recordingNotifier {
	notifier := NewNotificationManager("https://ntfy.invalid/test", "", "", "")
	notifier.HTTPClient = &MockHTTPClient{MockDo: func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(""))}, nil
	}}
	return &recordingNotifier{NotificationManager: notifier}
}

func (n *recordingNotifier) Dispatch(message, redacted string, priority AlertPriority, tag AlertTag, domain, name string) {
	n.NotificationManager.Dispatch(message, redacted, priority, tag, domain, name)
	n.captureAndFlush()
}

func (n *recordingNotifier) captureAndFlush() {
	n.alerts = append(n.alerts, n.alertBatch...)
	n.Flush()
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
