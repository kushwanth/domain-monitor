package main

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
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

func TestCopyMap(t *testing.T) {
	t.Parallel()

	var nilMap map[string]int
	copiedNil := CopyMap(nilMap)
	if copiedNil == nil || len(copiedNil) != 0 {
		t.Errorf("CopyMap(nil) expected non-nil empty map")
	}

	orig := map[string]int{"a": 1, "b": 2}
	cp := CopyMap(orig)
	if len(cp) != 2 || cp["a"] != 1 || cp["b"] != 2 {
		t.Errorf("CopyMap failed to copy entries correctly")
	}

	// Mutate copy, ensure orig is untouched
	cp["c"] = 3
	if _, exists := orig["c"]; exists {
		t.Errorf("Mutating copy affected original map")
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

func TestDeduplicateSlice(t *testing.T) {
	t.Parallel()

	if got := DeduplicateSlice[int](nil); got != nil {
		t.Errorf("DeduplicateSlice(nil) expected nil, got %v", got)
	}

	items := []string{"apple", "banana", "apple", "orange", "banana"}
	expected := []string{"apple", "banana", "orange"}
	got := DeduplicateSlice(items)
	if len(got) != len(expected) {
		t.Fatalf("DeduplicateSlice len = %d, expected %d", len(got), len(expected))
	}
	for i := range expected {
		if got[i] != expected[i] {
			t.Errorf("DeduplicateSlice[%d] = %q, expected %q", i, got[i], expected[i])
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

func TestIsSafeSubpath(t *testing.T) {
	t.Parallel()

	baseDir := "/app/data"

	tests := []struct {
		target   string
		expected bool
	}{
		{"/app/data/ct_logs", true},
		{"/app/data/ct_logs/example.com.json", true},
		{"/app/data", false}, // exactly the same as baseDir
		{"/app/data/../etc/passwd", false},
		{"/etc/passwd", false},
		{"/app/data_leak", false},
	}

	for _, tt := range tests {
		if got := IsSafeSubpath(baseDir, tt.target); got != tt.expected {
			t.Errorf("IsSafeSubpath(%q, %q) = %v, expected %v", baseDir, tt.target, got, tt.expected)
		}
	}
}

func TestAtomicWriteFile(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "test.txt")

	data1 := []byte("first content")
	if err := AtomicWriteFile(filePath, data1, 0600); err != nil {
		t.Fatalf("AtomicWriteFile failed: %v", err)
	}

	read1, err := os.ReadFile(filePath)
	if err != nil || string(read1) != string(data1) {
		t.Fatalf("ReadFile got %q, expected %q (err: %v)", read1, data1, err)
	}

	// Overwrite atomically
	data2 := []byte("second updated content")
	if err := AtomicWriteFile(filePath, data2, 0600); err != nil {
		t.Fatalf("AtomicWriteFile overwrite failed: %v", err)
	}

	read2, err := os.ReadFile(filePath)
	if err != nil || string(read2) != string(data2) {
		t.Fatalf("ReadFile after overwrite got %q, expected %q (err: %v)", read2, data2, err)
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

	if got := ResolveHTTPClient(nil); got != DefaultHTTPClient {
		t.Errorf("ResolveHTTPClient(nil) expected DefaultHTTPClient")
	}

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
	LogInfo("Test info message", "key", "value")
	LogInfof("Test infof %s", "formatted")
	LogWarn("Test warn message", "code", 123)
	LogWarnf("Test warnf %d", 456)
	LogError("Test error message", "error", "mock error")
	LogErrorf("Test errorf %s", "detailed error")
	LogDebug("Test debug message", "trace", "id-789")
	LogDebugf("Test debugf %s", "debug detail")
}

func TestLogUtil_CleanFormattingAndNoSource(t *testing.T) {
	var buf bytes.Buffer
	handler := NewConsoleHandler(&buf)
	oldLogger := slog.Default()
	defer slog.SetDefault(oldLogger)
	slog.SetDefault(slog.New(handler))

	LogInfo("Sample localized message", "test_attr", 42)

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

	root := errors.New("root cause")
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
	if got := AnyToString(errors.New("custom error")); got != "custom error" {
		t.Errorf("AnyToString(error) = %q, expected %q", got, "custom error")
	}
	if got := AnyToString(dummyStringer{}); got != "dummy-string" {
		t.Errorf("AnyToString(Stringer) = %q, expected %q", got, "dummy-string")
	}
	if got := AnyToString(12345); got != "12345" {
		t.Errorf("AnyToString(int) = %q, expected %q", got, "12345")
	}
}
