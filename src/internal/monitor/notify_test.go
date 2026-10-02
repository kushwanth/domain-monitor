package monitor

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/require"
)

func TestNotificationManager(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		alerts     []Alert
		expectSent int
	}{
		{
			name: "Single Alert",
			alerts: []Alert{
				{Message: "Test Alert", Redacted: "Test Alert 0", Priority: PriorityUrgent, Domain: "example.com"},
			},
			expectSent: 1,
		},
		{
			name: "Multiple Alerts",
			alerts: []Alert{
				{Message: "Test Alert 1", Redacted: "Test Alert 1", Priority: PriorityHigh, Domain: "example.com"},
				{Message: "Test Alert 2", Redacted: "Test Alert 2", Priority: PriorityUrgent, Domain: "example.com"},
			},
			expectSent: 2,
		},
		{
			name:       "No Alerts",
			alerts:     []Alert{},
			expectSent: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			nm := &NotificationManager{
				NtfyURL: "https://ntfy.invalid/test",
			}

			for _, a := range tt.alerts {
				nm.Dispatch(a.Message, a.Redacted, a.Priority, a.Tag, a.Domain, a.Name)
			}

			nm.mu.Lock()
			if len(nm.alertBatch) != tt.expectSent {
				t.Errorf("expected %d alerts in buffer, got %d", tt.expectSent, len(nm.alertBatch))
			}
			nm.mu.Unlock()
		})
	}
}

func TestNotificationManager_PriorityLogging(t *testing.T) {
	t.Parallel()

	priorities := []AlertPriority{PriorityUrgent, PriorityHigh, PriorityWarning, PriorityDefault}

	for _, p := range priorities {
		p := p
		t.Run(p.String(), func(t *testing.T) {
			t.Parallel()

			nm := &NotificationManager{
				NtfyURL: "https://ntfy.invalid/test",
			}

			nm.Dispatch("test message", "redacted", p, "tag", "example.com", "Test")

			nm.mu.Lock()
			if len(nm.alertBatch) != 1 {
				t.Errorf("priority %s: expected 1 alert sent, got %d", p, len(nm.alertBatch))
			}
			nm.mu.Unlock()
		})
	}
}

func TestNotificationRedaction_NtfyMatchesTelegram(t *testing.T) {
	var ntfyBody string
	nm := &NotificationManager{
		NtfyURL: "http://ntfy.invalid/topic",
		HTTPClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				return nil, err
			}
			ntfyBody = string(body)
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(""))}, nil
		})},
	}

	secretDomain := "corp-secret.internal"
	alert := Alert{
		Message:  "Raw alert containing " + secretDomain + " and secret token",
		Redacted: "Domain " + secretDomain + " registration expiring",
		Priority: PriorityHigh,
		Tag:      "warning",
		Domain:   secretDomain,
		Name:     "Corp Secret Portal",
	}

	res := nm.sendNtfyBatchContext(context.Background(), alert)
	if !res {
		t.Fatalf("expected sendNtfyBatchContext to succeed")
	}
	if strings.Contains(ntfyBody, secretDomain) {
		t.Errorf("expected redacted message, got %s", ntfyBody)
	}
	if !strings.Contains(ntfyBody, "Corp Secret Portal") {
		t.Errorf("expected Corp Secret Portal, got %s", ntfyBody)
	}
}

func TestNotification_SynchronousFlush(t *testing.T) {
	transport := &mockTransport{}

	nm := &NotificationManager{
		NtfyURL:        "http://dummy-ntfy",
		TelegramToken:  "testtoken",
		TelegramChatID: "12345",
		HTTPClient:     &http.Client{Transport: transport},
	}

	nm.Dispatch("msg1", "", PriorityHigh, "tag1", "domain1.com", "name1")
	nm.Flush()

	transport.mu.Lock()
	if transport.attempts != 2 {
		t.Errorf("expected 2 requests processed by flush, got %d", transport.attempts)
	}
	transport.mu.Unlock()
}

func TestNotification_PayloadBoundsAndTruncation(t *testing.T) {
	message := strings.Repeat("☃", MaxProviderMessageBytes)
	shortened := truncateAlertBytes(message, MaxProviderMessageBytes)
	if len(shortened) > MaxProviderMessageBytes || !utf8.ValidString(shortened) || !strings.HasSuffix(shortened, AlertTruncationNotice) {
		t.Fatalf("truncated message is not valid and disclosed: bytes=%d", len(shortened))
	}

	var deliveredText string
	nm := &NotificationManager{
		TelegramToken: "token", TelegramChatID: "chat",
		HTTPClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			body, err := io.ReadAll(req.Body)
			if err != nil {
				return nil, err
			}
			deliveredText = string(body)
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"ok":true}`)), Header: make(http.Header)}, nil
		})},
	}
	res := nm.sendTelegramBatchContext(context.Background(), Alert{Message: strings.Repeat("<", 1000), Name: strings.Repeat("&", 100)})
	if !res {
		t.Fatal("expected a bounded Telegram alert to be accepted")
	}
	if !strings.Contains(deliveredText, "truncated; see local state") {
		t.Fatal("expected truncation notice in delivered Telegram message")
	}
}

func TestTelegramRejectsOversizedAcceptance(t *testing.T) {
	nm := NewNotificationManager("", "", "token", "chat")
	nm.HTTPClient = &MockHTTPClient{MockDo: func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"ok":true}` + strings.Repeat(" ", MaxNotificationPayloadSize)))}, nil
	}}
	res := nm.sendTelegramBatchContext(context.Background(), Alert{Message: "test", Redacted: "test"})
	if res {
		t.Fatalf("Expected false on oversized")
	}
}

func TestTelegramRequestCreationRedactsToken(t *testing.T) {
	var output bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&output, nil)))
	defer slog.SetDefault(previous)
	token := "private-secret%zz"
	manager := NewNotificationManager("", "", token, "chat")
	res := manager.sendTelegramBatchContext(context.Background(), Alert{Message: "test"})
	if res {
		t.Fatalf("Expected false")
	}
	if strings.Contains(output.String(), token) {
		t.Fatalf("Expected token to be redacted")
	}
	if !strings.Contains(output.String(), MsgLogTelegramRequestFailed) && !strings.Contains(output.String(), MsgLogTelegramRequestError) && !strings.Contains(output.String(), MsgLogNotificationClientMissing) {
		t.Fatalf("Expected failure log")
	}
}

func TestNotificationProviderFailures(t *testing.T) {
	// Serial because the captured logger is shared by the process.
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	defer slog.SetDefault(previous)
	for _, provider := range []string{"ntfy", "telegram"} {
		for _, failure := range []string{"missing client", "invalid URL", "transport", "status", "invalid JSON", "rejected", "read"} {
			if provider == "ntfy" && (failure == "invalid JSON" || failure == "rejected" || failure == "read") {
				continue
			}
			t.Run(provider+"/"+failure, func(t *testing.T) {
				logs.Reset()
				nm := NewNotificationManager("https://ntfy.invalid/topic", "secret-auth", "secret-token", "chat")
				calls := 0
				nm.HTTPClient = &MockHTTPClient{MockDo: func(req *http.Request) (*http.Response, error) {
					calls++
					if req.Method != http.MethodPost || req.Header.Get(HeaderUserAgent) != DefaultUserAgent {
						t.Error("missing provider request method or user agent")
					}
					if provider == "ntfy" && req.Header.Get(HeaderAuthorization) != nm.NtfyAuth {
						t.Error("missing authentication")
					}
					if failure == "transport" {
						return nil, errors.New("transport failed: secret-auth secret-token")
					}
					status, body := http.StatusOK, `{"ok":true}`
					switch failure {
					case "status":
						status = http.StatusServiceUnavailable
					case "invalid JSON":
						body = "invalid"
					case "rejected":
						body = `{"ok":false}`
					}
					var reader io.Reader = strings.NewReader(body)
					if failure == "read" {
						reader = failingProviderReader{}
					}
					return &http.Response{StatusCode: status, Body: io.NopCloser(reader)}, nil
				}}
				if failure == "missing client" {
					nm.HTTPClient = nil
				}
				if failure == "invalid URL" {
					nm.NtfyURL = "://invalid"
					nm.TelegramToken = "secret-token%zz"
				}
				alert := Alert{Message: "test", Priority: PriorityHigh}
				var delivered bool
				if provider == "ntfy" {
					delivered = nm.sendNtfyBatchContext(context.Background(), alert)
				} else {
					delivered = nm.sendTelegramBatchContext(context.Background(), alert)
				}
				if delivered {
					t.Fatal("failure must not be reported as delivered")
				}
				wantCalls := 1
				switch failure {
				case "missing client", "invalid URL":
					wantCalls = 0
				case "status":
					wantCalls = MaxNetworkAttempts
				}
				if calls != wantCalls {
					t.Errorf("transport calls = %d, want %d", calls, wantCalls)
				}
				secret := nm.NtfyAuth
				if provider == "telegram" {
					secret = nm.TelegramToken
				}
				if strings.Contains(logs.String(), secret) {
					t.Fatal("provider credential leaked to logs")
				}
			})
		}
	}
}

func TestNotificationFormattingAndPayloadLimits(t *testing.T) {
	text := formatNtfyMessage(Alert{Message: strings.Repeat("x", MaxAlertMessageRunes+100)})
	if len(text) > MaxAlertMessageRunes || !strings.HasSuffix(text, AlertTruncationNotice) {
		t.Fatal("long ntfy message must be bounded with a truncation notice")
	}
	text = formatTelegramMessage(Alert{Message: strings.Repeat("&", MaxTelegramAlertRunes), Name: strings.Repeat("&", MaxAlertNameRunes)})
	if len(text) > MaxProviderMessageBytes || strings.Contains(text, "&&") {
		t.Fatal("escaped Telegram message exceeds limits or contains unescaped HTML")
	}
}

func TestNotificationFlushPriorityAndIndependentAttempts(t *testing.T) {
	for range 2 {
		nm := NewNotificationManager("https://ntfy.invalid/topic", "", "token", "chat")
		var previous context.Context
		var attempts []string
		nm.HTTPClient = &MockHTTPClient{MockDo: func(req *http.Request) (*http.Response, error) {
			if previous != nil && previous.Err() == nil {
				t.Error("previous attempt context was not canceled before next delivery")
			}
			if req.Context().Err() != nil {
				t.Error("previous failure canceled a subsequent attempt")
			}
			previous = req.Context()
			if req.URL.Host == "ntfy.invalid" {
				body, err := io.ReadAll(req.Body)
				if err != nil {
					return nil, err
				}
				attempts = append(attempts, string(body))
				return nil, context.DeadlineExceeded
			}
			attempts = append(attempts, "telegram")
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"ok":true}`))}, nil
		}}
		for _, alert := range []Alert{{Message: "warning", Priority: PriorityWarning}, {Message: "critical", Priority: PriorityHigh}, {Message: "urgent", Priority: PriorityUrgent}, {Message: "critical second", Priority: PriorityHigh}} {
			nm.Dispatch(alert.Message, "", alert.Priority, "", "", "")
		}
		nm.FlushContext(context.Background())
		want := []string{"urgent\ncritical\ncritical second\nwarning", "telegram"}
		if !slices.Equal(attempts, want) {
			t.Errorf("delivery order = %v, want %v", attempts, want)
		}
		if previous == nil || previous.Err() == nil {
			t.Error("last attempt context was not released")
		}
		if len(nm.takeAlertBatch()) != 0 {
			t.Error("completed attempts retained in queue")
		}
	}
}

func TestCycleReportIsBoundedAndKeepsHighestSeverity(t *testing.T) {
	nm := NewNotificationManager("https://ntfy.invalid/topic", "", "", "")
	for index := 0; index < MaxCycleReportItems+10; index++ {
		nm.Dispatch(fmt.Sprintf("warning-%03d", index), "", PriorityWarning, "", "", "")
	}
	nm.Dispatch("urgent-last", "", PriorityUrgent, "", "", "")
	batch, omitted := nm.takeAlertReportBatch()
	require.Len(t, batch, MaxCycleReportItems)
	require.Equal(t, 11, omitted)
	require.Equal(t, "urgent-last", batch[0].Message)
	report := buildCycleReport(batch, omitted)
	require.Contains(t, report.Message, "11 additional findings omitted")
	require.NotEmpty(t, report.ReportID)
}
