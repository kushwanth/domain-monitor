package main

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
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

func TestNotificationDeduplication(t *testing.T) {
	t.Parallel()

	nm := &NotificationManager{
		NtfyURL: "https://ntfy.invalid/test",
	}

	// First occurrence of alert
	nm.Dispatch("Critical Alert 1", "Redacted 1", PriorityUrgent, "skull", "example.com", "Test")

	// Same alert should be deduplicated / suppressed while active
	nm.Dispatch("Critical Alert 1", "Redacted 1", PriorityUrgent, "skull", "example.com", "Test")
	nm.Dispatch("Critical Alert 1", "Redacted 1", PriorityUrgent, "skull", "example.com", "Test")

	// Different alert should pass through
	nm.Dispatch("Critical Alert 2", "Redacted 2", PriorityUrgent, "skull", "example.com", "Test")

	nm.mu.Lock()
	if len(nm.alertBatch) != 2 {
		t.Fatalf("Expected 2 message in buffer (deduplicated), got %d", len(nm.alertBatch))
	}
	nm.mu.Unlock()
}

func TestNilSafety_NotificationManager(t *testing.T) {
	var nilNM *NotificationManager
	nilNM.Dispatch("msg", "redacted", PriorityHigh, "tag", "domain", "name")
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

	require.True(t, nm.sendNtfyBatchContext(context.Background(), []Alert{alert}))
	assert.NotContains(t, ntfyBody, secretDomain)
	assert.Contains(t, ntfyBody, "Corp Secret Portal")
}

func TestFlushContextCancellationRetainsAlert(t *testing.T) {
	called := false
	nm := &NotificationManager{
		NtfyURL: "http://ntfy.invalid/topic",
		HTTPClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			called = true
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(""))}, nil
		})},
	}
	nm.DispatchIdentified("warning", "warning", "warning", PriorityWarning, TagSkull, "example.com", "Example")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	nm.FlushContext(ctx)
	assert.False(t, called)
	require.Len(t, nm.alertBatch, 1)
	nm.Flush()
	assert.True(t, called)
	assert.Empty(t, nm.alertBatch)
}

type mockTransport struct {
	attempts  int
	mu        sync.Mutex
	failTimes int
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	m.mu.Lock()
	m.attempts++
	currentAttempt := m.attempts
	m.mu.Unlock()

	if currentAttempt <= m.failTimes {
		return &http.Response{
			StatusCode: http.StatusInternalServerError,
			Body:       io.NopCloser(strings.NewReader("internal server error")),
			Header:     make(http.Header),
		}, nil
	}

	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(`{"ok":true}`)),
		Header:     make(http.Header),
	}, nil
}

func TestNotification_SynchronousFlush(t *testing.T) {
	transport := &mockTransport{failTimes: 0}

	nm := &NotificationManager{
		NtfyURL:        "http://dummy-ntfy",
		TelegramToken:  "testtoken",
		TelegramChatID: "12345",
		HTTPClient:     &http.Client{Transport: transport},
	}

	nm.Dispatch("msg1", "", PriorityHigh, "tag1", "domain1.com", "name1")
	nm.Flush()

	transport.mu.Lock()
	// Should process 1 Ntfy and 1 Telegram = 2 requests
	if transport.attempts != 2 {
		t.Errorf("expected 2 requests processed by worker loop, got %d", transport.attempts)
	}
	transport.mu.Unlock()
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return fn(req) }

func TestNotification_ProviderAcceptanceAndRetry(t *testing.T) {
	var ntfyCalls, telegramCalls int
	nm := &NotificationManager{
		NtfyURL: "http://ntfy.invalid/topic", TelegramToken: "token", TelegramChatID: "chat",
		HTTPClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			body := `{"ok":true}`
			if strings.Contains(req.URL.Host, "ntfy.invalid") {
				ntfyCalls++
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
			}
			telegramCalls++
			if telegramCalls == 1 {
				body = `{"ok":false}`
			}
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
		})},
	}
	nm.DispatchIdentified("RDAP|example.com|expired", "expired now", "expired", PriorityHigh, TagSkull, "example.com", "Example")
	nm.Flush()
	if ntfyCalls != 1 || telegramCalls != 1 {
		t.Fatalf("expected one attempt per provider, got ntfy=%d telegram=%d", ntfyCalls, telegramCalls)
	}
	nm.Flush()
	if ntfyCalls != 1 || telegramCalls != 2 {
		t.Fatalf("expected retry only for rejected provider, got ntfy=%d telegram=%d", ntfyCalls, telegramCalls)
	}
}

func TestNotification_CooldownDoesNotStarveNewAlerts(t *testing.T) {
	t.Parallel()
	nm := NewNotificationManager("http://ntfy.invalid/topic", "", "token", "chat")
	now := time.Now()
	for i := range MaxPendingAlerts {
		identity := "already-sent-" + strconv.Itoa(i)
		nm.sentState["ntfy|"+identity] = now
		nm.sentState["telegram|"+identity] = now
		nm.DispatchIdentified(identity, "old failure", "old failure", PriorityHigh, TagSkull, "example.com", "Example")
	}
	nm.DispatchIdentified("new-failure", "new failure", "new failure", PriorityHigh, TagSkull, "example.com", "Example")
	require.Len(t, nm.alertBatch, 1)
	assert.Equal(t, "new-failure", nm.alertBatch[0].Identity)
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
	if !nm.sendTelegramBatchContext(context.Background(), []Alert{{Message: strings.Repeat("<", 1000), Name: strings.Repeat("&", 100)}}) {
		t.Fatal("expected a bounded Telegram alert to be accepted")
	}
	if !strings.Contains(deliveredText, "truncated; see local state") {
		t.Fatal("expected truncation notice in delivered Telegram message")
	}
}

func TestCriticalAlertIsAdmittedAheadOfFullBacklog(t *testing.T) {
	for _, backlogPriority := range []AlertPriority{PriorityWarning, PriorityHigh} {
		t.Run(backlogPriority.String(), func(t *testing.T) {
			notifier := NewNotificationManager("https://ntfy.invalid/test", "", "", "")
			var messages []string
			notifier.HTTPClient = &MockHTTPClient{MockDo: func(req *http.Request) (*http.Response, error) {
				body, err := io.ReadAll(req.Body)
				require.NoError(t, err)
				messages = append(messages, string(body))
				return &http.Response{StatusCode: http.StatusServiceUnavailable, Body: io.NopCloser(strings.NewReader(""))}, nil
			}}
			for i := 0; i < MaxPendingAlerts; i++ {
				notifier.DispatchIdentified(strconv.Itoa(i), "old warning", "old warning", backlogPriority, "", "example.com", "")
			}
			notifier.DispatchIdentified("critical", "critical-new", "critical-new", PriorityHigh, "", "example.com", "")
			assert.Len(t, notifier.alertBatch, MaxPendingAlerts)
			notifier.FlushContext(context.Background())
			require.NotEmpty(t, messages)
			assert.Contains(t, messages[0], "critical-new")
		})
	}
}

func TestTelegramRejectsOversizedAcceptance(t *testing.T) {
	nm := NewNotificationManager("", "", "token", "chat")
	nm.HTTPClient = &MockHTTPClient{MockDo: func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"ok":true}` + strings.Repeat(" ", MaxNotificationPayloadSize)))}, nil
	}}
	assert.False(t, nm.sendTelegramBatchContext(context.Background(), []Alert{{Message: "test", Redacted: "test"}}))
}

func TestTelegramRequestCreationRedactsToken(t *testing.T) {
	var output bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&output, nil)))
	defer slog.SetDefault(previous)
	token := "private-secret%zz"
	manager := NewNotificationManager("", "", token, "chat")
	assert.False(t, manager.sendTelegramBatchContext(context.Background(), []Alert{{Message: "test"}}))
	assert.NotContains(t, output.String(), token)
	assert.Contains(t, output.String(), MsgLogTelegramRequestFailed)
}
