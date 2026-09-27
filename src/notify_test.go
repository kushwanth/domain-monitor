package main

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"
	"unicode/utf8"
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

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return fn(req) }

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

type mockTransport struct {
	attempts  int
	mu        sync.Mutex
	failTimes int
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	m.mu.Lock()
	m.attempts++
	m.mu.Unlock()

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
	if !strings.Contains(output.String(), MsgLogTelegramRequestFailed) && !strings.Contains(output.String(), "missing") {
		t.Fatalf("Expected failure log")
	}
}
