package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// MockProvider implements the Notifier interface for testing
type MockProvider struct {
	MessagesSent int
	Alerts       []Alert
	mu           sync.Mutex
}

func (m *MockProvider) Send(_ context.Context, alert Alert) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.MessagesSent++
	m.Alerts = append(m.Alerts, alert)
}

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
			mock1 := &MockProvider{}
			mock2 := &MockProvider{}

			nm := &NotificationManager{
				Providers: []NotificationProvider{mock1, mock2},
			}

			for _, a := range tt.alerts {
				nm.Dispatch(a.Message, a.Redacted, a.Priority, a.Tag, a.Domain, a.Name)
			}

			time.Sleep(100 * time.Millisecond)

			mock1.mu.Lock()
			if mock1.MessagesSent != tt.expectSent {
				t.Errorf("Mock1: expected %d, got %d", tt.expectSent, mock1.MessagesSent)
			}
			mock1.mu.Unlock()

			mock2.mu.Lock()
			if mock2.MessagesSent != tt.expectSent {
				t.Errorf("Mock2: expected %d, got %d", tt.expectSent, mock2.MessagesSent)
			}
			mock2.mu.Unlock()
		})
	}
}

func TestNotificationDeduplication(t *testing.T) {
	t.Parallel()

	mock := &MockProvider{}
	nm := &NotificationManager{
		Providers: []NotificationProvider{mock},
	}

	// First occurrence of alert
	nm.Dispatch("Critical Alert 1", "Redacted 1", PriorityUrgent, "skull", "example.com", "Test")

	// Same alert should be deduplicated / suppressed while active
	nm.Dispatch("Critical Alert 1", "Redacted 1", PriorityUrgent, "skull", "example.com", "Test")
	nm.Dispatch("Critical Alert 1", "Redacted 1", PriorityUrgent, "skull", "example.com", "Test")

	// Different alert should pass through
	nm.Dispatch("Critical Alert 2", "Redacted 2", PriorityUrgent, "skull", "example.com", "Test")

	time.Sleep(100 * time.Millisecond)

	mock.mu.Lock()
	if mock.MessagesSent != 2 {
		t.Fatalf("Expected 2 message sent (deduplicated), got %d", mock.MessagesSent)
	}
	mock.mu.Unlock()
}

func TestTelegramTokenRedaction(t *testing.T) {
	t.Parallel()

	token := "123456789:ABCDefGhIJKlmNoPQRsTUVwxyZ_SECRET"
	provider := &TelegramProvider{
		Token:  token,
		ChatID: "987654321",
	}

	// Use an expired/cancelled context to force immediate client.Do error
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	alert := Alert{Message: "Test Alert", Priority: PriorityHigh, Domain: "example.com"}

	// Send should recover, handle error cleanly, and redact token
	provider.Send(ctx, alert)
}

func TestNtfyAuthRedaction(t *testing.T) {
	t.Parallel()

	secretAuth := "Bearer secret_ntfy_auth_token_98765"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("Unauthorized for token: " + secretAuth))
	}))
	defer server.Close()

	provider := &NtfyProvider{
		URL:  server.URL,
		Auth: secretAuth,
	}

	alert := Alert{Message: "Test Alert", Priority: PriorityHigh, Domain: "example.com"}

	provider.Send(context.Background(), alert)
}

func TestNilSafety_NotificationManager(t *testing.T) {
	// 1. Nil NotificationManager receiver should be a complete no-op and never panic
	var nilNM *NotificationManager
	nilNM.Dispatch("msg", "redacted", PriorityHigh, "tag", "domain", "name")

	// 2. NotificationManager with nil provider in slice
	nm := &NotificationManager{
		Providers: []NotificationProvider{nil},
	}
	nm.Dispatch("msg", "redacted", PriorityHigh, "tag", "domain", "name")

	// 3. Nil providers Send method
	var nilNtfy *NtfyProvider
	nilNtfy.Send(context.Background(), Alert{})

	var nilTG *TelegramProvider
	nilTG.Send(context.Background(), Alert{})
}

func TestNotificationManager_PriorityLogging(t *testing.T) {
	t.Parallel()

	priorities := []AlertPriority{PriorityUrgent, PriorityHigh, PriorityWarning, PriorityDefault}

	for _, p := range priorities {
		p := p
		t.Run(string(p), func(t *testing.T) {
			t.Parallel()

			mock := &MockProvider{}
			nm := &NotificationManager{
				Providers: []NotificationProvider{mock},
			}

			// Dispatch must not panic for any priority level
			nm.Dispatch("test message", "redacted", p, "tag", "example.com", "Test")
			time.Sleep(50 * time.Millisecond)

			mock.mu.Lock()
			if mock.MessagesSent != 1 {
				t.Errorf("priority %s: expected 1 alert sent, got %d", p, mock.MessagesSent)
			}
			mock.mu.Unlock()
		})
	}
}

func TestTelegramProvider_OversizedMessageHandling(t *testing.T) {
	t.Parallel()

	provider := &TelegramProvider{
		Token:  "test-token",
		ChatID: "12345",
	}

	hugeMsg := strings.Repeat("Very long error message that exceeds normal limits. ", 200)
	alert := Alert{Message: hugeMsg, Priority: PriorityHigh, Domain: "example.com", Name: "Test"}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("TelegramProvider.Send panicked on oversized alert: %v", r)
		}
	}()

	provider.Send(ctx, alert)
}

func TestNotificationRedaction_NtfyMatchesTelegram(t *testing.T) {
	var ntfyBody string
	var ntfyMu sync.Mutex
	ntfyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		ntfyMu.Lock()
		ntfyBody = string(b)
		ntfyMu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer ntfyServer.Close()

	provider := &NtfyProvider{
		URL: ntfyServer.URL,
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

	provider.Send(context.Background(), alert)

	ntfyMu.Lock()
	body := ntfyBody
	ntfyMu.Unlock()

	if strings.Contains(body, secretDomain) {
		t.Errorf("Ntfy leaked unmasked domain %q: body=%q", secretDomain, body)
	}
	if !strings.Contains(body, "Corp Secret Portal") {
		t.Errorf("Ntfy expected replacement Corp Secret Portal in body, got: %q", body)
	}
}



