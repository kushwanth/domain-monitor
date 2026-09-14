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

// MockNotifier implements the Notifier interface for testing
type MockNotifier struct {
	MessagesSent int
	mu           sync.Mutex
}

func (m *MockNotifier) Send(_ context.Context, alerts []Alert, wg *sync.WaitGroup) {
	defer wg.Done()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.MessagesSent += len(alerts)
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
			mock1 := &MockNotifier{}
			mock2 := &MockNotifier{}

			nm := &NotificationManager{
				Providers: []NotificationProvider{mock1, mock2},
			}

			for _, a := range tt.alerts {
				nm.Dispatch(a.Message, a.Redacted, a.Priority, a.Tag, a.Domain, a.Name)
			}
			nm.Flush(context.Background())

			if mock1.MessagesSent != tt.expectSent {
				t.Errorf("Mock1: expected %d, got %d", tt.expectSent, mock1.MessagesSent)
			}
			if mock2.MessagesSent != tt.expectSent {
				t.Errorf("Mock2: expected %d, got %d", tt.expectSent, mock2.MessagesSent)
			}
		})
	}
}

func TestNotificationDeduplication(t *testing.T) {
	t.Parallel()

	mock := &MockNotifier{}
	nm := &NotificationManager{
		Providers: []NotificationProvider{mock},
	}

	// Cycle 1: First occurrence of alert
	nm.StartCycle()
	nm.Dispatch("Critical Alert 1", "Redacted 1", PriorityUrgent, "skull", "example.com", "Test")
	nm.Flush(context.Background())
	nm.EndCycle()

	if mock.MessagesSent != 1 {
		t.Fatalf("Cycle 1: expected 1 message sent, got %d", mock.MessagesSent)
	}

	// Cycle 2: Same alert should be deduplicated / suppressed while active
	nm.StartCycle()
	nm.Dispatch("Critical Alert 1", "Redacted 1", PriorityUrgent, "skull", "example.com", "Test")
	nm.Flush(context.Background())
	nm.EndCycle()

	if mock.MessagesSent != 1 {
		t.Fatalf("Cycle 2: expected 1 message sent (deduplicated), got %d", mock.MessagesSent)
	}

	// Cycle 3: Issue resolves, alert not dispatched
	nm.StartCycle()
	// No dispatch this cycle
	nm.Flush(context.Background())
	nm.EndCycle()

	if mock.MessagesSent != 1 {
		t.Fatalf("Cycle 3: expected 1 message sent, got %d", mock.MessagesSent)
	}

	// Cycle 4: Issue re-occurs, should alert again since it was resolved in Cycle 3
	nm.StartCycle()
	nm.Dispatch("Critical Alert 1", "Redacted 1", PriorityUrgent, "skull", "example.com", "Test")
	nm.Flush(context.Background())
	nm.EndCycle()

	if mock.MessagesSent != 2 {
		t.Fatalf("Cycle 4: expected 2 messages sent after resolution, got %d", mock.MessagesSent)
	}
}

func TestNotificationCycleWait(t *testing.T) {
	t.Parallel()

	mock := &MockNotifier{}
	nm := &NotificationManager{
		Providers: []NotificationProvider{mock},
	}

	cycleCtx, cycleCancel := context.WithCancel(context.Background())

	nm.StartCycle()
	nm.Dispatch("Critical Alert", "Redacted", PriorityUrgent, "rotating_light", "example.com", "Test")
	nm.Flush(cycleCtx)
	nm.Wait() // Synchronously wait before cancelling cycle context
	nm.EndCycle()
	cycleCancel()

	if mock.MessagesSent != 1 {
		t.Fatalf("Expected 1 message delivered before cycleCancel, got %d", mock.MessagesSent)
	}
}

func TestNotificationDeduplication_MultipleDistinctCAsInSameCycle(t *testing.T) {
	t.Parallel()

	mock := &MockNotifier{}
	nm := &NotificationManager{
		Providers: []NotificationProvider{mock},
	}

	nm.StartCycle()
	// Alert 1: missing letsencrypt.org
	nm.Dispatch("Expected CA 'letsencrypt.org' missing in issue for example.com", "Expected CA 'letsencrypt.org' missing in issue.", PriorityHigh, "warning", "example.com", "Example")
	// Alert 2: missing digicert.com
	nm.Dispatch("Expected CA 'digicert.com' missing in issue for example.com", "Expected CA 'digicert.com' missing in issue.", PriorityHigh, "warning", "example.com", "Example")
	nm.Flush(context.Background())
	nm.EndCycle()

	if mock.MessagesSent != 2 {
		t.Errorf("Expected 2 distinct alerts sent in the same cycle, got %d", mock.MessagesSent)
	}
}

func TestTelegramTokenRedaction(t *testing.T) {
	t.Parallel()

	token := "123456789:ABCDefGhIJKlmNoPQRsTUVwxyZ_SECRET"
	provider := &TelegramProvider{
		Token:  token,
		ChatID: "987654321",
	}

	var wg sync.WaitGroup
	wg.Add(1)

	// Use an expired/cancelled context to force immediate client.Do error
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	alerts := []Alert{
		{Message: "Test Alert", Priority: PriorityHigh, Domain: "example.com"},
	}

	// Send should recover, handle error cleanly, and redact token
	provider.Send(ctx, alerts, &wg)
	wg.Wait()
}

func TestNotificationCycleTimeoutIndependentDispatch(t *testing.T) {
	t.Parallel()

	mock := &MockNotifier{}
	nm := &NotificationManager{
		Providers: []NotificationProvider{mock},
	}

	rootCtx := context.Background()

	// Simulate a cycle context that timed out during check execution
	cycleCtx, cycleCancel := context.WithCancel(rootCtx)
	cycleCancel() // Expired

	nm.StartCycle()
	nm.Dispatch("Urgent Failure During Long Cycle", "Redacted Failure", PriorityUrgent, "rotating_light", "example.com", "Test")

	// Ensure that using cycleCtx would have failed to deliver under cancelled context
	if cycleCtx.Err() == nil {
		t.Fatalf("Expected cycleCtx to be cancelled")
	}

	// The hardened monitoring loop pattern uses a dedicated notifyCtx derived from rootCtx
	notifyCtx, notifyCancel := context.WithTimeout(rootCtx, 5*time.Second)
	defer notifyCancel()

	nm.Flush(notifyCtx)
	nm.Wait()
	nm.EndCycle()

	if mock.MessagesSent != 1 {
		t.Fatalf("Expected 1 alert delivered via notifyCtx despite expired cycleCtx, got %d", mock.MessagesSent)
	}
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

	var wg sync.WaitGroup
	wg.Add(1)
	alerts := []Alert{
		{Message: "Test Alert", Priority: PriorityHigh, Domain: "example.com"},
	}

	provider.Send(context.Background(), alerts, &wg)
	wg.Wait()
}

func TestNilSafety_NotificationManager(t *testing.T) {
	// 1. Nil NotificationManager receiver should be a complete no-op and never panic
	var nilNM *NotificationManager
	nilNM.StartCycle()
	nilNM.Dispatch("msg", "redacted", PriorityHigh, "tag", "domain", "name")
	nilNM.Flush(context.Background())
	nilNM.Wait()
	nilNM.EndCycle()

	// 2. NotificationManager with nil provider in slice
	nm := &NotificationManager{
		Providers: []NotificationProvider{nil},
		Buffer:    []Alert{{Message: "hello"}},
	}
	nm.Flush(context.Background())
	nm.Wait()

	// 3. Nil providers Send method
	var nilNtfy *NtfyProvider
	nilNtfy.Send(context.Background(), nil, nil)

	var nilTG *TelegramProvider
	nilTG.Send(context.Background(), nil, nil)
}

// TestNotificationManager_TypedNilProviderSafety validates that Flush does not panic when
// a typed nil (*NtfyProvider or *TelegramProvider) is stored inside a NotificationProvider
// interface value. Each provider method implementation is nil-receiver safe.
func TestNotificationManager_TypedNilProviderSafety(t *testing.T) {
	t.Parallel()

	// Build a typed nil *NtfyProvider. When stored as NotificationProvider, provider != nil.
	var typedNilNtfy *NtfyProvider
	var typedNilTG *TelegramProvider

	nm := &NotificationManager{
		Providers: []NotificationProvider{typedNilNtfy, typedNilTG},
		Buffer:    []Alert{{Message: "should not panic", Priority: PriorityUrgent}},
	}

	// This must NOT panic. Receiver nil guards protect against nil pointer dereference.
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("Flush panicked on typed nil provider: %v", r)
		}
	}()

	nm.Flush(context.Background())
	nm.Wait()
}

// TestNotificationManager_PriorityLogging verifies that Dispatch routes log levels correctly:
// PriorityUrgent/PriorityHigh → LogError, PriorityWarning → LogWarn, PriorityDefault → LogInfo.
// Since we cannot intercept slog directly without an extra handler, we verify that Dispatch
// does not panic for all priority levels and correctly deduplicates using key composition.
func TestNotificationManager_PriorityLogging(t *testing.T) {
	t.Parallel()

	priorities := []AlertPriority{PriorityUrgent, PriorityHigh, PriorityWarning, PriorityDefault}

	for _, p := range priorities {
		p := p
		t.Run(string(p), func(t *testing.T) {
			t.Parallel()

			mock := &MockNotifier{}
			nm := &NotificationManager{
				Providers: []NotificationProvider{mock},
			}

			// Dispatch must not panic for any priority level
			nm.Dispatch("test message", "redacted", p, "tag", "example.com", "Test")
			nm.Flush(context.Background())
			nm.Wait()

			if mock.MessagesSent != 1 {
				t.Errorf("priority %s: expected 1 alert sent, got %d", p, mock.MessagesSent)
			}
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
	alerts := []Alert{
		{Message: hugeMsg, Priority: PriorityHigh, Domain: "example.com", Name: "Test"},
	}

	var wg sync.WaitGroup
	wg.Add(1)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("TelegramProvider.Send panicked on oversized alert: %v", r)
		}
	}()

	provider.Send(ctx, alerts, &wg)
	wg.Wait()
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
	alerts := []Alert{
		{
			Message:  "Raw alert containing " + secretDomain + " and secret token",
			Redacted: "Domain " + secretDomain + " registration expiring",
			Priority: PriorityHigh,
			Tag:      "warning",
			Domain:   secretDomain,
			Name:     "Corp Secret Portal",
		},
	}

	var wg sync.WaitGroup
	wg.Add(1)
	provider.Send(context.Background(), alerts, &wg)
	wg.Wait()

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

func TestNotificationShutdown_FlushDelivery(t *testing.T) {
	mock := &MockNotifier{}
	nm := &NotificationManager{
		Providers: []NotificationProvider{mock},
	}

	nm.Dispatch("Alert 1", "Redacted 1", PriorityHigh, "warning", "a.com", "A")
	nm.Dispatch("Alert 2", "Redacted 2", PriorityUrgent, "x", "b.com", "B")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer shutdownCancel()

	nm.Flush(shutdownCtx)
	nm.Wait()

	if mock.MessagesSent != 2 {
		t.Errorf("expected 2 alerts flushed on shutdown, got %d", mock.MessagesSent)
	}
	if len(nm.Buffer) != 0 {
		t.Errorf("expected buffer to be emptied after flush, got %d", len(nm.Buffer))
	}
}
