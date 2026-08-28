package main

import (
	"context"
	"sync"
	"testing"
	"time"
)

// MockNotifier implements the Notifier interface for testing
type MockNotifier struct {
	MessagesSent int
	mu           sync.Mutex
}

func (m *MockNotifier) Send(ctx context.Context, alerts []Alert, wg *sync.WaitGroup) {
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

	// Cycle 2: Same alert within 24h should be deduplicated / suppressed
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

func TestNotification24hExpiry(t *testing.T) {
	t.Parallel()

	mock := &MockNotifier{}
	nm := &NotificationManager{
		Providers: []NotificationProvider{mock},
	}

	nm.StartCycle()
	nm.Dispatch("Alert", "Redacted", PriorityHigh, "warning", "example.com", "Test")
	nm.Flush(context.Background())
	nm.EndCycle()

	if mock.MessagesSent != 1 {
		t.Fatalf("Expected 1 message, got %d", mock.MessagesSent)
	}

	// Artificially age the sent state by 25 hours
	key := "example.com|warning|Redacted"
	nm.mu.Lock()
	nm.sentState[key] = time.Now().Add(-25 * time.Hour)
	nm.mu.Unlock()

	// Should alert again because > 24 hours passed
	nm.StartCycle()
	nm.Dispatch("Alert", "Redacted", PriorityHigh, "warning", "example.com", "Test")
	nm.Flush(context.Background())
	nm.EndCycle()

	if mock.MessagesSent != 2 {
		t.Fatalf("Expected 2 messages after 25h expiry, got %d", mock.MessagesSent)
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


