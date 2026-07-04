package main

import (
	"testing"
)

// MockNotifier implements the Notifier interface for testing
type MockNotifier struct {
	MessagesSent int
}

func (m *MockNotifier) Send(alerts []Alert) {
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
				{Message: "Test Alert", Priority: "urgent", Domain: "example.com"},
			},
			expectSent: 1,
		},
		{
			name: "Multiple Alerts",
			alerts: []Alert{
				{Message: "Test Alert 1", Priority: "high", Domain: "example.com"},
				{Message: "Test Alert 2", Priority: "urgent", Domain: "example.com"},
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
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			mock1 := &MockNotifier{}
			mock2 := &MockNotifier{}

			nm := &NotificationManager{
				Providers: []Notifier{mock1, mock2},
			}

			for _, a := range tt.alerts {
				nm.Dispatch(a.Message, a.Redacted, a.Priority, a.Tag, a.Domain, a.Name)
			}
			nm.Flush()

			if mock1.MessagesSent != tt.expectSent {
				t.Errorf("Mock1: expected %d, got %d", tt.expectSent, mock1.MessagesSent)
			}
			if mock2.MessagesSent != tt.expectSent {
				t.Errorf("Mock2: expected %d, got %d", tt.expectSent, mock2.MessagesSent)
			}
		})
	}
}
