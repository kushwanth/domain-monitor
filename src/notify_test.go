package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
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
				TestMode:   true,
				TestBuffer: make([]Alert, 0),
			}

			for _, a := range tt.alerts {
				nm.Dispatch(a.Message, a.Redacted, a.Priority, a.Tag, a.Domain, a.Name)
			}

			nm.mu.Lock()
			if len(nm.TestBuffer) != tt.expectSent {
				t.Errorf("expected %d alerts in buffer, got %d", tt.expectSent, len(nm.TestBuffer))
			}
			nm.mu.Unlock()
		})
	}
}

func TestNotificationDeduplication(t *testing.T) {
	t.Parallel()

	nm := &NotificationManager{
		TestMode:   true,
		TestBuffer: make([]Alert, 0),
	}

	// First occurrence of alert
	nm.Dispatch("Critical Alert 1", "Redacted 1", PriorityUrgent, "skull", "example.com", "Test")

	// Same alert should be deduplicated / suppressed while active
	nm.Dispatch("Critical Alert 1", "Redacted 1", PriorityUrgent, "skull", "example.com", "Test")
	nm.Dispatch("Critical Alert 1", "Redacted 1", PriorityUrgent, "skull", "example.com", "Test")

	// Different alert should pass through
	nm.Dispatch("Critical Alert 2", "Redacted 2", PriorityUrgent, "skull", "example.com", "Test")

	nm.mu.Lock()
	if len(nm.TestBuffer) != 2 {
		t.Fatalf("Expected 2 message in buffer (deduplicated), got %d", len(nm.TestBuffer))
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
		t.Run(string(p), func(t *testing.T) {
			t.Parallel()

			nm := &NotificationManager{
				TestMode:   true,
				TestBuffer: make([]Alert, 0),
			}

			nm.Dispatch("test message", "redacted", p, "tag", "example.com", "Test")

			nm.mu.Lock()
			if len(nm.TestBuffer) != 1 {
				t.Errorf("priority %s: expected 1 alert sent, got %d", p, len(nm.TestBuffer))
			}
			nm.mu.Unlock()
		})
	}
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

	nm := &NotificationManager{
		NtfyURL: ntfyServer.URL,
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

	nm.sendNtfy(alert)

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
		Body:       io.NopCloser(strings.NewReader("ok")),
		Header:     make(http.Header),
	}, nil
}

func TestWorkerLoop_ExponentialBackoff(t *testing.T) {
	// Mock notifyHTTPClient
	originalClient := notifyHTTPClient
	defer func() { notifyHTTPClient = originalClient }()

	transport := &mockTransport{failTimes: 2}
	notifyHTTPClient = &http.Client{Transport: transport}

	nm := &NotificationManager{
		NtfyURL:        "http://dummy-ntfy",
		TelegramToken:  "testtoken",
		TelegramChatID: "12345",
	}

	// Because backoff takes 1s + 2s = 3 seconds, we don't want to run this in full if we can avoid it.
	// But it's hardcoded, so we just run it and wait. We test them sequentially.

	start := time.Now()
	nm.sendNtfyWithRetry(Alert{Message: "Test"})
	if time.Since(start) < 2*time.Second {
		t.Errorf("expected backoff to take time")
	}

	transport.mu.Lock()
	if transport.attempts != 3 {
		t.Errorf("expected 3 ntfy attempts, got %d", transport.attempts)
	}
	transport.mu.Unlock()

	transport.mu.Lock()
	transport.attempts = 0
	transport.failTimes = 2
	transport.mu.Unlock()

	nm.sendTelegramWithRetry(Alert{Message: "Test"})
	transport.mu.Lock()
	if transport.attempts != 3 {
		t.Errorf("expected 3 telegram attempts, got %d", transport.attempts)
	}
	transport.mu.Unlock()
}

func TestNotification_ChannelProcessing(t *testing.T) {
	originalClient := notifyHTTPClient
	defer func() { notifyHTTPClient = originalClient }()

	transport := &mockTransport{failTimes: 0}
	notifyHTTPClient = &http.Client{Transport: transport}

	nm := &NotificationManager{
		alertChan:      make(chan Alert, 10),
		NtfyURL:        "http://dummy-ntfy",
		TelegramToken:  "testtoken",
		TelegramChatID: "12345",
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		nm.workerLoop()
	}()

	nm.Dispatch("msg1", "", PriorityHigh, "tag1", "domain1.com", "name1")

	close(nm.alertChan)
	wg.Wait()

	transport.mu.Lock()
	// Should process 1 Ntfy and 1 Telegram = 2 requests
	if transport.attempts != 2 {
		t.Errorf("expected 2 requests processed by worker loop, got %d", transport.attempts)
	}
	transport.mu.Unlock()
}
