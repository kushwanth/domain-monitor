package monitor

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
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

func TestNotificationManagerSkipsWhenNoProviderConfigured(t *testing.T) {
	nm := NewNotificationManager("", "")
	nm.Dispatch("alert", "redacted", PriorityHigh, "", "example.com", "Example")
	batch, _ := nm.takeAlertBatch()
	require.Empty(t, batch)
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

func TestNotificationRedaction_NtfyRedactsDomain(t *testing.T) {
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
		NtfyURL:    "http://dummy-ntfy",
		HTTPClient: &http.Client{Transport: transport},
	}

	nm.Dispatch("msg1", "", PriorityHigh, "tag1", "domain1.com", "name1")
	nm.Flush()

	transport.mu.Lock()
	if transport.attempts != 1 {
		t.Errorf("expected 1 request processed by flush, got %d", transport.attempts)
	}
	transport.mu.Unlock()
}

func TestNotification_PayloadBoundsAndTruncation(t *testing.T) {
	message := strings.Repeat("☃", MaxProviderMessageBytes)
	shortened := truncateAlertBytes(message, MaxProviderMessageBytes)
	if len(shortened) > MaxProviderMessageBytes || !utf8.ValidString(shortened) || !strings.HasSuffix(shortened, AlertTruncationNotice) {
		t.Fatalf("truncated message is not valid and disclosed: bytes=%d", len(shortened))
	}
}

func TestNotificationProviderFailures(t *testing.T) {
	// Serial because the captured logger is shared by the process.
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	defer slog.SetDefault(previous)
	for _, failure := range []string{"missing client", "invalid URL", "transport", "status"} {
		t.Run("ntfy/"+failure, func(t *testing.T) {
			logs.Reset()
			nm := NewNotificationManager("https://ntfy.invalid/topic", "secret-auth")
			calls := 0
			nm.HTTPClient = &MockHTTPClient{MockDo: func(req *http.Request) (*http.Response, error) {
				calls++
				if req.Method != http.MethodPost || req.Header.Get(HeaderUserAgent) != DefaultUserAgent {
					t.Error("missing provider request method or user agent")
				}
				if req.Header.Get(HeaderAuthorization) != nm.NtfyAuth {
					t.Error("missing authentication")
				}
				if failure == "transport" {
					return nil, errors.New("transport failed: secret-auth")
				}
				status := http.StatusOK
				if failure == "status" {
					status = http.StatusServiceUnavailable
				}
				return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(""))}, nil
			}}
			if failure == "missing client" {
				nm.HTTPClient = nil
			}
			if failure == "invalid URL" {
				nm.NtfyURL = "://invalid"
			}
			alert := Alert{Message: "test", Priority: PriorityHigh}
			delivered := nm.sendNtfyBatchContext(context.Background(), alert)
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
			if strings.Contains(logs.String(), nm.NtfyAuth) {
				t.Fatal("provider credential leaked to logs")
			}
		})
	}
}

func TestNotificationFormattingAndPayloadLimits(t *testing.T) {
	text := formatNtfyMessage(Alert{Message: strings.Repeat("x", MaxAlertMessageRunes+100)})
	if len(text) > MaxAlertMessageRunes || !strings.HasSuffix(text, AlertTruncationNotice) {
		t.Fatal("long ntfy message must be bounded with a truncation notice")
	}
}

func TestNotificationSortsEqualPriorityByCheckAndDomain(t *testing.T) {
	alerts := []Alert{
		{Priority: PriorityHigh, Check: "z", Domain: "z.example", Name: "z"},
		{Priority: PriorityHigh, Check: "a", Domain: "z.example", Name: "z"},
		{Priority: PriorityHigh, Check: "a", Domain: "a.example", Name: "z"},
		{Priority: PriorityHigh, Check: "a", Domain: "a.example", Name: "a"},
	}
	sortAlerts(alerts)
	require.Equal(t, []string{"a", "z", "z", "z"}, []string{alerts[0].Name, alerts[1].Name, alerts[2].Name, alerts[3].Name})
	require.Equal(t, []string{"a.example", "a.example", "z.example", "z.example"}, []string{alerts[0].Domain, alerts[1].Domain, alerts[2].Domain, alerts[3].Domain})
}

func TestNotificationFlushPriorityAndIndependentAttempts(t *testing.T) {
	for range 2 {
		nm := NewNotificationManager("https://ntfy.invalid/topic", "")
		var previous context.Context
		var attempts []string
		nm.HTTPClient = &MockHTTPClient{MockDo: func(req *http.Request) (*http.Response, error) {
			if req.Context().Err() != nil {
				t.Error("previous failure canceled a subsequent attempt")
			}
			previous = req.Context()
			body, err := io.ReadAll(req.Body)
			if err != nil {
				return nil, err
			}
			attempts = append(attempts, string(body))
			return nil, context.DeadlineExceeded
		}}
		for _, alert := range []Alert{{Message: "warning", Priority: PriorityWarning}, {Message: "critical", Priority: PriorityHigh}, {Message: "urgent", Priority: PriorityUrgent}, {Message: "critical second", Priority: PriorityHigh}} {
			nm.Dispatch(alert.Message, "", alert.Priority, "", "", "")
		}
		nm.FlushContext(context.Background())
		want := make([]string, MaxNetworkAttempts)
		for index := range MaxNetworkAttempts {
			want[index] = "urgent\ncritical\ncritical second\nwarning"
		}
		if len(attempts) != len(want) {
			t.Errorf("delivery attempts = %d, want %d", len(attempts), len(want))
		}
		if previous == nil || previous.Err() == nil {
			t.Error("last attempt context was not released")
		}
		if batch, _ := nm.takeAlertBatch(); len(batch) != 0 {
			t.Error("completed attempts retained in queue")
		}
	}
}

func TestCycleReportIsBoundedAndKeepsHighestSeverity(t *testing.T) {
	nm := NewNotificationManager("https://ntfy.invalid/topic", "")
	for index := 0; index < MaxCycleReportItems+10; index++ {
		nm.Dispatch(fmt.Sprintf("warning-%03d", index), "", PriorityWarning, "", "", "")
	}
	nm.Dispatch("urgent-last", "", PriorityUrgent, "", "", "")
	batch, omitted := nm.takeAlertBatch()
	require.Len(t, batch, MaxCycleReportItems)
	require.Equal(t, 11, omitted)
	require.Equal(t, "urgent-last", batch[0].Message)
	report := buildCycleReport(batch, omitted)
	require.Contains(t, report.Message, "11 additional findings omitted")
	require.NotEmpty(t, report.ReportID)
}
