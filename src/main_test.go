package main

import (
	"context"
	jsonv2 "encoding/json/v2"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFastDomainWorkerPanicPreservesCompletedEmail(t *testing.T) {
	app := NewAppState(AppConfig{Resolvers: []string{"1.1.1.1"}})
	app.DNSClient = &MockDNSResolver{MockExchangeContext: func(_ context.Context, q *dns.Msg, _ string) (*dns.Msg, time.Duration, error) {
		if q.Question[0].Qtype == dns.TypeCAA {
			panic("CAA transport panic")
		}
		response := new(dns.Msg)
		response.SetReply(q)
		var record string
		switch {
		case q.Question[0].Qtype == dns.TypeMX:
			record = "example.com. IN MX 10 mail.example.com."
		case q.Question[0].Qtype == dns.TypeTXT && q.Question[0].Name == "example.com.":
			record = "example.com. IN TXT \"v=spf1 -all\""
		case q.Question[0].Qtype == dns.TypeTXT && q.Question[0].Name == "_dmarc.example.com.":
			record = "_dmarc.example.com. IN TXT \"v=DMARC1; p=reject\""
		}
		if record != "" {
			rr, err := dns.NewRR(record)
			require.NoError(t, err)
			response.Answer = []dns.RR{rr}
		}
		return response, 0, nil
	}}
	target := DomainConfig{Domain: "example.com", CheckEmailSecurity: true}
	results := executeFastDomainChecks(context.Background(), app, []DomainConfig{target})
	require.Len(t, results, 1)
	assert.Equal(t, StatusOK, results[0].Email.Status)
}

func TestRunMonitoringCycle(t *testing.T) {
	app := NewAppState(AppConfig{DNSRecords: []DNSTask{{
		Hostname: "example.com", Name: "example A", Type: RecordTypeA,
		Expected: []string{"192.0.2.10"},
	}}})
	app.DNSClient = &MockDNSResolver{MockExchangeContext: func(_ context.Context, q *dns.Msg, _ string) (*dns.Msg, time.Duration, error) {
		response := new(dns.Msg)
		response.SetReply(q)
		record, err := dns.NewRR("example.com. IN A 192.0.2.10")
		require.NoError(t, err)
		response.Answer = []dns.RR{record}
		return response, 0, nil
	}}
	app.LoopDuration = 10 * time.Millisecond
	state := runMonitoringCycle(
		context.Background(),
		app,
		nil,
		nil,
		nil,
		nil,
		make(map[string]StateCondition),
	)

	require.NotNil(t, state)
	assert.Equal(t, StatusOK, state.DNS["example A"].Status)
	encoded, ok := app.PrerenderedJSON.Load().([]byte)
	require.True(t, ok)
	var published struct {
		DNSChecks map[string]DNSState `json:"dns_checks"`
	}
	require.NoError(t, jsonv2.Unmarshal(encoded, &published))
	assert.Equal(t, StatusOK, published.DNSChecks["example A"].Status)
}

func TestMonitoringCycleDoesNotReportWrongClassDNSMatch(t *testing.T) {
	app := NewAppState(AppConfig{DNSRecords: []DNSTask{{
		Hostname: "example.com", Name: "example A", Type: RecordTypeA,
		Expected: []string{"192.0.2.10"},
	}}})
	app.DNSClient = &MockDNSResolver{MockExchangeContext: func(_ context.Context, query *dns.Msg, _ string) (*dns.Msg, time.Duration, error) {
		response := new(dns.Msg)
		response.SetReply(query)
		wrongClass, err := dns.NewRR("example.com. 60 CH A 192.0.2.10")
		require.NoError(t, err)
		internetClass, err := dns.NewRR("example.com. 60 IN A 192.0.2.11")
		require.NoError(t, err)
		response.Answer = []dns.RR{wrongClass, internetClass}
		return response, 0, nil
	}}
	state := runMonitoringCycle(context.Background(), app, nil, nil, nil, nil, nil)
	require.NotNil(t, state)
	assert.Equal(t, StatusMismatch, state.DNS["example A"].Status)
	assert.Equal(t, []string{"192.0.2.11"}, state.DNS["example A"].Found)
	encoded, ok := app.PrerenderedJSON.Load().([]byte)
	require.True(t, ok)
	var published struct {
		DNSChecks map[string]DNSState `json:"dns_checks"`
	}
	require.NoError(t, jsonv2.Unmarshal(encoded, &published))
	assert.Equal(t, StatusMismatch, published.DNSChecks["example A"].Status)
}

func TestSetupHTTPServerHandlers(t *testing.T) {
	app := NewAppState(AppConfig{})
	server, _ := setupHTTPServer(app, "0")
	t.Cleanup(func() { require.NoError(t, server.Close()) })

	for _, tc := range []struct {
		path string
		code int
		body string
	}{
		{path: RouteHealth, code: http.StatusOK, body: JSONResponseStatusOK},
		{path: RouteAPIState, code: http.StatusOK, body: JSONResponseStatusInit},
		{path: "/missing", code: http.StatusNotFound, body: "404 page not found"},
	} {
		t.Run(tc.path, func(t *testing.T) {
			response := httptest.NewRecorder()
			server.Handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, strings.TrimPrefix(tc.path, "GET "), nil))
			assert.Equal(t, tc.code, response.Code)
			assert.Contains(t, response.Body.String(), tc.body)
		})
	}
}

func TestRunLifecycleWithCancellation(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	tcpAddr, ok := listener.Addr().(*net.TCPAddr)
	require.True(t, ok)
	port := strconv.Itoa(tcpAddr.Port)
	require.NoError(t, listener.Close())

	configPath := filepath.Join(t.TempDir(), "config.json")
	configJSON := `{"notifications":{"ntfy":{"url":"https://ntfy.invalid/topic"}},"port":"` + port + `","domains":[],"dns_records":[]}`
	require.NoError(t, os.WriteFile(configPath, []byte(configJSON), 0600))

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	require.NoError(t, run(ctx, configPath))
}

func TestRunStartupErrors(t *testing.T) {
	base := t.TempDir()
	configPath := filepath.Join(base, "config.json")
	assert.ErrorContains(t, run(context.Background(), configPath), "load configuration")

}

func TestProcessConditionsAndAlerts_WarningIdentityAndRecovery(t *testing.T) {
	notifier := newRecordingNotifier()
	app := &AppState{Notifier: notifier}
	prev := make(map[string]StateCondition)
	domains := []DomainConfig{{Domain: "example.com", Name: "Example"}}
	state := NewCheckState()
	state.RDAP["example.com"] = RDAPState{Status: StatusWarning, Condition: &StateCondition{Code: CodeRDAPExpiringSoon, Target: "27 days"}}
	processConditionsAndAlerts(app, state, domains, nil, prev)
	require.Len(t, notifier.alerts, 1)
	assert.Equal(t, PriorityWarning, notifier.alerts[0].Priority)
	firstIdentity := notifier.alerts[0].Identity
	firstSince := state.RDAP["example.com"].Condition.Since
	require.False(t, firstSince.IsZero())

	state.RDAP["example.com"] = RDAPState{Status: StatusWarning, Condition: &StateCondition{Code: CodeRDAPExpiringSoon, Target: "26 days"}}
	processConditionsAndAlerts(app, state, domains, nil, prev)
	assert.Len(t, notifier.alerts, 1)
	assert.Equal(t, firstSince, state.RDAP["example.com"].Condition.Since)

	state.RDAP["example.com"] = RDAPState{Status: StatusOK, Condition: &StateCondition{Code: CodeRDAPSuccess}}
	processConditionsAndAlerts(app, state, domains, nil, prev)
	state.RDAP["example.com"] = RDAPState{Status: StatusWarning, Condition: &StateCondition{Code: CodeRDAPExpiringSoon, Target: "25 days"}}
	processConditionsAndAlerts(app, state, domains, nil, prev)
	require.Len(t, notifier.alerts, 2)
	assert.Equal(t, firstIdentity, notifier.alerts[1].Identity)
	assert.NotEqual(t, firstSince, state.RDAP["example.com"].Condition.Since)
}

func TestProcessConditionsAndAlerts_EscalationBypassesWarningCooldown(t *testing.T) {
	notifier := newRecordingNotifier()
	app := &AppState{Notifier: notifier}
	prev := make(map[string]StateCondition)
	domains := []DomainConfig{{Domain: "example.com", Name: "Example"}}
	state := NewCheckState()
	state.RDAP["example.com"] = RDAPState{Status: StatusWarning, Condition: &StateCondition{Code: CodeRDAPExpiringSoon}}
	processConditionsAndAlerts(app, state, domains, nil, prev)
	require.Len(t, notifier.alerts, 1)
	assert.Equal(t, PriorityWarning, notifier.alerts[0].Priority)

	state.RDAP["example.com"] = RDAPState{Status: StatusFailed, Condition: &StateCondition{Code: CodeRDAPExpiringSoon}}
	processConditionsAndAlerts(app, state, domains, nil, prev)
	require.Len(t, notifier.alerts, 2)
	assert.Equal(t, PriorityHigh, notifier.alerts[1].Priority)
	assert.NotEqual(t, notifier.alerts[0].Identity, notifier.alerts[1].Identity)
}

func TestProcessConditionsAndAlerts_AllChecksAndSuppression(t *testing.T) {
	for _, tc := range []struct {
		name       string
		suppress   bool
		wantAlerts int
	}{
		{name: "all failed checks alert", wantAlerts: 4},
		{name: "suppressed domain remains checked", suppress: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			notifier := newRecordingNotifier()
			app := &AppState{Notifier: notifier}
			domain := "example.com"
			state := NewCheckState()
			state.RDAP[domain] = RDAPState{Status: StatusFailed, Condition: &StateCondition{Code: CodeRDAPHTTPError}}
			state.Email[domain] = EmailState{Status: StatusHijacked, Condition: &StateCondition{Code: CodeEmailMissingMX}}
			state.DNSSEC[domain] = DNSSECResult{Status: StatusFailed, Condition: &StateCondition{Code: CodeDNSSECNetworkError}}
			state.NSHealth[domain] = NSHealthResult{Status: StatusWarning, Condition: &StateCondition{Code: CodeNSUnreachable}}
			prev := make(map[string]StateCondition)
			processConditionsAndAlerts(app, state, []DomainConfig{{Domain: domain, Name: "Example", SuppressAlerts: tc.suppress}}, nil, prev)
			assert.Len(t, notifier.alerts, tc.wantAlerts)
			assert.Len(t, prev, 4)
			if !tc.suppress {
				assert.Equal(t, PriorityWarning, notifier.alerts[3].Priority)
			}
		})
	}
}
