package main

import (
	"context"
	jsonv2 "encoding/json/v2"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCTQuotaKeepsDeferredProgress(t *testing.T) {
	requests := 0
	var queried []string
	app := &AppState{HTTPClient: &MockHTTPClient{MockDo: func(req *http.Request) (*http.Response, error) {
		requests++
		queried = append(queried, req.URL.String())
		return &http.Response{StatusCode: http.StatusTooManyRequests, Body: io.NopCloser(strings.NewReader(""))}, nil
	}}}
	domains := []DomainConfig{
		{Domain: "one.example", IsDelegatedZone: true, MonitorCTLogs: true},
		{Domain: "two.example", IsDelegatedZone: true, MonitorCTLogs: true},
	}
	previous := map[string]CTLogState{
		"one.example": {SeenIDs: []string{"one"}, Pending: []CTPending{{Cert: CTCert{ID: "one"}, NeedNtfy: true}}},
		"two.example": {BackfillCursor: "cursor", SeenIDs: []string{"two"}, Pending: []CTPending{{Cert: CTCert{ID: "two"}, NeedTelegram: true}}},
	}
	_, got := executeRateLimitedChecks(context.Background(), app, domains, nil, previous)
	require.Equal(t, 1, requests)
	for i, domain := range domains {
		assert.Equal(t, CodeCTLogsRateLimited, got[i].Condition.Code)
		assert.Equal(t, previous[domain.Domain].SeenIDs, got[i].SeenIDs)
		assert.Equal(t, previous[domain.Domain].Pending, got[i].Pending)
		assert.Equal(t, previous[domain.Domain].BackfillCursor, got[i].BackfillCursor)
	}
	for i, domain := range domains {
		previous[domain.Domain] = got[i]
	}
	_, _ = executeRateLimitedChecks(context.Background(), app, domains, nil, previous)
	require.Equal(t, 2, requests)
	assert.Contains(t, queried[1], "two.example")
}

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
	target := DomainConfig{Domain: "example.com", CheckEmailSecurity: true, CAA: &CAAConfig{}}
	results := executeFastDomainChecks(context.Background(), app, []DomainConfig{target})
	require.Len(t, results, 1)
	assert.Equal(t, StatusOK, results[0].Email.Status)
	assert.Equal(t, StatusFailed, results[0].CAA.Status)
	assert.Contains(t, results[0].CAA.Error, "CAA transport panic")
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
	ctLogPersist := make(map[string]CTLogState)

	// Use a temporary file for ct state path
	tmpFile, err := os.CreateTemp("", "ctstate_*.json")
	require.NoError(t, err)
	defer func() { _ = os.Remove(tmpFile.Name()) }()

	state := runMonitoringCycle(
		context.Background(),
		app,
		nil,
		tmpFile.Name(),
		ctLogPersist,
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
	state := runMonitoringCycle(context.Background(), app, nil, filepath.Join(t.TempDir(), "ct_state.json"), nil, nil, nil, nil, nil)
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

	dataDir := t.TempDir()
	configPath := filepath.Join(t.TempDir(), "config.json")
	configJSON := `{"notifications":{"ntfy":{"url":"https://ntfy.invalid/topic"}},"port":"` + port + `","data_dir":"` + dataDir + `","domains":[],"dns_records":[]}`
	require.NoError(t, os.WriteFile(configPath, []byte(configJSON), 0600))

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	require.NoError(t, run(ctx, configPath))
	_, err = os.Stat(filepath.Join(dataDir, DefaultCTStateFileName))
	require.NoError(t, err)
}

func TestRunStartupErrors(t *testing.T) {
	base := t.TempDir()
	configPath := filepath.Join(base, "config.json")
	assert.ErrorContains(t, run(context.Background(), configPath), "load configuration")

	blockedDir := filepath.Join(base, "not-a-directory")
	require.NoError(t, os.WriteFile(blockedDir, []byte("occupied"), 0600))
	configJSON := `{"notifications":{"ntfy":{"url":"https://ntfy.invalid/topic"}},"port":"9999","data_dir":"` + blockedDir + `","domains":[],"dns_records":[]}`
	require.NoError(t, os.WriteFile(configPath, []byte(configJSON), 0600))
	assert.ErrorContains(t, run(context.Background(), configPath), "create data directory")

	dataDir := filepath.Join(base, "data")
	require.NoError(t, os.MkdirAll(dataDir, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(dataDir, DefaultCTStateFileName), []byte("{"), 0600))
	configJSON = `{"notifications":{"ntfy":{"url":"https://ntfy.invalid/topic"}},"port":"9999","data_dir":"` + dataDir + `","domains":[],"dns_records":[]}`
	require.NoError(t, os.WriteFile(configPath, []byte(configJSON), 0600))
	assert.ErrorContains(t, run(context.Background(), configPath), "load CT state")
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
		{name: "all failed checks alert", wantAlerts: 7},
		{name: "suppressed domain remains checked", suppress: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			notifier := newRecordingNotifier()
			app := &AppState{Notifier: notifier}
			domain := "example.com"
			state := NewCheckState()
			state.RDAP[domain] = RDAPState{Status: StatusFailed, Condition: &StateCondition{Code: CodeRDAPHTTPError}}
			state.Email[domain] = EmailState{Status: StatusHijacked, Condition: &StateCondition{Code: CodeEmailMissingMX}}
			state.CAA[domain] = CAAResult{Status: StatusFailed, Condition: &StateCondition{Code: CodeCAAQueryFailed}}
			state.DNSSEC[domain] = DNSSECResult{Status: StatusFailed, Condition: &StateCondition{Code: CodeDNSSECNetworkError}}
			state.NSHealth[domain] = NSHealthResult{Status: StatusWarning, Condition: &StateCondition{Code: CodeNSUnreachable}}
			state.CTLogs[domain] = CTLogState{Status: StatusFailed, Condition: &StateCondition{Code: CodeCTLogsHTTPError}, Pending: []CTPending{{Cert: CTCert{ID: "cert-1"}, NeedNtfy: true}}}
			prev := make(map[string]StateCondition)
			processConditionsAndAlerts(app, state, []DomainConfig{{Domain: domain, Name: "Example", MonitorCTLogs: true, SuppressAlerts: tc.suppress}}, nil, prev)
			assert.Len(t, notifier.alerts, tc.wantAlerts)
			assert.Len(t, prev, 6)
			if !tc.suppress {
				assert.Equal(t, PriorityWarning, notifier.alerts[4].Priority)
				assert.True(t, notifier.alerts[6].CT)
				assert.Equal(t, "CT:example.com:cert-1", notifier.alerts[6].Identity)
			}
		})
	}
}

func TestMarkCTCommitFailed_RestoresCommittedProgress(t *testing.T) {
	state := NewCheckState()
	state.CTLogs["example.com"] = CTLogState{LatestID: "new", BackfillCursor: "next", NewCerts: []CTCert{{ID: "new"}}, Status: StatusOK}
	committed := map[string]CTLogState{"example.com": {LatestID: "old", BackfillCursor: "prior"}}
	markCTCommitFailed(state, committed, errors.New(MsgErrDiskUnavailable))
	assert.Equal(t, "old", state.CTLogs["example.com"].LatestID)
	assert.Equal(t, "prior", state.CTLogs["example.com"].BackfillCursor)
	assert.Empty(t, state.CTLogs["example.com"].NewCerts)
	assert.Equal(t, StatusFailed, state.CTLogs["example.com"].Status)
	assert.Equal(t, CodeCTPersistenceFailed, state.CTLogs["example.com"].Condition.Code)
	assert.Equal(t, "old", committed["example.com"].LatestID)
}

func TestServeCTLogFile_AuthorizationAndReadErrors(t *testing.T) {
	app := &AppState{config: AppConfig{Domains: []DomainConfig{{Domain: "example.com", MonitorCTLogs: true}}}, CTLogsPath: t.TempDir()}
	for _, tc := range []struct {
		name, domain string
		read         func(string) ([]byte, error)
		want         int
	}{
		{name: "unconfigured", domain: "other.com", want: http.StatusNotFound},
		{name: "read failure", domain: "example.com", read: func(string) ([]byte, error) { return nil, errors.New(MsgErrDiskFailed) }, want: http.StatusInternalServerError},
		{name: "corrupt", domain: "example.com", read: func(string) ([]byte, error) { return []byte("{bad"), nil }, want: http.StatusInternalServerError},
		{name: "valid", domain: "example.com", read: func(string) ([]byte, error) { return []byte(`[{"id":"cert"}]`), nil }, want: http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app.ReadCTHistory = tc.read
			recorder := httptest.NewRecorder()
			serveCTLogFile(app, recorder, tc.domain)
			assert.Equal(t, tc.want, recorder.Code)
			assert.Equal(t, "no-store", recorder.Header().Get(HeaderCacheControl))
		})
	}
}

type assuranceNotifier struct {
	alerts   []Alert
	queuedCT []Alert
	accepted map[string]CTAcceptance
	flushes  int
}

func (n *assuranceNotifier) Dispatch(message, redacted string, priority AlertPriority, tag AlertTag, domain, name string) {
	n.alerts = append(n.alerts, Alert{Message: message, Redacted: redacted, Priority: priority, Tag: tag, Domain: domain, Name: name})
}

func (n *assuranceNotifier) DispatchIdentified(identity, message, redacted string, priority AlertPriority, tag AlertTag, domain, name string) {
	n.alerts = append(n.alerts, Alert{Identity: identity, Message: message, Redacted: redacted, Priority: priority, Tag: tag, Domain: domain, Name: name})
}

func (n *assuranceNotifier) DispatchCT(alert Alert) {
	n.alerts = append(n.alerts, alert)
	n.queuedCT = append(n.queuedCT, alert)
}

func (n *assuranceNotifier) Flush() {
	n.flushes++
	if n.accepted == nil {
		n.accepted = make(map[string]CTAcceptance)
	}
	for _, alert := range n.queuedCT {
		n.accepted[alert.Identity] = CTAcceptance{Ntfy: true}
	}
	n.queuedCT = nil
}

func (n *assuranceNotifier) TakeCTAcceptances() map[string]CTAcceptance {
	accepted := n.accepted
	n.accepted = nil
	return accepted
}

func TestDaemonSixCyclesRestartWriteFailureAndRateLimit(t *testing.T) {
	const domain = "example.com"
	config := AppConfig{
		Resolvers:     []string{"192.0.2.53:53"},
		Domains:       []DomainConfig{{Domain: domain, Name: "Example", IsDelegatedZone: true, MonitorCTLogs: true, ExpectedNS: []string{"ns1.example.com"}}},
		DNSRecords:    []DNSTask{{Hostname: domain, Name: "example A", Type: RecordTypeA, Expected: []string{"192.0.2.10"}}},
		Notifications: Notifications{Ntfy: &NtfyConfig{URL: "https://ntfy.invalid/test"}},
	}
	goodA, err := dns.NewRR("example.com. 60 IN A 192.0.2.10")
	require.NoError(t, err)
	badA, err := dns.NewRR("example.com. 60 IN A 192.0.2.11")
	require.NoError(t, err)
	ns, err := dns.NewRR("example.com. 60 IN NS ns1.example.com.")
	require.NoError(t, err)

	cycle := 1
	historyPath := t.TempDir()
	newApp := func(notifier *assuranceNotifier) *AppState {
		app := NewAppState(config)
		app.Notifier = notifier
		app.CTLimiter = nil
		app.CTLogsPath = historyPath
		app.LoopDuration = time.Millisecond
		app.DNSClient = &MockDNSResolver{MockExchangeContext: func(_ context.Context, query *dns.Msg, _ string) (*dns.Msg, time.Duration, error) {
			response := new(dns.Msg)
			response.SetReply(query)
			switch query.Question[0].Qtype {
			case dns.TypeA:
				if cycle == 3 {
					response.Answer = []dns.RR{badA}
				} else {
					response.Answer = []dns.RR{goodA}
				}
			case dns.TypeNS:
				response.Answer = []dns.RR{ns}
			}
			return response, 0, nil
		}}
		app.HTTPClient = &MockHTTPClient{MockDo: func(*http.Request) (*http.Response, error) {
			if cycle == 5 {
				return &http.Response{StatusCode: http.StatusTooManyRequests, Body: io.NopCloser(strings.NewReader(""))}, nil
			}
			body := `{"rows":[{"id":"old","match":"example.com","issuer":"Old CA"}],"has_next":false}`
			if cycle >= 2 {
				body = `{"rows":[{"id":"new","match":"example.com","issuer":"New CA"},{"id":"old","match":"example.com","issuer":"Old CA"}],"has_next":false}`
			}
			if cycle >= 3 {
				body = `{"rows":[{"id":"newer","match":"example.com","issuer":"Newest CA"},{"id":"new","match":"example.com","issuer":"New CA"},{"id":"old","match":"example.com","issuer":"Old CA"}],"has_next":false}`
			}
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body))}, nil
		}}
		return app
	}

	path := filepath.Join(t.TempDir(), "ct_state.json")
	notifier := &assuranceNotifier{}
	app := newApp(notifier)
	committed := make(map[string]CTLogState)
	previousConditions := make(map[string]StateCondition)
	run := func() *CheckState {
		state := runMonitoringCycle(context.Background(), app, nil, path, committed, nil, nil, nil, previousConditions)
		encoded, ok := app.PrerenderedJSON.Load().([]byte)
		require.True(t, ok)
		var published CheckState
		require.NoError(t, jsonv2.Unmarshal(encoded, &published))
		assert.Equal(t, state.DNS["example A"].Status, published.DNS["example A"].Status)
		assert.Equal(t, state.CTLogs[domain].Status, published.CTLogs[domain].Status)
		if state.DNS["example A"].Condition != nil {
			require.NotNil(t, published.DNS["example A"].Condition)
			assert.Equal(t, state.DNS["example A"].Condition.Code, published.DNS["example A"].Condition.Code)
		}
		if state.CTLogs[domain].Condition != nil {
			require.NotNil(t, published.CTLogs[domain].Condition)
			assert.Equal(t, state.CTLogs[domain].Condition.Code, published.CTLogs[domain].Condition.Code)
		}
		return state
	}
	readCommitted := func() CTLogState {
		onDisk, err := loadCTStateFile(path, os.ReadFile, AtomicWriteFile)
		require.NoError(t, err)
		return onDisk[domain]
	}

	first := run()
	assert.Equal(t, StatusOK, first.DNS["example A"].Status)
	assert.Equal(t, StatusOK, first.CTLogs[domain].Status)
	assert.Equal(t, []string{"old"}, readCommitted().SeenIDs)
	assert.Empty(t, notifier.alerts, "baseline certificates must not alert")

	cycle = 2
	second := run()
	assert.Equal(t, StatusOK, second.CTLogs[domain].Status)
	assert.Equal(t, []string{"old", "new"}, readCommitted().SeenIDs)
	assert.Empty(t, readCommitted().Pending, "accepted CT alert must be acknowledged on disk")
	require.Len(t, notifier.alerts, 1)
	assert.Equal(t, "CT:example.com:new", notifier.alerts[0].Identity)

	cycle = 3
	app.WriteCTState = func(string, []byte, os.FileMode) error { return errors.New(MsgErrDiskFull) }
	third := run()
	assert.Equal(t, StatusMismatch, third.DNS["example A"].Status)
	assert.Equal(t, StatusFailed, third.CTLogs[domain].Status)
	require.NotNil(t, third.CTLogs[domain].Condition)
	assert.Equal(t, CodeCTPersistenceFailed, third.CTLogs[domain].Condition.Code)
	assert.Equal(t, []string{"old", "new"}, readCommitted().SeenIDs)
	assert.Equal(t, []string{"old", "new"}, committed[domain].SeenIDs)
	assert.Len(t, notifier.alerts, 3, "failed CT commit and DNS mismatch must both alert")
	for _, alert := range notifier.alerts {
		assert.NotEqual(t, "CT:example.com:newer", alert.Identity, "uncommitted discovery must not alert")
	}
	assert.Equal(t, 3, notifier.flushes)
	assert.Equal(t, "CTLogs:example.com:ctPersistenceFailed:failed", notifier.alerts[1].Identity)
	assert.Equal(t, "DNS:example A:dnsMismatch:mismatch", notifier.alerts[2].Identity)
	assert.Equal(t, PriorityHigh, notifier.alerts[1].Priority)
	assert.Equal(t, PriorityHigh, notifier.alerts[2].Priority)

	cycle = 4
	restartedNotifier := &assuranceNotifier{}
	app = newApp(restartedNotifier)
	committed, err = loadCTStateFile(path, os.ReadFile, AtomicWriteFile)
	require.NoError(t, err)
	previousConditions = make(map[string]StateCondition)
	fourth := run()
	assert.Equal(t, StatusOK, fourth.DNS["example A"].Status)
	assert.Equal(t, StatusOK, fourth.CTLogs[domain].Status)
	assert.Equal(t, []string{"old", "new", "newer"}, readCommitted().SeenIDs)
	assert.Empty(t, readCommitted().Pending)
	require.Len(t, restartedNotifier.alerts, 1, "restart must alert only for the new certificate")
	assert.Equal(t, "CT:example.com:newer", restartedNotifier.alerts[0].Identity)
	assert.Equal(t, 1, restartedNotifier.flushes)

	cycle = 5
	fifth := run()
	assert.Equal(t, StatusWarning, fifth.CTLogs[domain].Status)
	require.NotNil(t, fifth.CTLogs[domain].Condition)
	assert.Equal(t, CodeCTLogsRateLimited, fifth.CTLogs[domain].Condition.Code)
	assert.Equal(t, []string{"old", "new", "newer"}, readCommitted().SeenIDs)
	require.Len(t, restartedNotifier.alerts, 2)
	assert.Equal(t, PriorityWarning, restartedNotifier.alerts[1].Priority)
	assert.Equal(t, "CTLogs:example.com:ctLogsRateLimited:warning", restartedNotifier.alerts[1].Identity)

	cycle = 6
	sixth := run()
	assert.Equal(t, StatusOK, sixth.CTLogs[domain].Status)
	assert.Equal(t, []string{"old", "new", "newer"}, readCommitted().SeenIDs)
	assert.Len(t, restartedNotifier.alerts, 2, "recovery and duplicate certificate must not create alerts")
	assert.Equal(t, 3, restartedNotifier.flushes)
}

func TestDaemonRetriesCTNotificationAfterDeliveryFailure(t *testing.T) {
	const domain = "example.com"
	config := AppConfig{
		Resolvers:     []string{"192.0.2.53:53"},
		Domains:       []DomainConfig{{Domain: domain, Name: "Example", IsDelegatedZone: true, MonitorCTLogs: true, ExpectedNS: []string{"ns1.example.com"}}},
		Notifications: Notifications{Ntfy: &NtfyConfig{URL: "https://ntfy.invalid/test"}, Telegram: &TelegramConfig{Token: "token", ChatID: "chat"}},
	}
	ns, err := dns.NewRR("example.com. 60 IN NS ns1.example.com.")
	require.NoError(t, err)
	cycle := 1
	attempts := 0
	telegramAttempts := 0
	notifier := NewNotificationManager("https://ntfy.invalid/test", "", "token", "chat")
	notifier.HTTPClient = &MockHTTPClient{MockDo: func(req *http.Request) (*http.Response, error) {
		assert.Equal(t, http.MethodPost, req.Method)
		if req.URL.Host == "api.telegram.org" {
			telegramAttempts++
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"ok":true}`))}, nil
		}
		assert.Equal(t, "ntfy.invalid", req.URL.Host)
		attempts++
		status := http.StatusServiceUnavailable
		if cycle >= 3 {
			status = http.StatusOK
		}
		return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(""))}, nil
	}}
	app := NewAppState(config)
	app.Notifier = notifier
	app.CTLimiter = nil
	app.CTLogsPath = t.TempDir()
	app.DNSClient = &MockDNSResolver{MockExchangeContext: func(_ context.Context, query *dns.Msg, _ string) (*dns.Msg, time.Duration, error) {
		response := new(dns.Msg)
		response.SetReply(query)
		if query.Question[0].Qtype == dns.TypeNS {
			response.Answer = []dns.RR{ns}
		}
		return response, 0, nil
	}}
	app.HTTPClient = &MockHTTPClient{MockDo: func(*http.Request) (*http.Response, error) {
		body := `{"rows":[{"id":"old","match":"example.com","issuer":"Old CA"}],"has_next":false}`
		if cycle >= 2 {
			body = `{"rows":[{"id":"new","match":"example.com","issuer":"New CA"},{"id":"old","match":"example.com","issuer":"Old CA"}],"has_next":false}`
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body))}, nil
	}}
	path := filepath.Join(t.TempDir(), "ct_state.json")
	committed := make(map[string]CTLogState)
	previousConditions := make(map[string]StateCondition)
	run := func() CTLogState {
		state := runMonitoringCycle(context.Background(), app, nil, path, committed, nil, nil, nil, previousConditions)
		assert.Equal(t, StatusOK, state.CTLogs[domain].Status)
		onDisk, err := loadCTStateFile(path, os.ReadFile, AtomicWriteFile)
		require.NoError(t, err)
		assert.ElementsMatch(t, committed[domain].Pending, onDisk[domain].Pending)
		return onDisk[domain]
	}

	first := run()
	assert.Equal(t, []string{"old"}, first.SeenIDs)
	assert.Empty(t, first.Pending)
	assert.Zero(t, attempts)
	assert.Zero(t, telegramAttempts)

	cycle = 2
	second := run()
	assert.Equal(t, []string{"old", "new"}, second.SeenIDs)
	require.Len(t, second.Pending, 1)
	assert.Equal(t, "new", second.Pending[0].Cert.ID)
	assert.True(t, second.Pending[0].NeedNtfy)
	assert.False(t, second.Pending[0].NeedTelegram, "accepted Telegram delivery must be checkpointed")
	assert.Equal(t, 1, attempts)
	assert.Equal(t, 1, telegramAttempts)

	// Recreate the app and notifier from the committed checkpoint. The failed
	// delivery must survive both in-memory queues being discarded.
	dnsClient, ctClient, notificationClient := app.DNSClient, app.HTTPClient, notifier.HTTPClient
	historyPath := app.CTLogsPath
	committed, err = loadCTStateFile(path, os.ReadFile, AtomicWriteFile)
	require.NoError(t, err)
	restartedNotifier := NewNotificationManager("https://ntfy.invalid/test", "", "token", "chat")
	restartedNotifier.HTTPClient = notificationClient
	app = NewAppState(config)
	app.Notifier = restartedNotifier
	app.CTLimiter = nil
	app.CTLogsPath = historyPath
	app.DNSClient = dnsClient
	app.HTTPClient = ctClient
	previousConditions = make(map[string]StateCondition)

	cycle = 3
	third := run()
	assert.Equal(t, []string{"old", "new"}, third.SeenIDs)
	assert.Empty(t, third.Pending, "accepted notification must clear pending state on disk")
	assert.Equal(t, 2, attempts, "only the failed delivery should be retried")
	assert.Equal(t, 1, telegramAttempts, "accepted Telegram delivery must not be retried")

	cycle = 4
	fourth := run()
	assert.Empty(t, fourth.Pending)
	assert.Equal(t, 2, attempts, "acknowledged certificate must not be redelivered")
	assert.Equal(t, 1, telegramAttempts)
}

func TestDaemonRejectsMalformedNullMX(t *testing.T) {
	newRR := func(value string) dns.RR {
		record, err := dns.NewRR(value)
		require.NoError(t, err)
		return record
	}
	ns := newRR("example.com. 60 IN NS ns1.example.com.")
	spf := newRR(`example.com. 60 IN TXT "v=spf1 -all"`)
	dmarc := newRR(`_dmarc.example.com. 60 IN TXT "v=DMARC1; p=reject"`)
	validNullMX := newRR("example.com. 60 IN MX 0 .")
	wrongPreference := newRR("example.com. 60 IN MX 10 .")
	ordinaryMX := newRR("example.com. 60 IN MX 10 mail.example.com.")
	for _, test := range []struct {
		name    string
		mx      []dns.RR
		status  CheckStatus
		code    ResultCode
		invalid bool
	}{
		{name: "valid", mx: []dns.RR{validNullMX}, status: StatusOK, code: CodeEmailVerified},
		{name: "nonzero preference", mx: []dns.RR{wrongPreference}, status: StatusMismatch, code: CodeEmailInvalidNullMX, invalid: true},
		{name: "mixed with ordinary MX", mx: []dns.RR{validNullMX, ordinaryMX}, status: StatusMismatch, code: CodeEmailInvalidNullMX, invalid: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := AppConfig{
				Resolvers: []string{"192.0.2.53:53"},
				Domains: []DomainConfig{{Domain: "example.com", Name: "Example", IsDelegatedZone: true,
					ExpectedNS: []string{"ns1.example.com"}, CheckEmailSecurity: true, MXRecords: []string{"."}}},
			}
			app := NewAppState(config)
			notifier := &assuranceNotifier{}
			app.Notifier = notifier
			app.DNSClient = &MockDNSResolver{MockExchangeContext: func(_ context.Context, query *dns.Msg, _ string) (*dns.Msg, time.Duration, error) {
				response := new(dns.Msg)
				response.SetReply(query)
				switch question := query.Question[0]; question.Qtype {
				case dns.TypeNS:
					response.Answer = []dns.RR{ns}
				case dns.TypeMX:
					response.Answer = test.mx
				case dns.TypeTXT:
					switch question.Name {
					case "_dmarc.example.com.":
						response.Answer = []dns.RR{dmarc}
					case "example.com.":
						response.Answer = []dns.RR{spf}
					}
				}
				return response, 0, nil
			}}
			state := runMonitoringCycle(context.Background(), app, nil, filepath.Join(t.TempDir(), "ct_state.json"), nil, nil, nil, nil, nil)
			require.NotNil(t, state.Email["example.com"].Condition)
			assert.Equal(t, test.status, state.Email["example.com"].Status)
			assert.Equal(t, test.code, state.Email["example.com"].Condition.Code)
			encoded, ok := app.PrerenderedJSON.Load().([]byte)
			require.True(t, ok)
			var published CheckState
			require.NoError(t, jsonv2.Unmarshal(encoded, &published))
			assert.Equal(t, test.status, published.Email["example.com"].Status)
			assert.Equal(t, test.code, published.Email["example.com"].Condition.Code)
			if test.invalid {
				require.Len(t, notifier.alerts, 1)
				assert.Equal(t, "Email:example.com:emailInvalidNullMx:mismatch", notifier.alerts[0].Identity)
				assert.Equal(t, PriorityHigh, notifier.alerts[0].Priority)
			} else {
				assert.Empty(t, notifier.alerts)
			}
		})
	}
}

func TestDaemonPublishesWorkerPanicWithoutLosingCompletedChecks(t *testing.T) {
	config := AppConfig{
		Resolvers: []string{"192.0.2.53:53"},
		Domains: []DomainConfig{{
			Domain: "example.com", Name: "Example", IsDelegatedZone: true,
			ExpectedNS: []string{"ns1.example.com"}, CheckEmailSecurity: true, CAA: &CAAConfig{},
		}},
	}
	records := make(map[string]dns.RR)
	for key, value := range map[string]string{
		"NS:example.com.":         "example.com. 60 IN NS ns1.example.com.",
		"MX:example.com.":         "example.com. 60 IN MX 10 mail.example.com.",
		"TXT:example.com.":        `example.com. 60 IN TXT "v=spf1 -all"`,
		"TXT:_dmarc.example.com.": `_dmarc.example.com. 60 IN TXT "v=DMARC1; p=reject"`,
	} {
		rr, err := dns.NewRR(value)
		require.NoError(t, err)
		records[key] = rr
	}
	app := NewAppState(config)
	notifier := &assuranceNotifier{}
	app.Notifier = notifier
	app.DNSClient = &MockDNSResolver{MockExchangeContext: func(_ context.Context, query *dns.Msg, _ string) (*dns.Msg, time.Duration, error) {
		question := query.Question[0]
		if question.Qtype == dns.TypeCAA {
			panic("CAA resolver panic")
		}
		response := new(dns.Msg)
		response.SetReply(query)
		key := dns.TypeToString[question.Qtype] + ":" + question.Name
		if record := records[key]; record != nil {
			response.Answer = []dns.RR{record}
		}
		return response, 0, nil
	}}
	state := runMonitoringCycle(context.Background(), app, nil, filepath.Join(t.TempDir(), "ct_state.json"), nil, nil, nil, nil, nil)
	require.NotNil(t, state)
	assert.Equal(t, StatusOK, state.Email["example.com"].Status)
	assert.Equal(t, StatusFailed, state.CAA["example.com"].Status)
	assert.Equal(t, CodeCAAQueryFailed, state.CAA["example.com"].Condition.Code)
	assert.Contains(t, state.CAA["example.com"].Error, "CAA resolver panic")
	require.Len(t, notifier.alerts, 1)
	assert.Equal(t, PriorityHigh, notifier.alerts[0].Priority)
	assert.Equal(t, "CAA:example.com:caaQueryFailed:failed", notifier.alerts[0].Identity)
	encoded, ok := app.PrerenderedJSON.Load().([]byte)
	require.True(t, ok)
	var published CheckState
	require.NoError(t, jsonv2.Unmarshal(encoded, &published))
	assert.Equal(t, StatusOK, published.Email["example.com"].Status)
	assert.Equal(t, StatusFailed, published.CAA["example.com"].Status)
	assert.Equal(t, CodeCAAQueryFailed, published.CAA["example.com"].Condition.Code)
}

func TestDaemonCancellationPublishesFailureAndKeepsCTCheckpoint(t *testing.T) {
	const domain = "example.com"
	config := AppConfig{
		Resolvers:  []string{"192.0.2.53:53"},
		Domains:    []DomainConfig{{Domain: domain, Name: "Example", IsDelegatedZone: true, MonitorCTLogs: true, ExpectedNS: []string{"ns1.example.com"}}},
		DNSRecords: []DNSTask{{Hostname: domain, Name: "example A", Type: RecordTypeA, Expected: []string{"192.0.2.10"}}},
	}
	app := NewAppState(config)
	app.CTLimiter = nil
	notifier := &assuranceNotifier{}
	app.Notifier = notifier
	app.DNSClient = &MockDNSResolver{MockExchangeContext: func(ctx context.Context, _ *dns.Msg, _ string) (*dns.Msg, time.Duration, error) {
		return nil, 0, ctx.Err()
	}}
	app.HTTPClient = &MockHTTPClient{MockDo: func(req *http.Request) (*http.Response, error) {
		return nil, req.Context().Err()
	}}
	checkpoint := CTLogState{LatestID: "prior", Initialized: true, BackfillCursor: "page-2", ScanPages: 1, SeenIDs: []string{"prior"}, Status: StatusOK}
	committed := map[string]CTLogState{domain: checkpoint}
	path := filepath.Join(t.TempDir(), "ct_state.json")
	initial, err := encodeCTState(committed)
	require.NoError(t, err)
	require.NoError(t, AtomicWriteFile(path, initial, FilePermSecret))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	state := runMonitoringCycle(ctx, app, nil, path, committed, nil, nil, nil, nil)
	require.NotNil(t, state)
	assert.Equal(t, StatusFailed, state.DNS["example A"].Status)
	assert.Equal(t, StatusFailed, state.CTLogs[domain].Status)
	require.NotNil(t, state.CTLogs[domain].Condition)
	assert.Equal(t, CodeCTLogsHTTPError, state.CTLogs[domain].Condition.Code)
	assert.Equal(t, checkpoint.BackfillCursor, state.CTLogs[domain].BackfillCursor)
	assert.Equal(t, checkpoint.SeenIDs, state.CTLogs[domain].SeenIDs)
	onDisk, err := loadCTStateFile(path, os.ReadFile, AtomicWriteFile)
	require.NoError(t, err)
	assert.Equal(t, checkpoint.BackfillCursor, onDisk[domain].BackfillCursor)
	assert.Equal(t, checkpoint.SeenIDs, onDisk[domain].SeenIDs)
	encoded, ok := app.PrerenderedJSON.Load().([]byte)
	require.True(t, ok)
	var published CheckState
	require.NoError(t, jsonv2.Unmarshal(encoded, &published))
	assert.Equal(t, StatusFailed, published.DNS["example A"].Status)
	assert.Equal(t, StatusFailed, published.CTLogs[domain].Status)
	assert.Equal(t, checkpoint.BackfillCursor, published.CTLogs[domain].BackfillCursor)
	alertByIdentity := make(map[string]Alert, len(notifier.alerts))
	for _, alert := range notifier.alerts {
		alertByIdentity[alert.Identity] = alert
	}
	for _, identity := range []string{
		"DNS:example A:dnsLookupFailed:failed",
		"CTLogs:example.com:ctLogsHttpError:failed",
	} {
		alert, exists := alertByIdentity[identity]
		assert.True(t, exists, "missing cancellation alert %s", identity)
		assert.Equal(t, PriorityHigh, alert.Priority)
	}
}

func TestDaemonPublishesAllProtocolWorkerFailures(t *testing.T) {
	config := AppConfig{
		Resolvers: []string{"192.0.2.53:53"},
		Domains: []DomainConfig{{Domain: "example.com", Name: "Example", IsDelegatedZone: true,
			ExpectedNS: []string{"ns1.example.com"}, VerifyNSHealth: true, DNSSEC: true,
			CAA: &CAAConfig{}, CheckEmailSecurity: true}},
		DNSRecords: []DNSTask{{Hostname: "www.example.com", Name: "web A", Type: RecordTypeA,
			Expected: []string{"192.0.2.10"}}},
	}
	app := NewAppState(config)
	notifier := &assuranceNotifier{}
	app.Notifier = notifier
	address, err := dns.NewRR("www.example.com. 60 IN A 192.0.2.10")
	require.NoError(t, err)
	app.DNSClient = &MockDNSResolver{MockExchangeContext: func(_ context.Context, query *dns.Msg, _ string) (*dns.Msg, time.Duration, error) {
		if query.Question[0].Qtype == dns.TypeA && query.Question[0].Name == "www.example.com." {
			response := new(dns.Msg)
			response.SetReply(query)
			response.Answer = []dns.RR{address}
			return response, 0, nil
		}
		return nil, 0, errors.New(MsgErrResolverUnavailable)
	}}
	app.TLSCheck = func(_ context.Context, host string, ips []string, _ bool) (int, error) {
		assert.Equal(t, "www.example.com", host)
		assert.Equal(t, []string{"192.0.2.10"}, ips)
		return SSLDaysError, errors.New(MsgErrUntrustedChain)
	}
	state := runMonitoringCycle(context.Background(), app, nil, filepath.Join(t.TempDir(), "ct_state.json"), nil, nil, nil, nil, nil)
	require.NotNil(t, state)
	checks := map[string]CheckStatus{
		"DNS": state.DNS["web A"].Status, "RDAP": state.RDAP["example.com"].Status,
		"Email": state.Email["example.com"].Status, "DNSSEC": state.DNSSEC["example.com"].Status,
		"CAA": state.CAA["example.com"].Status, "NSHealth": state.NSHealth["example.com"].Status,
	}
	for name, status := range checks {
		assert.Equal(t, StatusFailed, status, "%s must not publish healthy after its dependency fails", name)
	}
	assert.Equal(t, CodeSSLValidationFailed, state.DNS["web A"].Condition.Code)
	encoded, ok := app.PrerenderedJSON.Load().([]byte)
	require.True(t, ok)
	var published CheckState
	require.NoError(t, jsonv2.Unmarshal(encoded, &published))
	assert.Equal(t, checks["DNS"], published.DNS["web A"].Status)
	assert.Equal(t, checks["RDAP"], published.RDAP["example.com"].Status)
	assert.Equal(t, checks["Email"], published.Email["example.com"].Status)
	assert.Equal(t, checks["DNSSEC"], published.DNSSEC["example.com"].Status)
	assert.Equal(t, checks["CAA"], published.CAA["example.com"].Status)
	assert.Equal(t, checks["NSHealth"], published.NSHealth["example.com"].Status)
	alertTypes := make(map[string]bool)
	for _, alert := range notifier.alerts {
		assert.Equal(t, PriorityHigh, alert.Priority)
		kind, _, _ := strings.Cut(alert.Identity, ":")
		alertTypes[kind] = true
	}
	for name := range checks {
		assert.True(t, alertTypes[name], "missing %s failure alert", name)
	}
}

func TestDaemonPublishesRDAPAndWHOISFailure(t *testing.T) {
	app := NewAppState(AppConfig{Domains: []DomainConfig{{Domain: "example.com", Name: "Example"}}})
	app.RDAPLimiter = nil
	app.WHOISClient = &MockWHOISClient{MockQuery: func(context.Context, string, string) (string, error) {
		return "", errors.New(MsgErrWHOISProviderUnavailable)
	}}
	notifier := &assuranceNotifier{}
	app.Notifier = notifier
	state := runMonitoringCycle(context.Background(), app, nil, filepath.Join(t.TempDir(), "ct_state.json"), nil, nil, nil, nil, nil)
	require.NotNil(t, state)
	assert.Equal(t, StatusFailed, state.RDAP["example.com"].Status)
	require.NotNil(t, state.RDAP["example.com"].Condition)
	assert.Equal(t, CodeRDAPHTTPError, state.RDAP["example.com"].Condition.Code)
	encoded, ok := app.PrerenderedJSON.Load().([]byte)
	require.True(t, ok)
	var published CheckState
	require.NoError(t, jsonv2.Unmarshal(encoded, &published))
	assert.Equal(t, StatusFailed, published.RDAP["example.com"].Status)
	assert.Equal(t, CodeRDAPHTTPError, published.RDAP["example.com"].Condition.Code)
	require.Len(t, notifier.alerts, 1)
	assert.Equal(t, "RDAP:example.com:rdapHttpError:failed", notifier.alerts[0].Identity)
	assert.Equal(t, PriorityHigh, notifier.alerts[0].Priority)
}

func TestDaemonWarnsUntilCTBackfillCompletes(t *testing.T) {
	const domain = "example.com"
	app := NewAppState(AppConfig{
		Resolvers: []string{"192.0.2.53:53"},
		Domains: []DomainConfig{{Domain: domain, Name: "Example", IsDelegatedZone: true,
			ExpectedNS: []string{"ns1.example.com"}, MonitorCTLogs: true}},
	})
	app.CTLimiter = nil
	app.CTLogsPath = t.TempDir()
	notifier := &assuranceNotifier{}
	app.Notifier = notifier
	ns, err := dns.NewRR("example.com. 60 IN NS ns1.example.com.")
	require.NoError(t, err)
	app.DNSClient = &MockDNSResolver{MockExchangeContext: func(_ context.Context, query *dns.Msg, _ string) (*dns.Msg, time.Duration, error) {
		response := new(dns.Msg)
		response.SetReply(query)
		if query.Question[0].Qtype == dns.TypeNS {
			response.Answer = []dns.RR{ns}
		}
		return response, 0, nil
	}}
	app.HTTPClient = &MockHTTPClient{MockDo: func(req *http.Request) (*http.Response, error) {
		body := `{"rows":[{"id":"head","match":"example.com"}],"has_next":true,"next_cursor":"page-2"}`
		if req.URL.Query().Get(ParamAfter) == "page-2" {
			body = `{"rows":[{"id":"older","match":"example.com"}],"has_next":false}`
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body))}, nil
	}}
	path := filepath.Join(t.TempDir(), "ct_state.json")
	committed := make(map[string]CTLogState)
	previousConditions := make(map[string]StateCondition)
	run := func() CTLogState {
		state := runMonitoringCycle(context.Background(), app, nil, path, committed, nil, nil, nil, previousConditions)
		encoded, ok := app.PrerenderedJSON.Load().([]byte)
		require.True(t, ok)
		var published CheckState
		require.NoError(t, jsonv2.Unmarshal(encoded, &published))
		assert.Equal(t, state.CTLogs[domain].Status, published.CTLogs[domain].Status)
		onDisk, err := loadCTStateFile(path, os.ReadFile, AtomicWriteFile)
		require.NoError(t, err)
		assert.Equal(t, state.CTLogs[domain].BackfillCursor, onDisk[domain].BackfillCursor)
		return state.CTLogs[domain]
	}
	first := run()
	assert.Equal(t, StatusWarning, first.Status)
	require.NotNil(t, first.Condition)
	assert.Equal(t, CodeCTCoverageIncomplete, first.Condition.Code)
	assert.Equal(t, "page-2", first.BackfillCursor)
	assert.False(t, first.BackfillComplete)
	require.Len(t, notifier.alerts, 1)
	assert.Equal(t, "CTLogs:example.com:ctCoverageIncomplete:warning", notifier.alerts[0].Identity)
	assert.Equal(t, PriorityWarning, notifier.alerts[0].Priority)
	second := run()
	assert.Equal(t, StatusOK, second.Status)
	assert.True(t, second.BackfillComplete)
	assert.Empty(t, second.BackfillCursor)
	assert.Len(t, notifier.alerts, 1, "completion must not repeat the coverage warning")
}

func TestDaemonDNSRecordOutcomeMatrix(t *testing.T) {
	cases := []struct {
		recordType string
		expected   string
		answer     string
	}{
		{RecordTypeA, "192.0.2.10", "A 192.0.2.10"},
		{RecordTypeAAAA, "2001:db8::10", "AAAA 2001:db8::10"},
		{RecordTypeCNAME, "target.example.com", "CNAME target.example.com."},
		{RecordTypeMX, "mail.example.com", "MX 10 mail.example.com."},
		{RecordTypeTXT, "v=spf1 -all", `TXT "v=spf1 -all"`},
		{RecordTypeCAA, `0 issue "letsencrypt.org"`, `CAA 0 issue "letsencrypt.org"`},
		{RecordTypeNS, "ns1.example.com", "NS ns1.example.com."},
		{RecordTypeIP, "192.0.2.10", "A 192.0.2.10"},
		{RecordTypeALIAS, "192.0.2.10", "A 192.0.2.10"},
	}
	for _, tc := range cases {
		t.Run(tc.recordType, func(t *testing.T) {
			target := DNSTask{Hostname: "example.com", Name: tc.recordType, Type: tc.recordType,
				Expected: []string{tc.expected}}
			require.NoError(t, normalizeDNSTask(&target, 0, map[string]bool{}))
			app := NewAppState(AppConfig{Resolvers: []string{"192.0.2.53:53"}, DNSRecords: []DNSTask{target}})
			notifier := &assuranceNotifier{}
			app.Notifier = notifier
			phase := 0
			app.DNSClient = &MockDNSResolver{MockExchangeContext: func(_ context.Context, query *dns.Msg, _ string) (*dns.Msg, time.Duration, error) {
				if phase == 2 {
					return nil, 0, errors.New(MsgErrResolverUnavailable)
				}
				response := new(dns.Msg)
				response.SetReply(query)
				accept := query.Question[0].Qtype == DNSTypeMap[tc.recordType]
				if tc.recordType == RecordTypeIP || tc.recordType == RecordTypeALIAS {
					accept = query.Question[0].Qtype == dns.TypeA
				}
				if !accept {
					return response, 0, nil
				}
				owner := "example.com."
				if phase == 1 {
					owner = "other.example."
				}
				rr, err := dns.NewRR(owner + " 60 IN " + tc.answer)
				require.NoError(t, err)
				response.Answer = []dns.RR{rr}
				return response, 0, nil
			}}
			previous := make(map[string]StateCondition)
			for _, want := range []struct {
				status CheckStatus
				code   ResultCode
			}{{StatusOK, CodeDNSMatchVerified}, {StatusMismatch, CodeDNSMismatch}, {StatusFailed, CodeDNSLookupFailed}} {
				state := runMonitoringCycle(context.Background(), app, nil, filepath.Join(t.TempDir(), "ct_state.json"), nil, nil, nil, nil, previous)
				require.NotNil(t, state)
				actual := state.DNS[tc.recordType]
				assert.Equal(t, want.status, actual.Status)
				require.NotNil(t, actual.Condition)
				assert.Equal(t, want.code, actual.Condition.Code)
				encoded, ok := app.PrerenderedJSON.Load().([]byte)
				require.True(t, ok)
				var published CheckState
				require.NoError(t, jsonv2.Unmarshal(encoded, &published))
				assert.Equal(t, want.status, published.DNS[tc.recordType].Status)
				phase++
			}
			assert.Len(t, notifier.alerts, 2, "mismatch and lookup failure each alert")
		})
	}
}

func TestCTCheckpointOwnership(t *testing.T) {
	original := CTLogState{Status: StatusOK, SeenIDs: []string{"cert"}, Pending: []CTPending{{Cert: CTCert{ID: "cert"}, NeedNtfy: true}}, Condition: &StateCondition{Code: CodeCTLogsVerified}}
	state := NewCheckState()
	state.CTLogs["example.com"] = original
	exported := state.ExportCTLogs()
	exported["example.com"].SeenIDs[0] = "mutated"
	exported["example.com"].Pending[0].NeedNtfy = false
	exported["example.com"].Condition.Code = CodeCTPersistenceFailed
	assert.Equal(t, "cert", state.CTLogs["example.com"].SeenIDs[0])
	assert.True(t, state.CTLogs["example.com"].Pending[0].NeedNtfy)
	assert.Equal(t, CodeCTLogsVerified, state.CTLogs["example.com"].Condition.Code)
}

func TestCTCommittedStateIsIndependentOfCycleResult(t *testing.T) {
	state := NewCheckState()
	state.CTLogs["example.com"] = CTLogState{Status: StatusOK, SeenIDs: []string{"cert"}, Pending: []CTPending{{Cert: CTCert{ID: "cert"}, NeedNtfy: true}}, Condition: &StateCondition{Code: CodeCTLogsVerified}, NewCerts: []CTCert{{ID: "cert"}}}
	committed := make(map[string]CTLogState)
	app := NewAppState(AppConfig{})
	app.WriteCTState = func(string, []byte, os.FileMode) error { return nil }
	commitCycleCTState(app, state, "unused", committed, map[string]bool{"example.com": true})
	state.CTLogs["example.com"].SeenIDs[0] = "mutated"
	state.CTLogs["example.com"].Pending[0].NeedNtfy = false
	state.CTLogs["example.com"].Condition.Code = CodeCTPersistenceFailed
	assert.Equal(t, "cert", committed["example.com"].SeenIDs[0])
	assert.True(t, committed["example.com"].Pending[0].NeedNtfy)
	assert.Equal(t, CodeCTLogsVerified, committed["example.com"].Condition.Code)
	assert.Empty(t, committed["example.com"].NewCerts, "committed state must not retain transient display discoveries")
	prepared, _ := prepareCycleState([]DomainConfig{{Domain: "example.com", MonitorCTLogs: true}}, committed)
	prepared.CTLogs["example.com"].Pending[0].NeedNtfy = false
	assert.True(t, committed["example.com"].Pending[0].NeedNtfy)
}

func TestCTDisabledOnRestartDoesNotPublishOrDeliverStaleWork(t *testing.T) {
	const domain = "example.com"
	committed := map[string]CTLogState{domain: {Status: StatusFailed, SeenIDs: []string{"cert"}, Pending: []CTPending{{Cert: CTCert{ID: "cert"}, NeedNtfy: true}}, Condition: &StateCondition{Code: CodeCTLogsHTTPError}}}
	cfg := DomainConfig{Domain: domain, MonitorCTLogs: false}
	state, active := prepareCycleState([]DomainConfig{cfg}, committed)
	notifier := newRecordingNotifier()
	app := NewAppState(AppConfig{Domains: []DomainConfig{cfg}})
	app.Notifier = notifier
	path := filepath.Join(t.TempDir(), "checkpoint.json")
	commitCycleCTState(app, state, path, committed, active)
	processConditionsAndAlerts(app, state, []DomainConfig{cfg}, nil, make(map[string]StateCondition))
	assert.Empty(t, state.CTLogs)
	assert.Empty(t, notifier.alerts)
	restarted, err := loadCTStateFile(path, os.ReadFile, AtomicWriteFile)
	require.NoError(t, err)
	assert.Empty(t, restarted)
}

func TestDNSResultsCannotMutateConfiguration(t *testing.T) {
	for _, panics := range []bool{false, true} {
		t.Run(strconv.FormatBool(panics), func(t *testing.T) {
			app := NewAppState(AppConfig{DNSRecords: []DNSTask{{Hostname: "example.com", Name: "example A", Type: RecordTypeA, Expected: []string{"192.0.2.10"}}}})
			app.DNSClient = &MockDNSResolver{MockExchangeContext: func(_ context.Context, query *dns.Msg, _ string) (*dns.Msg, time.Duration, error) {
				if panics {
					panic("injected failure")
				}
				response := new(dns.Msg)
				response.SetReply(query)
				response.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET}, A: net.ParseIP("192.0.2.10")}}
				return response, 0, nil
			}}
			results := executeDNSChecks(context.Background(), app, app.configuration().DNSRecords)
			require.Len(t, results, 1)
			results[0].State.Expected[0] = "192.0.2.99"
			assert.Equal(t, "192.0.2.10", app.Config().DNSRecords[0].Expected[0])
			next := executeDNSChecks(context.Background(), app, app.configuration().DNSRecords)
			assert.Equal(t, "192.0.2.10", next[0].State.Expected[0])
		})
	}
}

func TestDashboardRendersDomainsWithCTState(t *testing.T) {
	browser, err := exec.LookPath("chromium")
	if err != nil {
		t.Skip("Chromium is needed for the dashboard rendering regression")
	}
	harness := `
 try {
  appState = {
   rdap_checks: {"healthy.example": {status:"ok", nameservers:["ns.example"], renewal_price:11.08}, "warning.example": {status:"ok", nameservers:["ns.example"]}, "let-go.example": {status:"ok", nameservers:["ns.example"], allow_expiry:true}, "delegated.example": {status:"ok", nameservers:["ns.example"], is_delegated_zone:true}},
   ct_logs: {"healthy.example": {status:"ok", backfill_complete:true}, "warning.example": {status:"warning", coverage_incomplete:true, error:"provider temporarily unavailable", pending:[{}]}}
  };
  renderDomains();
  const cards = document.querySelectorAll('#view-domains details');
  if (cards.length !== 4) throw new Error("Missing domain cards");
  const warning = Array.from(cards).find(card => card.dataset.search === 'warning.example');
  if (!warning || !warning.querySelector('summary').textContent.includes('ct_coverage_warning')) throw new Error('Missing CT warning badge');
  for (const card of cards) {
   const price = {'healthy.example':'$11.08/yr', 'warning.example':'Unknown', 'let-go.example':'Not renewing', 'delegated.example':'Not applicable'}[card.dataset.search];
   for (const open of [false, true]) {
    card.open = open;

    const details = card.querySelector('.domain-details');
    if (!details.textContent.includes('Renewal Price:') || !details.textContent.includes(price)) throw new Error('Missing expanded renewal price');
    if (details.textContent.includes('Certificate Transparency') || details.textContent.includes('Alerts Awaiting Acknowledgement')) throw new Error('CT block still present');
   }
  }
  let scheduled = 0;
  window.setTimeout = () => { scheduled++; return scheduled; };
  window.fetch = () => new Promise(() => {});
  initialize();
  if (scheduled !== 0) throw new Error('Duplicate polling scheduled before the initial request completes');
  document.body.setAttribute('data-audit-result', 'passed');
 } catch (error) {
  document.body.setAttribute('data-audit-result', String(error));
 }
 `
	html := strings.Replace(string(indexHTML), "    initialize();", harness, 1)
	html = strings.Replace(html, "    // Theme initialization", "    Object.defineProperty(window, 'localStorage', {get() { throw new Error('Storage denied'); }});\n    // Theme initialization", 1)
	page := filepath.Join(t.TempDir(), "dashboard.html")
	require.NoError(t, os.WriteFile(page, []byte(html), 0600))
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, browser, "--headless", "--user-data-dir="+t.TempDir(), "--no-sandbox", "--disable-gpu", "--disable-background-networking", "--dump-dom", "file://"+page).Output()
	require.NoError(t, err)
	_, body, found := strings.Cut(string(output), "<body")
	require.True(t, found)
	require.Contains(t, strings.SplitN(body, ">", 2)[0], `data-audit-result="passed"`)
}

func TestWHOISPartialResponseCannotHideTransportError(t *testing.T) {
	app := NewAppState(AppConfig{})
	app.WHOISClient = &MockWHOISClient{MockQuery: func(context.Context, string, string) (string, error) {
		return "Domain Name: EXAMPLE.COM\nRegistry Expiry Date: 2030-01-01T00:00:00Z\nName Server: NS.EXAMPLE.COM\nDomain Status: clientTransferProhibited\n", io.ErrUnexpectedEOF
	}}
	_, err := fetchWHOIS(context.Background(), app, "example.com")
	require.ErrorIs(t, err, io.ErrUnexpectedEOF)
}
