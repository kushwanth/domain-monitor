package main

import (
	"context"
	jsonv2 "encoding/json/v2"
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

func TestFillPanicDomainResults(t *testing.T) {
	cfg := DomainConfig{CheckEmailSecurity: true, IsDelegatedZone: true, DNSSEC: true, VerifyNSHealth: true}
	var res DomainResult
	fillPanicDomainResults(cfg, &res, "some panic")
	assert.Equal(t, StatusFailed, res.Email.Status)
	assert.Equal(t, StatusFailed, res.RDAP.Status)
	assert.Equal(t, StatusFailed, res.DNSSEC.Status)
	assert.Equal(t, StatusFailed, res.NSHealth.Status)
	assert.Contains(t, res.RDAP.Error, "some panic")
}

func TestReleaseCycleDeliversAlerts(t *testing.T) {
	app := NewAppState(AppConfig{DNSRecords: []DNSTask{{Hostname: "example.com", Name: "web", Type: RecordTypeA, Expected: []string{"192.0.2.1"}}}})
	app.DNSClient = &MockDNSResolver{MockExchangeContext: func(_ context.Context, q *dns.Msg, _ string) (*dns.Msg, time.Duration, error) {
		return new(dns.Msg).SetReply(q), 0, nil
	}}
	requests := 0
	notifier := NewNotificationManager("https://ntfy.invalid/topic", "", "", "")
	notifier.HTTPClient = &MockHTTPClient{MockDo: func(req *http.Request) (*http.Response, error) {
		requests++
		assert.Equal(t, http.MethodPost, req.Method)
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(""))}, nil
	}}
	app.Notifier = notifier
	for range 2 {
		state := runMonitoringCycle(context.Background(), app, nil, nil, nil, nil, nil)
		assert.Equal(t, StatusMismatch, state.DNS["web"].Status)
	}
	assert.Equal(t, 2, requests)
	assert.Empty(t, notifier.alertBatch)
}

func TestReleaseCAAConfigIsolation(t *testing.T) {
	cfg := AppConfig{Domains: []DomainConfig{{Domain: "example.com", CAA: &CAAConfig{Issue: []string{"ca.example"}, IssueWild: []string{}, IssueMail: []string{"mail.example"}}}}}
	app := NewAppState(cfg)
	cfg.Domains[0].CAA.Issue[0] = "mutated.example"
	snapshot := app.Config()
	snapshot.Domains[0].CAA.IssueMail[0] = "mutated.example"
	snapshot.Domains[0].CAA.IssueWild = nil
	assert.Equal(t, []string{"ca.example"}, app.Config().Domains[0].CAA.Issue)
	assert.Equal(t, []string{"mail.example"}, app.Config().Domains[0].CAA.IssueMail)
	assert.NotNil(t, app.Config().Domains[0].CAA.IssueWild)
}

func TestReleaseProviderDKIMFromJSON(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "custom.json"), []byte(`{"mx_records":["mail.example.com"],"dkim_selectors":["custom"]}`), 0600))
	body, err := jsonv2.Marshal(map[string]any{"notifications": map[string]any{"ntfy": map[string]string{"url": "https://ntfy.invalid/topic"}}, "email_providers_dir": dir, "domains": []map[string]any{{"domain": "example.com", "name": "Example", "check_email_security": true, "mail_provider": "custom"}}})
	require.NoError(t, err)
	cfg, err := loadConfig(context.Background(), "memory", func(string) ([]byte, error) { return body, nil })
	require.NoError(t, err)
	app, err := InitializeApp(context.Background(), cfg)
	require.NoError(t, err)
	queried := false
	app.DNSClient = &MockDNSResolver{MockExchangeContext: func(_ context.Context, q *dns.Msg, _ string) (*dns.Msg, time.Duration, error) {
		if q.Question[0].Name == "custom._domainkey.example.com." {
			queried = true
		}
		return new(dns.Msg).SetReply(q), 0, nil
	}}
	target := cfg.Domains[0]
	snap := FetchEmailSnapshot(context.Background(), app, target)
	assert.True(t, queried, "JSON selector must be queried")
	snap.MXRecords = []string{"mail.example.com"}
	snap.SPFRecords = []string{"v=spf1 -all"}
	snap.DMARCRecords = []string{"v=DMARC1; p=reject"}
	status, cond, state := EvaluateEmailSecurity(target, snap, app)
	assert.True(t, state.DKIMExpected)
	assert.Equal(t, StatusWarning, status)
	require.NotNil(t, cond)
	assert.Equal(t, CodeEmailMissingDKIM, cond.Code)
}

func TestReleasePricingCachesAcrossCycles(t *testing.T) {
	requests := 0
	pm := NewPricingManager(&MockHTTPClient{MockDo: func(_ *http.Request) (*http.Response, error) {
		requests++
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"tlds":[{"tld":"com","renewal":12}]}`))}, nil
	}})
	app := NewAppState(AppConfig{Domains: []DomainConfig{{Domain: "example.com"}}})
	for range 2 {
		state := NewCheckState()
		state.RDAP["example.com"] = RDAPState{Status: StatusOK}
		computePortfolioPricing(context.Background(), app, state, pm)
		assert.Equal(t, float64(12), state.RDAP["example.com"].RenewalPrice)
	}
	assert.Equal(t, 1, requests)
}

func TestReleaseDashboardCAAAndDNSPolling(t *testing.T) {
	browser, err := exec.LookPath("chromium")
	if err != nil {
		t.Skip("Chromium is required for dashboard regression")
	}
	harness := `
 (async () => {
  try {
   const fixture = {last_updated:'2026-09-27T00:00:00Z',rdap_checks:{'example.com':{status:'ok',nameservers:['ns.example.com']}},dns_checks:{web:{hostname:'example.com',name:'web',type:'A',status:'ok'}},caa_checks:{'example.com':{valid:false,issue:['unexpected.example']}}};
   appState = fixture; renderDomains();
   currentFilter = 'issues'; renderDomains();
   if (!document.querySelector('#view-domains details')) throw new Error('Invalid CAA missing from issues');
   switchView('dns'); appState = {};
   window.fetch = async () => ({ok:true,json:async()=>fixture});
   window.setTimeout = () => 0;
   await pollState();
   if (document.getElementById('cert-domain-select')) throw new Error('Certificate selector replaced DNS summary');
   if (!document.getElementById('view-stats').textContent.includes('Healthy')) throw new Error('DNS summary missing');
   if (connectionError) throw new Error('Polling failed');
   document.body.setAttribute('data-audit-result','passed');
  } catch(error) { document.body.setAttribute('data-audit-result',String(error)); }
 })();`
	html := strings.Replace(string(indexHTML), "    initialize();", harness, 1)
	page := filepath.Join(t.TempDir(), "dashboard.html")
	require.NoError(t, os.WriteFile(page, []byte(html), 0600))
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, browser, "--headless", "--user-data-dir="+t.TempDir(), "--no-sandbox", "--disable-gpu", "--disable-background-networking", "--dump-dom", "file://"+page).Output()
	require.NoError(t, err)
	_, body, found := strings.Cut(string(output), "<body")
	require.True(t, found)
	assert.Contains(t, strings.SplitN(body, ">", 2)[0], `data-audit-result="passed"`)
}

func TestReleaseCAACyclePublishesCondition(t *testing.T) {
	for _, lookupFails := range []bool{false, true} {
		cfg, err := loadConfig(context.Background(), "memory", func(string) ([]byte, error) {
			return []byte(`{"notifications":{"ntfy":{"url":"https://ntfy.invalid/topic"}},"domains":[{"domain":"sub.example.com","name":"Subdomain","is_delegated_zone":true,"root_zone":"example.com","caa":{"issue":["ca.example"]}}]}`), nil
		})
		require.NoError(t, err)
		app := NewAppState(cfg)
		app.DNSClient = &MockDNSResolver{MockExchangeContext: func(_ context.Context, q *dns.Msg, _ string) (*dns.Msg, time.Duration, error) {
			response := new(dns.Msg).SetReply(q)
			if q.Question[0].Qtype == dns.TypeCAA {
				if lookupFails {
					return nil, 0, io.ErrUnexpectedEOF
				}
				rr, err := dns.NewRR(`sub.example.com. 60 IN CAA 0 issue "other.example"`)
				require.NoError(t, err)
				response.Answer = []dns.RR{rr}
			}
			return response, 0, nil
		}}
		state := runMonitoringCycle(context.Background(), app, nil, nil, nil, nil, nil)
		caa := state.CAA["sub.example.com"]
		require.NotNil(t, caa)
		want := StatusMismatch
		if lookupFails {
			want = StatusFailed
		}
		assert.Equal(t, want, caa.Status)
		require.NotNil(t, caa.Condition)
		assert.False(t, caa.Condition.Since.IsZero())
		encoded, ok := app.PrerenderedJSON.Load().([]byte)
		require.True(t, ok)
		var published CheckState
		require.NoError(t, jsonv2.Unmarshal(encoded, &published))
		assert.Equal(t, want, published.CAA["sub.example.com"].Status)
	}
}
