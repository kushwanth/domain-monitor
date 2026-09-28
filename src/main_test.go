package main

import (
	"context"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
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
	state := NewCheckState()
	executeFastChecks(context.Background(), app, AppConfig{Domains: []DomainConfig{target}}, activeChecks{domains: []int{0}}, state)
	assert.Equal(t, StatusOK, state.Email[target.Domain].Status)
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
		make(map[conditionKey]StateCondition),
	)

	require.NotNil(t, state)
	assert.Equal(t, StatusOK, state.DNS["example A"].Status)
	encoded, ok := app.PublishedJSON()
	require.True(t, ok)
	var published struct {
		DNSChecks map[string]DNSState `json:"dns_checks"`
	}
	require.NoError(t, jsonv2.Unmarshal(encoded, &published))
	assert.Equal(t, StatusOK, published.DNSChecks["example A"].Status)
	stored := state.DNS["example A"]
	stored.Expected[0] = "cycle mutation"
	assert.Equal(t, "192.0.2.10", app.Config().DNSRecords[0].Expected[0], "cycle state must not alias startup expectations")
}

func TestUnusedDomainSkipsEveryCheckAndOwnedDNSRecord(t *testing.T) {
	app := NewAppState(AppConfig{
		Domains:    []DomainConfig{{Domain: "example.com", Unused: true}},
		DNSRecords: []DNSTask{{Name: "unused A", Hostname: "www.example.com", Type: RecordTypeA}},
	})
	app.DNSClient = &MockDNSResolver{MockExchangeContext: func(context.Context, *dns.Msg, string) (*dns.Msg, time.Duration, error) {
		t.Fatal("unused domain caused a DNS lookup")
		return nil, 0, nil
	}}
	app.PublishInitialState()
	initialJSON, ok := app.PublishedJSON()
	require.True(t, ok)
	var initial CheckState
	require.NoError(t, jsonv2.Unmarshal(initialJSON, &initial))
	assert.Equal(t, StatusSkipped, initial.RDAP["example.com"].Status)
	assert.Empty(t, initial.DNS)

	state := runMonitoringCycle(context.Background(), app, nil, nil, nil, nil, nil)
	assert.Equal(t, StatusSkipped, state.RDAP["example.com"].Status)
	assert.Empty(t, state.DNS)
	assert.Empty(t, state.Email)
	assert.Empty(t, state.CAA)
	assert.Empty(t, state.DNSSEC)
	assert.Empty(t, state.NSHealth)
}

func TestActiveDNSRecordsUsesMostSpecificDomain(t *testing.T) {
	domains := []DomainConfig{{Domain: "example.com", Unused: true}, {Domain: "sub.example.com"}}
	records := []DNSTask{
		{Name: "parent", Hostname: "www.example.com"},
		{Name: "child", Hostname: "www.sub.example.com"},
		{Name: "unrelated", Hostname: "outside.test"},
	}
	active := activeDNSRecords(records, domains)
	require.Len(t, active, 2)
	assert.Equal(t, "child", records[active[0]].Name)
	assert.Equal(t, "unrelated", records[active[1]].Name)
}

func TestActiveViewsReferenceOwnedConfiguration(t *testing.T) {
	cfg := AppConfig{
		Domains:    []DomainConfig{{Domain: "active.example"}, {Domain: "unused.example", Unused: true}},
		DNSRecords: []DNSTask{{Name: "record", Hostname: "active.example"}},
	}
	app := NewAppState(cfg)
	require.Len(t, app.active.domains, 1)
	require.Len(t, app.active.dnsRecords, 1)
	assert.Equal(t, 0, app.active.domains[0])
	assert.Equal(t, 0, app.active.dnsRecords[0])
	cfg.Domains[0].Domain = "caller mutation"
	cfg.DNSRecords[0].Name = "caller mutation"
	assert.Equal(t, "active.example", app.config.Domains[app.active.domains[0]].Domain)
	assert.Equal(t, "record", app.config.DNSRecords[app.active.dnsRecords[0]].Name)
}

func TestBoundedWorkersVisitEveryTaskWithinLimit(t *testing.T) {
	const count = 1000
	seen := make([]atomic.Int32, count)
	var active, peak atomic.Int32
	runBoundedChecks(count, func(index int) {
		current := active.Add(1)
		for previous := peak.Load(); current > previous; previous = peak.Load() {
			if peak.CompareAndSwap(previous, current) {
				break
			}
		}
		seen[index].Add(1)
		runtime.Gosched()
		active.Add(-1)
	})
	for i := range seen {
		assert.EqualValues(t, 1, seen[i].Load(), "task %d", i)
	}
	assert.LessOrEqual(t, peak.Load(), int32(DefaultMaxConcurrency))
}

func TestFastChecksDoNotWaitForDNSPhase(t *testing.T) {
	// Fill the worker limit with DNS checks. A domain check must still start
	// before any of those checks completes.
	dnsRecords := make([]DNSTask, DefaultMaxConcurrency+1)
	for i := range dnsRecords {
		dnsRecords[i] = DNSTask{Name: fmt.Sprintf("address-%d", i), Hostname: "example.com", Type: RecordTypeA}
	}
	app := NewAppState(AppConfig{
		Domains:    []DomainConfig{{Domain: "example.com", CheckEmailSecurity: true}},
		DNSRecords: dnsRecords,
	})
	addressStarted := make(chan struct{}, 1)
	mailStarted := make(chan struct{}, 1)
	releaseAddress := make(chan struct{})
	app.DNSClient = &MockDNSResolver{MockExchangeContext: func(_ context.Context, query *dns.Msg, _ string) (*dns.Msg, time.Duration, error) {
		switch query.Question[0].Qtype {
		case dns.TypeA:
			select {
			case addressStarted <- struct{}{}:
			default:
			}
			<-releaseAddress
		case dns.TypeMX:
			select {
			case mailStarted <- struct{}{}:
			default:
			}
		}
		response := new(dns.Msg)
		response.SetReply(query)
		return response, 0, nil
	}}
	done := make(chan struct{})
	go func() {
		defer close(done)
		executeFastChecks(context.Background(), app, app.configuration(), app.active, NewCheckState())
	}()
	select {
	case <-addressStarted:
	case <-time.After(2 * time.Second):
		close(releaseAddress)
		t.Fatal("DNS task did not start")
	}
	select {
	case <-mailStarted:
	case <-time.After(2 * time.Second):
		close(releaseAddress)
		t.Fatal("domain task waited for DNS completion")
	}
	close(releaseAddress)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("fast checks did not finish")
	}
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
	encoded, ok := app.PublishedJSON()
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

func TestStateETagSkipsUnchangedBody(t *testing.T) {
	app := NewAppState(AppConfig{Domains: []DomainConfig{{Domain: "example.com"}}})
	app.PublishInitialState()
	server, _ := setupHTTPServer(app, "0")
	t.Cleanup(func() { require.NoError(t, server.Close()) })
	path := strings.TrimPrefix(RouteAPIState, "GET ")

	first := httptest.NewRecorder()
	server.Handler.ServeHTTP(first, httptest.NewRequest(http.MethodGet, path, nil))
	require.Equal(t, http.StatusOK, first.Code)
	etag := first.Header().Get("ETag")
	require.NotEmpty(t, etag)
	require.NotEmpty(t, first.Body.String())

	conditional := httptest.NewRequest(http.MethodGet, path, nil)
	conditional.Header.Set("If-None-Match", etag)
	unchanged := httptest.NewRecorder()
	server.Handler.ServeHTTP(unchanged, conditional)
	assert.Equal(t, http.StatusNotModified, unchanged.Code)
	assert.Empty(t, unchanged.Body.String())

	state := prepareCycleState([]DomainConfig{{Domain: "example.com"}})
	state.RDAP["example.com"] = RDAPState{Status: StatusOK}
	publishCycleState(app, state, time.Hour)
	changed := httptest.NewRecorder()
	server.Handler.ServeHTTP(changed, conditional)
	assert.Equal(t, http.StatusOK, changed.Code)
	assert.NotEqual(t, etag, changed.Header().Get("ETag"))
	assert.NotEmpty(t, changed.Body.String())
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
			prev := make(map[conditionKey]StateCondition)
			processConditionsAndAlerts(app, state, AppConfig{Domains: []DomainConfig{{Domain: domain, Name: "Example", SuppressAlerts: tc.suppress}}}, activeChecks{domains: []int{0}}, prev)
			assert.Len(t, notifier.alerts, tc.wantAlerts)
			assert.Len(t, prev, 4)
			if !tc.suppress {
				assert.Equal(t, PriorityWarning, notifier.alerts[3].Priority)
			}
		})
	}
}

func TestFillPanicDomainResults(t *testing.T) {
	cfg := DomainConfig{CheckEmailSecurity: true, MailProvider: "google", IsDelegatedZone: true, DNSSEC: true, VerifyNSHealth: true}
	var res DomainResult
	fillPanicDomainResults(cfg, &res, "some panic")
	assert.Equal(t, StatusFailed, res.Email.Status)
	assert.Equal(t, "google", res.Email.Provider)
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
   const previousTheme = document.documentElement.getAttribute('data-theme');
   toggleTheme();
   if (document.documentElement.getAttribute('data-theme') === previousTheme) throw new Error('Theme toggle failed without browser storage');
   const fixture = {last_updated:'2026-09-27T00:00:00Z',rdap_checks:{'example.com':{status:'ok',nameservers:['ns.example.com'],renewal_price:12}},dns_checks:{web:{hostname:'example.com',name:'web',type:'A',status:'ok'}},caa_checks:{'example.com':{valid:false,issue:['unexpected.example']}},ns_health:{'example.com':{status:'ok',valid:true,primary:'ns.example.com',servers:[{}]}}};
   appState = fixture; renderDomains();
   currentFilter = 'issues'; renderDomains();
   if (!document.querySelector('#view-domains details')) throw new Error('Invalid CAA missing from issues');
   switchView('nshealth');
   if (currentView !== 'domains' || document.getElementById('view-domains').classList.contains('hidden')) throw new Error('Legacy nameserver view hides domain cards');
   if (!document.getElementById('view-domains').textContent.includes('$12.00/yr')) throw new Error('Renewal price missing');
   if (!document.getElementById('view-domains').textContent.includes('Nameserver Health')) throw new Error('Nameserver health missing');
   switchView('dns'); appState = {};
   window.fetch = async () => ({ok:true,json:async()=>fixture});
   window.setTimeout = () => 0;
   await pollState();
   if (document.getElementById('cert-domain-select')) throw new Error('Certificate selector replaced DNS summary');
   if (!document.getElementById('view-stats').textContent.includes('Matched')) throw new Error('DNS summary missing');
   if (connectionError) throw new Error('Polling failed');
   document.body.setAttribute('data-audit-result','passed');
  } catch(error) { document.body.setAttribute('data-audit-result',String(error)); }
 })();`
	html := strings.Replace(string(indexHTML), "    initialize();", harness, 1)
	html = strings.Replace(html, "<script>", `<script>Object.defineProperty(window, 'localStorage', {get() {throw new Error('Storage unavailable');}});</script><script>`, 1)
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
		encoded, ok := app.PublishedJSON()
		require.True(t, ok)
		var published CheckState
		require.NoError(t, jsonv2.Unmarshal(encoded, &published))
		assert.Equal(t, want, published.CAA["sub.example.com"].Status)
	}
}

func TestSerialRDAPPanicPreservesCompletedChecks(t *testing.T) {
	domains := []DomainConfig{{Domain: "first.com"}, {Domain: "delegated.first.com", IsDelegatedZone: true}, {Domain: "last.com"}}
	app := NewAppState(AppConfig{Domains: domains})
	app.Bootstrap = &Bootstrap{services: map[string][]string{"com": {"https://rdap.example/"}}, fetchedAt: time.Now()}
	app.RDAPLimiter = nil
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) { panic("RDAP transport panic") })}
	state := prepareCycleState(domains)
	state.RDAP[domains[1].Domain] = RDAPState{Status: StatusOK, IsDelegatedZone: true}
	state.Email[domains[0].Domain] = EmailState{Status: StatusOK, MX: []string{"mail.first.com"}}
	executeRateLimitedChecks(context.Background(), app, domains, []int{0, 1, 2}, client, state)
	for _, domain := range []string{"first.com", "last.com"} {
		assert.Equal(t, StatusFailed, state.RDAP[domain].Status)
		assert.Contains(t, state.RDAP[domain].Error, "RDAP transport panic")
	}
	assert.Equal(t, StatusOK, state.RDAP[domains[1].Domain].Status)
	assert.Equal(t, []string{"mail.first.com"}, state.Email[domains[0].Domain].MX)
}

func TestCyclePublicationRemainsIsolated(t *testing.T) {
	app := NewAppState(AppConfig{})
	state := NewCheckState()
	result := DNSResult{Name: "__caa__example.com", State: DNSState{Status: StatusMismatch, Condition: &StateCondition{Code: CodeDNSLookupFailed}, Found: []string{`0 issue "other.example"`}}}
	storeDNSResult(state, result)
	publishCycleState(app, state, time.Hour)
	before, ok := app.PublishedJSON()
	require.True(t, ok)
	original := string(before)
	before[0] = 'x'
	state.CAA["example.com"].Issue[0] = "cycle mutation"
	state.CAA["example.com"].Condition.Target = "cycle mutation"
	after, ok := app.PublishedJSON()
	require.True(t, ok)
	assert.Equal(t, original, string(after))
	assert.NotContains(t, string(after), "mutation")
}

func TestSerialRDAPCancellationCompletesFailedResults(t *testing.T) {
	domains := []DomainConfig{{Domain: "first.com"}, {Domain: "last.com"}}
	app := NewAppState(AppConfig{Domains: domains})
	app.Bootstrap = &Bootstrap{services: map[string][]string{"com": {"https://rdap.example/"}}, fetchedAt: time.Now()}
	app.RDAPLimiter = nil
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) { return nil, request.Context().Err() })}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	state := prepareCycleState(domains)
	executeRateLimitedChecks(ctx, app, domains, []int{0, 1}, client, state)
	for _, domain := range domains {
		assert.Equal(t, StatusFailed, state.RDAP[domain.Domain].Status)
		assert.Contains(t, state.RDAP[domain.Domain].Error, context.Canceled.Error())
	}
}

func TestFastDomainNameserverHealthPublished(t *testing.T) {
	for _, mode := range []string{"matching", "different keys", "unreachable", "key lookup error"} {
		t.Run(mode, func(t *testing.T) {
			target := DomainConfig{Domain: "example.com", VerifyNSHealth: true, DNSSEC: true, ExpectedNS: []string{"192.0.2.1", "192.0.2.2"}, SecondaryNS: []string{"192.0.2.3"}}
			app := NewAppState(AppConfig{Domains: []DomainConfig{target}})
			app.DNSClient = &MockDNSResolver{MockExchangeContext: func(_ context.Context, q *dns.Msg, address string) (*dns.Msg, time.Duration, error) {
				redundantPrimary := strings.HasPrefix(address, "192.0.2.2:")
				if redundantPrimary && (mode == "unreachable" || mode == "key lookup error" && q.Question[0].Qtype == dns.TypeDNSKEY) {
					return nil, 0, errors.New("injected nameserver failure")
				}
				response := new(dns.Msg)
				response.SetReply(q)
				response.Authoritative = true
				switch q.Question[0].Qtype {
				case dns.TypeSOA:
					response.Answer = []dns.RR{&dns.SOA{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeSOA, Class: dns.ClassINET}, Serial: 42}}
				case dns.TypeDNSKEY:
					key := "AQID"
					if redundantPrimary && mode == "different keys" {
						key = "BAUG"
					}
					response.Answer = []dns.RR{&dns.DNSKEY{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET}, Flags: 257, Protocol: 3, Algorithm: dns.ED25519, PublicKey: key}}
				}
				return response, 0, nil
			}}
			state := NewCheckState()
			executeFastChecks(context.Background(), app, AppConfig{Domains: []DomainConfig{target}}, activeChecks{domains: []int{0}}, state)
			health := state.NSHealth[target.Domain]
			require.Len(t, health.Servers, 3)
			assert.Equal(t, target.ExpectedNS[0], health.Primary)
			assert.True(t, health.Servers[0].IsPrimary)
			assert.True(t, health.Servers[1].IsPrimary)
			assert.False(t, health.Servers[2].IsPrimary)
			assert.Equal(t, uint32(42), health.Servers[0].SOASerial)
			if mode == "matching" {
				assert.Equal(t, StatusOK, health.Status)
				assert.True(t, health.Valid)
				assert.True(t, health.Servers[1].DNSKEYMatch)
			} else {
				assert.Equal(t, StatusFailed, health.Status)
				assert.False(t, health.Valid)
				if mode == "different keys" {
					assert.False(t, health.Servers[1].DNSKEYMatch)
				} else {
					assert.Contains(t, health.Servers[1].Error, "injected nameserver failure")
				}
			}
			publishCycleState(app, state, time.Hour)
			var published CheckState
			publishedJSON, ok := app.PublishedJSON()
			require.True(t, ok)
			require.NoError(t, jsonv2.Unmarshal(publishedJSON, &published))
			assert.Equal(t, health, published.NSHealth[target.Domain])
		})
	}
}

func TestPublicationFailureKeepsLastSnapshot(t *testing.T) {
	app := NewAppState(AppConfig{Domains: []DomainConfig{{Domain: "example.com"}}, DNSRecords: []DNSTask{{Name: "web", Hostname: "example.com", Type: RecordTypeA, Expected: []string{"192.0.2.1"}}}})
	app.PublishInitialState()
	original, ok := app.PublishedJSON()
	require.True(t, ok)
	var initial CheckState
	require.NoError(t, jsonv2.Unmarshal(original, &initial))
	assert.Equal(t, StatusPending, initial.RDAP["example.com"].Status)
	assert.Equal(t, StatusPending, initial.DNS["web"].Status)
	assert.Equal(t, []string{"192.0.2.1"}, initial.DNS["web"].Expected)
	state := NewCheckState()
	state.RDAP["example.com"] = RDAPState{RenewalPrice: math.NaN()}
	publishCycleState(app, state, time.Hour)
	current, ok := app.PublishedJSON()
	require.True(t, ok)
	assert.Equal(t, original, current)
	publishCycleState(nil, state, time.Hour)
	assert.NotEmpty(t, state.NextRefresh)
}

func TestConditionAlertMessagePreservesText(t *testing.T) {
	for _, tc := range []struct {
		check  string
		status CheckStatus
		code   ResultCode
		target string
	}{
		{CheckTypeDNS, StatusMismatch, CodeDNSLookupFailed, "unexpected record"},
		{CheckTypeRDAP, StatusWarning, CodeRDAPHTTPError, ""},
	} {
		duration := "2h0m0s"
		assert.Equal(t,
			fmt.Sprintf(AlertConditionFormat, tc.check, tc.status, tc.code, tc.target, duration),
			conditionAlertMessage(tc.check, tc.status.String(), tc.code.String(), tc.target, duration, false),
		)
		assert.Equal(t,
			fmt.Sprintf(AlertConditionRedactedFormat, tc.check, tc.status, tc.code, duration),
			conditionAlertMessage(tc.check, tc.status.String(), tc.code.String(), StrEmpty, duration, true),
		)
	}
}

func TestConditionSinceTracksCodeWithoutRetainingDiagnostic(t *testing.T) {
	since := time.Now().Add(-time.Hour).UTC()
	key := conditionKey{check: "dns", domain: "example"}
	previous := map[conditionKey]StateCondition{key: {Code: CodeDNSLookupFailed, Since: since, Target: "old secret"}}
	same := &StateCondition{Code: CodeDNSLookupFailed, Target: "new secret"}
	applyConditionSince(same, key, previous)
	assert.Equal(t, since, same.Since)
	assert.Empty(t, previous[key].Target)
	changed := &StateCondition{Code: CodeDNSMatchVerified}
	applyConditionSince(changed, key, previous)
	assert.True(t, changed.Since.After(since))
	applyConditionSince(nil, key, previous)
	assert.Equal(t, changed.Code, previous[key].Code)
	assert.Equal(t, "1h0m0s", formatDurationSince(since))
}

func TestCAATaskMatchingScopes(t *testing.T) {
	for _, tc := range []struct {
		name, checks string
		want         CheckStatus
		domainPolicy bool
	}{
		{"explicit absence", `"dns_records":[{"hostname":"example.com","name":"CAA","type":"CAA","expected":[]}]`, StatusMismatch, false},
		{"explicit exact set", `"dns_records":[{"hostname":"example.com","name":"CAA","type":"CAA","expected":["0 issue \"ca.example\""]}]`, StatusMismatch, false},
		{"domain omitted tag", `"domains":[{"domain":"example.com","name":"Example","caa":{"issue":["ca.example"]}}]`, StatusOK, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := loadConfig(context.Background(), "memory", func(string) ([]byte, error) {
				return []byte(`{"notifications":{"ntfy":{"url":"https://ntfy.invalid/topic"}},` + tc.checks + `}`), nil
			})
			require.NoError(t, err)
			app, err := InitializeApp(context.Background(), cfg)
			require.NoError(t, err)
			app.DNSClient = &MockDNSResolver{MockExchangeContext: func(_ context.Context, q *dns.Msg, _ string) (*dns.Msg, time.Duration, error) {
				response := new(dns.Msg)
				response.SetReply(q)
				for _, text := range []string{`example.com. IN CAA 0 issue "ca.example"`, `example.com. IN CAA 0 issuewild "other.example"`} {
					rr, err := dns.NewRR(text)
					require.NoError(t, err)
					response.Answer = append(response.Answer, rr)
				}
				return response, 0, nil
			}}
			state := NewCheckState()
			executeFastChecks(context.Background(), app, app.configuration(), activeChecks{dnsRecords: app.active.dnsRecords}, state)
			if tc.domainPolicy {
				require.NotNil(t, state.CAA["example.com"])
				assert.Equal(t, tc.want, state.CAA["example.com"].Status)
				assert.Empty(t, state.DNS)
			} else {
				assert.Equal(t, tc.want, state.DNS["CAA"].Status)
			}
		})
	}
}
