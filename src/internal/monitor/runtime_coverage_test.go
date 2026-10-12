package monitor

import (
	"context"
	"errors"
	"math"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestRuntimeHandlesPanicEvidenceAndRegistrarMismatch(t *testing.T) {
	state := newTestCheckState()
	domain := DomainConfig{Domain: "example.com", Name: "Example", Email: &EmailConfig{}}
	evaluateFastDomainChecks(nil, domain, domainEvidence{panicText: "failed to gather"}, state)
	require.Equal(t, StatusFailed, state.Email[domain.Domain].Status)
	result := evaluateRDAPCheck(DomainConfig{Domain: "example.com", Registrar: "123"}, RDAPSnapshot{Expiration: "2099-01-01T00:00:00Z", RegistrarIANAID: "456"})
	require.True(t, result.RegistrarMismatch)
	require.Equal(t, StrIANA+"123", result.ExpectedRegistrar)
}

func TestRuntimeSkipsExpiredDependenciesAndHandlesNilClock(t *testing.T) {
	cfg := AppConfig{Domains: []DomainConfig{{Domain: "expired.example", AllowExpiry: true}, {Domain: "active.example"}}, DNSRecords: []DNSTask{{Hostname: "a.expired.example"}, {Hostname: "a.active.example"}}}
	app := NewAppState(cfg)
	active := activeChecksForCycleWithExpired(app, cfg, stringSet{"expired.example": {}})
	require.Equal(t, []int{1}, active.domains)
	require.Equal(t, []int{1}, active.dnsRecords)
	require.NotNil(t, nextExpiredDomains(nil, cfg, newCycleState(cfg, activeChecks{})))
	emptyApp := NewAppState(AppConfig{})
	emptyApp.Clock = nil
	emptyApp.Notifier = nil
	state := runMonitoringCycle(context.Background(), emptyApp, nil, nil, nil, nil, nil)
	require.NotNil(t, state)
}

func TestRuntimeNotificationWorkerClosesOnCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	wake := make(chan struct{})
	done := make(chan struct{})
	go runNotificationWorker(ctx, nil, wake, done)
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("worker did not exit")
	}
	flushNotifier(context.Background(), nil)
	app := &AppState{}
	publishCycleFailure(app, CycleMetadata{Outcome: CycleOutcomeFailed})
}

func TestHTTPServerReportsOccupiedPortAndUsesDefaultPort(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = listener.Close() }()
	port := strconv.Itoa(listener.Addr().(*net.TCPAddr).Port)
	_, failure := setupHTTPServer(&AppState{}, port)
	select {
	case err := <-failure:
		require.Error(t, err)
	case <-time.After(time.Second):
		t.Fatal("occupied port did not report startup failure")
	}
	server, _ := setupHTTPServer(&AppState{}, " ")
	require.Equal(t, ":"+DefaultServerPort, server.Addr)
	require.NoError(t, server.Shutdown(context.Background()))
}

func TestRuntimePanicRecoveryForNetworkEvidence(t *testing.T) {
	app := NewAppState(AppConfig{Resolvers: []string{"192.0.2.53"}})
	app.DNSClient = &MockDNSResolver{MockExchangeContext: func(context.Context, *dns.Msg, string) (*dns.Msg, time.Duration, error) {
		panic("synthetic resolver panic")
	}}
	dnsSnapshot := gatherDNSEvidence(context.Background(), app, DNSTask{Name: "A", Hostname: "example.com", Type: RecordTypeA})
	require.ErrorContains(t, dnsSnapshot.Err, StrInternalDNSCheckPanic)
	domainEvidence := gatherDomainEvidence(context.Background(), app, DomainConfig{Domain: "example.com", Email: &EmailConfig{}})
	require.NotEmpty(t, domainEvidence.panicText)
}

func TestRuntimeEvaluationRecoversInjectedPanics(t *testing.T) {
	record := DNSTask{Name: "web", Hostname: "example.com", Type: RecordTypeA}
	dnsResult := evaluateDNSCheckWith(record, DNSSnapshot{}, func(DNSTask, DNSSnapshot) (CheckStatus, StateCondition) {
		panic("DNS evaluation failed")
	})
	require.Equal(t, StatusFailed, dnsResult.State.Status)
	require.Equal(t, StrInternalDNSCheckPanic, dnsResult.State.Error)

	domain := DomainConfig{Domain: "example.com", Email: &EmailConfig{}}
	state := newTestCheckState()
	evaluateFastDomainChecksWithEmail(nil, domain, domainEvidence{}, state, func(DomainConfig, EmailSnapshot, map[string]ProviderConfig) (CheckStatus, StateCondition, EmailState) {
		panic("email evaluation failed")
	})
	require.Equal(t, StatusFailed, state.Email[domain.Domain].Status)

	rdap := evaluateRDAPCheckWith(domain, RDAPSnapshot{}, func(DomainConfig, RDAPSnapshot) (CheckStatus, StateCondition) {
		panic("RDAP evaluation failed")
	})
	require.Equal(t, StatusFailed, rdap.Status)
	require.Equal(t, StrInternalRDAPCheckPanic, rdap.Error)
}

func TestMonitoringCycleRecordsEmailAndRejectsUnencodableState(t *testing.T) {
	emailApp := NewAppState(AppConfig{Resolvers: []string{"192.0.2.53"}, Domains: []DomainConfig{{Domain: "example.com", Email: &EmailConfig{}}}})
	emailApp.Bootstrap = nil
	emailApp.WHOISDial = nil
	emailApp.DNSClient = &MockDNSResolver{MockExchangeContext: func(_ context.Context, q *dns.Msg, _ string) (*dns.Msg, time.Duration, error) {
		response := new(dns.Msg)
		response.SetReply(q)
		return response, 0, nil
	}}
	state := runMonitoringCycle(context.Background(), emailApp, nil, nil, nil, nil, nil)
	require.NotNil(t, state)
	require.Contains(t, state.Email, "example.com")

	invalidApp := NewAppState(AppConfig{Domains: []DomainConfig{{Domain: "example.com", RenewalPrice: math.NaN()}}})
	invalidApp.Bootstrap = nil
	invalidApp.WHOISDial = nil
	state = runMonitoringCycle(context.Background(), invalidApp, nil, nil, nil, nil, nil)
	require.Nil(t, state)
	_, published := invalidApp.PublishedJSON()
	require.False(t, published)
}

func TestMainAndRunInitializationPaths(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := strconv.Itoa(listener.Addr().(*net.TCPAddr).Port)
	require.NoError(t, listener.Close())
	configPath := filepath.Join(t.TempDir(), "config.json")
	require.NoError(t, os.WriteFile(configPath, []byte(`{"port":"`+port+`","domains":[],"dns_records":[]}`), 0600))
	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Millisecond)
	defer cancel()
	require.Zero(t, mainExitCode(ctx, configPath))

	err = runWithInitialize(context.Background(), configPath, func(context.Context, AppConfig) (*AppState, error) {
		return nil, errors.New("injected initialization failure")
	})
	require.ErrorContains(t, err, "injected initialization failure")

	ctx, cancel = context.WithTimeout(context.Background(), 75*time.Millisecond)
	defer cancel()
	err = runWithInitialize(ctx, configPath, func(_ context.Context, config AppConfig) (*AppState, error) {
		app := NewAppState(config)
		app.Bootstrap = nil
		app.WHOISDial = nil
		app.Clients.RDAP = nil
		app.Clock = nil
		app.LoopDuration = 0
		return app, nil
	})
	require.NoError(t, err)
}

type panicClock struct{}

func (panicClock) Now() time.Time               { panic("clock unavailable") }
func (panicClock) NewTimer(time.Duration) Timer { panic("unexpected timer") }

func TestRunReportsServerAndEngineFailure(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := strconv.Itoa(listener.Addr().(*net.TCPAddr).Port)
	configPath := filepath.Join(t.TempDir(), "config.json")
	require.NoError(t, os.WriteFile(configPath, []byte(`{"port":"`+port+`","domains":[],"dns_records":[]}`), 0600))
	err = runWithInitialize(context.Background(), configPath, func(_ context.Context, cfg AppConfig) (*AppState, error) {
		return NewAppState(cfg), nil
	})
	require.ErrorContains(t, err, "HTTP server")
	require.NoError(t, listener.Close())

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err = runWithInitialize(ctx, configPath, func(_ context.Context, cfg AppConfig) (*AppState, error) {
		app := NewAppState(cfg)
		app.Clock = panicClock{}
		return app, nil
	})
	require.ErrorContains(t, err, NameOpMonitoringEngine)
}

func TestMonitoringCyclePublishesDeadlineAtBothStages(t *testing.T) {
	for _, stage := range []string{"gather", "evaluate"} {
		t.Run(stage, func(t *testing.T) {
			app := NewAppState(AppConfig{})
			app.PublishInitialState()
			var cycleCtx context.Context
			hooks := cycleHooks{timeout: time.Millisecond}
			hooks.gather = func(ctx context.Context, _ *AppState, _ AppConfig, _ HTTPDoer) (activeChecks, cycleEvidence) {
				cycleCtx = ctx
				if stage == "gather" {
					<-ctx.Done()
				}
				return activeChecks{}, cycleEvidence{}
			}
			hooks.evaluate = func(_ map[string]ProviderConfig, cfg AppConfig, active activeChecks, _ cycleEvidence) *CheckState {
				if stage == "evaluate" {
					<-cycleCtx.Done()
				}
				return newCycleState(cfg, active)
			}
			state := runMonitoringCycleWithHooks(context.Background(), app, nil, nil, nil, nil, nil, hooks)
			require.Nil(t, state)
			body, ok := app.PublishedJSON()
			require.True(t, ok)
			require.Contains(t, string(body), string(CycleOutcomeFailed))
		})
	}
}

type coverageTimer struct{ channel <-chan time.Time }

func (timer coverageTimer) C() <-chan time.Time { return timer.channel }
func (coverageTimer) Stop() bool                { return true }

type coverageClock struct {
	mu      sync.Mutex
	created int
	started <-chan struct{}
}

func (clock *coverageClock) Now() time.Time { return time.Now() }
func (clock *coverageClock) NewTimer(time.Duration) Timer {
	clock.mu.Lock()
	clock.created++
	index := clock.created
	clock.mu.Unlock()
	channel := make(chan time.Time, 1)
	if index == 1 {
		go func() { <-clock.started; channel <- time.Now() }()
	} else if index == 2 {
		channel <- time.Now()
	}
	return coverageTimer{channel: channel}
}

type blockingCoverageNotifier struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (*blockingCoverageNotifier) Dispatch(string, string, AlertPriority, AlertTag, string, string) {}
func (notifier *blockingCoverageNotifier) FlushContext(context.Context) {
	notifier.once.Do(func() { close(notifier.started) })
	<-notifier.release
}

func TestRunCoalescesNotificationWakeupsAndTimesOutBlockedWorker(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := strconv.Itoa(listener.Addr().(*net.TCPAddr).Port)
	require.NoError(t, listener.Close())
	configPath := filepath.Join(t.TempDir(), "config.json")
	require.NoError(t, os.WriteFile(configPath, []byte(`{"port":"`+port+`","domains":[],"dns_records":[]}`), 0600))
	notifier := &blockingCoverageNotifier{started: make(chan struct{}), release: make(chan struct{})}
	clock := &coverageClock{started: notifier.started}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	cycles := 0
	hooks := lifecycleHooks{setup: setupHTTPServer, shutdownTimeout: time.Second, engineWait: time.Second, notificationWait: time.Millisecond}
	hooks.cycle = func(context.Context, *AppState, HTTPDoer, map[string]CheckStatus, map[string]CheckStatus, map[string]CheckStatus, map[conditionKey]StateCondition) *CheckState {
		cycles++
		if cycles == 3 {
			cancel()
		}
		return nil
	}
	err = runWithLifecycleHooks(ctx, configPath, func(_ context.Context, cfg AppConfig) (*AppState, error) {
		app := NewAppState(cfg)
		app.Notifier = notifier
		app.Clock = clock
		return app, nil
	}, hooks)
	close(notifier.release)
	require.NoError(t, err)
	require.Equal(t, 3, cycles)
	clock.mu.Lock()
	require.GreaterOrEqual(t, clock.created, 2)
	clock.mu.Unlock()
}

func TestRunCancelsNotificationWorkerAfterEngineTimeout(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := strconv.Itoa(listener.Addr().(*net.TCPAddr).Port)
	require.NoError(t, listener.Close())
	configPath := filepath.Join(t.TempDir(), "config.json")
	require.NoError(t, os.WriteFile(configPath, []byte(`{"port":"`+port+`","domains":[],"dns_records":[]}`), 0600))
	started := make(chan struct{})
	release := make(chan struct{})
	finished := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	hooks := lifecycleHooks{setup: setupHTTPServer, shutdownTimeout: time.Second, engineWait: time.Millisecond, notificationWait: time.Second}
	hooks.cycle = func(context.Context, *AppState, HTTPDoer, map[string]CheckStatus, map[string]CheckStatus, map[string]CheckStatus, map[conditionKey]StateCondition) *CheckState {
		close(started)
		<-release
		close(finished)
		return nil
	}
	result := make(chan error, 1)
	go func() {
		result <- runWithLifecycleHooks(ctx, configPath, InitializeApp, hooks)
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("monitoring engine did not start")
	}
	cancel()
	select {
	case err := <-result:
		require.ErrorContains(t, err, MsgErrMonitoringEngineShutdownTimeout)
	case <-time.After(time.Second):
		t.Fatal("shutdown did not respect engine timeout")
	}
	close(release)
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("released engine did not finish")
	}
}

func TestRunReportsHTTPShutdownDeadline(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.json")
	require.NoError(t, os.WriteFile(configPath, []byte(`{"port":"8081","domains":[],"dns_records":[]}`), 0600))
	started := make(chan struct{})
	release := make(chan struct{})
	requestDone := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	hooks := lifecycleHooks{shutdownTimeout: time.Millisecond, engineWait: time.Second, notificationWait: time.Second}
	hooks.setup = func(*AppState, string) (*http.Server, <-chan error) {
		server := &http.Server{Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			close(started)
			<-release
		})}
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		go func() { _ = server.Serve(listener) }()
		go func() {
			defer close(requestDone)
			response, err := http.Get("http://" + listener.Addr().String())
			if err == nil {
				_ = response.Body.Close()
			}
		}()
		return server, make(chan error)
	}
	hooks.cycle = func(context.Context, *AppState, HTTPDoer, map[string]CheckStatus, map[string]CheckStatus, map[string]CheckStatus, map[conditionKey]StateCondition) *CheckState {
		<-started
		cancel()
		return nil
	}
	err := runWithLifecycleHooks(ctx, configPath, InitializeApp, hooks)
	close(release)
	select {
	case <-requestDone:
	case <-time.After(time.Second):
		t.Fatal("request did not finish")
	}
	require.ErrorContains(t, err, "context deadline exceeded")
}

func TestRuntimeHelpersHandleEmptyAndExtremeWorkloads(t *testing.T) {
	runBoundedChecks(0, func(int) { t.Fatal("zero work must not run") })
	require.Equal(t, time.Second, saturatingWorkDuration(0, time.Second, time.Second))
	require.Equal(t, time.Second, saturatingWorkDuration(1, 0, time.Second))
	require.Equal(t, time.Duration(math.MaxInt64), saturatingWorkDuration(math.MaxInt, time.Hour, time.Second))
	require.Equal(t, time.Duration(3*time.Second), saturatingWorkDuration(2, time.Second, time.Second))
}

func TestStateTransitionsDropRemovedChecksAndIgnoreUnknown(t *testing.T) {
	previous := map[string]CheckStatus{"gone": StatusFailed, "removed": StatusOK}
	current := map[string]CheckStatus{"gone": StatusOK, "unknown": StatusUnknown}
	logStateTransitions("DNS", "record", current, func(status CheckStatus) CheckStatus { return status }, previous)
	require.Equal(t, map[string]CheckStatus{"gone": StatusOK}, previous)
}

func TestCAAResultPreservesKnownAndUnknownAuthorities(t *testing.T) {
	state := &CheckState{DNS: make(map[string]DNSState), CAA: make(map[string]CAAResult)}
	storeDNSResult(state, DNSResult{Name: InternalCAATaskPrefix + "example.com", State: DNSState{
		Status:   StatusMismatch,
		Expected: []string{"0 issue \"known.example\""},
		Found: []string{
			"0 issue \"known.example\"", "0 issue \"unknown.example\"",
			"0 issuewild \"wild.example\"", "0 issuemail \"mail.example\"", "malformed",
		},
	}})
	require.Empty(t, state.DNS)
	result := state.CAA["example.com"]
	require.Equal(t, []string{"known.example", "unknown.example"}, result.Issue)
	require.Equal(t, []string{"wild.example"}, result.IssueWild)
	require.Equal(t, []string{"mail.example"}, result.IssueMail)
	require.Equal(t, []string{"unknown.example", "wild.example", "mail.example", "malformed"}, result.UnknownCAs)
}

func TestFailedCyclePublicationKeepsLastValidState(t *testing.T) {
	app := &AppState{LoopDuration: time.Minute}
	storePublishedState(app, []byte("invalid JSON"))
	publishCycleFailure(app, CycleMetadata{Outcome: CycleOutcomeFailed})
	body, ok := app.PublishedJSON()
	require.True(t, ok)
	require.Equal(t, "invalid JSON", string(body))
}

func TestAdditionalFindingAlertsSkipPrimaryAndRespectWarning(t *testing.T) {
	primary := StateCondition{Code: CodeDNSLookupFailed, Target: "primary", Since: time.Now()}
	findings := []Finding{
		{Code: CodeDNSLookupFailed, Target: "primary"},
		{Code: CodeDNSMismatch, Target: "secondary"},
	}
	alerts := appendAdditionalFindingAlerts(nil, findings, primary, "Example", "example.com", CheckTypeEmail, StatusWarning, false)
	require.Len(t, alerts, 1)
	require.Equal(t, PriorityWarning, alerts[0].Priority)
	require.True(t, strings.Contains(alerts[0].Message, "secondary"))
	require.False(t, strings.Contains(alerts[0].Redacted, "secondary"))
	require.Empty(t, appendAdditionalFindingAlerts(nil, findings, primary, "Example", "example.com", CheckTypeEmail, StatusWarning, true))
}
