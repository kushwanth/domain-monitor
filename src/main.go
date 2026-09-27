package main

import (
	"context"
	_ "embed"
	jsonv2 "encoding/json/v2"
	"errors"
	"flag"
	"fmt"
	"maps"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sync/errgroup"
)

//go:embed index.html
var indexHTML []byte

func securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(HeaderXContentTypeOptions, XContentTypeOptionsNosniff)
		w.Header().Set(HeaderXFrameOptions, XFrameOptionsDeny)
		w.Header().Set(HeaderReferrerPolicy, ReferrerPolicyStrictOrigin)
		w.Header().Set(HeaderXXSSProtection, XXSSProtectionZero)
		w.Header().Set(HeaderContentSecurityPolicy, DefaultCSP)
		next.ServeHTTP(w, r)
	})
}

func setupHTTPServer(app *AppState, port string) (*http.Server, <-chan error) {
	mux := http.NewServeMux()

	mux.HandleFunc(RouteHealth, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(HeaderContentType, MIMEApplicationJSON)
		_, _ = w.Write([]byte(JSONResponseStatusOK))
	})

	mux.HandleFunc(RouteAPIState, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(HeaderContentType, MIMEApplicationJSON)
		w.Header().Set(HeaderCacheControl, CacheControlNoCache)
		if app != nil {
			if b, ok := app.PrerenderedJSON.Load().([]byte); ok {
				_, _ = w.Write(b)
				return
			}
		}
		_, _ = w.Write([]byte(JSONResponseStatusInit))
	})

	mux.HandleFunc(SymSlash, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != SymSlash {
			http.NotFound(w, r)
			return
		}
		w.Header().Set(HeaderContentType, MIMETextHTML)
		_, _ = w.Write(indexHTML)
	})

	cleanPort := strings.TrimPrefix(strings.TrimSpace(port), SymColon)
	if cleanPort == StrEmpty {
		cleanPort = DefaultServerPort
	}

	server := &http.Server{
		Addr:                SymColon + cleanPort,
		Handler:             securityHeadersMiddleware(mux),
		ReadTimeout:         DefaultDNSTimeout,
		ReadHeaderTimeout:   DefaultDNSTimeout,
		WriteTimeout:        DefaultHTTPTimeout,
		IdleTimeout:         DefaultIdleTimeout,
		MaxHeaderValueCount: DefaultMaxHeaderValueCount,
	}

	errChan := make(chan error, 1)
	go func() {
		LogInfof(MsgLogHTTPAPI, cleanPort)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			LogError(MsgLogHTTPServerFailed, FieldError, err)
			errChan <- err
		}
	}()

	return server, errChan
}

// logStateTransitions logs changes in check status across cycles in deterministic sorted order.
func logStateTransitions[T any](checkName, targetKey string, current map[string]T, getStatus func(T) CheckStatus, prev map[string]CheckStatus) {
	for _, k := range slices.Sorted(maps.Keys(current)) {
		item := current[k]
		currStatus := getStatus(item)
		if currStatus == StatusUnknown {
			continue
		}
		if prevStatus, ok := prev[k]; ok && prevStatus != currStatus {
			LogInfo(MsgLogStateTransition, FieldCheck, checkName, targetKey, k, FieldPrev, prevStatus, FieldCurrent, currStatus)
		}
		prev[k] = currStatus
	}
	for k := range prev {
		if _, ok := current[k]; !ok {
			delete(prev, k)
		}
	}
}

func executeDNSChecks(ctx context.Context, app *AppState, dnsRecords []DNSTask) []DNSResult {
	dnsResults := make([]DNSResult, len(dnsRecords))
	gDNS, _ := errgroup.WithContext(ctx)
	gDNS.SetLimit(min(len(dnsRecords), DefaultMaxConcurrency))
	for i, dnsTask := range dnsRecords {
		record := dnsTask
		index := i
		gDNS.Go(func() error {
			defer func() {
				if r := recover(); r != nil {
					LogError(MsgLogPanicDNSWorker, FieldRecord, record.Name, FieldPanic, r)
					dnsResults[index] = DNSResult{
						Name: record.Name,
						State: DNSState{
							Hostname:  record.Hostname,
							Name:      record.Name,
							Type:      record.Type,
							Expected:  slices.Clone(record.Expected),
							Status:    StatusFailed,
							Error:     fmt.Sprintf(MsgErrInternalDNSCheckPanic, AnyToString(r)),
							Condition: &StateCondition{Code: CodeDNSLookupFailed, Target: StrInternalDNSCheckPanic},
						},
					}
				}
			}()
			dnsSnap := FetchDNSSnapshot(ctx, app, record)
			status, cond := EvaluateDNS(record, dnsSnap)

			errStr := StrEmpty
			if cond != nil && cond.Code != CodeDNSMatchVerified {
				errStr = cond.Target
			}

			res := DNSState{
				Hostname:  record.Hostname,
				Name:      record.Name,
				Type:      record.Type,
				Expected:  slices.Clone(record.Expected),
				Status:    status,
				Condition: cond,
				Found:     dnsSnap.Records,
				Error:     errStr,
			}
			dnsResults[index] = DNSResult{Name: record.Name, State: res}
			return nil
		})
	}
	_ = gDNS.Wait()
	return dnsResults
}

func executeFastDomainChecks(ctx context.Context, app *AppState, domains []DomainConfig) []DomainResult {
	domainResults := make([]DomainResult, len(domains))
	gDomains, _ := errgroup.WithContext(ctx)
	gDomains.SetLimit(min(len(domains), DefaultMaxConcurrency))

	for i, domainConfig := range domains {
		domain := domainConfig
		index := i
		domainResults[index].Domain = domain.Domain
		gDomains.Go(func() error {
			defer func() {
				if r := recover(); r != nil {
					LogError(MsgLogPanicDomainWorker, FieldDomain, domain.Domain, FieldPanic, r)
					fillPanicDomainResults(domain, &domainResults[index], r)
				}
			}()
			res := &domainResults[index]

			emailSnap := FetchEmailSnapshot(ctx, app, domain)
			_, cond, emailState := EvaluateEmailSecurity(domain, emailSnap, app)
			emailState.Condition = cond
			res.Email = emailState

			if domain.IsDelegatedZone {
				snapshot := FetchNSDelegationSnapshot(ctx, app, domain)
				status, cond := EvaluateNSDelegation(domain, snapshot)
				res.RDAP = RDAPState{
					Status:          status,
					Condition:       cond,
					IsDelegatedZone: true,
					Source:          SourceDNSDelegation,
					AllowExpiry:     domain.AllowExpiry,
					Nameservers:     snapshot.Nameservers,
				}
			}

			{
				dnssecSnap := FetchDNSSECSnapshot(ctx, app, domain)
				dnssecStatus, dnssecCond, dnssecRes := EvaluateDNSSEC(domain, dnssecSnap)
				dnssecRes.Status = dnssecStatus
				dnssecRes.Condition = dnssecCond
				res.DNSSEC = dnssecRes

				if domain.VerifyNSHealth && len(domain.ExpectedNS) > 0 {
					snapshots := FetchNSHealthSnapshots(ctx, app, domain)
					status, nsCond := EvaluateNSHealth(domain, snapshots)

					var servers []NSHealthServerResult
					for idx, srvSnap := range snapshots {
						errStr := StrEmpty
						if combined := errors.Join(srvSnap.Err, srvSnap.PartialError, srvSnap.DNSKEYErr); combined != nil {
							errStr = combined.Error()
						}
						dnskeyMatch := true
						if idx > 0 {
							if len(snapshots[0].DNSKEYs) > 0 || len(srvSnap.DNSKEYs) > 0 {
								dnskeyMatch = slices.Equal(snapshots[0].DNSKEYs, srvSnap.DNSKEYs)
							}
						}
						servers = append(servers, NSHealthServerResult{
							Nameserver:    srvSnap.Nameserver,
							IsPrimary:     srvSnap.IsPrimary,
							Authoritative: srvSnap.Authoritative,
							HasSOA:        srvSnap.HasSOA,
							SOASerial:     srvSnap.SOASerial,
							HasDNSKEY:     srvSnap.HasDNSKEY,
							DNSKEYMatch:   dnskeyMatch,
							Error:         errStr,
						})
					}

					res.NSHealth = NSHealthResult{
						Valid:     status != StatusFailed,
						Primary:   domain.ExpectedNS[0],
						Status:    status,
						Condition: nsCond,
						Servers:   servers,
					}
				}
			}

			return nil
		})
	}
	_ = gDomains.Wait()
	return domainResults
}

func fillPanicDomainResults(domain DomainConfig, res *DomainResult, recovered any) {
	message := fmt.Sprintf(MsgErrDomainCheckPanic, AnyToString(recovered))
	if domain.CheckEmailSecurity && res.Email.Status == StatusUnknown {
		res.Email = EmailState{Status: StatusFailed, Error: message, Condition: &StateCondition{Code: CodeDNSLookupFailed, Target: message}}
	}
	if domain.IsDelegatedZone && res.RDAP.Status == StatusUnknown {
		res.RDAP = RDAPState{Status: StatusFailed, Error: message, IsDelegatedZone: true, Condition: &StateCondition{Code: CodeRDAPHTTPError, Target: message}}
	}
	if domain.DNSSEC && res.DNSSEC.Status == StatusUnknown {
		res.DNSSEC = DNSSECResult{Status: StatusFailed, Error: message, Condition: &StateCondition{Code: CodeDNSSECNetworkError, Target: message}}
	}

	if domain.VerifyNSHealth && res.NSHealth.Status == StatusUnknown {
		res.NSHealth = NSHealthResult{Status: StatusFailed, Condition: &StateCondition{Code: CodeNSUnreachable, Target: message}}
	}
}

func executeRateLimitedChecks(
	ctx context.Context,
	app *AppState,
	domains []DomainConfig,
	rdapHTTPClient *http.Client,
) []RDAPState {
	rdapResults := make([]RDAPState, len(domains))

	gRateLimitedChecks, _ := errgroup.WithContext(ctx)

	// RDAP pipeline: evaluates non-delegated zones with 10s token bucket
	gRateLimitedChecks.Go(func() error {
		defer RecoverAndLogPanic(NameOpRDAPCheckWorker)
		for i, domainConfig := range domains {
			if domainConfig.IsDelegatedZone {
				continue
			}
			func() {
				defer func() {
					if r := recover(); r != nil {
						LogError(MsgLogPanicRDAP, FieldDomain, domainConfig.Domain, FieldPanic, r)
						rdapResults[i] = RDAPState{
							Status:    StatusFailed,
							Error:     fmt.Sprintf(MsgErrInternalRDAPCheckPanic, AnyToString(r)),
							Condition: &StateCondition{Code: CodeRDAPHTTPError, Target: StrInternalRDAPCheckPanic},
						}
					}
				}()

				snapshot := FetchRDAPSnapshot(ctx, rdapHTTPClient, app, domainConfig.Domain)
				status, cond := EvaluateRDAP(domainConfig, snapshot)

				rdapState := RDAPState{
					Status:          status,
					Condition:       cond,
					Registrar:       snapshot.Registrar,
					RegistrarIANAID: snapshot.RegistrarIANAID,
					Expiration:      snapshot.Expiration,
					Nameservers:     snapshot.Nameservers,
					DomainStatus:    snapshot.DomainStatus,
					DNSSEC:          snapshot.DNSSEC,
					RenewalPrice:    domainConfig.RenewalPrice,
					AllowExpiry:     domainConfig.AllowExpiry,
					Source:          snapshot.Source,
					ProtocolUsed:    snapshot.ProtocolUsed,
					QueryDurationMs: snapshot.QueryDurationMs,
					RegistryTier:    snapshot.RegistryTier,
					RegistrarTier:   snapshot.RegistrarTier,
					Discrepancies:   snapshot.Discrepancies,
				}

				if snapshot.Err != nil {
					rdapState.Error = snapshot.Err.Error()
				}

				if cond != nil && cond.Code == CodeRDAPRegistrarMismatch {
					rdapState.RegistrarMismatch = true
					rdapState.ExpectedRegistrar = cond.Target
				}

				rdapResults[i] = rdapState
			}()
		}
		return nil
	})

	_ = gRateLimitedChecks.Wait()
	return rdapResults
}

func runMonitoringCycle(
	ctx context.Context,
	app *AppState,
	rdapHTTPClient *http.Client,
	prevRDAPStatus map[string]CheckStatus,
	prevDNSStatus map[string]CheckStatus,
	prevEmailStatus map[string]CheckStatus,
	prevConditions map[string]StateCondition,
) *CheckState {
	cycleStart := time.Now()

	loopDur := DefaultLoopDurationFallback
	if app != nil && app.LoopDuration > 0 {
		loopDur = app.LoopDuration
	}

	var domains []DomainConfig
	var dnsRecords []DNSTask
	if app != nil {
		cfg := app.configuration()
		domains = cfg.Domains
		dnsRecords = cfg.DNSRecords
	}

	// Bound cycle timeout safely: scale with domain and DNS record counts so large portfolios
	// have sufficient time for rate-limited RDAP requests and retries without hanging indefinitely.
	minRequiredTimeout := time.Duration(len(domains))*(10+5)*time.Second + time.Duration(len(dnsRecords))*5*time.Second + 5*time.Minute
	cycleMaxTimeout := max(loopDur, minRequiredTimeout, 5*time.Minute)
	cycleCtx, cycleCancel := context.WithTimeout(ctx, cycleMaxTimeout)
	defer cycleCancel()

	if prevRDAPStatus == nil {
		prevRDAPStatus = make(map[string]CheckStatus)
	}
	if prevDNSStatus == nil {
		prevDNSStatus = make(map[string]CheckStatus)
	}
	if prevEmailStatus == nil {
		prevEmailStatus = make(map[string]CheckStatus)
	}
	if prevConditions == nil {
		prevConditions = make(map[string]StateCondition)
	}

	loopState := prepareCycleState(domains)

	// 1. Dispatch DNS Records
	dnsResults := executeDNSChecks(cycleCtx, app, dnsRecords)

	// 2. Dispatch Fast Domain Checks (Email, DNSSEC, NS Health, NS Delegation)
	domainResults := executeFastDomainChecks(cycleCtx, app, domains)

	// 3. Dispatch Slow, Rate-Limited External Checks (RDAP)
	rdapResults := executeRateLimitedChecks(cycleCtx, app, domains, rdapHTTPClient)

	for i := range domains {
		if rdapResults[i].Status != StatusUnknown {
			domainResults[i].RDAP = rdapResults[i]
		}
	}

	// 4. Assemble CheckState using clean helper methods
	for _, res := range dnsResults {
		if strings.HasPrefix(res.Name, "__caa__") {
			domainName := strings.TrimPrefix(res.Name, "__caa__")

			caaRes := CAAResult{
				Status:    res.State.Status,
				Condition: res.State.Condition,
				Valid:     res.State.Status == StatusOK,
				Error:     res.State.Error,
			}

			expectedSet := make(map[string]bool)
			for _, exp := range res.State.Expected {
				expectedSet[exp] = true
			}

			for _, rec := range res.State.Found {
				parts := strings.SplitN(rec, " ", 3)
				if len(parts) == 3 {
					tag := strings.ToLower(parts[1])
					val := strings.Trim(parts[2], `"`)
					switch tag {
					case "issue":
						caaRes.Issue = append(caaRes.Issue, val)
					case "issuewild":
						caaRes.IssueWild = append(caaRes.IssueWild, val)
					case "issuemail":
						caaRes.IssueMail = append(caaRes.IssueMail, val)
					}
				}

				if !caaRes.Valid && !expectedSet[rec] {
					if len(parts) == 3 {
						caaRes.UnknownCAs = append(caaRes.UnknownCAs, strings.Trim(parts[2], `"`))
					} else {
						caaRes.UnknownCAs = append(caaRes.UnknownCAs, rec)
					}
				}
			}

			// We assign it here, but it doesn't get added to loopState.DNS!
			// So it won't trigger DNS alerts. It will trigger CAA alerts since we add it to CAA.
			InitMap(&loopState.CAA)[domainName] = &caaRes
			continue
		}

		loopState.ApplyDNSResult(res)
	}
	for _, res := range domainResults {
		loopState.ApplyDomainResult(res)
	}

	computePortfolioPricing(cycleCtx, app, loopState, app.Pricing)

	// 5. State transition logging
	logStateTransitions(CheckTypeRDAP, TargetKeyDomain, loopState.RDAP, func(s RDAPState) CheckStatus { return s.Status }, prevRDAPStatus)
	logStateTransitions(CheckTypeDNS, TargetKeyRecord, loopState.DNS, func(s DNSState) CheckStatus { return s.Status }, prevDNSStatus)
	logStateTransitions(CheckTypeEmail, TargetKeyDomain, loopState.Email, func(s EmailState) CheckStatus { return s.Status }, prevEmailStatus)

	// 6. Track Since Timestamps and Dispatch Cycle Report
	processConditionsAndAlerts(app, loopState, domains, dnsRecords, prevConditions)

	// 7. Update timestamps and pre-render atomic JSON cache
	loopState.LastUpdated = time.Now().UTC().Format(time.RFC3339)
	publishCycleState(app, loopState, loopDur)
	if app != nil && app.Notifier != nil {
		if notifier, ok := app.Notifier.(interface{ FlushContext(context.Context) }); ok {
			notifier.FlushContext(cycleCtx)
		} else {
			app.Notifier.Flush()
		}
	}

	cycleDuration := time.Since(cycleStart)
	LogInfo(MsgLogMonitoringCycleCompleted,
		FieldDurationMS, cycleDuration.Milliseconds(),
		FieldDomainsChecked, len(domains),
		FieldDNSRecordsChecked, len(dnsRecords),
	)

	return loopState
}

func publishCycleState(app *AppState, state *CheckState, loopDur time.Duration) {
	state.NextRefresh = time.Now().Add(loopDur).UTC().Format(time.RFC3339)
	if app == nil {
		return
	}
	encoded, err := jsonv2.Marshal(state)
	if err != nil {
		LogWarn(MsgLogStateMarshalFailed, FieldError, err)
		return
	}
	app.PrerenderedJSON.Store(encoded)
}

func prepareCycleState(domains []DomainConfig) *CheckState {
	state := NewCheckState()
	for _, domain := range domains {
		state.RDAP[domain.Domain] = RDAPState{Status: StatusPending}
	}
	return state
}

func applyConditionSince(cond *StateCondition, key string, prev map[string]StateCondition) {
	if cond == nil {
		return
	}
	prevCond, exists := prev[key]
	if exists && prevCond.Code == cond.Code {
		cond.Since = prevCond.Since
	} else {
		cond.Since = time.Now().UTC()
	}
	// History needs only the code and start time, not prior diagnostic text.
	prev[key] = StateCondition{Code: cond.Code, Since: cond.Since}
}

func formatDurationSince(since time.Time) string {
	d := time.Since(since).Round(time.Minute)
	if d < time.Minute {
		return StrJustNow
	}
	return d.String()
}

func processConditionsAndAlerts(app *AppState, state *CheckState, domains []DomainConfig, dnsRecords []DNSTask, prev map[string]StateCondition) {
	if app == nil || state == nil {
		return
	}
	var cycleAlerts []Alert
	active := make(map[string]bool)
	for _, domainCfg := range domains {
		cycleAlerts = append(cycleAlerts, collectDomainAlerts(app, state, domainCfg, prev, active)...)
	}
	for _, dnsCfg := range dnsRecords {
		name := dnsCfg.Name
		if st, ok := state.DNS[name]; ok {
			cycleAlerts = appendConditionAlert(cycleAlerts, name, name, CheckTypeDNS, st.Condition, st.Status, false, prev, active)
		}
	}
	if notifier, ok := app.Notifier.(interface{ RetainIdentities(map[string]bool) }); ok {
		notifier.RetainIdentities(active)
	}
	dispatchCycleAlerts(app, cycleAlerts)
}

func appendConditionAlert(alerts []Alert, name, domain, check string, cond *StateCondition, status CheckStatus, suppress bool, prev map[string]StateCondition, active map[string]bool) []Alert {
	key := check + SymColon + domain
	if cond == nil || (status != StatusFailed && status != StatusMismatch && status != StatusHijacked && status != StatusWarning) {
		delete(prev, key)
		return alerts
	}
	applyConditionSince(cond, key, prev)
	if suppress {
		return alerts
	}
	identity := key + SymColon + cond.Code.String() + SymColon + status.String()
	active[identity] = true
	priority := PriorityWarning
	if status != StatusWarning {
		priority = PriorityHigh
	}
	message := fmt.Sprintf(AlertConditionFormat, check, status, cond.Code, cond.Target, formatDurationSince(cond.Since))
	redacted := fmt.Sprintf(AlertConditionRedactedFormat, check, status, cond.Code, formatDurationSince(cond.Since))
	return append(alerts, Alert{Message: message, Redacted: redacted, Identity: identity, Priority: priority, Tag: TagSkull, Domain: domain, Name: name})
}

func collectDomainAlerts(app *AppState, state *CheckState, cfg DomainConfig, prev map[string]StateCondition, active map[string]bool) []Alert {
	var alerts []Alert
	domain, name, suppress := cfg.Domain, cfg.Name, cfg.SuppressAlerts
	if st, ok := state.RDAP[domain]; ok {
		alerts = appendConditionAlert(alerts, name, domain, CheckTypeRDAP, st.Condition, st.Status, suppress, prev, active)
	}
	if st, ok := state.Email[domain]; ok {
		alerts = appendConditionAlert(alerts, name, domain, CheckTypeEmail, st.Condition, st.Status, suppress, prev, active)
	}
	if st, ok := state.CAA[domain]; ok && st != nil {
		alerts = appendConditionAlert(alerts, name, domain, CheckTypeCAA, st.Condition, st.Status, suppress, prev, active)
	}

	if st, ok := state.DNSSEC[domain]; ok {
		alerts = appendConditionAlert(alerts, name, domain, CheckTypeDNSSEC, st.Condition, st.Status, suppress, prev, active)
	}
	if st, ok := state.NSHealth[domain]; ok {
		alerts = appendConditionAlert(alerts, name, domain, CheckTypeNSHealth, st.Condition, st.Status, suppress, prev, active)
	}
	return alerts
}

func dispatchCycleAlerts(app *AppState, cycleAlerts []Alert) {
	for _, alert := range cycleAlerts {

		if notifier, ok := app.Notifier.(interface {
			DispatchIdentified(string, string, string, AlertPriority, AlertTag, string, string)
		}); ok {
			notifier.DispatchIdentified(alert.Identity, alert.Message, alert.Redacted, alert.Priority, alert.Tag, alert.Domain, alert.Name)
		} else {
			app.SafeDispatch(alert.Message, alert.Redacted, alert.Priority, alert.Tag, alert.Domain, alert.Name)
		}
	}
}

func main() {
	os.Exit(mainExitCode())
}

func mainExitCode() int {
	var configPath string
	flag.StringVar(&configPath, FlagConfig, StrEmpty, FlagConfigUsage)
	flag.StringVar(&configPath, FlagConfigShort, StrEmpty, FlagConfigShortUsage)
	flag.Parse()

	if configPath == StrEmpty {
		configPath = os.Getenv(EnvConfigPath)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	if err := run(ctx, configPath); err != nil {
		LogError(MsgLogApplicationFailed, FieldError, err)
		return 1
	}
	return 0
}

func run(parent context.Context, configPath string) error {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()

	rawCfg, err := LoadConfig(ctx, configPath)
	if err != nil {
		return fmt.Errorf(MsgErrLoadConfiguration, err)
	}

	app, err := InitializeApp(ctx, rawCfg)
	if err != nil {
		return fmt.Errorf(MsgErrInitializeApplication, err)
	}

	rdapHTTPClient := NewRDAPHTTPClient(10 * time.Second)
	LogInfof(MsgLogStartup, len(app.configuration().Domains), len(app.configuration().DNSRecords))
	app.PublishInitialState()

	server, serverErrChan := setupHTTPServer(app, app.configuration().Port)

	engineDone := make(chan struct{})
	// Execute concurrent engine
	go func() {
		defer close(engineDone)
		defer RecoverAndLogPanic(NameOpMonitoringEngine)

		prevRDAPStatus := make(map[string]CheckStatus)
		prevDNSStatus := make(map[string]CheckStatus)
		prevEmailStatus := make(map[string]CheckStatus)
		prevConditions := make(map[string]StateCondition)

		for {
			_ = runMonitoringCycle(ctx, app, rdapHTTPClient, prevRDAPStatus, prevDNSStatus, prevEmailStatus, prevConditions)

			timer := time.NewTimer(app.LoopDuration)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		}
	}()

	// Graceful shutdown handling
	var runErr error
	select {
	case <-ctx.Done():
		LogInfof(MsgLogShutdownSignal, StrTerminationSignal)
	case sErr := <-serverErrChan:
		LogError(MsgLogHTTPServerStopped, FieldError, sErr)
		runErr = fmt.Errorf(MsgErrHTTPServerStopped, sErr)
	case <-engineDone:
		LogError(MsgLogMonitoringEngineStopped)
		runErr = fmt.Errorf(MsgErr2, NameOpMonitoringEngine, MsgErrMonitoringEngineExited)
	}

	// Trigger cancellation for engines
	cancel()

	// Shutdown HTTP Server
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), ShutdownTimeout)
	defer shutdownCancel()
	if server != nil {
		if err := server.Shutdown(shutdownCtx); err != nil {
			LogError(MsgLogHTTPServerStopped, FieldError, err)
			runErr = errors.Join(runErr, fmt.Errorf(MsgErrShutDownHTTPServer, err))
		}
	}

	// Wait for monitoring engine to complete in-flight writes
	select {
	case <-engineDone:
	case <-time.After(5 * time.Second):
		LogWarn(MsgLogMonitoringEngineTimeout)
		runErr = errors.Join(runErr, fmt.Errorf(MsgErr2, NameOpMonitoringEngine, MsgErrMonitoringEngineShutdownTimeout))
	}

	LogInfo(MsgLogShutdownComplete)
	return runErr
}

// PublishInitialState ...
func (a *AppState) PublishInitialState() {
	initialState := NewCheckState()
	for _, domainCfg := range a.configuration().Domains {
		initialState.RDAP[domainCfg.Domain] = RDAPState{Status: StatusPending}
	}
	for _, dnsRecord := range a.configuration().DNSRecords {
		initialState.DNS[dnsRecord.Name] = DNSState{
			Hostname: dnsRecord.Hostname, Name: dnsRecord.Name,
			Type: dnsRecord.Type, Expected: dnsRecord.Expected,
			Status: StatusPending,
		}
	}
	if b, err := jsonv2.Marshal(initialState); err == nil {
		a.PrerenderedJSON.Store(b)
	}

}
