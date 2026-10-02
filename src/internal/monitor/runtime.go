package monitor

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	jsonv2 "encoding/json/v2"
	"errors"
	"flag"
	"fmt"
	"maps"
	"math"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

//go:embed index.html
var indexHTML []byte

func storePublishedState(app *AppState, body []byte) {
	digest := sha256.Sum256(body)
	app.Published.store(&publishedState{body: body, etag: SymDoubleQuote + hex.EncodeToString(digest[:]) + SymDoubleQuote})
}

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

	mux.HandleFunc(RouteAPIState, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(HeaderContentType, MIMEApplicationJSON)
		w.Header().Set(HeaderCacheControl, CacheControlNoCache)
		if state := app.Published.load(); state != nil {
			w.Header().Set(HeaderETag, state.etag)
			if r.Header.Get(HeaderIfNoneMatch) == state.etag {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			_, _ = w.Write(state.body)
			return
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

// runBoundedChecks starts at most DefaultMaxConcurrency workers. Each worker
// claims the next item without allocating a goroutine or channel entry per task.
func runBoundedChecks(count int, check func(int)) {
	if count == 0 {
		return
	}
	var next atomic.Int64
	var workers sync.WaitGroup
	worker := func() {
		for {
			index := int(next.Add(1)) - 1
			if index >= count {
				return
			}
			check(index)
		}
	}
	for range min(count, DefaultMaxConcurrency) - 1 {
		workers.Go(worker)
	}
	worker()
	workers.Wait()
}

func gatherDNSEvidence(ctx context.Context, app *AppState, record DNSTask) (snapshot DNSSnapshot) {
	defer func() {
		if recovered := recover(); recovered != nil {
			LogError(MsgLogPanicDNSWorker, FieldRecord, record.Name, FieldPanic, recovered)
			snapshot = DNSSnapshot{Err: errors.New(StrInternalDNSCheckPanic)}
		}
	}()
	return FetchDNSSnapshot(ctx, app, record)
}

func evaluateDNSCheck(record DNSTask, snapshot DNSSnapshot) (result DNSResult) {
	result.Name = record.Name
	defer func() {
		if r := recover(); r != nil {
			LogError(MsgLogPanicDNSWorker, FieldRecord, record.Name, FieldPanic, r)
			result.State = DNSState{
				Hostname: record.Hostname, Name: record.Name, Type: record.Type,
				Expected: slices.Clone(record.Expected), Status: StatusFailed,
				Error:     StrInternalDNSCheckPanic,
				Condition: StateCondition{Code: CodeDNSLookupFailed, Target: StrInternalDNSCheckPanic},
			}
		}
	}()
	status, cond := EvaluateDNS(record, snapshot)
	errStr := StrEmpty
	if !cond.IsZero() && cond.Code != CodeDNSMatchVerified {
		errStr = cond.Target
	}
	result.State = DNSState{
		Hostname: record.Hostname, Name: record.Name, Type: record.Type,
		Expected: slices.Clone(record.Expected), Status: status, Condition: cond,
		Found: snapshot.Records, Error: errStr,
		Findings: findingsFromConditions(status, cond),
	}
	return result
}

func gatherDomainEvidence(ctx context.Context, app *AppState, domain DomainConfig) (evidence domainEvidence) {
	defer func() {
		if recovered := recover(); recovered != nil {
			LogError(MsgLogPanicDomainWorker, FieldDomain, domain.Domain, FieldPanic, recovered)
			evidence.panicText = AnyToString(recovered)
		}
	}()
	evidence.email = FetchEmailSnapshot(ctx, app, domain)
	if domain.isDelegatedZone() {
		evidence.delegation = FetchNSDelegationSnapshot(ctx, app, domain)
	}
	evidence.dnssec = FetchDNSSECEvidence(ctx, app, domain)
	if len(domain.Nameservers) > 0 {
		evidence.nsHealth = FetchNSHealthSnapshots(ctx, app, domain)
	}
	return evidence
}

func evaluateFastDomainChecks(providers map[string]ProviderConfig, domain DomainConfig, evidence domainEvidence, state *CheckState) {
	if evidence.panicText != StrEmpty {
		storePanicDomainResults(domain, state, evidence.panicText)
		return
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			LogError(MsgLogPanicDomainWorker, FieldDomain, domain.Domain, FieldPanic, recovered)
			storePanicDomainResults(domain, state, recovered)
		}
	}()

	_, cond, emailState := EvaluateEmailSecurity(domain, evidence.email, providers)
	emailState.Condition = cond
	if emailState.Status != StatusUnknown {
		state.Email[domain.Domain] = emailState
	}

	if domain.isDelegatedZone() {
		status, cond := EvaluateNSDelegation(domain, evidence.delegation)
		delegationState := RDAPState{
			Status:          status,
			Condition:       cond,
			AllowExpiry:     domain.AllowExpiry,
			IsDelegatedZone: true,
			Source:          SourceDNSDelegation,
			Nameservers:     evidence.delegation.Nameservers,
			Findings:        findingsFromConditions(status, cond),
		}
		state.RDAP[domain.Domain] = delegationState
	}

	dnssecStatus, dnssecCondition, dnssecResult := EvaluateDNSSEC(domain, evidence.dnssec)
	dnssecResult.Status = dnssecStatus
	dnssecResult.Condition = dnssecCondition
	dnssecResult.Findings = findingsFromConditions(dnssecStatus, dnssecCondition)
	if dnssecResult.Source != StrEmpty || dnssecResult.Error != StrEmpty || dnssecResult.Valid {
		state.DNSSEC[domain.Domain] = dnssecResult
	}

	if len(domain.Nameservers) > 0 {
		status, nsCondition := EvaluateNSHealth(domain, evidence.nsHealth)

		servers := make([]NSHealthServerResult, 0, len(evidence.nsHealth))
		var dnskeyBaseline []string
		for _, serverSnapshot := range evidence.nsHealth {
			if serverSnapshot.Authoritative && serverSnapshot.HasSOA {
				dnskeyBaseline = serverSnapshot.DNSKEYs
				break
			}
		}
		for _, serverSnapshot := range evidence.nsHealth {
			errStr := StrEmpty
			if combined := errors.Join(serverSnapshot.Err, serverSnapshot.PartialError, serverSnapshot.DNSKEYErr); combined != nil {
				errStr = combined.Error()
			}
			dnskeyMatch := true
			if len(dnskeyBaseline) > 0 || len(serverSnapshot.DNSKEYs) > 0 {
				dnskeyMatch = slices.Equal(dnskeyBaseline, serverSnapshot.DNSKEYs)
			}
			servers = append(servers, NSHealthServerResult{
				Nameserver:    serverSnapshot.Nameserver,
				Hidden:        serverSnapshot.Hidden,
				Authoritative: serverSnapshot.Authoritative,
				HasSOA:        serverSnapshot.HasSOA,
				SOASerial:     serverSnapshot.SOASerial,
				HasDNSKEY:     serverSnapshot.HasDNSKEY,
				DNSKEYMatch:   dnskeyMatch,
				Unreachable:   serverSnapshot.Unreachable,
				Error:         errStr,
			})
		}

		nsState := NSHealthResult{
			Valid:     status == StatusOK,
			Status:    status,
			Condition: nsCondition,
			Servers:   servers,
			Findings:  findingsFromConditions(status, nsCondition),
		}
		state.NSHealth[domain.Domain] = nsState
	}
}

// gatherFastEvidence shares one bounded worker group across DNS and domain requests.
func gatherFastEvidence(ctx context.Context, app *AppState, cfg AppConfig, active activeChecks, evidence *cycleEvidence) {
	dnsCount := len(active.dnsRecords)
	runBoundedChecks(dnsCount+len(active.domains), func(index int) {
		isDNS, checkIndex := fastCheckSlot(index, dnsCount, len(active.domains))
		if isDNS {
			record := cfg.DNSRecords[active.dnsRecords[checkIndex]]
			evidence.dns[checkIndex] = gatherDNSEvidence(ctx, app, record)
			return
		}
		domain := cfg.Domains[active.domains[checkIndex]]
		evidence.domains[checkIndex] = gatherDomainEvidence(ctx, app, domain)
	})
}

func evaluateFastEvidence(providers map[string]ProviderConfig, cfg AppConfig, active activeChecks, evidence cycleEvidence, state *CheckState) {
	for index, configIndex := range active.dnsRecords {
		storeDNSResult(state, evaluateDNSCheck(cfg.DNSRecords[configIndex], evidence.dns[index]))
	}
	for index, configIndex := range active.domains {
		evaluateFastDomainChecks(providers, cfg.Domains[configIndex], evidence.domains[index], state)
	}
}

// fastCheckSlot alternates check types while both have work, then drains the
// remainder. This keeps domain checks from waiting behind a large DNS portfolio.
func fastCheckSlot(position, dnsCount, domainCount int) (isDNS bool, checkIndex int) {
	paired := min(dnsCount, domainCount)
	if position < 2*paired {
		return position%2 == 0, position / 2
	}
	if dnsCount > domainCount {
		return true, position - domainCount
	}
	return false, position - dnsCount
}

func storePanicDomainResults(domain DomainConfig, state *CheckState, _ any) {
	message := StrInternalDomainCheckPanic
	if current := state.Email[domain.Domain]; domain.Email != nil && current.Status == StatusUnknown {
		provider := StrEmpty
		if domain.Email != nil {
			provider = domain.Email.Provider
		}
		state.Email[domain.Domain] = EmailState{Provider: provider, Status: StatusFailed, Error: message, Condition: StateCondition{Code: CodeDNSLookupFailed, Target: message}}
	}
	if current := state.RDAP[domain.Domain]; domain.isDelegatedZone() && current.Status == StatusUnknown {
		state.RDAP[domain.Domain] = RDAPState{Status: StatusFailed, Error: message, AllowExpiry: domain.AllowExpiry, IsDelegatedZone: true, Condition: StateCondition{Code: CodeRDAPHTTPError, Target: message}}
	}
	if current := state.DNSSEC[domain.Domain]; domain.DNSSEC && current.Status == StatusUnknown {
		state.DNSSEC[domain.Domain] = DNSSECResult{Status: StatusFailed, Error: message, Condition: StateCondition{Code: CodeDNSSECNetworkError, Target: message}}
	}

	if current := state.NSHealth[domain.Domain]; len(domain.Nameservers) > 0 && current.Status == StatusUnknown {
		state.NSHealth[domain.Domain] = NSHealthResult{Status: StatusFailed, Condition: StateCondition{Code: CodeNSUnreachable, Target: message}}
	}
}

func gatherRDAPEvidence(ctx context.Context, app *AppState, domain DomainConfig, rdapHTTPClient HTTPDoer) (snapshot RDAPSnapshot) {
	defer func() {
		if recovered := recover(); recovered != nil {
			LogError(MsgLogPanicRDAP, FieldDomain, domain.Domain, FieldPanic, recovered)
			snapshot = RDAPSnapshot{Err: errors.New(StrInternalRDAPCheckPanic)}
		}
	}()
	return FetchRDAPSnapshot(ctx, rdapHTTPClient, app, domain.Domain)
}

// gatherRateLimitedEvidence performs serial RDAP requests to respect registry limits.
func gatherRateLimitedEvidence(ctx context.Context, app *AppState, domains []DomainConfig, active []int, rdapHTTPClient HTTPDoer, evidence *cycleEvidence) {
	for position, index := range active {
		domain := domains[index]
		if domain.isDelegatedZone() {
			continue
		}
		evidence.rdap[position] = gatherRDAPEvidence(ctx, app, domain, rdapHTTPClient)
	}
}

func evaluateRDAPCheck(domainConfig DomainConfig, snapshot RDAPSnapshot) (result RDAPState) {
	defer func() {
		if r := recover(); r != nil {
			LogError(MsgLogPanicRDAP, FieldDomain, domainConfig.Domain, FieldPanic, r)
			result = RDAPState{
				Status:      StatusFailed,
				AllowExpiry: domainConfig.AllowExpiry,
				Error:       StrInternalRDAPCheckPanic,
				Condition:   StateCondition{Code: CodeRDAPHTTPError, Target: StrInternalRDAPCheckPanic},
			}
		}
	}()
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
		ExpiryConfirmed: domainConfig.AllowExpiry && status == StatusSkipped,
		Source:          snapshot.Source,
		ProtocolUsed:    snapshot.ProtocolUsed,
		QueryDurationMs: snapshot.QueryDurationMs,
		RegistryTier:    snapshot.RegistryTier,
		RegistrarTier:   snapshot.RegistrarTier,
		Discrepancies:   snapshot.Discrepancies,
		Findings:        findingsFromConditions(status, cond),
	}

	if snapshot.Err != nil {
		rdapState.Error = snapshot.Err.Error()
	}

	if !cond.IsZero() && cond.Code == CodeRDAPRegistrarMismatch {
		rdapState.RegistrarMismatch = true
		rdapState.ExpectedRegistrar = cond.Target
	}
	return rdapState
}

func evaluateRateLimitedEvidence(domains []DomainConfig, active []int, evidence cycleEvidence, state *CheckState) {
	for position, index := range active {
		domain := domains[index]
		if domain.isDelegatedZone() {
			continue
		}
		state.RDAP[domain.Domain] = evaluateRDAPCheck(domain, evidence.rdap[position])
	}
}

func storeDNSResult(state *CheckState, res DNSResult) {
	if strings.HasPrefix(res.Name, InternalCAATaskPrefix) {
		domainName := strings.TrimPrefix(res.Name, InternalCAATaskPrefix)

		caaRes := CAAResult{
			Status:    res.State.Status,
			Condition: res.State.Condition,
			Valid:     res.State.Status == StatusOK,
			Error:     res.State.Error,
			Findings:  slices.Clone(res.State.Findings),
		}
		expectedSet := make(stringSet)
		for _, exp := range res.State.Expected {
			expectedSet[exp] = struct{}{}
		}

		for _, rec := range res.State.Found {
			parts := strings.SplitN(rec, SymSpace, 3)
			if len(parts) == 3 {
				tag := strings.ToLower(parts[1])
				val := strings.Trim(parts[2], SymDoubleQuote)
				switch tag {
				case CAATagIssue:
					caaRes.Issue = append(caaRes.Issue, val)
				case CAATagIssueWild:
					caaRes.IssueWild = append(caaRes.IssueWild, val)
				case CAATagIssueMail:
					caaRes.IssueMail = append(caaRes.IssueMail, val)
				}
			}

			if _, expected := expectedSet[rec]; !caaRes.Valid && !expected {
				if len(parts) == 3 {
					caaRes.UnknownCAs = append(caaRes.UnknownCAs, strings.Trim(parts[2], SymDoubleQuote))
				} else {
					caaRes.UnknownCAs = append(caaRes.UnknownCAs, rec)
				}
			}
		}

		// We assign it here, but it doesn't get added to state.DNS!
		// So it won't trigger DNS alerts. It will trigger CAA alerts since we add it to CAA.
		state.CAA[domainName] = caaRes
		return
	}

	state.storeDNSResultValue(res)
}

func gatherCycleEvidence(ctx context.Context, app *AppState, cfg AppConfig, rdapHTTPClient HTTPDoer) (activeChecks, cycleEvidence) {
	rdapActive := app.active.rdapDomains
	evidence := cycleEvidence{
		rdap: make([]RDAPSnapshot, len(rdapActive)),
	}
	gatherRateLimitedEvidence(ctx, app, cfg.Domains, rdapActive, rdapHTTPClient, &evidence)
	rdapState := newCycleState(cfg, activeChecks{rdapDomains: rdapActive})
	evaluateRateLimitedEvidence(cfg.Domains, rdapActive, evidence, rdapState)
	updateExpiredDomains(app, cfg, rdapState)

	active := activeChecksForCycle(app, cfg)
	evidence.dns = make([]DNSSnapshot, len(active.dnsRecords))
	evidence.domains = make([]domainEvidence, len(active.domains))
	gatherFastEvidence(ctx, app, cfg, active, &evidence)
	if app.Pricing != nil && needsPricingCatalog(cfg) {
		evidence.pricing, evidence.pricingErr = app.Pricing.cachedCatalog(ctx)
	}
	return active, evidence
}

func evaluateCycleEvidence(providers map[string]ProviderConfig, cfg AppConfig, active activeChecks, evidence cycleEvidence) *CheckState {
	state := newCycleState(cfg, active)
	evaluateFastEvidence(providers, cfg, active, evidence, state)
	evaluateRateLimitedEvidence(cfg.Domains, active.rdapDomains, evidence, state)
	suppressExpiredDomainChecks(cfg, state)
	if evidence.pricingErr != nil {
		LogWarn(MsgLogPricingFetchFailed, FieldError, evidence.pricingErr)
	}
	applyPortfolioPricing(cfg, state, evidence.pricing)
	return state
}

func runMonitoringCycle(
	ctx context.Context,
	app *AppState,
	rdapHTTPClient HTTPDoer,
	prevRDAPStatus map[string]CheckStatus,
	prevDNSStatus map[string]CheckStatus,
	prevEmailStatus map[string]CheckStatus,
	prevConditions map[conditionKey]StateCondition,
) *CheckState {
	clock := app.Clock
	if clock == nil {
		clock = systemClock{}
	}
	cycleStart := clock.Now()
	cycleID := app.cycleSequence.Add(1)

	loopDur := app.LoopDuration
	if loopDur <= 0 {
		loopDur = DefaultLoopDurationFallback
	}

	cfg := app.configuration()
	// Bound cycle timeout safely: scale with domain and DNS record counts so large portfolios
	// have sufficient time for rate-limited RDAP requests and retries without hanging indefinitely.
	minRequiredTimeout := saturatingWorkDuration(len(app.active.rdapDomains), 15*time.Second, 5*time.Minute)
	minRequiredTimeout = saturatingWorkDuration(len(app.active.domains)+len(app.active.dnsRecords), 5*time.Second, minRequiredTimeout)
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
		prevConditions = make(map[conditionKey]StateCondition)
	}

	// RDAP selects the current dependent workload; final evaluation remains network-free.
	active, evidence := gatherCycleEvidence(cycleCtx, app, cfg, rdapHTTPClient)
	if cycleCtx.Err() != nil {
		if ctx.Err() == nil {
			publishCycleFailure(app, CycleMetadata{
				ID: cycleID, Phase: CyclePhaseIdle, Outcome: CycleOutcomeFailed,
				StartedAt:  cycleStart.UTC().Format(time.RFC3339),
				FinishedAt: clock.Now().UTC().Format(time.RFC3339),
				DurationMS: clock.Now().Sub(cycleStart).Milliseconds(),
			})
		}
		return nil
	}
	loopState := evaluateCycleEvidence(app.EmailProviders, cfg, active, evidence)
	if cycleCtx.Err() != nil {
		if ctx.Err() == nil {
			publishCycleFailure(app, CycleMetadata{
				ID: cycleID, Phase: CyclePhaseIdle, Outcome: CycleOutcomeFailed,
				StartedAt:  cycleStart.UTC().Format(time.RFC3339),
				FinishedAt: clock.Now().UTC().Format(time.RFC3339),
				DurationMS: clock.Now().Sub(cycleStart).Milliseconds(),
			})
		}
		return nil
	}

	// 5. State transition logging
	logStateTransitions(CheckTypeRDAP, TargetKeyDomain, loopState.RDAP, func(s RDAPState) CheckStatus { return s.Status }, prevRDAPStatus)
	logStateTransitions(CheckTypeDNS, TargetKeyRecord, loopState.DNS, func(s DNSState) CheckStatus { return s.Status }, prevDNSStatus)
	logStateTransitions(CheckTypeEmail, TargetKeyDomain, loopState.Email, func(s EmailState) CheckStatus { return s.Status }, prevEmailStatus)

	// 6. Track Since Timestamps and Dispatch Cycle Report
	processConditionsAndAlerts(app, loopState, cfg, active, prevConditions)

	// 7. Update timestamps and pre-render atomic JSON cache
	finishedAt := clock.Now()
	loopState.LastUpdated = finishedAt.UTC().Format(time.RFC3339)
	loopState.Cycle = CycleMetadata{
		ID: cycleID, Phase: CyclePhaseIdle, Outcome: CycleOutcomeSuccess,
		StartedAt:     cycleStart.UTC().Format(time.RFC3339),
		FinishedAt:    finishedAt.UTC().Format(time.RFC3339),
		LastSuccessAt: finishedAt.UTC().Format(time.RFC3339),
		DurationMS:    finishedAt.Sub(cycleStart).Milliseconds(),
		Overrun:       finishedAt.Sub(cycleStart) > loopDur,
	}
	publishCycleState(app, loopState, loopDur)

	cycleDuration := clock.Now().Sub(cycleStart)
	LogInfo(MsgLogMonitoringCycleCompleted,
		FieldDurationMS, cycleDuration.Milliseconds(),
		FieldDomainsChecked, len(active.rdapDomains),
		FieldDNSRecordsChecked, len(active.dnsRecords),
	)

	return loopState
}

func saturatingWorkDuration(count int, perItem, base time.Duration) time.Duration {
	if count <= 0 || perItem <= 0 {
		return base
	}
	maxDuration := time.Duration(math.MaxInt64)
	if count > int((maxDuration-base)/perItem) {
		return maxDuration
	}
	return base + time.Duration(count)*perItem
}

func flushNotifier(ctx context.Context, notifier Notifier) {
	if notifier == nil {
		return
	}
	notifier.FlushContext(ctx)
}

func runNotificationWorker(ctx context.Context, notifier Notifier, wake <-chan struct{}, done chan<- struct{}) {
	defer close(done)
	for {
		select {
		case <-ctx.Done():
			return
		case _, ok := <-wake:
			flushNotifier(ctx, notifier)
			if !ok {
				return
			}
		}
	}
}

func publishCycleState(app *AppState, state *CheckState, loopDur time.Duration) {
	now := time.Now()
	if app.Clock != nil {
		now = app.Clock.Now()
	}
	state.NextRefresh = now.Add(loopDur).UTC().Format(time.RFC3339)
	encoded, err := jsonv2.Marshal(toAPIState(state))
	if err != nil {
		LogWarn(MsgLogStateMarshalFailed, FieldError, err)
		return
	}
	storePublishedState(app, encoded)
}

func sortedAPIChecks[T any](values map[string]T) []apiCheck[T] {
	checks := make([]apiCheck[T], 0, len(values))
	for _, id := range slices.Sorted(maps.Keys(values)) {
		checks = append(checks, apiCheck[T]{ID: id, Result: values[id]})
	}
	return checks
}

func toAPIState(state *CheckState) apiState {
	return apiState{
		RDAP: sortedAPIChecks(state.RDAP), DNS: sortedAPIChecks(state.DNS), Email: sortedAPIChecks(state.Email),
		DNSSEC: sortedAPIChecks(state.DNSSEC), NSHealth: sortedAPIChecks(state.NSHealth), CAA: sortedAPIChecks(state.CAA),
		LastUpdated: state.LastUpdated, NextRefresh: state.NextRefresh, Cycle: state.Cycle,
	}
}

func publishCycleFailure(app *AppState, attempt CycleMetadata) {
	body, ok := app.PublishedJSON()
	if !ok {
		return
	}
	var state apiState
	if err := jsonv2.Unmarshal(body, &state); err != nil {
		LogWarn(MsgLogStateMarshalFailed, FieldError, err)
		return
	}
	attempt.LastSuccessAt = state.Cycle.LastSuccessAt
	state.Cycle = attempt
	interval := app.LoopDuration
	if interval <= 0 {
		interval = DefaultLoopDurationFallback
	}
	now := time.Now()
	if app.Clock != nil {
		now = app.Clock.Now()
	}
	state.NextRefresh = now.Add(interval).UTC().Format(time.RFC3339)
	if encoded, err := jsonv2.Marshal(&state); err == nil {
		storePublishedState(app, encoded)
	}
}

// newCycleState creates the maps owned by one monitoring cycle.
// Optional maps stay nil when their check type is absent.
func newCycleState(cfg AppConfig, active activeChecks) *CheckState {
	emailCount, dnssecCount, nsHealthCount, caaCount := 0, 0, 0, 0
	for _, index := range active.domains {
		domain := cfg.Domains[index]
		if domain.Email != nil {
			emailCount++
		}
		if domain.DNSSEC {
			dnssecCount++
		}
		if len(domain.Nameservers) > 0 {
			nsHealthCount++
		}
	}
	for _, index := range active.dnsRecords {
		record := cfg.DNSRecords[index]
		if strings.HasPrefix(record.Name, InternalCAATaskPrefix) {
			caaCount++
		}
	}
	state := &CheckState{
		RDAP:  make(map[string]RDAPState, len(cfg.Domains)),
		DNS:   make(map[string]DNSState, len(active.dnsRecords)-caaCount),
		Email: make(map[string]EmailState, emailCount),
	}
	if dnssecCount > 0 {
		state.DNSSEC = make(map[string]DNSSECResult, dnssecCount)
	}
	if nsHealthCount > 0 {
		state.NSHealth = make(map[string]NSHealthResult, nsHealthCount)
	}
	if caaCount > 0 {
		state.CAA = make(map[string]CAAResult, caaCount)
	}
	for _, domain := range cfg.Domains {
		state.RDAP[domain.Domain] = RDAPState{Status: StatusPending, AllowExpiry: domain.AllowExpiry}
	}
	return state
}

func suppressExpiredDomainChecks(cfg AppConfig, state *CheckState) {
	var expired stringSet
	for _, domain := range cfg.Domains {
		if domain.AllowExpiry && state.RDAP[domain.Domain].ExpiryConfirmed {
			if expired == nil {
				expired = make(stringSet)
			}
			expired[NormalizeDomain(domain.Domain)] = struct{}{}
			delete(state.Email, domain.Domain)
			delete(state.DNSSEC, domain.Domain)
			delete(state.NSHealth, domain.Domain)
			delete(state.CAA, domain.Domain)
		}
	}
	if len(expired) == 0 {
		return
	}
	for _, record := range cfg.DNSRecords {
		if _, isExpired := expired[configuredDomainOwner(record.Hostname, cfg.Domains)]; isExpired {
			delete(state.DNS, record.Name)
		}
	}
}

func configuredDomainOwner(hostname string, domains []DomainConfig) string {
	host := NormalizeDomain(hostname)
	owner := StrEmpty
	for _, domain := range domains {
		name := NormalizeDomain(domain.Domain)
		if (host == name || strings.HasSuffix(host, SymDot+name)) && len(name) > len(owner) {
			owner = name
		}
	}
	return owner
}

func activeChecksForCycle(app *AppState, cfg AppConfig) activeChecks {
	active := app.active
	if len(app.Runtime.ExpiredDomains) == 0 {
		return active
	}
	active.domains = make([]int, 0, len(app.active.domains))
	for _, index := range app.active.domains {
		if _, expired := app.Runtime.ExpiredDomains[cfg.Domains[index].Domain]; !expired {
			active.domains = append(active.domains, index)
		}
	}
	active.dnsRecords = make([]int, 0, len(app.active.dnsRecords))
	for _, index := range app.active.dnsRecords {
		owner := configuredDomainOwner(cfg.DNSRecords[index].Hostname, cfg.Domains)
		if _, expired := app.Runtime.ExpiredDomains[owner]; !expired {
			active.dnsRecords = append(active.dnsRecords, index)
		}
	}
	return active
}

func updateExpiredDomains(app *AppState, cfg AppConfig, state *CheckState) {
	for _, domain := range cfg.Domains {
		if !domain.AllowExpiry {
			delete(app.Runtime.ExpiredDomains, domain.Domain)
			continue
		}
		rdapState := state.RDAP[domain.Domain]
		if rdapState.ExpiryConfirmed {
			app.Runtime.ExpiredDomains[domain.Domain] = struct{}{}
			continue
		}
		if _, expired := app.Runtime.ExpiredDomains[domain.Domain]; expired && rdapState.Condition.Code == CodeRDAPHTTPError {
			continue
		}
		delete(app.Runtime.ExpiredDomains, domain.Domain)
	}
}

func applyConditionSince(cond StateCondition, key conditionKey, prev map[conditionKey]StateCondition) StateCondition {
	if cond.IsZero() {
		return cond
	}
	prevCond, exists := prev[key]
	if exists && prevCond.Code == cond.Code {
		cond.Since = prevCond.Since
	} else {
		cond.Since = time.Now().UTC()
	}
	// History needs only the code and start time, not prior diagnostic text.
	prev[key] = StateCondition{Code: cond.Code, Since: cond.Since}
	return cond
}

func formatDurationSince(since time.Time) string {
	d := time.Since(since).Round(time.Minute)
	if d < time.Minute {
		return StrJustNow
	}
	return d.String()
}

func processConditionsAndAlerts(app *AppState, state *CheckState, cfg AppConfig, active activeChecks, prev map[conditionKey]StateCondition) {
	var cycleAlerts []Alert
	for _, index := range active.domains {
		cycleAlerts = collectDomainAlerts(cycleAlerts, state, cfg.Domains[index], prev)
	}
	for _, index := range active.dnsRecords {
		dnsCfg := cfg.DNSRecords[index]
		name := dnsCfg.Name
		if st, ok := state.DNS[name]; ok {
			cycleAlerts, st.Condition = appendConditionAlert(cycleAlerts, name, name, CheckTypeDNS, st.Condition, st.Status, false, prev)
			state.DNS[name] = st
		}
	}
	pruneConditionHistory(state, prev)
	dispatchCycleAlerts(app, cycleAlerts)
}

func pruneConditionHistory(state *CheckState, prev map[conditionKey]StateCondition) {
	for key := range prev {
		var status CheckStatus
		var condition StateCondition
		var exists bool
		switch key.check {
		case CheckTypeRDAP:
			var result RDAPState
			result, exists = state.RDAP[key.domain]
			status, condition = result.Status, result.Condition
		case CheckTypeDNS:
			var result DNSState
			result, exists = state.DNS[key.domain]
			status, condition = result.Status, result.Condition
		case CheckTypeEmail:
			var result EmailState
			result, exists = state.Email[key.domain]
			status, condition = result.Status, result.Condition
		case CheckTypeCAA:
			var result CAAResult
			result, exists = state.CAA[key.domain]
			status, condition = result.Status, result.Condition
		case CheckTypeDNSSEC:
			var result DNSSECResult
			result, exists = state.DNSSEC[key.domain]
			status, condition = result.Status, result.Condition
		case CheckTypeNSHealth:
			var result NSHealthResult
			result, exists = state.NSHealth[key.domain]
			status, condition = result.Status, result.Condition
		}
		if !exists || condition.IsZero() || !alertableStatus(status) {
			delete(prev, key)
		}
	}
}

func alertableStatus(status CheckStatus) bool {
	return status == StatusFailed || status == StatusMismatch || status == StatusHijacked || status == StatusWarning
}

func appendConditionAlert(alerts []Alert, name, domain, check string, cond StateCondition, status CheckStatus, suppress bool, prev map[conditionKey]StateCondition) ([]Alert, StateCondition) {
	key := conditionKey{check: check, domain: domain}
	if cond.IsZero() || (status != StatusFailed && status != StatusMismatch && status != StatusHijacked && status != StatusWarning) {
		delete(prev, key)
		return alerts, cond
	}
	cond = applyConditionSince(cond, key, prev)
	if suppress {
		return alerts, cond
	}
	priority := PriorityWarning
	if status != StatusWarning {
		priority = PriorityHigh
	}
	duration := formatDurationSince(cond.Since)
	statusName, codeName := status.String(), cond.Code.String()
	message := conditionAlertMessage(check, statusName, codeName, cond.Target, duration, false)
	redacted := conditionAlertMessage(check, statusName, codeName, StrEmpty, duration, true)
	return append(alerts, Alert{Message: message, Redacted: redacted, Priority: priority, Tag: TagSkull, Domain: domain, Name: name, Check: check}), cond
}

func conditionAlertMessage(check, status, code, target, duration string, redacted bool) string {
	size := len(check) + len(status) + len(code) + len(duration) + len(AlertConditionFixedText)
	if !redacted {
		size += len(target) + 1
	}
	var message strings.Builder
	message.Grow(size)
	message.WriteString(check)
	message.WriteByte(' ')
	message.WriteString(status)
	message.WriteString(AlertStatusSeparator)
	message.WriteString(code)
	if !redacted {
		message.WriteByte(' ')
		message.WriteString(target)
	}
	message.WriteString(AlertSincePrefix)
	message.WriteString(duration)
	message.WriteByte(')')
	return message.String()
}

func collectDomainAlerts(alerts []Alert, state *CheckState, cfg DomainConfig, prev map[conditionKey]StateCondition) []Alert {
	domain, name, suppress := cfg.Domain, cfg.Name, cfg.SuppressAlerts
	if st, ok := state.RDAP[domain]; ok {
		alerts, st.Condition = appendConditionAlert(alerts, name, domain, CheckTypeRDAP, st.Condition, st.Status, suppress, prev)
		state.RDAP[domain] = st
	}
	if st, ok := state.Email[domain]; ok {
		alerts, st.Condition = appendConditionAlert(alerts, name, domain, CheckTypeEmail, st.Condition, st.Status, suppress, prev)
		alerts = appendAdditionalFindingAlerts(alerts, st.Findings, st.Condition, name, domain, CheckTypeEmail, st.Status, suppress)
		state.Email[domain] = st
	}
	if st, ok := state.CAA[domain]; ok {
		alerts, st.Condition = appendConditionAlert(alerts, name, domain, CheckTypeCAA, st.Condition, st.Status, suppress, prev)
		state.CAA[domain] = st
	}

	if st, ok := state.DNSSEC[domain]; ok {
		alerts, st.Condition = appendConditionAlert(alerts, name, domain, CheckTypeDNSSEC, st.Condition, st.Status, suppress, prev)
		state.DNSSEC[domain] = st
	}
	if st, ok := state.NSHealth[domain]; ok {
		alerts, st.Condition = appendConditionAlert(alerts, name, domain, CheckTypeNSHealth, st.Condition, st.Status, suppress, prev)
		state.NSHealth[domain] = st
	}
	return alerts
}

func appendAdditionalFindingAlerts(alerts []Alert, findings []Finding, primary StateCondition, name, domain, check string, status CheckStatus, suppress bool) []Alert {
	if suppress || !alertableStatus(status) {
		return alerts
	}
	priority := PriorityWarning
	if status != StatusWarning {
		priority = PriorityHigh
	}
	duration := formatDurationSince(primary.Since)
	for _, finding := range findings {
		if finding.Code == primary.Code && finding.Target == primary.Target {
			continue
		}
		message := conditionAlertMessage(check, status.String(), finding.Code.String(), finding.Target, duration, false)
		redacted := conditionAlertMessage(check, status.String(), finding.Code.String(), StrEmpty, duration, true)
		alerts = append(alerts, Alert{Message: message, Redacted: redacted, Priority: priority, Tag: TagSkull, Domain: domain, Name: name, Check: check})
	}
	return alerts
}

func dispatchCycleAlerts(app *AppState, cycleAlerts []Alert) {
	for _, alert := range cycleAlerts {
		app.SafeDispatch(alert.Message, alert.Redacted, alert.Priority, alert.Tag, alert.Domain, alert.Name)
	}
}

// MainExitCode parses process configuration, runs the monitor, and returns the
// exit code for the command package.
func MainExitCode() int {
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

	config, err := LoadConfig(ctx, configPath)
	if err != nil {
		return fmt.Errorf(MsgErrLoadConfiguration, err)
	}

	app, err := InitializeApp(ctx, config)
	if err != nil {
		return fmt.Errorf(MsgErrInitializeApplication, err)
	}

	rdapHTTPClient := app.Clients.RDAP
	if rdapHTTPClient == nil {
		rdapHTTPClient = NewRDAPHTTPClient(DefaultHTTPTimeout)
	}
	LogInfof(MsgLogStartup, len(app.configuration().Domains), len(app.configuration().DNSRecords))
	app.PublishInitialState()

	server, serverErrChan := setupHTTPServer(app, app.configuration().Port)
	notificationCtx, notificationCancel := context.WithCancel(context.Background())
	defer notificationCancel()
	notificationWake := make(chan struct{}, 1)
	notificationDone := make(chan struct{})
	go runNotificationWorker(notificationCtx, app.Notifier, notificationWake, notificationDone)

	engineDone := make(chan struct{})
	// Execute concurrent engine
	go func() {
		defer close(engineDone)
		defer RecoverAndLogPanic(NameOpMonitoringEngine)

		prevRDAPStatus := make(map[string]CheckStatus)
		prevDNSStatus := make(map[string]CheckStatus)
		prevEmailStatus := make(map[string]CheckStatus)
		prevConditions := make(map[conditionKey]StateCondition)

		for {
			_ = runMonitoringCycle(ctx, app, rdapHTTPClient, prevRDAPStatus, prevDNSStatus, prevEmailStatus, prevConditions)
			select {
			case notificationWake <- struct{}{}:
			default:
			}

			interval := app.LoopDuration
			if interval <= 0 {
				interval = DefaultLoopDurationFallback
			}
			clock := app.Clock
			if clock == nil {
				clock = systemClock{}
			}
			timer := clock.NewTimer(interval)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C():
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
		runErr = fmt.Errorf(MsgErrOperationDetail, NameOpMonitoringEngine, MsgErrMonitoringEngineExited)
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
	engineStopped := false
	select {
	case <-engineDone:
		engineStopped = true
	case <-time.After(5 * time.Second):
		LogWarn(MsgLogMonitoringEngineTimeout)
		runErr = errors.Join(runErr, fmt.Errorf(MsgErrOperationDetail, NameOpMonitoringEngine, MsgErrMonitoringEngineShutdownTimeout))
	}
	if engineStopped {
		close(notificationWake)
	} else {
		notificationCancel()
	}
	select {
	case <-notificationDone:
	case <-time.After(5 * time.Second):
		notificationCancel()
		LogWarn(MsgLogNotificationWorkerTimeout)
	}
	app.Clients.CloseIdleConnections()

	LogInfo(MsgLogShutdownComplete)
	return runErr
}

// PublishInitialState publishes pending checks before the first cycle completes.
func (a *AppState) PublishInitialState() {
	cfg := a.configuration()
	initialState := newCycleState(cfg, activeChecks{dnsRecords: a.active.dnsRecords})
	initialState.Cycle = CycleMetadata{Phase: CyclePhaseInitializing}
	for _, index := range a.active.dnsRecords {
		dnsRecord := cfg.DNSRecords[index]
		initialState.DNS[dnsRecord.Name] = DNSState{
			Hostname: dnsRecord.Hostname, Name: dnsRecord.Name,
			Type: dnsRecord.Type, Expected: dnsRecord.Expected,
			Status: StatusPending,
		}
	}
	if encoded, err := jsonv2.Marshal(toAPIState(initialState)); err == nil {
		storePublishedState(a, encoded)
	}

}
