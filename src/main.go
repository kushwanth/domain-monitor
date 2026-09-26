package main

import (
	"context"
	_ "embed"
	jsonv2 "encoding/json/v2"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"sort"
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

// serveCTLogFile serves the CT log history JSON file for the given domain.
func serveCTLogFile(app *AppState, w http.ResponseWriter, domain string) {
	w.Header().Set(HeaderContentType, MIMEApplicationJSON)
	w.Header().Set(HeaderCacheControl, StrNoStore)
	domain = NormalizeDomain(domain)
	if domain == StrEmpty || !ReValidDomain.MatchString(domain) {
		w.Header().Set(HeaderContentType, MIMEApplicationJSON)
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(JSONResponseInvalidDomain))
		return
	}
	if !isCTMonitored(app, domain) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(StrErrorDomainIsNot))
		return
	}

	logsPath := DefaultCTLogsSubdir
	if app != nil && app.CTLogsPath != StrEmpty {
		logsPath = app.CTLogsPath
	}
	filePath := filepath.Join(logsPath, domain+StrJSON)
	cleanPath := filepath.Clean(filePath)
	if !IsSafeSubpath(logsPath, cleanPath) {
		w.Header().Set(HeaderContentType, MIMEApplicationJSON)
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(JSONResponseInvalidDomain))
		return
	}

	if app.ReadCTHistory == nil {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(StrErrorCTHistoryReader))
		return
	}
	b, err := app.ReadCTHistory(cleanPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			_, _ = w.Write([]byte(JSONResponseEmptyArray))
			return
		}
		LogWarn(MsgLogReadCTLogFailed, FieldDomain, domain, FieldPath, cleanPath, FieldError, err)
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(StrErrorCTHistoryUnavailable))
		return
	}
	if len(b) == 0 {
		_, _ = w.Write([]byte(JSONResponseEmptyArray))
		return
	}
	var parsed []CTCert
	if err := jsonv2.Unmarshal(b, &parsed); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(StrErrorCTHistoryIs))
		return
	}
	_, _ = w.Write(b)
}

func isCTMonitored(app *AppState, domain string) bool {
	if app == nil {
		return false
	}
	for _, configured := range app.configuration().Domains {
		if configured.MonitorCTLogs && configured.Domain == domain {
			return true
		}
	}
	return false
}

func readBoundedCTFile(path string) ([]byte, error) {
	// #nosec G304 G703 -- path is the configured CT history location; caller validates domain filenames.
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf(MsgErrOpenCTFile, path, err)
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, MaxCTHistoryFileSize+1))
	if err != nil {
		return nil, fmt.Errorf(MsgErrReadCTFile, path, err)
	}
	if len(b) > MaxCTHistoryFileSize {
		return nil, fmt.Errorf(MsgErrCTFileExceedsBytes, path, MaxCTHistoryFileSize)
	}
	return b, nil
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

	mux.HandleFunc(RouteAPICerts, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(HeaderContentType, MIMEApplicationJSON)
		serveCTLogFile(app, w, r.URL.Query().Get(ParamDomain))
	})

	mux.HandleFunc(RouteAPICTLogs, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(HeaderContentType, MIMEApplicationJSON)
		serveCTLogFile(app, w, r.PathValue(ParamDomain))
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
							CheckSSL:  record.CheckSSL,
						},
					}
				}
			}()
			dnsSnap := FetchDNSSnapshot(ctx, app, record)
			status, cond := EvaluateDNS(record, dnsSnap)

			var sslDays *int
			if record.CheckSSL {
				// We fetch SSL snapshot regardless of DNS match as long as it's not a complete lookup failure,
				// but wait, if it's a lookup failure we still might want to try?
				// The original code did: sslDays = validateCertificate(ctx, app, target, foundRecords) unconditionally if CheckSSL.
				sslSnap := FetchSSLSnapshot(ctx, app, record, dnsSnap.Records)
				sslStatus, sslCond := EvaluateSSL(record, sslSnap)

				if sslSnap.ExpiryDays != SSLDaysError && sslSnap.ExpiryDays != SSLDaysNotApplicable {
					d := sslSnap.ExpiryDays
					sslDays = &d
				}

				if sslStatus != StatusOK {
					if status == StatusOK || status == StatusWarning {
						status = sslStatus
					}
					// Only overwrite condition if it was purely OK
					if cond == nil || cond.Code == CodeDNSMatchVerified {
						cond = sslCond
					} else {
						// Append to target for legacy support
						cond.Target += SymPipeSpaced + sslCond.Target
					}
				}
			}

			errStr := StrEmpty
			if cond != nil && cond.Code != CodeDNSMatchVerified && cond.Code != CodeSSLVerified {
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
				SSLDays:   sslDays,
				CheckSSL:  record.CheckSSL,
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
			_, cond, emailState := EvaluateEmailSecurity(domain, emailSnap)
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

				caaSnap := FetchCAASnapshot(ctx, app, domain)
				caaStatus, caaCond, caaRes := EvaluateCAA(domain, caaSnap)
				caaRes.Status = caaStatus
				caaRes.Condition = caaCond
				res.CAA = caaRes

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
	if domain.CAA != nil && res.CAA.Status == StatusUnknown {
		res.CAA = CAAResult{Status: StatusFailed, Error: message, Condition: &StateCondition{Code: CodeCAAQueryFailed, Target: message}}
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
	ctLogPersist map[string]CTLogState,
) ([]RDAPState, []CTLogState) {
	rdapResults := make([]RDAPState, len(domains))
	ctResults := make([]CTLogState, len(domains))

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

	// CT Logs pipeline: evaluates monitored domains with 5s token bucket
	gRateLimitedChecks.Go(func() error {
		defer RecoverAndLogPanic(NameOpCTLogsWorker)
		order := make([]int, 0, len(domains))
		for i := range domains {
			if domains[i].MonitorCTLogs {
				order = append(order, i)
			}
		}
		sort.SliceStable(order, func(a, b int) bool {
			return ctLogPersist[domains[order[a]].Domain].LastAttemptUnix < ctLogPersist[domains[order[b]].Domain].LastAttemptUnix
		})
		for position, i := range order {
			domainConfig := domains[i]
			func() {
				defer func() {
					if r := recover(); r != nil {
						LogError(MsgLogPanicCTLogs, FieldDomain, domainConfig.Domain, FieldPanic, r)
						ctResults[i] = ctLogPersist[domainConfig.Domain]
						ctResults[i].Status = StatusFailed
						ctResults[i].Error = fmt.Sprintf(MsgErrInternalCTLogsPanic, AnyToString(r))
						ctResults[i].Condition = &StateCondition{Code: CodeCTLogsHTTPError, Target: StrInternalCTCheckPanic}
					}
				}()
				ctSnap := FetchCTLogsSnapshot(ctx, app, domainConfig, ctLogPersist[domainConfig.Domain])
				ctStatus, ctCond, ctRes := EvaluateCTLogs(domainConfig, ctSnap)
				ctRes.Status = ctStatus
				ctRes.Condition = ctCond
				ctResults[i] = ctRes
			}()
			if ctResults[i].Condition != nil && ctResults[i].Condition.Code == CodeCTLogsRateLimited {
				for _, j := range order[position+1:] {
					ctResults[j] = ctLogPersist[domains[j].Domain]
					ctResults[j].Status = StatusWarning
					ctResults[j].Error = StrCTQuotaExhaustedDeferred
					ctResults[j].Condition = &StateCondition{Code: CodeCTLogsRateLimited}
				}
				return nil
			}
		}
		return nil
	})

	_ = gRateLimitedChecks.Wait()
	return rdapResults, ctResults
}

// runMonitoringCycle executes a single complete monitoring pass across all configured DNS tasks and domains.
func runMonitoringCycle(
	ctx context.Context,
	app *AppState,
	rdapHTTPClient *http.Client,
	ctStatePath string,
	ctLogPersist map[string]CTLogState,
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
	// have sufficient time under the 10-second token bucket RDAP and 5-second CTLogs rate limiters, while never hanging indefinitely.
	minRequiredTimeout := time.Duration(len(domains))*(10+5)*time.Second + time.Duration(len(dnsRecords))*5*time.Second + 5*time.Minute
	cycleMaxTimeout := max(loopDur, minRequiredTimeout, 5*time.Minute)
	cycleCtx, cycleCancel := context.WithTimeout(ctx, cycleMaxTimeout)
	defer cycleCancel()

	if ctLogPersist == nil {
		ctLogPersist = make(map[string]CTLogState)
	}
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

	loopState, activeDomains := prepareCycleState(domains, ctLogPersist)

	// 1. Dispatch DNS Records
	dnsResults := executeDNSChecks(cycleCtx, app, dnsRecords)

	// 2. Dispatch Fast Domain Checks (Email, DNSSEC, CAA, NS Health, NS Delegation)
	domainResults := executeFastDomainChecks(cycleCtx, app, domains)

	// 3. Dispatch Slow, Rate-Limited External Checks Concurrently (RDAP and CT Logs)
	rdapResults, ctResults := executeRateLimitedChecks(cycleCtx, app, domains, rdapHTTPClient, ctLogPersist)

	for i := range domains {
		if rdapResults[i].Status != StatusUnknown {
			domainResults[i].RDAP = rdapResults[i]
		}
		if ctResults[i].Status != StatusUnknown {
			domainResults[i].CTLogs = ctResults[i]
		}
	}

	// 3. Assemble CheckState using clean helper methods
	for _, res := range dnsResults {
		loopState.ApplyDNSResult(res)
	}
	for _, res := range domainResults {
		loopState.ApplyDomainResult(res)
	}

	commitCycleCTState(app, loopState, ctStatePath, ctLogPersist, activeDomains)

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

	cycleDuration := time.Since(cycleStart)
	LogInfo(MsgLogMonitoringCycleCompleted,
		FieldDurationMS, cycleDuration.Milliseconds(),
		FieldDomainsChecked, len(domains),
		FieldDNSRecordsChecked, len(dnsRecords),
	)

	finishCycleDelivery(cycleCtx, app, loopState, ctStatePath, ctLogPersist, loopDur)

	return loopState
}

func prepareCycleState(domains []DomainConfig, committed map[string]CTLogState) (*CheckState, map[string]bool) {
	state := NewCheckState()
	active := make(map[string]bool, len(domains))
	for _, domain := range domains {
		if domain.MonitorCTLogs {
			active[domain.Domain] = true
		}
		state.RDAP[domain.Domain] = RDAPState{Status: StatusPending}
	}
	for domain, previous := range committed {
		if active[domain] && previous.Status != StatusUnknown {
			state.CTLogs[domain] = cloneCTLogState(previous)
		}
	}
	return state, active
}

func commitCycleCTState(app *AppState, state *CheckState, path string, committed map[string]CTLogState, active map[string]bool) {
	candidate := maps.Clone(committed)
	maps.Copy(candidate, state.CTLogs)
	for domain := range candidate {
		if !active[domain] {
			delete(candidate, domain)
		}
	}
	write := AtomicWriteFile
	if app != nil && app.WriteCTState != nil {
		write = app.WriteCTState
	}
	b, err := encodeCTState(candidate)
	if err == nil {
		err = write(path, b, FilePermSecret)
	}
	if err != nil {
		markCTCommitFailed(state, committed, fmt.Errorf(MsgErrCommitCTState, path, err))
		return
	}
	for domain := range committed {
		delete(committed, domain)
	}
	for domain, current := range candidate {
		current.NewCerts = nil
		committed[domain] = cloneCTLogState(current)
	}
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

func finishCycleDelivery(ctx context.Context, app *AppState, state *CheckState, path string, committed map[string]CTLogState, loopDur time.Duration) {
	if app == nil {
		return
	}
	if app.Notifier != nil {
		if notifier, ok := app.Notifier.(interface{ FlushContext(context.Context) }); ok {
			notifier.FlushContext(ctx)
		} else {
			app.Notifier.Flush()
		}
	}
	var accepted map[string]CTAcceptance
	if notifier, ok := app.Notifier.(interface {
		TakeCTAcceptances() map[string]CTAcceptance
	}); ok {
		accepted = notifier.TakeCTAcceptances()
	}
	write := AtomicWriteFile
	if app.WriteCTState != nil {
		write = app.WriteCTState
	}
	if err := commitCTAcceptances(path, committed, app.configuration(), accepted, write); err != nil {
		LogWarn(MsgLogCTAcknowledgementPending, FieldError, err)
	} else {
		if notifier, ok := app.Notifier.(interface{ ForgetCTAcceptances(map[string]CTAcceptance) }); ok {
			notifier.ForgetCTAcceptances(accepted)
		}
		for domain, previous := range committed {
			if current, ok := state.CTLogs[domain]; ok {
				current.Pending = slices.Clone(previous.Pending)
				state.CTLogs[domain] = current
			}
		}
	}
	publishCycleState(app, state, loopDur)
}

func markCTCommitFailed(state *CheckState, committed map[string]CTLogState, err error) {
	LogWarn(MsgLogWriteCTStateFailed, FieldError, err)
	for domain := range state.CTLogs {
		previous := committed[domain]
		current := cloneCTLogState(previous)
		current.Status = StatusFailed
		current.Error = err.Error()
		current.Condition = &StateCondition{Code: CodeCTPersistenceFailed, Target: current.Error}
		state.CTLogs[domain] = current
	}
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
	if st, ok := state.CAA[domain]; ok {
		alerts = appendConditionAlert(alerts, name, domain, CheckTypeCAA, st.Condition, st.Status, suppress, prev, active)
	}
	if st, ok := state.DNSSEC[domain]; ok {
		alerts = appendConditionAlert(alerts, name, domain, CheckTypeDNSSEC, st.Condition, st.Status, suppress, prev, active)
	}
	if st, ok := state.NSHealth[domain]; ok {
		alerts = appendConditionAlert(alerts, name, domain, CheckTypeNSHealth, st.Condition, st.Status, suppress, prev, active)
	}
	if st, ok := state.CTLogs[domain]; ok && cfg.MonitorCTLogs {
		alerts = appendConditionAlert(alerts, name, domain, CheckTypeCTLogs, st.Condition, st.Status, suppress, prev, active)
		if !suppress && app.Notifier != nil {
			for _, pending := range st.Pending {
				issuer := pending.Cert.Issuer
				if issuer == StrEmpty {
					issuer = DefaultUnknownCA
				}
				identity := AlertCTIdentityPrefix + domain + SymColon + pending.Cert.ID
				alerts = append(alerts, Alert{Message: AlertNewCertificatePrefix + issuer, Redacted: AlertNewCertificateRedacted, Identity: identity, CT: true, NeedNtfy: pending.NeedNtfy, NeedTelegram: pending.NeedTelegram, Priority: PriorityWarning, Tag: TagSkull, Domain: domain, Name: name})
			}
		}
	}
	return alerts
}

func dispatchCycleAlerts(app *AppState, cycleAlerts []Alert) {
	for _, alert := range cycleAlerts {
		if alert.CT {
			if notifier, ok := app.Notifier.(interface{ DispatchCT(Alert) }); ok {
				notifier.DispatchCT(alert)
			}
			continue
		}
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

	ctStatePath, ctLogPersist, err := app.InitializeCTStorage()
	if err != nil {
		return err
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
			_ = runMonitoringCycle(ctx, app, rdapHTTPClient, ctStatePath, ctLogPersist, prevRDAPStatus, prevDNSStatus, prevEmailStatus, prevConditions)

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
			Status: StatusPending, CheckSSL: dnsRecord.CheckSSL,
		}
	}
	if b, err := jsonv2.Marshal(initialState); err == nil {
		a.PrerenderedJSON.Store(b)
	}

}

// InitializeCTStorage ...
func (a *AppState) InitializeCTStorage() (string, map[string]CTLogState, error) {
	dataDir := a.configuration().DataDir
	if dataDir == StrEmpty {
		dataDir = DefaultDataDir
		if _, err := os.Stat(DirContainerApp); os.IsNotExist(err) {
			dataDir = DefaultLocalDataDir
		}
	}
	// #nosec G703 -- dataDir is deliberately configurable by the operator.
	if err := os.MkdirAll(dataDir, DirPermDefault); err != nil {
		return StrEmpty, nil, WrapError(MsgErrCreateDataDirectory, err)
	}
	ctLogsDir := filepath.Join(dataDir, DefaultCTLogsSubdir)
	a.CTLogsPath = ctLogsDir
	// #nosec G703 -- ctLogsDir is a fixed child of the operator-selected dataDir.
	if err := os.MkdirAll(ctLogsDir, DirPermDefault); err != nil {
		return StrEmpty, nil, WrapError(MsgErrCreateCTLogsDirectory, err)
	}
	ctStatePath := filepath.Join(dataDir, DefaultCTStateFileName)
	ctLogPersist, err := loadCTStateFile(ctStatePath, a.ReadCTState, a.WriteCTState)
	if err != nil {
		return StrEmpty, nil, WrapError(MsgErrLoadCTState, err)
	}

	return ctStatePath, ctLogPersist, nil
}
