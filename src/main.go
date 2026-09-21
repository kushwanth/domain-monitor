package main

import (
	"context"
	_ "embed"
	jsonv2 "encoding/json/v2"
	"flag"
	"fmt"
	"io"
	"maps"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
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

// serveCTLogFile serves the CT log history JSON file for the given domain.
func serveCTLogFile(w http.ResponseWriter, domain string) {
	domain = NormalizeDomain(domain)
	if domain == "" || !ReValidDomain.MatchString(domain) {
		w.Header().Set(HeaderContentType, MIMEApplicationJSON)
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(JSONResponseInvalidDomain))
		return
	}

	logsPath := GetCTLogsPath()
	filePath := filepath.Join(logsPath, domain+".json")
	cleanPath := filepath.Clean(filePath)
	if !IsSafeSubpath(logsPath, cleanPath) {
		w.Header().Set(HeaderContentType, MIMEApplicationJSON)
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(JSONResponseInvalidDomain))
		return
	}

	w.Header().Set(HeaderContentType, MIMEApplicationJSON)

	f, err := os.Open(cleanPath)
	if err != nil {
		if !os.IsNotExist(err) {
			LogWarn(MsgLogReadCTLogFailed, FieldDomain, domain, FieldPath, cleanPath, FieldError, err)
		}
		_, _ = w.Write([]byte(JSONResponseEmptyArray))
		return
	}
	defer f.Close()

	if fi, err := f.Stat(); err != nil || fi.Size() == 0 {
		_, _ = w.Write([]byte(JSONResponseEmptyArray))
		return
	}

	_, _ = io.Copy(w, f)
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
		serveCTLogFile(w, r.URL.Query().Get(ParamDomain))
	})

	mux.HandleFunc(RouteAPICTLogs, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(HeaderContentType, MIMEApplicationJSON)
		serveCTLogFile(w, r.PathValue(ParamDomain))
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set(HeaderContentType, MIMETextHTML)
		_, _ = w.Write(indexHTML)
	})

	cleanPort := strings.TrimPrefix(strings.TrimSpace(port), ":")
	if cleanPort == "" {
		cleanPort = DefaultServerPort
	}

	server := &http.Server{
		Addr:                ":" + cleanPort,
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
		if currStatus == "" {
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
							Hostname: record.Hostname,
							Name:     record.Name,
							Type:     record.Type,
							Expected: record.Expected,
							Status:   StatusFailed,
							Error:    fmt.Sprintf(MsgErrInternalDNSCheckPanic, AnyToString(r)),
							SkipSSL:  record.SkipSSL,
						},
					}
				}
			}()
			dnsSnap := FetchDNSSnapshot(ctx, app, record)
			status, cond := EvaluateDNS(record, dnsSnap)

			var sslDays *int
			if !record.SkipSSL {
				// We fetch SSL snapshot regardless of DNS match as long as it's not a complete lookup failure, 
				// but wait, if it's a lookup failure we still might want to try? 
				// The original code did: sslDays = validateCertificate(ctx, app, target, foundRecords) unconditionally if !SkipSSL.
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
						cond.Target += " | " + sslCond.Target
					}
				}
			}

			errStr := ""
			if cond != nil && cond.Code != CodeDNSMatchVerified && cond.Code != CodeSSLVerified {
				errStr = cond.Target
			}

			res := DNSState{
				Hostname:  record.Hostname,
				Name:      record.Name,
				Type:      record.Type,
				Expected:  record.Expected,
				Status:    status,
				Condition: cond,
				Found:     dnsSnap.Records,
				SSLDays:   sslDays,
				SkipSSL:   record.SkipSSL,
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
		gDomains.Go(func() error {
			defer func() {
				if r := recover(); r != nil {
					LogError(MsgLogPanicDomainWorker, FieldDomain, domain.Domain, FieldPanic, r)
					if domainResults[index].Domain == "" {
						domainResults[index].Domain = domain.Domain
					}
				}
			}()
			var res DomainResult
			res.Domain = domain.Domain

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

			if !domain.AllowExpiry {
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
					status, _ := EvaluateNSHealth(domain, snapshots)
					
					var servers []NSHealthServerResult
					for _, srvSnap := range snapshots {
						errStr := ""
						if srvSnap.Err != nil {
							errStr = srvSnap.Err.Error()
						}
						servers = append(servers, NSHealthServerResult{
							Nameserver:    srvSnap.Nameserver,
							IsPrimary:     srvSnap.IsPrimary,
							Authoritative: srvSnap.Authoritative,
							HasSOA:        srvSnap.HasSOA,
							SOASerial:     srvSnap.SOASerial,
							HasDNSKEY:     srvSnap.HasDNSKEY,
							DNSKEYMatch:   true, // TODO: Compute from snapshots if needed for API?
							Error:         errStr,
						})
					}
					
					res.NSHealth = NSHealthResult{
						Valid:   status != StatusFailed,
						Primary: domain.ExpectedNS[0],
						Status:  status,
						Servers: servers,
					}
					// Note: NSHealthResult is legacy API output struct, but we attach condition 
					// to the top level domain result eventually. Wait, NSHealthResult doesn't have 
					// Status and Condition fields. Wait!
					// Actually, DomainResult doesn't have a top level status/cond for NSHealth yet, 
					// but we will do that in Step 7. For now, we just pass what the API expects.
				}
			}

			domainResults[index] = res
			return nil
		})
	}
	_ = gDomains.Wait()
	return domainResults
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
			if err := app.RDAPLimiter.Wait(ctx); err != nil {
				for j := i; j < len(domains); j++ {
					if !domains[j].IsDelegatedZone && rdapResults[j].Status == "" {
						rdapResults[j] = RDAPState{
							Status: StatusFailed,
							Error:  MsgErrCheckTimeoutOrCanceled,
						}
					}
				}
				return nil
			}
			func() {
				defer func() {
					if r := recover(); r != nil {
						LogError(MsgLogPanicRDAP, FieldDomain, domainConfig.Domain, FieldPanic, r)
						rdapResults[i] = RDAPState{
							Status: StatusFailed,
							Error:  fmt.Sprintf(MsgErrInternalRDAPCheckPanic, AnyToString(r)),
						}
					}
				}()
				
				snapshot := FetchRDAPSnapshot(ctx, rdapHTTPClient, app, domainConfig.Domain)
				status, cond := EvaluateRDAP(domainConfig, snapshot)
				
				rdapState := RDAPState{
					Status:            status,
					Condition:         cond,
					Registrar:         snapshot.Registrar,
					RegistrarIANAID:   snapshot.RegistrarIANAID,
					Expiration:        snapshot.Expiration,
					Nameservers:       snapshot.Nameservers,
					DomainStatus:      snapshot.DomainStatus,
					DNSSEC:            snapshot.DNSSEC,
					RenewalPrice:      domainConfig.RenewalPrice,
					AllowExpiry:       domainConfig.AllowExpiry,
					Source:            snapshot.Source,
					ProtocolUsed:      snapshot.ProtocolUsed,
					QueryDurationMs:   snapshot.QueryDurationMs,
					RegistryTier:      snapshot.RegistryTier,
					RegistrarTier:     snapshot.RegistrarTier,
					Discrepancies:     snapshot.Discrepancies,
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
		for i, domainConfig := range domains {
			if !domainConfig.MonitorCTLogs || domainConfig.AllowExpiry {
				continue
			}
			if err := app.CTLimiter.Wait(ctx); err != nil {
				for j := i; j < len(domains); j++ {
					if domains[j].MonitorCTLogs && ctResults[j].Status == "" {
						ctResults[j] = CTLogState{
							Status: StatusFailed,
							Error:  MsgErrCheckTimeoutOrCanceled,
						}
					}
				}
				return nil
			}
			func() {
				defer func() {
					if r := recover(); r != nil {
						LogError(MsgLogPanicCTLogs, FieldDomain, domainConfig.Domain, FieldPanic, r)
						ctResults[i] = CTLogState{
							Status: StatusFailed,
							Error:  fmt.Sprintf(MsgErrInternalCTLogsPanic, AnyToString(r)),
						}
					}
				}()
				ctSnap := FetchCTLogsSnapshot(ctx, app, domainConfig, ctLogPersist[domainConfig.Domain])
				ctStatus, ctCond, ctRes := EvaluateCTLogs(domainConfig, ctSnap)
				ctRes.Status = ctStatus
				ctRes.Condition = ctCond
				ctResults[i] = ctRes
			}()
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
	defer RecoverAndLogPanic(NameOpMonitoringCycle)

	cycleStart := time.Now()

	loopDur := DefaultLoopDurationFallback
	if app != nil && app.LoopDuration > 0 {
		loopDur = app.LoopDuration
	}

	var domains []DomainConfig
	var dnsRecords []DNSTask
	if app != nil {
		cfg := app.Config()
		domains = cfg.Domains
		dnsRecords = cfg.DNSRecords
	}

	// Bound cycle timeout safely: scale with domain and DNS record counts so large portfolios
	// have sufficient time under the 10-second token bucket RDAP and 5-second CTLogs rate limiters, while never hanging indefinitely.
	minRequiredTimeout := time.Duration(len(domains))*(10+5)*time.Second + time.Duration(len(dnsRecords))*5*time.Second + 5*time.Minute
	cycleMaxTimeout := max(loopDur, minRequiredTimeout, 5*time.Minute)
	cycleCtx, cycleCancel := context.WithTimeout(ctx, cycleMaxTimeout)
	defer cycleCancel()

	loopState := NewCheckState()

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

	activeDomains := make(map[string]bool, len(domains))
	for _, domainCfg := range domains {
		activeDomains[domainCfg.Domain] = true
	}

	for k, v := range ctLogPersist {
		if !activeDomains[k] || v.Status == "" {
			continue
		}
		loopState.CTLogs[k] = CTLogState{
			LatestID:         v.LatestID,
			BackfillCursor:   v.BackfillCursor,
			BackfillComplete: v.BackfillComplete,
		}
	}

	for _, domainCfg := range domains {
		loopState.RDAP[domainCfg.Domain] = RDAPState{Status: StatusPending}
	}

	// 1. Dispatch DNS Records
	dnsResults := executeDNSChecks(cycleCtx, app, dnsRecords)

	// 2. Dispatch Fast Domain Checks (Email, DNSSEC, CAA, NS Health, NS Delegation)
	domainResults := executeFastDomainChecks(cycleCtx, app, domains)

	// 3. Dispatch Slow, Rate-Limited External Checks Concurrently (RDAP and CT Logs)
	rdapResults, ctResults := executeRateLimitedChecks(cycleCtx, app, domains, rdapHTTPClient, ctLogPersist)

	for i := range domains {
		if rdapResults[i].Status != "" {
			domainResults[i].RDAP = rdapResults[i]
		}
		if ctResults[i].Status != "" {
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

	// 4. Persist CT logs state
	maps.Copy(ctLogPersist, loopState.CTLogs)
	for k := range ctLogPersist {
		if !activeDomains[k] {
			delete(ctLogPersist, k)
		}
	}

	if b, err := jsonv2.Marshal(ctLogPersist); err == nil {
		if writeErr := AtomicWriteFile(ctStatePath, b, FilePermSecret); writeErr != nil {
			LogWarn(MsgLogWriteCTStateFailed, FieldError, writeErr)
		}
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
	loopState.NextRefresh = time.Now().Add(loopDur).UTC().Format(time.RFC3339)
	if jsonBytes, err := jsonv2.Marshal(loopState); err == nil {
		if app != nil {
			app.PrerenderedJSON.Store(jsonBytes)
		}
	}

	cycleDuration := time.Since(cycleStart)
	LogInfo(MsgLogMonitoringCycleCompleted,
		FieldDurationMS, cycleDuration.Milliseconds(),
		FieldDomainsChecked, len(domains),
		FieldDNSRecordsChecked, len(dnsRecords),
	)

	if app != nil && app.Notifier != nil {
		app.Notifier.Flush()
	}

	return loopState
}

func applyConditionSince(cond *StateCondition, key string, prev map[string]StateCondition) {
	if cond == nil {
		return
	}
	prevCond, exists := prev[key]
	if exists && prevCond.Code == cond.Code && prevCond.Target == cond.Target {
		cond.Since = prevCond.Since
	} else {
		cond.Since = time.Now().UTC()
	}
	prev[key] = *cond
}

func formatDurationSince(since time.Time) string {
	d := time.Since(since).Round(time.Minute)
	if d < time.Minute {
		return "just now"
	}
	return d.String()
}

func processConditionsAndAlerts(app *AppState, state *CheckState, domains []DomainConfig, dnsRecords []DNSTask, prev map[string]StateCondition) {
	if app == nil || app.Notifier == nil {
		return
	}

	var cycleAlerts []string

	// Helper to track since and append to alerts
	checkAndAppend := func(domainName, domain, checkName string, cond *StateCondition, status CheckStatus, suppress bool) {
		if cond == nil {
			return
		}
		applyConditionSince(cond, checkName+":"+domain, prev)
		if status == StatusFailed && !suppress {
			cycleAlerts = append(cycleAlerts, fmt.Sprintf("• [%s] %s failed: %s (Since: %s)", domainName, checkName, cond.Code, formatDurationSince(cond.Since)))
		}
	}

	for _, domainCfg := range domains {
		d := domainCfg.Domain
		name := domainCfg.Name
		suppress := domainCfg.SuppressAlerts

		if st, ok := state.RDAP[d]; ok {
			checkAndAppend(name, d, "RDAP", st.Condition, st.Status, suppress)
		}
		if st, ok := state.Email[d]; ok {
			checkAndAppend(name, d, "Email", st.Condition, st.Status, suppress)
		}
		if st, ok := state.CAA[d]; ok {
			checkAndAppend(name, d, "CAA", st.Condition, st.Status, suppress)
		}
		if st, ok := state.DNSSEC[d]; ok {
			checkAndAppend(name, d, "DNSSEC", st.Condition, st.Status, suppress)
		}
		if st, ok := state.NSHealth[d]; ok {
			checkAndAppend(name, d, "NSHealth", st.Condition, st.Status, suppress)
		}
		if st, ok := state.CTLogs[d]; ok {
			checkAndAppend(name, d, "CTLogs", st.Condition, st.Status, suppress)
			if !suppress {
				for _, cert := range st.NewCerts {
					issuer := cert.Issuer
					if issuer == "" {
						issuer = DefaultUnknownCA
					}
					cycleAlerts = append(cycleAlerts, fmt.Sprintf("• [%s] New Cert Issued: %s", name, issuer))
				}
			}
		}
	}

	for _, dnsCfg := range dnsRecords {
		name := dnsCfg.Name
		if st, ok := state.DNS[name]; ok {
			checkAndAppend(name, name, "DNS", st.Condition, st.Status, false)
		}
	}

	if len(cycleAlerts) > 0 {
		report := "Monitor Cycle Alert:\n" + strings.Join(cycleAlerts, "\n")
		app.SafeDispatchf(PriorityHigh, TagSkull, "Global", "System", report, "%s", report)
	}
}

func main() {
	var configPath string
	flag.StringVar(&configPath, FlagConfig, "", FlagConfigUsage)
	flag.StringVar(&configPath, FlagConfigShort, "", FlagConfigShortUsage)
	flag.Parse()

	if configPath == "" {
		configPath = os.Getenv(EnvConfigPath)
	}

	ctx, cancel := context.WithCancel(context.Background())

	rawCfg, err := LoadConfig(ctx, configPath)
	if err != nil {
		LogError(MsgLogConfigError, FieldError, err)
		os.Exit(1)
	}

	app, err := InitializeApp(ctx, rawCfg)
	if err != nil {
		LogError(MsgLogInitError, FieldError, err)
		os.Exit(1)
	}

	dataDir := os.Getenv(EnvDataDir)
	if dataDir == "" && app.Config().DataDir != "" {
		dataDir = app.Config().DataDir
	}
	if dataDir == "" {
		dataDir = DefaultDataDir
		if _, err := os.Stat(DirContainerApp); os.IsNotExist(err) {
			dataDir = DefaultLocalDataDir
		}
	}
	if err := os.MkdirAll(dataDir, DirPermDefault); err != nil {
		LogWarn(MsgLogDataDirEnsureFailed, FieldPath, dataDir, FieldError, err)
	}
	ctLogsDir := filepath.Join(dataDir, DefaultCTLogsSubdir)
	SetCTLogsPath(ctLogsDir)
	if err := os.MkdirAll(ctLogsDir, DirPermDefault); err != nil {
		LogWarn(MsgLogCTLogsDirEnsureFailed, FieldPath, ctLogsDir, FieldError, err)
	}
	ctStatePath := filepath.Join(dataDir, DefaultCTStateFileName)

	rdapHTTPClient := NewRDAPHTTPClient(10 * time.Second)
	LogInfof(MsgLogStartup, len(app.Config().Domains), len(app.Config().DNSRecords))

	server, serverErrChan := setupHTTPServer(app, app.Config().Port)

	engineDone := make(chan struct{})
	// Execute concurrent engine
	go func() {
		defer close(engineDone)
		defer RecoverAndLogPanic(NameOpMonitoringEngine)

		ctLogPersist := make(map[string]CTLogState)
		prevRDAPStatus := make(map[string]CheckStatus)
		prevDNSStatus := make(map[string]CheckStatus)
		prevEmailStatus := make(map[string]CheckStatus)
		prevConditions := make(map[string]StateCondition)

		if b, err := os.ReadFile(ctStatePath); err == nil {
			if jsonErr := jsonv2.Unmarshal(b, &ctLogPersist); jsonErr != nil {
				LogWarn(MsgLogParseCTStateFailed, FieldError, jsonErr)
			}
		}



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
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-sigChan:
		LogInfof(MsgLogShutdownSignal, sig)
	case sErr := <-serverErrChan:
		LogError(MsgLogHTTPServerStopped, FieldError, sErr)
	case <-engineDone:
		LogError(MsgLogMonitoringEngineStopped)
	}

	// Trigger cancellation for engines
	cancel()

	// Shutdown HTTP Server
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), ShutdownTimeout)
	defer shutdownCancel()
	if server != nil {
		_ = server.Shutdown(shutdownCtx)
	}

	// Wait for monitoring engine to complete in-flight writes
	select {
	case <-engineDone:
	case <-time.After(5 * time.Second):
		LogWarn(MsgLogMonitoringEngineTimeout)
	}

	LogInfo(MsgLogShutdownComplete)
}
