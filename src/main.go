package main

import (
	"context"
	_ "embed"
	jsonv2 "encoding/json/v2"
	"flag"
	"fmt"
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
	"golang.org/x/time/rate"
)

//go:embed index.html
var indexHTML []byte

func securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("X-XSS-Protection", "0")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'self'; form-action 'self';")
		next.ServeHTTP(w, r)
	})
}

// serveCTLogFile serves the CT log history JSON file for the given domain.
func serveCTLogFile(w http.ResponseWriter, domain string) {
	domain = NormalizeDomain(domain)
	if domain == "" || !ReValidDomain.MatchString(domain) {
		http.Error(w, `{"error": "invalid domain"}`, http.StatusBadRequest)
		return
	}

	filePath := filepath.Join(CTLogsPath, domain+".json")
	cleanPath := filepath.Clean(filePath)
	if !IsSafeSubpath(CTLogsPath, cleanPath) {
		http.Error(w, `{"error": "invalid domain"}`, http.StatusBadRequest)
		return
	}

	b, err := os.ReadFile(cleanPath)
	if err != nil {
		if !os.IsNotExist(err) {
			LogWarn("Failed to read CT log history file", "domain", domain, "path", cleanPath, "error", err)
		}
		_, _ = w.Write([]byte("[]"))
		return
	}
	_, _ = w.Write(b)
}

// NewCheckState returns a fresh CheckState with all maps initialized.
func NewCheckState() *CheckState {
	return &CheckState{
		RDAP:     make(map[string]*RDAPState),
		DNS:      make(map[string]*DNSState),
		Email:    make(map[string]*EmailState),
		CAA:      make(map[string]*CAAResult),
		DNSSEC:   make(map[string]*DNSSECResult),
		CTLogs:   make(map[string]*CTLogState),
		NSHealth: make(map[string]*NSHealthResult),
	}
}

func setupHTTPServer(app *AppState, port string) (*http.Server, <-chan error) {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	mux.HandleFunc("GET /api/state", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-cache")
		if app != nil {
			if b, ok := app.PrerenderedJSON.Load().([]byte); ok {
				_, _ = w.Write(b)
				return
			}
		}
		_, _ = w.Write([]byte(`{"status":"initializing"}`))
	})

	mux.HandleFunc("GET /api/certs", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		serveCTLogFile(w, r.URL.Query().Get("domain"))
	})

	mux.HandleFunc("GET /api/ctlogs/{domain}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		serveCTLogFile(w, r.PathValue("domain"))
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(indexHTML)
	})

	cleanPort := strings.TrimPrefix(strings.TrimSpace(port), ":")
	if cleanPort == "" {
		cleanPort = "8080"
	}

	server := &http.Server{
		Addr:                ":" + cleanPort,
		Handler:             securityHeadersMiddleware(mux),
		ReadTimeout:         5 * time.Second,
		WriteTimeout:        10 * time.Second,
		IdleTimeout:         120 * time.Second,
		MaxHeaderValueCount: 100,
	}

	errChan := make(chan error, 1)
	go func() {
		LogInfof(MsgLogHTTPAPI, cleanPort)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			LogError("HTTP server failed", "error", err)
			errChan <- err
		}
	}()

	return server, errChan
}

const defaultMaxConcurrency = 8

// logStateTransitions logs changes in check status across cycles in deterministic sorted order.
func logStateTransitions[T comparable](checkName, targetKey string, current map[string]T, getStatus func(T) CheckStatus, prev map[string]CheckStatus) {
	var zero T
	for _, k := range slices.Sorted(maps.Keys(current)) {
		item := current[k]
		if item == zero {
			continue
		}
		currStatus := getStatus(item)
		if prevStatus, ok := prev[k]; ok && prevStatus != currStatus {
			LogInfo("State transition", "check", checkName, targetKey, k, "prev", prevStatus, "current", currStatus)
		}
		prev[k] = currStatus
	}
	for k := range prev {
		if _, ok := current[k]; !ok {
			delete(prev, k)
		}
	}
}

// runMonitoringCycle executes a single complete monitoring pass across all configured DNS tasks and domains.
func runMonitoringCycle(
	ctx context.Context,
	app *AppState,
	rdapHTTPClient *http.Client,
	ctStatePath string,
	ctLogPersist map[string]*CTLogState,
	prevRDAPStatus map[string]CheckStatus,
	prevDNSStatus map[string]CheckStatus,
	prevEmailStatus map[string]CheckStatus,
) *CheckState {
	defer RecoverAndLogPanic("Monitoring cycle")

	cycleStart := time.Now()

	loopDur := 6 * time.Hour
	if app != nil && app.LoopDuration > 0 {
		loopDur = app.LoopDuration
	}

	var domains []DomainConfig
	var dnsRecords []DNSTask
	if app != nil && app.Config != nil {
		domains = app.Config.Domains
		dnsRecords = app.Config.DNSRecords
	}

	// Bound cycle timeout safely: scale with domain and DNS record counts so large portfolios
	// have sufficient time under the 10-second token bucket RDAP and 5-second CTLogs rate limiters, while never hanging indefinitely.
	minRequiredTimeout := time.Duration(len(domains))*(10+5)*time.Second + time.Duration(len(dnsRecords))*5*time.Second + 5*time.Minute
	cycleMaxTimeout := max(loopDur, minRequiredTimeout, 5*time.Minute)
	cycleCtx, cycleCancel := context.WithTimeout(ctx, cycleMaxTimeout)
	defer cycleCancel()

	if app != nil && app.Notifier != nil {
		app.Notifier.StartCycle()
	}

	loopState := NewCheckState()

	if ctLogPersist == nil {
		ctLogPersist = make(map[string]*CTLogState)
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
		if !activeDomains[k] || v == nil {
			continue
		}
		loopState.CTLogs[k] = &CTLogState{
			LatestID:         v.LatestID,
			BackfillCursor:   v.BackfillCursor,
			BackfillComplete: v.BackfillComplete,
		}
	}

	for _, domainCfg := range domains {
		loopState.RDAP[domainCfg.Domain] = &RDAPState{Status: StatusPending}
	}

	// 1. Dispatch DNS Records
	dnsResults := make([]DNSResult, len(dnsRecords))
	gDNS, _ := errgroup.WithContext(cycleCtx)
	gDNS.SetLimit(min(len(dnsRecords), defaultMaxConcurrency))
	for i, dnsTask := range dnsRecords {
		record := dnsTask
		index := i
		gDNS.Go(func() error {
			defer func() {
				if r := recover(); r != nil {
					LogError("Recovered from unexpected panic in DNS check worker", "record", record.Name, "panic", r)
					dnsResults[index] = DNSResult{
						Name: record.Name,
						State: &DNSState{
							Hostname: record.Hostname,
							Name:     record.Name,
							Type:     record.Type,
							Expected: record.Expected,
							Status:   StatusFailed,
							Error:    fmt.Sprintf("internal check panic: %v", r),
							SkipSSL:  record.SkipSSL,
							SSLDays:  SSLDaysNotApplicable,
						},
					}
				}
			}()
			res := evaluateDNS(cycleCtx, app, record)
			dnsResults[index] = DNSResult{Name: record.Name, State: res}
			return nil
		})
	}
	_ = gDNS.Wait()

	// 2. Dispatch Fast Domain Checks (Email, DNSSEC, CAA, NS Health, NS Delegation)
	domainResults := make([]DomainResult, len(domains))
	gDomains, _ := errgroup.WithContext(cycleCtx)
	gDomains.SetLimit(min(len(domains), defaultMaxConcurrency))

	for i, domainConfig := range domains {
		domain := domainConfig
		index := i
		gDomains.Go(func() error {
			defer func() {
				if r := recover(); r != nil {
					LogError("Recovered from unexpected panic in Domain check worker", "domain", domain.Domain, "panic", r)
					if domainResults[index].Domain == "" {
						domainResults[index].Domain = domain.Domain
					}
				}
			}()
			var res DomainResult
			res.Domain = domain.Domain
			res.Email = evaluateEmailSecurity(cycleCtx, app, domain)

			if domain.IsDelegatedZone {
				res.RDAP = evaluateNSDelegation(cycleCtx, app, domain)
			}

			res.DNSSEC = evaluateDNSSEC(cycleCtx, app, domain)
			res.CAA = evaluateCAA(cycleCtx, app, domain)

			if domain.VerifyNSHealth && len(domain.ExpectedNS) > 0 {
				res.NSHealth = evaluateNSHealth(cycleCtx, app, domain)
			}

			domainResults[index] = res
			return nil
		})
	}
	_ = gDomains.Wait()

	// 3. Dispatch Slow, Rate-Limited External Checks Concurrently (RDAP and CT Logs)
	rdapLimiter := rate.NewLimiter(rate.Every(10*time.Second), 1)
	ctLimiter := rate.NewLimiter(rate.Every(5*time.Second), 1)

	rdapResults := make([]*RDAPState, len(domains))
	ctResults := make([]*CTLogState, len(domains))

	gRateLimitedChecks, _ := errgroup.WithContext(cycleCtx)

	// RDAP pipeline: evaluates non-delegated zones with 10s token bucket
	gRateLimitedChecks.Go(func() error {
		defer RecoverAndLogPanic("RDAP check worker")
		for i, domainConfig := range domains {
			if domainConfig.IsDelegatedZone {
				continue
			}
			if err := rdapLimiter.Wait(cycleCtx); err != nil {
				for j := i; j < len(domains); j++ {
					if !domains[j].IsDelegatedZone && rdapResults[j] == nil {
						rdapResults[j] = &RDAPState{
							Status: StatusFailed,
							Error:  "check timed out or canceled",
						}
					}
				}
				return nil
			}
			func() {
				defer func() {
					if r := recover(); r != nil {
						LogError("Recovered from unexpected panic in RDAP evaluation", "domain", domainConfig.Domain, "panic", r)
						rdapResults[i] = &RDAPState{
							Status: StatusFailed,
							Error:  fmt.Sprintf("internal rdap check panic: %v", r),
						}
					}
				}()
				rdapResults[i] = evaluateRDAP(cycleCtx, rdapHTTPClient, app, domainConfig)
			}()
		}
		return nil
	})

	// CT Logs pipeline: evaluates monitored domains with 5s token bucket
	gRateLimitedChecks.Go(func() error {
		defer RecoverAndLogPanic("CT logs worker")
		for i, domainConfig := range domains {
			if !domainConfig.MonitorCTLogs {
				continue
			}
			if err := ctLimiter.Wait(cycleCtx); err != nil {
				for j := i; j < len(domains); j++ {
					if domains[j].MonitorCTLogs && ctResults[j] == nil {
						ctResults[j] = &CTLogState{
							Status: StatusFailed,
							Error:  "check timed out or canceled",
						}
					}
				}
				return nil
			}
			func() {
				defer func() {
					if r := recover(); r != nil {
						LogError("Recovered from unexpected panic in CT logs evaluation", "domain", domainConfig.Domain, "panic", r)
						ctResults[i] = &CTLogState{
							Status: StatusFailed,
							Error:  fmt.Sprintf("internal ct logs panic: %v", r),
						}
					}
				}()
				ctResults[i] = evaluateCTLogs(cycleCtx, app, domainConfig, ctLogPersist[domainConfig.Domain])
			}()
		}
		return nil
	})

	_ = gRateLimitedChecks.Wait()

	for i := range domains {
		if rdapResults[i] != nil {
			domainResults[i].RDAP = rdapResults[i]
		}
		if ctResults[i] != nil {
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

	// Invariant validation: mathematically verify that all expected checks are populated and zero remain in pending status
	if invariantErrs := ValidateCycleInvariants(app, loopState); len(invariantErrs) > 0 {
		for _, invErr := range invariantErrs {
			LogError("Cycle invariant violation detected", "error", invErr)
		}
	}

	// 4. Persist CT logs state
	maps.Copy(ctLogPersist, loopState.ExportCTLogs())
	for k := range ctLogPersist {
		if !activeDomains[k] {
			delete(ctLogPersist, k)
		}
	}

	if b, err := jsonv2.Marshal(ctLogPersist); err == nil {
		if writeErr := AtomicWriteFile(ctStatePath, b, 0600); writeErr != nil {
			LogWarn("Failed to write ct_state.json", "error", writeErr)
		}
	}

	// 5. State transition logging
	logStateTransitions("RDAP", "domain", loopState.RDAP, func(s *RDAPState) CheckStatus { return s.Status }, prevRDAPStatus)
	logStateTransitions("DNS", "record", loopState.DNS, func(s *DNSState) CheckStatus { return s.Status }, prevDNSStatus)
	logStateTransitions("Email", "domain", loopState.Email, func(s *EmailState) CheckStatus { return s.Status }, prevEmailStatus)

	// 6. Dispatch notifications with dedicated timeout
	if app != nil && app.Notifier != nil {
		notifyCtx, notifyCancel := context.WithTimeout(ctx, 30*time.Second)
		app.Notifier.Flush(notifyCtx)
		app.Notifier.Wait()
		notifyCancel()
		app.Notifier.EndCycle()
	}

	// 7. Update timestamps and pre-render atomic JSON cache
	loopState.LastUpdated = time.Now().UTC().Format(time.RFC3339)
	loopState.NextRefresh = time.Now().Add(loopDur).UTC().Format(time.RFC3339)
	if jsonBytes, err := jsonv2.Marshal(loopState); err == nil {
		if app != nil {
			app.PrerenderedJSON.Store(jsonBytes)
		}
	}

	cycleDuration := time.Since(cycleStart)
	LogInfo("Monitoring cycle completed",
		"duration_ms", cycleDuration.Milliseconds(),
		"domains_checked", len(domains),
		"dns_records_checked", len(dnsRecords),
	)

	return loopState
}

// ValidateCycleInvariants formally verifies that all configured domains and DNS tasks
// have transitioned to concrete final states and no state leaks or dangling pending statuses remain.
func ValidateCycleInvariants(app *AppState, state *CheckState) []error {
	if app == nil || app.Config == nil || state == nil {
		return nil
	}
	var errs []error

	for _, domainCfg := range app.Config.Domains {
		d := domainCfg.Domain
		rdap, ok := state.RDAP[d]
		if !ok || rdap == nil {
			errs = append(errs, fmt.Errorf("domain %s: missing RDAP/delegation state", d))
		} else if rdap.Status == StatusPending {
			errs = append(errs, fmt.Errorf("domain %s: RDAP/delegation check remained in pending status", d))
		}

		if domainCfg.CheckEmailSecurity {
			if email, ok := state.Email[d]; !ok || email == nil {
				errs = append(errs, fmt.Errorf("domain %s: missing email security state", d))
			}
		}

		if domainCfg.DNSSEC {
			if dnssec, ok := state.DNSSEC[d]; !ok || dnssec == nil {
				errs = append(errs, fmt.Errorf("domain %s: missing DNSSEC state", d))
			}
		}

		if domainCfg.CAA != nil {
			if caa, ok := state.CAA[d]; !ok || caa == nil {
				errs = append(errs, fmt.Errorf("domain %s: missing CAA state", d))
			}
		}

		if domainCfg.VerifyNSHealth && len(domainCfg.ExpectedNS) > 0 {
			if nsHealth, ok := state.NSHealth[d]; !ok || nsHealth == nil {
				errs = append(errs, fmt.Errorf("domain %s: missing nameserver health state", d))
			}
		}

		if domainCfg.MonitorCTLogs {
			if ctLog, ok := state.CTLogs[d]; !ok || ctLog == nil {
				errs = append(errs, fmt.Errorf("domain %s: missing CT logs state", d))
			} else if ctLog.Status == StatusPending {
				errs = append(errs, fmt.Errorf("domain %s: CT logs remained in pending status", d))
			}
		}
	}

	for _, dnsRecord := range app.Config.DNSRecords {
		name := dnsRecord.Name
		dnsState, ok := state.DNS[name]
		if !ok || dnsState == nil {
			errs = append(errs, fmt.Errorf("dns record %s: missing DNS state", name))
		} else if dnsState.Status == StatusPending {
			errs = append(errs, fmt.Errorf("dns record %s: remained in pending status", name))
		}
	}

	return errs
}

func main() {
	var configPath string
	flag.StringVar(&configPath, "config", "", "Path to the JSON config file")
	flag.StringVar(&configPath, "c", "", "Path to the JSON config file (shorthand)")
	flag.Parse()

	if configPath == "" {
		configPath = os.Getenv("CONFIG_PATH")
	}

	ctx, cancel := context.WithCancel(context.Background())

	app, rawCfg, err := LoadConfig(ctx, configPath)
	if err != nil {
		LogError("Configuration error", "error", err)
		os.Exit(1)
	}

	if err := InitializeDependencies(ctx, app, rawCfg); err != nil {
		LogError("Initialization error", "error", err)
		os.Exit(1)
	}

	dataDir := os.Getenv("DATA_DIR")
	if dataDir == "" && app.Config.DataDir != "" {
		dataDir = app.Config.DataDir
	}
	if dataDir == "" {
		dataDir = DefaultDataDir
		if _, err := os.Stat("/app"); os.IsNotExist(err) {
			dataDir = "./data"
		}
	}
	if err := os.MkdirAll(dataDir, 0775); err != nil {
		LogWarn("Failed to ensure data directory exists (ensure directory is writable by UID 65532 or use :U volume mount)", "path", dataDir, "error", err)
	}
	CTLogsPath = filepath.Join(dataDir, "ct_logs")
	if err := os.MkdirAll(CTLogsPath, 0775); err != nil {
		LogWarn("Failed to ensure ct_logs directory exists (ensure directory is writable by UID 65532 or use :U volume mount)", "path", CTLogsPath, "error", err)
	}
	ctStatePath := filepath.Join(dataDir, "ct_state.json")

	rdapHTTPClient := NewRDAPHTTPClient(10 * time.Second)
	LogInfof(MsgLogStartup, len(app.Config.Domains), len(app.Config.DNSRecords))



	// Pre-render initial application state immediately so GET / and GET /api/state
	// are instantly available upon process startup.
	initialState := NewCheckState()
	for _, domainCfg := range app.Config.Domains {
		initialState.RDAP[domainCfg.Domain] = &RDAPState{Status: StatusPending}
		if domainCfg.VerifyNSHealth && len(domainCfg.ExpectedNS) > 0 {
			initialState.NSHealth[domainCfg.Domain] = &NSHealthResult{
				Primary: domainCfg.ExpectedNS[0],
			}
		}
	}
	for _, dnsRecord := range app.Config.DNSRecords {
		key := dnsRecord.Name
		initialState.DNS[key] = &DNSState{
			Hostname: dnsRecord.Hostname,
			Name:     dnsRecord.Name,
			Type:     dnsRecord.Type,
			Expected: dnsRecord.Expected,
			Status:   StatusPending,
			SkipSSL:  dnsRecord.SkipSSL,
			SSLDays:  SSLDaysNotApplicable,
		}
	}
	initialState.LastUpdated = time.Now().UTC().Format(time.RFC3339)
	initialState.NextRefresh = time.Now().Add(app.LoopDuration).UTC().Format(time.RFC3339)
	if b, err := jsonv2.Marshal(initialState); err == nil {
		app.PrerenderedJSON.Store(b)
	}

	server, serverErrChan := setupHTTPServer(app, app.Config.Port)

	engineDone := make(chan struct{})
	// Execute concurrent engine
	go func() {
		defer close(engineDone)
		defer func() {
			flushCtx, flushCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer flushCancel()
			if app != nil && app.Notifier != nil {
				app.Notifier.Flush(flushCtx)
				app.Notifier.Wait()
			}
		}()
		defer RecoverAndLogPanic("Monitoring engine")

		ctLogPersist := make(map[string]*CTLogState)
		prevRDAPStatus := make(map[string]CheckStatus)
		prevDNSStatus := make(map[string]CheckStatus)
		prevEmailStatus := make(map[string]CheckStatus)

		if b, err := os.ReadFile(ctStatePath); err == nil {
			if jsonErr := jsonv2.Unmarshal(b, &ctLogPersist); jsonErr != nil {
				LogWarn("Failed to parse ct_state.json", "error", jsonErr)
			}
		}

		for {
			_ = runMonitoringCycle(ctx, app, rdapHTTPClient, ctStatePath, ctLogPersist, prevRDAPStatus, prevDNSStatus, prevEmailStatus)

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
		LogError("HTTP server stopped unexpectedly", "error", sErr)
	case <-engineDone:
		LogError("Monitoring engine stopped unexpectedly")
	}

	// Trigger cancellation for engines
	cancel()

	// Shutdown HTTP Server
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	if server != nil {
		_ = server.Shutdown(shutdownCtx)
	}

	// Wait for monitoring engine to complete in-flight writes
	select {
	case <-engineDone:
	case <-time.After(5 * time.Second):
		LogWarn("Monitoring engine shutdown timed out")
	}

	// Wait for notifications to complete
	if app != nil && app.Notifier != nil {
		app.Notifier.Wait()
	}

	LogInfo(MsgLogShutdownComplete)
}
