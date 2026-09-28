package main

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

type publishedState struct {
	body []byte
	etag string
}

func storePublishedState(app *AppState, body []byte) {
	digest := sha256.Sum256(body)
	app.publishedState.Store(&publishedState{body: body, etag: `"` + hex.EncodeToString(digest[:]) + `"`})
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
		if app != nil {
			if state := app.publishedState.Load(); state != nil {
				w.Header().Set("ETag", state.etag)
				if r.Header.Get("If-None-Match") == state.etag {
					w.WriteHeader(http.StatusNotModified)
					return
				}
				_, _ = w.Write(state.body)
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

type conditionKey struct {
	check  string
	domain string
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

func evaluateDNSCheck(ctx context.Context, app *AppState, record DNSTask) (result DNSResult) {
	result.Name = record.Name
	defer func() {
		if r := recover(); r != nil {
			LogError(MsgLogPanicDNSWorker, FieldRecord, record.Name, FieldPanic, r)
			result.State = DNSState{
				Hostname: record.Hostname, Name: record.Name, Type: record.Type,
				Expected: slices.Clone(record.Expected), Status: StatusFailed,
				Error:     fmt.Sprintf(MsgErrInternalDNSCheckPanic, AnyToString(r)),
				Condition: &StateCondition{Code: CodeDNSLookupFailed, Target: StrInternalDNSCheckPanic},
			}
		}
	}()
	dnsSnap := FetchDNSSnapshot(ctx, app, record)
	status, cond := EvaluateDNS(record, dnsSnap)
	errStr := StrEmpty
	if cond != nil && cond.Code != CodeDNSMatchVerified {
		errStr = cond.Target
	}
	result.State = DNSState{
		Hostname: record.Hostname, Name: record.Name, Type: record.Type,
		Expected: slices.Clone(record.Expected), Status: status, Condition: cond,
		Found: dnsSnap.Records, Error: errStr,
	}
	return result
}

func evaluateFastDomainChecks(ctx context.Context, app *AppState, domain DomainConfig) (result DomainResult) {
	result.Domain = domain.Domain
	defer func() {
		if r := recover(); r != nil {
			LogError(MsgLogPanicDomainWorker, FieldDomain, domain.Domain, FieldPanic, r)
			fillPanicDomainResults(domain, &result, r)
		}
	}()
	res := &result

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
			Unused:          domain.Unused,
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

			servers := make([]NSHealthServerResult, 0, len(snapshots))
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

	return result
}

// executeFastChecks shares one bounded worker group across DNS and domain work.
// Each completed result is transferred into the cycle's keyed API state.
func executeFastChecks(ctx context.Context, app *AppState, cfg AppConfig, active activeChecks, state *CheckState) {
	var mu sync.Mutex
	dnsCount := len(active.dnsRecords)
	runBoundedChecks(dnsCount+len(active.domains), func(index int) {
		isDNS, checkIndex := fastCheckSlot(index, dnsCount, len(active.domains))
		if isDNS {
			result := evaluateDNSCheck(ctx, app, cfg.DNSRecords[active.dnsRecords[checkIndex]])
			mu.Lock()
			storeDNSResult(state, result)
			mu.Unlock()
			return
		}
		result := evaluateFastDomainChecks(ctx, app, cfg.Domains[active.domains[checkIndex]])
		mu.Lock()
		state.takeDomainResult(result)
		mu.Unlock()
	})
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

func fillPanicDomainResults(domain DomainConfig, res *DomainResult, recovered any) {
	message := fmt.Sprintf(MsgErrDomainCheckPanic, AnyToString(recovered))
	if domain.CheckEmailSecurity && res.Email.Status == StatusUnknown {
		res.Email = EmailState{Provider: domain.MailProvider, Status: StatusFailed, Error: message, Condition: &StateCondition{Code: CodeDNSLookupFailed, Target: message}}
	}
	if domain.IsDelegatedZone && res.RDAP.Status == StatusUnknown {
		res.RDAP = RDAPState{Status: StatusFailed, Error: message, IsDelegatedZone: true, Unused: domain.Unused, Condition: &StateCondition{Code: CodeRDAPHTTPError, Target: message}}
	}
	if domain.DNSSEC && res.DNSSEC.Status == StatusUnknown {
		res.DNSSEC = DNSSECResult{Status: StatusFailed, Error: message, Condition: &StateCondition{Code: CodeDNSSECNetworkError, Target: message}}
	}

	if domain.VerifyNSHealth && res.NSHealth.Status == StatusUnknown {
		res.NSHealth = NSHealthResult{Status: StatusFailed, Condition: &StateCondition{Code: CodeNSUnreachable, Target: message}}
	}
}

// executeRateLimitedChecks writes serial RDAP results directly into the cycle-owned state.
func executeRateLimitedChecks(ctx context.Context, app *AppState, domains []DomainConfig, active []int, rdapHTTPClient *http.Client, state *CheckState) {
	for _, index := range active {
		domain := domains[index]
		if domain.IsDelegatedZone {
			continue
		}
		state.takeDomainResult(DomainResult{Domain: domain.Domain, RDAP: executeRDAPCheck(ctx, app, domain, rdapHTTPClient)})
	}
}

func executeRDAPCheck(ctx context.Context, app *AppState, domainConfig DomainConfig, rdapHTTPClient *http.Client) (result RDAPState) {
	if domainConfig.Unused {
		return RDAPState{Status: StatusSkipped, Unused: true}
	}
	defer func() {
		if r := recover(); r != nil {
			LogError(MsgLogPanicRDAP, FieldDomain, domainConfig.Domain, FieldPanic, r)
			result = RDAPState{
				Status:    StatusFailed,
				Unused:    domainConfig.Unused,
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
		Unused:          domainConfig.Unused,
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
	return rdapState
}

func storeDNSResult(state *CheckState, res DNSResult) {
	if strings.HasPrefix(res.Name, InternalCAATaskPrefix) {
		domainName := strings.TrimPrefix(res.Name, InternalCAATaskPrefix)

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

		// We assign it here, but it doesn't get added to state.DNS!
		// So it won't trigger DNS alerts. It will trigger CAA alerts since we add it to CAA.
		InitMap(&state.CAA)[domainName] = &caaRes
		return
	}

	state.takeDNSResult(res)
}

func runMonitoringCycle(
	ctx context.Context,
	app *AppState,
	rdapHTTPClient *http.Client,
	prevRDAPStatus map[string]CheckStatus,
	prevDNSStatus map[string]CheckStatus,
	prevEmailStatus map[string]CheckStatus,
	prevConditions map[conditionKey]StateCondition,
) *CheckState {
	cycleStart := time.Now()

	loopDur := DefaultLoopDurationFallback
	if app != nil && app.LoopDuration > 0 {
		loopDur = app.LoopDuration
	}

	var cfg AppConfig
	var active activeChecks
	if app != nil {
		cfg = app.configuration()
		active = app.active
	}

	// Bound cycle timeout safely: scale with domain and DNS record counts so large portfolios
	// have sufficient time for rate-limited RDAP requests and retries without hanging indefinitely.
	minRequiredTimeout := time.Duration(len(active.domains))*(10+5)*time.Second + time.Duration(len(active.dnsRecords))*5*time.Second + 5*time.Minute
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

	loopState := prepareCycleStateForWorkload(cfg, active)

	// One bounded group writes DNS and domain results directly into cycle state.
	executeFastChecks(cycleCtx, app, cfg, active, loopState)
	executeRateLimitedChecks(cycleCtx, app, cfg.Domains, active.domains, rdapHTTPClient, loopState)

	if app != nil {
		computePortfolioPricing(cycleCtx, app, loopState, app.Pricing)
	}

	// 5. State transition logging
	logStateTransitions(CheckTypeRDAP, TargetKeyDomain, loopState.RDAP, func(s RDAPState) CheckStatus { return s.Status }, prevRDAPStatus)
	logStateTransitions(CheckTypeDNS, TargetKeyRecord, loopState.DNS, func(s DNSState) CheckStatus { return s.Status }, prevDNSStatus)
	logStateTransitions(CheckTypeEmail, TargetKeyDomain, loopState.Email, func(s EmailState) CheckStatus { return s.Status }, prevEmailStatus)

	// 6. Track Since Timestamps and Dispatch Cycle Report
	processConditionsAndAlerts(app, loopState, cfg, active, prevConditions)

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
		FieldDomainsChecked, len(active.domains),
		FieldDNSRecordsChecked, len(active.dnsRecords),
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
	storePublishedState(app, encoded)
}

func prepareCycleState(domains []DomainConfig) *CheckState {
	return prepareCycleStateForWorkload(AppConfig{Domains: domains}, activeChecks{})
}

// prepareCycleStateForWorkload sizes the maps that this cycle is likely to fill.
func prepareCycleStateForWorkload(cfg AppConfig, active activeChecks) *CheckState {
	emailCount, dnssecCount, nsHealthCount, caaCount := 0, 0, 0, 0
	for _, index := range active.domains {
		domain := cfg.Domains[index]
		if domain.CheckEmailSecurity {
			emailCount++
		}
		if domain.DNSSEC {
			dnssecCount++
		}
		if domain.VerifyNSHealth && len(domain.ExpectedNS) > 0 {
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
		DNS:   make(map[string]DNSState, len(active.dnsRecords)),
		Email: make(map[string]EmailState, emailCount),
	}
	if dnssecCount > 0 {
		state.DNSSEC = make(map[string]DNSSECResult, dnssecCount)
	}
	if nsHealthCount > 0 {
		state.NSHealth = make(map[string]NSHealthResult, nsHealthCount)
	}
	if caaCount > 0 {
		state.CAA = make(map[string]*CAAResult, caaCount)
	}
	for _, domain := range cfg.Domains {
		status := StatusPending
		if domain.Unused {
			status = StatusSkipped
		}
		state.RDAP[domain.Domain] = RDAPState{Status: status, Unused: domain.Unused}
	}
	return state
}

// activeDNSRecords excludes records owned by an unused domain. The most specific
// configured domain owns a record, so an active delegated child remains monitored.
func activeDNSRecords(records []DNSTask, domains []DomainConfig) []int {
	active := make([]int, 0, len(records))
	for i := range records {
		record := records[i]
		host := strings.TrimSuffix(strings.ToLower(record.Hostname), ".")
		ownerLength := -1
		unused := false
		for _, domain := range domains {
			name := strings.TrimSuffix(strings.ToLower(domain.Domain), ".")
			if (host == name || strings.HasSuffix(host, "."+name)) && len(name) > ownerLength {
				ownerLength = len(name)
				unused = domain.Unused
			}
		}
		if !unused {
			active = append(active, i)
		}
	}
	return active
}

func applyConditionSince(cond *StateCondition, key conditionKey, prev map[conditionKey]StateCondition) {
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

func processConditionsAndAlerts(app *AppState, state *CheckState, cfg AppConfig, active activeChecks, prev map[conditionKey]StateCondition) {
	if app == nil || state == nil {
		return
	}
	var cycleAlerts []Alert
	for _, index := range active.domains {
		cycleAlerts = collectDomainAlerts(cycleAlerts, state, cfg.Domains[index], prev)
	}
	for _, index := range active.dnsRecords {
		dnsCfg := cfg.DNSRecords[index]
		name := dnsCfg.Name
		if st, ok := state.DNS[name]; ok {
			cycleAlerts = appendConditionAlert(cycleAlerts, name, name, CheckTypeDNS, st.Condition, st.Status, false, prev)
		}
	}
	dispatchCycleAlerts(app, cycleAlerts)
}

func appendConditionAlert(alerts []Alert, name, domain, check string, cond *StateCondition, status CheckStatus, suppress bool, prev map[conditionKey]StateCondition) []Alert {
	key := conditionKey{check: check, domain: domain}
	if cond == nil || (status != StatusFailed && status != StatusMismatch && status != StatusHijacked && status != StatusWarning) {
		delete(prev, key)
		return alerts
	}
	applyConditionSince(cond, key, prev)
	if suppress {
		return alerts
	}
	priority := PriorityWarning
	if status != StatusWarning {
		priority = PriorityHigh
	}
	duration := formatDurationSince(cond.Since)
	statusName, codeName := status.String(), cond.Code.String()
	message := conditionAlertMessage(check, statusName, codeName, cond.Target, duration, false)
	redacted := conditionAlertMessage(check, statusName, codeName, StrEmpty, duration, true)
	return append(alerts, Alert{Message: message, Redacted: redacted, Priority: priority, Tag: TagSkull, Domain: domain, Name: name})
}

func conditionAlertMessage(check, status, code, target, duration string, redacted bool) string {
	size := len(check) + len(status) + len(code) + len(duration) + len(" :  (Since: )")
	if !redacted {
		size += len(target) + 1
	}
	var message strings.Builder
	message.Grow(size)
	message.WriteString(check)
	message.WriteByte(' ')
	message.WriteString(status)
	message.WriteString(": ")
	message.WriteString(code)
	if !redacted {
		message.WriteByte(' ')
		message.WriteString(target)
	}
	message.WriteString(" (Since: ")
	message.WriteString(duration)
	message.WriteByte(')')
	return message.String()
}

func collectDomainAlerts(alerts []Alert, state *CheckState, cfg DomainConfig, prev map[conditionKey]StateCondition) []Alert {
	domain, name, suppress := cfg.Domain, cfg.Name, cfg.SuppressAlerts
	if st, ok := state.RDAP[domain]; ok {
		alerts = appendConditionAlert(alerts, name, domain, CheckTypeRDAP, st.Condition, st.Status, suppress, prev)
	}
	if st, ok := state.Email[domain]; ok {
		alerts = appendConditionAlert(alerts, name, domain, CheckTypeEmail, st.Condition, st.Status, suppress, prev)
	}
	if st, ok := state.CAA[domain]; ok && st != nil {
		alerts = appendConditionAlert(alerts, name, domain, CheckTypeCAA, st.Condition, st.Status, suppress, prev)
	}

	if st, ok := state.DNSSEC[domain]; ok {
		alerts = appendConditionAlert(alerts, name, domain, CheckTypeDNSSEC, st.Condition, st.Status, suppress, prev)
	}
	if st, ok := state.NSHealth[domain]; ok {
		alerts = appendConditionAlert(alerts, name, domain, CheckTypeNSHealth, st.Condition, st.Status, suppress, prev)
	}
	return alerts
}

func dispatchCycleAlerts(app *AppState, cycleAlerts []Alert) {
	for _, alert := range cycleAlerts {
		app.SafeDispatch(alert.Message, alert.Redacted, alert.Priority, alert.Tag, alert.Domain, alert.Name)
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
		prevConditions := make(map[conditionKey]StateCondition)

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

// PublishInitialState publishes pending checks before the first cycle completes.
func (a *AppState) PublishInitialState() {
	cfg := a.configuration()
	initialState := prepareCycleStateForWorkload(cfg, activeChecks{dnsRecords: a.active.dnsRecords})
	for _, index := range a.active.dnsRecords {
		dnsRecord := cfg.DNSRecords[index]
		initialState.DNS[dnsRecord.Name] = DNSState{
			Hostname: dnsRecord.Hostname, Name: dnsRecord.Name,
			Type: dnsRecord.Type, Expected: dnsRecord.Expected,
			Status: StatusPending,
		}
	}
	if b, err := jsonv2.Marshal(initialState); err == nil {
		storePublishedState(a, b)
	}

}
