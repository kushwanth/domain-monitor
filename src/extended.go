package main

import (
	"cmp"
	"context"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
)

func encodeCTState(state map[string]CTLogState) ([]byte, error) {
	b, err := jsonv2.Marshal(CTStateFile{Version: CTStateVersion, Domains: state})
	if err != nil {
		return nil, fmt.Errorf("encode CT checkpoint: %w", err)
	}
	if len(b) > MaxCTHistoryFileSize {
		return nil, fmt.Errorf("CT checkpoint exceeds %d bytes", MaxCTHistoryFileSize)
	}
	return b, nil
}

func decodeCTState(b []byte) (map[string]CTLogState, bool, error) {
	state, versioned, err := decodeCTStatePayload(b)
	if err != nil {
		return nil, false, err
	}
	for domain, item := range state {
		if err := validateCTCheckpointEntry(domain, item); err != nil {
			return nil, false, err
		}
		if item.LatestID != "" && len(item.SeenIDs) == 0 {
			// Older checkpoints have no reliable ID window; scan it as a baseline.
			item.Initialized = false
			state[domain] = item
		}
	}
	return state, !versioned, nil
}

func decodeCTStatePayload(b []byte) (map[string]CTLogState, bool, error) {
	var root map[string]any
	if err := jsonv2.Unmarshal(b, &root); err != nil {
		return nil, false, fmt.Errorf("decode CT checkpoint: %w", err)
	}
	if root == nil {
		return nil, false, fmt.Errorf("CT checkpoint must be an object")
	}
	_, versioned := root["version"]
	var state map[string]CTLogState
	if versioned {
		var file CTStateFile
		if err := jsonv2.Unmarshal(b, &file); err != nil {
			return nil, false, fmt.Errorf("decode versioned CT checkpoint: %w", err)
		}
		if file.Version != CTStateVersion {
			return nil, false, fmt.Errorf("unsupported CT checkpoint version %d", file.Version)
		}
		state = file.Domains
		if state == nil {
			return nil, false, fmt.Errorf("CT checkpoint has no domains object")
		}
	} else {
		if err := jsonv2.Unmarshal(b, &state); err != nil {
			return nil, false, fmt.Errorf("decode legacy CT checkpoint: %w", err)
		}
	}
	return state, versioned, nil
}

func validateCTCheckpointEntry(domain string, item CTLogState) error {
	if NormalizeDomain(domain) != domain || !ReValidDomain.MatchString(domain) {
		return fmt.Errorf("invalid CT checkpoint domain %q", domain)
	}
	if !ctCheckpointWithinBounds(item) {
		return fmt.Errorf("CT checkpoint for %s exceeds retention bounds", domain)
	}
	seen := make(map[string]bool, len(item.SeenIDs))
	for _, id := range item.SeenIDs {
		if id == "" || seen[id] {
			return fmt.Errorf("CT checkpoint for %s has invalid seen IDs", domain)
		}
		seen[id] = true
	}
	for _, pending := range item.Pending {
		if pending.Cert.ID == "" || !seen[pending.Cert.ID] {
			return fmt.Errorf("CT checkpoint for %s has untracked pending discovery", domain)
		}
	}
	return nil
}

func ctCheckpointWithinBounds(item CTLogState) bool {
	return len(item.SeenIDs) <= MaxCTSeenIDs && len(item.Pending) <= MaxCTPendingItems &&
		pendingCTBytes(item.Pending) <= MaxCTPendingBytes && item.ScanPages >= 0 &&
		item.ScanPages < MaxCTScanPages && item.LastAttemptUnix >= 0 &&
		item.LastSuccessUnix >= 0 && item.LastCompleteUnix >= 0
}

func loadCTStateFile(path string, read func(string) ([]byte, error), write func(string, []byte, os.FileMode) error) (map[string]CTLogState, error) {
	b, err := read(path)
	if errors.Is(err, os.ErrNotExist) {
		return make(map[string]CTLogState), nil
	}
	if err != nil {
		return nil, fmt.Errorf("read CT checkpoint %s: %w", path, err)
	}
	state, legacy, err := decodeCTState(b)
	if err != nil {
		return nil, fmt.Errorf("load CT checkpoint %s: %w", path, err)
	}
	if legacy {
		if err := write(path+".legacy.bak", b, FilePermSecret); err != nil {
			return nil, fmt.Errorf("back up legacy CT checkpoint %s: %w", path, err)
		}
		encoded, err := encodeCTState(state)
		if err != nil {
			return nil, err
		}
		if err := write(path, encoded, FilePermSecret); err != nil {
			return nil, fmt.Errorf("migrate legacy CT checkpoint %s: %w", path, err)
		}
	}
	return state, nil
}

func settleCTPending(domain string, state CTLogState, cfg DomainConfig, ntfyEnabled, telegramEnabled bool, accepted map[string]CTAcceptance) (CTLogState, bool) {
	changed := false
	retained := make([]CTPending, 0, len(state.Pending))
	for _, item := range state.Pending {
		ack := accepted["CT:"+domain+":"+item.Cert.ID]
		before := item
		item.NeedNtfy = item.NeedNtfy && ntfyEnabled && !cfg.SuppressAlerts && !ack.Ntfy
		item.NeedTelegram = item.NeedTelegram && telegramEnabled && !cfg.SuppressAlerts && !ack.Telegram
		if item != before {
			changed = true
		}
		if item.NeedNtfy || item.NeedTelegram {
			retained = append(retained, item)
		} else {
			changed = true
		}
	}
	if changed {
		state.Pending = retained
	}
	return state, changed
}

func commitCTAcceptances(path string, state map[string]CTLogState, cfg AppConfig, accepted map[string]CTAcceptance, write func(string, []byte, os.FileMode) error) error {
	ntfyEnabled := cfg.Notifications.Ntfy != nil && cfg.Notifications.Ntfy.URL != ""
	telegramEnabled := cfg.Notifications.Telegram != nil && cfg.Notifications.Telegram.Token != ""
	configured := make(map[string]DomainConfig, len(cfg.Domains))
	for _, domain := range cfg.Domains {
		configured[domain.Domain] = domain
	}
	candidate := make(map[string]CTLogState, len(state))
	changed := false
	for domain, current := range state {
		updated, itemChanged := settleCTPending(domain, current, configured[domain], ntfyEnabled, telegramEnabled, accepted)
		candidate[domain] = updated
		changed = changed || itemChanged
	}
	if !changed {
		return nil
	}
	b, err := encodeCTState(candidate)
	if err != nil {
		return err
	}
	if err := write(path, b, FilePermSecret); err != nil {
		return fmt.Errorf("commit CT notification acknowledgement: %w", err)
	}
	for domain, updated := range candidate {
		state[domain] = updated
	}
	return nil
}

func FetchCTLogsSnapshot(ctx context.Context, app *AppState, target DomainConfig, prevState CTLogState) CTLogsSnapshot {
	if !target.MonitorCTLogs {
		return CTLogsSnapshot{}
	}

	snap := newCTSnapshot(prevState)
	if len(snap.Pending) >= MaxCTPendingItems || pendingCTBytes(snap.Pending) >= MaxCTPendingBytes {
		snap.CoverageIncomplete = true
		return snap
	}
	snap.LastAttemptUnix = time.Now().UnixNano()
	apiURL, err := ctPageURL(target.Domain, snap.BackfillCursor)
	if err != nil {
		snap.Page1Err = err
		return snap
	}
	page, err := fetchCTPage(ctx, app, apiURL)
	if err != nil {
		snap.Page1Err = err
		return snap
	}
	if page.HasNext && page.NextCursor == snap.BackfillCursor {
		snap.Page1Err = fmt.Errorf("CT scan cursor repeated for %s", target.Domain)
		return snap
	}
	discovered, ok := collectCTDiscoveries(&snap, page.Rows)
	if !ok {
		return snap
	}
	newPending, ok := buildCTPending(&snap, app, target, discovered)
	if !ok {
		return snap
	}
	if err := writeCTPageHistory(app, target.Domain, page.Rows); err != nil {
		snap.Page1Err = err
		return snap
	}
	advanceCTSnapshot(&snap, page, discovered, newPending)
	return snap
}

func collectCTDiscoveries(snap *CTLogsSnapshot, rows []CTCert) ([]CTCert, bool) {
	seen := make(map[string]bool, len(snap.SeenIDs)+len(rows))
	for _, id := range snap.SeenIDs {
		seen[id] = true
	}
	var discovered []CTCert
	for _, row := range rows {
		if seen[row.ID] {
			continue
		}
		if len(seen) >= MaxCTSeenIDs {
			snap.CoverageIncomplete = true
			return nil, false
		}
		seen[row.ID] = true
		discovered = append(discovered, row)
	}
	return discovered, true
}

func buildCTPending(snap *CTLogsSnapshot, app *AppState, target DomainConfig, discovered []CTCert) ([]CTPending, bool) {
	pending := slices.Clone(snap.Pending)
	if snap.IsFirstRun || target.SuppressAlerts || app == nil {
		return pending, true
	}
	cfg := app.configuration()
	needNtfy := cfg.Notifications.Ntfy != nil && cfg.Notifications.Ntfy.URL != ""
	needTelegram := cfg.Notifications.Telegram != nil && cfg.Notifications.Telegram.Token != ""
	for _, cert := range discovered {
		if !needNtfy && !needTelegram {
			break
		}
		pending = append(pending, CTPending{Cert: cert, NeedNtfy: needNtfy, NeedTelegram: needTelegram})
		if len(pending) > MaxCTPendingItems || pendingCTBytes(pending) > MaxCTPendingBytes {
			snap.CoverageIncomplete = true
			return nil, false
		}
	}
	return pending, true
}

func writeCTPageHistory(app *AppState, domain string, rows []CTCert) error {
	if len(rows) == 0 {
		return nil
	}
	if app == nil || app.WriteCTHistory == nil {
		return fmt.Errorf("CT history writer is not configured for %s", domain)
	}
	path := DefaultCTLogsSubdir
	if app.CTLogsPath != "" {
		path = app.CTLogsPath
	}
	if err := app.WriteCTHistory(domain, rows, path); err != nil {
		return fmt.Errorf("save CT history for %s: %w", domain, err)
	}
	return nil
}

func advanceCTSnapshot(snap *CTLogsSnapshot, page *ctLogsPageResponse, discovered []CTCert, newPending []CTPending) {
	if snap.BackfillCursor == "" && len(page.Rows) > 0 {
		snap.CheckpointID = page.Rows[0].ID
	}
	for _, cert := range discovered {
		snap.SeenIDs = append(snap.SeenIDs, cert.ID)
	}
	snap.Pending = newPending
	if !snap.IsFirstRun {
		snap.NewCerts = discovered
	}
	snap.LastSuccessUnix = time.Now().UnixNano()
	snap.ScanPages++
	if page.HasNext {
		snap.BackfillCursor = page.NextCursor
		snap.BackfillComplete = false
		if snap.ScanPages >= MaxCTScanPages {
			// Preserve resumable progress instead of mistaking a budget stop
			// for a terminal page. Each cycle still fetches only one page.
			snap.CoverageIncomplete = true
			snap.ScanPages = 0
		}
	} else {
		snap.BackfillCursor = ""
		snap.BackfillComplete = true
		snap.ScanPages = 0
		snap.Initialized = true
		snap.LastCompleteUnix = snap.LastSuccessUnix
		snap.CoverageIncomplete = false
	}
}

func newCTSnapshot(prevState CTLogState) CTLogsSnapshot {
	return CTLogsSnapshot{
		CheckpointID:       prevState.LatestID,
		Initialized:        prevState.Initialized,
		BackfillCursor:     prevState.BackfillCursor,
		BackfillComplete:   prevState.BackfillComplete,
		ScanPages:          prevState.ScanPages,
		LastAttemptUnix:    prevState.LastAttemptUnix,
		LastSuccessUnix:    prevState.LastSuccessUnix,
		LastCompleteUnix:   prevState.LastCompleteUnix,
		SeenIDs:            slices.Clone(prevState.SeenIDs),
		Pending:            slices.Clone(prevState.Pending),
		CoverageIncomplete: prevState.CoverageIncomplete,
		IsFirstRun:         !prevState.Initialized || (prevState.LatestID != "" && len(prevState.SeenIDs) == 0 && prevState.ScanPages == 0),
	}
}

func ctPageURL(domain, cursor string) (string, error) {
	apiURL := CTLogsAPIEndpoint + domain
	if cursor == "" {
		return apiURL, nil
	}
	u, err := url.Parse(apiURL)
	if err != nil {
		return "", fmt.Errorf("build CT cursor URL for %s: %w", domain, err)
	}
	q := u.Query()
	q.Set(ParamAfter, cursor)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func pendingCTBytes(items []CTPending) int {
	size := 0
	for _, item := range items {
		size += len(item.Cert.ID) + len(item.Cert.Match) + len(item.Cert.Issuer) + len(item.Cert.NotBefore) + len(item.Cert.NotAfter) + 128
	}
	return size
}

func EvaluateCTLogs(target DomainConfig, snapshot CTLogsSnapshot) (CheckStatus, *StateCondition, CTLogState) {
	if !target.MonitorCTLogs {
		return StatusOK, nil, CTLogState{}
	}

	state := CTLogState{
		LatestID:           snapshot.CheckpointID,
		Initialized:        snapshot.Initialized,
		BackfillCursor:     snapshot.BackfillCursor,
		BackfillComplete:   snapshot.BackfillComplete,
		ScanPages:          snapshot.ScanPages,
		LastAttemptUnix:    snapshot.LastAttemptUnix,
		LastSuccessUnix:    snapshot.LastSuccessUnix,
		LastCompleteUnix:   snapshot.LastCompleteUnix,
		SeenIDs:            snapshot.SeenIDs,
		Pending:            snapshot.Pending,
		CoverageIncomplete: snapshot.CoverageIncomplete,
	}
	if !snapshot.IsFirstRun {
		state.NewCerts = snapshot.NewCerts
	}

	if snapshot.Page1Err != nil {
		state.Error = snapshot.Page1Err.Error()
		code := CodeCTLogsHTTPError
		if errors.Is(snapshot.Page1Err, ErrCTLogsRateLimited) {
			code = CodeCTLogsRateLimited
			return StatusWarning, &StateCondition{Code: code, Target: state.Error}, state
		}
		return StatusFailed, &StateCondition{Code: code, Target: state.Error}, state
	}
	if snapshot.BackfillErr != nil {
		state.Error = snapshot.BackfillErr.Error()
		code := CodeCTLogsHTTPError
		if errors.Is(snapshot.BackfillErr, ErrCTLogsRateLimited) {
			code = CodeCTLogsRateLimited
			return StatusWarning, &StateCondition{Code: code, Target: state.Error}, state
		}
		return StatusFailed, &StateCondition{Code: code, Target: state.Error}, state
	}

	if state.CoverageIncomplete {
		state.Error = "CT scan coverage is incomplete; scan, seen ID or pending budget reached"
		return StatusWarning, &StateCondition{Code: CodeCTCoverageIncomplete, Target: state.Error}, state
	}
	if !state.Initialized && !state.BackfillComplete {
		state.Error = "CT baseline backfill is still in progress"
		return StatusWarning, &StateCondition{Code: CodeCTCoverageIncomplete, Target: state.Error}, state
	}
	return StatusOK, &StateCondition{Code: CodeCTLogsVerified}, state
}

func fetchCTPage(ctx context.Context, app *AppState, apiURL string) (*ctLogsPageResponse, error) {
	if app != nil && app.CTLimiter != nil {
		if err := app.CTLimiter.Wait(ctx); err != nil {
			return nil, fmt.Errorf("wait for CT request rate limit: %w", err)
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, err
	}

	apiKey := ""
	if app != nil {
		apiKey = app.configuration().CTLogsAPIKey
	}
	if apiKey != "" {
		req.Header.Set(HeaderAuthorization, PrefixBearer+apiKey)
	}

	req.Header.Set(HeaderUserAgent, DefaultUserAgent)

	if app == nil || app.HTTPClient == nil {
		return nil, fmt.Errorf("CT HTTP client is not configured for %s", apiURL)
	}
	resp, err := app.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer DrainAndClose(resp.Body, MaxBodyDrainSize)

	if err := checkCTPageResponse(resp, apiKey); err != nil {
		return nil, err
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxCTLogsResponseSize+1))
	if err != nil {
		return nil, WrapError(MsgErrJSONParse, err)
	}
	if len(body) > MaxCTLogsResponseSize {
		return nil, fmt.Errorf("CT API response exceeds %d bytes", MaxCTLogsResponseSize)
	}
	var ctResp ctLogsPageResponse
	if err := jsonv2.Unmarshal(body, &ctResp); err != nil {
		return nil, WrapError(MsgErrJSONParse, err)
	}
	if err := validateCTPage(ctResp); err != nil {
		return nil, err
	}

	return &ctResp, nil
}

func checkCTPageResponse(resp *http.Response, apiKey string) error {
	if resp.StatusCode == http.StatusTooManyRequests {
		return ErrCTLogsRateLimited
	}
	if resp.StatusCode == http.StatusOK {
		return nil
	}
	bodyBytes, readErr := io.ReadAll(io.LimitReader(resp.Body, MaxNotificationPayloadSize))
	if readErr != nil {
		return fmt.Errorf("read CT API error response: %w", readErr)
	}
	bodyStr := string(bodyBytes)
	if apiKey != "" {
		bodyStr = strings.ReplaceAll(bodyStr, apiKey, RedactedAPIKeyPlaceholder)
	}
	return fmt.Errorf(MsgErrAPIReturnedStatus, resp.StatusCode, bodyStr)
}

func validateCTPage(page ctLogsPageResponse) error {
	if page.HasNext && page.NextCursor == "" {
		return fmt.Errorf("CT page claims a next page without a cursor")
	}
	seen := make(map[string]bool, len(page.Rows))
	for _, row := range page.Rows {
		if row.ID == "" || seen[row.ID] {
			return fmt.Errorf("CT page has a missing or duplicate certificate ID")
		}
		seen[row.ID] = true
	}
	return nil
}

func saveCertsToHistory(domain string, certs []CTCert, logsPath string) error {
	cleanDomain := NormalizeDomain(domain)
	if cleanDomain == "" || !ReValidDomain.MatchString(cleanDomain) {
		return fmt.Errorf(MsgErrInvalidDomainCertsHistory, strconv.Quote(domain))
	}
	// #nosec G703 -- logsPath is the operator-selected CT storage directory; domain is validated above.
	if err := os.MkdirAll(logsPath, DirPermDefault); err != nil {
		return err
	}
	filePath := filepath.Join(logsPath, cleanDomain+".json")
	cleanPath := filepath.Clean(filePath)
	if !IsSafeSubpath(logsPath, cleanPath) {
		return fmt.Errorf(MsgErrInvalidFilePathCertsHistory, strconv.Quote(domain))
	}

	var existing []CTCert
	if b, err := readBoundedCTFile(cleanPath); err == nil {
		if unmarshalErr := jsonv2.Unmarshal(b, &existing); unmarshalErr != nil {
			return fmt.Errorf("parse CT history for %s: %w", domain, unmarshalErr)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read CT history for %s: %w", domain, err)
	}

	combined, addedNew := mergeCTCertHistory(existing, certs)
	if !addedNew {
		return nil
	}
	slices.SortFunc(combined, func(a, b CTCert) int {
		if n := cmp.Compare(b.NotBefore, a.NotBefore); n != 0 {
			return n
		}
		return cmp.Compare(b.ID, a.ID)
	})
	if len(combined) > MaxCTCertHistory {
		combined = combined[:MaxCTCertHistory]
	}
	b, err := jsonv2.Marshal(combined)
	if err != nil {
		return fmt.Errorf("encode CT history for %s: %w", domain, err)
	}
	if len(b) > MaxCTHistoryFileSize {
		return fmt.Errorf("CT history for %s exceeds %d bytes", domain, MaxCTHistoryFileSize)
	}
	return AtomicWriteFile(cleanPath, b, FilePermPublic)
}

func mergeCTCertHistory(existing, certs []CTCert) ([]CTCert, bool) {
	seen := make(map[string]bool, len(existing)+len(certs))
	combined := make([]CTCert, 0, len(existing)+len(certs))

	for _, cert := range existing {
		if !seen[cert.ID] {
			seen[cert.ID] = true
			combined = append(combined, cert)
		}
	}

	addedNew := false
	for _, cert := range certs {
		if !seen[cert.ID] {
			seen[cert.ID] = true
			combined = append(combined, cert)
			addedNew = true
		}
	}

	return combined, addedNew
}
