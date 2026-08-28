package main

import (
	"context"
	jsonv2 "encoding/json/v2"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var (
	CTLogsPath   = DefaultCTLogsSubdir
	ctHTTPClient = &http.Client{Timeout: 10 * time.Second}
)

func evaluateCTLogs(ctx context.Context, app *AppState, target DomainConfig, state *CheckState) {
	if !target.MonitorCTLogs {
		return
	}

	state.CTLogsMu.Lock()
	currentState, exists := state.CTLogs[target.Domain]
	if !exists {
		currentState = &CTLogState{Status: StatusPending}
		state.CTLogs[target.Domain] = currentState
	}
	latestID := currentState.LatestID
	backfillCursor := currentState.BackfillCursor
	backfillComplete := currentState.BackfillComplete
	state.CTLogsMu.Unlock()

	// 1. Fetch Page 1 (Forward Polling for New Certs)
	apiURL := fmt.Sprintf("%s%s", CTLogsAPIEndpoint, target.Domain)
	respPage1, err := fetchCTPage(ctx, app, apiURL)
	if err != nil {
		state.UpdateCTLogs(target.Domain, &CTLogState{
			LatestID:         latestID,
			BackfillCursor:   backfillCursor,
			BackfillComplete: backfillComplete,
			Status:           StatusFailed,
			Error:            err.Error(),
		})
		return
	}

	var newCerts []CTCert
	isFirstRun := (latestID == "")
	var newLatestID string = latestID
	var page1NextCursor string = respPage1.NextCursor

	if len(respPage1.Rows) > 0 {
		newLatestID = respPage1.Rows[0].ID

		for _, row := range respPage1.Rows {
			if row.ID == latestID {
				break
			}
			newCerts = append(newCerts, row)

			if !isFirstRun {
				issuerName := row.Issuer
				if issuerName == "" {
					issuerName = "Unknown CA"
				}
				msg := fmt.Sprintf(MsgAlertNewSSLCert, target.Domain, issuerName, row.Match)
				redacted := fmt.Sprintf("New SSL Certificate issued by %s for %s.", issuerName, row.Match)
				if !target.SuppressAlerts {
					app.Notifier.Dispatch(msg, redacted, PriorityHigh, "lock", target.Domain, target.Name)
				}
			}
		}
	}

	// Save new certs to history
	if len(newCerts) > 0 {
		if err := saveCertsToHistory(target.Domain, newCerts); err != nil {
			state.UpdateCTLogs(target.Domain, &CTLogState{
				LatestID:         latestID, // Keep previous checkpoint on write failure to allow retry
				BackfillCursor:   backfillCursor,
				BackfillComplete: backfillComplete,
				Status:           StatusFailed,
				Error:            "History save failed: " + err.Error(),
			})
			return
		}
	}

	// 2. Incremental Backfilling
	if !backfillComplete {
		cursorToUse := backfillCursor
		if cursorToUse == "" {
			cursorToUse = page1NextCursor
		}

		if cursorToUse != "" {
			var backfillURL string
			if baseParsed, pErr := url.Parse(fmt.Sprintf("%s%s", CTLogsAPIEndpoint, target.Domain)); pErr == nil {
				u := baseParsed.Clone()
				q := u.Query()
				q.Set("after", cursorToUse)
				u.RawQuery = q.Encode()
				backfillURL = u.String()
			} else {
				backfillURL = fmt.Sprintf("%s%s?after=%s", CTLogsAPIEndpoint, target.Domain, url.QueryEscape(cursorToUse))
			}

			respBackfill, err := fetchCTPage(ctx, app, backfillURL)
			if err != nil {
				state.UpdateCTLogs(target.Domain, &CTLogState{
					LatestID:         newLatestID,
					BackfillCursor:   cursorToUse, // Keep old cursor to retry later
					BackfillComplete: false,
					Status:           StatusFailed,
					Error:            "Backfill error: " + err.Error(),
				})
				return
			}

			if len(respBackfill.Rows) > 0 {
				if err := saveCertsToHistory(target.Domain, respBackfill.Rows); err != nil {
					state.UpdateCTLogs(target.Domain, &CTLogState{
						LatestID:         newLatestID,
						BackfillCursor:   cursorToUse, // don't advance cursor
						BackfillComplete: false,
						Status:           StatusFailed,
						Error:            "Backfill save failed: " + err.Error(),
					})
					return
				}
			}

			backfillCursor = respBackfill.NextCursor
			if !respBackfill.HasNext || backfillCursor == "" {
				backfillComplete = true
			}
		} else {
			// No cursor available on page 1, meaning there are no more pages
			backfillComplete = true
		}
	}

	state.UpdateCTLogs(target.Domain, &CTLogState{
		LatestID:         newLatestID,
		BackfillCursor:   backfillCursor,
		BackfillComplete: backfillComplete,
		Status:           StatusOk,
		Error:            "",
	})
}

func fetchCTPage(ctx context.Context, app *AppState, apiURL string) (*CTLogsDevResponse, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return nil, err
	}

	if app.Config.CTLogsAPIKey != "" {
		req.Header.Set("Authorization", "Bearer "+app.Config.CTLogsAPIKey)
	}

	req.Header.Set("User-Agent", "DomainMonitor/1.0")

	resp, err := ctHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusTooManyRequests {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, fmt.Errorf("api.ctlogs.dev rate limit exceeded")
	} else if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API returned %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var ctResp CTLogsDevResponse
	if err := jsonv2.UnmarshalRead(resp.Body, &ctResp); err != nil {
		return nil, fmt.Errorf("JSON parse error: %v", err)
	}

	return &ctResp, nil
}

func saveCertsToHistory(domain string, certs []CTCert) error {
	cleanDomain := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	if cleanDomain == "" || !ValidDomainRegex.MatchString(cleanDomain) {
		return fmt.Errorf("invalid domain for certs history: %q", domain)
	}
	if err := os.MkdirAll(CTLogsPath, 0755); err != nil {
		return err
	}
	filePath := filepath.Join(CTLogsPath, cleanDomain+".json")
	cleanPath := filepath.Clean(filePath)
	cleanBase := filepath.Clean(CTLogsPath)
	if cleanPath != cleanBase && !strings.HasPrefix(cleanPath, cleanBase+string(filepath.Separator)) {
		return fmt.Errorf("invalid file path for certs history: %q", domain)
	}

	var existing []CTCert
	if b, err := os.ReadFile(cleanPath); err == nil {
		_ = jsonv2.Unmarshal(b, &existing)
	}

	// We create a map to deduplicate, just in case backfill overlaps or page 1 repeats
	seen := make(map[string]bool)
	var combined []CTCert

	for _, c := range existing {
		if !seen[c.ID] {
			seen[c.ID] = true
			combined = append(combined, c)
		}
	}

	addedNew := false
	for _, c := range certs {
		if !seen[c.ID] {
			seen[c.ID] = true
			combined = append(combined, c)
			addedNew = true
		}
	}

	if addedNew {
		if b, err := jsonv2.Marshal(combined); err == nil {
			return atomicWriteFile(cleanPath, b, 0644)
		} else {
			return err
		}
	}
	return nil
}

// atomicWriteFile writes data to a temp file then renames it into place,
// preventing corruption if the process is killed mid-write.
func atomicWriteFile(path string, data []byte, perm os.FileMode) (err error) {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		if err != nil {
			_ = tmp.Close()
			_ = os.Remove(tmpName)
		}
	}()

	if err = os.Chmod(tmpName, perm); err != nil {
		return err
	}
	if _, err = tmp.Write(data); err != nil {
		return err
	}
	if err = tmp.Sync(); err != nil {
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	if err = os.Rename(tmpName, path); err != nil {
		return err
	}
	return nil
}
