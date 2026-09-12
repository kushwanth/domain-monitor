package main

import (
	"cmp"
	"context"
	jsonv2 "encoding/json/v2"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

var (
	CTLogsPath   = DefaultCTLogsSubdir
	ctHTTPClient = ResolveHTTPClient(&http.Client{Timeout: 10 * time.Second})
)

func evaluateCTLogs(ctx context.Context, app *AppState, target DomainConfig, prevState *CTLogState) *CTLogState {
	if !target.MonitorCTLogs {
		return nil
	}

	var latestID, backfillCursor string
	var backfillComplete bool
	if prevState != nil {
		latestID = prevState.LatestID
		backfillCursor = prevState.BackfillCursor
		backfillComplete = prevState.BackfillComplete
	}

	// 1. Fetch Page 1 (Forward Polling for New Certs)
	apiURL := fmt.Sprintf("%s%s", CTLogsAPIEndpoint, target.Domain)
	respPage1, err := fetchCTPage(ctx, app, apiURL)
	if err != nil {
		LogError("CT logs polling failed", "domain", target.Domain, "error", err)
		return &CTLogState{
			LatestID:         latestID,
			BackfillCursor:   backfillCursor,
			BackfillComplete: backfillComplete,
			Status:           StatusFailed,
			Error:            err.Error(),
		}
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
					app.SafeDispatch(msg, redacted, PriorityHigh, "lock", target.Domain, target.Name)
				}
			}
		}
	}

	// Save new certs to history
	if len(newCerts) > 0 {
		LogInfo("Discovered new SSL certificates via CT logs", "domain", target.Domain, "count", len(newCerts))
		if err := saveCertsToHistory(target.Domain, newCerts); err != nil {
			LogError("Failed to save CT logs history", "domain", target.Domain, "error", err)
			return &CTLogState{
				LatestID:         latestID, // Keep previous checkpoint on write failure to allow retry
				BackfillCursor:   backfillCursor,
				BackfillComplete: backfillComplete,
				Status:           StatusFailed,
				Error:            "History save failed: " + err.Error(),
			}
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
				LogWarn("CT logs backfill failed", "domain", target.Domain, "error", err)
				return &CTLogState{
					LatestID:         newLatestID,
					BackfillCursor:   cursorToUse, // Keep old cursor to retry later
					BackfillComplete: false,
					Status:           StatusFailed,
					Error:            "Backfill error: " + err.Error(),
				}
			}

			if len(respBackfill.Rows) > 0 {
				if err := saveCertsToHistory(target.Domain, respBackfill.Rows); err != nil {
					LogError("Failed to save backfilled CT logs", "domain", target.Domain, "error", err)
					return &CTLogState{
						LatestID:         newLatestID,
						BackfillCursor:   cursorToUse, // don't advance cursor
						BackfillComplete: false,
						Status:           StatusFailed,
						Error:            "Backfill save failed: " + err.Error(),
					}
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

	return &CTLogState{
		LatestID:         newLatestID,
		BackfillCursor:   backfillCursor,
		BackfillComplete: backfillComplete,
		Status:           StatusOK,
		Error:            "",
	}
}

func fetchCTPage(ctx context.Context, app *AppState, apiURL string) (*CTLogsDevResponse, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return nil, err
	}

	if app != nil && app.Config != nil && app.Config.CTLogsAPIKey != "" {
		req.Header.Set("Authorization", "Bearer "+app.Config.CTLogsAPIKey)
	}

	req.Header.Set("User-Agent", DefaultUserAgent)

	resp, err := ctHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer DrainAndClose(resp.Body, 4096)

	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, fmt.Errorf("api.ctlogs.dev rate limit exceeded")
	} else if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, MaxNotificationPayloadSize))
		bodyStr := string(bodyBytes)
		if app != nil && app.Config != nil && app.Config.CTLogsAPIKey != "" {
			bodyStr = strings.ReplaceAll(bodyStr, app.Config.CTLogsAPIKey, "[REDACTED_API_KEY]")
		}
		return nil, fmt.Errorf("API returned %d: %s", resp.StatusCode, bodyStr)
	}

	var ctResp CTLogsDevResponse
	if err := jsonv2.UnmarshalRead(io.LimitReader(resp.Body, MaxCTLogsResponseSize), &ctResp); err != nil {
		return nil, fmt.Errorf("json parse error: %w", err)
	}

	return &ctResp, nil
}

func saveCertsToHistory(domain string, certs []CTCert) error {
	cleanDomain := NormalizeDomain(domain)
	if cleanDomain == "" || !ReValidDomain.MatchString(cleanDomain) {
		return fmt.Errorf("invalid domain for certs history: %q", domain)
	}
	if err := os.MkdirAll(CTLogsPath, 0775); err != nil {
		return err
	}
	filePath := filepath.Join(CTLogsPath, cleanDomain+".json")
	cleanPath := filepath.Clean(filePath)
	if !IsSafeSubpath(CTLogsPath, cleanPath) {
		return fmt.Errorf("invalid file path for certs history: %q", domain)
	}

	var existing []CTCert
	if b, err := os.ReadFile(cleanPath); err == nil {
		_ = jsonv2.Unmarshal(b, &existing)
	}

	// We create a map to deduplicate, just in case backfill overlaps or page 1 repeats
	seen := make(map[string]bool)
	var combined []CTCert

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

	if addedNew {
		slices.SortFunc(combined, func(a, b CTCert) int {
			if n := cmp.Compare(b.NotBefore, a.NotBefore); n != 0 {
				return n
			}
			return cmp.Compare(b.ID, a.ID)
		})
		b, err := jsonv2.Marshal(combined)
		if err != nil {
			return err
		}
		return AtomicWriteFile(cleanPath, b, 0644)
	}
	return nil
}
