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
	"strconv"
	"strings"
)

var (
	CTLogsPath   = DefaultCTLogsSubdir
	ctHTTPClient = ResolveHTTPClient(&http.Client{Timeout: DefaultHTTPTimeout})
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
	apiURL := CTLogsAPIEndpoint + target.Domain
	respPage1, err := fetchCTPage(ctx, app, apiURL)
	if err != nil {
		LogError(MsgLogCTLogsPollingFailed, "domain", target.Domain, "error", err)
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
	var checkpointID string = latestID
	var firstPageCursor string = respPage1.NextCursor

	if len(respPage1.Rows) > 0 {
		checkpointID = respPage1.Rows[0].ID

		for _, row := range respPage1.Rows {
			if row.ID == latestID {
				break
			}
			newCerts = append(newCerts, row)

			if !isFirstRun {
				issuerName := row.Issuer
				if issuerName == "" {
					issuerName = DefaultUnknownCA
				}
				redacted := fmt.Sprintf(MsgRedactedNewSSLCert, issuerName, row.Match)
				if !target.SuppressAlerts {
					app.SafeDispatchf(PriorityHigh, TagLock, target.Domain, target.Name, redacted, MsgAlertNewSSLCert, target.Domain, issuerName, row.Match)
				}
			}
		}
	}

	// Save new certs to history
	if len(newCerts) > 0 {
		LogInfo(MsgLogDiscoveredNewCerts, "domain", target.Domain, "count", len(newCerts))
		if err := saveCertsToHistory(target.Domain, newCerts); err != nil {
			LogError(MsgLogSaveCTLogsFailed, "domain", target.Domain, "error", err)
			return &CTLogState{
				LatestID:         latestID, // Keep previous checkpoint on write failure to allow retry
				BackfillCursor:   backfillCursor,
				BackfillComplete: backfillComplete,
				Status:           StatusFailed,
				Error:            fmt.Sprintf(MsgErrHistorySaveFailed, err.Error()),
			}
		}
	}

	// 2. Incremental Backfilling
	if !backfillComplete {
		cursorToUse := backfillCursor
		if cursorToUse == "" {
			cursorToUse = firstPageCursor
		}

		if cursorToUse != "" {
			var backfillURL string
			if baseParsed, pErr := url.Parse(CTLogsAPIEndpoint + target.Domain); pErr == nil {
				u := baseParsed.Clone()
				q := u.Query()
				q.Set(ParamAfter, cursorToUse)
				u.RawQuery = q.Encode()
				backfillURL = u.String()
			} else {
				backfillURL = CTLogsAPIEndpoint + target.Domain + PrefixParamAfter + url.QueryEscape(cursorToUse)
			}

			respBackfill, err := fetchCTPage(ctx, app, backfillURL)
			if err != nil {
				LogWarn(MsgLogCTLogsBackfillFailed, "domain", target.Domain, "error", err)
				return &CTLogState{
					LatestID:         checkpointID,
					BackfillCursor:   cursorToUse, // Keep old cursor to retry later
					BackfillComplete: false,
					Status:           StatusFailed,
					Error:            fmt.Sprintf(MsgErrBackfillError, err.Error()),
				}
			}

			if len(respBackfill.Rows) > 0 {
				if err := saveCertsToHistory(target.Domain, respBackfill.Rows); err != nil {
					LogError(MsgLogSaveBackfilledCTLogsFailed, "domain", target.Domain, "error", err)
					return &CTLogState{
						LatestID:         checkpointID,
						BackfillCursor:   cursorToUse, // don't advance cursor
						BackfillComplete: false,
						Status:           StatusFailed,
						Error:            fmt.Sprintf(MsgErrBackfillSaveFailed, err.Error()),
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
		LatestID:         checkpointID,
		BackfillCursor:   backfillCursor,
		BackfillComplete: backfillComplete,
		Status:           StatusOK,
		Error:            "",
	}
}

func fetchCTPage(ctx context.Context, app *AppState, apiURL string) (*ctLogsPageResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, err
	}

	if key := app.Config().CTLogsAPIKey; key != "" {
		req.Header.Set(HeaderAuthorization, PrefixBearer+key)
	}

	req.Header.Set(HeaderUserAgent, DefaultUserAgent)

	resp, err := ctHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer DrainAndClose(resp.Body, MaxBodyDrainSize)

	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, ErrCTLogsRateLimited
	} else if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, MaxNotificationPayloadSize))
		bodyStr := string(bodyBytes)
		if key := app.Config().CTLogsAPIKey; key != "" {
			bodyStr = strings.ReplaceAll(bodyStr, key, RedactedAPIKeyPlaceholder)
		}
		return nil, fmt.Errorf(MsgErrAPIReturnedStatus, resp.StatusCode, bodyStr)
	}

	var ctResp ctLogsPageResponse
	if err := jsonv2.UnmarshalRead(io.LimitReader(resp.Body, MaxCTLogsResponseSize), &ctResp); err != nil {
		return nil, WrapError(MsgErrJSONParse, err)
	}

	return &ctResp, nil
}

func saveCertsToHistory(domain string, certs []CTCert) error {
	cleanDomain := NormalizeDomain(domain)
	if cleanDomain == "" || !ReValidDomain.MatchString(cleanDomain) {
		return fmt.Errorf(MsgErrInvalidDomainCertsHistory, strconv.Quote(domain))
	}
	if err := os.MkdirAll(CTLogsPath, 0750); err != nil {
		return err
	}
	filePath := filepath.Join(CTLogsPath, cleanDomain+".json")
	cleanPath := filepath.Clean(filePath)
	if !IsSafeSubpath(CTLogsPath, cleanPath) {
		return fmt.Errorf(MsgErrInvalidFilePathCertsHistory, strconv.Quote(domain))
	}

	var existing []CTCert
	if b, err := os.ReadFile(cleanPath); err == nil {
		if unmarshalErr := jsonv2.Unmarshal(b, &existing); unmarshalErr != nil {
			LogWarn(MsgLogUnmarshalCTLogFailed, "domain", domain, "error", unmarshalErr)
		}
	}

	// We create a map to deduplicate, just in case backfill overlaps or page 1 repeats
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

	if addedNew {
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
			return err
		}
		return AtomicWriteFile(cleanPath, b, 0644)
	}
	return nil
}
