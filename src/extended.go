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

func FetchCTLogsSnapshot(ctx context.Context, app *AppState, target DomainConfig, prevState CTLogState) CTLogsSnapshot {
	if !target.MonitorCTLogs {
		return CTLogsSnapshot{}
	}

	snap := CTLogsSnapshot{
		CheckpointID:     prevState.LatestID,
		BackfillCursor:   prevState.BackfillCursor,
		BackfillComplete: prevState.BackfillComplete,
		IsFirstRun:       prevState.LatestID == "",
	}

	apiURL := CTLogsAPIEndpoint + target.Domain
	respPage1, err := fetchCTPage(ctx, app, apiURL)
	if err != nil {
		snap.Page1Err = err
		return snap
	}

	if len(respPage1.Rows) > 0 {
		snap.CheckpointID = respPage1.Rows[0].ID
		for _, row := range respPage1.Rows {
			if row.ID == prevState.LatestID {
				break
			}
			snap.NewCerts = append(snap.NewCerts, row)
		}
	}

	if len(snap.NewCerts) > 0 {
		LogInfo(MsgLogDiscoveredNewCerts, FieldDomain, target.Domain, FieldCount, len(snap.NewCerts))

		path := DefaultCTLogsSubdir
		if app != nil && app.CTLogsPath != "" {
			path = app.CTLogsPath
		}
		if err := saveCertsToHistory(target.Domain, snap.NewCerts, path); err != nil {
			snap.CheckpointID = prevState.LatestID
			snap.Page1Err = fmt.Errorf(MsgErrHistorySaveFailed, err.Error())
			return snap
		}
	}

	if !snap.BackfillComplete {
		cursorToUse := snap.BackfillCursor
		if cursorToUse == "" {
			cursorToUse = respPage1.NextCursor
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
				snap.BackfillErr = err
				return snap
			}

			if len(respBackfill.Rows) > 0 {
				path := DefaultCTLogsSubdir
				if app != nil && app.CTLogsPath != "" {
					path = app.CTLogsPath
				}
				if err := saveCertsToHistory(target.Domain, respBackfill.Rows, path); err != nil {
					snap.BackfillErr = fmt.Errorf(MsgErrBackfillSaveFailed, err.Error())
					return snap
				}
			}

			snap.BackfillCursor = respBackfill.NextCursor
			if !respBackfill.HasNext || snap.BackfillCursor == "" {
				snap.BackfillComplete = true
			}
		} else {
			snap.BackfillComplete = true
		}
	}

	return snap
}

func EvaluateCTLogs(target DomainConfig, snapshot CTLogsSnapshot) (CheckStatus, *StateCondition, CTLogState) {
	if !target.MonitorCTLogs {
		return StatusOK, nil, CTLogState{}
	}

	state := CTLogState{
		LatestID:         snapshot.CheckpointID,
		BackfillCursor:   snapshot.BackfillCursor,
		BackfillComplete: snapshot.BackfillComplete,
	}

	if snapshot.Page1Err != nil {
		state.Error = snapshot.Page1Err.Error()
		code := CodeCTLogsHTTPError
		if strings.Contains(state.Error, "rate limit") {
			code = CodeCTLogsRateLimited
		}
		return StatusFailed, &StateCondition{Code: code, Target: state.Error}, state
	}
	if snapshot.BackfillErr != nil {
		state.Error = snapshot.BackfillErr.Error()
		code := CodeCTLogsHTTPError
		if strings.Contains(state.Error, "rate limit") {
			code = CodeCTLogsRateLimited
		}
		return StatusFailed, &StateCondition{Code: code, Target: state.Error}, state
	}

	if !snapshot.IsFirstRun && len(snapshot.NewCerts) > 0 {
		state.NewCerts = snapshot.NewCerts
	}

	return StatusOK, &StateCondition{Code: CodeCTLogsVerified}, state
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

	var client HTTPDoer
	if app != nil {
		client = app.HTTPClient
	}
	client = ResolveHTTPClient(client)

	resp, err := client.Do(req)
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

func saveCertsToHistory(domain string, certs []CTCert, logsPath string) error {
	cleanDomain := NormalizeDomain(domain)
	if cleanDomain == "" || !ReValidDomain.MatchString(cleanDomain) {
		return fmt.Errorf(MsgErrInvalidDomainCertsHistory, strconv.Quote(domain))
	}
	if err := os.MkdirAll(logsPath, DirPermDefault); err != nil {
		return err
	}
	filePath := filepath.Join(logsPath, cleanDomain+".json")
	cleanPath := filepath.Clean(filePath)
	if !IsSafeSubpath(logsPath, cleanPath) {
		return fmt.Errorf(MsgErrInvalidFilePathCertsHistory, strconv.Quote(domain))
	}

	var existing []CTCert
	if b, err := os.ReadFile(cleanPath); err == nil {
		if unmarshalErr := jsonv2.Unmarshal(b, &existing); unmarshalErr != nil {
			LogWarn(MsgLogUnmarshalCTLogFailed, FieldDomain, domain, FieldError, unmarshalErr)
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
		return AtomicWriteFile(cleanPath, b, FilePermPublic)
	}
	return nil
}
