package main

import (
	"bytes"
	"context"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func evaluateCTLogsForTest(ctx context.Context, app *AppState, target DomainConfig, prevState CTLogState) CTLogState {
	snap := FetchCTLogsSnapshot(ctx, app, target, prevState)
	status, cond, res := EvaluateCTLogs(target, snap)
	res.Status = status
	res.Condition = cond
	return res
}

func TestSaveCertsToHistory_CorruptFilePreserved(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "example.com.json")
	original := []byte("{corrupt")
	require.NoError(t, os.WriteFile(path, original, FilePermPublic))
	err := saveCertsToHistory("example.com", []CTCert{{ID: "new"}}, dir)
	require.Error(t, err)
	actual, readErr := os.ReadFile(path)
	require.NoError(t, readErr)
	assert.Equal(t, original, actual)
}

func TestEvaluateCTLogs_BackfillFailureKeepsDiscovery(t *testing.T) {
	snapshot := CTLogsSnapshot{CheckpointID: "new", BackfillErr: errors.New(MsgErrQuotaExceeded), NewCerts: []CTCert{{ID: "new"}}}
	status, _, state := EvaluateCTLogs(DomainConfig{Domain: "example.com", MonitorCTLogs: true}, snapshot)
	assert.Equal(t, StatusFailed, status)
	assert.Equal(t, "new", state.LatestID)
	require.Len(t, state.NewCerts, 1)
}

func TestCTLogs_EmptyBaselineThenFirstCertificate(t *testing.T) {
	rows := `{"rows":[],"has_next":false}`
	app := NewAppState(AppConfig{})
	app.CTLimiter = nil
	app.CTLogsPath = t.TempDir()
	app.HTTPClient = &MockHTTPClient{MockDo: func(_ *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(rows)), Header: make(http.Header)}, nil
	}}
	target := DomainConfig{Domain: "example.com", MonitorCTLogs: true}
	first := FetchCTLogsSnapshot(context.Background(), app, target, CTLogState{})
	status, _, state := EvaluateCTLogs(target, first)
	assert.Equal(t, StatusOK, status)
	assert.True(t, state.Initialized)
	assert.Empty(t, state.NewCerts)

	rows = `{"rows":[{"id":"first","match":"example.com"}],"has_next":false}`
	second := FetchCTLogsSnapshot(context.Background(), app, target, state)
	status, _, state = EvaluateCTLogs(target, second)
	assert.Equal(t, StatusOK, status)
	require.Len(t, state.NewCerts, 1)
	assert.Equal(t, "first", state.NewCerts[0].ID)
}

func TestDecodeCTState_VersionAndCorruption(t *testing.T) {
	for _, tc := range []struct {
		name, data      string
		legacy, wantErr bool
	}{
		{name: "versioned", data: `{"version":1,"domains":{"example.com":{"latest_id":"a"}}}`},
		{name: "legacy", data: `{"example.com":{"latest_id":"a"}}`, legacy: true},
		{name: "unsupported", data: `{"version":2,"domains":{}}`, wantErr: true},
		{name: "corrupt", data: `{broken`, wantErr: true},
		{name: "null", data: `null`, wantErr: true},
		{name: "invalid domain", data: `{"version":1,"domains":{"../bad":{"latest_id":"a"}}}`, wantErr: true},
		{name: "duplicate seen ID", data: `{"version":1,"domains":{"example.com":{"seen_ids":["a","a"]}}}`, wantErr: true},
		{name: "empty seen ID", data: `{"version":1,"domains":{"example.com":{"seen_ids":[""]}}}`, wantErr: true},
		{name: "pending without seen ID", data: `{"version":1,"domains":{"example.com":{"pending":[{"cert":{"id":"a"},"need_ntfy":true}]}}}`, wantErr: true},
		{name: "scan page limit", data: `{"version":1,"domains":{"example.com":{"scan_pages":10}}}`, wantErr: true},
		{name: "negative attempt time", data: `{"version":1,"domains":{"example.com":{"last_attempt_unix":-1}}}`, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state, legacy, err := decodeCTState([]byte(tc.data))
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.legacy, legacy)
			assert.Equal(t, "a", state["example.com"].LatestID)
		})
	}
}

func TestLoadCTStateFile_MigrationAndFailedCommit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ct_state.json")
	legacy := []byte(`{"example.com":{"latest_id":"a"}}`)
	require.NoError(t, os.WriteFile(path, legacy, FilePermSecret))
	state, err := loadCTStateFile(path, os.ReadFile, AtomicWriteFile)
	require.NoError(t, err)
	assert.False(t, state["example.com"].Initialized)
	backup, err := os.ReadFile(path + ".legacy.bak")
	require.NoError(t, err)
	assert.Equal(t, legacy, backup)
	current, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Contains(t, string(current), `"version":1`)

	require.NoError(t, os.WriteFile(path, legacy, FilePermSecret))
	_, err = loadCTStateFile(path, os.ReadFile, func(target string, content []byte, mode os.FileMode) error {
		if target == path {
			return errors.New(MsgErrCommitFailed)
		}
		return AtomicWriteFile(target, content, mode)
	})
	require.Error(t, err)
	current, err = os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, legacy, current)
}

func TestCTLogs_RescanFindsLateIndexedCertificate(t *testing.T) {
	cycle := 0
	app := NewAppState(AppConfig{Notifications: Notifications{Ntfy: &NtfyConfig{URL: "https://ntfy.invalid/topic"}}})
	app.CTLimiter = nil
	app.CTLogsPath = t.TempDir()
	app.HTTPClient = &MockHTTPClient{MockDo: func(req *http.Request) (*http.Response, error) {
		page := `{"rows":[{"id":"head","match":"example.com"}],"has_next":true,"next_cursor":"page-2"}`
		if req.URL.Query().Get(ParamAfter) == "page-2" {
			page = `{"rows":[{"id":"older","match":"example.com"}],"has_next":false}`
			if cycle >= 3 {
				page = `{"rows":[{"id":"older","match":"example.com"},{"id":"late","match":"example.com"}],"has_next":false}`
			}
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(page)), Header: make(http.Header)}, nil
	}}
	target := DomainConfig{Domain: "example.com", MonitorCTLogs: true}
	state := CTLogState{}
	for cycle = 0; cycle < 4; cycle++ {
		snap := FetchCTLogsSnapshot(context.Background(), app, target, state)
		status, cond, next := EvaluateCTLogs(target, snap)
		if cycle == 0 {
			assert.Equal(t, StatusWarning, status, "baseline is not complete after a page with a next cursor")
			assert.Equal(t, CodeCTCoverageIncomplete, cond.Code)
		} else {
			assert.Equal(t, StatusOK, status)
		}
		state = next
		if cycle < 3 {
			assert.Empty(t, state.Pending)
		}
	}
	require.Len(t, state.Pending, 1)
	assert.Equal(t, "late", state.Pending[0].Cert.ID)
	assert.True(t, state.Pending[0].NeedNtfy)
	assert.Contains(t, state.SeenIDs, "late")
}

func TestCTLogs_SeenBudgetAndRepeatedCursor(t *testing.T) {
	app := NewAppState(AppConfig{})
	app.CTLimiter = nil
	app.CTLogsPath = t.TempDir()
	app.HTTPClient = &MockHTTPClient{MockDo: func(_ *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"rows":[{"id":"new"}],"has_next":true,"next_cursor":"same"}`)), Header: make(http.Header)}, nil
	}}
	target := DomainConfig{Domain: "example.com", MonitorCTLogs: true}
	prev := CTLogState{Initialized: true, BackfillCursor: "same", SeenIDs: []string{"old"}}
	snap := FetchCTLogsSnapshot(context.Background(), app, target, prev)
	require.Error(t, snap.Page1Err)
	assert.Equal(t, "same", snap.BackfillCursor)
	assert.Equal(t, []string{"old"}, snap.SeenIDs)

	prev.BackfillCursor = ""
	prev.SeenIDs = make([]string, MaxCTSeenIDs)
	for i := range prev.SeenIDs {
		prev.SeenIDs[i] = strconv.Itoa(i)
	}
	snap = FetchCTLogsSnapshot(context.Background(), app, target, prev)
	status, cond, state := EvaluateCTLogs(target, snap)
	assert.Equal(t, StatusWarning, status)
	assert.Equal(t, CodeCTCoverageIncomplete, cond.Code)
	assert.Len(t, state.SeenIDs, MaxCTSeenIDs)
	assert.Empty(t, state.NewCerts)
}

func TestCTLogs_InvalidPageDoesNotAdvanceCheckpoint(t *testing.T) {
	app := NewAppState(AppConfig{})
	app.CTLimiter = nil
	app.CTLogsPath = t.TempDir()
	app.HTTPClient = &MockHTTPClient{MockDo: func(*http.Request) (*http.Response, error) {
		body := `{"rows":[{"id":"new","match":"example.com"}],"has_next":true}`
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body))}, nil
	}}
	prev := CTLogState{Initialized: true, LatestID: "old", BackfillCursor: "page-2", SeenIDs: []string{"old"}}
	snap := FetchCTLogsSnapshot(context.Background(), app, DomainConfig{Domain: "example.com", MonitorCTLogs: true}, prev)
	require.ErrorContains(t, snap.Page1Err, "without a cursor")
	assert.Equal(t, "page-2", snap.BackfillCursor)
	assert.Equal(t, "old", snap.CheckpointID)
	assert.Equal(t, []string{"old"}, snap.SeenIDs)
	assert.Empty(t, snap.NewCerts)
}

func TestCTPending_PartialAcceptanceAndCommitFailure(t *testing.T) {
	telegramCalls := 0
	nm := &NotificationManager{
		NtfyURL: "https://ntfy.invalid/topic", TelegramToken: "token", TelegramChatID: "chat",
		HTTPClient: &MockHTTPClient{MockDo: func(req *http.Request) (*http.Response, error) {
			body := `{"ok":true}`
			if req.URL.Host != "ntfy.invalid" {
				telegramCalls++
				if telegramCalls == 1 {
					body = `{"ok":false}`
				}
			}
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
		}},
	}
	identity := "CT:example.com:cert"
	alert := Alert{Identity: identity, Message: "new cert", Redacted: "new cert", Domain: "example.com", NeedNtfy: true, NeedTelegram: true}
	nm.DispatchCT(alert)
	nm.Flush()
	accepted := nm.TakeCTAcceptances()
	assert.True(t, accepted[identity].Ntfy)
	assert.False(t, accepted[identity].Telegram)
	state := map[string]CTLogState{"example.com": {SeenIDs: []string{"cert"}, Pending: []CTPending{{Cert: CTCert{ID: "cert"}, NeedNtfy: true, NeedTelegram: true}}}}
	cfg := AppConfig{Domains: []DomainConfig{{Domain: "example.com", MonitorCTLogs: true}}, Notifications: Notifications{Ntfy: &NtfyConfig{URL: "https://ntfy.invalid/topic"}, Telegram: &TelegramConfig{Token: "token", ChatID: "chat"}}}
	path := filepath.Join(t.TempDir(), "ct_state.json")
	err := commitCTAcceptances(path, state, cfg, accepted, func(string, []byte, os.FileMode) error { return errors.New(MsgErrDiskFull) })
	require.Error(t, err)
	assert.True(t, state["example.com"].Pending[0].NeedNtfy)

	require.NoError(t, commitCTAcceptances(path, state, cfg, accepted, AtomicWriteFile))
	require.Len(t, state["example.com"].Pending, 1)
	assert.False(t, state["example.com"].Pending[0].NeedNtfy)
	assert.True(t, state["example.com"].Pending[0].NeedTelegram)
	alert.NeedNtfy = false
	nm.DispatchCT(alert)
	nm.Flush()
	require.NoError(t, commitCTAcceptances(path, state, cfg, nm.TakeCTAcceptances(), AtomicWriteFile))
	assert.Empty(t, state["example.com"].Pending)
}

func TestEmailMXVerification(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		provider     string
		liveMXs      []string
		expectHijack bool
	}{
		{
			name:         "Google Valid",
			provider:     "google",
			liveMXs:      []string{"aspmx.l.google.com", "alt1.aspmx.l.google.com"},
			expectHijack: false,
		},
		{
			name:         "Google Hijacked",
			provider:     "google",
			liveMXs:      []string{"malicious-mail.com"},
			expectHijack: true,
		},
		{
			name:         "Unknown Provider",
			provider:     "unknown",
			liveMXs:      []string{"anything.com"},
			expectHijack: false, // Fallback ignores
		},
		{
			name:         "Microsoft Valid",
			provider:     "microsoft",
			liveMXs:      []string{"example-com.mail.protection.outlook.com"},
			expectHijack: false,
		},
		{
			name:         "Zoho Valid",
			provider:     "zoho",
			liveMXs:      []string{"mx.zoho.com", "mx2.zoho.in"},
			expectHijack: false,
		},
		{
			name:         "Fastmail Valid",
			provider:     "fastmail",
			liveMXs:      []string{"in1-smtp.messagingengine.com"},
			expectHijack: false,
		},
		{
			name:         "Google Valid Modern (smtp.google.com)",
			provider:     "google",
			liveMXs:      []string{"smtp.google.com"},
			expectHijack: false,
		},
		{
			name:         "Google Valid Legacy & Backup",
			provider:     "google",
			liveMXs:      []string{"aspmx.l.google.com", "aspmx2.googlemail.com"},
			expectHijack: false,
		},
		{
			name:         "Proton Modern Valid (proton.me)",
			provider:     "proton",
			liveMXs:      []string{"mail.proton.me"},
			expectHijack: false,
		},
		{
			name:         "Proton Valid (protonmail.ch)",
			provider:     "protonmail",
			liveMXs:      []string{"mail.protonmail.ch"},
			expectHijack: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			isSafe, known := isProviderMXSafe(tt.liveMXs, tt.provider)
			if !known {
				if tt.expectHijack {
					t.Errorf("Unexpected unknown provider marked as hijack")
				}
				return
			}

			isHijacked := !isSafe
			if isHijacked != tt.expectHijack {
				t.Errorf("Provider %s: Expected Hijack=%v, got %v (live: %v)", tt.provider, tt.expectHijack, isHijacked, tt.liveMXs)
			}
		})
	}
}

func TestExtended_AtomicWriteFile(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	targetPath := filepath.Join(tmpDir, "test.txt")

	data1 := []byte("Initial content")
	if err := AtomicWriteFile(targetPath, data1, 0644); err != nil {
		t.Fatalf("AtomicWriteFile failed: %v", err)
	}

	read1, err := os.ReadFile(targetPath)
	if err != nil || string(read1) != string(data1) {
		t.Fatalf("Expected '%s', got '%s', err: %v", string(data1), string(read1), err)
	}

	data2 := []byte("Updated content atomically")
	if err := AtomicWriteFile(targetPath, data2, 0644); err != nil {
		t.Fatalf("AtomicWriteFile overwrite failed: %v", err)
	}

	read2, err := os.ReadFile(targetPath)
	if err != nil || string(read2) != string(data2) {
		t.Fatalf("Expected '%s', got '%s', err: %v", string(data2), string(read2), err)
	}
}

func TestSaveCertsToHistory(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	logsPath := filepath.Join(os.TempDir(), "ct_logs_test")
	domain := "test-example-" + filepath.Base(tmpDir) + ".com"
	defer func() {
		_ = os.Remove(filepath.Join(logsPath, domain+".json"))
	}()

	certs1 := []CTCert{
		{ID: "cert-1", Match: "example.com", Issuer: "Let's Encrypt", NotBefore: "2026-01-01T00:00:00Z"},
		{ID: "cert-2", Match: "sub.example.com", Issuer: "DigiCert", NotBefore: "2026-02-01T00:00:00Z"},
	}

	if err := saveCertsToHistory(domain, certs1, logsPath); err != nil {
		t.Fatalf("saveCertsToHistory batch 1 failed: %v", err)
	}

	// Save batch 2 with overlapping and new certs
	certs2 := []CTCert{
		{ID: "cert-2", Match: "sub.example.com", Issuer: "DigiCert", NotBefore: "2026-02-01T00:00:00Z"},
		{ID: "cert-3", Match: "api.example.com", Issuer: "Let's Encrypt", NotBefore: "2026-03-01T00:00:00Z"},
	}
	if err := saveCertsToHistory(domain, certs2, logsPath); err != nil {
		t.Fatalf("saveCertsToHistory batch 2 failed: %v", err)
	}

	// Verify deduplicated combined file
	savedFile := filepath.Join(logsPath, domain+".json")
	b, err := os.ReadFile(savedFile)
	if err != nil {
		t.Fatalf("Failed to read saved certs file: %v", err)
	}

	var combined []CTCert
	if err := jsonv2.Unmarshal(b, &combined); err != nil {
		t.Fatalf("Failed to unmarshal certs: %v", err)
	}

	if len(combined) != 3 {
		t.Errorf("Expected 3 deduplicated certs, got %d", len(combined))
	}

	// Verify sorted descending by NotBefore (newest first: cert-3, then cert-2, then cert-1)
	if combined[0].ID != "cert-3" || combined[1].ID != "cert-2" || combined[2].ID != "cert-1" {
		t.Errorf("Expected certs sorted descending by NotBefore (cert-3, cert-2, cert-1), got: %v, %v, %v",
			combined[0].ID, combined[1].ID, combined[2].ID)
	}
}

func TestHTTPServerRoutes(t *testing.T) {
	app := NewAppState(AppConfig{Domains: []DomainConfig{{Domain: "testdomain.com", MonitorCTLogs: true}}})
	app.CTLogsPath = t.TempDir()
	app.PrerenderedJSON.Store([]byte(`{"status":"prerendered"}`))

	server, _ := setupHTTPServer(app, "0")
	handler := server.Handler

	// Write a mock certs file for testdomain.com
	testDomain := "testdomain.com"
	_ = saveCertsToHistory(testDomain, []CTCert{{ID: "c1", Match: testDomain, Issuer: "CA1"}}, app.CTLogsPath)

	// 1. GET /health
	req := httptest.NewRequest("GET", "/health", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("/health status = %d, expected 200", rec.Code)
	}

	// 2. GET /api/state
	req = httptest.NewRequest("GET", "/api/state", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("/api/state status = %d, expected 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "prerendered") {
		t.Errorf("/api/state body = %s, expected prerendered json", rec.Body.String())
	}

	// 3. GET /api/certs?domain=testdomain.com
	req = httptest.NewRequest("GET", "/api/certs?domain="+testDomain, nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("/api/certs valid status = %d, expected 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "c1") {
		t.Errorf("/api/certs body = %s, expected c1", rec.Body.String())
	}

	// 4. GET /api/certs invalid domain
	req = httptest.NewRequest("GET", "/api/certs?domain=invalid%20domain!", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("/api/certs invalid domain status = %d, expected 400", rec.Code)
	}

	// 5. GET /api/ctlogs/testdomain.com
	req = httptest.NewRequest("GET", "/api/ctlogs/"+testDomain, nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("/api/ctlogs valid status = %d, expected 200", rec.Code)
	}

	// 6. GET /
	req = httptest.NewRequest("GET", "/", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("/ status = %d, expected 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "DomainMonitor") {
		t.Errorf("/ body = %s, expected DomainMonitor", rec.Body.String())
	}

	// 7. GET /non-existent
	req = httptest.NewRequest("GET", "/non-existent", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("/non-existent status = %d, expected 404", rec.Code)
	}
}

func TestPathTraversalProtection(t *testing.T) {
	app := &AppState{}
	server, _ := setupHTTPServer(app, "0")
	handler := server.Handler

	traversalPayloads := []string{
		"../../etc/passwd",
		"../ct_state",
		"..",
		"....",
		"test/domain.com",
		"domain..com",
		"-badlabel.com",
		"badlabel-.com",
		"domain.com/something",
		"domain.com%2f..%2f..",
		"..\\windows\\win.ini",
	}

	for _, payload := range traversalPayloads {
		t.Run("CertsQuery_"+payload, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/api/certs?domain="+payload, nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Errorf("Expected 400 Bad Request for traversal payload %q, got %d", payload, rec.Code)
			}
		})

		t.Run("CTLogsPath_"+payload, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/api/ctlogs/"+payload, nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			// Route match may 404 or 400 depending on path parsing, but must never be 200 reading files outside
			if rec.Code == http.StatusOK {
				t.Errorf("Expected non-200 for traversal payload %q, got %d", payload, rec.Code)
			}
		})
	}
}

type mockRoundTripper func(req *http.Request) (*http.Response, error)

func (m mockRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return m(req)
}

func TestEvaluateCTLogs_FirstRunNoAlerts(t *testing.T) {
	mockClient := &http.Client{
		Transport: mockRoundTripper(func(_ *http.Request) (*http.Response, error) {
			payload := `{"rows":[{"id":"cert-first-1","match":"firstrun.example.com","issuer":"Let's Encrypt"}],"has_next":false,"next_cursor":""}`
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(payload)),
				Header:     make(http.Header),
			}, nil
		}),
	}

	app := NewAppState(AppConfig{})
	app.Notifier = newRecordingNotifier()
	app.HTTPClient = mockClient
	app.CTLimiter = nil
	app.CTLogsPath = t.TempDir()
	domain := "firstrun.example.com"

	target := DomainConfig{
		Domain:         domain,
		MonitorCTLogs:  true,
		SuppressAlerts: false,
	}
	saved := evaluateCTLogsForTest(context.Background(), app, target, CTLogState{})

	// First run must not emit notifications for existing cert baseline
	notifier, ok := app.Notifier.(*recordingNotifier)
	require.True(t, ok)
	if len(notifier.alerts) != 0 {
		t.Errorf("Expected 0 alerts on first-run baseline discovery, got %d", len(notifier.alerts))
	}

	if saved.Status == StatusUnknown {
		t.Fatalf("Expected CTLogState to be saved")
	}
	if saved.LatestID != "cert-first-1" {
		t.Errorf("Expected LatestID 'cert-first-1', got %q", saved.LatestID)
	}
	if saved.Status != StatusOK {
		t.Errorf("Expected StatusOK, got %s", saved.Status)
	}
}

func TestEvaluateCTLogs_RateLimitPreservesCursor(t *testing.T) {
	mockClient := &http.Client{
		Transport: mockRoundTripper(func(req *http.Request) (*http.Response, error) {
			if strings.Contains(req.URL.RawQuery, "after=") {
				return &http.Response{
					StatusCode: http.StatusTooManyRequests,
					Body:       io.NopCloser(bytes.NewBufferString("Too Many Requests")),
					Header:     make(http.Header),
				}, nil
			}
			// Page 1 succeeds with next_cursor
			payload := `{"rows":[{"id":"cert-existing-1","match":"ratelimit.example.com","issuer":"CA"}],"has_next":true,"next_cursor":"page1-cursor"}`
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(payload)),
				Header:     make(http.Header),
			}, nil
		}),
	}

	app := NewAppState(AppConfig{})
	app.Notifier = newRecordingNotifier()
	app.HTTPClient = mockClient
	app.CTLimiter = nil
	app.CTLogsPath = t.TempDir()
	domain := "ratelimit.example.com"

	target := DomainConfig{
		Domain:         domain,
		MonitorCTLogs:  true,
		SuppressAlerts: false,
	}
	savedCursor := "cursor-prior-checkpoint"
	existing := CTLogState{
		LatestID:         "cert-existing-1",
		BackfillCursor:   savedCursor,
		BackfillComplete: false,
		Status:           StatusOK,
	}

	res := evaluateCTLogsForTest(context.Background(), app, target, existing)

	if res.Status == StatusUnknown {
		t.Fatalf("Expected CTLogState to be present")
	}
	if res.BackfillComplete {
		t.Errorf("Expected BackfillComplete to remain false after rate limit failure")
	}
}

func TestSecurityHeadersMiddleware(t *testing.T) {
	app := &AppState{}
	server, _ := setupHTTPServer(app, "0")
	handler := server.Handler

	endpoints := []string{"/health", "/api/state", "/"}
	for _, ep := range endpoints {
		req := httptest.NewRequest("GET", ep, nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("Endpoint %s missing X-Content-Type-Options: nosniff", ep)
		}
		if rec.Header().Get("X-Frame-Options") != "DENY" {
			t.Errorf("Endpoint %s missing X-Frame-Options: DENY", ep)
		}
		if rec.Header().Get("Referrer-Policy") != "strict-origin-when-cross-origin" {
			t.Errorf("Endpoint %s missing Referrer-Policy", ep)
		}
		if rec.Header().Get("X-XSS-Protection") != "0" {
			t.Errorf("Endpoint %s missing X-XSS-Protection: 0", ep)
		}
		if !strings.Contains(rec.Header().Get("Content-Security-Policy"), "default-src 'self'") {
			t.Errorf("Endpoint %s missing CSP default-src 'self'", ep)
		}
	}
}

func TestFetchCTPage_KeyRedaction(t *testing.T) {
	apiKey := "SUPER_SECRET_CTLOGS_KEY"
	app := &AppState{
		config: AppConfig{
			CTLogsAPIKey: apiKey,
		},
		HTTPClient: &MockHTTPClient{MockDo: func(r *http.Request) (*http.Response, error) {
			assert.Equal(t, PrefixBearer+apiKey, r.Header.Get(HeaderAuthorization))
			return &http.Response{StatusCode: http.StatusUnauthorized, Body: io.NopCloser(strings.NewReader("Invalid key: " + apiKey))}, nil
		}},
	}
	_, err := fetchCTPage(context.Background(), app, "https://ct.example/lookup")
	require.Error(t, err)
	assert.NotContains(t, err.Error(), apiKey)
	assert.Contains(t, err.Error(), RedactedAPIKeyPlaceholder)
}

func TestFetchCTPageRejectsOversizedValidPrefix(t *testing.T) {
	validPage := `{"rows":[],"has_next":false}`
	oversized := validPage + strings.Repeat(" ", MaxCTLogsResponseSize-len(validPage)+1)
	app := &AppState{HTTPClient: &MockHTTPClient{MockDo: func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(oversized))}, nil
	}}}
	_, err := fetchCTPage(context.Background(), app, "https://ct.example/lookup")
	require.ErrorContains(t, err, "exceeds")
}

func TestSaveCertsToHistory_CapAtMaxHistory(t *testing.T) {
	domain := "cap-test.example.com"
	logsPath := filepath.Join(os.TempDir(), "ct_logs_test")
	cleanFile := filepath.Join(logsPath, domain+".json")
	defer func() { _ = os.Remove(cleanFile) }()

	// Create 1,050 certs
	certs := make([]CTCert, 1050)
	for i := range certs {
		certs[i] = CTCert{
			ID:        strconv.Itoa(i + 1),
			Match:     domain,
			Issuer:    "Test CA",
			NotBefore: "2026-01-01T00:00:00Z",
			NotAfter:  "2026-04-01T00:00:00Z",
		}
	}

	if err := saveCertsToHistory(domain, certs, logsPath); err != nil {
		t.Fatalf("saveCertsToHistory failed: %v", err)
	}

	b, err := os.ReadFile(cleanFile)
	if err != nil {
		t.Fatalf("failed to read written file: %v", err)
	}

	var saved []CTCert
	if err := jsonv2.Unmarshal(b, &saved); err != nil {
		t.Fatalf("failed to unmarshal saved certs: %v", err)
	}

	if len(saved) != MaxCTCertHistory {
		t.Errorf("expected history capped at %d, got %d", MaxCTCertHistory, len(saved))
	}
}

func TestCTScanBudgetResumesAcrossRestart(t *testing.T) {
	app := NewAppState(AppConfig{})
	app.CTLimiter = nil
	app.CTLogsPath = t.TempDir()
	app.HTTPClient = &MockHTTPClient{MockDo: func(req *http.Request) (*http.Response, error) {
		page := 0
		if cursor := req.URL.Query().Get(ParamAfter); cursor != "" {
			var err error
			page, err = strconv.Atoi(cursor)
			require.NoError(t, err)
		}
		body := fmt.Sprintf(`{"rows":[{"id":"%d"}],"has_next":%t,"next_cursor":"%d"}`, page, page < MaxCTScanPages+1, page+1)
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body))}, nil
	}}
	target := DomainConfig{Domain: "example.com", MonitorCTLogs: true}
	path := filepath.Join(t.TempDir(), "state.json")
	previous := CTLogState{}
	for cycle := 0; cycle < MaxCTScanPages+2; cycle++ {
		snapshot := FetchCTLogsSnapshot(context.Background(), app, target, previous)
		status, _, state := EvaluateCTLogs(target, snapshot)
		assert.Positive(t, state.LastSuccessUnix)
		if cycle < MaxCTScanPages+1 {
			assert.Zero(t, state.LastCompleteUnix)
			assert.Equal(t, StatusWarning, status)
			assert.False(t, state.Initialized)
			assert.False(t, state.BackfillComplete)
			assert.Equal(t, strconv.Itoa(cycle+1), state.BackfillCursor)
		} else {
			assert.Equal(t, StatusOK, status)
			assert.True(t, state.Initialized)
			assert.True(t, state.BackfillComplete)
			assert.False(t, state.CoverageIncomplete)
			assert.Equal(t, state.LastSuccessUnix, state.LastCompleteUnix)
		}
		encoded, err := encodeCTState(map[string]CTLogState{target.Domain: state})
		require.NoError(t, err)
		require.NoError(t, AtomicWriteFile(path, encoded, FilePermSecret))
		reloaded, err := loadCTStateFile(path, os.ReadFile, AtomicWriteFile)
		require.NoError(t, err)
		previous = reloaded[target.Domain]
	}
	assert.Len(t, previous.SeenIDs, MaxCTScanPages+2)
}

func TestCTAcknowledgementWriteFailureDoesNotRedeliverInProcess(t *testing.T) {
	const domain = "example.com"
	config := AppConfig{
		Domains:       []DomainConfig{{Domain: domain, MonitorCTLogs: true}},
		Notifications: Notifications{Ntfy: &NtfyConfig{URL: "https://ntfy.invalid/test"}},
	}
	app := NewAppState(config)
	notifier := NewNotificationManager("https://ntfy.invalid/test", "", "", "")
	calls := 0
	notifier.HTTPClient = &MockHTTPClient{MockDo: func(*http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(""))}, nil
	}}
	app.Notifier = notifier
	committed := map[string]CTLogState{domain: {
		Initialized: true, SeenIDs: []string{"new"},
		Pending: []CTPending{{Cert: CTCert{ID: "new"}, NeedNtfy: true}},
	}}
	state := NewCheckState()
	state.CTLogs[domain] = committed[domain]
	path := filepath.Join(t.TempDir(), "state.json")
	encoded, err := encodeCTState(committed)
	require.NoError(t, err)
	require.NoError(t, AtomicWriteFile(path, encoded, FilePermSecret))
	app.WriteCTState = func(string, []byte, os.FileMode) error { return errors.New(MsgErrDiskUnavailable) }
	alert := Alert{Identity: "CT:" + domain + ":new", Domain: domain, NeedNtfy: true}
	notifier.DispatchCT(alert)
	finishCycleDelivery(context.Background(), app, state, path, committed, time.Hour)
	assert.Equal(t, 1, calls)
	require.Len(t, committed[domain].Pending, 1)
	onDisk, err := loadCTStateFile(path, os.ReadFile, AtomicWriteFile)
	require.NoError(t, err)
	require.Len(t, onDisk[domain].Pending, 1, "restart must retain the unacknowledged delivery")

	app.WriteCTState = AtomicWriteFile
	notifier.DispatchCT(alert)
	finishCycleDelivery(context.Background(), app, state, path, committed, time.Hour)
	assert.Equal(t, 1, calls, "remote acceptance must survive a failed acknowledgement write in memory")
	assert.Empty(t, committed[domain].Pending)
	onDisk, err = loadCTStateFile(path, os.ReadFile, AtomicWriteFile)
	require.NoError(t, err)
	assert.Empty(t, onDisk[domain].Pending)
}

// TestLiveCTProviderReplay reads a real provider page, then replays the head
// page after reconstructing app state to check that seen IDs are not alerted
// twice. It does not establish complete or timely CT coverage.
func TestLiveCTProviderReplay(t *testing.T) {
	if os.Getenv("DOMAIN_MONITOR_LIVE") != "1" {
		t.Skip("set DOMAIN_MONITOR_LIVE=1 for external CT provider queries")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	target := DomainConfig{Domain: "cloudflare.com", MonitorCTLogs: true}
	historyPath := t.TempDir()
	newApp := func() *AppState {
		app := NewAppState(AppConfig{})
		app.HTTPClient = &http.Client{Timeout: 15 * time.Second}
		app.CTLimiter = nil
		app.CTLogsPath = historyPath
		return app
	}
	first := FetchCTLogsSnapshot(ctx, newApp(), target, CTLogState{})
	if first.Page1Err != nil {
		t.Fatalf("first provider page: %v", first.Page1Err)
	}
	firstStatus, firstCondition, committed := EvaluateCTLogs(target, first)
	if !committed.Initialized && !committed.BackfillComplete && (firstStatus != StatusWarning || firstCondition == nil || firstCondition.Code != CodeCTCoverageIncomplete) {
		t.Fatalf("unfinished provider baseline was published as %s instead of a coverage warning", firstStatus)
	}
	if len(committed.SeenIDs) == 0 {
		t.Fatal("provider returned no certificate IDs for replay")
	}
	seen := make(map[string]bool, len(committed.SeenIDs))
	for _, id := range committed.SeenIDs {
		seen[id] = true
	}
	checkpointPath := filepath.Join(t.TempDir(), "ct_state.json")
	encoded, err := encodeCTState(map[string]CTLogState{target.Domain: committed})
	if err != nil {
		t.Fatalf("encode CT checkpoint: %v", err)
	}
	if err := AtomicWriteFile(checkpointPath, encoded, FilePermSecret); err != nil {
		t.Fatalf("write CT checkpoint: %v", err)
	}
	reloaded, err := loadCTStateFile(checkpointPath, os.ReadFile, AtomicWriteFile)
	if err != nil {
		t.Fatalf("reload CT checkpoint: %v", err)
	}
	previous := reloaded[target.Domain]
	previous.BackfillCursor = "" // revisit the first page after a restart
	second := FetchCTLogsSnapshot(ctx, newApp(), target, previous)
	if second.Page1Err != nil {
		t.Fatalf("replayed provider page: %v", second.Page1Err)
	}
	secondStatus, _, replayed := EvaluateCTLogs(target, second)
	if replayed.Initialized && !replayed.BackfillComplete && secondStatus != StatusOK {
		t.Fatalf("post-baseline rescan should preserve healthy provider status, got %s", secondStatus)
	}
	for _, cert := range second.NewCerts {
		if seen[cert.ID] {
			t.Fatalf("previously seen certificate %q was rediscovered", cert.ID)
		}
	}
	t.Logf("first_seen=%d replay_new=%d cursor_present=%t status=%s coverage_budget_exhausted=%t", len(seen), len(second.NewCerts), second.BackfillCursor != "", secondStatus, second.CoverageIncomplete)
}
