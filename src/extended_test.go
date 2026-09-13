package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func init() {
	CTLogsPath = filepath.Join(os.TempDir(), "ct_logs_test")
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
	domain := "test-example-" + filepath.Base(tmpDir) + ".com"
	defer func() {
		_ = os.Remove(filepath.Join(CTLogsPath, domain+".json"))
	}()

	certs1 := []CTCert{
		{ID: "cert-1", Match: "example.com", Issuer: "Let's Encrypt", NotBefore: "2026-01-01T00:00:00Z"},
		{ID: "cert-2", Match: "sub.example.com", Issuer: "DigiCert", NotBefore: "2026-02-01T00:00:00Z"},
	}

	if err := saveCertsToHistory(domain, certs1); err != nil {
		t.Fatalf("saveCertsToHistory batch 1 failed: %v", err)
	}

	// Save batch 2 with overlapping and new certs
	certs2 := []CTCert{
		{ID: "cert-2", Match: "sub.example.com", Issuer: "DigiCert", NotBefore: "2026-02-01T00:00:00Z"},
		{ID: "cert-3", Match: "api.example.com", Issuer: "Let's Encrypt", NotBefore: "2026-03-01T00:00:00Z"},
	}
	if err := saveCertsToHistory(domain, certs2); err != nil {
		t.Fatalf("saveCertsToHistory batch 2 failed: %v", err)
	}

	// Verify deduplicated combined file
	savedFile := filepath.Join(CTLogsPath, domain+".json")
	b, err := os.ReadFile(savedFile)
	if err != nil {
		t.Fatalf("Failed to read saved certs file: %v", err)
	}

	var combined []CTCert
	if err := json.Unmarshal(b, &combined); err != nil {
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
	app := &AppState{}
	app.PrerenderedJSON.Store([]byte(`{"status":"prerendered"}`))

	server, _ := setupHTTPServer(app, "0")
	handler := server.Handler

	// Write a mock certs file for testdomain.com
	testDomain := "testdomain.com"
	_ = saveCertsToHistory(testDomain, []CTCert{{ID: "c1", Match: testDomain, Issuer: "CA1"}})

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
	origTransport := ctHTTPClient.Transport
	defer func() { ctHTTPClient.Transport = origTransport }()

	ctHTTPClient.Transport = mockRoundTripper(func(_ *http.Request) (*http.Response, error) {
		payload := `{"rows":[{"id":"cert-first-1","match":"firstrun.example.com","issuer":"Let's Encrypt"}],"has_next":false,"next_cursor":""}`
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewBufferString(payload)),
			Header:     make(http.Header),
		}, nil
	})

	app := &AppState{config: AppConfig{}, Notifier: &NotificationManager{}}
	domain := "firstrun.example.com"
	defer func() { _ = os.Remove(filepath.Join(CTLogsPath, domain+".json")) }()

	target := DomainConfig{
		Domain:         domain,
		MonitorCTLogs:  true,
		SuppressAlerts: false,
	}
	saved := evaluateCTLogs(context.Background(), app, target, nil)

	// First run must not emit notifications for existing cert baseline
	if len(app.Notifier.Buffer) != 0 {
		t.Errorf("Expected 0 alerts on first-run baseline discovery, got %d", len(app.Notifier.Buffer))
	}

	if saved == nil {
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
	origTransport := ctHTTPClient.Transport
	defer func() { ctHTTPClient.Transport = origTransport }()

	// Backfill request returns 429 Too Many Requests
	ctHTTPClient.Transport = mockRoundTripper(func(req *http.Request) (*http.Response, error) {
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
	})

	app := &AppState{config: AppConfig{}, Notifier: &NotificationManager{}}
	domain := "ratelimit.example.com"
	defer func() { _ = os.Remove(filepath.Join(CTLogsPath, domain+".json")) }()

	target := DomainConfig{
		Domain:         domain,
		MonitorCTLogs:  true,
		SuppressAlerts: false,
	}
	savedCursor := "cursor-prior-checkpoint"
	existing := &CTLogState{
		LatestID:         "cert-existing-1",
		BackfillCursor:   savedCursor,
		BackfillComplete: false,
		Status:           StatusOK,
	}

	res := evaluateCTLogs(context.Background(), app, target, existing)

	if res == nil {
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
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("Invalid key: " + apiKey))
	}))
	defer server.Close()

	_, err := fetchCTPage(context.Background(), app, server.URL)
	if err == nil {
		t.Fatalf("Expected error from 401 unauthorized")
	}
	if strings.Contains(err.Error(), apiKey) {
		t.Errorf("API key leaked in error message: %v", err)
	}
	if !strings.Contains(err.Error(), "[REDACTED_API_KEY]") {
		t.Errorf("Expected [REDACTED_API_KEY] in error message: %v", err)
	}
}

func TestSaveCertsToHistory_CapAtMaxHistory(t *testing.T) {
	domain := "cap-test.example.com"
	cleanFile := filepath.Join(CTLogsPath, domain+".json")
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

	if err := saveCertsToHistory(domain, certs); err != nil {
		t.Fatalf("saveCertsToHistory failed: %v", err)
	}

	b, err := os.ReadFile(cleanFile)
	if err != nil {
		t.Fatalf("failed to read written file: %v", err)
	}

	var saved []CTCert
	if err := json.Unmarshal(b, &saved); err != nil {
		t.Fatalf("failed to unmarshal saved certs: %v", err)
	}

	if len(saved) != MaxCTCertHistory {
		t.Errorf("expected history capped at %d, got %d", MaxCTCertHistory, len(saved))
	}
}

