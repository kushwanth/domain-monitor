package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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

func TestAtomicWriteFile(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	targetPath := filepath.Join(tmpDir, "test.txt")

	data1 := []byte("Initial content")
	if err := atomicWriteFile(targetPath, data1, 0644); err != nil {
		t.Fatalf("atomicWriteFile failed: %v", err)
	}

	read1, err := os.ReadFile(targetPath)
	if err != nil || string(read1) != string(data1) {
		t.Fatalf("Expected '%s', got '%s', err: %v", string(data1), string(read1), err)
	}

	data2 := []byte("Updated content atomically")
	if err := atomicWriteFile(targetPath, data2, 0644); err != nil {
		t.Fatalf("atomicWriteFile overwrite failed: %v", err)
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
		{ID: "cert-1", Match: "example.com", Issuer: "Let's Encrypt"},
		{ID: "cert-2", Match: "sub.example.com", Issuer: "DigiCert"},
	}

	if err := saveCertsToHistory(domain, certs1); err != nil {
		t.Fatalf("saveCertsToHistory batch 1 failed: %v", err)
	}

	// Save batch 2 with overlapping and new certs
	certs2 := []CTCert{
		{ID: "cert-2", Match: "sub.example.com", Issuer: "DigiCert"},
		{ID: "cert-3", Match: "api.example.com", Issuer: "Let's Encrypt"},
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
}

func TestHTTPServerRoutes(t *testing.T) {
	app := &AppState{}
	app.PrerenderedJSON.Store([]byte(`{"status":"prerendered"}`))
	app.PrerenderedHTML.Store([]byte(`<!DOCTYPE html><html><body>Loaded</body></html>`))

	firstRunDone := make(chan struct{})
	close(firstRunDone)

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
	if !strings.Contains(rec.Body.String(), "Loaded") {
		t.Errorf("/ body = %s, expected Loaded", rec.Body.String())
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
	firstRunDone := make(chan struct{})
	close(firstRunDone)

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
