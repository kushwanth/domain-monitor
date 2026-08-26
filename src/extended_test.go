package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func init() {
	CTLogsPath = filepath.Join(os.TempDir(), "ct_logs_test")
}

func TestFetchWhois(t *testing.T) {
	sampleWhois := `
Domain Name: EXAMPLE.COM
Registry Domain ID: 2336799_DOMAIN_COM-VRSN
Registrar WHOIS Server: whois.verisign-grs.com
Updated Date: 2024-08-14T07:00:00Z
Creation Date: 1995-08-14T04:00:00Z
Registry Expiry Date: 2025-08-13T04:00:00Z
Registrar: RESERVED-Internet Assigned Numbers Authority
Name Server: A.IANA-SERVERS.NET
Name Server: B.IANA-SERVERS.NET
DNSSEC: unsigned
`
	orig := whoisQueryFn
	defer func() { whoisQueryFn = orig }()

	whoisQueryFn = func(domain string) (string, error) {
		return sampleWhois, nil
	}

	state, err := fetchWhois("example.com")
	if err != nil {
		t.Fatalf("fetchWhois failed: %v", err)
	}

	if state.Status != StatusOk {
		t.Errorf("Expected status '%s', got '%s'", StatusOk, state.Status)
	}

	if len(state.Nameservers) == 0 {
		t.Errorf("Expected nameservers to be populated")
	}

	if state.Expiration == "" {
		t.Errorf("Expected expiration to be populated")
	}
}

func TestEmailMXVerification(t *testing.T) {
	t.Parallel()

	providerMXMap := map[string][]string{
		"google":    {"google.com", "googlemail.com"},
		"microsoft": {"protection.outlook.com"},
		"zoho":      {"zoho.com", "zoho.in"},
		"fastmail":  {"messagingengine.com"},
		"proton":    {"protonmail.ch"},
	}

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
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			expectedSuffixes, ok := providerMXMap[tt.provider]
			if !ok {
				// Unknown provider, hijacking logic is skipped
				return
			}

			hijackSafe := false
			for _, live := range tt.liveMXs {
				for _, suffix := range expectedSuffixes {
					if strings.HasSuffix(live, suffix) {
						hijackSafe = true
						break
					}
				}
				if hijackSafe {
					break
				}
			}

			isHijacked := !hijackSafe
			if isHijacked != tt.expectHijack {
				t.Errorf("Expected Hijack: %v, got %v", tt.expectHijack, isHijacked)
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
