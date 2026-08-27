package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openrdap/rdap"
)

func TestRDAPValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		targetNS      []string
		liveNS        []string
		expectUnauth  bool
		expectMissing bool
	}{
		{
			name:          "Perfect Match",
			targetNS:      []string{"ns1.example.com", "ns2.example.com"},
			liveNS:        []string{"ns1.example.com", "ns2.example.com"},
			expectUnauth:  false,
			expectMissing: false,
		},
		{
			name:          "Missing NS",
			targetNS:      []string{"ns1.example.com", "ns2.example.com"},
			liveNS:        []string{"ns1.example.com"},
			expectUnauth:  false,
			expectMissing: true,
		},
		{
			name:          "Unauthorized NS",
			targetNS:      []string{"ns1.example.com"},
			liveNS:        []string{"ns1.example.com", "rogue.ns.com"},
			expectUnauth:  true,
			expectMissing: false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			expectedMap := make(map[string]bool)
			for _, expected := range tt.targetNS {
				expectedMap[expected] = true
			}

			liveNSMap := make(map[string]bool)
			unauthFound := false

			for _, live := range tt.liveNS {
				liveNSMap[live] = true
				if !expectedMap[live] {
					unauthFound = true
				}
			}

			missingFound := false
			for _, expected := range tt.targetNS {
				if !liveNSMap[expected] {
					missingFound = true
				}
			}

			if unauthFound != tt.expectUnauth {
				t.Errorf("Expected Unauth: %v, got %v", tt.expectUnauth, unauthFound)
			}
			if missingFound != tt.expectMissing {
				t.Errorf("Expected Missing: %v, got %v", tt.expectMissing, missingFound)
			}
		})
	}
}

func TestRDAPStatusLock(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		statuses   []string
		expectLock bool
		expectSusp bool
	}{
		{
			name:       "Standard Locked",
			statuses:   []string{"clientTransferProhibited", "clientUpdateProhibited"},
			expectLock: true,
			expectSusp: false,
		},
		{
			name:       "Standard Locked with ICANN URL",
			statuses:   []string{"clientTransferProhibited https://icann.org/epp#clientTransferProhibited"},
			expectLock: true,
			expectSusp: false,
		},
		{
			name:       "Server Transfer Prohibited",
			statuses:   []string{"serverTransferProhibited"},
			expectLock: true,
			expectSusp: false,
		},
		{
			name:       "Unlocked",
			statuses:   []string{"ok"},
			expectLock: false,
			expectSusp: false,
		},
		{
			name:       "Suspended (ServerHold)",
			statuses:   []string{"serverHold"},
			expectLock: false,
			expectSusp: true,
		},
		{
			name:       "Suspended (ClientHold)",
			statuses:   []string{"clientHold"},
			expectLock: false,
			expectSusp: true,
		},
		{
			name:       "Suspended (PendingDelete)",
			statuses:   []string{"pendingDelete"},
			expectLock: false,
			expectSusp: true,
		},
		{
			name:       "Suspended (RedemptionPeriod)",
			statuses:   []string{"redemptionPeriod"},
			expectLock: false,
			expectSusp: true,
		},
		{
			name:       "Suspended (Inactive)",
			statuses:   []string{"inactive"},
			expectLock: false,
			expectSusp: true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cleaned := cleanStatuses(tt.statuses)
			isLocked := isTransferLocked(cleaned)
			isSusp, _ := getSuspensionStatus(cleaned)

			if isLocked != tt.expectLock {
				t.Errorf("Expected Lock: %v, got %v (cleaned: %v)", tt.expectLock, isLocked, cleaned)
			}
			if isSusp != tt.expectSusp {
				t.Errorf("Expected Suspended: %v, got %v (cleaned: %v)", tt.expectSusp, isSusp, cleaned)
			}
		})
	}
}

func TestExtractVCardText(t *testing.T) {
	t.Parallel()

	// 1. String property
	p1 := &rdap.VCardProperty{Name: "fn", Value: "Cloudflare, Inc."}
	if val := extractVCardText(p1); val != "Cloudflare, Inc." {
		t.Errorf("Expected 'Cloudflare, Inc.', got %q", val)
	}

	// 2. Array of interface{} property (RFC 7095 multi-part jCard)
	p2 := &rdap.VCardProperty{Name: "org", Value: []interface{}{"GoDaddy.com, LLC", "Domain Services"}}
	if val := extractVCardText(p2); val != "GoDaddy.com, LLC Domain Services" {
		t.Errorf("Expected 'GoDaddy.com, LLC Domain Services', got %q", val)
	}

	// 3. Array of string property
	p3 := &rdap.VCardProperty{Name: "fn", Value: []string{"Namecheap", "Support"}}
	if val := extractVCardText(p3); val != "Namecheap Support" {
		t.Errorf("Expected 'Namecheap Support', got %q", val)
	}

	// 4. Nil property
	if val := extractVCardText(nil); val != "" {
		t.Errorf("Expected empty string for nil property, got %q", val)
	}
}

func TestCollectRDAPReferralLinks(t *testing.T) {
	t.Parallel()

	domainInfo := &rdap.Domain{
		Links: []rdap.Link{
			{Rel: "self", Href: "https://rdap.verisign.com/com/v1/domain/example.com"},
		},
		Entities: []rdap.Entity{
			{
				Roles: []string{"registrar"},
				Links: []rdap.Link{
					{
						Rel:  "related",
						Href: "https://rdap.markmonitor.com/rdap/domain/example.com",
						Type: "application/rdap+json",
					},
				},
			},
		},
	}

	links := collectRDAPReferralLinks(domainInfo, "https://rdap.verisign.com/com/v1")
	if len(links) != 1 {
		t.Fatalf("Expected 1 referral link, got %d (%v)", len(links), links)
	}
	if links[0] != "https://rdap.markmonitor.com/rdap/domain/example.com" {
		t.Errorf("Expected MarkMonitor referral link, got %s", links[0])
	}
}

func TestValidateRDAPStateAlertsAndStatus(t *testing.T) {
	t.Parallel()

	app := &AppState{
		Notifier: &NotificationManager{},
	}
	state := &CheckState{
		RDAP: make(map[string]*RDAPState),
	}

	target := DomainConfig{
		Domain:         "example.com",
		Name:           "Example Domain",
		ExpectedNS:     []string{"ns1.example.com", "ns2.example.com"},
		SuppressAlerts: false,
	}

	// Case 1: Active domain with matching NS and lock
	parsed1 := &RDAPState{
		Status:       StatusOk,
		Nameservers:  []string{"ns1.example.com", "ns2.example.com"},
		DomainStatus: []string{"clientTransferProhibited"},
		Expiration:   time.Now().Add(60 * 24 * time.Hour).UTC().Format(time.RFC3339),
	}
	validateRDAPState(app, target, state, parsed1)

	state.RDAPMu.Lock()
	savedState1 := state.RDAP["example.com"]
	state.RDAPMu.Unlock()

	if savedState1.Status != StatusOk {
		t.Errorf("Expected StatusOk, got %s", savedState1.Status)
	}

	// Case 2: Suspended domain (serverHold) -> Status should be StatusFailed
	parsed2 := &RDAPState{
		Status:       StatusOk,
		Nameservers:  []string{"ns1.example.com", "ns2.example.com"},
		DomainStatus: []string{"serverHold"},
	}
	validateRDAPState(app, target, state, parsed2)

	state.RDAPMu.Lock()
	savedState2 := state.RDAP["example.com"]
	state.RDAPMu.Unlock()

	if savedState2.Status != StatusFailed {
		t.Errorf("Expected StatusFailed for serverHold, got %s", savedState2.Status)
	}
}

func TestFlexibleDateParsing(t *testing.T) {
	t.Parallel()

	testDates := []struct {
		input    string
		expected string // ISO year-month-day
	}{
		{"2026-08-13T04:00:00Z", "2026-08-13"},
		{"2026-08-13T04:00:00.000Z", "2026-08-13"},
		{"2026-08-13 04:00:00 UTC", "2026-08-13"},
		{"2026-08-13 04:00:00 MST", "2026-08-13"},
		{"2026-08-13 04:00:00 JST", "2026-08-12"}, // 04:00 JST is 19:00 UTC previous day
		{"2026-08-13 14:00:00 JST", "2026-08-13"},
		{"2026-08-13 04:00:00", "2026-08-13"},
		{"2026-08-13", "2026-08-13"},
		{"13-Aug-2026", "2026-08-13"},
		{"13-Aug-2026 04:00:00 UTC", "2026-08-13"},
		{"2026.08.13", "2026-08-13"},
		{"2026.08.13 04:00:00", "2026-08-13"},
		{"2026/08/13", "2026-08-13"},
		{"2026/08/13 04:00:00", "2026-08-13"},
		{"13/08/2026", "2026-08-13"},
		{"13.08.2026", "2026-08-13"},
		{"Thu Aug 13 04:00:00 UTC 2026", "2026-08-13"},
		{"20260813", "2026-08-13"},
		{"2026-08-13T04:00:00-04:00", "2026-08-13"},
		{`"2026-08-13" (YYYY-MM-DD)`, "2026-08-13"},
		{"Expires on: 2026-08-13", "2026-08-13"},
		{"Renewal Date: 2026-08-13T04:00:00Z", "2026-08-13"},
	}

	for _, tc := range testDates {
		_, norm, err := parseFlexibleDate(tc.input)
		if err != nil {
			t.Errorf("parseFlexibleDate(%q) failed: %v", tc.input, err)
			continue
		}
		if !strings.HasPrefix(norm, tc.expected) {
			t.Errorf("parseFlexibleDate(%q) = %q, expected prefix %q", tc.input, norm, tc.expected)
		}
	}
}

func TestNormalizeEPPStatus(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input    string
		expected string
	}{
		{"clientTransferProhibited https://icann.org/epp#clientTransferProhibited", "clientTransferProhibited"},
		{"https://icann.org/epp#serverHold", "serverHold"},
		{"ok", "ok"},
		{"ACTIVE", "ACTIVE"},
		{"clientTransferProhibited (server-managed)", "clientTransferProhibited"},
		{"inactive", "inactive"},
		{"redemptionPeriod", "redemptionPeriod"},
		{"", ""},
	}

	for _, tc := range tests {
		actual := normalizeEPPStatus(tc.input)
		if actual != tc.expected {
			t.Errorf("normalizeEPPStatus(%q) = %q, expected %q", tc.input, actual, tc.expected)
		}
	}
}

func TestFindRegistrarRecursively(t *testing.T) {
	t.Parallel()

	// Entity with VCard fn
	entities1 := []rdap.Entity{
		{
			Roles: []string{"registrar"},
			VCard: &rdap.VCard{
				Properties: []*rdap.VCardProperty{
					{Name: "fn", Value: "GoDaddy.com, LLC"},
				},
			},
		},
	}
	if reg := findRegistrarRecursively(entities1); reg != "GoDaddy.com, LLC" {
		t.Errorf("Expected 'GoDaddy.com, LLC', got %q", reg)
	}

	// Entity with VCard org as array
	entities2 := []rdap.Entity{
		{
			Roles: []string{"sponsor"},
			VCard: &rdap.VCard{
				Properties: []*rdap.VCardProperty{
					{Name: "org", Value: []interface{}{"NameCheap, Inc."}},
				},
			},
		},
	}
	if reg := findRegistrarRecursively(entities2); reg != "NameCheap, Inc." {
		t.Errorf("Expected 'NameCheap, Inc.', got %q", reg)
	}

	// Entity with PublicID (IANA ID)
	entities3 := []rdap.Entity{
		{
			Roles: []string{"registrar"},
			PublicIDs: []rdap.PublicID{
				{Type: "iana", Identifier: "1068"},
			},
		},
	}
	if reg := findRegistrarRecursively(entities3); reg != "Registrar (IANA 1068)" {
		t.Errorf("Expected 'Registrar (IANA 1068)', got %q", reg)
	}
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
	orig := getWhoisQueryFn()
	defer func() { setWhoisQueryFn(orig) }()

	setWhoisQueryFn(func(domain string) (string, error) {
		return sampleWhois, nil
	})

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

func TestFetchWhois_AlternativeTemplates(t *testing.T) {
	orig := getWhoisQueryFn()
	defer func() { setWhoisQueryFn(orig) }()

	// Test ccTLD style with paid-till and nserver (e.g. RU/SU/ccTLDs)
	whoisRu := `
domain:        EXAMPLE.RU
nserver:       ns1.example.ru.
nserver:       ns2.example.ru.
state:         REGISTERED, DELEGATED, VERIFIED
org:           Example LLC
registrar:     RU-CENTER-RU
paid-till:     2026-09-15
`
	setWhoisQueryFn(func(domain string) (string, error) {
		return whoisRu, nil
	})

	state, err := fetchWhois("example.ru")
	if err != nil {
		t.Fatalf("fetchWhois failed on RU template: %v", err)
	}
	if state.Expiration == "" || !strings.HasPrefix(state.Expiration, "2026-09-15") {
		t.Errorf("Expected expiration 2026-09-15, got %q", state.Expiration)
	}
	if state.Registrar != "RU-CENTER-RU" {
		t.Errorf("Expected registrar RU-CENTER-RU, got %q", state.Registrar)
	}
	if len(state.Nameservers) < 2 {
		t.Errorf("Expected at least 2 nameservers, got %v", state.Nameservers)
	}

	// Test UK style with Expiry date: and Sponsoring Registrar:
	whoisUk := `
    Domain name:
        example.co.uk

    Registrar:
        Nominet UK [Tag = NOMINET]
        URL: http://www.nominet.uk

    Relevant dates:
        Registered on: 01-Aug-1996
        Expiry date:  01-Aug-2027
        Last updated:  08-Jul-2024

    Name servers:
        ns1.nominet.org.uk
        ns2.nominet.org.uk
`
	setWhoisQueryFn(func(domain string) (string, error) {
		return whoisUk, nil
	})

	stateUk, err := fetchWhois("example.co.uk")
	if err != nil {
		t.Fatalf("fetchWhois failed on UK template: %v", err)
	}
	if stateUk.Expiration == "" || !strings.HasPrefix(stateUk.Expiration, "2027-08-01") {
		t.Errorf("Expected expiration 2027-08-01, got %q", stateUk.Expiration)
	}
}

func TestFetchWhois_NotFound(t *testing.T) {
	orig := getWhoisQueryFn()
	defer func() { setWhoisQueryFn(orig) }()

	setWhoisQueryFn(func(domain string) (string, error) {
		return "No match for domain NOTFOUND12345.COM.", nil
	})

	_, err := fetchWhois("notfound12345.com")
	if err == nil {
		t.Fatalf("Expected error for non-existent domain, got nil")
	}
	if !strings.Contains(err.Error(), "404") && !strings.Contains(err.Error(), "not found") {
		t.Errorf("Expected 404 or not found error, got: %v", err)
	}
}

func TestFollowRegistrarRDAPLinks(t *testing.T) {
	registrarServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		_, _ = w.Write([]byte(`{
			"objectClassName": "domain",
			"handle": "REG-12345",
			"ldhName": "example.com",
			"status": ["clientTransferProhibited", "clientUpdateProhibited"],
			"entities": [
				{
					"roles": ["registrar"],
					"vcardArray": [
						"vcard",
						[
							["version", {}, "text", "4.0"],
							["fn", {}, "text", "Detailed Registrar Inc."]
						]
					]
				}
			],
			"events": [
				{
					"eventAction": "expiration",
					"eventDate": "2028-05-10T12:00:00Z"
				}
			],
			"nameservers": [
				{"ldhName": "ns1.detailedreg.com"},
				{"ldhName": "ns2.detailedreg.com"}
			]
		}`))
	}))
	defer registrarServer.Close()

	links := []string{registrarServer.URL + "/domain/example.com"}

	relDomain := followRegistrarRDAPLinks(context.Background(), "example.com", links, nil)
	if relDomain == nil {
		t.Fatalf("Expected non-nil relDomain from registrar RDAP server")
	}

	rarTier := extractRDAPDomainTier(relDomain, "registrar_rdap", registrarServer.URL)
	regTier := &DomainTierData{
		Source:       "registry_rdap",
		Server:       "https://registry.example",
		Expiration:   "2028-05-10T12:00:00Z",
		Nameservers:  []string{"ns1.detailedreg.com", "ns2.detailedreg.com"},
		DomainStatus: []string{"serverTransferProhibited"},
	}

	state, _ := synthesizeTierData("example.com", regTier, rarTier)

	if state.Source != "registry_rdap+registrar_rdap" {
		t.Errorf("Expected Source 'registry_rdap+registrar_rdap', got %q", state.Source)
	}

	if state.Registrar != "Detailed Registrar Inc." {
		t.Errorf("Expected Registrar 'Detailed Registrar Inc.', got %q", state.Registrar)
	}

	if !strings.HasPrefix(state.Expiration, "2028-05-10") {
		t.Errorf("Expected Expiration 2028-05-10, got %q", state.Expiration)
	}

	if len(state.Nameservers) != 2 || state.Nameservers[0] != "ns1.detailedreg.com" {
		t.Errorf("Expected nameservers to be populated from registrar, got %v", state.Nameservers)
	}

	if !isTransferLocked(state.DomainStatus) {
		t.Errorf("Expected domain to be transfer locked from registrar statuses")
	}
}

func TestTwoTierHierarchySynthesis(t *testing.T) {
	t.Parallel()

	// Scenario 1: Auto-Renew Grace Period Expiry Discrepancy
	regTier := &DomainTierData{
		Source:       "registry_rdap",
		Server:       "https://rdap.verisign.com",
		Registrar:    "MarkMonitor Inc.",
		Expiration:   "2029-08-15T04:00:00Z", // Registry auto-extended +1 year
		Nameservers:  []string{"ns1.example.com", "ns2.example.com"},
		DomainStatus: []string{"serverTransferProhibited"},
		DNSSEC:       true,
	}

	rarTier := &DomainTierData{
		Source:       "registrar_rdap",
		Server:       "https://rdap.markmonitor.com",
		Registrar:    "MarkMonitor Inc.",
		IANAID:       "292",
		Expiration:   "2028-08-15T04:00:00Z", // Customer expiry is 1 year earlier
		Nameservers:  []string{"ns1.example.com", "ns2.example.com"},
		DomainStatus: []string{"clientTransferProhibited", "clientUpdateProhibited"},
		DNSSEC:       true,
	}

	state, disc := synthesizeTierData("example.com", regTier, rarTier)

	if len(disc) == 0 {
		t.Errorf("Expected Auto-Renew Grace Period discrepancy to be detected")
	}
	if !strings.Contains(disc[0], "Auto-Renew Grace Period") {
		t.Errorf("Expected discrepancy message to mention Auto-Renew Grace Period, got: %s", disc[0])
	}
	// Conservative date (earlier date) should be used for expiration
	if !strings.HasPrefix(state.Expiration, "2028-08-15") {
		t.Errorf("Expected conservative expiration 2028-08-15, got %s", state.Expiration)
	}
	if state.Registrar != "MarkMonitor Inc." {
		t.Errorf("Expected Registrar 'MarkMonitor Inc.', got %s", state.Registrar)
	}
	if !isTransferLocked(state.DomainStatus) {
		t.Errorf("Expected domain to be transfer locked")
	}
	if !state.DNSSEC {
		t.Errorf("Expected DNSSEC to be true")
	}

	// Scenario 2: Nameserver Desynchronization
	rarTierDesync := &DomainTierData{
		Source:       "registrar_rdap",
		Registrar:    "MarkMonitor Inc.",
		Expiration:   "2029-08-15T04:00:00Z",
		Nameservers:  []string{"ns3.desync.com", "ns4.desync.com"}, // Different from registry
		DomainStatus: []string{"clientTransferProhibited"},
	}

	state2, disc2 := synthesizeTierData("example.com", regTier, rarTierDesync)
	if len(disc2) == 0 {
		t.Errorf("Expected Nameserver desync discrepancy to be detected")
	}
	if !strings.Contains(disc2[0], "Nameserver desync") {
		t.Errorf("Expected discrepancy message to mention Nameserver desync, got: %s", disc2[0])
	}
	// Authoritative parent delegation should be preserved for DNS resolution
	if state2.Nameservers[0] != "ns1.example.com" {
		t.Errorf("Expected registry delegation NS to be preserved, got %v", state2.Nameservers)
	}
}

func TestWHOISContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := queryWhoisWithContext(ctx, "example.com")
	if err == nil {
		t.Errorf("Expected error from cancelled context, got nil")
	}
	if err != context.Canceled {
		t.Errorf("Expected context.Canceled error, got %v", err)
	}
}

func TestWHOISRateLimitingClassification(t *testing.T) {
	t.Parallel()

	rateLimitSamples := []string{
		"Error: Your query limit exceeded. Please try again later.",
		"Status: ACCESS DENIED (Too many requests)",
		"WHOIS LIMIT EXCEEDED - try after 60 seconds",
		"Connection reset by peer: Exceeded your access quota",
	}

	for _, sample := range rateLimitSamples {
		if !isWhoisRateLimited(sample, nil) {
			t.Errorf("Expected %q to be classified as rate limited", sample)
		}
	}

	normalSample := "Domain Name: EXAMPLE.COM\nRegistry Expiry Date: 2028-08-13T04:00:00Z"
	if isWhoisRateLimited(normalSample, nil) {
		t.Errorf("Expected normal WHOIS output not to be rate limited")
	}
}

func TestRDAPTLSConfig(t *testing.T) {
	t.Parallel()

	tlsCfg := RDAPTLSConfig()
	if tlsCfg == nil {
		t.Fatalf("RDAPTLSConfig returned nil")
	}

	if len(tlsCfg.CipherSuites) == 0 {
		t.Errorf("Expected CipherSuites to be populated")
	}
}

func TestFetchWhois_Extensive(t *testing.T) {
	files, err := os.ReadDir("testdata/whois")
	if err != nil {
		t.Skip("testdata/whois not found, skipping extensive tests")
	}

	orig := getWhoisQueryFn()
	defer func() { setWhoisQueryFn(orig) }()

	successCount := 0
	totalCount := 0

	for _, file := range files {
		if file.IsDir() {
			continue
		}
		name := file.Name()
		if strings.HasSuffix(name, ".json") || strings.HasSuffix(name, ".pre") || name == "README.md" || strings.HasPrefix(name, "ac_git.ac") {
			continue
		}

		totalCount++
		filePath := filepath.Join("testdata/whois", name)
		contentBytes, err := os.ReadFile(filePath)
		if err != nil {
			t.Fatalf("failed to read test file %s: %v", filePath, err)
		}
		content := string(contentBytes)

		setWhoisQueryFn(func(domain string) (string, error) {
			return content, nil
		})

		state, err := fetchWhois("example" + filepath.Ext(name))
		if err != nil {
			t.Logf("Failed to parse %s: %v", name, err)
			continue
		}

		if state.Expiration != "" || state.Registrar != "" || len(state.Nameservers) > 0 {
			successCount++
		}
	}

	t.Logf("Successfully extracted some data from %d/%d WHOIS templates", successCount, totalCount)
}
