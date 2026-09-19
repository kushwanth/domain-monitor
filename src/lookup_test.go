package main

import (
	"context"
	jsonv2 "encoding/json/v2"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var whoisTestMu sync.RWMutex

func setWHOISQueryFn(fn func(string) (string, error)) {
	whoisTestMu.Lock()
	defer whoisTestMu.Unlock()
	whoisQueryFn = fn
}

func getWHOISQueryFn() func(string) (string, error) {
	whoisTestMu.RLock()
	defer whoisTestMu.RUnlock()
	return whoisQueryFn
}

func TestRDAPValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		targetNS      []string
		secondaryNS   []string
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
		{
			name:          "Secondary/Slave NS Authorized At Registrar",
			targetNS:      []string{"ns1.example.com", "ns2.example.com"},
			secondaryNS:   []string{"slave1.example.com", "slave2.example.com"},
			liveNS:        []string{"ns1.example.com", "ns2.example.com", "slave1.example.com", "slave2.example.com"},
			expectUnauth:  false,
			expectMissing: false,
		},
		{
			name:          "Unauthorized NS Even With Secondary NS Configured",
			targetNS:      []string{"ns1.example.com"},
			secondaryNS:   []string{"slave.example.com"},
			liveNS:        []string{"ns1.example.com", "slave.example.com", "rogue.ns.com"},
			expectUnauth:  true,
			expectMissing: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			app := &AppState{
				Notifier: &NotificationManager{TestMode: true},
			}

			target := DomainConfig{
				Domain:      "example.com",
				Name:        "Example",
				ExpectedNS:  tt.targetNS,
				SecondaryNS: tt.secondaryNS,
			}

			parsed := RDAPState{
				Status:       StatusOK,
				Nameservers:  tt.liveNS,
				DomainStatus: []string{"clientTransferProhibited"},
			}

			parsed = validateRDAPState(app, target, parsed)

			unauthAlert := false
			missingAlert := false

			for _, alert := range app.Notifier.TestBuffer {
				if strings.Contains(alert.Message, "unauthorized ns on") || alert.Redacted == "Unauthorized nameserver detected." {
					unauthAlert = true
				}
				if strings.Contains(alert.Message, "expected ns missing from") || alert.Redacted == "Expected nameserver is missing." {
					missingAlert = true
				}
			}

			if unauthAlert != tt.expectUnauth {
				t.Errorf("Expected Unauth alert=%v, got %v (buffer: %+v)", tt.expectUnauth, unauthAlert, app.Notifier.TestBuffer)
			}
			if missingAlert != tt.expectMissing {
				t.Errorf("Expected Missing alert=%v, got %v (buffer: %+v)", tt.expectMissing, missingAlert, app.Notifier.TestBuffer)
			}
			expectedStatus := StatusOK
			if tt.expectUnauth || tt.expectMissing {
				expectedStatus = StatusFailed
			}
			if parsed.Status != expectedStatus {
				t.Errorf("Expected parsed.Status=%s, got %s", expectedStatus, parsed.Status)
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
			name:       "Standard Locked (RDAP space-separated)",
			statuses:   []string{"client transfer prohibited", "client update prohibited"},
			expectLock: true,
			expectSusp: false,
		},
		{
			name:       "Server Transfer Prohibited (RDAP space-separated)",
			statuses:   []string{"server transfer prohibited"},
			expectLock: true,
			expectSusp: false,
		},
		{
			name:       "Transfer Prohibited (Hyphenated)",
			statuses:   []string{"client-transfer-prohibited"},
			expectLock: true,
			expectSusp: false,
		},
		{
			name:       "Suspended (RDAP client hold)",
			statuses:   []string{"client hold"},
			expectLock: false,
			expectSusp: true,
		},
		{
			name:       "Suspended (RDAP server hold)",
			statuses:   []string{"server hold"},
			expectLock: false,
			expectSusp: true,
		},
		{
			name:       "Suspended (RDAP pending delete)",
			statuses:   []string{"pending delete"},
			expectLock: false,
			expectSusp: true,
		},
		{
			name:       "Suspended (RDAP redemption period)",
			statuses:   []string{"redemption period"},
			expectLock: false,
			expectSusp: true,
		},
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
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cleaned := NormalizeDomainStatuses(tt.statuses)
			isLocked := isTransferLocked(cleaned)
			isSusp, _ := isDomainSuspended(cleaned)

			if isLocked != tt.expectLock {
				t.Errorf("Expected Lock: %v, got %v (cleaned: %v)", tt.expectLock, isLocked, cleaned)
			}
			if isSusp != tt.expectSusp {
				t.Errorf("Expected Suspended: %v, got %v (cleaned: %v)", tt.expectSusp, isSusp, cleaned)
			}
		})
	}
}

func TestNormalizeDomainStatusesDeduplication(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    []string
		expected []string
	}{
		{
			name:     "Client and Generic Duplicate Prohibitions",
			input:    []string{"Client Delete Prohibited", "Client Transfer Prohibited", "Delete Prohibited", "Transfer Prohibited"},
			expected: []string{"clientDeleteProhibited", "clientTransferProhibited"},
		},
		{
			name:     "Server and Generic Duplicate Prohibitions",
			input:    []string{"serverDeleteProhibited", "serverTransferProhibited", "deleteProhibited", "transferProhibited"},
			expected: []string{"serverDeleteProhibited", "serverTransferProhibited"},
		},
		{
			name:     "Update and Renew Prohibitions",
			input:    []string{"clientUpdateProhibited", "updateProhibited", "clientRenewProhibited", "renewProhibited"},
			expected: []string{"clientUpdateProhibited", "clientRenewProhibited"},
		},
		{
			name:     "Hold Deduplication",
			input:    []string{"clientHold", "hold"},
			expected: []string{"clientHold"},
		},
		{
			name:     "Generic Only Prohibitions Retained",
			input:    []string{"transferProhibited", "deleteProhibited"},
			expected: []string{"transferProhibited", "deleteProhibited"},
		},
		{
			name:     "Both Client and Server Prohibitions Retained",
			input:    []string{"clientTransferProhibited", "serverTransferProhibited", "transferProhibited"},
			expected: []string{"clientTransferProhibited", "serverTransferProhibited"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			actual := NormalizeDomainStatuses(tt.input)
			if len(actual) != len(tt.expected) {
				t.Fatalf("NormalizeDomainStatuses(%v) = %v (len %d), expected %v (len %d)", tt.input, actual, len(actual), tt.expected, len(tt.expected))
			}
			for i := range actual {
				if actual[i] != tt.expected[i] {
					t.Errorf("Index %d: got %s, expected %s", i, actual[i], tt.expected[i])
				}
			}
		})
	}
}

func TestExtractVCardText(t *testing.T) {
	t.Parallel()

	// 1. String property
	if val := extractVCardText("Cloudflare, Inc."); val != "Cloudflare, Inc." {
		t.Errorf("Expected 'Cloudflare, Inc.', got %q", val)
	}

	// 2. Array of interface{} property (RFC 7095 multi-part jCard)
	if val := extractVCardText([]any{"GoDaddy.com, LLC", "Domain Services"}); val != "GoDaddy.com, LLC Domain Services" {
		t.Errorf("Expected 'GoDaddy.com, LLC Domain Services', got %q", val)
	}

	// 3. Array of string property
	if val := extractVCardText([]string{"Namecheap", "Support"}); val != "Namecheap Support" {
		t.Errorf("Expected 'Namecheap Support', got %q", val)
	}

	// 4. Nil property
	if val := extractVCardText(nil); val != "" {
		t.Errorf("Expected empty string for nil property, got %q", val)
	}

	// 5. extractVCardProperty from full vcardArray
	vcard := []any{
		"vcard",
		[]any{
			[]any{"version", map[string]any{}, "text", "4.0"},
			[]any{"fn", map[string]any{}, "text", "Cloudflare, Inc."},
			[]any{"org", map[string]any{}, "text", []any{"GoDaddy.com, LLC", "Domain Services"}},
		},
	}
	if fn := extractVCardProperty(vcard, "fn"); fn != "Cloudflare, Inc." {
		t.Errorf("Expected 'Cloudflare, Inc.', got %q", fn)
	}
	if org := extractVCardProperty(vcard, "org"); org != "GoDaddy.com, LLC Domain Services" {
		t.Errorf("Expected 'GoDaddy.com, LLC Domain Services', got %q", org)
	}
}

func TestCollectRDAPReferralLinks(t *testing.T) {
	t.Parallel()

	domainInfo := &RDAPDomainResponse{
		Links: []RDAPLink{
			{Rel: "self", Href: "https://rdap.verisign.com/com/v1/domain/example.com"},
		},
		Entities: []RDAPEntity{
			{
				Roles: []string{"registrar"},
				Links: []RDAPLink{
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
		Notifier: &NotificationManager{TestMode: true},
	}

	target := DomainConfig{
		Domain:         "example.com",
		Name:           "Example Domain",
		ExpectedNS:     []string{"ns1.example.com", "ns2.example.com"},
		SuppressAlerts: false,
	}

	// Case 1: Active domain with matching NS and lock
	parsed1 := RDAPState{
		Status:       StatusOK,
		Nameservers:  []string{"ns1.example.com", "ns2.example.com"},
		DomainStatus: []string{"clientTransferProhibited"},
		Expiration:   time.Now().Add(60 * 24 * time.Hour).UTC().Format(time.RFC3339),
	}
	res1 := validateRDAPState(app, target, parsed1)

	if res1.Status != StatusOK {
		t.Errorf("Expected StatusOK, got %s", res1.Status)
	}

	// Case 2: Suspended domain (serverHold) -> Status should be StatusFailed
	parsed2 := RDAPState{
		Status:       StatusOK,
		Nameservers:  []string{"ns1.example.com", "ns2.example.com"},
		DomainStatus: []string{"serverHold"},
	}
	savedState2 := validateRDAPState(app, target, parsed2)

	if savedState2.Status != StatusFailed {
		t.Errorf("Expected StatusFailed for serverHold, got %s", savedState2.Status)
	}
}

func TestValidateRDAPState_SuppressAlertsStoresSnapshot(t *testing.T) {
	t.Parallel()

	app := &AppState{
		Notifier: &NotificationManager{TestMode: true},
	}

	target := DomainConfig{
		Domain:         "suppressed.example.com",
		Name:           "Suppressed Domain",
		ExpectedNS:     []string{"ns1.example.com"},
		SuppressAlerts: true,
	}

	// Multiple alertable conditions: expired in 2 days, missing NS, serverHold
	parsed := RDAPState{
		Status:       StatusOK,
		Nameservers:  []string{"unauthorized.ns.com"},
		DomainStatus: []string{"serverHold"},
		Expiration:   time.Now().Add(2 * 24 * time.Hour).UTC().Format(time.RFC3339),
	}

	saved := validateRDAPState(app, target, parsed)

	if saved.Status == "" {
		t.Fatalf("Expected state snapshot to be saved even when alerts are suppressed")
	}
	if saved.Status != StatusFailed {
		t.Errorf("Expected StatusFailed for serverHold, got %s", saved.Status)
	}
	if len(saved.Nameservers) != 1 || saved.Nameservers[0] != "unauthorized.ns.com" {
		t.Errorf("Expected nameservers to be preserved in snapshot, got %v", saved.Nameservers)
	}
}

func TestValidateRDAPState_RegistrarValidation(t *testing.T) {
	t.Parallel()

	// 1. ExpectedRegistrarID Match
	app1 := &AppState{Notifier: &NotificationManager{TestMode: true}}

	target1 := DomainConfig{
		Domain:              "example.com",
		Name:                "Test Domain",
		ExpectedRegistrarID: "292",
	}
	parsed1 := RDAPState{
		Status:          StatusOK,
		Registrar:       "MarkMonitor Inc.",
		RegistrarIANAID: "292",
		DomainStatus:    []string{"clientTransferProhibited"},
	}
	parsed1 = validateRDAPState(app1, target1, parsed1)
	if parsed1.Status != StatusOK {
		t.Errorf("Expected StatusOK on matching IANA ID, got %s", parsed1.Status)
	}
	if parsed1.RegistrarMismatch {
		t.Errorf("Expected RegistrarMismatch=false on matching IANA ID")
	}
	if len(app1.Notifier.TestBuffer) != 0 {
		t.Errorf("Expected 0 alerts on matching IANA ID, got %d", len(app1.Notifier.TestBuffer))
	}

	// 2. ExpectedRegistrarID Mismatch
	app2 := &AppState{Notifier: &NotificationManager{TestMode: true}}
	target2 := DomainConfig{
		Domain:              "example.com",
		Name:                "Test Domain",
		ExpectedRegistrarID: "292",
	}
	parsed2 := RDAPState{
		Status:          StatusOK,
		Registrar:       "Other Registrar LLC",
		RegistrarIANAID: "146",
		DomainStatus:    []string{"clientTransferProhibited"},
	}
	parsed2 = validateRDAPState(app2, target2, parsed2)
	if parsed2.Status != StatusFailed {
		t.Errorf("Expected StatusFailed on IANA ID mismatch, got %s", parsed2.Status)
	}
	if !parsed2.RegistrarMismatch {
		t.Errorf("Expected RegistrarMismatch=true on IANA ID mismatch")
	}
	if parsed2.ExpectedRegistrar != "IANA 292" {
		t.Errorf("Expected ExpectedRegistrar 'IANA 292', got %q", parsed2.ExpectedRegistrar)
	}
	if len(app2.Notifier.TestBuffer) != 1 {
		t.Errorf("Expected 1 alert on IANA ID mismatch, got %d", len(app2.Notifier.TestBuffer))
	}

	// 3. ExpectedRegistrarName Match (case-insensitive substring)
	app3 := &AppState{Notifier: &NotificationManager{TestMode: true}}

	target3 := DomainConfig{
		Domain:                "example.com",
		Name:                  "Test Domain",
		ExpectedRegistrarName: "markmonitor",
	}
	parsed3 := RDAPState{
		Status:       StatusOK,
		Registrar:    "MarkMonitor, Inc.",
		DomainStatus: []string{"clientTransferProhibited"},
	}
	parsed3 = validateRDAPState(app3, target3, parsed3)
	if parsed3.Status != StatusOK {
		t.Errorf("Expected StatusOK on matching registrar name, got %s", parsed3.Status)
	}
	if parsed3.RegistrarMismatch {
		t.Errorf("Expected RegistrarMismatch=false on matching registrar name")
	}
	if len(app3.Notifier.TestBuffer) != 0 {
		t.Errorf("Expected 0 alerts on matching registrar name, got %d", len(app3.Notifier.TestBuffer))
	}

	// 4. ExpectedRegistrarName Mismatch
	app4 := &AppState{Notifier: &NotificationManager{TestMode: true}}
	target4 := DomainConfig{
		Domain:                "example.com",
		Name:                  "Test Domain",
		ExpectedRegistrarName: "markmonitor",
	}
	parsed4 := RDAPState{
		Status:       StatusOK,
		Registrar:    "GoDaddy.com, LLC",
		DomainStatus: []string{"clientTransferProhibited"},
	}
	parsed4 = validateRDAPState(app4, target4, parsed4)
	if parsed4.Status != StatusFailed {
		t.Errorf("Expected StatusFailed on registrar name mismatch, got %s", parsed4.Status)
	}
	if !parsed4.RegistrarMismatch {
		t.Errorf("Expected RegistrarMismatch=true on registrar name mismatch")
	}
	if parsed4.ExpectedRegistrar != "markmonitor" {
		t.Errorf("Expected ExpectedRegistrar 'markmonitor', got %q", parsed4.ExpectedRegistrar)
	}
	if len(app4.Notifier.TestBuffer) != 1 {
		t.Errorf("Expected 1 alert on registrar name mismatch, got %d", len(app4.Notifier.TestBuffer))
	}

	// 5. Both set: Priority 1 (ID) matches, while Priority 2 (Name) would mismatch -> Passes on prioritized ID
	app5 := &AppState{Notifier: &NotificationManager{TestMode: true}}

	target5 := DomainConfig{
		Domain:                "example.com",
		Name:                  "Priority Test Domain 1",
		ExpectedRegistrarID:   "292",
		ExpectedRegistrarName: "godaddy", // Name would mismatch, but ID 292 matches!
	}
	parsed5 := RDAPState{
		Status:          StatusOK,
		Registrar:       "MarkMonitor Inc.",
		RegistrarIANAID: "292",
		DomainStatus:    []string{"clientTransferProhibited"},
	}
	parsed5 = validateRDAPState(app5, target5, parsed5)
	if parsed5.Status != StatusOK {
		t.Errorf("Expected StatusOK when prioritized IANA ID matches, got %s", parsed5.Status)
	}
	if parsed5.RegistrarMismatch {
		t.Errorf("Expected RegistrarMismatch=false when prioritized IANA ID matches")
	}
	if len(app5.Notifier.TestBuffer) != 0 {
		t.Errorf("Expected 0 alerts when prioritized IANA ID matches, got %d", len(app5.Notifier.TestBuffer))
	}

	// 6. Both set: Priority 1 (ID) mismatches, even though Priority 2 (Name) matches -> Fails on prioritized ID
	app6 := &AppState{Notifier: &NotificationManager{TestMode: true}}

	target6 := DomainConfig{
		Domain:                "example.com",
		Name:                  "Priority Test Domain 2",
		ExpectedRegistrarID:   "999",         // ID mismatches
		ExpectedRegistrarName: "markmonitor", // Name matches
	}
	parsed6 := RDAPState{
		Status:          StatusOK,
		Registrar:       "MarkMonitor Inc.",
		RegistrarIANAID: "292",
		DomainStatus:    []string{"clientTransferProhibited"},
	}
	parsed6 = validateRDAPState(app6, target6, parsed6)
	if parsed6.Status != StatusFailed {
		t.Errorf("Expected StatusFailed because prioritized IANA ID mismatched, got %s", parsed6.Status)
	}
	if !parsed6.RegistrarMismatch {
		t.Errorf("Expected RegistrarMismatch=true on prioritized IANA ID mismatch")
	}
	if parsed6.ExpectedRegistrar != "IANA 999" {
		t.Errorf("Expected ExpectedRegistrar 'IANA 999', got %q", parsed6.ExpectedRegistrar)
	}
	if len(app6.Notifier.TestBuffer) != 1 {
		t.Errorf("Expected 1 alert for IANA ID mismatch, got %d", len(app6.Notifier.TestBuffer))
	}
}

func TestValidateRDAPState_DomainTransferLockedGating(t *testing.T) {
	t.Parallel()

	// Scenario 1: domain_transfer_locked is false (default) and domain is unlocked -> No alert
	app1 := &AppState{Notifier: &NotificationManager{TestMode: true}}

	target1 := DomainConfig{
		Domain:               "example.com",
		Name:                 "Test Domain",
		DomainTransferLocked: false,
	}
	parsed1 := RDAPState{
		Status:       StatusOK,
		DomainStatus: []string{"ok"}, // Not locked
	}
	parsed1 = validateRDAPState(app1, target1, parsed1)
	if len(app1.Notifier.TestBuffer) != 0 {
		t.Errorf("Expected 0 alerts when DomainTransferLocked=false, got %d", len(app1.Notifier.TestBuffer))
	}

	// Scenario 2: domain_transfer_locked is true and domain is unlocked -> Alert dispatched
	app2 := &AppState{Notifier: &NotificationManager{TestMode: true}}

	target2 := DomainConfig{
		Domain:               "example.com",
		Name:                 "Test Domain",
		DomainTransferLocked: true,
	}
	parsed2 := RDAPState{
		Status:       StatusOK,
		DomainStatus: []string{"ok"}, // Not locked
	}
	parsed2 = validateRDAPState(app2, target2, parsed2)
	if len(app2.Notifier.TestBuffer) != 1 {
		t.Errorf("Expected 1 alert when DomainTransferLocked=true and unlocked, got %d", len(app2.Notifier.TestBuffer))
	} else {
		expectedMsg := "example.com is unlocked (missing transfer prohibitions)"
		if app2.Notifier.TestBuffer[0].Message != expectedMsg {
			t.Errorf("Expected alert message %q, got %q", expectedMsg, app2.Notifier.TestBuffer[0].Message)
		}
	}
	if parsed2.Status != StatusWarning {
		t.Errorf("Expected StatusWarning when domain is unlocked and DomainTransferLocked=true, got %s", parsed2.Status)
	}

	// Scenario 3: domain_transfer_locked is true and domain is locked -> No alert
	app3 := &AppState{Notifier: &NotificationManager{TestMode: true}}

	target3 := DomainConfig{
		Domain:               "example.com",
		Name:                 "Test Domain",
		DomainTransferLocked: true,
	}
	parsed3 := RDAPState{
		Status:       StatusOK,
		DomainStatus: []string{"clientTransferProhibited"},
	}
	parsed3 = validateRDAPState(app3, target3, parsed3)
	if len(app3.Notifier.TestBuffer) != 0 {
		t.Errorf("Expected 0 alerts when DomainTransferLocked=true and domain is locked, got %d", len(app3.Notifier.TestBuffer))
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
		{"2026-08-13 04:00:00 JST", "2026-08-12"},
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
		{"2026-08-13 15:00:00 JST", "2026-08-13T06:00:00Z"},
		{"2026-08-13 15:00:00 EDT", "2026-08-13T19:00:00Z"},
		{"2026-08-13 15:00:00 KST", "2026-08-13T06:00:00Z"},
		{"2026-08-13 15:00:00 AEST", "2026-08-13T05:00:00Z"},
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
		{"client transfer prohibited", "clientTransferProhibited"},
		{"server transfer prohibited", "serverTransferProhibited"},
		{"transfer prohibited", "transferProhibited"},
		{"client update prohibited", "clientUpdateProhibited"},
		{"client delete prohibited", "clientDeleteProhibited"},
		{"client renew prohibited", "clientRenewProhibited"},
		{"client hold", "clientHold"},
		{"server hold", "serverHold"},
		{"pending delete", "pendingDelete"},
		{"pending transfer", "pendingTransfer"},
		{"redemption period", "redemptionPeriod"},
		{"auto renew period", "autoRenewPeriod"},
		{"client-transfer-prohibited", "clientTransferProhibited"},
		{"client_transfer_prohibited", "clientTransferProhibited"},
		{"https://icann.org/epp#serverHold", "serverHold"},
		{"ok", "ok"},
		{"ACTIVE", "active"},
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
	entities1 := []RDAPEntity{
		{
			Roles: []string{"registrar"},
			VCardArray: []any{
				"vcard",
				[]any{
					[]any{"fn", map[string]any{}, "text", "GoDaddy.com, LLC"},
				},
			},
		},
	}
	if reg := findRegistrarRecursively(entities1); reg != "GoDaddy.com, LLC" {
		t.Errorf("Expected 'GoDaddy.com, LLC', got %q", reg)
	}

	// Entity with VCard org as array
	entities2 := []RDAPEntity{
		{
			Roles: []string{"sponsor"},
			VCardArray: []any{
				"vcard",
				[]any{
					[]any{"org", map[string]any{}, "text", []any{"NameCheap, Inc."}},
				},
			},
		},
	}
	if reg := findRegistrarRecursively(entities2); reg != "NameCheap, Inc." {
		t.Errorf("Expected 'NameCheap, Inc.', got %q", reg)
	}

	// Entity with PublicID (IANA ID)
	entities3 := []RDAPEntity{
		{
			Roles: []string{"registrar"},
			PublicIDs: []RDAPPublicID{
				{Type: "iana", Identifier: "1068"},
			},
		},
	}
	if reg := findRegistrarRecursively(entities3); reg != "Registrar (IANA 1068)" {
		t.Errorf("Expected 'Registrar (IANA 1068)', got %q", reg)
	}
}

func TestFetchWHOIS(t *testing.T) {
	sampleWHOIS := `
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
	orig := getWHOISQueryFn()
	defer func() { setWHOISQueryFn(orig) }()

	setWHOISQueryFn(func(_ string) (string, error) {
		return sampleWHOIS, nil
	})

	state, err := fetchWHOIS(context.Background(), nil, "example.com")
	if err != nil {
		t.Fatalf("fetchWHOIS failed: %v", err)
	}

	if state.Status != StatusOK {
		t.Errorf("Expected status '%s', got '%s'", StatusOK, state.Status)
	}

	if len(state.Nameservers) == 0 {
		t.Errorf("Expected nameservers to be populated")
	}

	if state.Expiration == "" {
		t.Errorf("Expected expiration to be populated")
	}
}

func TestFetchWHOIS_AlternativeTemplates(t *testing.T) {
	orig := getWHOISQueryFn()
	defer func() { setWHOISQueryFn(orig) }()

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
	setWHOISQueryFn(func(_ string) (string, error) {
		return whoisRu, nil
	})

	state, err := fetchWHOIS(context.Background(), nil, "example.ru")
	if err != nil {
		t.Fatalf("fetchWHOIS failed on RU template: %v", err)
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
	setWHOISQueryFn(func(_ string) (string, error) {
		return whoisUk, nil
	})

	stateUk, err := fetchWHOIS(context.Background(), nil, "example.co.uk")
	if err != nil {
		t.Fatalf("fetchWHOIS failed on UK template: %v", err)
	}
	if stateUk.Expiration == "" || !strings.HasPrefix(stateUk.Expiration, "2027-08-01") {
		t.Errorf("Expected expiration 2027-08-01, got %q", stateUk.Expiration)
	}

	// Test Japanese JPRS style with [Header] brackets
	whoisJp := `
[Domain Name]                   SONY.CO.JP
[Organization]                  Sony Group Corporation
[State]                         Connected (2027/01/31)
[Registered Date]               1996/01/29
[Connected Date]                1996/02/06
[Last Update]                   2026/02/01 01:21:40 (JST)
[Name Server]                   ns1.sony.co.jp
[Name Server]                   ns2.sony.co.jp
`
	setWHOISQueryFn(func(_ string) (string, error) {
		return whoisJp, nil
	})

	stateJp, err := fetchWHOIS(context.Background(), nil, "sony.co.jp")
	if err != nil {
		t.Fatalf("fetchWHOIS failed on JPRS template: %v", err)
	}
	if len(stateJp.Nameservers) < 2 {
		t.Errorf("Expected at least 2 nameservers for JPRS, got %v", stateJp.Nameservers)
	}
	if stateJp.Registrar != "Sony Group Corporation" {
		t.Errorf("Expected organization/registrar Sony Group Corporation, got %q", stateJp.Registrar)
	}
}

func TestFetchWHOIS_NotFound(t *testing.T) {
	orig := getWHOISQueryFn()
	defer func() { setWHOISQueryFn(orig) }()

	setWHOISQueryFn(func(_ string) (string, error) {
		return "No match for domain NOTFOUND12345.COM.", nil
	})

	_, err := fetchWHOIS(context.Background(), nil, "notfound12345.com")
	if err == nil {
		t.Fatalf("Expected error for non-existent domain, got nil")
	}
	if !strings.Contains(err.Error(), "404") && !strings.Contains(err.Error(), "not found") {
		t.Errorf("Expected 404 or not found error, got: %v", err)
	}

	// Test SIDN Dutch "is free" response
	setWHOISQueryFn(func(_ string) (string, error) {
		return "unregistered-dutch-test-555.nl is free\n", nil
	})
	_, errNl := fetchWHOIS(context.Background(), nil, "unregistered-dutch-test-555.nl")
	if errNl == nil {
		t.Fatalf("Expected error for SIDN is free domain, got nil")
	}
	if !strings.Contains(errNl.Error(), "404") && !strings.Contains(errNl.Error(), "not found") {
		t.Errorf("Expected 404 error for is free domain, got: %v", errNl)
	}
}

func TestFollowRegistrarRDAPLinks(t *testing.T) {
	allowInsecureRDAPURLs = true
	defer func() { allowInsecureRDAPURLs = false }()

	registrarServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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

	state, _ := synthesizeTierData(regTier, rarTier)

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

	state, disc := synthesizeTierData(regTier, rarTier)

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

	state2, disc2 := synthesizeTierData(regTier, rarTierDesync)
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

	// Scenario 3: Nameserver Desynchronization with Equal Slice Length but Duplicate Entries
	rarTierDuplicate := &DomainTierData{
		Source:       "registrar_rdap",
		Registrar:    "MarkMonitor Inc.",
		Expiration:   "2029-08-15T04:00:00Z",
		Nameservers:  []string{"ns1.example.com", "ns1.example.com"}, // Same count (2), but duplicate
		DomainStatus: []string{"clientTransferProhibited"},
	}

	_, disc3 := synthesizeTierData(regTier, rarTierDuplicate)
	if len(disc3) == 0 {
		t.Errorf("Expected Nameserver desync discrepancy when duplicate NS reduces set size")
	} else if !strings.Contains(disc3[0], "Nameserver desync") {
		t.Errorf("Expected discrepancy message to mention Nameserver desync, got: %s", disc3[0])
	}
}

func TestWHOISContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := queryWHOISWithContext(ctx, nil, "example.com")
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
		if !isWHOISRateLimited(sample, nil) {
			t.Errorf("Expected %q to be classified as rate limited", sample)
		}
	}

	normalSample := "Domain Name: EXAMPLE.COM\nRegistry Expiry Date: 2028-08-13T04:00:00Z"
	if isWHOISRateLimited(normalSample, nil) {
		t.Errorf("Expected normal WHOIS output not to be rate limited")
	}
}

func TestFetchWHOIS_Extensive(t *testing.T) {
	files, err := os.ReadDir("testdata/whois")
	if err != nil {
		t.Skip("testdata/whois not found, skipping extensive tests")
	}

	orig := getWHOISQueryFn()
	defer func() { setWHOISQueryFn(orig) }()

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

		setWHOISQueryFn(func(_ string) (string, error) {
			return content, nil
		})

		state, err := fetchWHOIS(context.Background(), nil, "example"+filepath.Ext(name))
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

func FuzzFlexibleDateParsing(f *testing.F) {
	seeds := []string{
		"2026-08-28T12:00:00Z",
		"2026-08-28",
		"28-Aug-2026",
		"28/08/2026",
		"2026.08.28",
		"Fri Aug 28 12:00:00 2026",
		"Expires: 2026-08-28 (UTC)",
		"invalid-date",
		"",
	}
	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(_ *testing.T, dateStr string) {
		// Should never panic regardless of arbitrary input
		_, _, _ = parseFlexibleDate(dateStr)
	})
}

func FuzzNormalizeEPPStatus(f *testing.F) {
	seeds := []string{
		"clientTransferProhibited",
		"https://icann.org/epp#clientTransferProhibited",
		"serverDeleteProhibited",
		"ok",
		"clientHold (inactive)",
		"",
	}
	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(_ *testing.T, rawStatus string) {
		// Should never panic regardless of arbitrary input
		_ = normalizeEPPStatus(rawStatus)
	})
}

func TestNativeRDAPDomainParsing(t *testing.T) {
	t.Parallel()

	rawJSON := `{
		"objectClassName": "domain",
		"handle": "2336799_DOMAIN_COM-VRSN",
		"ldhName": "EXAMPLE.COM",
		"status": [
			"clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited",
			"clientTransferProhibited https://icann.org/epp#clientTransferProhibited",
			"clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited"
		],
		"entities": [
			{
				"objectClassName": "entity",
				"handle": "292",
				"roles": ["registrar"],
				"publicIds": [
					{
						"type": "IANA Registrar ID",
						"identifier": "292"
					}
				],
				"vcardArray": [
					"vcard",
					[
						["version", {}, "text", "4.0"],
						["fn", {}, "text", "Example Registrar, Inc."],
						["email", {"type": "work"}, "text", "abuse@exampleregistrar.com"]
					]
				],
				"links": [
					{
						"value": "https://rdap.verisign.com/com/v1/domain/EXAMPLE.COM",
						"rel": "related",
						"href": "https://rdap.exampleregistrar.com/rdap/domain/EXAMPLE.COM",
						"type": "application/rdap+json"
					}
				]
			}
		],
		"events": [
			{
				"eventAction": "registration",
				"eventDate": "1995-08-14T04:00:00Z"
			},
			{
				"eventAction": "expiration",
				"eventDate": "2028-08-13T04:00:00Z"
			},
			{
				"eventAction": "last changed",
				"eventDate": "2024-08-14T07:00:00Z"
			}
		],
		"nameservers": [
			{"objectClassName": "nameserver", "ldhName": "a.iana-servers.net."},
			{"objectClassName": "nameserver", "ldhName": "b.iana-servers.net."}
		],
		"secureDNS": {
			"delegationSigned": true,
			"zoneSigned": true
		}
	}`

	var domain RDAPDomainResponse
	if err := jsonv2.Unmarshal([]byte(rawJSON), &domain); err != nil {
		t.Fatalf("Failed to unmarshal RDAP JSON: %v", err)
	}

	tier := extractRDAPDomainTier(&domain, "registry_rdap", "https://rdap.verisign.com/com/v1")
	if tier.Registrar != "Example Registrar, Inc." {
		t.Errorf("Expected registrar 'Example Registrar, Inc.', got %q", tier.Registrar)
	}
	if tier.IANAID != "292" {
		t.Errorf("Expected IANA ID '292', got %q", tier.IANAID)
	}
	if tier.Expiration != "2028-08-13T04:00:00Z" {
		t.Errorf("Expected expiration '2028-08-13T04:00:00Z', got %q", tier.Expiration)
	}
	if tier.Created != "1995-08-14T04:00:00Z" {
		t.Errorf("Expected created '1995-08-14T04:00:00Z', got %q", tier.Created)
	}
	if len(tier.Nameservers) != 2 || tier.Nameservers[0] != "a.iana-servers.net" || tier.Nameservers[1] != "b.iana-servers.net" {
		t.Errorf("Unexpected nameservers: %v", tier.Nameservers)
	}
	if !tier.DNSSEC {
		t.Errorf("Expected DNSSEC true")
	}

	referrals := collectRDAPReferralLinks(&domain, "https://rdap.verisign.com/com/v1")
	if len(referrals) != 1 || referrals[0] != "https://rdap.exampleregistrar.com/rdap/domain/EXAMPLE.COM" {
		t.Errorf("Unexpected referral links: %v", referrals)
	}
}

func TestFollowRegistrarRDAPLinks_SSRFProtection(t *testing.T) {
	unsafeLinks := []string{
		"http://169.254.169.254/latest/meta-data/",
		"http://127.0.0.1:8080/api/certs",
		"http://[::1]:8080/api/state",
		"http://10.0.0.1/admin",
		"http://192.168.1.1/secret",
		"http://172.16.0.1/internal",
		"http://localhost:8080/metrics",
		"http://service.local/rdap",
		"http://metadata.google.internal/computeMetadata/v1/",
		"ftp://rdap.example.com/domain/test",
		"https://user:password@rdap.example.com/domain/test",
		"https://admin@rdap.example.com/domain/test",
		"https://100.64.0.1/rdap",
		"https://100.127.255.254/rdap",
		"https://0.0.0.0/rdap",
	}

	for _, unsafeURL := range unsafeLinks {
		if isSafeRDAPURL(unsafeURL) {
			t.Errorf("Expected isSafeRDAPURL to reject unsafe URL %q", unsafeURL)
		}
	}

	res := followRegistrarRDAPLinks(context.Background(), "example.com", unsafeLinks, nil)
	if res != nil {
		t.Errorf("Expected nil response when all referral links are unsafe SSRF targets")
	}

	// Valid public HTTPS RDAP endpoint format should be permitted
	validPublicURL := "https://rdap.markmonitor.com/rdap/domain/example.com"
	if !isSafeRDAPURL(validPublicURL) {
		t.Errorf("Expected isSafeRDAPURL to accept valid public HTTPS URL %q", validPublicURL)
	}
}

func TestFollowRegistrarRDAPLinks_QueryParamReferral(t *testing.T) {
	allowInsecureRDAPURLs = true
	defer func() { allowInsecureRDAPURLs = false }()

	var receivedPath string
	var receivedQuery string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.URL.Path
		receivedQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/rdap+json")
		_, _ = w.Write([]byte(`{
			"objectClassName": "domain",
			"handle": "REG-QUERY-TEST",
			"ldhName": "example.com",
			"status": ["clientTransferProhibited"]
		}`))
	}))
	defer server.Close()

	// Referral URL with query parameter and base path
	links := []string{server.URL + "/rdap_service?apiKey=secret123"}
	res := followRegistrarRDAPLinks(context.Background(), "example.com", links, nil)

	if res == nil {
		t.Fatalf("Expected non-nil response from referral server")
	}
	if receivedPath != "/rdap_service/domain/example.com" {
		t.Errorf("Expected URL path '/rdap_service/domain/example.com', got %q", receivedPath)
	}
	if receivedQuery != "apiKey=secret123" {
		t.Errorf("Expected query 'apiKey=secret123' preserved, got %q", receivedQuery)
	}
}

func TestNewRDAPHTTPClient_BlocksInsecureRedirects(t *testing.T) {
	// Insecure RDAP URLs disallowed (default)
	allowInsecureRDAPURLs = false

	client := NewRDAPHTTPClient(2 * time.Second)
	if client.CheckRedirect == nil {
		t.Fatalf("Expected client.CheckRedirect to be defined")
	}

	// 1. Verify CheckRedirect rejects insecure/unsafe redirect target
	targetReq, err := http.NewRequestWithContext(context.Background(), "GET", "http://127.0.0.1:80/secret", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	via := []*http.Request{{}}
	redirectErr := client.CheckRedirect(targetReq, via)
	if redirectErr == nil || !strings.Contains(redirectErr.Error(), "insecure or invalid redirect URL") {
		t.Errorf("Expected insecure redirect error, got: %v", redirectErr)
	}

	// 2. Verify CheckRedirect halts redirect loops (>= 10)
	loopReq, _ := http.NewRequestWithContext(context.Background(), "GET", "https://rdap.example.com/domain/test", nil)
	tenVia := make([]*http.Request, 10)
	loopErr := client.CheckRedirect(loopReq, tenVia)
	if loopErr == nil || !strings.Contains(loopErr.Error(), "stopped after 10 redirects") {
		t.Errorf("Expected stopped after 10 redirects error, got: %v", loopErr)
	}

	// 3. Verify dial-time SSRF prevention blocks connection to restricted IPs
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer testServer.Close()

	req, err := http.NewRequestWithContext(context.Background(), "GET", testServer.URL, nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	_, dialErr := client.Do(req)
	if dialErr == nil || !strings.Contains(dialErr.Error(), "connection to restricted IP blocked (SSRF)") {
		t.Errorf("Expected dial-time SSRF blocked error, got: %v", dialErr)
	}
}

func TestNilSafety_LookupGuards(t *testing.T) {
	// 1. collectRDAPReferralLinks with nil domainInfo
	if links := collectRDAPReferralLinks(nil, "https://example.com"); links != nil {
		t.Errorf("expected nil links from nil domainInfo")
	}

	// 2. extractRDAPDomainTier with nil domainInfo
	if tier := extractRDAPDomainTier(nil, "src", "srv"); tier != nil {
		t.Errorf("expected nil tier from nil domainInfo")
	}

	// 3. validateRDAPState with empty parsed
	if res := validateRDAPState(nil, DomainConfig{}, RDAPState{}); res.Status != "" {
		t.Errorf("expected empty result from empty parsed RDAPState")
	}
}

func TestLookupSentinelsAndHelpers(t *testing.T) {
	t.Parallel()

	// Verify isDomainSuspended canonical function
	isSusp, suspStatus := isDomainSuspended([]string{"serverHold"})
	if !isSusp || suspStatus != "serverHold" {
		t.Errorf("expected isDomainSuspended to report serverHold, got %v, %q", isSusp, suspStatus)
	}

	// Verify resolveRootZoneResolvers canonical function
	ips := resolveRootZoneResolvers(context.Background(), &AppState{}, "invalid-root-test.example", []string{"192.0.2.1"})
	if len(ips) != 0 {
		t.Errorf("expected empty root zone IPs, got %v", ips)
	}

	// Verify ErrWHOISRateLimited sentinel error
	wrapped := WrapError("lookup failed", ErrWHOISRateLimited)
	if !errors.Is(wrapped, ErrWHOISRateLimited) {
		t.Errorf("expected errors.Is(wrapped, ErrWHOISRateLimited) = true")
	}
}

// TestValidateRDAPState_ExpiredDomain verifies the critical expiry bug fix:
// when Expiration is in the past (days < 0), parsed.Status must be StatusFailed
// and MsgAlertRDAPExpired alert must be dispatched via SafeDispatch.
func TestValidateRDAPState_ExpiredDomain(t *testing.T) {
	t.Parallel()

	app := &AppState{
		Notifier: &NotificationManager{TestMode: true},
	}

	// Expiration 10 days in the past
	expired := time.Now().Add(-10 * 24 * time.Hour).UTC().Format(time.RFC3339)
	parsed := RDAPState{
		Status:     StatusOK,
		Expiration: expired,
	}

	target := DomainConfig{
		Domain:         "expired-domain.com",
		Name:           "Expired Domain",
		SuppressAlerts: false,
	}

	result := validateRDAPState(app, target, parsed)

	if result.Status != StatusFailed {
		t.Errorf("expected StatusFailed for expired domain, got %s", result.Status)
	}

	if len(app.Notifier.TestBuffer) == 0 {
		t.Fatal("expected at least one alert dispatched for expired domain, got none")
	}

	found := false
	for _, a := range app.Notifier.TestBuffer {
		if a.Priority == PriorityUrgent && strings.Contains(a.Message, "EXPIRED") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected PriorityUrgent EXPIRED alert, got alerts: %+v", app.Notifier.TestBuffer)
	}
}

// TestValidateRDAPState_ExpiryWarning verifies that expiration within 7 days produces
// StatusWarning and PriorityUrgent, and expiration within 8-30 days produces PriorityWarning
// without setting StatusFailed.
func TestValidateRDAPState_ExpiryWarning(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		daysFromNow  float64
		wantStatus   CheckStatus
		wantPriority AlertPriority
	}{
		{"6 days left - urgent", 6, StatusWarning, PriorityUrgent},
		{"7 days left - urgent boundary", 7, StatusWarning, PriorityUrgent},
		{"15 days left - warning", 15, StatusWarning, PriorityWarning},
		{"30 days left - warning boundary", 30, StatusWarning, PriorityWarning},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			app := &AppState{Notifier: &NotificationManager{TestMode: true}}
			expiry := time.Now().Add(time.Duration(tt.daysFromNow * float64(24*time.Hour))).UTC().Format(time.RFC3339)
			parsed := RDAPState{
				Status:     StatusOK,
				Expiration: expiry,
			}
			target := DomainConfig{Domain: "example.com", Name: "Test", SuppressAlerts: false}

			result := validateRDAPState(app, target, parsed)

			if result.Status != tt.wantStatus {
				t.Errorf("days=%.0f: expected status %s, got %s", tt.daysFromNow, tt.wantStatus, result.Status)
			}

			found := false
			for _, a := range app.Notifier.TestBuffer {
				if a.Priority == tt.wantPriority {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("days=%.0f: expected priority %s alert, got: %+v", tt.daysFromNow, tt.wantPriority, app.Notifier.TestBuffer)
			}
		})
	}
}

// mockAlertCollector is a test helper NotificationProvider that collects alerts via callback.
type mockAlertCollector struct {
	collect func(Alert)
	mu      sync.Mutex
}

func (m *mockAlertCollector) Send(_ context.Context, alert Alert) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.collect(alert)
}

// TestSynthesizeTierData_RegistryIANAIDPreserved validates that registry IANA ID is not
// dropped when the registrar tier provides the registrar name but lacks an IANA ID.
func TestSynthesizeTierData_RegistryIANAIDPreserved(t *testing.T) {
	t.Parallel()

	regTier := &DomainTierData{
		Source:       "registry_rdap",
		Registrar:    "MarkMonitor Inc.",
		IANAID:       "292",
		Expiration:   "2029-01-01T00:00:00Z",
		DomainStatus: []string{"clientTransferProhibited"},
	}

	rarTier := &DomainTierData{
		Source:       "registrar_whois",
		Registrar:    "MarkMonitor International Ltd.",
		IANAID:       "", // registrar text didn't report IANA ID
		Expiration:   "2029-01-01T00:00:00Z",
		DomainStatus: []string{"clientTransferProhibited"},
	}

	state, _ := synthesizeTierData(regTier, rarTier)

	if state.Registrar != "MarkMonitor International Ltd." {
		t.Errorf("Expected Registrar 'MarkMonitor International Ltd.', got %q", state.Registrar)
	}
	if state.RegistrarIANAID != "292" {
		t.Errorf("Expected RegistrarIANAID '292' from registry tier, got %q", state.RegistrarIANAID)
	}
}

func TestEvaluateRDAP(t *testing.T) {
	app := &AppState{
		Notifier: &NotificationManager{TestMode: true},
	}
	target := DomainConfig{
		Domain:     "example.com",
		ExpectedNS: []string{"ns1.example.com"},
	}

	// Fast fail because RDAP needs a bootstrap server
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Create a mock server that returns 404 for RDAP to test the WHOIS fallback
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	// Temporarily override rdapBootstrap
	oldBootstrap := rdapBootstrap
	defer func() { rdapBootstrap = oldBootstrap }()

	rdapBootstrap = &Bootstrap{
		url:  server.URL,
		http: server.Client(),
		services: map[string][]string{
			"com": {server.URL + "/"},
		},
		fetchedAt: time.Now(),
	}

	state := evaluateRDAP(ctx, server.Client(), app, target)
	require.NotNil(t, state)
}

func TestFetchRDAP(t *testing.T) {
	ctx := context.Background()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{ "rdapConformance": [ "rdap_level_0" ], "handle": "123" }`))
	}))
	defer server.Close()

	oldBootstrap := rdapBootstrap
	defer func() { rdapBootstrap = oldBootstrap }()

	rdapBootstrap = &Bootstrap{
		url:  server.URL,
		http: server.Client(),
		services: map[string][]string{
			"com": {server.URL + "/"},
		},
		fetchedAt: time.Now(),
	}

	state, err := fetchRDAP(ctx, server.Client(), "example.com")
	assert.NoError(t, err)
	assert.NotNil(t, state)
}

func TestEvaluateNSDelegation(t *testing.T) {
	app := &AppState{
		Notifier: &NotificationManager{TestMode: true},
	}
	target := DomainConfig{
		Domain:     "example.com",
		ExpectedNS: []string{"ns1.example.com", "ns2.example.com"},
	}

	state := evaluateNSDelegation(context.Background(), app, target)
	require.NotNil(t, state)
}

func TestEvaluateRDAP_MockedPaths(t *testing.T) {
	app := NewAppState(AppConfig{Resolvers: []string{"1.1.1.1"}})
	ctx := context.Background()

	origRDAP := fetchRDAPFn
	defer func() { fetchRDAPFn = origRDAP }()
	origWHOIS := fetchWHOISFn
	defer func() { fetchWHOISFn = origWHOIS }()

	// Test RDAP fallback to WHOIS on rate limit
	fetchRDAPFn = func(ctx context.Context, httpClient HTTPClient, domain string) (RDAPState, error) {
		return RDAPState{}, ErrRDAPRateLimited
	}

	fetchWHOISFn = func(ctx context.Context, app *AppState, domain string) (RDAPState, error) {
		return RDAPState{Status: StatusOK}, nil
	}

	res := evaluateRDAP(ctx, nil, app, DomainConfig{Domain: "example.com"})
	assert.Equal(t, StatusOK, res.Status)

	// Test WHOIS fallback Not Found
	fetchWHOISFn = func(ctx context.Context, app *AppState, domain string) (RDAPState, error) {
		return RDAPState{}, ErrDomainNotFound
	}
	res = evaluateRDAP(ctx, nil, app, DomainConfig{Domain: "example.com"})
	assert.Equal(t, StatusFailed, res.Status)
}

func TestResolveRootZoneResolvers_MockedPaths(t *testing.T) {
	app := NewAppState(AppConfig{Resolvers: []string{"1.1.1.1"}})
	ctx := context.Background()

	orig := queryDNSMsgFn
	defer func() { queryDNSMsgFn = orig }()

	queryDNSMsgFn = func(ctx context.Context, app *AppState, hostname string, qtype uint16, resolvers []string) (*dns.Msg, error) {
		m := new(dns.Msg)
		if qtype == dns.TypeNS {
			m.Answer = append(m.Answer, &dns.NS{Hdr: dns.RR_Header{Name: hostname, Rrtype: dns.TypeNS}, Ns: "ns1.tld."})
			return m, nil
		}
		if qtype == dns.TypeA {
			m.Answer = append(m.Answer, &dns.A{Hdr: dns.RR_Header{Name: "ns1.tld.", Rrtype: dns.TypeA}, A: net.ParseIP("1.2.3.4")})
			return m, nil
		}
		return nil, errors.New("mock error")
	}

	res := resolveRootZoneResolvers(ctx, app, "com", []string{"1.1.1.1"})
	assert.Contains(t, res, "1.2.3.4")
}
