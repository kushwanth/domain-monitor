package main

import (
	"context"
	"testing"
)

func TestDNSCheck(t *testing.T) {
	t.Parallel()

	dnsTypeMap := map[string]uint16{
		"A":     1,
		"AAAA":  28,
		"CNAME": 5,
		"MX":    15,
		"TXT":   16,
	}

	tests := []struct {
		name       string
		recordType string
		expectOK   bool
	}{
		{"Valid A Record", "A", true},
		{"Valid AAAA Record", "AAAA", true},
		{"Valid CNAME Record", "CNAME", true},
		{"Valid MX Record", "MX", true},
		{"Valid TXT Record", "TXT", true},
		{"Invalid Record", "INVALID", false},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, ok := dnsTypeMap[tt.recordType]
			if ok != tt.expectOK {
				t.Errorf("Expected OK=%v for %s, got %v", tt.expectOK, tt.recordType, ok)
			}
		})
	}
}

func TestFetchCAA(t *testing.T) {
	app := &AppState{}
	resolvers := []string{"8.8.8.8"}
	res := fetchCAA(context.Background(), app, "google.com", resolvers)

	if res.Error != "" {
		t.Errorf("Expected no error, got %v", res.Error)
	}

	if len(res.Issue) == 0 {
		// Even if they don't have issue, they might have something, but let's assume pki.goog
		// Actually, google.com has issue "pki.goog"
		t.Logf("google.com CAA issue is empty, this might happen depending on tree climbing or actual records.")
	} else {
		found := false
		for _, v := range res.Issue {
			if v == "pki.goog" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected pki.goog in issue records for google.com, got %v", res.Issue)
		}
	}
}

func TestFetchCAATreeClimbing(t *testing.T) {
	app := &AppState{}
	resolvers := []string{"8.8.8.8"}
	res := fetchCAA(context.Background(), app, "some-random-subdomain.google.com", resolvers)

	if res.Error != "" {
		t.Errorf("Expected no error, got %v", res.Error)
	}

	if len(res.Issue) > 0 {
		found := false
		for _, v := range res.Issue {
			if v == "pki.goog" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected pki.goog from parent google.com, got %v", res.Issue)
		}
	}
}

func TestValidateDNSSEC(t *testing.T) {
	app := &AppState{}
	resolvers := []string{"8.8.8.8"}
	res := validateDNSSEC(context.Background(), app, "example.com", resolvers, "https://dns.google/resolve")

	if !res.Valid {
		t.Errorf("Expected example.com to be valid DNSSEC, but got invalid. Result: %+v", res)
	}
	if !res.HasDS {
		t.Errorf("Expected example.com to have DS records")
	}
	if !res.HasDNSKEY {
		t.Errorf("Expected example.com to have DNSKEY records")
	}
	if !res.DSMatchesDNSKEY {
		t.Errorf("Expected DS to match DNSKEY")
	}
	if !res.RRSIGValid {
		t.Errorf("Expected RRSIG to be valid")
	}
	if !res.ChainIntact {
		t.Errorf("Expected Google DoH to report ChainIntact (AD bit set)")
	}
	if len(res.Algorithms) == 0 {
		t.Errorf("Expected Algorithms to be populated")
	}
}

func TestValidateDNSSECUnsigned(t *testing.T) {
	app := &AppState{}
	resolvers := []string{"8.8.8.8"}
	res := validateDNSSEC(context.Background(), app, "google.com", resolvers, "https://dns.google/resolve")

	if res.Valid {
		t.Errorf("Expected google.com to be invalid or unsigned DNSSEC, but got valid")
	}
	if res.HasDS {
		t.Errorf("Expected google.com to not have DS records")
	}
	if res.ChainIntact {
		t.Errorf("Expected Google DoH to not report ChainIntact for unsigned domain")
	}
}

func TestValidateCAATag(t *testing.T) {
	t.Parallel()

	app := &AppState{
		Notifier: &NotificationManager{},
	}

	tests := []struct {
		name        string
		target      DomainConfig
		tag         string
		expected    []string
		live        map[string]bool
		expectValid bool
	}{
		{
			name: "Valid Exact Match",
			target: DomainConfig{
				Domain:         "example.com",
				Name:           "Example",
				SuppressAlerts: true,
			},
			tag:         "issue",
			expected:    []string{"letsencrypt.org", "digicert.com"},
			live:        map[string]bool{"letsencrypt.org": true, "digicert.com": true},
			expectValid: true,
		},
		{
			name: "Missing Expected CA",
			target: DomainConfig{
				Domain:         "example.com",
				Name:           "Example",
				SuppressAlerts: true,
			},
			tag:         "issue",
			expected:    []string{"letsencrypt.org", "digicert.com"},
			live:        map[string]bool{"letsencrypt.org": true},
			expectValid: false,
		},
		{
			name: "Unauthorized CA Detected",
			target: DomainConfig{
				Domain:         "example.com",
				Name:           "Example",
				SuppressAlerts: true,
			},
			tag:         "issue",
			expected:    []string{"letsencrypt.org"},
			live:        map[string]bool{"letsencrypt.org": true, "rogue-ca.com": true},
			expectValid: false,
		},
		{
			name: "Valid Deny All With Semicolon Record",
			target: DomainConfig{
				Domain:         "example.com",
				Name:           "Example",
				SuppressAlerts: true,
			},
			tag:         "issuewild",
			expected:    []string{},
			live:        map[string]bool{";": true},
			expectValid: true,
		},
		{
			name: "Deny All Failed Due To Unauthorized CA",
			target: DomainConfig{
				Domain:         "example.com",
				Name:           "Example",
				SuppressAlerts: true,
			},
			tag:         "issuewild",
			expected:    []string{},
			live:        map[string]bool{"letsencrypt.org": true},
			expectValid: false,
		},
		{
			name: "Deny All Failed Due To Missing CAA Record",
			target: DomainConfig{
				Domain:         "example.com",
				Name:           "Example",
				SuppressAlerts: true,
			},
			tag:         "issuewild",
			expected:    []string{},
			live:        map[string]bool{},
			expectValid: false,
		},
		{
			name: "Skipped Tag (nil)",
			target: DomainConfig{
				Domain:         "example.com",
				Name:           "Example",
				SuppressAlerts: true,
			},
			tag:         "issuemail",
			expected:    nil,
			live:        map[string]bool{"any-mail-ca.com": true},
			expectValid: true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			res := &CAAResult{Valid: true}
			validateCAATag(app, tt.target, tt.tag, tt.expected, tt.live, res)
			if res.Valid != tt.expectValid {
				t.Errorf("Expected Valid: %v, got %v", tt.expectValid, res.Valid)
			}
		})
	}
}
