package main

import (
	"strings"
	"testing"
)

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
