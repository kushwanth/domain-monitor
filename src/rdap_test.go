package main

import (
	"strings"
	"testing"
)

func TestRDAPValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		targetNS    []string
		liveNS      []string
		expectUnauth bool
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
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			isLocked := false
			isSuspended := false

			for _, s := range tt.statuses {
				status := strings.ReplaceAll(strings.ToLower(s), " ", "")
				if status == "serverhold" || status == "clienthold" || status == "pendingdelete" {
					isSuspended = true
				}
				if strings.Contains(status, "transferprohibited") {
					isLocked = true
				}
			}

			if isLocked != tt.expectLock {
				t.Errorf("Expected Lock: %v, got %v", tt.expectLock, isLocked)
			}
			if isSuspended != tt.expectSusp {
				t.Errorf("Expected Suspended: %v, got %v", tt.expectSusp, isSuspended)
			}
		})
	}
}
