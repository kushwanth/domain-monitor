package main

import (
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
