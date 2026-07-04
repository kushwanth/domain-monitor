package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCloudflareCIDRLoading(t *testing.T) {
	// Create a mock HTTP server that returns fake Cloudflare IPs
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("192.0.2.0/24\n2001:db8::/32\n"))
	}))
	defer mockServer.Close()

	cf := &CFClient{}

	// Temporarily override the hardcoded URLs in a real scenario you'd pass these as arguments,
	// but for this test, we validate the parsing logic manually mimicking the LoadCIDRs function.
	resp, err := http.Get(mockServer.URL)
	if err != nil {
		t.Fatalf("Failed to reach mock server: %v", err)
	}
	defer resp.Body.Close()

	// Mimic the internal parsing logic of LoadCIDRs
	cf.CIDRs = cf.LoadCIDRsFromReader(resp.Body)

	if len(cf.CIDRs) != 2 {
		t.Fatalf("Expected 2 CIDR blocks, got %d", len(cf.CIDRs))
	}

	tests := []struct {
		name     string
		ip       string
		expected bool
	}{
		{"Valid IPv4 in CIDR", "192.0.2.100", true},
		{"Invalid IPv4 outside CIDR", "203.0.113.5", false},
		{"Valid IPv6 in CIDR", "2001:db8::1", true},
		{"Invalid IPv6 outside CIDR", "2001:db9::1", false},
		{"Malformed IP", "not-an-ip", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := cf.IsCloudflareIP(tt.ip)
			if result != tt.expected {
				t.Errorf("IsCloudflareIP(%q) = %v; want %v", tt.ip, result, tt.expected)
			}
		})
	}
}
