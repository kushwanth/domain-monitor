package main

import (
	"net"
	"testing"
)

func TestCloudflareCIDRLoading(t *testing.T) {
	cf := &CFClient{}
	
	// Manually populate CIDRs for testing IsCloudflareIP logic
	_, ipnet1, _ := net.ParseCIDR("192.0.2.0/24")
	_, ipnet2, _ := net.ParseCIDR("2001:db8::/32")
	cf.CIDRs = []*net.IPNet{ipnet1, ipnet2}

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
