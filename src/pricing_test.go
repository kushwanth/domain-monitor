package main

import (
	"context"
	jsonv2 "encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestExtractTLD(t *testing.T) {
	t.Parallel()

	tests := []struct {
		domain   string
		expected string
	}{
		{"example.com", "com"},
		{"sub.domain.example.com", "com"},
		{"bbc.co.uk", "co.uk"},
		{"news.bbc.co.uk", "co.uk"},
		{"google.com.au", "com.au"},
		{"test.org", "org"},
		{"my-app.io", "io"},
		{"standalone", "standalone"},
		{"example.COM.", "com"},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.domain, func(t *testing.T) {
			t.Parallel()
			got := extractTLD(tc.domain)
			if got != tc.expected {
				t.Errorf("extractTLD(%q) = %q; want %q", tc.domain, got, tc.expected)
			}
		})
	}
}

func TestPricingManager_FetchAndAntiDDoS(t *testing.T) {
	t.Parallel()

	var requestCount atomic.Int32
	mockResponse := DotSweepResponse{
		TLDs: []DotSweepTLD{
			{TLD: "com", Registration: 10.50, Renewal: 11.08},
			{TLD: "org", Registration: 12.00, Renewal: 14.50},
			{TLD: "co.uk", Registration: 6.99, Renewal: 7.99},
			{TLD: "regonly", Registration: 5.00},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		w.Header().Set(HeaderContentType, "application/json")
		out, _ := jsonv2.Marshal(mockResponse)
		_, _ = w.Write(out)
	}))
	defer server.Close()

	pm := NewPricingManager(server.Client())
	pm.url = server.URL

	ctx := context.Background()

	// 1. First ensure call should trigger HTTP fetch
	if err := pm.ensure(ctx); err != nil {
		t.Fatalf("ensure() returned unexpected error: %v", err)
	}
	if count := requestCount.Load(); count != 1 {
		t.Fatalf("Expected 1 HTTP request, got %d", count)
	}

	// Verify loaded prices
	if price, ok := pm.GetPrice("com"); !ok || price != 11.08 {
		t.Errorf("Expected com price 11.08, got %v (ok=%v)", price, ok)
	}
	if price, ok := pm.GetPrice("org"); !ok || price != 14.50 {
		t.Errorf("Expected org price 14.50, got %v (ok=%v)", price, ok)
	}
	if price, ok := pm.GetPrice("co.uk"); !ok || price != 7.99 {
		t.Errorf("Expected co.uk price 7.99, got %v (ok=%v)", price, ok)
	}
	// Fallback to registration if renewal is 0
	if price, ok := pm.GetPrice("regonly"); !ok || price != 5.00 {
		t.Errorf("Expected regonly price 5.00, got %v (ok=%v)", price, ok)
	}

	// 2. Immediate subsequent ensure calls should hit in-memory cache (anti-DDoS protection)
	for i := 0; i < 5; i++ {
		if err := pm.ensure(ctx); err != nil {
			t.Fatalf("subsequent ensure() failed: %v", err)
		}
	}
	if count := requestCount.Load(); count != 1 {
		t.Errorf("DDoS guard failed: expected requestCount to remain 1, got %d", count)
	}
}

func TestPricingManager_StaleCacheFallback(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "upstream service unavailable", http.StatusServiceUnavailable)
	}))
	defer server.Close()

	pm := NewPricingManager(server.Client())
	pm.url = server.URL

	// Pre-populate stale cache (e.g. 2 days old)
	pm.prices = map[string]float64{"com": 11.08}
	pm.fetchedAt = time.Now().Add(-48 * time.Hour)

	ctx := context.Background()
	// Should fall back to existing cache and not return a fatal error
	if err := pm.ensure(ctx); err != nil {
		t.Fatalf("Expected graceful stale cache fallback, got error: %v", err)
	}

	if price, ok := pm.GetPrice("com"); !ok || price != 11.08 {
		t.Errorf("Expected cached price 11.08 to remain available, got %v (ok=%v)", price, ok)
	}
}

func TestComputePortfolioPricing(t *testing.T) {
	t.Parallel()

	mockResponse := DotSweepResponse{
		TLDs: []DotSweepTLD{
			{TLD: "com", Renewal: 11.08},
			{TLD: "net", Renewal: 13.50},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(HeaderContentType, "application/json")
		out, _ := jsonv2.Marshal(mockResponse)
		_, _ = w.Write(out)
	}))
	defer server.Close()

	pm := NewPricingManager(server.Client())
	pm.url = server.URL

	// Temporarily override defaultPricingManager for the test
	origManager := defaultPricingManager
	defaultPricingManager = pm
	defer func() { defaultPricingManager = origManager }()

	app := &AppState{
		config: AppConfig{
			Domains: []DomainConfig{
				{
					Domain:       "standard.com",
					Name:         "Standard Domain",
					RenewalPrice: 0,
				},
				{
					Domain:       "premium.com",
					Name:         "Premium Domain",
					RenewalPrice: 299.99,
				},
				{
					Domain:       "expiring.com",
					Name:         "Expiring Domain",
					AllowExpiry:  true,
					RenewalPrice: 0,
				},
			},
		},
	}

	loopState := &CheckState{
		RDAP: map[string]*RDAPState{
			"standard.com": {},
			"premium.com":  {},
			"expiring.com": {},
		},
	}

	computePortfolioPricing(context.Background(), app, loopState, pm)

	// Verify standard domain got DotSweep pricing
	if state := loopState.RDAP["standard.com"]; state == nil || state.RenewalPrice != 11.08 {
		t.Errorf("Expected standard.com renewal price 11.08, got %+v", state)
	}

	// Verify premium domain used explicit renewal_price override
	if state := loopState.RDAP["premium.com"]; state == nil || state.RenewalPrice != 299.99 {
		t.Errorf("Expected premium.com renewal price 299.99, got %+v", state)
	}

	// Verify expiring domain has no renewal price assigned
	if state := loopState.RDAP["expiring.com"]; state == nil || state.RenewalPrice != 0 {
		t.Errorf("Expected expiring.com renewal price to be 0, got %+v", state)
	}
}

func TestLoadConfig_NegativeRenewalPrice(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.json")
	configJSON := `{
		"domains": [
			{
				"domain": "invalid.com",
				"name": "Invalid Negative Price",
				"renewal_price": -10.0
			}
		]
	}`
	if err := os.WriteFile(cfgPath, []byte(configJSON), 0644); err != nil {
		t.Fatalf("failed to write test config: %v", err)
	}

	_, err := LoadConfig(context.Background(), cfgPath)
	if err == nil {
		t.Fatalf("Expected validation error for negative renewal_price, got nil")
	}
	if !strings.Contains(err.Error(), "renewal_price cannot be negative") {
		t.Errorf("Expected error to mention renewal_price cannot be negative, got: %v", err)
	}
}

func BenchmarkExtractTLD(b *testing.B) {
	domains := []string{
		"example.com",
		"sub.domain.example.com",
		"bbc.co.uk",
		"google.com.au",
		"standalone",
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = extractTLD(domains[i%len(domains)])
	}
}

func BenchmarkGetPrice(b *testing.B) {
	pm := &PricingManager{
		prices: map[string]float64{
			"com":    11.08,
			"org":    14.50,
			"co.uk":  7.99,
			"net":    13.50,
			"io":     35.00,
			"com.au": 7.88,
		},
		fetchedAt: time.Now(),
	}
	tlds := []string{"com", "org", "co.uk", "net", "io", "unknown"}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = pm.GetPrice(tlds[i%len(tlds)])
	}
}

func BenchmarkComputePortfolioPricing(b *testing.B) {
	pm := &PricingManager{
		prices: map[string]float64{
			"com":   11.08,
			"net":   13.50,
			"org":   14.50,
			"co.uk": 7.99,
		},
		fetchedAt: time.Now(),
	}
	origManager := defaultPricingManager
	defaultPricingManager = pm
	defer func() { defaultPricingManager = origManager }()

	app := &AppState{
		config: AppConfig{
			Domains: []DomainConfig{
				{Domain: "domain1.com", Name: "D1"},
				{Domain: "domain2.net", Name: "D2", RenewalPrice: 199.99},
				{Domain: "domain3.org", Name: "D3"},
				{Domain: "domain4.co.uk", Name: "D4", AllowExpiry: true},
				{Domain: "domain5.com", Name: "D5"},
			},
		},
	}

	loopState := &CheckState{
		RDAP: map[string]*RDAPState{
			"domain1.com":   {},
			"domain2.net":   {},
			"domain3.org":   {},
			"domain4.co.uk": {},
			"domain5.com":   {},
		},
	}

	ctx := context.Background()
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		computePortfolioPricing(ctx, app, loopState, pm)
	}
}
