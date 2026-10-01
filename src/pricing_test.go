package main

import (
	"context"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func TestPricingRequiresInjectedHTTPClient(t *testing.T) {
	pm := NewPricingManager(nil)
	_, err := pm.fetch(context.Background())
	if err == nil || !strings.Contains(err.Error(), "HTTP client is not configured") {
		t.Fatalf("Expected HTTP client error, got %v", err)
	}
}

func TestPricingManager_Fetch(t *testing.T) {
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

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requestCount.Add(1)
		w.Header().Set(HeaderContentType, "application/json")
		out, _ := jsonv2.Marshal(mockResponse)
		_, _ = w.Write(out)
	}))
	defer server.Close()

	pm := NewPricingManager(server.Client())
	pm.url = server.URL

	ctx := context.Background()

	catalog, err := pm.fetch(ctx)
	if err != nil {
		t.Fatalf("fetch() returned unexpected error: %v", err)
	}

	if price, ok := catalog.price("com"); !ok || price != 11.08 {
		t.Errorf("Expected com price 11.08, got %v", price)
	}
	if price, ok := catalog.price("regonly"); ok {
		t.Errorf("Expected regonly to be missing, got %v", price)
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

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(HeaderContentType, "application/json")
		out, _ := jsonv2.Marshal(mockResponse)
		_, _ = w.Write(out)
	}))
	defer server.Close()

	pm := NewPricingManager(server.Client())
	pm.url = server.URL

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
		RDAP: map[string]RDAPState{
			"standard.com": {Status: StatusOK},
			"premium.com":  {Status: StatusOK},
			"expiring.com": {Status: StatusOK},
		},
	}

	computePortfolioPricingForTest(context.Background(), app, loopState, pm)

	if state := loopState.RDAP["standard.com"]; state.Status == StatusUnknown || state.RenewalPrice != 11.08 {
		t.Errorf("Expected standard.com renewal price 11.08, got %+v", state)
	}

	if state := loopState.RDAP["premium.com"]; state.Status == StatusUnknown || state.RenewalPrice != 299.99 {
		t.Errorf("Expected premium.com renewal price 299.99, got %+v", state)
	}

	if state := loopState.RDAP["expiring.com"]; state.Status == StatusUnknown || state.RenewalPrice != 11.08 {
		t.Errorf("Expected nonexpired allowed domain renewal price 11.08, got %+v", state)
	}
}

func TestLoadConfig_NegativeRenewalPrice(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.json")
	configJSON := `{"notifications":{"ntfy":{"url":"https://ntfy.invalid/topic"}},
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

func TestPricingRejectsOversizedValidPrefix(t *testing.T) {
	body := `{"tlds":[{"tld":"com","renewal":10}]}` + strings.Repeat(" ", MaxPricingResponseSize)
	manager := NewPricingManager(&MockHTTPClient{MockDo: func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body))}, nil
	}})
	_, err := manager.fetch(context.Background())
	if err == nil {
		t.Fatalf("Expected error for oversized response, got nil")
	}
}

func TestPricingStaleFallbackAndSnapshotIsolation(t *testing.T) {
	fail := false
	manager := NewPricingManager(&MockHTTPClient{MockDo: func(*http.Request) (*http.Response, error) {
		if fail {
			return &http.Response{StatusCode: http.StatusServiceUnavailable, Status: "503 Service Unavailable", Body: io.NopCloser(strings.NewReader(""))}, nil
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"tlds":[{"tld":"com","renewal":12}]}`))}, nil
	}})
	catalog, err := manager.cachedCatalog(context.Background())
	require.NoError(t, err)
	original := catalog
	fail = true
	manager.catalog = &pricingCatalog{prices: catalog.prices, fetchedAt: time.Now().Add(-2 * PricingCacheTTL)}
	catalog, err = manager.cachedCatalog(context.Background())
	require.NoError(t, err)
	price, ok := catalog.price("com")
	require.True(t, ok)
	assert.Equal(t, float64(12), price)
	assert.NotSame(t, original, catalog)
	assert.Equal(t, float64(12), original.prices["com"])
	manager.catalog = &pricingCatalog{prices: catalog.prices, fetchedAt: time.Now().Add(-PricingMaxStaleAge - time.Hour)}
	catalog, err = manager.cachedCatalog(context.Background())
	require.Error(t, err)
	assert.Nil(t, catalog)
}

func TestPricingCatalogRefreshKeepsExistingReadersStable(t *testing.T) {
	var requests atomic.Int32
	manager := NewPricingManager(&MockHTTPClient{MockDo: func(*http.Request) (*http.Response, error) {
		price := 12
		if requests.Add(1) > 1 {
			price = 24
		}
		body := fmt.Sprintf(`{"tlds":[{"tld":"com","renewal":%d}]}`, price)
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body))}, nil
	}})
	original, err := manager.cachedCatalog(context.Background())
	require.NoError(t, err)
	manager.catalog = &pricingCatalog{prices: original.prices, fetchedAt: time.Now().Add(-2 * PricingCacheTTL)}
	var readers sync.WaitGroup
	for range 8 {
		readers.Go(func() {
			for range 1000 {
				price, ok := original.price("com")
				if !ok || price != 12 {
					t.Error("refresh mutated an existing catalog")
				}
			}
		})
	}
	updated, err := manager.cachedCatalog(context.Background())
	readers.Wait()
	require.NoError(t, err)
	price, ok := updated.price("com")
	require.True(t, ok)
	assert.Equal(t, float64(24), price)
	assert.Equal(t, int32(2), requests.Load())
	cached, err := manager.cachedCatalog(context.Background())
	require.NoError(t, err)
	assert.Same(t, updated, cached)
	assert.Equal(t, int32(2), requests.Load())
}

func BenchmarkPricingCatalogRead(b *testing.B) {
	prices := make(map[string]float64, 2000)
	for i := range 2000 {
		prices[fmt.Sprintf("tld%d", i)] = 12
	}
	manager := &PricingManager{catalog: &pricingCatalog{prices: prices, fetchedAt: time.Now()}}
	b.Run("copied_catalog", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			manager.mu.Lock()
			copyPrices := maps.Clone(manager.catalog.prices)
			manager.mu.Unlock()
			if copyPrices["tld0"] != 12 {
				b.Fatal("missing price")
			}
		}
	})
	b.Run("immutable_catalog", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			catalog, err := manager.cachedCatalog(context.Background())
			if err != nil {
				b.Fatal(err)
			}
			if price, ok := catalog.price("tld0"); !ok || price != 12 {
				b.Fatal("missing price")
			}
		}
	})
}

func TestPricingFetchFailuresDoNotPublishCatalog(t *testing.T) {
	for _, failure := range []string{"invalid URL", "transport", "read", "invalid JSON", "empty catalog", "unusable prices"} {
		t.Run(failure, func(t *testing.T) {
			pm := NewPricingManager(&MockHTTPClient{MockDo: func(*http.Request) (*http.Response, error) {
				if failure == "transport" {
					return nil, errors.New("offline")
				}
				body := `{"tlds":[]}`
				if failure == "invalid JSON" {
					body = "invalid"
				}
				if failure == "unusable prices" {
					body = `{"tlds":[{"tld":" ","renewal":12},{"tld":"com","renewal":0},{"tld":"org","renewal":-1}]}`
				}
				var reader io.Reader = strings.NewReader(body)
				if failure == "read" {
					reader = failingProviderReader{}
				}
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(reader)}, nil
			}})
			if failure == "invalid URL" {
				pm.url = "://invalid"
			}
			catalog, err := pm.cachedCatalog(context.Background())
			require.Error(t, err)
			assert.Nil(t, catalog)
			assert.Nil(t, pm.catalog)
		})
	}
}

func TestPortfolioPricingUnavailableKeepsManualPrice(t *testing.T) {
	app := NewAppState(AppConfig{Domains: []DomainConfig{{Domain: "manual.com", RenewalPrice: 42}, {Domain: "automatic.com"}}})
	for _, pm := range []*PricingManager{nil, NewPricingManager(nil)} {
		state := newTestCheckState()
		state.RDAP["manual.com"] = RDAPState{Status: StatusOK}
		state.RDAP["automatic.com"] = RDAPState{Status: StatusOK}
		computePortfolioPricingForTest(context.Background(), app, state, pm)
		assert.Equal(t, float64(42), state.RDAP["manual.com"].RenewalPrice)
		assert.Zero(t, state.RDAP["automatic.com"].RenewalPrice)
	}
	computePortfolioPricingForTest(context.Background(), nil, newTestCheckState(), nil)
	computePortfolioPricingForTest(context.Background(), app, nil, nil)
}
