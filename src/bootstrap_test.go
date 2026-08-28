package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestRDAPTLSConfig(t *testing.T) {
	t.Parallel()

	tlsCfg := RDAPTLSConfig()
	if tlsCfg == nil {
		t.Fatalf("RDAPTLSConfig returned nil")
	}

	if tlsCfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("Expected MinVersion to be TLS 1.2 (0x%x), got 0x%x", tls.VersionTLS12, tlsCfg.MinVersion)
	}

	if len(tlsCfg.CipherSuites) == 0 {
		t.Fatalf("Expected CipherSuites to be populated")
	}

	// Verify modern ciphers come before legacy CBC ciphers
	modernCount := len(tls.CipherSuites())
	if len(tlsCfg.CipherSuites) <= modernCount {
		t.Errorf("Expected legacy cipher suites to be appended after modern suites")
	}

	// Verify the first suite is a modern suite, not weak RSA-CBC
	if tlsCfg.CipherSuites[0] == tls.TLS_RSA_WITH_AES_128_CBC_SHA || tlsCfg.CipherSuites[0] == tls.TLS_RSA_WITH_AES_256_CBC_SHA {
		t.Errorf("Weak RSA-CBC cipher suite found at top priority in CipherSuites")
	}
}

func TestNewRDAPHTTPClient(t *testing.T) {
	t.Parallel()

	timeout := 8 * time.Second
	client := NewRDAPHTTPClient(timeout)
	if client == nil {
		t.Fatalf("NewRDAPHTTPClient returned nil")
	}
	if client.Timeout != timeout {
		t.Errorf("Expected client timeout %v, got %v", timeout, client.Timeout)
	}

	transport, ok := client.Transport.(*http.Transport)
	if !ok || transport == nil {
		t.Fatalf("Expected *http.Transport, got %T", client.Transport)
	}
	if transport.TLSClientConfig == nil || transport.TLSClientConfig.MinVersion != tls.VersionTLS12 {
		t.Errorf("Expected TLSClientConfig with MinVersion TLS 1.2 on transport")
	}
}

func TestGetKnownWhoisServer(t *testing.T) {
	t.Parallel()

	tests := []struct {
		domain   string
		expected string
	}{
		{"example.de", "whois.denic.de"},
		{"example.com.au", "whois.auda.org.au"},
		{"example.co.uk", "whois.nominet.uk"},
		{"example.ru", "whois.tcinet.ru"},
		{"example.com", ""}, // Generic TLD not in CCTLDWhoisServers
	}

	for _, tt := range tests {
		server := GetKnownWhoisServer(tt.domain)
		if server != tt.expected {
			t.Errorf("GetKnownWhoisServer(%q) = %q, expected %q", tt.domain, server, tt.expected)
		}
	}
}

func TestBootstrapFetchAndResolution(t *testing.T) {
	ianaData := dnsRegistry{
		Services: [][][]string{
			{
				{"com", "net"},
				{"https://rdap.verisign.com/com/v1/"},
			},
			{
				{"org"},
				{"https://rdap.publicinterestregistry.org/rdap/"},
			},
			{
				{"co.uk", "org.uk"},
				{"https://rdap.nominet.uk/"},
			},
			{
				{"xn--p1ai"}, // .рф
				{"https://rdap.tcinet.ru/"},
			},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ianaData)
	}))
	defer server.Close()

	b := NewBootstrap(server.Client())
	b.url = server.URL

	ctx := context.Background()

	// 1. Standard gTLD resolution
	comServers, err := b.ServersFor(ctx, "example.com")
	if err != nil || len(comServers) == 0 || comServers[0] != "https://rdap.verisign.com/com/v1/" {
		t.Errorf("Expected com server URL, got %v (err: %v)", comServers, err)
	}

	// 2. Multi-level SLD resolution (.co.uk)
	ukServers, err := b.ServersFor(ctx, "test.co.uk")
	if err != nil || len(ukServers) == 0 || ukServers[0] != "https://rdap.nominet.uk/" {
		t.Errorf("Expected co.uk server URL, got %v (err: %v)", ukServers, err)
	}

	// 3. IDN Punycode resolution (.рф)
	idnServers, err := b.ServersFor(ctx, "россия.рф")
	if err != nil || len(idnServers) == 0 || idnServers[0] != "https://rdap.tcinet.ru/" {
		t.Errorf("Expected .рф server URL, got %v (err: %v)", idnServers, err)
	}

	// 4. StealthSeeds fallback for TLDs not in IANA registry (e.g. .io, .ai)
	ioServers, err := b.ServersFor(ctx, "project.io")
	if err != nil || len(ioServers) == 0 {
		t.Errorf("Expected StealthSeeds fallback for .io, got %v (err: %v)", ioServers, err)
	}

	// 5. Unknown non-existent TLD
	_, err = b.ServersFor(ctx, "test.invalidrandomtld98765")
	if err == nil {
		t.Errorf("Expected error for non-existent TLD, got nil")
	}
}

func TestBootstrapCacheExpiryAndFallback(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "simulated 500 internal error", http.StatusInternalServerError)
	}))
	defer server.Close()

	b := NewBootstrap(server.Client())
	b.url = server.URL

	// 1. Pre-populate cache with timestamp 30 hours ago (expired TTL, but within 72h max age)
	b.services = map[string][]string{
		"com": {"https://rdap.verisign.com/com/v1/"},
	}
	b.fetchedAt = time.Now().Add(-30 * time.Hour)

	// ensure() should encounter server error, but successfully fall back to cached services
	err := b.ensure(context.Background())
	if err != nil {
		t.Fatalf("Expected graceful fallback to cache within 72h, got error: %v", err)
	}

	servers, err := b.ServersFor(context.Background(), "example.com")
	if err != nil || len(servers) == 0 || servers[0] != "https://rdap.verisign.com/com/v1/" {
		t.Errorf("Expected cached server URL, got %v (err: %v)", servers, err)
	}

	// 2. Set timestamp to 80 hours ago (beyond 72h max age)
	b.fetchedAt = time.Now().Add(-80 * time.Hour)
	err = b.ensure(context.Background())
	if err == nil {
		t.Errorf("Expected error when cache is older than 72h and IANA is down, got nil")
	}
}

func TestBootstrapConcurrentColdStart(t *testing.T) {
	var requestCount int
	var countMu sync.Mutex

	ianaData := dnsRegistry{
		Services: [][][]string{
			{
				{"com"},
				{"https://rdap.verisign.com/com/v1/"},
			},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		countMu.Lock()
		requestCount++
		countMu.Unlock()
		time.Sleep(20 * time.Millisecond) // Artificial latency
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ianaData)
	}))
	defer server.Close()

	b := NewBootstrap(server.Client())
	b.url = server.URL

	var wg sync.WaitGroup
	workers := 10
	errChan := make(chan error, workers)

	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := b.ServersFor(context.Background(), "example.com")
			if err != nil {
				errChan <- err
			}
		}()
	}

	wg.Wait()
	close(errChan)

	for err := range errChan {
		t.Errorf("Unexpected error in concurrent ServersFor: %v", err)
	}

	countMu.Lock()
	totalReqs := requestCount
	countMu.Unlock()

	if totalReqs != 1 {
		t.Errorf("Expected exactly 1 HTTP request due to singleflight double-checked fetch, got %d", totalReqs)
	}
}

