// Package main implements domain and DNS monitoring services.
package main

import (
	"context"
	"crypto/tls"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"strings"
	"syscall"
	"time"
)

// RDAPTLSConfig returns a TLS configuration compatible with both modern and legacy ccTLD
// RDAP registries (such as older RSA-CBC cipher suites). Modern AEAD ciphers are prioritized first.
func RDAPTLSConfig() *tls.Config {
	var ids []uint16
	// 1. Add all secure modern cipher suites first (AES-GCM, ChaCha20-Poly1305, etc.)
	for _, cipherSuite := range tls.CipherSuites() {
		ids = append(ids, cipherSuite.ID)
	}
	// 2. Append legacy fallback cipher suites for older ccTLD registries
	legacySuites := []uint16{
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_RSA_WITH_AES_256_CBC_SHA,
	}
	ids = append(ids, legacySuites...)

	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		CipherSuites: ids,
	}
}

// NewRDAPHTTPClient creates an HTTP client configured with legacy-compatible TLS and strict timeouts.
func NewRDAPHTTPClient(timeout time.Duration) *http.Client {
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   timeout,
			KeepAlive: 30 * time.Second,
			Control: func(network, address string, c syscall.RawConn) error {
				if allowInsecureRDAPURLs {
					return nil
				}
				host, _, err := net.SplitHostPort(address)
				if err != nil {
					host = address
				}
				if ip := net.ParseIP(host); ip != nil {
					if IsRestrictedIP(ip) {
						return fmt.Errorf("connection to restricted IP blocked (SSRF): %s", host)
					}
				}
				return nil
			},
		}).DialContext,
		TLSClientConfig:       RDAPTLSConfig(),
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
		ExpectContinueTimeout: 1 * time.Second,
	}
	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("stopped after 10 redirects")
			}
			if !isSafeRDAPURL(req.URL.String()) {
				return fmt.Errorf("insecure or invalid redirect URL: %s", req.URL.String())
			}
			return nil
		},
	}
}

// KnownWhoisServer returns a dedicated WHOIS server for a given domain suffix if known.
func KnownWhoisServer(domain string) string {
	asciiDomain := NormalizeDomainToASCIIText(domain)
	labels := strings.Split(asciiDomain, ".")
	for i := range labels {
		suffix := strings.Join(labels[i:], ".")
		if server, ok := CCTLDWhoisServers[suffix]; ok {
			return server
		}
	}
	return ""
}

func NewBootstrap(httpClient *http.Client) *Bootstrap {
	return &Bootstrap{http: httpClient, url: BootstrapURL}
}

func (b *Bootstrap) ServersFor(ctx context.Context, domain string) ([]string, error) {
	if b == nil {
		return nil, errors.New("bootstrap client is nil")
	}
	if err := b.ensure(ctx); err != nil {
		return nil, err
	}

	b.mu.RLock()
	defer b.mu.RUnlock()

	asciiDomain := NormalizeDomainToASCIIText(domain)
	labels := strings.Split(asciiDomain, ".")
	for i := range labels {
		suffix := strings.Join(labels[i:], ".")
		if urls, ok := b.services[suffix]; ok && len(urls) > 0 {
			return slices.Clone(urls), nil
		}
	}
	return nil, fmt.Errorf("no rdap server found for domain %s", domain)
}

func (b *Bootstrap) isFresh() bool {
	if b == nil {
		return false
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.services) > 0 && time.Since(b.fetchedAt) < BootstrapTTL
}

func (b *Bootstrap) ensure(ctx context.Context) error {
	if b == nil {
		return errors.New("bootstrap client is nil")
	}
	if b.isFresh() {
		return nil
	}

	b.fetchMu.Lock()
	defer b.fetchMu.Unlock()

	if b.isFresh() {
		return nil
	}

	if err := b.fetch(ctx); err != nil {
		b.mu.RLock()
		hasData := len(b.services) > 0
		cacheAge := time.Since(b.fetchedAt)
		b.mu.RUnlock()

		if hasData && cacheAge <= BootstrapMaxAge {
			LogWarn("Failed to refresh RDAP bootstrap from IANA; falling back to cached registry", "error", err, "cache_age", cacheAge.Round(time.Minute))
			return nil
		}
		return fmt.Errorf("bootstrap registry unavailable: %w", err)
	}
	return nil
}

func (b *Bootstrap) fetch(ctx context.Context) error {
	if b == nil {
		return errors.New("bootstrap client is nil")
	}
	client := ResolveHTTPClient(b.http)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, b.url, nil)
	if err != nil {
		return fmt.Errorf("bootstrap request error: %w", err)
	}
	req.Header.Set("User-Agent", DefaultUserAgent)

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("bootstrap fetch error: %w", err)
	}
	defer DrainAndClose(resp.Body, 4096)

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bootstrap status %d", resp.StatusCode)
	}

	var registry dnsRegistry
	if err := jsonv2.UnmarshalRead(io.LimitReader(resp.Body, MaxBootstrapResponseSize), &registry); err != nil {
		return fmt.Errorf("bootstrap decode error: %w", err)
	}

	services := make(map[string][]string)
	for _, serviceEntry := range registry.Services {
		if len(serviceEntry) < 2 {
			continue
		}
		var validURLs []string
		for _, rawURL := range DeduplicateNonEmptyStrings(serviceEntry[1]) {
			if strings.HasPrefix(rawURL, "https://") || strings.HasPrefix(rawURL, "http://") {
				validURLs = append(validURLs, rawURL)
			}
		}
		if len(validURLs) > 0 {
			for _, tld := range serviceEntry[0] {
				cleanTLD := NormalizeDomain(tld)
				if cleanTLD != "" {
					services[cleanTLD] = validURLs
				}
			}
		}
	}

	if len(services) == 0 {
		return fmt.Errorf("empty bootstrap registry")
	}

	for tld, urls := range StealthSeeds {
		cleanTLD := NormalizeDomain(tld)
		if _, ok := services[cleanTLD]; !ok {
			services[cleanTLD] = urls
		}
	}

	b.mu.Lock()
	b.services = services
	b.fetchedAt = time.Now()
	b.mu.Unlock()
	return nil
}
