package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/idna"
)

// RDAPTLSConfig returns a TLS configuration compatible with both modern and legacy ccTLD
// RDAP registries (such as older RSA-CBC cipher suites).
func RDAPTLSConfig() *tls.Config {
	ids := []uint16{
		tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	}
	for _, cs := range tls.CipherSuites() {
		ids = append(ids, cs.ID)
	}
	return &tls.Config{
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
		}).DialContext,
		TLSClientConfig:       RDAPTLSConfig(),
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
		ExpectContinueTimeout: 1 * time.Second,
	}
	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}
}

// GetKnownWhoisServer returns a dedicated WHOIS server for a given domain suffix if known.
func GetKnownWhoisServer(domain string) string {
	asciiDomain, err := idna.ToASCII(strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), ".")))
	if err != nil {
		asciiDomain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	}
	labels := strings.Split(asciiDomain, ".")
	for i := range labels {
		suffix := strings.Join(labels[i:], ".")
		if server, ok := CCTLDWhoisServers[suffix]; ok {
			return server
		}
	}
	return ""
}

type Bootstrap struct {
	http *http.Client
	url  string

	mu        sync.RWMutex
	services  map[string][]string
	fetchedAt time.Time
}

func NewBootstrap(httpClient *http.Client) *Bootstrap {
	return &Bootstrap{http: httpClient, url: BootstrapURL}
}

type dnsRegistry struct {
	Services [][][]string `json:"services"`
}

func (b *Bootstrap) ServersFor(ctx context.Context, domain string) ([]string, error) {
	if err := b.ensure(ctx); err != nil {
		return nil, err
	}

	b.mu.RLock()
	defer b.mu.RUnlock()

	asciiDomain, err := idna.ToASCII(strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), ".")))
	if err != nil {
		asciiDomain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	}

	labels := strings.Split(asciiDomain, ".")
	for i := range labels {
		suffix := strings.Join(labels[i:], ".")
		if urls, ok := b.services[suffix]; ok && len(urls) > 0 {
			return urls, nil
		}
	}
	return nil, fmt.Errorf("no rdap server found for domain %s", domain)
}

func (b *Bootstrap) ensure(ctx context.Context) error {
	b.mu.RLock()
	fresh := b.services != nil && time.Since(b.fetchedAt) < BootstrapTTL
	b.mu.RUnlock()
	if fresh {
		return nil
	}
	return b.fetch(ctx)
}

func (b *Bootstrap) fetch(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, b.url, nil)
	if err != nil {
		return fmt.Errorf("bootstrap request error: %w", err)
	}
	req.Header.Set("User-Agent", "DomainMonitor/1.0 (+https://github.com/domain-monitor)")

	resp, err := b.http.Do(req)
	if err != nil {
		return fmt.Errorf("bootstrap fetch error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bootstrap status %d", resp.StatusCode)
	}

	var reg dnsRegistry
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&reg); err != nil {
		return fmt.Errorf("bootstrap decode error: %w", err)
	}

	services := make(map[string][]string)
	for _, svc := range reg.Services {
		if len(svc) < 2 {
			continue
		}
		for _, tld := range svc[0] {
			services[strings.ToLower(tld)] = svc[1]
		}
	}

	if len(services) == 0 {
		return fmt.Errorf("empty bootstrap registry")
	}

	for tld, urls := range StealthSeeds {
		if _, ok := services[tld]; !ok {
			services[tld] = urls
		}
	}

	b.mu.Lock()
	b.services = services
	b.fetchedAt = time.Now()
	b.mu.Unlock()
	return nil
}
