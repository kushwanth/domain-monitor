// Package main implements domain and DNS monitoring services.
package main

import (
	"context"
	"crypto/tls"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
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
			KeepAlive: DefaultTCPKeepAlive,
			Control: func(_, address string, _ syscall.RawConn) error {
				host, _, err := net.SplitHostPort(address)
				if err != nil {
					host = address
				}
				if strings.Contains(host, SymPercent) {
					return WrapError(host, ErrRestrictedIP)
				}
				if ip := net.ParseIP(host); ip != nil {
					if IsRestrictedIP(ip) {
						return WrapError(host, ErrRestrictedIP)
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
			if len(via) >= MaxRedirects {
				return errors.New(MsgErrStoppedAfterRedirects)
			}
			if !IsSafeRDAPURL(req.URL.String()) {
				return fmt.Errorf(MsgErrInsecureRedirectURL, req.URL.String())
			}
			return nil
		},
	}
}

// KnownWHOISServer returns a dedicated WHOIS server for a given domain suffix if known.
func KnownWHOISServer(domain string) string {
	suffix := NormalizeDomainToASCIIText(domain)
	for {
		if server, ok := CCTLDWHOISServers[suffix]; ok {
			return server
		}
		idx := strings.IndexByte(suffix, '.')
		if idx == -1 {
			break
		}
		suffix = suffix[idx+1:]
	}
	return StrEmpty
}

// NewBootstrap creates a bootstrap cache using the injected HTTP client.
func NewBootstrap(httpClient HTTPDoer) *Bootstrap {
	return &Bootstrap{http: ResolveHTTPClient(httpClient), url: BootstrapURL}
}

// ServersFor returns an independent server list for the longest matching domain suffix.
func (b *Bootstrap) ServersFor(ctx context.Context, domain string) ([]string, error) {
	if err := b.ensure(ctx); err != nil {
		return nil, err
	}

	b.mu.RLock()
	defer b.mu.RUnlock()

	suffix := NormalizeDomainToASCIIText(domain)
	for {
		if urls, ok := b.services[suffix]; ok && len(urls) > 0 {
			return slices.Clone(urls), nil
		}
		idx := strings.IndexByte(suffix, '.')
		if idx == -1 {
			break
		}
		suffix = suffix[idx+1:]
	}
	return nil, fmt.Errorf(MsgErrNoRDAPServerForDomain, domain)
}

func (b *Bootstrap) isFresh() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.services) > 0 && time.Since(b.fetchedAt) < BootstrapTTL
}

func (b *Bootstrap) ensure(ctx context.Context) error {
	if b.isFresh() {
		return nil
	}

	b.fetchMu.Lock()
	defer b.fetchMu.Unlock()

	if b.isFresh() {
		return nil
	}

	if err := b.fetch(ctx); err != nil {
		hasData, cacheAge := b.cachedRegistryAge()

		if hasData && cacheAge <= BootstrapMaxAge {
			LogWarn(MsgLogRDAPRefreshFailed, StrError, err, StrCacheAge, cacheAge.Round(time.Minute))
			return nil
		}
		return WrapError(MsgErrBootstrapRegistryUnavailable, err)
	}
	return nil
}

func (b *Bootstrap) cachedRegistryAge() (bool, time.Duration) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.services) > 0, time.Since(b.fetchedAt)
}

func (b *Bootstrap) fetch(ctx context.Context) error {
	client := ResolveHTTPClient(b.http)
	if client == nil {
		return fmt.Errorf(MsgErrFetchRDAPBootstrapRegistry, ErrBootstrapClientNil)
	}
	resp, err := doHTTPWithRetry(ctx, NameOpRDAPBootstrap, client, true, func() (*http.Request, error) {
		// #nosec G704 -- bootstrap URL is a configured endpoint; callers control its HTTP transport.
		req, requestErr := http.NewRequestWithContext(ctx, http.MethodGet, b.url, nil)
		if requestErr != nil {
			return nil, WrapError(MsgErrBootstrapRequestError, requestErr)
		}
		req.Header.Set(HeaderUserAgent, DefaultUserAgent)
		return req, nil
	})
	if err != nil {
		return WrapError(MsgErrBootstrapFetchError, err)
	}
	defer DrainAndClose(resp.Body, MaxBodyDrainSize)

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf(MsgErrBootstrapStatus, resp.StatusCode)
	}

	var registry dnsRegistry
	body, err := readBounded(resp.Body, MaxBootstrapResponseSize)
	if errors.Is(err, ErrReadLimitExceeded) {
		return fmt.Errorf(MsgErrRDAPBootstrapResponseExceedsBytes, MaxBootstrapResponseSize)
	}
	if err != nil {
		return fmt.Errorf(MsgErrReadRDAPBootstrapResponse, err)
	}
	if err := jsonv2.Unmarshal(body, &registry); err != nil {
		return WrapError(MsgErrBootstrapDecodeError, err)
	}

	services := bootstrapServices(registry)
	if len(services) == 0 {
		return ErrEmptyBootstrapRegistry
	}

	for tld, urls := range StealthSeeds {
		cleanTLD := NormalizeDomain(tld)
		if _, ok := services[cleanTLD]; !ok {
			services[cleanTLD] = slices.Clone(urls)
		}
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	b.services = services
	b.fetchedAt = time.Now()
	return nil
}

func bootstrapServices(registry dnsRegistry) map[string][]string {
	services := make(map[string][]string)
	for _, serviceEntry := range registry.Services {
		if len(serviceEntry) < 2 {
			continue
		}
		var validURLs []string
		for _, rawURL := range DeduplicateNonEmptyStrings(serviceEntry[1]) {
			if strings.HasPrefix(rawURL, PrefixHTTPS) || strings.HasPrefix(rawURL, PrefixHTTP) {
				validURLs = append(validURLs, rawURL)
			}
		}
		if len(validURLs) > 0 {
			for _, tld := range serviceEntry[0] {
				cleanTLD := NormalizeDomain(tld)
				if cleanTLD != StrEmpty {
					services[cleanTLD] = validURLs
				}
			}
		}
	}

	return services
}
