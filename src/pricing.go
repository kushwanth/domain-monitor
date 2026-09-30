package main

import (
	"context"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"
)

// NewPricingManager initializes a PricingManager targeting DotSweep with the provided HTTP client.
func NewPricingManager(httpClient HTTPDoer) *PricingManager {
	return &PricingManager{
		http: ResolveHTTPClient(httpClient),
		url:  DotSweepAPIEndpoint,
	}
}

// normalizeTLD strips whitespace, lowercases, and removes a leading dot from a TLD string.
func normalizeTLD(tld string) string {
	return strings.TrimPrefix(strings.ToLower(strings.TrimSpace(tld)), SymDot)
}

func (p *PricingManager) cachedCatalog(ctx context.Context) (*pricingCatalog, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.catalog != nil && time.Since(p.catalog.fetchedAt) < PricingCacheTTL {
		return p.catalog, nil
	}
	catalog, err := p.fetch(ctx)
	if err != nil {
		if p.catalog != nil && time.Since(p.catalog.fetchedAt) <= PricingMaxStaleAge {
			LogWarn(MsgLogPricingFetchFailed, FieldError, err)
			return p.catalog, nil
		}
		return nil, err
	}
	p.catalog = catalog
	return p.catalog, nil
}

func (p *PricingManager) fetch(ctx context.Context) (*pricingCatalog, error) {
	client := ResolveHTTPClient(p.http)
	if client == nil {
		return nil, errors.New(MsgErrPricingHTTPClientNotConfigured)
	}
	resp, err := doHTTPWithRetry(ctx, NameOpPricingCatalog, client, true, func() (*http.Request, error) {
		// #nosec G704 -- p.url is the fixed DotSweep endpoint or a test-injected URL.
		req, requestErr := http.NewRequestWithContext(ctx, http.MethodGet, p.url, nil)
		if requestErr != nil {
			return nil, WrapError(MsgErrDotSweepFetchFailed, requestErr)
		}
		req.Header.Set(HeaderUserAgent, DefaultUserAgent)
		return req, nil
	})
	if err != nil {
		return nil, WrapError(MsgErrDotSweepFetchFailed, err)
	}
	defer DrainAndClose(resp.Body, MaxBodyDrainSize)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf(MsgErr2, MsgErrDotSweepFetchFailed, resp.Status)
	}

	var pResp DotSweepResponse
	body, err := readBounded(resp.Body, MaxPricingResponseSize)
	if errors.Is(err, ErrReadLimitExceeded) {
		return nil, fmt.Errorf(MsgErrPricingResponseExceedsBytes, MaxPricingResponseSize)
	}
	if err != nil {
		return nil, fmt.Errorf(MsgErrReadPricingResponse, err)
	}
	if err := jsonv2.Unmarshal(body, &pResp); err != nil {
		return nil, WrapError(MsgErrDotSweepParseError, err)
	}

	if len(pResp.TLDs) == 0 {
		return nil, errors.New(MsgErrDotSweepNoData)
	}

	newPrices := make(map[string]float64, len(pResp.TLDs))
	for _, item := range pResp.TLDs {
		tldClean := normalizeTLD(item.TLD)
		if tldClean == StrEmpty {
			continue
		}
		if item.Renewal > 0 {
			newPrices[tldClean] = item.Renewal
		}
	}

	if len(newPrices) == 0 {
		return nil, errors.New(MsgErrDotSweepNoData)
	}

	return &pricingCatalog{prices: newPrices, fetchedAt: time.Now()}, nil
}

// extractTLD resolves the public suffix/TLD of a domain name using the public suffix list.
func extractTLD(domain string) string {
	domain = NormalizeDomain(domain)
	ps, _ := publicsuffix.PublicSuffix(domain)
	if ps != StrEmpty {
		return ps
	}
	idx := strings.LastIndexByte(domain, '.')
	if idx != -1 && idx < len(domain)-1 {
		return domain[idx+1:]
	}
	return domain
}

func needsPricingCatalog(cfg AppConfig) bool {
	for _, domainCfg := range cfg.Domains {
		if !domainCfg.Unused && !domainCfg.IsDelegatedZone && domainCfg.RenewalPrice <= 0 {
			return true
		}
	}
	return false
}

func applyPortfolioPricing(cfg AppConfig, loopState *CheckState, catalog *pricingCatalog) {
	for _, domainCfg := range cfg.Domains {
		state, eligible := eligibleForRenewalPrice(domainCfg, loopState.RDAP)
		if !eligible {
			continue
		}
		if domainCfg.RenewalPrice > 0 {
			state.RenewalPrice = domainCfg.RenewalPrice
			loopState.RDAP[domainCfg.Domain] = state
			continue
		}
		if catalog == nil {
			continue
		}
		tld := extractTLD(domainCfg.Domain)
		if price, ok := catalog.price(tld); ok && price > 0 {
			state.RenewalPrice = price
			loopState.RDAP[domainCfg.Domain] = state
		}
	}
}

func eligibleForRenewalPrice(domainCfg DomainConfig, states map[string]RDAPState) (RDAPState, bool) {
	if domainCfg.Unused || domainCfg.IsDelegatedZone {
		return RDAPState{}, false
	}
	state, exists := states[domainCfg.Domain]
	return state, exists && state.Status != StatusUnknown
}
