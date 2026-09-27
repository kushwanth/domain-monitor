package main

import (
	"context"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"io"
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
	if p == nil {
		return nil, ErrPricingManagerNil
	}
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
	if p == nil {
		return nil, ErrPricingManagerNil
	}
	client := ResolveHTTPClient(p.http)
	if client == nil {
		return nil, errors.New(MsgErrPricingHTTPClientNotConfigured)
	}
	// #nosec G704 -- p.url is the fixed DotSweep endpoint or a test-injected URL.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.url, nil)
	if err != nil {
		return nil, WrapError(MsgErrDotSweepFetchFailed, err)
	}
	req.Header.Set(HeaderUserAgent, DefaultUserAgent)

	resp, err := client.Do(req)
	if err != nil {
		return nil, WrapError(MsgErrDotSweepFetchFailed, err)
	}
	defer DrainAndClose(resp.Body, MaxBodyDrainSize)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf(MsgErr2, MsgErrDotSweepFetchFailed, resp.Status)
	}

	var pResp DotSweepResponse
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxPricingResponseSize+1))
	if err != nil {
		return nil, fmt.Errorf(MsgErrReadPricingResponse, err)
	}
	if len(body) > MaxPricingResponseSize {
		return nil, fmt.Errorf(MsgErrPricingResponseExceedsBytes, MaxPricingResponseSize)
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

// computePortfolioPricing updates RDAP state renewal prices from manual config or the DotSweep TLD catalog.
func computePortfolioPricing(ctx context.Context, app *AppState, loopState *CheckState, pm *PricingManager) {
	if app == nil || loopState == nil {
		return
	}

	cfg := app.configuration()

	var needsTLDPricing bool
	for _, domainCfg := range cfg.Domains {
		state, eligible := eligibleForRenewalPrice(domainCfg, loopState.RDAP)
		if !eligible {
			continue
		}
		if domainCfg.RenewalPrice > 0 {
			state.RenewalPrice = domainCfg.RenewalPrice
			loopState.RDAP[domainCfg.Domain] = state
		} else {
			needsTLDPricing = true
		}
	}

	if !needsTLDPricing {
		return
	}

	if pm == nil {
		return
	}

	catalog, err := pm.cachedCatalog(ctx)
	if err != nil {
		LogWarn(MsgLogPricingFetchFailed, FieldError, err)
		return
	}

	for _, domainCfg := range cfg.Domains {
		if domainCfg.RenewalPrice > 0 {
			continue
		}
		state, eligible := eligibleForRenewalPrice(domainCfg, loopState.RDAP)
		if !eligible {
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
