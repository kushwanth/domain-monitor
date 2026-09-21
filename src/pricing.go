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

var (
	defaultPricingManager = NewPricingManager(&http.Client{Timeout: DefaultPricingHTTPTimeout})
)

// NewPricingManager initializes a PricingManager targeting DotSweep with the provided HTTP client.
func NewPricingManager(httpClient HTTPDoer) *PricingManager {
	return &PricingManager{
		http:   ResolveHTTPClient(httpClient),
		url:    DotSweepAPIEndpoint,
		prices: make(map[string]float64),
	}
}

func (p *PricingManager) isFresh() bool {
	if p == nil {
		return false
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.prices) > 0 && time.Since(p.fetchedAt) < PricingCacheTTL
}

func (p *PricingManager) ensure(ctx context.Context) error {
	if p == nil {
		return ErrPricingManagerNil
	}
	if p.isFresh() {
		return nil
	}

	p.fetchMu.Lock()
	defer p.fetchMu.Unlock()

	if p.isFresh() {
		return nil
	}

	if err := p.fetch(ctx); err != nil {
		p.mu.RLock()
		hasData := len(p.prices) > 0
		cacheAge := time.Since(p.fetchedAt)
		p.mu.RUnlock()

		if hasData && cacheAge <= PricingMaxStaleAge {
			LogWarn(MsgLogDotSweepFetchFailed, FieldError, err, FieldCacheAge, cacheAge.Round(time.Minute))
			return nil
		}
		return err
	}
	return nil
}

// normalizeTLD strips whitespace, lowercases, and removes a leading dot from a TLD string.
func normalizeTLD(tld string) string {
	return strings.TrimPrefix(strings.ToLower(strings.TrimSpace(tld)), ".")
}

func (p *PricingManager) fetch(ctx context.Context) error {
	if p == nil {
		return ErrPricingManagerNil
	}
	client := ResolveHTTPClient(p.http)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.url, nil)
	if err != nil {
		return WrapError(MsgErrDotSweepFetchFailed, err)
	}
	req.Header.Set(HeaderUserAgent, DefaultUserAgent)

	resp, err := client.Do(req)
	if err != nil {
		return WrapError(MsgErrDotSweepFetchFailed, err)
	}
	defer DrainAndClose(resp.Body, MaxBodyDrainSize)

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: %s", MsgErrDotSweepFetchFailed, resp.Status)
	}

	var pResp DotSweepResponse
	if err := jsonv2.UnmarshalRead(io.LimitReader(resp.Body, MaxPricingResponseSize), &pResp); err != nil {
		return WrapError(MsgErrDotSweepParseError, err)
	}

	if len(pResp.TLDs) == 0 {
		return errors.New(MsgErrDotSweepNoData)
	}

	newPrices := make(map[string]float64, len(pResp.TLDs))
	for _, item := range pResp.TLDs {
		tldClean := normalizeTLD(item.TLD)
		if tldClean == "" {
			continue
		}
		if item.Renewal > 0 {
			newPrices[tldClean] = item.Renewal
		} else if item.Registration > 0 {
			newPrices[tldClean] = item.Registration
		}
	}

	p.mu.Lock()
	p.prices = newPrices
	p.fetchedAt = time.Now()
	p.mu.Unlock()

	return nil
}

// GetPrice retrieves the cached renewal price for a normalized TLD.
func (p *PricingManager) GetPrice(tld string) (float64, bool) {
	if p == nil {
		return 0, false
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	price, ok := p.prices[normalizeTLD(tld)]
	return price, ok
}

// extractTLD resolves the public suffix/TLD of a domain name using the public suffix list.
func extractTLD(domain string) string {
	domain = NormalizeDomain(domain)
	ps, _ := publicsuffix.PublicSuffix(domain)
	if ps != "" {
		return ps
	}
	parts := strings.Split(domain, ".")
	if len(parts) > 1 {
		return parts[len(parts)-1]
	}
	return domain
}

// computePortfolioPricing updates RDAP state renewal prices from manual config or the DotSweep TLD catalog.
func computePortfolioPricing(ctx context.Context, app *AppState, loopState *CheckState, pm *PricingManager) {
	if app == nil || loopState == nil {
		return
	}

	cfg := app.Config()

	var needsTLDPricing bool
	for _, domainCfg := range cfg.Domains {
		if domainCfg.AllowExpiry {
			continue
		}
		state, exists := loopState.RDAP[domainCfg.Domain]
		if !exists || state.Status == "" {
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
		pm = defaultPricingManager
	}

	if err := pm.ensure(ctx); err != nil {
		LogWarn(MsgLogPricingFetchFailed, FieldError, err)
		return
	}

	for _, domainCfg := range cfg.Domains {
		if domainCfg.AllowExpiry || domainCfg.RenewalPrice > 0 {
			continue
		}
		state, exists := loopState.RDAP[domainCfg.Domain]
		if !exists || state.Status == "" {
			continue
		}
		tld := extractTLD(domainCfg.Domain)
		if price, ok := pm.GetPrice(tld); ok && price > 0 {
			state.RenewalPrice = price
			loopState.RDAP[domainCfg.Domain] = state
		}
	}
}
