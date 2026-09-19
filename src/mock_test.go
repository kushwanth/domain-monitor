package main

import (
	"context"
	"net/http"
	"time"

	"github.com/miekg/dns"
)

// MockHTTPClient implements HTTPClient for tests.
type MockHTTPClient struct {
	MockDo func(req *http.Request) (*http.Response, error)
}

func (m *MockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	if m.MockDo != nil {
		return m.MockDo(req)
	}
	return nil, nil
}

// MockDNSResolver implements DNSResolver for tests.
type MockDNSResolver struct {
	MockExchangeContext func(ctx context.Context, m *dns.Msg, a string) (*dns.Msg, time.Duration, error)
}

func (m *MockDNSResolver) ExchangeContext(ctx context.Context, msg *dns.Msg, a string) (*dns.Msg, time.Duration, error) {
	if m.MockExchangeContext != nil {
		return m.MockExchangeContext(ctx, msg, a)
	}
	return nil, 0, nil
}

// MockWHOISClient implements WHOISClient for tests.
type MockWHOISClient struct {
	MockQuery func(ctx context.Context, domain, server string) (string, error)
}

func (m *MockWHOISClient) Query(ctx context.Context, domain, server string) (string, error) {
	if m.MockQuery != nil {
		return m.MockQuery(ctx, domain, server)
	}
	return "", nil
}
