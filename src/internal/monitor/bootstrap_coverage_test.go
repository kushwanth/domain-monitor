package monitor

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestOutboundClientRedirectPolicies(t *testing.T) {
	same := httptest.NewRequest(http.MethodGet, "https://rdap.example/domain/example.com", nil)
	private := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/domain/example.com", nil)
	other := httptest.NewRequest(http.MethodGet, "https://other.example/domain/example.com", nil)
	many := make([]*http.Request, MaxRedirects)
	for index := range many {
		many[index] = same
	}

	rdap := NewRDAPHTTPClient(time.Second)
	require.NoError(t, rdap.CheckRedirect(same, []*http.Request{same}))
	require.Error(t, rdap.CheckRedirect(private, []*http.Request{same}))
	require.Error(t, rdap.CheckRedirect(same, many))

	public := NewPublicHTTPClient(time.Second)
	require.NoError(t, public.CheckRedirect(same, []*http.Request{same}))
	require.Error(t, public.CheckRedirect(private, []*http.Request{same}))
	require.Error(t, public.CheckRedirect(same, many))

	notifications := NewNotificationHTTPClient(time.Second)
	require.NoError(t, notifications.CheckRedirect(same, []*http.Request{same}))
	require.Error(t, notifications.CheckRedirect(other, []*http.Request{same}))
	require.Error(t, notifications.CheckRedirect(same, many))
}

func TestPublicDestinationPolicyRejectsLocalAndMalformedTargets(t *testing.T) {
	for _, raw := range []string{
		"https://user:secret@example.com/", "ftp://example.com/", "https://localhost/",
		"https://service.local/", "https://service.internal/", "https://127.0.0.1/",
		"https://[fe80::1%25eth0]/", "https:///missing-host",
	} {
		u, err := url.Parse(raw)
		require.NoError(t, err)
		require.False(t, isSafePublicURL(u), raw)
	}
	require.False(t, isSafePublicURL(nil))
	for _, raw := range []string{"https://example.com/", "http://93.184.216.34/"} {
		u, err := url.Parse(raw)
		require.NoError(t, err)
		require.True(t, isSafePublicURL(u), raw)
	}
}

func TestRestrictedDialerChecksActualDialAddress(t *testing.T) {
	control := restrictedPublicDialer(time.Second).Control
	for _, address := range []string{"127.0.0.1:43", "[fe80::1%eth0]:43", "10.0.0.1"} {
		require.ErrorIs(t, control("tcp", address, nil), ErrRestrictedIP, address)
	}
	require.NoError(t, control("tcp", "93.184.216.34:43", nil))
}

func TestBootstrapFetchRejectsMalformedAndUnreadableResponses(t *testing.T) {
	for _, tc := range []struct {
		name   string
		url    string
		status int
		body   io.Reader
	}{
		{name: "invalid URL", url: "://bad"},
		{name: "unexpected status", status: http.StatusNotFound},
		{name: "read error", status: http.StatusOK, body: failingProviderReader{}},
		{name: "invalid JSON", status: http.StatusOK, body: strings.NewReader(`{"services":`)},
		{name: "malformed services", status: http.StatusOK, body: strings.NewReader(`{"services":[[]]}`)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			bootstrap := NewBootstrap(&MockHTTPClient{MockDo: func(*http.Request) (*http.Response, error) {
				calls++
				body := tc.body
				if body == nil {
					body = strings.NewReader("")
				}
				return &http.Response{StatusCode: tc.status, Body: io.NopCloser(body)}, nil
			}})
			if tc.url != "" {
				bootstrap.url = tc.url
			}
			err := bootstrap.fetch(context.Background())
			require.Error(t, err)
			if tc.name == "invalid URL" {
				require.Zero(t, calls)
			} else {
				require.Equal(t, 1, calls)
			}
			require.Empty(t, bootstrap.services)
		})
	}
}

func TestBootstrapRejectsNilResponse(t *testing.T) {
	bootstrap := NewBootstrap(&MockHTTPClient{MockDo: func(*http.Request) (*http.Response, error) {
		return nil, errors.New("offline")
	}})
	require.ErrorContains(t, bootstrap.fetch(context.Background()), "offline")
}

func TestBootstrapConcurrentRefreshKeepsAcceptablyStaleRegistry(t *testing.T) {
	bootstrap := &Bootstrap{services: map[string][]string{"com": {"https://rdap.example/"}}, fetchedAt: time.Now().Add(-2 * BootstrapTTL)}
	bootstrap.fetchMu.Lock()
	err := bootstrap.ensure(context.Background())
	bootstrap.fetchMu.Unlock()
	require.NoError(t, err)
	require.Equal(t, []string{"https://rdap.example/"}, bootstrap.services["com"])
}

func TestCloneTransportFallsBackForCustomRoundTripper(t *testing.T) {
	custom := roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, errors.New("unused") })
	require.NotNil(t, cloneTransport(custom))
	require.NotNil(t, cloneTransport(nil))
}
