package monitor

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	whoisparser "github.com/likexian/whois-parser"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
	"golang.org/x/time/rate"
)

func TestWHOISDiscoveryRejectsMissingTopLevelAndReferral(t *testing.T) {
	app := &AppState{WHOISDial: func(context.Context, string) (net.Conn, error) {
		t.Fatal("single-label domain must not be queried")
		return nil, nil
	}}
	_, err := discoverWHOISServer(context.Background(), app, "singlelabel")
	require.ErrorContains(t, err, "top-level")

	app.WHOISDial = func(_ context.Context, host string) (net.Conn, error) {
		require.Equal(t, WHOISIANAHost, host)
		client, server := net.Pipe()
		go func() {
			defer func() { _ = server.Close() }()
			_, _ = bufio.NewReader(server).ReadString('\n')
			_, _ = server.Write([]byte("domain: com\nstatus: active"))
		}()
		return client, nil
	}
	_, err = discoverWHOISServer(context.Background(), app, "example.com")
	require.ErrorContains(t, err, "no referral")
}

func TestWHOISExtractionUsesFallbackFieldsAndDetachesLargeResponse(t *testing.T) {
	require.Equal(t, "2030-04-05T00:00:00Z", normalizedWHOISDate("2030-04-05"))
	require.Equal(t, "unknown", normalizedWHOISDate("unknown"))
	raw := strings.Join([]string{
		"Expiry Date: 2030-04-05", "Created on: 2020-04-05", "Last Modified: 2025-04-05",
		"Registrar Name: Example Registrar", "Registrar IANA ID: 42",
		"Name Server: NS1.EXAMPLE.COM", "Name Server: NS2.EXAMPLE.COM",
		"Domain Status: clientTransferProhibited", "DNSSEC: signed",
	}, "\n") + strings.Repeat(" ", 65<<10)
	tier := extractWHOISTier(raw, SourceRegistryWHOIS, "whois.example")
	require.Equal(t, "2030-04-05T00:00:00Z", tier.Expiration)
	require.Equal(t, "2020-04-05T00:00:00Z", tier.Created)
	require.Equal(t, "2025-04-05T00:00:00Z", tier.Updated)
	require.Equal(t, "Example Registrar", tier.Registrar)
	require.Equal(t, "42", tier.IANAID)
	require.Equal(t, []string{"ns1.example.com", "ns2.example.com"}, tier.Nameservers)
	require.True(t, tier.DNSSEC)
	require.NotEmpty(t, tier.DomainStatus)

	bad := extractWHOISTier("Expiry Date: unknown\nCreated on: unknown\nLast Modified: unknown\nRegistrar Name: n/a\nName Server: invalid.example\nDNSSEC: no", SourceRegistryWHOIS, "whois.example")
	require.Equal(t, "unknown", bad.Expiration)
	require.Empty(t, bad.Created)
	require.Empty(t, bad.Updated)
	require.False(t, bad.DNSSEC)
}

func TestWHOISParserUnconvertedDatesRemainAvailable(t *testing.T) {
	for _, input := range []string{"2030-04-05", "unknown"} {
		tier := extractWHOISTierWithParser("", SourceRegistryWHOIS, "whois.example", func(string) (whoisparser.WhoisInfo, error) {
			return whoisparser.WhoisInfo{Domain: &whoisparser.Domain{ExpirationDate: input, CreatedDate: input, UpdatedDate: input}}, nil
		})
		require.Equal(t, normalizedWHOISDate(input), tier.Expiration)
		require.Equal(t, normalizedWHOISDate(input), tier.Created)
		require.Equal(t, normalizedWHOISDate(input), tier.Updated)
	}
}

func TestRDAPEvaluationRecognizesTransientFailureAndSuspensionCodes(t *testing.T) {
	target := DomainConfig{Domain: "example.com"}
	status, condition := EvaluateRDAP(target, RDAPSnapshot{Err: errors.New("connection refused")})
	require.Equal(t, StatusWarning, status)
	require.Equal(t, CodeRDAPHTTPError, condition.Code)
	for _, tc := range []struct {
		status string
		code   ResultCode
	}{
		{"clientHold", CodeEPPClientHold}, {"pendingDelete", CodeEPPPendingDelete},
		{"redemptionPeriod", CodeEPPRedemptionPeriod}, {"inactive", CodeEPPInactive},
	} {
		status, condition = EvaluateRDAP(target, RDAPSnapshot{Expiration: "2099-01-01T00:00:00Z", DomainStatus: []string{tc.status}})
		require.Equal(t, StatusFailed, status, tc.status)
		require.Equal(t, tc.code, condition.Code, tc.status)
	}
}

func TestRegistrarRDAPReferralRejectsInvalidTargetsAndResponses(t *testing.T) {
	require.Empty(t, registrarRDAPURL(" ", "example.com"))
	require.Equal(t, "https://rdap.example/domain/example.com", registrarRDAPURL("https://rdap.example", "example.com"))
	require.Nil(t, followRegistrarRDAPLinks(context.Background(), "example.com", []string{" ", "https://unsafe.example"}, http.DefaultClient, func(string) bool { return false }, nil))
	response, err := readRegistrarRDAPResponse(nil)
	require.Nil(t, response)
	require.ErrorIs(t, err, ErrEmptyHTTPResponse)
}

func TestRDAPResponseReaderReportsTransportAndFormatErrors(t *testing.T) {
	response, err := readRDAPDomainResponse(nil)
	require.Nil(t, response)
	require.ErrorIs(t, err, ErrEmptyHTTPResponse)
	for _, tc := range []struct {
		status int
		body   io.Reader
		want   string
	}{
		{http.StatusTooManyRequests, strings.NewReader(""), ErrRDAPRateLimited.Error()},
		{http.StatusForbidden, strings.NewReader(""), "403"},
		{http.StatusOK, failingProviderReader{}, "read RDAP"},
		{http.StatusOK, strings.NewReader("{"), "parse RDAP"},
	} {
		_, err := readRDAPDomainResponse(&http.Response{StatusCode: tc.status, Body: io.NopCloser(tc.body)})
		require.ErrorContains(t, err, tc.want)
	}
	for _, tc := range []struct {
		body io.Reader
		want string
	}{
		{failingProviderReader{}, "read registrar"},
		{strings.NewReader("{"), "parse registrar"},
	} {
		_, err := readRegistrarRDAPResponse(&http.Response{Body: io.NopCloser(tc.body)})
		require.ErrorContains(t, err, tc.want)
	}
}

func TestRDAPFetchRejectsMissingClientAndMalformedRequest(t *testing.T) {
	bootstrap := &Bootstrap{services: map[string][]string{"com": {"https://rdap.example/"}}, fetchedAt: time.Now()}
	app := &AppState{Bootstrap: bootstrap, RDAPURLAllowed: func(string) bool { return true }}
	_, err := fetchRDAP(context.Background(), nil, app, "example.com")
	require.ErrorContains(t, err, "HTTP client")
	bootstrap.services["com"] = []string{"https://rdap.example/\n"}
	_, err = fetchRDAP(context.Background(), &MockHTTPClient{MockDo: func(*http.Request) (*http.Response, error) {
		t.Fatal("malformed request must not be sent")
		return nil, nil
	}}, app, "example.com")
	require.Error(t, err)
}

func TestRDAPFetchHandlesLimiterTransportAndHTTPFailures(t *testing.T) {
	makeApp := func() *AppState {
		return &AppState{Bootstrap: &Bootstrap{services: map[string][]string{"com": {"https://rdap.example/"}}, fetchedAt: time.Now()}, RDAPURLAllowed: func(string) bool { return true }}
	}
	t.Run("limiter canceled", func(t *testing.T) {
		app := makeApp()
		limiter := rate.NewLimiter(rate.Every(time.Hour), 1)
		require.True(t, limiter.Allow())
		app.RDAPLimiter = limiter
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := fetchRDAP(ctx, &MockHTTPClient{MockDo: func(*http.Request) (*http.Response, error) { t.Fatal("limiter must stop request"); return nil, nil }}, app, "example.com")
		require.Error(t, err)
	})
	for _, tc := range []struct {
		name         string
		status       int
		body         string
		transportErr error
	}{
		{"transport with response", http.StatusOK, "", errors.New("transport unavailable")},
		{"temporary status", http.StatusServiceUnavailable, "", nil},
		{"invalid body", http.StatusOK, "{", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			client := &MockHTTPClient{MockDo: func(*http.Request) (*http.Response, error) {
				cancel()
				return &http.Response{StatusCode: tc.status, Body: io.NopCloser(strings.NewReader(tc.body))}, tc.transportErr
			}}
			_, err := fetchRDAP(ctx, client, makeApp(), "example.com")
			require.Error(t, err)
		})
	}
}

func TestRegistrarReferralHandlesMalformedAndFailedResponses(t *testing.T) {
	allow := func(string) bool { return true }
	require.Nil(t, followRegistrarRDAPLinks(context.Background(), "example.com", []string{"://bad"}, http.DefaultClient, allow, nil))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	limiter := rate.NewLimiter(rate.Every(time.Hour), 1)
	require.True(t, limiter.Allow())
	require.Nil(t, followRegistrarRDAPLinks(ctx, "example.com", []string{"https://rdap.example"}, &MockHTTPClient{MockDo: func(*http.Request) (*http.Response, error) { t.Fatal("limiter must stop request"); return nil, nil }}, allow, limiter))
	for _, tc := range []struct {
		name         string
		status       int
		body         string
		transportErr error
	}{
		{"transport with response", http.StatusOK, "", errors.New("offline")},
		{"rate limited", http.StatusTooManyRequests, "", nil},
		{"invalid body", http.StatusOK, "{", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			client := &MockHTTPClient{MockDo: func(*http.Request) (*http.Response, error) {
				cancel()
				return &http.Response{StatusCode: tc.status, Body: io.NopCloser(strings.NewReader(tc.body))}, tc.transportErr
			}}
			require.Nil(t, followRegistrarRDAPLinks(ctx, "example.com", []string{"https://rdap.example"}, client, allow, nil))
		})
	}
}

func TestThinRDAPUsesValidRegistrarReferral(t *testing.T) {
	app := &AppState{Bootstrap: &Bootstrap{services: map[string][]string{"com": {"https://registry.example/"}}, fetchedAt: time.Now()}, RDAPURLAllowed: func(string) bool { return true }}
	requests := 0
	client := &MockHTTPClient{MockDo: func(request *http.Request) (*http.Response, error) {
		requests++
		body := `{"objectClassName":"domain","ldhName":"example.com","links":[{"rel":"related","href":"https://registrar.example/domain/example.com"}]}`
		if strings.Contains(request.URL.Host, "registrar") {
			body = `{"objectClassName":"domain","ldhName":"example.com","events":[{"eventAction":"expiration","eventDate":"2030-04-05T00:00:00Z"}],"entities":[{"roles":["registrar"],"handle":"Example Registrar"}]}`
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body))}, nil
	}}
	snapshot := FetchRDAPSnapshot(context.Background(), client, app, "example.com")
	require.NoError(t, snapshot.Err)
	require.Equal(t, 2, requests)
	require.NotNil(t, snapshot.RegistrarTier)
	require.Equal(t, SourceRegistrarRDAP, snapshot.RegistrarTier.Source)
}

func TestLookupRejectsNilBootstrapMalformedURLAndDelegationTransport(t *testing.T) {
	_, err := rdapServersFor(context.Background(), nil, "example.com")
	require.ErrorContains(t, err, "bootstrap")
	require.False(t, IsSafeRDAPURL("://bad"))
	app := NewAppState(AppConfig{Resolvers: []string{"192.0.2.53"}})
	app.DNSClient = &MockDNSResolver{MockExchangeContext: func(context.Context, *dns.Msg, string) (*dns.Msg, time.Duration, error) {
		return nil, 0, errors.New("resolver unavailable")
	}}
	snapshot := FetchNSDelegationSnapshot(context.Background(), app, DomainConfig{Domain: "example.com"})
	require.ErrorContains(t, snapshot.Err, "resolver unavailable")
}

func TestWHOISReferralFailureKeepsRegistryEvidence(t *testing.T) {
	app := &AppState{WHOISClient: &MockWHOISClient{MockQuery: func(_ context.Context, _, server string) (string, error) {
		if server != "" {
			return "", errors.New("referral unavailable")
		}
		return "Expiry Date: 2030-04-05\nRegistrar Name: Example Registrar\nWhois Server: whois.example.com", nil
	}}}
	snapshot, err := fetchWHOIS(context.Background(), app, "example.com")
	require.NoError(t, err)
	require.Equal(t, "Example Registrar", snapshot.Registrar)
}

func TestWHOISKnownServerAndUnsafeReferral(t *testing.T) {
	server, err := discoverWHOISServer(context.Background(), &AppState{}, "example.de")
	require.NoError(t, err)
	require.NotEmpty(t, server)
	app := &AppState{WHOISClient: &MockWHOISClient{MockQuery: func(_ context.Context, _, referral string) (string, error) {
		require.Empty(t, referral)
		return "Expiry Date: 2030-04-05\nRegistrar Name: Example Registrar\nWhois Server: 127.0.0.1", nil
	}}}
	snapshot, err := fetchWHOIS(context.Background(), app, "example.com")
	require.NoError(t, err)
	require.Equal(t, "Example Registrar", snapshot.Registrar)
}

func TestWHOISRetryPreservesPartialFailureAndRateLimit(t *testing.T) {
	app := &AppState{WHOISClient: &MockWHOISClient{MockQuery: func(context.Context, string, string) (string, error) {
		return "partial evidence", errors.New("truncated")
	}}}
	_, err := queryWHOISWithRetry(context.Background(), app, "example.com", "", NameOpWHOIS)
	require.ErrorContains(t, err, "truncated")
	ctx, cancel := context.WithCancel(context.Background())
	app.WHOISClient = &MockWHOISClient{MockQuery: func(context.Context, string, string) (string, error) {
		cancel()
		return "rate limit exceeded", nil
	}}
	_, err = queryWHOISWithRetry(ctx, app, "example.com", "", NameOpWHOIS)
	require.Error(t, err)
}

func TestRateLimitedRDAPFallsBackToValidWHOIS(t *testing.T) {
	app := &AppState{WHOISClient: &MockWHOISClient{MockQuery: func(context.Context, string, string) (string, error) {
		return "Expiry Date: 2030-04-05\nRegistrar Name: Example Registrar", nil
	}}}
	snapshot := fallbackWHOISSnapshot(context.Background(), app, "example.com", ErrRDAPRateLimited)
	require.NoError(t, snapshot.Err)
	require.Equal(t, ProtocolWHOIS, snapshot.ProtocolUsed)
}

func TestRegistrarURLMalformedFallbackAndEmptyDelegationEntry(t *testing.T) {
	require.Equal(t, "://bad/domain/example.com", registrarRDAPURL("://bad", "example.com"))
	require.Equal(t, "bad\n/domain/example.com", registrarRDAPURL("bad\n/domain/example.com", "example.com"))
	tracker := ConditionTracker{Status: StatusOK}
	evaluateNameserverDelegation([]NameserverConfig{{Hostname: "ns.example.com"}}, []string{"", "ns.example.com"}, &tracker)
	require.Equal(t, StatusOK, tracker.Status)
}

func TestParentDelegationUsesResolvedRootNameserver(t *testing.T) {
	app := NewAppState(AppConfig{Resolvers: []string{"192.0.2.53:53"}})
	app.DNSClient = &MockDNSResolver{MockExchangeContext: func(_ context.Context, q *dns.Msg, address string) (*dns.Msg, time.Duration, error) {
		r := new(dns.Msg)
		r.SetReply(q)
		name := q.Question[0].Name
		var raw string
		switch q.Question[0].Qtype {
		case dns.TypeNS:
			if name == "com." {
				raw = "com. 60 IN NS ns.com."
			} else {
				raw = "example.com. 60 IN NS ns1.example.com."
				require.Equal(t, "8.8.8.8:53", address)
			}
		case dns.TypeA:
			raw = "ns.com. 60 IN A 8.8.8.8"
		}
		if raw != "" {
			rr, err := dns.NewRR(raw)
			require.NoError(t, err)
			r.Answer = []dns.RR{rr}
		}
		return r, 0, nil
	}}
	snapshot := FetchNSDelegationSnapshot(context.Background(), app, DomainConfig{Domain: "example.com", RootZone: "com"})
	require.NoError(t, snapshot.Err)
	require.Equal(t, []string{"ns1.example.com"}, snapshot.Nameservers)
}

func TestWHOISQueryRejectsControlCharactersAndCanceledLimiter(t *testing.T) {
	app := &AppState{WHOISDial: func(context.Context, string) (net.Conn, error) {
		t.Fatal("invalid query must not dial")
		return nil, nil
	}}
	_, err := queryWHOISServer(context.Background(), app, "example.com\nextra", "whois.example.com")
	require.Error(t, err)

	limiter := rate.NewLimiter(rate.Every(time.Hour), 1)
	require.True(t, limiter.Allow())
	app.RDAPLimiter = limiter
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = queryWHOISServer(ctx, app, "example.com", "whois.example.com")
	require.ErrorIs(t, err, context.Canceled)
}

func TestWHOISDialBoundsConnectionAttempts(t *testing.T) {
	var addresses []net.IPAddr
	for _, raw := range []string{"8.8.8.8", "1.1.1.1", "9.9.9.9", "208.67.222.222"} {
		addresses = append(addresses, net.IPAddr{IP: net.ParseIP(raw)})
	}
	calls := 0
	_, err := dialPublicWHOISWith(context.Background(), "whois.example.com",
		func(context.Context, string) ([]net.IPAddr, error) { return addresses, nil },
		func(context.Context, string, string) (net.Conn, error) {
			calls++
			return nil, errors.New("offline")
		})
	require.ErrorContains(t, err, "offline")
	require.Equal(t, MaxNetworkAttempts, calls)
}

func TestPublicWHOISDialRejectsEmptyHost(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := dialPublicWHOIS(ctx, "")
	require.Nil(t, conn)
	require.Error(t, err)
}

func TestWHOISInjectedTransportPreservesPartialError(t *testing.T) {
	partial := errors.New("truncated response")
	app := &AppState{WHOISClient: &MockWHOISClient{MockQuery: func(context.Context, string, string) (string, error) {
		return "partial", partial
	}}}
	response, err := queryWHOISWithContext(context.Background(), app, "example.com", " whois.example.com ")
	require.Equal(t, "partial", response)
	require.ErrorIs(t, err, partial)
	require.True(t, strings.Contains(err.Error(), "example.com"))
}

func TestWHOISQueryBoundaryFailures(t *testing.T) {
	app := &AppState{WHOISDial: func(context.Context, string) (net.Conn, error) {
		return nil, errors.New("dial failed")
	}}
	_, err := queryWHOISWithContext(context.Background(), app, "singlelabel", "")
	require.ErrorContains(t, err, "top-level")
	_, err = discoverWHOISServer(context.Background(), app, "example.com")
	require.ErrorContains(t, err, "dial failed")
	_, err = queryWHOISServer(context.Background(), nil, "example.com", "whois.example.com")
	require.ErrorContains(t, err, "not configured")
	_, err = queryWHOISServer(context.Background(), app, "example.com", "whois.example.com")
	require.ErrorContains(t, err, "dial failed")
	_, err = queryWHOISServer(context.Background(), app, "example.com", "127.0.0.1")
	require.ErrorContains(t, err, "unsafe")
	require.Equal(t, WHOISGoDaddyHost, canonicalWHOISServer(WHOISGoDaddyAlias))
	require.Equal(t, WHOISPorkbunHost, canonicalWHOISServer(WHOISPorkbunAlias))
	require.Equal(t, WHOISARINPrefix+"example.com", whoisQueryText("example.com", WHOISARINHost))
}

type failingWHOISConn struct {
	net.Conn
	deadlineErr error
	writeErr    error
	readErr     error
}

func (c failingWHOISConn) SetDeadline(time.Time) error { return c.deadlineErr }
func (c failingWHOISConn) Write(p []byte) (int, error) {
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	return len(p), nil
}
func (c failingWHOISConn) Read([]byte) (int, error) { return 0, c.readErr }

func TestWHOISExchangePropagatesTransportFailures(t *testing.T) {
	for _, step := range []string{"deadline", "write", "read"} {
		t.Run(step, func(t *testing.T) {
			client, server := net.Pipe()
			defer func() { _ = client.Close(); _ = server.Close() }()
			failure := errors.New(step + " failed")
			conn := failingWHOISConn{Conn: client}
			switch step {
			case "deadline":
				conn.deadlineErr = failure
			case "write":
				conn.writeErr = failure
			case "read":
				conn.readErr = failure
			}
			_, err := exchangeWHOIS(context.Background(), conn, "example.com", "example.com", "whois.example.com")
			require.ErrorIs(t, err, failure)
		})
	}
}

func TestWHOISStatusNormalizesAliasesAndInvalidFragments(t *testing.T) {
	require.Empty(t, normalizeEPPStatus("()"))
	require.Equal(t, "unknownExtension", normalizeEPPStatus("https://example.com/epp#unknownExtension"))
	require.Equal(t, "https://example.com/epp#bad/path", normalizeEPPStatus("https://example.com/epp#bad/path"))
	require.True(t, isTransferLocked([]string{EPPTokenTransferLock}))
	for generic, specific := range map[string]string{
		EPPTokenUpdateProhibited: EPPTokenServerUpdateProhibited,
		EPPTokenRenewProhibited:  EPPTokenServerRenewProhibited,
		StrHold:                  EPPTokenServerHold,
	} {
		result := NormalizeDomainStatuses([]string{generic, specific})
		require.Len(t, result, 1)
		require.True(t, strings.EqualFold(result[0], specific))
	}
}

func TestWHOISRateLimitAndMalformedVCardEvidence(t *testing.T) {
	require.True(t, isWHOISRateLimited("", errors.New("query quota reached")))
	require.Equal(t, "42", extractVCardText(42))
	require.Empty(t, extractVCardProperty([]any{"vcard"}, "fn"))
	require.Empty(t, extractVCardProperty([]any{"vcard", "not properties"}, "fn"))
	require.Empty(t, extractVCardProperty([]any{"vcard", []any{"broken", []any{"fn"}, []any{"fn", nil, nil, " "}}}, "fn"))
}

func TestRegistrarEntityUsesIDAndNestedReferralEvidence(t *testing.T) {
	entities := []RDAPEntity{{Roles: []string{RoleRegistrar}, PublicIDs: []RDAPPublicID{{Type: PublicIDTypeIANA, Identifier: " 123 "}}, Port43: "whois.example.com"}}
	name, id, _, whois := findRegistrarEntity(entities)
	require.Contains(t, name, "123")
	require.Equal(t, "123", id)
	require.Equal(t, "whois.example.com", whois)

	nested := []RDAPEntity{{Entities: []RDAPEntity{{Roles: []string{RoleRegistrar}, Handle: "REG-42", Links: []RDAPLink{{Rel: RelRelated, Href: "https://rdap.example/domain/example.com"}}}}}}
	name, _, referral, _ := findRegistrarEntity(nested)
	require.Equal(t, "REG-42", name)
	require.Equal(t, "https://rdap.example/domain/example.com", referral)
	links := collectRDAPReferralLinks(&RDAPDomainResponse{Links: []RDAPLink{{Rel: RelRelated, Href: " "}}, Entities: nested}, "https://registry.example")
	require.Equal(t, []string{"https://rdap.example/domain/example.com"}, links)
}

func TestRDAPTierPreservesUnparseableRegistryDates(t *testing.T) {
	response := &RDAPDomainResponse{Events: []RDAPEvent{
		{Action: "expiration", Date: "unknown expiry"},
		{Action: "registration", Date: "unknown creation"},
		{Action: "last changed", Date: "unknown update"},
	}, Nameservers: []RDAPNameserver{{LDHName: "NS.EXAMPLE.COM."}}}
	tier := extractRDAPDomainTier(response, SourceRegistryRDAP, "https://rdap.example")
	require.Equal(t, "unknown expiry", tier.Expiration)
	require.Equal(t, "unknown creation", tier.Created)
	require.Equal(t, "unknown update", tier.Updated)
	require.Equal(t, []string{"ns.example.com"}, tier.Nameservers)
}

func TestTierSynthesisHandlesMissingAndUnparseableEvidence(t *testing.T) {
	empty, _ := synthesizeTierData(nil, nil)
	require.Error(t, empty.Err)
	registrar := &DomainTierData{Source: SourceRegistrarRDAP, Expiration: "2030-01-01T00:00:00Z", Nameservers: []string{"ns.registrar.example"}}
	state, _ := synthesizeTierData(nil, registrar)
	require.Equal(t, registrar.Source, state.Source)
	require.Equal(t, registrar.Expiration, state.Expiration)
	require.Equal(t, registrar.Nameservers, state.Nameservers)

	for _, tc := range []struct {
		registryExpiry, registrarExpiry, want string
	}{
		{"2030-01-01T00:00:00Z", "invalid", "2030-01-01T00:00:00Z"},
		{"invalid", "2031-01-01T00:00:00Z", "2031-01-01T00:00:00Z"},
		{"invalid", "also invalid", "invalid"},
	} {
		state, _ := synthesizeTierData(&DomainTierData{Expiration: tc.registryExpiry}, &DomainTierData{Expiration: tc.registrarExpiry})
		require.Equal(t, tc.want, state.Expiration)
	}
}
