package monitor

import (
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestDNSMatchersHandleLargeSetsAndMultipleExpectations(t *testing.T) {
	for _, tc := range []struct {
		matchType string
		expected  StringList
		found     []string
		wantMatch bool
		wantCode  ResultCode
	}{
		{MatchPrefix, StringList{"alpha", "beta"}, []string{" ALPHABET ", "BETAMAX"}, true, CodeDNSMatchVerified},
		{MatchPrefix, StringList{"alpha", "missing"}, []string{"alphabet", "beta"}, false, CodeDNSPrefixMismatch},
		{MatchPrefix, StringList{"alpha", "beta"}, []string{"alpha", "beta", "c", "d", "e", "f", "g", "h", "i"}, true, CodeDNSMatchVerified},
		{MatchContains, StringList{"alpha", "beta"}, []string{"XXALPHAYY", "XXBETAYY"}, true, CodeDNSMatchVerified},
		{MatchContains, StringList{"alpha", "missing"}, []string{"alphabet", "beta"}, false, CodeDNSSubstringMismatch},
		{MatchContains, StringList{"alpha", "beta"}, []string{"alpha", "beta", "c", "d", "e", "f", "g", "h", "i"}, true, CodeDNSMatchVerified},
		{MatchAnyOf, StringList{"alpha", "beta"}, []string{"other"}, false, CodeDNSMismatch},
	} {
		matched, _, code := validateRecordsWithReason(DNSTask{MatchType: tc.matchType, Expected: tc.expected}, tc.found)
		require.Equal(t, tc.wantMatch, matched, tc.matchType)
		require.Equal(t, tc.wantCode, code, tc.matchType)
	}
}

func TestDNSQueryRejectsIncompleteAndUnexpectedResponses(t *testing.T) {
	for _, tc := range []struct {
		name    string
		answer  func(*dns.Msg) (*dns.Msg, error)
		tcp     func(*dns.Msg) (*dns.Msg, error)
		wantErr string
	}{
		{name: "empty response", answer: func(*dns.Msg) (*dns.Msg, error) { return nil, nil }, wantErr: "empty"},
		{name: "truncated without TCP", answer: func(query *dns.Msg) (*dns.Msg, error) {
			response := new(dns.Msg)
			response.SetReply(query)
			response.Truncated = true
			return response, nil
		}, wantErr: "truncated"},
		{name: "still truncated over TCP", answer: func(query *dns.Msg) (*dns.Msg, error) {
			response := new(dns.Msg)
			response.SetReply(query)
			response.Truncated = true
			return response, nil
		}, tcp: func(query *dns.Msg) (*dns.Msg, error) {
			response := new(dns.Msg)
			response.SetReply(query)
			response.Truncated = true
			return response, nil
		}, wantErr: "TCP"},
		{name: "unexpected extended Rcode", answer: func(query *dns.Msg) (*dns.Msg, error) {
			response := new(dns.Msg)
			response.SetReply(query)
			response.Rcode = dns.RcodeBadVers
			return response, nil
		}, wantErr: "error code 16"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app := &AppState{DNSClient: &MockDNSResolver{MockExchangeContext: func(_ context.Context, query *dns.Msg, _ string) (*dns.Msg, time.Duration, error) {
				response, err := tc.answer(query)
				return response, 0, err
			}}}
			if tc.tcp != nil {
				app.DNSTCPClient = &MockDNSResolver{MockExchangeContext: func(_ context.Context, query *dns.Msg, _ string) (*dns.Msg, time.Duration, error) {
					response, err := tc.tcp(query)
					return response, 0, err
				}}
			}
			_, err := queryDNSMsg(context.Background(), app, "example.com", dns.TypeA, []string{"192.0.2.53"})
			require.ErrorContains(t, err, tc.wantErr)
		})
	}
}

func TestDNSQueryReturnsContextCancellationAfterTransportFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	app := &AppState{DNSClient: &MockDNSResolver{MockExchangeContext: func(context.Context, *dns.Msg, string) (*dns.Msg, time.Duration, error) {
		return nil, 0, errors.New("offline")
	}}}
	_, err := queryDNSMsg(ctx, app, "example.com", dns.TypeA, []string{"192.0.2.53"})
	require.ErrorIs(t, err, context.Canceled)
}

func TestDNSConsensusRejectsDisagreementAndAcceptsUnanimousNXDOMAIN(t *testing.T) {
	for _, tc := range []struct {
		name    string
		answer  func(*dns.Msg, string) *dns.Msg
		wantErr error
	}{
		{name: "both absent", answer: func(query *dns.Msg, _ string) *dns.Msg {
			response := new(dns.Msg)
			response.SetRcode(query, dns.RcodeNameError)
			return response
		}, wantErr: ErrNXDOMAIN},
		{name: "different answers", answer: func(query *dns.Msg, address string) *dns.Msg {
			response := new(dns.Msg)
			response.SetReply(query)
			ip := "192.0.2.1"
			if address == "192.0.2.54:53" {
				ip = "192.0.2.2"
			}
			response.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET}, A: net.ParseIP(ip)}}
			return response
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app := &AppState{DNSClient: &MockDNSResolver{MockExchangeContext: func(_ context.Context, query *dns.Msg, address string) (*dns.Msg, time.Duration, error) {
				return tc.answer(query, address), 0, nil
			}}}
			_, err := queryDNS(context.Background(), app, "example.com", dns.TypeA, []string{"192.0.2.53", "192.0.2.54"})
			require.Error(t, err)
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
			} else {
				require.ErrorContains(t, err, "disagree")
			}
		})
	}
}

func TestDNSObservationsBoundDistinctAttempts(t *testing.T) {
	calls := 0
	observations, selected := collectDNSObservations([]string{"192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4", "192.0.2.5"}, 2, func(string) ([]string, error) {
		calls++
		return nil, errors.New("offline")
	})
	require.Len(t, observations, MaxNetworkAttempts)
	require.Empty(t, selected)
	require.Equal(t, MaxNetworkAttempts, calls)
}

func TestDNSRejectsNonzeroPreferenceNullMX(t *testing.T) {
	app := &AppState{DNSClient: &MockDNSResolver{MockExchangeContext: func(_ context.Context, query *dns.Msg, _ string) (*dns.Msg, time.Duration, error) {
		response := new(dns.Msg)
		response.SetReply(query)
		response.Answer = []dns.RR{&dns.MX{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeMX, Class: dns.ClassINET}, Preference: 10, Mx: "."}}
		return response, 0, nil
	}}}
	_, err := queryDNSOne(context.Background(), app, "example.com", dns.TypeMX, []string{"192.0.2.53"})
	require.ErrorIs(t, err, ErrInvalidNullMX)
}

func TestDNSRejectsMixedNullMXAndSERVFAIL(t *testing.T) {
	app := &AppState{DNSClient: &MockDNSResolver{MockExchangeContext: func(_ context.Context, query *dns.Msg, address string) (*dns.Msg, time.Duration, error) {
		response := new(dns.Msg)
		response.SetReply(query)
		if query.Question[0].Qtype == dns.TypeMX {
			response.Answer = []dns.RR{
				&dns.MX{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeMX, Class: dns.ClassINET}, Mx: "."},
				&dns.MX{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeMX, Class: dns.ClassINET}, Mx: "mail.example.com."},
			}
		} else {
			response.Rcode = dns.RcodeServerFailure
		}
		return response, 0, nil
	}}}
	_, err := queryDNSOne(context.Background(), app, "example.com", dns.TypeMX, []string{"192.0.2.53"})
	require.ErrorIs(t, err, ErrInvalidNullMX)
	_, err = queryDNSMsg(context.Background(), app, "example.com", dns.TypeA, []string{"192.0.2.53"})
	require.ErrorIs(t, err, ErrSERVFAIL)
}

func TestDNSHelpersHandleUnsupportedAndUnrelatedAnswers(t *testing.T) {
	_, ok := dnsAnswerText(&dns.SOA{}, dns.TypeSOA)
	require.False(t, ok)
	owners := dnsAnswerOwners([]dns.RR{
		&dns.CNAME{Hdr: dns.RR_Header{Name: "unrelated.example.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET}, Target: "hidden.example."},
	}, "example.com")
	require.NotContains(t, owners, "hidden.example.")
	require.Equal(t, []string{"192.0.2.53"}, func() []string {
		app := NewAppState(AppConfig{Resolvers: []string{"192.0.2.53"}})
		return app.resolvers()
	}())
	for _, name := range []string{RecordTypeTXT, RecordTypeNS} {
		_, ok := dnsTypeForName(name)
		require.True(t, ok)
	}
	_, err := resolveTargetWithResolvers(context.Background(), &AppState{}, DNSTask{Type: "UNKNOWN"}, nil)
	require.ErrorContains(t, err, "unsupported")
}

func TestDNSHealthSkipsDuplicateAndEmptyNameservers(t *testing.T) {
	target := DomainConfig{Nameservers: []NameserverConfig{{Hostname: ""}, {Hostname: "  "}, {Hostname: "8.8.8.8"}, {Hostname: "8.8.8.8."}}}
	app := &AppState{DNSClient: &MockDNSResolver{MockExchangeContext: func(_ context.Context, query *dns.Msg, _ string) (*dns.Msg, time.Duration, error) {
		response := new(dns.Msg)
		response.SetReply(query)
		return response, 0, nil
	}}}
	snapshots := FetchNSHealthSnapshots(context.Background(), app, target)
	require.Len(t, snapshots, 1)
}

func TestDNSAliasExpectedResolutionReportsFailure(t *testing.T) {
	app := NewAppState(AppConfig{Resolvers: []string{"192.0.2.53"}})
	app.DNSClient = &MockDNSResolver{MockExchangeContext: func(_ context.Context, query *dns.Msg, address string) (*dns.Msg, time.Duration, error) {
		require.Equal(t, "192.0.2.54:53", address)
		name := query.Question[0].Name
		if name == "expected.example." {
			return nil, 0, errors.New("expected target unavailable")
		}
		response := new(dns.Msg)
		response.SetReply(query)
		if query.Question[0].Qtype == dns.TypeA {
			rr, err := dns.NewRR("alias.example. 60 IN A 192.0.2.1")
			require.NoError(t, err)
			response.Answer = []dns.RR{rr}
		}
		return response, 0, nil
	}}
	target := DNSTask{Hostname: "alias.example", Type: RecordTypeALIAS, Expected: StringList{"expected.example"}, CustomResolver: "192.0.2.54"}
	snapshot := FetchDNSSnapshot(context.Background(), app, target)
	require.ErrorContains(t, snapshot.Err, "expected.example")
}

func TestEmailSnapshotDistinguishesNXDOMAINAndDKIMFailure(t *testing.T) {
	app := NewAppState(AppConfig{Resolvers: []string{"192.0.2.53"}})
	app.DNSClient = &MockDNSResolver{MockExchangeContext: func(_ context.Context, q *dns.Msg, _ string) (*dns.Msg, time.Duration, error) {
		name := q.Question[0].Name
		if name == "bad._domainkey.example.com." {
			return nil, 0, errors.New("selector lookup failed")
		}
		response := new(dns.Msg)
		if q.Question[0].Qtype == dns.TypeMX || name == "missing._domainkey.example.com." {
			response.SetRcode(q, dns.RcodeNameError)
		} else {
			response.SetReply(q)
		}
		return response, 0, nil
	}}
	target := DomainConfig{Domain: "example.com", Email: &EmailConfig{DKIMSelectors: []string{"bad", "missing"}}}
	snapshot := FetchEmailSnapshot(context.Background(), app, target)
	require.NoError(t, snapshot.MXErr)
	require.ErrorContains(t, snapshot.DKIMErrs["bad"], "selector lookup failed")
	require.False(t, snapshot.DKIMResults["missing"])
}

func TestNameserverSnapshotReportsAddressAndDNSKEYFailures(t *testing.T) {
	app := NewAppState(AppConfig{Resolvers: []string{"192.0.2.53"}})
	app.DNSClient = &MockDNSResolver{MockExchangeContext: func(_ context.Context, q *dns.Msg, _ string) (*dns.Msg, time.Duration, error) {
		response := new(dns.Msg)
		response.SetReply(q)
		if q.Question[0].Qtype == dns.TypeSOA {
			response.Authoritative = true
			rr, err := dns.NewRR("example.com. 60 IN SOA ns.example.com. hostmaster.example.com. 1 3600 600 86400 60")
			require.NoError(t, err)
			response.Answer = []dns.RR{rr}
		}
		return response, 0, nil
	}}
	failed := FetchNSSnapshot(context.Background(), app, NameserverConfig{Hostname: "missing.example.com"}, DomainConfig{Domain: "example.com"})
	require.True(t, failed.Unreachable)
	noKey := FetchNSSnapshot(context.Background(), app, NameserverConfig{Hostname: "8.8.8.8"}, DomainConfig{Domain: "example.com", DNSSEC: true})
	require.ErrorContains(t, noKey.DNSKEYErr, "authoritative")
}

func TestDNSSnapshotHandlesConsensusAndExpectedAliasValues(t *testing.T) {
	app := NewAppState(AppConfig{Resolvers: []string{"192.0.2.53", "192.0.2.54"}})
	app.DNSClient = &MockDNSResolver{MockExchangeContext: func(_ context.Context, query *dns.Msg, _ string) (*dns.Msg, time.Duration, error) {
		response := new(dns.Msg)
		if query.Question[0].Name == "missing.example." {
			response.SetRcode(query, dns.RcodeNameError)
			return response, 0, nil
		}
		response.SetReply(query)
		if query.Question[0].Qtype == dns.TypeA {
			rr, err := dns.NewRR(query.Question[0].Name + " 60 IN A 192.0.2.1")
			require.NoError(t, err)
			response.Answer = []dns.RR{rr}
		}
		return response, 0, nil
	}}
	missing := FetchDNSSnapshot(context.Background(), app, DNSTask{Hostname: "missing.example", Type: RecordTypeA})
	require.ErrorIs(t, missing.Err, ErrNXDOMAIN)
	alias := FetchDNSSnapshot(context.Background(), app, DNSTask{Hostname: "alias.example", Type: RecordTypeALIAS, Expected: StringList{"expected.example", "192.0.2.2"}, CustomResolver: "192.0.2.53"})
	require.NoError(t, alias.Err)
	require.ElementsMatch(t, []string{"192.0.2.1", "192.0.2.2"}, alias.ExpectedRecords)
}

func TestDNSSnapshotReportsMixedResolverFailures(t *testing.T) {
	app := NewAppState(AppConfig{Resolvers: []string{"192.0.2.53", "192.0.2.54"}})
	app.DNSClient = &MockDNSResolver{MockExchangeContext: func(_ context.Context, query *dns.Msg, address string) (*dns.Msg, time.Duration, error) {
		if address == "192.0.2.54:53" {
			return nil, 0, errors.New("resolver offline")
		}
		response := new(dns.Msg)
		response.SetRcode(query, dns.RcodeNameError)
		return response, 0, nil
	}}
	snapshot := FetchDNSSnapshot(context.Background(), app, DNSTask{Hostname: "missing.example", Type: RecordTypeA})
	require.ErrorContains(t, snapshot.Err, "incomplete")
	app.DNSClient = &MockDNSResolver{MockExchangeContext: func(_ context.Context, query *dns.Msg, address string) (*dns.Msg, time.Duration, error) {
		response := new(dns.Msg)
		if address == "192.0.2.53:53" {
			response.SetRcode(query, dns.RcodeNameError)
		} else {
			response.SetReply(query)
			rr, parseErr := dns.NewRR("missing.example. 60 IN A 192.0.2.1")
			require.NoError(t, parseErr)
			response.Answer = []dns.RR{rr}
		}
		return response, 0, nil
	}}
	snapshot = FetchDNSSnapshot(context.Background(), app, DNSTask{Hostname: "missing.example", Type: RecordTypeA})
	require.ErrorContains(t, snapshot.Err, "incomplete")
}

func TestDNSDefensiveGuardsHandleImpossibleTransportCombinations(t *testing.T) {
	_, err := queryDNSOneWithQuery(context.Background(), nil, "example.com", dns.TypeA, nil, func(context.Context, *AppState, string, uint16, []string) (*dns.Msg, error) {
		return nil, nil
	})
	require.ErrorIs(t, err, ErrEmptyDNSResponse)
	_, _, err = resolveNSAddressesWithPort(context.Background(), nil, "bad", func(string, string) string { return "missing-port" })
	require.ErrorContains(t, err, "invalid")
	queryNil := func(context.Context, *AppState, string, uint16, []string, bool) (*dns.Msg, error) { return nil, nil }
	_, _, err = selectNSSOAWithQuery(context.Background(), nil, "example.com", []string{"192.0.2.53:53"}, queryNil)
	require.ErrorContains(t, err, "nil")
	snapshot := &NSSnapshot{}
	fetchNSDNSKEYWithQuery(context.Background(), nil, "example.com", "192.0.2.53:53", snapshot, queryNil)
	require.ErrorContains(t, snapshot.DNSKEYErr, "nil")
}

func TestDNSSECFinalizationReportsInconsistentUpstreamEvidence(t *testing.T) {
	result := finalizeDNSSECResult(DNSSECResult{Source: DNSSECSourceLocalDoH, HasDS: true, HasDNSKEY: true, DSMatchesDNSKEY: true, RRSIGValid: true})
	require.False(t, result.Valid)
	require.Equal(t, MsgErrDNSSECUpstreamChainBroken, result.Error)
}

func TestDNSSECDoHHandlesPartialAndImpossibleHTTPResponses(t *testing.T) {
	app := &AppState{Clients: OutboundClients{Public: &MockHTTPClient{MockDo: func(*http.Request) (*http.Response, error) {
		t.Fatal("injected fetch should own the response")
		return nil, nil
	}}}}
	newRequest := func(ctx context.Context, raw string) (*http.Request, error) {
		return http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	}
	for _, tc := range []struct {
		name string
		deps dnssecDoHDependencies
	}{
		{"request rejected", dnssecDoHDependencies{
			newRequest: func(context.Context, string) (*http.Request, error) { return nil, errors.New("request rejected") },
			fetch: func(_ context.Context, _ HTTPDoer, requestFn func() (*http.Request, error)) (*http.Response, error) {
				_, err := requestFn()
				return nil, err
			},
		}},
		{"response with error", dnssecDoHDependencies{
			newRequest: newRequest,
			fetch: func(context.Context, HTTPDoer, func() (*http.Request, error)) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("unused"))}, errors.New("partial failure")
			},
		}},
		{"nil response", dnssecDoHDependencies{
			newRequest: newRequest,
			fetch: func(context.Context, HTTPDoer, func() (*http.Request, error)) (*http.Response, error) {
				return nil, nil
			},
		}},
		{"wrong parsed RR type", dnssecDoHDependencies{
			newRequest: newRequest,
			fetch: func(context.Context, HTTPDoer, func() (*http.Request, error)) (*http.Response, error) {
				body := `{"Status":0,"AD":true,"Question":[{"name":"example.com.","type":48}],"Answer":[{"name":"example.com.","type":48,"data":"257 3 15 AQID"}]}`
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body))}, nil
			},
			parseRR: func(string) (dns.RR, error) { return &dns.A{}, nil },
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.False(t, verifyDNSSECDoHWith(context.Background(), app, "https://doh.example/dns-query", "example.com", "example.com.", tc.deps))
		})
	}
}

func TestDNSSECRejectsCryptographicallyValidExpiredSignature(t *testing.T) {
	key := &dns.DNSKEY{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 60}, Flags: 257, Protocol: 3, Algorithm: dns.ED25519}
	private, err := key.Generate(256)
	require.NoError(t, err)
	ds := key.ToDS(dns.SHA256)
	require.NotNil(t, ds)
	signature := &dns.RRSIG{Hdr: dns.RR_Header{Ttl: 60}, Algorithm: dns.ED25519, KeyTag: key.KeyTag(), SignerName: "example.com.", Inception: uint32(time.Now().Add(-2 * time.Hour).Unix()), Expiration: uint32(time.Now().Add(-time.Hour).Unix())}
	require.NoError(t, signature.Sign(private.(ed25519.PrivateKey), []dns.RR{key}))
	app := &AppState{DNSClient: &MockDNSResolver{MockExchangeContext: func(_ context.Context, query *dns.Msg, _ string) (*dns.Msg, time.Duration, error) {
		response := new(dns.Msg)
		response.SetReply(query)
		if query.Question[0].Qtype == dns.TypeDS {
			response.Answer = []dns.RR{ds}
		} else {
			response.Answer = []dns.RR{key, signature}
		}
		return response, 0, nil
	}}}
	result := validateDNSSEC(context.Background(), app, "example.com", []string{"192.0.2.53"}, "")
	require.False(t, result.RRSIGValid)
	require.Equal(t, MsgErrRRSIGExpiredOrNotYetValid, result.Error)
}

func TestRawDNSClientRetriesTruncatedUDPOverTCP(t *testing.T) {
	udpListener, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	address := udpListener.LocalAddr().String()
	tcpListener, err := net.Listen("tcp", address)
	require.NoError(t, err)
	handler := dns.HandlerFunc(func(writer dns.ResponseWriter, query *dns.Msg) {
		response := new(dns.Msg)
		response.SetReply(query)
		if _, isUDP := writer.RemoteAddr().(*net.UDPAddr); isUDP {
			response.Truncated = true
		} else {
			rr, parseErr := dns.NewRR("example.com. 60 IN A 192.0.2.1")
			if parseErr != nil {
				t.Error(parseErr)
				return
			}
			response.Answer = []dns.RR{rr}
		}
		if writeErr := writer.WriteMsg(response); writeErr != nil {
			t.Error(writeErr)
		}
	})
	udpStarted := make(chan struct{})
	tcpStarted := make(chan struct{})
	udpServer := &dns.Server{PacketConn: udpListener, Handler: handler, NotifyStartedFunc: func() { close(udpStarted) }}
	tcpServer := &dns.Server{Listener: tcpListener, Handler: handler, NotifyStartedFunc: func() { close(tcpStarted) }}
	go func() { _ = udpServer.ActivateAndServe() }()
	go func() { _ = tcpServer.ActivateAndServe() }()
	defer func() { _ = udpServer.Shutdown(); _ = tcpServer.Shutdown() }()
	select {
	case <-udpStarted:
	case <-time.After(time.Second):
		t.Fatal("UDP server did not start")
	}
	select {
	case <-tcpStarted:
	case <-time.After(time.Second):
		t.Fatal("TCP server did not start")
	}
	response, err := queryDNSMsg(context.Background(), nil, "example.com", dns.TypeA, []string{address})
	require.NoError(t, err)
	require.Len(t, response.Answer, 1)
}

func TestCNAMEFlatteningPropagatesAddressLookupError(t *testing.T) {
	app := NewAppState(AppConfig{Resolvers: []string{"192.0.2.53"}})
	app.DNSClient = &MockDNSResolver{MockExchangeContext: func(_ context.Context, query *dns.Msg, _ string) (*dns.Msg, time.Duration, error) {
		if query.Question[0].Qtype == dns.TypeA || query.Question[0].Qtype == dns.TypeAAAA {
			return nil, 0, errors.New("flattening unavailable")
		}
		response := new(dns.Msg)
		response.SetReply(query)
		return response, 0, nil
	}}
	_, err := resolveTarget(context.Background(), app, DNSTask{Hostname: "example.com", Type: RecordTypeCNAME, Expected: StringList{"alias.example"}, CustomResolver: "192.0.2.53"})
	require.ErrorContains(t, err, "flattening unavailable")
}

func TestEmailWithoutDMARCIsWarningWhenOtherChecksPass(t *testing.T) {
	status, condition, _ := EvaluateEmailSecurity(DomainConfig{Domain: "example.com", Email: &EmailConfig{}}, EmailSnapshot{MXRecords: []string{"mail.example.com"}, SPFRecords: []string{"v=spf1 -all"}}, nil)
	require.Equal(t, StatusWarning, status)
	require.Equal(t, CodeEmailMissingDMARC, condition.Code)
}

func TestDNSSECEvidenceUsesConfiguredDoHURL(t *testing.T) {
	app := NewAppState(AppConfig{Resolvers: []string{"192.0.2.53"}, DoHURL: "https://doh.example/dns-query"})
	app.DNSClient = &MockDNSResolver{MockExchangeContext: func(_ context.Context, query *dns.Msg, _ string) (*dns.Msg, time.Duration, error) {
		response := new(dns.Msg)
		response.SetReply(query)
		return response, 0, nil
	}}
	app.Clients.Public = &MockHTTPClient{MockDo: func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"Status":0,"AD":false}`))}, nil
	}}
	result := FetchDNSSECEvidence(context.Background(), app, DomainConfig{Domain: "example.com", DNSSEC: true})
	require.False(t, result.Valid)
}

func TestEmailEvaluationPreservesDistinctPolicyFailures(t *testing.T) {
	valid := EmailSnapshot{
		MXRecords:    []string{"mx.good.example"},
		SPFRecords:   []string{"v=spf1 -all"},
		DMARCRecords: []string{"v=DMARC1; p=reject"},
	}
	for _, tc := range []struct {
		name       string
		email      EmailConfig
		snapshot   EmailSnapshot
		providers  map[string]ProviderConfig
		wantStatus CheckStatus
		wantCode   ResultCode
	}{
		{name: "invalid null MX", snapshot: EmailSnapshot{MXErr: ErrInvalidNullMX, SPFRecords: valid.SPFRecords, DMARCRecords: valid.DMARCRecords}, wantStatus: StatusMismatch, wantCode: CodeEmailInvalidNullMX},
		{name: "explicit MX mismatch", email: EmailConfig{MXRecords: []string{"expected.mx"}}, snapshot: valid, wantStatus: StatusMismatch, wantCode: CodeEmailMissingMX},
		{name: "provider MX hijack", email: EmailConfig{Provider: "known"}, providers: map[string]ProviderConfig{"known": {MXRecords: []string{"mx.good"}}}, snapshot: valid, wantStatus: StatusHijacked, wantCode: CodeEmailHijackedMX},
		{name: "SPF transport failure", snapshot: EmailSnapshot{MXRecords: valid.MXRecords, SPFErr: errors.New("offline"), DMARCRecords: valid.DMARCRecords}, wantStatus: StatusWarning, wantCode: CodeDNSLookupFailed},
		{name: "multiple SPF", snapshot: EmailSnapshot{MXRecords: valid.MXRecords, SPFRecords: []string{"v=spf1 -all", "v=spf1 ~all"}, DMARCRecords: valid.DMARCRecords}, wantStatus: StatusWarning, wantCode: CodeEmailMultipleSPF},
		{name: "multiple DMARC", snapshot: EmailSnapshot{MXRecords: valid.MXRecords, SPFRecords: valid.SPFRecords, DMARCRecords: []string{"v=DMARC1; p=reject", "v=DMARC1; p=none"}}, wantStatus: StatusWarning, wantCode: CodeEmailMultipleDMARC},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status, condition, state := EvaluateEmailSecurity(DomainConfig{Domain: "example.com", Email: &tc.email}, tc.snapshot, tc.providers)
			require.Equal(t, tc.wantStatus, status)
			require.Equal(t, tc.wantCode, condition.Code)
			require.NotEmpty(t, state.Findings)
		})
	}
}

func TestDNSSECReportsDNSKEYTransportFailure(t *testing.T) {
	app := &AppState{DNSClient: &MockDNSResolver{MockExchangeContext: func(_ context.Context, query *dns.Msg, _ string) (*dns.Msg, time.Duration, error) {
		if query.Question[0].Qtype == dns.TypeDNSKEY {
			return nil, 0, errors.New("key resolver offline")
		}
		response := new(dns.Msg)
		response.SetReply(query)
		return response, 0, nil
	}}}
	result := validateDNSSEC(context.Background(), app, "example.com", []string{"192.0.2.53"}, "")
	require.True(t, result.NetworkError)
	require.Contains(t, result.Error, "key resolver offline")
}

func TestDNSSECRejectsMismatchedDSAndNamesUnknownAlgorithms(t *testing.T) {
	key := &dns.DNSKEY{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET}, Flags: 257, Protocol: 3, Algorithm: dns.ED25519}
	_, err := key.Generate(256)
	require.NoError(t, err)
	ds := key.ToDS(dns.SHA256)
	require.NotNil(t, ds)
	ds.Digest = strings.Repeat("0", len(ds.Digest))
	app := &AppState{DNSClient: &MockDNSResolver{MockExchangeContext: func(_ context.Context, query *dns.Msg, _ string) (*dns.Msg, time.Duration, error) {
		response := new(dns.Msg)
		response.SetReply(query)
		if query.Question[0].Qtype == dns.TypeDS {
			response.Answer = []dns.RR{ds}
		} else {
			response.Answer = []dns.RR{key}
		}
		return response, 0, nil
	}}}
	result := validateDNSSEC(context.Background(), app, "example.com", []string{"192.0.2.53"}, "")
	require.True(t, result.HasDS)
	require.True(t, result.HasDNSKEY)
	require.False(t, result.DSMatchesDNSKEY)
	require.Equal(t, MsgErrDSRecordDoesNotMatchDNSKEY, result.Error)

	unknown := *key
	unknown.Algorithm = 250
	app.DNSClient = &MockDNSResolver{MockExchangeContext: func(_ context.Context, query *dns.Msg, _ string) (*dns.Msg, time.Duration, error) {
		response := new(dns.Msg)
		response.SetReply(query)
		if query.Question[0].Qtype == dns.TypeDNSKEY {
			response.Answer = []dns.RR{&unknown}
		}
		return response, 0, nil
	}}
	result = validateDNSSEC(context.Background(), app, "example.com", []string{"192.0.2.53"}, "")
	require.Contains(t, result.Algorithms, PrefixAlgo+"250")
}

func TestDNSSECEvaluationClassifiesQueryFailure(t *testing.T) {
	status, condition, _ := EvaluateDNSSEC(DomainConfig{DNSSEC: true}, DNSSECResult{Source: DNSSECSourceLocalOnly, Error: "DNSKEY query failed: timeout"})
	require.Equal(t, StatusFailed, status)
	require.Equal(t, CodeDNSLookupFailed, condition.Code)
}

func TestDNSSECDoHRejectsInvalidURLJSONAndKey(t *testing.T) {
	app := &AppState{Clients: OutboundClients{Public: &MockHTTPClient{MockDo: func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("invalid"))}, nil
	}}}}
	require.False(t, verifyDNSSECDoH(context.Background(), app, "://bad", "example.com", "example.com."))
	require.False(t, verifyDNSSECDoH(context.Background(), app, "https://doh.example/dns-query", "example.com", "example.com."))

	app.Clients.Public = &MockHTTPClient{MockDo: func(*http.Request) (*http.Response, error) {
		body := `{"Status":0,"AD":true,"Question":[{"name":"example.com.","type":48}],"Answer":[{"name":"example.com.","type":48,"data":"bad"}]}`
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body))}, nil
	}}
	require.False(t, verifyDNSSECDoH(context.Background(), app, "https://doh.example/dns-query", "example.com", "example.com."))
}

func TestDNSPolicyHelpersRejectMalformedEvidence(t *testing.T) {
	require.False(t, caaTagIsUnconstrained("malformed", nil))
	tags, valid := parseSemicolonTags(" ; p=reject;;")
	require.True(t, valid)
	require.Equal(t, "reject", tags["p"])
	require.Empty(t, dmarcPSDValue("invalid"))
	require.Empty(t, parentDomain("com"))
	require.False(t, isProviderMXSafeDynamic(nil, ProviderConfig{MXRecords: []string{"example.com"}}))
	require.False(t, isProviderMXSafeDynamic([]string{"attacker.example"}, ProviderConfig{MXRecords: []string{"example.com"}}))
}

func TestDNSNoResolverAndEmptyNameserverEvidence(t *testing.T) {
	_, err := queryDNSMsg(context.Background(), nil, "example.com", dns.TypeA, nil)
	require.ErrorIs(t, err, ErrNoResolvers)
	require.Nil(t, FetchNSHealthSnapshots(context.Background(), nil, DomainConfig{Domain: "example.com"}))
	_, found := findSOAForDomain(nil, "example.com")
	require.False(t, found)
	status, condition := EvaluateNSHealth(DomainConfig{Domain: "example.com"}, nil)
	require.Equal(t, StatusOK, status)
	require.True(t, condition.IsZero())
	status, condition = EvaluateNSHealth(DomainConfig{Domain: "example.com", Nameservers: []NameserverConfig{{Hostname: "ns.example.com"}}}, nil)
	require.Equal(t, StatusFailed, status)
	require.Equal(t, CodeNSUnreachable, condition.Code)
}
