package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDNSCheck(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		recordType string
		expectOK   bool
	}{
		{"Valid A Record", "A", true},
		{"Valid AAAA Record", "AAAA", true},
		{"Valid CNAME Record", "CNAME", true},
		{"Valid MX Record", "MX", true},
		{"Valid TXT Record", "TXT", true},
		{"Invalid Record", "INVALID", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, ok := DNSTypeMap[tt.recordType]
			assert.Equal(t, tt.expectOK, ok, "Expected OK=%v for %s, got %v", tt.expectOK, tt.recordType, ok)
		})
	}
}

// testResolvers supplies documentation addresses; test queries use injected resolvers.
func testResolvers() []string {
	return []string{"192.0.2.53"}
}

func TestValidateDNSSECOfflineChain(t *testing.T) {
	key := &dns.DNSKEY{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 60}, Flags: 257, Protocol: 3, Algorithm: dns.ED25519}
	privateKey, err := key.Generate(256)
	require.NoError(t, err)
	ds := key.ToDS(dns.SHA256)
	require.NotNil(t, ds)
	wrongOwnerDS := *ds
	wrongOwnerDS.Hdr.Name = "other.example."
	sig := &dns.RRSIG{Hdr: dns.RR_Header{Ttl: 60}, Algorithm: dns.ED25519, KeyTag: key.KeyTag(), SignerName: "example.com.", Inception: uint32(time.Now().Add(-time.Hour).Unix()), Expiration: uint32(time.Now().Add(time.Hour).Unix())}
	edKey, ok := privateKey.(ed25519.PrivateKey)
	require.True(t, ok)
	require.NoError(t, sig.Sign(edKey, []dns.RR{key}))
	rolloverKey := &dns.DNSKEY{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 60}, Flags: 257, Protocol: 3, Algorithm: dns.ED25519}
	_, err = rolloverKey.Generate(256)
	require.NoError(t, err)
	rolloverSig := *sig
	require.NoError(t, rolloverSig.Sign(edKey, []dns.RR{key, rolloverKey}))
	validDoHBody := fmt.Sprintf(`{"Status":0,"AD":true,"Question":[{"name":"example.com.","type":48}],"Answer":[{"name":"example.com.","type":48,"data":"%d %d %d %s"}]}`,
		key.Flags, key.Protocol, key.Algorithm, key.PublicKey)
	rolloverDoHBody := fmt.Sprintf(`{"Status":0,"AD":true,"Question":[{"name":"example.com.","type":48}],"Answer":[{"name":"example.com.","type":48,"data":"%d %d %d %s"},{"name":"example.com.","type":48,"data":"%d %d %d %s"}]}`,
		key.Flags, key.Protocol, key.Algorithm, key.PublicKey, rolloverKey.Flags, rolloverKey.Protocol, rolloverKey.Algorithm, rolloverKey.PublicKey)
	wrongKeyDoHBody := fmt.Sprintf(`{"Status":0,"AD":true,"Question":[{"name":"example.com.","type":48}],"Answer":[{"name":"example.com.","type":48,"data":"%d %d %d AQID"}]}`,
		key.Flags, key.Protocol, key.Algorithm)
	wrongOwnerDoHBody := fmt.Sprintf(`{"Status":0,"AD":true,"Question":[{"name":"example.com.","type":48}],"Answer":[{"name":"other.example.","type":48,"data":"%d %d %d %s"}]}`,
		key.Flags, key.Protocol, key.Algorithm, key.PublicKey)

	for _, tc := range []struct {
		name, dohBody string
		signed        bool
		noHTTPClient  bool
		wrongDSOwner  bool
		rollover      bool
		wantValid     bool
	}{
		{name: "verified signed chain", signed: true, dohBody: validDoHBody, wantValid: true},
		{name: "verified with second published key", signed: true, rollover: true, dohBody: rolloverDoHBody, wantValid: true},
		{name: "authenticated empty answer", signed: true, dohBody: `{"Status":0,"AD":true,"Question":[{"name":"example.com.","type":48}]}`},
		{name: "authenticated different key", signed: true, dohBody: wrongKeyDoHBody},
		{name: "authenticated wrong owner", signed: true, dohBody: wrongOwnerDoHBody},
		{name: "wrong local DS owner", signed: true, wrongDSOwner: true, dohBody: validDoHBody},
		{name: "unsigned delegation", dohBody: `{"Status":0,"AD":false,"Question":[{"name":"example.com.","type":48}]}`},
		{name: "missing AD bit", signed: true, dohBody: `{"Status":0,"AD":false,"Question":[{"name":"example.com.","type":48}]}`},
		{name: "missing HTTP client", signed: true, noHTTPClient: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app := &AppState{
				DNSClient: &MockDNSResolver{MockExchangeContext: func(_ context.Context, query *dns.Msg, _ string) (*dns.Msg, time.Duration, error) {
					response := new(dns.Msg)
					response.SetReply(query)
					if tc.signed {
						switch query.Question[0].Qtype {
						case dns.TypeDS:
							if tc.wrongDSOwner {
								response.Answer = []dns.RR{&wrongOwnerDS}
							} else {
								response.Answer = []dns.RR{ds}
							}
						case dns.TypeDNSKEY:
							if tc.rollover {
								response.Answer = []dns.RR{key, rolloverKey, &rolloverSig}
							} else {
								response.Answer = []dns.RR{key, sig}
							}
						}
					}
					return response, 0, nil
				}},
				HTTPClient: &MockHTTPClient{MockDo: func(req *http.Request) (*http.Response, error) {
					assert.Equal(t, "example.com", req.URL.Query().Get(ParamName))
					return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(tc.dohBody))}, nil
				}},
			}
			if tc.noHTTPClient {
				app.HTTPClient = nil
			}
			result := validateDNSSEC(context.Background(), app, "example.com", testResolvers(), "https://doh.example/resolve")
			assert.Equal(t, tc.wantValid, result.Valid)
			assert.Equal(t, tc.signed && !tc.wrongDSOwner, result.HasDS)
			if tc.wantValid {
				assert.True(t, result.DSMatchesDNSKEY)
				assert.True(t, result.RRSIGValid)
				assert.True(t, result.ChainIntact)
			} else {
				assert.False(t, result.Valid)
			}
		})
	}
}

// Empty domain

// Single label domain

func TestDNSSECValidationFallback(t *testing.T) {
	assert.False(t, verifyDNSSECDoH(context.Background(), &AppState{}, "https://doh.example/resolve", "example.com", "example.com."))
}

func TestDNSSECValidationDoHHTTPError(t *testing.T) {
	app := &AppState{HTTPClient: &MockHTTPClient{MockDo: func(_ *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusInternalServerError, Body: io.NopCloser(strings.NewReader("server error"))}, nil
	}}}
	assert.False(t, verifyDNSSECDoH(context.Background(), app, "https://doh.example/resolve", "example.com", "example.com."))
}

func TestQueryIPRecords_PartialLookupDoesNotPass(t *testing.T) {
	app := NewAppState(AppConfig{Resolvers: []string{"192.0.2.53:53"}})
	app.DNSClient = &MockDNSResolver{MockExchangeContext: func(_ context.Context, msg *dns.Msg, _ string) (*dns.Msg, time.Duration, error) {
		if msg.Question[0].Qtype == dns.TypeAAAA {
			return nil, 0, errors.New(MsgErrIPv6ResolverTimeout)
		}
		response := new(dns.Msg)
		response.SetReply(msg)
		rr, err := dns.NewRR(msg.Question[0].Name + " 60 IN A 192.0.2.10")
		require.NoError(t, err)
		response.Answer = []dns.RR{rr}
		return response, 0, nil
	}}
	records, err := queryIPRecords(context.Background(), app, "example.com", app.Resolvers())
	assert.Equal(t, []string{"192.0.2.10"}, records)
	require.Error(t, err)
	status, cond := EvaluateDNS(DNSTask{Type: RecordTypeIP, Expected: []string{"192.0.2.10"}}, DNSSnapshot{Records: records, Err: err})
	assert.Equal(t, StatusFailed, status)
	assert.Equal(t, CodeDNSLookupFailed, cond.Code)
}

func TestEvaluateEmailSecurity_DMARCFailurePromotesSPFWarning(t *testing.T) {
	status, cond, state := EvaluateEmailSecurity(DomainConfig{Domain: "example.com", CheckEmailSecurity: true}, EmailSnapshot{
		MXRecords: []string{"mx.example.com"},
		DMARCErr:  errors.New(MsgErrResolverTimeout),
	}, nil)
	assert.Equal(t, StatusFailed, status)
	assert.Equal(t, StatusFailed, state.Status)
	require.NotNil(t, cond)
	assert.Equal(t, CodeDNSLookupFailed, cond.Code)
	assert.Contains(t, cond.Target, "DMARC")
}

// Should never panic regardless of arbitrary input

func TestValidateRecords_MatchTypes(t *testing.T) {
	t.Parallel()

	// 1. Prefix match (e.g. SPF TXT records where other TXT records exist)
	spfTask := DNSTask{
		Hostname:  "google.com",
		Type:      "TXT",
		Expected:  []string{"v=spf1"},
		MatchType: "prefix",
	}
	foundTXTs := []string{
		"google-site-verification=abc123xyz",
		"apple-domain-verification=xyz789",
		"v=spf1 include:_spf.google.com ~all",
	}
	if !validateRecords(spfTask, foundTXTs) {
		t.Errorf("Expected prefix match to succeed for SPF")
	}

	// 2. Contains match
	containsTask := DNSTask{
		Hostname:  "example.com",
		Type:      "TXT",
		Expected:  []string{"_spf.google.com"},
		MatchType: "contains",
	}
	if !validateRecords(containsTask, foundTXTs) {
		t.Errorf("Expected contains match to succeed")
	}

	// 3. Any_of match (e.g. Anycast IP pool)
	anyOfTask := DNSTask{
		Hostname:  "google.com",
		Type:      "A",
		Expected:  []string{"142.250.190.46", "142.251.221.174", "172.217.16.206"},
		MatchType: "any_of",
	}
	foundA := []string{"142.251.221.174"}
	if !validateRecords(anyOfTask, foundA) {
		t.Errorf("Expected any_of match to succeed for live Anycast IP")
	}

	// 4. Exact match failure when unauthorized record exists
	exactTask := DNSTask{
		Hostname:  "static.example.com",
		Type:      "A",
		Expected:  []string{"1.2.3.4"},
		MatchType: "exact",
	}
	unauthA := []string{"1.2.3.4", "5.6.7.8"}
	if validateRecords(exactTask, unauthA) {
		t.Errorf("Expected exact match to fail due to unauthorized IP")
	}
}

func TestDNSSEC_AuthenticatedKSKLinkage(t *testing.T) {
	mux := dns.NewServeMux()

	key1 := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: "testsec.example.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Algorithm: dns.RSASHA256,
		Flags:     257,
		PublicKey: "AQAB",
	}
	ds1 := key1.ToDS(dns.SHA256)

	key2 := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: "testsec.example.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Algorithm: dns.RSASHA256,
		Flags:     256,
		PublicKey: "AQAB",
	}

	rrsig := &dns.RRSIG{
		Hdr:         dns.RR_Header{Name: "testsec.example.", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 3600},
		TypeCovered: dns.TypeDNSKEY,
		Algorithm:   dns.RSASHA256,
		Labels:      2,
		OrigTtl:     3600,
		Expiration:  uint32(time.Now().Add(1 * time.Hour).Unix()),
		Inception:   uint32(time.Now().Add(-1 * time.Hour).Unix()),
		KeyTag:      key2.KeyTag(), // Signed with unlinked key2
		SignerName:  "testsec.example.",
	}

	mux.HandleFunc("testsec.example.", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		if len(r.Question) > 0 {
			switch r.Question[0].Qtype {
			case dns.TypeDS:
				m.Answer = append(m.Answer, ds1)
			case dns.TypeDNSKEY:
				m.Answer = append(m.Answer, key1, key2, rrsig)
			}
		}
		_ = w.WriteMsg(m)
	})

	server := &dns.Server{Addr: "127.0.0.1:0", Net: "udp", Handler: mux}
	l, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen packet: %v", err)
	}
	server.PacketConn = l
	defer func() { _ = server.Shutdown() }()
	go func() { _ = server.ActivateAndServe() }()

	app := &AppState{config: AppConfig{Resolvers: []string{l.LocalAddr().String()}}}
	res := validateDNSSEC(context.Background(), app, "testsec.example", []string{l.LocalAddr().String()}, "")

	if res.Valid {
		t.Errorf("Expected DNSSEC validation to fail when dns.RRSIG is signed by unlinked key2, but got Valid=true")
	}
}

func TestEmailSecurity_DNSLookupError_NoFalseAlerts(t *testing.T) {
	app := &AppState{
		config: AppConfig{
			Resolvers: []string{"192.0.2.1:53"}, // Unroutable TEST-NET-1 IP
		},
		Notifier: &NotificationManager{NtfyURL: "https://ntfy.invalid/test"},
	}
	target := DomainConfig{
		Domain:             "unreachable-domain.com",
		Name:               "Unreachable",
		CheckEmailSecurity: true,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	savedState := evaluateEmailSecurityForTest(ctx, app, target)

	notifier, ok := app.Notifier.(*NotificationManager)
	require.True(t, ok)
	for _, alert := range notifier.alertBatch {
		if strings.Contains(alert.Message, "Missing SPF") || strings.Contains(alert.Message, "Missing DMARC") {
			t.Errorf("Unexpected false alert on DNS lookup error: %s", alert.Message)
		}
	}

	if savedState.Status == StatusUnknown {
		t.Errorf("Expected email security check to execute")
	}
	if savedState.Status != StatusFailed && savedState.Status != StatusWarning {
		t.Errorf("Expected status Failed or Warning, got %s", savedState.Status)
	}
}

func TestEmailSecurity_MultiSelectorDKIM_NXDOMAIN(t *testing.T) {
	mux := dns.NewServeMux()

	mxRR := &dns.MX{
		Hdr:        dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: 300},
		Preference: 10,
		Mx:         "mail.example.com.",
	}
	spfRR := &dns.TXT{
		Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 300},
		Txt: []string{"v=spf1 include:_spf.example.com ~all"},
	}
	dmarcRR := &dns.TXT{
		Hdr: dns.RR_Header{Name: "_dmarc.example.com.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 300},
		Txt: []string{"v=DMARC1; p=reject;"},
	}
	dkim1RR := &dns.TXT{
		Hdr: dns.RR_Header{Name: "s1._domainkey.example.com.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 300},
		Txt: []string{"v=DKIM1; k=ed25519; p=AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="},
	}

	mux.HandleFunc("example.com.", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		if len(r.Question) > 0 {
			switch r.Question[0].Qtype {
			case dns.TypeMX:
				m.Answer = append(m.Answer, mxRR)
			case dns.TypeTXT:
				m.Answer = append(m.Answer, spfRR)
			}
		}
		_ = w.WriteMsg(m)
	})

	mux.HandleFunc("_dmarc.example.com.", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		if len(r.Question) > 0 && r.Question[0].Qtype == dns.TypeTXT {
			m.Answer = append(m.Answer, dmarcRR)
		}
		_ = w.WriteMsg(m)
	})

	mux.HandleFunc("s1._domainkey.example.com.", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		if len(r.Question) > 0 && r.Question[0].Qtype == dns.TypeTXT {
			m.Answer = append(m.Answer, dkim1RR)
		}
		_ = w.WriteMsg(m)
	})

	// s2 returns NXDOMAIN to simulate unused/alternate candidate selector
	mux.HandleFunc("s2._domainkey.example.com.", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Rcode = dns.RcodeNameError
		_ = w.WriteMsg(m)
	})

	server := &dns.Server{Addr: "127.0.0.1:0", Net: "udp", Handler: mux}
	l, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen packet: %v", err)
	}
	server.PacketConn = l
	defer func() { _ = server.Shutdown() }()
	go func() { _ = server.ActivateAndServe() }()

	app := &AppState{
		config: AppConfig{
			Resolvers: []string{l.LocalAddr().String()},
		},
		Notifier: &NotificationManager{NtfyURL: "https://ntfy.invalid/test"},
	}
	target := DomainConfig{
		Domain:             "example.com",
		Name:               "Example Test",
		CheckEmailSecurity: true,
		MXRecords:          []string{"mail.example.com"},
		DKIMSelectors:      []string{"s1", "s2"},
	}
	state := &CheckState{
		Email: make(map[string]EmailState),
	}

	res := evaluateEmailSecurityForTest(context.Background(), app, target)

	state.Email["example.com"] = res
	savedState := state.Email["example.com"]

	if savedState.Status == StatusUnknown {
		t.Fatalf("Expected EmailState to be saved for example.com")
	}
	if savedState.Status != StatusOK {
		t.Errorf("Expected email status StatusOK when at least one selector is valid, got %s (error: %s)", savedState.Status, savedState.Error)
	}
	if !savedState.SPF {
		t.Errorf("Expected SPF=true, got false")
	}
	if !savedState.DMARC {
		t.Errorf("Expected DMARC=true, got false")
	}
	if !savedState.DKIMExpected {
		t.Errorf("Expected DKIMExpected=true, got false")
	}
	if len(savedState.DKIMValid) != 1 || savedState.DKIMValid[0] != "s1" {
		t.Errorf("Expected DKIMValid=[s1], got %v", savedState.DKIMValid)
	}
	if savedState.Error != "" {
		t.Errorf("Expected empty error, got %q", savedState.Error)
	}
}

func TestMultipleSameTypeDNSTasks_NoKeyCollision(t *testing.T) {
	mux := dns.NewServeMux()
	txt1 := &dns.TXT{
		Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 300},
		Txt: []string{"v=spf1 include:_spf.google.com ~all"},
	}
	txt2 := &dns.TXT{
		Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 300},
		Txt: []string{"google-site-verification=abc123xyz"},
	}

	mux.HandleFunc("example.com.", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		if len(r.Question) > 0 && r.Question[0].Qtype == dns.TypeTXT {
			m.Answer = append(m.Answer, txt1, txt2)
		}
		_ = w.WriteMsg(m)
	})

	server := &dns.Server{Addr: "127.0.0.1:0", Net: "udp", Handler: mux}
	l, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen packet: %v", err)
	}
	server.PacketConn = l
	defer func() { _ = server.Shutdown() }()
	go func() { _ = server.ActivateAndServe() }()

	app := &AppState{
		config:   AppConfig{Resolvers: []string{l.LocalAddr().String()}},
		Notifier: &NotificationManager{NtfyURL: "https://ntfy.invalid/test"},
	}
	state := &CheckState{
		DNS: make(map[string]DNSState),
	}

	task1 := DNSTask{
		Hostname:  "example.com",
		Name:      "SPF TXT",
		Type:      "TXT",
		Expected:  []string{"v=spf1"},
		MatchType: "prefix",
	}
	task2 := DNSTask{
		Hostname:  "example.com",
		Name:      "Google Verification",
		Type:      "TXT",
		Expected:  []string{"google-site-verification=abc123xyz"},
		MatchType: "contains",
	}

	res1 := evaluateDNSForTest(context.Background(), app, task1)
	res2 := evaluateDNSForTest(context.Background(), app, task2)

	state.DNS[task1.Name] = res1
	state.DNS[task2.Name] = res2
	count := len(state.DNS)
	s1 := state.DNS["SPF TXT"]
	s2 := state.DNS["Google Verification"]

	if count != 2 {
		t.Errorf("Expected 2 distinct DNS states, got %d", count)
	}
	if s1.Status == StatusUnknown || s1.Status != StatusOK {
		t.Errorf("Expected task 1 to be StatusOK, got %+v", s1)
	}
	if s2.Status == StatusUnknown || s2.Status != StatusOK {
		t.Errorf("Expected task 2 to be StatusOK, got %+v", s2)
	}
}

func TestDMARC_SubdomainInheritance(t *testing.T) {
	mux := dns.NewServeMux()
	orgDMARC := &dns.TXT{
		Hdr: dns.RR_Header{Name: "_dmarc.example.com.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 300},
		Txt: []string{"v=DMARC1; p=reject; sp=reject; rua=mailto:dmarc@example.com"},
	}

	// Subdomain _dmarc.api.example.com returns empty (NODATA / no record)
	mux.HandleFunc("_dmarc.api.example.com.", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		_ = w.WriteMsg(m)
	})

	// Organizational domain _dmarc.example.com returns valid DMARC record
	mux.HandleFunc("_dmarc.example.com.", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		if len(r.Question) > 0 && r.Question[0].Qtype == dns.TypeTXT {
			m.Answer = append(m.Answer, orgDMARC)
		}
		_ = w.WriteMsg(m)
	})

	server := &dns.Server{Addr: "127.0.0.1:0", Net: "udp", Handler: mux}
	l, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen packet: %v", err)
	}
	server.PacketConn = l
	defer func() { _ = server.Shutdown() }()
	go func() { _ = server.ActivateAndServe() }()

	app := &AppState{
		config:   AppConfig{Resolvers: []string{l.LocalAddr().String()}},
		Notifier: &NotificationManager{NtfyURL: "https://ntfy.invalid/test"},
	}
	target := DomainConfig{
		Domain:             "api.example.com",
		Name:               "API Subdomain",
		CheckEmailSecurity: true,
	}

	state := evaluateEmailSecurityForTest(context.Background(), app, target)
	if !state.DMARC {
		t.Errorf("Expected DMARC to be discovered from parent organizational domain example.com")
	}
}

func TestDMARCTreeWalkQueriesPublicSuffix(t *testing.T) {
	var queried []string
	app := &AppState{
		config: AppConfig{Resolvers: testResolvers()},
		DNSClient: &MockDNSResolver{MockExchangeContext: func(_ context.Context, query *dns.Msg, _ string) (*dns.Msg, time.Duration, error) {
			response := new(dns.Msg)
			response.SetReply(query)
			name := query.Question[0].Name
			if strings.HasPrefix(name, "_dmarc.") {
				queried = append(queried, name)
				if name == "_dmarc.com." {
					record, err := dns.NewRR(`_dmarc.com. 60 IN TXT "v=DMARC1; p=reject; psd=y"`)
					require.NoError(t, err)
					response.Answer = []dns.RR{record}
				}
			}
			return response, 0, nil
		}},
	}
	snapshot := FetchEmailSnapshot(context.Background(), app, DomainConfig{Domain: "a.example.com", CheckEmailSecurity: true})
	require.NoError(t, snapshot.DMARCErr)
	require.Equal(t, []string{"_dmarc.a.example.com.", "_dmarc.example.com.", "_dmarc.com."}, queried)
	require.Equal(t, []string{"v=DMARC1; p=reject; psd=y"}, snapshot.DMARCRecords)
}

func TestDMARCTreeWalkBoundsLongNames(t *testing.T) {
	var queried []string
	app := &AppState{
		config: AppConfig{Resolvers: testResolvers()},
		DNSClient: &MockDNSResolver{MockExchangeContext: func(_ context.Context, query *dns.Msg, _ string) (*dns.Msg, time.Duration, error) {
			response := new(dns.Msg)
			response.SetReply(query)
			if strings.HasPrefix(query.Question[0].Name, "_dmarc.") {
				queried = append(queried, query.Question[0].Name)
			}
			return response, 0, nil
		}},
	}
	domain := "a.b.c.d.e.f.g.h.i.example.com"
	_ = FetchEmailSnapshot(context.Background(), app, DomainConfig{Domain: domain, CheckEmailSecurity: true})
	require.Len(t, queried, 8)
	assert.Equal(t, "_dmarc."+domain+".", queried[0])
	assert.Equal(t, "_dmarc.com.", queried[len(queried)-1])
}

func TestQueryDNSMsg_FailoverOnServerErrors(t *testing.T) {
	// Server 1: Returns REFUSED
	mux1 := dns.NewServeMux()
	mux1.HandleFunc("failover.example.com.", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeRefused)
		_ = w.WriteMsg(m)
	})
	s1 := &dns.Server{Addr: "127.0.0.1:0", Net: "udp", Handler: mux1}
	l1, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen on udp: %v", err)
	}
	s1.PacketConn = l1
	defer func() { _ = s1.Shutdown() }()
	go func() { _ = s1.ActivateAndServe() }()

	// Server 2: Returns NOTIMP
	mux2 := dns.NewServeMux()
	mux2.HandleFunc("failover.example.com.", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeNotImplemented)
		_ = w.WriteMsg(m)
	})
	s2 := &dns.Server{Addr: "127.0.0.1:0", Net: "udp", Handler: mux2}
	l2, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen on udp: %v", err)
	}
	s2.PacketConn = l2
	defer func() { _ = s2.Shutdown() }()
	go func() { _ = s2.ActivateAndServe() }()

	// Server 3: Returns valid A record
	mux3 := dns.NewServeMux()
	aRecord := &dns.A{
		Hdr: dns.RR_Header{Name: "failover.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   net.ParseIP("93.184.215.14"),
	}
	mux3.HandleFunc("failover.example.com.", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = append(m.Answer, aRecord)
		_ = w.WriteMsg(m)
	})
	s3 := &dns.Server{Addr: "127.0.0.1:0", Net: "udp", Handler: mux3}
	l3, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen on udp: %v", err)
	}
	s3.PacketConn = l3
	defer func() { _ = s3.Shutdown() }()
	go func() { _ = s3.ActivateAndServe() }()

	resolvers := []string{l1.LocalAddr().String(), l2.LocalAddr().String(), l3.LocalAddr().String()}
	app := NewAppState(AppConfig{})

	msg, err := queryDNSMsg(context.Background(), app, "failover.example.com", dns.TypeA, resolvers)
	if err != nil {
		t.Fatalf("Expected successful resolution after failovers, got error: %v", err)
	}
	if msg == nil || len(msg.Answer) == 0 {
		t.Fatalf("Expected answers in resolved message, got empty answer section")
	}
	if a, ok := msg.Answer[0].(*dns.A); !ok || !a.A.Equal(net.ParseIP("93.184.215.14")) {
		t.Errorf("Expected A record 93.184.215.14, got %v", msg.Answer[0])
	}
}

func TestValidateRecords_EmptyExpectedWithLiveRecords(t *testing.T) {
	t.Parallel()

	app := &AppState{
		Notifier: &NotificationManager{NtfyURL: "https://ntfy.invalid/test"},
	}

	task := DNSTask{
		Hostname:  "decommissioned.example.com",
		Name:      "Decommissioned Host",
		Type:      "A",
		Expected:  []string{},
		MatchType: "exact",
	}

	// 1. When unexpected live records exist, exact match must fail and alert
	liveRecords := []string{"198.51.100.25"}
	if validateRecords(task, liveRecords) {
		t.Errorf("Expected validateRecords to return false when live records exist for empty expected list, got true")
	}

	// 2. When no live records exist, exact match must succeed
	notifier, ok := app.Notifier.(*NotificationManager)
	require.True(t, ok)
	notifier.alertBatch = nil
	if !validateRecords(task, []string{}) {
		t.Errorf("Expected validateRecords to return true when no live records exist for empty expected list, got false")
	}
}

func TestQueryDNSMsgWithRD_AuthoritativeNonRecursive(t *testing.T) {
	mux := dns.NewServeMux()
	mux.HandleFunc("sub.example.com.", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		// If query has RecursionDesired=true, reject with REFUSED like strict auth servers
		if r.RecursionDesired {
			m.SetRcode(r, dns.RcodeRefused)
		} else {
			m.SetReply(r)
			m.Ns = append(m.Ns, &dns.NS{
				Hdr: dns.RR_Header{Name: "sub.example.com.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300},
				Ns:  "ns1.childzone.com.",
			})
		}
		_ = w.WriteMsg(m)
	})

	server := &dns.Server{Addr: "127.0.0.1:0", Net: "udp", Handler: mux}
	l, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen on udp: %v", err)
	}
	server.PacketConn = l
	defer func() { _ = server.Shutdown() }()
	go func() { _ = server.ActivateAndServe() }()

	resolvers := []string{l.LocalAddr().String()}
	app := NewAppState(AppConfig{})

	// 1. With recursionDesired=false, query succeeds
	msgNonRec, err := queryDNSMsgWithRD(context.Background(), app, "sub.example.com", dns.TypeNS, resolvers, false)
	if err != nil {
		t.Fatalf("Expected query with RD=false to succeed, got %v", err)
	}
	if len(msgNonRec.Ns) == 0 {
		t.Errorf("Expected NS in authority section for referral, got 0")
	}

	// 2. With recursionDesired=true, server returns REFUSED error
	_, errRec := queryDNSMsgWithRD(context.Background(), app, "sub.example.com", dns.TypeNS, resolvers, true)
	if errRec == nil {
		t.Errorf("Expected query with RD=true to fail against strict auth server, got nil error")
	}
}

func TestQueryDNSMsg_NXDOMAIN_ErrorsIs(t *testing.T) {
	t.Parallel()

	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeNameError)
		_ = w.WriteMsg(m)
	})

	server := &dns.Server{Addr: "127.0.0.1:0", Net: "udp", Handler: mux}
	l, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen on udp: %v", err)
	}
	server.PacketConn = l
	defer func() { _ = server.Shutdown() }()
	go func() { _ = server.ActivateAndServe() }()

	resolvers := []string{l.LocalAddr().String()}
	app := NewAppState(AppConfig{})

	_, qErr := queryDNSMsgWithRD(context.Background(), app, "nonexistent.example.com", dns.TypeA, resolvers, true)
	if qErr == nil {
		t.Fatalf("Expected NXDOMAIN error, got nil")
	}

	if !errors.Is(qErr, ErrNXDOMAIN) {
		t.Errorf("Expected errors.Is(qErr, ErrNXDOMAIN) to be true, got error: %v", qErr)
	}
}

func TestQueryDNSMsg_QuestionEchoValidation(t *testing.T) {
	t.Parallel()

	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Question = nil // Strip question section to simulate broken server or spoofed response
		m.Answer = append(m.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   net.ParseIP("93.184.215.14"),
		})
		_ = w.WriteMsg(m)
	})

	server := &dns.Server{Addr: "127.0.0.1:0", Net: "udp", Handler: mux}
	l, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen on udp: %v", err)
	}
	server.PacketConn = l
	defer func() { _ = server.Shutdown() }()
	go func() { _ = server.ActivateAndServe() }()

	resolvers := []string{l.LocalAddr().String()}
	app := NewAppState(AppConfig{})

	_, qErr := queryDNSMsgWithRD(context.Background(), app, "example.com", dns.TypeA, resolvers, true)
	if qErr == nil {
		t.Fatalf("Expected error when response question section is stripped, got success")
	}

	if !strings.Contains(qErr.Error(), "mismatch or missing") {
		t.Errorf("Expected question mismatch error, got: %v", qErr)
	}
}

func TestQueryDNSMsgRetriesTruncatedAnswerOverInjectedTCP(t *testing.T) {
	t.Parallel()
	const domain = "example.com"
	app := NewAppState(AppConfig{})
	tcpCalled := false
	app.DNSClient = &MockDNSResolver{MockExchangeContext: func(_ context.Context, query *dns.Msg, _ string) (*dns.Msg, time.Duration, error) {
		response := new(dns.Msg)
		response.SetReply(query)
		response.Truncated = true
		return response, 0, nil
	}}
	app.DNSTCPClient = &MockDNSResolver{MockExchangeContext: func(_ context.Context, query *dns.Msg, _ string) (*dns.Msg, time.Duration, error) {
		tcpCalled = true
		response := new(dns.Msg)
		response.SetReply(query)
		response.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: dns.Fqdn(domain), Rrtype: dns.TypeA, Class: dns.ClassINET}, A: net.ParseIP("192.0.2.1")}}
		return response, 0, nil
	}}

	response, err := queryDNSMsg(context.Background(), app, domain, dns.TypeA, []string{"192.0.2.53"})
	require.NoError(t, err)
	require.True(t, tcpCalled)
	require.Len(t, response.Answer, 1)

	app.DNSTCPClient = nil
	_, err = queryDNSMsg(context.Background(), app, domain, dns.TypeA, []string{"192.0.2.53"})
	require.ErrorContains(t, err, "TCP resolver is not configured")
}

func TestQueryDNSMsgUsesFreshIDsAndRejectsWrongQuestionClass(t *testing.T) {
	t.Parallel()
	app := NewAppState(AppConfig{})
	ids := make(map[uint16]bool)
	app.DNSClient = &MockDNSResolver{MockExchangeContext: func(_ context.Context, query *dns.Msg, _ string) (*dns.Msg, time.Duration, error) {
		ids[query.Id] = true
		response := new(dns.Msg)
		response.SetReply(query)
		return response, 0, nil
	}}
	for range 16 {
		_, err := queryDNSMsg(context.Background(), app, "example.com", dns.TypeA, []string{"192.0.2.53"})
		require.NoError(t, err)
	}
	require.Greater(t, len(ids), 1, "DNS request IDs must not be fixed across queries")

	app.DNSClient = &MockDNSResolver{MockExchangeContext: func(_ context.Context, query *dns.Msg, _ string) (*dns.Msg, time.Duration, error) {
		response := new(dns.Msg)
		response.SetReply(query)
		response.Question[0].Qclass = dns.ClassCHAOS
		return response, 0, nil
	}}
	_, err := queryDNSMsg(context.Background(), app, "example.com", dns.TypeA, []string{"192.0.2.53"})
	require.ErrorContains(t, err, "mismatch")
}

func TestDNSAnswerOwnerFiltering(t *testing.T) {
	tests := []struct {
		name    string
		qtype   uint16
		answers []string
		want    []string
	}{
		{
			name: "direct A ignores unrelated answer", qtype: dns.TypeA,
			answers: []string{"other.example. 60 IN A 192.0.2.1", "host.example. 60 IN A 192.0.2.2"},
			want:    []string{"192.0.2.2"},
		},
		{
			name: "direct A ignores wrong DNS class", qtype: dns.TypeA,
			answers: []string{"host.example. 60 CH A 192.0.2.1", "host.example. 60 IN A 192.0.2.2"},
			want:    []string{"192.0.2.2"},
		},
		{
			name: "CNAME chain accepts target and rejects unrelated answer", qtype: dns.TypeA,
			answers: []string{"final.example. 60 IN A 192.0.2.3", "host.example. 60 IN CNAME middle.example.", "middle.example. 60 IN CNAME final.example.", "other.example. 60 IN A 192.0.2.4"},
			want:    []string{"192.0.2.3"},
		},
		{
			name: "wrong-class CNAME cannot authorize target", qtype: dns.TypeA,
			answers: []string{"host.example. 60 CH CNAME target.example.", "target.example. 60 IN A 192.0.2.3"},
		},
		{
			name: "CNAME check uses immediate target", qtype: dns.TypeCNAME,
			answers: []string{"host.example. 60 IN CNAME middle.example.", "middle.example. 60 IN CNAME final.example."},
			want:    []string{"middle.example"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			app := &AppState{DNSClient: &MockDNSResolver{MockExchangeContext: func(_ context.Context, query *dns.Msg, _ string) (*dns.Msg, time.Duration, error) {
				response := new(dns.Msg)
				response.SetReply(query)
				for _, raw := range tc.answers {
					record, err := dns.NewRR(raw)
					require.NoError(t, err)
					response.Answer = append(response.Answer, record)
				}
				return response, 0, nil
			}}}

			got, err := queryDNS(context.Background(), app, "host.example", tc.qtype, []string{"192.0.2.53"})
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

// Create a cycle between loop.example. and alias.example.

// For CAA or other types, return empty Answer (NODATA)

func evaluateNSHealthForTest(ctx context.Context, app *AppState, target DomainConfig) NSHealthResult {
	if !target.VerifyNSHealth || len(target.ExpectedNS) == 0 {
		return NSHealthResult{}
	}
	snapshots := FetchNSHealthSnapshots(ctx, app, target)
	status, _ := EvaluateNSHealth(target, snapshots)
	var servers []NSHealthServerResult
	for _, srvSnap := range snapshots {
		errStr := ""
		if srvSnap.Err != nil {
			errStr = srvSnap.Err.Error()
		}
		servers = append(servers, NSHealthServerResult{
			Nameserver:    srvSnap.Nameserver,
			IsPrimary:     srvSnap.IsPrimary,
			Authoritative: srvSnap.Authoritative,
			HasSOA:        srvSnap.HasSOA,
			SOASerial:     srvSnap.SOASerial,
			HasDNSKEY:     srvSnap.HasDNSKEY,
			DNSKEYMatch:   true,
			Error:         errStr,
		})
	}
	return NSHealthResult{
		Valid:   status != StatusFailed,
		Primary: target.ExpectedNS[0],
		Servers: servers,
	}
}

func TestEvaluateNSHealth(t *testing.T) {
	t.Parallel()

	startMockNSWithKeys := func(serial uint32, authoritative bool, dnskeys []dns.RR) (string, func()) {
		mux := dns.NewServeMux()
		mux.HandleFunc("example.com.", func(w dns.ResponseWriter, r *dns.Msg) {
			m := new(dns.Msg)
			m.SetReply(r)
			m.Authoritative = authoritative
			if len(r.Question) > 0 {
				q := r.Question[0]
				switch q.Qtype {
				case dns.TypeSOA:
					soaStr := "example.com. 3600 IN SOA ns1.example.com. hostmaster.example.com. " + strconv.FormatUint(uint64(serial), 10) + " 7200 3600 1209600 3600"
					rr, _ := dns.NewRR(soaStr)
					m.Answer = append(m.Answer, rr)
				case dns.TypeDNSKEY:
					for _, k := range dnskeys {
						if k != nil {
							m.Answer = append(m.Answer, dns.Copy(k))
						}
					}
				}
			}
			_ = w.WriteMsg(m)
		})
		l, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("failed to listen packet: %v", err)
		}
		srv := &dns.Server{PacketConn: l, Handler: mux}
		go func() { _ = srv.ActivateAndServe() }()
		return l.LocalAddr().String(), func() { _ = srv.Shutdown() }
	}

	primaryKey := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags:     257,
		Protocol:  3,
		Algorithm: dns.ECDSAP256SHA256,
		PublicKey: "mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9UxUovEsok4rA==",
	}
	independentKey := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags:     257,
		Protocol:  3,
		Algorithm: dns.ECDSAP256SHA256,
		PublicKey: "ZtsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9UxUovEsok4rA==",
	}

	// 1. Happy Path: Dumb Secondary replicates primary's exact DNSKEYs
	t.Run("HappyPathReplicatedDNSKEY", func(t *testing.T) {
		pAddr, pClose := startMockNSWithKeys(2026090101, true, []dns.RR{primaryKey})
		defer pClose()
		sAddr, sClose := startMockNSWithKeys(2026090101, true, []dns.RR{primaryKey})
		defer sClose()

		app := &AppState{config: AppConfig{Resolvers: []string{pAddr}}, Notifier: &NotificationManager{NtfyURL: "https://ntfy.invalid/test"}}
		target := DomainConfig{
			Domain:         "example.com",
			Name:           "Sync Domain",
			ExpectedNS:     []string{pAddr},
			SecondaryNS:    []string{sAddr},
			VerifyNSHealth: true,
			DNSSEC:         true,
		}
		res := evaluateNSHealthForTest(context.Background(), app, target)

		if !res.Valid {
			t.Fatalf("Expected valid NSHealth for identical replicated DNSKEY")
		}
	})

	// 2. Happy Path: Unsigned zone (neither primary nor secondary has DNSKEY)
	t.Run("HappyPathUnsignedZone", func(t *testing.T) {
		pAddr, pClose := startMockNSWithKeys(2026090101, true, nil)
		defer pClose()
		sAddr, sClose := startMockNSWithKeys(2026090101, true, nil)
		defer sClose()

		app := &AppState{config: AppConfig{Resolvers: []string{pAddr}}, Notifier: &NotificationManager{NtfyURL: "https://ntfy.invalid/test"}}
		target := DomainConfig{
			Domain:         "example.com",
			Name:           "Unsigned Domain",
			ExpectedNS:     []string{pAddr},
			SecondaryNS:    []string{sAddr},
			VerifyNSHealth: true,
			DNSSEC:         true,
		}
		res := evaluateNSHealthForTest(context.Background(), app, target)

		if !res.Valid {
			t.Fatalf("Expected valid NSHealth for unsigned zone without DNSKEY")
		}
	})

	// 3. DNSKEY Mismatch (Secondary generates its own keys / smart secondary) -> REJECTED
	t.Run("DNSKEYMismatchIndependentKeys", func(t *testing.T) {
		pAddr, pClose := startMockNSWithKeys(2026090101, true, []dns.RR{primaryKey})
		defer pClose()
		sAddr, sClose := startMockNSWithKeys(2026090101, true, []dns.RR{independentKey}) // Distinct key!
		defer sClose()

		app := &AppState{config: AppConfig{Resolvers: []string{pAddr}}, Notifier: &NotificationManager{NtfyURL: "https://ntfy.invalid/test"}}
		target := DomainConfig{
			Domain:         "example.com",
			Name:           "Mismatched DNSKEY Domain",
			ExpectedNS:     []string{pAddr},
			SecondaryNS:    []string{sAddr},
			VerifyNSHealth: true,
			DNSSEC:         true,
		}
		res := evaluateNSHealthForTest(context.Background(), app, target)

		if res.Valid {
			t.Errorf("Expected NSHealth to be invalid when secondary uses its own DNSKEYs")
		}
	})

	// 4. DNSKEY Unexpected (Primary is unsigned, but secondary serves DNSKEY) -> REJECTED
	t.Run("DNSKEYUnexpectedOnSecondary", func(t *testing.T) {
		pAddr, pClose := startMockNSWithKeys(2026090101, true, nil) // Unsigned primary
		defer pClose()
		sAddr, sClose := startMockNSWithKeys(2026090101, true, []dns.RR{independentKey}) // Signed secondary!
		defer sClose()

		app := &AppState{config: AppConfig{Resolvers: []string{pAddr}}, Notifier: &NotificationManager{NtfyURL: "https://ntfy.invalid/test"}}
		target := DomainConfig{
			Domain:         "example.com",
			Name:           "Unexpected DNSKEY Domain",
			ExpectedNS:     []string{pAddr},
			SecondaryNS:    []string{sAddr},
			VerifyNSHealth: true,
			DNSSEC:         true,
		}
		res := evaluateNSHealthForTest(context.Background(), app, target)

		if res.Valid {
			t.Errorf("Expected NSHealth to be invalid when secondary serves unexpected DNSKEY")
		}
	})

	// DNSKEY comparison is requested only for DNSSEC-enabled NS health checks.
	t.Run("DNSKEYIgnoredWhenDNSSECIsFalse", func(t *testing.T) {
		pAddr, pClose := startMockNSWithKeys(2026090101, true, nil) // Unsigned primary
		defer pClose()
		sAddr, sClose := startMockNSWithKeys(2026090101, true, []dns.RR{independentKey}) // Secondary serves DNSKEY!
		defer sClose()

		app := &AppState{config: AppConfig{Resolvers: []string{pAddr}}, Notifier: &NotificationManager{NtfyURL: "https://ntfy.invalid/test"}}
		target := DomainConfig{
			Domain:         "example.com",
			Name:           "Dumb Secondary Unsigned Violation",
			ExpectedNS:     []string{pAddr},
			SecondaryNS:    []string{sAddr},
			VerifyNSHealth: true,
			DNSSEC:         false, // Explicitly false!
		}
		res := evaluateNSHealthForTest(context.Background(), app, target)

		if !res.Valid {
			t.Errorf("Expected NSHealth to skip DNSKEY when DNSSEC=false")
		}
	})

	// 6. DNSKEY Missing on Secondary when Primary is signed -> REJECTED
	t.Run("DNSKEYMissingOnSecondary", func(t *testing.T) {
		pAddr, pClose := startMockNSWithKeys(2026090101, true, []dns.RR{primaryKey})
		defer pClose()
		sAddr, sClose := startMockNSWithKeys(2026090101, true, nil) // Missing DNSKEY!
		defer sClose()

		app := &AppState{config: AppConfig{Resolvers: []string{pAddr}}, Notifier: &NotificationManager{NtfyURL: "https://ntfy.invalid/test"}}
		target := DomainConfig{
			Domain:         "example.com",
			Name:           "Missing DNSKEY Domain",
			ExpectedNS:     []string{pAddr},
			SecondaryNS:    []string{sAddr},
			VerifyNSHealth: true,
			DNSSEC:         true,
		}
		res := evaluateNSHealthForTest(context.Background(), app, target)

		if res.Valid {
			t.Errorf("Expected NSHealth to be invalid on missing DNSKEY")
		}
	})

	// 6. Secondary SOA Lag (stale zone transfer)
	t.Run("SecondarySOALag", func(t *testing.T) {
		pAddr, pClose := startMockNSWithKeys(2026090102, true, nil)
		defer pClose()
		sAddr, sClose := startMockNSWithKeys(2026090101, true, nil) // 2026090101 < 2026090102
		defer sClose()

		app := &AppState{config: AppConfig{Resolvers: []string{pAddr}}, Notifier: &NotificationManager{NtfyURL: "https://ntfy.invalid/test"}}
		target := DomainConfig{
			Domain:         "example.com",
			Name:           "Lagging Domain",
			ExpectedNS:     []string{pAddr},
			SecondaryNS:    []string{sAddr},
			VerifyNSHealth: true,
		}
		res := evaluateNSHealthForTest(context.Background(), app, target)

		status, condition := EvaluateNSHealth(target, FetchNSHealthSnapshots(context.Background(), app, target))
		assert.Equal(t, StatusWarning, status)
		assert.Equal(t, CodeNSSOALags, condition.Code)
		assert.True(t, res.Valid)
	})

	// 7. Happy Path: Primary Only (secondary_ns omitted -> secondary checks skipped)
	t.Run("HappyPathPrimaryOnly", func(t *testing.T) {
		pAddr, pClose := startMockNSWithKeys(2026090101, true, []dns.RR{primaryKey})
		defer pClose()

		app := &AppState{config: AppConfig{Resolvers: []string{pAddr}}, Notifier: &NotificationManager{NtfyURL: "https://ntfy.invalid/test"}}
		target := DomainConfig{
			Domain:         "example.com",
			Name:           "Primary Only Domain",
			ExpectedNS:     []string{pAddr},
			SecondaryNS:    nil, // secondary_ns is omitted!
			VerifyNSHealth: true,
			DNSSEC:         true,
		}
		res := evaluateNSHealthForTest(context.Background(), app, target)

		if !res.Valid {
			t.Fatalf("Expected valid NSHealth for primary-only nameserver check")
		}
		if len(res.Servers) != 1 {
			t.Errorf("Expected exactly 1 server (primary), got %d", len(res.Servers))
		}
		if !res.Servers[0].IsPrimary {
			t.Errorf("Expected server to be marked primary")
		}
		if !res.Servers[0].Authoritative {
			t.Errorf("Expected primary server to be authoritative")
		}
		if res.Servers[0].SOASerial != 2026090101 {
			t.Errorf("Expected SOA serial 2026090101, got %d", res.Servers[0].SOASerial)
		}
	})

	// 8. Primary Only Non-Authoritative (fails and alerts even without secondary_ns)
	t.Run("PrimaryOnlyNonAuthoritative", func(t *testing.T) {
		pAddr, pClose := startMockNSWithKeys(2026090101, false, nil) // AA=0!
		defer pClose()

		app := &AppState{config: AppConfig{Resolvers: []string{pAddr}}, Notifier: &NotificationManager{NtfyURL: "https://ntfy.invalid/test"}}
		target := DomainConfig{
			Domain:         "example.com",
			Name:           "Non-Authoritative Primary Domain",
			ExpectedNS:     []string{pAddr},
			SecondaryNS:    nil, // secondary_ns is omitted!
			VerifyNSHealth: true,
		}
		res := evaluateNSHealthForTest(context.Background(), app, target)

		if res.Valid {
			t.Fatalf("Expected NSHealth to be invalid when primary is not authoritative")
		}
	})

	// 9. Primary Missing SOA Record (fails and alerts)
	t.Run("PrimaryMissingSOA", func(t *testing.T) {
		mux := dns.NewServeMux()
		mux.HandleFunc("example.com.", func(w dns.ResponseWriter, r *dns.Msg) {
			m := new(dns.Msg)
			m.SetReply(r)
			m.Authoritative = true
			// Deliberately empty Answer and Ns sections (no SOA)
			_ = w.WriteMsg(m)
		})
		l, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("failed to listen packet: %v", err)
		}
		srv := &dns.Server{PacketConn: l, Handler: mux}
		go func() { _ = srv.ActivateAndServe() }()
		defer func() { _ = srv.Shutdown() }()

		pAddr := l.LocalAddr().String()
		app := &AppState{config: AppConfig{Resolvers: []string{pAddr}}, Notifier: &NotificationManager{NtfyURL: "https://ntfy.invalid/test"}}
		target := DomainConfig{
			Domain:         "example.com",
			Name:           "Missing SOA Primary Domain",
			ExpectedNS:     []string{pAddr},
			VerifyNSHealth: true,
		}
		res := evaluateNSHealthForTest(context.Background(), app, target)

		if res.Valid {
			t.Fatalf("Expected NSHealth to be invalid when primary returns no SOA")
		}
		if res.Servers[0].Error != "No SOA record returned in answer or authority sections" {
			t.Errorf("Expected specific missing SOA error, got %q", res.Servers[0].Error)
		}
	})

	// 10. Primary SOA in Authority Section (standard DNS behavior, succeeds and parses serial)
	t.Run("PrimarySOAInAuthoritySection", func(t *testing.T) {
		mux := dns.NewServeMux()
		mux.HandleFunc("example.com.", func(w dns.ResponseWriter, r *dns.Msg) {
			m := new(dns.Msg)
			m.SetReply(r)
			m.Authoritative = true
			// SOA placed in Authority (Ns) section, NOT Answer section
			m.Ns = []dns.RR{
				&dns.SOA{
					Hdr:     dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 3600},
					Ns:      "ns1.example.com.",
					Mbox:    "hostmaster.example.com.",
					Serial:  2026090501,
					Refresh: 3600,
					Retry:   600,
					Expire:  86400,
					Minttl:  300,
				},
			}
			_ = w.WriteMsg(m)
		})
		l, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("failed to listen packet: %v", err)
		}
		srv := &dns.Server{PacketConn: l, Handler: mux}
		go func() { _ = srv.ActivateAndServe() }()
		defer func() { _ = srv.Shutdown() }()

		pAddr := l.LocalAddr().String()
		app := &AppState{config: AppConfig{Resolvers: []string{pAddr}}, Notifier: &NotificationManager{NtfyURL: "https://ntfy.invalid/test"}}
		target := DomainConfig{
			Domain:         "example.com",
			Name:           "SOA In Authority Domain",
			ExpectedNS:     []string{pAddr},
			VerifyNSHealth: true,
		}
		res := evaluateNSHealthForTest(context.Background(), app, target)

		if !res.Valid {
			t.Fatalf("Expected NSHealth to be valid when primary returns SOA in Ns section, got invalid")
		}
		if res.Servers[0].SOASerial != 2026090501 {
			t.Errorf("Expected SOA serial 2026090501, got %d", res.Servers[0].SOASerial)
		}
	})
}

func TestNSHealthChecksAllExpectedServersAndSOAOwner(t *testing.T) {
	queries := make(map[string]int)
	app := &AppState{DNSClient: &MockDNSResolver{MockExchangeContext: func(_ context.Context, q *dns.Msg, address string) (*dns.Msg, time.Duration, error) {
		queries[address]++
		response := new(dns.Msg)
		response.SetReply(q)
		response.Authoritative = true
		if q.Question[0].Qtype == dns.TypeSOA {
			owner := "example.com."
			if address == "93.184.216.35:53" {
				owner = "other.example."
			}
			record, _ := dns.NewRR(owner + " 3600 IN SOA ns.example.com. hostmaster.example.com. 1 7200 3600 1209600 3600")
			response.Answer = []dns.RR{record}
		}
		return response, 0, nil
	}}}
	target := DomainConfig{Domain: "example.com", ExpectedNS: []string{"93.184.216.34", "93.184.216.35"}, SecondaryNS: []string{"93.184.216.34"}, VerifyNSHealth: true}
	snapshots := FetchNSHealthSnapshots(context.Background(), app, target)
	require.Len(t, snapshots, 2)
	assert.Equal(t, 1, queries["93.184.216.34:53"])
	assert.Equal(t, 1, queries["93.184.216.35:53"])
	assert.False(t, snapshots[1].HasSOA)
	status, condition := EvaluateNSHealth(target, snapshots)
	assert.Equal(t, StatusFailed, status)
	assert.Equal(t, CodeNSMissingSOA, condition.Code)
}

func TestNSHealthIgnoresWrongClassSOAAndDNSKEY(t *testing.T) {
	app := &AppState{DNSClient: &MockDNSResolver{MockExchangeContext: func(_ context.Context, query *dns.Msg, _ string) (*dns.Msg, time.Duration, error) {
		response := new(dns.Msg)
		response.SetReply(query)
		response.Authoritative = true
		switch query.Question[0].Qtype {
		case dns.TypeSOA:
			rr, err := dns.NewRR("example.com. 60 CH SOA ns.example.com. hostmaster.example.com. 1 7200 3600 1209600 3600")
			require.NoError(t, err)
			response.Answer = []dns.RR{rr}
		case dns.TypeDNSKEY:
			response.Answer = []dns.RR{&dns.DNSKEY{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassCHAOS}, Flags: 257, Protocol: 3, Algorithm: dns.ECDSAP256SHA256, PublicKey: "AQEBAQ=="}}
		}
		return response, 0, nil
	}}}
	target := DomainConfig{Domain: "example.com", ExpectedNS: []string{"192.0.2.53"}, VerifyNSHealth: true, DNSSEC: true}
	snapshots := FetchNSHealthSnapshots(context.Background(), app, target)
	require.Len(t, snapshots, 1)
	assert.False(t, snapshots[0].HasSOA)
	assert.False(t, snapshots[0].HasDNSKEY)
	status, condition := EvaluateNSHealth(target, snapshots)
	assert.Equal(t, StatusFailed, status)
	assert.Equal(t, CodeNSMissingSOA, condition.Code)
}

func TestDNS_MultiIPCanonicalSorting(t *testing.T) {
	mux := dns.NewServeMux()
	mux.HandleFunc("multi.example.com.", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		switch r.Question[0].Qtype {
		case dns.TypeA:
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: "multi.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("198.51.100.2"),
			})
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: "multi.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("192.0.2.1"),
			})
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: "multi.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("192.0.2.1"), // duplicate
			})
		case dns.TypeAAAA:
			m.Answer = append(m.Answer, &dns.AAAA{
				Hdr:  dns.RR_Header{Name: "multi.example.com.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 300},
				AAAA: net.ParseIP("2001:db8::1"),
			})
		}
		_ = w.WriteMsg(m)
	})

	l, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen packet: %v", err)
	}
	srv := &dns.Server{PacketConn: l, Handler: mux}
	go func() { _ = srv.ActivateAndServe() }()
	defer func() { _ = srv.Shutdown() }()

	pAddr := l.LocalAddr().String()
	app := &AppState{
		config: AppConfig{
			Resolvers: []string{pAddr},
		},
		Notifier: &NotificationManager{NtfyURL: "https://ntfy.invalid/test"},
	}
	state := &CheckState{
		DNS: make(map[string]DNSState),
	}

	task := DNSTask{
		Hostname: "multi.example.com",
		Name:     "Multi IP Test",
		Type:     "IP",
		Expected: []string{"192.0.2.1", "198.51.100.2", "2001:db8::1"},
	}

	res := evaluateDNSForTest(context.Background(), app, task)

	state.DNS[task.Name] = res
	res = state.DNS["Multi IP Test"]

	if res.Error != "" {
		t.Fatalf("expected state for 'Multi IP Test' to exist")
	}
	if res.Status != StatusOK {
		t.Fatalf("expected StatusOK, got %s (error: %s)", res.Status, res.Error)
	}
	expectedOrder := []string{"192.0.2.1", "198.51.100.2", "2001:db8::1"}
	if !slices.Equal(res.Found, expectedOrder) {
		t.Errorf("expected sorted and deduplicated Found %v, got %v", expectedOrder, res.Found)
	}
}

func TestDNS_CNAMEFlattening_DirectIPExpected(t *testing.T) {
	mux := dns.NewServeMux()
	mux.HandleFunc("flattened.example.com.", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		if r.Question[0].Qtype == dns.TypeA {
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: "flattened.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("192.0.2.99"),
			})
		}
		_ = w.WriteMsg(m)
	})

	l, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen packet: %v", err)
	}
	srv := &dns.Server{PacketConn: l, Handler: mux}
	go func() { _ = srv.ActivateAndServe() }()
	defer func() { _ = srv.Shutdown() }()

	pAddr := l.LocalAddr().String()
	app := &AppState{
		config: AppConfig{
			Resolvers: []string{pAddr},
		},
		Notifier: &NotificationManager{NtfyURL: "https://ntfy.invalid/test"},
	}
	state := &CheckState{
		DNS: make(map[string]DNSState),
	}

	task := DNSTask{
		Hostname: "flattened.example.com",
		Name:     "Flattened CNAME Direct IP",
		Type:     "CNAME",
		Expected: []string{"192.0.2.99"},
	}

	res := evaluateDNSForTest(context.Background(), app, task)

	state.DNS[task.Name] = res
	res = state.DNS["Flattened CNAME Direct IP"]

	if res.Error != "" {
		t.Fatalf("expected state for 'Flattened CNAME Direct IP' to exist")
	}
	if res.Status != StatusOK {
		t.Errorf("expected StatusOK, got %s (error: %s)", res.Status, res.Error)
	}
	if len(res.Found) != 1 || res.Found[0] != "192.0.2.99" {
		t.Errorf("expected Found [192.0.2.99], got %v", res.Found)
	}
}

func TestDNS_ValidateRecords_MultiIPConsolidatedAlert(t *testing.T) {
	task := DNSTask{
		Hostname: "cluster.example.com",
		Name:     "Cluster Multi IP",
		Type:     "IP",
		Expected: []string{"192.0.2.1", "192.0.2.2"},
	}

	// 2 missing ("192.0.2.1", "192.0.2.2"), 2 unauthorized ("198.51.100.1", "198.51.100.2")
	found := []string{"198.51.100.1", "198.51.100.2"}

	valid, reason, _ := validateRecordsWithReason(task, found)
	if valid {
		t.Fatalf("expected validateRecords to return false on mismatch")
	}

	if !strings.Contains(reason, "192.0.2.1, 192.0.2.2") {
		t.Errorf("expected missing alert to join missing IPs, got: %s", reason)
	}

	if !strings.Contains(reason, "198.51.100.1, 198.51.100.2") {
		t.Errorf("expected unauthorized alert to join unauth IPs, got: %s", reason)
	}
}

func TestNilSafety_AppState(t *testing.T) {
	// 1. Nil AppState
	var nilApp *AppState
	resolvers := nilApp.Resolvers()
	if len(resolvers) == 0 {
		t.Errorf("expected fallback resolvers for nil AppState")
	}
	nilApp.SafeDispatch("test message", "redacted", PriorityHigh, "tag", "domain", "name")

	// 2. AppState with nil Config
	appNilCfg := &AppState{Notifier: nil}
	res2 := appNilCfg.Resolvers()
	if len(res2) == 0 {
		t.Errorf("expected fallback resolvers for AppState with nil Config")
	}
	appNilCfg.SafeDispatch("test message", "redacted", PriorityHigh, "tag", "domain", "name")

	// 3. AppState with empty Config.Resolvers
	appEmptyRes := &AppState{config: AppConfig{Resolvers: []string{}}}
	res3 := appEmptyRes.Resolvers()
	if len(res3) == 0 {
		t.Errorf("expected fallback resolvers for empty Resolvers slice")
	}
}

func TestNilSafety_EvaluationsWithNilApp(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// 3. evaluateDNSSEC with nil app
	dnssecCfg := DomainConfig{
		Domain: "example.com",
		DNSSEC: true,
	}
	dnssecRes := evaluateDNSSECForTest(ctx, nil, dnssecCfg)
	if dnssecRes.Source == "" {
		t.Errorf("expected non-nil DNSSECResult")
	}

	// 4. evaluateDNS with nil app
	dnsTask := DNSTask{
		Hostname: "example.com",
		Name:     "example-a",
		Type:     "A",
		Expected: StringList{"93.184.216.34"},
	}
	dnsState := evaluateDNSForTest(ctx, nil, dnsTask)
	if dnsState.Status == StatusUnknown {
		t.Errorf("expected non-nil DNSState")
	}

	// 5. evaluateEmailSecurity with nil app
	emailCfg := DomainConfig{
		Domain:             "example.com",
		CheckEmailSecurity: true,
		MXRecords:          []string{"mail.example.com"},
	}
	emailState := evaluateEmailSecurityForTest(ctx, nil, emailCfg)
	if emailState.Status == StatusUnknown {
		t.Errorf("expected non-nil EmailState")
	}

	// 7. evaluateNSHealth with nil app
	nsCfg := DomainConfig{
		Domain:         "example.com",
		VerifyNSHealth: true,
		ExpectedNS:     []string{"ns1.example.com"},
	}
	nsRes := evaluateNSHealthForTest(ctx, nil, nsCfg)
	if nsRes.Primary == "" {
		t.Errorf("expected non-nil NSHealthResult")
	}
}

func TestValidateMX_TransientErrorNoFalseAlert(t *testing.T) {
	app := &AppState{
		config: AppConfig{
			Resolvers: []string{"192.0.2.1:53"}, // Unreachable
		},
		Notifier: &NotificationManager{NtfyURL: "https://ntfy.invalid/test"},
	}
	target := DomainConfig{
		Domain:             "transient-error.example.com",
		CheckEmailSecurity: true,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()

	state := evaluateEmailSecurityForTest(ctx, app, target)
	if state.Status != StatusFailed {
		t.Fatalf("Expected error on unreachable resolver")
	}
	if len(state.MX) != 0 {
		t.Errorf("Expected 0 MX records on error, got %v", state.MX)
	}
	if state.Condition.Code != CodeDNSLookupFailed {
		t.Errorf("Expected CodeDNSLookupFailed, got %v", state.Condition.Code)
	}
}

func TestDNSState_ErrorPopulatedOnMismatch(t *testing.T) {
	task := DNSTask{
		Hostname: "test.example.com",
		Name:     "Test Mismatch Task",
		Type:     "A",
		Expected: []string{"192.0.2.1"},
	}

	valid, reason, _ := validateRecordsWithReason(task, []string{"198.51.100.1"})
	if valid {
		t.Fatalf("expected mismatch to return valid=false")
	}
	if reason == "" || !strings.Contains(reason, "missing expected records") {
		t.Errorf("expected reason to document missing records, got: %q", reason)
	}

	// Also verify prefix mismatch reason
	prefixTask := DNSTask{
		Hostname:  "prefix.example.com",
		Name:      "Prefix Task",
		Type:      "TXT",
		MatchType: "prefix",
		Expected:  []string{"v=spf1"},
	}
	pValid, pReason, _ := validateRecordsWithReason(prefixTask, []string{"other text"})
	if pValid {
		t.Fatalf("expected prefix mismatch to return valid=false")
	}
	if !strings.Contains(pReason, "prefix") {
		t.Errorf("expected prefix mismatch reason, got: %q", pReason)
	}
}

func TestDNS_ResolverIndexOverflow(t *testing.T) {
	app := &AppState{}

	resolvers := []string{"1.1.1.1", "8.8.8.8", "9.9.9.9"}
	// Set index near max uint32 boundary where signed int overflow would occur on 32-bit systems
	app.GlobalResolverIndex.Store(math.MaxUint32 - 2)

	indices := make(map[int]int)
	for range 10 {
		startIdx := int(app.GlobalResolverIndex.Add(1) % uint32(len(resolvers)))
		if startIdx < 0 || startIdx >= len(resolvers) {
			t.Fatalf("startIdx %d out of bounds [0, %d)", startIdx, len(resolvers))
		}
		indices[startIdx]++
	}

	// Verify all resolvers are utilized in round-robin and never pinned to index 0
	if len(indices) < len(resolvers) {
		t.Errorf("expected round-robin across all %d resolvers, but only got %d unique indices: %v", len(resolvers), len(indices), indices)
	}
}

func TestEvaluateDNSSECExtensive(t *testing.T) {
	status, condition, _ := EvaluateDNSSEC(DomainConfig{Domain: "example.com", DNSSEC: true}, DNSSECSnapshot{})
	assert.Equal(t, StatusFailed, status)
	require.NotNil(t, condition)
	assert.Equal(t, CodeDNSSECNetworkError, condition.Code)

	snapshot := FetchDNSSECSnapshot(context.Background(), nil, DomainConfig{Domain: "example.com", DNSSEC: true})
	assert.Equal(t, MsgErrDNSSECResolverNotConfigured, snapshot.Result.Error)
	status, condition, _ = EvaluateDNSSEC(DomainConfig{Domain: "example.com", DNSSEC: true}, snapshot)
	assert.Equal(t, StatusFailed, status)
	require.NotNil(t, condition)
	assert.Equal(t, CodeDNSSECNetworkError, condition.Code)
}

func TestEvaluateDNSSECConditions(t *testing.T) {
	base := DNSSECResult{Source: DNSSECSourceLocalDoH, HasDS: true, HasDNSKEY: true, DSMatchesDNSKEY: true, RRSIGValid: true, ChainIntact: true, Valid: true}
	for _, tc := range []struct {
		name string
		edit func(*DNSSECResult)
		want CheckStatus
		code ResultCode
	}{
		{name: "verified", want: StatusOK, code: CodeDNSSECVerified},
		{name: "transport unavailable", edit: func(r *DNSSECResult) { r.Valid = false; r.NetworkError = true; r.Error = "resolver timeout" }, want: StatusFailed, code: CodeDNSSECNetworkError},
		{name: "unsigned", edit: func(r *DNSSECResult) { r.Valid = false; r.HasDS = false; r.HasDNSKEY = false }, want: StatusFailed, code: CodeDNSSECDisabled},
		{name: "missing DS", edit: func(r *DNSSECResult) { r.Valid = false; r.HasDS = false }, want: StatusFailed, code: CodeDNSSECNoDS},
		{name: "missing DNSKEY", edit: func(r *DNSSECResult) { r.Valid = false; r.HasDNSKEY = false }, want: StatusFailed, code: CodeDNSSECNoDNSKEY},
		{name: "DS mismatch", edit: func(r *DNSSECResult) { r.Valid = false; r.DSMatchesDNSKEY = false }, want: StatusFailed, code: CodeDNSSECDSMismatch},
		{name: "bad signature", edit: func(r *DNSSECResult) { r.Valid = false; r.RRSIGValid = false }, want: StatusFailed, code: CodeDNSSECRRSIGFailed},
		{name: "no trusted chain evidence", edit: func(r *DNSSECResult) { r.Valid = false; r.ChainIntact = false; r.Error = "DoH unavailable" }, want: StatusFailed, code: CodeDNSLookupFailed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := base
			if tc.edit != nil {
				tc.edit(&result)
			}
			status, condition, _ := EvaluateDNSSEC(DomainConfig{Domain: "example.com", DNSSEC: true}, DNSSECSnapshot{Result: result})
			assert.Equal(t, tc.want, status)
			require.NotNil(t, condition)
			assert.Equal(t, tc.code, condition.Code)
		})
	}
}

func TestResolveTargetExtensive(t *testing.T) {
	app := &AppState{activeResolvers: testResolvers(), DNSClient: &MockDNSResolver{MockExchangeContext: func(_ context.Context, query *dns.Msg, _ string) (*dns.Msg, time.Duration, error) {
		response := new(dns.Msg)
		response.SetReply(query)
		var answer string
		switch query.Question[0].Qtype {
		case dns.TypeA:
			answer = "host.example. 60 IN A 192.0.2.10"
		case dns.TypeCNAME:
			answer = "host.example. 60 IN CNAME target.example."
		case dns.TypeMX:
			answer = "host.example. 60 IN MX 10 mail.example."
		}
		if answer != "" {
			record, err := dns.NewRR(answer)
			require.NoError(t, err)
			response.Answer = []dns.RR{record}
		}
		return response, 0, nil
	}}}
	for _, tc := range []struct {
		recordType string
		want       []string
	}{
		{recordType: RecordTypeA, want: []string{"192.0.2.10"}},
		{recordType: RecordTypeCNAME, want: []string{"target.example"}},
		{recordType: RecordTypeMX, want: []string{"mail.example"}},
	} {
		t.Run(tc.recordType, func(t *testing.T) {
			got, err := resolveTarget(context.Background(), app, DNSTask{Hostname: "host.example", Type: tc.recordType})
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestValidateEmailSecurity(t *testing.T) {
	app := &AppState{
		Notifier: &NotificationManager{NtfyURL: "https://ntfy.invalid/test"},
	}
	target := DomainConfig{Domain: "example.com"}
	_ = evaluateEmailSecurityForTest(context.Background(), app, target)
}

func TestEvaluateDNSSEC_MockedPaths(t *testing.T) {
	app := NewAppState(AppConfig{Resolvers: []string{"1.1.1.1"}})
	ctx := context.Background()

	tests := []struct {
		name          string
		mockResult    DNSSECResult
		expectedValid bool
	}{
		{"NetworkError", DNSSECResult{Valid: false, Source: DNSSECSourceLocalDoH, Error: "query failed"}, false},
		{"NoDSAndDNSKEY", DNSSECResult{Valid: false, Source: DNSSECSourceLocalDoH, HasDS: false, HasDNSKEY: false}, false},
		{"NoDS", DNSSECResult{Valid: false, Source: DNSSECSourceLocalDoH, HasDS: false, HasDNSKEY: true}, false},
		{"NoDNSKEY", DNSSECResult{Valid: false, Source: DNSSECSourceLocalDoH, HasDS: true, HasDNSKEY: false}, false},
		{"DSMismatch", DNSSECResult{Valid: false, Source: DNSSECSourceLocalDoH, HasDS: true, HasDNSKEY: true, DSMatchesDNSKEY: false}, false},
		{"RRSIGInvalid", DNSSECResult{Valid: false, Source: DNSSECSourceLocalDoH, HasDS: true, HasDNSKEY: true, DSMatchesDNSKEY: true, RRSIGValid: false}, false},
		{"ChainBroken", DNSSECResult{Valid: false, Source: DNSSECSourceLocalDoH, HasDS: true, HasDNSKEY: true, DSMatchesDNSKEY: true, RRSIGValid: true, ChainIntact: false}, false},
		{"CryptoMismatch", DNSSECResult{Valid: false, Source: DNSSECSourceLocalDoH, HasDS: true, HasDNSKEY: true, DSMatchesDNSKEY: false, RRSIGValid: false, ChainIntact: false}, false},
		{"NilSource", DNSSECResult{Valid: false, Source: ""}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app.HTTPClient = &MockHTTPClient{
				MockDo: func(req *http.Request) (*http.Response, error) {
					if tt.expectedValid {
						return &http.Response{
							StatusCode: 200,
							Body:       io.NopCloser(strings.NewReader(`{"Status": 0, "AD": true}`)),
						}, nil
					}
					return nil, errors.New(MsgErrMockDohError)
				},
			}
			app.DNSClient = &MockDNSResolver{
				MockExchangeContext: func(ctx context.Context, msg *dns.Msg, a string) (*dns.Msg, time.Duration, error) {
					resp := new(dns.Msg)
					resp.SetReply(msg)
					if tt.mockResult.Valid {
						if msg.Question[0].Qtype == dns.TypeDS {
							rr, _ := dns.NewRR(msg.Question[0].Name + " IN DS 2371 13 2 1234567890")
							resp.Answer = append(resp.Answer, rr)
						}
						if msg.Question[0].Qtype == dns.TypeDNSKEY {
							rr, _ := dns.NewRR(msg.Question[0].Name + " IN DNSKEY 256 3 13 1234567890")
							resp.Answer = append(resp.Answer, rr)
						}
					} else {
						return nil, 0, errors.New(MsgErrMockDNSSECError)
					}
					return resp, 0, nil
				},
			}
			res := evaluateDNSSECForTest(ctx, app, DomainConfig{Domain: "example.com", DNSSEC: true, Name: "Test"})
			assert.Equal(t, tt.expectedValid, res.Valid)
		})
	}
}

func TestEvaluateDNS_MockedPaths(t *testing.T) {
	app := NewAppState(AppConfig{Resolvers: []string{"1.1.1.1"}})
	ctx := context.Background()

	tests := []struct {
		name    string
		mockRes []string
		mockErr error
		expect  CheckStatus
	}{
		{"Error", nil, errors.New(MsgErrResolutionFailed), StatusFailed},
		{"NoRecords", []string{}, nil, StatusMismatch},
		{"Valid", []string{"1.2.3.4"}, nil, StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app.DNSClient = &MockDNSResolver{
				MockExchangeContext: func(ctx context.Context, msg *dns.Msg, a string) (*dns.Msg, time.Duration, error) {
					if tt.mockErr != nil {
						return nil, 0, tt.mockErr
					}
					resp := new(dns.Msg)
					resp.SetReply(msg)
					for _, ip := range tt.mockRes {
						rr, _ := dns.NewRR(msg.Question[0].Name + " IN A " + ip)
						resp.Answer = append(resp.Answer, rr)
					}
					return resp, 0, nil
				},
			}
			res := evaluateDNSForTest(ctx, app, DNSTask{Hostname: "example.com", Type: "A", Expected: []string{"1.2.3.4"}})
			assert.Equal(t, tt.expect, res.Status)
		})
	}
}

func TestResolveTarget_MockedPaths(t *testing.T) {
	app := NewAppState(AppConfig{Resolvers: []string{"1.1.1.1"}})
	ctx := context.Background()

	app.DNSClient = &MockDNSResolver{
		MockExchangeContext: func(ctx context.Context, msg *dns.Msg, a string) (*dns.Msg, time.Duration, error) {
			if len(msg.Question) == 0 {
				return nil, 0, errors.New(MsgErrMockError)
			}
			hostname := msg.Question[0].Name
			m := new(dns.Msg)
			m.SetReply(msg)
			normalized := strings.TrimSuffix(hostname, ".")
			if normalized == "cname.com" {
				m.Answer = append(m.Answer, &dns.CNAME{Hdr: dns.RR_Header{Name: "cname.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300}, Target: "target.com."})
				m.Answer = append(m.Answer, &dns.A{Hdr: dns.RR_Header{Name: "target.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.ParseIP("1.2.3.4")})
				return m, 0, nil
			}
			if normalized == "cname-loop.com" {
				return nil, 0, errors.New(MsgErrResolverErrorCNAMELoopDetected)
			}
			if normalized == "target.com" || normalized == "example.com" {
				m.Answer = append(m.Answer, &dns.A{Hdr: dns.RR_Header{Name: hostname, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.ParseIP("1.2.3.4")})
				return m, 0, nil
			}
			return nil, 0, errors.New(MsgErrMockError)
		},
	}

	t.Run("CNAME Resolution", func(t *testing.T) {
		res, err := resolveTarget(ctx, app, DNSTask{Hostname: "cname.com", Type: "A"})
		assert.NoError(t, err)
		assert.Contains(t, res, "1.2.3.4")
	})

	t.Run("CNAME Loop", func(t *testing.T) {
		_, err := resolveTarget(ctx, app, DNSTask{Hostname: "cname-loop.com", Type: "A"})
		assert.Error(t, err)
	})

	t.Run("Network Error on First Query", func(t *testing.T) {
		_, err := resolveTarget(ctx, app, DNSTask{Hostname: "fail.com", Type: "A"})
		assert.Error(t, err)
	})
}

func TestEvaluateEmailSecurity_MockedPaths(t *testing.T) {
	app := NewAppState(AppConfig{Resolvers: []string{"1.1.1.1"}})
	ctx := context.Background()

	app.DNSClient = &MockDNSResolver{
		MockExchangeContext: func(ctx context.Context, msg *dns.Msg, a string) (*dns.Msg, time.Duration, error) {
			if len(msg.Question) == 0 {
				return nil, 0, errors.New(MsgErrMockError)
			}
			hostname := msg.Question[0].Name
			qtype := msg.Question[0].Qtype
			m := new(dns.Msg)
			m.SetReply(msg)
			normalized := strings.TrimSuffix(hostname, ".")
			if qtype == dns.TypeMX && normalized == "example.com" {
				m.Answer = append(m.Answer, &dns.MX{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: 300}, Mx: "aspmx.l.google.com.", Preference: 10})
				return m, 0, nil
			}
			if qtype == dns.TypeTXT && normalized == "example.com" {
				m.Answer = append(m.Answer, &dns.TXT{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 300}, Txt: []string{"v=spf1 -all"}})
				return m, 0, nil
			}
			if qtype == dns.TypeTXT && normalized == "_dmarc.example.com" {
				m.Answer = append(m.Answer, &dns.TXT{Hdr: dns.RR_Header{Name: "_dmarc.example.com.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 300}, Txt: []string{"v=DMARC1; p=reject;"}})
				return m, 0, nil
			}
			if qtype == dns.TypeA && normalized == "mail.example.com" {
				m.Answer = append(m.Answer, &dns.A{Hdr: dns.RR_Header{Name: "mail.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.ParseIP("1.2.3.4")})
				return m, 0, nil
			}
			if qtype == dns.TypeTXT && normalized == "google._domainkey.example.com" {
				m.Answer = append(m.Answer, &dns.TXT{Hdr: dns.RR_Header{Name: "google._domainkey.example.com.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 300}, Txt: []string{"v=DKIM1; k=ed25519; p=AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=;"}})
				return m, 0, nil
			}
			return nil, 0, errors.New(MsgErrMockError)
		},
	}

	app.EmailProviders = map[string]ProviderConfig{
		"google": {MXRecords: []string{"aspmx.l.google.com"}},
	}
	res := evaluateEmailSecurityForTest(ctx, app, DomainConfig{Domain: "example.com", CheckEmailSecurity: true, MailProvider: "google", DKIMSelectors: []string{"google"}})
	assert.Equal(t, StatusOK, res.Status)
}

func evaluateDNSForTest(ctx context.Context, app *AppState, record DNSTask) DNSState {
	dnsSnap := FetchDNSSnapshot(ctx, app, record)
	status, cond := EvaluateDNS(record, dnsSnap)
	errStr := ""
	if cond != nil && cond.Code != CodeDNSMatchVerified {
		errStr = cond.Target
	}
	return DNSState{
		Hostname:  record.Hostname,
		Name:      record.Name,
		Type:      record.Type,
		Expected:  record.Expected,
		Status:    status,
		Condition: cond,
		Found:     dnsSnap.Records,

		Error: errStr,
	}
}

func evaluateEmailSecurityForTest(ctx context.Context, app *AppState, target DomainConfig) EmailState {
	snap := FetchEmailSnapshot(ctx, app, target)
	_, cond, state := EvaluateEmailSecurity(target, snap, nil)
	state.Condition = cond
	return state
}

func evaluateDNSSECForTest(ctx context.Context, app *AppState, target DomainConfig) DNSSECResult {
	snap := FetchDNSSECSnapshot(ctx, app, target)
	status, cond, res := EvaluateDNSSEC(target, snap)
	res.Status = status
	res.Condition = cond
	return res
}

func TestHasUsableDKIMKey(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)
	rsaDER, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	require.NoError(t, err)
	for _, tt := range []struct {
		record string
		usable bool
	}{
		{"v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(rsaDER), true},
		{"v=DKIM1; k=ed25519; p=AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=", true},
		{"v=DKIM1; k=rsa; p=QUJD", false},
		{"v=DKIM1; p=", false},
		{"v=DKIM1; note=incidental p=QUJD", false},
		{"v=DKIM1; k=unknown; p=QUJD", false},
		{"v=DKIM1; p=not-base64", false},
		{"v=DKIM1; p=QUJD; p=REVG", false},
	} {
		assert.Equal(t, tt.usable, hasUsableDKIMKey(tt.record), tt.record)
	}
}

func TestDMARCTransientFailureStopsParentDiscovery(t *testing.T) {
	var dmarcQueries []string
	app := NewAppState(AppConfig{Resolvers: []string{"1.1.1.1"}})
	app.DNSClient = &MockDNSResolver{MockExchangeContext: func(_ context.Context, q *dns.Msg, _ string) (*dns.Msg, time.Duration, error) {
		name := q.Question[0].Name
		if strings.HasPrefix(name, "_dmarc.") {
			dmarcQueries = append(dmarcQueries, name)
			return nil, 0, errors.New(MsgErrTemporaryDNSFailure)
		}
		response := new(dns.Msg)
		response.SetReply(q)
		return response, 0, nil
	}}
	snapshot := FetchEmailSnapshot(context.Background(), app, DomainConfig{Domain: "sub.example.com", CheckEmailSecurity: true})
	require.Error(t, snapshot.DMARCErr)
	assert.Equal(t, []string{"_dmarc.sub.example.com."}, dmarcQueries)
}

func TestHasValidDMARCPolicy(t *testing.T) {
	for _, tt := range []struct {
		record string
		valid  bool
	}{
		{"v=DMARC1; p=reject; rua=mailto:dmarc@example.com", true},
		{"v=DMARC1; p=none", true},
		{"v=DMARC1; p=reject; sp=quarantine; np=none; psd=n", true},
		{"v=DMARC1", false},
		{"v=DMARC1; p=invalid", false},
		{"v=DMARC1; p=reject; sp=invalid", false},
		{"v=DMARC1; p=reject; np=invalid", false},
		{"v=DMARC1; p=reject; psd=maybe", false},
		{"v=DMARC1; p=reject; p=none", false},
		{"note=v=DMARC1; p=reject", false},
	} {
		assert.Equal(t, tt.valid, hasValidDMARCPolicy(tt.record), tt.record)
	}
}

func TestMalformedDMARCDoesNotInheritParentPolicy(t *testing.T) {
	var dmarcQueries []string
	app := NewAppState(AppConfig{Resolvers: []string{"1.1.1.1"}})
	app.DNSClient = &MockDNSResolver{MockExchangeContext: func(_ context.Context, q *dns.Msg, _ string) (*dns.Msg, time.Duration, error) {
		response := new(dns.Msg)
		response.SetReply(q)
		name := q.Question[0].Name
		if strings.HasPrefix(name, "_dmarc.") {
			dmarcQueries = append(dmarcQueries, name)
			response.Answer = []dns.RR{&dns.TXT{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeTXT, Class: dns.ClassINET}, Txt: []string{"v=DMARC1; p=invalid"}}}
		}
		return response, 0, nil
	}}
	snapshot := FetchEmailSnapshot(context.Background(), app, DomainConfig{Domain: "sub.example.com", CheckEmailSecurity: true})
	require.ErrorContains(t, snapshot.DMARCErr, "invalid DMARC policy")
	assert.Equal(t, []string{"_dmarc.sub.example.com."}, dmarcQueries)
}

func TestDNSSECRejectsOversizedValidPrefix(t *testing.T) {
	key := &dns.DNSKEY{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET}, Flags: 257, Protocol: 3, Algorithm: dns.ED25519, PublicKey: "AQID"}
	valid := `{"Status":0,"AD":true,"Question":[{"name":"example.com.","type":48}],"Answer":[{"name":"example.com.","type":48,"data":"257 3 15 AQID"}]}`
	app := NewAppState(AppConfig{})
	app.HTTPClient = &MockHTTPClient{MockDo: func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(valid + strings.Repeat(" ", MaxNotificationPayloadSize)))}, nil
	}}
	assert.False(t, verifyDNSSECDoH(context.Background(), app, DefaultDoHURL, "example.com", "example.com.", key))
}

func TestPolicyTagsRejectMalformedFragments(t *testing.T) {
	assert.False(t, hasValidDMARCPolicy("v=DMARC1; p=reject; broken"))
}

func FuzzEmailPolicyRecords(f *testing.F) {
	for _, record := range []string{"", "v=DMARC1; p=reject", "v=DMARC1; p=reject; broken", "v=DKIM1; p=", "v=DKIM1; p=AA==; p=AA=="} {
		f.Add(record)
	}
	f.Fuzz(func(_ *testing.T, record string) {
		hasValidDMARCPolicy(record)
		hasUsableDKIMKey(record)
	})
}

func TestEmailUnavailableSelectorCannotHideBehindValidKey(t *testing.T) {
	snapshot := EmailSnapshot{
		MXRecords: []string{"mail.example.com"}, SPFRecords: []string{"v=spf1 -all"},
		DMARCRecords: []string{"v=DMARC1; p=reject"},
		DKIMResults:  map[string]bool{"good": true}, DKIMErrs: map[string]error{"other": errors.New(MsgErrDNSTimeout)},
	}
	target := DomainConfig{CheckEmailSecurity: true, DKIMSelectors: []string{"good", "other"}}
	status, condition, state := EvaluateEmailSecurity(target, snapshot, nil)
	assert.Equal(t, StatusWarning, status)
	require.NotNil(t, condition)
	assert.Equal(t, CodeDNSLookupFailed, condition.Code)
	assert.Equal(t, []string{"good"}, state.DKIMValid)
}

// TestLiveDNSSECMatrix compares monitor verdicts for signed, unsigned, and
// deliberately broken zones. Confirm the expected outcomes independently with
// delv before recording a release review; live DNS and DoH can change.
func TestLiveDNSSECMatrix(t *testing.T) {
	if os.Getenv("DOMAIN_MONITOR_LIVE") != "1" {
		t.Skip("set DOMAIN_MONITOR_LIVE=1 for external DNSSEC queries")
	}
	for _, test := range []struct {
		domain string
		status CheckStatus
		code   ResultCode
	}{
		{domain: "cloudflare.com", status: StatusOK, code: CodeDNSSECVerified},
		{domain: "google.com", status: StatusFailed, code: CodeDNSSECDisabled},
		{domain: "dnssec-failed.org", status: StatusFailed, code: CodeDNSLookupFailed},
	} {
		t.Run(test.domain, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
			defer cancel()
			target := DomainConfig{Domain: test.domain, DNSSEC: true}
			app := NewAppState(AppConfig{Resolvers: []string{"1.1.1.1", "8.8.8.8"}})
			app.HTTPClient = &http.Client{Timeout: 10 * time.Second}
			status, condition, result := EvaluateDNSSEC(target, FetchDNSSECSnapshot(ctx, app, target))
			t.Logf("status=%s condition=%v hasDS=%t hasDNSKEY=%t chainIntact=%t source=%s error=%q", status, condition, result.HasDS, result.HasDNSKEY, result.ChainIntact, result.Source, result.Error)
			if status != test.status || condition == nil || condition.Code != test.code {
				t.Fatalf("expected status=%s code=%s; got status=%s condition=%v", test.status, test.code, status, condition)
			}
		})
	}
}

// TestLiveCAADiscoveryMatrix checks parent-policy and alias-policy discovery
// against issuer sets observed with dig on the review date.

// TestLiveNullMX compares a public preference-zero null MX with direct dig
// output. Other email policy records are evaluated by their own checks.
func TestLiveNullMX(t *testing.T) {
	if os.Getenv("DOMAIN_MONITOR_LIVE") != "1" {
		t.Skip("set DOMAIN_MONITOR_LIVE=1 for external MX queries")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	target := DomainConfig{Domain: "example.com", CheckEmailSecurity: true, MXRecords: []string{"."}}
	app := NewAppState(AppConfig{Resolvers: []string{"1.1.1.1", "8.8.8.8"}})
	snapshot := FetchEmailSnapshot(ctx, app, target)
	status, condition, state := EvaluateEmailSecurity(target, snapshot, nil)
	t.Logf("status=%s condition=%v mx=%v spf=%t dmarc=%t", status, condition, state.MX, state.SPF, state.DMARC)
	if snapshot.MXErr != nil || !slices.Equal(snapshot.MXRecords, []string{"."}) || !slices.Equal(state.MX, []string{"."}) {
		t.Fatalf("monitor did not preserve the public null MX: records=%v error=%v", snapshot.MXRecords, snapshot.MXErr)
	}
}
func TestCanonicalCAARecordValue(t *testing.T) {
	record, err := dns.NewRR(`example.com. 300 IN CAA 0 issue "letsencrypt.org"`)
	require.NoError(t, err)
	caa := record.(*dns.CAA)
	val := canonicalCAARecordValue(caa)
	assert.Equal(t, `0 issue "letsencrypt.org"`, val)
	val2, ok := dnsAnswerText(caa, dns.TypeCAA)
	assert.True(t, ok)
	assert.Equal(t, `0 issue "letsencrypt.org"`, val2)
}

func TestSOALookupPreservesErrorCause(t *testing.T) {
	app := NewAppState(AppConfig{})
	app.DNSClient = &MockDNSResolver{MockExchangeContext: func(context.Context, *dns.Msg, string) (*dns.Msg, time.Duration, error) {
		return nil, 0, io.ErrUnexpectedEOF
	}}
	_, _, err := selectNSSOA(context.Background(), app, "example.com", []string{"192.0.2.53:53"})
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("SOA error lost its cause: %v", err)
	}
}
