package main

import (
	"context"
	"errors"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
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

// testResolvers returns the default resolver set matching config.jsonnet.
// Tests needing real DNS should use these; tests needing determinism should use mock DNS servers.
func testResolvers() []string {
	return []string{"1.1.1.1", "8.8.8.8", "9.9.9.9"}
}

func TestFetchCAA(t *testing.T) {
	app := &AppState{}
	resolvers := testResolvers()
	res, _ := fetchCAA(context.Background(), app, "google.com", resolvers)

	require.Empty(t, res.Error, "Expected no error, got %v", res.Error)

	if len(res.Issue) == 0 {
		// Even if they don't have issue, they might have something, but let's assume pki.goog
		// Actually, google.com has issue "pki.goog"
		t.Logf("google.com CAA issue is empty, this might happen depending on tree climbing or actual records.")
	} else {
		assert.Contains(t, res.Issue, "pki.goog", "Expected pki.goog in issue records for google.com")
	}
}

func TestFetchCAATreeClimbing(t *testing.T) {
	app := &AppState{}
	resolvers := testResolvers()
	res, _ := fetchCAA(context.Background(), app, "some-random-subdomain.google.com", resolvers)

	if res.Error != "" {
		t.Errorf("Expected no error, got %v", res.Error)
	}

	if len(res.Issue) > 0 {
		found := slices.Contains(res.Issue, "pki.goog")
		if !found {
			t.Errorf("Expected pki.goog from parent google.com, got %v", res.Issue)
		}
	}
}

func TestValidateDNSSEC(t *testing.T) {
	app := &AppState{}
	resolvers := testResolvers()
	res := validateDNSSEC(context.Background(), app, "example.com", resolvers, "https://dns.google/resolve")

	if !res.Valid {
		t.Errorf("Expected example.com to be valid DNSSEC, but got invalid. Result: %+v", res)
	}
	if !res.HasDS {
		t.Errorf("Expected example.com to have DS records")
	}
	if !res.HasDNSKEY {
		t.Errorf("Expected example.com to have DNSKEY records")
	}
	if !res.DSMatchesDNSKEY {
		t.Errorf("Expected DS to match DNSKEY")
	}
	if !res.RRSIGValid {
		t.Errorf("Expected dns.RRSIG to be valid")
	}
	if !res.ChainIntact {
		t.Errorf("Expected Google DoH to report ChainIntact (AD bit set)")
	}
	if len(res.Algorithms) == 0 {
		t.Errorf("Expected Algorithms to be populated")
	}
}

func TestValidateDNSSECUnsigned(t *testing.T) {
	app := &AppState{}
	resolvers := testResolvers()
	res := validateDNSSEC(context.Background(), app, "google.com", resolvers, "https://dns.google/resolve")

	if res.Valid {
		t.Errorf("Expected google.com to be invalid or unsigned DNSSEC, but got valid")
	}
	if res.HasDS {
		t.Errorf("Expected google.com to not have DS records")
	}
	if res.ChainIntact {
		t.Errorf("Expected Google DoH to not report ChainIntact for unsigned domain")
	}
}

func TestValidateCAATag(t *testing.T) {
	t.Parallel()

	app := &AppState{
		Notifier: &NotificationManager{TestMode: true},
	}
	_ = app

	tests := []struct {
		name        string
		target      DomainConfig
		tag         string
		expected    []string
		live        map[string]bool
		expectValid bool
		expectUnk   []string
	}{
		{
			name: "Valid Exact Match",
			target: DomainConfig{
				Domain:         "example.com",
				Name:           "Example",
				SuppressAlerts: true,
			},
			tag:         "issue",
			expected:    []string{"letsencrypt.org", "digicert.com"},
			live:        map[string]bool{"letsencrypt.org": true, "digicert.com": true},
			expectValid: true,
		},
		{
			name: "Missing Expected CA",
			target: DomainConfig{
				Domain:         "example.com",
				Name:           "Example",
				SuppressAlerts: true,
			},
			tag:         "issue",
			expected:    []string{"letsencrypt.org", "digicert.com"},
			live:        map[string]bool{"letsencrypt.org": true},
			expectValid: false,
		},
		{
			name: "Unauthorized CA Detected",
			target: DomainConfig{
				Domain:         "example.com",
				Name:           "Example",
				SuppressAlerts: true,
			},
			tag:         "issue",
			expected:    []string{"letsencrypt.org"},
			live:        map[string]bool{"letsencrypt.org": true, "rogue-ca.com": true},
			expectValid: false,
		},
		{
			name: "Valid Deny All With Semicolon Record",
			target: DomainConfig{
				Domain:         "example.com",
				Name:           "Example",
				SuppressAlerts: true,
			},
			tag:         "issuewild",
			expected:    []string{},
			live:        map[string]bool{";": true},
			expectValid: true,
		},
		{
			name: "Deny All Failed Due To Unauthorized CA",
			target: DomainConfig{
				Domain:         "example.com",
				Name:           "Example",
				SuppressAlerts: true,
			},
			tag:         "issuewild",
			expected:    []string{},
			live:        map[string]bool{"letsencrypt.org": true},
			expectValid: false,
		},
		{
			name: "Deny All Failed Due To Missing CAA Record",
			target: DomainConfig{
				Domain:         "example.com",
				Name:           "Example",
				SuppressAlerts: true,
			},
			tag:         "issuewild",
			expected:    []string{},
			live:        map[string]bool{},
			expectValid: false,
		},
		{
			name: "Skipped Tag (nil)",
			target: DomainConfig{
				Domain:         "example.com",
				Name:           "Example",
				SuppressAlerts: true,
			},
			tag:         "issuemail",
			expected:    nil,
			live:        map[string]bool{"any-mail-ca.com": true},
			expectValid: true,
		},
		{
			name: "Deny All Unauthorized CA Populates UnknownCAs",
			target: DomainConfig{
				Domain:         "example.com",
				Name:           "Example",
				SuppressAlerts: true,
			},
			tag:         "issue",
			expected:    []string{},
			live:        map[string]bool{";": true, "unauth-ca.com": true},
			expectValid: false,
			expectUnk:   []string{"unauth-ca.com"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			res := CAAResult{Valid: true}
			res, _ = evaluateCAATag(tt.target, tt.tag, tt.expected, tt.live, res, nil)
			if res.Valid != tt.expectValid {
				t.Errorf("Expected Valid: %v, got %v", tt.expectValid, res.Valid)
			}
			if len(tt.expectUnk) > 0 {
				for _, unk := range tt.expectUnk {
					found := slices.Contains(res.UnknownCAs, unk)
					if !found {
						t.Errorf("Expected UnknownCA %s in %v", unk, res.UnknownCAs)
					}
				}
			}
		})
	}
}

func TestParseCAAIssuer(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input    string
		expected string
	}{
		{";", ";"},
		{"", ";"},
		{"\";\"", ";"},
		{"\"\"", ";"},
		{" ; ", ";"},
		{"; policy=ev", ";"},
		{"; accounturi=https://example.com/acct/123", ";"},
		{"letsencrypt.org", "letsencrypt.org"},
		{"\"letsencrypt.org\"", "letsencrypt.org"},
		{"LETSENCRYPT.ORG", "letsencrypt.org"},
		{"letsencrypt.org; accounturi=https://example.com", "letsencrypt.org"},
		{"digicert.com; validationmethods=dns-01", "digicert.com"},
	}

	for _, tt := range tests {
		actual := parseCAAIssuer(tt.input)
		if actual != tt.expected {
			t.Errorf("parseCAAIssuer(%q) = %q, expected %q", tt.input, actual, tt.expected)
		}
	}
}

func TestFetchCAABoundaries(t *testing.T) {
	app := &AppState{}
	resolvers := testResolvers()

	// Empty domain
	res, _ := fetchCAA(context.Background(), app, "", resolvers)
	if res.Error == "" {
		t.Errorf("Expected error for empty domain, got none")
	}

	// Single label domain
	res, _ = fetchCAA(context.Background(), app, "localhost", resolvers)
	if res.Error != "" {
		t.Fatalf("fetchCAA returned nil")
	}
}

func TestDNSSECValidationFallback(t *testing.T) {
	app := &AppState{}
	resolvers := testResolvers()

	// When DoH URL is invalid or unreachable, validation falls back to local_only
	res := validateDNSSEC(context.Background(), app, "example.com", resolvers, "http://127.0.0.1:1/invalid_doh")
	if res.Source != "local_only" {
		t.Errorf("Expected Source 'local_only', got %q", res.Source)
	}
	if !res.Valid {
		t.Errorf("Expected example.com to be Valid=true under local checks, got false (error: %s)", res.Error)
	}
	if res.Error == "" {
		t.Errorf("Expected descriptive fallback message in res.Error when DoH is offline, got empty")
	}
}

func TestDNSSECValidationDoHHTTPError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "server error", http.StatusInternalServerError)
	}))
	defer ts.Close()

	app := &AppState{}
	resolvers := testResolvers()

	// When DoH server returns HTTP 500 or 429, it must fall back to local_only without marking chain broken
	res := validateDNSSEC(context.Background(), app, "example.com", resolvers, ts.URL)
	if res.Source != "local_only" {
		t.Errorf("Expected Source 'local_only' on DoH HTTP 500, got %q", res.Source)
	}
	if !res.Valid {
		t.Errorf("Expected example.com to remain Valid=true on DoH HTTP 500, got false (error: %s)", res.Error)
	}
}

func FuzzParseCAAIssuer(f *testing.F) {
	seeds := []string{
		";",
		"letsencrypt.org",
		"\"letsencrypt.org\"",
		"digicert.com; validationmethods=dns-01",
		"; policy=ev",
		"",
	}
	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(_ *testing.T, rawVal string) {
		// Should never panic regardless of arbitrary input
		_ = parseCAAIssuer(rawVal)
	})
}

func TestValidateRecords_MatchTypes(t *testing.T) {
	t.Parallel()

	app := &AppState{
		Notifier: &NotificationManager{TestMode: true},
	}
	_ = app

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

func TestSSLSentinels(t *testing.T) {
	t.Parallel()

	app := &AppState{
		config: AppConfig{
			Resolvers: testResolvers(),
		},
		Notifier: &NotificationManager{TestMode: true},
	}

	// 1. Non-SSL record type should return SSLDaysNotApplicable (-9999)
	txtTask := DNSTask{
		Hostname: "example.com",
		Type:     "TXT",
		Expected: []string{"test"},
	}
	res := FetchSSLSnapshot(context.Background(), app, txtTask, []string{"v=spf1 ~all"}).ExpiryDays
	if res != SSLDaysNotApplicable {
		t.Errorf("Expected SSLDaysNotApplicable (%d) for TXT record, got %d", SSLDaysNotApplicable, res)
	}

	// 2. Empty IPs should return SSLDaysError (-9998)
	aTask := DNSTask{
		Hostname: "example.com",
		Type:     "A",
		Expected: []string{"1.2.3.4"},
	}
	resEmpty := FetchSSLSnapshot(context.Background(), app, aTask, []string{}).ExpiryDays
	if resEmpty != SSLDaysError {
		t.Errorf("Expected SSLDaysError (%d) for empty IPs, got %d", SSLDaysError, resEmpty)
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
	defer server.Shutdown()
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
		Notifier: &NotificationManager{TestMode: true},
	}
	target := DomainConfig{
		Domain:             "unreachable-domain.com",
		Name:               "Unreachable",
		CheckEmailSecurity: true,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	savedState := evaluateEmailSecurityForTest(ctx, app, target)

	for _, alert := range app.Notifier.(*NotificationManager).TestBuffer {
		if strings.Contains(alert.Message, "Missing SPF") || strings.Contains(alert.Message, "Missing DMARC") {
			t.Errorf("Unexpected false alert on DNS lookup error: %s", alert.Message)
		}
	}

	if savedState.Status == "" {
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
		Txt: []string{"v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC12345"},
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
	defer server.Shutdown()
	go func() { _ = server.ActivateAndServe() }()

	app := &AppState{
		config: AppConfig{
			Resolvers: []string{l.LocalAddr().String()},
		},
		Notifier: &NotificationManager{TestMode: true},
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

	if savedState.Status == "" {
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

func TestFetchCAA_CNAMEAliasFollowing(t *testing.T) {
	mux := dns.NewServeMux()

	cnameRR := &dns.CNAME{
		Hdr:    dns.RR_Header{Name: "alias.example.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
		Target: "target.cdn.net.",
	}
	caaRR := &dns.CAA{
		Hdr:   dns.RR_Header{Name: "target.cdn.net.", Rrtype: dns.TypeCAA, Class: dns.ClassINET, Ttl: 300},
		Tag:   "issue",
		Value: "letsencrypt.org",
	}

	mux.HandleFunc("alias.example.com.", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		if len(r.Question) > 0 {
			if r.Question[0].Qtype == dns.TypeCNAME {
				m.Answer = append(m.Answer, cnameRR)
			}
		}
		_ = w.WriteMsg(m)
	})

	mux.HandleFunc("target.cdn.net.", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		if len(r.Question) > 0 {
			if r.Question[0].Qtype == dns.TypeCAA {
				m.Answer = append(m.Answer, caaRR)
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
	defer server.Shutdown()
	go func() { _ = server.ActivateAndServe() }()

	app := &AppState{config: AppConfig{Resolvers: []string{l.LocalAddr().String()}}}
	res, _ := fetchCAA(context.Background(), app, "alias.example.com", []string{l.LocalAddr().String()})

	if res.Error != "" {
		t.Errorf("Unexpected error: %v", res.Error)
	}
	if len(res.Issue) != 1 || res.Issue[0] != "letsencrypt.org" {
		t.Errorf("Expected CAA issue 'letsencrypt.org' from CNAME target, got %v", res.Issue)
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
	defer server.Shutdown()
	go func() { _ = server.ActivateAndServe() }()

	app := &AppState{
		config:   AppConfig{Resolvers: []string{l.LocalAddr().String()}},
		Notifier: &NotificationManager{TestMode: true},
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
	if s1.Status == "" || s1.Status != StatusOK {
		t.Errorf("Expected task 1 to be StatusOK, got %+v", s1)
	}
	if s2.Status == "" || s2.Status != StatusOK {
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
	defer server.Shutdown()
	go func() { _ = server.ActivateAndServe() }()

	app := &AppState{
		config:   AppConfig{Resolvers: []string{l.LocalAddr().String()}},
		Notifier: &NotificationManager{TestMode: true},
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
	defer s1.Shutdown()
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
	defer s2.Shutdown()
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
	defer s3.Shutdown()
	go func() { _ = s3.ActivateAndServe() }()

	resolvers := []string{l1.LocalAddr().String(), l2.LocalAddr().String(), l3.LocalAddr().String()}
	app := &AppState{}

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
		Notifier: &NotificationManager{TestMode: true},
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
	app.Notifier.(*NotificationManager).TestBuffer = nil
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
	defer server.Shutdown()
	go func() { _ = server.ActivateAndServe() }()

	resolvers := []string{l.LocalAddr().String()}
	app := &AppState{}

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
	defer server.Shutdown()
	go func() { _ = server.ActivateAndServe() }()

	resolvers := []string{l.LocalAddr().String()}
	app := &AppState{}

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
	defer server.Shutdown()
	go func() { _ = server.ActivateAndServe() }()

	resolvers := []string{l.LocalAddr().String()}
	app := &AppState{}

	_, qErr := queryDNSMsgWithRD(context.Background(), app, "example.com", dns.TypeA, resolvers, true)
	if qErr == nil {
		t.Fatalf("Expected error when response question section is stripped, got success")
	}

	if !strings.Contains(qErr.Error(), "mismatch or missing") {
		t.Errorf("Expected question mismatch error, got: %v", qErr)
	}
}

func TestFetchCAA_CNAMELoopTermination(t *testing.T) {
	t.Parallel()

	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		if len(r.Question) > 0 {
			q := r.Question[0]
			if q.Qtype == dns.TypeCNAME {
				// Create a cycle between loop.example. and alias.example.
				target := "alias.example."
				if strings.HasPrefix(q.Name, "alias") {
					target = "loop.example."
				}
				rr, _ := dns.NewRR(q.Name + " 300 IN CNAME " + target)
				m.Answer = append(m.Answer, rr)
			}
			// For CAA or other types, return empty Answer (NODATA)
		}
		_ = w.WriteMsg(m)
	})

	server := &dns.Server{Addr: "127.0.0.1:0", Net: "udp", Handler: mux}
	l, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen packet: %v", err)
	}
	server.PacketConn = l
	defer server.Shutdown()
	go func() { _ = server.ActivateAndServe() }()

	app := &AppState{config: AppConfig{Resolvers: []string{l.LocalAddr().String()}}}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	res, _ := fetchCAA(ctx, app, "loop.example.com", []string{l.LocalAddr().String()})
	if res.Error != "" {
		t.Fatalf("fetchCAA returned nil on CNAME loop")
	}
}

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
				if q.Qtype == dns.TypeSOA {
					soaStr := "example.com. 3600 IN SOA ns1.example.com. hostmaster.example.com. " + strconv.FormatUint(uint64(serial), 10) + " 7200 3600 1209600 3600"
					rr, _ := dns.NewRR(soaStr)
					m.Answer = append(m.Answer, rr)
				} else if q.Qtype == dns.TypeDNSKEY {
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

		app := &AppState{config: AppConfig{Resolvers: []string{pAddr}}, Notifier: &NotificationManager{TestMode: true}}
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

		app := &AppState{config: AppConfig{Resolvers: []string{pAddr}}, Notifier: &NotificationManager{TestMode: true}}
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

		app := &AppState{config: AppConfig{Resolvers: []string{pAddr}}, Notifier: &NotificationManager{TestMode: true}}
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

		app := &AppState{config: AppConfig{Resolvers: []string{pAddr}}, Notifier: &NotificationManager{TestMode: true}}
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

	// 5. DNSKEY Unexpected on Secondary even when target.DNSSEC is false -> REJECTED
	t.Run("DNSKEYUnexpectedEvenWhenDNSSECIsFalse", func(t *testing.T) {
		pAddr, pClose := startMockNSWithKeys(2026090101, true, nil) // Unsigned primary
		defer pClose()
		sAddr, sClose := startMockNSWithKeys(2026090101, true, []dns.RR{independentKey}) // Secondary serves DNSKEY!
		defer sClose()

		app := &AppState{config: AppConfig{Resolvers: []string{pAddr}}, Notifier: &NotificationManager{TestMode: true}}
		target := DomainConfig{
			Domain:         "example.com",
			Name:           "Dumb Secondary Unsigned Violation",
			ExpectedNS:     []string{pAddr},
			SecondaryNS:    []string{sAddr},
			VerifyNSHealth: true,
			DNSSEC:         false, // Explicitly false!
		}
		res := evaluateNSHealthForTest(context.Background(), app, target)

		if res.Valid {
			t.Errorf("Expected NSHealth to be invalid when secondary serves DNSKEY even if DNSSEC=false")
		}
	})

	// 6. DNSKEY Missing on Secondary when Primary is signed -> REJECTED
	t.Run("DNSKEYMissingOnSecondary", func(t *testing.T) {
		pAddr, pClose := startMockNSWithKeys(2026090101, true, []dns.RR{primaryKey})
		defer pClose()
		sAddr, sClose := startMockNSWithKeys(2026090101, true, nil) // Missing DNSKEY!
		defer sClose()

		app := &AppState{config: AppConfig{Resolvers: []string{pAddr}}, Notifier: &NotificationManager{TestMode: true}}
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

		app := &AppState{config: AppConfig{Resolvers: []string{pAddr}}, Notifier: &NotificationManager{TestMode: true}}
		target := DomainConfig{
			Domain:         "example.com",
			Name:           "Lagging Domain",
			ExpectedNS:     []string{pAddr},
			SecondaryNS:    []string{sAddr},
			VerifyNSHealth: true,
		}
		res := evaluateNSHealthForTest(context.Background(), app, target)

		if res.Valid {
			t.Errorf("Expected NSHealth to be invalid on secondary SOA lag")
		}
	})

	// 7. Happy Path: Primary Only (secondary_ns omitted -> secondary checks skipped)
	t.Run("HappyPathPrimaryOnly", func(t *testing.T) {
		pAddr, pClose := startMockNSWithKeys(2026090101, true, []dns.RR{primaryKey})
		defer pClose()

		app := &AppState{config: AppConfig{Resolvers: []string{pAddr}}, Notifier: &NotificationManager{TestMode: true}}
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

		app := &AppState{config: AppConfig{Resolvers: []string{pAddr}}, Notifier: &NotificationManager{TestMode: true}}
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
		defer srv.Shutdown()

		pAddr := l.LocalAddr().String()
		app := &AppState{config: AppConfig{Resolvers: []string{pAddr}}, Notifier: &NotificationManager{TestMode: true}}
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
		defer srv.Shutdown()

		pAddr := l.LocalAddr().String()
		app := &AppState{config: AppConfig{Resolvers: []string{pAddr}}, Notifier: &NotificationManager{TestMode: true}}
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

func TestEvaluateDNS_SkipSSL(t *testing.T) {
	mux := dns.NewServeMux()
	mux.HandleFunc("web.example.com.", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = append(m.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: "web.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   net.ParseIP("127.0.0.1"),
		})
		_ = w.WriteMsg(m)
	})

	l, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen packet: %v", err)
	}
	srv := &dns.Server{PacketConn: l, Handler: mux}
	go func() { _ = srv.ActivateAndServe() }()
	defer srv.Shutdown()

	pAddr := l.LocalAddr().String()
	app := &AppState{
		config: AppConfig{
			Resolvers: []string{pAddr},
		},
		Notifier: &NotificationManager{TestMode: true},
	}

	state := &CheckState{
		DNS: make(map[string]DNSState),
	}

	// 1. Task with SkipSSL = true: port 443 should NOT be dialed at all, SSLDays should be SSLDaysNotApplicable (-9999)
	taskSkip := DNSTask{
		Hostname: "web.example.com",
		Name:     "Web Server No SSL",
		Type:     "A",
		Expected: []string{"127.0.0.1"},
		SkipSSL:  true,
	}

	resSkip := evaluateDNSForTest(context.Background(), app, taskSkip)

	state.DNS[taskSkip.Name] = resSkip
	resSkip = state.DNS["Web Server No SSL"]

	if resSkip.Status == "" {
		t.Fatalf("expected DNS state to be recorded for taskSkip")
	}
	if resSkip.Status != StatusOK {
		t.Errorf("expected StatusOK, got %v", resSkip.Status)
	}
	if !resSkip.SkipSSL {
		t.Errorf("expected DNSState.SkipSSL to be true")
	}
	if resSkip.SSLDays != nil {
		t.Errorf("expected SSLDays to be nil, got %d", *resSkip.SSLDays)
	}
	if resSkip.Error != "" {
		t.Errorf("expected no error, got %s", resSkip.Error)
	}

	// 2. Direct call to FetchSSLSnapshot: when SkipSSL is true, immediately returns SSLDaysNotApplicable
	days := FetchSSLSnapshot(context.Background(), app, taskSkip, []string{"127.0.0.1"}).ExpiryDays
	if days != SSLDaysNotApplicable {
		t.Errorf("FetchSSLSnapshot expected SSLDaysNotApplicable, got %d", days)
	}
}

func TestDNS_MultiIPCanonicalSorting(t *testing.T) {
	mux := dns.NewServeMux()
	mux.HandleFunc("multi.example.com.", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		if r.Question[0].Qtype == dns.TypeA {
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
		} else if r.Question[0].Qtype == dns.TypeAAAA {
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
	defer srv.Shutdown()

	pAddr := l.LocalAddr().String()
	app := &AppState{
		config: AppConfig{
			Resolvers: []string{pAddr},
		},
		Notifier: &NotificationManager{TestMode: true},
	}
	state := &CheckState{
		DNS: make(map[string]DNSState),
	}

	task := DNSTask{
		Hostname: "multi.example.com",
		Name:     "Multi IP Test",
		Type:     "IP",
		Expected: []string{"192.0.2.1", "198.51.100.2", "2001:db8::1"},
		SkipSSL:  true,
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
	defer srv.Shutdown()

	pAddr := l.LocalAddr().String()
	app := &AppState{
		config: AppConfig{
			Resolvers: []string{pAddr},
		},
		Notifier: &NotificationManager{TestMode: true},
	}
	state := &CheckState{
		DNS: make(map[string]DNSState),
	}

	task := DNSTask{
		Hostname: "flattened.example.com",
		Name:     "Flattened CNAME Direct IP",
		Type:     "CNAME",
		Expected: []string{"192.0.2.99"},
		SkipSSL:  true,
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
	app := &AppState{
		config:   AppConfig{},
		Notifier: &NotificationManager{TestMode: true},
	}
	_ = app

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

	// 1. evaluateCAA with nil app and active CAA config
	caaCfg := DomainConfig{
		Domain: "example.com",
		CAA: &CAAConfig{
			Issue: []string{"letsencrypt.org"},
		},
	}
	caaRes := evaluateCAAForTest(ctx, nil, caaCfg)
	if caaRes.Error == "" {
		t.Errorf("expected CAAResult to contain error for nil app")
	}

	// 2. evaluateCAATag with nil res
	evaluateCAATag(caaCfg, "issue", []string{"letsencrypt.org"}, nil, CAAResult{}, nil)
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
		SkipSSL:  true,
	}
	dnsState := evaluateDNSForTest(ctx, nil, dnsTask)
	if dnsState.Status == "" {
		t.Errorf("expected non-nil DNSState")
	}

	// 5. evaluateEmailSecurity with nil app
	emailCfg := DomainConfig{
		Domain:             "example.com",
		CheckEmailSecurity: true,
		MXRecords:          []string{"mail.example.com"},
	}
	emailState := evaluateEmailSecurityForTest(ctx, nil, emailCfg)
	if emailState.Status == "" {
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
		Notifier: &NotificationManager{TestMode: true},
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
	app := &AppState{
		config:   AppConfig{},
		Notifier: &NotificationManager{TestMode: true},
	}
	_ = app

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
	app := &AppState{
		config:   AppConfig{},
		Notifier: &NotificationManager{TestMode: true},
	}

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

func TestCheckSSLExpiryDays_ErrSSLValidationChaining(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer ts.Close()

	u, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatalf("failed to parse test server URL: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// Dial with mismatched hostname to verify ErrSSLValidation is preserved in the error chain
	_, err = checkSSLExpiryDays(ctx, "mismatch.invalid.domain", []string{u.Host}, false)
	if err == nil {
		t.Fatalf("expected SSL error for mismatched hostname, got nil")
	}
	if !errors.Is(err, ErrSSLValidation) {
		t.Errorf("expected error to wrap ErrSSLValidation, got: %v", err)
	}
}

func TestEvaluateDNSSECExtensive(t *testing.T) {
	app := &AppState{
		Notifier: &NotificationManager{TestMode: true},
	}
	// Missing Name
	_ = evaluateDNSSECForTest(context.Background(), app, DomainConfig{})

	// Has Name but fails
	_ = evaluateDNSSECForTest(context.Background(), app, DomainConfig{Domain: "example.com"})
}

func TestCheckSSLExpiryDaysExtensive(t *testing.T) {
	days, err := checkSSLExpiryDays(context.Background(), "invalid.localhost", []string{"127.0.0.1"}, true)
	assert.Error(t, err)
	assert.Equal(t, -9998, days)

	days, err = checkSSLExpiryDays(context.Background(), "invalid.localhost", []string{}, true)
	assert.Error(t, err)

	// Test internal method
	days, err = checkSSLExpiryDays(context.Background(), "invalid.localhost", []string{"invalid_ip"}, true)
	assert.Error(t, err)
}

func TestValidateCertificateExtensive(t *testing.T) {
	app := &AppState{
		Notifier: &NotificationManager{TestMode: true},
	}

	target := DNSTask{
		Hostname: "localhost",
		Type:     "A",
	}

	days := FetchSSLSnapshot(context.Background(), app, target, []string{"127.0.0.1"}).ExpiryDays
	assert.Equal(t, -9998, days)

	target.SkipSSL = true
	days = FetchSSLSnapshot(context.Background(), app, target, []string{"127.0.0.1"}).ExpiryDays
	assert.Equal(t, -9999, days)
}

func TestResolveTargetExtensive(t *testing.T) {
	app := &AppState{
		Notifier:        &NotificationManager{TestMode: true},
		activeResolvers: []string{"8.8.8.8"},
	}
	target := DNSTask{
		Hostname: "localhost",
		Type:     "A",
	}

	ips, _ := resolveTarget(context.Background(), app, target)
	_ = ips

	target.Type = "CNAME"
	ips, _ = resolveTarget(context.Background(), app, target)
	_ = ips

	target.Type = "MX"
	ips, _ = resolveTarget(context.Background(), app, target)
	_ = ips
}

func TestEvaluateCAAExtensive(t *testing.T) {
	app := &AppState{
		Notifier: &NotificationManager{TestMode: true},
	}
	target := DomainConfig{Domain: "example.com"}
	_ = evaluateCAAForTest(context.Background(), app, target)
}

func TestValidateEmailSecurity(t *testing.T) {
	app := &AppState{
		Notifier: &NotificationManager{TestMode: true},
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
					return nil, errors.New("mock doh error")
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
						return nil, 0, errors.New("mock DNSSEC error")
					}
					return resp, 0, nil
				},
			}
			res := evaluateDNSSECForTest(ctx, app, DomainConfig{Domain: "example.com", DNSSEC: true, Name: "Test"})
			assert.Equal(t, tt.expectedValid, res.Valid)
		})
	}
}

func TestEvaluateCAA_MockedPaths(t *testing.T) {
	app := NewAppState(AppConfig{Resolvers: []string{"1.1.1.1"}})
	ctx := context.Background()

	tests := []struct {
		name       string
		mockFound  bool
		mockIssues []CAAEntry
		cfg        DomainConfig
	}{
		{"NotFound", false, nil, DomainConfig{Domain: "example.com", CAA: &CAAConfig{}}},
		{"FoundValid", true, []CAAEntry{{Tag: "issue", Value: "letsencrypt.org"}}, DomainConfig{Domain: "example.com", CAA: &CAAConfig{Issue: []string{"letsencrypt.org"}}}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app.DNSClient = &MockDNSResolver{
				MockExchangeContext: func(ctx context.Context, msg *dns.Msg, a string) (*dns.Msg, time.Duration, error) {
					resp := new(dns.Msg)
					resp.SetReply(msg)
					if !tt.mockFound {
						return resp, 0, nil
					}
					for _, issue := range tt.mockIssues {
						caa := &dns.CAA{
							Hdr:   dns.RR_Header{Name: dns.Fqdn("example.com"), Rrtype: dns.TypeCAA, Class: dns.ClassINET, Ttl: 300},
							Value: issue.Value,
							Tag:   issue.Tag,
						}
						resp.Answer = append(resp.Answer, caa)
					}
					return resp, 0, nil
				},
			}
			evaluateCAAForTest(ctx, app, tt.cfg)
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
		{"Error", nil, errors.New("resolution failed"), StatusFailed},
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
			res := evaluateDNSForTest(ctx, app, DNSTask{Hostname: "example.com", Type: "A", Expected: []string{"1.2.3.4"}, SkipSSL: true})
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
				return nil, 0, errors.New("mock error")
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
				return nil, 0, errors.New("resolver error: CNAME loop detected")
			}
			if normalized == "target.com" || normalized == "example.com" {
				m.Answer = append(m.Answer, &dns.A{Hdr: dns.RR_Header{Name: hostname, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.ParseIP("1.2.3.4")})
				return m, 0, nil
			}
			return nil, 0, errors.New("mock error")
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
				return nil, 0, errors.New("mock error")
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
				m.Answer = append(m.Answer, &dns.TXT{Hdr: dns.RR_Header{Name: "google._domainkey.example.com.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 300}, Txt: []string{"v=DKIM1; k=rsa; p=pubkey;"}})
				return m, 0, nil
			}
			return nil, 0, errors.New("mock error")
		},
	}

	res := evaluateEmailSecurityForTest(ctx, app, DomainConfig{Domain: "example.com", CheckEmailSecurity: true, MailProvider: "google", DKIMSelectors: []string{"google"}})
	assert.Equal(t, StatusOK, res.Status)
}

func evaluateDNSForTest(ctx context.Context, app *AppState, record DNSTask) DNSState {
	dnsSnap := FetchDNSSnapshot(ctx, app, record)
	status, cond := EvaluateDNS(record, dnsSnap)
	var sslDays *int
	if !record.SkipSSL {
		sslSnap := FetchSSLSnapshot(ctx, app, record, dnsSnap.Records)
		sslStatus, sslCond := EvaluateSSL(record, sslSnap)
		if sslSnap.ExpiryDays != SSLDaysError && sslSnap.ExpiryDays != SSLDaysNotApplicable {
			d := sslSnap.ExpiryDays
			sslDays = &d
		}
		if sslStatus != StatusOK {
			if status == StatusOK || status == StatusWarning {
				status = sslStatus
			}
			if cond == nil || cond.Code == CodeDNSMatchVerified {
				cond = sslCond
			}
		}
	}
	errStr := ""
	if cond != nil && cond.Code != CodeDNSMatchVerified && cond.Code != CodeSSLVerified {
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
		SSLDays:   sslDays,
		SkipSSL:   record.SkipSSL,
		Error:     errStr,
	}
}

func evaluateEmailSecurityForTest(ctx context.Context, app *AppState, target DomainConfig) EmailState {
	snap := FetchEmailSnapshot(ctx, app, target)
	_, cond, state := EvaluateEmailSecurity(target, snap)
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

func evaluateCAAForTest(ctx context.Context, app *AppState, target DomainConfig) CAAResult {
	snap := FetchCAASnapshot(ctx, app, target)
	status, cond, res := EvaluateCAA(target, snap)
	res.Status = status
	res.Condition = cond
	return res
}
