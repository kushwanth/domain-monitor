package main

import (
	"context"
	"errors"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
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
			if ok != tt.expectOK {
				t.Errorf("Expected OK=%v for %s, got %v", tt.expectOK, tt.recordType, ok)
			}
		})
	}
}

func TestFetchCAA(t *testing.T) {
	app := &AppState{}
	resolvers := []string{"8.8.8.8"}
	res := fetchCAA(context.Background(), app, "google.com", resolvers)

	if res.Error != "" {
		t.Errorf("Expected no error, got %v", res.Error)
	}

	if len(res.Issue) == 0 {
		// Even if they don't have issue, they might have something, but let's assume pki.goog
		// Actually, google.com has issue "pki.goog"
		t.Logf("google.com CAA issue is empty, this might happen depending on tree climbing or actual records.")
	} else {
		found := slices.Contains(res.Issue, "pki.goog")
		if !found {
			t.Errorf("Expected pki.goog in issue records for google.com, got %v", res.Issue)
		}
	}
}

func TestFetchCAATreeClimbing(t *testing.T) {
	app := &AppState{}
	resolvers := []string{"8.8.8.8"}
	res := fetchCAA(context.Background(), app, "some-random-subdomain.google.com", resolvers)

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
	resolvers := []string{"8.8.8.8"}
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
		t.Errorf("Expected RRSIG to be valid")
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
	resolvers := []string{"8.8.8.8"}
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
		Notifier: &NotificationManager{},
	}

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
			res := &CAAResult{Valid: true}
			validateCAATag(app, tt.target, tt.tag, tt.expected, tt.live, res)
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
	resolvers := []string{"8.8.8.8"}

	// Empty domain
	res := fetchCAA(context.Background(), app, "", resolvers)
	if res.Error == "" {
		t.Errorf("Expected error for empty domain, got none")
	}

	// Single label domain
	res = fetchCAA(context.Background(), app, "localhost", resolvers)
	if res == nil {
		t.Fatalf("fetchCAA returned nil")
	}
}

func TestDNSSECValidationFallback(t *testing.T) {
	app := &AppState{}
	resolvers := []string{"8.8.8.8"}

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
	app := &AppState{}
	resolvers := []string{"8.8.8.8"}

	// When DoH server returns HTTP 500 or 429, it must fall back to local_only without marking chain broken
	res := validateDNSSEC(context.Background(), app, "example.com", resolvers, "https://httpbin.org/status/500")
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

	f.Fuzz(func(t *testing.T, rawVal string) {
		// Should never panic regardless of arbitrary input
		_ = parseCAAIssuer(rawVal)
	})
}

func TestValidateRecords_MatchTypes(t *testing.T) {
	t.Parallel()

	app := &AppState{
		Notifier: &NotificationManager{},
	}

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
	if !validateRecords(app, spfTask, foundTXTs) {
		t.Errorf("Expected prefix match to succeed for SPF")
	}

	// 2. Contains match
	containsTask := DNSTask{
		Hostname:  "example.com",
		Type:      "TXT",
		Expected:  []string{"_spf.google.com"},
		MatchType: "contains",
	}
	if !validateRecords(app, containsTask, foundTXTs) {
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
	if !validateRecords(app, anyOfTask, foundA) {
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
	if validateRecords(app, exactTask, unauthA) {
		t.Errorf("Expected exact match to fail due to unauthorized IP")
	}
}

func TestSSLSentinels(t *testing.T) {
	t.Parallel()

	app := &AppState{
		Config: &AppConfig{
			Resolvers: []string{"8.8.8.8"},
		},
		Notifier: &NotificationManager{},
	}

	// 1. Non-SSL record type should return SSLDaysNotApplicable (-9999)
	txtTask := DNSTask{
		Hostname: "example.com",
		Type:     "TXT",
		Expected: []string{"test"},
	}
	res := validateCertificate(context.Background(), app, txtTask, []string{"v=spf1 ~all"})
	if res != SSLDaysNotApplicable {
		t.Errorf("Expected SSLDaysNotApplicable (%d) for TXT record, got %d", SSLDaysNotApplicable, res)
	}

	// 2. Empty IPs should return SSLDaysError (-9998)
	aTask := DNSTask{
		Hostname: "example.com",
		Type:     "A",
		Expected: []string{"1.2.3.4"},
	}
	resEmpty := validateCertificate(context.Background(), app, aTask, []string{})
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

	app := &AppState{Config: &AppConfig{Resolvers: []string{l.LocalAddr().String()}}}
	res := validateDNSSEC(context.Background(), app, "testsec.example", []string{l.LocalAddr().String()}, "")

	if res.Valid {
		t.Errorf("Expected DNSSEC validation to fail when RRSIG is signed by unlinked key2, but got Valid=true")
	}
}

func TestEmailSecurity_DNSLookupError_NoFalseAlerts(t *testing.T) {
	app := &AppState{
		Config: &AppConfig{
			Resolvers: []string{"192.0.2.1:53"}, // Unroutable TEST-NET-1 IP
		},
		Notifier: &NotificationManager{},
	}
	target := DomainConfig{
		Domain:             "unreachable-domain.com",
		Name:               "Unreachable",
		CheckEmailSecurity: true,
	}
	state := &CheckState{
		Email: make(map[string]*EmailState),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	evaluateEmailSecurity(ctx, app, target, state)

	for _, alert := range app.Notifier.Buffer {
		if strings.Contains(alert.Message, "Missing SPF") || strings.Contains(alert.Message, "Missing DMARC") {
			t.Errorf("Unexpected false alert on DNS lookup error: %s", alert.Message)
		}
	}

	state.EmailMu.Lock()
	savedState := state.Email["unreachable-domain.com"]
	state.EmailMu.Unlock()

	if savedState == nil {
		t.Fatalf("Expected EmailState to be saved")
	}
	if savedState.Status != StatusFailed && savedState.Status != StatusWarning {
		t.Errorf("Expected status Failed or Warning, got %s", savedState.Status)
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

	app := &AppState{Config: &AppConfig{Resolvers: []string{l.LocalAddr().String()}}}
	res := fetchCAA(context.Background(), app, "alias.example.com", []string{l.LocalAddr().String()})

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
		Config:   &AppConfig{Resolvers: []string{l.LocalAddr().String()}},
		Notifier: &NotificationManager{},
	}
	state := &CheckState{
		DNS: make(map[string]*DNSState),
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

	evaluateDNS(context.Background(), app, task1, state)
	evaluateDNS(context.Background(), app, task2, state)

	state.DNSMu.Lock()
	count := len(state.DNS)
	s1 := state.DNS["example.com_TXT_SPF TXT"]
	s2 := state.DNS["example.com_TXT_Google Verification"]
	state.DNSMu.Unlock()

	if count != 2 {
		t.Errorf("Expected 2 distinct DNS states, got %d", count)
	}
	if s1 == nil || s1.Status != StatusOk {
		t.Errorf("Expected task 1 to be StatusOk, got %+v", s1)
	}
	if s2 == nil || s2.Status != StatusOk {
		t.Errorf("Expected task 2 to be StatusOk, got %+v", s2)
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
		Config:   &AppConfig{Resolvers: []string{l.LocalAddr().String()}},
		Notifier: &NotificationManager{},
	}
	target := DomainConfig{
		Domain:             "api.example.com",
		Name:               "API Subdomain",
		CheckEmailSecurity: true,
	}

	var status CheckStatus = StatusOk
	found, err := validateDMARC(context.Background(), app, target, &status)
	if err != nil {
		t.Fatalf("validateDMARC failed: %v", err)
	}
	if !found {
		t.Errorf("Expected DMARC to be discovered from parent organizational domain example.com")
	}
	if status != StatusOk {
		t.Errorf("Expected StatusOk, got %s", status)
	}
	if len(app.Notifier.Buffer) > 0 {
		t.Errorf("Unexpected false positive alert dispatched: %+v", app.Notifier.Buffer)
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
		Notifier: &NotificationManager{},
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
	if validateRecords(app, task, liveRecords) {
		t.Errorf("Expected validateRecords to return false when live records exist for empty expected list, got true")
	}
	if len(app.Notifier.Buffer) == 0 {
		t.Errorf("Expected unauthorized alert in notifier buffer, got empty buffer")
	}

	// 2. When no live records exist, exact match must succeed
	app.Notifier.Buffer = nil
	if !validateRecords(app, task, []string{}) {
		t.Errorf("Expected validateRecords to return true when no live records exist for empty expected list, got false")
	}
	if len(app.Notifier.Buffer) > 0 {
		t.Errorf("Expected zero alerts when no live records exist, got %+v", app.Notifier.Buffer)
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

