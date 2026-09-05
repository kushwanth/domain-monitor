package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestLoadConfig(t *testing.T) {
	tests := []struct {
		name        string
		configJSON  string
		envVars     map[string]string
		expectErr   bool
		errContains string
		validate    func(*testing.T, *AppState)
	}{
		{
			name: "Valid Config",
			configJSON: `{
				"port": "9090",
				"loop_interval": "1h",
				"request_delay": "2s",
				"whois_delay": "3s",
				"domains": [
					{
						"domain": "EXAMPLE.COM.",
						"name": "Test Domain",
						"expected_ns": ["NS1.EXAMPLE.COM."],
						"check_email_security": true,
						"mail_provider": "GOOGLE",
						"dkim_selectors": ["SEL1"],
						"caa": {
							"issue": ["LETSENCRYPT.ORG"],
							"issuewild": ["LETSENCRYPT.ORG"],
							"issuemail": ["LETSENCRYPT.ORG"]
						}
					}
				],
				"dns_records": [
					{
						"hostname": "WWW.EXAMPLE.COM.",
						"name": "WWW A Record",
						"type": "a",
						"expected": ["93.184.215.14"]
					}
				]
			}`,
			expectErr: false,
			validate: func(t *testing.T, app *AppState) {
				if app.Config.Port != "9090" {
					t.Errorf("Expected port 9090, got %s", app.Config.Port)
				}
				if app.LoopDuration != 1*time.Hour {
					t.Errorf("Expected 1h loop duration, got %v", app.LoopDuration)
				}
				if app.ReqDelay != 2*time.Second {
					t.Errorf("Expected 2s req delay, got %v", app.ReqDelay)
				}
				if app.WhoisDelay != 3*time.Second {
					t.Errorf("Expected 3s whois delay, got %v", app.WhoisDelay)
				}
				d := app.Config.Domains[0]
				if d.Domain != "example.com" {
					t.Errorf("Expected domain example.com, got %s", d.Domain)
				}
				if d.ExpectedNS[0] != "ns1.example.com" {
					t.Errorf("Expected ns1.example.com, got %s", d.ExpectedNS[0])
				}
				if d.MailProvider != "google" {
					t.Errorf("Expected mail_provider google, got %s", d.MailProvider)
				}
				if d.DKIMSelectors[0] != "sel1" {
					t.Errorf("Expected dkim selector sel1, got %s", d.DKIMSelectors[0])
				}
				if d.CAA.Issue[0] != "letsencrypt.org" {
					t.Errorf("Expected issue letsencrypt.org, got %s", d.CAA.Issue[0])
				}
				r := app.Config.DNSRecords[0]
				if r.Hostname != "www.example.com" {
					t.Errorf("Expected hostname www.example.com, got %s", r.Hostname)
				}
				if r.Type != "A" {
					t.Errorf("Expected type A, got %s", r.Type)
				}
			},
		},
		{
			name: "CAA Config Normalization with Deny All and Skipped Tags",
			configJSON: `{
				"domains": [
					{
						"domain": "example.com",
						"name": "Example",
						"caa": {
							"issue": ["letsencrypt.org; validationmethods=dns-01", "digicert.com"],
							"issuewild": [],
							"issuemail": [";"]
						}
					},
					{
						"domain": "skipped.com",
						"name": "Skipped",
						"caa": {
							"issue": ["letsencrypt.org"]
						}
					}
				]
			}`,
			expectErr: false,
			validate: func(t *testing.T, app *AppState) {
				d1 := app.Config.Domains[0]
				if len(d1.CAA.Issue) != 2 || d1.CAA.Issue[0] != "letsencrypt.org" || d1.CAA.Issue[1] != "digicert.com" {
					t.Errorf("Expected 2 normalized issue CAs (letsencrypt.org, digicert.com), got %v", d1.CAA.Issue)
				}
				// issuewild: [] should be empty slice (len 0, non-nil)
				if d1.CAA.IssueWild == nil || len(d1.CAA.IssueWild) != 0 {
					t.Errorf("Expected issuewild to be empty non-nil slice, got %v", d1.CAA.IssueWild)
				}
				// issuemail: [";"] should be normalized to empty slice (len 0, non-nil)
				if d1.CAA.IssueMail == nil || len(d1.CAA.IssueMail) != 0 {
					t.Errorf("Expected issuemail to be empty non-nil slice, got %v", d1.CAA.IssueMail)
				}

				d2 := app.Config.Domains[1]
				if d2.CAA.IssueWild != nil {
					t.Errorf("Expected omitted issuewild to remain nil, got %v", d2.CAA.IssueWild)
				}
				if d2.CAA.IssueMail != nil {
					t.Errorf("Expected omitted issuemail to remain nil, got %v", d2.CAA.IssueMail)
				}
			},
		},
		{
			name: "RFC 7505 Null MX Normalization",
			configJSON: `{
				"domains": [
					{
						"domain": "nomail.example.com",
						"name": "NoMail Domain",
						"check_email_security": true,
						"mx_records": ["."]
					}
				]
			}`,
			expectErr: false,
			validate: func(t *testing.T, app *AppState) {
				d := app.Config.Domains[0]
				if len(d.MXRecords) != 1 || d.MXRecords[0] != "." {
					t.Errorf("Expected Null MX '.' to be preserved, got %v", d.MXRecords)
				}
			},
		},
		{
			name: "Missing Domain Name",
			configJSON: `{
				"domains": [{"domain": "example.com"}]
			}`,
			expectErr:   true,
			errContains: "missing a mandatory 'name' field",
		},
		{
			name: "Delegated Zone Missing Root Zone",
			configJSON: `{
				"domains": [{"domain": "api.example.com", "name": "API", "is_delegated_zone": true}]
			}`,
			expectErr:   true,
			errContains: "missing a mandatory 'root_zone' field",
		},
		{
			name: "Mail Provider and MX Records Mutually Exclusive",
			configJSON: `{
				"domains": [{
					"domain": "example.com",
					"name": "Example",
					"check_email_security": true,
					"mail_provider": "google",
					"mx_records": ["mail.example.com"]
				}]
			}`,
			expectErr:   true,
			errContains: "mutually exclusive",
		},
		{
			name: "DNS Record Missing Name",
			configJSON: `{
				"dns_records": [{"hostname": "example.com", "type": "A"}]
			}`,
			expectErr:   true,
			errContains: "missing a mandatory 'name' field",
		},
		{
			name: "DNS Record Missing Type",
			configJSON: `{
				"dns_records": [{"hostname": "example.com", "name": "Apex"}]
			}`,
			expectErr:   true,
			errContains: "missing a type",
		},
		{
			name: "Exceeding Max Resolvers",
			configJSON: `{
				"resolvers": ["1.1.1.1", "8.8.8.8", "9.9.9.9", "1.0.0.1", "8.8.4.4", "9.9.9.10", "208.67.222.222", "208.67.220.220", "84.200.69.80", "84.200.70.40"]
			}`,
			expectErr:   true,
			errContains: "exceed maximum limit of 9",
		},
		{
			name: "Resolvers Config",
			configJSON: `{
				"resolvers": ["1.1.1.1:53", "8.8.8.8", "9.9.9.9"],
				"domains": [{"domain": "example.com", "name": "Example"}]
			}`,
			expectErr: false,
			validate: func(t *testing.T, app *AppState) {
				if len(app.Config.Resolvers) != 3 {
					t.Errorf("Expected 3 resolvers, got %d", len(app.Config.Resolvers))
				}
			},
		},
		{
			name: "Environment Variable Overrides",
			configJSON: `{
				"domains": [{"domain": "example.com", "name": "Example"}]
			}`,
			envVars: map[string]string{
				"PORT":             "8888",
				"TELEGRAM_TOKEN":   "test-token",
				"TELEGRAM_CHAT_ID": "12345",
				"CTLOGS_API_KEY":   "ct-key-abc",
				"DOH_URL":          "https://custom-doh.com/resolve",
			},
			expectErr: false,
			validate: func(t *testing.T, app *AppState) {
				if app.Config.Port != "8888" {
					t.Errorf("Expected port 8888 from env, got %s", app.Config.Port)
				}
				if app.Config.Notifications.Telegram == nil || app.Config.Notifications.Telegram.Token != "test-token" {
					t.Errorf("Expected telegram token test-token, got %+v", app.Config.Notifications.Telegram)
				}
				if app.Config.CTLogsAPIKey != "ct-key-abc" {
					t.Errorf("Expected ctlogs key ct-key-abc, got %s", app.Config.CTLogsAPIKey)
				}
				if app.Config.DoHURL != "https://custom-doh.com/resolve" {
					t.Errorf("Expected custom DoH URL, got %s", app.Config.DoHURL)
				}
			},
		},
		{
			name: "Empty Domain Rejection",
			configJSON: `{
				"domains": [{"domain": "", "name": "Empty"}]
			}`,
			expectErr:   true,
			errContains: "empty domain",
		},
		{
			name: "Multiple Domain Entries Allowed",
			configJSON: `{
				"domains": [
					{"domain": "example.com", "name": "Primary"},
					{"domain": "EXAMPLE.COM.", "name": "Secondary View"}
				]
			}`,
			expectErr: false,
			validate: func(t *testing.T, app *AppState) {
				if len(app.Config.Domains) != 2 {
					t.Errorf("Expected 2 domain entries, got %d", len(app.Config.Domains))
				}
			},
		},
		{
			name: "Empty Hostname Rejection",
			configJSON: `{
				"dns_records": [{"hostname": "", "name": "NoHost", "type": "A"}]
			}`,
			expectErr:   true,
			errContains: "empty hostname",
		},
		{
			name: "Non-positive Durations Default Gracefully",
			configJSON: `{
				"loop_interval": "-1h",
				"request_delay": "-5s",
				"whois_delay": "-10s",
				"domains": [{"domain": "example.com", "name": "Example"}]
			}`,
			expectErr: false,
			validate: func(t *testing.T, app *AppState) {
				if app.LoopDuration != 6*time.Hour {
					t.Errorf("Expected fallback 6h, got %v", app.LoopDuration)
				}
				if app.ReqDelay != 5*time.Second {
					t.Errorf("Expected fallback 5s, got %v", app.ReqDelay)
				}
				if app.WhoisDelay != 10*time.Second {
					t.Errorf("Expected fallback 10s, got %v", app.WhoisDelay)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for k, v := range tt.envVars {
				t.Setenv(k, v)
			}

			tmpDir := t.TempDir()
			cfgPath := tmpDir + "/config.json"
			if err := os.WriteFile(cfgPath, []byte(tt.configJSON), 0644); err != nil {
				t.Fatalf("failed to write test config file: %v", err)
			}

			app, err := LoadConfig(context.Background(), cfgPath)
			if tt.expectErr {
				if err == nil {
					t.Fatalf("Expected error containing '%s', got nil", tt.errContains)
				}
				if tt.errContains != "" {
					if !strings.Contains(err.Error(), tt.errContains) {
						t.Errorf("Expected error to contain '%s', got '%v'", tt.errContains, err)
					}
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if tt.validate != nil {
				tt.validate(t, app)
			}
		})
	}
}

func TestInitializeDependencies_ResolverResilience(t *testing.T) {
	mux := dns.NewServeMux()
	mux.HandleFunc("example.com.", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		rr, _ := dns.NewRR("example.com. 300 IN A 93.184.215.14")
		m.Answer = append(m.Answer, rr)
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

	localAddr := l.LocalAddr().String()

	// Scenario 1: One valid resolver, one invalid resolver
	app1 := &AppState{
		Config: &AppConfig{
			Resolvers: []string{localAddr, "192.0.2.1:53"}, // 192.0.2.1 is unroutable TEST-NET-1
		},
		Notifier: &NotificationManager{},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 7*time.Second)
	defer cancel()

	err = InitializeDependencies(ctx, app1)
	if err != nil {
		t.Errorf("Expected InitializeDependencies to succeed with 1 healthy resolver, got error: %v", err)
	}
	if len(app1.Config.Resolvers) != 1 || app1.Config.Resolvers[0] != localAddr {
		t.Errorf("Expected resolvers to contain only healthy %s, got %v", localAddr, app1.Config.Resolvers)
	}

	// Scenario 2: All resolvers invalid
	app2 := &AppState{
		Config: &AppConfig{
			Resolvers: []string{"192.0.2.1:53", "192.0.2.2:53"},
		},
		Notifier: &NotificationManager{},
	}
	ctx2, cancel2 := context.WithTimeout(context.Background(), 7*time.Second)
	defer cancel2()

	err2 := InitializeDependencies(ctx2, app2)
	if err2 == nil {
		t.Errorf("Expected error when all resolvers fail health check, got nil")
	}
}

func TestIDNNormalizationAndAliasCase(t *testing.T) {
	configJSON := `{
		"domains": [
			{
				"domain": "münchen.de",
				"name": "Munich Domain",
				"expected_ns": ["ns1.münchen.de"],
				"check_email_security": true,
				"mx_records": ["mail.münchen.de"]
			}
		],
		"dns_records": [
			{
				"hostname": "münchen.de",
				"name": "Alias Record",
				"type": "CNAME",
				"expected": ["ALIAS:target.münchen.de"]
			}
		]
	}`

	tmpDir := t.TempDir()
	cfgPath := tmpDir + "/config.json"
	if err := os.WriteFile(cfgPath, []byte(configJSON), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	app, err := LoadConfig(context.Background(), cfgPath)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	d := app.Config.Domains[0]
	if d.Domain != "xn--mnchen-3ya.de" {
		t.Errorf("Expected Punycode xn--mnchen-3ya.de, got %s", d.Domain)
	}
	if d.ExpectedNS[0] != "ns1.xn--mnchen-3ya.de" {
		t.Errorf("Expected Punycode NS ns1.xn--mnchen-3ya.de, got %s", d.ExpectedNS[0])
	}
	if d.MXRecords[0] != "mail.xn--mnchen-3ya.de" {
		t.Errorf("Expected Punycode MX mail.xn--mnchen-3ya.de, got %s", d.MXRecords[0])
	}

	r := app.Config.DNSRecords[0]
	if r.Hostname != "xn--mnchen-3ya.de" {
		t.Errorf("Expected Punycode Hostname xn--mnchen-3ya.de, got %s", r.Hostname)
	}
	if len(r.Expected) == 0 || r.Expected[0] != "target.xn--mnchen-3ya.de" {
		t.Errorf("Expected stripped and Punycode expected target.xn--mnchen-3ya.de, got %v", r.Expected)
	}
}

func TestConfig_RegistrarBothAllowed(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()

	// Both set -> config allows both
	bothJSON := `{
		"domains": [
			{
				"domain": "example.com",
				"name": "Both Registrar Fields Test",
				"expected_registrar_id": "292",
				"expected_registrar_name": "markmonitor"
			}
		]
	}`
	cfgPath := tmpDir + "/both_reg.json"
	if err := os.WriteFile(cfgPath, []byte(bothJSON), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}
	appBoth, err := LoadConfig(context.Background(), cfgPath)
	if err != nil {
		t.Fatalf("Expected config with both registrar fields to load successfully, got error: %v", err)
	}
	if appBoth.Config.Domains[0].ExpectedRegistrarID != "292" {
		t.Errorf("Expected ExpectedRegistrarID '292', got %q", appBoth.Config.Domains[0].ExpectedRegistrarID)
	}
	if appBoth.Config.Domains[0].ExpectedRegistrarName != "markmonitor" {
		t.Errorf("Expected ExpectedRegistrarName 'markmonitor', got %q", appBoth.Config.Domains[0].ExpectedRegistrarName)
	}

	// Only ID set -> valid
	validIDJSON := `{
		"domains": [
			{
				"domain": "example.com",
				"name": "Registrar ID Test",
				"expected_registrar_id": "292"
			}
		]
	}`
	cfgPathID := tmpDir + "/valid_id.json"
	_ = os.WriteFile(cfgPathID, []byte(validIDJSON), 0644)
	appID, err := LoadConfig(context.Background(), cfgPathID)
	if err != nil {
		t.Fatalf("Expected valid config with only expected_registrar_id, got error: %v", err)
	}
	if appID.Config.Domains[0].ExpectedRegistrarID != "292" {
		t.Errorf("Expected ExpectedRegistrarID '292', got %q", appID.Config.Domains[0].ExpectedRegistrarID)
	}

	// Only Name set -> valid
	validNameJSON := `{
		"domains": [
			{
				"domain": "example.com",
				"name": "Registrar Name Test",
				"expected_registrar_name": "markmonitor"
			}
		]
	}`
	cfgPathName := tmpDir + "/valid_name.json"
	_ = os.WriteFile(cfgPathName, []byte(validNameJSON), 0644)
	appName, err := LoadConfig(context.Background(), cfgPathName)
	if err != nil {
		t.Fatalf("Expected valid config with only expected_registrar_name, got error: %v", err)
	}
	if appName.Config.Domains[0].ExpectedRegistrarName != "markmonitor" {
		t.Errorf("Expected ExpectedRegistrarName 'markmonitor', got %q", appName.Config.Domains[0].ExpectedRegistrarName)
	}
}

func TestConfig_VerifyNSHealthRequirements(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()

	// 1. verify_ns_health: true but no expected_ns -> must error
	invalidJSON1 := `{
		"domains": [
			{
				"domain": "example.com",
				"name": "No Expected NS Test",
				"verify_ns_health": true,
				"secondary_ns": ["slave.example.com"]
			}
		]
	}`
	cfgPath1 := tmpDir + "/invalid_ns_health1.json"
	_ = os.WriteFile(cfgPath1, []byte(invalidJSON1), 0644)
	_, err1 := LoadConfig(context.Background(), cfgPath1)
	if err1 == nil || !strings.Contains(err1.Error(), "no primary expected_ns") {
		t.Fatalf("Expected error when verify_ns_health is enabled without expected_ns, got: %v", err1)
	}

	// 2. verify_ns_health: true with expected_ns but no secondary_ns -> valid (secondary_ns is optional)
	validPrimaryOnlyJSON := `{
		"domains": [
			{
				"domain": "example.com",
				"name": "Primary Only NS Health Test",
				"expected_ns": ["ns1.example.com"],
				"verify_ns_health": true
			}
		]
	}`
	cfgPath2 := tmpDir + "/valid_primary_only.json"
	_ = os.WriteFile(cfgPath2, []byte(validPrimaryOnlyJSON), 0644)
	app2, err2 := LoadConfig(context.Background(), cfgPath2)
	if err2 != nil {
		t.Fatalf("Expected valid config when secondary_ns is omitted, got error: %v", err2)
	}
	if len(app2.Config.Domains[0].SecondaryNS) != 0 {
		t.Errorf("Expected 0 secondary_ns, got %v", app2.Config.Domains[0].SecondaryNS)
	}

	// 3. verify_ns_health: true with both expected_ns and secondary_ns -> valid
	validJSON := `{
		"domains": [
			{
				"domain": "example.com",
				"name": "Valid Dual-DNS",
				"expected_ns": ["ns1.example.com"],
				"secondary_ns": ["slave.otherprovider.com"],
				"verify_ns_health": true
			}
		]
	}`
	cfgPath3 := tmpDir + "/valid_ns_health.json"
	_ = os.WriteFile(cfgPath3, []byte(validJSON), 0644)
	app, err3 := LoadConfig(context.Background(), cfgPath3)
	if err3 != nil {
		t.Fatalf("Expected valid config with expected_ns and secondary_ns, got error: %v", err3)
	}
	if len(app.Config.Domains[0].SecondaryNS) != 1 || app.Config.Domains[0].SecondaryNS[0] != "slave.otherprovider.com" {
		t.Errorf("Expected secondary_ns 'slave.otherprovider.com', got %v", app.Config.Domains[0].SecondaryNS)
	}

	// 4. empty entry in expected_ns -> must error
	emptyExpectedNSJSON := `{
		"domains": [
			{
				"domain": "example.com",
				"name": "Empty Expected NS Test",
				"expected_ns": ["   "]
			}
		]
	}`
	cfgPath4 := tmpDir + "/empty_expected_ns.json"
	_ = os.WriteFile(cfgPath4, []byte(emptyExpectedNSJSON), 0644)
	_, err4 := LoadConfig(context.Background(), cfgPath4)
	if err4 == nil || !strings.Contains(err4.Error(), "empty entry in expected_ns") {
		t.Fatalf("Expected error for empty entry in expected_ns, got: %v", err4)
	}

	// 5. empty entry in secondary_ns -> must error
	emptySecondaryNSJSON := `{
		"domains": [
			{
				"domain": "example.com",
				"name": "Empty Secondary NS Test",
				"expected_ns": ["ns1.example.com"],
				"secondary_ns": [""]
			}
		]
	}`
	cfgPath5 := tmpDir + "/empty_secondary_ns.json"
	_ = os.WriteFile(cfgPath5, []byte(emptySecondaryNSJSON), 0644)
	_, err5 := LoadConfig(context.Background(), cfgPath5)
	if err5 == nil || !strings.Contains(err5.Error(), "empty entry in secondary_ns") {
		t.Fatalf("Expected error for empty entry in secondary_ns, got: %v", err5)
	}

	// 6. secondary_ns configured but no expected_ns -> must error
	secondaryNoExpectedJSON := `{
		"domains": [
			{
				"domain": "example.com",
				"name": "Secondary Without Expected Test",
				"secondary_ns": ["b.iana-servers.net"]
			}
		]
	}`
	cfgPath6 := tmpDir + "/secondary_no_expected.json"
	_ = os.WriteFile(cfgPath6, []byte(secondaryNoExpectedJSON), 0644)
	_, err6 := LoadConfig(context.Background(), cfgPath6)
	if err6 == nil || !strings.Contains(err6.Error(), "no primary expected_ns configured") {
		t.Fatalf("Expected error for secondary_ns without expected_ns, got: %v", err6)
	}
}

func TestLoadDefaultConfigJsonnet(t *testing.T) {
	app, err := LoadConfig(context.Background(), "../config.jsonnet")
	if err != nil {
		t.Fatalf("Failed to parse and load default repo config.jsonnet: %v", err)
	}
	if app == nil || app.Config == nil {
		t.Fatalf("Loaded app or AppConfig is nil")
	}
	if len(app.Config.Domains) == 0 {
		t.Errorf("Expected domains in config.jsonnet, got 0")
	}
}

func TestSkipSSLValidation(t *testing.T) {
	// 1. Valid record types that can have SSL: A, AAAA, CNAME, ALIAS, IP
	validTypes := []string{"A", "AAAA", "CNAME", "ALIAS", "IP"}
	for _, vt := range validTypes {
		t.Run("Valid_"+vt, func(t *testing.T) {
			expectedVal := `"1.2.3.4"`
			if vt == "AAAA" {
				expectedVal = `"2001:db8::1"`
			}
			cfgJSON := fmt.Sprintf(`{
				"dns_records": [
					{
						"hostname": "web.example.com",
						"name": "Web Test",
						"type": "%s",
						"expected": [%s],
						"skip_ssl": true
					}
				]
			}`, vt, expectedVal)
			tmpFile := t.TempDir() + "/valid_skip_ssl.json"
			if err := os.WriteFile(tmpFile, []byte(cfgJSON), 0644); err != nil {
				t.Fatalf("failed to write temp file: %v", err)
			}
			app, err := LoadConfig(context.Background(), tmpFile)
			if err != nil {
				t.Fatalf("expected valid config for skip_ssl with type %s, got error: %v", vt, err)
			}
			if !app.Config.DNSRecords[0].SkipSSL {
				t.Errorf("expected SkipSSL to be true for %s", vt)
			}
		})
	}

	// 2. Invalid record types for skip_ssl: TXT, MX, CAA, NS
	invalidTypes := []string{"TXT", "MX", "CAA", "NS"}
	for _, it := range invalidTypes {
		t.Run("Invalid_"+it, func(t *testing.T) {
			cfgJSON := fmt.Sprintf(`{
				"dns_records": [
					{
						"hostname": "record.example.com",
						"name": "Invalid Test",
						"type": "%s",
						"expected": ["something"],
						"skip_ssl": true
					}
				]
			}`, it)
			tmpFile := t.TempDir() + "/invalid_skip_ssl.json"
			if err := os.WriteFile(tmpFile, []byte(cfgJSON), 0644); err != nil {
				t.Fatalf("failed to write temp file: %v", err)
			}
			_, err := LoadConfig(context.Background(), tmpFile)
			if err == nil {
				t.Fatalf("expected validation error when skip_ssl is configured on %s, got nil", it)
			}
			if !strings.Contains(err.Error(), "skip_ssl is only applicable for A, AAAA, CNAME, ALIAS, and IP record types") {
				t.Errorf("expected error message to mention allowed types, got: %v", err)
			}
		})
	}

	// 3. Omitted skip_ssl defaults to false and succeeds for any valid record type
	t.Run("Default_Omitted", func(t *testing.T) {
		cfgJSON := `{
			"dns_records": [
				{
					"hostname": "record.example.com",
					"name": "Default Test",
					"type": "TXT",
					"expected": ["hello"]
				}
			]
		}`
		tmpFile := t.TempDir() + "/default_skip_ssl.json"
		if err := os.WriteFile(tmpFile, []byte(cfgJSON), 0644); err != nil {
			t.Fatalf("failed to write temp file: %v", err)
		}
		app, err := LoadConfig(context.Background(), tmpFile)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if app.Config.DNSRecords[0].SkipSSL {
			t.Errorf("expected SkipSSL to default to false")
		}
	})
}

func TestConfig_DuplicateDNSRecordName(t *testing.T) {
	cfgJSON := `{
		"dns_records": [
			{
				"hostname": "a.example.com",
				"name": "Duplicate Record",
				"type": "A",
				"expected": ["1.2.3.4"]
			},
			{
				"hostname": "b.example.com",
				"name": "Duplicate Record",
				"type": "A",
				"expected": ["1.2.3.5"]
			}
		]
	}`
	tmpFile := t.TempDir() + "/dup_name.json"
	if err := os.WriteFile(tmpFile, []byte(cfgJSON), 0644); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}
	_, err := LoadConfig(context.Background(), tmpFile)
	if err == nil {
		t.Fatalf("expected error for duplicate DNS record name, got nil")
	}
	if !strings.Contains(err.Error(), "duplicate dns record name \"Duplicate Record\"") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestConfig_StringListExpected(t *testing.T) {
	// 1. Single string in expected
	cfgJSON := `{
		"dns_records": [
			{
				"hostname": "single.example.com",
				"name": "Single String Expected",
				"type": "A",
				"expected": "1.2.3.4"
			},
			{
				"hostname": "slice.example.com",
				"name": "Slice Expected",
				"type": "A",
				"expected": ["5.6.7.8", "9.10.11.12"]
			}
		]
	}`
	tmpFile := t.TempDir() + "/stringlist.json"
	if err := os.WriteFile(tmpFile, []byte(cfgJSON), 0644); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}
	app, err := LoadConfig(context.Background(), tmpFile)
	if err != nil {
		t.Fatalf("failed to load config with StringList expected: %v", err)
	}
	if len(app.Config.DNSRecords[0].Expected) != 1 || app.Config.DNSRecords[0].Expected[0] != "1.2.3.4" {
		t.Errorf("expected single string parsed as slice of 1 element, got %v", app.Config.DNSRecords[0].Expected)
	}
	if len(app.Config.DNSRecords[1].Expected) != 2 {
		t.Errorf("expected slice parsed with 2 elements, got %v", app.Config.DNSRecords[1].Expected)
	}
}

func TestConfig_TypeSpecificIPValidation(t *testing.T) {
	// A record with IPv6 should fail
	t.Run("A_RejectIPv6", func(t *testing.T) {
		cfgJSON := `{
			"dns_records": [
				{
					"hostname": "a.example.com",
					"name": "Bad A",
					"type": "A",
					"expected": ["2001:db8::1"]
				}
			]
		}`
		tmpFile := t.TempDir() + "/bad_a.json"
		if err := os.WriteFile(tmpFile, []byte(cfgJSON), 0644); err != nil {
			t.Fatalf("failed to write temp file: %v", err)
		}
		_, err := LoadConfig(context.Background(), tmpFile)
		if err == nil || !strings.Contains(err.Error(), "requires IPv4") {
			t.Errorf("expected error requiring IPv4, got %v", err)
		}
	})

	// AAAA record with IPv4 should fail
	t.Run("AAAA_RejectIPv4", func(t *testing.T) {
		cfgJSON := `{
			"dns_records": [
				{
					"hostname": "aaaa.example.com",
					"name": "Bad AAAA",
					"type": "AAAA",
					"expected": ["1.2.3.4"]
				}
			]
		}`
		tmpFile := t.TempDir() + "/bad_aaaa.json"
		if err := os.WriteFile(tmpFile, []byte(cfgJSON), 0644); err != nil {
			t.Fatalf("failed to write temp file: %v", err)
		}
		_, err := LoadConfig(context.Background(), tmpFile)
		if err == nil || !strings.Contains(err.Error(), "requires IPv6") {
			t.Errorf("expected error requiring IPv6, got %v", err)
		}
	})

	// IP record accepts both IPv4 and IPv6 and canonicalizes them sorted
	t.Run("IP_AcceptsBothIPv4AndIPv6", func(t *testing.T) {
		cfgJSON := `{
			"dns_records": [
				{
					"hostname": "dual.example.com",
					"name": "Dual Stack IP",
					"type": "IP",
					"expected": ["2001:db8::1", "192.0.2.1", "2001:db8::1", "198.51.100.1"]
				}
			]
		}`
		tmpFile := t.TempDir() + "/dual.json"
		if err := os.WriteFile(tmpFile, []byte(cfgJSON), 0644); err != nil {
			t.Fatalf("failed to write temp file: %v", err)
		}
		app, err := LoadConfig(context.Background(), tmpFile)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		expected := app.Config.DNSRecords[0].Expected
		// Deduplicated: 3 elements ("192.0.2.1", "198.51.100.1", "2001:db8::1")
		if len(expected) != 3 {
			t.Fatalf("expected 3 canonicalized elements, got %d: %v", len(expected), expected)
		}
		if !slices.IsSorted(expected) {
			t.Errorf("expected elements to be sorted, got %v", expected)
		}
	})
}


