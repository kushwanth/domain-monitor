package main

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadConfigInjectedReader(t *testing.T) {
	for _, tc := range []struct {
		name    string
		content string
		readErr error
		wantErr string
	}{
		{name: "valid", content: `{"notifications":{"ntfy":{"url":"https://ntfy.invalid/topic"}}}`},
		{name: "read error", readErr: os.ErrPermission, wantErr: "read"},
		{name: "invalid JSON", content: `{`, wantErr: "unmarshal"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			cfg, err := loadConfig(context.Background(), "memory.json", func(path string) ([]byte, error) {
				assert.Equal(t, "memory.json", path)
				called = true
				return []byte(tc.content), tc.readErr
			})
			assert.True(t, called)
			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)
				if tc.readErr != nil {
					assert.True(t, errors.Is(err, tc.readErr))
				}
				return
			}
			require.NoError(t, err)
			assert.Equal(t, DefaultServerPort, cfg.Port)
		})
	}
}

func TestUnusedDomainConfigAndLegacyMigration(t *testing.T) {
	configJSON := `{"notifications":{"ntfy":{"url":"https://ntfy.invalid/topic"}},"domains":[{"domain":"unused-one.example","name":"Unused One","unused":true},{"domain":"unused-two.example","name":"Unused Two","unused":true,"allow_expiry":true},{"domain":"renewing.example","name":"Renewing","allow_expiry":true}]}`
	cfg, err := loadConfig(context.Background(), "memory.json", func(string) ([]byte, error) {
		return []byte(configJSON), nil
	})
	require.NoError(t, err)
	require.Len(t, cfg.Domains, 3)
	assert.True(t, cfg.Domains[0].Unused)
	assert.True(t, cfg.Domains[1].Unused)
	assert.True(t, cfg.Domains[2].Unused)

	state := prepareCycleState(cfg.Domains)
	assert.True(t, state.RDAP["unused-one.example"].Unused)
	assert.True(t, state.RDAP["unused-two.example"].Unused)
	assert.True(t, state.RDAP["renewing.example"].Unused)
	assert.Equal(t, StatusSkipped, state.RDAP["renewing.example"].Status)
}

func FuzzNormalizeExpectedDNSValue(f *testing.F) {
	for _, seed := range []struct{ recordType, value string }{
		{RecordTypeA, "192.0.2.1"},
		{RecordTypeAAAA, "2001:db8::1"},
		{RecordTypeIP, "not-an-ip"},
		{RecordTypeALIAS, "alias:example.com"},
		{RecordTypeTXT, "v=spf1 -all"},
	} {
		f.Add(seed.recordType, seed.value)
	}
	f.Fuzz(func(t *testing.T, recordType, value string) {
		switch recordType {
		case RecordTypeA, RecordTypeAAAA, RecordTypeIP, RecordTypeALIAS, RecordTypeTXT:
		default:
			return
		}
		got, err := normalizeExpectedDNSValue(DNSTask{Type: recordType, Name: "fuzz", Hostname: "example.com"}, value)
		if err != nil || got == "" {
			return
		}
		if recordType == RecordTypeA || recordType == RecordTypeAAAA || recordType == RecordTypeIP {
			ip := net.ParseIP(got)
			require.NotNil(t, ip)
			switch recordType {
			case RecordTypeA:
				assert.NotNil(t, ip.To4())
			case RecordTypeAAAA:
				assert.Nil(t, ip.To4())
			}
		}
	})
}

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
			configJSON: `{"notifications":{"ntfy":{"url":"https://ntfy.invalid/topic"}},
				"port": "9090",
				"loop_interval_days": 1.0,
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
				if app.Config().Port != "9090" {
					t.Errorf("Expected port 9090, got %s", app.Config().Port)
				}
				if app.LoopDuration != 24*time.Hour {
					t.Errorf("Expected 24h loop duration, got %v", app.LoopDuration)
				}

				d := app.Config().Domains[0]
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

				r := app.Config().DNSRecords[0]
				if r.Hostname != "www.example.com" {
					t.Errorf("Expected hostname www.example.com, got %s", r.Hostname)
				}
				if r.Type != "A" {
					t.Errorf("Expected type A, got %s", r.Type)
				}
			},
		},

		{
			name: "RFC 7505 Null MX Normalization",
			configJSON: `{"notifications":{"ntfy":{"url":"https://ntfy.invalid/topic"}},
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
				d := app.Config().Domains[0]
				if len(d.MXRecords) != 1 || d.MXRecords[0] != "." {
					t.Errorf("Expected Null MX '.' to be preserved, got %v", d.MXRecords)
				}
			},
		},
		{
			name: "Missing Domain Name",
			configJSON: `{"notifications":{"ntfy":{"url":"https://ntfy.invalid/topic"}},
				"domains": [{"domain": "example.com"}]
			}`,
			expectErr:   true,
			errContains: "missing a mandatory 'name' field",
		},
		{
			name: "Delegated Zone Missing Root Zone",
			configJSON: `{"notifications":{"ntfy":{"url":"https://ntfy.invalid/topic"}},
				"domains": [{"domain": "api.example.com", "name": "API", "is_delegated_zone": true}]
			}`,
			expectErr:   true,
			errContains: "missing a mandatory 'root_zone' field",
		},
		{
			name: "Mail Provider and MX Records Mutually Exclusive",
			configJSON: `{"notifications":{"ntfy":{"url":"https://ntfy.invalid/topic"}},
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
			configJSON: `{"notifications":{"ntfy":{"url":"https://ntfy.invalid/topic"}},
				"dns_records": [{"hostname": "example.com", "type": "A"}]
			}`,
			expectErr:   true,
			errContains: "missing a mandatory 'name' field",
		},
		{
			name: "DNS Record Missing Type",
			configJSON: `{"notifications":{"ntfy":{"url":"https://ntfy.invalid/topic"}},
				"dns_records": [{"hostname": "example.com", "name": "Apex"}]
			}`,
			expectErr:   true,
			errContains: "missing a type",
		},
		{
			name: "Exceeding Max Resolvers",
			configJSON: `{"notifications":{"ntfy":{"url":"https://ntfy.invalid/topic"}},
				"resolvers": ["1.1.1.1", "8.8.8.8", "9.9.9.9", "1.0.0.1", "8.8.4.4", "9.9.9.10", "208.67.222.222", "208.67.220.220", "84.200.69.80", "84.200.70.40"]
			}`,
			expectErr:   true,
			errContains: "exceed maximum limit of 9",
		},
		{
			name: "Resolvers Config",
			configJSON: `{"notifications":{"ntfy":{"url":"https://ntfy.invalid/topic"}},
				"resolvers": ["1.1.1.1:53", "8.8.8.8", "9.9.9.9"],
				"domains": [{"domain": "example.com", "name": "Example"}]
			}`,
			expectErr: false,
			validate: func(t *testing.T, app *AppState) {
				if len(app.Config().Resolvers) != 3 {
					t.Errorf("Expected 3 resolvers, got %d", len(app.Config().Resolvers))
				}
			},
		},
		{
			name: "Environment Variable Overrides",
			configJSON: `{"notifications":{"ntfy":{"url":"https://ntfy.invalid/topic"}},
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
				if app.Config().Port != "8888" {
					t.Errorf("Expected port 8888 from env, got %s", app.Config().Port)
				}
				if app.Config().Notifications.Telegram == nil || app.Config().Notifications.Telegram.Token != "test-token" {
					t.Errorf("Expected telegram token test-token, got %+v", app.Config().Notifications.Telegram)
				}

				if app.Config().DoHURL != "https://custom-doh.com/resolve" {
					t.Errorf("Expected custom DoH URL, got %s", app.Config().DoHURL)
				}
			},
		},
		{
			name: "Empty Domain Rejection",
			configJSON: `{"notifications":{"ntfy":{"url":"https://ntfy.invalid/topic"}},
				"domains": [{"domain": "", "name": "Empty"}]
			}`,
			expectErr:   true,
			errContains: "empty domain",
		},
		{
			name: "Duplicate Domain Rejection",
			configJSON: `{"notifications":{"ntfy":{"url":"https://ntfy.invalid/topic"}},
				"domains": [
					{"domain": "example.com", "name": "Primary"},
					{"domain": "EXAMPLE.COM.", "name": "Secondary View"}
				]
			}`,
			expectErr:   true,
			errContains: "duplicate domain \"example.com\"",
		},
		{
			name: "Multiple Unique Domain Entries Allowed",
			configJSON: `{"notifications":{"ntfy":{"url":"https://ntfy.invalid/topic"}},
				"domains": [
					{"domain": "example.com", "name": "Primary"},
					{"domain": "example.net", "name": "Secondary View"}
				]
			}`,
			expectErr: false,
			validate: func(t *testing.T, app *AppState) {
				if len(app.Config().Domains) != 2 {
					t.Errorf("Expected 2 domain entries, got %d", len(app.Config().Domains))
				}
			},
		},
		{
			name: "Empty Hostname Rejection",
			configJSON: `{"notifications":{"ntfy":{"url":"https://ntfy.invalid/topic"}},
				"dns_records": [{"hostname": "", "name": "NoHost", "type": "A"}]
			}`,
			expectErr:   true,
			errContains: "empty hostname",
		},
		{
			name: "Non-positive Durations Default Gracefully",
			configJSON: `{"notifications":{"ntfy":{"url":"https://ntfy.invalid/topic"}},
				"loop_interval_days": -1,
				"domains": [{"domain": "example.com", "name": "Example"}]
			}`,
			expectErr: false,
			validate: func(t *testing.T, app *AppState) {
				if app.LoopDuration != 3*time.Hour {
					t.Errorf("Expected fallback 3h (0.125 days), got %v", app.LoopDuration)
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

			cfg, err := LoadConfig(context.Background(), cfgPath)
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
				app := NewAppState(cfg)
				tt.validate(t, app)
			}
		})
	}
}

func TestInitializeApp_ResolverResilience(t *testing.T) {
	for _, tc := range []struct {
		name          string
		notifications Notifications
		wantNotifier  bool
	}{
		{name: "none"},
		{name: "ntfy", notifications: Notifications{Ntfy: &NtfyConfig{URL: "https://ntfy.invalid/topic"}}, wantNotifier: true},
		{name: "telegram", notifications: Notifications{Telegram: &TelegramConfig{Token: "token", ChatID: "chat"}}, wantNotifier: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := AppConfig{Resolvers: []string{"192.0.2.1:53", "192.0.2.2:53"}, Notifications: tc.notifications}
			app, err := InitializeApp(context.Background(), cfg)
			require.NoError(t, err)
			assert.Equal(t, cfg.Resolvers, app.Resolvers())
			assert.Equal(t, tc.wantNotifier, app.Notifier != nil)
		})
	}
}

func TestIDNNormalizationAndAliasCase(t *testing.T) {
	configJSON := `{"notifications":{"ntfy":{"url":"https://ntfy.invalid/topic"}},
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

	cfg, err := LoadConfig(context.Background(), cfgPath)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	d := cfg.Domains[0]
	if d.Domain != "xn--mnchen-3ya.de" {
		t.Errorf("Expected Punycode xn--mnchen-3ya.de, got %s", d.Domain)
	}
	if d.ExpectedNS[0] != "ns1.xn--mnchen-3ya.de" {
		t.Errorf("Expected Punycode NS ns1.xn--mnchen-3ya.de, got %s", d.ExpectedNS[0])
	}
	if d.MXRecords[0] != "mail.xn--mnchen-3ya.de" {
		t.Errorf("Expected Punycode MX mail.xn--mnchen-3ya.de, got %s", d.MXRecords[0])
	}

	r := cfg.DNSRecords[0]
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
	bothJSON := `{"notifications":{"ntfy":{"url":"https://ntfy.invalid/topic"}},
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
	cfgBoth, err := LoadConfig(context.Background(), cfgPath)
	if err != nil {
		t.Fatalf("Expected config with both registrar fields to load successfully, got error: %v", err)
	}
	if cfgBoth.Domains[0].ExpectedRegistrarID != "292" {
		t.Errorf("Expected ExpectedRegistrarID '292', got %q", cfgBoth.Domains[0].ExpectedRegistrarID)
	}
	if cfgBoth.Domains[0].ExpectedRegistrarName != "markmonitor" {
		t.Errorf("Expected ExpectedRegistrarName 'markmonitor', got %q", cfgBoth.Domains[0].ExpectedRegistrarName)
	}

	// Only ID set -> valid
	validIDJSON := `{"notifications":{"ntfy":{"url":"https://ntfy.invalid/topic"}},
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
	cfgID, err := LoadConfig(context.Background(), cfgPathID)
	if err != nil {
		t.Fatalf("Expected valid config with only expected_registrar_id, got error: %v", err)
	}
	if cfgID.Domains[0].ExpectedRegistrarID != "292" {
		t.Errorf("Expected ExpectedRegistrarID '292', got %q", cfgID.Domains[0].ExpectedRegistrarID)
	}

	// Only Name set -> valid
	validNameJSON := `{"notifications":{"ntfy":{"url":"https://ntfy.invalid/topic"}},
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
	cfgName, err := LoadConfig(context.Background(), cfgPathName)
	if err != nil {
		t.Fatalf("Expected valid config with only expected_registrar_name, got error: %v", err)
	}
	if cfgName.Domains[0].ExpectedRegistrarName != "markmonitor" {
		t.Errorf("Expected ExpectedRegistrarName 'markmonitor', got %q", cfgName.Domains[0].ExpectedRegistrarName)
	}
}

func TestConfig_VerifyNSHealthRequirements(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()

	// 1. verify_ns_health: true but no expected_ns -> must error
	invalidJSON1 := `{"notifications":{"ntfy":{"url":"https://ntfy.invalid/topic"}},
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
	validPrimaryOnlyJSON := `{"notifications":{"ntfy":{"url":"https://ntfy.invalid/topic"}},
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
	cfg2, err2 := LoadConfig(context.Background(), cfgPath2)
	if err2 != nil {
		t.Fatalf("Expected valid config when secondary_ns is omitted, got error: %v", err2)
	}
	if len(cfg2.Domains[0].SecondaryNS) != 0 {
		t.Errorf("Expected 0 secondary_ns, got %v", cfg2.Domains[0].SecondaryNS)
	}

	// 3. verify_ns_health: true with both expected_ns and secondary_ns -> valid
	validJSON := `{"notifications":{"ntfy":{"url":"https://ntfy.invalid/topic"}},
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
	cfg3, err3 := LoadConfig(context.Background(), cfgPath3)
	if err3 != nil {
		t.Fatalf("Expected valid config with expected_ns and secondary_ns, got error: %v", err3)
	}
	if len(cfg3.Domains[0].SecondaryNS) != 1 || cfg3.Domains[0].SecondaryNS[0] != "slave.otherprovider.com" {
		t.Errorf("Expected secondary_ns 'slave.otherprovider.com', got %v", cfg3.Domains[0].SecondaryNS)
	}

	// 4. empty entry in expected_ns -> must error
	emptyExpectedNSJSON := `{"notifications":{"ntfy":{"url":"https://ntfy.invalid/topic"}},
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
	emptySecondaryNSJSON := `{"notifications":{"ntfy":{"url":"https://ntfy.invalid/topic"}},
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
	secondaryNoExpectedJSON := `{"notifications":{"ntfy":{"url":"https://ntfy.invalid/topic"}},
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

func TestConfig_DuplicateDNSRecordName(t *testing.T) {
	cfgJSON := `{"notifications":{"ntfy":{"url":"https://ntfy.invalid/topic"}},
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
	cfgJSON := `{"notifications":{"ntfy":{"url":"https://ntfy.invalid/topic"}},
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
	cfg, err := LoadConfig(context.Background(), tmpFile)
	if err != nil {
		t.Fatalf("failed to load config with StringList expected: %v", err)
	}
	if len(cfg.DNSRecords[0].Expected) != 1 || cfg.DNSRecords[0].Expected[0] != "1.2.3.4" {
		t.Errorf("expected single string parsed as slice of 1 element, got %v", cfg.DNSRecords[0].Expected)
	}
	if len(cfg.DNSRecords[1].Expected) != 2 {
		t.Errorf("expected slice parsed with 2 elements, got %v", cfg.DNSRecords[1].Expected)
	}
}

func TestConfig_TypeSpecificIPValidation(t *testing.T) {
	// A record with IPv6 should fail
	t.Run("A_RejectIPv6", func(t *testing.T) {
		cfgJSON := `{"notifications":{"ntfy":{"url":"https://ntfy.invalid/topic"}},
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
		cfgJSON := `{"notifications":{"ntfy":{"url":"https://ntfy.invalid/topic"}},
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
		cfgJSON := `{"notifications":{"ntfy":{"url":"https://ntfy.invalid/topic"}},
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
		cfg, err := LoadConfig(context.Background(), tmpFile)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		expected := cfg.DNSRecords[0].Expected
		// Deduplicated: 3 elements ("192.0.2.1", "198.51.100.1", "2001:db8::1")
		if len(expected) != 3 {
			t.Fatalf("expected 3 canonicalized elements, got %d: %v", len(expected), expected)
		}
		if !slices.IsSorted(expected) {
			t.Errorf("expected elements to be sorted, got %v", expected)
		}
	})
}

func TestNilSafety_CheckState(t *testing.T) {
	// 1. Nil receiver should not panic
	var nilCS *CheckState
	nilCS.ApplyDNSResult(DNSResult{Name: "test", State: DNSState{}})
	nilCS.ApplyDomainResult(DomainResult{Domain: "example.com", RDAP: RDAPState{}})

	// 2. Uninitialized inner maps should be lazily initialized without panicking
	emptyCS := &CheckState{}
	emptyCS.ApplyDNSResult(DNSResult{Name: "test.example.com", State: DNSState{Hostname: "test.example.com", Status: StatusOK}})
	if dnsState, ok := emptyCS.DNS["test.example.com"]; !ok || dnsState.Hostname == "" {
		t.Errorf("expected DNS result to be safely applied to empty CheckState")
	}

	emptyCS.ApplyDomainResult(DomainResult{
		Domain:   "example.com",
		RDAP:     RDAPState{Status: StatusOK},
		Email:    EmailState{Status: StatusOK},
		DNSSEC:   DNSSECResult{Valid: true, Status: StatusOK},
		NSHealth: NSHealthResult{Valid: true, Status: StatusOK},
	})
	if rdap, ok := emptyCS.RDAP["example.com"]; !ok || rdap.Status == StatusUnknown {
		t.Errorf("expected RDAP result applied")
	}
	if email, ok := emptyCS.Email["example.com"]; !ok || email.Status == StatusUnknown {
		t.Errorf("expected Email result applied")
	}

	if dnssec, ok := emptyCS.DNSSEC["example.com"]; !ok || !dnssec.Valid {
		t.Errorf("expected DNSSEC result applied")
	}
}

func TestNilSafety_StringList(t *testing.T) {
	var nilSL *StringList
	if err := nilSL.UnmarshalJSON([]byte(`"test"`)); err == nil {
		t.Errorf("expected error from nil StringList receiver")
	}
}

// TestLoadConfig_LoopIntervalClamping verifies that loop_interval_days below 0.125
// is clamped to the minimum floor of 0.125 (3 hours).
func TestLoadConfig_LoopIntervalClamping(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.json")

	content := []byte(`{"notifications":{"ntfy":{"url":"https://ntfy.invalid/topic"}},
		"loop_interval_days": 0.05,
		"domains": [{"domain": "example.com", "name": "Ex"}],
		"dns_records": []
	}`)
	if err := os.WriteFile(configPath, content, 0600); err != nil {
		t.Fatalf("Failed to write test config: %v", err)
	}

	cfg, err := LoadConfig(context.Background(), configPath)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}
	if cfg.LoopIntervalDays != 0.125 {
		t.Errorf("expected LoopIntervalDays clamped to 0.125, got %f", cfg.LoopIntervalDays)
	}
	app := NewAppState(cfg)
	expectedDur := time.Duration(0.125 * 24 * float64(time.Hour))
	if app.LoopDuration != expectedDur {
		t.Errorf("expected LoopDuration %v, got %v", expectedDur, app.LoopDuration)
	}
}

// TestLoadConfig_LoopIntervalMaxClamping verifies that excessively large loop_interval_days
// is clamped to the maximum ceiling of 365 days to prevent integer duration overflow.
func TestLoadConfig_LoopIntervalMaxClamping(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.json")

	content := []byte(`{"notifications":{"ntfy":{"url":"https://ntfy.invalid/topic"}},
		"loop_interval_days": 1000.0,
		"domains": [{"domain": "example.com", "name": "Ex"}],
		"dns_records": []
	}`)
	if err := os.WriteFile(configPath, content, 0600); err != nil {
		t.Fatalf("Failed to write test config: %v", err)
	}

	cfg, err := LoadConfig(context.Background(), configPath)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}
	if cfg.LoopIntervalDays != 365 {
		t.Errorf("expected LoopIntervalDays clamped to 365, got %f", cfg.LoopIntervalDays)
	}
	app := NewAppState(cfg)
	expectedDur := time.Duration(365 * 24 * float64(time.Hour))
	if app.LoopDuration != expectedDur {
		t.Errorf("expected LoopDuration %v, got %v", expectedDur, app.LoopDuration)
	}
}

func TestConfig_CompileTimeImmutability(t *testing.T) {
	t.Parallel()

	cfg := AppConfig{
		Port:      "8080",
		Resolvers: []string{"1.1.1.1", "8.8.8.8"},
		Domains: []DomainConfig{
			{Domain: "example.com", Name: "Example"},
		},
	}
	app := NewAppState(cfg)

	// Verify reading via value getter
	if app.Config().Port != "8080" {
		t.Fatalf("expected port 8080, got %s", app.Config().Port)
	}

	// Mutating scalar fields on the returned value copy does not mutate internal state
	copied := app.Config()
	copied.Port = "9999"
	if app.Config().Port != "8080" {
		t.Errorf("changing copied port to %s changed internal port: got %s, want 8080", copied.Port, app.Config().Port)
	}

	// activeResolvers holds a cloned slice
	res := app.Resolvers()
	res[0] = "192.0.2.1"
	if app.Resolvers()[0] == "192.0.2.1" {
		t.Errorf("expected Resolvers() to return defensive clone, but internal slice was mutated")
	}
}

func TestNormalizeDNSTaskRejectsUnsupportedAndVacuousChecks(t *testing.T) {
	tests := []struct {
		name    string
		task    DNSTask
		wantErr bool
	}{
		{"unsupported type", DNSTask{Hostname: "example.com", Name: "record", Type: "BOGUS", Expected: StringList{"x"}}, true},
		{"unsupported match", DNSTask{Hostname: "example.com", Name: "record", Type: RecordTypeTXT, MatchType: "fuzzy", Expected: StringList{"x"}}, true},
		{"missing expectation", DNSTask{Hostname: "example.com", Name: "record", Type: RecordTypeTXT}, true},
		{"empty prefix", DNSTask{Hostname: "example.com", Name: "record", Type: RecordTypeTXT, MatchType: MatchPrefix, Expected: StringList{}}, true},
		{"explicit absence", DNSTask{Hostname: "example.com", Name: "record", Type: RecordTypeTXT, MatchType: MatchExact, Expected: StringList{}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := normalizeDNSTask(&tt.task, 0, map[string]bool{})
			if tt.wantErr && err == nil {
				t.Fatal("expected configuration error")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected configuration error: %v", err)
			}
		})
	}
}

func TestEndpointAndProviderValidation(t *testing.T) {
	for _, endpoint := range []string{"1.1.1.1", "[2001:db8::1]:5353", "dns.internal:53", "resolver.local"} {
		if err := validateResolverEndpoint(endpoint); err != nil {
			t.Errorf("valid resolver %q rejected: %v", endpoint, err)
		}
	}
	for _, endpoint := range []string{"", "1.1.1.1:0", "dns.internal:70000", "dns.internal/path"} {
		if err := validateResolverEndpoint(endpoint); err == nil {
			t.Errorf("invalid resolver %q accepted", endpoint)
		}
	}
	for _, endpoint := range []string{"https://dns.google/resolve", "http://localhost:8080/dns-query"} {
		if err := validateHTTPURL(endpoint); err != nil {
			t.Errorf("valid URL %q rejected: %v", endpoint, err)
		}
	}
	for _, endpoint := range []string{"ftp://dns.example.com", "https://user:pass@dns.example.com", "http://localhost:0"} {
		if err := validateHTTPURL(endpoint); err == nil {
			t.Errorf("invalid URL %q accepted", endpoint)
		}
	}
}

func TestLoadConfigRejectsIncompleteNotifications(t *testing.T) {
	t.Setenv(EnvPort, "")
	t.Setenv(EnvTelegramToken, "")
	t.Setenv(EnvTelegramChatID, "")
	t.Setenv(EnvDoHURL, "")
	for _, tc := range []struct {
		name string
		body string
	}{
		{"bad port", `{"notifications":{"ntfy":{"url":"https://ntfy.invalid/topic"}},"port":"0"}`},
		{"ntfy without URL", `{"notifications":{"ntfy":{"auth":"token"}}}`},
		{"bad DoH URL", `{"notifications":{"ntfy":{"url":"https://ntfy.invalid/topic"}},"doh_url":"ftp://dns.example.com"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.json")
			require.NoError(t, os.WriteFile(path, []byte(tc.body), 0600))
			_, err := LoadConfig(context.Background(), path)
			require.Error(t, err)
		})
	}
}

func TestRequiredNtfyAndOptionalTelegram(t *testing.T) {
	for _, tc := range []struct {
		name          string
		notifications Notifications
		wantError     bool
	}{
		{"missing ntfy", Notifications{}, true},
		{"telegram only", Notifications{Telegram: &TelegramConfig{Token: "token", ChatID: "chat"}}, true},
		{"ntfy only", Notifications{Ntfy: &NtfyConfig{URL: "https://ntfy.invalid/topic"}}, false},
		{"both", Notifications{Ntfy: &NtfyConfig{URL: "https://ntfy.invalid/topic"}, Telegram: &TelegramConfig{Token: "token", ChatID: "chat"}}, false},
		{"incomplete telegram", Notifications{Ntfy: &NtfyConfig{URL: "https://ntfy.invalid/topic"}, Telegram: &TelegramConfig{Token: "token"}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateNotificationEndpoints(&tc.notifications)
			assert.Equal(t, tc.wantError, err != nil)
		})
	}
}

func TestConfigSnapshotOwnsNestedData(t *testing.T) {
	config := AppConfig{
		Resolvers:     []string{"1.1.1.1"},
		Notifications: Notifications{Ntfy: &NtfyConfig{URL: "https://ntfy.invalid/topic"}, Telegram: &TelegramConfig{Token: "token", ChatID: "chat"}},
		Domains:       []DomainConfig{{Domain: "example.com", ExpectedNS: []string{"ns.example.com"}, SecondaryNS: []string{"secondary.example.com"}, MXRecords: []string{"mail.example.com"}, DKIMSelectors: []string{"selector"}}},
		DNSRecords:    []DNSTask{{Expected: StringList{"192.0.2.1"}}},
	}
	app := NewAppState(config)
	original := app.Config()
	mutate := func(snapshot AppConfig) {
		snapshot.Resolvers[0] = "8.8.8.8"
		snapshot.Domains[0].ExpectedNS[0] = "changed.example"
		snapshot.Domains[0].SecondaryNS[0] = "changed.example"
		snapshot.Domains[0].MXRecords[0] = "changed.example"
		snapshot.Domains[0].DKIMSelectors[0] = "changed"

		snapshot.DNSRecords[0].Expected[0] = "192.0.2.2"
		snapshot.Notifications.Ntfy.URL = "https://changed.invalid"
		snapshot.Notifications.Telegram.Token = "changed"
	}
	mutate(config)
	assert.Equal(t, original, app.Config(), "startup input must not remain shared")
	snapshot := app.Config()
	mutate(snapshot)
	assert.Equal(t, original, app.Config(), "returned nested config must not remain shared")
	resolvers := app.Resolvers()
	resolvers[0] = "9.9.9.9"
	assert.Equal(t, original.Resolvers, app.Resolvers())
}

func TestConfigAndEnvironmentAreReadOnlyAtStartup(t *testing.T) {
}

func TestOptionalTelegramDoesNotBlockNtfyStartup(t *testing.T) {
	for _, tc := range []struct {
		name, telegram, tokenEnv, chatEnv string
		wantTelegram                      bool
	}{
		{name: "omitted"},
		{name: "empty object", telegram: `,"telegram":{}`},
		{name: "token only", telegram: `,"telegram":{"token":"token"}`},
		{name: "chat only", telegram: `,"telegram":{"chat_id":"chat"}`},
		{name: "whitespace", telegram: `,"telegram":{"token":"  ","chat_id":"  "}`},
		{name: "token environment only", tokenEnv: "token"},
		{name: "chat environment only", chatEnv: "chat"},
		{name: "both environment", tokenEnv: "token", chatEnv: "chat", wantTelegram: true},
		{name: "config plus environment", telegram: `,"telegram":{"token":"token"}`, chatEnv: "chat", wantTelegram: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(EnvTelegramToken, tc.tokenEnv)
			t.Setenv(EnvTelegramChatID, tc.chatEnv)
			cfg, err := loadConfig(context.Background(), "unused", func(string) ([]byte, error) {
				return []byte(`{"notifications":{"ntfy":{"url":"https://ntfy.invalid/topic"}` + tc.telegram + `}}`), nil
			})
			require.NoError(t, err)
			assert.Equal(t, tc.wantTelegram, cfg.Notifications.Telegram != nil)
			app, err := InitializeApp(context.Background(), cfg)
			require.NoError(t, err)
			require.IsType(t, &NotificationManager{}, app.Notifier)
			notifier, ok := app.Notifier.(*NotificationManager)
			require.True(t, ok)
			assert.Equal(t, "https://ntfy.invalid/topic", notifier.NtfyURL)
			assert.Equal(t, tc.wantTelegram, notifier.TelegramToken != "" && notifier.TelegramChatID != "")
		})
	}
}

func TestExpectedTXTValuesRemainLiteral(t *testing.T) {
	for _, literal := range []string{"verification=AbC.", "alias:LiteralValue", "."} {
		value, err := normalizeExpectedDNSValue(DNSTask{Type: RecordTypeTXT, Hostname: "example.com"}, literal)
		require.NoError(t, err)
		assert.Equal(t, literal, value)
	}
}

func TestNormalizeExpectedDNSValue_CAA(t *testing.T) {
	val, err := normalizeExpectedDNSValue(DNSTask{Type: RecordTypeCAA, Hostname: "example.com"}, `0 issue "letsencrypt.org"`)
	require.NoError(t, err)
	assert.Equal(t, `0 issue "letsencrypt.org"`, val)
	_, err = normalizeExpectedDNSValue(DNSTask{Type: RecordTypeCAA, Hostname: "example.com"}, `invalid caa`)
	assert.ErrorContains(t, err, "invalid expected CAA value")
}

func TestLoadConfigRejectsUnpersistableCTDomain(t *testing.T) {
	for _, domain := range []string{"bad/name.example", "bad..example", "-bad.example"} {
		t.Run(domain, func(t *testing.T) {
			_, err := loadConfig(context.Background(), "memory.json", func(string) ([]byte, error) {
				return []byte(`{"notifications":{"ntfy":{"url":"https://ntfy.invalid/topic"}},"domains":[{"domain":"` + domain + `","name":"CT target","monitor_ct_logs":true}]}`), nil
			})
			require.Error(t, err)
		})
	}
}

func TestExternalEmailProviderValidation(t *testing.T) {
	for _, body := range []string{
		`{`, `{"mx_records":[]}`, `{"mx_records":["bad/path"]}`,
		`{"mx_records":["mail.example"],"dkim_selectors":[""]}`,
		strings.Repeat(" ", (64<<10)+1),
	} {
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, "custom.json"), []byte(body), 0600))
		_, err := InitializeApp(context.Background(), AppConfig{EmailProvidersDir: dir})
		require.Error(t, err)
	}
	_, err := InitializeApp(context.Background(), AppConfig{EmailProvidersDir: filepath.Join(t.TempDir(), "missing")})
	require.Error(t, err)
	_, err = InitializeApp(context.Background(), AppConfig{Domains: []DomainConfig{{Domain: "example.com", CheckEmailSecurity: true, MailProvider: "unknown"}}})
	require.ErrorContains(t, err, "unknown mail provider")
}

func TestExternalEmailProvidersOverrideAndStayOwned(t *testing.T) {
	dir := t.TempDir()
	providerPath := filepath.Join(dir, "google.json")
	require.NoError(t, os.WriteFile(providerPath, []byte(`{"mx_records":[" MAIL.EXAMPLE.COM. "],"dkim_selectors":["Custom"]}`), 0600))
	app, err := InitializeApp(context.Background(), AppConfig{EmailProvidersDir: dir})
	require.NoError(t, err)
	assert.Equal(t, []string{"mail.example.com"}, app.EmailProviders["google"].MXRecords)
	assert.Equal(t, []string{"custom"}, app.EmailProviders["google"].DKIMSelectors)
	assert.Contains(t, app.EmailProviders, "fastmail")
	require.NoError(t, os.WriteFile(providerPath, []byte(`{}`), 0600))
	assert.Equal(t, []string{"custom"}, app.EmailProviders["google"].DKIMSelectors, "provider files are read only at startup")
}

func TestEmailProviderFilesystemFailures(t *testing.T) {
	providers := make(map[string]ProviderConfig)
	require.Error(t, readEmailProviders(os.DirFS(filepath.Join(t.TempDir(), "missing")), providers))
	_, err := readEmailProvider(fstest.MapFS{}, "missing.json")
	require.ErrorIs(t, err, os.ErrNotExist)
	source := fstest.MapFS{
		"nested":        &fstest.MapFile{Mode: os.ModeDir},
		"notes.txt":     &fstest.MapFile{Data: []byte("not a provider")},
		"bad name.json": &fstest.MapFile{Data: []byte(`{"mx_records":["mail.example.com"]}`)},
	}
	require.ErrorContains(t, readEmailProviders(source, providers), "name")
	assert.Empty(t, providers)
	dir := t.TempDir()
	file := filepath.Join(dir, "file")
	require.NoError(t, os.WriteFile(file, []byte("not a directory"), 0600))
	_, err = InitializeApp(context.Background(), AppConfig{EmailProvidersDir: file})
	require.Error(t, err)
}

func TestLoadConfigAdditionalValidationFailures(t *testing.T) {
	for _, env := range []string{EnvPort, EnvNtfyAuth, EnvTelegramToken, EnvTelegramChatID, EnvDoHURL} {
		t.Setenv(env, "")
	}
	for _, tc := range []struct{ name, checks, want string }{
		{"duplicate names", `"domains":[{"domain":"one.example","name":"same"},{"domain":"two.example","name":"same"}]`, "duplicate"},
		{"health without primary", `"domains":[{"domain":"example.com","name":"example","verify_ns_health":true}]`, "expected_ns"},
		{"wrong parent zone", `"domains":[{"domain":"example.com","name":"example","is_delegated_zone":true,"root_zone":"example.org"}]`, "root zone"},
		{"invalid resolver port", `"dns_records":[{"hostname":"example.com","name":"web","type":"A","expected":[],"custom_resolver":"192.0.2.1:0"}]`, "resolver"},
		{"invalid IPv6", `"dns_records":[{"hostname":"example.com","name":"web","type":"AAAA","expected":["invalid"]}]`, "IPv6"},
		{"invalid IP", `"dns_records":[{"hostname":"example.com","name":"web","type":"IP","expected":["invalid"]}]`, "IP"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			content := `{"notifications":{"ntfy":{"url":"https://ntfy.invalid/topic"}},` + tc.checks + `}`
			_, err := loadConfig(context.Background(), "memory.json", func(string) ([]byte, error) { return []byte(content), nil })
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := loadConfig(ctx, "", func(string) ([]byte, error) { t.Error("canceled load must not read files"); return nil, nil })
	require.ErrorIs(t, err, context.Canceled)
	_, err = InitializeApp(ctx, AppConfig{})
	require.ErrorIs(t, err, context.Canceled)
}

func TestConfigRejectsReservedDNSTaskNames(t *testing.T) {
	for _, env := range []string{EnvPort, EnvNtfyAuth, EnvTelegramToken, EnvTelegramChatID, EnvDoHURL} {
		t.Setenv(env, "")
	}
	_, err := loadConfig(context.Background(), "memory", func(string) ([]byte, error) {
		return []byte(`{"notifications":{"ntfy":{"url":"https://ntfy.invalid/topic"}},"dns_records":[{"hostname":"example.com","name":" __caa__web ","type":"A","expected":["192.0.2.1"]}]}`), nil
	})
	require.ErrorContains(t, err, "reserved")
}
