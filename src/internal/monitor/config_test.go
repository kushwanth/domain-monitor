package monitor

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

func TestRepositoryExampleConfigCompiles(t *testing.T) {
	for _, environmentVariable := range []string{EnvPort, EnvNtfyAuth, EnvTelegramToken, EnvTelegramChatID, EnvDoHURL} {
		t.Setenv(environmentVariable, StrEmpty)
	}

	configPath := filepath.Join("..", "..", "..", DefaultConfigFile)
	config, err := LoadConfig(context.Background(), configPath)
	require.NoError(t, err)
	assert.NotEmpty(t, config.Domains)
	assert.NotEmpty(t, config.DNSRecords)
}

func TestReadConfigFileRejectsOversizedInput(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "oversized.json")
	content := strings.Repeat("x", MaxConfigFileSize+1)
	require.NoError(t, os.WriteFile(path, []byte(content), 0600))

	body, err := readConfigFile(path)
	assert.Nil(t, body)
	assert.ErrorIs(t, err, ErrReadLimitExceeded)
}

func TestAllowExpiryPolicy(t *testing.T) {
	configJSON := `{"notifications":{"ntfy":{"url":"https://ntfy.invalid/topic"}},"domains":[{"domain":"unused-one.example","name":"Unused One","allow_expiry":true},{"domain":"renewing.example","name":"Renewing","allow_expiry":true}]}`
	cfg, err := loadConfig(context.Background(), "memory.json", func(string) ([]byte, error) {
		return []byte(configJSON), nil
	})
	require.NoError(t, err)
	require.Len(t, cfg.Domains, 2)
	assert.True(t, cfg.Domains[0].AllowExpiry)
	assert.True(t, cfg.Domains[1].AllowExpiry)
	for _, domain := range cfg.Domains {
		assert.True(t, domain.AllowExpiry)
		futureStatus, _ := EvaluateRDAP(domain, RDAPSnapshot{Expiration: time.Now().AddDate(1, 0, 0).UTC().Format(time.RFC3339)})
		expiredStatus, _ := EvaluateRDAP(domain, RDAPSnapshot{Expiration: time.Now().Add(-24 * time.Hour).UTC().Format(time.RFC3339)})
		assert.Equal(t, StatusOK, futureStatus)
		assert.Equal(t, StatusSkipped, expiredStatus)
	}

	state := newCycleState(AppConfig{Domains: cfg.Domains}, activeChecks{})
	assert.False(t, state.RDAP["unused-one.example"].ExpiryConfirmed)
	assert.False(t, state.RDAP["renewing.example"].ExpiryConfirmed)
	assert.True(t, state.RDAP["unused-one.example"].AllowExpiry)
	assert.True(t, state.RDAP["renewing.example"].AllowExpiry)
	assert.Equal(t, StatusPending, state.RDAP["renewing.example"].Status)
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
						"nameservers": [{"hostname":"NS1.EXAMPLE.COM."}],
						"email": {"provider":"GOOGLE","dkim_selectors":["SEL1"]},
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
				if d.Nameservers[0].Hostname != "ns1.example.com" {
					t.Errorf("Expected ns1.example.com, got %s", d.Nameservers[0].Hostname)
				}
				if d.Email.Provider != "google" {
					t.Errorf("Expected email provider google, got %s", d.Email.Provider)
				}
				if d.Email.DKIMSelectors[0] != "sel1" {
					t.Errorf("Expected dkim selector sel1, got %s", d.Email.DKIMSelectors[0])
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
						"email": {"mx_records":["."]}
					}
				]
			}`,
			expectErr: false,
			validate: func(t *testing.T, app *AppState) {
				d := app.Config().Domains[0]
				if len(d.Email.MXRecords) != 1 || d.Email.MXRecords[0] != "." {
					t.Errorf("Expected Null MX '.' to be preserved, got %v", d.Email.MXRecords)
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
			name: "Mail Provider and MX Records Mutually Exclusive",
			configJSON: `{"notifications":{"ntfy":{"url":"https://ntfy.invalid/topic"}},
				"domains": [{
					"domain": "example.com",
					"name": "Example",
					"email": {"provider":"google","mx_records":["mail.example.com"]}
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
				"nameservers": [{"hostname":"ns1.münchen.de"}],
				"email": {"mx_records":["mail.münchen.de"]}
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
	if d.Nameservers[0].Hostname != "ns1.xn--mnchen-3ya.de" {
		t.Errorf("Expected Punycode NS ns1.xn--mnchen-3ya.de, got %s", d.Nameservers[0].Hostname)
	}
	if d.Email.MXRecords[0] != "mail.xn--mnchen-3ya.de" {
		t.Errorf("Expected Punycode MX mail.xn--mnchen-3ya.de, got %s", d.Email.MXRecords[0])
	}

	r := cfg.DNSRecords[0]
	if r.Hostname != "xn--mnchen-3ya.de" {
		t.Errorf("Expected Punycode Hostname xn--mnchen-3ya.de, got %s", r.Hostname)
	}
	if len(r.Expected) == 0 || r.Expected[0] != "target.xn--mnchen-3ya.de" {
		t.Errorf("Expected stripped and Punycode expected target.xn--mnchen-3ya.de, got %v", r.Expected)
	}
}

func TestConfig_RegistrarNormalization(t *testing.T) {
	t.Parallel()

	body := `{"notifications":{"ntfy":{"url":"https://ntfy.invalid/topic"}},"domains":[{"domain":"example.com","name":"Registrar","registrar":" 292 "}]}`
	path := filepath.Join(t.TempDir(), "config.json")
	require.NoError(t, os.WriteFile(path, []byte(body), 0600))
	cfg, err := LoadConfig(context.Background(), path)
	require.NoError(t, err)
	assert.Equal(t, "292", cfg.Domains[0].Registrar)
}

func TestConfig_NameserverRequirements(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()

	hiddenOnlyJSON := `{"notifications":{"ntfy":{"url":"https://ntfy.invalid/topic"}},
		"domains": [
			{
				"domain": "example.com",
				"name": "Hidden Only",
				"nameservers": [{"hostname":"hidden.example.com","hidden":true}]
			}
		]
	}`
	cfgPath1 := tmpDir + "/hidden_only.json"
	_ = os.WriteFile(cfgPath1, []byte(hiddenOnlyJSON), 0644)
	_, err1 := LoadConfig(context.Background(), cfgPath1)
	if err1 == nil || !strings.Contains(err1.Error(), "at least one non-hidden") {
		t.Fatalf("expected hidden-only nameservers to fail, got: %v", err1)
	}

	validJSON := `{"notifications":{"ntfy":{"url":"https://ntfy.invalid/topic"}},
		"domains": [
			{
				"domain": "example.com",
				"name": "Public And Hidden",
				"nameservers": [
					{"hostname":"NS1.EXAMPLE.COM."},
					{"hostname":"hidden.example.com","hidden":true}
				]
			}
		]
	}`
	cfgPath2 := tmpDir + "/valid_nameservers.json"
	_ = os.WriteFile(cfgPath2, []byte(validJSON), 0644)
	cfg2, err2 := LoadConfig(context.Background(), cfgPath2)
	if err2 != nil {
		t.Fatalf("expected valid nameserver config, got: %v", err2)
	}
	if got := cfg2.Domains[0].Nameservers; len(got) != 2 || got[0].Hostname != "ns1.example.com" || !got[1].Hidden {
		t.Fatalf("unexpected normalized nameservers: %#v", got)
	}

	emptyJSON := `{"notifications":{"ntfy":{"url":"https://ntfy.invalid/topic"}},
		"domains": [
			{
				"domain": "example.com",
				"name": "Empty Nameserver",
				"nameservers": [{"hostname":"   "}]
			}
		]
	}`
	cfgPath3 := tmpDir + "/empty_nameserver.json"
	_ = os.WriteFile(cfgPath3, []byte(emptyJSON), 0644)
	_, err3 := LoadConfig(context.Background(), cfgPath3)
	if err3 == nil || !strings.Contains(err3.Error(), "empty nameserver hostname") {
		t.Fatalf("expected empty hostname error, got: %v", err3)
	}

	duplicateJSON := `{"notifications":{"ntfy":{"url":"https://ntfy.invalid/topic"}},
		"domains": [
			{
				"domain": "example.com",
				"name": "Duplicate Nameserver",
				"nameservers": [
					{"hostname":"ns1.example.com"},
					{"hostname":"NS1.EXAMPLE.COM.","hidden":true}
				]
			}
		]
	}`
	cfgPath4 := tmpDir + "/duplicate_nameserver.json"
	_ = os.WriteFile(cfgPath4, []byte(duplicateJSON), 0644)
	_, err4 := LoadConfig(context.Background(), cfgPath4)
	if err4 == nil || !strings.Contains(err4.Error(), "duplicate nameserver") {
		t.Fatalf("expected duplicate hostname error, got: %v", err4)
	}
}

func TestConfigRejectsMalformedDomainEndpoints(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name, domainField, want string
	}{
		{"invalid nameserver", `"nameservers":[{"hostname":"ns.example.com/path"}]`, "invalid nameserver"},
		{"invalid root zone", `"root_zone":"bad zone"`, "invalid root zone"},
		{"empty expected MX", `"email":{"mx_records":[" "]}`, "invalid expected MX"},
		{"invalid DKIM selector", `"email":{"dkim_selectors":["bad selector"]}`, "invalid DKIM selector"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := `{"notifications":{"ntfy":{"url":"https://ntfy.invalid/topic"}},"domains":[{"domain":"sub.example.com","name":"Test",` + tc.domainField + `}]}`
			cfgPath := filepath.Join(t.TempDir(), "config.json")
			require.NoError(t, os.WriteFile(cfgPath, []byte(body), 0600))
			_, err := LoadConfig(context.Background(), cfgPath)
			require.ErrorContains(t, err, tc.want)
		})
	}
}

func TestConfigMigratesV3DomainFields(t *testing.T) {
	t.Parallel()

	for _, field := range []string{
		`"check_email_security":false`,
		`"mail_provider":"google"`,
		`"mx_records":["mail.example.com"]`,
		`"dkim_selectors":["default"]`,
		`"unused":false`,
		`"expected_registrar_id":"292"`,
		`"expected_registrar_name":"example"`,
	} {
		path := filepath.Join(t.TempDir(), "config.json")
		body := `{"notifications":{"ntfy":{"url":"https://ntfy.invalid/topic"}},"domains":[{"domain":"example.com","name":"example",` + field + `}]}`
		require.NoError(t, os.WriteFile(path, []byte(body), 0600))
		_, err := LoadConfig(context.Background(), path)
		require.NoError(t, err)
	}
}

func TestConfigRejectsUnsafeV3Fields(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name, body string
	}{
		{name: "data directory", body: `{"data_dir":"state","notifications":{"ntfy":{"url":"https://ntfy.invalid/topic"}}}`},
		{name: "skip SSL", body: `{"notifications":{"ntfy":{"url":"https://ntfy.invalid/topic"}},"dns_records":[{"hostname":"example.com","name":"example","type":"A","expected":["192.0.2.1"],"skip_ssl":true}]}`},
		{name: "expected nameservers", body: `{"notifications":{"ntfy":{"url":"https://ntfy.invalid/topic"}},"domains":[{"domain":"example.com","name":"example","expected_ns":["ns1.example.com"]}]}`},
		{name: "secondary nameservers", body: `{"notifications":{"ntfy":{"url":"https://ntfy.invalid/topic"}},"domains":[{"domain":"example.com","name":"example","secondary_ns":["ns2.example.com"]}]}`},
		{name: "NS health toggle", body: `{"notifications":{"ntfy":{"url":"https://ntfy.invalid/topic"}},"domains":[{"domain":"example.com","name":"example","verify_ns_health":false}]}`},
		{name: "delegation marker", body: `{"notifications":{"ntfy":{"url":"https://ntfy.invalid/topic"}},"domains":[{"domain":"example.com","name":"example","is_delegated_zone":true}]}`},
		{name: "CT monitoring", body: `{"notifications":{"ntfy":{"url":"https://ntfy.invalid/topic"}},"domains":[{"domain":"example.com","name":"example","monitor_ct_logs":true}]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := loadConfig(context.Background(), "memory.json", func(string) ([]byte, error) {
				return []byte(tc.body), nil
			})
			require.ErrorContains(t, err, "cannot be migrated safely")
		})
	}
}

func TestConfigMigratesV3Values(t *testing.T) {
	t.Parallel()

	body := `{"notifications":{"ntfy":{"url":"https://ntfy.invalid/topic"}},"domains":[{"domain":"example.com","name":"example","check_email_security":true,"mail_provider":"google","dkim_selectors":["default"],"expected_registrar_id":"292","unused":true}]}`
	cfg, err := loadConfig(context.Background(), "memory.json", func(string) ([]byte, error) { return []byte(body), nil })
	require.NoError(t, err)
	require.Len(t, cfg.Domains, 1)
	require.NotNil(t, cfg.Domains[0].Email)
	assert.Equal(t, "google", cfg.Domains[0].Email.Provider)
	assert.Equal(t, []string{"default"}, cfg.Domains[0].Email.DKIMSelectors)
	assert.Equal(t, "292", cfg.Domains[0].Registrar)
	assert.True(t, cfg.Domains[0].AllowExpiry)
}

func TestConfigMigrationPreservesDisabledLegacyEmail(t *testing.T) {
	t.Parallel()

	body := `{"notifications":{"ntfy":{"url":"https://ntfy.invalid/topic"}},"domains":[{"domain":"example.com","name":"example","check_email_security":false,"mail_provider":"google","dkim_selectors":["default"]}]}`
	cfg, err := loadConfig(context.Background(), "memory.json", func(string) ([]byte, error) { return []byte(body), nil })
	require.NoError(t, err)
	require.Len(t, cfg.Domains, 1)
	assert.Nil(t, cfg.Domains[0].Email)
}

func TestConfigMigrationRejectsAmbiguousRegistrar(t *testing.T) {
	t.Parallel()

	body := `{"notifications":{"ntfy":{"url":"https://ntfy.invalid/topic"}},"domains":[{"domain":"example.com","name":"example","expected_registrar_id":"292","expected_registrar_name":"Example Registrar"}]}`
	_, err := loadConfig(context.Background(), "memory.json", func(string) ([]byte, error) { return []byte(body), nil })
	require.ErrorContains(t, err, "select one current")
}

func TestMigrateV3ConfigDefensiveParsing(t *testing.T) {
	t.Parallel()

	unchanged := []byte(`{"notifications":{}}`)
	got, err := migrateV3Config(unchanged)
	require.NoError(t, err)
	assert.Equal(t, unchanged, got)

	for _, body := range []string{
		`{`,
		`{"domains":{}}`,
		`{"dns_records":{}}`,
		`{"domains":[{"domain":false,"unused":true}]}`,
		`{"domains":[{"domain":"example.com","check_email_security":"yes"}]}`,
	} {
		_, err := migrateV3Config([]byte(body))
		require.Error(t, err, body)
	}
}

func TestConfigRejectsUnknownMembersAtEveryLevel(t *testing.T) {
	t.Parallel()

	for _, body := range []string{
		`{"unknown":true,"notifications":{"ntfy":{"url":"https://ntfy.invalid/topic"}}}`,
		`{"notifications":{"ntfy":{"url":"https://ntfy.invalid/topic","unknown":true}}}`,
		`{"notifications":{"ntfy":{"url":"https://ntfy.invalid/topic"}},"domains":[{"domain":"example.com","name":"example","unknown":true}]}`,
		`{"notifications":{"ntfy":{"url":"https://ntfy.invalid/topic"}},"domains":[{"domain":"example.com","name":"example","email":{"unknown":true}}]}`,
		`{"notifications":{"ntfy":{"url":"https://ntfy.invalid/topic"}},"domains":[{"domain":"example.com","name":"example","caa":{"unknown":[]}}]}`,
		`{"notifications":{"ntfy":{"url":"https://ntfy.invalid/topic"}},"dns_records":[{"hostname":"example.com","name":"example","type":"A","expected":["192.0.2.1"],"unknown":true}]}`,
	} {
		_, err := loadConfig(context.Background(), "memory.json", func(string) ([]byte, error) {
			return []byte(body), nil
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unknown")
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

	// Resolvers returns a defensive copy of the owned configuration.
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
			err := normalizeDNSTask(&tt.task, 0, stringSet{})
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
		Domains:       []DomainConfig{{Domain: "example.com", Nameservers: []NameserverConfig{{Hostname: "ns.example.com"}, {Hostname: "hidden.example.com", Hidden: true}}, Email: &EmailConfig{MXRecords: []string{"mail.example.com"}, DKIMSelectors: []string{"selector"}}}},
		DNSRecords:    []DNSTask{{Expected: StringList{"192.0.2.1"}}},
	}
	app := NewAppState(config)
	original := app.Config()
	mutate := func(snapshot AppConfig) {
		snapshot.Resolvers[0] = "8.8.8.8"
		snapshot.Domains[0].Nameservers[0].Hostname = "changed.example"
		snapshot.Domains[0].Email.MXRecords[0] = "changed.example"
		snapshot.Domains[0].Email.DKIMSelectors[0] = "changed"

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

func TestCompileRawConfigOwnsNestedData(t *testing.T) {
	t.Parallel()

	raw := RawConfig{
		Notifications: Notifications{
			Ntfy:     &NtfyConfig{URL: "https://ntfy.invalid/topic", Auth: "secret"},
			Telegram: &TelegramConfig{Token: "token", ChatID: "chat"},
		},
		Resolvers: []string{"1.1.1.1", "8.8.8.8"},
		Domains: []DomainConfig{{
			Domain:      "EXAMPLE.COM.",
			Name:        "Example",
			Nameservers: []NameserverConfig{{Hostname: "NS1.EXAMPLE.COM."}},
			Email:       &EmailConfig{MXRecords: []string{"MAIL.EXAMPLE.COM."}, DKIMSelectors: []string{"SELECTOR"}},
			CAA:         &CAAConfig{Issue: []string{"LETSENCRYPT.ORG"}},
		}},
		DNSRecords: []DNSTask{{
			Hostname: "WWW.EXAMPLE.COM.",
			Name:     "Web",
			Type:     RecordTypeA,
			Expected: StringList{"192.0.2.1"},
		}},
	}

	compiled, err := compileRawConfig(raw)
	require.NoError(t, err)

	raw.Notifications.Ntfy.URL = "https://changed.invalid/topic"
	raw.Notifications.Telegram.Token = "changed"
	raw.Resolvers[0] = "9.9.9.9"
	raw.Domains[0].Nameservers[0].Hostname = "changed.example"
	raw.Domains[0].Email.MXRecords[0] = "changed.example"
	raw.Domains[0].Email.DKIMSelectors[0] = "changed"
	raw.Domains[0].CAA.Issue[0] = "changed.example"
	raw.DNSRecords[0].Expected[0] = "192.0.2.2"

	assert.Equal(t, "https://ntfy.invalid/topic", compiled.Notifications.Ntfy.URL)
	assert.Equal(t, "token", compiled.Notifications.Telegram.Token)
	assert.Equal(t, []string{"1.1.1.1", "8.8.8.8"}, compiled.Resolvers)
	assert.Equal(t, "ns1.example.com", compiled.Domains[0].Nameservers[0].Hostname)
	assert.Equal(t, []string{"mail.example.com"}, compiled.Domains[0].Email.MXRecords)
	assert.Equal(t, []string{"selector"}, compiled.Domains[0].Email.DKIMSelectors)
	assert.Equal(t, []string{"letsencrypt.org"}, compiled.Domains[0].CAA.Issue)
	assert.Equal(t, StringList{"192.0.2.1"}, compiled.DNSRecords[0].Expected)

	compiled.Domains[0].Email.MXRecords[0] = "compiled-change.example"
	assert.Equal(t, "changed.example", raw.Domains[0].Email.MXRecords[0], "compiled values must not alias raw input")
}

func TestAppStateOwnsCompiledConfig(t *testing.T) {
	t.Parallel()

	cfg := AppConfig{
		Port:              "9090",
		LoopIntervalDays:  0.5,
		Notifications:     Notifications{Ntfy: &NtfyConfig{URL: "https://ntfy.invalid/topic"}},
		Resolvers:         []string{"1.1.1.1", "8.8.8.8"},
		DoHURL:            "https://dns.example/resolve",
		EmailProvidersDir: "providers",
		Domains:           []DomainConfig{{Domain: "example.com", Name: "Example"}},
		DNSRecords:        []DNSTask{{Hostname: "www.example.com", Name: "Web", Type: RecordTypeA, Expected: StringList{"192.0.2.1"}}},
	}

	app := NewAppState(cfg)
	assert.Equal(t, 12*time.Hour, app.LoopDuration)
	assert.Equal(t, cfg, app.Config())

	cfg.Resolvers[0] = "9.9.9.9"
	cfg.Domains[0].Domain = "changed.example"
	cfg.DNSRecords[0].Expected[0] = "192.0.2.2"
	owned := app.Config()
	assert.Equal(t, "1.1.1.1", owned.Resolvers[0])
	assert.Equal(t, "example.com", owned.Domains[0].Domain)
	assert.Equal(t, StringList{"192.0.2.1"}, owned.DNSRecords[0].Expected)
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

	val, err = normalizeExpectedDNSValue(DNSTask{Type: RecordTypeCAA, Hostname: "example.com"}, `0 ISSUE "LETSENCRYPT.ORG; account=AbC123"`)
	require.NoError(t, err)
	assert.Equal(t, `0 issue "letsencrypt.org; account=AbC123"`, val)
}

func TestLoadConfigRejectsRemovedCTFieldBeforeDomainValidation(t *testing.T) {
	for _, domain := range []string{"bad/name.example", "bad..example", "-bad.example"} {
		t.Run(domain, func(t *testing.T) {
			_, err := loadConfig(context.Background(), "memory.json", func(string) ([]byte, error) {
				return []byte(`{"notifications":{"ntfy":{"url":"https://ntfy.invalid/topic"}},"domains":[{"domain":"` + domain + `","name":"CT target","monitor_ct_logs":true}]}`), nil
			})
			require.ErrorContains(t, err, "cannot be migrated safely")
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
	_, err = InitializeApp(context.Background(), AppConfig{Domains: []DomainConfig{{Domain: "example.com", Email: &EmailConfig{Provider: "unknown"}}}})
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
		{"hidden nameserver only", `"domains":[{"domain":"example.com","name":"example","nameservers":[{"hostname":"hidden.example","hidden":true}]}]`, "non-hidden"},
		{"wrong parent zone", `"domains":[{"domain":"example.com","name":"example","root_zone":"example.org"}]`, "root zone"},
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
