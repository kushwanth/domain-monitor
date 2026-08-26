package main

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
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
			name:        "Malformed JSON",
			configJSON:  `{ "port": "9090", `,
			expectErr:   true,
			errContains: "Unexpected: end of file while parsing field definition",
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
	}

	for _, tt := range tests {
		tt := tt
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
				if err != nil && tt.errContains != "" {
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
