package main

import (
	"os"
	"strings"
	"testing"
)

func TestLoadConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		configJSON  string
		expectErr   bool
		errContains string
		validate    func(*testing.T, *AppState)
	}{
		{
			name: "Valid Config",
			configJSON: `{
				"port": "9090",
				"domains": [{"domain": "EXAMPLE.COM", "name": "Test Name", "expected_ns": ["NS1.EXAMPLE.COM"]}]
			}`,
			expectErr: false,
			validate: func(t *testing.T, app *AppState) {
				if app.Config.Port != "9090" {
					t.Errorf("Expected port 9090, got %s", app.Config.Port)
				}
				if app.Config.Domains[0].Domain != "example.com" {
					t.Errorf("Expected domain example.com, got %s", app.Config.Domains[0].Domain)
				}
				if app.Config.Domains[0].ExpectedNS[0] != "ns1.example.com" {
					t.Errorf("Expected ns1.example.com, got %s", app.Config.Domains[0].ExpectedNS[0])
				}
			},
		},
		{
			name: "Malformed JSON",
			configJSON: `{ "port": "9090", `,
			expectErr: true,
			errContains: "Unexpected: end of file while parsing field definition",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			
			tmpDir := t.TempDir()
			cfgPath := tmpDir + "/config.json"
			os.WriteFile(cfgPath, []byte(tt.configJSON), 0644)

			app, err := LoadConfig(cfgPath)
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
