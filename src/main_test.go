package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRunMonitoringCycle(t *testing.T) {
	app := &AppState{
		Notifier: &NotificationManager{TestMode: true},
		config: AppConfig{
			Domains: []DomainConfig{
				{Domain: "example.com", MonitorCTLogs: true},
			},
			DNSRecords: []DNSTask{
				{Hostname: "example.com", Type: "A", Expected: []string{"93.184.216.34"}},
			},
		},
		LoopDuration: 10 * time.Millisecond,
	}

	httpClient := &http.Client{Timeout: 2 * time.Second}
	ctLogPersist := make(map[string]CTLogState)
	
	// Use a temporary file for ct state path
	tmpFile, err := os.CreateTemp("", "ctstate_*.json")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())

	state := runMonitoringCycle(
		context.Background(),
		app,
		httpClient,
		tmpFile.Name(),
		ctLogPersist,
		nil,
		nil,
		nil,
	)

	require.NotNil(t, state)
	assert.NotEmpty(t, state.RDAP)
}

func TestMainFunc(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	tmpFile, err := os.CreateTemp("", "config_*.json")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())

	configJSON := `{"domains": [], "dns_records": [], "notifications": {"ntfy": {"url": "` + ts.URL + `"}}}`
	_, _ = tmpFile.Write([]byte(configJSON))
	tmpFile.Close()

	os.Setenv("CONFIG_PATH", tmpFile.Name())
	defer os.Unsetenv("CONFIG_PATH")

	go func() {
		time.Sleep(200 * time.Millisecond)
		process, _ := os.FindProcess(os.Getpid())
		process.Signal(os.Interrupt)
	}()

	// Temporarily override os.Args to prevent flag parsing from taking the test flags
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()
	os.Args = []string{"domain_monitor", "-c", tmpFile.Name()}

	main()
}
