package main

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/openrdap/rdap"
	"golang.org/x/sync/errgroup"
)

//go:embed index.html
var indexHTML []byte

type CheckStatus string

const (
	StatusPending  CheckStatus = "pending"
	StatusOk       CheckStatus = "ok"
	StatusFailed   CheckStatus = "failed"
	StatusMismatch CheckStatus = "mismatch"
	StatusWarning  CheckStatus = "warning"
	StatusHijacked CheckStatus = "hijacked"
)

func setupHTTPServer(app *AppState, port string, firstRunDone chan struct{}) *http.Server {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	mux.HandleFunc("GET /api/state", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-cache")
		if firstRunDone != nil {
			select {
			case <-firstRunDone:
			case <-r.Context().Done():
				return
			}
		}
		if b, ok := app.PrerenderedJSON.Load().([]byte); ok {
			_, _ = w.Write(b)
		} else {
			_, _ = w.Write([]byte("{}"))
		}
	})

	mux.HandleFunc("GET /api/certs", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		domain := r.URL.Query().Get("domain")
		if domain == "" || !ValidDomainRegex.MatchString(domain) {
			http.Error(w, `{"error": "invalid domain"}`, http.StatusBadRequest)
			return
		}

		filePath := filepath.Join(CTLogsPath, domain+".json")
		b, err := os.ReadFile(filePath)
		if err != nil {
			_, _ = w.Write([]byte("[]"))
			return
		}
		_, _ = w.Write(b)
	})

	mux.HandleFunc("GET /api/ctlogs/{domain}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		domain := r.PathValue("domain")
		if !ValidDomainRegex.MatchString(domain) {
			http.Error(w, `{"error": "invalid domain"}`, http.StatusBadRequest)
			return
		}

		filePath := filepath.Join(CTLogsPath, domain+".json")
		b, err := os.ReadFile(filePath)
		if err != nil {
			_, _ = w.Write([]byte("[]"))
			return
		}
		_, _ = w.Write(b)
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if firstRunDone != nil {
			select {
			case <-firstRunDone:
			case <-r.Context().Done():
				return
			}
		}
		if b, ok := app.PrerenderedHTML.Load().([]byte); ok {
			_, _ = w.Write(b)
		} else {
			_, _ = w.Write([]byte("Loading..."))
		}
	})

	server := &http.Server{
		Addr:         ":" + port,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	go func() {
		slog.Info(fmt.Sprintf(MsgLogHTTPAPI, port))
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("HTTP server failed", "error", err)
			os.Exit(1)
		}
	}()

	return server
}

func main() {
	var configPath string
	flag.StringVar(&configPath, "config", "", "Path to the jsonnet config file")
	flag.StringVar(&configPath, "c", "", "Path to the jsonnet config file (shorthand)")
	flag.Parse()

	if configPath == "" {
		configPath = os.Getenv("CONFIG_PATH")
	}

	ctx, cancel := context.WithCancel(context.Background())

	app, err := LoadConfig(ctx, configPath)
	if err != nil {
		slog.Error("Configuration error", "error", err)
		os.Exit(1)
	}

	if err := InitializeDependencies(ctx, app); err != nil {
		slog.Error("Initialization error", "error", err)
		os.Exit(1)
	}

	dataDir := os.Getenv("DATA_DIR")
	if dataDir == "" {
		dataDir = DefaultDataDir
		if _, err := os.Stat("/app"); os.IsNotExist(err) {
			dataDir = "./data"
		}
	}
	if err := os.MkdirAll(dataDir, 0775); err != nil {
		slog.Warn("Failed to ensure data directory exists", "path", dataDir, "error", err)
	}
	CTLogsPath = filepath.Join(dataDir, "ct_logs")
	if err := os.MkdirAll(CTLogsPath, 0775); err != nil {
		slog.Warn("Failed to ensure ct_logs directory exists", "path", CTLogsPath, "error", err)
	}
	ctStatePath := filepath.Join(dataDir, "ct_state.json")

	rdapClient := &rdap.Client{
		HTTP: NewRDAPHTTPClient(10 * time.Second),
	}
	slog.Info(fmt.Sprintf(MsgLogStartup, len(app.Config.Domains), len(app.Config.DNSRecords)))

	firstRunDone := make(chan struct{})
	server := setupHTTPServer(app, app.Config.Port, firstRunDone)

	// Execute concurrent engine
	go func() {
		defer app.Notifier.Flush(ctx)
		maxWorkers := runtime.NumCPU() * 10
		if maxWorkers < 50 {
			maxWorkers = 50
		}

		isFirstRun := true
		ctLogPersist := make(map[string]*CTLogState)

		if b, err := os.ReadFile(ctStatePath); err == nil {
			if jsonErr := json.Unmarshal(b, &ctLogPersist); jsonErr != nil {
				slog.Warn("Failed to parse ct_state.json", "error", jsonErr)
			}
		}

		indexTmpl, err := template.New("index").Parse(string(indexHTML))
		if err != nil {
			slog.Error("Failed to parse index template", "error", err)
		}

		for {
			app.Notifier.StartCycle()

			loopState := &CheckState{
				RDAP:   make(map[string]*RDAPState),
				DNS:    make(map[string]*DNSState),
				Email:  make(map[string]*EmailState),
				CAA:    make(map[string]*CAAResult),
				DNSSEC: make(map[string]*DNSSECResult),
				CTLogs: make(map[string]*CTLogState),
			}

			for k, v := range ctLogPersist {
				loopState.CTLogs[k] = &CTLogState{
					LatestID:         v.LatestID,
					BackfillCursor:   v.BackfillCursor,
					BackfillComplete: v.BackfillComplete,
				}
			}

			for _, dt := range app.Config.Domains {
				loopState.UpdateRDAP(dt.Domain, &RDAPState{Status: StatusPending})
			}

			// Execute DNS & Email concurrently
			g, gCtx := errgroup.WithContext(ctx)
			g.SetLimit(maxWorkers)

			// Dispatch DNS
			for _, dnc := range app.Config.DNSRecords {
				record := dnc
				g.Go(func() error {
					evaluateDNS(gCtx, app, record, loopState)
					return nil
				})
			}

			// Dispatch Domain Checks
			for _, dt := range app.Config.Domains {
				domain := dt
				g.Go(func() error {
					evaluateEmailSecurity(gCtx, app, domain, loopState)
					return nil
				})
				if domain.IsDelegatedZone {
					g.Go(func() error {
						validateNSDelegation(gCtx, app, domain, loopState)
						return nil
					})
				}
				g.Go(func() error {
					evaluateDNSSEC(gCtx, app, domain, loopState)
					return nil
				})
				g.Go(func() error {
					evaluateCAA(gCtx, app, domain, loopState)
					return nil
				})
			}

			_ = g.Wait()

			// Run RDAP sequentially with rate limits
			whoisTicker := time.NewTicker(app.WhoisDelay)
			for _, dt := range app.Config.Domains {
				if dt.IsDelegatedZone {
					continue
				}
				select {
				case <-ctx.Done():
					whoisTicker.Stop()
					return
				case <-whoisTicker.C:
					evaluateRDAP(ctx, rdapClient, app, dt, loopState)
				}
			}
			whoisTicker.Stop()

			// Run CTLogs sequentially with rate limits
			reqTicker := time.NewTicker(app.ReqDelay)
			for _, dt := range app.Config.Domains {
				if !dt.MonitorCTLogs {
					continue
				}
				select {
				case <-ctx.Done():
					reqTicker.Stop()
					return
				case <-reqTicker.C:
					evaluateCTLogs(ctx, app, dt, loopState)
				}
			}
			reqTicker.Stop()

			for k, v := range loopState.ExportCTLogs() {
				ctLogPersist[k] = v
			}

			if b, err := json.Marshal(ctLogPersist); err == nil {
				if writeErr := atomicWriteFile(ctStatePath, b, 0600); writeErr != nil {
					slog.Warn("Failed to write ct_state.json", "error", writeErr)
				}
			}

			// Dispatch notifications
			app.Notifier.Flush(ctx)
			app.Notifier.EndCycle()

			// Pre-render JSON and HTML
			loopState.NextRefresh = time.Now().Add(app.LoopDuration).UTC().Format(time.RFC3339)
			jsonBytes, _ := json.Marshal(loopState)
			app.PrerenderedJSON.Store(jsonBytes)

			if indexTmpl != nil {
				var buf bytes.Buffer
				if err := indexTmpl.Execute(&buf, map[string]interface{}{
					"StateJSON": template.JS(jsonBytes),
				}); err != nil {
					slog.Error("HTML prerender failed", "error", err)
				} else {
					app.PrerenderedHTML.Store(buf.Bytes())
				}
			}

			if isFirstRun {
				close(firstRunDone)
				isFirstRun = false
			}

			// Wait for next cycle
			timer := time.NewTimer(app.LoopDuration)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		}
	}()

	// Graceful shutdown handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	sig := <-sigChan
	slog.Info(fmt.Sprintf(MsgLogShutdownSignal, sig))

	// Trigger cancellation for engines
	cancel()

	// Shutdown HTTP Server
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	_ = server.Shutdown(shutdownCtx)

	// Wait for notifications to complete
	app.Notifier.Wait()

	slog.Info(MsgLogShutdownComplete)
}

type DomainTierData struct {
	Source       string   `json:"source,omitempty"`
	Server       string   `json:"server,omitempty"`
	Registrar    string   `json:"registrar,omitempty"`
	IANAID       string   `json:"iana_id,omitempty"`
	Expiration   string   `json:"expiration,omitempty"`
	Created      string   `json:"created,omitempty"`
	Updated      string   `json:"updated,omitempty"`
	Nameservers  []string `json:"nameservers,omitempty"`
	DomainStatus []string `json:"domain_status,omitempty"`
	DNSSEC       bool     `json:"dnssec,omitempty"`
	Raw          string   `json:"-"`
}

type RDAPState struct {
	Status          CheckStatus     `json:"status"`
	Registrar       string          `json:"registrar,omitempty"`
	Expiration      string          `json:"expiration,omitempty"`
	Nameservers     []string        `json:"nameservers,omitempty"`
	DomainStatus    []string        `json:"domain_status,omitempty"`
	DNSSEC          bool            `json:"dnssec,omitempty"`
	Error           string          `json:"error,omitempty"`
	IsDelegatedZone bool            `json:"is_delegated_zone,omitempty"`
	Source          string          `json:"source,omitempty"`
	RegistryTier    *DomainTierData `json:"registry_tier,omitempty"`
	RegistrarTier   *DomainTierData `json:"registrar_tier,omitempty"`
	Discrepancies   []string        `json:"discrepancies,omitempty"`
}

type DNSState struct {
	Hostname string      `json:"hostname"`
	Name     string      `json:"name"`
	Type     string      `json:"type"`
	Expected []string    `json:"expected"`
	Status   CheckStatus `json:"status"`
	Found    []string    `json:"found,omitempty"`
	SSLDays  int         `json:"ssl_days,omitempty"`
	Error    string      `json:"error,omitempty"`
}

type EmailState struct {
	Provider  string      `json:"provider,omitempty"`
	Status    CheckStatus `json:"status"`
	SPF       bool        `json:"spf,omitempty"`
	DMARC     bool        `json:"dmarc,omitempty"`
	DKIMValid []string    `json:"dkim_valid,omitempty"`
	MX        []string    `json:"mx,omitempty"`
	Error     string      `json:"error,omitempty"`
}

type CheckState struct {
	RDAPMu      sync.RWMutex             `json:"-"`
	RDAP        map[string]*RDAPState    `json:"rdap_checks"`
	DNSMu       sync.RWMutex             `json:"-"`
	DNS         map[string]*DNSState     `json:"dns_checks"`
	EmailMu     sync.RWMutex             `json:"-"`
	Email       map[string]*EmailState   `json:"email_checks"`
	CAAMu       sync.RWMutex             `json:"-"`
	CAA         map[string]*CAAResult    `json:"caa_checks,omitempty"`
	DNSSECMu    sync.RWMutex             `json:"-"`
	DNSSEC      map[string]*DNSSECResult `json:"dnssec_checks,omitempty"`
	CTLogsMu    sync.RWMutex             `json:"-"`
	CTLogs      map[string]*CTLogState   `json:"ct_logs,omitempty"`
	LastMu      sync.RWMutex             `json:"-"`
	LastUpdated string                   `json:"last_updated"`
	NextRefresh string                   `json:"next_refresh"`
}

func (c *CheckState) UpdateRDAP(key string, state *RDAPState) {
	c.RDAPMu.Lock()
	c.RDAP[key] = state
	c.RDAPMu.Unlock()
	c.LastMu.Lock()
	defer c.LastMu.Unlock()
	c.LastUpdated = time.Now().UTC().Format(time.RFC3339)
}

func (c *CheckState) UpdateDNS(key string, state *DNSState) {
	c.DNSMu.Lock()
	c.DNS[key] = state
	c.DNSMu.Unlock()
	c.LastMu.Lock()
	defer c.LastMu.Unlock()
	c.LastUpdated = time.Now().UTC().Format(time.RFC3339)
}

func (c *CheckState) UpdateEmail(key string, state *EmailState) {
	c.EmailMu.Lock()
	c.Email[key] = state
	c.EmailMu.Unlock()
	c.LastMu.Lock()
	defer c.LastMu.Unlock()
	c.LastUpdated = time.Now().UTC().Format(time.RFC3339)
}

func (c *CheckState) UpdateCAA(key string, state *CAAResult) {
	c.CAAMu.Lock()
	c.CAA[key] = state
	c.CAAMu.Unlock()
	c.LastMu.Lock()
	defer c.LastMu.Unlock()
	c.LastUpdated = time.Now().UTC().Format(time.RFC3339)
}

func (c *CheckState) UpdateDNSSEC(key string, state *DNSSECResult) {
	c.DNSSECMu.Lock()
	c.DNSSEC[key] = state
	c.DNSSECMu.Unlock()
	c.LastMu.Lock()
	defer c.LastMu.Unlock()
	c.LastUpdated = time.Now().UTC().Format(time.RFC3339)
}

func (c *CheckState) UpdateCTLogs(key string, state *CTLogState) {
	c.CTLogsMu.Lock()
	c.CTLogs[key] = state
	c.CTLogsMu.Unlock()
	c.LastMu.Lock()
	defer c.LastMu.Unlock()
	c.LastUpdated = time.Now().UTC().Format(time.RFC3339)
}

func (c *CheckState) ExportCTLogs() map[string]*CTLogState {
	c.CTLogsMu.RLock()
	defer c.CTLogsMu.RUnlock()
	res := make(map[string]*CTLogState)
	for k, v := range c.CTLogs {
		res[k] = v
	}
	return res
}
