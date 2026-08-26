package main

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"flag"
	"html/template"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
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

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	mux.HandleFunc("/api/state", func(w http.ResponseWriter, r *http.Request) {
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

	mux.HandleFunc("/api/certs", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		domain := r.URL.Query().Get("domain")
		if domain == "" {
			http.Error(w, `{"error": "domain required"}`, http.StatusBadRequest)
			return
		}

		// Prevent path traversal — domain must be a simple filename component
		if domain != filepath.Base(domain) || strings.Contains(domain, "..") || strings.ContainsAny(domain, "/\\") {
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
		log.Printf(MsgLogHTTPAPI, port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("[FATAL] HTTP server failed: %v", err)
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
		log.Fatalf("[FATAL] Configuration error: %v", err)
	}

	defaultDataDir := "./data"
	CTLogsPath = filepath.Join(defaultDataDir, "ct_logs")
	ctStatePath := filepath.Join(defaultDataDir, "ct_state.json")

	rdapClient := &rdap.Client{
		HTTP: &http.Client{Timeout: 10 * time.Second},
	}
	log.Printf(MsgLogStartup, len(app.Config.Domains), len(app.Config.DNSRecords))

	firstRunDone := make(chan struct{})
	server := setupHTTPServer(app, app.Config.Port, firstRunDone)

	// Execute concurrent engine
	go func() {
		defer app.Notifier.Flush()
		maxWorkers := runtime.NumCPU() * 10
		if maxWorkers < 50 {
			maxWorkers = 50
		}

		isFirstRun := true
		ctLogPersist := make(map[string]*CTLogState)

		if b, err := os.ReadFile(ctStatePath); err == nil {
			if jsonErr := json.Unmarshal(b, &ctLogPersist); jsonErr != nil {
				log.Printf("[WARN] Failed to parse ct_state.json: %v", jsonErr)
			}
		}

		indexTmpl, err := template.New("index").Parse(string(indexHTML))
		if err != nil {
			log.Printf("[ERROR] Failed to parse index template: %v", err)
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
			for _, dt := range app.Config.Domains {
				if dt.IsDelegatedZone {
					continue
				}
				select {
				case <-ctx.Done():
					return
				default:
					evaluateRDAP(ctx, rdapClient, app, dt, loopState)
					select {
					case <-ctx.Done():
						return
					case <-time.After(app.WhoisDelay):
					}
				}
			}

			// Run CTLogs sequentially with rate limits
			for _, dt := range app.Config.Domains {
				if !dt.MonitorCTLogs {
					continue
				}
				select {
				case <-ctx.Done():
					return
				default:
					evaluateCTLogs(ctx, app, dt, loopState)
					select {
					case <-ctx.Done():
						return
					case <-time.After(app.ReqDelay):
					}
				}
			}

			for k, v := range loopState.ExportCTLogs() {
				ctLogPersist[k] = v
			}

			if b, err := json.Marshal(ctLogPersist); err == nil {
				if writeErr := atomicWriteFile(ctStatePath, b, 0644); writeErr != nil {
					log.Printf("[WARN] Failed to write ct_state.json: %v", writeErr)
				}
			}

			// Dispatch notifications
			app.Notifier.Flush()
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
					log.Printf("[ERROR] HTML prerender failed: %v", err)
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
	log.Printf(MsgLogShutdownSignal, sig)

	// Trigger cancellation for engines
	cancel()

	// Shutdown HTTP Server
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	_ = server.Shutdown(shutdownCtx)

	// Wait for notifications to complete
	app.Notifier.Wait()

	log.Println(MsgLogShutdownComplete)
}

type RDAPState struct {
	Status          CheckStatus `json:"status"`
	Registrar       string      `json:"registrar,omitempty"`
	Expiration      string      `json:"expiration,omitempty"`
	Nameservers     []string    `json:"nameservers,omitempty"`
	DomainStatus    []string    `json:"domain_status,omitempty"`
	DNSSEC          bool        `json:"dnssec,omitempty"`
	Error           string      `json:"error,omitempty"`
	IsDelegatedZone bool        `json:"is_delegated_zone,omitempty"`
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
	sync.Mutex  `json:"-"`
	RDAP        map[string]*RDAPState    `json:"rdap_checks"`
	DNS         map[string]*DNSState     `json:"dns_checks"`
	Email       map[string]*EmailState   `json:"email_checks"`
	CAA         map[string]*CAAResult    `json:"caa_checks,omitempty"`
	DNSSEC      map[string]*DNSSECResult `json:"dnssec_checks,omitempty"`
	CTLogs      map[string]*CTLogState   `json:"ct_logs,omitempty"`
	LastUpdated string                   `json:"last_updated"`
	NextRefresh string                   `json:"next_refresh"`
}

func (c *CheckState) UpdateRDAP(key string, state *RDAPState) {
	c.Lock()
	defer c.Unlock()
	c.RDAP[key] = state
	c.LastUpdated = time.Now().UTC().Format(time.RFC3339)
}

func (c *CheckState) UpdateDNS(key string, state *DNSState) {
	c.Lock()
	defer c.Unlock()
	c.DNS[key] = state
	c.LastUpdated = time.Now().UTC().Format(time.RFC3339)
}

func (c *CheckState) UpdateEmail(key string, state *EmailState) {
	c.Lock()
	defer c.Unlock()
	c.Email[key] = state
	c.LastUpdated = time.Now().UTC().Format(time.RFC3339)
}

func (c *CheckState) UpdateCAA(key string, state *CAAResult) {
	c.Lock()
	defer c.Unlock()
	c.CAA[key] = state
	c.LastUpdated = time.Now().UTC().Format(time.RFC3339)
}

func (c *CheckState) UpdateDNSSEC(key string, state *DNSSECResult) {
	c.Lock()
	defer c.Unlock()
	c.DNSSEC[key] = state
	c.LastUpdated = time.Now().UTC().Format(time.RFC3339)
}

func (c *CheckState) UpdateCTLogs(key string, state *CTLogState) {
	c.Lock()
	defer c.Unlock()
	c.CTLogs[key] = state
	c.LastUpdated = time.Now().UTC().Format(time.RFC3339)
}

func (c *CheckState) ExportCTLogs() map[string]*CTLogState {
	c.Lock()
	defer c.Unlock()
	res := make(map[string]*CTLogState)
	for k, v := range c.CTLogs {
		res[k] = v
	}
	return res
}
