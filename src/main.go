package main

import (
	"bytes"
	"context"
	_ "embed"
	jsonv2 "encoding/json/v2"
	"flag"
	"fmt"
	"html/template"
	"log/slog"
	"maps"
	"math/rand/v2"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/openrdap/rdap"
)

//go:embed index.html
var indexHTML []byte

func setupHTTPServer(app *AppState, port string, firstRunDone chan struct{}) (*http.Server, <-chan error) {
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
		domain := strings.TrimSuffix(strings.TrimSpace(r.URL.Query().Get("domain")), ".")
		if domain == "" || !ValidDomainRegex.MatchString(domain) {
			http.Error(w, `{"error": "invalid domain"}`, http.StatusBadRequest)
			return
		}

		filePath := filepath.Join(CTLogsPath, domain+".json")
		cleanPath := filepath.Clean(filePath)
		cleanBase := filepath.Clean(CTLogsPath)
		if cleanPath != cleanBase && !strings.HasPrefix(cleanPath, cleanBase+string(filepath.Separator)) {
			http.Error(w, `{"error": "invalid domain"}`, http.StatusBadRequest)
			return
		}

		b, err := os.ReadFile(cleanPath)
		if err != nil {
			_, _ = w.Write([]byte("[]"))
			return
		}
		_, _ = w.Write(b)
	})

	mux.HandleFunc("GET /api/ctlogs/{domain}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		domain := strings.TrimSuffix(strings.TrimSpace(r.PathValue("domain")), ".")
		if domain == "" || !ValidDomainRegex.MatchString(domain) {
			http.Error(w, `{"error": "invalid domain"}`, http.StatusBadRequest)
			return
		}

		filePath := filepath.Join(CTLogsPath, domain+".json")
		cleanPath := filepath.Clean(filePath)
		cleanBase := filepath.Clean(CTLogsPath)
		if cleanPath != cleanBase && !strings.HasPrefix(cleanPath, cleanBase+string(filepath.Separator)) {
			http.Error(w, `{"error": "invalid domain"}`, http.StatusBadRequest)
			return
		}

		b, err := os.ReadFile(cleanPath)
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
		Addr:                ":" + port,
		Handler:             mux,
		ReadTimeout:         5 * time.Second,
		WriteTimeout:        10 * time.Second,
		IdleTimeout:         120 * time.Second,
		MaxHeaderValueCount: 100,
	}

	errChan := make(chan error, 1)
	go func() {
		slog.Info(fmt.Sprintf(MsgLogHTTPAPI, port))
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("HTTP server failed", "error", err)
			errChan <- err
		}
	}()

	return server, errChan
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
	if dataDir == "" && app.Config.DataDir != "" {
		dataDir = app.Config.DataDir
	}
	if dataDir == "" {
		dataDir = DefaultDataDir
		if _, err := os.Stat("/app"); os.IsNotExist(err) {
			dataDir = "./data"
		}
	}
	if err := os.MkdirAll(dataDir, 0775); err != nil {
		slog.Warn("Failed to ensure data directory exists (ensure directory is writable by UID 65532 or use :U volume mount)", "path", dataDir, "error", err)
	}
	CTLogsPath = filepath.Join(dataDir, "ct_logs")
	if err := os.MkdirAll(CTLogsPath, 0775); err != nil {
		slog.Warn("Failed to ensure ct_logs directory exists (ensure directory is writable by UID 65532 or use :U volume mount)", "path", CTLogsPath, "error", err)
	}
	ctStatePath := filepath.Join(dataDir, "ct_state.json")

	rdapClient := &rdap.Client{
		HTTP: NewRDAPHTTPClient(10 * time.Second),
	}
	slog.Info(fmt.Sprintf(MsgLogStartup, len(app.Config.Domains), len(app.Config.DNSRecords)))

	firstRunDone := make(chan struct{})
	server, serverErrChan := setupHTTPServer(app, app.Config.Port, firstRunDone)

	// Execute concurrent engine
	go func() {
		defer app.Notifier.Flush(ctx)
		maxWorkers := max(runtime.NumCPU()*10, 50)

		isFirstRun := true
		ctLogPersist := make(map[string]*CTLogState)
		prevRDAPStatus := make(map[string]CheckStatus)
		prevDNSStatus := make(map[string]CheckStatus)
		prevEmailStatus := make(map[string]CheckStatus)

		if b, err := os.ReadFile(ctStatePath); err == nil {
			if jsonErr := jsonv2.Unmarshal(b, &ctLogPersist); jsonErr != nil {
				slog.Warn("Failed to parse ct_state.json", "error", jsonErr)
			}
		}

		indexTmpl, err := template.New("index").Parse(string(indexHTML))
		if err != nil {
			slog.Error("Failed to parse index template", "error", err)
		}

		for {
			cycleStart := time.Now()
			cycleMaxTimeout := max(app.LoopDuration, 15*time.Minute)
			cycleCtx, cycleCancel := context.WithTimeout(ctx, cycleMaxTimeout)

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

			// Execute DNS & Email concurrently with panic recovery
			g := newWorkerGroup(cycleCtx, maxWorkers)

			safeGo := func(fn func()) {
				g.Go(func() {
					defer func() {
						if r := recover(); r != nil {
							slog.Error("Worker panicked during check execution", "panic", r)
						}
					}()
					fn()
				})
			}

			// Dispatch DNS
			for _, dnc := range app.Config.DNSRecords {
				record := dnc
				safeGo(func() {
					evaluateDNS(cycleCtx, app, record, loopState)
				})
			}

			// Dispatch Domain Checks
			for _, dt := range app.Config.Domains {
				domain := dt
				safeGo(func() {
					evaluateEmailSecurity(cycleCtx, app, domain, loopState)
				})
				if domain.IsDelegatedZone {
					safeGo(func() {
						validateNSDelegation(cycleCtx, app, domain, loopState)
					})
				}
				safeGo(func() {
					evaluateDNSSEC(cycleCtx, app, domain, loopState)
				})
				safeGo(func() {
					evaluateCAA(cycleCtx, app, domain, loopState)
				})
			}

			g.Wait()

			// Run RDAP concurrently with bounded workers & rate limiting
			gRDAP := newWorkerGroup(cycleCtx, 3)
			rdapTicker := time.NewTicker(app.WhoisDelay)

			for _, dt := range app.Config.Domains {
				if dt.IsDelegatedZone {
					continue
				}
				targetDomain := dt
				select {
				case <-cycleCtx.Done():
					break
				case <-rdapTicker.C:
				}
				gRDAP.Go(func() {
					defer func() {
						if r := recover(); r != nil {
							slog.Error("RDAP check panicked", "domain", targetDomain.Domain, "panic", r)
						}
					}()
					evaluateRDAP(cycleCtx, rdapClient, app, targetDomain, loopState)
				})
			}
			gRDAP.Wait()
			rdapTicker.Stop()

			// Run CTLogs concurrently with bounded workers & rate limiting
			gCT := newWorkerGroup(cycleCtx, 3)
			ctTicker := time.NewTicker(app.ReqDelay)

			for _, dt := range app.Config.Domains {
				if !dt.MonitorCTLogs {
					continue
				}
				targetDomain := dt
				select {
				case <-cycleCtx.Done():
					break
				case <-ctTicker.C:
				}
				gCT.Go(func() {
					defer func() {
						if r := recover(); r != nil {
							slog.Error("CT log check panicked", "domain", targetDomain.Domain, "panic", r)
						}
					}()
					evaluateCTLogs(cycleCtx, app, targetDomain, loopState)
				})
			}
			gCT.Wait()
			ctTicker.Stop()

			maps.Copy(ctLogPersist, loopState.ExportCTLogs())

			if b, err := jsonv2.Marshal(ctLogPersist); err == nil {
				if writeErr := atomicWriteFile(ctStatePath, b, 0600); writeErr != nil {
					slog.Warn("Failed to write ct_state.json", "error", writeErr)
				}
			}

			// State transition logging
			for domain, currRDAP := range loopState.RDAP {
				if prev, ok := prevRDAPStatus[domain]; ok && prev != currRDAP.Status {
					slog.Info("State transition", "check", "RDAP", "domain", domain, "prev", prev, "current", currRDAP.Status)
				}
				prevRDAPStatus[domain] = currRDAP.Status
			}
			for name, currDNS := range loopState.DNS {
				if prev, ok := prevDNSStatus[name]; ok && prev != currDNS.Status {
					slog.Info("State transition", "check", "DNS", "record", name, "prev", prev, "current", currDNS.Status)
				}
				prevDNSStatus[name] = currDNS.Status
			}
			for domain, currEmail := range loopState.Email {
				if prev, ok := prevEmailStatus[domain]; ok && prev != currEmail.Status {
					slog.Info("State transition", "check", "Email", "domain", domain, "prev", prev, "current", currEmail.Status)
				}
				prevEmailStatus[domain] = currEmail.Status
			}

			// Dispatch notifications
			app.Notifier.Flush(cycleCtx)
			app.Notifier.EndCycle()

			// Pre-render JSON and HTML
			loopState.LastUpdated = time.Now().UTC().Format(time.RFC3339)
			loopState.NextRefresh = time.Now().Add(app.LoopDuration).UTC().Format(time.RFC3339)
			jsonBytes, _ := jsonv2.Marshal(loopState)
			app.PrerenderedJSON.Store(jsonBytes)

			if indexTmpl != nil {
				var buf bytes.Buffer
				if err := indexTmpl.Execute(&buf, map[string]any{
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

			cycleDuration := time.Since(cycleStart)
			slog.Info("Monitoring cycle completed",
				"duration_ms", cycleDuration.Milliseconds(),
				"domains_checked", len(app.Config.Domains),
				"dns_records_checked", len(app.Config.DNSRecords),
			)
			cycleCancel()

			// Wait for next cycle with ±5% jitter using Go 1.27 generic rand.N on time.Duration
			jitterRange := app.LoopDuration / 20
			var jitter time.Duration
			if jitterRange > 0 {
				jitter = rand.N(jitterRange*2) - jitterRange
			}
			nextInterval := max(app.LoopDuration+jitter, 1*time.Second)

			timer := time.NewTimer(nextInterval)
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

	select {
	case sig := <-sigChan:
		slog.Info(fmt.Sprintf(MsgLogShutdownSignal, sig))
	case sErr := <-serverErrChan:
		slog.Error("HTTP server stopped unexpectedly", "error", sErr)
	}

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
