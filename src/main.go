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
	"slices"
	"strings"
	"syscall"
	"time"
)

//go:embed index.html
var indexHTML []byte

func securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("X-XSS-Protection", "0")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'self'; form-action 'self';")
		next.ServeHTTP(w, r)
	})
}

func setupHTTPServer(app *AppState, port string) (*http.Server, <-chan error) {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	mux.HandleFunc("GET /api/state", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-cache")
		if b, ok := app.PrerenderedJSON.Load().([]byte); ok {
			_, _ = w.Write(b)
		} else {
			_, _ = w.Write([]byte(`{"status":"initializing"}`))
		}
	})

	mux.HandleFunc("GET /api/certs", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		domain := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(r.URL.Query().Get("domain")), "."))
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
		domain := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(r.PathValue("domain")), "."))
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
		if b, ok := app.PrerenderedHTML.Load().([]byte); ok {
			_, _ = w.Write(b)
		} else {
			_, _ = w.Write([]byte(`<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta http-equiv="refresh" content="2">
  <title>DomainGuard - Initializing</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f172a; color: #f8fafc; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }
    .card { background: #1e293b; border: 1px solid #334155; padding: 32px; border-radius: 12px; text-align: center; max-width: 420px; box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.3); }
    .spinner { width: 36px; height: 36px; border: 3px solid #334155; border-top-color: #3b82f6; border-radius: 50%; animation: spin 1s linear infinite; margin: 0 auto 16px; }
    @keyframes spin { to { transform: rotate(360deg); } }
    h2 { margin: 0 0 8px; font-size: 1.25rem; font-weight: 600; }
    p { color: #94a3b8; font-size: 0.9rem; margin: 0; line-height: 1.5; }
  </style>
</head>
<body>
  <div class="card">
    <div class="spinner"></div>
    <h2>DomainGuard Initializing</h2>
    <p>Running initial domain, DNS, and SSL security checks. This page will update automatically in a moment...</p>
  </div>
</body>
</html>`))
		}
	})

	server := &http.Server{
		Addr:                ":" + port,
		Handler:             securityHeadersMiddleware(mux),
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

	rdapHTTPClient := NewRDAPHTTPClient(10 * time.Second)
	slog.Info(fmt.Sprintf(MsgLogStartup, len(app.Config.Domains), len(app.Config.DNSRecords)))

	indexTmpl, err := template.New("index").Parse(string(indexHTML))
	if err != nil {
		slog.Error("Failed to parse index template", "error", err)
	}

	// Pre-render initial application state immediately so GET / and GET /api/state
	// are instantly available upon process startup.
	initialState := &CheckState{
		RDAP:     make(map[string]*RDAPState),
		DNS:      make(map[string]*DNSState),
		Email:    make(map[string]*EmailState),
		CAA:      make(map[string]*CAAResult),
		DNSSEC:   make(map[string]*DNSSECResult),
		CTLogs:   make(map[string]*CTLogState),
		NSHealth: make(map[string]*NSHealthResult),
	}
	for _, dt := range app.Config.Domains {
		initialState.RDAP[dt.Domain] = &RDAPState{Status: StatusPending}
		if dt.VerifyNSHealth && len(dt.ExpectedNS) > 0 {
			initialState.NSHealth[dt.Domain] = &NSHealthResult{
				Primary: dt.ExpectedNS[0],
			}
		}
	}
	for _, rec := range app.Config.DNSRecords {
		key := rec.Name
		initialState.DNS[key] = &DNSState{
			Hostname: rec.Hostname,
			Name:     rec.Name,
			Type:     rec.Type,
			Expected: rec.Expected,
			Status:   StatusPending,
			SkipSSL:  rec.SkipSSL,
			SSLDays:  SSLDaysNotApplicable,
		}
	}
	if b, err := jsonv2.Marshal(initialState); err == nil {
		app.PrerenderedJSON.Store(b)
		if indexTmpl != nil {
			var buf bytes.Buffer
			escapedJSON := bytes.ReplaceAll(b, []byte("</"), []byte(`<\/`))
			if err := indexTmpl.Execute(&buf, map[string]any{
				"StateJSON": template.JS(escapedJSON),
			}); err == nil {
				app.PrerenderedHTML.Store(buf.Bytes())
			}
		}
	}

	server, serverErrChan := setupHTTPServer(app, app.Config.Port)

	engineDone := make(chan struct{})
	// Execute concurrent engine
	go func() {
		defer close(engineDone)
		defer func() {
			flushCtx, flushCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer flushCancel()
			app.Notifier.Flush(flushCtx)
		}()
		defer func() {
			if r := recover(); r != nil {
				slog.Error("Monitoring engine encountered unexpected panic", "panic", r)
			}
		}()
		maxWorkers := max(runtime.NumCPU()*10, 50)

		ctLogPersist := make(map[string]*CTLogState)
		prevRDAPStatus := make(map[string]CheckStatus)
		prevDNSStatus := make(map[string]CheckStatus)
		prevEmailStatus := make(map[string]CheckStatus)

		if b, err := os.ReadFile(ctStatePath); err == nil {
			if jsonErr := jsonv2.Unmarshal(b, &ctLogPersist); jsonErr != nil {
				slog.Warn("Failed to parse ct_state.json", "error", jsonErr)
			}
		}

		for {
			func() {
				defer func() {
					if r := recover(); r != nil {
						slog.Error("Monitoring cycle encountered unexpected panic", "panic", r)
					}
				}()

				cycleStart := time.Now()
				ctCount := 0
				for _, dt := range app.Config.Domains {
					if dt.MonitorCTLogs {
						ctCount++
					}
				}
				estimatedRequiredTime := (time.Duration(len(app.Config.Domains)) * app.WhoisDelay) +
					(time.Duration(ctCount) * app.ReqDelay) + 5*time.Minute
				cycleMaxTimeout := max(app.LoopDuration, 15*time.Minute, estimatedRequiredTime)
				cycleCtx, cycleCancel := context.WithTimeout(ctx, cycleMaxTimeout)

				app.Notifier.StartCycle()

				loopState := &CheckState{
					RDAP:     make(map[string]*RDAPState),
					DNS:      make(map[string]*DNSState),
					Email:    make(map[string]*EmailState),
					CAA:      make(map[string]*CAAResult),
					DNSSEC:   make(map[string]*DNSSECResult),
					CTLogs:   make(map[string]*CTLogState),
					NSHealth: make(map[string]*NSHealthResult),
				}

				activeDomains := make(map[string]bool, len(app.Config.Domains))
				for _, dt := range app.Config.Domains {
					activeDomains[dt.Domain] = true
				}

				for k, v := range ctLogPersist {
					if !activeDomains[k] {
						continue
					}
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
					if domain.VerifyNSHealth && len(domain.ExpectedNS) > 0 {
						safeGo(func() {
							evaluateNSHealth(cycleCtx, app, domain, loopState)
						})
					}
				}

				g.Wait()

				// Run RDAP concurrently with bounded workers & rate limiting
				gRDAP := newWorkerGroup(cycleCtx, 3)
				rdapTicker := time.NewTicker(app.WhoisDelay)
				rdapFirst := true

			rdapLoop:
				for _, dt := range app.Config.Domains {
					if dt.IsDelegatedZone {
						continue
					}
					targetDomain := dt
					if !rdapFirst {
						select {
						case <-cycleCtx.Done():
							break rdapLoop
						case <-rdapTicker.C:
						}
					}
					rdapFirst = false

					gRDAP.Go(func() {
						defer func() {
							if r := recover(); r != nil {
								slog.Error("RDAP check panicked", "domain", targetDomain.Domain, "panic", r)
							}
						}()
						evaluateRDAP(cycleCtx, rdapHTTPClient, app, targetDomain, loopState)
					})
				}
				gRDAP.Wait()
				rdapTicker.Stop()

				// Run CTLogs concurrently with bounded workers & rate limiting
				gCT := newWorkerGroup(cycleCtx, 3)
				ctTicker := time.NewTicker(app.ReqDelay)
				ctFirst := true

			ctLoop:
				for _, dt := range app.Config.Domains {
					if !dt.MonitorCTLogs {
						continue
					}
					targetDomain := dt
					if !ctFirst {
						select {
						case <-cycleCtx.Done():
							break ctLoop
						case <-ctTicker.C:
						}
					}
					ctFirst = false

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
				for k := range ctLogPersist {
					if !activeDomains[k] {
						delete(ctLogPersist, k)
					}
				}

				if b, err := jsonv2.Marshal(ctLogPersist); err == nil {
					if writeErr := atomicWriteFile(ctStatePath, b, 0600); writeErr != nil {
						slog.Warn("Failed to write ct_state.json", "error", writeErr)
					}
				}

				// State transition logging with Go 1.27 sorted map key iterators
				for _, domain := range slices.Sorted(maps.Keys(loopState.RDAP)) {
					currRDAP := loopState.RDAP[domain]
					if currRDAP == nil {
						continue
					}
					if prev, ok := prevRDAPStatus[domain]; ok && prev != currRDAP.Status {
						slog.Info("State transition", "check", "RDAP", "domain", domain, "prev", prev, "current", currRDAP.Status)
					}
					prevRDAPStatus[domain] = currRDAP.Status
				}
				for _, name := range slices.Sorted(maps.Keys(loopState.DNS)) {
					currDNS := loopState.DNS[name]
					if currDNS == nil {
						continue
					}
					if prev, ok := prevDNSStatus[name]; ok && prev != currDNS.Status {
						slog.Info("State transition", "check", "DNS", "record", name, "prev", prev, "current", currDNS.Status)
					}
					prevDNSStatus[name] = currDNS.Status
				}
				for _, domain := range slices.Sorted(maps.Keys(loopState.Email)) {
					currEmail := loopState.Email[domain]
					if currEmail == nil {
						continue
					}
					if prev, ok := prevEmailStatus[domain]; ok && prev != currEmail.Status {
						slog.Info("State transition", "check", "Email", "domain", domain, "prev", prev, "current", currEmail.Status)
					}
					prevEmailStatus[domain] = currEmail.Status
				}

				// Dispatch notifications with dedicated context so alerts are sent even if cycleCtx expired
				notifyCtx, notifyCancel := context.WithTimeout(ctx, 30*time.Second)
				app.Notifier.Flush(notifyCtx)
				app.Notifier.Wait()
				notifyCancel()
				app.Notifier.EndCycle()

				// Pre-render JSON and HTML
				loopState.LastUpdated = time.Now().UTC().Format(time.RFC3339)
				loopState.NextRefresh = time.Now().Add(app.LoopDuration).UTC().Format(time.RFC3339)
				jsonBytes, _ := jsonv2.Marshal(loopState)
				app.PrerenderedJSON.Store(jsonBytes)

				if indexTmpl != nil {
					var buf bytes.Buffer
					escapedJSON := bytes.ReplaceAll(jsonBytes, []byte("</"), []byte(`<\/`))
					if err := indexTmpl.Execute(&buf, map[string]any{
						"StateJSON": template.JS(escapedJSON),
					}); err != nil {
						slog.Error("HTML prerender failed", "error", err)
					} else {
						app.PrerenderedHTML.Store(buf.Bytes())
					}
				}

				cycleDuration := time.Since(cycleStart)
				slog.Info("Monitoring cycle completed",
					"duration_ms", cycleDuration.Milliseconds(),
					"domains_checked", len(app.Config.Domains),
					"dns_records_checked", len(app.Config.DNSRecords),
				)
				cycleCancel()
			}()

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
	case <-engineDone:
		slog.Error("Monitoring engine stopped unexpectedly")
	}

	// Trigger cancellation for engines
	cancel()

	// Shutdown HTTP Server
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	_ = server.Shutdown(shutdownCtx)

	// Wait for monitoring engine to complete in-flight writes
	select {
	case <-engineDone:
	case <-time.After(5 * time.Second):
		slog.Warn("Monitoring engine shutdown timed out")
	}

	// Wait for notifications to complete
	app.Notifier.Wait()

	slog.Info(MsgLogShutdownComplete)
}
