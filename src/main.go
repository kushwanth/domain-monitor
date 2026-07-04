package main

import (
	_ "embed"
	"context"
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/openrdap/rdap"
	"golang.org/x/sync/errgroup"
)

//go:embed index.html
var indexHTML []byte

func setupHTTPServer(port string, firstRunDone chan struct{}) *http.Server {
	mux := http.NewServeMux()

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok"}`))
	})

	mux.HandleFunc("/api/state", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=300")

		LiveState.RLock()
		defer LiveState.RUnlock()
		json.NewEncoder(w).Encode(LiveState)
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(indexHTML)
	})

	server := &http.Server{
		Addr:    ":" + port,
		Handler: mux,
	}

	go func() {
		<-firstRunDone
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

	app, err := LoadConfig(configPath)
	if err != nil {
		log.Fatalf("[FATAL] Configuration error: %v", err)
	}

	rdapClient := &rdap.Client{}
	log.Printf(MsgLogStartup, len(app.Config.Domains), len(app.Config.DNSRecords))

	ctx, cancel := context.WithCancel(context.Background())

	for _, dt := range app.Config.Domains {
		UpdateRDAPState(dt.Domain, map[string]interface{}{"status": "pending"})
	}

	firstRunDone := make(chan struct{})
	server := setupHTTPServer(app.Config.Port, firstRunDone)

	// Unified Execution Engine
	go func() {
		maxWorkers := runtime.NumCPU()
		if maxWorkers < 2 {
			maxWorkers = 2
		}

		isFirstRun := true

		for {

			// Phase 1: High-Speed Concurrent DNS & Email Security
			g, _ := errgroup.WithContext(ctx)
			g.SetLimit(maxWorkers)

			// Dispatch DNS Records
			for _, dnc := range app.Config.DNSRecords {
				record := dnc
				g.Go(func() error {
					evaluateDNS(app, record)
					return nil
				})
			}

			// Dispatch Email Security
			for _, dt := range app.Config.Domains {
				domain := dt
				g.Go(func() error {
					evaluateEmailSecurity(app, domain)
					return nil
				})
			}

			g.Wait() // Wait for DNS & Email to finish

			// Phase 2: Sequential Rate-Limited RDAP Sweep
			for _, dt := range app.Config.Domains {
				select {
				case <-ctx.Done():
					return
				default:
					evaluateRDAP(rdapClient, app, dt)
					time.Sleep(app.ReqDelay)
				}
			}

			// Phase 3: Flush Consolidated Notifications
			app.Notifier.Flush()

			if isFirstRun {
				close(firstRunDone)
				isFirstRun = false
			}

			// Wait for next cycle
			select {
			case <-ctx.Done():
				return
			case <-time.After(app.LoopDuration):
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
	server.Shutdown(shutdownCtx)

	log.Println(MsgLogShutdownComplete)
}

type CheckState struct {
	sync.RWMutex
	RDAP        map[string]map[string]interface{} `json:"rdap_checks"`
	DNS         map[string]map[string]interface{} `json:"dns_checks"`
	Email       map[string]map[string]interface{} `json:"email_checks"`
	LastUpdated string                            `json:"last_updated"`
}

var LiveState = &CheckState{
	RDAP:  make(map[string]map[string]interface{}),
	DNS:   make(map[string]map[string]interface{}),
	Email: make(map[string]map[string]interface{}),
}

func UpdateRDAPState(domain string, data map[string]interface{}) {
	LiveState.Lock()
	defer LiveState.Unlock()
	LiveState.RDAP[domain] = data
	LiveState.LastUpdated = time.Now().UTC().Format(time.RFC3339)
}

func UpdateDNSState(record string, data map[string]interface{}) {
	LiveState.Lock()
	defer LiveState.Unlock()
	LiveState.DNS[record] = data
	LiveState.LastUpdated = time.Now().UTC().Format(time.RFC3339)
}

func UpdateEmailState(domain string, data map[string]interface{}) {
	LiveState.Lock()
	defer LiveState.Unlock()
	LiveState.Email[domain] = data
	LiveState.LastUpdated = time.Now().UTC().Format(time.RFC3339)
}
