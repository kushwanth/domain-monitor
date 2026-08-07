package main

import (
	_ "embed"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"html/template"
	"log"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/openrdap/rdap"
	"golang.org/x/sync/errgroup"
)

//go:embed index.html
var indexHTML []byte

var prerenderedHTML atomic.Value
var prerenderedJSON atomic.Value

func setupHTTPServer(port string, firstRunDone chan struct{}) *http.Server {
	mux := http.NewServeMux()

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok"}`))
	})

	mux.HandleFunc("/api/state", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=300")
		if b, ok := prerenderedJSON.Load().([]byte); ok {
			w.Write(b)
		} else {
			w.Write([]byte("{}"))
		}
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if b, ok := prerenderedHTML.Load().([]byte); ok {
			w.Write(b)
		} else {
			w.Write([]byte("Loading..."))
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

	ctx, cancel := context.WithCancel(context.Background())

	app, err := LoadConfig(ctx, configPath)
	if err != nil {
		log.Fatalf("[FATAL] Configuration error: %v", err)
	}

	rdapClient := &rdap.Client{}
	log.Printf(MsgLogStartup, len(app.Config.Domains), len(app.Config.DNSRecords))



	firstRunDone := make(chan struct{})
	server := setupHTTPServer(app.Config.Port, firstRunDone)

	// Execute concurrent engine
	go func() {
		maxWorkers := runtime.NumCPU()
		if maxWorkers < 2 {
			maxWorkers = 2
		}

		isFirstRun := true

		for {

			loopState := &CheckState{
				RDAP:  make(map[string]map[string]interface{}),
				DNS:   make(map[string]map[string]interface{}),
				Email: make(map[string]map[string]interface{}),
			}

			for _, dt := range app.Config.Domains {
				loopState.UpdateState("rdap", dt.Domain, map[string]interface{}{"status": "pending"})
			}

			// Execute DNS & Email concurrently
			g, _ := errgroup.WithContext(ctx)
			g.SetLimit(maxWorkers)

			// Dispatch DNS
			for _, dnc := range app.Config.DNSRecords {
				record := dnc
				g.Go(func() error {
					evaluateDNS(app, record, loopState)
					return nil
				})
			}

			// Dispatch Email
			for _, dt := range app.Config.Domains {
				domain := dt
				g.Go(func() error {
					evaluateEmailSecurity(app, domain, loopState)
					return nil
				})
			}

			g.Wait()

			// Run RDAP sequentially with rate limits
			for _, dt := range app.Config.Domains {
				select {
				case <-ctx.Done():
					return
				default:
					evaluateRDAP(rdapClient, app, dt, loopState)
					time.Sleep(app.ReqDelay)
				}
			}

			// Dispatch notifications
			app.Notifier.Flush()

			// Pre-render JSON and HTML
			loopState.NextRefresh = time.Now().Add(app.LoopDuration).UTC().Format(time.RFC3339)
			jsonBytes, _ := json.Marshal(loopState)
			prerenderedJSON.Store(jsonBytes)
			
			tmpl, err := template.New("index").Parse(string(indexHTML))
			if err == nil {
				var buf bytes.Buffer
				tmpl.Execute(&buf, map[string]interface{}{
					"StateJSON": template.JS(jsonBytes),
				})
				prerenderedHTML.Store(buf.Bytes())
			}

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

	// Wait for notifications to complete
	app.Notifier.Wait()

	log.Println(MsgLogShutdownComplete)
}

type CheckState struct {
	sync.Mutex
	RDAP        map[string]map[string]interface{} `json:"rdap_checks"`
	DNS         map[string]map[string]interface{} `json:"dns_checks"`
	Email       map[string]map[string]interface{} `json:"email_checks"`
	LastUpdated string                            `json:"last_updated"`
	NextRefresh string                            `json:"next_refresh"`
}

func (c *CheckState) UpdateState(category, key string, data map[string]interface{}) {
	c.Lock()
	defer c.Unlock()

	switch category {
	case "rdap":
		c.RDAP[key] = data
	case "dns":
		c.DNS[key] = data
	case "email":
		c.Email[key] = data
	}
	c.LastUpdated = time.Now().UTC().Format(time.RFC3339)
}
