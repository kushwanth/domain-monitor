package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/go-jsonnet"
)

type Providers struct {
	CloudflareToken string `json:"cloudflare_token"`
}

type NtfyConfig struct {
	URL  string `json:"url"`
	Auth string `json:"auth"`
}

type TelegramConfig struct {
	Token  string `json:"token"`
	ChatID string `json:"chat_id"`
}

type Notifications struct {
	Ntfy     *NtfyConfig     `json:"ntfy"`
	Telegram *TelegramConfig `json:"telegram"`
	// Add other platforms here in the future
}

type AppConfig struct {
	Port          string         `json:"port"`
	LoopInterval  string         `json:"loop_interval"`
	RequestDelay  string         `json:"request_delay"`
	Notifications Notifications  `json:"notifications"`
	Providers     Providers      `json:"providers"`
	Resolvers     []string       `json:"resolvers"`
	Domains       []DomainConfig `json:"domains"`
	DNSRecords    []DNSTask      `json:"dns_records"`
}

type DomainConfig struct {
	Domain             string   `json:"domain"`
	Name               string   `json:"name"`
	ExpectedNS         []string `json:"expected_ns"`
	CheckEmailSecurity bool     `json:"check_email_security"`
	MailProvider       string   `json:"mail_provider"`
	MXRecords          []string `json:"mx_records"`
	DKIMSelectors      []string `json:"dkim_selectors"`
	SuppressAlerts     bool     `json:"suppress_alerts"`
}

type DNSTask struct {
	Hostname       string   `json:"hostname"`
	Name           string   `json:"name"`
	Type           string   `json:"type"`
	Expected       []string `json:"expected"`
	Provider       string   `json:"provider"`
	CustomResolver string   `json:"custom_resolver"`
}

type AppState struct {
	Config           *AppConfig
	CF               *CFClient
	Notifier         *NotificationManager
	LoopDuration     time.Duration
	ReqDelay         time.Duration
	StateMu          sync.Mutex
	StateLastChanged map[string]string
}

func LoadConfig(path string) (*AppState, error) {
	if path == "" {
		path = "config.jsonnet"
	}

	vm := jsonnet.MakeVM()
	jsonStr, err := vm.EvaluateFile(path)
	if err != nil {
		return nil, fmt.Errorf("jsonnet evaluation failed: %v", err)
	}

	var rawCfg AppConfig
	if err := json.Unmarshal([]byte(jsonStr), &rawCfg); err != nil {
		return nil, fmt.Errorf("json unmarshal failed: %v", err)
	}

	// Override with environment variables if provided
	if t := strings.TrimSpace(os.Getenv("CLOUDFLARE_TOKEN")); t != "" {
		rawCfg.Providers.CloudflareToken = t
	}
	if t := strings.TrimSpace(os.Getenv("NTFY_AUTH")); t != "" {
		if rawCfg.Notifications.Ntfy == nil {
			rawCfg.Notifications.Ntfy = &NtfyConfig{}
		}
		rawCfg.Notifications.Ntfy.Auth = t
	}
	if t := strings.TrimSpace(os.Getenv("TELEGRAM_TOKEN")); t != "" {
		if rawCfg.Notifications.Telegram == nil {
			rawCfg.Notifications.Telegram = &TelegramConfig{}
		}
		rawCfg.Notifications.Telegram.Token = t
	}
	if id := strings.TrimSpace(os.Getenv("TELEGRAM_CHAT_ID")); id != "" {
		if rawCfg.Notifications.Telegram == nil {
			rawCfg.Notifications.Telegram = &TelegramConfig{}
		}
		rawCfg.Notifications.Telegram.ChatID = id
	}

	nm := &NotificationManager{}

	// 1. Validate and Register Ntfy
	if rawCfg.Notifications.Ntfy != nil && rawCfg.Notifications.Ntfy.URL != "" {
		if rawCfg.Notifications.Ntfy.Auth != "" && !strings.HasPrefix(strings.ToLower(rawCfg.Notifications.Ntfy.Auth), "bearer ") && !strings.HasPrefix(strings.ToLower(rawCfg.Notifications.Ntfy.Auth), "basic ") {
			rawCfg.Notifications.Ntfy.Auth = "Bearer " + rawCfg.Notifications.Ntfy.Auth
		}

		client := &http.Client{Timeout: 5 * time.Second}
		req, _ := http.NewRequest("POST", rawCfg.Notifications.Ntfy.URL, strings.NewReader("System Boot: Connectivity Test"))
		if rawCfg.Notifications.Ntfy.Auth != "" {
			req.Header.Set("Authorization", rawCfg.Notifications.Ntfy.Auth)
		}
		resp, err := client.Do(req)
		if err != nil {
			log.Fatalf("[FATAL] Ntfy URL provided is unreachable: %v", err)
		}
		resp.Body.Close()

		nm.Providers = append(nm.Providers, &NtfyProvider{
			URL:  rawCfg.Notifications.Ntfy.URL,
			Auth: rawCfg.Notifications.Ntfy.Auth,
		})
	}

	if rawCfg.Notifications.Telegram != nil && rawCfg.Notifications.Telegram.Token != "" && rawCfg.Notifications.Telegram.ChatID != "" {
		nm.Providers = append(nm.Providers, &TelegramProvider{
			Token:  rawCfg.Notifications.Telegram.Token,
			ChatID: rawCfg.Notifications.Telegram.ChatID,
		})
		log.Println("[INFO] Telegram notifications configured.")
	}

	// 2. Set Default Resolvers and Verify Health
	if len(rawCfg.Resolvers) == 0 {
		rawCfg.Resolvers = []string{"1.1.1.1", "8.8.8.8", "9.9.9.9"}
	}
	if len(rawCfg.Resolvers) > 9 {
		log.Fatalf("[FATAL] Configured resolvers exceed maximum limit of 9.")
	}
	for _, res := range rawCfg.Resolvers {
		ip := res
		if !strings.Contains(ip, ":") {
			ip += ":53"
		}
		resolver := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				return net.Dial("udp", ip)
			},
		}
		if _, err := resolver.LookupHost(context.Background(), "example.com"); err != nil {
			log.Fatalf("[FATAL] Global resolver health check failed for %s: %v", res, err)
		}
	}

	// 3. Provider Config Logic Validations
	for _, rec := range rawCfg.DNSRecords {
		if rec.Provider == "cloudflare" && rawCfg.Providers.CloudflareToken == "" {
			log.Fatalf("[FATAL] Record %s requests Cloudflare API, but 'cloudflare_token' is missing.", rec.Hostname)
		}
	}

	// 4. Schema Normalization
	for i := range rawCfg.Domains {
		d := &rawCfg.Domains[i]
		d.Domain = strings.ToLower(strings.TrimSpace(d.Domain))
		for j := range d.ExpectedNS {
			d.ExpectedNS[j] = strings.ToLower(strings.TrimSpace(d.ExpectedNS[j]))
		}

		// Enforce Name is mandatory for domains
		if d.Name == "" {
			log.Fatalf("[FATAL] Domain %s is missing a mandatory 'name' field.", d.Domain)
		}

		if d.CheckEmailSecurity {
			if d.MailProvider != "" && len(d.MXRecords) > 0 {
				log.Fatalf("[FATAL] Domain %s has both mail_provider and mx_records set. These are mutually exclusive.", d.Domain)
			}
			d.MailProvider = strings.ToLower(strings.TrimSpace(d.MailProvider))
			for j := range d.MXRecords {
				d.MXRecords[j] = strings.ToLower(strings.TrimSpace(d.MXRecords[j]))
			}
			for j := range d.DKIMSelectors {
				d.DKIMSelectors[j] = strings.ToLower(strings.TrimSpace(d.DKIMSelectors[j]))
			}
		}
	}

	for i := range rawCfg.DNSRecords {
		r := &rawCfg.DNSRecords[i]
		r.Hostname = strings.ToLower(strings.TrimSpace(r.Hostname))

		if r.Name == "" {
			log.Fatalf("[FATAL] DNS Record %s (%s) is missing a mandatory 'name' field.", r.Hostname, r.Type)
		}

		r.Type = strings.ToUpper(strings.TrimSpace(r.Type))
		if r.Type == "" {
			log.Fatalf("[FATAL] DNS Record %s is missing a type (e.g. A, CNAME).", r.Hostname)
		}
		for j := range r.Expected {
			cleanVal := strings.ToLower(strings.TrimPrefix(strings.TrimSuffix(strings.TrimSpace(r.Expected[j]), "."), "alias:"))
			r.Expected[j] = cleanVal
		}

		if r.Type == "TUNNEL" && r.Provider != "cloudflare" {
			log.Fatalf("[FATAL] Record %s uses type TUNNEL, which requires 'provider: \"cloudflare\"' to resolve tunnel names via API.", r.Hostname)
		}
	}

	app := &AppState{
		Config:           &rawCfg,
		Notifier:         nm,
		CF:               InitCloudflare(rawCfg.Providers.CloudflareToken),
		StateLastChanged: make(map[string]string),
	}

	app.LoopDuration, _ = time.ParseDuration(rawCfg.LoopInterval)
	if app.LoopDuration == 0 {
		app.LoopDuration = 6 * time.Hour
	}
	app.ReqDelay, _ = time.ParseDuration(rawCfg.RequestDelay)
	if app.ReqDelay == 0 {
		app.ReqDelay = 5 * time.Second
	}

	return app, nil
}
