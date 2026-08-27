package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/go-jsonnet"
	"github.com/miekg/dns"
)

type CAAConfig struct {
	Issue     []string `json:"issue"`
	IssueWild []string `json:"issuewild"`
	IssueMail []string `json:"issuemail"`
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
	WhoisDelay    string         `json:"whois_delay"`
	Notifications Notifications  `json:"notifications"`
	Resolvers     []string       `json:"resolvers"`
	DoHURL        string         `json:"doh_url,omitempty"`
	CTLogsAPIKey  string         `json:"ctlogs_api_key,omitempty"`
	Domains       []DomainConfig `json:"domains"`
	DNSRecords    []DNSTask      `json:"dns_records"`
}

type DomainConfig struct {
	Domain             string     `json:"domain"`
	Name               string     `json:"name"`
	IsDelegatedZone    bool       `json:"is_delegated_zone"`
	RootZone           string     `json:"root_zone"`
	ExpectedNS         []string   `json:"expected_ns"`
	CheckEmailSecurity bool       `json:"check_email_security"`
	MailProvider       string     `json:"mail_provider"`
	MXRecords          []string   `json:"mx_records"`
	DKIMSelectors      []string   `json:"dkim_selectors"`
	DNSSEC             bool       `json:"dnssec"`
	MonitorCTLogs      bool       `json:"monitor_ct_logs"`
	CAA                *CAAConfig `json:"caa,omitempty"`
	AcceptSelfSigned   bool       `json:"accept_self_signed"`
	SuppressAlerts     bool       `json:"suppress_alerts"`
}

type DNSTask struct {
	Hostname         string   `json:"hostname"`
	Name             string   `json:"name"`
	Type             string   `json:"type"`
	Expected         []string `json:"expected"`
	CustomResolver   string   `json:"custom_resolver"`
	AcceptSelfSigned bool     `json:"accept_self_signed"`
}

type AppState struct {
	Config              *AppConfig
	Notifier            *NotificationManager
	LoopDuration        time.Duration
	ReqDelay            time.Duration
	WhoisDelay          time.Duration
	StateMu             sync.Mutex
	StateLastChanged    map[string]string
	PrerenderedHTML     atomic.Value
	PrerenderedJSON     atomic.Value
	GlobalResolverIndex atomic.Uint32
}

func LoadConfig(ctx context.Context, path string) (*AppState, error) {
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
	if p := strings.TrimSpace(os.Getenv("PORT")); p != "" {
		rawCfg.Port = p
	}
	if rawCfg.Port == "" {
		rawCfg.Port = "8080"
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
	if k := strings.TrimSpace(os.Getenv("CTLOGS_API_KEY")); k != "" {
		rawCfg.CTLogsAPIKey = k
	}
	if u := strings.TrimSpace(os.Getenv("DOH_URL")); u != "" {
		rawCfg.DoHURL = u
	}

	// Defaults that do not require side-effects
	if len(rawCfg.Resolvers) == 0 {
		rawCfg.Resolvers = []string{"1.1.1.1", "8.8.8.8", "9.9.9.9"}
	}
	if len(rawCfg.Resolvers) > 9 {
		return nil, fmt.Errorf("configured resolvers exceed maximum limit of 9")
	}

	// 3. Schema Normalization
	for i := range rawCfg.Domains {
		d := &rawCfg.Domains[i]
		d.Domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(d.Domain), "."))
		for j := range d.ExpectedNS {
			d.ExpectedNS[j] = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(d.ExpectedNS[j]), "."))
		}

		// Enforce Name is mandatory for domains
		if d.Name == "" {
			return nil, fmt.Errorf("domain %s is missing a mandatory 'name' field", d.Domain)
		}

		if d.IsDelegatedZone {
			d.RootZone = strings.ToLower(strings.TrimSpace(d.RootZone))
			if d.RootZone == "" {
				return nil, fmt.Errorf("delegated domain %s is missing a mandatory 'root_zone' field", d.Domain)
			}
		}

		if d.CAA != nil {
			normalizeCAAList := func(list []string) []string {
				if list == nil {
					return nil
				}
				var res []string
				for _, item := range list {
					val := strings.ToLower(strings.TrimSpace(item))
					if val != "" && val != ";" && val != "none" {
						res = append(res, val)
					}
				}
				if len(res) == 0 {
					return []string{} // non-nil empty slice represents explicit deny-all
				}
				return res
			}

			if d.CAA.Issue != nil {
				d.CAA.Issue = normalizeCAAList(d.CAA.Issue)
			}
			if d.CAA.IssueWild != nil {
				d.CAA.IssueWild = normalizeCAAList(d.CAA.IssueWild)
			}
			if d.CAA.IssueMail != nil {
				d.CAA.IssueMail = normalizeCAAList(d.CAA.IssueMail)
			}
		}

		if d.CheckEmailSecurity {
			if d.MailProvider != "" && len(d.MXRecords) > 0 {
				return nil, fmt.Errorf("domain %s has both mail_provider and mx_records set; these are mutually exclusive", d.Domain)
			}
			d.MailProvider = strings.ToLower(strings.TrimSpace(d.MailProvider))
			for j := range d.MXRecords {
				d.MXRecords[j] = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(d.MXRecords[j]), "."))
			}
			for j := range d.DKIMSelectors {
				d.DKIMSelectors[j] = strings.ToLower(strings.TrimSpace(d.DKIMSelectors[j]))
			}
		}
	}

	for i := range rawCfg.DNSRecords {
		r := &rawCfg.DNSRecords[i]
		r.Hostname = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(r.Hostname), "."))

		if r.Name == "" {
			return nil, fmt.Errorf("dns record %s (%s) is missing a mandatory 'name' field", r.Hostname, r.Type)
		}

		r.Type = strings.ToUpper(strings.TrimSpace(r.Type))
		if r.Type == "" {
			return nil, fmt.Errorf("dns record %s is missing a type (e.g. A, CNAME)", r.Hostname)
		}
		for j := range r.Expected {
			cleanVal := strings.TrimPrefix(strings.TrimSuffix(strings.TrimSpace(r.Expected[j]), "."), "alias:")
			if r.Type != "TXT" {
				cleanVal = strings.ToLower(cleanVal)
			}

			// Normalize IPs for A, AAAA, IP types
			if r.Type == "A" || r.Type == "AAAA" || r.Type == "IP" {
				if ip := net.ParseIP(cleanVal); ip != nil {
					cleanVal = ip.String()
				}
			}

			r.Expected[j] = cleanVal
		}

	}

	if rawCfg.DoHURL == "" {
		rawCfg.DoHURL = DefaultDoHURL
	}

	app := &AppState{
		Config:           &rawCfg,
		Notifier:         &NotificationManager{},
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
	app.WhoisDelay, _ = time.ParseDuration(rawCfg.WhoisDelay)
	if app.WhoisDelay == 0 {
		app.WhoisDelay = 10 * time.Second
	}

	return app, nil
}

// InitializeDependencies handles side-effects like validating notifications and resolver health checks
func InitializeDependencies(ctx context.Context, app *AppState) error {
	rawCfg := app.Config
	nm := app.Notifier

	if rawCfg.Notifications.Ntfy != nil && rawCfg.Notifications.Ntfy.URL != "" {
		if rawCfg.Notifications.Ntfy.Auth != "" && !strings.HasPrefix(strings.ToLower(rawCfg.Notifications.Ntfy.Auth), "bearer ") && !strings.HasPrefix(strings.ToLower(rawCfg.Notifications.Ntfy.Auth), "basic ") {
			rawCfg.Notifications.Ntfy.Auth = "Bearer " + rawCfg.Notifications.Ntfy.Auth
		}

		client := &http.Client{Timeout: 5 * time.Second}
		req, err := http.NewRequestWithContext(ctx, "POST", rawCfg.Notifications.Ntfy.URL, strings.NewReader("System Boot: Connectivity Test"))
		if err != nil {
			return fmt.Errorf("failed to create ntfy request: %w", err)
		}
		if rawCfg.Notifications.Ntfy.Auth != "" {
			req.Header.Set("Authorization", rawCfg.Notifications.Ntfy.Auth)
		}
		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("ntfy URL provided is unreachable: %w", err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()

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
		slog.Info(MsgLogTelegramConfig)
	}

	for _, res := range rawCfg.Resolvers {
		ip := res
		if _, _, err := net.SplitHostPort(ip); err != nil {
			ip = net.JoinHostPort(ip, "53")
		}
		c := new(dns.Client)
		c.Timeout = 5 * time.Second
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn("example.com"), dns.TypeA)
		m.RecursionDesired = true
		if _, _, err := c.ExchangeContext(ctx, m, ip); err != nil {
			return fmt.Errorf("global resolver health check failed for %s: %w", res, err)
		}
	}

	return nil
}
