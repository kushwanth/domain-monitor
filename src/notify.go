package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Alert represents a single notification event
type Alert struct {
	Message  string
	Redacted string
	Priority string
	Tag      string
	Domain   string
	Name     string
}

// Notifier interface allows easy expansion to Slack, Telegram, Discord, etc.
type Notifier interface {
	Send(alerts []Alert)
}

// NotificationManager handles broadcasting to all configured providers
type NotificationManager struct {
	Providers []Notifier
	Buffer    []Alert
	mu        sync.Mutex
}

func (nm *NotificationManager) Dispatch(message, redacted, priority, tag, domain, name string) {
	log.Println(message)
	nm.mu.Lock()
	defer nm.mu.Unlock()
	nm.Buffer = append(nm.Buffer, Alert{
		Message:  message,
		Redacted: redacted,
		Priority: priority,
		Tag:      tag,
		Domain:   domain,
		Name:     name,
	})
}

func (nm *NotificationManager) Flush() {
	nm.mu.Lock()
	alerts := nm.Buffer
	nm.Buffer = nil
	nm.mu.Unlock()

	if len(alerts) == 0 {
		return
	}

	for _, provider := range nm.Providers {
		provider.Send(alerts)
	}
}

// --- Ntfy Implementation ---

type NtfyProvider struct {
	URL  string
	Auth string
}

func (n *NtfyProvider) Send(alerts []Alert) {
	go func() {
		var sb strings.Builder
		highestPriority := "default"

		for _, alert := range alerts {
			sb.WriteString(alert.Message)
			sb.WriteString("\n\n")
			if alert.Priority == "urgent" {
				highestPriority = "urgent"
			} else if alert.Priority == "high" && highestPriority != "urgent" {
				highestPriority = "high"
			}
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, "POST", n.URL, strings.NewReader(strings.TrimSpace(sb.String())))
		if err != nil {
			return
		}
		if n.Auth != "" {
			req.Header.Set("Authorization", n.Auth)
		}
		req.Header.Set("Title", "Domain Monitor Alerts")
		req.Header.Set("Priority", highestPriority)
		req.Header.Set("Tags", "rotating_light")

		client := &http.Client{}
		if resp, err := client.Do(req); err == nil {
			resp.Body.Close()
		}
	}()
}

// --- Telegram Implementation ---

type TelegramProvider struct {
	Token  string
	ChatID string
}

func (t *TelegramProvider) Send(alerts []Alert) {
	go func() {
		var sb strings.Builder
		sb.WriteString("⚠️ <b>Domain Monitor Alerts</b>\n\n")

		for _, alert := range alerts {
			msg := alert.Redacted
			if msg == "" {
				msg = alert.Message
			}

			if alert.Domain != "" {
				replacement := "[Hidden Domain]"
				if alert.Name != "" {
					replacement = alert.Name
				}
				msg = strings.ReplaceAll(msg, alert.Domain, replacement)
			}

			prefix := ""
			if alert.Name != "" {
				prefix = fmt.Sprintf("<b>[%s]</b> ", alert.Name)
			}

			sb.WriteString(fmt.Sprintf("• %s%s\n", prefix, msg))
		}

		apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", t.Token)

		// Escape JSON payload properly
		payloadBytes, _ := json.Marshal(map[string]interface{}{
			"chat_id":    t.ChatID,
			"text":       sb.String(),
			"parse_mode": "HTML",
		})

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, "POST", apiURL, strings.NewReader(string(payloadBytes)))
		if err != nil {
			return
		}
		req.Header.Set("Content-Type", "application/json")

		client := &http.Client{}
		if resp, err := client.Do(req); err == nil {
			resp.Body.Close()
		}
	}()
}

const (
	// DNS Alerts
	MsgAlertDNSFailed   = "[CRITICAL] DNS Resolution Failed: %s (%s)"
	MsgAlertDNSMismatch = "[CRITICAL] Mismatch on %s (%s)! Missing expected: %s. Found: [%s]"

	// DNS Info
	MsgLogDNSSuccess    = "[INFO] ✓ DNS: %s (%s) -> [%s]"
	MsgLogDNSCFDetect   = "[INFO] Auto-detected %s as Cloudflare Proxied. Pivoting to API SDK."
	MsgLogDNSCFBypass   = "[WARN] %s requires Cloudflare API but token is missing. Skipping backend verification."
	MsgLogDNSCustomFail = "[WARN] Custom resolver %s failed for %s. Falling back to global pool."

	// Email Security Alerts
	MsgAlertEmailNoMX      = "[CRITICAL] Email Security: No MX records found for %s"
	MsgAlertEmailMXMissing = "[CRITICAL] Email Security: Missing expected MX %s on %s. Found: [%s]"
	MsgAlertEmailMXHijack  = "[CRITICAL] MX HIJACK DETECTED for %s! Expected provider %s infrastructure, found: [%s]"
	MsgAlertEmailNoSPF     = "[HIGH] Missing SPF record for %s"
	MsgAlertEmailMultiSPF  = "[CRITICAL] Multiple SPF records found for %s! This breaks email delivery."
	MsgAlertEmailNoDMARC   = "[HIGH] Missing DMARC record for %s (_dmarc.%s)"
	MsgAlertEmailNoDKIM    = "[HIGH] No valid DKIM records found for %s (checked: %s)"

	// Email Security Info
	MsgLogEmailCustomMX     = "[INFO] ✓ Email Security (Custom MX): %s -> [%s]"
	MsgLogEmailUnknownProv  = "[WARN] Unknown mail_provider '%s' for %s. Skipping MX hijack prevention."
	MsgLogEmailSPFFail      = "[WARN] SPF lookup failed for %s: %v"
	MsgLogEmailDMARCFail    = "[WARN] DMARC lookup failed for %s: %v"
	MsgLogEmailDKIMFail     = "[WARN] DKIM lookup failed for %s: %v"
	MsgLogEmailSuccess      = "[INFO] ✓ Email Security: %s | Provider: %s | SPF: %v | DMARC: %v | DKIM: %d valid"
	MsgLogEmailBasicSuccess = "[INFO] ✓ Email Security (Basic MX): %s -> [%s]"

	// RDAP Alerts
	MsgAlertRDAPExpiry    = "%s expires in %.0f days"
	MsgAlertRDAPModified  = "registry record modified for %s! timestamp: %s"
	MsgAlertRDAPUnauthNS  = "unauthorized ns on %s: %s"
	MsgAlertRDAPMissingNS = "expected ns missing from %s: %s"
	MsgAlertRDAPSuspended = "domain %s suspended! status: %s"
	MsgAlertRDAPUnlocked  = "%s is unlocked (missing transfer prohibitions)"

	// RDAP Info
	MsgLogRDAPFail    = "[ERROR] RDAP query failed for %s: %v"
	MsgLogRDAPSuccess = "[INFO] ✓ RDAP: %s | DNSSEC: %s | Statuses: [%s]"

	// Cloudflare Info
	MsgLogCFValid = "[INFO] Cloudflare API Token validated as strictly Read-Only."
	MsgLogCFCIDRs = "[INFO] Fetched %d Cloudflare CIDR blocks"

	// System Info
	MsgLogStartup          = "[INFO] Daemon initialized successfully. Domains: %d, DNS Records: %d"
	MsgLogHTTPAPI          = "[INFO] HTTP API running on :%s (Endpoints: /, /health)"
	MsgLogTelegramConfig   = "[INFO] Telegram notifications configured."
	MsgLogShutdownSignal   = "[INFO] Received signal: %v. Initiating graceful shutdown..."
	MsgLogShutdownComplete = "[INFO] Daemon shutdown complete."
)
