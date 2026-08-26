package main

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

const TelegramAPIEndpoint = "https://api.telegram.org/bot%s/sendMessage"

type AlertPriority string

const (
	PriorityUrgent  AlertPriority = "urgent"
	PriorityHigh    AlertPriority = "high"
	PriorityWarning AlertPriority = "warning"
	PriorityDefault AlertPriority = "default"
)

// Alert represents a single notification event
type Alert struct {
	Message  string
	Redacted string
	Priority AlertPriority
	Tag      string
	Domain   string
	Name     string
}

// Notifier interface allows easy expansion to Slack, Telegram, Discord, etc.
type Notifier interface {
	Send(alerts []Alert, wg *sync.WaitGroup)
}

// NotificationManager handles broadcasting to all configured providers
type NotificationManager struct {
	Providers     []Notifier
	Buffer        []Alert
	mu            sync.Mutex
	wg            sync.WaitGroup
	sentState     map[string]time.Time
	seenThisCycle map[string]bool
}

func (nm *NotificationManager) StartCycle() {
	nm.mu.Lock()
	defer nm.mu.Unlock()
	nm.seenThisCycle = make(map[string]bool)
}

func (nm *NotificationManager) EndCycle() {
	nm.mu.Lock()
	defer nm.mu.Unlock()
	if nm.sentState != nil {
		for key := range nm.sentState {
			if !nm.seenThisCycle[key] {
				delete(nm.sentState, key)
			}
		}
	}
}

func (nm *NotificationManager) Dispatch(message, redacted string, priority AlertPriority, tag, domain, name string) {
	log.Println(message)
	nm.mu.Lock()
	defer nm.mu.Unlock()

	if nm.sentState == nil {
		nm.sentState = make(map[string]time.Time)
	}

	key := fmt.Sprintf("%s|%s", domain, redacted)
	if nm.seenThisCycle != nil {
		nm.seenThisCycle[key] = true
	}

	if lastSent, exists := nm.sentState[key]; exists {
		// Alert deduplication: suppress exact same alert for 24 hours
		if time.Since(lastSent) < 24*time.Hour {
			return
		}
	}
	nm.sentState[key] = time.Now()

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
	if len(nm.Buffer) == 0 {
		nm.mu.Unlock()
		return
	}

	alerts := make([]Alert, len(nm.Buffer))
	copy(alerts, nm.Buffer)
	nm.Buffer = nm.Buffer[:0]
	nm.mu.Unlock()

	for _, provider := range nm.Providers {
		nm.wg.Add(1)
		provider.Send(alerts, &nm.wg)
	}
}

func (nm *NotificationManager) Wait() {
	nm.wg.Wait()
}

// --- Ntfy Implementation ---

type NtfyProvider struct {
	URL  string
	Auth string
}

func (n *NtfyProvider) Send(alerts []Alert, wg *sync.WaitGroup) {
	go func() {
		defer wg.Done()
		defer func() {
			if r := recover(); r != nil {
				log.Printf("[ERROR] Ntfy provider panicked: %v", r)
			}
		}()

		const maxLen = 3500 // Safe limit for Ntfy

		sendChunk := func(text string, highestPriority AlertPriority, tags []string) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			req, err := http.NewRequestWithContext(ctx, "POST", n.URL, strings.NewReader(strings.TrimSpace(text)))
			if err != nil {
				return
			}
			if n.Auth != "" {
				req.Header.Set("Authorization", n.Auth)
			}
			req.Header.Set("Title", "Domain Monitor Alerts")
			req.Header.Set("Priority", string(highestPriority))

			// Deduplicate tags and limit to 5
			uniqueTags := make(map[string]bool)
			var finalTags []string
			for _, t := range tags {
				if !uniqueTags[t] {
					uniqueTags[t] = true
					if len(finalTags) < 5 {
						finalTags = append(finalTags, t)
					}
				}
			}

			if len(finalTags) > 0 {
				req.Header.Set("Tags", strings.Join(finalTags, ","))
			} else {
				req.Header.Set("Tags", "rotating_light")
			}

			client := &http.Client{Timeout: 10 * time.Second}
			if resp, err := client.Do(req); err == nil {
				if resp.StatusCode >= 400 {
					bodyBytes, _ := io.ReadAll(resp.Body)
					log.Printf("[ERROR] Ntfy delivery failed (status %d): %s", resp.StatusCode, string(bodyBytes))
				} else {
					_, _ = io.Copy(io.Discard, resp.Body)
				}
				_ = resp.Body.Close()
			} else {
				log.Printf("[ERROR] Ntfy request error: %v", err)
			}
			time.Sleep(1 * time.Second)
		}

		var currentChunk strings.Builder
		highestPriority := PriorityDefault
		var currentTags []string

		for _, alert := range alerts {
			line := alert.Message + "\n\n"

			if currentChunk.Len()+len(line) > maxLen {
				sendChunk(currentChunk.String(), highestPriority, currentTags)
				currentChunk.Reset()
				highestPriority = PriorityDefault
				currentTags = nil
			}

			currentChunk.WriteString(line)
			if alert.Priority == PriorityUrgent {
				highestPriority = PriorityUrgent
			} else if alert.Priority == PriorityHigh && highestPriority != PriorityUrgent {
				highestPriority = PriorityHigh
			} else if alert.Priority == PriorityWarning && highestPriority != PriorityUrgent && highestPriority != PriorityHigh {
				highestPriority = PriorityWarning
			}
			if alert.Tag != "" {
				currentTags = append(currentTags, alert.Tag)
			}
		}

		if currentChunk.Len() > 0 {
			sendChunk(currentChunk.String(), highestPriority, currentTags)
		}
	}()
}

// --- Telegram Implementation ---

type TelegramProvider struct {
	Token  string
	ChatID string
}

func (t *TelegramProvider) Send(alerts []Alert, wg *sync.WaitGroup) {
	go func() {
		defer wg.Done()
		defer func() {
			if r := recover(); r != nil {
				log.Printf("[ERROR] Telegram provider panicked: %v", r)
			}
		}()

		const maxLen = 3500 // Leave room for prefix, suffix, JSON overhead

		sendChunk := func(text string) {
			apiURL := fmt.Sprintf(TelegramAPIEndpoint, t.Token)
			payloadBytes, _ := json.Marshal(map[string]interface{}{
				"chat_id":    t.ChatID,
				"text":       text,
				"parse_mode": "HTML",
			})

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			req, err := http.NewRequestWithContext(ctx, "POST", apiURL, strings.NewReader(string(payloadBytes)))
			if err != nil {
				return
			}
			req.Header.Set("Content-Type", "application/json")

			client := &http.Client{Timeout: 10 * time.Second}
			if resp, err := client.Do(req); err == nil {
				if resp.StatusCode >= 400 {
					bodyBytes, _ := io.ReadAll(resp.Body)
					log.Printf("[ERROR] Telegram delivery failed (status %d): %s", resp.StatusCode, string(bodyBytes))
				} else {
					_, _ = io.Copy(io.Discard, resp.Body)
				}
				_ = resp.Body.Close()
			} else {
				log.Printf("[ERROR] Telegram request error: %v", err)
			}
			time.Sleep(1 * time.Second)
		}

		var currentChunk strings.Builder
		currentChunk.WriteString("⚠️ <b>Domain Monitor Alerts</b>\n\n")

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
				prefix = fmt.Sprintf("<b>[%s]</b> ", html.EscapeString(alert.Name))
			}

			line := fmt.Sprintf("• %s%s\n", prefix, html.EscapeString(msg))

			if currentChunk.Len()+len(line) > maxLen {
				sendChunk(currentChunk.String())
				currentChunk.Reset()
				currentChunk.WriteString("⚠️ <b>Domain Monitor Alerts (Cont.)</b>\n\n")
			}
			currentChunk.WriteString(line)
		}

		if currentChunk.Len() > 0 && currentChunk.String() != "⚠️ <b>Domain Monitor Alerts</b>\n\n" && currentChunk.String() != "⚠️ <b>Domain Monitor Alerts (Cont.)</b>\n\n" {
			sendChunk(currentChunk.String())
		}
	}()
}

const (
	// DNS Alerts
	MsgAlertDNSFailed   = "[CRITICAL] DNS Resolution Failed: %s (%s)"
	MsgAlertDNSMismatch = "[CRITICAL] Mismatch on %s (%s)! Missing expected: %s. Found: [%s]"
	MsgAlertDNSUnauth   = "[CRITICAL] Unauthorized record found on %s (%s): %s! Expected: [%s]"

	// DNS Info
	MsgLogDNSCustomFail = "[WARN] Custom resolver %s failed for %s. Falling back to global pool."

	// DNSSEC Alerts
	MsgAlertDNSSECNoDS        = "[HIGH] DNSSEC: No DS record at parent for %s"
	MsgAlertDNSSECNoDNSKEY    = "[HIGH] DNSSEC: No DNSKEY records found for %s"
	MsgAlertDNSSECMismatch    = "[CRITICAL] DNSSEC: DS does not match any DNSKEY for %s"
	MsgAlertDNSSECRRSIGFail   = "[CRITICAL] DNSSEC: RRSIG verification failed for %s"
	MsgAlertDNSSECChainBroken = "[CRITICAL] DNSSEC: Full chain of trust validation failed (AD flag missing) for %s"

	// CAA Alerts
	MsgAlertCAAMissing    = "[HIGH] CAA: No %s records found for %s"
	MsgAlertCAAUnauth     = "[CRITICAL] CAA: Unauthorized CA '%s' in %s record for %s"
	MsgAlertCAAExpectedNA = "[HIGH] CAA: Expected CA '%s' missing from %s record for %s"

	// CT Logs Alerts
	MsgAlertNewSSLCert = "[INFO] New SSL Certificate issued for %s by %s. Match: %s"

	// Email Security Alerts
	MsgAlertEmailNoMX      = "[CRITICAL] Email Security: No MX records found for %s"
	MsgAlertEmailMXMissing = "[CRITICAL] Email Security: Missing expected MX %s on %s. Found: [%s]"
	MsgAlertEmailMXUnauth  = "[CRITICAL] Email Security: Unauthorized MX %s on %s! Expected: [%s]"
	MsgAlertEmailMXHijack  = "[CRITICAL] MX HIJACK DETECTED for %s! Expected provider %s infrastructure, found: [%s]"
	MsgAlertEmailNoSPF     = "[HIGH] Missing SPF record for %s"
	MsgAlertEmailMultiSPF  = "[CRITICAL] Multiple SPF records found for %s! This breaks email delivery."
	MsgAlertEmailNoDMARC   = "[HIGH] Missing DMARC record for %s (_dmarc.%s)"
	MsgAlertEmailNoDKIM    = "[HIGH] No valid DKIM records found for %s (checked: %s)"

	// Email Security Info
	MsgLogEmailUnknownProv = "[WARN] Unknown mail_provider '%s' for %s. Skipping MX hijack prevention."

	// RDAP Alerts
	MsgAlertRDAPExpiry    = "%s expires in %.0f days"
	MsgAlertRDAPModified  = "registry record modified for %s! timestamp: %s"
	MsgAlertRDAPUnauthNS  = "unauthorized ns on %s: %s"
	MsgAlertRDAPMissingNS = "expected ns missing from %s: %s"
	MsgAlertRDAPSuspended = "domain %s suspended! status: %s"
	MsgAlertRDAPUnlocked  = "%s is unlocked (missing transfer prohibitions)"

	// RDAP Info
	MsgLogRDAPFail = "[ERROR] RDAP query failed for %s: %v"

	// WHOIS Info
	MsgLogWHOISFallback = "[INFO] RDAP failed for %s, attempting WHOIS fallback..."
	MsgLogWHOISFail     = "[ERROR] WHOIS fallback also failed for %s: %v"
	MsgLogWHOISSuccess  = "[INFO] WHOIS fallback succeeded for %s"

	// System Info
	MsgLogStartup          = "[INFO] Daemon initialized successfully. Domains: %d, DNS Records: %d"
	MsgLogHTTPAPI          = "[INFO] HTTP API running on :%s (Endpoints: /, /health)"
	MsgLogTelegramConfig   = "[INFO] Telegram notifications configured."
	MsgLogShutdownSignal   = "[INFO] Received signal: %v. Initiating graceful shutdown..."
	MsgLogShutdownComplete = "[INFO] Daemon shutdown complete."
)
