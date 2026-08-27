package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
)

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

// NotificationProvider interface allows easy expansion to Slack, Telegram, Discord, etc.
type NotificationProvider interface {
	Send(ctx context.Context, alerts []Alert, wg *sync.WaitGroup)
}

// NotificationManager handles broadcasting to all configured providers
type NotificationManager struct {
	Providers     []NotificationProvider
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
	slog.Info(message)
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

func (nm *NotificationManager) Flush(ctx context.Context) {
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
		provider.Send(ctx, alerts, &nm.wg)
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

func (p *NtfyProvider) Send(ctx context.Context, alerts []Alert, wg *sync.WaitGroup) {
	go func() {
		defer wg.Done()
		defer func() {
			if r := recover(); r != nil {
				slog.Error("Ntfy provider panicked", "error", r)
			}
		}()

		const maxLen = 3500 // Safe limit for Ntfy

		sendChunk := func(text string, highestPriority AlertPriority, tags []string) {
			req, err := http.NewRequestWithContext(ctx, "POST", p.URL, strings.NewReader(strings.TrimSpace(text)))
			if err != nil {
				return
			}
			if p.Auth != "" {
				req.Header.Set("Authorization", p.Auth)
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
					slog.Error("Ntfy delivery failed", "status", resp.StatusCode, "response", string(bodyBytes))
				} else {
					_, _ = io.Copy(io.Discard, resp.Body)
				}
				_ = resp.Body.Close()
			} else {
				slog.Error("Ntfy request error", "error", err)
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

func (p *TelegramProvider) Send(ctx context.Context, alerts []Alert, wg *sync.WaitGroup) {
	go func() {
		defer wg.Done()
		defer func() {
			if r := recover(); r != nil {
				slog.Error("Telegram provider panicked", "error", r)
			}
		}()

		const maxLen = 3500 // Leave room for prefix, suffix, JSON overhead

		sendChunk := func(text string) {
			apiURL := fmt.Sprintf(TelegramAPIEndpoint, p.Token)
			payloadBytes, _ := json.Marshal(map[string]interface{}{
				"chat_id":    p.ChatID,
				"text":       text,
				"parse_mode": "HTML",
			})

			req, err := http.NewRequestWithContext(ctx, "POST", apiURL, bytes.NewBuffer(payloadBytes))
			if err != nil {
				return
			}
			req.Header.Set("Content-Type", "application/json")

			client := &http.Client{Timeout: 10 * time.Second}
			if resp, err := client.Do(req); err == nil {
				if resp.StatusCode >= 400 {
					bodyBytes, _ := io.ReadAll(resp.Body)
					slog.Error("Telegram delivery failed", "status", resp.StatusCode, "response", string(bodyBytes))
				} else {
					_, _ = io.Copy(io.Discard, resp.Body)
				}
				_ = resp.Body.Close()
			} else {
				slog.Error("Telegram request error", "error", err)
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
