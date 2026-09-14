package main

import (
	"bytes"
	"context"
	jsonv2 "encoding/json/v2"
	"fmt"
	"html"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

var notifyHTTPClient = ResolveHTTPClient(&http.Client{Timeout: DefaultHTTPTimeout})

func (nm *NotificationManager) StartCycle() {
	if nm == nil {
		return
	}
	nm.mu.Lock()
	defer nm.mu.Unlock()
	nm.seenThisCycle = make(map[string]bool)
}

func (nm *NotificationManager) EndCycle() {
	if nm == nil {
		return
	}
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
	switch priority {
	case PriorityUrgent, PriorityHigh:
		LogError(message, "domain", domain, "priority", priority, "tag", tag)
	case PriorityWarning:
		LogWarn(message, "domain", domain, "priority", priority, "tag", tag)
	default:
		LogInfo(message, "domain", domain, "priority", priority, "tag", tag)
	}

	if nm == nil {
		return
	}
	nm.mu.Lock()
	defer nm.mu.Unlock()

	InitMap(&nm.sentState)

	key := domain + "|" + tag + "|" + redacted
	if nm.seenThisCycle != nil {
		nm.seenThisCycle[key] = true
	}

	if _, exists := nm.sentState[key]; exists {
		// Alert deduplication: suppress exact same alert as long as it remains active
		return
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
	if nm == nil {
		return
	}
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
		if provider == nil {
			continue
		}
		nm.wg.Add(1)
		provider.Send(ctx, alerts, &nm.wg)
	}
}

func (nm *NotificationManager) Wait() {
	if nm == nil {
		return
	}
	nm.wg.Wait()
}

// --- Ntfy Implementation ---

func (p *NtfyProvider) Send(ctx context.Context, alerts []Alert, wg *sync.WaitGroup) {
	if p == nil {
		if wg != nil {
			wg.Done()
		}
		return
	}
	go func() {
		if wg != nil {
			defer wg.Done()
		}
		defer RecoverAndLogPanic(NameNtfyProvider)

		sendChunk := func(text string, highestPriority AlertPriority, tags []string) {
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.URL, strings.NewReader(strings.TrimSpace(text)))
			if err != nil {
				LogError(MsgLogNtfyRequestFailed, "error", err)
				return
			}
			req.Header.Set(HeaderUserAgent, DefaultUserAgent)
			if p.Auth != "" {
				req.Header.Set(HeaderAuthorization, p.Auth)
			}
			req.Header.Set(HeaderNtfyTitle, NotificationAlertTitle)
			req.Header.Set(HeaderNtfyPriority, string(highestPriority))

			// Deduplicate tags and limit to 5
			finalTags := DeduplicateNonEmptyStrings(tags)
			if len(finalTags) > 5 {
				finalTags = finalTags[:5]
			}

			if len(finalTags) > 0 {
				req.Header.Set(HeaderNtfyTags, strings.Join(finalTags, TagSeparator))
			}

			if resp, err := notifyHTTPClient.Do(req); err == nil {
				if resp.StatusCode >= http.StatusBadRequest {
					bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, MaxNotificationPayloadSize))
					bodyStr := string(bodyBytes)
					if p.Auth != "" {
						bodyStr = strings.ReplaceAll(bodyStr, p.Auth, RedactedAuthPlaceholder)
					}
					LogError(MsgLogNtfyDeliveryFailed, "status", resp.StatusCode, "response", bodyStr)
				}
				DrainAndClose(resp.Body, MaxBodyDrainSize)
			} else {
				errStr := err.Error()
				if p.Auth != "" {
					errStr = strings.ReplaceAll(errStr, p.Auth, RedactedAuthPlaceholder)
				}
				LogError(MsgLogNtfyRequestError, "error", errStr)
			}
		}

		var chunks []ChunkData
		var currentChunk strings.Builder
		highestPriority := PriorityDefault
		var currentTags []string

		for _, alert := range alerts {
			msg := alert.Redacted
			if msg == "" {
				msg = alert.Message
			}

			if alert.Domain != "" {
				replacement := RedactedDomainPlaceholder
				if alert.Name != "" {
					replacement = alert.Name
				}
				msg = strings.ReplaceAll(msg, alert.Domain, replacement)
			}

			prefix := ""
			if alert.Name != "" {
				prefix = fmt.Sprintf(NtfyPrefixFormat, alert.Name)
			}

			line := prefix + TruncateRunes(msg, 1000) + AlertChunkSeparator

			if currentChunk.Len()+len(line) > MaxNotificationMessageLen {
				chunks = append(chunks, ChunkData{
					text:     currentChunk.String(),
					priority: highestPriority,
					tags:     currentTags,
				})
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
			chunks = append(chunks, ChunkData{
				text:     currentChunk.String(),
				priority: highestPriority,
				tags:     currentTags,
			})
		}

		for i, chunk := range chunks {
			sendChunk(chunk.text, chunk.priority, chunk.tags)
			if i < len(chunks)-1 {
				timer := time.NewTimer(1 * time.Second)
				select {
				case <-ctx.Done():
					timer.Stop()
					return
				case <-timer.C:
				}
			}
		}
	}()
}

// --- Telegram Implementation ---

func (p *TelegramProvider) Send(ctx context.Context, alerts []Alert, wg *sync.WaitGroup) {
	if p == nil {
		if wg != nil {
			wg.Done()
		}
		return
	}
	go func() {
		if wg != nil {
			defer wg.Done()
		}
		defer RecoverAndLogPanic(NameTelegramProvider)

		sendChunk := func(text string) {
			apiURL := TelegramAPIBase + p.Token + TelegramAPISendMessageSuffix
			payloadBytes, err := jsonv2.Marshal(map[string]any{
				FieldChatID:    p.ChatID,
				FieldText:      text,
				FieldParseMode: TelegramParseModeHTML,
			})
			if err != nil {
				LogError(MsgLogTelegramMarshalFailed, "error", err)
				return
			}

			req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, bytes.NewBuffer(payloadBytes))
			if err != nil {
				LogError(MsgLogTelegramRequestFailed, "error", err)
				return
			}
			req.Header.Set(HeaderUserAgent, DefaultUserAgent)
			req.Header.Set(HeaderContentType, MIMEApplicationJSON)

			if resp, err := notifyHTTPClient.Do(req); err == nil {
				if resp.StatusCode >= http.StatusBadRequest {
					bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, MaxNotificationPayloadSize))
					bodyStr := string(bodyBytes)
					if p.Token != "" {
						bodyStr = strings.ReplaceAll(bodyStr, p.Token, RedactedTokenPlaceholder)
					}
					LogError(MsgLogTelegramDeliveryFailed, "status", resp.StatusCode, "response", bodyStr)
				}
				DrainAndClose(resp.Body, MaxBodyDrainSize)
			} else {
				errStr := err.Error()
				if p.Token != "" {
					errStr = strings.ReplaceAll(errStr, p.Token, RedactedTokenPlaceholder)
				}
				LogError(MsgLogTelegramRequestError, "error", errStr)
			}
		}

		var chunks []string
		var currentChunk strings.Builder
		currentChunk.WriteString(TelegramAlertHeader)

		for _, alert := range alerts {
			msg := alert.Redacted
			if msg == "" {
				msg = alert.Message
			}

			if alert.Domain != "" {
				replacement := RedactedDomainPlaceholder
				if alert.Name != "" {
					replacement = alert.Name
				}
				msg = strings.ReplaceAll(msg, alert.Domain, replacement)
			}

			// Clamp raw alert message so escaped content never exceeds Telegram message limit
			msg = TruncateRunes(msg, 1000)

			prefix := ""
			if alert.Name != "" {
				prefix = fmt.Sprintf(TelegramPrefixFormat, html.EscapeString(alert.Name))
			}

			line := fmt.Sprintf(TelegramLineFormat, prefix, html.EscapeString(msg))

			if currentChunk.Len()+len(line) > MaxNotificationMessageLen {
				chunks = append(chunks, currentChunk.String())
				currentChunk.Reset()
				currentChunk.WriteString(TelegramAlertHeaderCont)
			}
			currentChunk.WriteString(line)
		}

		if currentChunk.Len() > 0 && currentChunk.String() != TelegramAlertHeader && currentChunk.String() != TelegramAlertHeaderCont {
			chunks = append(chunks, currentChunk.String())
		}

		for i, chunk := range chunks {
			sendChunk(chunk)
			if i < len(chunks)-1 {
				timer := time.NewTimer(1 * time.Second)
				select {
				case <-ctx.Done():
					timer.Stop()
					return
				case <-timer.C:
				}
			}
		}
	}()
}
