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
	"time"
)

var notifyHTTPClient = ResolveHTTPClient(&http.Client{Timeout: DefaultHTTPTimeout})

func (nm *NotificationManager) Dispatch(message, redacted string, priority AlertPriority, tag AlertTag, domain, name string) {
	switch priority {
	case PriorityUrgent, PriorityHigh:
		LogError(message, FieldDomain, domain, FieldPriority, priority, FieldTag, tag)
	case PriorityWarning:
		LogWarn(message, FieldDomain, domain, FieldPriority, priority, FieldTag, tag)
	default:
		LogInfo(message, FieldDomain, domain, FieldPriority, priority, FieldTag, tag)
	}

	if nm == nil || (len(nm.Providers) == 0 && !nm.TestMode) {
		return
	}

	nm.mu.Lock()
	InitMap(&nm.sentState)

	// Clean up stale entries older than DefaultAlertCooldown to prevent unbounded memory growth
	now := time.Now()
	for k, sentTime := range nm.sentState {
		if now.Sub(sentTime) >= DefaultAlertCooldown {
			delete(nm.sentState, k)
		}
	}

	key := domain + "|" + string(tag) + "|" + redacted
	if lastSent, exists := nm.sentState[key]; exists && now.Sub(lastSent) < DefaultAlertCooldown {
		// Alert deduplication: suppress exact same alert within cooldown window
		nm.mu.Unlock()
		return
	}
	nm.sentState[key] = now

	alert := Alert{
		Message:  message,
		Redacted: redacted,
		Priority: priority,
		Tag:      tag,
		Domain:   domain,
		Name:     name,
	}

	if nm.TestMode {
		nm.TestBuffer = append(nm.TestBuffer, alert)
	}
	nm.mu.Unlock()

	// Dispatch asynchronously with bounded timeout context
	for _, provider := range nm.Providers {
		if provider != nil {
			go func(p NotificationProvider) {
				ctx, cancel := context.WithTimeout(context.Background(), DefaultHTTPTimeout)
				defer cancel()
				p.Send(ctx, alert)
			}(provider)
		}
	}
}



// --- Ntfy Implementation ---

func (p *NtfyProvider) Send(ctx context.Context, alert Alert) {
	if p == nil {
		return
	}

	defer RecoverAndLogPanic(NameNtfyProvider)

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

	text := prefix + TruncateRunes(msg, MaxAlertMessageRunes)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.URL, strings.NewReader(strings.TrimSpace(text)))
	if err != nil {
		LogError(MsgLogNtfyRequestFailed, FieldError, err)
		return
	}
	req.Header.Set(HeaderUserAgent, DefaultUserAgent)
	if p.Auth != "" {
		req.Header.Set(HeaderAuthorization, p.Auth)
	}
	req.Header.Set(HeaderNtfyTitle, NotificationAlertTitle)
	req.Header.Set(HeaderNtfyPriority, string(alert.Priority))

	if alert.Tag != "" {
		req.Header.Set(HeaderNtfyTags, string(alert.Tag))
	}

	if resp, err := notifyHTTPClient.Do(req); err == nil {
		if resp.StatusCode >= http.StatusBadRequest {
			bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, MaxNotificationPayloadSize))
			bodyStr := string(bodyBytes)
			if p.Auth != "" {
				bodyStr = strings.ReplaceAll(bodyStr, p.Auth, RedactedAuthPlaceholder)
			}
			LogError(MsgLogNtfyDeliveryFailed, FieldStatus, resp.StatusCode, FieldResponse, bodyStr)
		}
		DrainAndClose(resp.Body, MaxBodyDrainSize)
	} else {
		errStr := err.Error()
		if p.Auth != "" {
			errStr = strings.ReplaceAll(errStr, p.Auth, RedactedAuthPlaceholder)
		}
		LogError(MsgLogNtfyRequestError, FieldError, errStr)
	}
}

// --- Telegram Implementation ---

func (p *TelegramProvider) Send(ctx context.Context, alert Alert) {
	if p == nil {
		return
	}

	defer RecoverAndLogPanic(NameTelegramProvider)

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

	msg = TruncateRunes(msg, MaxAlertMessageRunes)

	prefix := ""
	if alert.Name != "" {
		prefix = fmt.Sprintf(TelegramPrefixFormat, html.EscapeString(alert.Name))
	}

	line := fmt.Sprintf(TelegramLineFormat, prefix, html.EscapeString(msg))
	text := TelegramAlertHeader + line

	apiURL := TelegramAPIBase + p.Token + TelegramAPISendMessageSuffix
	payloadBytes, err := jsonv2.Marshal(map[string]any{
		FieldChatID:    p.ChatID,
		FieldText:      text,
		FieldParseMode: TelegramParseModeHTML,
	})
	if err != nil {
		LogError(MsgLogTelegramMarshalFailed, FieldError, err)
		return
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, bytes.NewBuffer(payloadBytes))
	if err != nil {
		LogError(MsgLogTelegramRequestFailed, FieldError, err)
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
			LogError(MsgLogTelegramDeliveryFailed, FieldStatus, resp.StatusCode, FieldResponse, bodyStr)
		}
		DrainAndClose(resp.Body, MaxBodyDrainSize)
	} else {
		errStr := err.Error()
		if p.Token != "" {
			errStr = strings.ReplaceAll(errStr, p.Token, RedactedTokenPlaceholder)
		}
		LogError(MsgLogTelegramRequestError, FieldError, errStr)
	}
}
