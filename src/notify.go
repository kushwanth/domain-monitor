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

func (nm *NotificationManager) workerLoop() {
	if nm.alertChan == nil {
		return
	}
	for alert := range nm.alertChan {
		if nm.NtfyURL != "" {
			nm.sendNtfyWithRetry(alert)
		}
		if nm.TelegramToken != "" {
			nm.sendTelegramWithRetry(alert)
		}
	}
}

func (nm *NotificationManager) Dispatch(message, redacted string, priority AlertPriority, tag AlertTag, domain, name string) {
	switch priority {
	case PriorityUrgent, PriorityHigh:
		LogError(message, FieldDomain, domain, FieldPriority, priority, FieldTag, tag)
	case PriorityWarning:
		LogWarn(message, FieldDomain, domain, FieldPriority, priority, FieldTag, tag)
	default:
		LogInfo(message, FieldDomain, domain, FieldPriority, priority, FieldTag, tag)
	}

	if nm == nil || (!nm.TestMode && nm.NtfyURL == "" && nm.TelegramToken == "") {
		return
	}

	nm.mu.Lock()
	InitMap(&nm.sentState)

	now := time.Now()
	for k, sentTime := range nm.sentState {
		if now.Sub(sentTime) >= DefaultAlertCooldown {
			delete(nm.sentState, k)
		}
	}

	key := domain + "|" + string(tag) + "|" + redacted
	if lastSent, exists := nm.sentState[key]; exists && now.Sub(lastSent) < DefaultAlertCooldown {
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
		nm.mu.Unlock()
		return
	}
	nm.mu.Unlock()

	if nm.alertChan != nil {
		select {
		case nm.alertChan <- alert:
		default:
			LogError("alert channel full, dropping alert", FieldDomain, domain)
		}
	}
}

func (nm *NotificationManager) sendNtfyWithRetry(alert Alert) {
	maxRetries := 3
	backoff := 1 * time.Second

	for i := 0; i < maxRetries; i++ {
		success := nm.sendNtfy(alert)
		if success {
			return
		}
		if i < maxRetries-1 {
			time.Sleep(backoff)
			backoff *= 2
		}
	}
	LogError("Ntfy notification failed after retries", FieldDomain, alert.Domain)
}

func (nm *NotificationManager) sendNtfy(alert Alert) bool {
	ctx, cancel := context.WithTimeout(context.Background(), DefaultHTTPTimeout)
	defer cancel()

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

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, nm.NtfyURL, strings.NewReader(strings.TrimSpace(text)))
	if err != nil {
		LogError(MsgLogNtfyRequestFailed, FieldError, err)
		return false
	}
	req.Header.Set(HeaderUserAgent, DefaultUserAgent)
	if nm.NtfyAuth != "" {
		req.Header.Set(HeaderAuthorization, nm.NtfyAuth)
	}
	req.Header.Set(HeaderNtfyTitle, NotificationAlertTitle)
	req.Header.Set(HeaderNtfyPriority, string(alert.Priority))

	if alert.Tag != "" {
		req.Header.Set(HeaderNtfyTags, string(alert.Tag))
	}

	resp, err := notifyHTTPClient.Do(req)
	if err != nil {
		errStr := err.Error()
		if nm.NtfyAuth != "" {
			errStr = strings.ReplaceAll(errStr, nm.NtfyAuth, RedactedAuthPlaceholder)
		}
		LogError(MsgLogNtfyRequestError, FieldError, errStr)
		return false
	}
	defer DrainAndClose(resp.Body, MaxBodyDrainSize)

	if resp.StatusCode >= http.StatusBadRequest {
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, MaxNotificationPayloadSize))
		bodyStr := string(bodyBytes)
		if nm.NtfyAuth != "" {
			bodyStr = strings.ReplaceAll(bodyStr, nm.NtfyAuth, RedactedAuthPlaceholder)
		}
		LogError(MsgLogNtfyDeliveryFailed, FieldStatus, resp.StatusCode, FieldResponse, bodyStr)
		return false // Retry on any error
	}
	return true
}

func (nm *NotificationManager) sendTelegramWithRetry(alert Alert) {
	maxRetries := 3
	backoff := 1 * time.Second

	for i := 0; i < maxRetries; i++ {
		success := nm.sendTelegram(alert)
		if success {
			return
		}
		if i < maxRetries-1 {
			time.Sleep(backoff)
			backoff *= 2
		}
	}
	LogError("Telegram notification failed after retries", FieldDomain, alert.Domain)
}

func (nm *NotificationManager) sendTelegram(alert Alert) bool {
	ctx, cancel := context.WithTimeout(context.Background(), DefaultHTTPTimeout)
	defer cancel()

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

	apiURL := TelegramAPIBase + nm.TelegramToken + TelegramAPISendMessageSuffix
	payloadBytes, err := jsonv2.Marshal(map[string]any{
		FieldChatID:    nm.TelegramChatID,
		FieldText:      text,
		FieldParseMode: TelegramParseModeHTML,
	})
	if err != nil {
		LogError(MsgLogTelegramMarshalFailed, FieldError, err)
		return false
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, bytes.NewBuffer(payloadBytes))
	if err != nil {
		LogError(MsgLogTelegramRequestFailed, FieldError, err)
		return false
	}
	req.Header.Set(HeaderUserAgent, DefaultUserAgent)
	req.Header.Set(HeaderContentType, MIMEApplicationJSON)

	resp, err := notifyHTTPClient.Do(req)
	if err != nil {
		errStr := err.Error()
		if nm.TelegramToken != "" {
			errStr = strings.ReplaceAll(errStr, nm.TelegramToken, RedactedTokenPlaceholder)
		}
		LogError(MsgLogTelegramRequestError, FieldError, errStr)
		return false
	}
	defer DrainAndClose(resp.Body, MaxBodyDrainSize)

	if resp.StatusCode >= http.StatusBadRequest {
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, MaxNotificationPayloadSize))
		bodyStr := string(bodyBytes)
		if nm.TelegramToken != "" {
			bodyStr = strings.ReplaceAll(bodyStr, nm.TelegramToken, RedactedTokenPlaceholder)
		}
		LogError(MsgLogTelegramDeliveryFailed, FieldStatus, resp.StatusCode, FieldResponse, bodyStr)
		return false // Retry on any error
	}
	return true
}
