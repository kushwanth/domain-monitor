package main

import (
	"bytes"
	"cmp"
	"context"
	jsonv2 "encoding/json/v2"
	"fmt"
	"html"
	"io"
	"net/http"
	"slices"
	"strings"
	"unicode/utf8"
)

// NewNotificationManager configures delivery providers; callers must inject its HTTP client.
func NewNotificationManager(ntfyURL, ntfyAuth, teleToken, teleChatID string) *NotificationManager {
	return &NotificationManager{
		NtfyURL:        ntfyURL,
		NtfyAuth:       ntfyAuth,
		TelegramToken:  teleToken,
		TelegramChatID: teleChatID,
	}
}

func truncateAlertBytes(message string, limit int) string {
	if len(message) <= limit {
		return message
	}
	remaining := limit - len(AlertTruncationNotice)
	var b strings.Builder
	for _, r := range message {
		if b.Len()+utf8.RuneLen(r) > remaining {
			break
		}
		b.WriteRune(r)
	}
	return b.String() + AlertTruncationNotice
}

// Dispatch queues an alert for delivery.
func (nm *NotificationManager) Dispatch(message, redacted string, priority AlertPriority, tag AlertTag, domain, name string) {
	alert := Alert{Message: message, Redacted: redacted, Priority: priority, Tag: tag, Domain: domain, Name: name}
	logQueuedAlert(alert)
	if nm == nil || (nm.NtfyURL == StrEmpty && nm.TelegramToken == StrEmpty) {
		return
	}
	nm.mu.Lock()
	defer nm.mu.Unlock()
	nm.alertBatch = append(nm.alertBatch, alert)
}

func logQueuedAlert(alert Alert) {
	switch alert.Priority {
	case PriorityUrgent, PriorityHigh:
		LogError(alert.Message, FieldDomain, alert.Domain, FieldPriority, alert.Priority, FieldTag, alert.Tag)
	case PriorityWarning:
		LogWarn(alert.Message, FieldDomain, alert.Domain, FieldPriority, alert.Priority, FieldTag, alert.Tag)
	default:
		LogInfo(alert.Message, FieldDomain, alert.Domain, FieldPriority, alert.Priority, FieldTag, alert.Tag)
	}
}

// Flush delivers the queued batch.
func (nm *NotificationManager) Flush() {
	nm.FlushContext(context.Background())
}

// FlushContext delivers the queued batch.
func (nm *NotificationManager) FlushContext(parent context.Context) {
	if nm == nil {
		return
	}
	batch := nm.takeAlertBatch()

	if len(batch) == 0 {
		return
	}

	slices.SortStableFunc(batch, func(a, b Alert) int {
		return cmp.Compare(b.Priority, a.Priority)
	})

	for _, alert := range batch {
		if parent.Err() != nil {
			break
		}
		if nm.NtfyURL != StrEmpty {
			ctx, cancel := context.WithTimeout(parent, DefaultHTTPTimeout)
			nm.sendNtfyBatchContext(ctx, alert)
			cancel()
		}
		if nm.TelegramToken != StrEmpty {
			ctx, cancel := context.WithTimeout(parent, DefaultHTTPTimeout)
			nm.sendTelegramBatchContext(ctx, alert)
			cancel()
		}
	}
}

// takeAlertBatch detaches the queue before network I/O so dispatch can continue.
func (nm *NotificationManager) takeAlertBatch() []Alert {
	nm.mu.Lock()
	defer nm.mu.Unlock()
	batch := nm.alertBatch
	nm.alertBatch = nil
	return batch
}

func (nm *NotificationManager) sendNtfyBatchContext(ctx context.Context, alert Alert) bool {
	defer RecoverAndLogPanic(NameNtfyProvider)
	text := formatNtfyMessage(alert)
	// #nosec G704 -- NtfyURL is an operator-selected notification endpoint.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, nm.NtfyURL, strings.NewReader(strings.TrimSpace(text)))
	if err != nil {
		LogError(MsgLogNtfyRequestFailed, FieldError, err)
		return false
	}
	req.Header.Set(HeaderUserAgent, DefaultUserAgent)
	if nm.NtfyAuth != StrEmpty {
		req.Header.Set(HeaderAuthorization, nm.NtfyAuth)
	}
	req.Header.Set(HeaderNtfyTitle, NotificationAlertTitle)

	req.Header.Set(HeaderNtfyPriority, alert.Priority.String())

	if alert.Tag != StrEmpty {
		req.Header.Set(HeaderNtfyTags, string(alert.Tag))
	}

	if nm.HTTPClient == nil {
		LogError(MsgLogNotificationClientMissing)
		return false
	}
	resp, err := nm.HTTPClient.Do(req)
	if err != nil {
		errStr := err.Error()
		if nm.NtfyAuth != StrEmpty {
			errStr = strings.ReplaceAll(errStr, nm.NtfyAuth, RedactedAuthPlaceholder)
		}
		LogError(MsgLogNtfyRequestError, FieldError, errStr)
		return false
	}
	defer DrainAndClose(resp.Body, MaxBodyDrainSize)

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		LogError(MsgLogNtfyDeliveryFailed, FieldStatus, resp.StatusCode)
		return false
	}
	return true
}

func formatNtfyMessage(alert Alert) string {
	msg := alert.Redacted
	if msg == StrEmpty {
		msg = alert.Message
	}

	if alert.Domain != StrEmpty {
		replacement := RedactedDomainPlaceholder
		if alert.Name != StrEmpty {
			replacement = alert.Name
		}
		msg = strings.ReplaceAll(msg, alert.Domain, replacement)
	}

	prefix := StrEmpty
	if alert.Name != StrEmpty {
		prefix = fmt.Sprintf(NtfyPrefixFormat, TruncateRunes(alert.Name, MaxAlertNameRunes))
	}

	text := prefix + msg
	if utf8.RuneCountInString(text) > MaxAlertMessageRunes {
		text = TruncateRunes(text, MaxAlertMessageRunes-utf8.RuneCountInString(AlertTruncationNotice)) + AlertTruncationNotice
	}
	text = truncateAlertBytes(text, MaxProviderMessageBytes)
	return text
}

func (nm *NotificationManager) sendTelegramBatchContext(ctx context.Context, alert Alert) bool {
	defer RecoverAndLogPanic(NameTelegramProvider)
	text := formatTelegramMessage(alert)
	if len(text) > MaxProviderMessageBytes {
		LogWarn(MsgLogTelegramPayloadTooLarge, FieldBytes, len(text))
		return false
	}

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

	// #nosec G704 -- TelegramAPIBase is fixed; the configured token only selects its path.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, bytes.NewBuffer(payloadBytes))
	if err != nil {
		LogError(MsgLogTelegramRequestFailed, FieldError, strings.ReplaceAll(err.Error(), nm.TelegramToken, RedactedTokenPlaceholder))
		return false
	}
	req.Header.Set(HeaderUserAgent, DefaultUserAgent)
	req.Header.Set(HeaderContentType, MIMEApplicationJSON)

	if nm.HTTPClient == nil {
		LogError(MsgLogNotificationClientMissing)
		return false
	}
	resp, err := nm.HTTPClient.Do(req)
	if err != nil {
		errStr := err.Error()
		if nm.TelegramToken != StrEmpty {
			errStr = strings.ReplaceAll(errStr, nm.TelegramToken, RedactedTokenPlaceholder)
		}
		LogError(MsgLogTelegramRequestError, FieldError, errStr)
		return false
	}
	defer DrainAndClose(resp.Body, MaxBodyDrainSize)

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		LogError(MsgLogTelegramDeliveryFailed, FieldStatus, resp.StatusCode)
		return false
	}
	var result struct {
		OK bool `json:"ok"`
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxNotificationPayloadSize+1))
	if err != nil || len(body) > MaxNotificationPayloadSize {
		LogError(MsgLogTelegramRejected, FieldStatus, resp.StatusCode)
		return false
	}
	if err := jsonv2.Unmarshal(body, &result); err != nil || !result.OK {
		LogError(MsgLogTelegramRejected, FieldStatus, resp.StatusCode)
		return false
	}
	return true
}

func formatTelegramMessage(alert Alert) string {
	var sb strings.Builder
	sb.WriteString(TelegramAlertHeader)

	msg := alert.Redacted
	if msg == StrEmpty {
		msg = alert.Message
	}

	if alert.Domain != StrEmpty {
		replacement := RedactedDomainPlaceholder
		if alert.Name != StrEmpty {
			replacement = alert.Name
		}
		msg = strings.ReplaceAll(msg, alert.Domain, replacement)
	}

	if utf8.RuneCountInString(msg) > MaxTelegramAlertRunes {
		msg = TruncateRunes(msg, MaxTelegramAlertRunes-utf8.RuneCountInString(AlertTruncationNotice)) + AlertTruncationNotice
	}

	prefix := StrEmpty
	if alert.Name != StrEmpty {
		prefix = fmt.Sprintf(TelegramPrefixFormat, html.EscapeString(TruncateRunes(alert.Name, MaxAlertNameRunes)))
	}

	line := fmt.Sprintf(TelegramLineFormat, prefix, html.EscapeString(msg))
	sb.WriteString(line)

	return sb.String()
}
