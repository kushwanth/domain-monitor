package monitor

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	jsonv2 "encoding/json/v2"
	"fmt"
	"html"
	"net/http"
	"slices"
	"strings"
	"unicode/utf8"

	"domain_monitor/src/internal/netpolicy"
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
	if nm.NtfyURL == StrEmpty && nm.TelegramToken == StrEmpty {
		return
	}
	nm.mu.Lock()
	defer nm.mu.Unlock()
	nm.alertBatch = append(nm.alertBatch, alert)
	sortAlerts(nm.alertBatch)
	if len(nm.alertBatch) > MaxCycleReportItems {
		nm.alertBatch = nm.alertBatch[:MaxCycleReportItems]
		nm.omitted++
	}
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
	batch, omitted := nm.takeAlertReportBatch()

	if len(batch) == 0 {
		return
	}

	sortAlerts(batch)

	report := buildCycleReport(batch, omitted)
	if nm.NtfyURL != StrEmpty && parent.Err() == nil {
		ctx, cancel := context.WithTimeout(parent, DefaultHTTPTimeout)
		nm.sendNtfyBatchContext(ctx, report)
		cancel()
	}
	if nm.TelegramToken != StrEmpty && parent.Err() == nil {
		ctx, cancel := context.WithTimeout(parent, DefaultHTTPTimeout)
		nm.sendTelegramBatchContext(ctx, report)
		cancel()
	}
}

func sortAlerts(batch []Alert) {
	slices.SortStableFunc(batch, func(a, b Alert) int {
		if order := cmp.Compare(b.Priority, a.Priority); order != 0 {
			return order
		}
		if order := cmp.Compare(a.Check, b.Check); order != 0 {
			return order
		}
		if order := cmp.Compare(a.Domain, b.Domain); order != 0 {
			return order
		}
		return cmp.Compare(a.Name, b.Name)
	})
}

func buildCycleReport(batch []Alert, omitted int) Alert {
	itemCount := len(batch)
	var message, redacted strings.Builder
	for index := range itemCount {
		if index > 0 {
			message.WriteByte('\n')
			redacted.WriteByte('\n')
		}
		message.WriteString(batch[index].Message)
		redacted.WriteString(formatNtfyMessage(batch[index]))
	}
	if omitted > 0 {
		notice := fmt.Sprintf(MsgCycleFindingsOmitted, omitted)
		message.WriteString(notice)
		redacted.WriteString(notice)
	}
	priority := PriorityDefault
	tag := AlertTag(StrEmpty)
	if len(batch) > 0 {
		priority, tag = batch[0].Priority, batch[0].Tag
	}
	digest := sha256.Sum256([]byte(redacted.String()))
	return Alert{
		Message: message.String(), Redacted: redacted.String(), Priority: priority, Tag: tag,
		ReportID: hex.EncodeToString(digest[:8]),
	}
}

// takeAlertBatch detaches the queue before network I/O so dispatch can continue.
func (nm *NotificationManager) takeAlertBatch() []Alert {
	batch, _ := nm.takeAlertReportBatch()
	return batch
}

func (nm *NotificationManager) takeAlertReportBatch() ([]Alert, int) {
	nm.mu.Lock()
	defer nm.mu.Unlock()
	batch := nm.alertBatch
	omitted := nm.omitted
	nm.alertBatch = nil
	nm.omitted = 0
	return batch, omitted
}

func (nm *NotificationManager) sendNtfyBatchContext(ctx context.Context, alert Alert) bool {
	defer RecoverAndLogPanic(NameNtfyProvider)
	text := formatNtfyMessage(alert)
	if nm.HTTPClient == nil {
		LogError(MsgLogNotificationClientMissing)
		return false
	}
	resp, err := doHTTPWithRetry(ctx, NameNtfyProvider, nm.HTTPClient, RetryHTTPTransient, func() (*http.Request, error) {
		// #nosec G704 -- NtfyURL is an operator-selected notification endpoint.
		req, requestErr := http.NewRequestWithContext(ctx, http.MethodPost, nm.NtfyURL, strings.NewReader(strings.TrimSpace(text)))
		if requestErr != nil {
			return nil, requestErr
		}
		req.Header.Set(HeaderUserAgent, DefaultUserAgent)
		if nm.NtfyAuth != StrEmpty {
			req.Header.Set(HeaderAuthorization, nm.NtfyAuth)
		}
		req.Header.Set(HeaderNtfyTitle, NotificationAlertTitle)
		req.Header.Set(HeaderNtfyPriority, alert.Priority.String())
		req.Header.Set(HeaderReportID, alert.ReportID)
		if alert.Tag != StrEmpty {
			req.Header.Set(HeaderNtfyTags, string(alert.Tag))
		}
		return req, nil
	})
	if err != nil {
		errStr := err.Error()
		errStr = strings.ReplaceAll(errStr, nm.NtfyURL, netpolicy.SanitizeURL(nm.NtfyURL))
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

	if nm.HTTPClient == nil {
		LogError(MsgLogNotificationClientMissing)
		return false
	}
	resp, err := doHTTPWithRetry(ctx, NameTelegramProvider, nm.HTTPClient, RetryHTTPTransient, func() (*http.Request, error) {
		// #nosec G704 -- TelegramAPIBase is fixed; the configured token only selects its path.
		req, requestErr := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, bytes.NewBuffer(payloadBytes))
		if requestErr != nil {
			return nil, requestErr
		}
		req.Header.Set(HeaderUserAgent, DefaultUserAgent)
		req.Header.Set(HeaderContentType, MIMEApplicationJSON)
		return req, nil
	})
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
	var result telegramResponse
	body, err := readBounded(resp.Body, MaxNotificationPayloadSize)
	if err != nil {
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
