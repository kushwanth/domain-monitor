package main

import (
	"bytes"
	"context"
	jsonv2 "encoding/json/v2"
	"fmt"
	"html"
	"io"
	"maps"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// NotificationManager sends a bounded set of alerts at the end of each cycle.
type NotificationManager struct {
	NtfyURL        string
	NtfyAuth       string
	TelegramToken  string
	TelegramChatID string

	mu         sync.Mutex
	sentState  map[string]time.Time
	alertBatch []Alert
	nextAlert  int
	ctAccepted map[string]CTAcceptance

	// Dependencies for network/IO
	HTTPClient HTTPDoer
}

// NewNotificationManager ...
func NewNotificationManager(ntfyURL, ntfyAuth, teleToken, teleChatID string) *NotificationManager {
	nm := &NotificationManager{
		NtfyURL:        ntfyURL,
		NtfyAuth:       ntfyAuth,
		TelegramToken:  teleToken,
		TelegramChatID: teleChatID,
		sentState:      make(map[string]time.Time),
	}
	return nm
}

func maxPriority(batch []Alert) AlertPriority {
	priority := PriorityDefault
	for _, alert := range batch {
		if alertPriorityRank(alert.Priority) > alertPriorityRank(priority) {
			priority = alert.Priority
		}
	}
	return priority
}

func alertPriorityRank(priority AlertPriority) int {
	switch priority {
	case PriorityUrgent:
		return 3
	case PriorityHigh:
		return 2
	case PriorityWarning:
		return 1
	default:
		return 0
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

// Dispatch ...
func (nm *NotificationManager) Dispatch(message, redacted string, priority AlertPriority, tag AlertTag, domain, name string) {
	nm.DispatchIdentified(domain+SymPipe+string(tag)+SymPipe+redacted, message, redacted, priority, tag, domain, name)
}

// DispatchIdentified queues an alert under a stable condition identity.
func (nm *NotificationManager) DispatchIdentified(identity, message, redacted string, priority AlertPriority, tag AlertTag, domain, name string) {
	nm.enqueueAlert(Alert{Message: message, Redacted: redacted, Identity: identity, Priority: priority, Tag: tag, Domain: domain, Name: name})
}

// DispatchCT queues a committed CT discovery for its outstanding providers.
func (nm *NotificationManager) DispatchCT(alert Alert) {
	alert.CT = true
	nm.enqueueAlert(alert)
}

func (nm *NotificationManager) enqueueAlert(alert Alert) {
	logQueuedAlert(alert)
	if nm == nil || (nm.NtfyURL == StrEmpty && nm.TelegramToken == StrEmpty) {
		return
	}

	nm.mu.Lock()
	InitMap(&nm.sentState)
	now := time.Now()
	nm.pruneExpiredCooldowns(now)

	if !alert.CT {
		ntfyDue := nm.NtfyURL != StrEmpty && now.Sub(nm.sentState[StrNtfy+alert.Identity]) >= DefaultAlertCooldown
		telegramDue := nm.TelegramToken != StrEmpty && now.Sub(nm.sentState[StrTelegram+alert.Identity]) >= DefaultAlertCooldown
		if !ntfyDue && !telegramDue {
			nm.mu.Unlock()
			return
		}
	}
	for _, queued := range nm.alertBatch {
		if queued.Identity == alert.Identity {
			nm.mu.Unlock()
			return
		}
	}
	if len(nm.alertBatch) >= MaxPendingAlerts {
		lowest := 0
		for i := range nm.alertBatch {
			if alertPriorityRank(nm.alertBatch[i].Priority) < alertPriorityRank(nm.alertBatch[lowest].Priority) {
				lowest = i
			}
		}
		incoming := alertPriorityRank(alert.Priority)
		queued := alertPriorityRank(nm.alertBatch[lowest].Priority)
		if incoming > queued || (incoming >= 2 && incoming == queued) {
			// Deferred CT discoveries remain in the durable pending checkpoint.
			nm.alertBatch[lowest] = alert
			nm.nextAlert = lowest
			nm.mu.Unlock()
			return
		}
		nm.mu.Unlock()
		LogWarn(MsgLogNotificationBacklogFull, FieldDomain, alert.Domain)
		return
	}
	nm.alertBatch = append(nm.alertBatch, alert)
	nm.mu.Unlock()
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

func (nm *NotificationManager) pruneExpiredCooldowns(now time.Time) {
	for k, sentTime := range nm.sentState {
		if now.Sub(sentTime) >= DefaultAlertCooldown {
			delete(nm.sentState, k)
		}
	}
}

// Flush delivers a bounded batch using the default delivery deadline.
func (nm *NotificationManager) Flush() {
	nm.FlushContext(context.Background())
}

// FlushContext delivers a bounded batch and stops when the cycle is cancelled.
func (nm *NotificationManager) FlushContext(parent context.Context) {
	if nm == nil {
		return
	}
	nm.mu.Lock()
	batch := nm.alertBatch
	nm.alertBatch = nil
	start := nm.nextAlert
	nm.mu.Unlock()
	if len(batch) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(parent, DefaultHTTPTimeout*2)
	defer cancel()
	processed := 0
	var retry []Alert
	for count := 0; count < len(batch) && count < MaxAlertsPerFlush; count++ {
		if ctx.Err() != nil {
			break
		}
		alert := batch[(start+count)%len(batch)]
		if nm.deliverAlert(ctx, alert) {
			retry = append(retry, alert)
		}
		processed++
	}
	nm.requeueAlerts(batch, retry, start, processed)
	if processed < len(batch) {
		LogWarn(MsgLogNotificationDeliveryDeferred, FieldCount, len(batch)-processed)
	}
}

func (nm *NotificationManager) deliverAlert(ctx context.Context, alert Alert) bool {
	ntfyRetry := nm.deliverNtfy(ctx, alert)
	telegramRetry := nm.deliverTelegram(ctx, alert)
	return ntfyRetry || telegramRetry
}

func (nm *NotificationManager) deliverNtfy(ctx context.Context, alert Alert) bool {
	if alert.CT && nm.ctProviderAccepted(alert.Identity, true) {
		return false
	}
	if nm.NtfyURL != StrEmpty && (!alert.CT || alert.NeedNtfy) && (alert.CT || nm.shouldDeliver(StrNtfy+alert.Identity)) {
		attemptCtx, cancel := context.WithTimeout(ctx, DefaultHTTPTimeout)
		accepted := nm.sendNtfyBatchContext(attemptCtx, []Alert{alert})
		cancel()
		if accepted {
			if alert.CT {
				nm.recordCTAccepted(alert.Identity, true)
			} else {
				nm.markDelivered(StrNtfy + alert.Identity)
			}
		} else if !alert.CT {
			return true
		}
	}
	return false
}

func (nm *NotificationManager) deliverTelegram(ctx context.Context, alert Alert) bool {
	if alert.CT && nm.ctProviderAccepted(alert.Identity, false) {
		return false
	}
	if nm.TelegramToken != StrEmpty && (!alert.CT || alert.NeedTelegram) && (alert.CT || nm.shouldDeliver(StrTelegram+alert.Identity)) {
		attemptCtx, cancel := context.WithTimeout(ctx, DefaultHTTPTimeout)
		accepted := nm.sendTelegramBatchContext(attemptCtx, []Alert{alert})
		cancel()
		if accepted {
			if alert.CT {
				nm.recordCTAccepted(alert.Identity, false)
			} else {
				nm.markDelivered(StrTelegram + alert.Identity)
			}
		} else if !alert.CT {
			return true
		}
	}
	return false
}

func (nm *NotificationManager) requeueAlerts(batch, retry []Alert, start, processed int) {
	nm.mu.Lock()
	for _, alert := range retry {
		if len(nm.alertBatch) < MaxPendingAlerts {
			nm.alertBatch = append(nm.alertBatch, alert)
		}
	}
	for count := processed; count < len(batch); count++ {
		alert := batch[(start+count)%len(batch)]
		if len(nm.alertBatch) < MaxPendingAlerts {
			nm.alertBatch = append(nm.alertBatch, alert)
		}
	}
	nm.nextAlert = (start + processed) % len(batch)
	nm.mu.Unlock()
}

func (nm *NotificationManager) shouldDeliver(key string) bool {
	nm.mu.Lock()
	defer nm.mu.Unlock()
	return time.Since(nm.sentState[key]) >= DefaultAlertCooldown
}

func (nm *NotificationManager) markDelivered(key string) {
	nm.mu.Lock()
	InitMap(&nm.sentState)
	nm.sentState[key] = time.Now()
	nm.mu.Unlock()
}

func (nm *NotificationManager) recordCTAccepted(identity string, ntfy bool) {
	nm.mu.Lock()
	InitMap(&nm.ctAccepted)
	accepted := nm.ctAccepted[identity]
	if ntfy {
		accepted.Ntfy = true
	} else {
		accepted.Telegram = true
	}
	nm.ctAccepted[identity] = accepted
	nm.mu.Unlock()
}

func (nm *NotificationManager) ctProviderAccepted(identity string, ntfy bool) bool {
	nm.mu.Lock()
	defer nm.mu.Unlock()
	accepted := nm.ctAccepted[identity]
	if ntfy {
		return accepted.Ntfy
	}
	return accepted.Telegram
}

// TakeCTAcceptances snapshots provider acceptances until they are durably committed.
func (nm *NotificationManager) TakeCTAcceptances() map[string]CTAcceptance {
	nm.mu.Lock()
	defer nm.mu.Unlock()
	return maps.Clone(nm.ctAccepted)
}

// ForgetCTAcceptances releases only the acceptances included in a successful commit.
func (nm *NotificationManager) ForgetCTAcceptances(committed map[string]CTAcceptance) {
	nm.mu.Lock()
	defer nm.mu.Unlock()
	for identity, accepted := range committed {
		current := nm.ctAccepted[identity]
		current.Ntfy = current.Ntfy && !accepted.Ntfy
		current.Telegram = current.Telegram && !accepted.Telegram
		if current.Ntfy || current.Telegram {
			nm.ctAccepted[identity] = current
		} else {
			delete(nm.ctAccepted, identity)
		}
	}
}

// RetainIdentities clears cooldowns for conditions that recovered.
func (nm *NotificationManager) RetainIdentities(active map[string]bool) {
	nm.mu.Lock()
	defer nm.mu.Unlock()
	for key := range nm.sentState {
		_, identity, found := strings.Cut(key, SymPipe)
		if found && !active[identity] && !strings.HasPrefix(identity, StrCT) {
			delete(nm.sentState, key)
		}
	}
	retained := nm.alertBatch[:0]
	for _, alert := range nm.alertBatch {
		if active[alert.Identity] {
			retained = append(retained, alert)
		}
	}
	clear(nm.alertBatch[len(retained):])
	nm.alertBatch = retained
}

func (nm *NotificationManager) sendNtfyBatchContext(ctx context.Context, batch []Alert) bool {
	defer RecoverAndLogPanic(NameNtfyProvider)
	text := formatNtfyMessage(batch)
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

	pri := maxPriority(batch)
	req.Header.Set(HeaderNtfyPriority, pri.String())

	var tags []string
	seenTags := make(map[string]bool)
	for _, a := range batch {
		if a.Tag != StrEmpty && !seenTags[string(a.Tag)] {
			seenTags[string(a.Tag)] = true
			tags = append(tags, string(a.Tag))
		}
	}
	if len(tags) > 0 {
		req.Header.Set(HeaderNtfyTags, strings.Join(tags, SymComma))
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
		return false // Retry on any error
	}
	return true
}

func formatNtfyMessage(batch []Alert) string {
	var sb strings.Builder
	for i, alert := range batch {
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

		sb.WriteString(prefix + msg)
		if i < len(batch)-1 {
			sb.WriteString(StrN)
		}
	}

	text := sb.String()
	if utf8.RuneCountInString(text) > MaxAlertMessageRunes {
		text = TruncateRunes(text, MaxAlertMessageRunes-utf8.RuneCountInString(AlertTruncationNotice)) + AlertTruncationNotice
	}
	text = truncateAlertBytes(text, MaxProviderMessageBytes)
	return text
}

func (nm *NotificationManager) sendTelegramBatchContext(ctx context.Context, batch []Alert) bool {
	defer RecoverAndLogPanic(NameTelegramProvider)
	text := formatTelegramMessage(batch)
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
		return false // Retry on any error
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

func formatTelegramMessage(batch []Alert) string {
	var sb strings.Builder
	sb.WriteString(TelegramAlertHeader)

	for _, alert := range batch {
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
	}

	return sb.String()
}
