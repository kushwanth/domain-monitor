package main

import (
	"context"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unique"

	"github.com/likexian/whois"
	whoisparser "github.com/likexian/whois-parser"
	"github.com/miekg/dns"
)

var (
	allowInsecureRDAPURLs = false
	whoisQueryFn          = defaultWhoisQuery
	rdapBootstrap         = NewBootstrap(&http.Client{Timeout: 10 * time.Second})
)

func defaultWhoisQuery(domain string) (string, error) {
	asciiDomain := NormalizeDomainToASCIIText(domain)
	client := whois.NewClient().SetTimeout(10 * time.Second)
	if knownServer := KnownWhoisServer(asciiDomain); knownServer != "" {
		return client.Whois(asciiDomain, knownServer)
	}
	return client.Whois(asciiDomain)
}

// queryWhoisWithContext executes a WHOIS query asynchronously, honoring ctx cancellation.
// Note: the WHOIS library (likexian/whois) does not natively support context. When ctx is
// cancelled, the spawned goroutine continues running until the library's 10s TCP timeout
// expires. This is a bounded leak by design — the goroutine always terminates within 10s.
func queryWhoisWithContext(ctx context.Context, domain string, host ...string) (string, error) {
	asciiDomain := NormalizeDomainToASCIIText(domain)

	ch := make(chan queryResult, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				ch <- queryResult{err: fmt.Errorf("whois query panicked: %v", r)}
			}
		}()
		client := whois.NewClient().SetTimeout(10 * time.Second)
		if len(host) > 0 && strings.TrimSpace(host[0]) != "" {
			raw, qErr := client.Whois(asciiDomain, host[0])
			ch <- queryResult{raw: raw, err: qErr}
		} else {
			raw, qErr := whoisQueryFn(asciiDomain)
			ch <- queryResult{raw: raw, err: qErr}
		}
	}()

	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case res := <-ch:
		return res.raw, res.err
	}
}

// parseFlexibleDate parses dates from diverse global registry/registrar formats and converts them to UTC RFC3339.
func parseFlexibleDate(dateStr string) (time.Time, string, error) {
	clean := strings.TrimSpace(dateStr)
	if clean == "" {
		return time.Time{}, "", fmt.Errorf("empty date string")
	}

	// Remove common leading prefixes like "Expires on:", "Renewal:", etc.
	if prefix, after, found := strings.Cut(clean, ":"); found && !strings.Contains(prefix, "T") {
		prefixLower := strings.ToLower(prefix)
		if strings.Contains(prefixLower, "expire") || strings.Contains(prefixLower, "date") || strings.Contains(prefixLower, "valid") {
			clean = strings.TrimSpace(after)
		}
	}

	// Remove trailing parenthetical notes like "(UTC)", "(YYYY-MM-DD)", "(JST)", etc.
	if before, _, found := strings.Cut(clean, "("); found {
		clean = strings.TrimSpace(before)
	}
	clean = strings.Trim(clean, `"' `)

	// Clean known timezone abbreviations and normalize
	cleanNormalized := clean
	for tz, repl := range TZReplacements {
		if before, ok := strings.CutSuffix(cleanNormalized, tz); ok {
			cleanNormalized = before + repl
			break
		}
	}

	targets := []string{cleanNormalized}
	if clean != cleanNormalized {
		targets = append(targets, clean)
	}

	for _, target := range targets {
		for _, format := range FlexibleDateFormats {
			if t, err := time.Parse(format, target); err == nil {
				utc := t.UTC()
				return utc, utc.Format(time.RFC3339), nil
			}
		}
	}

	return time.Time{}, "", fmt.Errorf("unable to parse date format: %q", dateStr)
}

// normalizeEPPStatus extracts canonical EPP status token from raw status strings.
func normalizeEPPStatus(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}

	// 1. If raw contains a URL with an anchor (e.g., "https://icann.org/epp#clientTransferProhibited"
	// or "clientTransferProhibited https://icann.org/epp#clientTransferProhibited"), extract the anchor token if valid.
	if _, tokenRaw, found := strings.CutLast(s, "#"); found {
		token := strings.TrimSpace(tokenRaw)
		token = strings.TrimRight(token, ")/;, \t\r\n")
		if token != "" && !strings.Contains(token, "/") && !strings.Contains(token, " ") {
			cleanKey := NormalizeStatusToken(token)
			if canon, ok := EPPStatusMap[cleanKey]; ok {
				return canon
			}
			return token
		}
	}

	// 2. Strip parenthesis notes like "(server-managed)"
	if before, _, found := strings.Cut(s, "("); found {
		s = strings.TrimSpace(before)
	}

	// 3. Strip any full URL tokens (e.g., "https://...", "http://...")
	fields := strings.Fields(s)
	var nonURLFields []string
	for _, f := range fields {
		if !strings.HasPrefix(strings.ToLower(f), "http://") && !strings.HasPrefix(strings.ToLower(f), "https://") {
			nonURLFields = append(nonURLFields, f)
		}
	}
	if len(nonURLFields) > 0 {
		s = strings.Join(nonURLFields, " ")
	}

	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}

	// 4. Map known multi-word, hyphenated, or camelCase EPP / RDAP status strings to canonical format
	cleanKey := NormalizeStatusToken(s)
	if canon, ok := EPPStatusMap[cleanKey]; ok {
		return unique.Make(canon).Value()
	}

	return unique.Make(s).Value()
}

// NormalizeDomainStatuses deduplicates and normalizes status strings.
// It also removes redundant generic status tokens (e.g. "transferProhibited", "deleteProhibited")
// when a more specific client/server status (e.g. "clientTransferProhibited", "serverTransferProhibited") is present.
func NormalizeDomainStatuses(statuses []string) []string {
	seen := make(map[string]bool)
	var normalized []string
	for _, s := range statuses {
		norm := normalizeEPPStatus(s)
		if norm != "" {
			key := strings.ToLower(norm)
			if !seen[key] {
				seen[key] = true
				normalized = append(normalized, norm)
			}
		}
	}

	var result []string
	for _, norm := range normalized {
		key := strings.ToLower(norm)
		switch key {
		case "transferprohibited":
			if seen["clienttransferprohibited"] || seen["servertransferprohibited"] {
				continue
			}
		case "deleteprohibited":
			if seen["clientdeleteprohibited"] || seen["serverdeleteprohibited"] {
				continue
			}
		case "updateprohibited":
			if seen["clientupdateprohibited"] || seen["serverupdateprohibited"] {
				continue
			}
		case "renewprohibited":
			if seen["clientrenewprohibited"] || seen["serverrenewprohibited"] {
				continue
			}
		case "hold":
			if seen["clienthold"] || seen["serverhold"] {
				continue
			}
		}
		result = append(result, norm)
	}
	return result
}

func isTransferLocked(statuses []string) bool {
	for _, s := range statuses {
		clean := NormalizeStatusToken(s)
		if strings.Contains(clean, "transferprohibited") || strings.Contains(clean, "prohibittransfer") || strings.Contains(clean, "transferlock") {
			return true
		}
	}
	return false
}

func isDomainSuspended(statuses []string) (bool, string) {
	for _, s := range statuses {
		clean := NormalizeStatusToken(s)
		if clean == "serverhold" || clean == "clienthold" || clean == "pendingdelete" || clean == "redemptionperiod" || clean == "inactive" || clean == "hold" {
			return true, s
		}
	}
	return false, ""
}

// isDomainNotFoundInWhois checks for common registrar and registry not-found responses.
func isDomainNotFoundInWhois(text string) bool {
	lower := strings.ToLower(text)
	for _, ind := range WhoisNotFoundIndicators {
		if strings.Contains(lower, ind) {
			return true
		}
	}
	return false
}

// isWhoisRateLimited checks if a raw WHOIS output or error indicates rate limiting.
func isWhoisRateLimited(text string, err error) bool {
	if err != nil {
		errLower := strings.ToLower(err.Error())
		if strings.Contains(errLower, "limit") || strings.Contains(errLower, "quota") || strings.Contains(errLower, "too many") {
			return true
		}
	}
	lower := strings.ToLower(text)
	indicators := []string{
		"limit exceeded",
		"query limit exceeded",
		"too many requests",
		"quota exceeded",
		"access denied",
		"connection reset by peer",
		"exceeded your access quota",
		"lookup quota exceeded",
		"rate limit",
		"rate-limit",
	}
	for _, ind := range indicators {
		if strings.Contains(lower, ind) {
			return true
		}
	}
	return false
}

// extractVCardText safely extracts text from polymorphic jCard / vCard property values (string, []any, []string).
func extractVCardText(val any) string {
	if val == nil {
		return ""
	}
	switch v := val.(type) {
	case string:
		return strings.TrimSpace(v)
	case []any:
		var parts []string
		for _, item := range v {
			if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
				parts = append(parts, strings.TrimSpace(s))
			}
		}
		return strings.TrimSpace(strings.Join(parts, " "))
	case []string:
		var parts []string
		for _, s := range v {
			if strings.TrimSpace(s) != "" {
				parts = append(parts, strings.TrimSpace(s))
			}
		}
		return strings.TrimSpace(strings.Join(parts, " "))
	default:
		return fmt.Sprintf("%v", v)
	}
}

// extractVCardProperty finds a named property (e.g. "fn", "org") in a jCard vcardArray (RFC 7095).
func extractVCardProperty(vcardArray []any, targetProp string) string {
	if len(vcardArray) < 2 {
		return ""
	}
	props, ok := vcardArray[1].([]any)
	if !ok {
		return ""
	}
	for _, p := range props {
		items, ok := p.([]any)
		if !ok || len(items) < 4 {
			continue
		}
		propName, ok := items[0].(string)
		if !ok || !strings.EqualFold(propName, targetProp) {
			continue
		}
		if text := extractVCardText(items[3]); text != "" {
			return text
		}
	}
	return ""
}

// findRegistrarEntity extracts registrar name, IANA ID, referral RDAP URL, and WHOIS server recursively from RDAP entities.
func findRegistrarEntity(entities []RDAPEntity) (name string, ianaID string, relURL string, whoisServer string) {
	for _, entity := range entities {
		isRegistrar := false
		for _, role := range entity.Roles {
			r := strings.ToLower(role)
			if r == "registrar" || r == "sponsor" || r == "reseller" {
				isRegistrar = true
				break
			}
		}

		if isRegistrar {
			// 1. Extract Name from VCard properties (fn, org)
			if len(entity.VCardArray) > 0 {
				name = extractVCardProperty(entity.VCardArray, "fn")
				if name == "" {
					name = extractVCardProperty(entity.VCardArray, "org")
				}
			}

			// 2. Extract IANA ID from PublicIDs
			for _, pid := range entity.PublicIDs {
				if strings.EqualFold(pid.Type, "iana") || strings.EqualFold(pid.Type, "iana registrar id") {
					ianaID = strings.TrimSpace(pid.Identifier)
					if name == "" && ianaID != "" {
						name = fmt.Sprintf("Registrar (IANA %s)", ianaID)
					}
					break
				}
			}

			// 3. Extract Entity Handle fallback
			if name == "" && entity.Handle != "" && !strings.Contains(entity.Handle, " ") {
				name = entity.Handle
			}

			// 4. Extract Referral Links on the Registrar Entity (RFC 9083 / ICANN standard)
			for _, link := range entity.Links {
				if link.Rel == "related" || link.Rel == "alternate" || strings.Contains(link.Type, "rdap+json") {
					if strings.HasPrefix(link.Href, "http") {
						relURL = link.Href
						break
					}
				}
			}

			// 5. Extract Port-43 WHOIS server if present
			if entity.Port43 != "" {
				whoisServer = entity.Port43
			}

			if name != "" {
				return name, ianaID, relURL, whoisServer
			}
		}

		if len(entity.Entities) > 0 {
			if n, id, u, w := findRegistrarEntity(entity.Entities); n != "" {
				return n, id, u, w
			}
		}
	}
	return name, ianaID, relURL, whoisServer
}

// findRegistrarRecursively preserves backwards-compatibility for registrar name resolution.
func findRegistrarRecursively(entities []RDAPEntity) string {
	name, _, _, _ := findRegistrarEntity(entities)
	return name
}

// collectRDAPReferralLinks scans both top-level domain links and all entity links for candidate registrar RDAP endpoints.
func collectRDAPReferralLinks(domainInfo *RDAPDomainResponse, baseURL string) []string {
	if domainInfo == nil {
		return nil
	}
	var candidates []string
	seen := make(map[string]bool)

	addLink := func(link RDAPLink) {
		href := strings.TrimSpace(link.Href)
		if href == "" || !strings.HasPrefix(href, "http") {
			return
		}
		if baseURL != "" && strings.HasPrefix(href, strings.TrimRight(baseURL, "/")) {
			return // Avoid self-referral loop
		}
		isRelated := link.Rel == "related" || link.Rel == "alternate"
		isRDAPType := strings.Contains(link.Type, "rdap+json") || strings.Contains(href, "/domain/")
		if (isRelated || isRDAPType) && !seen[href] {
			seen[href] = true
			candidates = append(candidates, href)
		}
	}

	for _, link := range domainInfo.Links {
		addLink(link)
	}

	var scanEntities func(entities []RDAPEntity)
	scanEntities = func(entities []RDAPEntity) {
		for _, e := range entities {
			for _, l := range e.Links {
				addLink(l)
			}
			if len(e.Entities) > 0 {
				scanEntities(e.Entities)
			}
		}
	}
	scanEntities(domainInfo.Entities)

	return candidates
}

// extractRDAPDomainTier converts an RDAPDomainResponse object to a DomainTierData.
func extractRDAPDomainTier(domainInfo *RDAPDomainResponse, source string, server string) *DomainTierData {
	if domainInfo == nil {
		return nil
	}
	tier := &DomainTierData{
		Source: source,
		Server: server,
	}

	tier.Registrar, tier.IANAID, _, _ = findRegistrarEntity(domainInfo.Entities)

	for _, event := range domainInfo.Events {
		action := strings.ToLower(event.Action)
		if strings.Contains(action, "expiration") {
			if _, norm, err := parseFlexibleDate(event.Date); err == nil {
				tier.Expiration = norm
			} else {
				tier.Expiration = event.Date
			}
		} else if strings.Contains(action, "registration") || strings.Contains(action, "created") {
			if _, norm, err := parseFlexibleDate(event.Date); err == nil {
				tier.Created = norm
			} else {
				tier.Created = event.Date
			}
		} else if strings.Contains(action, "last changed") || strings.Contains(action, "last modified") || strings.Contains(action, "updated") {
			if _, norm, err := parseFlexibleDate(event.Date); err == nil {
				tier.Updated = norm
			} else {
				tier.Updated = event.Date
			}
		}
	}

	for _, ns := range domainInfo.Nameservers {
		live := NormalizeDomain(ns.LDHName)
		if live != "" {
			tier.Nameservers = append(tier.Nameservers, live)
		}
	}

	tier.DomainStatus = NormalizeDomainStatuses(domainInfo.Status)

	if domainInfo.SecureDNS != nil && DerefOrDefault(domainInfo.SecureDNS.DelegationSigned, false) {
		tier.DNSSEC = true
	}

	return tier
}

// extractWhoisTier extracts a DomainTierData from raw WHOIS output.
func extractWhoisTier(raw string, source string, server string) *DomainTierData {
	tier := &DomainTierData{
		Source: source,
		Server: server,
		Raw:    raw,
	}

	parsed, parseErr := whoisparser.Parse(raw)
	if parseErr == nil && parsed.Registrar != nil && parsed.Registrar.Name != "" {
		tier.Registrar = parsed.Registrar.Name
		tier.IANAID = parsed.Registrar.ID
	}

	if parseErr == nil && parsed.Domain != nil {
		if parsed.Domain.ExpirationDateInTime != nil {
			tier.Expiration = parsed.Domain.ExpirationDateInTime.UTC().Format(time.RFC3339)
		} else if parsed.Domain.ExpirationDate != "" {
			if _, norm, err := parseFlexibleDate(parsed.Domain.ExpirationDate); err == nil {
				tier.Expiration = norm
			} else {
				tier.Expiration = parsed.Domain.ExpirationDate
			}
		}

		if parsed.Domain.CreatedDateInTime != nil {
			tier.Created = parsed.Domain.CreatedDateInTime.UTC().Format(time.RFC3339)
		} else if parsed.Domain.CreatedDate != "" {
			if _, norm, err := parseFlexibleDate(parsed.Domain.CreatedDate); err == nil {
				tier.Created = norm
			} else {
				tier.Created = parsed.Domain.CreatedDate
			}
		}

		if parsed.Domain.UpdatedDateInTime != nil {
			tier.Updated = parsed.Domain.UpdatedDateInTime.UTC().Format(time.RFC3339)
		} else if parsed.Domain.UpdatedDate != "" {
			if _, norm, err := parseFlexibleDate(parsed.Domain.UpdatedDate); err == nil {
				tier.Updated = norm
			} else {
				tier.Updated = parsed.Domain.UpdatedDate
			}
		}

		tier.DomainStatus = NormalizeDomainStatuses(parsed.Domain.Status)
		tier.DNSSEC = parsed.Domain.DNSSec

		for _, ns := range parsed.Domain.NameServers {
			if ns != "" {
				tier.Nameservers = append(tier.Nameservers, NormalizeDomain(ns))
			}
		}
	}

	// Supplementary regex field extraction if missing
	if tier.Expiration == "" {
		if m := ReWhoisExpiry.FindStringSubmatch(raw); len(m) > 1 {
			dateStr := strings.TrimSpace(m[1])
			if _, norm, err := parseFlexibleDate(dateStr); err == nil {
				tier.Expiration = norm
			} else {
				tier.Expiration = dateStr
			}
		}
	}

	if tier.Created == "" {
		if m := ReWhoisCreated.FindStringSubmatch(raw); len(m) > 1 {
			dateStr := strings.TrimSpace(m[1])
			if _, norm, err := parseFlexibleDate(dateStr); err == nil {
				tier.Created = norm
			}
		}
	}

	if tier.Updated == "" {
		if m := ReWhoisUpdated.FindStringSubmatch(raw); len(m) > 1 {
			dateStr := strings.TrimSpace(m[1])
			if _, norm, err := parseFlexibleDate(dateStr); err == nil {
				tier.Updated = norm
			}
		}
	}

	if tier.Registrar == "" {
		if m := ReWhoisRegistrar.FindStringSubmatch(raw); len(m) > 1 {
			reg := strings.TrimSpace(m[1])
			if !strings.EqualFold(reg, "not applicable") && !strings.EqualFold(reg, "none") {
				tier.Registrar = reg
			}
		}
	}

	if tier.IANAID == "" {
		if m := ReWhoisIANAID.FindStringSubmatch(raw); len(m) > 1 {
			tier.IANAID = strings.TrimSpace(m[1])
		}
	}

	if len(tier.Nameservers) == 0 {
		matches := ReWhoisNS.FindAllStringSubmatch(raw, -1)
		for _, m := range matches {
			if len(m) > 1 {
				ns := NormalizeDomain(m[1])
				if ns != "" && !strings.Contains(ns, " ") {
					tier.Nameservers = append(tier.Nameservers, ns)
				}
			}
		}
	}

	if len(tier.DomainStatus) == 0 {
		matches := ReWhoisStatus.FindAllStringSubmatch(raw, -1)
		var statuses []string
		for _, m := range matches {
			if len(m) > 1 {
				statuses = append(statuses, strings.TrimSpace(m[1]))
			}
		}
		tier.DomainStatus = NormalizeDomainStatuses(statuses)
	}

	if !tier.DNSSEC {
		if m := ReWhoisDNSSEC.FindStringSubmatch(raw); len(m) > 1 {
			val := strings.ToLower(strings.TrimSpace(m[1]))
			if strings.Contains(val, "signed") || strings.Contains(val, "yes") || strings.Contains(val, "active") {
				tier.DNSSEC = true
			}
		}
	}

	return tier
}

// synthesizeTierData merges RegistryTier and RegistrarTier into a coherent RDAPState,
// detecting hierarchy discrepancies like Auto-Renew Grace Period date mismatch and NS desync.
func synthesizeTierData(registry *DomainTierData, registrar *DomainTierData) (*RDAPState, []string) {
	state := &RDAPState{
		Status:        StatusOK,
		RegistryTier:  registry,
		RegistrarTier: registrar,
	}

	var discrepancies []string

	// 1. Synthesize Source
	if registry != nil && registrar != nil {
		state.Source = fmt.Sprintf("%s+%s", registry.Source, registrar.Source)
	} else if registry != nil {
		state.Source = registry.Source
	} else if registrar != nil {
		state.Source = registrar.Source
	}

	// 2. Synthesize Registrar Identity
	if registrar != nil && registrar.Registrar != "" {
		state.Registrar = registrar.Registrar
	} else if registry != nil && registry.Registrar != "" {
		state.Registrar = registry.Registrar
	}

	if registrar != nil && registrar.IANAID != "" {
		state.RegistrarIANAID = registrar.IANAID
	} else if registry != nil && registry.IANAID != "" {
		state.RegistrarIANAID = registry.IANAID
	}

	// 3. Synthesize Expiration & Check for Grace Period Discrepancies
	if registry != nil && registry.Expiration != "" && registrar != nil && registrar.Expiration != "" {
		regTime, _, errReg := parseFlexibleDate(registry.Expiration)
		rarTime, _, errRar := parseFlexibleDate(registrar.Expiration)
		if errReg == nil && errRar == nil {
			deltaDays := math.Abs(regTime.Sub(rarTime).Hours() / 24)
			if deltaDays > 45 {
				disc := fmt.Sprintf("Auto-Renew Grace Period discrepancy: Registry expiration (%s) vs Registrar expiration (%s)",
					regTime.Format("2006-01-02"), rarTime.Format("2006-01-02"))
				discrepancies = append(discrepancies, disc)
			}
			// Use the earlier date for alert evaluation to be conservative
			if rarTime.Before(regTime) {
				state.Expiration = registrar.Expiration
			} else {
				state.Expiration = registry.Expiration
			}
		} else if errReg == nil {
			state.Expiration = registry.Expiration
		} else if errRar == nil {
			state.Expiration = registrar.Expiration
		} else {
			state.Expiration = registry.Expiration
		}
	} else if registry != nil && registry.Expiration != "" {
		state.Expiration = registry.Expiration
	} else if registrar != nil && registrar.Expiration != "" {
		state.Expiration = registrar.Expiration
	}

	// 4. Synthesize Nameservers & Check for Desynchronization
	if registry != nil && len(registry.Nameservers) > 0 && registrar != nil && len(registrar.Nameservers) > 0 {
		regMap := make(map[string]bool)
		for _, ns := range registry.Nameservers {
			regMap[ns] = true
		}
		rarMap := make(map[string]bool)
		for _, ns := range registrar.Nameservers {
			rarMap[ns] = true
		}

		mismatch := false
		if len(registry.Nameservers) != len(registrar.Nameservers) || len(regMap) != len(rarMap) {
			mismatch = true
		} else {
			for ns := range regMap {
				if !rarMap[ns] {
					mismatch = true
					break
				}
			}
		}

		if mismatch {
			disc := fmt.Sprintf("Nameserver desync: Registry delegation [%s] != Registrar configuration [%s]",
				strings.Join(registry.Nameservers, ", "), strings.Join(registrar.Nameservers, ", "))
			discrepancies = append(discrepancies, disc)
		}
		// Registry delegation is authoritative for global DNS resolution
		state.Nameservers = registry.Nameservers
	} else if registry != nil && len(registry.Nameservers) > 0 {
		state.Nameservers = registry.Nameservers
	} else if registrar != nil && len(registrar.Nameservers) > 0 {
		state.Nameservers = registrar.Nameservers
	}

	// 5. Synthesize Domain Statuses (Union of Registry and Registrar holds/prohibitions)
	var allStatuses []string
	if registry != nil {
		allStatuses = append(allStatuses, registry.DomainStatus...)
	}
	if registrar != nil {
		allStatuses = append(allStatuses, registrar.DomainStatus...)
	}
	state.DomainStatus = NormalizeDomainStatuses(allStatuses)

	// 6. Synthesize DNSSEC
	if (registry != nil && registry.DNSSEC) || (registrar != nil && registrar.DNSSEC) {
		state.DNSSEC = true
	}

	state.Discrepancies = discrepancies
	return state, discrepancies
}

func evaluateRDAP(ctx context.Context, httpClient *http.Client, app *AppState, target DomainConfig) *RDAPState {
	rdapState, err := fetchRDAP(ctx, httpClient, target.Domain)
	if err != nil {
		if errors.Is(err, ErrRDAPNotFound) {
			LogInfo("RDAP returned 404, attempting WHOIS fallback", "domain", target.Domain)
		} else if errors.Is(err, ErrRDAPRateLimited) {
			LogWarn("RDAP rate limited, falling back to WHOIS", "domain", target.Domain)
		} else {
			LogInfof(MsgLogWHOISFallback, target.Domain)
		}

		whoisState, whoisErr := fetchWhois(ctx, target.Domain)
		if whoisErr != nil {
			if errors.Is(whoisErr, ErrDomainNotFound) || strings.Contains(whoisErr.Error(), "404") || strings.Contains(whoisErr.Error(), "not found") {
				LogInfo("WHOIS reports domain is unregistered (404)", "domain", target.Domain)
				return &RDAPState{
					Status:       StatusFailed,
					Error:        "Domain not found (404)",
					Source:       "whois_404",
					ProtocolUsed: "whois",
				}
			}

			LogErrorf(MsgLogWHOISFailed, target.Domain, whoisErr)

			status := StatusFailed
			errStr := whoisErr.Error()
			if strings.Contains(errStr, "connection refused") || strings.Contains(errStr, "i/o timeout") || strings.Contains(errStr, "no such host") || strings.Contains(errStr, "temporary failure") || isWhoisRateLimited(errStr, whoisErr) || errors.Is(whoisErr, ErrWhoisRateLimited) {
				status = StatusWarning
			}

			return &RDAPState{
				Status:       status,
				Error:        fmt.Sprintf("RDAP: %v | WHOIS: %v", err, whoisErr),
				ProtocolUsed: "whois_failed",
			}
		}

		LogInfof(MsgLogWHOISSuccess, target.Domain)
		return validateRDAPState(app, target, whoisState)
	}

	// Hybrid Tier Supplementation: If RDAP is thin (no registrar tier), attempt WHOIS referral supplement
	if rdapState != nil && rdapState.RegistrarTier == nil && (rdapState.Expiration == "" || rdapState.Registrar == "") {
		if whoisState, whoisErr := fetchWhois(ctx, target.Domain); whoisErr == nil {
			if whoisState.RegistrarTier != nil {
				rdapState.RegistrarTier = whoisState.RegistrarTier
			} else if whoisState.RegistryTier != nil && rdapState.RegistryTier == nil {
				rdapState.RegistryTier = whoisState.RegistryTier
			}
			synthesized, discrepancies := synthesizeTierData(rdapState.RegistryTier, rdapState.RegistrarTier)
			rdapState.Expiration = synthesized.Expiration
			rdapState.Registrar = synthesized.Registrar
			rdapState.RegistrarIANAID = synthesized.RegistrarIANAID
			rdapState.Nameservers = synthesized.Nameservers
			rdapState.DomainStatus = synthesized.DomainStatus
			rdapState.DNSSEC = synthesized.DNSSEC
			rdapState.Discrepancies = discrepancies
			rdapState.Source = synthesized.Source
			rdapState.ProtocolUsed = "hybrid"
		}
	}

	return validateRDAPState(app, target, rdapState)
}

func fetchRDAP(ctx context.Context, httpClient *http.Client, domain string) (*RDAPState, error) {
	start := time.Now()
	asciiDomain := NormalizeDomainToASCIIText(domain)

	urls, err := rdapBootstrap.ServersFor(ctx, asciiDomain)
	if err != nil {
		return nil, fmt.Errorf("no RDAP server: %w", err)
	}

	httpClient = ResolveHTTPClient(httpClient)

	var lastErr error
	for _, rawBaseURL := range urls {
		baseURL := strings.TrimRight(rawBaseURL, "/")
		reqURL := baseURL + "/domain/" + asciiDomain
		req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
		if err != nil {
			lastErr = err
			continue
		}
		req.Header.Set("Accept", "application/rdap+json, application/json")
		req.Header.Set("User-Agent", DefaultUserAgent)

		resp, err := httpClient.Do(req)
		if err != nil {
			lastErr = err
			continue
		}

		if resp.StatusCode == http.StatusNotFound {
			DrainAndClose(resp.Body, 4096)
			return nil, ErrRDAPNotFound
		}
		if resp.StatusCode == http.StatusTooManyRequests {
			DrainAndClose(resp.Body, 4096)
			return nil, ErrRDAPRateLimited
		}
		if resp.StatusCode != http.StatusOK {
			DrainAndClose(resp.Body, 4096)
			lastErr = fmt.Errorf("rdap HTTP error: %d", resp.StatusCode)
			continue
		}

		bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, MaxBootstrapResponseSize))
		DrainAndClose(resp.Body, 4096)
		if err != nil {
			lastErr = err
			continue
		}

		var domainInfo RDAPDomainResponse
		if err := jsonv2.Unmarshal(bodyBytes, &domainInfo); err != nil {
			lastErr = err
			continue
		}

		registryTier := extractRDAPDomainTier(&domainInfo, "registry_rdap", baseURL)

		var registrarTier *DomainTierData

		// 1. Follow Registrar RDAP Referral Links (scans both domain links and nested entity links)
		referralLinks := collectRDAPReferralLinks(&domainInfo, baseURL)
		if relDomain := followRegistrarRDAPLinks(ctx, asciiDomain, referralLinks, httpClient); relDomain != nil {
			registrarTier = extractRDAPDomainTier(relDomain, "registrar_rdap", "referral")
		}

		// 2. Synthesize 2-Tier State
		state, _ := synthesizeTierData(registryTier, registrarTier)
		state.ProtocolUsed = "rdap"
		state.QueryDurationMs = time.Since(start).Milliseconds()
		return state, nil
	}

	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("rdap lookup failed across all candidate servers")
}

// isSafeRDAPURL validates that candidate registrar RDAP referral URLs are safe to query,
// blocking loopback, private, link-local, multicast, and cloud metadata destinations (RFC 7480 Section 5.3).
func isSafeRDAPURL(rawURL string) bool {
	if allowInsecureRDAPURLs {
		return true
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	if u.User != nil {
		return false
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "https" {
		return false
	}
	host := strings.ToLower(u.Hostname())
	if host == "" || host == "localhost" || strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".internal") {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		if IsRestrictedIP(ip) {
			return false
		}
	}
	return true
}

func followRegistrarRDAPLinks(ctx context.Context, domain string, links []string, client *http.Client) *RDAPDomainResponse {
	httpClient := client
	if httpClient == nil {
		httpClient = NewRDAPHTTPClient(6 * time.Second)
	}

	for _, rawHref := range links {
		href := strings.TrimSpace(rawHref)
		if href == "" {
			continue
		}
		targetURL := href
		if u, err := url.Parse(href); err == nil {
			if !strings.Contains(u.Path, "/domain/") {
				u.Path = strings.TrimRight(u.Path, "/") + "/domain/" + domain
				targetURL = u.String()
			}
		} else {
			if !strings.Contains(targetURL, "/domain/") {
				targetURL = strings.TrimRight(targetURL, "/") + "/domain/" + domain
			}
		}
		if !isSafeRDAPURL(targetURL) {
			LogWarn("Skipping unsafe RDAP referral URL", "domain", domain, "url", targetURL)
			continue
		}
		LogInfo("Querying registrar RDAP link", "domain", domain, "url", targetURL)
		relReq, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
		if err != nil {
			continue
		}
		relReq.Header.Set("Accept", "application/rdap+json, application/json")
		relReq.Header.Set("User-Agent", DefaultUserAgent)

		relResp, err := httpClient.Do(relReq)
		if err != nil || relResp.StatusCode != http.StatusOK {
			if relResp != nil {
				if relResp.StatusCode == http.StatusTooManyRequests {
					LogWarn("Rate limited by registrar RDAP", "domain", domain)
				}
				DrainAndClose(relResp.Body, 4096)
			}
			continue
		}

		bodyBytes, err := io.ReadAll(io.LimitReader(relResp.Body, MaxBootstrapResponseSize))
		DrainAndClose(relResp.Body, 4096)
		if err != nil {
			continue
		}

		var relDomain RDAPDomainResponse
		if err := jsonv2.Unmarshal(bodyBytes, &relDomain); err != nil {
			continue
		}

		return &relDomain
	}
	return nil
}

func fetchWhois(ctx context.Context, domain string) (*RDAPState, error) {
	start := time.Now()
	if ctx == nil {
		ctx = context.Background()
	}
	qCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	result, queryErr := queryWhoisWithContext(qCtx, domain)
	durationMs := time.Since(start).Milliseconds()

	if queryErr != nil && result == "" {
		return nil, fmt.Errorf("whois query failed: %w", queryErr)
	}

	if isWhoisRateLimited(result, queryErr) {
		return nil, ErrWhoisRateLimited
	}

	registryTier := extractWhoisTier(result, "registry_whois", "registry")
	var registrarTier *DomainTierData

	// Always follow referral server if present to guarantee cross-tier 2-tier ARGP detection
	if m := ReWhoisReferral.FindStringSubmatch(result); len(m) > 1 {
		referralServer := strings.TrimSpace(m[1])
		if referralServer != "" && !strings.Contains(referralServer, "iana") && !strings.Contains(referralServer, "internic") {
			LogInfo("Following WHOIS referral", "domain", domain, "referral_server", referralServer)
			refCtx, refCancel := context.WithTimeout(ctx, 10*time.Second)
			defer refCancel()

			if refResult, err := queryWhoisWithContext(refCtx, domain, referralServer); err == nil && refResult != "" && !isDomainNotFoundInWhois(refResult) {
				registrarTier = extractWhoisTier(refResult, "registrar_whois", referralServer)
			}
		}
	}

	state, _ := synthesizeTierData(registryTier, registrarTier)
	state.ProtocolUsed = "whois"
	state.QueryDurationMs = durationMs

	// Check for domain not registered
	if isDomainNotFoundInWhois(result) && state.Expiration == "" && len(state.Nameservers) == 0 {
		return nil, ErrDomainNotFound
	}

	if state.Expiration == "" && state.Registrar == "" && len(state.Nameservers) == 0 && len(state.DomainStatus) == 0 {
		if queryErr != nil {
			return nil, fmt.Errorf("whois query failed: %w", queryErr)
		}
		return nil, fmt.Errorf("whois parsing failed to extract required domain fields")
	}

	return state, nil
}

func validateRDAPState(app *AppState, target DomainConfig, parsed *RDAPState) *RDAPState {
	if parsed == nil {
		return nil
	}
	if parsed.Expiration != "" {
		if t, norm, err := parseFlexibleDate(parsed.Expiration); err == nil {
			parsed.Expiration = norm
			days := time.Until(t).Hours() / 24
			if days < 0 {
				parsed.Status = StatusFailed
				msg := fmt.Sprintf(MsgAlertRDAPExpired, target.Domain, math.Abs(days))
				redacted := "Domain registration has EXPIRED."
				if !target.SuppressAlerts {
					app.SafeDispatch(msg, redacted, PriorityUrgent, "rotating_light", target.Domain, target.Name)
				}
			} else if days <= 30 {
				priority := PriorityWarning
				if days <= 7 {
					priority = PriorityUrgent
				}
				if parsed.Status == StatusOK {
					parsed.Status = StatusWarning
				}
				msg := fmt.Sprintf(MsgAlertRDAPExpiry, target.Domain, days)
				redacted := fmt.Sprintf("Domain is expiring in %.0f days.", days)
				if !target.SuppressAlerts {
					app.SafeDispatch(msg, redacted, priority, "warning", target.Domain, target.Name)
				}
			}
		}
	}

	validateDelegatedNameservers(app, target, parsed.Nameservers, parsed)

	// Status & Suspension evaluation
	parsed.DomainStatus = NormalizeDomainStatuses(parsed.DomainStatus)
	if isSusp, suspStatus := isDomainSuspended(parsed.DomainStatus); isSusp {
		parsed.Status = StatusFailed
		msg := fmt.Sprintf(MsgAlertRDAPSuspended, target.Domain, suspStatus)
		redacted := fmt.Sprintf("Domain suspended (Status: %s).", suspStatus)
		if !target.SuppressAlerts {
			app.SafeDispatch(msg, redacted, PriorityUrgent, "x", target.Domain, target.Name)
		}
	}

	if target.DomainTransferLocked && !isTransferLocked(parsed.DomainStatus) {
		if parsed.Status == StatusOK {
			parsed.Status = StatusWarning
		}
		msg := fmt.Sprintf(MsgAlertRDAPUnlocked, target.Domain)
		redacted := "Domain transfer lock is disabled."
		if !target.SuppressAlerts {
			app.SafeDispatch(msg, redacted, PriorityHigh, "unlock", target.Domain, target.Name)
		}
	}

	// Registrar Validation: Both fields can be present in config.
	// Order of priority: expected_registrar_id (Priority 1) takes precedence over expected_registrar_name (Priority 2).
	// In evaluation, they are mutually exclusive: if expected_registrar_id is configured, it is evaluated and name is superseded.
	if target.ExpectedRegistrarID != "" {
		if parsed.RegistrarIANAID != target.ExpectedRegistrarID {
			parsed.Status = StatusFailed
			parsed.RegistrarMismatch = true
			parsed.ExpectedRegistrar = fmt.Sprintf("IANA %s", target.ExpectedRegistrarID)
			msg := fmt.Sprintf(MsgAlertRDAPRegistrarIDMismatch, target.Domain, target.ExpectedRegistrarID, parsed.RegistrarIANAID)
			redacted := fmt.Sprintf("Registrar IANA ID mismatch (expected %s).", target.ExpectedRegistrarID)
			if !target.SuppressAlerts {
				app.SafeDispatch(msg, redacted, PriorityUrgent, "rotating_light", target.Domain, target.Name)
			}
		}
	} else if target.ExpectedRegistrarName != "" {
		if !strings.Contains(strings.ToLower(parsed.Registrar), strings.ToLower(target.ExpectedRegistrarName)) {
			parsed.Status = StatusFailed
			parsed.RegistrarMismatch = true
			parsed.ExpectedRegistrar = target.ExpectedRegistrarName
			msg := fmt.Sprintf(MsgAlertRDAPRegistrarNameMismatch, target.Domain, target.ExpectedRegistrarName, parsed.Registrar)
			redacted := fmt.Sprintf("Registrar name mismatch (expected %s).", target.ExpectedRegistrarName)
			if !target.SuppressAlerts {
				app.SafeDispatch(msg, redacted, PriorityUrgent, "rotating_light", target.Domain, target.Name)
			}
		}
	}

	// Report Hierarchy Discrepancies if detected
	for _, discrepancy := range parsed.Discrepancies {
		LogWarnf(MsgLogHierarchyWarn, target.Domain, discrepancy)
		if !target.SuppressAlerts {
			msg := fmt.Sprintf(MsgAlertRDAPDiscrepancy, target.Domain, discrepancy)
			app.SafeDispatch(msg, discrepancy, PriorityWarning, "warning", target.Domain, target.Name)
		}
	}

	return parsed
}

func resolveRootZoneResolvers(ctx context.Context, app *AppState, rootZone string, globalResolvers []string) []string {
	rootNS, err := queryDNS(ctx, app, rootZone, dns.TypeNS, globalResolvers)
	if err != nil || len(rootNS) == 0 {
		return nil
	}
	var rootIPs []string
	for _, ns := range rootNS {
		ips, err := queryIPRecords(ctx, app, ns, globalResolvers)
		if err == nil {
			rootIPs = append(rootIPs, ips...)
		}
	}
	return rootIPs
}

func evaluateNSDelegation(ctx context.Context, app *AppState, target DomainConfig) *RDAPState {
	parsed := &RDAPState{
		Status:          StatusOK,
		IsDelegatedZone: true,
		Source:          "dns_delegation",
	}

	resolversToUse := app.Resolvers()
	rd := true
	if target.RootZone != "" {
		rootIPs := resolveRootZoneResolvers(ctx, app, target.RootZone, app.Resolvers())
		if len(rootIPs) > 0 {
			resolversToUse = rootIPs
			rd = false // Querying parent authoritative nameservers directly
		}
	}

	r, err := queryDNSMsgWithRD(ctx, app, target.Domain, dns.TypeNS, resolversToUse, rd)
	if err != nil {
		parsed.Status = StatusFailed
		parsed.Error = fmt.Sprintf("Failed to query NS records: %v", err)
		return parsed
	}

	var nsRecords []string
	if r != nil {
		for _, ans := range r.Answer {
			if ns, ok := ans.(*dns.NS); ok {
				nsRecords = append(nsRecords, ns.Ns)
			}
		}

		if len(nsRecords) == 0 {
			fqdn := dns.Fqdn(target.Domain)
			for _, auth := range r.Ns {
				if ns, ok := auth.(*dns.NS); ok && strings.EqualFold(ns.Header().Name, fqdn) {
					nsRecords = append(nsRecords, ns.Ns)
				}
			}
		}
	}

	for _, ns := range nsRecords {
		parsed.Nameservers = append(parsed.Nameservers, NormalizeDomain(ns))
	}

	validateDelegatedNameservers(app, target, parsed.Nameservers, parsed)

	return parsed
}

// validateDelegatedNameservers verifies that delegated nameservers returned by the registrar/registry
// match the configured expected primary nameservers and secondary (slave/replica) nameservers.
func validateDelegatedNameservers(app *AppState, target DomainConfig, nameservers []string, parsed *RDAPState) {
	liveNS := make(map[string]bool)
	authorizedMap := make(map[string]bool)

	for _, ns := range target.ExpectedNS {
		norm := NormalizeDomain(ns)
		if norm != "" {
			authorizedMap[norm] = true
		}
	}
	for _, ns := range target.SecondaryNS {
		norm := NormalizeDomain(ns)
		if norm != "" {
			authorizedMap[norm] = true
		}
	}

	hasConfiguredNS := len(authorizedMap) > 0
	for _, raw := range nameservers {
		ns := NormalizeDomain(raw)
		if ns == "" {
			continue
		}
		liveNS[ns] = true
		if hasConfiguredNS && !authorizedMap[ns] {
			if parsed != nil {
				parsed.Status = StatusFailed
			}
			msg := fmt.Sprintf(MsgAlertRDAPUnauthorizedNS, target.Domain, ns)
			redacted := "Unauthorized nameserver detected."
			if !target.SuppressAlerts {
				app.SafeDispatch(msg, redacted, PriorityUrgent, "skull", target.Domain, target.Name)
			}
		}
	}

	for _, expectedRaw := range target.ExpectedNS {
		expected := NormalizeDomain(expectedRaw)
		if expected != "" && !liveNS[expected] {
			if parsed != nil {
				parsed.Status = StatusFailed
			}
			msg := fmt.Sprintf(MsgAlertRDAPMissingNS, target.Domain, expectedRaw)
			redacted := "Expected nameserver is missing."
			if !target.SuppressAlerts {
				app.SafeDispatch(msg, redacted, PriorityHigh, "warning", target.Domain, target.Name)
			}
		}
	}
}
