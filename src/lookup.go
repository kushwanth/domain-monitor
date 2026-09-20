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
	whoisQueryFn          = defaultWHOISQuery
	rdapBootstrap         = NewBootstrap(&http.Client{Timeout: DefaultHTTPTimeout})
)

func defaultWHOISQuery(domain string) (string, error) {
	asciiDomain := NormalizeDomainToASCIIText(domain)
	client := whois.NewClient().SetTimeout(DefaultWHOISTimeout)
	if knownServer := KnownWHOISServer(asciiDomain); knownServer != "" {
		return client.Whois(asciiDomain, knownServer)
	}
	return client.Whois(asciiDomain)
}

// queryWHOISWithContext executes a WHOIS query asynchronously, honoring ctx cancellation.
// Note: the WHOIS library (likexian/whois) does not natively support context. When ctx is
// cancelled, the spawned goroutine continues running until the library's 10s TCP timeout
// expires. This is a bounded leak by design — the goroutine always terminates within 10s.
func queryWHOISWithContext(ctx context.Context, app *AppState, domain string, host ...string) (string, error) {
	asciiDomain := NormalizeDomainToASCIIText(domain)

	ch := make(chan queryResult, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				LogError(MsgLogWHOISPanicked, FieldDomain, asciiDomain, FieldPanic, r)
				ch <- queryResult{err: errors.New(MsgErrWHOISPanicked)}
			}
		}()

		server := ""
		if len(host) > 0 {
			server = strings.TrimSpace(host[0])
		}

		var raw string
		var qErr error

		if app != nil && app.WHOISClient != nil {
			raw, qErr = app.WHOISClient.Query(ctx, asciiDomain, server)
		} else {
			// fallback if WHOISClient not provided
			if server != "" {
				raw, qErr = whois.NewClient().SetTimeout(DefaultWHOISTimeout).Whois(asciiDomain, server)
			} else {
				raw, qErr = whoisQueryFn(asciiDomain)
			}
		}
		ch <- queryResult{raw: raw, err: qErr}
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
		return time.Time{}, "", ErrEmptyDate
	}

	// Remove common leading prefixes like "Expires on:", "Renewal:", etc.
	if prefix, after, found := strings.Cut(clean, ":"); found && !strings.Contains(prefix, "T") {
		prefixLower := strings.ToLower(prefix)
		if strings.Contains(prefixLower, "expire") || strings.Contains(prefixLower, "date") || strings.Contains(prefixLower, "valid") {
			clean = strings.TrimSpace(after)
		}
	}

	// Remove trailing parenthetical notes like "(UTC)", "(YYYY-MM-DD)", etc.
	if before, _, found := strings.Cut(clean, "("); found {
		clean = strings.TrimSpace(before)
	}
	clean = strings.Trim(clean, `"' `)

	// Clean known timezone abbreviations to explicit numeric offsets for UTC conversion
	cleanNormalized := clean
	for tz, offset := range TZOffsets {
		if before, ok := strings.CutSuffix(cleanNormalized, tz); ok {
			cleanNormalized = before + offset
			break
		}
	}

	targets := []string{cleanNormalized}
	if clean != cleanNormalized {
		targets = append(targets, clean)
	}

	for _, target := range targets {
		for _, format := range RegistryDateLayouts {
			if t, err := time.Parse(format, target); err == nil {
				utc := t.UTC()
				return utc, utc.Format(time.RFC3339), nil
			}
		}
	}

	return time.Time{}, "", fmt.Errorf(MsgErrUnableToParseDate, dateStr)
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
		if !strings.HasPrefix(strings.ToLower(f), PrefixHTTP) && !strings.HasPrefix(strings.ToLower(f), PrefixHTTPS) {
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
		if clean == EPPStatusServerHold || clean == EPPStatusClientHold || clean == EPPStatusPendingDelete || clean == EPPStatusRedemptionPeriod || clean == EPPStatusInactive || clean == EPPStatusHold {
			return true, s
		}
	}
	return false, ""
}

// isDomainNotFoundInWHOIS checks for common registrar and registry not-found responses.
func isDomainNotFoundInWHOIS(text string) bool {
	lower := strings.ToLower(text)
	for _, ind := range WHOISNotFoundIndicators {
		if strings.Contains(lower, ind) {
			return true
		}
	}
	return false
}

// isWHOISRateLimited checks if a raw WHOIS output or error indicates rate limiting.
func isWHOISRateLimited(text string, err error) bool {
	if err != nil {
		errLower := strings.ToLower(err.Error())
		if strings.Contains(errLower, "limit") || strings.Contains(errLower, "quota") || strings.Contains(errLower, "too many") {
			return true
		}
	}
	lower := strings.ToLower(text)
	for _, ind := range WHOISRateLimitIndicators {
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
		return AnyToString(v)
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
			if r == RoleRegistrar || r == RoleSponsor || r == RoleReseller {
				isRegistrar = true
				break
			}
		}

		if isRegistrar {
			// 1. Extract Name from VCard properties (fn, org)
			if len(entity.VCardArray) > 0 {
				name = extractVCardProperty(entity.VCardArray, VCardPropFN)
				if name == "" {
					name = extractVCardProperty(entity.VCardArray, VCardPropOrg)
				}
			}

			// 2. Extract IANA ID from PublicIDs
			for _, pid := range entity.PublicIDs {
				if strings.EqualFold(pid.Type, PublicIDTypeIANA) || strings.EqualFold(pid.Type, "iana registrar id") {
					ianaID = strings.TrimSpace(pid.Identifier)
					if name == "" && ianaID != "" {
						name = "Registrar (IANA " + ianaID + ")"
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
				if link.Rel == RelRelated || link.Rel == RelAlternate || strings.Contains(link.Type, ContentTypeRDAPJSON) {
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
		isRelated := link.Rel == RelRelated || link.Rel == RelAlternate
		isRDAPType := strings.Contains(link.Type, ContentTypeRDAPJSON) || strings.Contains(href, "/domain/")
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

// extractWHOISTier extracts a DomainTierData from raw WHOIS output.
func extractWHOISTier(raw string, source string, server string) *DomainTierData {
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
		if m := ReWHOISExpiry.FindStringSubmatch(raw); len(m) > 1 {
			dateStr := strings.TrimSpace(m[1])
			if _, norm, err := parseFlexibleDate(dateStr); err == nil {
				tier.Expiration = norm
			} else {
				tier.Expiration = dateStr
			}
		}
	}

	if tier.Created == "" {
		if m := ReWHOISCreated.FindStringSubmatch(raw); len(m) > 1 {
			dateStr := strings.TrimSpace(m[1])
			if _, norm, err := parseFlexibleDate(dateStr); err == nil {
				tier.Created = norm
			}
		}
	}

	if tier.Updated == "" {
		if m := ReWHOISUpdated.FindStringSubmatch(raw); len(m) > 1 {
			dateStr := strings.TrimSpace(m[1])
			if _, norm, err := parseFlexibleDate(dateStr); err == nil {
				tier.Updated = norm
			}
		}
	}

	if tier.Registrar == "" {
		if m := ReWHOISRegistrar.FindStringSubmatch(raw); len(m) > 1 {
			reg := strings.TrimSpace(m[1])
			if !strings.EqualFold(reg, "not applicable") && !strings.EqualFold(reg, "none") {
				tier.Registrar = reg
			}
		}
	}

	if tier.IANAID == "" {
		if m := ReWHOISIANAID.FindStringSubmatch(raw); len(m) > 1 {
			tier.IANAID = strings.TrimSpace(m[1])
		}
	}

	if len(tier.Nameservers) == 0 {
		matches := ReWHOISNS.FindAllStringSubmatch(raw, -1)
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
		matches := ReWHOISStatus.FindAllStringSubmatch(raw, -1)
		var statuses []string
		for _, m := range matches {
			if len(m) > 1 {
				statuses = append(statuses, strings.TrimSpace(m[1]))
			}
		}
		tier.DomainStatus = NormalizeDomainStatuses(statuses)
	}

	if !tier.DNSSEC {
		if m := ReWHOISDNSSEC.FindStringSubmatch(raw); len(m) > 1 {
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
func synthesizeTierData(registry *DomainTierData, registrar *DomainTierData) (RDAPState, []string) {
	if registry == nil && registrar == nil {
		return RDAPState{
			Status: StatusFailed,
			Error:  MsgErrNoTierData,
		}, nil
	}
	state := RDAPState{
		Status:        StatusOK,
		RegistryTier:  registry,
		RegistrarTier: registrar,
	}

	var discrepancies []string

	// 1. Synthesize Source
	if registry != nil && registrar != nil {
		state.Source = registry.Source + "+" + registrar.Source
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
			if deltaDays > AutoRenewGracePeriodThresholdDays {
				disc := "Auto-Renew Grace Period discrepancy: Registry expiration (" + regTime.Format("2006-01-02") + ") vs Registrar expiration (" + rarTime.Format("2006-01-02") + ")"
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
			disc := "Nameserver desync: Registry delegation [" + strings.Join(registry.Nameservers, ", ") + "] != Registrar configuration [" + strings.Join(registrar.Nameservers, ", ") + "]"
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

func evaluateRDAP(ctx context.Context, httpClient HTTPClient, app *AppState, target DomainConfig) RDAPState {
	rdapState, err := fetchRDAPFn(ctx, httpClient, target.Domain)
	if err != nil {
		if errors.Is(err, ErrRDAPNotFound) {
			LogInfo(MsgLogRDAPReturned404, FieldDomain, target.Domain)
		} else if errors.Is(err, ErrRDAPRateLimited) {
			LogWarn(MsgLogRDAPRateLimited, FieldDomain, target.Domain)
		} else {
			LogInfof(MsgLogWHOISFallback, target.Domain)
		}

		whoisState, whoisErr := fetchWHOISFn(ctx, app, target.Domain)
		if whoisErr != nil {
			if errors.Is(whoisErr, ErrDomainNotFound) || strings.Contains(whoisErr.Error(), "404") || strings.Contains(whoisErr.Error(), "not found") {
				LogInfo(MsgLogWHOISUnregistered, FieldDomain, target.Domain)
				return RDAPState{
					Status:       StatusFailed,
					Error:        MsgErrDomainNotFound404,
					Source:       SourceWHOIS404,
					ProtocolUsed: ProtocolWHOIS,
				}
			}

			LogErrorf(MsgLogWHOISFailed, target.Domain, whoisErr)

			status := StatusFailed
			errStr := whoisErr.Error()
			if strings.Contains(errStr, "connection refused") || strings.Contains(errStr, "i/o timeout") || strings.Contains(errStr, "no such host") || strings.Contains(errStr, "temporary failure") || isWHOISRateLimited(errStr, whoisErr) || errors.Is(whoisErr, ErrWHOISRateLimited) {
				status = StatusWarning
			}

			return RDAPState{
				Status:       status,
				Error:        fmt.Sprintf(MsgErrRDAPAndWHOIS, err.Error(), whoisErr.Error()),
				ProtocolUsed: ProtocolWHOISFailed,
			}
		}

		LogInfof(MsgLogWHOISSuccess, target.Domain)
		return validateRDAPState(app, target, whoisState)
	}

	// Hybrid Tier Supplementation: If RDAP is thin (no registrar tier), attempt WHOIS referral supplement
	if rdapState.Status != "" && rdapState.RegistrarTier == nil && (rdapState.Expiration == "" || rdapState.Registrar == "") {
		if whoisState, whoisErr := fetchWHOISFn(ctx, app, target.Domain); whoisErr == nil {
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
			rdapState.ProtocolUsed = ProtocolHybrid
		}
	}

	return validateRDAPState(app, target, rdapState)
}

// fetchRDAPFn is a variable to allow mocking in tests
var fetchRDAPFn = fetchRDAP

func fetchRDAP(ctx context.Context, httpClient HTTPClient, domain string) (RDAPState, error) {
	start := time.Now()
	asciiDomain := NormalizeDomainToASCIIText(domain)

	urls, err := rdapBootstrap.ServersFor(ctx, asciiDomain)
	if err != nil {
		return RDAPState{}, WrapError(MsgErrNoRDAPServer, err)
	}

	if httpClient == nil {
		httpClient = NewRDAPHTTPClient(DefaultHTTPTimeout)
	}

	var lastErr error
	for _, rawBaseURL := range urls {
		baseURL := strings.TrimRight(rawBaseURL, "/")
		reqURL := baseURL + PathRDAPDomain + asciiDomain
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
		if err != nil {
			lastErr = err
			continue
		}
		req.Header.Set(HeaderAccept, AcceptRDAP)
		req.Header.Set(HeaderUserAgent, DefaultUserAgent)

		resp, err := httpClient.Do(req)
		if err != nil {
			lastErr = err
			continue
		}

		if resp.StatusCode == http.StatusNotFound {
			DrainAndClose(resp.Body, MaxBodyDrainSize)
			return RDAPState{}, ErrRDAPNotFound
		}
		if resp.StatusCode == http.StatusTooManyRequests {
			DrainAndClose(resp.Body, MaxBodyDrainSize)
			return RDAPState{}, ErrRDAPRateLimited
		}
		if resp.StatusCode != http.StatusOK {
			DrainAndClose(resp.Body, MaxBodyDrainSize)
			lastErr = fmt.Errorf(MsgErrRDAPHTTPError, resp.StatusCode)
			continue
		}

		bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, MaxBootstrapResponseSize))
		DrainAndClose(resp.Body, MaxBodyDrainSize)
		if err != nil {
			lastErr = err
			continue
		}

		var domainInfo RDAPDomainResponse
		if err := jsonv2.Unmarshal(bodyBytes, &domainInfo); err != nil {
			lastErr = err
			continue
		}

		registryTier := extractRDAPDomainTier(&domainInfo, SourceRegistryRDAP, baseURL)

		var registrarTier *DomainTierData

		// 1. Follow Registrar RDAP Referral Links (scans both domain links and nested entity links)
		referralLinks := collectRDAPReferralLinks(&domainInfo, baseURL)
		if relDomain := followRegistrarRDAPLinks(ctx, asciiDomain, referralLinks, httpClient); relDomain != nil {
			registrarTier = extractRDAPDomainTier(relDomain, SourceRegistrarRDAP, SourceReferral)
		}

		// 2. Synthesize 2-Tier State
		state, _ := synthesizeTierData(registryTier, registrarTier)
		state.ProtocolUsed = ProtocolRDAP
		state.QueryDurationMs = time.Since(start).Milliseconds()
		return state, nil
	}

	if lastErr != nil {
		return RDAPState{}, lastErr
	}
	return RDAPState{}, errors.New(MsgErrRDAPLookupFailedAllCandidates)
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
	if scheme != SchemeHTTPSName {
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

// isSafeWHOISServer validates that a WHOIS referral server address is safe to query,
// preventing SSRF against loopback, private, link-local, multicast, or cloud metadata endpoints.
func isSafeWHOISServer(server string) bool {
	clean := strings.TrimSpace(server)
	if clean == "" {
		return false
	}
	host := clean
	if h, _, err := net.SplitHostPort(clean); err == nil {
		host = h
	}
	host = strings.ToLower(strings.Trim(host, "[]"))
	if host == "" || host == "localhost" || strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".internal") {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		return !IsRestrictedIP(ip)
	}
	return ReValidDomain.MatchString(host)
}

func followRegistrarRDAPLinks(ctx context.Context, domain string, links []string, client HTTPClient) *RDAPDomainResponse {
	httpClient := client
	if httpClient == nil {
		httpClient = NewRDAPHTTPClient(DefaultReferralRDAPTimeout)
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
			LogWarn(MsgLogSkippingUnsafeRDAP, FieldDomain, domain, FieldURL, targetURL)
			continue
		}
		LogInfo(MsgLogQueryingRegistrarRDAP, FieldDomain, domain, FieldURL, targetURL)
		relReq, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
		if err != nil {
			continue
		}
		relReq.Header.Set(HeaderAccept, AcceptRDAP)
		relReq.Header.Set(HeaderUserAgent, DefaultUserAgent)

		relResp, err := httpClient.Do(relReq)
		if err != nil || relResp.StatusCode != http.StatusOK {
			if relResp != nil {
				if relResp.StatusCode == http.StatusTooManyRequests {
					LogWarn(MsgLogRateLimitedRegistrarRDAP, FieldDomain, domain)
				}
				DrainAndClose(relResp.Body, MaxBodyDrainSize)
			}
			continue
		}

		bodyBytes, err := io.ReadAll(io.LimitReader(relResp.Body, MaxBootstrapResponseSize))
		DrainAndClose(relResp.Body, MaxBodyDrainSize)
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

// fetchWHOISFn is a variable to allow mocking in tests
var fetchWHOISFn = fetchWHOIS

func fetchWHOIS(ctx context.Context, app *AppState, domain string) (RDAPState, error) {
	start := time.Now()
	if ctx == nil {
		ctx = context.Background()
	}

	var result string
	var queryErr error
	var attempts int

	for attempts = 1; attempts <= 3; attempts++ {
		qCtx, cancel := context.WithTimeout(ctx, DefaultWHOISQueryTimeout)
		result, queryErr = queryWHOISWithContext(qCtx, app, domain)
		cancel()

		if queryErr != nil && result == "" {
			return RDAPState{}, WrapError(MsgErrWHOISQueryFailed, queryErr)
		}

		if !isWHOISRateLimited(result, queryErr) {
			break
		}

		if attempts < 3 {
			backoff := time.Duration(attempts*2) * time.Second
			LogWarn(MsgLogWHOISRateLimitedRetry, FieldDomain, domain, FieldAttempt, attempts, FieldRetryIn, backoff)
			timer := time.NewTimer(backoff)
			select {
			case <-ctx.Done():
				timer.Stop()
				return RDAPState{}, ctx.Err()
			case <-timer.C:
			}
		} else {
			return RDAPState{}, ErrWHOISRateLimited
		}
	}

	durationMs := time.Since(start).Milliseconds()

	registryTier := extractWHOISTier(result, SourceRegistryWHOIS, SourceRegistry)
	var registrarTier *DomainTierData

	// Always follow referral server if present to guarantee cross-tier 2-tier ARGP detection
	if m := ReWHOISReferral.FindStringSubmatch(result); len(m) > 1 {
		referralServer := strings.TrimSpace(m[1])
		if referralServer != "" && !strings.Contains(referralServer, "iana") && !strings.Contains(referralServer, "internic") {
			if !isSafeWHOISServer(referralServer) {
				LogWarn(MsgLogSkippingUnsafeRDAP, FieldDomain, domain, FieldReferralServer, referralServer)
			} else {
				LogInfo(MsgLogFollowingWHOISReferral, FieldDomain, domain, FieldReferralServer, referralServer)
				refCtx, refCancel := context.WithTimeout(ctx, DefaultHTTPTimeout)
				defer refCancel()

				if refResult, err := queryWHOISWithContext(refCtx, app, domain, referralServer); err == nil && refResult != "" && !isDomainNotFoundInWHOIS(refResult) {
					registrarTier = extractWHOISTier(refResult, SourceRegistrarWHOIS, referralServer)
				}
			}
		}
	}

	state, _ := synthesizeTierData(registryTier, registrarTier)
	state.ProtocolUsed = ProtocolWHOIS
	state.QueryDurationMs = durationMs

	// Check for domain not registered
	if isDomainNotFoundInWHOIS(result) && state.Expiration == "" && len(state.Nameservers) == 0 {
		return RDAPState{}, ErrDomainNotFound
	}

	if state.Expiration == "" && state.Registrar == "" && len(state.Nameservers) == 0 && len(state.DomainStatus) == 0 {
		if queryErr != nil {
			return RDAPState{}, WrapError(MsgErrWHOISQueryFailed, queryErr)
		}
		return RDAPState{}, errors.New(MsgErrWHOISParsingFailed)
	}

	return state, nil
}

func validateRDAPState(app *AppState, target DomainConfig, parsed RDAPState) RDAPState {
	if target.Domain == "" || parsed.Status == "" {
		return parsed
	}
	parsed.AllowExpiry = target.AllowExpiry
	if parsed.Expiration != "" {
		if t, norm, err := parseFlexibleDate(parsed.Expiration); err == nil {
			parsed.Expiration = norm
			days := time.Until(t).Hours() / 24
			if days < 0 {
				parsed.Status = StatusFailed
				if !target.SuppressAlerts && !target.AllowExpiry {
					app.SafeDispatchf(PriorityUrgent, TagRotatingLight, target.Domain, target.Name, MsgRedactedRDAPExpired, MsgAlertRDAPExpired, target.Domain, math.Abs(days))
				}
			} else if days <= DefaultRDAPExpiryWarningDays {
				priority := PriorityWarning
				if days <= 7 {
					priority = PriorityUrgent
				}
				if parsed.Status == StatusOK {
					parsed.Status = StatusWarning
				}
				if !target.SuppressAlerts && !target.AllowExpiry {
					app.SafeDispatchf(priority, TagWarning, target.Domain, target.Name, fmt.Sprintf(MsgRedactedRDAPExpiring, int(days)), MsgAlertRDAPExpiry, target.Domain, days)
				}
			}
		}
	}

	validateDelegatedNameservers(app, target, parsed.Nameservers, &parsed)

	// Status & Suspension evaluation
	parsed.DomainStatus = NormalizeDomainStatuses(parsed.DomainStatus)
	if isSusp, suspStatus := isDomainSuspended(parsed.DomainStatus); isSusp {
		parsed.Status = StatusFailed
		if !target.SuppressAlerts {
			app.SafeDispatchf(PriorityUrgent, TagError, target.Domain, target.Name, fmt.Sprintf(MsgRedactedRDAPSuspended, suspStatus), MsgAlertRDAPSuspended, target.Domain, suspStatus)
		}
	}

	if target.DomainTransferLocked && !isTransferLocked(parsed.DomainStatus) {
		if parsed.Status == StatusOK {
			parsed.Status = StatusWarning
		}
		if !target.SuppressAlerts {
			app.SafeDispatchf(PriorityHigh, TagUnlock, target.Domain, target.Name, MsgRedactedRDAPUnlocked, MsgAlertRDAPUnlocked, target.Domain)
		}
	}

	// Registrar Validation: Both fields can be present in config.
	// Order of priority: expected_registrar_id (Priority 1) takes precedence over expected_registrar_name (Priority 2).
	// In evaluation, they are mutually exclusive: if expected_registrar_id is configured, it is evaluated and name is superseded.
	if target.ExpectedRegistrarID != "" {
		if parsed.RegistrarIANAID != target.ExpectedRegistrarID {
			parsed.Status = StatusFailed
			parsed.RegistrarMismatch = true
			parsed.ExpectedRegistrar = "IANA " + target.ExpectedRegistrarID
			if !target.SuppressAlerts {
				app.SafeDispatchf(PriorityUrgent, TagRotatingLight, target.Domain, target.Name, fmt.Sprintf(MsgRedactedRDAPRegistrarID, target.ExpectedRegistrarID), MsgAlertRDAPRegistrarIDMismatch, target.Domain, target.ExpectedRegistrarID, parsed.RegistrarIANAID)
			}
		}
	} else if target.ExpectedRegistrarName != "" {
		if !strings.Contains(strings.ToLower(parsed.Registrar), strings.ToLower(target.ExpectedRegistrarName)) {
			parsed.Status = StatusFailed
			parsed.RegistrarMismatch = true
			parsed.ExpectedRegistrar = target.ExpectedRegistrarName
			if !target.SuppressAlerts {
				app.SafeDispatchf(PriorityUrgent, TagRotatingLight, target.Domain, target.Name, fmt.Sprintf(MsgRedactedRDAPRegistrarName, target.ExpectedRegistrarName), MsgAlertRDAPRegistrarNameMismatch, target.Domain, target.ExpectedRegistrarName, parsed.Registrar)
			}
		}
	}

	// Report Hierarchy Discrepancies if detected
	for _, discrepancy := range parsed.Discrepancies {
		if !target.SuppressAlerts {
			app.SafeDispatchf(PriorityWarning, TagWarning, target.Domain, target.Name, discrepancy, MsgAlertRDAPDiscrepancy, target.Domain, discrepancy)
		}
	}

	if target.RenewalPrice > 0 {
		parsed.RenewalPrice = target.RenewalPrice
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

func evaluateNSDelegation(ctx context.Context, app *AppState, target DomainConfig) RDAPState {
	parsed := RDAPState{
		Status:          StatusOK,
		IsDelegatedZone: true,
		Source:          SourceDNSDelegation,
		AllowExpiry:     target.AllowExpiry,
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

	r, err := queryDNSMsgWithRDFn(ctx, app, target.Domain, dns.TypeNS, resolversToUse, rd)
	if err != nil {
		parsed.Status = StatusFailed
		parsed.Error = fmt.Sprintf(MsgErrFailedToQueryNSRecords, err.Error())
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

	validateDelegatedNameservers(app, target, parsed.Nameservers, &parsed)

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
			if !target.SuppressAlerts {
				app.SafeDispatchf(PriorityUrgent, TagSkull, target.Domain, target.Name, MsgRedactedRDAPUnauthorizedNS, MsgAlertRDAPUnauthorizedNS, target.Domain, ns)
			}
		}
	}

	for _, expectedRaw := range target.ExpectedNS {
		expected := NormalizeDomain(expectedRaw)
		if expected != "" && !liveNS[expected] {
			if parsed != nil {
				parsed.Status = StatusFailed
			}
			if !target.SuppressAlerts {
				app.SafeDispatchf(PriorityHigh, TagWarning, target.Domain, target.Name, MsgRedactedRDAPMissingNS, MsgAlertRDAPMissingNS, target.Domain, expectedRaw)
			}
		}
	}
}
