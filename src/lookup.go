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

	whoisparser "github.com/likexian/whois-parser"
	"github.com/miekg/dns"
)

// queryWHOISWithContext owns IANA discovery and the one TCP query it selects.
// fetchWHOIS owns the optional registrar referral.
func queryWHOISWithContext(ctx context.Context, app *AppState, domain string, host ...string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	asciiDomain := NormalizeDomainToASCIIText(domain)
	server := ""
	if len(host) > 0 {
		server = strings.TrimSpace(host[0])
	}
	if app != nil && app.WHOISClient != nil {
		response, err := app.WHOISClient.Query(ctx, asciiDomain, server)
		if err != nil {
			return response, fmt.Errorf("query WHOIS for %s through injected client: %w", asciiDomain, err)
		}
		return response, nil
	}
	if app == nil || app.WHOISDial == nil {
		return "", fmt.Errorf("WHOIS transport is not configured for %s", asciiDomain)
	}
	if server == "" {
		var err error
		server, err = discoverWHOISServer(ctx, app, asciiDomain)
		if err != nil {
			return "", err
		}
	}
	return queryWHOISServer(ctx, app, asciiDomain, server)
}

func discoverWHOISServer(ctx context.Context, app *AppState, domain string) (string, error) {
	if server := KnownWHOISServer(domain); server != "" {
		return server, nil
	}
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return "", fmt.Errorf("WHOIS domain %q has no top-level label", domain)
	}
	iana, err := queryWHOISServer(ctx, app, parts[len(parts)-1], WHOISIANAHost)
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(iana, "\n") {
		key, value, ok := strings.Cut(line, ":")
		if ok && (strings.EqualFold(strings.TrimSpace(key), WHOISIANAReferralField) || strings.EqualFold(strings.TrimSpace(key), WHOISIANAWHOISField)) {
			return strings.TrimSpace(value), nil
		}
	}
	return "", fmt.Errorf("IANA WHOIS response has no referral for %s", domain)
}

// dialPublicWHOIS resolves and validates each address before connecting. Dialing the
// validated IP prevents a DNS change between validation and connection.
func dialPublicWHOIS(ctx context.Context, host string) (net.Conn, error) {
	dialer := net.Dialer{Timeout: DefaultWHOISTimeout}
	return dialPublicWHOISWith(ctx, host, net.DefaultResolver.LookupIPAddr, dialer.DialContext)
}

// dialPublicWHOISWith keeps address validation and dialing together while
// allowing deterministic tests for DNS rebinding and connection failures.
func dialPublicWHOISWith(
	ctx context.Context,
	host string,
	lookup func(context.Context, string) ([]net.IPAddr, error),
	dial func(context.Context, string, string) (net.Conn, error),
) (net.Conn, error) {
	addresses, err := lookup(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("resolve WHOIS server %s: %w", host, err)
	}
	var lastErr error
	for _, address := range addresses {
		if address.IP == nil || IsRestrictedIP(address.IP) {
			continue
		}
		conn, err := dial(ctx, "tcp", net.JoinHostPort(address.IP.String(), WHOISPort))
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	if lastErr != nil {
		return nil, fmt.Errorf("connect to WHOIS server %s: %w", host, lastErr)
	}
	return nil, fmt.Errorf("WHOIS server %s has no permitted public address", host)
}

func queryWHOISServer(ctx context.Context, app *AppState, domain, server string) (string, error) {
	server = canonicalWHOISServer(server)
	if !isSafeWHOISServer(server) {
		return "", fmt.Errorf("unsafe WHOIS server: %q", server)
	}
	if app != nil && app.RDAPLimiter != nil {
		if err := app.RDAPLimiter.Wait(ctx); err != nil {
			return "", fmt.Errorf("wait for WHOIS request to %s: %w", server, err)
		}
	}
	query := whoisQueryText(domain, server)
	if strings.ContainsAny(query, "\r\n") {
		return "", fmt.Errorf("invalid WHOIS query for %s", domain)
	}
	if app == nil || app.WHOISDial == nil {
		return "", fmt.Errorf("WHOIS transport is not configured for %s", domain)
	}
	conn, err := app.WHOISDial(ctx, server)
	if err != nil {
		return "", fmt.Errorf("connect to WHOIS server %s: %w", server, err)
	}
	defer func() { _ = conn.Close() }()
	return exchangeWHOIS(ctx, conn, query, domain, server)
}

func canonicalWHOISServer(server string) string {
	switch server {
	case WHOISGoDaddyAlias:
		return WHOISGoDaddyHost
	case WHOISPorkbunAlias:
		return WHOISPorkbunHost
	default:
		return server
	}
}

func whoisQueryText(domain, server string) string {
	if server == WHOISARINHost {
		return WHOISARINPrefix + domain
	}
	return domain
}

func exchangeWHOIS(ctx context.Context, conn net.Conn, query, domain, server string) (string, error) {
	deadline := time.Now().Add(DefaultWHOISTimeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return "", fmt.Errorf("set WHOIS deadline for %s: %w", server, err)
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	if _, err := io.WriteString(conn, query+"\r\n"); err != nil {
		return "", fmt.Errorf("write WHOIS query for %s to %s: %w", domain, server, err)
	}
	data, err := io.ReadAll(io.LimitReader(conn, MaxWHOISResponseBytes+1))
	if ctx.Err() != nil {
		return "", ctx.Err()
	}
	if err != nil {
		return "", fmt.Errorf("read WHOIS response for %s from %s: %w", domain, server, err)
	}
	if len(data) > MaxWHOISResponseBytes {
		return "", fmt.Errorf("WHOIS response for %s exceeds %d bytes", domain, MaxWHOISResponseBytes)
	}
	return strings.TrimSpace(string(data)), nil
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

	// Strip parenthesis notes like "(server-managed)"
	if before, _, found := strings.Cut(s, "("); found {
		s = strings.TrimSpace(before)
	}

	// Strip any full URL tokens (e.g., "https://...", "http://...")
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

	// Explicit status text takes precedence over documentation links.
	// Map known multi-word, hyphenated, or camelCase EPP / RDAP status strings to canonical format
	cleanKey := NormalizeStatusToken(s)
	if canon, ok := EPPStatusMap[cleanKey]; ok {
		return unique.Make(canon).Value()
	}

	if len(nonURLFields) > 0 {
		return unique.Make(s).Value()
	}

	// A URL-only status may identify its token with an anchor (e.g., "https://icann.org/epp#clientTransferProhibited"
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

// classifyEPPStatus keeps protocol decisions numeric without discarding extension text.
func classifyEPPStatus(status string) EPPCode {
	key := NormalizeStatusToken(status)
	for code := EPPOK; code <= EPPHold; code++ {
		if key == eppCodeKeys[code] {
			return code
		}
	}
	return EPPUnknown
}

func isTransferLocked(statuses []string) bool {
	for _, s := range statuses {
		switch classifyEPPStatus(s) {
		case EPPClientTransferProhibited, EPPServerTransferProhibited, EPPTransferProhibited:
			return true
		}
		// Preserve explicit registrar aliases, without matching arbitrary extension substrings.
		key := NormalizeStatusToken(s)
		if key == "prohibittransfer" || key == "transferlock" {
			return true
		}
	}
	return false
}

func isDomainSuspended(statuses []string) (bool, string) {
	for _, s := range statuses {
		switch classifyEPPStatus(s) {
		case EPPServerHold, EPPClientHold, EPPPendingDelete, EPPRedemptionPeriod, EPPInactive, EPPHold:
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
		switch {
		case strings.Contains(action, "expiration"):
			if _, norm, err := parseFlexibleDate(event.Date); err == nil {
				tier.Expiration = norm
			} else {
				tier.Expiration = event.Date
			}
		case strings.Contains(action, "registration") || strings.Contains(action, "created"):
			if _, norm, err := parseFlexibleDate(event.Date); err == nil {
				tier.Created = norm
			} else {
				tier.Created = event.Date
			}
		case strings.Contains(action, "last changed") || strings.Contains(action, "last modified") || strings.Contains(action, "updated"):
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
			if isWHOISDNSSECSigned(val) {
				tier.DNSSEC = true
			}
		}
	}

	return tier
}

func isWHOISDNSSECSigned(value string) bool {
	switch value {
	case WHOISDNSSECSigned, WHOISDNSSECYes, WHOISDNSSECActive, WHOISDNSSECTrue:
		return true
	default:
		return false
	}
}

// synthesizeTierData merges RegistryTier and RegistrarTier into a coherent RDAPSnapshot,
// detecting hierarchy discrepancies like Auto-Renew Grace Period date mismatch and NS desync.
func synthesizeTierData(registry *DomainTierData, registrar *DomainTierData) (RDAPSnapshot, []string) {
	if registry == nil && registrar == nil {
		return RDAPSnapshot{
			Err: errors.New(MsgErrNoTierData),
		}, nil
	}
	state := RDAPSnapshot{
		RegistryTier:  registry,
		RegistrarTier: registrar,
	}

	var discrepancies []string

	// 1. Synthesize Source
	switch {
	case registry != nil && registrar != nil:
		state.Source = registry.Source + "+" + registrar.Source
	case registry != nil:
		state.Source = registry.Source
	case registrar != nil:
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
	switch {
	case registry != nil && registry.Expiration != "" && registrar != nil && registrar.Expiration != "":
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
	case registry != nil && registry.Expiration != "":
		state.Expiration = registry.Expiration
	case registrar != nil && registrar.Expiration != "":
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

// FetchRDAPSnapshot fetches raw registry data via RDAP, falling back to WHOIS.
// Returns raw data only — no business logic, no alerting.
func FetchRDAPSnapshot(ctx context.Context, httpClient HTTPDoer, app *AppState, domain string) RDAPSnapshot {
	snapshot, err := fetchRDAP(ctx, httpClient, app, domain)
	if err != nil {
		return fallbackWHOISSnapshot(ctx, app, domain, err)
	}
	if snapshot.Err == nil && snapshot.RegistrarTier == nil && (snapshot.Expiration == "" || snapshot.Registrar == "") {
		snapshot = supplementThinRDAP(ctx, app, domain, snapshot)
	}
	return snapshot
}

func fallbackWHOISSnapshot(ctx context.Context, app *AppState, domain string, rdapErr error) RDAPSnapshot {
	if errors.Is(rdapErr, ErrRDAPNotFound) {
		LogInfo(MsgLogRDAPReturned404, FieldDomain, domain)
	} else if errors.Is(rdapErr, ErrRDAPRateLimited) {
		LogWarn(MsgLogRDAPRateLimited, FieldDomain, domain)
	} else {
		LogInfof(MsgLogWHOISFallback, domain)
	}
	whoisSnapshot, whoisErr := fetchWHOIS(ctx, app, domain)
	if whoisErr == nil {
		LogInfof(MsgLogWHOISSuccess, domain)
		return whoisSnapshot
	}
	if errors.Is(whoisErr, ErrDomainNotFound) {
		LogInfo(MsgLogWHOISUnregistered, FieldDomain, domain)
		return RDAPSnapshot{Source: SourceWHOIS404, ProtocolUsed: ProtocolWHOIS, Err: ErrDomainNotFound}
	}
	LogErrorf(MsgLogWHOISFailed, domain, whoisErr)
	return RDAPSnapshot{ProtocolUsed: ProtocolWHOISFailed, Err: fmt.Errorf(MsgErrRDAPAndWHOIS, rdapErr, whoisErr)}
}

func supplementThinRDAP(ctx context.Context, app *AppState, domain string, snapshot RDAPSnapshot) RDAPSnapshot {
	whoisSnapshot, whoisErr := fetchWHOIS(ctx, app, domain)
	if whoisErr != nil {
		return snapshot
	}
	if whoisSnapshot.RegistrarTier != nil {
		snapshot.RegistrarTier = whoisSnapshot.RegistrarTier
	} else if whoisSnapshot.RegistryTier != nil && snapshot.RegistryTier == nil {
		snapshot.RegistryTier = whoisSnapshot.RegistryTier
	}
	synthesized, discrepancies := synthesizeTierData(snapshot.RegistryTier, snapshot.RegistrarTier)
	if snapshot.Expiration == "" {
		snapshot.Expiration = firstNonEmptyString(synthesized.Expiration, whoisSnapshot.Expiration)
	}
	if snapshot.Registrar == "" {
		snapshot.Registrar = firstNonEmptyString(synthesized.Registrar, whoisSnapshot.Registrar)
	}
	if snapshot.RegistrarIANAID == "" {
		snapshot.RegistrarIANAID = firstNonEmptyString(synthesized.RegistrarIANAID, whoisSnapshot.RegistrarIANAID)
	}
	if len(snapshot.Nameservers) == 0 {
		snapshot.Nameservers = firstNonEmptyStrings(synthesized.Nameservers, whoisSnapshot.Nameservers)
	}
	if len(snapshot.DomainStatus) == 0 {
		snapshot.DomainStatus = firstNonEmptyStrings(synthesized.DomainStatus, whoisSnapshot.DomainStatus)
	}
	if !snapshot.DNSSEC {
		snapshot.DNSSEC = synthesized.DNSSEC || whoisSnapshot.DNSSEC
	}
	snapshot.Discrepancies = discrepancies
	snapshot.Source = supplementedRDAPSource(synthesized.Source, snapshot.RegistryTier, whoisSnapshot)
	snapshot.ProtocolUsed = ProtocolHybrid
	return snapshot
}

func supplementedRDAPSource(source string, registry *DomainTierData, whois RDAPSnapshot) string {
	if whois.RegistrarTier == nil && whois.RegistryTier != nil && registry != whois.RegistryTier {
		return source + "+" + whois.Source
	}
	return source
}

func firstNonEmptyString(primary, fallback string) string {
	if primary != "" {
		return primary
	}
	return fallback
}

func firstNonEmptyStrings(primary, fallback []string) []string {
	if len(primary) > 0 {
		return primary
	}
	return fallback
}

// EvaluateRDAP compares expected config against fetched RDAP snapshot.
// Pure CPU — no network calls, no alerting.
// Returns (CheckStatus, *StateCondition).
func EvaluateRDAP(target DomainConfig, snapshot RDAPSnapshot) (CheckStatus, *StateCondition) {
	if target.Domain == "" {
		return StatusPending, nil
	}

	if snapshot.Err != nil {
		if errors.Is(snapshot.Err, ErrDomainNotFound) {
			return StatusFailed, &StateCondition{Code: CodeDomainNotFound}
		}

		errStr := snapshot.Err.Error()
		if strings.Contains(errStr, "connection refused") || strings.Contains(errStr, "i/o timeout") || strings.Contains(errStr, "no such host") || strings.Contains(errStr, "temporary failure") || isWHOISRateLimited(errStr, snapshot.Err) || errors.Is(snapshot.Err, ErrWHOISRateLimited) {
			return StatusWarning, &StateCondition{Code: CodeRDAPHTTPError}
		}

		return StatusFailed, &StateCondition{Code: CodeRDAPHTTPError}
	}

	ct := ConditionTracker{Status: StatusOK}

	// 1. Checks expiration
	if !target.AllowExpiry {
		if t, _, err := parseFlexibleDate(snapshot.Expiration); err == nil {
			days := time.Until(t).Hours() / 24
			if days < 0 {
				ct.Promote(StatusFailed, CodeRDAPExpired, "")
			} else if days <= DefaultRDAPExpiryWarningDays {
				priority := StatusWarning
				if days <= 7 {
					priority = StatusFailed
				}
				ct.Promote(priority, CodeRDAPExpiringSoon, "")
			}
		} else {
			ct.Promote(StatusFailed, CodeRDAPExpiryUnavailable, snapshot.Expiration)
		}
	}

	// 2. Checks NS delegation
	if len(target.ExpectedNS) > 0 {
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

		for _, raw := range snapshot.Nameservers {
			ns := NormalizeDomain(raw)
			if ns == "" {
				continue
			}
			liveNS[ns] = true
			if !authorizedMap[ns] {
				ct.Promote(StatusFailed, CodeUnauthorizedNS, ns)
			}
		}

		for _, expectedRaw := range target.ExpectedNS {
			expected := NormalizeDomain(expectedRaw)
			if expected != "" && !liveNS[expected] {
				ct.Promote(StatusFailed, CodeExpectedNSMissing, expectedRaw)
			}
		}
	}

	// 3. Checks EPP statuses
	if isSusp, suspStatus := isDomainSuspended(snapshot.DomainStatus); isSusp {
		code := CodeRDAPSuspended
		switch classifyEPPStatus(suspStatus) {
		case EPPServerHold:
			code = CodeEPPServerHold
		case EPPClientHold:
			code = CodeEPPClientHold
		case EPPPendingDelete:
			code = CodeEPPPendingDelete
		case EPPRedemptionPeriod:
			code = CodeEPPRedemptionPeriod
		case EPPInactive:
			code = CodeEPPInactive
		}
		ct.Promote(StatusFailed, code, "")
	}

	// 4. Checks transfer lock
	if target.DomainTransferLocked && !isTransferLocked(snapshot.DomainStatus) {
		ct.Promote(StatusWarning, CodeRDAPTransferUnlocked, "")
	}

	// 5. Checks registrar match
	if target.ExpectedRegistrarID != "" {
		if snapshot.RegistrarIANAID != target.ExpectedRegistrarID {
			ct.Promote(StatusFailed, CodeRDAPRegistrarMismatch, "IANA "+target.ExpectedRegistrarID)
		}
	} else if target.ExpectedRegistrarName != "" {
		if !strings.Contains(strings.ToLower(snapshot.Registrar), strings.ToLower(target.ExpectedRegistrarName)) {
			ct.Promote(StatusFailed, CodeRDAPRegistrarMismatch, target.ExpectedRegistrarName)
		}
	}

	if ct.Cond == nil {
		ct.Cond = &StateCondition{Code: CodeRDAPSuccess}
	}
	return ct.Status, ct.Cond
}

func fetchRDAP(ctx context.Context, httpClient HTTPDoer, app *AppState, domain string) (RDAPSnapshot, error) {
	start := time.Now()
	asciiDomain := NormalizeDomainToASCIIText(domain)
	urls, err := rdapServersFor(ctx, app, asciiDomain)
	if err != nil {
		return RDAPSnapshot{}, err
	}

	httpClient = resolveRDAPClient(httpClient, app)
	if httpClient == nil {
		return RDAPSnapshot{}, fmt.Errorf("RDAP HTTP client is not configured for %s", asciiDomain)
	}

	var lastErr error
	for _, rawBaseURL := range urls {
		baseURL := strings.TrimRight(rawBaseURL, "/")
		reqURL := baseURL + PathRDAPDomain + asciiDomain
		if !rdapURLAllowed(app, reqURL) {
			lastErr = fmt.Errorf("unsafe RDAP URL: %q", reqURL)
			continue
		}
		// #nosec G704 -- rdapURLAllowed rejects unsafe hosts immediately above.
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
		if err != nil {
			lastErr = err
			continue
		}
		req.Header.Set(HeaderAccept, AcceptRDAP)
		req.Header.Set(HeaderUserAgent, DefaultUserAgent)
		if app.RDAPLimiter != nil {
			if err := app.RDAPLimiter.Wait(ctx); err != nil {
				return RDAPSnapshot{}, err
			}
		}

		resp, err := httpClient.Do(req)
		if err != nil {
			lastErr = err
			continue
		}

		domainInfo, err := readRDAPDomainResponse(resp)
		if errors.Is(err, ErrRDAPNotFound) || errors.Is(err, ErrRDAPRateLimited) {
			return RDAPSnapshot{}, err
		}
		if err != nil {
			lastErr = err
			continue
		}
		if err := validateRDAPDomainIdentity(domainInfo, asciiDomain); err != nil {
			lastErr = err
			continue
		}

		registryTier := extractRDAPDomainTier(domainInfo, SourceRegistryRDAP, baseURL)

		var registrarTier *DomainTierData

		// 1. Follow Registrar RDAP Referral Links (scans both domain links and nested entity links)
		referralLinks := collectRDAPReferralLinks(domainInfo, baseURL)
		if relDomain := followRegistrarRDAPLinks(ctx, asciiDomain, referralLinks, httpClient, app); relDomain != nil {
			registrarTier = extractRDAPDomainTier(relDomain, SourceRegistrarRDAP, SourceReferral)
		}

		// 2. Synthesize 2-Tier State
		state, _ := synthesizeTierData(registryTier, registrarTier)
		state.ProtocolUsed = ProtocolRDAP
		state.QueryDurationMs = time.Since(start).Milliseconds()
		return state, nil
	}

	if lastErr != nil {
		return RDAPSnapshot{}, lastErr
	}
	return RDAPSnapshot{}, fmt.Errorf("RDAP lookup for %s: %s", asciiDomain, MsgErrRDAPLookupFailedAllCandidates)
}

func rdapServersFor(ctx context.Context, app *AppState, domain string) ([]string, error) {
	if app == nil || app.Bootstrap == nil {
		return nil, fmt.Errorf("RDAP bootstrap is unavailable for %s", domain)
	}
	servers, err := app.Bootstrap.ServersFor(ctx, domain)
	if err != nil {
		return nil, WrapError(MsgErrNoRDAPServer, err)
	}
	return servers, nil
}

func resolveRDAPClient(client HTTPDoer, app *AppState) HTTPDoer {
	if client != nil {
		return client
	}
	if app != nil {
		return app.HTTPClient
	}
	return nil
}

func readRDAPDomainResponse(response *http.Response) (*RDAPDomainResponse, error) {
	defer DrainAndClose(response.Body, MaxBodyDrainSize)
	switch response.StatusCode {
	case http.StatusNotFound:
		return nil, ErrRDAPNotFound
	case http.StatusTooManyRequests:
		return nil, ErrRDAPRateLimited
	case http.StatusOK:
	default:
		return nil, fmt.Errorf(MsgErrRDAPHTTPError, response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, MaxBootstrapResponseSize+1))
	if err != nil {
		return nil, fmt.Errorf("read RDAP response: %w", err)
	}
	if len(body) > MaxBootstrapResponseSize {
		return nil, fmt.Errorf("RDAP response exceeds %d bytes", MaxBootstrapResponseSize)
	}
	var domain RDAPDomainResponse
	if err := jsonv2.Unmarshal(body, &domain); err != nil {
		return nil, fmt.Errorf("parse RDAP response: %w", err)
	}
	return &domain, nil
}

func validateRDAPDomainIdentity(response *RDAPDomainResponse, expected string) error {
	if response == nil || response.ObjectClassName != RDAPObjectClassDomain {
		return fmt.Errorf("RDAP response for %s is not a domain object", expected)
	}
	if response.LDHName == "" && response.UnicodeName == "" {
		return fmt.Errorf("RDAP response for %s has no domain name", expected)
	}
	for _, name := range []string{response.LDHName, response.UnicodeName} {
		if name != "" && NormalizeDomainToASCIIText(name) != expected {
			return fmt.Errorf("RDAP response domain %q does not match requested %s", name, expected)
		}
	}
	return nil
}

// IsSafeRDAPURL validates that candidate registrar RDAP referral URLs are safe to query,
// blocking loopback, private, link-local, multicast, and cloud metadata destinations (RFC 7480 Section 5.3).
func IsSafeRDAPURL(rawURL string) bool {
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
	host := strings.TrimRight(strings.ToLower(u.Hostname()), ".")
	if host == "" || host == "localhost" || strings.Contains(host, "%") || strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".internal") {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		if IsRestrictedIP(ip) {
			return false
		}
	}
	return true
}

func rdapURLAllowed(app *AppState, target string) bool {
	if app != nil && app.RDAPURLAllowed != nil {
		return app.RDAPURLAllowed(target)
	}
	return IsSafeRDAPURL(target)
}

// isSafeWHOISServer validates that a WHOIS referral server address is safe to query,
// preventing SSRF against loopback, private, link-local, multicast, or cloud metadata endpoints.
func isSafeWHOISServer(server string) bool {
	clean := strings.TrimSpace(server)
	if clean == "" || strings.ContainsAny(clean, "/:@?#\\ ") {
		return false
	}
	host := strings.ToLower(clean)
	if host == "" || host == "localhost" || strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".internal") {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		return !IsRestrictedIP(ip)
	}
	return ReValidDomain.MatchString(host)
}

func followRegistrarRDAPLinks(ctx context.Context, domain string, links []string, client HTTPDoer, apps ...*AppState) *RDAPDomainResponse {
	policyApp := firstApp(apps)
	httpClient := resolveRDAPClient(client, policyApp)
	if httpClient == nil {
		return nil
	}

	for _, rawHref := range links {
		targetURL := registrarRDAPURL(rawHref, domain)
		if targetURL == "" {
			continue
		}
		if !rdapURLAllowed(policyApp, targetURL) {
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
		if policyApp != nil && policyApp.RDAPLimiter != nil {
			if err := policyApp.RDAPLimiter.Wait(ctx); err != nil {
				return nil
			}
		}

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

		relDomain, err := readRegistrarRDAPResponse(relResp)
		if err != nil {
			LogWarn(MsgLogRegistrarReferralInvalid, FieldURL, targetURL, FieldError, err)
			continue
		}
		if err := validateRDAPDomainIdentity(relDomain, NormalizeDomainToASCIIText(domain)); err != nil {
			LogWarn(MsgLogRegistrarReferralInvalid, FieldURL, targetURL, FieldError, err)
			continue
		}
		return relDomain
	}
	return nil
}

func firstApp(apps []*AppState) *AppState {
	if len(apps) == 0 {
		return nil
	}
	return apps[0]
}

func readRegistrarRDAPResponse(response *http.Response) (*RDAPDomainResponse, error) {
	body, err := io.ReadAll(io.LimitReader(response.Body, MaxBootstrapResponseSize+1))
	DrainAndClose(response.Body, MaxBodyDrainSize)
	if err != nil {
		return nil, fmt.Errorf("read registrar RDAP referral: %w", err)
	}
	if len(body) > MaxBootstrapResponseSize {
		return nil, fmt.Errorf("registrar RDAP response exceeds %d bytes", MaxBootstrapResponseSize)
	}
	var domain RDAPDomainResponse
	if err := jsonv2.Unmarshal(body, &domain); err != nil {
		return nil, fmt.Errorf("parse registrar RDAP referral: %w", err)
	}
	return &domain, nil
}

func registrarRDAPURL(rawHref, domain string) string {
	href := strings.TrimSpace(rawHref)
	if href == "" {
		return ""
	}
	if u, err := url.Parse(href); err == nil {
		if !strings.Contains(u.Path, PathRDAPDomain) {
			u.Path = strings.TrimRight(u.Path, "/") + PathRDAPDomain + domain
		}
		return u.String()
	}
	if !strings.Contains(href, PathRDAPDomain) {
		return strings.TrimRight(href, "/") + PathRDAPDomain + domain
	}
	return href
}

func fetchWHOIS(ctx context.Context, app *AppState, domain string) (RDAPSnapshot, error) {
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
			return RDAPSnapshot{}, WrapError(MsgErrWHOISQueryFailed, queryErr)
		}

		if !isWHOISRateLimited(result, queryErr) {
			if queryErr != nil {
				return RDAPSnapshot{}, WrapError(MsgErrWHOISQueryFailed, queryErr)
			}
			break
		}

		if attempts < 3 {
			backoff := time.Duration(attempts*2) * time.Second
			LogWarn(MsgLogWHOISRateLimitedRetry, FieldDomain, domain, FieldAttempt, attempts, FieldRetryIn, backoff)
			timer := time.NewTimer(backoff)
			select {
			case <-ctx.Done():
				timer.Stop()
				return RDAPSnapshot{}, ctx.Err()
			case <-timer.C:
			}
		} else {
			return RDAPSnapshot{}, ErrWHOISRateLimited
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
		return RDAPSnapshot{}, ErrDomainNotFound
	}

	if state.Expiration == "" && state.Registrar == "" && len(state.Nameservers) == 0 && len(state.DomainStatus) == 0 {
		if queryErr != nil {
			return RDAPSnapshot{}, WrapError(MsgErrWHOISQueryFailed, queryErr)
		}
		return RDAPSnapshot{}, errors.New(MsgErrWHOISParsingFailed)
	}

	return state, nil
}

func resolveRootZoneResolvers(ctx context.Context, app *AppState, rootZone string, globalResolvers []string) []string {
	rootNS, err := queryDNS(ctx, app, rootZone, dns.TypeNS, globalResolvers)
	if err != nil || len(rootNS) == 0 {
		return nil
	}
	var rootIPs []string
	for _, ns := range rootNS {
		ips, err := queryIPRecords(ctx, app, ns, globalResolvers)
		if err != nil {
			LogWarn("partial parent nameserver address lookup", FieldDomain, ns, FieldError, err)
		}
		rootIPs = append(rootIPs, ips...)
	}
	return rootIPs
}

func FetchNSDelegationSnapshot(ctx context.Context, app *AppState, target DomainConfig) NSDelegationSnapshot {
	var snapshot NSDelegationSnapshot

	resolversToUse := app.resolvers()
	rd := true
	if target.RootZone != "" {
		rootIPs := resolveRootZoneResolvers(ctx, app, target.RootZone, app.resolvers())
		if len(rootIPs) == 0 {
			snapshot.Err = fmt.Errorf("parent nameservers for %s have no usable address", target.RootZone)
			return snapshot
		}
		resolversToUse = rootIPs
		rd = false // Querying parent authoritative nameservers directly
	}

	r, err := queryDNSMsgWithRD(ctx, app, target.Domain, dns.TypeNS, resolversToUse, rd)
	if err != nil {
		snapshot.Err = fmt.Errorf("failed to query NS records: %w", err)
		return snapshot
	}

	var nsRecords []string
	if r != nil {
		fqdn := dns.Fqdn(target.Domain)
		for _, ans := range r.Answer {
			if ns, ok := ans.(*dns.NS); ok && ns.Hdr.Class == dns.ClassINET && strings.EqualFold(ns.Header().Name, fqdn) {
				nsRecords = append(nsRecords, ns.Ns)
			}
		}

		if len(nsRecords) == 0 {
			for _, auth := range r.Ns {
				if ns, ok := auth.(*dns.NS); ok && ns.Hdr.Class == dns.ClassINET && strings.EqualFold(ns.Header().Name, fqdn) {
					nsRecords = append(nsRecords, ns.Ns)
				}
			}
		}
	}

	for _, ns := range nsRecords {
		snapshot.Nameservers = append(snapshot.Nameservers, NormalizeDomain(ns))
	}

	return snapshot
}

func EvaluateNSDelegation(target DomainConfig, snapshot NSDelegationSnapshot) (CheckStatus, *StateCondition) {
	if snapshot.Err != nil {
		return StatusFailed, &StateCondition{Code: CodeDNSLookupFailed, Target: snapshot.Err.Error()}
	}
	if len(snapshot.Nameservers) == 0 {
		return StatusFailed, &StateCondition{Code: CodeDNSLookupFailed, Target: "delegation returned no nameservers"}
	}

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

	ct := ConditionTracker{Status: StatusOK}

	for _, raw := range snapshot.Nameservers {
		ns := NormalizeDomain(raw)
		if ns == "" {
			continue
		}
		liveNS[ns] = true
		if hasConfiguredNS && !authorizedMap[ns] {
			ct.Promote(StatusFailed, CodeUnauthorizedNS, ns)
		}
	}

	for _, expectedRaw := range target.ExpectedNS {
		expected := NormalizeDomain(expectedRaw)
		if expected != "" && !liveNS[expected] {
			ct.Promote(StatusFailed, CodeExpectedNSMissing, expectedRaw)
		}
	}

	return ct.Status, ct.Cond
}
