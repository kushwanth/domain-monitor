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
	"strconv"
	"strings"
	"time"
	"unique"

	whoisparser "github.com/likexian/whois-parser"
	"github.com/miekg/dns"
)

// queryWHOISWithContext owns IANA discovery and the one TCP query it selects.
// fetchWHOIS owns the optional registrar referral.
func queryWHOISWithContext(ctx context.Context, app *AppState, domain, server string) (string, error) {
	if err := ctx.Err(); err != nil {
		return StrEmpty, err
	}
	asciiDomain := NormalizeDomainToASCIIText(domain)
	server = strings.TrimSpace(server)
	if app != nil && app.WHOISClient != nil {
		response, err := app.WHOISClient.Query(ctx, asciiDomain, server)
		if err != nil {
			return response, fmt.Errorf(MsgErrQueryWHOISForThroughInjected, asciiDomain, err)
		}
		return response, nil
	}
	if app == nil || app.WHOISDial == nil {
		return StrEmpty, fmt.Errorf(MsgErrWHOISTransportIsNotConfigured, asciiDomain)
	}
	if server == StrEmpty {
		var err error
		server, err = discoverWHOISServer(ctx, app, asciiDomain)
		if err != nil {
			return StrEmpty, err
		}
	}
	return queryWHOISServer(ctx, app, asciiDomain, server)
}

func discoverWHOISServer(ctx context.Context, app *AppState, domain string) (string, error) {
	if server := KnownWHOISServer(domain); server != StrEmpty {
		return server, nil
	}
	idx := strings.LastIndexByte(domain, '.')
	if idx == -1 || idx == len(domain)-1 {
		return StrEmpty, fmt.Errorf(MsgErrWHOISDomainHasNoToplevel, domain)
	}
	iana, err := queryWHOISServer(ctx, app, domain[idx+1:], WHOISIANAHost)
	if err != nil {
		return StrEmpty, err
	}
	rem := iana
	for len(rem) > 0 {
		var line string
		idx := strings.IndexByte(rem, '\n')
		if idx >= 0 {
			line = rem[:idx]
			rem = rem[idx+1:]
		} else {
			line = rem
			rem = ""
		}
		key, value, ok := strings.Cut(line, SymColon)
		if ok && (strings.EqualFold(strings.TrimSpace(key), WHOISIANAReferralField) || strings.EqualFold(strings.TrimSpace(key), WHOISIANAWHOISField)) {
			return strings.TrimSpace(value), nil
		}
	}
	return StrEmpty, fmt.Errorf(MsgErrIANAWHOISResponseHasNo, domain)
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
		return nil, fmt.Errorf(MsgErrResolveWHOISServer, host, err)
	}
	var lastErr error
	attempts := 0
	for _, address := range addresses {
		if address.IP == nil || IsRestrictedIP(address.IP) {
			continue
		}
		if attempts == MaxNetworkAttempts {
			break
		}
		attempts++
		conn, err := dial(ctx, StrTCP, net.JoinHostPort(address.IP.String(), WHOISPort))
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	if lastErr != nil {
		return nil, fmt.Errorf(MsgErrConnectToWHOISServer, host, lastErr)
	}
	return nil, fmt.Errorf(MsgErrWHOISServerHasNoPermitted, host)
}

func queryWHOISServer(ctx context.Context, app *AppState, domain, server string) (string, error) {
	server = canonicalWHOISServer(server)
	if !isSafeWHOISServer(server) {
		return StrEmpty, fmt.Errorf(MsgErrUnsafeWHOISServer, server)
	}
	if app != nil && app.RDAPLimiter != nil {
		if err := app.RDAPLimiter.Wait(ctx); err != nil {
			return StrEmpty, fmt.Errorf(MsgErrWaitForWHOISRequestTo, server, err)
		}
	}
	query := whoisQueryText(domain, server)
	if strings.ContainsAny(query, StrRN) {
		return StrEmpty, fmt.Errorf(MsgErrInvalidWHOISQueryFor, domain)
	}
	if app == nil || app.WHOISDial == nil {
		return StrEmpty, fmt.Errorf(MsgErrWHOISTransportIsNotConfigured, domain)
	}
	conn, err := app.WHOISDial(ctx, server)
	if err != nil {
		return StrEmpty, fmt.Errorf(MsgErrConnectToWHOISServer, server, err)
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
		return StrEmpty, fmt.Errorf(MsgErrSetWHOISDeadlineFor, server, err)
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	if _, err := io.WriteString(conn, query+StrRN); err != nil {
		return StrEmpty, fmt.Errorf(MsgErrWriteWHOISQueryForTo, domain, server, err)
	}
	data, err := readBounded(conn, MaxWHOISResponseBytes)
	if ctx.Err() != nil {
		return StrEmpty, ctx.Err()
	}
	if errors.Is(err, ErrReadLimitExceeded) {
		return StrEmpty, fmt.Errorf(MsgErrWHOISResponseForExceedsBytes, domain, MaxWHOISResponseBytes)
	}
	if err != nil {
		return StrEmpty, fmt.Errorf(MsgErrReadWHOISResponseForFrom, domain, server, err)
	}
	return strings.TrimSpace(string(data)), nil
}

// parseFlexibleDate parses dates from diverse global registry/registrar formats and converts them to UTC RFC3339.
func parseFlexibleDate(dateStr string) (time.Time, string, error) {
	clean := strings.TrimSpace(dateStr)
	if clean == StrEmpty {
		return time.Time{}, StrEmpty, ErrEmptyDate
	}

	// Remove common leading prefixes like "Expires on:", "Renewal:", etc.
	if prefix, after, found := strings.Cut(clean, SymColon); found && !strings.Contains(prefix, StrT) {
		prefixLower := strings.ToLower(prefix)
		if strings.Contains(prefixLower, StrExpire) || strings.Contains(prefixLower, StrDate) || strings.Contains(prefixLower, StrValid) {
			clean = strings.TrimSpace(after)
		}
	}

	// Remove trailing parenthetical notes like "(UTC)", "(YYYY-MM-DD)", etc.
	if before, _, found := strings.Cut(clean, SymParenOpen); found {
		clean = strings.TrimSpace(before)
	}
	clean = strings.Trim(clean, SymQuoteSpace)

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

	return time.Time{}, StrEmpty, fmt.Errorf(MsgErrUnableToParseDate, dateStr)
}

// normalizeEPPStatus extracts canonical EPP status token from raw status strings.
func normalizeEPPStatus(raw string) string {
	s := strings.TrimSpace(raw)
	if s == StrEmpty {
		return StrEmpty
	}

	// Strip parenthesis notes like "(server-managed)"
	if before, _, found := strings.Cut(s, SymParenOpen); found {
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
		s = strings.Join(nonURLFields, SymSpace)
	}

	s = strings.TrimSpace(s)
	if s == StrEmpty {
		return StrEmpty
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
	if _, tokenRaw, found := strings.CutLast(s, SymHash); found {
		token := strings.TrimSpace(tokenRaw)
		token = strings.TrimRight(token, StrTRN)
		if token != StrEmpty && !strings.Contains(token, SymSlash) && !strings.Contains(token, SymSpace) {
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
		if norm != StrEmpty {
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
		case StrTransferprohibited:
			if seen[StrClienttransferprohibited] || seen[StrServertransferprohibited] {
				continue
			}
		case StrDeleteprohibited:
			if seen[StrClientdeleteprohibited] || seen[StrServerdeleteprohibited] {
				continue
			}
		case StrUpdateprohibited:
			if seen[StrClientupdateprohibited] || seen[StrServerupdateprohibited] {
				continue
			}
		case StrRenewprohibited:
			if seen[StrClientrenewprohibited] || seen[StrServerrenewprohibited] {
				continue
			}
		case StrHold:
			if seen[StrClienthold] || seen[StrServerhold] {
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
		if key == StrProhibittransfer || key == StrTransferlock {
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
	return false, StrEmpty
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
		if strings.Contains(errLower, StrLimit) || strings.Contains(errLower, StrQuota) || strings.Contains(errLower, StrTooMany) {
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
		return StrEmpty
	}
	switch v := val.(type) {
	case string:
		return strings.TrimSpace(v)
	case []any:
		var parts []string
		for _, item := range v {
			if s, ok := item.(string); ok && strings.TrimSpace(s) != StrEmpty {
				parts = append(parts, strings.TrimSpace(s))
			}
		}
		return strings.TrimSpace(strings.Join(parts, SymSpace))
	case []string:
		var parts []string
		for _, s := range v {
			if strings.TrimSpace(s) != StrEmpty {
				parts = append(parts, strings.TrimSpace(s))
			}
		}
		return strings.TrimSpace(strings.Join(parts, SymSpace))
	default:
		return AnyToString(v)
	}
}

// extractVCardProperty finds a named property (e.g. "fn", "org") in a jCard vcardArray (RFC 7095).
func extractVCardProperty(vcardArray []any, targetProp string) string {
	if len(vcardArray) < 2 {
		return StrEmpty
	}
	props, ok := vcardArray[1].([]any)
	if !ok {
		return StrEmpty
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
		if text := extractVCardText(items[3]); text != StrEmpty {
			return text
		}
	}
	return StrEmpty
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
				if name == StrEmpty {
					name = extractVCardProperty(entity.VCardArray, VCardPropOrg)
				}
			}

			// 2. Extract IANA ID from PublicIDs
			for _, pid := range entity.PublicIDs {
				if strings.EqualFold(pid.Type, PublicIDTypeIANA) || strings.EqualFold(pid.Type, StrIANARegistrarID) {
					ianaID = strings.TrimSpace(pid.Identifier)
					if name == StrEmpty && ianaID != StrEmpty {
						name = StrRegistrarIANA + ianaID + SymParenClose
					}
					break
				}
			}

			// 3. Extract Entity Handle fallback
			if name == StrEmpty && entity.Handle != StrEmpty && !strings.Contains(entity.Handle, SymSpace) {
				name = entity.Handle
			}

			// 4. Extract Referral Links on the Registrar Entity (RFC 9083 / ICANN standard)
			for _, link := range entity.Links {
				if link.Rel == RelRelated || link.Rel == RelAlternate || strings.Contains(link.Type, ContentTypeRDAPJSON) {
					if strings.HasPrefix(link.Href, StrHTTP) {
						relURL = link.Href
						break
					}
				}
			}

			// 5. Extract Port-43 WHOIS server if present
			if entity.Port43 != StrEmpty {
				whoisServer = entity.Port43
			}

			if name != StrEmpty {
				return name, ianaID, relURL, whoisServer
			}
		}

		if len(entity.Entities) > 0 {
			if n, id, u, w := findRegistrarEntity(entity.Entities); n != StrEmpty {
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
		if href == StrEmpty || !strings.HasPrefix(href, StrHTTP) {
			return
		}
		if baseURL != StrEmpty && strings.HasPrefix(href, strings.TrimRight(baseURL, SymSlash)) {
			return // Avoid self-referral loop
		}
		isRelated := link.Rel == RelRelated || link.Rel == RelAlternate
		isRDAPType := strings.Contains(link.Type, ContentTypeRDAPJSON) || strings.Contains(href, StrDomain)
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
		case strings.Contains(action, StrExpiration):
			if _, norm, err := parseFlexibleDate(event.Date); err == nil {
				tier.Expiration = norm
			} else {
				tier.Expiration = event.Date
			}
		case strings.Contains(action, StrRegistration) || strings.Contains(action, StrCreated):
			if _, norm, err := parseFlexibleDate(event.Date); err == nil {
				tier.Created = norm
			} else {
				tier.Created = event.Date
			}
		case strings.Contains(action, StrLastChanged) || strings.Contains(action, StrLastModified) || strings.Contains(action, StrUpdated):
			if _, norm, err := parseFlexibleDate(event.Date); err == nil {
				tier.Updated = norm
			} else {
				tier.Updated = event.Date
			}
		}
	}

	for _, ns := range domainInfo.Nameservers {
		live := NormalizeDomain(ns.LDHName)
		if live != StrEmpty {
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
	}

	parsed, parseErr := whoisparser.Parse(raw)
	if parseErr == nil && parsed.Registrar != nil && parsed.Registrar.Name != StrEmpty {
		tier.Registrar = parsed.Registrar.Name
		tier.IANAID = parsed.Registrar.ID
	}

	if parseErr == nil && parsed.Domain != nil {
		if parsed.Domain.ExpirationDateInTime != nil {
			tier.Expiration = parsed.Domain.ExpirationDateInTime.UTC().Format(time.RFC3339)
		} else if parsed.Domain.ExpirationDate != StrEmpty {
			if _, norm, err := parseFlexibleDate(parsed.Domain.ExpirationDate); err == nil {
				tier.Expiration = norm
			} else {
				tier.Expiration = parsed.Domain.ExpirationDate
			}
		}

		if parsed.Domain.CreatedDateInTime != nil {
			tier.Created = parsed.Domain.CreatedDateInTime.UTC().Format(time.RFC3339)
		} else if parsed.Domain.CreatedDate != StrEmpty {
			if _, norm, err := parseFlexibleDate(parsed.Domain.CreatedDate); err == nil {
				tier.Created = norm
			} else {
				tier.Created = parsed.Domain.CreatedDate
			}
		}

		if parsed.Domain.UpdatedDateInTime != nil {
			tier.Updated = parsed.Domain.UpdatedDateInTime.UTC().Format(time.RFC3339)
		} else if parsed.Domain.UpdatedDate != StrEmpty {
			if _, norm, err := parseFlexibleDate(parsed.Domain.UpdatedDate); err == nil {
				tier.Updated = norm
			} else {
				tier.Updated = parsed.Domain.UpdatedDate
			}
		}

		tier.DomainStatus = NormalizeDomainStatuses(parsed.Domain.Status)
		tier.DNSSEC = parsed.Domain.DNSSec

		for _, ns := range parsed.Domain.NameServers {
			if ns != StrEmpty {
				tier.Nameservers = append(tier.Nameservers, NormalizeDomain(ns))
			}
		}
	}

	// Supplementary regex field extraction if missing
	if tier.Expiration == StrEmpty {
		if m := ReWHOISExpiry.FindStringSubmatch(raw); len(m) > 1 {
			dateStr := strings.TrimSpace(m[1])
			if _, norm, err := parseFlexibleDate(dateStr); err == nil {
				tier.Expiration = norm
			} else {
				tier.Expiration = dateStr
			}
		}
	}

	if tier.Created == StrEmpty {
		if m := ReWHOISCreated.FindStringSubmatch(raw); len(m) > 1 {
			dateStr := strings.TrimSpace(m[1])
			if _, norm, err := parseFlexibleDate(dateStr); err == nil {
				tier.Created = norm
			}
		}
	}

	if tier.Updated == StrEmpty {
		if m := ReWHOISUpdated.FindStringSubmatch(raw); len(m) > 1 {
			dateStr := strings.TrimSpace(m[1])
			if _, norm, err := parseFlexibleDate(dateStr); err == nil {
				tier.Updated = norm
			}
		}
	}

	if tier.Registrar == StrEmpty {
		if m := ReWHOISRegistrar.FindStringSubmatch(raw); len(m) > 1 {
			reg := strings.TrimSpace(m[1])
			if !strings.EqualFold(reg, StrNotApplicable) && !strings.EqualFold(reg, StrNone) {
				tier.Registrar = reg
			}
		}
	}

	if tier.IANAID == StrEmpty {
		if m := ReWHOISIANAID.FindStringSubmatch(raw); len(m) > 1 {
			tier.IANAID = strings.TrimSpace(m[1])
		}
	}

	if len(tier.Nameservers) == 0 {
		matches := ReWHOISNS.FindAllStringSubmatch(raw, -1)
		for _, m := range matches {
			if len(m) > 1 {
				ns := NormalizeDomain(m[1])
				if ns != StrEmpty && !strings.Contains(ns, SymSpace) {
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

	// A small extracted substring can otherwise keep an unusually large WHOIS
	// response alive for the entire monitoring cycle.
	if len(raw) > 64<<10 {
		tier.Registrar = strings.Clone(tier.Registrar)
		tier.IANAID = strings.Clone(tier.IANAID)
		tier.Expiration = strings.Clone(tier.Expiration)
		tier.Created = strings.Clone(tier.Created)
		tier.Updated = strings.Clone(tier.Updated)
		for i := range tier.Nameservers {
			tier.Nameservers[i] = strings.Clone(tier.Nameservers[i])
		}
		for i := range tier.DomainStatus {
			tier.DomainStatus[i] = strings.Clone(tier.DomainStatus[i])
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
		state.Source = registry.Source + SymPlus + registrar.Source
	case registry != nil:
		state.Source = registry.Source
	case registrar != nil:
		state.Source = registrar.Source
	}

	// 2. Synthesize Registrar Identity
	if registrar != nil && registrar.Registrar != StrEmpty {
		state.Registrar = registrar.Registrar
	} else if registry != nil && registry.Registrar != StrEmpty {
		state.Registrar = registry.Registrar
	}

	if registrar != nil && registrar.IANAID != StrEmpty {
		state.RegistrarIANAID = registrar.IANAID
	} else if registry != nil && registry.IANAID != StrEmpty {
		state.RegistrarIANAID = registry.IANAID
	}

	// 3. Synthesize Expiration & Check for Grace Period Discrepancies
	switch {
	case registry != nil && registry.Expiration != StrEmpty && registrar != nil && registrar.Expiration != StrEmpty:
		regTime, _, errReg := parseFlexibleDate(registry.Expiration)
		rarTime, _, errRar := parseFlexibleDate(registrar.Expiration)
		if errReg == nil && errRar == nil {
			deltaDays := math.Abs(regTime.Sub(rarTime).Hours() / 24)
			if deltaDays > AutoRenewGracePeriodThresholdDays {
				disc := StrAutoRenewGracePeriod + regTime.Format(Str20060102) + StrVsRegistrarExpiration + rarTime.Format(Str20060102) + SymParenClose
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
	case registry != nil && registry.Expiration != StrEmpty:
		state.Expiration = registry.Expiration
	case registrar != nil && registrar.Expiration != StrEmpty:
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
			disc := StrNameserverDesyncRegistryDelegation + strings.Join(registry.Nameservers, SymCommaSpace) + StrRegistrarConfiguration + strings.Join(registrar.Nameservers, SymCommaSpace) + SymBracketClose
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
	if err == nil {
		if snapshot.RegistrarTier == nil && (snapshot.Expiration == StrEmpty || snapshot.Registrar == StrEmpty) {
			return supplementThinRDAP(ctx, app, domain, snapshot)
		}
		return snapshot
	}
	if errors.Is(err, ErrRDAPNotFound) {
		return RDAPSnapshot{Err: err, ProtocolUsed: ProtocolRDAP}
	}
	return fallbackWHOISSnapshot(ctx, app, domain, err)
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
	if snapshot.Expiration == StrEmpty {
		snapshot.Expiration = firstNonEmptyString(synthesized.Expiration, whoisSnapshot.Expiration)
	}
	if snapshot.Registrar == StrEmpty {
		snapshot.Registrar = firstNonEmptyString(synthesized.Registrar, whoisSnapshot.Registrar)
	}
	if snapshot.RegistrarIANAID == StrEmpty {
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
		return source + SymPlus + whois.Source
	}
	return source
}

func firstNonEmptyString(primary, fallback string) string {
	if primary != StrEmpty {
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
// Returns the status and its condition. A zero condition means no check ran.
func EvaluateRDAP(target DomainConfig, snapshot RDAPSnapshot) (CheckStatus, StateCondition) {
	if target.Domain == StrEmpty {
		return StatusPending, StateCondition{}
	}

	if snapshot.Err != nil {
		if errors.Is(snapshot.Err, ErrDomainNotFound) || errors.Is(snapshot.Err, ErrRDAPNotFound) {
			if target.AllowExpiry {
				return StatusSkipped, StateCondition{}
			}
			return StatusFailed, StateCondition{Code: CodeDomainNotFound}
		}

		errStr := snapshot.Err.Error()
		if strings.Contains(errStr, StrConnectionRefused) || strings.Contains(errStr, StrIOTimeout) || strings.Contains(errStr, StrNoSuchHost) || strings.Contains(errStr, StrTemporaryFailure) || isWHOISRateLimited(errStr, snapshot.Err) || errors.Is(snapshot.Err, ErrWHOISRateLimited) {
			return StatusWarning, StateCondition{Code: CodeRDAPHTTPError}
		}

		return StatusFailed, StateCondition{Code: CodeRDAPHTTPError}
	}

	ct := ConditionTracker{Status: StatusOK}

	// 1. Checks expiration
	if t, _, err := parseFlexibleDate(snapshot.Expiration); err == nil {
		days := time.Until(t).Hours() / 24
		if days < 0 {
			if target.AllowExpiry {
				return StatusSkipped, StateCondition{}
			}
			ct.Promote(StatusFailed, CodeRDAPExpired, StrEmpty)
		} else if days <= DefaultRDAPExpiryWarningDays && !target.AllowExpiry {
			priority := StatusWarning
			if days <= 7 {
				priority = StatusFailed
			}
			ct.Promote(priority, CodeRDAPExpiringSoon, StrEmpty)
		}
	} else {
		ct.Promote(StatusFailed, CodeRDAPExpiryUnavailable, snapshot.Expiration)
	}

	// 2. Checks public NS delegation and hidden-server non-exposure.
	evaluateNameserverDelegation(target.Nameservers, snapshot.Nameservers, &ct)

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
		ct.Promote(StatusFailed, code, StrEmpty)
	}

	// 4. Checks transfer lock
	if target.DomainTransferLocked && !isTransferLocked(snapshot.DomainStatus) {
		ct.Promote(StatusWarning, CodeRDAPTransferUnlocked, StrEmpty)
	}

	// 5. Checks registrar match
	if target.Registrar != StrEmpty {
		if _, err := strconv.Atoi(target.Registrar); err == nil {
			if snapshot.RegistrarIANAID != target.Registrar {
				ct.Promote(StatusFailed, CodeRDAPRegistrarMismatch, StrIANA+target.Registrar)
			}
		} else if !strings.Contains(strings.ToLower(snapshot.Registrar), strings.ToLower(target.Registrar)) {
			ct.Promote(StatusFailed, CodeRDAPRegistrarMismatch, target.Registrar)
		}
	}

	if ct.Cond.IsZero() {
		ct.Cond = StateCondition{Code: CodeRDAPSuccess}
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
		return RDAPSnapshot{}, fmt.Errorf(MsgErrRDAPHTTPClientIsNot, asciiDomain)
	}

	safeURLs := make([]string, 0, len(urls))
	for _, rawBaseURL := range urls {
		baseURL := strings.TrimRight(rawBaseURL, SymSlash)
		reqURL := baseURL + PathRDAPDomain + asciiDomain
		if !rdapURLAllowed(app, reqURL) {
			continue
		}
		safeURLs = append(safeURLs, baseURL)
	}
	if len(safeURLs) == 0 {
		return RDAPSnapshot{}, fmt.Errorf(MsgErrRDAPLookupFor, asciiDomain, MsgErrRDAPLookupFailedAllCandidates)
	}

	return retryWithBackoff(ctx, NameOpRegistryRDAP, HTTPRetryBaseDelay, func(attempt int) (RDAPSnapshot, bool, time.Duration, error) {
		baseURL := safeURLs[(attempt-1)%len(safeURLs)]
		reqURL := baseURL + PathRDAPDomain + asciiDomain
		// #nosec G704 -- rdapURLAllowed rejects unsafe hosts immediately above.
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
		if err != nil {
			return RDAPSnapshot{}, false, 0, err
		}
		req.Header.Set(HeaderAccept, AcceptRDAP)
		req.Header.Set(HeaderUserAgent, DefaultUserAgent)
		if app.RDAPLimiter != nil {
			if err := app.RDAPLimiter.Wait(ctx); err != nil {
				return RDAPSnapshot{}, false, 0, err
			}
		}

		resp, err := httpClient.Do(req)
		if err != nil {
			if resp != nil {
				DrainAndClose(resp.Body, MaxBodyDrainSize)
			}
			return RDAPSnapshot{}, transientNetworkError(err), 0, err
		}
		if retryableHTTPStatus(resp.StatusCode) && attempt < MaxNetworkAttempts {
			delay := responseRetryAfter(resp, time.Now())
			statusErr := fmt.Errorf(MsgErrRDAPHTTPError, resp.StatusCode)
			DrainAndClose(resp.Body, MaxBodyDrainSize)
			return RDAPSnapshot{}, true, delay, statusErr
		}

		domainInfo, err := readRDAPDomainResponse(resp)
		if errors.Is(err, ErrRDAPNotFound) || errors.Is(err, ErrRDAPRateLimited) {
			return RDAPSnapshot{}, false, 0, err
		}
		if err != nil {
			return RDAPSnapshot{}, attempt < len(safeURLs), 0, err
		}
		if err := validateRDAPDomainIdentity(domainInfo, asciiDomain); err != nil {
			return RDAPSnapshot{}, attempt < len(safeURLs), 0, err
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
		return state, false, 0, nil
	})
}

func rdapServersFor(ctx context.Context, app *AppState, domain string) ([]string, error) {
	if app == nil || app.Bootstrap == nil {
		return nil, fmt.Errorf(MsgErrRDAPBootstrapIsUnavailableFor, domain)
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
	body, err := readBounded(response.Body, MaxBootstrapResponseSize)
	if errors.Is(err, ErrReadLimitExceeded) {
		return nil, fmt.Errorf(MsgErrRDAPResponseExceedsBytes, MaxBootstrapResponseSize)
	}
	if err != nil {
		return nil, fmt.Errorf(MsgErrReadRDAPResponse, err)
	}
	var domain RDAPDomainResponse
	if err := jsonv2.Unmarshal(body, &domain); err != nil {
		return nil, fmt.Errorf(MsgErrParseRDAPResponse, err)
	}
	return &domain, nil
}

func validateRDAPDomainIdentity(response *RDAPDomainResponse, expected string) error {
	if response == nil || response.ObjectClassName != RDAPObjectClassDomain {
		return fmt.Errorf(MsgErrRDAPResponseForIsNot, expected)
	}
	if response.LDHName == StrEmpty && response.UnicodeName == StrEmpty {
		return fmt.Errorf(MsgErrRDAPResponseForHasNo, expected)
	}
	for _, name := range []string{response.LDHName, response.UnicodeName} {
		if name != StrEmpty && NormalizeDomainToASCIIText(name) != expected {
			return fmt.Errorf(MsgErrRDAPResponseDomainDoesNot, name, expected)
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
	host := strings.TrimRight(strings.ToLower(u.Hostname()), SymDot)
	if host == StrEmpty || host == StrLocalhost || strings.Contains(host, SymPercent) || strings.HasSuffix(host, StrLocal) || strings.HasSuffix(host, StrInternal) {
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
	if clean == StrEmpty || strings.ContainsAny(clean, SymURLControlChars) {
		return false
	}
	host := strings.ToLower(clean)
	if host == StrEmpty || host == StrLocalhost || strings.HasSuffix(host, StrLocal) || strings.HasSuffix(host, StrInternal) {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		return !IsRestrictedIP(ip)
	}
	return ReValidDomain.MatchString(host)
}

func followRegistrarRDAPLinks(ctx context.Context, domain string, links []string, client HTTPDoer, policyApp *AppState) *RDAPDomainResponse {
	httpClient := resolveRDAPClient(client, policyApp)
	if httpClient == nil {
		return nil
	}

	var targets []string
	for _, rawHref := range links {
		targetURL := registrarRDAPURL(rawHref, domain)
		if targetURL == StrEmpty {
			continue
		}
		if !rdapURLAllowed(policyApp, targetURL) {
			LogWarn(MsgLogSkippingUnsafeRDAP, FieldDomain, domain, FieldURL, targetURL)
			continue
		}
		targets = append(targets, targetURL)
	}
	if len(targets) == 0 {
		return nil
	}

	result, _ := retryWithBackoff(ctx, NameOpRegistrarRDAP, HTTPRetryBaseDelay, func(attempt int) (*RDAPDomainResponse, bool, time.Duration, error) {
		targetURL := targets[(attempt-1)%len(targets)]
		LogInfo(MsgLogQueryingRegistrarRDAP, FieldDomain, domain, FieldURL, targetURL)
		relReq, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
		if err != nil {
			return nil, false, 0, err
		}
		relReq.Header.Set(HeaderAccept, AcceptRDAP)
		relReq.Header.Set(HeaderUserAgent, DefaultUserAgent)
		if policyApp != nil && policyApp.RDAPLimiter != nil {
			if err := policyApp.RDAPLimiter.Wait(ctx); err != nil {
				return nil, false, 0, err
			}
		}

		relResp, err := httpClient.Do(relReq)
		if err != nil {
			if relResp != nil {
				DrainAndClose(relResp.Body, MaxBodyDrainSize)
			}
			return nil, transientNetworkError(err), 0, err
		}
		if relResp.StatusCode != http.StatusOK {
			delay := responseRetryAfter(relResp, time.Now())
			statusErr := fmt.Errorf(MsgErrRDAPHTTPError, relResp.StatusCode)
			if relResp.StatusCode == http.StatusTooManyRequests {
				LogWarn(MsgLogRateLimitedRegistrarRDAP, FieldDomain, domain)
			}
			DrainAndClose(relResp.Body, MaxBodyDrainSize)
			return nil, retryableHTTPStatus(relResp.StatusCode) || len(targets) > 1, delay, statusErr
		}

		relDomain, err := readRegistrarRDAPResponse(relResp)
		if err != nil {
			LogWarn(MsgLogRegistrarReferralInvalid, FieldURL, targetURL, FieldError, err)
			return nil, attempt < len(targets), 0, err
		}
		if err := validateRDAPDomainIdentity(relDomain, NormalizeDomainToASCIIText(domain)); err != nil {
			LogWarn(MsgLogRegistrarReferralInvalid, FieldURL, targetURL, FieldError, err)
			return nil, attempt < len(targets), 0, err
		}
		return relDomain, false, 0, nil
	})
	return result
}

func readRegistrarRDAPResponse(response *http.Response) (*RDAPDomainResponse, error) {
	body, err := readBounded(response.Body, MaxBootstrapResponseSize)
	DrainAndClose(response.Body, MaxBodyDrainSize)
	if errors.Is(err, ErrReadLimitExceeded) {
		return nil, fmt.Errorf(MsgErrRegistrarRDAPResponseExceedsBytes, MaxBootstrapResponseSize)
	}
	if err != nil {
		return nil, fmt.Errorf(MsgErrReadRegistrarRDAPReferral, err)
	}
	var domain RDAPDomainResponse
	if err := jsonv2.Unmarshal(body, &domain); err != nil {
		return nil, fmt.Errorf(MsgErrParseRegistrarRDAPReferral, err)
	}
	return &domain, nil
}

func registrarRDAPURL(rawHref, domain string) string {
	href := strings.TrimSpace(rawHref)
	if href == StrEmpty {
		return StrEmpty
	}
	if u, err := url.Parse(href); err == nil {
		if !strings.Contains(u.Path, PathRDAPDomain) {
			u.Path = strings.TrimRight(u.Path, SymSlash) + PathRDAPDomain + domain
		}
		return u.String()
	}
	if !strings.Contains(href, PathRDAPDomain) {
		return strings.TrimRight(href, SymSlash) + PathRDAPDomain + domain
	}
	return href
}

func fetchWHOIS(ctx context.Context, app *AppState, domain string) (RDAPSnapshot, error) {
	start := time.Now()
	result, err := queryWHOISWithRetry(ctx, app, domain, StrEmpty, NameOpWHOIS)
	if err != nil {
		return RDAPSnapshot{}, err
	}

	durationMs := time.Since(start).Milliseconds()

	registryTier := extractWHOISTier(result, SourceRegistryWHOIS, SourceRegistry)
	var registrarTier *DomainTierData

	// Always follow referral server if present to guarantee cross-tier 2-tier ARGP detection
	if m := ReWHOISReferral.FindStringSubmatch(result); len(m) > 1 {
		referralServer := strings.TrimSpace(m[1])
		if referralServer != StrEmpty && !strings.Contains(referralServer, StrIana2) && !strings.Contains(referralServer, StrInternic) {
			if !isSafeWHOISServer(referralServer) {
				LogWarn(MsgLogSkippingUnsafeWHOIS, FieldDomain, domain, FieldReferralServer, referralServer)
			} else {
				LogInfo(MsgLogFollowingWHOISReferral, FieldDomain, domain, FieldReferralServer, referralServer)
				refResult, refErr := queryWHOISWithRetry(ctx, app, domain, referralServer, NameOpWHOISReferral)
				if refErr != nil {
					LogWarn(MsgLogWHOISReferralFailed, FieldDomain, domain, FieldReferralServer, referralServer, FieldError, refErr)
				} else if refResult != StrEmpty && !isDomainNotFoundInWHOIS(refResult) {
					registrarTier = extractWHOISTier(refResult, SourceRegistrarWHOIS, referralServer)
				}
			}
		}
	}

	state, _ := synthesizeTierData(registryTier, registrarTier)
	state.ProtocolUsed = ProtocolWHOIS
	state.QueryDurationMs = durationMs

	// Check for domain not registered
	if isDomainNotFoundInWHOIS(result) && state.Expiration == StrEmpty && len(state.Nameservers) == 0 {
		return RDAPSnapshot{}, ErrDomainNotFound
	}

	if state.Expiration == StrEmpty && state.Registrar == StrEmpty && len(state.Nameservers) == 0 && len(state.DomainStatus) == 0 {
		return RDAPSnapshot{}, errors.New(MsgErrWHOISParsingFailed)
	}

	return state, nil
}

func queryWHOISWithRetry(ctx context.Context, app *AppState, domain, server, operation string) (string, error) {
	return retryWithBackoff(ctx, operation, WHOISRetryBaseDelay, func(_ int) (string, bool, time.Duration, error) {
		qCtx, cancel := context.WithTimeout(ctx, DefaultWHOISQueryTimeout)
		attemptResult, queryErr := queryWHOISWithContext(qCtx, app, domain, server)
		cancel()

		if queryErr != nil && attemptResult == StrEmpty {
			wrapped := WrapError(MsgErrWHOISQueryFailed, queryErr)
			return StrEmpty, transientNetworkError(queryErr), 0, wrapped
		}

		if !isWHOISRateLimited(attemptResult, queryErr) {
			if queryErr != nil {
				return StrEmpty, false, 0, WrapError(MsgErrWHOISQueryFailed, queryErr)
			}
			return attemptResult, false, 0, nil
		}
		return attemptResult, true, 0, ErrWHOISRateLimited
	})
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
			LogWarn(MsgLogPartialParentNameserverAddressLookup, FieldDomain, ns, FieldError, err)
		}
		rootIPs = append(rootIPs, ips...)
	}
	return rootIPs
}

// FetchNSDelegationSnapshot fetches delegation evidence from the configured parent zone.
func FetchNSDelegationSnapshot(ctx context.Context, app *AppState, target DomainConfig) NSDelegationSnapshot {
	var snapshot NSDelegationSnapshot

	resolversToUse := app.resolvers()
	rd := true
	if target.RootZone != StrEmpty {
		rootIPs := resolveRootZoneResolvers(ctx, app, target.RootZone, app.resolvers())
		if len(rootIPs) == 0 {
			snapshot.Err = fmt.Errorf(MsgErrParentNameserversForHaveNo, target.RootZone)
			return snapshot
		}
		resolversToUse = rootIPs
		rd = false // Querying parent authoritative nameservers directly
	}

	r, err := queryDNSMsgWithRD(ctx, app, target.Domain, dns.TypeNS, resolversToUse, rd)
	if err != nil {
		snapshot.Err = fmt.Errorf(MsgErrFailedToQueryNSRecords, err)
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

// EvaluateNSDelegation compares observed delegation with configured nameservers.
func EvaluateNSDelegation(target DomainConfig, snapshot NSDelegationSnapshot) (CheckStatus, StateCondition) {
	if snapshot.Err != nil {
		return StatusFailed, StateCondition{Code: CodeDNSLookupFailed, Target: snapshot.Err.Error()}
	}
	if len(snapshot.Nameservers) == 0 {
		return StatusFailed, StateCondition{Code: CodeDNSLookupFailed, Target: StrDelegationReturnedNoNameservers}
	}

	ct := ConditionTracker{Status: StatusOK}
	evaluateNameserverDelegation(target.Nameservers, snapshot.Nameservers, &ct)
	return ct.Status, ct.Cond
}

func evaluateNameserverDelegation(configured []NameserverConfig, observed []string, ct *ConditionTracker) {
	if len(configured) == 0 {
		return
	}

	liveNS := make(map[string]bool, len(observed))
	answering := make(map[string]bool, len(configured))
	hidden := make(map[string]bool, len(configured))
	for _, nameserver := range configured {
		name := NormalizeDomain(nameserver.Hostname)
		if nameserver.Hidden {
			hidden[name] = true
		} else {
			answering[name] = true
		}
	}

	for _, raw := range observed {
		ns := NormalizeDomain(raw)
		if ns == StrEmpty {
			continue
		}
		liveNS[ns] = true
		switch {
		case hidden[ns]:
			ct.Promote(StatusFailed, CodeNSHiddenExposed, ns)
		case !answering[ns]:
			ct.Promote(StatusFailed, CodeUnauthorizedNS, ns)
		}
	}

	for _, nameserver := range configured {
		if !nameserver.Hidden && !liveNS[NormalizeDomain(nameserver.Hostname)] {
			ct.Promote(StatusFailed, CodeExpectedNSMissing, nameserver.Hostname)
		}
	}
}
