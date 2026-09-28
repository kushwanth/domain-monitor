package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// queryDNSMsg queries the given resolvers for the specified hostname and record type using miekg/dns.
// It retries on network errors and SERVFAIL using the next resolver in round-robin order.
func queryDNSMsg(ctx context.Context, app *AppState, hostname string, qtype uint16, resolvers []string) (*dns.Msg, error) {
	return queryDNSMsgWithRD(ctx, app, hostname, qtype, resolvers, true)
}

// queryDNSMsgWithRD queries the given resolvers with explicit recursionDesired configuration.
// The "RD" acronym corresponds directly to the RFC 1035 wire-format header bit (Recursion Desired),
// which is set to false (RD=0) when querying authoritative nameservers directly.
func queryDNSMsgWithRD(ctx context.Context, app *AppState, hostname string, qtype uint16, resolvers []string, recursionDesired bool) (*dns.Msg, error) {
	if len(resolvers) == 0 {
		return nil, ErrNoResolvers
	}
	startIdx := 0
	if app != nil {
		startIdx = int(uint64(app.GlobalResolverIndex.Add(1)) % uint64(len(resolvers))) // #nosec G115 -- modulo bounds the result by slice length.
	}

	var lastErr error
	dnsClient := &dns.Client{Timeout: DefaultDNSTimeout}
	dnsMsg := new(dns.Msg)
	fqdn := dns.Fqdn(hostname)
	dnsMsg.SetQuestion(fqdn, qtype)
	dnsMsg.SetEdns0(MaxBodyDrainSize, true)
	dnsMsg.RecursionDesired = recursionDesired

	for attempt := range resolvers {
		idx := (startIdx + attempt) % len(resolvers)
		ip := DefaultPort(resolvers[idx], DefaultDNSPort)

		dnsClient.Net = StrEmpty
		dnsMsg.Id = dns.Id()

		var r *dns.Msg
		var err error
		if app != nil && app.DNSClient != nil {
			r, _, err = app.DNSClient.ExchangeContext(ctx, dnsMsg, ip)
			if err == nil && r != nil && r.Truncated {
				if app.DNSTCPClient == nil {
					lastErr = fmt.Errorf(MsgErrQueryDNSForOnTruncated, hostname, ip)
					continue
				}
				r, _, err = app.DNSTCPClient.ExchangeContext(ctx, dnsMsg, ip)
			}
		} else {
			r, _, err = dnsClient.ExchangeContext(ctx, dnsMsg, ip)
			if err == nil && r != nil && r.Truncated {
				dnsClient.Net = ProtocolTCP
				r, _, err = dnsClient.ExchangeContext(ctx, dnsMsg, ip)
			}
		}

		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			lastErr = WrapError(fmt.Sprintf(MsgPrefixLookupOn, hostname, ip), err)
			continue
		}

		if r == nil {
			lastErr = fmt.Errorf(MsgErrLookupEmptyResponse, hostname, ip)
			continue
		}
		if r.Truncated {
			lastErr = fmt.Errorf(MsgErrQueryDNSForOnTCP, hostname, ip)
			continue
		}

		// Verify question section echoes request per RFC 5452 Section 4
		if len(r.Question) != 1 || !strings.EqualFold(r.Question[0].Name, fqdn) || r.Question[0].Qtype != qtype || r.Question[0].Qclass != dns.ClassINET {
			lastErr = fmt.Errorf(MsgErrLookupQuestionMismatch, hostname, ip)
			continue
		}

		if r.Rcode != dns.RcodeSuccess {
			if r.Rcode == dns.RcodeNameError {
				// NXDOMAIN is authoritative — do not retry on other resolvers
				return nil, WrapError(fmt.Sprintf(MsgPrefixLookupOn, hostname, ip), ErrNXDOMAIN)
			}
			if r.Rcode == dns.RcodeServerFailure {
				lastErr = WrapError(fmt.Sprintf(MsgPrefixLookupOnWithRcode, hostname, ip, dns.RcodeToString[r.Rcode]), ErrSERVFAIL)
				continue
			}
			// REFUSED, NOTIMP, FORMERR are server-specific failures — retry next resolver
			if r.Rcode == dns.RcodeRefused || r.Rcode == dns.RcodeNotImplemented || r.Rcode == dns.RcodeFormatError {
				lastErr = fmt.Errorf(MsgErrLookupServerError, hostname, ip, dns.RcodeToString[r.Rcode])
				continue
			}
			return nil, fmt.Errorf(MsgErrLookupServerErrorCode, hostname, ip, r.Rcode)
		}

		return r, nil
	}

	return nil, lastErr
}

// queryDNS queries the given resolvers and returns parsed string results.
// It bypasses the OS resolver completely and forces a direct UDP/TCP connection to the provided IP.
func queryDNS(ctx context.Context, app *AppState, hostname string, qtype uint16, resolvers []string) ([]string, error) {
	r, err := queryDNSMsg(ctx, app, hostname, qtype, resolvers)
	if err != nil {
		return nil, err
	}
	if r == nil {
		return nil, ErrEmptyDNSResponse
	}

	allowedOwners := dnsAnswerOwners(r.Answer, hostname)
	queriedOwner := strings.ToLower(dns.Fqdn(hostname))
	var results []string
	invalidNullMXPreference := false
	for _, ans := range r.Answer {
		if ans.Header().Class != dns.ClassINET {
			continue
		}
		owner := strings.ToLower(dns.Fqdn(ans.Header().Name))
		if !allowedOwners[owner] || (qtype == dns.TypeCNAME && owner != queriedOwner) {
			continue
		}
		if value, matchesType := dnsAnswerText(ans, qtype); matchesType {
			results = append(results, value)
			if value == NullMXRecord {
				if mx, ok := ans.(*dns.MX); ok && mx.Preference != 0 {
					invalidNullMXPreference = true
				}
			}
		}
	}
	if qtype == dns.TypeMX && slices.Contains(results, NullMXRecord) && (invalidNullMXPreference || len(results) != 1) {
		return nil, fmt.Errorf(MsgErrExpectedOneMXRecordWith, ErrInvalidNullMX)
	}

	return results, nil
}

func dnsAnswerText(answer dns.RR, qtype uint16) (string, bool) {
	switch record := answer.(type) {
	case *dns.A:
		return record.A.String(), qtype == dns.TypeA
	case *dns.AAAA:
		return record.AAAA.String(), qtype == dns.TypeAAAA
	case *dns.CNAME:
		return NormalizeDomain(record.Target), qtype == dns.TypeCNAME
	case *dns.MX:
		mx := NormalizeDomain(record.Mx)
		if mx == StrEmpty && record.Mx == NullMXRecord {
			mx = NullMXRecord
		}
		return mx, qtype == dns.TypeMX
	case *dns.TXT:
		return strings.Join(record.Txt, StrEmpty), qtype == dns.TypeTXT
	case *dns.CAA:
		return canonicalCAARecordValue(record), qtype == dns.TypeCAA
	case *dns.NS:
		return NormalizeDomain(record.Ns), qtype == dns.TypeNS
	}
	return StrEmpty, false
}

// canonicalCAARecordValue omits owner and TTL, which are transport metadata
// rather than the configured CAA RDATA being monitored.
func canonicalCAARecordValue(record *dns.CAA) string {
	return fmt.Sprintf(StrDSQ, record.Flag, strings.ToLower(record.Tag), record.Value)
}

// dnsAnswerOwners follows CNAMEs in the answer section so only records for the
// queried name or its bounded alias chain are accepted.
func dnsAnswerOwners(answers []dns.RR, hostname string) map[string]bool {
	owners := map[string]bool{strings.ToLower(dns.Fqdn(hostname)): true}
	for range MaxCNAMEAliasTraversals {
		changed := false
		for _, answer := range answers {
			if answer.Header().Class != dns.ClassINET {
				continue
			}
			alias, ok := answer.(*dns.CNAME)
			if !ok || !owners[strings.ToLower(dns.Fqdn(alias.Hdr.Name))] {
				continue
			}
			target := strings.ToLower(dns.Fqdn(alias.Target))
			if !owners[target] {
				owners[target] = true
				changed = true
			}
		}
		if !changed {
			break
		}
	}
	return owners
}

func queryIPRecords(ctx context.Context, app *AppState, hostname string, resolvers []string) ([]string, error) {
	aRecords, aErr := queryDNS(ctx, app, hostname, dns.TypeA, resolvers)
	aaaaRecords, aaaaErr := queryDNS(ctx, app, hostname, dns.TypeAAAA, resolvers)

	var found []string
	if aErr == nil {
		found = append(found, aRecords...)
	}
	if aaaaErr == nil {
		found = append(found, aaaaRecords...)
	}
	if aErr != nil || aaaaErr != nil {
		return found, WrapError(MsgErrLookupFailedAandAAAA, errors.Join(aErr, aaaaErr))
	}
	return found, nil
}

func validateDNSSEC(ctx context.Context, app *AppState, domain string, resolvers []string, dohURLTemplate string) DNSSECResult {
	res := DNSSECResult{
		Source: DNSSECSourceLocalDoH,
	}

	fqdn := dns.Fqdn(domain)

	// 1. Query DS
	dsResp, err := queryDNSMsg(ctx, app, domain, dns.TypeDS, resolvers)
	if err != nil {
		res.Valid = false
		res.Error = fmt.Sprintf(MsgErrDSQueryFailed, err.Error())
		return res
	}

	var dsRecords []*dns.DS
	if dsResp != nil {
		for _, ans := range dsResp.Answer {
			if ds, ok := ans.(*dns.DS); ok && strings.EqualFold(ds.Hdr.Name, fqdn) && ds.Hdr.Class == dns.ClassINET {
				dsRecords = append(dsRecords, ds)
				res.HasDS = true
			}
		}
	}

	// 2. Query DNSKEY
	keyResp, err := queryDNSMsg(ctx, app, domain, dns.TypeDNSKEY, resolvers)
	if err != nil {
		res.Valid = false
		res.Error = fmt.Sprintf(MsgErrDNSKEYQueryFailed, err.Error())
		return res
	}

	var dnskeyRecords []*dns.DNSKEY
	var rrsigRecords []*dns.RRSIG
	var rrset []dns.RR

	if keyResp != nil {
		for _, ans := range keyResp.Answer {
			if key, ok := ans.(*dns.DNSKEY); ok && strings.EqualFold(key.Hdr.Name, fqdn) && key.Hdr.Class == dns.ClassINET {
				dnskeyRecords = append(dnskeyRecords, key)
				res.HasDNSKEY = true
				rrset = append(rrset, ans)

				algoStr := dns.AlgorithmToString[key.Algorithm]
				if algoStr == StrEmpty {
					algoStr = PrefixAlgo + strconv.Itoa(int(key.Algorithm))
				}

				found := slices.Contains(res.Algorithms, algoStr)
				if !found {
					res.Algorithms = append(res.Algorithms, algoStr)
				}

			} else if sig, ok := ans.(*dns.RRSIG); ok {
				if sig.TypeCovered == dns.TypeDNSKEY && strings.EqualFold(sig.Hdr.Name, fqdn) && sig.Hdr.Class == dns.ClassINET {
					rrsigRecords = append(rrsigRecords, sig)
				}
			}
		}
	}

	// 3. Match DS to DNSKEY and record authenticated KSKs (RFC 4035 Section 5.2)
	var authenticatedKSKs []*dns.DNSKEY
	for _, key := range dnskeyRecords {
		for _, ds := range dsRecords {
			if key.KeyTag() == ds.KeyTag && key.Algorithm == ds.Algorithm {
				computedDS := key.ToDS(ds.DigestType)
				if computedDS != nil && strings.EqualFold(computedDS.Digest, ds.Digest) {
					res.DSMatchesDNSKEY = true
					authenticatedKSKs = append(authenticatedKSKs, key)
					break
				}
			}
		}
	}

	if len(dsRecords) > 0 && len(dnskeyRecords) > 0 && !res.DSMatchesDNSKEY {
		res.Error = MsgErrDSRecordDoesNotMatchDNSKEY
	}

	// 4. Validate dns.RRSIG covering DNSKEY RRset using DS-authenticated KSK (RFC 4035 Section 5.3)
	if len(rrsigRecords) > 0 && len(rrset) > 0 {

		keysToVerify := authenticatedKSKs
		if len(keysToVerify) == 0 && len(dsRecords) == 0 {
			keysToVerify = dnskeyRecords // Fallback for unsigned delegation or trust anchor testing
		}

		for _, sig := range rrsigRecords {
			if strings.EqualFold(sig.SignerName, fqdn) {
				for _, key := range keysToVerify {
					if key.KeyTag() == sig.KeyTag && key.Algorithm == sig.Algorithm {
						err := sig.Verify(key, rrset)
						if err == nil {
							now := time.Now().Unix()
							inception := int64(sig.Inception)
							expiration := int64(sig.Expiration)
							if (inception <= now+DNSSECClockSkew) && (now <= expiration+DNSSECClockSkew) {
								res.RRSIGValid = true
								res.Error = StrEmpty // Clear any stale error from previous iteration
								expiryStr := dns.TimeToString(sig.Expiration)
								if et, parseErr := time.Parse(LayoutCompactDateTime, expiryStr); parseErr == nil {
									res.RRSIGExpiry = et.UTC().Format(time.RFC3339)
								}
								break
							}
							res.Error = MsgErrRRSIGExpiredOrNotYetValid
						}
					}
				}
				if res.RRSIGValid {
					break
				}
			}
		}
	}

	// Tier 2: a trusted DoH AD response is required for a verified chain.
	if dohURLTemplate != StrEmpty && verifyDNSSECDoH(ctx, app, dohURLTemplate, domain, fqdn, authenticatedKSKs...) {
		res.ChainIntact = true
	} else {
		res.Source = DNSSECSourceLocalOnly
	}

	switch {
	case res.HasDS && res.HasDNSKEY && res.DSMatchesDNSKEY && res.RRSIGValid:
		switch {
		case res.ChainIntact && res.Source != DNSSECSourceLocalOnly:
			res.Valid = true
			res.Error = StrEmpty
		case res.Source == DNSSECSourceLocalOnly:
			res.Valid = false
			if res.Error == StrEmpty {
				res.Error = MsgErrDNSSECLocalVerifiedDoHUnavailable
			}
		default:
			res.Valid = false
			if res.Error == StrEmpty {
				res.Error = MsgErrDNSSECUpstreamChainBroken
			}
		}
	case !res.HasDS && !res.HasDNSKEY:
		// Not signed
		res.Valid = false
	default:
		res.Valid = false
		if res.Error == StrEmpty {
			res.Error = MsgErrDNSSECValidationFailed
		}
	}

	return res
}

func verifyDNSSECDoH(ctx context.Context, app *AppState, endpoint, domain, fqdn string, authenticatedKSKs ...*dns.DNSKEY) bool {
	if app == nil || ResolveHTTPClient(app.HTTPClient) == nil {
		return false
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return false
	}
	query := u.Query()
	query.Set(ParamName, domain)
	query.Set(ParamType, RecordTypeDNSKEY)
	query.Set(ParamDO, ParamDOValue)
	u.RawQuery = query.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return false
	}
	req.Header.Set(HeaderAccept, MIMEDNSJSON)
	req.Header.Set(HeaderUserAgent, DefaultUserAgent)
	resp, err := app.HTTPClient.Do(req)
	if err != nil {
		if resp != nil {
			DrainAndClose(resp.Body, MaxBodyDrainSize)
		}
		return false
	}
	if resp == nil {
		return false
	}
	defer DrainAndClose(resp.Body, MaxBodyDrainSize)
	if resp.StatusCode != http.StatusOK {
		return false
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxNotificationPayloadSize+1))
	if err != nil || len(body) > MaxNotificationPayloadSize {
		return false
	}
	var result dohJSONResponse
	if err := jsonv2.Unmarshal(body, &result); err != nil {
		return false
	}
	if result.Status != 0 || !result.AD || len(result.Question) != 1 ||
		!strings.EqualFold(dns.Fqdn(result.Question[0].Name), fqdn) || result.Question[0].Type != int(dns.TypeDNSKEY) {
		return false
	}
	// AD authenticates the provider's response, but an authenticated NODATA or
	// a different DNSKEY RRset cannot corroborate the locally verified key.
	for _, answer := range result.Answer {
		if answer.Type != int(dns.TypeDNSKEY) || !strings.EqualFold(dns.Fqdn(answer.Name), fqdn) {
			continue
		}
		rr, err := dns.NewRR(fmt.Sprintf(StrS0InDnskey, answer.Name, answer.Data))
		if err != nil {
			continue
		}
		observed, ok := rr.(*dns.DNSKEY)
		if !ok {
			continue
		}
		for _, key := range authenticatedKSKs {
			if key != nil && observed.Flags == key.Flags && observed.Protocol == key.Protocol &&
				observed.Algorithm == key.Algorithm && observed.PublicKey == key.PublicKey {
				return true
			}
		}
	}
	return false
}

// FetchDNSSECSnapshot fetches DNSSEC evidence when the check is enabled.
func FetchDNSSECSnapshot(ctx context.Context, app *AppState, target DomainConfig) DNSSECSnapshot {
	if !target.DNSSEC {
		return DNSSECSnapshot{}
	}
	if app == nil {
		return DNSSECSnapshot{Result: DNSSECResult{Source: DNSSECSourceLocalOnly, NetworkError: true, Error: MsgErrDNSSECResolverNotConfigured}}
	}
	dohURL := DefaultDoHURL
	if app.configuration().DoHURL != StrEmpty {
		dohURL = app.configuration().DoHURL
	}
	res := validateDNSSEC(ctx, app, target.Domain, app.resolvers(), dohURL)
	return DNSSECSnapshot{Result: res}
}

// EvaluateDNSSEC evaluates fetched local and upstream DNSSEC evidence.
func EvaluateDNSSEC(target DomainConfig, snapshot DNSSECSnapshot) (CheckStatus, *StateCondition, DNSSECResult) {
	if !target.DNSSEC {
		return StatusOK, nil, DNSSECResult{}
	}
	res := snapshot.Result
	if res.Source == StrEmpty {
		res.Source = DNSSECSourceLocalOnly
		res.Error = MsgErrValidateDNSSECNil
		res.Valid = false
		return StatusFailed, &StateCondition{Code: CodeDNSSECNetworkError, Target: res.Error}, res
	}
	status := StatusOK
	var cond *StateCondition
	if !res.Valid {
		status = StatusFailed
		switch {
		case res.NetworkError:
			cond = &StateCondition{Code: CodeDNSSECNetworkError, Target: res.Error}
		case res.Error != StrEmpty && strings.Contains(res.Error, StrQueryFailed):
			cond = &StateCondition{Code: CodeDNSLookupFailed, Target: res.Error}
		case !res.HasDS && !res.HasDNSKEY:
			cond = &StateCondition{Code: CodeDNSSECDisabled}
		case !res.HasDS:
			cond = &StateCondition{Code: CodeDNSSECNoDS}
		case !res.HasDNSKEY:
			cond = &StateCondition{Code: CodeDNSSECNoDNSKEY}
		case !res.DSMatchesDNSKEY:
			cond = &StateCondition{Code: CodeDNSSECDSMismatch}
		case !res.RRSIGValid:
			cond = &StateCondition{Code: CodeDNSSECRRSIGFailed}
		case !res.ChainIntact:
			cond = &StateCondition{Code: CodeDNSLookupFailed, Target: res.Error}
		}
	} else {
		cond = &StateCondition{Code: CodeDNSSECVerified}
	}
	return status, cond, res
}

// FetchDNSSnapshot performs the DNS resolution and returns a snapshot
func FetchDNSSnapshot(ctx context.Context, app *AppState, target DNSTask) DNSSnapshot {
	foundRecords, err := resolveTarget(ctx, app, target)
	snap := DNSSnapshot{
		Records: foundRecords,
		Err:     err,
	}
	if err == nil && (target.Type == RecordTypeALIAS || target.Type == RecordTypeCNAME) && len(foundRecords) > 0 && net.ParseIP(foundRecords[0]) != nil {
		resolvers := app.resolvers()
		if target.CustomResolver != StrEmpty {
			resolvers = []string{target.CustomResolver}
		}
		for _, expected := range target.Expected {
			if net.ParseIP(expected) != nil {
				snap.ExpectedRecords = append(snap.ExpectedRecords, expected)
				continue
			}
			ips, lookupErr := queryIPRecords(ctx, app, expected, resolvers)
			if lookupErr != nil {
				snap.Err = fmt.Errorf(MsgErrResolveExpectedAlias, expected, lookupErr)
				return snap
			}
			snap.ExpectedRecords = append(snap.ExpectedRecords, ips...)
		}
		slices.Sort(snap.ExpectedRecords)
		snap.ExpectedRecords = slices.Compact(snap.ExpectedRecords)
	}
	return snap
}

// EvaluateDNS evaluates the DNS records against the expected ones
func EvaluateDNS(target DNSTask, snapshot DNSSnapshot) (CheckStatus, *StateCondition) {
	if snapshot.Err != nil {
		return StatusFailed, &StateCondition{Code: CodeDNSLookupFailed, Target: snapshot.Err.Error()}
	}

	if snapshot.ExpectedRecords != nil {
		target.Expected = snapshot.ExpectedRecords
	}
	allMatch, mismatchReason, mismatchCode := validateRecordsWithReason(target, snapshot.Records)
	if !allMatch {
		return StatusMismatch, &StateCondition{Code: mismatchCode, Target: mismatchReason}
	}

	return StatusOK, &StateCondition{Code: CodeDNSMatchVerified}
}

func resolveTarget(ctx context.Context, app *AppState, target DNSTask) ([]string, error) {
	resolvers := app.resolvers()
	if target.CustomResolver != StrEmpty {
		resolvers = []string{target.CustomResolver}
	}

	var foundRecords []string
	var err error

	if target.Type == RecordTypeIP || target.Type == RecordTypeALIAS {
		foundRecords, err = queryIPRecords(ctx, app, target.Hostname, resolvers)
	} else if qtype, ok := DNSTypeMap[target.Type]; ok {
		foundRecords, err = queryDNS(ctx, app, target.Hostname, qtype, resolvers)

		// CNAME Flattening
		if target.Type == RecordTypeCNAME && len(foundRecords) == 0 && err == nil && len(target.Expected) > 0 {
			apexIPs, apexErr := queryIPRecords(ctx, app, target.Hostname, resolvers)
			if apexErr != nil {
				err = apexErr
			} else if len(apexIPs) > 0 {
				foundRecords = apexIPs
			}
		}
	} else {
		err = fmt.Errorf(MsgErrUnsupportedDNSType, target.Type)
	}

	// Canonicalize and deduplicate foundRecords for IP-returning types
	if err == nil && (target.Type == RecordTypeA || target.Type == RecordTypeAAAA || target.Type == RecordTypeIP || ((target.Type == RecordTypeALIAS || target.Type == RecordTypeCNAME) && len(foundRecords) > 0 && net.ParseIP(foundRecords[0]) != nil)) {
		var canonicalIPs []string
		for _, r := range foundRecords {
			if ip := net.ParseIP(r); ip != nil {
				can := ip.String()
				if !slices.Contains(canonicalIPs, can) {
					canonicalIPs = append(canonicalIPs, can)
				}
			}
		}
		if len(canonicalIPs) > 0 {
			slices.Sort(canonicalIPs)
			foundRecords = canonicalIPs
		}
	}

	return foundRecords, err
}

func validateRecords(target DNSTask, foundRecords []string) bool {
	valid, _, _ := validateRecordsWithReason(target, foundRecords)
	return valid
}

func validateRecordsWithReason(target DNSTask, foundRecords []string) (bool, string, ResultCode) {
	matchType := strings.ToLower(strings.TrimSpace(target.MatchType))
	if matchType == StrEmpty {
		matchType = MatchExact
	}

	switch matchType {
	case MatchPrefix:
		allMatch := true
		var mismatchReasons []string
		var inlineFound [8]string
		var lowerFound []string
		if len(target.Expected) > 1 {
			if len(foundRecords) <= len(inlineFound) {
				lowerFound = inlineFound[:len(foundRecords)]
			} else {
				lowerFound = make([]string, len(foundRecords))
			}
			for i, found := range foundRecords {
				lowerFound[i] = strings.ToLower(strings.TrimSpace(found))
			}
		}
		for _, expected := range target.Expected {
			matched := false
			normalizedExpected := strings.ToLower(strings.TrimSpace(expected))
			for i, found := range foundRecords {
				var value string
				if lowerFound != nil {
					value = lowerFound[i]
				} else {
					value = strings.ToLower(strings.TrimSpace(found))
				}
				if strings.HasPrefix(value, normalizedExpected) {
					matched = true
					break
				}
			}
			if !matched {
				allMatch = false
				mismatchReasons = append(mismatchReasons, fmt.Sprintf(MsgReasonPrefixNotFound, expected, strings.Join(foundRecords, SymCommaSpace)))
			}
		}
		if !allMatch {
			return false, strings.Join(mismatchReasons, SymSemicolonSpace), CodeDNSPrefixMismatch
		}
		return true, StrEmpty, CodeDNSMatchVerified

	case MatchContains:
		allMatch := true
		var mismatchReasons []string
		var inlineFound [8]string
		var lowerFound []string
		if len(target.Expected) > 1 {
			if len(foundRecords) <= len(inlineFound) {
				lowerFound = inlineFound[:len(foundRecords)]
			} else {
				lowerFound = make([]string, len(foundRecords))
			}
			for i, found := range foundRecords {
				lowerFound[i] = strings.ToLower(found)
			}
		}
		for _, expected := range target.Expected {
			matched := false
			normalizedExpected := strings.ToLower(expected)
			for i, found := range foundRecords {
				var value string
				if lowerFound != nil {
					value = lowerFound[i]
				} else {
					value = strings.ToLower(found)
				}
				if strings.Contains(value, normalizedExpected) {
					matched = true
					break
				}
			}
			if !matched {
				allMatch = false
				mismatchReasons = append(mismatchReasons, fmt.Sprintf(MsgReasonSubstringNotFound, expected, strings.Join(foundRecords, SymCommaSpace)))
			}
		}
		if !allMatch {
			return false, strings.Join(mismatchReasons, SymSemicolonSpace), CodeDNSSubstringMismatch
		}
		return true, StrEmpty, CodeDNSMatchVerified

	case MatchAnyOf:
		matched := false
		for _, found := range foundRecords {
			if slices.Contains(target.Expected, found) {
				matched = true
				break
			}
		}
		if !matched {
			return false, fmt.Sprintf(MsgReasonNoneMatched, strings.Join(target.Expected, StrOr), strings.Join(foundRecords, SymCommaSpace)), CodeDNSMismatch
		}
		return true, StrEmpty, CodeDNSMatchVerified

	default: // MatchExact
		allMatch := true
		var mismatchReasons []string
		var missing []string
		for _, expected := range target.Expected {
			if !slices.Contains(foundRecords, expected) {
				missing = append(missing, expected)
				allMatch = false
			}
		}
		if len(missing) > 0 {
			mismatchReasons = append(mismatchReasons, fmt.Sprintf(MsgReasonMissingRecords, strings.Join(missing, SymCommaSpace)))
		}

		var unauthorized []string
		for _, found := range foundRecords {
			if !slices.Contains(target.Expected, found) {
				if target.domainCAA && target.Type == RecordTypeCAA && caaTagIsUnconstrained(found, target.Expected) {
					continue
				}
				unauthorized = append(unauthorized, found)
				allMatch = false
			}
		}
		if len(unauthorized) > 0 {
			mismatchReasons = append(mismatchReasons, fmt.Sprintf(MsgReasonUnauthorizedRecords, strings.Join(unauthorized, SymCommaSpace)))
		}

		if !allMatch {
			return false, strings.Join(mismatchReasons, SymPipeSpaced), CodeDNSMismatch
		}
		return true, StrEmpty, CodeDNSMatchVerified
	}
}

// caaTagIsUnconstrained reports whether a well-formed record uses an omitted policy tag.
func caaTagIsUnconstrained(record string, expected []string) bool {
	parts := strings.SplitN(record, SymSpace, 3)
	if len(parts) != 3 {
		return false
	}
	for _, value := range expected {
		expectedParts := strings.SplitN(value, SymSpace, 3)
		if len(expectedParts) == 3 && strings.EqualFold(expectedParts[1], parts[1]) {
			return false
		}
	}
	return true
}

func hasUsableDKIMKey(record string) bool {
	tags, valid := parseSemicolonTags(record)
	if !valid {
		return false
	}
	if version, exists := tags[DNSPolicyTagVersion]; exists && !strings.EqualFold(DNSPolicyTagVersion+SymEquals+version, DKIMPrefix) {
		return false
	}
	keyType := strings.ToLower(tags[DKIMTagKeyType])
	if keyType != StrEmpty && keyType != DKIMKeyTypeRSA && keyType != DKIMKeyTypeEd25519 {
		return false
	}
	key, exists := tags[DNSPolicyTagPublicKey]
	if !exists || key == StrEmpty {
		return false
	}
	return validDKIMPublicKey(keyType, key)
}

func parseSemicolonTags(record string) (map[string]string, bool) {
	tags := make(map[string]string)
	rem := record
	for len(rem) > 0 {
		var part string
		idx := strings.IndexByte(rem, ';')
		if idx >= 0 {
			part = rem[:idx]
			rem = rem[idx+1:]
		} else {
			part = rem
			rem = ""
		}
		if strings.TrimSpace(part) == StrEmpty {
			continue
		}
		key, value, ok := strings.Cut(strings.TrimSpace(part), SymEquals)
		if !ok || strings.TrimSpace(key) == StrEmpty {
			return nil, false
		}
		key = strings.ToLower(strings.TrimSpace(key))
		if _, duplicate := tags[key]; duplicate {
			return nil, false
		}
		tags[key] = strings.TrimSpace(value)
	}
	return tags, true
}

func validDKIMPublicKey(keyType, key string) bool {
	decoded, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(key), StrEmpty))
	if err != nil {
		decoded, err = base64.RawStdEncoding.DecodeString(strings.Join(strings.Fields(key), StrEmpty))
	}
	if err != nil || len(decoded) == 0 {
		return false
	}
	if keyType == DKIMKeyTypeEd25519 {
		return len(decoded) == ed25519.PublicKeySize
	}
	parsed, err := x509.ParsePKIXPublicKey(decoded)
	if err != nil {
		return false
	}
	_, ok := parsed.(*rsa.PublicKey)
	return ok
}

func hasValidDMARCPolicy(record string) bool {
	var firstPart string
	if idx := strings.IndexByte(record, ';'); idx != -1 {
		firstPart = record[:idx]
	} else {
		firstPart = record
	}
	if !strings.EqualFold(strings.TrimSpace(firstPart), DMARCPrefix) {
		return false
	}
	tags, valid := parseSemicolonTags(record)
	if !valid {
		return false
	}
	validPolicy := func(policy string) bool {
		switch strings.ToLower(policy) {
		case DMARCPolicyNone, DMARCPolicyQuarantine, DMARCPolicyReject:
			return true
		default:
			return false
		}
	}
	if !validPolicy(tags[DNSPolicyTagPublicKey]) {
		return false
	}
	for _, tag := range []string{StrSp, StrNp} {
		if value, ok := tags[tag]; ok && !validPolicy(value) {
			return false
		}
	}
	if psd, ok := tags[StrPsd]; ok && !strings.EqualFold(psd, StrY) && !strings.EqualFold(psd, StrN2) {
		return false
	}
	return true
}

// FetchEmailSnapshot queries MX, SPF, DMARC, and configured DKIM selectors.
func FetchEmailSnapshot(ctx context.Context, app *AppState, target DomainConfig) EmailSnapshot {
	var snap EmailSnapshot
	if !target.CheckEmailSecurity {
		return snap
	}

	mxs, mxErr := queryDNS(ctx, app, target.Domain, dns.TypeMX, app.resolvers())
	if mxErr != nil && errors.Is(mxErr, ErrNXDOMAIN) {
		mxs = nil
		mxErr = nil // NXDOMAIN is authoritatively empty
	}
	snap.MXRecords = mxs
	snap.MXErr = mxErr

	snap.SPFRecords, snap.SPFErr = queryDNS(ctx, app, target.Domain, dns.TypeTXT, app.resolvers())

	currentDomain := NormalizeDomain(target.Domain)
	// RFC 9989 Section 4.10 permits at most eight DNS Tree Walk queries. For
	// longer names, query the exact name and then resume at its last seven labels.
	for queryCount := 0; queryCount < 8; queryCount++ {
		dmarcHost := StrDMARC + currentDomain
		dmarcTxts, dmarcErr := queryDNS(ctx, app, dmarcHost, dns.TypeTXT, app.resolvers())
		if dmarcErr != nil {
			snap.DMARCErr = dmarcErr
			if !errors.Is(dmarcErr, ErrNXDOMAIN) {
				break // A transient failure cannot be replaced by parent evidence.
			}
		} else {
			snap.DMARCErr = nil
			snap.DMARCRecords = dmarcTxts
			dmarcFound := false
			invalidPolicy := false
			for _, txt := range dmarcTxts {
				if hasValidDMARCPolicy(txt) {
					dmarcFound = true
				} else if strings.HasPrefix(strings.ToLower(strings.TrimSpace(txt)), DMARCPrefix) {
					invalidPolicy = true
				}
			}
			if invalidPolicy {
				snap.DMARCErr = fmt.Errorf(MsgErrInvalidDMARCPolicyAt, dmarcHost)
				break
			}
			if dmarcFound {
				break
			}
		}

		idx := strings.IndexByte(currentDomain, '.')
		if idx == -1 {
			break
		}
		if queryCount == 0 {
			labelCount := 1
			for i := 0; i < len(currentDomain); i++ {
				if currentDomain[i] == '.' {
					labelCount++
				}
			}
			if labelCount > 8 {
				drop := labelCount - 7
				for i := 0; i < drop; i++ {
					currentDomain = currentDomain[strings.IndexByte(currentDomain, '.')+1:]
				}
			} else {
				currentDomain = currentDomain[idx+1:]
			}
		} else {
			currentDomain = currentDomain[idx+1:]
		}
	}
	// Note: if last query failed with non-NXDOMAIN, snap.DMARCErr retains it

	var selectorsToCheck []string
	if target.MailProvider != StrEmpty && app != nil {
		selectorsToCheck = append(selectorsToCheck, app.EmailProviders[target.MailProvider].DKIMSelectors...)
	}
	selectorsToCheck = append(selectorsToCheck, target.DKIMSelectors...)

	for _, selector := range DeduplicateNonEmptyStrings(selectorsToCheck) {
		dkimHost := selector + StrDomainkey + target.Domain
		dkimTxts, err := queryDNS(ctx, app, dkimHost, dns.TypeTXT, app.resolvers())
		if err != nil {
			if !errors.Is(err, ErrNXDOMAIN) {
				if snap.DKIMErrs == nil {
					snap.DKIMErrs = make(map[string]error)
				}
				snap.DKIMErrs[selector] = err
			} else {
				if snap.DKIMResults == nil {
					snap.DKIMResults = make(map[string]bool)
				}
				snap.DKIMResults[selector] = false
			}
		} else {
			dkimFound := false
			for _, txt := range dkimTxts {
				if hasUsableDKIMKey(txt) {
					dkimFound = true
					break
				}
			}
			if snap.DKIMResults == nil {
				snap.DKIMResults = make(map[string]bool)
			}
			snap.DKIMResults[selector] = dkimFound
		}
	}

	return snap
}

// EvaluateEmailSecurity evaluates published email records without sending alerts.
func EvaluateEmailSecurity(target DomainConfig, snap EmailSnapshot, app *AppState) (CheckStatus, *StateCondition, EmailState) {
	if !target.CheckEmailSecurity {
		return StatusOK, nil, EmailState{}
	}

	var conditions []StateCondition
	emailStatus := StatusOK

	// MX
	var liveMXs []string
	switch {
	case errors.Is(snap.MXErr, ErrInvalidNullMX):
		emailStatus = StatusMismatch
		conditions = append(conditions, StateCondition{Code: CodeEmailInvalidNullMX, Target: snap.MXErr.Error()})
	case snap.MXErr != nil:
		emailStatus = StatusFailed
		conditions = append(conditions, StateCondition{Code: CodeDNSLookupFailed, Target: snap.MXErr.Error()})
	case len(snap.MXRecords) == 0:
		emailStatus = StatusFailed
		conditions = append(conditions, StateCondition{Code: CodeEmailMissingMX})
	default:
		liveMXs = append(liveMXs, snap.MXRecords...)
		if len(target.MXRecords) > 0 {
			allMatch := true
			for _, expected := range target.MXRecords {
				if !slices.Contains(liveMXs, expected) {
					allMatch = false
					conditions = append(conditions, StateCondition{Code: CodeEmailMissingMX, Target: expected})
				}
			}
			for _, found := range liveMXs {
				if !slices.Contains(target.MXRecords, found) {
					allMatch = false
					conditions = append(conditions, StateCondition{Code: CodeEmailUnauthorizedMX, Target: found})
				}
			}
			if !allMatch && emailStatus == StatusOK {
				emailStatus = StatusMismatch
			}
		} else if target.MailProvider != StrEmpty {
			var safe, known bool
			if app != nil {
				if provider, ok := app.EmailProviders[target.MailProvider]; ok {
					known = true
					safe = isProviderMXSafeDynamic(liveMXs, provider)
				}
			}
			if !known {
				LogWarnf(MsgLogEmailUnknownProvider, target.MailProvider, target.Domain)
			} else if !safe {
				emailStatus = StatusHijacked
				conditions = append(conditions, StateCondition{Code: CodeEmailHijackedMX, Target: strings.Join(liveMXs, SymCommaSpace)})
			}
		}
	}

	// SPF
	var spfFound bool
	if snap.SPFErr != nil {
		if emailStatus == StatusOK {
			emailStatus = StatusWarning
		}
		conditions = append(conditions, StateCondition{Code: CodeDNSLookupFailed, Target: StrSPF + snap.SPFErr.Error()})
	} else {
		spfCount := 0
		for _, txt := range snap.SPFRecords {
			txtLower := strings.ToLower(strings.TrimSpace(txt))
			if strings.HasPrefix(txtLower, SPFPrefix+SymSpace) || txtLower == SPFPrefix {
				spfCount++
			}
		}
		switch {
		case spfCount == 0:
			if emailStatus == StatusOK {
				emailStatus = StatusWarning
			}
			conditions = append(conditions, StateCondition{Code: CodeEmailMissingSPF})
		case spfCount > 1:
			if emailStatus == StatusOK {
				emailStatus = StatusWarning
			}
			conditions = append(conditions, StateCondition{Code: CodeEmailMultipleSPF})
		default:
			spfFound = true
		}
	}

	// DMARC
	var dmarcFound bool
	if snap.DMARCErr != nil && !errors.Is(snap.DMARCErr, ErrNXDOMAIN) {
		emailStatus = StatusFailed
		conditions = append(conditions, StateCondition{Code: CodeDNSLookupFailed, Target: StrDmarc2 + snap.DMARCErr.Error()})
	} else {
		dmarcCount := 0
		for _, txt := range snap.DMARCRecords {
			if hasValidDMARCPolicy(txt) {
				dmarcCount++
			}
		}
		if dmarcCount > 0 {
			if dmarcCount > 1 {
				if emailStatus == StatusOK {
					emailStatus = StatusWarning
				}
				conditions = append(conditions, StateCondition{Code: CodeEmailMultipleDMARC})
			} else {
				dmarcFound = true
			}
		} else {
			if emailStatus == StatusOK {
				emailStatus = StatusWarning
			}
			conditions = append(conditions, StateCondition{Code: CodeEmailMissingDMARC})
		}
	}

	// DKIM
	var validDkims []string
	var missingDkims []string
	var dkimNetworkErr error
	for sel, err := range snap.DKIMErrs {
		if err != nil {
			dkimNetworkErr = err
			missingDkims = append(missingDkims, sel)
		}
	}
	for sel, found := range snap.DKIMResults {
		if found {
			validDkims = append(validDkims, sel)
		} else {
			missingDkims = append(missingDkims, sel)
		}
	}

	hasDKIMExpected := len(target.DKIMSelectors) > 0
	if app != nil && len(app.EmailProviders[target.MailProvider].DKIMSelectors) > 0 {
		hasDKIMExpected = true
	}
	slices.Sort(validDkims)
	slices.Sort(missingDkims)
	if hasDKIMExpected && (len(validDkims) == 0 || dkimNetworkErr != nil) {
		if dkimNetworkErr != nil {
			if emailStatus == StatusOK {
				emailStatus = StatusWarning
			}
			conditions = append(conditions, StateCondition{Code: CodeDNSLookupFailed, Target: StrDKIM + dkimNetworkErr.Error()})
		} else {
			if emailStatus == StatusOK {
				emailStatus = StatusWarning
			}
			conditions = append(conditions, StateCondition{Code: CodeEmailMissingDKIM, Target: strings.Join(missingDkims, SymCommaSpace)})
		}
	}

	var errs []string
	if snap.SPFErr != nil {
		errs = append(errs, fmt.Sprintf(MsgErrSPFLookupError, snap.SPFErr.Error()))
	}
	if snap.DMARCErr != nil && !errors.Is(snap.DMARCErr, ErrNXDOMAIN) {
		errs = append(errs, fmt.Sprintf(MsgErrDMARCLookupError, snap.DMARCErr.Error()))
	}
	if dkimNetworkErr != nil {
		errs = append(errs, fmt.Sprintf(MsgErrDKIMLookupError, dkimNetworkErr.Error()))
	}

	state := EmailState{
		Status:       emailStatus,
		Provider:     target.MailProvider,
		SPF:          spfFound,
		DMARC:        dmarcFound,
		DKIMExpected: hasDKIMExpected,
		DKIMValid:    validDkims,
		MX:           liveMXs,
		Error:        strings.Join(errs, SymPipeSpaced),
	}

	// Return highest priority condition
	var finalCond *StateCondition
	if len(conditions) > 0 {
		c := conditions[0]
		if emailStatus == StatusFailed && snap.DMARCErr != nil && !errors.Is(snap.DMARCErr, ErrNXDOMAIN) {
			c = StateCondition{Code: CodeDNSLookupFailed, Target: StrDmarc2 + snap.DMARCErr.Error()}
		}
		finalCond = &c
	} else if emailStatus == StatusOK {
		finalCond = &StateCondition{Code: CodeEmailVerified}
	}

	return emailStatus, finalCond, state
}

func isProviderMXSafeDynamic(liveMXs []string, provider ProviderConfig) bool {
	suffixes := provider.MXRecords
	if len(liveMXs) == 0 {
		return false
	}

	for _, mx := range liveMXs {
		mxLower := NormalizeDomain(mx)
		matched := false
		for _, sfx := range suffixes {
			if mxLower == sfx || strings.HasSuffix(mxLower, SymDot+sfx) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

// FetchNSSnapshot queries SOA and optional DNSKEY evidence for one nameserver.
func FetchNSSnapshot(ctx context.Context, app *AppState, nsName string, isPrimary bool, target DomainConfig) NSSnapshot {
	srv := NSSnapshot{Nameserver: nsName, IsPrimary: isPrimary}
	addresses, partial, err := resolveNSAddresses(ctx, app, nsName)
	srv.PartialError = partial
	if err != nil {
		srv.Err, srv.Unreachable = err, true
		return srv
	}
	soaMsg, selectedAddress, queryError := selectNSSOA(ctx, app, target.Domain, addresses)
	if queryError != nil {
		srv.PartialError = queryError
	}
	if selectedAddress == StrEmpty {
		srv.Err, srv.Unreachable = srv.PartialError, true
		return srv
	}
	srv.Authoritative = soaMsg.Authoritative
	if !srv.Authoritative {
		if isPrimary {
			srv.Err = errors.New(MsgErrPrimaryNSNotAuthoritative) //nolint:staticcheck // ST1005: preserve existing diagnostic text.
		} else {
			srv.Err = errors.New(MsgErrSecondaryNSNotAuthoritative) //nolint:staticcheck // ST1005: preserve existing diagnostic text.
		}
	}

	srv.SOASerial, srv.HasSOA = findSOASerial(soaMsg, target.Domain)
	if !srv.HasSOA {
		soaMissingErr := errors.New(MsgErrNoSOARecordReturned) //nolint:staticcheck // ST1005: preserve existing diagnostic text.
		if srv.Err == nil {
			srv.Err = soaMissingErr
		}
	}

	if target.DNSSEC {
		fetchNSDNSKEY(ctx, app, target.Domain, selectedAddress, &srv)
	}
	return srv
}

func resolveNSAddresses(ctx context.Context, app *AppState, name string) ([]string, error, error) {
	host, port, err := net.SplitHostPort(DefaultPort(name, DefaultDNSPort))
	if err != nil {
		return nil, nil, WrapError(fmt.Sprintf(MsgErrInvalidNSAddress, name), err)
	}
	if net.ParseIP(host) != nil {
		return []string{net.JoinHostPort(host, port)}, nil, nil
	}
	ips, lookupErr := queryIPRecords(ctx, app, host, app.resolvers())
	var partial error
	if lookupErr != nil {
		partial = WrapError(MsgErrFailedToResolveIP, lookupErr)
	}
	if len(ips) == 0 {
		if partial != nil {
			return nil, partial, partial
		}
		return nil, nil, fmt.Errorf(MsgErrNoIPRecordsForHost, host)
	}
	addresses := make([]string, 0, len(ips))
	for _, ip := range ips {
		addresses = append(addresses, net.JoinHostPort(ip, port))
	}
	return addresses, partial, nil
}

func selectNSSOA(ctx context.Context, app *AppState, domain string, addresses []string) (*dns.Msg, string, error) {
	var firstResponse *dns.Msg
	var firstAddress string
	var partial error
	for _, address := range addresses {
		response, err := queryDNSMsgWithRD(ctx, app, domain, dns.TypeSOA, []string{address}, false)
		if err == nil && response != nil {
			if firstResponse == nil {
				firstResponse, firstAddress = response, address
			}
			if response.Authoritative && hasSOAForDomain(response, domain) {
				return response, address, partial
			}
			partial = fmt.Errorf(MsgErrNameserverAddressDidNotReturn, address, domain)
			continue
		}
		if err == nil {
			err = fmt.Errorf(MsgErrNameserverAddressReturnedANil, address)
		}
		partial = fmt.Errorf(MsgErrSOALookupFailed, err)
	}
	return firstResponse, firstAddress, partial
}

func hasSOAForDomain(message *dns.Msg, domain string) bool {
	_, found := findSOAForDomain(message, domain)
	return found
}

func findSOASerial(message *dns.Msg, domain string) (uint32, bool) {
	soa, found := findSOAForDomain(message, domain)
	if found {
		return soa.Serial, true
	}
	return 0, false
}

func findSOAForDomain(message *dns.Msg, domain string) (*dns.SOA, bool) {
	owner := dns.Fqdn(domain)
	for _, rr := range message.Answer {
		if soa, ok := rr.(*dns.SOA); ok && soa.Hdr.Class == dns.ClassINET && strings.EqualFold(soa.Hdr.Name, owner) {
			return soa, true
		}
	}
	for _, rr := range message.Ns {
		if soa, ok := rr.(*dns.SOA); ok && soa.Hdr.Class == dns.ClassINET && strings.EqualFold(soa.Hdr.Name, owner) {
			return soa, true
		}
	}
	return nil, false
}

func fetchNSDNSKEY(ctx context.Context, app *AppState, domain, address string, srv *NSSnapshot) {
	message, err := queryDNSMsgWithRD(ctx, app, domain, dns.TypeDNSKEY, []string{address}, false)
	if err != nil || message == nil {
		if err == nil {
			err = fmt.Errorf(MsgErrNilDnskeyResponseFor, domain)
		}
		srv.DNSKEYErr = err
		return
	}
	for _, rr := range message.Answer {
		if key, ok := rr.(*dns.DNSKEY); ok && key.Hdr.Class == dns.ClassINET && strings.EqualFold(key.Hdr.Name, dns.Fqdn(domain)) {
			fingerprint := strconv.Itoa(int(key.Flags)) + SymHyphen + strconv.Itoa(int(key.Protocol)) + SymHyphen + strconv.Itoa(int(key.Algorithm)) + SymHyphen + key.PublicKey
			srv.DNSKEYs = append(srv.DNSKEYs, fingerprint)
		}
	}
	if len(srv.DNSKEYs) > 0 {
		slices.Sort(srv.DNSKEYs)
		srv.HasDNSKEY = true
	}
}

// FetchNSHealthSnapshots queries each distinct configured nameserver in order.
func FetchNSHealthSnapshots(ctx context.Context, app *AppState, target DomainConfig) []NSSnapshot {
	if !target.VerifyNSHealth || len(target.ExpectedNS) == 0 {
		return nil
	}

	snapshots := make([]NSSnapshot, 0, len(target.ExpectedNS)+len(target.SecondaryNS))
	seen := make(map[string]bool)
	for index, name := range append(slices.Clone(target.ExpectedNS), target.SecondaryNS...) {
		name = strings.TrimSpace(name)
		key := strings.ToLower(strings.TrimSuffix(name, SymDot))
		if key == StrEmpty || seen[key] {
			continue
		}
		seen[key] = true
		snapshots = append(snapshots, FetchNSSnapshot(ctx, app, name, index < len(target.ExpectedNS), target))
	}

	return snapshots
}

// EvaluateNSHealth checks authority, SOA consistency, and optional DNSKEY agreement.
func EvaluateNSHealth(target DomainConfig, snapshots []NSSnapshot) (CheckStatus, *StateCondition) {
	if len(snapshots) == 0 {
		return StatusOK, nil
	}

	ct := ConditionTracker{Status: StatusOK}

	var baseline *NSSnapshot
	for i := range snapshots {
		srv := &snapshots[i]
		switch {
		case srv.Unreachable:
			ct.Promote(StatusFailed, CodeNSUnreachable, srv.Nameserver)
		case !srv.Authoritative:
			ct.Promote(StatusFailed, CodeNSNotAuthoritative, srv.Nameserver)
		case !srv.HasSOA:
			ct.Promote(StatusFailed, CodeNSMissingSOA, srv.Nameserver)
		}
		if srv.PartialError != nil {
			ct.Promote(StatusWarning, CodeNSUnreachable, srv.Nameserver)
		}
		if target.DNSSEC && srv.DNSKEYErr != nil {
			ct.Promote(StatusFailed, CodeNSDNSKEYMismatch, srv.Nameserver)
		}
		if !srv.Authoritative || !srv.HasSOA {
			continue
		}
		if baseline == nil {
			baseline = srv
			continue
		}
		if srv.SOASerial != baseline.SOASerial {
			ct.Promote(StatusWarning, CodeNSSOALags, srv.Nameserver)
		}
		if target.DNSSEC && !slices.Equal(baseline.DNSKEYs, srv.DNSKEYs) {
			ct.Promote(StatusFailed, CodeNSDNSKEYMismatch, srv.Nameserver)
		}
	}

	if ct.Cond == nil {
		ct.Cond = &StateCondition{Code: CodeNSSyncVerified, Target: target.Domain}
	}

	return ct.Status, ct.Cond
}
