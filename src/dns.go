package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
)


func checkSSLExpiryDays(ctx context.Context, hostname string, ips []string, acceptSelfSigned bool) (int, error) {
	dialHost := hostname
	if strings.HasPrefix(dialHost, PrefixWildcard) {
		// Replace *. with www. to ensure a valid FQDN is used for DNS resolution and SNI
		dialHost = strings.Replace(dialHost, PrefixWildcard, PrefixWWW, 1)
	}

	targets := []string{}
	for _, ipStr := range ips {
		clean := strings.TrimSpace(ipStr)
		if host, _, err := net.SplitHostPort(clean); err == nil {
			if net.ParseIP(host) != nil {
				targets = append(targets, clean)
			}
		} else if net.ParseIP(clean) != nil {
			targets = append(targets, DefaultPort(clean, DefaultHTTPSPort))
		}
	}

	if len(targets) == 0 {
		targets = []string{DefaultPort(dialHost, DefaultHTTPSPort)}
	}

	minDays := MaxSSLDaysSentinel
	hasDays := false
	var lastErr error
	successCount := 0

	for _, targetAddr := range targets {
		dialer := &tls.Dialer{
			NetDialer: &net.Dialer{Timeout: DefaultDNSTimeout},
			Config: &tls.Config{
				ServerName:         dialHost,
				InsecureSkipVerify: true,
				VerifyConnection: func(cs tls.ConnectionState) error {
					if len(cs.PeerCertificates) == 0 {
						return ErrNoPeerCertificates
					}
					cert := cs.PeerCertificates[0]
					if err := cert.VerifyHostname(dialHost); err != nil {
						return fmt.Errorf(MsgErrSSLInvalid, ErrSSLValidation, dialHost, targetAddr, err)
					}
					if !acceptSelfSigned {
						opts := x509.VerifyOptions{
							DNSName:       dialHost,
							Intermediates: x509.NewCertPool(),
						}
						for _, c := range cs.PeerCertificates[1:] {
							opts.Intermediates.AddCert(c)
						}
						if _, err := cert.Verify(opts); err != nil {
							var invalidErr x509.CertificateInvalidError
							if errors.As(err, &invalidErr) && invalidErr.Reason == x509.Expired {
								return nil // Allow expired to pass handshake to measure negative days
							}
							return fmt.Errorf(MsgErrSSLCertValidationFailed, ErrSSLValidation, dialHost, targetAddr, err)
						}
					}
					return nil
				},
			},
		}
		conn, err := dialer.DialContext(ctx, "tcp", targetAddr)
		if err != nil {
			lastErr = err
			continue
		}
		if conn == nil {
			lastErr = fmt.Errorf(MsgErrNilConnection, targetAddr)
			continue
		}

		tlsConn, ok := conn.(*tls.Conn)
		if !ok {
			_ = conn.Close()
			lastErr = fmt.Errorf(MsgErrNonTLSConnection, targetAddr)
			continue
		}
		state := tlsConn.ConnectionState()
		_ = conn.Close()

		if len(state.PeerCertificates) == 0 {
			lastErr = fmt.Errorf(MsgErrNoPeerCertsFound, targetAddr)
			continue
		}

		cert := state.PeerCertificates[0]
		days := int(math.Floor(time.Until(cert.NotAfter).Hours() / 24))
		if !hasDays || days < minDays {
			minDays = days
			hasDays = true
		}
		successCount++
	}

	if successCount == 0 {
		return SSLDaysError, lastErr
	}

	return minDays, nil
}

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
	if app != nil && len(resolvers) > 0 {
		startIdx = int(app.GlobalResolverIndex.Add(1) % uint32(len(resolvers)))
	}

	var lastErr error
	dnsClient := new(dns.Client)
	dnsClient.Timeout = DefaultDNSTimeout
	dnsMsg := new(dns.Msg)
	fqdn := dns.Fqdn(hostname)
	dnsMsg.SetQuestion(fqdn, qtype)
	dnsMsg.SetEdns0(MaxBodyDrainSize, true)
	dnsMsg.RecursionDesired = recursionDesired

	for attempt := range resolvers {
		idx := (startIdx + attempt) % len(resolvers)
		ip := DefaultPort(resolvers[idx], DefaultDNSPort)

		// Reset Net to UDP before each retry in case a previous attempt used TCP
		dnsClient.Net = ""
		dnsMsg.Id = 0

		var r *dns.Msg
		var err error

		if app != nil && app.DNSClient != nil {
			r, _, err = app.DNSClient.ExchangeContext(ctx, dnsMsg, ip)
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

		// Verify question section echoes request per RFC 5452 Section 4
		if len(r.Question) == 0 || !strings.EqualFold(r.Question[0].Name, fqdn) || r.Question[0].Qtype != qtype {
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

	var results []string
	for _, ans := range r.Answer {
		switch record := ans.(type) {
		case *dns.A:
			if qtype == dns.TypeA {
				results = append(results, record.A.String())
			}
		case *dns.AAAA:
			if qtype == dns.TypeAAAA {
				results = append(results, record.AAAA.String())
			}
		case *dns.CNAME:
			if qtype == dns.TypeCNAME {
				results = append(results, NormalizeDomain(record.Target))
			}
		case *dns.MX:
			if qtype == dns.TypeMX {
				mx := NormalizeDomain(record.Mx)
				if mx == "" && record.Mx == NullMXRecord {
					mx = NullMXRecord
				}
				results = append(results, mx)
			}
		case *dns.TXT:
			if qtype == dns.TypeTXT {
				results = append(results, strings.Join(record.Txt, ""))
			}
		case *dns.CAA:
			if qtype == dns.TypeCAA {
				results = append(results, record.String())
			}
		case *dns.NS:
			if qtype == dns.TypeNS {
				results = append(results, NormalizeDomain(record.Ns))
			}
		}
	}

	return results, nil
}

// queryCAARecords queries CAA records and returns structured entries
// instead of raw string representations that require brittle re-parsing.
func queryCAARecords(ctx context.Context, app *AppState, hostname string, resolvers []string) ([]CAAEntry, error) {
	r, err := queryDNSMsg(ctx, app, hostname, dns.TypeCAA, resolvers)
	if err != nil {
		return nil, err
	}
	if r == nil {
		return nil, ErrEmptyDNSResponse
	}

	var entries []CAAEntry
	for _, ans := range r.Answer {
		if caa, ok := ans.(*dns.CAA); ok {
			val := strings.Trim(strings.TrimSpace(caa.Value), "\"")
			val = strings.TrimSpace(val)
			if val == "" || val == CAADenyAll {
				val = CAADenyAll
			}
			entries = append(entries, CAAEntry{
				Flag:  caa.Flag,
				Tag:   strings.ToLower(caa.Tag),
				Value: val,
			})
		}
	}
	return entries, nil
}

// parseCAAIssuer extracts the CA domain from a CAA value string.
// Returns ";" if the record is an explicit deny-all (e.g. ";", "", "\";\"", or "; parameter=val").
func parseCAAIssuer(rawVal string) string {
	val := strings.Trim(strings.TrimSpace(rawVal), "\"")
	val = strings.TrimSpace(val)
	if val == "" || val == CAADenyAll {
		return CAADenyAll
	}
	parts := strings.SplitN(val, ";", 2)
	issuer := strings.Trim(strings.TrimSpace(parts[0]), "\"")
	issuer = strings.TrimSpace(issuer)
	if issuer == "" || issuer == CAADenyAll {
		return CAADenyAll
	}
	return strings.ToLower(issuer)
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
	if aErr != nil && aaaaErr != nil {
		return found, WrapError(MsgErrLookupFailedAandAAAA, errors.Join(aErr, aaaaErr))
	}
	return found, nil
}

func FetchCAASnapshot(ctx context.Context, app *AppState, target DomainConfig) CAASnapshot {
	if target.CAA == nil {
		return CAASnapshot{}
	}
	res, found := fetchCAA(ctx, app, target.Domain, app.Resolvers())
	return CAASnapshot{Found: found, Result: res}
}

func EvaluateCAA(target DomainConfig, snapshot CAASnapshot) (CheckStatus, *StateCondition, CAAResult) {
	if target.CAA == nil {
		return StatusOK, nil, CAAResult{}
	}
	if !snapshot.Found {
		return StatusFailed, &StateCondition{Code: CodeDNSLookupFailed, Target: MsgErrFailedToQueryCAA}, CAAResult{Valid: false, Error: MsgErrFailedToQueryCAA}
	}
	res := snapshot.Result
	if res.Error != "" {
		res.Valid = false
		return StatusFailed, &StateCondition{Code: CodeDNSLookupFailed, Target: res.Error}, res
	}

	liveIssue := make(map[string]bool)
	liveIssueWild := make(map[string]bool)
	liveIssueMail := make(map[string]bool)

	for _, v := range res.Issue {
		if issuer := parseCAAIssuer(v); issuer != "" {
			liveIssue[issuer] = true
		}
	}
	for _, v := range res.IssueWild {
		if issuer := parseCAAIssuer(v); issuer != "" {
			liveIssueWild[issuer] = true
		}
	}
	for _, v := range res.IssueMail {
		if issuer := parseCAAIssuer(v); issuer != "" {
			liveIssueMail[issuer] = true
		}
	}

	res.Valid = true
	var cond *StateCondition
	status := StatusOK

	if target.CAA.Issue != nil {
		res, cond = evaluateCAATag(target, CAATagIssue, target.CAA.Issue, liveIssue, res, cond)
	}
	if target.CAA.IssueWild != nil {
		res, cond = evaluateCAATag(target, CAATagIssueWild, target.CAA.IssueWild, liveIssueWild, res, cond)
	}
	if target.CAA.IssueMail != nil {
		res, cond = evaluateCAATag(target, CAATagIssueMail, target.CAA.IssueMail, liveIssueMail, res, cond)
	}

	if !res.Valid {
		status = StatusFailed
	} else {
		cond = &StateCondition{Code: CodeCAAVerified}
	}

	return status, cond, res
}

func evaluateCAATag(target DomainConfig, tag string, expected []string, live map[string]bool, res CAAResult, cond *StateCondition) (CAAResult, *StateCondition) {
	if expected == nil {
		return res, cond
	}

	if len(expected) == 0 {
		if len(live) == 0 {
			res.Valid = false
			return res, &StateCondition{Code: CodeCAAMissingDenyAll, Target: tag}
		}

		for liveCA := range live {
			if liveCA != CAADenyAll {
				if !slices.Contains(res.UnknownCAs, liveCA) {
					res.UnknownCAs = append(res.UnknownCAs, liveCA)
				}
				res.Valid = false
				if cond == nil {
					cond = &StateCondition{Code: CodeCAAUnexpectedIssuer, Target: liveCA + " in " + tag}
				}
			}
		}
		return res, cond
	}

	expectedMap := make(map[string]bool)
	for _, v := range expected {
		expectedMap[v] = true
	}

	if len(live) == 0 {
		res.Valid = false
		return res, &StateCondition{Code: CodeCAAMissingIssuer, Target: tag}
	}

	for _, exp := range expected {
		if !live[exp] {
			res.Valid = false
			if cond == nil {
				cond = &StateCondition{Code: CodeCAAMissingIssuer, Target: exp + " in " + tag}
			}
		}
	}

	for liveCA := range live {
		if !expectedMap[liveCA] {
			if !slices.Contains(res.UnknownCAs, liveCA) {
				res.UnknownCAs = append(res.UnknownCAs, liveCA)
			}
			res.Valid = false
			if cond == nil {
				cond = &StateCondition{Code: CodeCAAUnexpectedIssuer, Target: liveCA + " in " + tag}
			}
		}
	}
	return res, cond
}

func fetchCAANode(ctx context.Context, app *AppState, domain string, resolvers []string, visitedAliases map[string]bool) (CAAResult, bool) {
	entries, err := queryCAARecords(ctx, app, domain, resolvers)
	if err != nil && !errors.Is(err, ErrNXDOMAIN) {
		return CAAResult{Error: fmt.Sprintf(MsgErrFailedToQueryCAAPattern, domain, err.Error())}, true
	}

	if len(entries) > 0 {
		res := CAAResult{}
		for _, entry := range entries {
			switch entry.Tag {
			case CAATagIssue:
				res.Issue = append(res.Issue, entry.Value)
			case CAATagIssueWild:
				res.IssueWild = append(res.IssueWild, entry.Value)
			case CAATagIssueMail:
				res.IssueMail = append(res.IssueMail, entry.Value)
			}
		}
		return res, true
	}

	// Check for CNAME alias traversal per RFC 8659 Section 3
	if !visitedAliases[domain] && len(visitedAliases) < MaxCNAMEAliasTraversals {
		visitedAliases[domain] = true
		cnames, cErr := queryDNS(ctx, app, domain, dns.TypeCNAME, resolvers)
		if cErr == nil && len(cnames) > 0 {
			target := NormalizeDomain(cnames[0])
			if target != "" && !visitedAliases[target] {
				// Follow the alias and climb its tree. If the alias tree yields no records,
				// it returns nil, allowing the original domain's tree climbing to resume.
				return fetchCAATree(ctx, app, target, resolvers, visitedAliases)
			}
		}
	}
	return CAAResult{}, false
}

func fetchCAATree(ctx context.Context, app *AppState, domain string, resolvers []string, visitedAliases map[string]bool) (CAAResult, bool) {
	currentDomain := domain
	for {
		if res, found := fetchCAANode(ctx, app, currentDomain, resolvers, visitedAliases); found {
			return res, true
		}

		// Tree climbing: strip leftmost label
		_, parent, found := strings.Cut(currentDomain, ".")
		if !found || parent == "" || !strings.Contains(parent, ".") {
			break // Stop at TLD or single label
		}
		currentDomain = parent
	}
	return CAAResult{}, false
}

func fetchCAA(ctx context.Context, app *AppState, domain string, resolvers []string) (CAAResult, bool) {
	currentDomain := NormalizeDomain(domain)
	if currentDomain == "" {
		return CAAResult{Error: MsgErrInvalidEmptyDomainCAA}, true
	}
	return fetchCAATree(ctx, app, currentDomain, resolvers, make(map[string]bool))
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
			if ds, ok := ans.(*dns.DS); ok {
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
			if key, ok := ans.(*dns.DNSKEY); ok {
				dnskeyRecords = append(dnskeyRecords, key)
				res.HasDNSKEY = true
				rrset = append(rrset, ans)

				algoStr := dns.AlgorithmToString[key.Algorithm]
				if algoStr == "" {
					algoStr = PrefixAlgo + strconv.Itoa(int(key.Algorithm))
				}

				found := slices.Contains(res.Algorithms, algoStr)
				if !found {
					res.Algorithms = append(res.Algorithms, algoStr)
				}

			} else if sig, ok := ans.(*dns.RRSIG); ok {
				if sig.TypeCovered == dns.TypeDNSKEY {
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

	// 4. Validate RRSIG covering DNSKEY RRset using DS-authenticated KSK (RFC 4035 Section 5.3)
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
								res.Error = "" // Clear any stale error from previous iteration
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

	// 5. Tier 2: Google DoH (Query zone apex DNSKEY to authenticate chain of trust)
	if dohURLTemplate != "" {
		dohURL := dohURLTemplate
		if u, parseErr := url.Parse(dohURLTemplate); parseErr == nil {
			q := u.Query()
			q.Set(ParamName, domain)
			q.Set(ParamType, RecordTypeDNSKEY)
			q.Set(ParamDO, ParamDOValue)
			u.RawQuery = q.Encode()
			dohURL = u.String()
		} else {
			dohURL = dohURLTemplate + fmt.Sprintf(DoHQueryTemplate, url.QueryEscape(domain))
		}

		dohReq, reqErr := http.NewRequestWithContext(ctx, http.MethodGet, dohURL, nil)

		if reqErr != nil {
			res.Source = DNSSECSourceLocalOnly
		} else {
			dohReq.Header.Set(HeaderAccept, MIMEDNSJSON)
			dohReq.Header.Set(HeaderUserAgent, DefaultUserAgent)
			
			var httpClient HTTPDoer
			if app != nil {
				httpClient = app.HTTPClient
			}
			client := ResolveHTTPClient(httpClient)
			
			dohResp, err := client.Do(dohReq)

			if err != nil || dohResp.StatusCode != http.StatusOK {
				if dohResp != nil {
					DrainAndClose(dohResp.Body, MaxBodyDrainSize)
				}
				res.Source = DNSSECSourceLocalOnly
			} else {
				var dohResult dohJSONResponse
				readErr := jsonv2.UnmarshalRead(io.LimitReader(dohResp.Body, MaxNotificationPayloadSize), &dohResult)
				DrainAndClose(dohResp.Body, MaxBodyDrainSize)
				if readErr == nil {
					if dohResult.Status == 0 && dohResult.AD {
						res.ChainIntact = true
					}
				} else {
					res.Source = DNSSECSourceLocalOnly
				}
			}
		}
	} else {
		res.Source = DNSSECSourceLocalOnly
	}

	// Also check if local validating resolver provided AD flag
	if (keyResp != nil && keyResp.AuthenticatedData) || (dsResp != nil && dsResp.AuthenticatedData) {
		res.ChainIntact = true
	}

	if res.HasDS && res.HasDNSKEY && res.DSMatchesDNSKEY && res.RRSIGValid {
		if res.ChainIntact && res.Source != DNSSECSourceLocalOnly {
			res.Valid = true
			res.Error = ""
		} else if res.Source == DNSSECSourceLocalOnly {
			res.Valid = true
			if res.Error == "" {
				res.Error = MsgErrDNSSECLocalVerifiedDoHUnavailable
			}
		} else {
			res.Valid = false
			if res.Error == "" {
				res.Error = MsgErrDNSSECUpstreamChainBroken
			}
		}
	} else if !res.HasDS && !res.HasDNSKEY {
		// Not signed
		res.Valid = false
	} else {
		res.Valid = false
		if res.Error == "" {
			res.Error = MsgErrDNSSECValidationFailed
		}
	}

	return res
}
func FetchDNSSECSnapshot(ctx context.Context, app *AppState, target DomainConfig) DNSSECSnapshot {
	if !target.DNSSEC {
		return DNSSECSnapshot{}
	}
	dohURL := DefaultDoHURL
	if app != nil && app.Config().DoHURL != "" {
		dohURL = app.Config().DoHURL
	}
	res := validateDNSSEC(ctx, app, target.Domain, app.Resolvers(), dohURL)
	return DNSSECSnapshot{Result: res}
}

func EvaluateDNSSEC(target DomainConfig, snapshot DNSSECSnapshot) (CheckStatus, *StateCondition, DNSSECResult) {
	if !target.DNSSEC {
		return StatusOK, nil, DNSSECResult{}
	}
	res := snapshot.Result
	if res.Source == "" {
		res.Source = DNSSECSourceLocalOnly
		res.Error = MsgErrValidateDNSSECNil
		res.Valid = false
	}
	status := StatusOK
	var cond *StateCondition
	if !res.Valid {
		status = StatusFailed
		if res.Error != "" && strings.Contains(res.Error, "query failed") {
			cond = &StateCondition{Code: CodeDNSLookupFailed, Target: res.Error}
		} else if !res.HasDS && !res.HasDNSKEY {
			cond = &StateCondition{Code: CodeDNSSECDisabled}
		} else if !res.HasDS {
			cond = &StateCondition{Code: CodeDNSSECNoDS}
		} else if !res.HasDNSKEY {
			cond = &StateCondition{Code: CodeDNSSECNoDNSKEY}
		} else if !res.DSMatchesDNSKEY {
			cond = &StateCondition{Code: CodeDNSSECDSMismatch}
		} else if !res.RRSIGValid {
			cond = &StateCondition{Code: CodeDNSSECRRSIGFailed}
		} else if !res.ChainIntact && res.Source != DNSSECSourceLocalOnly {
			cond = &StateCondition{Code: CodeDNSSECChainBroken}
		}
	} else {
		cond = &StateCondition{Code: CodeDNSSECVerified}
	}
	return status, cond, res
}


// FetchDNSSnapshot performs the DNS resolution and returns a snapshot
func FetchDNSSnapshot(ctx context.Context, app *AppState, target DNSTask) DNSSnapshot {
	foundRecords, err := resolveTarget(ctx, app, target)
	return DNSSnapshot{
		Records: foundRecords,
		Err:     err,
	}
}

// EvaluateDNS evaluates the DNS records against the expected ones
func EvaluateDNS(target DNSTask, snapshot DNSSnapshot) (CheckStatus, *StateCondition) {
	if snapshot.Err != nil {
		return StatusFailed, &StateCondition{Code: CodeDNSLookupFailed, Target: snapshot.Err.Error()}
	}

	allMatch, mismatchReason, mismatchCode := validateRecordsWithReason(target, snapshot.Records)
	if !allMatch {
		return StatusMismatch, &StateCondition{Code: mismatchCode, Target: mismatchReason}
	}

	return StatusOK, &StateCondition{Code: CodeDNSMatchVerified}
}

// FetchSSLSnapshot connects to the target on port 443 and fetches the certificate
func FetchSSLSnapshot(ctx context.Context, app *AppState, target DNSTask, foundRecords []string) SSLSnapshot {
	sslDays := SSLDaysNotApplicable
	if !target.SkipSSL {
		sslDays = validateCertificate(ctx, app, target, foundRecords)
	}
	return SSLSnapshot{
		ExpiryDays: sslDays,
	}
}

// EvaluateSSL evaluates the SSL certificate expiry
func EvaluateSSL(target DNSTask, snapshot SSLSnapshot) (CheckStatus, *StateCondition) {
	if snapshot.ExpiryDays == SSLDaysNotApplicable {
		return StatusOK, nil
	}

	if snapshot.ExpiryDays == SSLDaysError || snapshot.ExpiryDays < 0 {
		return StatusFailed, &StateCondition{Code: CodeSSLExpired} // Wait, validateCertificate returns SSLDaysError for network issues. CodeSSLResolveFailed or CodeSSLValidationFailed.
	} else if snapshot.ExpiryDays <= DefaultSSLExpiryWarningDays {
		return StatusWarning, &StateCondition{Code: CodeSSLExpiringSoon}
	}

	return StatusOK, &StateCondition{Code: CodeSSLVerified}
}

func resolveTarget(ctx context.Context, app *AppState, target DNSTask) ([]string, error) {
	resolvers := app.Resolvers()
	if target.CustomResolver != "" {
		resolvers = []string{target.CustomResolver}
	}

	var foundRecords []string
	var err error

	if target.Type == RecordTypeIP || target.Type == RecordTypeALIAS {
		foundRecords, err = queryIPRecords(ctx, app, target.Hostname, resolvers)
		if target.Type == RecordTypeALIAS && err == nil && len(target.Expected) > 0 {
			hasHostnameExpected := false
			for _, exp := range target.Expected {
				if net.ParseIP(exp) == nil {
					hasHostnameExpected = true
					break
				}
			}
			if hasHostnameExpected && len(foundRecords) > 0 {
				var matchedTargets []string
				for _, expectedTarget := range target.Expected {
					expectedIPs, expErr := queryIPRecords(ctx, app, expectedTarget, resolvers)
					if expErr != nil {
						continue
					}
					for _, foundIP := range foundRecords {
						if slices.Contains(expectedIPs, foundIP) {
							matchedTargets = append(matchedTargets, expectedTarget)
							break
						}
					}
				}
				if len(matchedTargets) > 0 {
					foundRecords = matchedTargets
				}
			}
		}
	} else if qtype, ok := DNSTypeMap[target.Type]; ok {
		foundRecords, err = queryDNS(ctx, app, target.Hostname, qtype, resolvers)

		// CNAME Flattening
		if target.Type == RecordTypeCNAME && len(foundRecords) == 0 && err == nil && len(target.Expected) > 0 {
			apexIPs, apexErr := queryIPRecords(ctx, app, target.Hostname, resolvers)
			if apexErr != nil {
				err = apexErr
			} else if len(apexIPs) > 0 {
				hasHostnameExpected := false
				for _, exp := range target.Expected {
					if net.ParseIP(exp) == nil {
						hasHostnameExpected = true
						break
					}
				}
				if hasHostnameExpected {
					for _, expectedTarget := range target.Expected {
						expectedIPs, expErr := queryIPRecords(ctx, app, expectedTarget, resolvers)
						if expErr != nil {
							continue
						}
						if len(expectedIPs) > 0 {
							matchFound := false
							for _, aIP := range apexIPs {
								if slices.Contains(expectedIPs, aIP) {
									matchFound = true
									break
								}
							}
							if matchFound {
								foundRecords = append(foundRecords, expectedTarget)
							}
						}
					}
				} else {
					foundRecords = apexIPs
				}
			}
		}
	} else {
		err = fmt.Errorf(MsgErrUnsupportedDNSType, target.Type)
	}

	// Resilient Fallback mechanism
	if err != nil && target.CustomResolver != "" {
		LogWarnf(MsgLogDNSCustomResolverFailed, target.CustomResolver, target.Hostname)
		target.CustomResolver = ""             // clear custom resolver
		return resolveTarget(ctx, app, target) // Recursive fallback with global resolvers
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
	if matchType == "" {
		matchType = MatchExact
	}

	switch matchType {
	case MatchPrefix:
		allMatch := true
		var mismatchReasons []string
		for _, expected := range target.Expected {
			matched := false
			for _, found := range foundRecords {
				if strings.HasPrefix(strings.ToLower(strings.TrimSpace(found)), strings.ToLower(strings.TrimSpace(expected))) {
					matched = true
					break
				}
			}
			if !matched {
				allMatch = false
				mismatchReasons = append(mismatchReasons, fmt.Sprintf(MsgReasonPrefixNotFound, expected, strings.Join(foundRecords, ", ")))
			}
		}
		if !allMatch {
			return false, strings.Join(mismatchReasons, "; "), CodeDNSPrefixMismatch
		}
		return true, "", CodeDNSMatchVerified

	case MatchContains:
		allMatch := true
		var mismatchReasons []string
		for _, expected := range target.Expected {
			matched := false
			for _, found := range foundRecords {
				if strings.Contains(strings.ToLower(found), strings.ToLower(expected)) {
					matched = true
					break
				}
			}
			if !matched {
				allMatch = false
				mismatchReasons = append(mismatchReasons, fmt.Sprintf(MsgReasonSubstringNotFound, expected, strings.Join(foundRecords, ", ")))
			}
		}
		if !allMatch {
			return false, strings.Join(mismatchReasons, "; "), CodeDNSSubstringMismatch
		}
		return true, "", CodeDNSMatchVerified

	case MatchAnyOf:
		matched := false
		for _, found := range foundRecords {
			if slices.Contains(target.Expected, found) {
				matched = true
				break
			}
		}
		if !matched {
			return false, fmt.Sprintf(MsgReasonNoneMatched, strings.Join(target.Expected, " OR "), strings.Join(foundRecords, ", ")), CodeDNSMismatch
		}
		return true, "", CodeDNSMatchVerified

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
			mismatchReasons = append(mismatchReasons, fmt.Sprintf(MsgReasonMissingRecords, strings.Join(missing, ", ")))
		}

		var unauthorized []string
		for _, found := range foundRecords {
			if !slices.Contains(target.Expected, found) {
				unauthorized = append(unauthorized, found)
				allMatch = false
			}
		}
		if len(unauthorized) > 0 {
			mismatchReasons = append(mismatchReasons, fmt.Sprintf(MsgReasonUnauthorizedRecords, strings.Join(unauthorized, ", ")))
		}

		if !allMatch {
			return false, strings.Join(mismatchReasons, " | "), CodeDNSMismatch
		}
		return true, "", CodeDNSMatchVerified
	}
}

func validateCertificate(ctx context.Context, app *AppState, target DNSTask, foundRecords []string) int {
	if target.SkipSSL {
		return SSLDaysNotApplicable
	}

	if target.Type != RecordTypeA && target.Type != RecordTypeAAAA && target.Type != RecordTypeIP && target.Type != RecordTypeCNAME && target.Type != RecordTypeALIAS {
		return SSLDaysNotApplicable
	}

	var sslIPs []string
	if target.Type == RecordTypeCNAME || target.Type == RecordTypeALIAS {
		resolversToUse := app.Resolvers()
		if target.CustomResolver != "" {
			resolversToUse = []string{target.CustomResolver}
		}
		var ipErr error
		sslIPs, ipErr = queryIPRecords(ctx, app, target.Hostname, resolversToUse)
		if ipErr != nil {
			LogWarn(MsgLogSSLResolveIPsFailed, FieldDomain, target.Hostname, FieldError, ipErr)
		}
	} else {
		sslIPs = foundRecords
	}

	if len(sslIPs) == 0 {
		return SSLDaysError
	}

	days, err := checkSSLExpiryDays(ctx, target.Hostname, sslIPs, target.AcceptSelfSigned)
	if err != nil {
		app.SafeDispatchf(PriorityUrgent, TagRotatingLight, target.Hostname, target.Name, MsgRedactedSSLValidationFailed, MsgAlertSSLError, target.Hostname, err)
		return SSLDaysError
	}

	if days < 0 {
		app.SafeDispatchf(PriorityUrgent, TagRotatingLight, target.Hostname, target.Name, MsgRedactedSSLExpired, MsgAlertSSLExpired, target.Hostname, days)
	} else if days <= DefaultSSLExpiryWarningDays {
		app.SafeDispatchf(PriorityHigh, TagWarning, target.Hostname, target.Name, fmt.Sprintf(MsgRedactedSSLExpires, int(days)), MsgAlertSSLExpiry, target.Hostname, days)
	}
	return days
}

func FetchEmailSnapshot(ctx context.Context, app *AppState, target DomainConfig) EmailSnapshot {
	snap := EmailSnapshot{
		DKIMResults: make(map[string]bool),
		DKIMErrs:    make(map[string]error),
	}
	if !target.CheckEmailSecurity {
		return snap
	}

	mxs, mxErr := queryDNS(ctx, app, target.Domain, dns.TypeMX, app.Resolvers())
	if mxErr != nil && errors.Is(mxErr, ErrNXDOMAIN) {
		mxs = nil
		mxErr = nil // NXDOMAIN is authoritatively empty
	}
	snap.MXRecords = mxs
	snap.MXErr = mxErr

	snap.SPFRecords, snap.SPFErr = queryDNS(ctx, app, target.Domain, dns.TypeTXT, app.Resolvers())

	currentDomain := NormalizeDomain(target.Domain)
	for {
		dmarcHost := "_dmarc." + currentDomain
		dmarcTxts, dmarcErr := queryDNS(ctx, app, dmarcHost, dns.TypeTXT, app.Resolvers())
		if dmarcErr != nil {
			snap.DMARCErr = dmarcErr
		} else {
			snap.DMARCErr = nil
			snap.DMARCRecords = dmarcTxts
			dmarcFound := false
			for _, txt := range dmarcTxts {
				txtLower := strings.ToLower(strings.TrimSpace(txt))
				if strings.HasPrefix(txtLower, DMARCPrefix+" ") || strings.HasPrefix(txtLower, DMARCPrefix+";") || txtLower == DMARCPrefix {
					dmarcFound = true
					break
				}
			}
			if dmarcFound {
				break
			}
		}
		
		_, parent, found := strings.Cut(currentDomain, ".")
		if !found || parent == "" || !strings.Contains(parent, ".") {
			break
		}
		currentDomain = parent
	}
	// Note: if last query failed with non-NXDOMAIN, snap.DMARCErr retains it

	var selectorsToCheck []string
	if target.MailProvider != "" {
		if defaults, ok := ProviderDKIMMap[target.MailProvider]; ok {
			selectorsToCheck = append(selectorsToCheck, defaults...)
		}
	}
	selectorsToCheck = append(selectorsToCheck, target.DKIMSelectors...)

	for _, selector := range selectorsToCheck {
		dkimHost := selector + "._domainkey." + target.Domain
		dkimTxts, err := queryDNS(ctx, app, dkimHost, dns.TypeTXT, app.Resolvers())
		if err != nil {
			if !errors.Is(err, ErrNXDOMAIN) {
				snap.DKIMErrs[selector] = err
			} else {
				snap.DKIMResults[selector] = false
			}
		} else {
			dkimFound := false
			for _, txt := range dkimTxts {
				txtLower := strings.TrimSpace(strings.ToLower(txt))
				if strings.HasPrefix(txtLower, DKIMPrefix) || strings.Contains(txtLower, DKIMPublicKeyTag) {
					dkimFound = true
					break
				}
			}
			snap.DKIMResults[selector] = dkimFound
		}
	}

	return snap
}

func EvaluateEmailSecurity(target DomainConfig, snap EmailSnapshot) (CheckStatus, *StateCondition, EmailState) {
	if !target.CheckEmailSecurity {
		return StatusOK, nil, EmailState{}
	}

	var conditions []StateCondition
	emailStatus := StatusOK

	// MX
	var liveMXs []string
	if snap.MXErr != nil {
		emailStatus = StatusFailed
		conditions = append(conditions, StateCondition{Code: CodeDNSLookupFailed, Target: snap.MXErr.Error()})
	} else if len(snap.MXRecords) == 0 {
		emailStatus = StatusFailed
		conditions = append(conditions, StateCondition{Code: CodeEmailMissingMX})
	} else {
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
		} else if target.MailProvider != "" {
			safe, known := isProviderMXSafe(liveMXs, target.MailProvider)
			if !known {
				LogWarnf(MsgLogEmailUnknownProvider, target.MailProvider, target.Domain)
			} else if !safe {
				emailStatus = StatusHijacked
				conditions = append(conditions, StateCondition{Code: CodeEmailHijackedMX, Target: strings.Join(liveMXs, ", ")})
			}
		}
	}

	// SPF
	var spfFound bool
	if snap.SPFErr != nil {
		if emailStatus == StatusOK {
			emailStatus = StatusWarning
		}
		conditions = append(conditions, StateCondition{Code: CodeDNSLookupFailed, Target: "SPF: " + snap.SPFErr.Error()})
	} else {
		spfCount := 0
		for _, txt := range snap.SPFRecords {
			txtLower := strings.ToLower(strings.TrimSpace(txt))
			if strings.HasPrefix(txtLower, SPFPrefix+" ") || txtLower == SPFPrefix {
				spfCount++
			}
		}
		if spfCount == 0 {
			if emailStatus == StatusOK {
				emailStatus = StatusWarning
			}
			conditions = append(conditions, StateCondition{Code: CodeEmailMissingSPF})
		} else if spfCount > 1 {
			if emailStatus == StatusOK {
				emailStatus = StatusWarning
			}
			conditions = append(conditions, StateCondition{Code: CodeEmailMultipleSPF})
		} else {
			spfFound = true
		}
	}

	// DMARC
	var dmarcFound bool
	if snap.DMARCErr != nil && !errors.Is(snap.DMARCErr, ErrNXDOMAIN) {
		if emailStatus == StatusOK {
			emailStatus = StatusFailed // original logic set status to failed for DMARC error
		}
		conditions = append(conditions, StateCondition{Code: CodeDNSLookupFailed, Target: "DMARC: " + snap.DMARCErr.Error()})
	} else {
		dmarcCount := 0
		for _, txt := range snap.DMARCRecords {
			txtLower := strings.ToLower(strings.TrimSpace(txt))
			if strings.HasPrefix(txtLower, DMARCPrefix+" ") || strings.HasPrefix(txtLower, DMARCPrefix+";") || txtLower == DMARCPrefix {
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

	hasDKIMExpected := (target.MailProvider != "" && len(ProviderDKIMMap[target.MailProvider]) > 0) || len(target.DKIMSelectors) > 0
	if hasDKIMExpected && len(validDkims) == 0 {
		if dkimNetworkErr != nil {
			if emailStatus == StatusOK {
				emailStatus = StatusWarning
			}
			conditions = append(conditions, StateCondition{Code: CodeDNSLookupFailed, Target: "DKIM: " + dkimNetworkErr.Error()})
		} else {
			if emailStatus == StatusOK {
				emailStatus = StatusWarning
			}
			conditions = append(conditions, StateCondition{Code: CodeEmailMissingDKIM, Target: strings.Join(missingDkims, ", ")})
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
		Error:        strings.Join(errs, " | "),
	}

	// Return highest priority condition
	var finalCond *StateCondition
	if len(conditions) > 0 {
		finalCond = &conditions[0]
		// In a complete implementation we might want to attach multiple conditions,
		// but since we return one *StateCondition, we just pick the first (which is usually MX).
	} else if emailStatus == StatusOK {
		finalCond = &StateCondition{Code: CodeEmailVerified}
	}

	return emailStatus, finalCond, state
}

// isProviderMXSafe checks whether all live MX hostnames match the expected provider's domain suffixes.
func isProviderMXSafe(liveMXs []string, provider string) (isSafe bool, knownProvider bool) {
	suffixes, ok := ProviderMXMap[strings.ToLower(strings.TrimSpace(provider))]
	if !ok {
		return false, false
	}
	if len(liveMXs) == 0 {
		return false, true
	}

	for _, mx := range liveMXs {
		mxLower := NormalizeDomain(mx)
		matched := false
		for _, sfx := range suffixes {
			if mxLower == sfx || strings.HasSuffix(mxLower, "."+sfx) {
				matched = true
				break
			}
		}
		if !matched {
			return false, true
		}
	}
	return true, true
}

func FetchNSSnapshot(ctx context.Context, app *AppState, nsName string, isPrimary bool, target DomainConfig) NSSnapshot {
	srv := NSSnapshot{
		Nameserver: nsName,
		IsPrimary:  isPrimary,
	}

	host, port, err := net.SplitHostPort(DefaultPort(nsName, DefaultDNSPort))
	if err != nil {
		srv.Err = WrapError(fmt.Sprintf(MsgErrInvalidNSAddress, nsName), err)
		return srv
	}

	var ip string
	if net.ParseIP(host) != nil {
		ip = net.JoinHostPort(host, port)
	} else {
		ips, ipErr := queryIPRecords(ctx, app, host, app.Resolvers())
		if ipErr != nil {
			srv.Err = WrapError(MsgErrFailedToResolveIP, ipErr)
			return srv
		}
		if len(ips) == 0 {
			srv.Err = fmt.Errorf(MsgErrNoIPRecordsForHost, host)
			return srv
		}
		ip = net.JoinHostPort(ips[0], port)
	}

	soaMsg, soaErr := queryDNSMsgWithRD(ctx, app, target.Domain, dns.TypeSOA, []string{ip}, false)
	if soaErr != nil || soaMsg == nil {
		if soaErr == nil {
			soaErr = fmt.Errorf("nil SOA response")
		}
		srv.Err = fmt.Errorf(MsgErrSOALookupFailed, soaErr.Error())
		return srv
	}

	srv.Authoritative = soaMsg.Authoritative
	if !srv.Authoritative {
		if isPrimary {
			srv.Err = fmt.Errorf(MsgErrPrimaryNSNotAuthoritative)
		} else {
			srv.Err = fmt.Errorf(MsgErrSecondaryNSNotAuthoritative)
		}
	}

	for _, ans := range soaMsg.Answer {
		if soa, ok := ans.(*dns.SOA); ok {
			srv.SOASerial = soa.Serial
			srv.HasSOA = true
			break
		}
	}
	if !srv.HasSOA {
		for _, nsRec := range soaMsg.Ns {
			if soa, ok := nsRec.(*dns.SOA); ok {
				srv.SOASerial = soa.Serial
				srv.HasSOA = true
				break
			}
		}
	}
	if !srv.HasSOA {
		soaMissingErr := fmt.Errorf(MsgErrNoSOARecordReturned)
		if srv.Err == nil {
			srv.Err = soaMissingErr
		}
	}

	if dnskeyMsg, _ := queryDNSMsgWithRD(ctx, app, target.Domain, dns.TypeDNSKEY, []string{ip}, false); dnskeyMsg != nil {
		for _, rr := range dnskeyMsg.Answer {
			if dnskey, ok := rr.(*dns.DNSKEY); ok {
				fps := strconv.Itoa(int(dnskey.Flags)) + "-" + strconv.Itoa(int(dnskey.Protocol)) + "-" + strconv.Itoa(int(dnskey.Algorithm)) + "-" + dnskey.PublicKey
				srv.DNSKEYs = append(srv.DNSKEYs, fps)
			}
		}
		if len(srv.DNSKEYs) > 0 {
			slices.Sort(srv.DNSKEYs)
			srv.HasDNSKEY = true
		}
	}
	return srv
}

func FetchNSHealthSnapshots(ctx context.Context, app *AppState, target DomainConfig) []NSSnapshot {
	if !target.VerifyNSHealth || len(target.ExpectedNS) == 0 {
		return nil
	}

	primaryNS := target.ExpectedNS[0]
	snapshots := make([]NSSnapshot, 0, 1+len(target.SecondaryNS))

	primarySnapshot := FetchNSSnapshot(ctx, app, primaryNS, true, target)
	snapshots = append(snapshots, primarySnapshot)

	for _, secNS := range target.SecondaryNS {
		secNS = strings.TrimSpace(secNS)
		if secNS == "" {
			continue
		}
		secSnapshot := FetchNSSnapshot(ctx, app, secNS, false, target)
		snapshots = append(snapshots, secSnapshot)
	}

	return snapshots
}

func EvaluateNSHealth(target DomainConfig, snapshots []NSSnapshot) (CheckStatus, *StateCondition) {
	if len(snapshots) == 0 {
		return StatusOK, nil
	}

	worstStatus := StatusOK
	var worstCond *StateCondition

	setCond := func(status CheckStatus, code ResultCode, tgt string) {
		if status == StatusFailed {
			worstStatus = StatusFailed
			if worstCond == nil || worstCond.Code == CodeNone || worstStatus != StatusFailed {
				worstCond = &StateCondition{Code: code, Target: tgt}
			}
		} else if status == StatusWarning && worstStatus != StatusFailed {
			worstStatus = StatusWarning
			if worstCond == nil || worstCond.Code == CodeNone {
				worstCond = &StateCondition{Code: code, Target: tgt}
			}
		}
	}

	primary := snapshots[0]
	if primary.Err != nil {
		errStr := primary.Err.Error()
		if strings.Contains(errStr, "resolve IP") || strings.Contains(errStr, "invalid nameserver") || strings.Contains(errStr, "SOA lookup failed") || strings.Contains(errStr, "no IP records") {
			setCond(StatusFailed, CodeNSUnreachable, primary.Nameserver)
		} else if !primary.Authoritative {
			setCond(StatusFailed, CodeNSNotAuthoritative, primary.Nameserver)
		} else if !primary.HasSOA {
			setCond(StatusFailed, CodeNSMissingSOA, primary.Nameserver)
		}
	}

	for _, sec := range snapshots[1:] {
		if sec.Err != nil {
			errStr := sec.Err.Error()
			if strings.Contains(errStr, "resolve IP") || strings.Contains(errStr, "invalid nameserver") || strings.Contains(errStr, "SOA lookup failed") || strings.Contains(errStr, "no IP records") {
				setCond(StatusFailed, CodeNSUnreachable, sec.Nameserver)
			} else if !sec.Authoritative {
				setCond(StatusFailed, CodeNSNotAuthoritative, sec.Nameserver)
			} else if !sec.HasSOA {
				setCond(StatusFailed, CodeNSMissingSOA, sec.Nameserver)
			}
		}

		if primary.HasSOA && sec.HasSOA {
			if sec.SOASerial < primary.SOASerial {
				setCond(StatusFailed, CodeNSSOALags, sec.Nameserver)
			} else if sec.SOASerial != primary.SOASerial {
				setCond(StatusWarning, CodeNSSOALags, sec.Nameserver) // Changed to lags or mismatch
			}
		}

		if primary.HasDNSKEY {
			if !sec.HasDNSKEY {
				setCond(StatusFailed, CodeNSDNSKEYMismatch, sec.Nameserver)
			} else if !slices.Equal(primary.DNSKEYs, sec.DNSKEYs) {
				setCond(StatusFailed, CodeNSDNSKEYMismatch, sec.Nameserver)
			}
		} else if sec.HasDNSKEY {
			setCond(StatusFailed, CodeNSDNSKEYMismatch, sec.Nameserver)
		}
	}

	if worstCond == nil {
		worstCond = &StateCondition{Code: CodeNSSyncVerified, Target: target.Domain}
	}

	return worstStatus, worstCond
}
