package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
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

var dohHTTPClient = ResolveHTTPClient(&http.Client{Timeout: DefaultDNSTimeout})

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

	minDays := 999999
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
		now := time.Now()
		var days int
		if now.After(cert.NotAfter) {
			// Expired: ensure strictly negative integer
			days = int(time.Until(cert.NotAfter).Hours()/24) - 1
			if days >= 0 {
				days = -1
			}
		} else {
			days = int(time.Until(cert.NotAfter).Hours() / 24)
		}
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
	for attempt := range resolvers {
		idx := (startIdx + attempt) % len(resolvers)
		ip := DefaultPort(resolvers[idx], DefaultDNSPort)

		dnsClient := new(dns.Client)
		dnsClient.Timeout = DefaultDNSTimeout

		dnsMsg := new(dns.Msg)
		fqdn := dns.Fqdn(hostname)
		dnsMsg.SetQuestion(fqdn, qtype)
		dnsMsg.SetEdns0(MaxBodyDrainSize, true)
		dnsMsg.RecursionDesired = recursionDesired

		r, _, err := dnsClient.ExchangeContext(ctx, dnsMsg, ip)
		if err == nil && r != nil && r.Truncated {
			dnsClient.Net = "tcp"
			r, _, err = dnsClient.ExchangeContext(ctx, dnsMsg, ip)
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

func evaluateCAA(ctx context.Context, app *AppState, target DomainConfig) *CAAResult {
	if target.CAA == nil {
		return nil
	}

	res := fetchCAA(ctx, app, target.Domain, app.Resolvers())
	if res == nil {
		return &CAAResult{Valid: false, Error: MsgErrFailedToQueryCAA}
	}

	if res.Error != "" {
		res.Valid = false
		return res
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

	// Validate 'issue' if configured
	if target.CAA.Issue != nil {
		validateCAATag(app, target, CAATagIssue, target.CAA.Issue, liveIssue, res)
	}
	// Validate 'issuewild' if configured
	if target.CAA.IssueWild != nil {
		validateCAATag(app, target, CAATagIssueWild, target.CAA.IssueWild, liveIssueWild, res)
	}
	// Validate 'issuemail' if configured
	if target.CAA.IssueMail != nil {
		validateCAATag(app, target, CAATagIssueMail, target.CAA.IssueMail, liveIssueMail, res)
	}

	return res
}

func validateCAATag(app *AppState, target DomainConfig, tag string, expected []string, live map[string]bool, res *CAAResult) {
	if expected == nil || res == nil {
		return
	}

	// 1. Explicit Deny-All (empty slice / no CAs authorized)
	if len(expected) == 0 {
		if len(live) == 0 {
			// In DNS, absence of CAA records means any CA can issue certs by default
			if !target.SuppressAlerts {
				app.SafeDispatchf(PriorityHigh, TagWarning, target.Domain, target.Name, fmt.Sprintf(MsgRedactedCAADenyAllMissing, tag), MsgAlertCAAMissing, tag, target.Domain)
			}
			res.Valid = false
			return
		}

		for liveCA := range live {
			if liveCA != CAADenyAll {
				if !target.SuppressAlerts {
					app.SafeDispatchf(PriorityUrgent, TagRotatingLight, target.Domain, target.Name, fmt.Sprintf(MsgRedactedCAAUnauthorizedDeny, liveCA, tag), MsgAlertCAAUnauthorized, liveCA, tag, target.Domain)
				}
				res.UnknownCAs = append(res.UnknownCAs, liveCA)
				res.Valid = false
			}
		}
		return
	}

	// 2. Specific CAs expected
	expectedMap := make(map[string]bool)
	for _, v := range expected {
		expectedMap[v] = true
	}

	if len(live) == 0 {
		if !target.SuppressAlerts {
			app.SafeDispatchf(PriorityHigh, TagWarning, target.Domain, target.Name, fmt.Sprintf(MsgRedactedCAAMissing, tag), MsgAlertCAAMissing, tag, target.Domain)
		}
		res.Valid = false
		return
	}

	// Check for missing expected CAs
	for _, exp := range expected {
		if !live[exp] {
			if !target.SuppressAlerts {
				app.SafeDispatchf(PriorityHigh, TagWarning, target.Domain, target.Name, fmt.Sprintf(MsgRedactedCAAExpectedMissing, exp, tag), MsgAlertCAAExpectedNA, exp, tag, target.Domain)
			}
			res.Valid = false
		}
	}

	// Check for unauthorized CAs
	for liveCA := range live {
		if !expectedMap[liveCA] {
			if !target.SuppressAlerts {
				app.SafeDispatchf(PriorityUrgent, TagRotatingLight, target.Domain, target.Name, fmt.Sprintf(MsgRedactedCAAUnauthorized, liveCA, tag), MsgAlertCAAUnauthorized, liveCA, tag, target.Domain)
			}
			res.UnknownCAs = append(res.UnknownCAs, liveCA)
			res.Valid = false
		}
	}
}

func fetchCAA(ctx context.Context, app *AppState, domain string, resolvers []string) *CAAResult {
	res := &CAAResult{}
	currentDomain := NormalizeDomain(domain)
	if currentDomain == "" {
		res.Error = MsgErrInvalidEmptyDomainCAA
		return res
	}

	visitedAliases := make(map[string]bool)

	for {
		entries, err := queryCAARecords(ctx, app, currentDomain, resolvers)
		if err != nil {
			if errors.Is(err, ErrNXDOMAIN) {
				entries = nil
			} else {
				res.Error = fmt.Sprintf(MsgErrFailedToQueryCAAPattern, currentDomain, err.Error())
				return res
			}
		}

		if len(entries) > 0 {
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
			return res
		}

		// Check for CNAME alias traversal per RFC 8659 Section 3
		if !visitedAliases[currentDomain] && len(visitedAliases) < 5 {
			visitedAliases[currentDomain] = true
			cnames, cErr := queryDNS(ctx, app, currentDomain, dns.TypeCNAME, resolvers)
			if cErr == nil && len(cnames) > 0 {
				target := NormalizeDomain(cnames[0])
				if target != "" && !visitedAliases[target] {
					currentDomain = target
					continue
				}
			}
		}

		// Tree climbing: strip leftmost label
		_, parent, found := strings.Cut(currentDomain, ".")
		if !found {
			break // Reached top-level label
		}
		if parent == "" || !strings.Contains(parent, ".") {
			break // Stop at TLD or single label
		}
		currentDomain = parent
	}

	return res
}

func validateDNSSEC(ctx context.Context, app *AppState, domain string, resolvers []string, dohURLTemplate string) *DNSSECResult {
	res := &DNSSECResult{
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
			dohResp, err := dohHTTPClient.Do(dohReq)

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

func evaluateDNSSEC(ctx context.Context, app *AppState, target DomainConfig) *DNSSECResult {
	if !target.DNSSEC {
		return nil
	}

	dohURL := DefaultDoHURL
	if app != nil && app.Config().DoHURL != "" {
		dohURL = app.Config().DoHURL
	}

	res := validateDNSSEC(ctx, app, target.Domain, app.Resolvers(), dohURL)
	if res == nil {
		return &DNSSECResult{Valid: false, Source: DNSSECSourceLocalOnly, Error: MsgErrValidateDNSSECNil}
	}

	if !res.Valid && !target.SuppressAlerts {
		if res.Error != "" && strings.Contains(res.Error, "query failed") {
			app.SafeDispatchf(PriorityHigh, TagWarning, target.Domain, target.Name, MsgRedactedDNSSECFailedNetwork, MsgAlertDNSSECNetworkError, target.Domain, res.Error)
		} else if !res.HasDS && !res.HasDNSKEY {
			app.SafeDispatchf(PriorityUrgent, TagRotatingLight, target.Domain, target.Name, MsgRedactedDNSSECDisabled, MsgAlertDNSSECUnsigned, target.Domain)
		} else if !res.HasDS {
			app.SafeDispatchf(PriorityUrgent, TagRotatingLight, target.Domain, target.Name, MsgRedactedDNSSECDSNotFound, MsgAlertDNSSECNoDS, target.Domain)
		} else if !res.HasDNSKEY {
			app.SafeDispatchf(PriorityUrgent, TagRotatingLight, target.Domain, target.Name, MsgRedactedDNSSECDNSKEYNotFound, MsgAlertDNSSECNoDNSKEY, target.Domain)
		} else if !res.DSMatchesDNSKEY {
			app.SafeDispatchf(PriorityUrgent, TagRotatingLight, target.Domain, target.Name, MsgRedactedDNSSECDSMismatch, MsgAlertDNSSECMismatch, target.Domain)
		} else if !res.RRSIGValid {
			app.SafeDispatchf(PriorityUrgent, TagRotatingLight, target.Domain, target.Name, MsgRedactedDNSSECRRSIGFailed, MsgAlertDNSSECRRSIGFailed, target.Domain)
		} else if !res.ChainIntact && res.Source != DNSSECSourceLocalOnly {
			app.SafeDispatchf(PriorityUrgent, TagRotatingLight, target.Domain, target.Name, MsgRedactedDNSSECChainFailed, MsgAlertDNSSECChainBroken, target.Domain)
		}
	}

	return res
}

// evaluateDNS orchestrates the resolution and validation of a DNS task
func evaluateDNS(ctx context.Context, app *AppState, target DNSTask) *DNSState {
	foundRecords, err := resolveTarget(ctx, app, target)

	if err != nil {
		app.SafeDispatchf(PriorityUrgent, TagRotatingLight, target.Hostname, target.Name, fmt.Sprintf(MsgRedactedDNSResolutionFailed, target.Hostname, target.Type), MsgAlertDNSFailed, target.Hostname, target.Type)

		return &DNSState{
			Hostname: target.Hostname,
			Name:     target.Name,
			Type:     target.Type,
			Expected: target.Expected,
			Status:   StatusFailed,
			SSLDays:  SSLDaysNotApplicable,
			Error:    err.Error(),
		}
	}

	allMatch, mismatchReason := validateRecordsWithReason(app, target, foundRecords)
	sslDays := SSLDaysNotApplicable
	if !target.SkipSSL {
		sslDays = validateCertificate(ctx, app, target, foundRecords)
	}

	status := StatusOK
	var recordErr string
	if !allMatch {
		status = StatusMismatch
		recordErr = mismatchReason
	}

	return &DNSState{
		Hostname: target.Hostname,
		Name:     target.Name,
		Type:     target.Type,
		Expected: target.Expected,
		Status:   status,
		Found:    foundRecords,
		SSLDays:  sslDays,
		SkipSSL:  target.SkipSSL,
		Error:    recordErr,
	}
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

func validateRecords(app *AppState, target DNSTask, foundRecords []string) bool {
	valid, _ := validateRecordsWithReason(app, target, foundRecords)
	return valid
}

func validateRecordsWithReason(app *AppState, target DNSTask, foundRecords []string) (bool, string) {
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
				redacted := fmt.Sprintf(MsgRedactedDNSMismatchPrefix, target.Hostname, target.Type)
				app.SafeDispatchf(PriorityUrgent, TagRotatingLight, target.Hostname, target.Name, redacted, MsgAlertDNSMismatch, target.Hostname, target.Type, expected, strings.Join(foundRecords, ", "))
				allMatch = false
				mismatchReasons = append(mismatchReasons, fmt.Sprintf(MsgReasonPrefixNotFound, expected, strings.Join(foundRecords, ", ")))
			}
		}
		return allMatch, strings.Join(mismatchReasons, "; ")

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
				redacted := fmt.Sprintf(MsgRedactedDNSMismatchSubstring, target.Hostname, target.Type)
				app.SafeDispatchf(PriorityUrgent, TagRotatingLight, target.Hostname, target.Name, redacted, MsgAlertDNSMismatch, target.Hostname, target.Type, expected, strings.Join(foundRecords, ", "))
				allMatch = false
				mismatchReasons = append(mismatchReasons, fmt.Sprintf(MsgReasonSubstringNotFound, expected, strings.Join(foundRecords, ", ")))
			}
		}
		return allMatch, strings.Join(mismatchReasons, "; ")

	case MatchAnyOf:
		matched := false
		for _, found := range foundRecords {
			if slices.Contains(target.Expected, found) {
				matched = true
				break
			}
		}
		if !matched {
			redacted := fmt.Sprintf(MsgRedactedDNSMismatchAnyOf, target.Hostname, target.Type)
			app.SafeDispatchf(PriorityUrgent, TagRotatingLight, target.Hostname, target.Name, redacted, MsgAlertDNSMismatch, target.Hostname, target.Type, strings.Join(target.Expected, " OR "), strings.Join(foundRecords, ", "))
			return false, fmt.Sprintf(MsgReasonNoneMatched, strings.Join(target.Expected, " OR "), strings.Join(foundRecords, ", "))
		}
		return true, ""

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
			redacted := fmt.Sprintf(MsgRedactedDNSMismatchExact, target.Hostname, target.Type)
			app.SafeDispatchf(PriorityUrgent, TagRotatingLight, target.Hostname, target.Name, redacted, MsgAlertDNSMismatch, target.Hostname, target.Type, strings.Join(missing, ", "), strings.Join(foundRecords, ", "))
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
			redacted := fmt.Sprintf(MsgRedactedDNSUnauthorized, target.Hostname, target.Type)
			app.SafeDispatchf(PriorityUrgent, TagRotatingLight, target.Hostname, target.Name, redacted, MsgAlertDNSUnauthorized, target.Hostname, target.Type, strings.Join(unauthorized, ", "), strings.Join(target.Expected, ", "))
			mismatchReasons = append(mismatchReasons, fmt.Sprintf(MsgReasonUnauthorizedRecords, strings.Join(unauthorized, ", ")))
		}
		return allMatch, strings.Join(mismatchReasons, "; ")
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
			LogWarn(MsgLogSSLResolveIPsFailed, "hostname", target.Hostname, "error", ipErr)
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

func evaluateEmailSecurity(ctx context.Context, app *AppState, target DomainConfig) *EmailState {
	if !target.CheckEmailSecurity {
		return nil
	}

	emailStatus := StatusOK
	liveMXs, mxStatus, err := validateMX(ctx, app, target)
	if err != nil {
		return &EmailState{Status: StatusFailed, Error: err.Error()}
	}
	if mxStatus != StatusOK {
		emailStatus = mxStatus
	}

	foundSPF, spfStatus, spfErr := validateSPF(ctx, app, target)
	if spfStatus != StatusOK && emailStatus == StatusOK {
		emailStatus = spfStatus
	}

	foundDMARC, dmarcStatus, dmarcErr := validateDMARC(ctx, app, target)
	if dmarcStatus != StatusOK && emailStatus == StatusOK {
		emailStatus = dmarcStatus
	}

	validDkims, dkimStatus, dkimErr := validateDKIM(ctx, app, target)
	if dkimStatus != StatusOK && emailStatus == StatusOK {
		emailStatus = dkimStatus
	}

	var errs []string
	if spfErr != nil {
		errs = append(errs, fmt.Sprintf(MsgErrSPFLookupError, spfErr.Error()))
	}
	if dmarcErr != nil {
		errs = append(errs, fmt.Sprintf(MsgErrDMARCLookupError, dmarcErr.Error()))
	}
	if dkimErr != nil {
		errs = append(errs, fmt.Sprintf(MsgErrDKIMLookupError, dkimErr.Error()))
	}
	if len(errs) > 0 && emailStatus == StatusOK {
		emailStatus = StatusWarning
	}

	hasDKIMExpected := (target.MailProvider != "" && len(ProviderDKIMMap[target.MailProvider]) > 0) || len(target.DKIMSelectors) > 0

	return &EmailState{
		Status:       emailStatus,
		Provider:     target.MailProvider,
		SPF:          foundSPF,
		DMARC:        foundDMARC,
		DKIMExpected: hasDKIMExpected,
		DKIMValid:    validDkims,
		MX:           liveMXs,
		Error:        strings.Join(errs, " | "),
	}
}

func validateMX(ctx context.Context, app *AppState, target DomainConfig) ([]string, CheckStatus, error) {
	mxs, err := queryDNS(ctx, app, target.Domain, dns.TypeMX, app.Resolvers())
	if err != nil {
		if !errors.Is(err, ErrNXDOMAIN) {
			return nil, StatusFailed, WrapError(MsgErrMXQueryError, err)
		}
		// NXDOMAIN is authoritatively non-existent
		mxs = nil
	}
	if len(mxs) == 0 {
		if !target.SuppressAlerts {
			app.SafeDispatchf(PriorityUrgent, TagEnvelope, target.Domain, target.Name, MsgRedactedEmailNoMX, MsgAlertEmailNoMX, target.Domain)
		}
		return nil, StatusFailed, errors.New(MsgErrNoMXRecordsFound)
	}

	var liveMXs []string
	liveMXs = append(liveMXs, mxs...)
	derivedStatus := StatusOK

	if len(target.MXRecords) > 0 {
		allMatch := true
		for _, expected := range target.MXRecords {
			if !slices.Contains(liveMXs, expected) {
				allMatch = false
				if !target.SuppressAlerts {
					app.SafeDispatchf(PriorityUrgent, TagEnvelope, target.Domain, target.Name, MsgRedactedEmailMXMissing, MsgAlertEmailMXMissing, expected, target.Domain, strings.Join(liveMXs, ", "))
				}
			}
		}
		for _, found := range liveMXs {
			if !slices.Contains(target.MXRecords, found) {
				allMatch = false
				if !target.SuppressAlerts {
					app.SafeDispatchf(PriorityUrgent, TagRotatingLight, target.Domain, target.Name, MsgRedactedEmailMXUnauthorized, MsgAlertEmailMXUnauthorized, found, target.Domain, strings.Join(target.MXRecords, ", "))
				}
			}
		}
		if !allMatch {
			derivedStatus = StatusMismatch
		}
	} else if target.MailProvider != "" {
		safe, known := isProviderMXSafe(liveMXs, target.MailProvider)
		if !known {
			LogWarnf(MsgLogEmailUnknownProvider, target.MailProvider, target.Domain)
		} else if !safe {
			if !target.SuppressAlerts {
				app.SafeDispatchf(PriorityUrgent, TagRotatingLight, target.Domain, target.Name, MsgRedactedEmailMXHijack, MsgAlertEmailMXHijack, target.Domain, target.MailProvider, strings.Join(liveMXs, ", "))
			}
			derivedStatus = StatusHijacked
		}
	}

	return liveMXs, derivedStatus, nil
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
		mxLower := strings.ToLower(strings.TrimSuffix(mx, "."))
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

func validateSPF(ctx context.Context, app *AppState, target DomainConfig) (bool, CheckStatus, error) {
	txts, err := queryDNS(ctx, app, target.Domain, dns.TypeTXT, app.Resolvers())
	if err != nil {
		return false, StatusFailed, err
	}
	spfCount := 0

	for _, txt := range txts {
		txtLower := strings.ToLower(strings.TrimSpace(txt))
		if strings.HasPrefix(txtLower, SPFPrefix+" ") || txtLower == SPFPrefix {
			spfCount++
		}
	}

	if spfCount == 0 {
		if !target.SuppressAlerts {
			app.SafeDispatchf(PriorityHigh, TagWarning, target.Domain, target.Name, MsgRedactedEmailNoSPF, MsgAlertEmailNoSPF, target.Domain)
		}
		return false, StatusWarning, nil
	} else if spfCount > 1 {
		if !target.SuppressAlerts {
			app.SafeDispatchf(PriorityUrgent, TagError, target.Domain, target.Name, MsgRedactedEmailMultiSPF, MsgAlertEmailMultiSPF, target.Domain)
		}
		return false, StatusWarning, nil
	}
	return true, StatusOK, nil
}

func validateDMARC(ctx context.Context, app *AppState, target DomainConfig) (bool, CheckStatus, error) {
	currentDomain := NormalizeDomain(target.Domain)
	var lastErr error

	for {
		dmarcHost := "_dmarc." + currentDomain
		dmarcTxts, err := queryDNS(ctx, app, dmarcHost, dns.TypeTXT, app.Resolvers())
		if err != nil {
			lastErr = err
		} else {
			dmarcFound := false
			dmarcCount := 0
			for _, txt := range dmarcTxts {
				txtLower := strings.ToLower(strings.TrimSpace(txt))
				if strings.HasPrefix(txtLower, DMARCPrefix+" ") || strings.HasPrefix(txtLower, DMARCPrefix+";") || txtLower == DMARCPrefix {
					dmarcFound = true
					dmarcCount++
				}
			}

			if dmarcFound {
				if dmarcCount > 1 {
					if !target.SuppressAlerts {
						app.SafeDispatchf(PriorityUrgent, TagError, target.Domain, target.Name, MsgRedactedEmailMultiDMARC, MsgAlertEmailMultiDMARC, target.Domain)
					}
					return false, StatusWarning, nil
				}
				return true, StatusOK, nil
			}
		}

		// Tree climbing per RFC 7489 Section 6.6.3: strip leftmost label
		_, parent, found := strings.Cut(currentDomain, ".")
		if !found || parent == "" || !strings.Contains(parent, ".") {
			break // Stop at TLD or apex
		}
		currentDomain = parent
	}

	if lastErr != nil && !errors.Is(lastErr, ErrNXDOMAIN) {
		return false, StatusFailed, lastErr
	}

	if !target.SuppressAlerts {
		app.SafeDispatchf(PriorityHigh, TagWarning, target.Domain, target.Name, MsgRedactedEmailNoDMARC, MsgAlertEmailNoDMARC, target.Domain, target.Domain)
	}
	return false, StatusWarning, nil
}

func validateDKIM(ctx context.Context, app *AppState, target DomainConfig) ([]string, CheckStatus, error) {
	var selectorsToCheck []string
	if target.MailProvider != "" {
		if defaults, ok := ProviderDKIMMap[target.MailProvider]; ok {
			selectorsToCheck = append(selectorsToCheck, defaults...)
		}
	}
	selectorsToCheck = append(selectorsToCheck, target.DKIMSelectors...)

	var validDkims []string
	var missingDkims []string
	var lookupErr error

	for _, selector := range selectorsToCheck {
		dkimHost := selector + "._domainkey." + target.Domain
		dkimTxts, err := queryDNS(ctx, app, dkimHost, dns.TypeTXT, app.Resolvers())
		if err != nil {
			if !errors.Is(err, ErrNXDOMAIN) {
				lookupErr = err
			}
			missingDkims = append(missingDkims, selector)
			continue
		}

		dkimFound := false
		for _, txt := range dkimTxts {
			txtLower := strings.TrimSpace(strings.ToLower(txt))
			if strings.HasPrefix(txtLower, DKIMPrefix) || strings.Contains(txtLower, DKIMPublicKeyTag) {
				dkimFound = true
				break
			}
		}

		if dkimFound {
			validDkims = append(validDkims, selector)
		} else {
			missingDkims = append(missingDkims, selector)
		}
	}

	// If at least one selector is valid, DKIM authentication passes for the domain;
	// non-matching or unused alternate candidate selectors do not fail the check.
	if len(validDkims) > 0 {
		return validDkims, StatusOK, nil
	}

	derivedStatus := StatusOK
	if len(missingDkims) > 0 && len(selectorsToCheck) > 0 {
		if lookupErr == nil {
			if !target.SuppressAlerts {
				app.SafeDispatchf(PriorityHigh, TagWarning, target.Domain, target.Name, MsgRedactedEmailNoDKIM, MsgAlertEmailNoDKIM, target.Domain, strings.Join(missingDkims, ", "))
			}
			derivedStatus = StatusWarning
		}
	}
	return validDkims, derivedStatus, lookupErr
}

// evaluateNSHealth validates primary authoritative nameserver health (expected_ns[0]) directly (RD=0)
// for reachability, authoritative answer (AA flag), and SOA serial. If secondary_ns is configured, it also validates
// secondary reachability, AA flag, SOA serial synchronization, and dumb secondary DNSSEC consistency
// (strictly enforcing that secondary nameservers either do not use DNSSEC or replicate the primary's exact DNSKEYs).
func evaluateNSHealth(ctx context.Context, app *AppState, target DomainConfig) *NSHealthResult {
	if !target.VerifyNSHealth || len(target.ExpectedNS) == 0 {
		return nil
	}

	primaryNS := target.ExpectedNS[0]
	res := &NSHealthResult{
		Valid:   true,
		Primary: primaryNS,
		Servers: make([]NSHealthServerResult, 0, 1+len(target.SecondaryNS)),
	}

	resolveTargetIP := func(nsName string) (string, error) {
		host, port, err := net.SplitHostPort(DefaultPort(nsName, DefaultDNSPort))
		if err != nil {
			return "", WrapError(fmt.Sprintf(MsgErrInvalidNSAddress, nsName), err)
		}
		if net.ParseIP(host) != nil {
			return net.JoinHostPort(host, port), nil
		}
		ips, err := queryIPRecords(ctx, app, host, app.Resolvers())
		if err != nil {
			return "", WrapError(MsgErrFailedToResolveIP, err)
		}
		if len(ips) == 0 {
			return "", fmt.Errorf(MsgErrNoIPRecordsForHost, host)
		}
		return net.JoinHostPort(ips[0], port), nil
	}

	// 1. Query Primary Nameserver
	primaryIP, pErr := resolveTargetIP(primaryNS)
	primarySrv := NSHealthServerResult{
		Nameserver: primaryNS,
		IsPrimary:  true,
	}

	if pErr != nil {
		primarySrv.Error = pErr.Error()
		res.Valid = false
		res.Servers = append(res.Servers, primarySrv)
		if !target.SuppressAlerts {
			app.SafeDispatchf(PriorityHigh, TagWarning, target.Domain, target.Name, MsgRedactedNSUnreachablePrimary, MsgAlertNSUnreachable, primaryNS, target.Domain, pErr)
		}
		return res
	}

	primarySOAMsg, pSOAErr := queryDNSMsgWithRD(ctx, app, target.Domain, dns.TypeSOA, []string{primaryIP}, false)
	if pSOAErr != nil || primarySOAMsg == nil {
		primarySrv.Error = fmt.Sprintf(MsgErrSOALookupFailed, pSOAErr.Error())
		res.Valid = false
		res.Servers = append(res.Servers, primarySrv)
		if !target.SuppressAlerts {
			app.SafeDispatchf(PriorityHigh, TagWarning, target.Domain, target.Name, MsgRedactedNSUnreachablePrimary, MsgAlertNSUnreachable, primaryNS, target.Domain, pSOAErr)
		}
		return res
	}

	primarySrv.Authoritative = primarySOAMsg.Authoritative
	if !primarySrv.Authoritative {
		primarySrv.Error = MsgErrPrimaryNSNotAuthoritative
		res.Valid = false
		if !target.SuppressAlerts {
			app.SafeDispatchf(PriorityHigh, TagWarning, target.Domain, target.Name, MsgRedactedNSNonAuthoritative, MsgAlertNSNonAuthoritative, primaryNS, target.Domain)
		}
	}

	var primarySerial uint32
	var primaryFoundSOA bool
	for _, ans := range primarySOAMsg.Answer {
		if soa, ok := ans.(*dns.SOA); ok {
			primarySerial = soa.Serial
			primaryFoundSOA = true
			break
		}
	}
	if !primaryFoundSOA {
		for _, nsRec := range primarySOAMsg.Ns {
			if soa, ok := nsRec.(*dns.SOA); ok {
				primarySerial = soa.Serial
				primaryFoundSOA = true
				break
			}
		}
	}
	if !primaryFoundSOA {
		primarySrv.Error = MsgErrNoSOARecordReturned
		res.Valid = false
		if !target.SuppressAlerts {
			app.SafeDispatchf(PriorityHigh, TagWarning, target.Domain, target.Name, MsgRedactedNSMissingSOA, MsgAlertNSMissingSOA, primaryNS, target.Domain)
		}
	}
	primarySrv.SOASerial = primarySerial

	extractDNSKEYFingerprints := func(msg *dns.Msg) []string {
		if msg == nil {
			return nil
		}
		var fps []string
		for _, rr := range msg.Answer {
			if dnskey, ok := rr.(*dns.DNSKEY); ok {
				fps = append(fps, strconv.Itoa(int(dnskey.Flags))+"-"+strconv.Itoa(int(dnskey.Protocol))+"-"+strconv.Itoa(int(dnskey.Algorithm))+"-"+dnskey.PublicKey)
			}
		}
		slices.Sort(fps)
		return fps
	}

	var primaryDNSKEYs []string
	if dnskeyMsg, _ := queryDNSMsgWithRD(ctx, app, target.Domain, dns.TypeDNSKEY, []string{primaryIP}, false); dnskeyMsg != nil {
		primaryDNSKEYs = extractDNSKEYFingerprints(dnskeyMsg)
		if len(primaryDNSKEYs) > 0 {
			primarySrv.HasDNSKEY = true
		}
	}
	primarySrv.DNSKEYMatch = true

	res.Servers = append(res.Servers, primarySrv)

	// Validate each configured secondary nameserver
	for _, secNS := range target.SecondaryNS {
		secNS = strings.TrimSpace(secNS)
		if secNS == "" {
			continue
		}
		secSrv := NSHealthServerResult{
			Nameserver: secNS,
			IsPrimary:  false,
		}

		secIP, sErr := resolveTargetIP(secNS)
		if sErr != nil {
			secSrv.Error = sErr.Error()
			res.Valid = false
			res.Servers = append(res.Servers, secSrv)
			if !target.SuppressAlerts {
				app.SafeDispatchf(PriorityHigh, TagWarning, target.Domain, target.Name, MsgRedactedNSUnreachableSecondary, MsgAlertNSUnreachable, secNS, target.Domain, sErr)
			}
			continue
		}

		secSOAMsg, secSOAErr := queryDNSMsgWithRD(ctx, app, target.Domain, dns.TypeSOA, []string{secIP}, false)
		if secSOAErr != nil || secSOAMsg == nil {
			secSrv.Error = fmt.Sprintf(MsgErrSOALookupFailed, secSOAErr.Error())
			res.Valid = false
			res.Servers = append(res.Servers, secSrv)
			if !target.SuppressAlerts {
				app.SafeDispatchf(PriorityHigh, TagWarning, target.Domain, target.Name, MsgRedactedNSUnreachableSecondary, MsgAlertNSUnreachable, secNS, target.Domain, secSOAErr)
			}
			continue
		}

		secSrv.Authoritative = secSOAMsg.Authoritative
		if !secSrv.Authoritative {
			secSrv.Error = MsgErrSecondaryNSNotAuthoritative
			res.Valid = false
			if !target.SuppressAlerts {
				app.SafeDispatchf(PriorityHigh, TagWarning, target.Domain, target.Name, MsgRedactedNSNonAuthoritative, MsgAlertNSNonAuthoritative, secNS, target.Domain)
			}
		}

		var secSerial uint32
		var secFoundSOA bool
		for _, ans := range secSOAMsg.Answer {
			if soa, ok := ans.(*dns.SOA); ok {
				secSerial = soa.Serial
				secFoundSOA = true
				break
			}
		}
		if !secFoundSOA {
			for _, nsRec := range secSOAMsg.Ns {
				if soa, ok := nsRec.(*dns.SOA); ok {
					secSerial = soa.Serial
					secFoundSOA = true
					break
				}
			}
		}
		if !secFoundSOA {
			secSrv.Error = MsgErrNoSOARecordReturned
			res.Valid = false
			if !target.SuppressAlerts {
				app.SafeDispatchf(PriorityHigh, TagWarning, target.Domain, target.Name, MsgRedactedNSMissingSOA, MsgAlertNSMissingSOA, secNS, target.Domain)
			}
		}
		secSrv.SOASerial = secSerial

		// Compare SOA serials between Primary and Secondary
		if primaryFoundSOA && secFoundSOA {
			if secSerial < primarySerial {
				res.Valid = false
				if !target.SuppressAlerts {
					app.SafeDispatchf(PriorityHigh, TagWarning, target.Domain, target.Name, MsgRedactedNSSOALags, MsgAlertNSSOALag, secNS, secSerial, primaryNS, primarySerial, target.Domain)
				}
			} else if secSerial != primarySerial {
				res.Valid = false
				if !target.SuppressAlerts {
					app.SafeDispatchf(PriorityWarning, TagWarning, target.Domain, target.Name, MsgRedactedNSSOADiffers, MsgAlertNSSOAMismatch, secNS, secSerial, primaryNS, primarySerial, target.Domain)
				}
			}
		}

		// Dumb secondary DNSKEY verification:
		// A dumb secondary must either be unsigned (no DNSKEYs) or strictly replicate the primary's exact DNSKEYs.
		// Independent signing / multi-signer setups where the secondary has its own keys are rejected.
		var secDNSKEYs []string
		if dnskeyMsg, _ := queryDNSMsgWithRD(ctx, app, target.Domain, dns.TypeDNSKEY, []string{secIP}, false); dnskeyMsg != nil {
			secDNSKEYs = extractDNSKEYFingerprints(dnskeyMsg)
			if len(secDNSKEYs) > 0 {
				secSrv.HasDNSKEY = true
			}
		}

		if len(primaryDNSKEYs) > 0 {
			if len(secDNSKEYs) == 0 {
				res.Valid = false
				secSrv.DNSKEYMatch = false
				if !target.SuppressAlerts {
					app.SafeDispatchf(PriorityHigh, TagWarning, target.Domain, target.Name, MsgRedactedNSDNSKEYMissing, MsgAlertNSDNSKEYMissing, secNS, target.Domain)
				}
			} else if !slices.Equal(primaryDNSKEYs, secDNSKEYs) {
				res.Valid = false
				secSrv.DNSKEYMatch = false
				if !target.SuppressAlerts {
					app.SafeDispatchf(PriorityHigh, TagWarning, target.Domain, target.Name, MsgRedactedNSDNSKEYMismatch, MsgAlertNSDNSKEYMismatch, secNS, target.Domain)
				}
			} else {
				secSrv.DNSKEYMatch = true
			}
		} else if len(secDNSKEYs) > 0 {
			// Primary is unsigned, but secondary serves DNSKEYs!
			res.Valid = false
			secSrv.DNSKEYMatch = false
			if !target.SuppressAlerts {
				app.SafeDispatchf(PriorityHigh, TagWarning, target.Domain, target.Name, MsgRedactedNSDNSKEYUnexpected, MsgAlertNSDNSKEYUnexpected, secNS, target.Domain)
			}
		} else {
			// Both unsigned
			secSrv.DNSKEYMatch = true
		}

		res.Servers = append(res.Servers, secSrv)
	}

	return res
}
