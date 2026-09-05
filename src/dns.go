package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/miekg/dns"
)

var dohHTTPClient = &http.Client{Timeout: 5 * time.Second}

func checkSSL(ctx context.Context, hostname string, ips []string, acceptSelfSigned bool) (int, error) {
	dialHost := hostname
	if strings.HasPrefix(dialHost, "*.") {
		// Replace *. with www. to ensure a valid FQDN is used for DNS resolution and SNI
		dialHost = strings.Replace(dialHost, "*.", "www.", 1)
	}

	targets := []string{}
	for _, ipStr := range ips {
		if net.ParseIP(ipStr) != nil {
			if strings.Contains(ipStr, ":") && !strings.HasPrefix(ipStr, "[") {
				ipStr = "[" + ipStr + "]"
			}
			targets = append(targets, ipStr+":443")
		}
	}

	if len(targets) == 0 {
		targets = []string{dialHost + ":443"}
	}

	minDays := 999999
	hasDays := false
	var lastErr error
	successCount := 0

	for _, targetAddr := range targets {
		dialer := &tls.Dialer{
			NetDialer: &net.Dialer{Timeout: 5 * time.Second},
			Config: &tls.Config{
				ServerName:         dialHost,
				InsecureSkipVerify: true,
				VerifyConnection: func(cs tls.ConnectionState) error {
					if len(cs.PeerCertificates) == 0 {
						return errors.New("no peer certificates returned")
					}
					cert := cs.PeerCertificates[0]
					if err := cert.VerifyHostname(dialHost); err != nil {
						return fmt.Errorf("certificate invalid for %s on %s: %v", dialHost, targetAddr, err)
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
							return fmt.Errorf("certificate validation failed for %s on %s: %v", dialHost, targetAddr, err)
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

		tlsConn, ok := conn.(*tls.Conn)
		if !ok {
			_ = conn.Close()
			lastErr = fmt.Errorf("unexpected connection type %T for %s", conn, targetAddr)
			continue
		}
		state := tlsConn.ConnectionState()
		_ = conn.Close()

		if len(state.PeerCertificates) == 0 {
			lastErr = fmt.Errorf("no peer certificates found for %s", targetAddr)
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
func queryDNSMsgWithRD(ctx context.Context, app *AppState, hostname string, qtype uint16, resolvers []string, recursionDesired bool) (*dns.Msg, error) {
	if len(resolvers) == 0 {
		return nil, errors.New("no resolvers configured")
	}

	startIdx := 0
	if app != nil {
		startIdx = int(app.GlobalResolverIndex.Add(1) % uint32(len(resolvers)))
	}

	var lastErr error
	for attempt := range resolvers {
		idx := (startIdx + attempt) % len(resolvers)
		ip := resolvers[idx]
		if _, _, err := net.SplitHostPort(ip); err != nil {
			ip = net.JoinHostPort(ip, "53")
		}

		c := new(dns.Client)
		c.Timeout = 5 * time.Second

		m := new(dns.Msg)
		fqdn := dns.Fqdn(hostname)
		m.SetQuestion(fqdn, qtype)
		m.SetEdns0(4096, true)
		m.RecursionDesired = recursionDesired

		r, _, err := c.ExchangeContext(ctx, m, ip)
		if err == nil && r != nil && r.Truncated {
			c.Net = "tcp"
			r, _, err = c.ExchangeContext(ctx, m, ip)
		}

		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			lastErr = fmt.Errorf("lookup %s on %s: %w", hostname, ip, err)
			continue
		}

		if r == nil {
			lastErr = fmt.Errorf("lookup %s on %s: empty response", hostname, ip)
			continue
		}

		// Verify question section echoes request per RFC 5452 Section 4
		if len(r.Question) == 0 || !strings.EqualFold(r.Question[0].Name, fqdn) || r.Question[0].Qtype != qtype {
			lastErr = fmt.Errorf("lookup %s on %s: response question mismatch or missing", hostname, ip)
			continue
		}

		if r.Rcode != dns.RcodeSuccess {
			if r.Rcode == dns.RcodeNameError {
				// NXDOMAIN is authoritative — do not retry on other resolvers
				return nil, fmt.Errorf("lookup %s on %s: %w", hostname, ip, ErrNXDOMAIN)
			}
			// SERVFAIL, REFUSED, NOTIMP, FORMERR are server-specific failures — retry next resolver
			if r.Rcode == dns.RcodeServerFailure || r.Rcode == dns.RcodeRefused || r.Rcode == dns.RcodeNotImplemented || r.Rcode == dns.RcodeFormatError {
				lastErr = fmt.Errorf("lookup %s on %s: server error (%s)", hostname, ip, dns.RcodeToString[r.Rcode])
				continue
			}
			return nil, fmt.Errorf("lookup %s on %s: server returned error code %d", hostname, ip, r.Rcode)
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
				results = append(results, strings.ToLower(strings.TrimSuffix(record.Target, ".")))
			}
		case *dns.MX:
			if qtype == dns.TypeMX {
				mx := strings.ToLower(strings.TrimSuffix(record.Mx, "."))
				if mx == "" && record.Mx == "." {
					mx = "."
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
				results = append(results, strings.ToLower(strings.TrimSuffix(strings.TrimSpace(record.Ns), ".")))
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

	var entries []CAAEntry
	for _, ans := range r.Answer {
		if caa, ok := ans.(*dns.CAA); ok {
			val := strings.Trim(strings.TrimSpace(caa.Value), "\"")
			val = strings.TrimSpace(val)
			if val == "" || val == ";" {
				val = ";"
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
	if val == "" || val == ";" {
		return ";"
	}
	parts := strings.SplitN(val, ";", 2)
	issuer := strings.Trim(strings.TrimSpace(parts[0]), "\"")
	issuer = strings.TrimSpace(issuer)
	if issuer == "" || issuer == ";" {
		return ";"
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
		return found, fmt.Errorf("lookup failed for A and AAAA: %w", errors.Join(aErr, aaaaErr))
	}
	return found, nil
}

func evaluateCAA(ctx context.Context, app *AppState, target DomainConfig, state *CheckState) {
	if target.CAA == nil {
		return
	}

	res := fetchCAA(ctx, app, target.Domain, app.Config.Resolvers)

	if res.Error != "" {
		res.Valid = false
		state.UpdateCAA(target.Domain, res)
		return
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
		validateCAATag(app, target, "issue", target.CAA.Issue, liveIssue, res)
	}
	// Validate 'issuewild' if configured
	if target.CAA.IssueWild != nil {
		validateCAATag(app, target, "issuewild", target.CAA.IssueWild, liveIssueWild, res)
	}
	// Validate 'issuemail' if configured
	if target.CAA.IssueMail != nil {
		validateCAATag(app, target, "issuemail", target.CAA.IssueMail, liveIssueMail, res)
	}

	state.UpdateCAA(target.Domain, res)
}

func validateCAATag(app *AppState, target DomainConfig, tag string, expected []string, live map[string]bool, res *CAAResult) {
	if expected == nil {
		return
	}

	// 1. Explicit Deny-All (empty slice / no CAs authorized)
	if len(expected) == 0 {
		if len(live) == 0 {
			// In DNS, absence of CAA records means any CA can issue certs by default
			msg := fmt.Sprintf(MsgAlertCAAMissing, tag, target.Domain)
			redacted := fmt.Sprintf("Missing %s deny-all record (';').", tag)
			if !target.SuppressAlerts {
				app.Notifier.Dispatch(msg, redacted, PriorityHigh, "warning", target.Domain, target.Name)
			}
			res.Valid = false
			return
		}

		for liveCA := range live {
			if liveCA != ";" {
				msg := fmt.Sprintf(MsgAlertCAAUnauth, liveCA, tag, target.Domain)
				redacted := fmt.Sprintf("Unauthorized CA '%s' in %s (expected deny all).", liveCA, tag)
				if !target.SuppressAlerts {
					app.Notifier.Dispatch(msg, redacted, PriorityUrgent, "rotating_light", target.Domain, target.Name)
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
		msg := fmt.Sprintf(MsgAlertCAAMissing, tag, target.Domain)
		redacted := fmt.Sprintf("Missing %s records.", tag)
		if !target.SuppressAlerts {
			app.Notifier.Dispatch(msg, redacted, PriorityHigh, "warning", target.Domain, target.Name)
		}
		res.Valid = false
		return
	}

	// Check for missing expected CAs
	for _, exp := range expected {
		if !live[exp] {
			msg := fmt.Sprintf(MsgAlertCAAExpectedNA, exp, tag, target.Domain)
			redacted := fmt.Sprintf("Expected CA '%s' missing in %s.", exp, tag)
			if !target.SuppressAlerts {
				app.Notifier.Dispatch(msg, redacted, PriorityHigh, "warning", target.Domain, target.Name)
			}
			res.Valid = false
		}
	}

	// Check for unauthorized CAs
	for liveCA := range live {
		if !expectedMap[liveCA] {
			msg := fmt.Sprintf(MsgAlertCAAUnauth, liveCA, tag, target.Domain)
			redacted := fmt.Sprintf("Unauthorized CA '%s' in %s.", liveCA, tag)
			if !target.SuppressAlerts {
				app.Notifier.Dispatch(msg, redacted, PriorityUrgent, "rotating_light", target.Domain, target.Name)
			}
			res.UnknownCAs = append(res.UnknownCAs, liveCA)
			res.Valid = false
		}
	}
}

func fetchCAA(ctx context.Context, app *AppState, domain string, resolvers []string) *CAAResult {
	res := &CAAResult{}
	currentDomain := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	if currentDomain == "" {
		res.Error = "invalid empty domain for CAA"
		return res
	}

	visitedAliases := make(map[string]bool)

	for {
		entries, err := queryCAARecords(ctx, app, currentDomain, resolvers)
		if err != nil {
			if errors.Is(err, ErrNXDOMAIN) {
				entries = nil
			} else {
				res.Error = fmt.Sprintf("Failed to query CAA for %s: %v", currentDomain, err)
				return res
			}
		}

		if len(entries) > 0 {
			for _, entry := range entries {
				switch entry.Tag {
				case "issue":
					res.Issue = append(res.Issue, entry.Value)
				case "issuewild":
					res.IssueWild = append(res.IssueWild, entry.Value)
				case "issuemail":
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
				target := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(cnames[0]), "."))
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
		Source: "local+doh",
	}

	fqdn := dns.Fqdn(domain)

	// 1. Query DS
	dsResp, err := queryDNSMsg(ctx, app, domain, dns.TypeDS, resolvers)
	if err != nil {
		res.Valid = false
		res.Error = fmt.Sprintf("DS query failed: %v", err)
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
		res.Error = fmt.Sprintf("DNSKEY query failed: %v", err)
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
					algoStr = fmt.Sprintf("ALGO_%d", key.Algorithm)
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
		res.Error = "DS record does not match any DNSKEY"
	}

	// 4. Validate RRSIG covering DNSKEY RRset using DS-authenticated KSK (RFC 4035 Section 5.3)
	if len(rrsigRecords) > 0 && len(rrset) > 0 {
		const dnssecClockSkew = int64(300) // 5 minutes clock skew tolerance per RFC 4035 Section 5.3.1
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
							if (inception <= now+dnssecClockSkew) && (now <= expiration+dnssecClockSkew) {
								res.RRSIGValid = true
								res.Error = "" // Clear any stale error from previous iteration
								expiryStr := dns.TimeToString(sig.Expiration)
								if et, parseErr := time.Parse("20060102150405", expiryStr); parseErr == nil {
									res.RRSIGExpiry = et.UTC().Format(time.RFC3339)
								}
								break
							}
							res.Error = "RRSIG is expired or not yet valid"
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
		dohURL := fmt.Sprintf("%s?name=%s&type=DNSKEY&do=1", dohURLTemplate, url.QueryEscape(domain))
		if u, parseErr := url.Parse(dohURLTemplate); parseErr == nil {
			q := u.Query()
			q.Set("name", domain)
			q.Set("type", "DNSKEY")
			q.Set("do", "1")
			u.RawQuery = q.Encode()
			dohURL = u.String()
		}

		dohReq, reqErr := http.NewRequestWithContext(ctx, "GET", dohURL, nil)

		if reqErr != nil {
			res.Source = "local_only"
		} else {
			dohReq.Header.Set("Accept", "application/dns-json")
			dohResp, err := dohHTTPClient.Do(dohReq)

			if err != nil || dohResp.StatusCode != http.StatusOK {
				if dohResp != nil {
					_, _ = io.Copy(io.Discard, dohResp.Body)
					_ = dohResp.Body.Close()
				}
				res.Source = "local_only"
			} else {
				defer func() {
					_, _ = io.Copy(io.Discard, dohResp.Body)
					_ = dohResp.Body.Close()
				}()
				var dohResult googleDoHResponse
				if err := jsonv2.UnmarshalRead(dohResp.Body, &dohResult); err == nil {
					if dohResult.Status == 0 && dohResult.AD {
						res.ChainIntact = true
					}
				} else {
					res.Source = "local_only"
				}
			}
		}
	} else {
		res.Source = "local_only"
	}

	// Also check if local validating resolver provided AD flag
	if (keyResp != nil && keyResp.AuthenticatedData) || (dsResp != nil && dsResp.AuthenticatedData) {
		res.ChainIntact = true
	}

	if res.HasDS && res.HasDNSKEY && res.DSMatchesDNSKEY && res.RRSIGValid {
		if res.ChainIntact && res.Source != "local_only" {
			res.Valid = true
		} else if res.Source == "local_only" {
			res.Valid = true
			if res.Error == "" {
				res.Error = "Local DNSSEC records verified; upstream DoH chain integrity unavailable"
			}
		} else {
			res.Valid = false
			if res.Error == "" {
				res.Error = "Upstream validating resolver returned AD=false (chain broken)"
			}
		}
	} else if !res.HasDS && !res.HasDNSKEY {
		// Not signed
		res.Valid = false
	} else {
		res.Valid = false
		if res.Error == "" {
			res.Error = "DNSSEC Validation Failed"
		}
	}

	return res
}

func evaluateDNSSEC(ctx context.Context, app *AppState, target DomainConfig, state *CheckState) {
	if !target.DNSSEC {
		return
	}

	res := validateDNSSEC(ctx, app, target.Domain, app.Config.Resolvers, app.Config.DoHURL)

	if !res.Valid && !target.SuppressAlerts {
		var msg, redacted string
		if res.Error != "" && strings.Contains(res.Error, "query failed") {
			msg = fmt.Sprintf("[WARN] DNSSEC Check Failed for %s: %s", target.Domain, res.Error)
			redacted = "DNSSEC query failed due to network error."
			app.Notifier.Dispatch(msg, redacted, PriorityHigh, "warning", target.Domain, target.Name)
		} else if !res.HasDS && !res.HasDNSKEY {
			msg = fmt.Sprintf("[CRITICAL] DNSSEC: Zone is completely unsigned (No DS or DNSKEY) for %s", target.Domain)
			redacted = "DNSSEC is completely disabled or stripped."
			app.Notifier.Dispatch(msg, redacted, PriorityUrgent, "rotating_light", target.Domain, target.Name)
		} else if !res.HasDS {
			msg = fmt.Sprintf(MsgAlertDNSSECNoDS, target.Domain)
			redacted = "DNSSEC DS record is missing."
			app.Notifier.Dispatch(msg, redacted, PriorityUrgent, "rotating_light", target.Domain, target.Name)
		} else if !res.HasDNSKEY {
			msg = fmt.Sprintf(MsgAlertDNSSECNoDNSKEY, target.Domain)
			redacted = "DNSSEC DNSKEY record is missing."
			app.Notifier.Dispatch(msg, redacted, PriorityUrgent, "rotating_light", target.Domain, target.Name)
		} else if !res.DSMatchesDNSKEY {
			msg = fmt.Sprintf(MsgAlertDNSSECMismatch, target.Domain)
			redacted = "DNSSEC DS does not match KSK."
			app.Notifier.Dispatch(msg, redacted, PriorityUrgent, "rotating_light", target.Domain, target.Name)
		} else if !res.RRSIGValid {
			msg = fmt.Sprintf(MsgAlertDNSSECRRSIGFail, target.Domain)
			redacted = "DNSSEC RRSIG verification failed or expired."
			app.Notifier.Dispatch(msg, redacted, PriorityUrgent, "rotating_light", target.Domain, target.Name)
		} else if !res.ChainIntact && res.Source != "local_only" {
			msg = fmt.Sprintf(MsgAlertDNSSECChainBroken, target.Domain)
			redacted = "DNSSEC Full chain of trust validation failed."
			app.Notifier.Dispatch(msg, redacted, PriorityUrgent, "rotating_light", target.Domain, target.Name)
		}
	}

	state.UpdateDNSSEC(target.Domain, res)
}

// evaluateDNS orchestrates the resolution and validation of a DNS task
func evaluateDNS(ctx context.Context, app *AppState, target DNSTask, state *CheckState) {
	foundRecords, err := resolveTarget(ctx, app, target)

	recordKey := target.Name

	if err != nil {
		slog.Error("DNS Resolution Failed", "hostname", target.Hostname, "type", target.Type, "error", err)
		msg := fmt.Sprintf(MsgAlertDNSFailed, target.Hostname, target.Type)
		redacted := fmt.Sprintf("DNS Resolution Failed for %s (%s).", target.Hostname, target.Type)
		app.Notifier.Dispatch(msg, redacted, PriorityUrgent, "rotating_light", target.Hostname, target.Name)

		state.UpdateDNS(recordKey, &DNSState{
			Hostname: target.Hostname,
			Name:     target.Name,
			Type:     target.Type,
			Expected: target.Expected,
			Status:   StatusFailed,
			SSLDays:  SSLDaysNotApplicable,
			Error:    err.Error(),
		})
		return
	}

	allMatch := validateRecords(app, target, foundRecords)
	sslDays := SSLDaysNotApplicable
	if !target.SkipSSL {
		sslDays = validateCertificate(ctx, app, target, foundRecords)
	}

	status := StatusOk
	if !allMatch {
		status = StatusMismatch
	}

	state.UpdateDNS(recordKey, &DNSState{
		Hostname: target.Hostname,
		Name:     target.Name,
		Type:     target.Type,
		Expected: target.Expected,
		Status:   status,
		Found:    foundRecords,
		SSLDays:  sslDays,
		SkipSSL:  target.SkipSSL,
	})
}

func resolveTarget(ctx context.Context, app *AppState, target DNSTask) ([]string, error) {
	resolvers := app.Config.Resolvers
	if target.CustomResolver != "" {
		resolvers = []string{target.CustomResolver}
	}

	var foundRecords []string
	var err error

	if target.Type == "IP" || target.Type == "ALIAS" {
		foundRecords, err = queryIPRecords(ctx, app, target.Hostname, resolvers)
		if target.Type == "ALIAS" && err == nil && len(target.Expected) > 0 {
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
					for _, fIP := range foundRecords {
						if slices.Contains(expectedIPs, fIP) {
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
	} else if qType, ok := DNSTypeMap[target.Type]; ok {
		foundRecords, err = queryDNS(ctx, app, target.Hostname, qType, resolvers)

		// CNAME Flattening
		if target.Type == "CNAME" && len(foundRecords) == 0 && err == nil && len(target.Expected) > 0 {
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
		err = fmt.Errorf("unsupported DNS type: %s", target.Type)
	}

	// Resilient Fallback mechanism
	if err != nil && target.CustomResolver != "" {
		slog.Warn("Custom resolver failed, falling back to global pool", "resolver", target.CustomResolver, "hostname", target.Hostname)
		target.CustomResolver = ""             // clear custom resolver
		return resolveTarget(ctx, app, target) // Recursive fallback with global resolvers
	}

	// Canonicalize and deduplicate foundRecords for IP-returning types
	if err == nil && (target.Type == "A" || target.Type == "AAAA" || target.Type == "IP" || ((target.Type == "ALIAS" || target.Type == "CNAME") && len(foundRecords) > 0 && net.ParseIP(foundRecords[0]) != nil)) {
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
	matchType := strings.ToLower(strings.TrimSpace(target.MatchType))
	if matchType == "" {
		matchType = "exact"
	}

	switch matchType {
	case "prefix":
		allMatch := true
		for _, expected := range target.Expected {
			matched := false
			for _, found := range foundRecords {
				if strings.HasPrefix(strings.ToLower(strings.TrimSpace(found)), strings.ToLower(strings.TrimSpace(expected))) {
					matched = true
					break
				}
			}
			if !matched {
				msg := fmt.Sprintf(MsgAlertDNSMismatch, target.Hostname, target.Type, expected, strings.Join(foundRecords, ", "))
				redacted := fmt.Sprintf("Mismatch on %s (%s). Prefix not found.", target.Hostname, target.Type)
				app.Notifier.Dispatch(msg, redacted, PriorityUrgent, "rotating_light", target.Hostname, target.Name)
				allMatch = false
			}
		}
		return allMatch

	case "contains":
		allMatch := true
		for _, expected := range target.Expected {
			matched := false
			for _, found := range foundRecords {
				if strings.Contains(strings.ToLower(found), strings.ToLower(expected)) {
					matched = true
					break
				}
			}
			if !matched {
				msg := fmt.Sprintf(MsgAlertDNSMismatch, target.Hostname, target.Type, expected, strings.Join(foundRecords, ", "))
				redacted := fmt.Sprintf("Mismatch on %s (%s). Expected substring not found.", target.Hostname, target.Type)
				app.Notifier.Dispatch(msg, redacted, PriorityUrgent, "rotating_light", target.Hostname, target.Name)
				allMatch = false
			}
		}
		return allMatch

	case "any_of":
		matched := false
		for _, found := range foundRecords {
			if slices.Contains(target.Expected, found) {
				matched = true
				break
			}
		}
		if !matched {
			msg := fmt.Sprintf(MsgAlertDNSMismatch, target.Hostname, target.Type, strings.Join(target.Expected, " OR "), strings.Join(foundRecords, ", "))
			redacted := fmt.Sprintf("Mismatch on %s (%s). None of expected values matched.", target.Hostname, target.Type)
			app.Notifier.Dispatch(msg, redacted, PriorityUrgent, "rotating_light", target.Hostname, target.Name)
			return false
		}
		return true

	default: // "exact"
		allMatch := true
		var missing []string
		for _, expected := range target.Expected {
			if !slices.Contains(foundRecords, expected) {
				missing = append(missing, expected)
				allMatch = false
			}
		}
		if len(missing) > 0 {
			msg := fmt.Sprintf(MsgAlertDNSMismatch, target.Hostname, target.Type, strings.Join(missing, ", "), strings.Join(foundRecords, ", "))
			redacted := fmt.Sprintf("Mismatch on %s (%s). Values aren't mapped as expected.", target.Hostname, target.Type)
			app.Notifier.Dispatch(msg, redacted, PriorityUrgent, "rotating_light", target.Hostname, target.Name)
		}

		var unauthorized []string
		for _, found := range foundRecords {
			if !slices.Contains(target.Expected, found) {
				unauthorized = append(unauthorized, found)
				allMatch = false
			}
		}
		if len(unauthorized) > 0 {
			msg := fmt.Sprintf(MsgAlertDNSUnauth, target.Hostname, target.Type, strings.Join(unauthorized, ", "), strings.Join(target.Expected, ", "))
			redacted := fmt.Sprintf("Unauthorized record found on %s (%s).", target.Hostname, target.Type)
			app.Notifier.Dispatch(msg, redacted, PriorityUrgent, "rotating_light", target.Hostname, target.Name)
		}
		return allMatch
	}
}

func validateCertificate(ctx context.Context, app *AppState, target DNSTask, foundRecords []string) int {
	if target.SkipSSL {
		return SSLDaysNotApplicable
	}

	if target.Type != "A" && target.Type != "AAAA" && target.Type != "IP" && target.Type != "CNAME" && target.Type != "ALIAS" {
		return SSLDaysNotApplicable
	}

	var sslIPs []string
	if target.Type == "CNAME" || target.Type == "ALIAS" {
		resolversToUse := app.Config.Resolvers
		if target.CustomResolver != "" {
			resolversToUse = []string{target.CustomResolver}
		}
		sslIPs, _ = queryIPRecords(ctx, app, target.Hostname, resolversToUse)
	} else {
		sslIPs = foundRecords
	}

	if len(sslIPs) == 0 {
		return SSLDaysError
	}

	days, err := checkSSL(ctx, target.Hostname, sslIPs, target.AcceptSelfSigned)
	if err != nil {
		slog.Error("SSL Validation Error", "hostname", target.Hostname, "error", err)
		msg := fmt.Sprintf("SSL Validation Error for %s: %v", target.Hostname, err)
		redacted := "SSL Certificate Validation Failed."
		app.Notifier.Dispatch(msg, redacted, PriorityUrgent, "rotating_light", target.Hostname, target.Name)
		return SSLDaysError
	}

	if days < 0 {
		msg := fmt.Sprintf("SSL Certificate for %s is EXPIRED! (%d days)", target.Hostname, days)
		redacted := "SSL Certificate is EXPIRED."
		app.Notifier.Dispatch(msg, redacted, PriorityUrgent, "rotating_light", target.Hostname, target.Name)
	} else if days <= 14 {
		msg := fmt.Sprintf("SSL Certificate for %s expires in %d days", target.Hostname, days)
		redacted := fmt.Sprintf("SSL Certificate expires in %d days.", days)
		app.Notifier.Dispatch(msg, redacted, PriorityHigh, "warning", target.Hostname, target.Name)
	}
	return days
}

func evaluateEmailSecurity(ctx context.Context, app *AppState, target DomainConfig, state *CheckState) {
	if !target.CheckEmailSecurity {
		return
	}

	emailStatus := StatusOk
	liveMXs, err := validateMX(ctx, app, target, &emailStatus)
	if err != nil {
		state.UpdateEmail(target.Domain, &EmailState{Status: StatusFailed, Error: err.Error()})
		return
	}

	foundSPF, spfErr := validateSPF(ctx, app, target, &emailStatus)
	foundDMARC, dmarcErr := validateDMARC(ctx, app, target, &emailStatus)
	validDkims, dkimErr := validateDKIM(ctx, app, target, &emailStatus)

	var errs []string
	if spfErr != nil {
		errs = append(errs, "SPF lookup error: "+spfErr.Error())
	}
	if dmarcErr != nil {
		errs = append(errs, "DMARC lookup error: "+dmarcErr.Error())
	}
	if dkimErr != nil {
		errs = append(errs, "DKIM lookup error: "+dkimErr.Error())
	}
	if len(errs) > 0 && emailStatus == StatusOk {
		emailStatus = StatusWarning
	}

	hasDKIMExpected := (target.MailProvider != "" && len(ProviderDKIMMap[target.MailProvider]) > 0) || len(target.DKIMSelectors) > 0

	state.UpdateEmail(target.Domain, &EmailState{
		Status:       emailStatus,
		Provider:     target.MailProvider,
		SPF:          foundSPF,
		DMARC:        foundDMARC,
		DKIMExpected: hasDKIMExpected,
		DKIMValid:    validDkims,
		MX:           liveMXs,
		Error:        strings.Join(errs, " | "),
	})
}

func validateMX(ctx context.Context, app *AppState, target DomainConfig, emailStatus *CheckStatus) ([]string, error) {
	mxs, err := queryDNS(ctx, app, target.Domain, dns.TypeMX, app.Config.Resolvers)
	if err != nil || len(mxs) == 0 {
		slog.Error("No MX records found", "domain", target.Domain)
		msg := fmt.Sprintf(MsgAlertEmailNoMX, target.Domain)
		redacted := "No MX records found. Email delivery is broken."
		if !target.SuppressAlerts {
			app.Notifier.Dispatch(msg, redacted, PriorityUrgent, "envelope", target.Domain, target.Name)
		}
		return nil, errors.New("no MX records found")
	}

	var liveMXs []string
	liveMXs = append(liveMXs, mxs...)

	if len(target.MXRecords) > 0 {
		allMatch := true
		for _, expected := range target.MXRecords {
			if !slices.Contains(liveMXs, expected) {
				allMatch = false
				msg := fmt.Sprintf(MsgAlertEmailMXMissing, expected, target.Domain, strings.Join(liveMXs, ", "))
				redacted := "Expected MX record is missing."
				if !target.SuppressAlerts {
					app.Notifier.Dispatch(msg, redacted, PriorityUrgent, "envelope", target.Domain, target.Name)
				}
			}
		}
		for _, found := range liveMXs {
			if !slices.Contains(target.MXRecords, found) {
				allMatch = false
				msg := fmt.Sprintf(MsgAlertEmailMXUnauth, found, target.Domain, strings.Join(target.MXRecords, ", "))
				redacted := "Unauthorized MX record detected."
				if !target.SuppressAlerts {
					app.Notifier.Dispatch(msg, redacted, PriorityUrgent, "rotating_light", target.Domain, target.Name)
				}
			}
		}
		if !allMatch {
			*emailStatus = StatusMismatch
		}
	} else if target.MailProvider != "" {
		safe, known := isProviderMXSafe(liveMXs, target.MailProvider)
		if !known {
			slog.Warn("Unknown mail_provider", "provider", target.MailProvider, "domain", target.Domain)
		} else if !safe {
			msg := fmt.Sprintf(MsgAlertEmailMXHijack, target.Domain, target.MailProvider, strings.Join(liveMXs, ", "))
			redacted := "MX records do not match the expected provider (Possible Hijack)."
			if !target.SuppressAlerts {
				app.Notifier.Dispatch(msg, redacted, PriorityUrgent, "rotating_light", target.Domain, target.Name)
			}
			*emailStatus = StatusHijacked
		}
	}

	return liveMXs, nil
}

// isProviderMXSafe checks whether all live MX hostnames match the expected provider's domain suffixes.
func isProviderMXSafe(liveMXs []string, provider string) (isSafe bool, knownProvider bool) {
	provKey := strings.ToLower(strings.TrimSpace(provider))
	expectedSuffixes, ok := ProviderMXMap[provKey]
	if !ok {
		return true, false
	}
	for _, live := range liveMXs {
		liveClean := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(live), "."))
		matchedProvider := false
		for _, suffix := range expectedSuffixes {
			suffixClean := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(suffix), "."))
			if liveClean == suffixClean || strings.HasSuffix(liveClean, "."+suffixClean) {
				matchedProvider = true
				break
			}
		}
		if !matchedProvider {
			return false, true
		}
	}
	return true, true
}

func validateSPF(ctx context.Context, app *AppState, target DomainConfig, emailStatus *CheckStatus) (bool, error) {
	txts, err := queryDNS(ctx, app, target.Domain, dns.TypeTXT, app.Config.Resolvers)
	if err != nil {
		return false, err
	}
	spfCount := 0

	for _, txt := range txts {
		txtLower := strings.ToLower(strings.TrimSpace(txt))
		if strings.HasPrefix(txtLower, "v=spf1 ") || txtLower == "v=spf1" {
			spfCount++
		}
	}

	if spfCount == 0 {
		msg := fmt.Sprintf(MsgAlertEmailNoSPF, target.Domain)
		redacted := "No valid SPF record found."
		if !target.SuppressAlerts {
			app.Notifier.Dispatch(msg, redacted, PriorityHigh, "warning", target.Domain, target.Name)
		}
		if *emailStatus == StatusOk {
			*emailStatus = StatusWarning
		}
		return false, nil
	} else if spfCount > 1 {
		msg := fmt.Sprintf(MsgAlertEmailMultiSPF, target.Domain)
		redacted := "Multiple SPF records found (Invalid Configuration)."
		if !target.SuppressAlerts {
			app.Notifier.Dispatch(msg, redacted, PriorityUrgent, "x", target.Domain, target.Name)
		}
		if *emailStatus == StatusOk {
			*emailStatus = StatusWarning
		}
		return false, nil
	}
	return true, nil
}

func validateDMARC(ctx context.Context, app *AppState, target DomainConfig, emailStatus *CheckStatus) (bool, error) {
	currentDomain := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(target.Domain), "."))
	var lastErr error

	for {
		dmarcHost := "_dmarc." + currentDomain
		dmarcTxts, err := queryDNS(ctx, app, dmarcHost, dns.TypeTXT, app.Config.Resolvers)
		if err != nil {
			lastErr = err
		} else {
			dmarcFound := false
			dmarcCount := 0
			for _, txt := range dmarcTxts {
				txtLower := strings.ToLower(strings.TrimSpace(txt))
				if strings.HasPrefix(txtLower, "v=dmarc1 ") || strings.HasPrefix(txtLower, "v=dmarc1;") || txtLower == "v=dmarc1" {
					dmarcFound = true
					dmarcCount++
				}
			}

			if dmarcFound {
				if dmarcCount > 1 {
					msg := fmt.Sprintf("Multiple DMARC records found for %s! This breaks email delivery.", target.Domain)
					redacted := "Multiple DMARC records found (Invalid Configuration)."
					if !target.SuppressAlerts {
						app.Notifier.Dispatch(msg, redacted, PriorityUrgent, "x", target.Domain, target.Name)
					}
					if *emailStatus == StatusOk {
						*emailStatus = StatusWarning
					}
					return false, nil
				}
				return true, nil
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
		return false, lastErr
	}

	msg := fmt.Sprintf(MsgAlertEmailNoDMARC, target.Domain, target.Domain)
	redacted := "No valid DMARC record found."
	if !target.SuppressAlerts {
		app.Notifier.Dispatch(msg, redacted, PriorityHigh, "warning", target.Domain, target.Name)
	}
	if *emailStatus == StatusOk {
		*emailStatus = StatusWarning
	}
	return false, nil
}

func validateDKIM(ctx context.Context, app *AppState, target DomainConfig, emailStatus *CheckStatus) ([]string, error) {
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
		dkimTxts, err := queryDNS(ctx, app, dkimHost, dns.TypeTXT, app.Config.Resolvers)
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
			if strings.HasPrefix(txtLower, "v=dkim1") || strings.Contains(txtLower, "p=") {
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
		return validDkims, nil
	}

	if len(missingDkims) > 0 && len(selectorsToCheck) > 0 {
		if lookupErr == nil {
			msg := fmt.Sprintf(MsgAlertEmailNoDKIM, target.Domain, strings.Join(missingDkims, ", "))
			redacted := "No valid DKIM records found for expected selectors."
			if !target.SuppressAlerts {
				app.Notifier.Dispatch(msg, redacted, PriorityHigh, "warning", target.Domain, target.Name)
			}
			if *emailStatus == StatusOk {
				*emailStatus = StatusWarning
			}
		}
	}
	return validDkims, lookupErr
}

// evaluateNSHealth validates primary authoritative nameserver health (expected_ns[0]) directly (RD=0)
// for reachability, authoritative answer (AA flag), and SOA serial. If secondary_ns is configured, it also validates
// secondary reachability, AA flag, SOA serial synchronization, and dumb secondary DNSSEC consistency
// (strictly enforcing that secondary nameservers either do not use DNSSEC or replicate the primary's exact DNSKEYs).
func evaluateNSHealth(ctx context.Context, app *AppState, target DomainConfig, state *CheckState) {
	if !target.VerifyNSHealth || len(target.ExpectedNS) == 0 {
		return
	}

	primaryNS := target.ExpectedNS[0]
	res := &NSHealthResult{
		Valid:   true,
		Primary: primaryNS,
		Servers: make([]NSHealthServerResult, 0, 1+len(target.SecondaryNS)),
	}

	resolveTargetIP := func(nsName string) (string, error) {
		host := nsName
		port := "53"
		if h, p, err := net.SplitHostPort(nsName); err == nil {
			host = h
			port = p
		}
		if net.ParseIP(host) != nil {
			return net.JoinHostPort(host, port), nil
		}
		ips, err := queryIPRecords(ctx, app, host, app.Config.Resolvers)
		if err != nil || len(ips) == 0 {
			return "", fmt.Errorf("failed to resolve IP: %w", err)
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
			msg := fmt.Sprintf(MsgAlertNSUnreachable, primaryNS, target.Domain, pErr)
			app.Notifier.Dispatch(msg, "Primary nameserver IP resolution failed.", PriorityHigh, "warning", target.Domain, target.Name)
		}
		state.UpdateNSHealth(target.Domain, res)
		return
	}

	primarySOAMsg, pSOAErr := queryDNSMsgWithRD(ctx, app, target.Domain, dns.TypeSOA, []string{primaryIP}, false)
	if pSOAErr != nil || primarySOAMsg == nil {
		primarySrv.Error = fmt.Sprintf("SOA lookup failed: %v", pSOAErr)
		res.Valid = false
		res.Servers = append(res.Servers, primarySrv)
		if !target.SuppressAlerts {
			msg := fmt.Sprintf(MsgAlertNSUnreachable, primaryNS, target.Domain, pSOAErr)
			app.Notifier.Dispatch(msg, "Primary nameserver unreachable.", PriorityHigh, "warning", target.Domain, target.Name)
		}
		state.UpdateNSHealth(target.Domain, res)
		return
	}

	primarySrv.Authoritative = primarySOAMsg.Authoritative
	if !primarySrv.Authoritative {
		primarySrv.Error = "Primary nameserver not authoritative (AA flag missing)"
		res.Valid = false
		if !target.SuppressAlerts {
			msg := fmt.Sprintf(MsgAlertNSNonAuthoritative, primaryNS, target.Domain)
			app.Notifier.Dispatch(msg, "Primary nameserver missing AA flag.", PriorityHigh, "warning", target.Domain, target.Name)
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
		primarySrv.Error = "No SOA record returned in answer or authority sections"
		res.Valid = false
		if !target.SuppressAlerts {
			msg := fmt.Sprintf(MsgAlertNSMissingSOA, primaryNS, target.Domain)
			app.Notifier.Dispatch(msg, "Primary nameserver missing SOA record.", PriorityHigh, "warning", target.Domain, target.Name)
		}
	}
	primarySrv.SOASerial = primarySerial

	extractDNSKEYFingerprints := func(msg *dns.Msg) []string {
		if msg == nil {
			return nil
		}
		var keys []string
		for _, ans := range msg.Answer {
			if dk, ok := ans.(*dns.DNSKEY); ok {
				keys = append(keys, fmt.Sprintf("%d-%d-%d-%s", dk.Flags, dk.Protocol, dk.Algorithm, dk.PublicKey))
			}
		}
		slices.Sort(keys)
		return keys
	}

	var primaryDNSKEYs []string
	if dnskeyMsg, _ := queryDNSMsgWithRD(ctx, app, target.Domain, dns.TypeDNSKEY, []string{primaryIP}, false); dnskeyMsg != nil {
		primaryDNSKEYs = extractDNSKEYFingerprints(dnskeyMsg)
		if len(primaryDNSKEYs) > 0 {
			primarySrv.HasDNSKEY = true
			primarySrv.DNSKEYMatch = true
		}
	}

	res.Servers = append(res.Servers, primarySrv)

	// 2. Query Secondary / Slave Nameservers
	for _, secNS := range target.SecondaryNS {
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
				msg := fmt.Sprintf(MsgAlertNSUnreachable, secNS, target.Domain, sErr)
				app.Notifier.Dispatch(msg, "Secondary nameserver IP resolution failed.", PriorityHigh, "warning", target.Domain, target.Name)
			}
			continue
		}

		secSOAMsg, secSOAErr := queryDNSMsgWithRD(ctx, app, target.Domain, dns.TypeSOA, []string{secIP}, false)
		if secSOAErr != nil || secSOAMsg == nil {
			secSrv.Error = fmt.Sprintf("SOA lookup failed: %v", secSOAErr)
			res.Valid = false
			res.Servers = append(res.Servers, secSrv)
			if !target.SuppressAlerts {
				msg := fmt.Sprintf(MsgAlertNSUnreachable, secNS, target.Domain, secSOAErr)
				app.Notifier.Dispatch(msg, "Secondary nameserver unreachable.", PriorityHigh, "warning", target.Domain, target.Name)
			}
			continue
		}

		secSrv.Authoritative = secSOAMsg.Authoritative
		if !secSrv.Authoritative {
			secSrv.Error = "Secondary nameserver not authoritative (AA flag missing)"
			res.Valid = false
			if !target.SuppressAlerts {
				msg := fmt.Sprintf(MsgAlertNSNonAuthoritative, secNS, target.Domain)
				app.Notifier.Dispatch(msg, "Secondary nameserver missing AA flag.", PriorityHigh, "warning", target.Domain, target.Name)
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
			secSrv.Error = "No SOA record returned in answer or authority sections"
			res.Valid = false
			if !target.SuppressAlerts {
				msg := fmt.Sprintf(MsgAlertNSMissingSOA, secNS, target.Domain)
				app.Notifier.Dispatch(msg, "Secondary nameserver missing SOA record.", PriorityHigh, "warning", target.Domain, target.Name)
			}
		}
		secSrv.SOASerial = secSerial

		// Compare SOA serials between Primary and Secondary
		if primaryFoundSOA && secFoundSOA {
			if secSerial < primarySerial {
				res.Valid = false
				if !target.SuppressAlerts {
					msg := fmt.Sprintf(MsgAlertNSSOALag, secNS, secSerial, primaryNS, primarySerial, target.Domain)
					app.Notifier.Dispatch(msg, "Secondary nameserver SOA serial lags behind primary.", PriorityHigh, "warning", target.Domain, target.Name)
				}
			} else if secSerial != primarySerial {
				res.Valid = false
				if !target.SuppressAlerts {
					msg := fmt.Sprintf(MsgAlertNSSOAMismatch, secNS, secSerial, primaryNS, primarySerial, target.Domain)
					app.Notifier.Dispatch(msg, "Secondary nameserver SOA serial differs from primary.", PriorityWarning, "warning", target.Domain, target.Name)
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
					msg := fmt.Sprintf(MsgAlertNSDNSKEYMissing, secNS, target.Domain)
					app.Notifier.Dispatch(msg, "Secondary nameserver missing DNSKEY records present on primary.", PriorityHigh, "warning", target.Domain, target.Name)
				}
			} else if !slices.Equal(primaryDNSKEYs, secDNSKEYs) {
				res.Valid = false
				secSrv.DNSKEYMatch = false
				if !target.SuppressAlerts {
					msg := fmt.Sprintf(MsgAlertNSDNSKEYMismatch, secNS, target.Domain)
					app.Notifier.Dispatch(msg, "Secondary nameserver DNSKEY mismatch (not replicating primary keys).", PriorityHigh, "warning", target.Domain, target.Name)
				}
			} else {
				secSrv.DNSKEYMatch = true
			}
		} else if len(secDNSKEYs) > 0 {
			// Primary is unsigned, but secondary serves DNSKEYs!
			res.Valid = false
			secSrv.DNSKEYMatch = false
			if !target.SuppressAlerts {
				msg := fmt.Sprintf(MsgAlertNSDNSKEYUnexpected, secNS, target.Domain)
				app.Notifier.Dispatch(msg, "Secondary nameserver serves DNSKEY while primary is unsigned.", PriorityHigh, "warning", target.Domain, target.Name)
			}
		} else {
			// Both unsigned
			secSrv.DNSKEYMatch = true
		}

		res.Servers = append(res.Servers, secSrv)
	}

	state.UpdateNSHealth(target.Domain, res)
}
