package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/miekg/dns"
)

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

	minDays := -1
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

		tlsConn := conn.(*tls.Conn)
		state := tlsConn.ConnectionState()
		_ = conn.Close()

		cert := state.PeerCertificates[0]
		days := int(time.Until(cert.NotAfter).Hours() / 24)
		if minDays == -1 || days < minDays {
			minDays = days
		}
		successCount++
	}

	if successCount == 0 {
		return -1, lastErr
	}

	return minDays, nil
}

// queryDNSMsg queries the given resolvers for the specified hostname and record type using miekg/dns.
// It retries on network errors and SERVFAIL using the next resolver in round-robin order.
func queryDNSMsg(ctx context.Context, app *AppState, hostname string, qtype uint16, resolvers []string) (*dns.Msg, error) {
	if len(resolvers) == 0 {
		return nil, errors.New("no resolvers configured")
	}

	startIdx := 0
	if app != nil {
		startIdx = int(app.GlobalResolverIndex.Add(1) % uint32(len(resolvers)))
	}

	var lastErr error
	for attempt := 0; attempt < len(resolvers); attempt++ {
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
		m.RecursionDesired = true

		r, _, err := c.ExchangeContext(ctx, m, ip)
		if err == nil && r != nil && r.Truncated {
			c.Net = "tcp"
			r, _, err = c.ExchangeContext(ctx, m, ip)
		}

		if err != nil {
			lastErr = fmt.Errorf("lookup %s on %s: %w", hostname, ip, err)
			continue
		}

		if r.Rcode != dns.RcodeSuccess {
			if r.Rcode == dns.RcodeNameError {
				// NXDOMAIN is authoritative — do not retry on other resolvers
				return nil, fmt.Errorf("lookup %s on %s: no such host (NXDOMAIN)", hostname, ip)
			}
			if r.Rcode == dns.RcodeServerFailure {
				// SERVFAIL may be transient — retry on next resolver
				lastErr = fmt.Errorf("lookup %s on %s: server failure (SERVFAIL)", hostname, ip)
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

// CAAEntry represents a structured CAA DNS record.
type CAAEntry struct {
	Flag  uint8
	Tag   string
	Value string
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
			val := strings.ToLower(strings.TrimSpace(caa.Value))
			if val == ";" {
				val = ""
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

type CAAResult struct {
	Valid      bool     `json:"valid"`
	Issue      []string `json:"issue"`
	IssueWild  []string `json:"issuewild"`
	IssueMail  []string `json:"issuemail"`
	UnknownCAs []string `json:"unknown_cas,omitempty"`
	Error      string   `json:"error,omitempty"`
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
		clean := strings.TrimSpace(strings.SplitN(v, ";", 2)[0])
		if clean == "" && strings.Contains(v, ";") {
			clean = ";"
		}
		if clean != "" {
			liveIssue[clean] = true
		}
	}
	for _, v := range res.IssueWild {
		clean := strings.TrimSpace(strings.SplitN(v, ";", 2)[0])
		if clean == "" && strings.Contains(v, ";") {
			clean = ";"
		}
		if clean != "" {
			liveIssueWild[clean] = true
		}
	}
	for _, v := range res.IssueMail {
		clean := strings.TrimSpace(strings.SplitN(v, ";", 2)[0])
		if clean == "" && strings.Contains(v, ";") {
			clean = ";"
		}
		if clean != "" {
			liveIssueMail[clean] = true
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
				redacted := fmt.Sprintf("Unauthorized CA in %s (expected deny all).", tag)
				if !target.SuppressAlerts {
					app.Notifier.Dispatch(msg, redacted, PriorityUrgent, "rotating_light", target.Domain, target.Name)
				}
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
			redacted := fmt.Sprintf("Expected CA missing in %s.", tag)
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
			redacted := fmt.Sprintf("Unauthorized CA in %s.", tag)
			if !target.SuppressAlerts {
				app.Notifier.Dispatch(msg, redacted, PriorityUrgent, "rotating_light", target.Domain, target.Name)
			}
			res.Valid = false
		}
	}
}

func fetchCAA(ctx context.Context, app *AppState, domain string, resolvers []string) *CAAResult {
	res := &CAAResult{}
	currentDomain := domain

	for {
		entries, err := queryCAARecords(ctx, app, currentDomain, resolvers)
		if err != nil {
			if strings.Contains(err.Error(), "(NXDOMAIN)") {
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

		// Tree climbing
		parts := strings.SplitN(currentDomain, ".", 2)
		if len(parts) < 2 || !strings.Contains(parts[1], ".") {
			break // Reached TLD or invalid domain
		}
		currentDomain = parts[1]
	}

	return res
}

type DNSSECResult struct {
	Valid           bool     `json:"valid"`
	HasDS           bool     `json:"has_ds"`
	HasDNSKEY       bool     `json:"has_dnskey"`
	DSMatchesDNSKEY bool     `json:"ds_matches_dnskey"`
	RRSIGValid      bool     `json:"rrsig_valid"`
	RRSIGExpiry     string   `json:"rrsig_expiry,omitempty"`
	ChainIntact     bool     `json:"chain_intact"`
	Algorithms      []string `json:"algorithms,omitempty"`
	Source          string   `json:"source"`
	Error           string   `json:"error,omitempty"`
}

type googleDoHResponse struct {
	Status int  `json:"Status"`
	AD     bool `json:"AD"`
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

				found := false
				for _, a := range res.Algorithms {
					if a == algoStr {
						found = true
						break
					}
				}
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

	// 3. Match DS to KSK
	for _, key := range dnskeyRecords {
		// Flag 257 indicates KSK
		if key.Flags == 257 {
			for _, ds := range dsRecords {
				computedDS := key.ToDS(ds.DigestType)
				if computedDS != nil && strings.EqualFold(computedDS.Digest, ds.Digest) {
					res.DSMatchesDNSKEY = true
					break
				}
			}
			if res.DSMatchesDNSKEY {
				break
			}
		}
	}

	if len(dsRecords) == 0 && len(dnskeyRecords) > 0 {
		// If no DS records but DNSKEY is present, it might be a root or trust anchor
		// Or it might be missing DS at parent. We can't match it.
	} else if len(dnskeyRecords) == 0 {
		// No DNSKEY
	} else if !res.DSMatchesDNSKEY {
		res.Error = "DS record does not match any KSK"
	}

	// 4. Validate RRSIG
	if len(rrsigRecords) > 0 && len(rrset) > 0 {
		for _, sig := range rrsigRecords {
			if strings.EqualFold(sig.SignerName, fqdn) {
				// Find the key that signed this RRSIG by KeyTag
				for _, key := range dnskeyRecords {
					if key.KeyTag() == sig.KeyTag {
						err := sig.Verify(key, rrset)
						if err == nil {
							now := uint32(time.Now().Unix())
							if sig.Inception <= now && now <= sig.Expiration {
								res.RRSIGValid = true
								expiryStr := dns.TimeToString(sig.Expiration)
								if et, parseErr := time.Parse("20060102150405", expiryStr); parseErr == nil {
									res.RRSIGExpiry = et.UTC().Format(time.RFC3339)
								}
								break
							} else {
								res.Error = "RRSIG is expired or not yet valid"
							}
						}
					}
				}
				if res.RRSIGValid {
					break
				}
			}
		}
	}

	// 5. Tier 2: Google DoH
	dohURL := fmt.Sprintf("%s?name=%s&type=A&do=1", dohURLTemplate, domain)
	dohClient := &http.Client{Timeout: 5 * time.Second}
	dohReq, reqErr := http.NewRequestWithContext(ctx, "GET", dohURL, nil)

	if reqErr != nil {
		res.Source = "local_only"
	} else {
		dohReq.Header.Set("Accept", "application/dns-json")
		dohResp, err := dohClient.Do(dohReq)

		if err != nil {
			res.Source = "local_only"
		} else {
			defer func() { _ = dohResp.Body.Close() }()
			var dohResult googleDoHResponse
			if err := json.NewDecoder(dohResp.Body).Decode(&dohResult); err == nil {
				if dohResult.Status == 0 && dohResult.AD {
					res.ChainIntact = true
				}
			}
		}
	}

	if res.HasDS && res.HasDNSKEY && res.DSMatchesDNSKEY && res.RRSIGValid && (res.ChainIntact || res.Source == "local_only") {
		res.Valid = true
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

	if err != nil {
		slog.Error("DNS Resolution Failed", "hostname", target.Hostname, "type", target.Type, "error", err)
		msg := fmt.Sprintf(MsgAlertDNSFailed, target.Hostname, target.Type)
		redacted := fmt.Sprintf("DNS Resolution Failed for %s (%s).", target.Hostname, target.Type)
		app.Notifier.Dispatch(msg, redacted, PriorityUrgent, "rotating_light", target.Hostname, target.Name)

		recordKey := fmt.Sprintf("%s_%s", target.Hostname, target.Type)
		state.UpdateDNS(recordKey, &DNSState{
			Hostname: target.Hostname,
			Name:     target.Name,
			Type:     target.Type,
			Expected: target.Expected,
			Status:   StatusFailed,
			Error:    err.Error(),
		})
		return
	}

	allMatch := validateRecords(app, target, foundRecords)

	recordKey := fmt.Sprintf("%s_%s", target.Hostname, target.Type)
	sslDays := validateCertificate(ctx, app, target, foundRecords)

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
	})
}

func resolveTarget(ctx context.Context, app *AppState, target DNSTask) ([]string, error) {
	resolvers := app.Config.Resolvers
	if target.CustomResolver != "" {
		resolvers = []string{target.CustomResolver}
	}

	dnsTypeMap := map[string]uint16{
		"A":     dns.TypeA,
		"AAAA":  dns.TypeAAAA,
		"CNAME": dns.TypeCNAME,
		"MX":    dns.TypeMX,
		"TXT":   dns.TypeTXT,
	}

	var foundRecords []string
	var err error

	if target.Type == "IP" {
		foundRecords, err = queryIPRecords(ctx, app, target.Hostname, resolvers)
	} else if qType, ok := dnsTypeMap[target.Type]; ok {
		foundRecords, err = queryDNS(ctx, app, target.Hostname, qType, resolvers)

		// CNAME Flattening
		if target.Type == "CNAME" && len(foundRecords) == 0 && err == nil && len(target.Expected) > 0 {
			apexIPs, apexErr := queryIPRecords(ctx, app, target.Hostname, resolvers)
			if apexErr != nil {
				err = apexErr
			} else if len(apexIPs) > 0 {
				for _, expectedTarget := range target.Expected {
					expectedIPs, expErr := queryIPRecords(ctx, app, expectedTarget, resolvers)
					if expErr != nil {
						err = expErr
						break
					}
					if len(expectedIPs) > 0 {
						matchFound := false
						for _, aIP := range apexIPs {
							for _, eIP := range expectedIPs {
								if aIP == eIP {
									matchFound = true
									break
								}
							}
							if matchFound {
								break
							}
						}
						if matchFound {
							foundRecords = append(foundRecords, expectedTarget)
						}
					}
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

	return foundRecords, err
}

func validateRecords(app *AppState, target DNSTask, foundRecords []string) bool {
	allMatch := true
	for _, expected := range target.Expected {
		if !slices.Contains(foundRecords, expected) {
			msg := fmt.Sprintf(MsgAlertDNSMismatch, target.Hostname, target.Type, expected, strings.Join(foundRecords, ", "))
			redacted := fmt.Sprintf("Mismatch on %s (%s). Values aren't mapped as expected.", target.Hostname, target.Type)
			app.Notifier.Dispatch(msg, redacted, PriorityUrgent, "rotating_light", target.Hostname, target.Name)
			allMatch = false
		}
	}

	if len(target.Expected) > 0 {
		for _, found := range foundRecords {
			if !slices.Contains(target.Expected, found) {
				msg := fmt.Sprintf(MsgAlertDNSUnauth, target.Hostname, target.Type, found, strings.Join(target.Expected, ", "))
				redacted := fmt.Sprintf("Unauthorized record found on %s (%s).", target.Hostname, target.Type)
				app.Notifier.Dispatch(msg, redacted, PriorityUrgent, "rotating_light", target.Hostname, target.Name)
				allMatch = false
			}
		}
	}
	return allMatch
}

func validateCertificate(ctx context.Context, app *AppState, target DNSTask, foundRecords []string) int {
	if target.Type != "A" && target.Type != "AAAA" && target.Type != "IP" && target.Type != "CNAME" {
		return -2
	}

	var sslIPs []string
	if target.Type == "CNAME" {
		resolversToUse := app.Config.Resolvers
		if target.CustomResolver != "" {
			resolversToUse = []string{target.CustomResolver}
		}
		sslIPs, _ = queryIPRecords(ctx, app, target.Hostname, resolversToUse)
	} else {
		sslIPs = foundRecords
	}

	if len(sslIPs) == 0 {
		return -1
	}

	days, err := checkSSL(ctx, target.Hostname, sslIPs, target.AcceptSelfSigned)
	if err != nil {
		slog.Error("SSL Validation Error", "hostname", target.Hostname, "error", err)
		msg := fmt.Sprintf("SSL Validation Error for %s: %v", target.Hostname, err)
		redacted := "SSL Certificate Validation Failed."
		app.Notifier.Dispatch(msg, redacted, PriorityUrgent, "rotating_light", target.Hostname, target.Name)
		return -1
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

	foundSPF := validateSPF(ctx, app, target, &emailStatus)
	foundDMARC := validateDMARC(ctx, app, target, &emailStatus)
	validDkims := validateDKIM(ctx, app, target, &emailStatus)

	state.UpdateEmail(target.Domain, &EmailState{
		Status:    emailStatus,
		Provider:  target.MailProvider,
		SPF:       foundSPF,
		DMARC:     foundDMARC,
		DKIMValid: validDkims,
		MX:        liveMXs,
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
		expectedSuffixes, ok := ProviderMXMap[target.MailProvider]
		if !ok {
			slog.Warn("Unknown mail_provider", "provider", target.MailProvider, "domain", target.Domain)
		} else {
			hijackSafe := true
			for _, live := range liveMXs {
				matchedProvider := false
				for _, suffix := range expectedSuffixes {
					if live == suffix || strings.HasSuffix(live, "."+suffix) {
						matchedProvider = true
						break
					}
				}
				if !matchedProvider {
					hijackSafe = false
					break
				}
			}
			if !hijackSafe {
				msg := fmt.Sprintf(MsgAlertEmailMXHijack, target.Domain, target.MailProvider, strings.Join(liveMXs, ", "))
				redacted := "MX records do not match the expected provider (Possible Hijack)."
				if !target.SuppressAlerts {
					app.Notifier.Dispatch(msg, redacted, PriorityUrgent, "rotating_light", target.Domain, target.Name)
				}
				*emailStatus = StatusHijacked
			}
		}
	}

	return liveMXs, nil
}

func validateSPF(ctx context.Context, app *AppState, target DomainConfig, emailStatus *CheckStatus) bool {
	txts, _ := queryDNS(ctx, app, target.Domain, dns.TypeTXT, app.Config.Resolvers)
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
		return false
	} else if spfCount > 1 {
		msg := fmt.Sprintf(MsgAlertEmailMultiSPF, target.Domain)
		redacted := "Multiple SPF records found (Invalid Configuration)."
		if !target.SuppressAlerts {
			app.Notifier.Dispatch(msg, redacted, PriorityUrgent, "x", target.Domain, target.Name)
		}
		if *emailStatus == StatusOk {
			*emailStatus = StatusWarning
		}
	}
	return true
}

func validateDMARC(ctx context.Context, app *AppState, target DomainConfig, emailStatus *CheckStatus) bool {
	dmarcHost := "_dmarc." + target.Domain
	dmarcTxts, _ := queryDNS(ctx, app, dmarcHost, dns.TypeTXT, app.Config.Resolvers)
	dmarcFound := false
	dmarcCount := 0

	for _, txt := range dmarcTxts {
		txtLower := strings.ToLower(strings.TrimSpace(txt))
		if strings.HasPrefix(txtLower, "v=dmarc1 ") || strings.HasPrefix(txtLower, "v=dmarc1;") || txtLower == "v=dmarc1" {
			dmarcFound = true
			dmarcCount++
		}
	}
	if !dmarcFound {
		msg := fmt.Sprintf(MsgAlertEmailNoDMARC, target.Domain, target.Domain)
		redacted := "No valid DMARC record found."
		if !target.SuppressAlerts {
			app.Notifier.Dispatch(msg, redacted, PriorityHigh, "warning", target.Domain, target.Name)
		}
		if *emailStatus == StatusOk {
			*emailStatus = StatusWarning
		}
	} else if dmarcCount > 1 {
		msg := fmt.Sprintf("Multiple DMARC records found for %s! This breaks email delivery.", target.Domain)
		redacted := "Multiple DMARC records found (Invalid Configuration)."
		if !target.SuppressAlerts {
			app.Notifier.Dispatch(msg, redacted, PriorityUrgent, "x", target.Domain, target.Name)
		}
		if *emailStatus == StatusOk {
			*emailStatus = StatusWarning
		}
	}
	return dmarcFound
}

func validateDKIM(ctx context.Context, app *AppState, target DomainConfig, emailStatus *CheckStatus) []string {
	var selectorsToCheck []string
	if target.MailProvider != "" {
		if defaults, ok := ProviderDKIMMap[target.MailProvider]; ok {
			selectorsToCheck = append(selectorsToCheck, defaults...)
		}
	}
	selectorsToCheck = append(selectorsToCheck, target.DKIMSelectors...)

	var validDkims []string
	var missingDkims []string

	for _, selector := range selectorsToCheck {
		dkimHost := selector + "._domainkey." + target.Domain
		dkimTxts, _ := queryDNS(ctx, app, dkimHost, dns.TypeTXT, app.Config.Resolvers)

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

	if len(missingDkims) > 0 && len(selectorsToCheck) > 0 {
		if len(validDkims) == 0 {
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
	return validDkims
}
