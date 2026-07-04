package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

func checkSSL(hostname string, ips []string) (int, error) {
	dialHost := hostname
	if strings.HasPrefix(dialHost, "*.") {
		// Replace *. with www. to ensure a valid FQDN is used for DNS resolution and SNI
		dialHost = strings.Replace(dialHost, "*.", "www.", 1)
	}

	targetAddr := dialHost + ":443"
	if len(ips) > 0 {
		if net.ParseIP(ips[0]) != nil {
			ipStr := ips[0]
			if strings.Contains(ipStr, ":") && !strings.HasPrefix(ipStr, "[") {
				ipStr = "[" + ipStr + "]"
			}
			targetAddr = ipStr + ":443"
		}
	}

	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", targetAddr, &tls.Config{
		ServerName:         dialHost,
		InsecureSkipVerify: true,
	})
	if err != nil {
		return -1, err
	}
	defer conn.Close()
	cert := conn.ConnectionState().PeerCertificates[0]
	return int(time.Until(cert.NotAfter).Hours() / 24), nil
}

func evaluateDNS(app *AppState, target DNSTask) {
	var foundRecords []string
	var err error

	resolvers := app.Config.Resolvers
	if target.CustomResolver != "" {
		resolvers = []string{target.CustomResolver}
	}

	var isCF bool
	if target.Provider == "cloudflare" {
		isCF = true
	}

	if !isCF {
		dnsTypeMap := map[string]uint16{
			"A":     dns.TypeA,
			"AAAA":  dns.TypeAAAA,
			"CNAME": dns.TypeCNAME,
			"MX":    dns.TypeMX,
			"TXT":   dns.TypeTXT,
		}

		if qType, ok := dnsTypeMap[target.Type]; ok {
			foundRecords, err = queryDNS(target.Hostname, qType, resolvers)
			
			// CNAME Flattening
			// If target is CNAME but resolution returned nothing, the resolver
			// might have flattened it to A/AAAA records. We must resolve the
			// expected CNAME string itself to IPs and compare with the apex IPs.
			if target.Type == "CNAME" && len(foundRecords) == 0 && err == nil && len(target.Expected) > 0 {
				apexIPs, apexErr := queryDNS(target.Hostname, dns.TypeA, resolvers)
				if apexErr == nil && len(apexIPs) > 0 {
					expectedTarget := target.Expected[0]
					expectedIPs, expErr := queryDNS(expectedTarget, dns.TypeA, resolvers)
					
					if expErr == nil && len(expectedIPs) > 0 {
						// Check if any apex IP exists in expected IPs
						matchFound := false
						for _, aIP := range apexIPs {
							for _, eIP := range expectedIPs {
								if aIP == eIP {
									matchFound = true
									break
								}
							}
						}
						// If match found, simulate the unflattened record to pass validation
						if matchFound {
							foundRecords = []string{expectedTarget}
						}
					}
				}
			}
		} else {
			err = fmt.Errorf("unsupported DNS type: %s", target.Type)
		}
	}

	// Resilient Fallback mechanism
	if !isCF && err != nil && target.CustomResolver != "" {
		log.Printf(MsgLogDNSCustomFail, target.CustomResolver, target.Hostname)
		dnsTypeMap := map[string]uint16{
			"A":     dns.TypeA,
			"AAAA":  dns.TypeAAAA,
			"CNAME": dns.TypeCNAME,
			"MX":    dns.TypeMX,
			"TXT":   dns.TypeTXT,
		}
		if qType, ok := dnsTypeMap[target.Type]; ok {
			foundRecords, err = queryDNS(target.Hostname, qType, app.Config.Resolvers)
		}
	}

	if !isCF && err != nil {
		msg := fmt.Sprintf(MsgAlertDNSFailed, target.Hostname, target.Type)
		redacted := fmt.Sprintf("DNS Resolution Failed for %s (%s).", target.Hostname, target.Type)
		app.Notifier.Dispatch(msg, redacted, "urgent", "rotating_light", target.Hostname, target.Name)
		recordKey := fmt.Sprintf("%s_%s", target.Hostname, target.Type)
		UpdateDNSState(recordKey, map[string]interface{}{
			"hostname": target.Hostname,
			"name":     target.Name,
			"type":     target.Type,
			"expected": target.Expected,
			"status":   "failed",
			"error":    err.Error(),
		})
		return
	}

	// Smart Auto-Detect Logic (Cloudflare)
	if !isCF && app.CF.API != nil && (target.Type == "A" || target.Type == "AAAA") {
		isCF = true
		for _, rec := range foundRecords {
			if !app.CF.IsCloudflareIP(rec) {
				isCF = false
				break
			}
		}
	}

	if isCF && (len(foundRecords) > 0 || target.Type == "TUNNEL") {
		if target.Type != "TUNNEL" {
			log.Printf(MsgLogDNSCFDetect, target.Hostname)
		}

		if app.CF.API == nil {
			log.Printf(MsgLogDNSCFBypass, target.Hostname)
			recordKey := fmt.Sprintf("%s_%s", target.Hostname, target.Type)
			UpdateDNSState(recordKey, map[string]interface{}{
				"hostname": target.Hostname,
				"name":     target.Name,
				"type":     target.Type,
				"expected": target.Expected,
				"status":   "proxied_unverified",
			})
			return
		}

		foundRecords, err = app.CF.FetchBackendRecords(target.Hostname, target.Type)
		if err != nil {
			recordKey := fmt.Sprintf("%s_%s", target.Hostname, target.Type)
			UpdateDNSState(recordKey, map[string]interface{}{
				"hostname": target.Hostname,
				"name":     target.Name,
				"type":     target.Type,
				"expected": target.Expected,
				"status":   "api_error",
				"error":    err.Error(),
			})
			return
		}
	}
	liveMap := make(map[string]bool)
	for _, rec := range foundRecords {
		liveMap[rec] = true
	}

	allMatch := true
	for _, expected := range target.Expected {
		if !liveMap[expected] {
			msg := fmt.Sprintf(MsgAlertDNSMismatch, target.Hostname, target.Type, expected, strings.Join(foundRecords, ", "))
			redacted := fmt.Sprintf("Mismatch on %s (%s). Values aren't mapped as expected.", target.Hostname, target.Type)
			app.Notifier.Dispatch(msg, redacted, "urgent", "rotating_light", target.Hostname, target.Name)
			allMatch = false
		}
	}

	recordKey := fmt.Sprintf("%s_%s", target.Hostname, target.Type)

	// Check SSL concurrently while assembling state
	sslDays := -1
	if target.Type == "A" || target.Type == "AAAA" || target.Type == "CNAME" || target.Type == "TUNNEL" {
		if days, err := checkSSL(target.Hostname, foundRecords); err == nil {
			sslDays = days
		}
	}

	if allMatch {
		UpdateDNSState(recordKey, map[string]interface{}{
			"hostname": target.Hostname,
			"name":     target.Name,
			"type":     target.Type,
			"expected": target.Expected,
			"status":   "ok",
			"found":    foundRecords,
			"ssl_days": sslDays,
		})
	} else {
		UpdateDNSState(recordKey, map[string]interface{}{
			"hostname": target.Hostname,
			"name":     target.Name,
			"type":     target.Type,
			"expected": target.Expected,
			"status":   "mismatch",
			"found":    foundRecords,
			"ssl_days": sslDays,
		})
	}
}

var globalResolverIndex uint32

// queryDNS queries the given resolvers for the specified hostname and record type using miekg/dns.
// It bypasses the OS resolver completely and forces a direct UDP/TCP connection to the provided IP.
func queryDNS(hostname string, qtype uint16, resolvers []string) ([]string, error) {
	if len(resolvers) == 0 {
		return nil, errors.New("no resolvers configured")
	}

	idx := atomic.AddUint32(&globalResolverIndex, 1) % uint32(len(resolvers))
	ip := resolvers[idx]
	if !strings.Contains(ip, ":") {
		ip += ":53"
	}

	c := new(dns.Client)
	c.Timeout = 5 * time.Second

	m := new(dns.Msg)
	// Ensure the hostname ends with a dot for FQDN format required by miekg/dns
	fqdn := dns.Fqdn(hostname)
	m.SetQuestion(fqdn, qtype)

	r, _, err := c.Exchange(m, ip)
	if err != nil {
		return nil, fmt.Errorf("lookup %s on %s: %w", hostname, ip, err)
	}

	if r.Rcode != dns.RcodeSuccess {
		if r.Rcode == dns.RcodeNameError {
			return nil, fmt.Errorf("lookup %s on %s: no such host", hostname, ip)
		}
		return nil, fmt.Errorf("lookup %s on %s: server returned error code %d", hostname, ip, r.Rcode)
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
				results = append(results, strings.ToLower(strings.TrimSuffix(record.Mx, ".")))
			}
		case *dns.TXT:
			if qtype == dns.TypeTXT {
				results = append(results, strings.Join(record.Txt, ""))
			}
		}
	}

	return results, nil
}
