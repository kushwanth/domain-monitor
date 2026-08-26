package main

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/openrdap/rdap"
)

func evaluateRDAP(ctx context.Context, client *rdap.Client, app *AppState, target DomainConfig, state *CheckState) {
	rdapState, err := fetchRDAP(ctx, client, target.Domain)
	if err != nil {
		log.Printf(MsgLogWHOISFallback, target.Domain)

		whoisState, whoisErr := fetchWhois(target.Domain)
		if whoisErr != nil {
			log.Printf(MsgLogWHOISFail, target.Domain, whoisErr)
			state.UpdateRDAP(target.Domain, &RDAPState{
				Status: StatusFailed,
				Error:  fmt.Sprintf("RDAP: %v | WHOIS: %v", err, whoisErr),
			})
			return
		}

		log.Printf(MsgLogWHOISSuccess, target.Domain)
		validateRDAPState(app, target, state, whoisState)
		return
	}

	validateRDAPState(app, target, state, rdapState)
}

func fetchRDAP(ctx context.Context, client *rdap.Client, domain string) (*RDAPState, error) {
	req := rdap.NewDomainRequest(domain)
	if ctx != nil {
		req = req.WithContext(ctx)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	domainInfo, ok := resp.Object.(*rdap.Domain)
	if !ok {
		return nil, fmt.Errorf("unexpected RDAP response object: %T", resp.Object)
	}

	state := &RDAPState{
		Status: StatusOk,
		DNSSEC: false,
	}

	for _, entity := range domainInfo.Entities {
		isRegistrar := false
		for _, role := range entity.Roles {
			if role == "registrar" {
				isRegistrar = true
				break
			}
		}
		if isRegistrar && entity.VCard != nil {
			for _, prop := range entity.VCard.Properties {
				if prop.Name == "fn" {
					if str, ok := prop.Value.(string); ok {
						state.Registrar = str
					}
					break
				}
			}
		}
	}

	for _, event := range domainInfo.Events {
		action := strings.ToLower(event.Action)
		if strings.Contains(action, "expiration") {
			state.Expiration = event.Date
		}
	}

	for _, ns := range domainInfo.Nameservers {
		live := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(ns.LDHName), "."))
		state.Nameservers = append(state.Nameservers, live)
	}

	state.DomainStatus = append(state.DomainStatus, domainInfo.Status...)

	if domainInfo.SecureDNS != nil && domainInfo.SecureDNS.DelegationSigned != nil && *domainInfo.SecureDNS.DelegationSigned {
		state.DNSSEC = true
	}

	return state, nil
}

func validateRDAPState(app *AppState, target DomainConfig, state *CheckState, parsed *RDAPState) {
	if parsed.Expiration != "" {
		if t, err := time.Parse(time.RFC3339, parsed.Expiration); err == nil {
			days := time.Until(t).Hours() / 24
			if days <= 30 {
				msg := fmt.Sprintf(MsgAlertRDAPExpiry, target.Domain, days)
				redacted := fmt.Sprintf("Domain is expiring in %.0f days.", days)
				if !target.SuppressAlerts {
					app.Notifier.Dispatch(msg, redacted, PriorityWarning, "warning", target.Domain, target.Name)
				}
			}
		} else if t, err := time.Parse("2006-01-02T15:04:05Z", parsed.Expiration); err == nil {
			// fallback format sometimes used by WHOIS
			days := time.Until(t).Hours() / 24
			if days <= 30 {
				msg := fmt.Sprintf(MsgAlertRDAPExpiry, target.Domain, days)
				redacted := fmt.Sprintf("Domain is expiring in %.0f days.", days)
				if !target.SuppressAlerts {
					app.Notifier.Dispatch(msg, redacted, PriorityWarning, "warning", target.Domain, target.Name)
				}
			}
		}
	}

	liveNS := make(map[string]bool)
	expectedMap := make(map[string]bool)
	for _, expected := range target.ExpectedNS {
		expectedMap[expected] = true
	}

	if len(target.ExpectedNS) > 0 {
		for _, ns := range parsed.Nameservers {
			liveNS[ns] = true
			if !expectedMap[ns] {
				msg := fmt.Sprintf(MsgAlertRDAPUnauthNS, target.Domain, ns)
				redacted := "Unauthorized nameserver detected."
				if !target.SuppressAlerts {
					app.Notifier.Dispatch(msg, redacted, PriorityUrgent, "skull", target.Domain, target.Name)
				}
			}
		}
	} else {
		for _, ns := range parsed.Nameservers {
			liveNS[ns] = true
		}
	}

	for _, expected := range target.ExpectedNS {
		if !liveNS[expected] {
			msg := fmt.Sprintf(MsgAlertRDAPMissingNS, target.Domain, expected)
			redacted := "Expected nameserver is missing."
			if !target.SuppressAlerts {
				app.Notifier.Dispatch(msg, redacted, PriorityHigh, "warning", target.Domain, target.Name)
			}
		}
	}

	isLocked := false
	for _, s := range parsed.DomainStatus {
		status := strings.ReplaceAll(strings.ToLower(s), " ", "")

		if status == "serverhold" || status == "clienthold" || status == "pendingdelete" {
			parsed.Status = StatusFailed
			msg := fmt.Sprintf(MsgAlertRDAPSuspended, target.Domain, status)
			redacted := fmt.Sprintf("Domain suspended (Status: %s).", status)
			if !target.SuppressAlerts {
				app.Notifier.Dispatch(msg, redacted, PriorityUrgent, "x", target.Domain, target.Name)
			}
		}
		if strings.Contains(status, "transferprohibited") {
			isLocked = true
		}
	}

	if !isLocked {
		msg := fmt.Sprintf(MsgAlertRDAPUnlocked, target.Domain)
		redacted := "Domain transfer lock is disabled."
		if !target.SuppressAlerts {
			app.Notifier.Dispatch(msg, redacted, PriorityHigh, "unlock", target.Domain, target.Name)
		}
	}
	state.UpdateRDAP(target.Domain, parsed)
}

func getRootZoneResolvers(ctx context.Context, app *AppState, rootZone string, globalResolvers []string) []string {
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

func validateNSDelegation(ctx context.Context, app *AppState, target DomainConfig, state *CheckState) {
	parsed := &RDAPState{
		Status:          StatusOk,
		IsDelegatedZone: true,
	}

	resolversToUse := app.Config.Resolvers
	if target.RootZone != "" {
		rootIPs := getRootZoneResolvers(ctx, app, target.RootZone, app.Config.Resolvers)
		if len(rootIPs) > 0 {
			resolversToUse = rootIPs
		}
	}

	r, err := queryDNSMsg(ctx, app, target.Domain, dns.TypeNS, resolversToUse)
	if err != nil {
		parsed.Status = StatusFailed
		parsed.Error = fmt.Sprintf("Failed to query NS records: %v", err)
		state.UpdateRDAP(target.Domain, parsed)
		return
	}

	var nsRecords []string
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

	for _, ns := range nsRecords {
		parsed.Nameservers = append(parsed.Nameservers, strings.ToLower(strings.TrimSuffix(strings.TrimSpace(ns), ".")))
	}

	liveNS := make(map[string]bool)
	expectedMap := make(map[string]bool)
	for _, expected := range target.ExpectedNS {
		expectedMap[expected] = true
	}

	if len(target.ExpectedNS) > 0 {
		for _, ns := range parsed.Nameservers {
			liveNS[ns] = true
			if !expectedMap[ns] {
				msg := fmt.Sprintf(MsgAlertRDAPUnauthNS, target.Domain, ns)
				redacted := "Unauthorized nameserver detected."
				if !target.SuppressAlerts {
					app.Notifier.Dispatch(msg, redacted, PriorityUrgent, "skull", target.Domain, target.Name)
				}
			}
		}
	} else {
		for _, ns := range parsed.Nameservers {
			liveNS[ns] = true
		}
	}

	for _, expected := range target.ExpectedNS {
		if !liveNS[expected] {
			msg := fmt.Sprintf(MsgAlertRDAPMissingNS, target.Domain, expected)
			redacted := "Expected nameserver is missing."
			if !target.SuppressAlerts {
				app.Notifier.Dispatch(msg, redacted, PriorityHigh, "warning", target.Domain, target.Name)
			}
		}
	}

	state.UpdateRDAP(target.Domain, parsed)
}
