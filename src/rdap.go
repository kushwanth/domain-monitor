package main

import (
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/openrdap/rdap"
)

func evaluateRDAP(client *rdap.Client, app *AppState, target DomainConfig) {
	domainInfo, err := client.QueryDomain(target.Domain)
	if err != nil {
		log.Printf(MsgLogRDAPFail, target.Domain, err)
		UpdateRDAPState(target.Domain, map[string]interface{}{
			"status": "failed",
			"error":  err.Error(),
		})
		return
	}

	var expirationDate string
	var lastChangedDate string
	var registrar string

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
						registrar = str
					}
					break
				}
			}
		}
	}

	for _, event := range domainInfo.Events {
		action := strings.ToLower(event.Action)
		if strings.Contains(action, "expiration") {
			expirationDate = event.Date
			if t, err := time.Parse(time.RFC3339, event.Date); err == nil {
				days := time.Until(t).Hours() / 24
				if days <= 30 {
					msg := fmt.Sprintf(MsgAlertRDAPExpiry, target.Domain, days)
					redacted := fmt.Sprintf("Domain is expiring in %.0f days.", days)
					if !target.SuppressAlerts {
						app.Notifier.Dispatch(msg, redacted, "warning", "warning", target.Domain, target.Name)
					}
				}
			}
		} else if strings.Contains(action, "last changed") {
			lastChangedDate = event.Date
			app.StateMu.Lock()
			if prev, exists := app.StateLastChanged[target.Domain]; exists && prev != event.Date {
				msg := fmt.Sprintf(MsgAlertRDAPModified, target.Domain, event.Date)
				redacted := "Domain registration was modified."
				if !target.SuppressAlerts {
					app.Notifier.Dispatch(msg, redacted, "urgent", "rotating_light", target.Domain, target.Name)
				}
			}
			app.StateLastChanged[target.Domain] = event.Date
			app.StateMu.Unlock()
		}
	}

	liveNS := make(map[string]bool)
	expectedMap := make(map[string]bool)
	for _, expected := range target.ExpectedNS {
		expectedMap[expected] = true
	}

	var nameservers []string

	for _, ns := range domainInfo.Nameservers {
		live := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(ns.LDHName), "."))
		liveNS[live] = true
		nameservers = append(nameservers, live)

		if !expectedMap[live] {
			msg := fmt.Sprintf(MsgAlertRDAPUnauthNS, target.Domain, live)
			redacted := "Unauthorized nameserver detected."
			if !target.SuppressAlerts {
				app.Notifier.Dispatch(msg, redacted, "urgent", "skull", target.Domain, target.Name)
			}
		}
	}

	for _, expected := range target.ExpectedNS {
		if !liveNS[expected] {
			msg := fmt.Sprintf(MsgAlertRDAPMissingNS, target.Domain, expected)
			redacted := "Expected nameserver is missing."
			if !target.SuppressAlerts {
				app.Notifier.Dispatch(msg, redacted, "high", "warning", target.Domain, target.Name)
			}
		}
	}

	isLocked := false
	var rawStatuses []string

	for _, s := range domainInfo.Status {
		rawStatuses = append(rawStatuses, s)
		status := strings.ReplaceAll(strings.ToLower(s), " ", "")

		if status == "serverhold" || status == "clienthold" || status == "pendingdelete" {
			msg := fmt.Sprintf(MsgAlertRDAPSuspended, target.Domain, status)
			redacted := fmt.Sprintf("Domain suspended (Status: %s).", status)
			if !target.SuppressAlerts {
				app.Notifier.Dispatch(msg, redacted, "urgent", "x", target.Domain, target.Name)
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
			app.Notifier.Dispatch(msg, redacted, "high", "unlock", target.Domain, target.Name)
		}
	}

	dnssec := false
	if domainInfo.SecureDNS != nil && domainInfo.SecureDNS.DelegationSigned != nil && *domainInfo.SecureDNS.DelegationSigned {
		dnssec = true
	}

	UpdateRDAPState(target.Domain, map[string]interface{}{
		"status":        "ok",
		"expiration":    expirationDate,
		"last_changed":  lastChangedDate,
		"nameservers":   nameservers,
		"domain_status": rawStatuses,
		"dnssec":        dnssec,
		"registrar":     registrar,
	})
}
