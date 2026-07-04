package main

import (
	"fmt"
	"log"
	"strings"

	"github.com/miekg/dns"
)

var providerMXMap = map[string][]string{
	"google":     {"aspmx.l.google.com"},
	"microsoft":  {"mail.protection.outlook.com"},
	"fastmail":   {"messagingengine.com"},
	"protonmail": {"protonmail.ch"},
	"icloud":     {"icloud.com"},
	"zoho":       {"zoho.com", "zoho.in", "zoho.eu"},
	"aws":        {"amazonaws.com"},
	"mailgun":    {"mailgun.org"},
	"sendgrid":   {"sendgrid.net"},
	"postmark":   {"postmarkapp.com"},
	"yandex":     {"yandex.ru", "yandex.net"},
}

var providerDKIMMap = map[string][]string{
	"google":     {"google"},
	"microsoft":  {"selector1"},
	"fastmail":   {"fm1", "fm2", "fm3", "mesmtp"},
	"protonmail": {"protonmail", "protonmail2", "protonmail3"},
	"icloud":     {"sig1"},
	"zoho":       {"zoho", "zmail"},
}

func evaluateEmailSecurity(app *AppState, target DomainConfig) {
	if !target.CheckEmailSecurity {
		return
	}

	mxs, err := queryDNS(target.Domain, dns.TypeMX, app.Config.Resolvers)
	if err != nil || len(mxs) == 0 {
		msg := fmt.Sprintf(MsgAlertEmailNoMX, target.Domain)
		redacted := "No MX records found. Email delivery is broken."
		if !target.SuppressAlerts {
			app.Notifier.Dispatch(msg, redacted, "urgent", "envelope", target.Domain, target.Name)
		}
		UpdateEmailState(target.Domain, map[string]interface{}{"status": "failed", "error": "No MX records found"})
		return
	}

	var liveMXs []string
	for _, mx := range mxs {
		liveMXs = append(liveMXs, mx) // mx is already trimmed and lowercased by queryDNS
	}

	if len(target.MXRecords) > 0 {
		allMatch := true
		liveMap := make(map[string]bool)
		for _, m := range liveMXs {
			liveMap[m] = true
		}
		for _, expected := range target.MXRecords {
			if !liveMap[expected] {
				allMatch = false
				msg := fmt.Sprintf(MsgAlertEmailMXMissing, expected, target.Domain, strings.Join(liveMXs, ", "))
				redacted := "Expected MX record is missing."
				if !target.SuppressAlerts {
					app.Notifier.Dispatch(msg, redacted, "urgent", "envelope", target.Domain, target.Name)
				}
			}
		}
		if allMatch {
			UpdateEmailState(target.Domain, map[string]interface{}{"status": "ok", "type": "custom_mx", "found": liveMXs})
		} else {
			UpdateEmailState(target.Domain, map[string]interface{}{"status": "mismatch", "type": "custom_mx", "found": liveMXs})
		}
		return
	}

	if target.MailProvider != "" {
		expectedSuffixes, ok := providerMXMap[target.MailProvider]
		if !ok {
			log.Printf(MsgLogEmailUnknownProv, target.MailProvider, target.Domain)
		} else {
			// Ensure at least one live MX ends with one of the expected suffixes
			hijackSafe := false
			for _, live := range liveMXs {
				for _, suffix := range expectedSuffixes {
					if strings.HasSuffix(live, suffix) {
						hijackSafe = true
						break
					}
				}
				if hijackSafe {
					break
				}
			}
			if !hijackSafe {
				msg := fmt.Sprintf(MsgAlertEmailMXHijack, target.Domain, target.MailProvider, strings.Join(liveMXs, ", "))
				redacted := "MX records do not match the expected provider (Possible Hijack)."
				if !target.SuppressAlerts {
					app.Notifier.Dispatch(msg, redacted, "urgent", "rotating_light", target.Domain, target.Name)
				}
				UpdateEmailState(target.Domain, map[string]interface{}{"status": "hijacked", "found": liveMXs})
				return
			}
		}

		txts, _ := queryDNS(target.Domain, dns.TypeTXT, app.Config.Resolvers)
		var foundSPF string
		spfCount := 0

		for _, txt := range txts {
			txt = strings.TrimSpace(txt)
			if strings.HasPrefix(strings.ToLower(txt), "v=spf1") {
				spfCount++
				foundSPF = txt
			}
		}

		if spfCount == 0 {
			msg := fmt.Sprintf(MsgAlertEmailNoSPF, target.Domain)
			redacted := "No valid SPF record found."
			if !target.SuppressAlerts {
				app.Notifier.Dispatch(msg, redacted, "high", "warning", target.Domain, target.Name)
			}
		} else if spfCount > 1 {
			msg := fmt.Sprintf(MsgAlertEmailMultiSPF, target.Domain)
			redacted := "Multiple SPF records found (Invalid Configuration)."
			if !target.SuppressAlerts {
				app.Notifier.Dispatch(msg, redacted, "urgent", "x", target.Domain, target.Name)
			}
		}

		dmarcHost := "_dmarc." + target.Domain
		dmarcTxts, _ := queryDNS(dmarcHost, dns.TypeTXT, app.Config.Resolvers)
		var foundDMARC string
		dmarcFound := false

		for _, txt := range dmarcTxts {
			txt = strings.TrimSpace(txt)
			if strings.HasPrefix(strings.ToLower(txt), "v=dmarc1") {
				dmarcFound = true
				foundDMARC = txt
				break
			}
		}
		if !dmarcFound {
			msg := fmt.Sprintf(MsgAlertEmailNoDMARC, target.Domain, target.Domain)
			redacted := "No valid DMARC record found."
			if !target.SuppressAlerts {
				app.Notifier.Dispatch(msg, redacted, "high", "warning", target.Domain, target.Name)
			}
		}

		var selectorsToCheck []string
		if target.MailProvider != "" {
			if defaults, ok := providerDKIMMap[target.MailProvider]; ok {
				selectorsToCheck = append(selectorsToCheck, defaults...)
			}
		}
		selectorsToCheck = append(selectorsToCheck, target.DKIMSelectors...)

		validDkims := []string{}
		missingDkims := []string{}

		for _, selector := range selectorsToCheck {
			dkimHost := selector + "._domainkey." + target.Domain
			dkimTxts, _ := queryDNS(dkimHost, dns.TypeTXT, app.Config.Resolvers)

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
					app.Notifier.Dispatch(msg, redacted, "high", "warning", target.Domain, target.Name)
				}
			}
		}

		UpdateEmailState(target.Domain, map[string]interface{}{
			"status":     "ok",
			"type":       "provider",
			"provider":   target.MailProvider,
			"spf":        foundSPF,
			"dmarc":      foundDMARC,
			"dkim_valid": validDkims,
			"mx":         liveMXs,
		})
	} else {
		UpdateEmailState(target.Domain, map[string]interface{}{"status": "ok", "type": "basic", "mx": liveMXs})
	}
}
