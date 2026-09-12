package main

import (
	"context"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/miekg/dns"
)

func LoadConfig(ctx context.Context, path string) (*AppState, *AppConfig, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	if path == "" {
		path = "config.json"
	}

	jsonBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var rawCfg AppConfig
	if err := jsonv2.Unmarshal(jsonBytes, &rawCfg); err != nil {
		return nil, nil, fmt.Errorf("json unmarshal failed: %w", err)
	}

	// Override with environment variables if provided
	if p := strings.TrimSpace(os.Getenv("PORT")); p != "" {
		rawCfg.Port = p
	}
	if rawCfg.Port == "" {
		rawCfg.Port = "8080"
	}
	if t := strings.TrimSpace(os.Getenv("NTFY_AUTH")); t != "" {
		if rawCfg.Notifications.Ntfy == nil {
			rawCfg.Notifications.Ntfy = &NtfyConfig{}
		}
		rawCfg.Notifications.Ntfy.Auth = t
	}
	if t := strings.TrimSpace(os.Getenv("TELEGRAM_TOKEN")); t != "" {
		if rawCfg.Notifications.Telegram == nil {
			rawCfg.Notifications.Telegram = &TelegramConfig{}
		}
		rawCfg.Notifications.Telegram.Token = t
	}
	if id := strings.TrimSpace(os.Getenv("TELEGRAM_CHAT_ID")); id != "" {
		if rawCfg.Notifications.Telegram == nil {
			rawCfg.Notifications.Telegram = &TelegramConfig{}
		}
		rawCfg.Notifications.Telegram.ChatID = id
	}
	if k := strings.TrimSpace(os.Getenv("CTLOGS_API_KEY")); k != "" {
		rawCfg.CTLogsAPIKey = k
	}
	if u := strings.TrimSpace(os.Getenv("DOH_URL")); u != "" {
		rawCfg.DoHURL = u
	}

	// Defaults that do not require side-effects
	if len(rawCfg.Resolvers) == 0 {
		rawCfg.Resolvers = []string{"1.1.1.1", "8.8.8.8", "9.9.9.9"}
	}
	if len(rawCfg.Resolvers) > 9 {
		return nil, nil, fmt.Errorf("configured resolvers exceed maximum limit of 9")
	}

	// 3. Schema Normalization
	seenDomains := make(map[string]bool, len(rawCfg.Domains))
	seenDomainNames := make(map[string]bool, len(rawCfg.Domains))
	for i := range rawCfg.Domains {
		domainCfg := &rawCfg.Domains[i]
		domainCfg.Domain = NormalizeDomainToASCIIText(domainCfg.Domain)
		if domainCfg.Domain == "" {
			return nil, nil, fmt.Errorf("domain entry at index %d has an empty domain", i)
		}
		if seenDomains[domainCfg.Domain] {
			return nil, nil, fmt.Errorf("duplicate domain %q; each domain entry must be unique", domainCfg.Domain)
		}
		seenDomains[domainCfg.Domain] = true
		for j := range domainCfg.ExpectedNS {
			nsClean := NormalizeDomainToASCIIText(domainCfg.ExpectedNS[j])
			if nsClean == "" {
				return nil, nil, fmt.Errorf("domain %s has an empty entry in expected_ns at index %d", domainCfg.Domain, j)
			}
			domainCfg.ExpectedNS[j] = nsClean
		}
		for j := range domainCfg.SecondaryNS {
			nsClean := NormalizeDomainToASCIIText(domainCfg.SecondaryNS[j])
			if nsClean == "" {
				return nil, nil, fmt.Errorf("domain %s has an empty entry in secondary_ns at index %d", domainCfg.Domain, j)
			}
			domainCfg.SecondaryNS[j] = nsClean
		}

		// Enforce Name is mandatory for domains and unique
		if domainCfg.Name == "" {
			return nil, nil, fmt.Errorf("domain %s is missing a mandatory 'name' field", domainCfg.Domain)
		}
		if seenDomainNames[domainCfg.Name] {
			return nil, nil, fmt.Errorf("duplicate domain name %q; each domain must have a unique name", domainCfg.Name)
		}
		seenDomainNames[domainCfg.Name] = true

		// Registrar validation fields: config accepts both expected_registrar_id and expected_registrar_name.
		// Order of priority: expected_registrar_id (Priority 1) takes precedence over expected_registrar_name (Priority 2).
		// In evaluation, they are mutually exclusive (if expected_registrar_id is specified, it is evaluated and name is superseded).
		domainCfg.ExpectedRegistrarID = strings.TrimSpace(domainCfg.ExpectedRegistrarID)
		domainCfg.ExpectedRegistrarName = strings.TrimSpace(domainCfg.ExpectedRegistrarName)

		if len(domainCfg.SecondaryNS) > 0 && len(domainCfg.ExpectedNS) == 0 {
			return nil, nil, fmt.Errorf("domain %s has secondary_ns configured but no primary expected_ns configured", domainCfg.Domain)
		}

		if domainCfg.VerifyNSHealth {
			if len(domainCfg.ExpectedNS) == 0 {
				return nil, nil, fmt.Errorf("domain %s has verify_ns_health enabled but no primary expected_ns configured", domainCfg.Domain)
			}
			// secondary_ns is optional: if configured, secondary NS replication is checked; if omitted, secondary checks are skipped.
		}

		if domainCfg.IsDelegatedZone {
			domainCfg.RootZone = NormalizeDomainToASCIIText(domainCfg.RootZone)
			if domainCfg.RootZone == "" {
				return nil, nil, fmt.Errorf("delegated domain %s is missing a mandatory 'root_zone' field", domainCfg.Domain)
			}
		}

		if domainCfg.CAA != nil {
			normalizeCAAList := func(list []string) []string {
				if list == nil {
					return nil
				}
				var res []string
				for _, item := range list {
					val := parseCAAIssuer(item)
					if val != "" && val != ";" {
						res = append(res, val)
					}
				}
				if len(res) == 0 {
					return []string{} // non-nil empty slice represents explicit deny-all (e.g. [] or [";"])
				}
				return res
			}

			if domainCfg.CAA.Issue != nil {
				domainCfg.CAA.Issue = normalizeCAAList(domainCfg.CAA.Issue)
			}
			if domainCfg.CAA.IssueWild != nil {
				domainCfg.CAA.IssueWild = normalizeCAAList(domainCfg.CAA.IssueWild)
			}
			if domainCfg.CAA.IssueMail != nil {
				domainCfg.CAA.IssueMail = normalizeCAAList(domainCfg.CAA.IssueMail)
			}
		}

		if domainCfg.CheckEmailSecurity {
			if domainCfg.MailProvider != "" && len(domainCfg.MXRecords) > 0 {
				return nil, nil, fmt.Errorf("domain %s has both mail_provider and mx_records set; these are mutually exclusive", domainCfg.Domain)
			}
			domainCfg.MailProvider = strings.ToLower(strings.TrimSpace(domainCfg.MailProvider))
			for j := range domainCfg.MXRecords {
				rawMX := strings.TrimSpace(domainCfg.MXRecords[j])
				var mxClean string
				if rawMX == "." {
					mxClean = "."
				} else {
					mxClean = NormalizeDomainToASCIIText(rawMX)
				}
				domainCfg.MXRecords[j] = mxClean
			}
			for j := range domainCfg.DKIMSelectors {
				domainCfg.DKIMSelectors[j] = strings.ToLower(strings.TrimSpace(domainCfg.DKIMSelectors[j]))
			}
		}
	}

	seenDNSNames := make(map[string]bool, len(rawCfg.DNSRecords))
	for i := range rawCfg.DNSRecords {
		dnsRecord := &rawCfg.DNSRecords[i]
		dnsRecord.Hostname = NormalizeDomainToASCIIText(dnsRecord.Hostname)

		if dnsRecord.Hostname == "" {
			return nil, nil, fmt.Errorf("dns record at index %d has an empty hostname", i)
		}

		dnsRecord.Name = strings.TrimSpace(dnsRecord.Name)
		if dnsRecord.Name == "" {
			return nil, nil, fmt.Errorf("dns record %s (%s) is missing a mandatory 'name' field", dnsRecord.Hostname, dnsRecord.Type)
		}
		if seenDNSNames[dnsRecord.Name] {
			return nil, nil, fmt.Errorf("duplicate dns record name %q; each dns record must have a unique name", dnsRecord.Name)
		}
		seenDNSNames[dnsRecord.Name] = true

		dnsRecord.Type = strings.ToUpper(strings.TrimSpace(dnsRecord.Type))
		if dnsRecord.Type == "" {
			return nil, nil, fmt.Errorf("dns record %s is missing a type (e.g. A, CNAME)", dnsRecord.Hostname)
		}
		if dnsRecord.SkipSSL {
			if dnsRecord.Type != "A" && dnsRecord.Type != "AAAA" && dnsRecord.Type != "CNAME" && dnsRecord.Type != "ALIAS" && dnsRecord.Type != "IP" {
				return nil, nil, fmt.Errorf("dns record %s (%s) has skip_ssl enabled; skip_ssl is only applicable for A, AAAA, CNAME, ALIAS, and IP record types", dnsRecord.Hostname, dnsRecord.Type)
			}
		}

		var normalizedExpected []string
		for _, rawVal := range dnsRecord.Expected {
			cleanVal := strings.TrimSuffix(strings.TrimSpace(rawVal), ".")
			if cleanVal == "" {
				continue
			}
			if strings.HasPrefix(strings.ToLower(cleanVal), "alias:") {
				cleanVal = strings.TrimSpace(cleanVal[6:])
			}
			if dnsRecord.Type != "TXT" {
				cleanVal = strings.ToLower(cleanVal)
			}

			// Validate and normalize according to record type
			parsedIP := net.ParseIP(cleanVal)
			switch dnsRecord.Type {
			case "A":
				if parsedIP != nil {
					if parsedIP.To4() == nil {
						return nil, nil, fmt.Errorf("dns record %q (%s): expected %q is an IPv6 address, but record type is A (requires IPv4)", dnsRecord.Name, dnsRecord.Hostname, rawVal)
					}
					cleanVal = parsedIP.String()
				} else {
					return nil, nil, fmt.Errorf("dns record %q (%s): expected %q is not a valid IPv4 address for type A", dnsRecord.Name, dnsRecord.Hostname, rawVal)
				}
			case "AAAA":
				if parsedIP != nil {
					if parsedIP.To4() != nil {
						return nil, nil, fmt.Errorf("dns record %q (%s): expected %q is an IPv4 address, but record type is AAAA (requires IPv6)", dnsRecord.Name, dnsRecord.Hostname, rawVal)
					}
					cleanVal = parsedIP.String()
				} else {
					return nil, nil, fmt.Errorf("dns record %q (%s): expected %q is not a valid IPv6 address for type AAAA", dnsRecord.Name, dnsRecord.Hostname, rawVal)
				}
			case "IP":
				if parsedIP != nil {
					cleanVal = parsedIP.String()
				} else {
					return nil, nil, fmt.Errorf("dns record %q (%s): expected %q is not a valid IPv4 or IPv6 address for composite type IP", dnsRecord.Name, dnsRecord.Hostname, rawVal)
				}
			case "ALIAS", "CNAME":
				if parsedIP != nil {
					cleanVal = parsedIP.String()
				} else {
					cleanVal = NormalizeDomainToASCIIText(cleanVal)
				}
			default:
				if dnsRecord.Type != "TXT" {
					cleanVal = NormalizeDomainToASCIIText(cleanVal)
				}
			}

			if !slices.Contains(normalizedExpected, cleanVal) {
				normalizedExpected = append(normalizedExpected, cleanVal)
			}
		}

		// Sort IP arrays for deterministic canonical order
		if dnsRecord.Type == "A" || dnsRecord.Type == "AAAA" || dnsRecord.Type == "IP" {
			slices.Sort(normalizedExpected)
		}

		dnsRecord.Expected = normalizedExpected
	}

	if rawCfg.DoHURL == "" {
		rawCfg.DoHURL = DefaultDoHURL
	}

	app := &AppState{
		Notifier: &NotificationManager{},
	}

	if rawCfg.LoopIntervalDays == 0 {
		rawCfg.LoopIntervalDays = 0.25
	} else if rawCfg.LoopIntervalDays < 0.125 {
		LogInfo("loop_interval_days is below minimum (0.125 days / 3 hours); defaulting to 0.125", "configured", rawCfg.LoopIntervalDays)
		rawCfg.LoopIntervalDays = 0.125
	} else if rawCfg.LoopIntervalDays > 365 {
		LogInfo("loop_interval_days exceeds maximum (365 days); defaulting to 365", "configured", rawCfg.LoopIntervalDays)
		rawCfg.LoopIntervalDays = 365
	}
	app.LoopDuration = time.Duration(rawCfg.LoopIntervalDays * 24 * float64(time.Hour))

	return app, &rawCfg, nil
}

// InitializeDependencies handles side-effects like validating notifications and resolver health checks
func InitializeDependencies(ctx context.Context, app *AppState, rawCfg *AppConfig) error {
	if app == nil {
		return errors.New("cannot initialize dependencies: app is nil")
	}
	if rawCfg == nil {
		return errors.New("cannot initialize dependencies: config is nil")
	}
	if app.Notifier == nil {
		return errors.New("cannot initialize dependencies: notifier is nil")
	}
	nm := app.Notifier

	if rawCfg.Notifications.Ntfy == nil || strings.TrimSpace(rawCfg.Notifications.Ntfy.URL) == "" {
		return errors.New("cannot initialize dependencies: notifications.ntfy.url is mandatory (primary notification mechanism)")
	}

	var auth string
	auth = rawCfg.Notifications.Ntfy.Auth
	if auth != "" && !strings.HasPrefix(strings.ToLower(auth), "bearer ") && !strings.HasPrefix(strings.ToLower(auth), "basic ") {
		auth = "Bearer " + auth
	}

	client := ResolveHTTPClient(&http.Client{Timeout: 5 * time.Second})
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, rawCfg.Notifications.Ntfy.URL, nil)
	if err != nil {
		return fmt.Errorf("failed to create ntfy request: %w", err)
	}
	req.Header.Set("User-Agent", DefaultUserAgent)
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("ntfy URL provided is unreachable: %w", err)
	}
	DrainAndClose(resp.Body, 4096)

	nm.Providers = append(nm.Providers, &NtfyProvider{
		URL:  rawCfg.Notifications.Ntfy.URL,
		Auth: auth,
	})

	if rawCfg.Notifications.Telegram != nil && rawCfg.Notifications.Telegram.Token != "" && rawCfg.Notifications.Telegram.ChatID != "" {
		nm.Providers = append(nm.Providers, &TelegramProvider{
			Token:  rawCfg.Notifications.Telegram.Token,
			ChatID: rawCfg.Notifications.Telegram.ChatID,
		})
		LogInfo(MsgLogTelegramConfig)
	}

	var healthyResolvers []string
	var lastResolverErr error
	for _, resolver := range rawCfg.Resolvers {
		ip := DefaultPort(resolver, "53")
		dnsClient := new(dns.Client)
		dnsClient.Timeout = 5 * time.Second
		dnsMsg := new(dns.Msg)
		dnsMsg.SetQuestion(dns.Fqdn("example.com"), dns.TypeA)
		dnsMsg.RecursionDesired = true
		if _, _, err := dnsClient.ExchangeContext(ctx, dnsMsg, ip); err != nil {
			LogWarn("Configured resolver unreachable during health check", "resolver", resolver, "error", err)
			lastResolverErr = err
		} else {
			healthyResolvers = append(healthyResolvers, resolver)
		}
	}

	if len(healthyResolvers) == 0 {
		return fmt.Errorf("all configured resolvers failed health checks: %w", lastResolverErr)
	}

	rawCfg.Resolvers = healthyResolvers
	if auth != "" && rawCfg.Notifications.Ntfy != nil {
		rawCfg.Notifications.Ntfy.Auth = auth
	}
	app.Config = rawCfg

	return nil
}
