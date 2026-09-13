package main

import (
	"context"
	jsonv2 "encoding/json/v2"
	"errors"
	"net"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// LoadConfig reads, unmarshals, normalizes, and validates the configuration file.
// It is a pure function returning a value-based AppConfig and error, with zero runtime side effects.
func LoadConfig(ctx context.Context, path string) (AppConfig, error) {
	if err := ctx.Err(); err != nil {
		return AppConfig{}, err
	}
	if path == "" {
		path = DefaultConfigFile
	}

	jsonBytes, err := os.ReadFile(path)
	if err != nil {
		return AppConfig{}, WrapError("failed to read config file", err)
	}

	var rawCfg AppConfig
	if err := jsonv2.Unmarshal(jsonBytes, &rawCfg); err != nil {
		return AppConfig{}, WrapError("json unmarshal failed", err)
	}

	// Override with environment variables if provided
	if p := strings.TrimSpace(os.Getenv(EnvPort)); p != "" {
		rawCfg.Port = p
	}
	if rawCfg.Port == "" {
		rawCfg.Port = DefaultServerPort
	}
	if t := strings.TrimSpace(os.Getenv(EnvNtfyAuth)); t != "" {
		if rawCfg.Notifications.Ntfy == nil {
			rawCfg.Notifications.Ntfy = &NtfyConfig{}
		}
		rawCfg.Notifications.Ntfy.Auth = t
	}
	if t := strings.TrimSpace(os.Getenv(EnvTelegramToken)); t != "" {
		if rawCfg.Notifications.Telegram == nil {
			rawCfg.Notifications.Telegram = &TelegramConfig{}
		}
		rawCfg.Notifications.Telegram.Token = t
	}
	if id := strings.TrimSpace(os.Getenv(EnvTelegramChatID)); id != "" {
		if rawCfg.Notifications.Telegram == nil {
			rawCfg.Notifications.Telegram = &TelegramConfig{}
		}
		rawCfg.Notifications.Telegram.ChatID = id
	}
	if k := strings.TrimSpace(os.Getenv(EnvCTLogsAPIKey)); k != "" {
		rawCfg.CTLogsAPIKey = k
	}
	if u := strings.TrimSpace(os.Getenv(EnvDoHURL)); u != "" {
		rawCfg.DoHURL = u
	}

	// Defaults that do not require side-effects
	if len(rawCfg.Resolvers) == 0 {
		rawCfg.Resolvers = []string{"1.1.1.1", "8.8.8.8", "9.9.9.9"}
	}
	if len(rawCfg.Resolvers) > MaxResolversLimit {
		return AppConfig{}, errors.New("configured resolvers exceed maximum limit of 9")
	}

	// 3. Schema Normalization
	seenDomains := make(map[string]bool, len(rawCfg.Domains))
	seenDomainNames := make(map[string]bool, len(rawCfg.Domains))
	for i := range rawCfg.Domains {
		domainCfg := &rawCfg.Domains[i]
		domainCfg.Domain = NormalizeDomainToASCIIText(domainCfg.Domain)
		if domainCfg.Domain == "" {
			return AppConfig{}, errors.New("domain entry at index " + strconv.Itoa(i) + " has an empty domain")
		}
		if seenDomains[domainCfg.Domain] {
			return AppConfig{}, errors.New("duplicate domain " + strconv.Quote(domainCfg.Domain) + "; each domain entry must be unique")
		}
		seenDomains[domainCfg.Domain] = true
		for j := range domainCfg.ExpectedNS {
			nsClean := NormalizeDomainToASCIIText(domainCfg.ExpectedNS[j])
			if nsClean == "" {
				return AppConfig{}, errors.New("domain " + domainCfg.Domain + " has an empty entry in expected_ns at index " + strconv.Itoa(j))
			}
			domainCfg.ExpectedNS[j] = nsClean
		}
		for j := range domainCfg.SecondaryNS {
			nsClean := NormalizeDomainToASCIIText(domainCfg.SecondaryNS[j])
			if nsClean == "" {
				return AppConfig{}, errors.New("domain " + domainCfg.Domain + " has an empty entry in secondary_ns at index " + strconv.Itoa(j))
			}
			domainCfg.SecondaryNS[j] = nsClean
		}

		// Enforce Name is mandatory for domains and unique
		if domainCfg.Name == "" {
			return AppConfig{}, errors.New("domain " + domainCfg.Domain + " is missing a mandatory 'name' field")
		}
		if seenDomainNames[domainCfg.Name] {
			return AppConfig{}, errors.New("duplicate domain name " + strconv.Quote(domainCfg.Name) + "; each domain must have a unique name")
		}
		seenDomainNames[domainCfg.Name] = true

		// Registrar validation fields: config accepts both expected_registrar_id and expected_registrar_name.
		// Order of priority: expected_registrar_id (Priority 1) takes precedence over expected_registrar_name (Priority 2).
		// In evaluation, they are mutually exclusive (if expected_registrar_id is specified, it is evaluated and name is superseded).
		domainCfg.ExpectedRegistrarID = strings.TrimSpace(domainCfg.ExpectedRegistrarID)
		domainCfg.ExpectedRegistrarName = strings.TrimSpace(domainCfg.ExpectedRegistrarName)

		if len(domainCfg.SecondaryNS) > 0 && len(domainCfg.ExpectedNS) == 0 {
			return AppConfig{}, errors.New("domain " + domainCfg.Domain + " has secondary_ns configured but no primary expected_ns configured")
		}

		if domainCfg.VerifyNSHealth {
			if len(domainCfg.ExpectedNS) == 0 {
				return AppConfig{}, errors.New("domain " + domainCfg.Domain + " has verify_ns_health enabled but no primary expected_ns configured")
			}
			// secondary_ns is optional: if configured, secondary NS replication is checked; if omitted, secondary checks are skipped.
		}

		if domainCfg.IsDelegatedZone {
			domainCfg.RootZone = NormalizeDomainToASCIIText(domainCfg.RootZone)
			if domainCfg.RootZone == "" {
				return AppConfig{}, errors.New("delegated domain " + domainCfg.Domain + " is missing a mandatory 'root_zone' field")
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
				return AppConfig{}, errors.New("domain " + domainCfg.Domain + " has both mail_provider and mx_records set; these are mutually exclusive")
			}
			domainCfg.MailProvider = strings.ToLower(strings.TrimSpace(domainCfg.MailProvider))
			for j := range domainCfg.MXRecords {
				rawMX := strings.TrimSpace(domainCfg.MXRecords[j])
				var mxClean string
				if rawMX == NullMXRecord {
					mxClean = NullMXRecord
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
			return AppConfig{}, errors.New("dns record at index " + strconv.Itoa(i) + " has an empty hostname")
		}

		dnsRecord.Name = strings.TrimSpace(dnsRecord.Name)
		if dnsRecord.Name == "" {
			return AppConfig{}, errors.New("dns record " + dnsRecord.Hostname + " (" + dnsRecord.Type + ") is missing a mandatory 'name' field")
		}
		if seenDNSNames[dnsRecord.Name] {
			return AppConfig{}, errors.New("duplicate dns record name " + strconv.Quote(dnsRecord.Name) + "; each dns record must have a unique name")
		}
		seenDNSNames[dnsRecord.Name] = true

		dnsRecord.Type = strings.ToUpper(strings.TrimSpace(dnsRecord.Type))
		if dnsRecord.Type == "" {
			return AppConfig{}, errors.New("dns record " + dnsRecord.Hostname + " is missing a type (e.g. A, CNAME)")
		}
		if dnsRecord.SkipSSL {
			if dnsRecord.Type != "A" && dnsRecord.Type != "AAAA" && dnsRecord.Type != "CNAME" && dnsRecord.Type != "ALIAS" && dnsRecord.Type != "IP" {
				return AppConfig{}, errors.New("dns record " + dnsRecord.Hostname + " (" + dnsRecord.Type + ") has skip_ssl enabled; skip_ssl is only applicable for A, AAAA, CNAME, ALIAS, and IP record types")
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
						return AppConfig{}, errors.New("dns record " + strconv.Quote(dnsRecord.Name) + " (" + dnsRecord.Hostname + "): expected " + strconv.Quote(rawVal) + " is an IPv6 address, but record type is A (requires IPv4)")
					}
					cleanVal = parsedIP.String()
				} else {
					return AppConfig{}, errors.New("dns record " + strconv.Quote(dnsRecord.Name) + " (" + dnsRecord.Hostname + "): expected " + strconv.Quote(rawVal) + " is not a valid IPv4 address for type A")
				}
			case "AAAA":
				if parsedIP != nil {
					if parsedIP.To4() != nil {
						return AppConfig{}, errors.New("dns record " + strconv.Quote(dnsRecord.Name) + " (" + dnsRecord.Hostname + "): expected " + strconv.Quote(rawVal) + " is an IPv4 address, but record type is AAAA (requires IPv6)")
					}
					cleanVal = parsedIP.String()
				} else {
					return AppConfig{}, errors.New("dns record " + strconv.Quote(dnsRecord.Name) + " (" + dnsRecord.Hostname + "): expected " + strconv.Quote(rawVal) + " is not a valid IPv6 address for type AAAA")
				}
			case "IP":
				if parsedIP != nil {
					cleanVal = parsedIP.String()
				} else {
					return AppConfig{}, errors.New("dns record " + strconv.Quote(dnsRecord.Name) + " (" + dnsRecord.Hostname + "): expected " + strconv.Quote(rawVal) + " is not a valid IPv4 or IPv6 address for composite type IP")
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
		if dnsRecord.Type == RecordTypeA || dnsRecord.Type == RecordTypeAAAA || dnsRecord.Type == RecordTypeIP {
			slices.Sort(normalizedExpected)
		}

		dnsRecord.Expected = normalizedExpected
	}

	if rawCfg.DoHURL == "" {
		rawCfg.DoHURL = DefaultDoHURL
	}

	if rawCfg.LoopIntervalDays == 0 {
		rawCfg.LoopIntervalDays = DefaultLoopIntervalDays
	} else if rawCfg.LoopIntervalDays < MinLoopIntervalDays {
		LogInfo(MsgLogLoopIntervalBelowMin, "configured", rawCfg.LoopIntervalDays)
		rawCfg.LoopIntervalDays = MinLoopIntervalDays
	} else if rawCfg.LoopIntervalDays > MaxLoopIntervalDays {
		LogInfo(MsgLogLoopIntervalAboveMax, "configured", rawCfg.LoopIntervalDays)
		rawCfg.LoopIntervalDays = MaxLoopIntervalDays
	}

	return rawCfg, nil
}

// InitializeApp handles side-effects like validating notifications and resolver health checks,
// constructing and returning a fully wired AppState. It does not mutate the provided AppConfig.
func InitializeApp(ctx context.Context, cfg AppConfig) (*AppState, error) {
	app := &AppState{
		config:       cfg,
		Notifier:     &NotificationManager{},
		LoopDuration: time.Duration(cfg.LoopIntervalDays * HoursPerDay * float64(time.Hour)),
	}

	if cfg.Notifications.Ntfy == nil || strings.TrimSpace(cfg.Notifications.Ntfy.URL) == "" {
		return nil, errors.New("cannot initialize dependencies: notifications.ntfy.url is mandatory (primary notification mechanism)")
	}

	var auth string
	auth = cfg.Notifications.Ntfy.Auth
	if auth != "" && !strings.HasPrefix(strings.ToLower(auth), "bearer ") && !strings.HasPrefix(strings.ToLower(auth), "basic ") {
		auth = "Bearer " + auth
	}

	client := ResolveHTTPClient(&http.Client{Timeout: DefaultDNSTimeout})
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, cfg.Notifications.Ntfy.URL, nil)
	if err != nil {
		return nil, WrapError("failed to create ntfy request", err)
	}
	req.Header.Set("User-Agent", DefaultUserAgent)
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, WrapError("ntfy URL provided is unreachable", err)
	}
	DrainAndClose(resp.Body, MaxBodyDrainSize)

	app.Notifier.Providers = append(app.Notifier.Providers, &NtfyProvider{
		URL:  cfg.Notifications.Ntfy.URL,
		Auth: auth,
	})

	if cfg.Notifications.Telegram != nil && cfg.Notifications.Telegram.Token != "" && cfg.Notifications.Telegram.ChatID != "" {
		app.Notifier.Providers = append(app.Notifier.Providers, &TelegramProvider{
			Token:  cfg.Notifications.Telegram.Token,
			ChatID: cfg.Notifications.Telegram.ChatID,
		})
		LogInfo(MsgLogTelegramConfig)
	}

	var healthyResolvers []string
	var lastResolverErr error
	for _, resolver := range cfg.Resolvers {
		ip := DefaultPort(resolver, DefaultDNSPort)
		dnsClient := new(dns.Client)
		dnsClient.Timeout = DefaultDNSTimeout
		dnsMsg := new(dns.Msg)
		dnsMsg.SetQuestion(dns.Fqdn("example.com"), dns.TypeA)
		dnsMsg.RecursionDesired = true
		if _, _, err := dnsClient.ExchangeContext(ctx, dnsMsg, ip); err != nil {
			LogWarn(MsgLogResolverUnreachable, "resolver", resolver, "error", err)
			lastResolverErr = err
		} else {
			healthyResolvers = append(healthyResolvers, resolver)
		}
	}

	if len(healthyResolvers) == 0 {
		return nil, WrapError("all configured resolvers failed health checks", lastResolverErr)
	}

	app.activeResolvers = healthyResolvers

	return app, nil
}

// InitializeDependencies is a backward-compatible adapter for InitializeApp,
// intended strictly for process initialization before background workers start.
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
	initialized, err := InitializeApp(ctx, *rawCfg)
	if err != nil {
		return err
	}
	app.config = initialized.config
	app.activeResolvers = initialized.activeResolvers
	app.Notifier.Providers = initialized.Notifier.Providers
	app.LoopDuration = initialized.LoopDuration
	return nil
}
