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
		return AppConfig{}, WrapError(MsgErrFailedToReadConfig, err)
	}

	var rawCfg AppConfig
	if err := jsonv2.Unmarshal(jsonBytes, &rawCfg); err != nil {
		return AppConfig{}, WrapError(MsgErrJSONUnmarshalFailed, err)
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
		rawCfg.Resolvers = DefaultResolvers()
	}
	if len(rawCfg.Resolvers) > MaxResolversLimit {
		return AppConfig{}, errors.New(MsgErrResolversExceedLimit)
	}

	// 3. Schema Normalization
	seenDomains := make(map[string]bool, len(rawCfg.Domains))
	seenDomainNames := make(map[string]bool, len(rawCfg.Domains))
	for i := range rawCfg.Domains {
		domainCfg := &rawCfg.Domains[i]
		domainCfg.Domain = NormalizeDomainToASCIIText(domainCfg.Domain)
		if domainCfg.Domain == "" {
			return AppConfig{}, fmt.Errorf(MsgErrDomainEmptyDomain, i)
		}
		if seenDomains[domainCfg.Domain] {
			return AppConfig{}, fmt.Errorf(MsgErrDuplicateDomain, strconv.Quote(domainCfg.Domain))
		}
		seenDomains[domainCfg.Domain] = true
		for j := range domainCfg.ExpectedNS {
			nsClean := NormalizeDomainToASCIIText(domainCfg.ExpectedNS[j])
			if nsClean == "" {
				return AppConfig{}, fmt.Errorf(MsgErrDomainEmptyExpectedNS, domainCfg.Domain, j)
			}
			domainCfg.ExpectedNS[j] = nsClean
		}
		for j := range domainCfg.SecondaryNS {
			nsClean := NormalizeDomainToASCIIText(domainCfg.SecondaryNS[j])
			if nsClean == "" {
				return AppConfig{}, fmt.Errorf(MsgErrDomainEmptySecondaryNS, domainCfg.Domain, j)
			}
			domainCfg.SecondaryNS[j] = nsClean
		}

		// Enforce Name is mandatory for domains and unique
		if domainCfg.Name == "" {
			return AppConfig{}, fmt.Errorf(MsgErrDomainMissingName, domainCfg.Domain)
		}
		if seenDomainNames[domainCfg.Name] {
			return AppConfig{}, fmt.Errorf(MsgErrDuplicateDomainName, strconv.Quote(domainCfg.Name))
		}
		seenDomainNames[domainCfg.Name] = true

		// Registrar validation fields: config accepts both expected_registrar_id and expected_registrar_name.
		// Order of priority: expected_registrar_id (Priority 1) takes precedence over expected_registrar_name (Priority 2).
		// In evaluation, they are mutually exclusive (if expected_registrar_id is specified, it is evaluated and name is superseded).
		domainCfg.ExpectedRegistrarID = strings.TrimSpace(domainCfg.ExpectedRegistrarID)
		domainCfg.ExpectedRegistrarName = strings.TrimSpace(domainCfg.ExpectedRegistrarName)

		if domainCfg.RenewalPrice < 0 {
			return AppConfig{}, fmt.Errorf(MsgErrDomainNegativeRenewalPrice, domainCfg.Domain)
		}

		if len(domainCfg.SecondaryNS) > 0 && len(domainCfg.ExpectedNS) == 0 {
			return AppConfig{}, fmt.Errorf(MsgErrSecondaryNSWithoutPrimary, domainCfg.Domain)
		}

		if domainCfg.VerifyNSHealth {
			if len(domainCfg.ExpectedNS) == 0 {
				return AppConfig{}, fmt.Errorf(MsgErrVerifyNSHealthWithoutPrimary, domainCfg.Domain)
			}
			// secondary_ns is optional: if configured, secondary NS replication is checked; if omitted, secondary checks are skipped.
		}

		if domainCfg.IsDelegatedZone {
			domainCfg.RootZone = NormalizeDomainToASCIIText(domainCfg.RootZone)
			if domainCfg.RootZone == "" {
				return AppConfig{}, fmt.Errorf(MsgErrDelegatedMissingRootZone, domainCfg.Domain)
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
					if val != "" && val != CAAIssuerDenyAll {
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
				return AppConfig{}, fmt.Errorf(MsgErrMailProviderAndMXMutuallyExclusive, domainCfg.Domain)
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
			return AppConfig{}, fmt.Errorf(MsgErrDNSEmptyHostname, i)
		}

		dnsRecord.Name = strings.TrimSpace(dnsRecord.Name)
		if dnsRecord.Name == "" {
			return AppConfig{}, fmt.Errorf(MsgErrDNSMissingName, dnsRecord.Hostname, dnsRecord.Type)
		}
		if seenDNSNames[dnsRecord.Name] {
			return AppConfig{}, fmt.Errorf(MsgErrDuplicateDNSName, strconv.Quote(dnsRecord.Name))
		}
		seenDNSNames[dnsRecord.Name] = true

		dnsRecord.Type = strings.ToUpper(strings.TrimSpace(dnsRecord.Type))
		if dnsRecord.Type == "" {
			return AppConfig{}, fmt.Errorf(MsgErrDNSMissingType, dnsRecord.Hostname)
		}
		if dnsRecord.SkipSSL {
			if dnsRecord.Type != RecordTypeA && dnsRecord.Type != RecordTypeAAAA && dnsRecord.Type != RecordTypeCNAME && dnsRecord.Type != RecordTypeALIAS && dnsRecord.Type != RecordTypeIP {
				return AppConfig{}, fmt.Errorf(MsgErrSkipSSLNotApplicable, dnsRecord.Hostname, dnsRecord.Type)
			}
		}

		var normalizedExpected []string
		for _, rawVal := range dnsRecord.Expected {
			cleanVal := strings.TrimSuffix(strings.TrimSpace(rawVal), ".")
			if cleanVal == "" {
				continue
			}
			if strings.HasPrefix(strings.ToLower(cleanVal), PrefixAlias) {
				cleanVal = strings.TrimSpace(cleanVal[len(PrefixAlias):])
			}
			if dnsRecord.Type != RecordTypeTXT {
				cleanVal = strings.ToLower(cleanVal)
			}

			// Validate and normalize according to record type
			parsedIP := net.ParseIP(cleanVal)
			switch dnsRecord.Type {
			case RecordTypeA:
				if parsedIP != nil {
					if parsedIP.To4() == nil {
						return AppConfig{}, fmt.Errorf(MsgErrExpectedIPv6ForTypeA, strconv.Quote(dnsRecord.Name), dnsRecord.Hostname, strconv.Quote(rawVal))
					}
					cleanVal = parsedIP.String()
				} else {
					return AppConfig{}, fmt.Errorf(MsgErrExpectedNotValidIPv4, strconv.Quote(dnsRecord.Name), dnsRecord.Hostname, strconv.Quote(rawVal))
				}
			case RecordTypeAAAA:
				if parsedIP != nil {
					if parsedIP.To4() != nil {
						return AppConfig{}, fmt.Errorf(MsgErrExpectedIPv4ForTypeAAAA, strconv.Quote(dnsRecord.Name), dnsRecord.Hostname, strconv.Quote(rawVal))
					}
					cleanVal = parsedIP.String()
				} else {
					return AppConfig{}, fmt.Errorf(MsgErrExpectedNotValidIPv6, strconv.Quote(dnsRecord.Name), dnsRecord.Hostname, strconv.Quote(rawVal))
				}
			case RecordTypeIP:
				if parsedIP != nil {
					cleanVal = parsedIP.String()
				} else {
					return AppConfig{}, fmt.Errorf(MsgErrExpectedNotValidIP, strconv.Quote(dnsRecord.Name), dnsRecord.Hostname, strconv.Quote(rawVal))
				}
			case RecordTypeALIAS, RecordTypeCNAME:
				if parsedIP != nil {
					cleanVal = parsedIP.String()
				} else {
					cleanVal = NormalizeDomainToASCIIText(cleanVal)
				}
			default:
				if dnsRecord.Type != RecordTypeTXT {
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
		return nil, errors.New(MsgErrNtfyURLMandatory)
	}

	var auth string
	auth = cfg.Notifications.Ntfy.Auth
	if auth != "" && !strings.HasPrefix(strings.ToLower(auth), strings.ToLower(PrefixBearer)) && !strings.HasPrefix(strings.ToLower(auth), strings.ToLower(PrefixBasic)) {
		auth = PrefixBearer + auth
	}

	client := ResolveHTTPClient(&http.Client{Timeout: DefaultDNSTimeout})
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, cfg.Notifications.Ntfy.URL, nil)
	if err != nil {
		return nil, WrapError(MsgErrFailedCreateNtfyRequest, err)
	}
	req.Header.Set(HeaderUserAgent, DefaultUserAgent)
	if auth != "" {
		req.Header.Set(HeaderAuthorization, auth)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, WrapError(MsgErrNtfyURLUnreachable, err)
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
		dnsMsg.SetQuestion(dns.Fqdn(TestFqdn), dns.TypeA)
		dnsMsg.RecursionDesired = true
		if _, _, err := dnsClient.ExchangeContext(ctx, dnsMsg, ip); err != nil {
			LogWarn(MsgLogResolverUnreachable, "resolver", resolver, "error", err)
			lastResolverErr = err
		} else {
			healthyResolvers = append(healthyResolvers, resolver)
		}
	}

	if len(healthyResolvers) == 0 {
		return nil, WrapError(MsgErrAllResolversFailed, lastResolverErr)
	}

	app.activeResolvers = healthyResolvers

	return app, nil
}

// InitializeDependencies is a backward-compatible adapter for InitializeApp,
// intended strictly for process initialization before background workers start.
func InitializeDependencies(ctx context.Context, app *AppState, rawCfg *AppConfig) error {
	if app == nil {
		return errors.New(MsgErrInitAppNil)
	}
	if rawCfg == nil {
		return errors.New(MsgErrInitConfigNil)
	}
	if app.Notifier == nil {
		return errors.New(MsgErrInitNotifierNil)
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
