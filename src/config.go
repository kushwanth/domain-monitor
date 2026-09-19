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
		if err := normalizeDomainConfig(&rawCfg.Domains[i], i, seenDomains, seenDomainNames); err != nil {
			return AppConfig{}, err
		}
	}


	seenDNSNames := make(map[string]bool, len(rawCfg.DNSRecords))
	for i := range rawCfg.DNSRecords {
		if err := normalizeDNSTask(&rawCfg.DNSRecords[i], i, seenDNSNames); err != nil {
			return AppConfig{}, err
		}
	}

	if rawCfg.DoHURL == "" {
		rawCfg.DoHURL = DefaultDoHURL
	}

	if rawCfg.LoopIntervalDays == 0 {
		rawCfg.LoopIntervalDays = DefaultLoopIntervalDays
	} else if rawCfg.LoopIntervalDays < MinLoopIntervalDays {
		LogInfo(MsgLogLoopIntervalBelowMin, FieldConfigured, rawCfg.LoopIntervalDays)
		rawCfg.LoopIntervalDays = MinLoopIntervalDays
	} else if rawCfg.LoopIntervalDays > MaxLoopIntervalDays {
		LogInfo(MsgLogLoopIntervalAboveMax, FieldConfigured, rawCfg.LoopIntervalDays)
		rawCfg.LoopIntervalDays = MaxLoopIntervalDays
	}

	return rawCfg, nil
}

func normalizeDomainConfig(domainCfg *DomainConfig, i int, seenDomains map[string]bool, seenDomainNames map[string]bool) error {
	domainCfg.Domain = NormalizeDomainToASCIIText(domainCfg.Domain)
	if domainCfg.Domain == "" {
		return fmt.Errorf(MsgErrDomainEmptyDomain, i)
	}
	if seenDomains[domainCfg.Domain] {
		return fmt.Errorf(MsgErrDuplicateDomain, strconv.Quote(domainCfg.Domain))
	}
	seenDomains[domainCfg.Domain] = true
	for j := range domainCfg.ExpectedNS {
		nsClean := NormalizeDomainToASCIIText(domainCfg.ExpectedNS[j])
		if nsClean == "" {
			return fmt.Errorf(MsgErrDomainEmptyExpectedNS, domainCfg.Domain, j)
		}
		domainCfg.ExpectedNS[j] = nsClean
	}
	for j := range domainCfg.SecondaryNS {
		nsClean := NormalizeDomainToASCIIText(domainCfg.SecondaryNS[j])
		if nsClean == "" {
			return fmt.Errorf(MsgErrDomainEmptySecondaryNS, domainCfg.Domain, j)
		}
		domainCfg.SecondaryNS[j] = nsClean
	}

	if domainCfg.Name == "" {
		return fmt.Errorf(MsgErrDomainMissingName, domainCfg.Domain)
	}
	if seenDomainNames[domainCfg.Name] {
		return fmt.Errorf(MsgErrDuplicateDomainName, strconv.Quote(domainCfg.Name))
	}
	seenDomainNames[domainCfg.Name] = true

	domainCfg.ExpectedRegistrarID = strings.TrimSpace(domainCfg.ExpectedRegistrarID)
	domainCfg.ExpectedRegistrarName = strings.TrimSpace(domainCfg.ExpectedRegistrarName)

	if domainCfg.RenewalPrice < 0 {
		return fmt.Errorf(MsgErrDomainNegativeRenewalPrice, domainCfg.Domain)
	}

	if len(domainCfg.SecondaryNS) > 0 && len(domainCfg.ExpectedNS) == 0 {
		return fmt.Errorf(MsgErrSecondaryNSWithoutPrimary, domainCfg.Domain)
	}

	if domainCfg.VerifyNSHealth {
		if len(domainCfg.ExpectedNS) == 0 {
			return fmt.Errorf(MsgErrVerifyNSHealthWithoutPrimary, domainCfg.Domain)
		}
	}

	if domainCfg.IsDelegatedZone {
		domainCfg.RootZone = NormalizeDomainToASCIIText(domainCfg.RootZone)
		if domainCfg.RootZone == "" {
			return fmt.Errorf(MsgErrDelegatedMissingRootZone, domainCfg.Domain)
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
				return []string{} // non-nil empty slice represents explicit deny-all
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
			return fmt.Errorf(MsgErrMailProviderAndMXMutuallyExclusive, domainCfg.Domain)
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

	return nil
}

func normalizeDNSTask(dnsRecord *DNSTask, i int, seenDNSNames map[string]bool) error {
	dnsRecord.Hostname = NormalizeDomainToASCIIText(dnsRecord.Hostname)

	if dnsRecord.Hostname == "" {
		return fmt.Errorf(MsgErrDNSEmptyHostname, i)
	}

	dnsRecord.Name = strings.TrimSpace(dnsRecord.Name)
	if dnsRecord.Name == "" {
		return fmt.Errorf(MsgErrDNSMissingName, dnsRecord.Hostname, dnsRecord.Type)
	}
	if seenDNSNames[dnsRecord.Name] {
		return fmt.Errorf(MsgErrDuplicateDNSName, strconv.Quote(dnsRecord.Name))
	}
	seenDNSNames[dnsRecord.Name] = true

	dnsRecord.Type = strings.ToUpper(strings.TrimSpace(dnsRecord.Type))
	if dnsRecord.Type == "" {
		return fmt.Errorf(MsgErrDNSMissingType, dnsRecord.Hostname)
	}
	if dnsRecord.SkipSSL {
		if dnsRecord.Type != RecordTypeA && dnsRecord.Type != RecordTypeAAAA && dnsRecord.Type != RecordTypeCNAME && dnsRecord.Type != RecordTypeALIAS && dnsRecord.Type != RecordTypeIP {
			return fmt.Errorf(MsgErrSkipSSLNotApplicable, dnsRecord.Hostname, dnsRecord.Type)
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

		parsedIP := net.ParseIP(cleanVal)
		switch dnsRecord.Type {
		case RecordTypeA:
			if parsedIP != nil {
				if parsedIP.To4() == nil {
					return fmt.Errorf(MsgErrExpectedIPv6ForTypeA, strconv.Quote(dnsRecord.Name), dnsRecord.Hostname, strconv.Quote(rawVal))
				}
				cleanVal = parsedIP.String()
			} else {
				return fmt.Errorf(MsgErrExpectedNotValidIPv4, strconv.Quote(dnsRecord.Name), dnsRecord.Hostname, strconv.Quote(rawVal))
			}
		case RecordTypeAAAA:
			if parsedIP != nil {
				if parsedIP.To4() != nil {
					return fmt.Errorf(MsgErrExpectedIPv4ForTypeAAAA, strconv.Quote(dnsRecord.Name), dnsRecord.Hostname, strconv.Quote(rawVal))
				}
				cleanVal = parsedIP.String()
			} else {
				return fmt.Errorf(MsgErrExpectedNotValidIPv6, strconv.Quote(dnsRecord.Name), dnsRecord.Hostname, strconv.Quote(rawVal))
			}
		case RecordTypeIP:
			if parsedIP != nil {
				cleanVal = parsedIP.String()
			} else {
				return fmt.Errorf(MsgErrExpectedNotValidIP, strconv.Quote(dnsRecord.Name), dnsRecord.Hostname, strconv.Quote(rawVal))
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

	if dnsRecord.Type == RecordTypeA || dnsRecord.Type == RecordTypeAAAA || dnsRecord.Type == RecordTypeIP {
		slices.Sort(normalizedExpected)
	}

	dnsRecord.Expected = normalizedExpected
	return nil
}

// InitializeApp handles side-effects like validating notifications and resolver health checks,
// constructing and returning a fully wired AppState. It does not mutate the provided AppConfig.
func InitializeApp(ctx context.Context, cfg AppConfig) (*AppState, error) {
	app := NewAppState(cfg)

	if cfg.Notifications.Ntfy == nil || strings.TrimSpace(cfg.Notifications.Ntfy.URL) == "" {
		return nil, errors.New(MsgErrNtfyURLMandatory)
	}

	var auth string
	auth = cfg.Notifications.Ntfy.Auth
	if auth != "" && !strings.HasPrefix(strings.ToLower(auth), strings.ToLower(PrefixBearer)) && !strings.HasPrefix(strings.ToLower(auth), strings.ToLower(PrefixBasic)) {
		auth = PrefixBearer + auth
	}

	client := ResolveHTTPClient(&http.Client{Timeout: DefaultHTTPTimeout})
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

	app.Notifier.NtfyURL = cfg.Notifications.Ntfy.URL
	app.Notifier.NtfyAuth = auth
	app.Notifier.alertChan = make(chan Alert, 1000)
	go app.Notifier.workerLoop()

	if cfg.Notifications.Telegram != nil && cfg.Notifications.Telegram.Token != "" && cfg.Notifications.Telegram.ChatID != "" {
		app.Notifier.TelegramToken = cfg.Notifications.Telegram.Token
		app.Notifier.TelegramChatID = cfg.Notifications.Telegram.ChatID
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
			LogWarn(MsgLogResolverUnreachable, FieldResolver, resolver, FieldError, err)
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
