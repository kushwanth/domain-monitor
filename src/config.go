package main

import (
	"context"
	"embed"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/miekg/dns"
)

// LoadConfig reads, unmarshals, normalizes, and validates the configuration file.
func LoadConfig(ctx context.Context, path string) (AppConfig, error) {
	return loadConfig(ctx, path, readConfigFile)
}

func readConfigFile(path string) ([]byte, error) {
	// #nosec G304,G703 -- path is the operator-selected configuration file.
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }() // read-only close
	return readBounded(file, MaxConfigFileSize)
}

func loadConfig(ctx context.Context, path string, readFile func(string) ([]byte, error)) (AppConfig, error) {
	if err := ctx.Err(); err != nil {
		return AppConfig{}, fmt.Errorf(MsgErrLoadConfiguration, err)
	}
	if path == StrEmpty {
		path = DefaultConfigFile
	}

	jsonBytes, err := readFile(path)
	if err != nil {
		return AppConfig{}, WrapError(MsgErrFailedToReadConfig, err)
	}

	var rawCfg AppConfig
	if err := jsonv2.Unmarshal(jsonBytes, &rawCfg); err != nil {
		return AppConfig{}, WrapError(MsgErrJSONUnmarshalFailed, err)
	}
	// Preserve old allow_expiry:true configurations as unused domains.
	var legacy legacyConfig
	if err := jsonv2.Unmarshal(jsonBytes, &legacy); err != nil {
		return AppConfig{}, WrapError(MsgErrJSONUnmarshalFailed, err)
	}
	for i := range rawCfg.Domains {
		if i < len(legacy.Domains) && legacy.Domains[i].AllowExpiry {
			rawCfg.Domains[i].Unused = true
		}
	}

	applyConfigOverrides(&rawCfg)
	if err := validateConfigEndpoints(&rawCfg); err != nil {
		return AppConfig{}, err
	}
	if err := normalizeConfiguredChecks(&rawCfg); err != nil {
		return AppConfig{}, err
	}
	applyLoopIntervalBounds(&rawCfg)
	return rawCfg, nil
}

func applyConfigOverrides(rawCfg *AppConfig) {
	if p := strings.TrimSpace(os.Getenv(EnvPort)); p != StrEmpty {
		rawCfg.Port = p
	}
	if t := strings.TrimSpace(os.Getenv(EnvNtfyAuth)); t != StrEmpty {
		if rawCfg.Notifications.Ntfy == nil {
			rawCfg.Notifications.Ntfy = &NtfyConfig{}
		}
		rawCfg.Notifications.Ntfy.Auth = t
	}
	if t := strings.TrimSpace(os.Getenv(EnvTelegramToken)); t != StrEmpty {
		if rawCfg.Notifications.Telegram == nil {
			rawCfg.Notifications.Telegram = &TelegramConfig{}
		}
		rawCfg.Notifications.Telegram.Token = t
	}
	if id := strings.TrimSpace(os.Getenv(EnvTelegramChatID)); id != StrEmpty {
		if rawCfg.Notifications.Telegram == nil {
			rawCfg.Notifications.Telegram = &TelegramConfig{}
		}
		rawCfg.Notifications.Telegram.ChatID = id
	}
	if u := strings.TrimSpace(os.Getenv(EnvDoHURL)); u != StrEmpty {
		rawCfg.DoHURL = u
	}
}

func validateConfigEndpoints(rawCfg *AppConfig) error {
	if rawCfg.Port == StrEmpty {
		rawCfg.Port = DefaultServerPort
	}
	if err := validateTCPPort(rawCfg.Port); err != nil {
		return fmt.Errorf(MsgErrInvalidServerPort, err)
	}
	if len(rawCfg.Resolvers) == 0 {
		rawCfg.Resolvers = DefaultResolvers()
	}
	if len(rawCfg.Resolvers) > MaxResolversLimit {
		return fmt.Errorf(MsgErrValidateConfiguredResolvers, len(rawCfg.Resolvers), MsgErrResolversExceedLimit)
	}
	for _, endpoint := range rawCfg.Resolvers {
		if err := validateResolverEndpoint(endpoint); err != nil {
			return fmt.Errorf(MsgErrInvalidResolver, endpoint, err)
		}
	}
	if rawCfg.DoHURL == StrEmpty {
		rawCfg.DoHURL = DefaultDoHURL
	}
	if err := validateHTTPURL(rawCfg.DoHURL); err != nil {
		return fmt.Errorf(MsgErrInvalidDohURL, err)
	}
	return validateNotificationEndpoints(&rawCfg.Notifications)
}

func validateNotificationEndpoints(notifications *Notifications) error {
	if notifications.Ntfy == nil {
		return fmt.Errorf(MsgErrValidateNotificationsntfy, MsgErrNtfyURLRequired)
	}
	ntfy := notifications.Ntfy
	if ntfy.URL == StrEmpty {
		return fmt.Errorf(MsgErrValidateNotificationsntfy, MsgErrNtfyURLRequired)
	}
	if err := validateHTTPURL(ntfy.URL); err != nil {
		return fmt.Errorf(MsgErrInvalidNtfyURL, err)
	}
	if notifications.Telegram != nil {
		telegram := notifications.Telegram
		telegram.Token = strings.TrimSpace(telegram.Token)
		telegram.ChatID = strings.TrimSpace(telegram.ChatID)
		if telegram.Token == StrEmpty || telegram.ChatID == StrEmpty {
			LogWarn(MsgLogTelegramDisabled)
			notifications.Telegram = nil
		}
	}
	return nil
}

func normalizeConfiguredChecks(rawCfg *AppConfig) error {
	for _, task := range rawCfg.DNSRecords {
		if strings.HasPrefix(strings.TrimSpace(task.Name), InternalCAATaskPrefix) {
			return fmt.Errorf(MsgErrReservedDNSName, task.Name, InternalCAATaskPrefix)
		}
	}
	seenDomains := make(map[string]bool, len(rawCfg.Domains))
	seenDomainNames := make(map[string]bool, len(rawCfg.Domains))
	for i := range rawCfg.Domains {
		if err := normalizeDomainConfig(&rawCfg.Domains[i], i, seenDomains, seenDomainNames); err != nil {
			return err
		}

		d := &rawCfg.Domains[i]
		if d.CAA != nil {
			var expected []string
			if d.CAA.Issue != nil {
				if len(d.CAA.Issue) == 0 {
					expected = append(expected, CAARecordIssueDenyAll)
				} else {
					for _, val := range d.CAA.Issue {
						expected = append(expected, fmt.Sprintf(CAARecordIssueFormat, val))
					}
				}
			}
			if d.CAA.IssueWild != nil {
				if len(d.CAA.IssueWild) == 0 {
					expected = append(expected, CAARecordIssueWildDenyAll)
				} else {
					for _, val := range d.CAA.IssueWild {
						expected = append(expected, fmt.Sprintf(CAARecordIssueWildFormat, val))
					}
				}
			}
			if d.CAA.IssueMail != nil {
				if len(d.CAA.IssueMail) == 0 {
					expected = append(expected, CAARecordIssueMailDenyAll)
				} else {
					for _, val := range d.CAA.IssueMail {
						expected = append(expected, fmt.Sprintf(CAARecordIssueMailFormat, val))
					}
				}
			}

			if len(expected) > 0 {
				task := DNSTask{
					domainCAA: true,
					Hostname:  d.Domain,
					Name:      InternalCAATaskPrefix + d.Domain,
					Type:      RecordTypeCAA,
					Expected:  expected,
				}
				rawCfg.DNSRecords = append(rawCfg.DNSRecords, task)
			}
		}
	}

	seenDNSNames := make(map[string]bool, len(rawCfg.DNSRecords))
	for i := range rawCfg.DNSRecords {
		if err := normalizeDNSTask(&rawCfg.DNSRecords[i], i, seenDNSNames); err != nil {
			return err
		}
	}
	return nil
}

func applyLoopIntervalBounds(rawCfg *AppConfig) {
	switch {
	case rawCfg.LoopIntervalDays == 0:
		rawCfg.LoopIntervalDays = DefaultLoopIntervalDays
	case rawCfg.LoopIntervalDays < MinLoopIntervalDays:
		LogInfo(MsgLogLoopIntervalBelowMin, FieldConfigured, rawCfg.LoopIntervalDays)
		rawCfg.LoopIntervalDays = MinLoopIntervalDays
	case rawCfg.LoopIntervalDays > MaxLoopIntervalDays:
		LogInfo(MsgLogLoopIntervalAboveMax, FieldConfigured, rawCfg.LoopIntervalDays)
		rawCfg.LoopIntervalDays = MaxLoopIntervalDays
	}

}

func validateTCPPort(port string) error {
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf(MsgErrPortMustBeBetween1, port)
	}
	return nil
}

func validateResolverEndpoint(endpoint string) error {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == StrEmpty {
		return fmt.Errorf(MsgErrResolverEndpointIsEmpty, endpoint)
	}
	if net.ParseIP(endpoint) != nil {
		return nil
	}
	host := endpoint
	if strings.Contains(endpoint, SymColon) {
		var port string
		var err error
		host, port, err = net.SplitHostPort(endpoint)
		if err != nil {
			return fmt.Errorf(MsgErrExpectedAnIPAddressOr, err)
		}
		if err := validateTCPPort(port); err != nil {
			return err
		}
	}
	if net.ParseIP(host) == nil && (host == StrEmpty || strings.ContainsAny(host, SymInvalidURLChars)) {
		return fmt.Errorf(MsgErrResolverEndpointHasAnInvalid, endpoint)
	}
	return nil
}

func validateHTTPURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u == nil || (u.Scheme != StrHTTP && u.Scheme != StrHTTPS) || u.Hostname() == StrEmpty || u.User != nil {
		return errors.New(MsgErrExpectedAnHTTPSURLWith)
	}
	if port := u.Port(); port != StrEmpty {
		return validateTCPPort(port)
	}
	return nil
}

func normalizeDomainConfig(domainCfg *DomainConfig, i int, seenDomains map[string]bool, seenDomainNames map[string]bool) error {
	if err := normalizeDomainName(domainCfg, i, seenDomains); err != nil {
		return err
	}
	if err := normalizeDomainNameservers(domainCfg); err != nil {
		return err
	}
	if err := normalizeDomainMetadata(domainCfg, seenDomainNames); err != nil {
		return err
	}
	if err := normalizeDomainEmail(domainCfg); err != nil {
		return err
	}
	return normalizeDomainCAA(domainCfg)
}

func normalizeDomainCAA(domainCfg *DomainConfig) error {
	if domainCfg.CAA != nil {
		normalizeCAAList := func(list []string) []string {
			if list == nil {
				return nil
			}
			var res []string
			for _, item := range list {
				val := strings.ToLower(strings.TrimSpace(item))
				if val != StrEmpty && val != SymSemicolon && val != StrNone {
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
	return nil
}

func normalizeDomainName(domainCfg *DomainConfig, i int, seenDomains map[string]bool) error {
	domainCfg.Domain = NormalizeDomainToASCIIText(domainCfg.Domain)
	if domainCfg.Domain == StrEmpty {
		return fmt.Errorf(MsgErrDomainEmptyDomain, i)
	}
	if !ReValidDomain.MatchString(domainCfg.Domain) || len(domainCfg.Domain) > 253 {
		return fmt.Errorf(MsgErrInvalidMonitoredDomain, domainCfg.Domain)
	}
	if seenDomains[domainCfg.Domain] {
		return fmt.Errorf(MsgErrDuplicateDomain, strconv.Quote(domainCfg.Domain))
	}
	seenDomains[domainCfg.Domain] = true
	return nil
}

func normalizeDomainNameservers(domainCfg *DomainConfig) error {
	for j := range domainCfg.ExpectedNS {
		nsClean := NormalizeDomainToASCIIText(domainCfg.ExpectedNS[j])
		if nsClean == StrEmpty {
			return fmt.Errorf(MsgErrDomainEmptyExpectedNS, domainCfg.Domain, j)
		}
		domainCfg.ExpectedNS[j] = nsClean
	}
	for j := range domainCfg.SecondaryNS {
		nsClean := NormalizeDomainToASCIIText(domainCfg.SecondaryNS[j])
		if nsClean == StrEmpty {
			return fmt.Errorf(MsgErrDomainEmptySecondaryNS, domainCfg.Domain, j)
		}
		domainCfg.SecondaryNS[j] = nsClean
	}
	return nil
}

func normalizeDomainMetadata(domainCfg *DomainConfig, seenDomainNames map[string]bool) error {
	if domainCfg.Name == StrEmpty {
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
		if domainCfg.RootZone == StrEmpty {
			return fmt.Errorf(MsgErrDelegatedMissingRootZone, domainCfg.Domain)
		}
		if !strings.HasSuffix(domainCfg.Domain, SymDot+domainCfg.RootZone) {
			return fmt.Errorf(MsgErrRootZoneIsNotA, domainCfg.RootZone, domainCfg.Domain)
		}
	}
	return nil
}

func normalizeDomainEmail(domainCfg *DomainConfig) error {
	if domainCfg.CheckEmailSecurity {
		if domainCfg.MailProvider != StrEmpty && len(domainCfg.MXRecords) > 0 {
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
	if err := normalizeDNSTaskIdentity(dnsRecord, i, seenDNSNames); err != nil {
		return err
	}
	if err := validateDNSTaskOptions(dnsRecord); err != nil {
		return err
	}
	return normalizeDNSTaskExpected(dnsRecord)
}

func normalizeDNSTaskIdentity(dnsRecord *DNSTask, i int, seenDNSNames map[string]bool) error {
	dnsRecord.Hostname = NormalizeDomainToASCIIText(dnsRecord.Hostname)

	if dnsRecord.Hostname == StrEmpty {
		return fmt.Errorf(MsgErrDNSEmptyHostname, i)
	}

	dnsRecord.Name = strings.TrimSpace(dnsRecord.Name)
	if dnsRecord.Name == StrEmpty {
		return fmt.Errorf(MsgErrDNSMissingName, dnsRecord.Hostname, dnsRecord.Type)
	}
	if seenDNSNames[dnsRecord.Name] {
		return fmt.Errorf(MsgErrDuplicateDNSName, strconv.Quote(dnsRecord.Name))
	}
	seenDNSNames[dnsRecord.Name] = true
	return nil
}

func validateDNSTaskOptions(dnsRecord *DNSTask) error {
	dnsRecord.Type = strings.ToUpper(strings.TrimSpace(dnsRecord.Type))
	if dnsRecord.Type == StrEmpty {
		return fmt.Errorf(MsgErrDNSMissingType, dnsRecord.Hostname)
	}
	if _, known := DNSTypeMap[dnsRecord.Type]; !known && dnsRecord.Type != RecordTypeIP && dnsRecord.Type != RecordTypeALIAS {
		return fmt.Errorf(MsgErrUnsupportedDNSRecordTypeFor, dnsRecord.Type, dnsRecord.Hostname)
	}
	dnsRecord.MatchType = strings.ToLower(strings.TrimSpace(dnsRecord.MatchType))
	switch dnsRecord.MatchType {
	case StrEmpty, MatchExact, MatchPrefix, MatchContains, MatchAnyOf:
	default:
		return fmt.Errorf(MsgErrUnsupportedDNSMatchTypeFor, dnsRecord.MatchType, dnsRecord.Hostname)
	}
	if dnsRecord.Expected == nil {
		return fmt.Errorf(MsgErrMissingExpectedDNSRecordsFor, dnsRecord.Hostname)
	}
	if dnsRecord.CustomResolver != StrEmpty {
		if err := validateResolverEndpoint(dnsRecord.CustomResolver); err != nil {
			return fmt.Errorf(MsgErrInvalidCustomResolverFor, dnsRecord.Hostname, err)
		}
	}
	return nil
}

func normalizeDNSTaskExpected(dnsRecord *DNSTask) error {
	var normalizedExpected []string
	for _, rawVal := range dnsRecord.Expected {
		cleanVal, err := normalizeExpectedDNSValue(*dnsRecord, rawVal)
		if err != nil {
			return err
		}
		if cleanVal == StrEmpty {
			continue
		}
		if !slices.Contains(normalizedExpected, cleanVal) {
			normalizedExpected = append(normalizedExpected, cleanVal)
		}
	}

	if dnsRecord.Type == RecordTypeA || dnsRecord.Type == RecordTypeAAAA || dnsRecord.Type == RecordTypeIP {
		slices.Sort(normalizedExpected)
	}

	dnsRecord.Expected = normalizedExpected
	if len(dnsRecord.Expected) == 0 && dnsRecord.MatchType != StrEmpty && dnsRecord.MatchType != MatchExact {
		return fmt.Errorf(MsgErrEmptyExpectedDNSRecordsFor, dnsRecord.Hostname, dnsRecord.MatchType)
	}
	return nil
}

func normalizeExpectedDNSValue(record DNSTask, rawVal string) (string, error) {
	if record.Type == RecordTypeTXT {
		return strings.TrimSpace(rawVal), nil
	}
	if record.Type == RecordTypeCAA {
		if strings.TrimSpace(rawVal) == StrEmpty {
			return StrEmpty, nil
		}
		rr, err := dns.NewRR(StrExample60InCAA + strings.TrimSpace(rawVal))
		if err != nil {
			return StrEmpty, fmt.Errorf(MsgErrInvalidExpectedCAAValueFor, rawVal, record.Hostname, err)
		}
		caa, ok := rr.(*dns.CAA)
		if !ok {
			return StrEmpty, fmt.Errorf(MsgErrInvalidExpectedCAAValueFor2, rawVal, record.Hostname)
		}
		return canonicalCAARecordValue(caa), nil
	}
	cleanVal := strings.TrimSuffix(strings.TrimSpace(rawVal), SymDot)
	if cleanVal == StrEmpty {
		return StrEmpty, nil
	}
	if strings.HasPrefix(strings.ToLower(cleanVal), PrefixAlias) {
		cleanVal = strings.TrimSpace(cleanVal[len(PrefixAlias):])
	}
	cleanVal = strings.ToLower(cleanVal)
	parsedIP := net.ParseIP(cleanVal)
	switch record.Type {
	case RecordTypeA, RecordTypeAAAA, RecordTypeIP:
		return normalizeExpectedIPValue(record, rawVal, parsedIP)
	case RecordTypeALIAS, RecordTypeCNAME:
		if parsedIP != nil {
			return parsedIP.String(), nil
		}
		return NormalizeDomainToASCIIText(cleanVal), nil
	default:
		return NormalizeDomainToASCIIText(cleanVal), nil
	}
}

func normalizeExpectedIPValue(record DNSTask, rawVal string, parsedIP net.IP) (string, error) {
	quotedName := strconv.Quote(record.Name)
	quotedValue := strconv.Quote(rawVal)
	if parsedIP == nil {
		switch record.Type {
		case RecordTypeA:
			return StrEmpty, fmt.Errorf(MsgErrExpectedNotValidIPv4, quotedName, record.Hostname, quotedValue)
		case RecordTypeAAAA:
			return StrEmpty, fmt.Errorf(MsgErrExpectedNotValidIPv6, quotedName, record.Hostname, quotedValue)
		default:
			return StrEmpty, fmt.Errorf(MsgErrExpectedNotValidIP, quotedName, record.Hostname, quotedValue)
		}
	}
	if record.Type == RecordTypeA && parsedIP.To4() == nil {
		return StrEmpty, fmt.Errorf(MsgErrExpectedIPv6ForTypeA, quotedName, record.Hostname, quotedValue)
	}
	if record.Type == RecordTypeAAAA && parsedIP.To4() != nil {
		return StrEmpty, fmt.Errorf(MsgErrExpectedIPv4ForTypeAAAA, quotedName, record.Hostname, quotedValue)
	}
	return parsedIP.String(), nil
}

// InitializeApp wires the application without requiring upstream services to be reachable.
// It does not mutate the provided AppConfig.
func InitializeApp(ctx context.Context, cfg AppConfig) (*AppState, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf(MsgErrInitializeApplication, err)
	}
	app := NewAppState(cfg)
	app.HTTPClient = &http.Client{Timeout: DefaultHTTPTimeout}
	app.Bootstrap = NewBootstrap(app.HTTPClient)
	app.Pricing = NewPricingManager(app.HTTPClient)

	var auth, ntfyURL string
	if cfg.Notifications.Ntfy != nil {
		auth = cfg.Notifications.Ntfy.Auth
		ntfyURL = strings.TrimSpace(cfg.Notifications.Ntfy.URL)
	}
	if auth != StrEmpty && !strings.HasPrefix(strings.ToLower(auth), strings.ToLower(PrefixBearer)) && !strings.HasPrefix(strings.ToLower(auth), strings.ToLower(PrefixBasic)) {
		auth = PrefixBearer + auth
	}

	var telegramToken, telegramChatID string
	if cfg.Notifications.Telegram != nil {
		telegramToken = cfg.Notifications.Telegram.Token
		telegramChatID = cfg.Notifications.Telegram.ChatID
	}
	if ntfyURL != StrEmpty || telegramToken != StrEmpty {
		notifier := NewNotificationManager(ntfyURL, auth, telegramToken, telegramChatID)
		notifier.HTTPClient = app.HTTPClient
		app.Notifier = notifier
	}

	providers, err := loadEmailProviders(cfg.EmailProvidersDir)
	if err != nil {
		return nil, err
	}
	for _, domain := range app.configuration().Domains {
		if domain.CheckEmailSecurity && domain.MailProvider != StrEmpty {
			if _, known := providers[domain.MailProvider]; !known {
				return nil, fmt.Errorf(MsgErrUnknownMailProviderFor, domain.MailProvider, domain.Domain)
			}
		}
	}
	app.EmailProviders = providers

	return app, nil
}

//go:embed data/email_providers/*.json
var emailProvidersFS embed.FS

func loadEmailProviders(directory string) (map[string]ProviderConfig, error) {
	builtin, err := fs.Sub(emailProvidersFS, DefaultEmailProvidersDir)
	if err != nil {
		return nil, fmt.Errorf(MsgErrOpenEmbeddedEmailProviders, err)
	}
	providers := make(map[string]ProviderConfig)
	if err := readEmailProviders(builtin, providers); err != nil {
		return nil, err
	}
	explicit := strings.TrimSpace(directory) != StrEmpty
	if !explicit {
		directory = DefaultEmailProvidersDir
	}
	if _, err := os.Stat(directory); err != nil {
		if !explicit && errors.Is(err, os.ErrNotExist) {
			return providers, nil
		}
		return nil, fmt.Errorf(MsgErrOpenEmailProviderDirectory, directory, err)
	}
	if err := readEmailProviders(os.DirFS(directory), providers); err != nil {
		return nil, fmt.Errorf(MsgErrLoadEmailProviders, directory, err)
	}
	return providers, nil
}

func readEmailProviders(source fs.FS, providers map[string]ProviderConfig) error {
	entries, err := fs.ReadDir(source, SymDot)
	if err != nil {
		return fmt.Errorf(MsgErrListEmailProviders, err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), JSONFileExtension) {
			continue
		}
		cfg, err := readEmailProvider(source, entry.Name())
		if err != nil {
			return err
		}
		name := strings.ToLower(strings.TrimSuffix(entry.Name(), JSONFileExtension))
		if !ReValidDomain.MatchString(name + ValidationDomainSuffix) {
			return fmt.Errorf(MsgErrInvalidEmailProviderName, name)
		}
		providers[name] = cfg
	}
	return nil
}

func readEmailProvider(source fs.FS, name string) (ProviderConfig, error) {
	file, err := source.Open(name)
	if err != nil {
		return ProviderConfig{}, fmt.Errorf(MsgErrOpenEmailProvider, name, err)
	}
	defer func() { _ = file.Close() }() // read-only close
	body, err := readBounded(file, MaxEmailProviderResponseSize)
	if errors.Is(err, ErrReadLimitExceeded) {
		return ProviderConfig{}, fmt.Errorf(MsgErrEmailProviderExceedsBytes, name, MaxEmailProviderResponseSize)
	}
	if err != nil {
		return ProviderConfig{}, fmt.Errorf(MsgErrReadEmailProvider, name, err)
	}
	var cfg ProviderConfig
	if err := jsonv2.Unmarshal(body, &cfg); err != nil {
		return cfg, fmt.Errorf(MsgErrDecodeEmailProvider, name, err)
	}
	if len(cfg.MXRecords) == 0 {
		return cfg, fmt.Errorf(MsgErrEmailProviderMissingMX, name)
	}
	for i, mx := range cfg.MXRecords {
		mx = NormalizeDomainToASCIIText(mx)
		if !ReValidDomain.MatchString(mx) || len(mx) > 253 {
			return cfg, fmt.Errorf(MsgErrEmailProviderInvalidMX, name, mx)
		}
		cfg.MXRecords[i] = mx
	}
	for i, selector := range cfg.DKIMSelectors {
		selector = strings.ToLower(strings.TrimSpace(selector))
		if !ReValidDomain.MatchString(selector+ValidationDomainSuffix) || len(selector) > 200 {
			return cfg, fmt.Errorf(MsgErrEmailProviderInvalidSelector, name, selector)
		}
		cfg.DKIMSelectors[i] = selector
	}
	return cfg, nil
}
