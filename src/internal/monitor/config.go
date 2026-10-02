package monitor

import (
	"context"
	"embed"
	jsonv1 "encoding/json"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/miekg/dns"
)

// LoadConfig reads raw operator input and compiles an owned runtime configuration.
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

	var looseConfig RawConfig
	if err := jsonv2.Unmarshal(jsonBytes, &looseConfig); err != nil {
		return AppConfig{}, enrichJSONError(err, &looseConfig)
	}
	jsonBytes, err = migrateV3Config(jsonBytes)
	if err != nil {
		return AppConfig{}, WrapError(MsgErrJSONUnmarshalFailed, err)
	}

	var config RawConfig
	if err := jsonv2.Unmarshal(jsonBytes, &config, jsonv2.RejectUnknownMembers(true)); err != nil {
		return AppConfig{}, enrichJSONError(err, &looseConfig)
	}

	applyConfigOverrides(&config)
	return compileRawConfig(config)
}

func migrateV3Config(data []byte) ([]byte, error) {
	var root map[string]jsonv1.RawMessage
	if err := jsonv1.Unmarshal(data, &root); err != nil {
		return nil, err
	}
	if _, exists := root["data_dir"]; exists {
		return nil, fmt.Errorf("legacy configuration field %q cannot be migrated safely; remove it after reviewing the v4 upgrade notes", "data_dir")
	}
	changed := false
	if rawDomains, ok := root["domains"]; ok {
		var domains []map[string]jsonv1.RawMessage
		if err := jsonv1.Unmarshal(rawDomains, &domains); err != nil {
			return nil, err
		}
		for _, domain := range domains {
			domainChanged, err := migrateV3Domain(domain)
			if err != nil {
				return nil, err
			}
			changed = domainChanged || changed
		}
		if changed {
			encoded, err := jsonv1.Marshal(domains)
			if err != nil {
				return nil, err
			}
			root["domains"] = encoded
		}
	}
	if rawRecords, ok := root["dns_records"]; ok {
		var records []map[string]jsonv1.RawMessage
		if err := jsonv1.Unmarshal(rawRecords, &records); err != nil {
			return nil, err
		}
		for index, record := range records {
			if _, exists := record["skip_ssl"]; exists {
				return nil, fmt.Errorf("dns record at index %d uses legacy field %q, which cannot be migrated safely; remove it after reviewing the v4 upgrade notes", index, "skip_ssl")
			}
		}
		if changed {
			encoded, err := jsonv1.Marshal(records)
			if err != nil {
				return nil, err
			}
			root["dns_records"] = encoded
		}
	}
	if !changed {
		return data, nil
	}
	return jsonv1.Marshal(root)
}

func migrateV3Domain(domain map[string]jsonv1.RawMessage) (bool, error) {
	changed := false
	var domainName string
	if rawDomain, exists := domain["domain"]; exists {
		if err := jsonv1.Unmarshal(rawDomain, &domainName); err != nil {
			return false, err
		}
	}
	for _, key := range []string{"expected_ns", "secondary_ns", "verify_ns_health", "is_delegated_zone", "monitor_ct_logs"} {
		if _, exists := domain[key]; exists {
			return false, fmt.Errorf("domain %q uses legacy field %q, which cannot be migrated safely; replace it with the current v4 schema", domainName, key)
		}
	}
	if _, exists := domain["email"]; !exists {
		email := make(map[string]jsonv1.RawMessage)
		for legacy, current := range map[string]string{"mail_provider": "provider", "mx_records": "mx_records", "dkim_selectors": "dkim_selectors"} {
			if raw, ok := domain[legacy]; ok {
				email[current] = raw
			}
		}
		var enabled bool
		if raw, ok := domain["check_email_security"]; ok {
			if err := jsonv1.Unmarshal(raw, &enabled); err != nil {
				return false, err
			}
		}
		if enabled {
			encoded, err := jsonv1.Marshal(email)
			if err != nil {
				return false, err
			}
			domain["email"] = encoded
			changed = true
		}
	}
	if _, exists := domain["registrar"]; !exists {
		registrarID, hasID := domain["expected_registrar_id"]
		registrarName, hasName := domain["expected_registrar_name"]
		if hasID && hasName {
			return false, fmt.Errorf("domain %q configures both legacy registrar fields; select one current %q value", domainName, "registrar")
		}
		if hasID {
			domain["registrar"] = registrarID
			changed = true
		} else if hasName {
			domain["registrar"] = registrarName
			changed = true
		}
	}
	if _, exists := domain["allow_expiry"]; !exists {
		if raw, ok := domain["unused"]; ok {
			domain["allow_expiry"] = raw
			changed = true
		}
	}
	for _, key := range []string{"check_email_security", "mail_provider", "mx_records", "dkim_selectors", "unused", "expected_registrar_id", "expected_registrar_name"} {
		changed = deleteJSONField(domain, key) || changed
	}
	return changed, nil
}

func deleteJSONField(object map[string]jsonv1.RawMessage, key string) bool {
	if _, exists := object[key]; !exists {
		return false
	}
	delete(object, key)
	return true
}

func enrichJSONError(err error, config *RawConfig) error {
	errMsg := err.Error()
	match := ReJSONDomainPointer.FindStringSubmatch(errMsg)
	if match != nil {
		idx, _ := strconv.Atoi(match[1])
		domainContext := fmt.Sprintf(MsgErrDomainIndexContext, idx)
		if config != nil && idx >= 0 && idx < len(config.Domains) {
			if name := config.Domains[idx].Domain; name != StrEmpty {
				domainContext = fmt.Sprintf(MsgErrDomainNameContext, name)
			}
		}
		return fmt.Errorf(MsgErrEnrichedJSONUnmarshalFailed, domainContext, err)
	}
	return WrapError(MsgErrJSONUnmarshalFailed, err)
}

// compileRawConfig creates an independently owned runtime configuration before
// applying defaults and normalization. The input remains isolated from all
// mutations performed during compilation or later runtime use.
func compileRawConfig(raw RawConfig) (AppConfig, error) {
	cfg := cloneConfig(AppConfig(raw))
	if err := validateConfigEndpoints(&cfg); err != nil {
		return AppConfig{}, err
	}
	if err := normalizeConfiguredChecks(&cfg); err != nil {
		return AppConfig{}, err
	}
	applyLoopIntervalBounds(&cfg)
	return cfg, nil
}

func applyConfigOverrides(config *RawConfig) {
	if p := strings.TrimSpace(os.Getenv(EnvPort)); p != StrEmpty {
		config.Port = p
	}
	if t := strings.TrimSpace(os.Getenv(EnvNtfyAuth)); t != StrEmpty {
		if config.Notifications.Ntfy == nil {
			config.Notifications.Ntfy = &NtfyConfig{}
		}
		config.Notifications.Ntfy.Auth = t
	}
	if t := strings.TrimSpace(os.Getenv(EnvTelegramToken)); t != StrEmpty {
		if config.Notifications.Telegram == nil {
			config.Notifications.Telegram = &TelegramConfig{}
		}
		config.Notifications.Telegram.Token = t
	}
	if id := strings.TrimSpace(os.Getenv(EnvTelegramChatID)); id != StrEmpty {
		if config.Notifications.Telegram == nil {
			config.Notifications.Telegram = &TelegramConfig{}
		}
		config.Notifications.Telegram.ChatID = id
	}
	if u := strings.TrimSpace(os.Getenv(EnvDoHURL)); u != StrEmpty {
		config.DoHURL = u
	}
}

func validateConfigEndpoints(config *AppConfig) error {
	if config.Port == StrEmpty {
		config.Port = DefaultServerPort
	}
	if err := validateTCPPort(config.Port); err != nil {
		return fmt.Errorf(MsgErrInvalidServerPort, err)
	}
	if len(config.Resolvers) == 0 {
		config.Resolvers = DefaultResolvers()
	}
	if len(config.Resolvers) > MaxResolversLimit {
		return fmt.Errorf(MsgErrValidateConfiguredResolvers, len(config.Resolvers), MsgErrResolversExceedLimit)
	}
	for _, endpoint := range config.Resolvers {
		if err := validateResolverEndpoint(endpoint); err != nil {
			return fmt.Errorf(MsgErrInvalidResolver, endpoint, err)
		}
	}
	if config.DoHURL == StrEmpty {
		config.DoHURL = DefaultDoHURL
	}
	if err := validateHTTPURL(config.DoHURL); err != nil {
		return fmt.Errorf(MsgErrInvalidDohURL, err)
	}
	return validateNotificationEndpoints(&config.Notifications)
}

func validateNotificationEndpoints(notifications *Notifications) error {
	if notifications.Ntfy == nil {
		return fmt.Errorf(MsgErrValidateNotificationsNtfy, MsgErrNtfyURLRequired)
	}
	ntfy := notifications.Ntfy
	if ntfy.URL == StrEmpty {
		return fmt.Errorf(MsgErrValidateNotificationsNtfy, MsgErrNtfyURLRequired)
	}
	if err := validateHTTPURL(ntfy.URL); err != nil {
		return fmt.Errorf(MsgErrInvalidNtfyURL, err)
	}
	if ntfy.Auth != StrEmpty {
		endpoint, err := url.Parse(ntfy.URL)
		if err != nil || !strings.EqualFold(endpoint.Scheme, SchemeHTTPSName) {
			return fmt.Errorf(MsgErrInvalidNtfyURL, errors.New(MsgErrAuthenticatedNtfyRequiresHTTPS))
		}
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

func normalizeConfiguredChecks(config *AppConfig) error {
	for _, task := range config.DNSRecords {
		if strings.HasPrefix(strings.TrimSpace(task.Name), InternalCAATaskPrefix) {
			return fmt.Errorf(MsgErrReservedDNSName, task.Name, InternalCAATaskPrefix)
		}
	}
	seenDomains := make(stringSet, len(config.Domains))
	seenDomainNames := make(stringSet, len(config.Domains))
	for i := range config.Domains {
		if err := normalizeDomainConfig(&config.Domains[i], i, seenDomains, seenDomainNames); err != nil {
			return err
		}

		d := &config.Domains[i]
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
				config.DNSRecords = append(config.DNSRecords, task)
			}
		}
	}

	seenDNSNames := make(stringSet, len(config.DNSRecords))
	for i := range config.DNSRecords {
		if err := normalizeDNSTask(&config.DNSRecords[i], i, seenDNSNames); err != nil {
			return err
		}
	}
	return nil
}

func applyLoopIntervalBounds(config *AppConfig) {
	switch {
	case config.LoopIntervalDays == 0:
		config.LoopIntervalDays = DefaultLoopIntervalDays
	case config.LoopIntervalDays < MinLoopIntervalDays:
		LogInfo(MsgLogLoopIntervalBelowMin, FieldConfigured, config.LoopIntervalDays)
		config.LoopIntervalDays = MinLoopIntervalDays
	case config.LoopIntervalDays > MaxLoopIntervalDays:
		LogInfo(MsgLogLoopIntervalAboveMax, FieldConfigured, config.LoopIntervalDays)
		config.LoopIntervalDays = MaxLoopIntervalDays
	}

}

func validateTCPPort(port string) error {
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf(MsgErrPortOutOfRange, port)
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
			return fmt.Errorf(MsgErrExpectedIPAddressOrHostPort, err)
		}
		if err := validateTCPPort(port); err != nil {
			return err
		}
	}
	if net.ParseIP(host) == nil && (host == StrEmpty || strings.ContainsAny(host, SymInvalidURLChars)) {
		return fmt.Errorf(MsgErrResolverEndpointInvalidHost, endpoint)
	}
	return nil
}

func validateHTTPURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u == nil || (u.Scheme != StrHTTP && u.Scheme != StrHTTPS) || u.Hostname() == StrEmpty || u.User != nil {
		return errors.New(MsgErrExpectedHTTPURLWithHost)
	}
	if port := u.Port(); port != StrEmpty {
		return validateTCPPort(port)
	}
	return nil
}

func normalizeDomainConfig(domainCfg *DomainConfig, i int, seenDomains, seenDomainNames stringSet) error {
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
				val := canonicalCAAIssueValue(item)
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

func normalizeDomainName(domainCfg *DomainConfig, i int, seenDomains stringSet) error {
	domainCfg.Domain = NormalizeDomainToASCIIText(domainCfg.Domain)
	if domainCfg.Domain == StrEmpty {
		return fmt.Errorf(MsgErrDomainEmptyDomain, i)
	}
	if !ReValidDomain.MatchString(domainCfg.Domain) || len(domainCfg.Domain) > 253 {
		return fmt.Errorf(MsgErrInvalidMonitoredDomain, domainCfg.Domain)
	}
	if _, exists := seenDomains[domainCfg.Domain]; exists {
		return fmt.Errorf(MsgErrDuplicateDomain, strconv.Quote(domainCfg.Domain))
	}
	seenDomains[domainCfg.Domain] = struct{}{}
	return nil
}

func normalizeDomainNameservers(domainCfg *DomainConfig) error {
	seen := make(stringSet, len(domainCfg.Nameservers))
	hasAnswering := false
	for j := range domainCfg.Nameservers {
		nameserver := &domainCfg.Nameservers[j]
		nsClean := NormalizeDomainToASCIIText(nameserver.Hostname)
		if nsClean == StrEmpty {
			return fmt.Errorf(MsgErrDomainEmptyNameserver, domainCfg.Domain, j)
		}
		if !ReValidDomain.MatchString(nsClean) || len(nsClean) > 253 {
			return fmt.Errorf(MsgErrDomainInvalidNameserver, domainCfg.Domain, strconv.Quote(nsClean))
		}
		if _, exists := seen[nsClean]; exists {
			return fmt.Errorf(MsgErrDomainDuplicateNameserver, domainCfg.Domain, nsClean)
		}
		seen[nsClean] = struct{}{}
		nameserver.Hostname = nsClean
		hasAnswering = hasAnswering || !nameserver.Hidden
	}
	if len(domainCfg.Nameservers) > 0 && !hasAnswering {
		return fmt.Errorf(MsgErrDomainNeedsAnsweringNameserver, domainCfg.Domain)
	}
	return nil
}

func normalizeDomainMetadata(domainCfg *DomainConfig, seenDomainNames stringSet) error {
	if domainCfg.Name == StrEmpty {
		return fmt.Errorf(MsgErrDomainMissingName, domainCfg.Domain)
	}
	if _, exists := seenDomainNames[domainCfg.Name]; exists {
		return fmt.Errorf(MsgErrDuplicateDomainName, strconv.Quote(domainCfg.Name))
	}
	seenDomainNames[domainCfg.Name] = struct{}{}

	domainCfg.Registrar = strings.TrimSpace(domainCfg.Registrar)

	if domainCfg.RenewalPrice < 0 {
		return fmt.Errorf(MsgErrDomainNegativeRenewalPrice, domainCfg.Domain)
	}

	domainCfg.RootZone = NormalizeDomainToASCIIText(domainCfg.RootZone)
	if domainCfg.isDelegatedZone() {
		if !ReValidDomain.MatchString(domainCfg.RootZone) || len(domainCfg.RootZone) > 253 {
			return fmt.Errorf(MsgErrDomainInvalidRootZone, domainCfg.Domain, strconv.Quote(domainCfg.RootZone))
		}
		if !strings.HasSuffix(domainCfg.Domain, SymDot+domainCfg.RootZone) {
			return fmt.Errorf(MsgErrRootZoneIsNotA, domainCfg.RootZone, domainCfg.Domain)
		}
	}
	return nil
}

func normalizeDomainEmail(domainCfg *DomainConfig) error {
	if domainCfg.Email != nil {
		email := domainCfg.Email
		if email.Provider != StrEmpty && len(email.MXRecords) > 0 {
			return fmt.Errorf(MsgErrMailProviderAndMXMutuallyExclusive, domainCfg.Domain)
		}
		email.Provider = strings.ToLower(strings.TrimSpace(email.Provider))
		for j := range email.MXRecords {
			rawMX := strings.TrimSpace(email.MXRecords[j])
			var mxClean string
			if rawMX == NullMXRecord {
				mxClean = NullMXRecord
			} else {
				mxClean = NormalizeDomainToASCIIText(rawMX)
			}
			if mxClean != NullMXRecord && (!ReValidDomain.MatchString(mxClean) || len(mxClean) > 253) {
				return fmt.Errorf(MsgErrDomainInvalidMX, domainCfg.Domain, strconv.Quote(mxClean))
			}
			email.MXRecords[j] = mxClean
		}
		for j := range email.DKIMSelectors {
			selector := strings.ToLower(strings.TrimSpace(email.DKIMSelectors[j]))
			if !ReValidDomain.MatchString(selector+ValidationDomainSuffix) || len(selector) > 200 {
				return fmt.Errorf(MsgErrDomainInvalidDKIMSelector, domainCfg.Domain, strconv.Quote(selector))
			}
			email.DKIMSelectors[j] = selector
		}
	}

	return nil
}

func normalizeDNSTask(dnsRecord *DNSTask, i int, seenDNSNames stringSet) error {
	if err := normalizeDNSTaskIdentity(dnsRecord, i, seenDNSNames); err != nil {
		return err
	}
	if err := validateDNSTaskOptions(dnsRecord); err != nil {
		return err
	}
	return normalizeDNSTaskExpected(dnsRecord)
}

func normalizeDNSTaskIdentity(dnsRecord *DNSTask, i int, seenDNSNames stringSet) error {
	dnsRecord.Hostname = NormalizeDomainToASCIIText(dnsRecord.Hostname)

	if dnsRecord.Hostname == StrEmpty {
		return fmt.Errorf(MsgErrDNSEmptyHostname, i)
	}

	dnsRecord.Name = strings.TrimSpace(dnsRecord.Name)
	if dnsRecord.Name == StrEmpty {
		return fmt.Errorf(MsgErrDNSMissingName, dnsRecord.Hostname, dnsRecord.Type)
	}
	if _, exists := seenDNSNames[dnsRecord.Name]; exists {
		return fmt.Errorf(MsgErrDuplicateDNSName, strconv.Quote(dnsRecord.Name))
	}
	seenDNSNames[dnsRecord.Name] = struct{}{}
	return nil
}

func validateDNSTaskOptions(dnsRecord *DNSTask) error {
	dnsRecord.Type = strings.ToUpper(strings.TrimSpace(dnsRecord.Type))
	if dnsRecord.Type == StrEmpty {
		return fmt.Errorf(MsgErrDNSMissingType, dnsRecord.Hostname)
	}
	if _, known := dnsTypeForName(dnsRecord.Type); !known && dnsRecord.Type != RecordTypeIP && dnsRecord.Type != RecordTypeALIAS {
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
			return StrEmpty, fmt.Errorf(MsgErrInvalidExpectedCAAValue, rawVal, record.Hostname)
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
			return StrEmpty, fmt.Errorf(MsgErrExpectedInvalidIPv4, quotedName, record.Hostname, quotedValue)
		case RecordTypeAAAA:
			return StrEmpty, fmt.Errorf(MsgErrExpectedInvalidIPv6, quotedName, record.Hostname, quotedValue)
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
	app.Clients = OutboundClients{
		Public: NewPublicHTTPClient(DefaultHTTPTimeout), Notification: NewNotificationHTTPClient(DefaultHTTPTimeout), RDAP: NewRDAPHTTPClient(DefaultHTTPTimeout),
	}
	app.Bootstrap = NewBootstrap(app.Clients.Public)
	app.Pricing = NewPricingManager(app.Clients.Public)

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
		notifier.HTTPClient = app.Clients.Notification
		app.Notifier = notifier
	}

	providers, err := loadEmailProviders(cfg.EmailProvidersDir)
	if err != nil {
		return nil, err
	}
	for _, domain := range app.configuration().Domains {
		if domain.Email != nil && domain.Email.Provider != StrEmpty {
			if _, known := providers[domain.Email.Provider]; !known {
				return nil, fmt.Errorf(MsgErrUnknownMailProviderFor, domain.Email.Provider, domain.Domain)
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
