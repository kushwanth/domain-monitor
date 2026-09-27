package main

import (
	"bytes"
	"context"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/time/rate"
)

// ResultCode represents a typed, zero-allocation condition code for protocol-level evaluator verdicts.
type ResultCode int16

// String returns the diagnostic name of a ResultCode.
func (r ResultCode) String() string {
	if int(r) >= 0 && int(r) < len(resultCodeNames) {
		return resultCodeNames[r]
	}
	return ""
}

// EPPCode identifies known domain lifecycle statuses; unknown provider text stays on the wire.
type EPPCode uint8

// StringList is a slice of strings that unmarshals from either a single JSON string or an array of strings.
type StringList []string

// UnmarshalJSON accepts a single string, a string array, or null.
func (s *StringList) UnmarshalJSON(data []byte) error {
	if s == nil {
		return errors.New(MsgErrNilStringListReceiver)
	}
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte(StrNull)) {
		*s = nil
		return nil
	}
	if trimmed[0] == '"' {
		var single string
		if err := jsonv2.Unmarshal(data, &single); err != nil {
			return err
		}
		*s = []string{single}
		return nil
	}
	var list []string
	if err := jsonv2.Unmarshal(data, &list); err != nil {
		return err
	}
	*s = list
	return nil
}

// StateCondition represents a typed evaluator verdict with optional context and duration tracking.
// Code is a compact numeric enum; Target contains diagnostic text when needed.
type StateCondition struct {
	Code   ResultCode `json:"code"`
	Target string     `json:"target,omitempty"`
	Since  time.Time  `json:"since,omitempty"`
}

// ConditionTracker tracks the worst status and its associated condition.
type ConditionTracker struct {
	Status CheckStatus
	Cond   *StateCondition
}

// Promote escalates the tracked status/condition if the new status is worse.
func (ct *ConditionTracker) Promote(status CheckStatus, code ResultCode, target string) {
	if status == StatusFailed && ct.Status != StatusFailed {
		ct.Status = StatusFailed
		ct.Cond = &StateCondition{Code: code, Target: target}
	} else if status == StatusWarning && ct.Status == StatusOK {
		ct.Status = StatusWarning
		ct.Cond = &StateCondition{Code: code, Target: target}
	}
}

// 1. Status & Priority Enums

// CheckStatus represents lifecycle status of a check
type CheckStatus uint8

// String returns the stable API representation of a check status.
func (s CheckStatus) String() string {
	if int(s) < len(checkStatusNames) {
		return checkStatusNames[s]
	}
	return StrEmpty
}

// MarshalText preserves readable status names at JSON boundaries.
func (s CheckStatus) MarshalText() ([]byte, error) {
	if int(s) >= len(checkStatusNames) {
		return nil, fmt.Errorf(MsgErrInvalidCheckStatus, uint8(s))
	}
	return []byte(s.String()), nil
}

// UnmarshalJSON accepts only the stable status names stored in state files and APIs.
func (s *CheckStatus) UnmarshalJSON(data []byte) error {
	var name string
	if err := jsonv2.Unmarshal(data, &name); err != nil {
		return err
	}
	for i, known := range checkStatusNames {
		if name == known {
			*s = CheckStatus(i)
			return nil
		}
	}
	return fmt.Errorf(MsgErrUnknownCheckStatus, name)
}

// AlertPriority defines the urgency level of a notification alert
type AlertPriority uint8

// String returns the priority name accepted by notification providers.
func (p AlertPriority) String() string {
	if int(p) < len(alertPriorityNames) {
		return alertPriorityNames[p]
	}
	return StrEmpty
}

// MarshalText preserves readable notification priorities at JSON boundaries.
func (p AlertPriority) MarshalText() ([]byte, error) {
	if int(p) >= len(alertPriorityNames) {
		return nil, fmt.Errorf(MsgErrInvalidAlertPriority, uint8(p))
	}
	return []byte(p.String()), nil
}

// UnmarshalText accepts only known notification priority names.
func (p *AlertPriority) UnmarshalText(text []byte) error {
	for i, name := range alertPriorityNames {
		if name == string(text) {
			*p = AlertPriority(i)
			return nil
		}
	}
	return fmt.Errorf(MsgErrUnknownAlertPriority, text)
}

// AlertTag defines the visual badge or emoji category for an alert
type AlertTag string

// ProviderConfig represents dynamic provider data (MX and DKIM selectors)
type ProviderConfig struct {
	MXRecords     []string `json:"mx_records"`
	DKIMSelectors []string `json:"dkim_selectors"`
}

// 2. Configuration Models

// NtfyConfig contains the notification topic URL and optional authorization.
type NtfyConfig struct {
	URL  string `json:"url"`
	Auth string `json:"auth"`
}

// TelegramConfig contains the optional bot token and destination chat ID.
type TelegramConfig struct {
	Token  string `json:"token"`
	ChatID string `json:"chat_id"`
}

// Notifications contains the configured delivery providers.
type Notifications struct {
	Ntfy     *NtfyConfig     `json:"ntfy"`
	Telegram *TelegramConfig `json:"telegram"`
}

// AppConfig defines startup settings and the checks to run.
type AppConfig struct {
	Port              string        `json:"port"`
	LoopIntervalDays  float64       `json:"loop_interval_days"`
	Notifications     Notifications `json:"notifications"`
	Resolvers         []string      `json:"resolvers"`
	DoHURL            string        `json:"doh_url,omitempty"`
	EmailProvidersDir string        `json:"email_providers_dir,omitempty"`

	Domains    []DomainConfig `json:"domains"`
	DNSRecords []DNSTask      `json:"dns_records"`
}

// DomainConfig defines expected registration, DNS, and email evidence for a domain.
type DomainConfig struct {
	Domain                string     `json:"domain"`
	Name                  string     `json:"name"`
	IsDelegatedZone       bool       `json:"is_delegated_zone"`
	RootZone              string     `json:"root_zone"`
	ExpectedNS            []string   `json:"expected_ns"`
	SecondaryNS           []string   `json:"secondary_ns,omitempty"`
	ExpectedRegistrarID   string     `json:"expected_registrar_id,omitempty"`
	ExpectedRegistrarName string     `json:"expected_registrar_name,omitempty"`
	AllowExpiry           bool       `json:"allow_expiry,omitempty"`
	RenewalPrice          float64    `json:"renewal_price,omitempty"`
	DomainTransferLocked  bool       `json:"domain_transfer_locked,omitempty"`
	VerifyNSHealth        bool       `json:"verify_ns_health,omitempty"`
	CheckEmailSecurity    bool       `json:"check_email_security"`
	MailProvider          string     `json:"mail_provider"`
	MXRecords             []string   `json:"mx_records"`
	DKIMSelectors         []string   `json:"dkim_selectors"`
	DNSSEC                bool       `json:"dnssec"`
	CAA                   *CAAConfig `json:"caa,omitempty"`

	SuppressAlerts bool `json:"suppress_alerts"`
}

// CAAConfig specifies expected certificate-authority records.
type CAAConfig struct {
	Issue     []string `json:"issue,omitempty"`
	IssueWild []string `json:"issuewild,omitempty"`
	IssueMail []string `json:"issuemail,omitempty"`
}

// CAAResult contains the evaluated CAA records and their condition.
type CAAResult struct {
	Status     CheckStatus     `json:"status"`
	Condition  *StateCondition `json:"condition,omitempty"`
	Valid      bool            `json:"valid"`
	Issue      []string        `json:"issue,omitempty"`
	IssueWild  []string        `json:"issuewild,omitempty"`
	IssueMail  []string        `json:"issuemail,omitempty"`
	UnknownCAs []string        `json:"unknown_cas,omitempty"`
	Error      string          `json:"error,omitempty"`
}

// DNSTask defines a DNS record query and its expected values.
type DNSTask struct {
	domainCAA      bool       // Generated domain policy; omitted issuer tags are unconstrained.
	Hostname       string     `json:"hostname"`
	Name           string     `json:"name"`
	Type           string     `json:"type"`
	Expected       StringList `json:"expected"`
	MatchType      string     `json:"match_type,omitempty"`
	CustomResolver string     `json:"custom_resolver,omitempty"`
}

// HTTPDoer defines an interface for executing HTTP requests, allowing for mocking in tests.
type HTTPDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// Resolver defines an interface for executing DNS queries, allowing for mocking in tests.
type Resolver interface {
	ExchangeContext(ctx context.Context, m *dns.Msg, a string) (r *dns.Msg, rtt time.Duration, err error)
}

// WHOISQuerier defines an interface for executing WHOIS queries, allowing for mocking in tests.
type WHOISQuerier interface {
	Query(ctx context.Context, domain, server string) (string, error)
}

// AppState holds application configuration, notification manager, and atomic runtime state caches.
type AppState struct {
	config              AppConfig
	activeResolvers     []string
	Notifier            Notifier
	Pricing             *PricingManager
	LoopDuration        time.Duration
	PrerenderedJSON     atomic.Value
	GlobalResolverIndex atomic.Uint32

	Bootstrap      *Bootstrap
	HTTPClient     HTTPDoer
	DNSClient      Resolver
	DNSTCPClient   Resolver
	WHOISClient    WHOISQuerier
	WHOISDial      func(context.Context, string) (net.Conn, error)
	RDAPURLAllowed func(string) bool
	RDAPLimiter    *rate.Limiter

	EmailProviders map[string]ProviderConfig
}

// Config returns an independent copy of the startup configuration.
func (a *AppState) Config() AppConfig {
	return cloneConfig(a.configuration())
}

// configuration shares immutable startup data with internal read-only callers.
func (a *AppState) configuration() AppConfig {
	if a == nil {
		return AppConfig{}
	}
	return a.config
}

// Resolvers returns an independent copy of the startup resolver list.
func (a *AppState) Resolvers() []string {
	return slices.Clone(a.resolvers())
}

// resolvers shares an immutable list with internal callers, avoiding per-query copies.
func (a *AppState) resolvers() []string {
	if a != nil && len(a.activeResolvers) > 0 {
		return a.activeResolvers
	}
	if a != nil && len(a.config.Resolvers) > 0 {
		return a.config.Resolvers
	}
	return DefaultResolvers()
}

// NewAppState constructs an AppState with the provided AppConfig value.
func NewAppState(cfg AppConfig) *AppState {
	cfg = cloneConfig(cfg)
	resolvers := cfg.Resolvers
	if len(resolvers) == 0 {
		resolvers = DefaultResolvers()
	}
	return &AppState{
		config:          cfg,
		activeResolvers: resolvers,
		Notifier:        nil,
		Pricing:         NewPricingManager(nil),
		Bootstrap:       NewBootstrap(nil),
		LoopDuration:    time.Duration(cfg.LoopIntervalDays * HoursPerDay * float64(time.Hour)),
		RDAPLimiter:     rate.NewLimiter(rate.Every(RDAPRateLimitInterval), 1),
		WHOISDial:       dialPublicWHOIS,
		DNSClient:       &dns.Client{Timeout: DefaultDNSTimeout},
		DNSTCPClient:    &dns.Client{Net: ProtocolTCP, Timeout: DefaultDNSTimeout},
		RDAPURLAllowed:  IsSafeRDAPURL,
	}
}

func cloneConfig(cfg AppConfig) AppConfig {
	cfg.Resolvers = slices.Clone(cfg.Resolvers)
	cfg.Domains = slices.Clone(cfg.Domains)
	cfg.DNSRecords = slices.Clone(cfg.DNSRecords)
	if cfg.Notifications.Ntfy != nil {
		ntfy := *cfg.Notifications.Ntfy
		cfg.Notifications.Ntfy = &ntfy
	}
	if cfg.Notifications.Telegram != nil {
		telegram := *cfg.Notifications.Telegram
		cfg.Notifications.Telegram = &telegram
	}
	for i := range cfg.Domains {
		domain := &cfg.Domains[i]
		domain.ExpectedNS = slices.Clone(domain.ExpectedNS)
		domain.SecondaryNS = slices.Clone(domain.SecondaryNS)
		domain.MXRecords = slices.Clone(domain.MXRecords)
		domain.DKIMSelectors = slices.Clone(domain.DKIMSelectors)
		if domain.CAA != nil {
			caa := *domain.CAA
			caa.Issue = slices.Clone(caa.Issue)
			caa.IssueWild = slices.Clone(caa.IssueWild)
			caa.IssueMail = slices.Clone(caa.IssueMail)
			domain.CAA = &caa
		}
	}
	for i := range cfg.DNSRecords {
		cfg.DNSRecords[i].Expected = slices.Clone(cfg.DNSRecords[i].Expected)
	}
	return cfg
}

// SafeDispatch safely dispatches an alert via Notifier if both app and Notifier are non-nil,
// while always logging the alert message.
func (a *AppState) SafeDispatch(message, redacted string, priority AlertPriority, tag AlertTag, domain, name string) {
	if a == nil || a.Notifier == nil {
		switch priority {
		case PriorityUrgent, PriorityHigh:
			LogError(message, StrDomain2, domain, StrPriority, priority, StrTag, tag)
		case PriorityWarning:
			LogWarn(message, StrDomain2, domain, StrPriority, priority, StrTag, tag)
		default:
			LogInfo(message, StrDomain2, domain, StrPriority, priority, StrTag, tag)
		}
		return
	}
	a.Notifier.Dispatch(message, redacted, priority, tag, domain, name)
}

// 3. Domain & Check Result Models

// RDAPLink represents an RFC 9083 web link.
type RDAPLink struct {
	Rel  string `json:"rel,omitempty"`
	Href string `json:"href"`
	Type string `json:"type,omitempty"`
}

// RDAPEvent represents an RFC 9083 lifecycle event (registration, expiration, last-changed).
type RDAPEvent struct {
	Action string `json:"eventAction"`
	Date   string `json:"eventDate"`
}

// RDAPNameserver represents an RFC 9083 nameserver object.
type RDAPNameserver struct {
	LDHName string `json:"ldhName"`
}

// RDAPPublicID represents an RFC 9083 public identifier (e.g. IANA registrar ID).
type RDAPPublicID struct {
	Type       string `json:"type"`
	Identifier string `json:"identifier"`
}

// RDAPSecureDNS represents RFC 9083 DNSSEC status.
type RDAPSecureDNS struct {
	DelegationSigned *bool `json:"delegationSigned,omitempty"`
	ZoneSigned       *bool `json:"zoneSigned,omitempty"`
}

// RDAPEntity represents an RFC 9083 entity (registrar, registrant, reseller, etc.).
type RDAPEntity struct {
	Handle     string         `json:"handle,omitempty"`
	Roles      []string       `json:"roles,omitempty"`
	Port43     string         `json:"port43,omitempty"`
	PublicIDs  []RDAPPublicID `json:"publicIds,omitempty"`
	VCardArray []any          `json:"vcardArray,omitempty"`
	Links      []RDAPLink     `json:"links,omitempty"`
	Entities   []RDAPEntity   `json:"entities,omitempty"`
}

// RDAPDomainResponse represents an RFC 9083 domain object response.
type RDAPDomainResponse struct {
	ObjectClassName string           `json:"objectClassName,omitempty"`
	Handle          string           `json:"handle,omitempty"`
	LDHName         string           `json:"ldhName,omitempty"`
	UnicodeName     string           `json:"unicodeName,omitempty"`
	Status          []string         `json:"status,omitempty"`
	Events          []RDAPEvent      `json:"events,omitempty"`
	Nameservers     []RDAPNameserver `json:"nameservers,omitempty"`
	SecureDNS       *RDAPSecureDNS   `json:"secureDNS,omitempty"`
	Entities        []RDAPEntity     `json:"entities,omitempty"`
	Links           []RDAPLink       `json:"links,omitempty"`
}

// DomainTierData stores evidence from one registry or registrar response.
type DomainTierData struct {
	Source       string   `json:"source,omitempty"`
	Server       string   `json:"server,omitempty"`
	Registrar    string   `json:"registrar,omitempty"`
	IANAID       string   `json:"iana_id,omitempty"`
	Expiration   string   `json:"expiration,omitempty"`
	Created      string   `json:"created,omitempty"`
	Updated      string   `json:"updated,omitempty"`
	Nameservers  []string `json:"nameservers,omitempty"`
	DomainStatus []string `json:"domain_status,omitempty"`
	DNSSEC       bool     `json:"dnssec,omitempty"`
	Raw          string   `json:"-"`
}

// RDAPState stores evaluated registration evidence and renewal pricing.
type RDAPState struct {
	Status            CheckStatus     `json:"status"`
	Condition         *StateCondition `json:"condition,omitempty"`
	Registrar         string          `json:"registrar,omitempty"`
	RegistrarIANAID   string          `json:"registrar_iana_id,omitempty"`
	RegistrarMismatch bool            `json:"registrar_mismatch,omitempty"`
	ExpectedRegistrar string          `json:"expected_registrar,omitempty"`
	Expiration        string          `json:"expiration,omitempty"`
	Nameservers       []string        `json:"nameservers,omitempty"`
	DomainStatus      []string        `json:"domain_status,omitempty"`
	DNSSEC            bool            `json:"dnssec,omitempty"`
	RenewalPrice      float64         `json:"renewal_price,omitempty"`
	AllowExpiry       bool            `json:"allow_expiry,omitempty"`
	Error             string          `json:"error,omitempty"`
	IsDelegatedZone   bool            `json:"is_delegated_zone,omitempty"`
	Source            string          `json:"source,omitempty"`
	ProtocolUsed      string          `json:"protocol_used,omitempty"`
	RawResponsePath   string          `json:"raw_response_path,omitempty"`
	QueryDurationMs   int64           `json:"query_duration_ms,omitempty"`
	RegistryTier      *DomainTierData `json:"registry_tier,omitempty"`
	RegistrarTier     *DomainTierData `json:"registrar_tier,omitempty"`
	Discrepancies     []string        `json:"discrepancies,omitempty"`
}

// DNSState stores expected and observed DNS records with their verdict.
type DNSState struct {
	Hostname  string          `json:"hostname"`
	Name      string          `json:"name"`
	Type      string          `json:"type"`
	Expected  []string        `json:"expected"`
	Status    CheckStatus     `json:"status"`
	Condition *StateCondition `json:"condition,omitempty"`
	Found     []string        `json:"found,omitempty"`
	Error     string          `json:"error,omitempty"`
}

// EmailState stores evaluated MX, SPF, DMARC, and DKIM publication evidence.
type EmailState struct {
	Provider     string          `json:"provider,omitempty"`
	Status       CheckStatus     `json:"status"`
	Condition    *StateCondition `json:"condition,omitempty"`
	SPF          bool            `json:"spf,omitempty"`
	DMARC        bool            `json:"dmarc,omitempty"`
	DKIMExpected bool            `json:"dkim_expected,omitempty"`
	DKIMValid    []string        `json:"dkim_valid,omitempty"`
	MX           []string        `json:"mx,omitempty"`
	Error        string          `json:"error,omitempty"`
}

// DNSSECResult stores local cryptographic and upstream validation evidence.
type DNSSECResult struct {
	Status          CheckStatus     `json:"status"`
	Condition       *StateCondition `json:"condition,omitempty"`
	Valid           bool            `json:"valid"`
	HasDS           bool            `json:"has_ds"`
	HasDNSKEY       bool            `json:"has_dnskey"`
	DSMatchesDNSKEY bool            `json:"ds_matches_dnskey"`
	RRSIGValid      bool            `json:"rrsig_valid"`
	RRSIGExpiry     string          `json:"rrsig_expiry,omitempty"`
	ChainIntact     bool            `json:"chain_intact"`
	Algorithms      []string        `json:"algorithms,omitempty"`
	Source          string          `json:"source"`
	NetworkError    bool            `json:"network_error,omitempty"`
	Disabled        bool            `json:"disabled,omitempty"`
	Error           string          `json:"error,omitempty"`
}

// NSHealthServerResult stores the evaluation metrics for an individual authoritative nameserver.
type NSHealthServerResult struct {
	Nameserver    string `json:"nameserver"`
	IsPrimary     bool   `json:"is_primary"`
	Authoritative bool   `json:"authoritative"`
	HasSOA        bool   `json:"has_soa"`
	SOASerial     uint32 `json:"soa_serial,omitempty"`
	HasDNSKEY     bool   `json:"has_dnskey,omitempty"`
	DNSKEYMatch   bool   `json:"dnskey_match,omitempty"`
	Unreachable   bool   `json:"unreachable,omitempty"`
	Error         string `json:"error,omitempty"`
}

// NSHealthResult stores the aggregated nameserver health and dumb secondary replication status for a domain.
type NSHealthResult struct {
	Valid     bool                   `json:"valid"`
	Primary   string                 `json:"primary"`
	Status    CheckStatus            `json:"status"`
	Condition *StateCondition        `json:"condition,omitempty"`
	Servers   []NSHealthServerResult `json:"servers"`
}

// CheckState coordinates the per-cycle aggregated state across all checks.
type CheckState struct {
	RDAP        map[string]RDAPState      `json:"rdap_checks"`
	DNS         map[string]DNSState       `json:"dns_checks"`
	Email       map[string]EmailState     `json:"email_checks"`
	DNSSEC      map[string]DNSSECResult   `json:"dnssec_checks,omitempty"`
	NSHealth    map[string]NSHealthResult `json:"ns_health,omitempty"`
	CAA         map[string]*CAAResult     `json:"caa_checks,omitempty"`
	LastUpdated string                    `json:"last_updated"`
	NextRefresh string                    `json:"next_refresh"`
}

// DomainResult holds the evaluation results for a single domain.
type DomainResult struct {
	Domain   string
	RDAP     RDAPState
	Email    EmailState
	DNSSEC   DNSSECResult
	NSHealth NSHealthResult
	CAA      *CAAResult
}

// DNSResult holds the evaluation result for a single DNS task.
type DNSResult struct {
	Name  string
	State DNSState
}

// NewCheckState returns a fresh CheckState with all maps initialized.
func NewCheckState() *CheckState {
	return &CheckState{
		RDAP:     make(map[string]RDAPState),
		DNS:      make(map[string]DNSState),
		Email:    make(map[string]EmailState),
		DNSSEC:   make(map[string]DNSSECResult),
		NSHealth: make(map[string]NSHealthResult),
	}
}

// ApplyDNSResult stores an independent copy of a worker result in cycle-owned state.
func (c *CheckState) ApplyDNSResult(res DNSResult) {
	if c == nil || res.State.Status == StatusUnknown || res.Name == StrEmpty {
		return
	}
	res.State.Expected = slices.Clone(res.State.Expected)
	res.State.Found = slices.Clone(res.State.Found)
	res.State.Condition = clonePointer(res.State.Condition)
	InitMap(&c.DNS)[res.Name] = res.State
}

// ApplyDomainResult isolates all mutable worker data before storing it in cycle-owned state.
func (c *CheckState) ApplyDomainResult(res DomainResult) {
	if c == nil || res.Domain == StrEmpty {
		return
	}
	if res.RDAP.Status != StatusUnknown {
		InitMap(&c.RDAP)[res.Domain] = cloneRDAPState(res.RDAP)
	}
	if res.Email.Status != StatusUnknown {
		res.Email.Condition = clonePointer(res.Email.Condition)
		res.Email.MX = slices.Clone(res.Email.MX)
		res.Email.DKIMValid = slices.Clone(res.Email.DKIMValid)
		InitMap(&c.Email)[res.Domain] = res.Email
	}
	if res.DNSSEC.Source != StrEmpty || res.DNSSEC.Error != StrEmpty || res.DNSSEC.Valid {
		res.DNSSEC.Condition = clonePointer(res.DNSSEC.Condition)
		res.DNSSEC.Algorithms = slices.Clone(res.DNSSEC.Algorithms)
		InitMap(&c.DNSSEC)[res.Domain] = res.DNSSEC
	}
	if res.NSHealth.Status != StatusUnknown {
		res.NSHealth.Condition = clonePointer(res.NSHealth.Condition)
		res.NSHealth.Servers = slices.Clone(res.NSHealth.Servers)
		InitMap(&c.NSHealth)[res.Domain] = res.NSHealth
	}
	if res.CAA != nil {
		caa := *res.CAA
		caa.Condition = clonePointer(caa.Condition)
		caa.Issue = slices.Clone(caa.Issue)
		caa.IssueWild = slices.Clone(caa.IssueWild)
		caa.IssueMail = slices.Clone(caa.IssueMail)
		caa.UnknownCAs = slices.Clone(caa.UnknownCAs)
		InitMap(&c.CAA)[res.Domain] = &caa
	}
}

// clonePointer copies scalar-only pointed-to values; nested mutable fields need explicit cloning.
func clonePointer[T any](value *T) *T {
	if value == nil {
		return nil
	}
	copyValue := *value
	return &copyValue
}

func cloneDomainTier(tier *DomainTierData) *DomainTierData {
	cloned := clonePointer(tier)
	if cloned != nil {
		cloned.Nameservers = slices.Clone(cloned.Nameservers)
		cloned.DomainStatus = slices.Clone(cloned.DomainStatus)
	}
	return cloned
}

func cloneRDAPState(state RDAPState) RDAPState {
	state.Condition = clonePointer(state.Condition)
	state.Nameservers = slices.Clone(state.Nameservers)
	state.DomainStatus = slices.Clone(state.DomainStatus)
	state.Discrepancies = slices.Clone(state.Discrepancies)
	state.RegistryTier = cloneDomainTier(state.RegistryTier)
	state.RegistrarTier = cloneDomainTier(state.RegistrarTier)
	return state
}

// 7. Pipeline Snapshot Structs (Phase 2 Fetcher Outputs)

// RDAPSnapshot holds raw registry/registrar data fetched from RDAP or WHOIS.
// Fields mirror RDAPState for direct assembly.
type RDAPSnapshot struct {
	Registrar       string
	RegistrarIANAID string
	Expiration      string
	Nameservers     []string
	DomainStatus    []string
	DNSSEC          bool
	Source          string
	ProtocolUsed    string
	QueryDurationMs int64
	RegistryTier    *DomainTierData
	RegistrarTier   *DomainTierData
	Discrepancies   []string
	RawResponsePath string
	Err             error
}

// NSDelegationSnapshot holds raw nameserver records fetched from root/parent zones.
type NSDelegationSnapshot struct {
	Nameservers []string
	Err         error
}

// NSSnapshot holds raw data fetched from a single authoritative nameserver.
type NSSnapshot struct {
	Nameserver    string
	IsPrimary     bool
	Authoritative bool
	HasSOA        bool
	SOASerial     uint32
	HasDNSKEY     bool
	DNSKEYs       []string
	DNSKEYErr     error
	PartialError  error
	Unreachable   bool
	Err           error
}

// DNSSnapshot holds raw DNS query results for a single record check.
type DNSSnapshot struct {
	Records         []string
	ExpectedRecords []string
	Err             error
}

// EmailSnapshot holds raw email security DNS lookups.
type EmailSnapshot struct {
	MXRecords    []string
	SPFRecords   []string
	DMARCRecords []string
	DKIMResults  map[string]bool
	MXErr        error
	SPFErr       error
	DMARCErr     error
	DKIMErrs     map[string]error
}

// DNSSECSnapshot holds raw DNSSEC chain data.
type DNSSECSnapshot struct {
	Result DNSSECResult
}

// 4. Notification Models & Interfaces

// Alert represents a single notification event
type Alert struct {
	Message  string
	Redacted string

	Priority AlertPriority
	Tag      AlertTag
	Domain   string
	Name     string
}

// Notifier is the interface for dispatching alerts.
type Notifier interface {
	Dispatch(message, redacted string, priority AlertPriority, tag AlertTag, domain, name string)
	Flush()
}

// 5. External API & Response Payloads

type dnsRegistry struct {
	Services [][][]string `json:"services"`
}

type dohJSONResponse struct {
	Status   int  `json:"Status"`
	AD       bool `json:"AD"`
	Question []struct {
		Name string `json:"name"`
		Type int    `json:"type"`
	} `json:"Question"`
	Answer []struct {
		Name string `json:"name"`
		Type int    `json:"type"`
		Data string `json:"data"`
	} `json:"Answer"`
}

// 6. Concurrency & Network Infrastructure

// Bootstrap manages IANA RDAP bootstrap registry caches and queries.
type Bootstrap struct {
	http      HTTPDoer
	url       string
	mu        sync.RWMutex
	fetchMu   sync.Mutex
	services  map[string][]string
	fetchedAt time.Time
}

// DotSweepTLD represents individual TLD pricing returned by DotSweep.
type DotSweepTLD struct {
	TLD          string  `json:"tld"`
	Registration float64 `json:"registration,omitempty"`
	Renewal      float64 `json:"renewal,omitempty"`
	Vendor       string  `json:"vendor,omitempty"`
}

// DotSweepResponse represents the root JSON payload from DotSweep.
type DotSweepResponse struct {
	TLDs []DotSweepTLD `json:"tlds"`
}

// PricingManager caches TLD renewal prices and bounds stale-data retention.
type PricingManager struct {
	http    HTTPDoer
	url     string
	mu      sync.Mutex
	catalog *pricingCatalog
}

// pricingCatalog is immutable after construction; refreshes replace the entire catalog.
type pricingCatalog struct {
	prices    map[string]float64
	fetchedAt time.Time
}

func (c *pricingCatalog) price(tld string) (float64, bool) {
	price, ok := c.prices[tld]
	return price, ok
}

// NotificationManager sends alerts directly.
type NotificationManager struct {
	NtfyURL        string
	NtfyAuth       string
	TelegramToken  string
	TelegramChatID string

	// Dependencies for network/IO
	HTTPClient HTTPDoer

	mu         sync.Mutex
	alertBatch []Alert
}

// ConsoleHandler formats log records into human-readable lines without key=value syntax or source annotations.
type ConsoleHandler struct {
	w     io.Writer
	mu    *sync.Mutex
	attrs []string
}
