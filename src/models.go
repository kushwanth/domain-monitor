package main

import (
	"bytes"
	"context"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

// StringList is a slice of strings that unmarshals from either a single JSON string or an array of strings.
type StringList []string

func (s *StringList) UnmarshalJSON(data []byte) error {
	if s == nil {
		return errors.New(MsgErrNilStringListReceiver)
	}
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
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

// 1. Status & Priority Enums

// CheckStatus represents lifecycle status of a check
type CheckStatus string

// AlertPriority defines the urgency level of a notification alert
type AlertPriority string

// AlertTag defines the visual badge or emoji category for an alert
type AlertTag = string

// 2. Configuration Models

type CAAConfig struct {
	Issue     []string `json:"issue"`
	IssueWild []string `json:"issuewild"`
	IssueMail []string `json:"issuemail"`
}

type NtfyConfig struct {
	URL  string `json:"url"`
	Auth string `json:"auth"`
}

type TelegramConfig struct {
	Token  string `json:"token"`
	ChatID string `json:"chat_id"`
}

type Notifications struct {
	Ntfy     *NtfyConfig     `json:"ntfy"`
	Telegram *TelegramConfig `json:"telegram"`
}

type AppConfig struct {
	Port             string         `json:"port"`
	DataDir          string         `json:"data_dir,omitempty"`
	LoopIntervalDays float64        `json:"loop_interval_days"`
	Notifications    Notifications  `json:"notifications"`
	Resolvers        []string       `json:"resolvers"`
	DoHURL           string         `json:"doh_url,omitempty"`
	CTLogsAPIKey     string         `json:"ctlogs_api_key,omitempty"`
	Domains          []DomainConfig `json:"domains"`
	DNSRecords       []DNSTask      `json:"dns_records"`
}

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
	MonitorCTLogs         bool       `json:"monitor_ct_logs"`
	CAA                   *CAAConfig `json:"caa,omitempty"`
	AcceptSelfSigned      bool       `json:"accept_self_signed"`
	SuppressAlerts        bool       `json:"suppress_alerts"`
}

type DNSTask struct {
	Hostname         string     `json:"hostname"`
	Name             string     `json:"name"`
	Type             string     `json:"type"`
	Expected         StringList `json:"expected"`
	MatchType        string     `json:"match_type,omitempty"`
	CustomResolver   string     `json:"custom_resolver,omitempty"`
	AcceptSelfSigned bool       `json:"accept_self_signed,omitempty"`
	SkipSSL          bool       `json:"skip_ssl,omitempty"`
}

// AppState holds application configuration, notification manager, and atomic runtime state caches.
type AppState struct {
	config              AppConfig
	activeResolvers     []string
	Notifier            *NotificationManager
	Pricing             *PricingManager
	LoopDuration        time.Duration
	PrerenderedJSON     atomic.Value
	GlobalResolverIndex atomic.Uint32
}

// Config returns a value copy of the application configuration loaded at startup.
// Note: While the AppConfig struct is copied by value, callers must treat slice and pointer
// fields as read-only to preserve internal configuration integrity across cycles.
func (a *AppState) Config() AppConfig {
	if a == nil {
		return AppConfig{}
	}
	return a.config
}

// Resolvers returns the runtime verified DNS resolvers (or configured/default fallback).
func (a *AppState) Resolvers() []string {
	if a != nil && len(a.activeResolvers) > 0 {
		return slices.Clone(a.activeResolvers)
	}
	if a != nil && len(a.config.Resolvers) > 0 {
		return slices.Clone(a.config.Resolvers)
	}
	return slices.Clone(DefaultResolvers())
}

// NewAppState constructs an AppState with the provided AppConfig value.
func NewAppState(cfg AppConfig) *AppState {
	return &AppState{
		config:          cfg,
		activeResolvers: slices.Clone(cfg.Resolvers),
		Notifier:        &NotificationManager{},
		LoopDuration:    time.Duration(cfg.LoopIntervalDays * HoursPerDay * float64(time.Hour)),
	}
}

// SafeDispatch safely dispatches an alert via Notifier if both app and Notifier are non-nil,
// while always logging the alert message.
func (a *AppState) SafeDispatch(message, redacted string, priority AlertPriority, tag, domain, name string) {
	if a == nil || a.Notifier == nil {
		switch priority {
		case PriorityUrgent, PriorityHigh:
			LogError(message, "domain", domain, "priority", priority, "tag", tag)
		case PriorityWarning:
			LogWarn(message, "domain", domain, "priority", priority, "tag", tag)
		default:
			LogInfo(message, "domain", domain, "priority", priority, "tag", tag)
		}
		return
	}
	a.Notifier.Dispatch(message, redacted, priority, tag, domain, name)
}

// SafeDispatchf formats the full alert message and safely dispatches it via Notifier.
func (a *AppState) SafeDispatchf(priority AlertPriority, tag, domain, name, redacted, format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	a.SafeDispatch(msg, redacted, priority, tag, domain, name)
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
	Handle      string           `json:"handle,omitempty"`
	LDHName     string           `json:"ldhName,omitempty"`
	Status      []string         `json:"status,omitempty"`
	Events      []RDAPEvent      `json:"events,omitempty"`
	Nameservers []RDAPNameserver `json:"nameservers,omitempty"`
	SecureDNS   *RDAPSecureDNS   `json:"secureDNS,omitempty"`
	Entities    []RDAPEntity     `json:"entities,omitempty"`
	Links       []RDAPLink       `json:"links,omitempty"`
}

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

type RDAPState struct {
	Status            CheckStatus     `json:"status"`
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

type DNSState struct {
	Hostname string      `json:"hostname"`
	Name     string      `json:"name"`
	Type     string      `json:"type"`
	Expected []string    `json:"expected"`
	Status   CheckStatus `json:"status"`
	Found    []string    `json:"found,omitempty"`
	SSLDays  int         `json:"ssl_days,omitempty"`
	SkipSSL  bool        `json:"skip_ssl,omitempty"`
	Error    string      `json:"error,omitempty"`
}

type EmailState struct {
	Provider     string      `json:"provider,omitempty"`
	Status       CheckStatus `json:"status"`
	SPF          bool        `json:"spf,omitempty"`
	DMARC        bool        `json:"dmarc,omitempty"`
	DKIMExpected bool        `json:"dkim_expected,omitempty"`
	DKIMValid    []string    `json:"dkim_valid,omitempty"`
	MX           []string    `json:"mx,omitempty"`
	Error        string      `json:"error,omitempty"`
}

type CAAEntry struct {
	Flag  uint8
	Tag   string
	Value string
}

type CAAResult struct {
	Valid      bool     `json:"valid"`
	Issue      []string `json:"issue"`
	IssueWild  []string `json:"issuewild"`
	IssueMail  []string `json:"issuemail"`
	UnknownCAs []string `json:"unknown_cas,omitempty"`
	Error      string   `json:"error,omitempty"`
}

type DNSSECResult struct {
	Valid           bool     `json:"valid"`
	HasDS           bool     `json:"has_ds"`
	HasDNSKEY       bool     `json:"has_dnskey"`
	DSMatchesDNSKEY bool     `json:"ds_matches_dnskey"`
	RRSIGValid      bool     `json:"rrsig_valid"`
	RRSIGExpiry     string   `json:"rrsig_expiry,omitempty"`
	ChainIntact     bool     `json:"chain_intact"`
	Algorithms      []string `json:"algorithms,omitempty"`
	Source          string   `json:"source"`
	Error           string   `json:"error,omitempty"`
}

type CTCert struct {
	ID        string `json:"id"`
	Match     string `json:"match"`
	Issuer    string `json:"issuer"`
	NotBefore string `json:"not_before"`
	NotAfter  string `json:"not_after"`
}

type CTLogState struct {
	LatestID         string      `json:"latest_id"`
	BackfillCursor   string      `json:"backfill_cursor"`
	BackfillComplete bool        `json:"backfill_complete"`
	Status           CheckStatus `json:"status"`
	Error            string      `json:"error,omitempty"`
}

// NSHealthServerResult stores the evaluation metrics for an individual authoritative nameserver.
type NSHealthServerResult struct {
	Nameserver    string `json:"nameserver"`
	IsPrimary     bool   `json:"is_primary"`
	Authoritative bool   `json:"authoritative"`
	SOASerial     uint32 `json:"soa_serial,omitempty"`
	HasDNSKEY     bool   `json:"has_dnskey,omitempty"`
	DNSKEYMatch   bool   `json:"dnskey_match,omitempty"`
	Error         string `json:"error,omitempty"`
}

// NSHealthResult stores the aggregated nameserver health and dumb secondary replication status for a domain.
type NSHealthResult struct {
	Valid   bool                   `json:"valid"`
	Primary string                 `json:"primary"`
	Servers []NSHealthServerResult `json:"servers"`
	Error   string                 `json:"error,omitempty"`
}

// CheckState coordinates the per-cycle aggregated state across all checks.
type CheckState struct {
	RDAP        map[string]*RDAPState      `json:"rdap_checks"`
	DNS         map[string]*DNSState       `json:"dns_checks"`
	Email       map[string]*EmailState     `json:"email_checks"`
	CAA         map[string]*CAAResult      `json:"caa_checks,omitempty"`
	DNSSEC      map[string]*DNSSECResult   `json:"dnssec_checks,omitempty"`
	CTLogs      map[string]*CTLogState     `json:"ct_logs,omitempty"`
	NSHealth    map[string]*NSHealthResult `json:"ns_health,omitempty"`
	LastUpdated string                     `json:"last_updated"`
	NextRefresh string                     `json:"next_refresh"`
}

// DomainResult holds the evaluation results for a single domain.
type DomainResult struct {
	Domain   string
	RDAP     *RDAPState
	Email    *EmailState
	CAA      *CAAResult
	DNSSEC   *DNSSECResult
	CTLogs   *CTLogState
	NSHealth *NSHealthResult
}

// DNSResult holds the evaluation result for a single DNS task.
type DNSResult struct {
	Name  string
	State *DNSState
}

func (c *CheckState) ExportCTLogs() map[string]*CTLogState {
	if c == nil {
		return make(map[string]*CTLogState)
	}
	return CopyMap(c.CTLogs)
}

// ApplyDNSResult safely incorporates an individual DNS check result into the state.
func (c *CheckState) ApplyDNSResult(res DNSResult) {
	if c == nil || res.State == nil || res.Name == "" {
		return
	}
	InitMap(&c.DNS)[res.Name] = res.State
}

// ApplyDomainResult safely incorporates an individual domain check result into the state.
func (c *CheckState) ApplyDomainResult(res DomainResult) {
	if c == nil || res.Domain == "" {
		return
	}
	if res.RDAP != nil {
		InitMap(&c.RDAP)[res.Domain] = res.RDAP
	}
	if res.Email != nil {
		InitMap(&c.Email)[res.Domain] = res.Email
	}
	if res.CAA != nil {
		InitMap(&c.CAA)[res.Domain] = res.CAA
	}
	if res.DNSSEC != nil {
		InitMap(&c.DNSSEC)[res.Domain] = res.DNSSEC
	}
	if res.CTLogs != nil {
		InitMap(&c.CTLogs)[res.Domain] = res.CTLogs
	}
	if res.NSHealth != nil {
		InitMap(&c.NSHealth)[res.Domain] = res.NSHealth
	}
}

// 4. Notification Models & Interfaces

// Alert represents a single notification event
type Alert struct {
	Message  string
	Redacted string
	Priority AlertPriority
	Tag      string
	Domain   string
	Name     string
}

// NotificationProvider interface allows expansion to Ntfy, Telegram, Slack, etc.
type NotificationProvider interface {
	Send(ctx context.Context, alerts []Alert, wg *sync.WaitGroup)
}

// NotificationManager handles broadcasting to all configured notification providers.
type NotificationManager struct {
	Providers     []NotificationProvider
	Buffer        []Alert
	mu            sync.Mutex
	wg            sync.WaitGroup
	sentState     map[string]time.Time
	seenThisCycle map[string]bool
}

type NtfyProvider struct {
	URL  string
	Auth string
}

type TelegramProvider struct {
	Token  string
	ChatID string
}

// 5. External API & Response Payloads

type ctLogsPageResponse struct {
	Rows       []CTCert `json:"rows"`
	HasNext    bool     `json:"has_next"`
	NextCursor string   `json:"next_cursor"`
}

type dnsRegistry struct {
	Services [][][]string `json:"services"`
}

type dohJSONResponse struct {
	Status int  `json:"Status"`
	AD     bool `json:"AD"`
}

type queryResult struct {
	raw string
	err error
}

// 6. Concurrency & Network Infrastructure

// Bootstrap manages IANA RDAP bootstrap registry caches and queries.
type Bootstrap struct {
	http      *http.Client
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

// PricingManager manages TLD renewal pricing cache and scheduled upstream fetching.
type PricingManager struct {
	http      *http.Client
	url       string
	mu        sync.RWMutex
	fetchMu   sync.Mutex
	prices    map[string]float64
	fetchedAt time.Time
}

// ConsoleHandler formats log records into human-readable lines without key=value syntax or source annotations.
type ConsoleHandler struct {
	w     io.Writer
	mu    *sync.Mutex
	attrs []string
}

// ChunkData represents a chunk of alert notifications.
type ChunkData struct {
	text     string
	priority AlertPriority
	tags     []string
}
