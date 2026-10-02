package monitor

import (
	"errors"
	"regexp"
	"slices"
	"time"
)

// System & Default Paths and Files
const (
	DefaultConfigFile        = "config.json"
	DefaultEmailProvidersDir = "data/email_providers"
	InternalCAATaskPrefix    = "__caa__"
	DefaultServerPort        = "8080"
	DefaultDNSPort           = "53"
	DefaultDoHURL            = "https://dns.google/resolve"
	JSONFileExtension        = ".json"
	ValidationDomainSuffix   = ".example"

	DefaultUserAgent         = "DomainMonitor/1.0 (+https://github.com/domain-monitor)"
	MaxConfigFileSize        = 8 << 20 // 8 MB
	MaxBootstrapResponseSize = 8 << 20 // 8 MB

	MaxNotificationPayloadSize   = 1 << 20  // 1 MB
	MaxPricingResponseSize       = 5 << 20  // 5 MB
	MaxEmailProviderResponseSize = 64 << 10 // 64 KB
)

// Standard Timeouts & Intervals
const (
	DefaultDNSTimeout            = 5 * time.Second
	DefaultHTTPTimeout           = 10 * time.Second
	DefaultExpectContinueTimeout = time.Second
	PricingCacheTTL              = 24 * time.Hour
	PricingMaxStaleAge           = 7 * 24 * time.Hour
	DefaultWHOISTimeout          = 10 * time.Second
	DefaultWHOISQueryTimeout     = 15 * time.Second
	MaxWHOISResponseBytes        = 1 << 20
	DefaultTCPKeepAlive          = 30 * time.Second
	ShutdownTimeout              = 5 * time.Second
	DefaultLoopDurationFallback  = 6 * time.Hour
	RDAPRateLimitInterval        = 10 * time.Second
)

// WHOIS transport protocol and known server aliases.
const (
	WHOISPort              = "43"
	WHOISIANAHost          = "whois.iana.org"
	WHOISIANAReferralField = "refer"
	WHOISIANAWHOISField    = "whois"
	WHOISARINHost          = "whois.arin.net"
	WHOISARINPrefix        = "n + "
	WHOISGoDaddyAlias      = "whois.godaddy"
	WHOISGoDaddyHost       = "whois.godaddy.com"
	WHOISPorkbunAlias      = "porkbun.com/whois"
	WHOISPorkbunHost       = "whois.porkbun.com"
)

// System Thresholds & Limits
const (
	MaxRedirects                      = 10
	MaxResolversLimit                 = 9
	MaxCNAMEAliasTraversals           = 5
	DefaultRDAPExpiryWarningDays      = 30
	AutoRenewGracePeriodThresholdDays = 45.0
	DefaultLoopIntervalDays           = 0.25
	MinLoopIntervalDays               = 0.125
	MaxLoopIntervalDays               = 365.0
	MaxBodyDrainSize                  = 4096
	MaxAlertMessageRunes              = 1000
	MaxProviderMessageBytes           = 3500
	MaxTelegramAlertRunes             = 400
	MaxAlertNameRunes                 = 80
	MaxCycleReportItems               = 64
	MaxFindingsPerCheck               = 16
	AlertTruncationNotice             = " [truncated; see local state]"
	HoursPerDay                       = 24
)

// Environment Variable Keys
const (
	EnvConfigPath     = "CONFIG_PATH"
	EnvPort           = "PORT"
	EnvDoHURL         = "DOH_URL"
	EnvNtfyAuth       = "NTFY_AUTH"
	EnvTelegramToken  = "TELEGRAM_TOKEN"
	EnvTelegramChatID = "TELEGRAM_CHAT_ID"
)

// HTTP Constants
const (
	DotSweepAPIEndpoint = "https://dotsweep.com/tlds"
)

// HTTP Headers & Media Types
const (
	HeaderContentType           = "Content-Type"
	HeaderCacheControl          = "Cache-Control"
	HeaderETag                  = "ETag"
	HeaderIfNoneMatch           = "If-None-Match"
	HeaderRetryAfter            = "Retry-After"
	HeaderUserAgent             = "User-Agent"
	HeaderAuthorization         = "Authorization"
	HeaderAccept                = "Accept"
	HeaderNtfyTitle             = "Title"
	HeaderNtfyPriority          = "Priority"
	HeaderNtfyTags              = "Tags"
	HeaderReportID              = "X-Domain-Monitor-Report-ID"
	HeaderXContentTypeOptions   = "X-Content-Type-Options"
	HeaderXFrameOptions         = "X-Frame-Options"
	HeaderReferrerPolicy        = "Referrer-Policy"
	HeaderXXSSProtection        = "X-XSS-Protection"
	HeaderContentSecurityPolicy = "Content-Security-Policy"

	MIMEApplicationJSON        = "application/json"
	AcceptRDAP                 = "application/rdap+json, application/json"
	MIMETextHTML               = "text/html; charset=utf-8"
	CacheControlNoCache        = "no-cache"
	XContentTypeOptionsNosniff = "nosniff"
	XFrameOptionsDeny          = "DENY"
	ReferrerPolicyStrictOrigin = "strict-origin-when-cross-origin"
	XXSSProtectionZero         = "0"
	DefaultCSP                 = "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'self'; form-action 'self';"

	TelegramParseModeHTML = "HTML"

	RedactedDomainPlaceholder = "[Hidden Domain]"
	RedactedAuthPlaceholder   = "[REDACTED_AUTH]"
	RedactedTokenPlaceholder  = "[REDACTED_TELEGRAM_TOKEN]" // #nosec G101 -- redaction marker, not a credential.
	NotificationAlertTitle    = "Domain Monitor Alert"

	PrefixHTTP      = "http://"
	PrefixHTTPS     = "https://"
	SchemeHTTPSName = "https"
)

// External API Endpoints
const (
	BootstrapURL        = "https://data.iana.org/rdap/dns.json"
	BootstrapTTL        = 24 * time.Hour
	BootstrapMaxAge     = 72 * time.Hour
	MaxNetworkAttempts  = 3
	HTTPRetryBaseDelay  = 500 * time.Millisecond
	DNSRetryBaseDelay   = 100 * time.Millisecond
	WHOISRetryBaseDelay = 2 * time.Second
	MaxRetryDelay       = 30 * time.Second

	TelegramAPIBase              = "https://api.telegram.org/bot"
	TelegramAPISendMessageSuffix = "/sendMessage"
)

// Notification Alert Tags (Icons / Emojis)
const (
	TagSkull AlertTag = "skull"
)

// DNS Record Types
const (
	RecordTypeA               = "A"
	RecordTypeAAAA            = "AAAA"
	RecordTypeCNAME           = "CNAME"
	RecordTypeMX              = "MX"
	RecordTypeTXT             = "TXT"
	RecordTypeCAA             = "CAA"
	RecordTypeNS              = "NS"
	RecordTypeIP              = "IP"
	RecordTypeALIAS           = "ALIAS"
	CAATagIssue               = "issue"
	CAATagIssueWild           = "issuewild"
	CAATagIssueMail           = "issuemail"
	CAARecordIssueFormat      = `0 issue "%s"`
	CAARecordIssueWildFormat  = `0 issuewild "%s"`
	CAARecordIssueMailFormat  = `0 issuemail "%s"`
	CAARecordIssueDenyAll     = `0 issue ";"`
	CAARecordIssueWildDenyAll = `0 issuewild ";"`
	CAARecordIssueMailDenyAll = `0 issuemail ";"`
)

// DNS Match Types
const (
	MatchExact    = "exact"
	MatchPrefix   = "prefix"
	MatchContains = "contains"
	MatchAnyOf    = "any_of"
)

// Email Security & Protocol Sentinels
const (
	SPFPrefix             = "v=spf1"
	DMARCVersion          = "DMARC1"
	DKIMVersion           = "DKIM1"
	DNSPolicyTagVersion   = "v"
	DNSPolicyTagP         = "p"
	DKIMTagKeyType        = "k"
	DKIMKeyTypeRSA        = "rsa"
	DKIMKeyTypeEd25519    = "ed25519"
	DMARCPolicyNone       = "none"
	DMARCPolicyQuarantine = "quarantine"
	DMARCPolicyReject     = "reject"
	NullMXRecord          = "."
)

// DNSSEC Source Constants
const (
	DNSSECSourceLocalOnly = "local_only"
	DNSSECSourceLocalDoH  = "local+doh"
)

// Protocols
const (
	ProtocolRDAP        = "rdap"
	ProtocolWHOIS       = "whois"
	ProtocolWHOISFailed = "whois_failed"
	ProtocolTCP         = "tcp"
	WHOISDNSSECSigned   = "signed"
	WHOISDNSSECYes      = "yes"
	WHOISDNSSECActive   = "active"
	WHOISDNSSECTrue     = "true"
)

// RDAP & WHOIS Data Sources
const (
	SourceRegistryRDAP   = "registry_rdap"
	SourceRegistrarRDAP  = "registrar_rdap"
	SourceRegistryWHOIS  = "registry_whois"
	SourceRegistrarWHOIS = "registrar_whois"
	SourceWHOIS          = "whois"
	SourceWHOIS404       = "whois_404"
	SourceReferral       = "referral"
	SourceRegistry       = "registry"
	SourceDNSDelegation  = "dns_delegation"
)

// RDAP Roles, Link Relations & VCard Properties
const (
	RoleRegistrar       = "registrar"
	RoleSponsor         = "sponsor"
	RoleReseller        = "reseller"
	RelRelated          = "related"
	RelAlternate        = "alternate"
	ContentTypeRDAPJSON = "rdap+json"
	VCardPropFN         = "fn"
	VCardPropOrg        = "org"
	PublicIDTypeIANA    = "iana"
)

const (
	StatusUnknown CheckStatus = iota
	StatusPending
	StatusOK
	StatusFailed
	StatusMismatch
	StatusWarning
	StatusHijacked
	StatusSkipped
)

const (
	PriorityDefault AlertPriority = iota
	PriorityWarning
	PriorityHigh
	PriorityUrgent
)

var checkStatusNames = [...]string{"", "pending", "ok", "failed", "mismatch", "warning", "hijacked", "skipped"}
var alertPriorityNames = [...]string{"default", "warning", "high", "urgent"}
var findingSeverityNames = [...]string{"info", "warning", "error"}

const (
	CyclePhaseIdle         = "idle"
	CyclePhaseInitializing = "initializing"
	CycleOutcomeFailed     = "failed"
	CycleOutcomeSuccess    = "success"
)

const (
	CodeNone ResultCode = iota

	// RDAP / WHOIS
	CodeRDAPSuccess
	CodeWHOISSuccess
	CodeDomainNotFound
	CodeRDAPHTTPError
	CodeWHOISParsingFailed
	CodeEPPServerHold
	CodeEPPClientHold
	CodeEPPPendingDelete
	CodeEPPRedemptionPeriod
	CodeEPPInactive
	CodeRDAPExpired
	CodeRDAPExpiringSoon
	CodeRDAPExpiryUnavailable
	CodeRDAPRegistrarMismatch
	CodeRDAPTransferUnlocked
	CodeRDAPSuspended

	// NS Health
	CodeNSSyncVerified
	CodeNSUnreachable
	CodeNSNotAuthoritative
	CodeNSMissingSOA
	CodeNSSOAMismatch
	CodeNSDNSKEYMismatch
	CodeExpectedNSMissing
	CodeUnauthorizedNS
	CodeNSHiddenExposed

	// DNS Records
	CodeDNSMatchVerified
	CodeDNSMismatch
	CodeDNSLookupFailed
	CodeDNSServerError
	CodeDNSPrefixMismatch
	CodeDNSSubstringMismatch

	// Email Security
	CodeEmailVerified
	CodeEmailMissingMX
	CodeEmailUnauthorizedMX
	CodeEmailHijackedMX
	CodeEmailMissingSPF
	CodeEmailMultipleSPF
	CodeEmailMissingDMARC
	CodeEmailMultipleDMARC
	CodeEmailMissingDKIM
	CodeMXQueryFailed
	CodeNoMXRecords
	CodeSPFLookupFailed
	CodeDMARCLookupFailed
	CodeDKIMLookupFailed

	// DNSSEC
	CodeDNSSECVerified
	CodeDNSSECNetworkError
	CodeDNSSECDisabled
	CodeDNSSECNoDS
	CodeDNSSECNoDNSKEY
	CodeDNSSECDSMismatch
	CodeDNSSECRRSIGFailed
	CodeDNSSECChainBroken

	// CAA
	CodeCAAVerified
	CodeCAAQueryFailed
	CodeCAAMissingDenyAll
	CodeCAAUnexpectedIssuer
	CodeCAAMissingIssuer

	// Reserved legacy CT codes preserve published numeric values.
	CodeCTLogsVerified
	CodeCTLogsRateLimited
	CodeCTLogsHTTPError
	CodeCTPersistenceFailed
	CodeCTCoverageIncomplete

	// App-level
	CodeCheckTimeout
	CodeCheckPanic
	// Append new codes here to preserve existing numeric values in published state.
	CodeEmailInvalidNullMX
)

// resultCodeNames maps compact numeric codes to readable diagnostic names.
var resultCodeNames = [...]string{
	CodeNone: "",

	// RDAP / WHOIS
	CodeRDAPSuccess:           "rdapSuccess",
	CodeWHOISSuccess:          "whoisSuccess",
	CodeDomainNotFound:        "domainNotFound",
	CodeRDAPHTTPError:         "rdapHttpError",
	CodeWHOISParsingFailed:    "whoisParsingFailed",
	CodeEPPServerHold:         "serverHold",
	CodeEPPClientHold:         "clientHold",
	CodeEPPPendingDelete:      "pendingDelete",
	CodeEPPRedemptionPeriod:   "redemptionPeriod",
	CodeEPPInactive:           "inactive",
	CodeRDAPExpired:           "rdapExpired",
	CodeRDAPExpiringSoon:      "rdapExpiringSoon",
	CodeRDAPExpiryUnavailable: "rdapExpiryUnavailable",
	CodeRDAPRegistrarMismatch: "rdapRegistrarMismatch",
	CodeRDAPTransferUnlocked:  "rdapTransferUnlocked",
	CodeRDAPSuspended:         "rdapSuspended",

	// NS Health
	CodeNSSyncVerified:     "nsSyncVerified",
	CodeNSUnreachable:      "nsUnreachable",
	CodeNSNotAuthoritative: "nsNotAuthoritative",
	CodeNSMissingSOA:       "nsMissingSoa",
	CodeNSSOAMismatch:      "nsSoaMismatch",
	CodeNSDNSKEYMismatch:   "nsDnskeyMismatch",
	CodeExpectedNSMissing:  "expectedNsMissing",
	CodeUnauthorizedNS:     "unauthorizedNs",
	CodeNSHiddenExposed:    "nsHiddenExposed",

	// DNS Records
	CodeDNSMatchVerified:     "dnsMatchVerified",
	CodeDNSMismatch:          "dnsMismatch",
	CodeDNSLookupFailed:      "dnsLookupFailed",
	CodeDNSServerError:       "dnsServerError",
	CodeDNSPrefixMismatch:    "dnsPrefixMismatch",
	CodeDNSSubstringMismatch: "dnsSubstringMismatch",

	// Email Security
	CodeEmailVerified:       "emailVerified",
	CodeEmailMissingMX:      "emailMissingMx",
	CodeEmailUnauthorizedMX: "emailUnauthorizedMx",
	CodeEmailInvalidNullMX:  "emailInvalidNullMx",
	CodeEmailHijackedMX:     "emailHijackedMx",
	CodeEmailMissingSPF:     "emailMissingSpf",
	CodeEmailMultipleSPF:    "emailMultipleSpf",
	CodeEmailMissingDMARC:   "emailMissingDmarc",
	CodeEmailMultipleDMARC:  "emailMultipleDmarc",
	CodeEmailMissingDKIM:    "emailMissingDkim",
	CodeMXQueryFailed:       "mxQueryFailed",
	CodeNoMXRecords:         "noMxRecords",
	CodeSPFLookupFailed:     "spfLookupFailed",
	CodeDMARCLookupFailed:   "dmarcLookupFailed",
	CodeDKIMLookupFailed:    "dkimLookupFailed",

	// DNSSEC
	CodeDNSSECVerified:     "dnssecVerified",
	CodeDNSSECNetworkError: "dnssecNetworkError",
	CodeDNSSECDisabled:     "dnssecDisabled",
	CodeDNSSECNoDS:         "dnssecNoDs",
	CodeDNSSECNoDNSKEY:     "dnssecNoDnskey",
	CodeDNSSECDSMismatch:   "dnssecDsMismatch",
	CodeDNSSECRRSIGFailed:  "dnssecRrsigFailed",
	CodeDNSSECChainBroken:  "dnssecChainBroken",

	// CAA
	CodeCAAVerified:         "caaVerified",
	CodeCAAQueryFailed:      "caaQueryFailed",
	CodeCAAMissingDenyAll:   "caaMissingDenyAll",
	CodeCAAUnexpectedIssuer: "caaUnexpectedIssuer",
	CodeCAAMissingIssuer:    "caaMissingIssuer",

	CodeCTPersistenceFailed:  "ctPersistenceFailed",
	CodeCTCoverageIncomplete: "ctCoverageIncomplete",

	// App-level
	CodeCheckTimeout: "checkTimeout",
	CodeCheckPanic:   "checkPanic",
}

// System Errors
var (
	ErrDNSResolution     = errors.New("dns resolution failed")
	ErrNXDOMAIN          = errors.New("no such host (NXDOMAIN)")
	ErrSERVFAIL          = errors.New("server failure (SERVFAIL)")
	ErrRDAPNotFound      = errors.New("RDAP domain not found (404)")
	ErrRDAPRateLimited   = errors.New("RDAP rate limited (429)")
	ErrWHOISRateLimited  = errors.New("whois rate limited (429)")
	ErrDomainNotFound    = errors.New("domain not found in whois (404)")
	ErrNoResolvers       = errors.New("no resolvers configured")
	ErrEmptyDNSResponse  = errors.New("empty dns response")
	ErrEmptyHTTPResponse = errors.New("empty HTTP response")
	ErrHTTPClientNil     = errors.New("HTTP client is nil")
	ErrInvalidNullMX     = errors.New("invalid null MX record")
	ErrReadLimitExceeded = errors.New("read limit exceeded")

	ErrRestrictedIP           = errors.New("connection to restricted IP blocked (SSRF)")
	ErrBootstrapClientNil     = errors.New("bootstrap client is nil")
	ErrNoRDAPServer           = errors.New("no rdap server found")
	ErrEmptyDate              = errors.New("empty date string")
	ErrEmptyBootstrapRegistry = errors.New("empty bootstrap registry")
)

// Compact domain statuses from RFC 5731, RGP (RFC 3915), and generic RDAP evidence.
const (
	EPPUnknown EPPCode = iota
	EPPOK
	EPPInactive
	EPPClientHold
	EPPServerHold
	EPPClientTransferProhibited
	EPPServerTransferProhibited
	EPPClientDeleteProhibited
	EPPServerDeleteProhibited
	EPPClientUpdateProhibited
	EPPServerUpdateProhibited
	EPPClientRenewProhibited
	EPPServerRenewProhibited
	EPPPendingCreate
	EPPPendingDelete
	EPPPendingRenew
	EPPPendingTransfer
	EPPPendingUpdate
	EPPRedemptionPeriod
	EPPPendingRestore
	EPPAddPeriod
	EPPAutoRenewPeriod
	EPPRenewPeriod
	EPPTransferPeriod
	EPPTransferProhibited
	EPPHold
)

var eppCodeKeys = [...]string{
	EPPUnknown:                  "",
	EPPOK:                       "ok",
	EPPInactive:                 "inactive",
	EPPClientHold:               "clienthold",
	EPPServerHold:               "serverhold",
	EPPClientTransferProhibited: "clienttransferprohibited",
	EPPServerTransferProhibited: "servertransferprohibited",
	EPPClientDeleteProhibited:   "clientdeleteprohibited",
	EPPServerDeleteProhibited:   "serverdeleteprohibited",
	EPPClientUpdateProhibited:   "clientupdateprohibited",
	EPPServerUpdateProhibited:   "serverupdateprohibited",
	EPPClientRenewProhibited:    "clientrenewprohibited",
	EPPServerRenewProhibited:    "serverrenewprohibited",
	EPPPendingCreate:            "pendingcreate",
	EPPPendingDelete:            "pendingdelete",
	EPPPendingRenew:             "pendingrenew",
	EPPPendingTransfer:          "pendingtransfer",
	EPPPendingUpdate:            "pendingupdate",
	EPPRedemptionPeriod:         "redemptionperiod",
	EPPPendingRestore:           "pendingrestore",
	EPPAddPeriod:                "addperiod",
	EPPAutoRenewPeriod:          "autorenewperiod",
	EPPRenewPeriod:              "renewperiod",
	EPPTransferPeriod:           "transferperiod",
	EPPTransferProhibited:       "transferprohibited",
	EPPHold:                     "hold",
}

// eppStatusMap maps raw or formatted EPP/RDAP tokens to canonical camelCase strings.
var eppStatusMap = map[string]string{
	"clienttransferprohibited": "clientTransferProhibited",
	"servertransferprohibited": "serverTransferProhibited",
	"transferprohibited":       "transferProhibited",
	"clientupdateprohibited":   "clientUpdateProhibited",
	"serverupdateprohibited":   "serverUpdateProhibited",
	"updateprohibited":         "updateProhibited",
	"clientdeleteprohibited":   "clientDeleteProhibited",
	"serverdeleteprohibited":   "serverDeleteProhibited",
	"deleteprohibited":         "deleteProhibited",
	"clientrenewprohibited":    "clientRenewProhibited",
	"serverrenewprohibited":    "serverRenewProhibited",
	"renewprohibited":          "renewProhibited",
	"clienthold":               "clientHold",
	"serverhold":               "serverHold",
	"hold":                     "hold",
	"pendingcreate":            "pendingCreate",
	"pendingdelete":            "pendingDelete",
	"pendingrenew":             "pendingRenew",
	"pendingrestore":           "pendingRestore",
	"pendingtransfer":          "pendingTransfer",
	"pendingupdate":            "pendingUpdate",
	"redemptionperiod":         "redemptionPeriod",
	"addperiod":                "addPeriod",
	"autorenewperiod":          "autoRenewPeriod",
	"renewperiod":              "renewPeriod",
	"transferperiod":           "transferPeriod",
	"inactive":                 "inactive",
	"active":                   "active",
	"ok":                       "ok",
	"validated":                "validated",
	"associated":               "associated",
	"notassociated":            "notAssociated",
	"connected":                "active",
}

// timezoneOffsets maps common global registrar and WHOIS timezone abbreviations to ISO numeric offsets.
var timezoneOffsets = map[string]string{
	" UTC":  " +0000",
	" GMT":  " +0000",
	" Z":    " +0000",
	" EDT":  " -0400",
	" EST":  " -0500",
	" CDT":  " -0500",
	" CST":  " -0600",
	" MDT":  " -0600",
	" MST":  " -0700",
	" PDT":  " -0700",
	" PST":  " -0800",
	" JST":  " +0900",
	" KST":  " +0900",
	" AEST": " +1000",
	" AEDT": " +1100",
	" CET":  " +0100",
	" CEST": " +0200",
	" BST":  " +0100",
}

// whoisNotFoundIndicators lists indicators across global registrars and registries denoting an unregistered domain.
var whoisNotFoundIndicators = []string{
	"no match for",
	"not found",
	"status: free",
	"status: available",
	"status: not registered",
	"status: unregistered",
	"is free",
	"is available",
	"domain is free",
	"domain not found",
	"domain name not found",
	"not found in whois",
	"no data found",
	"domain not registered",
	"domain not registered in",
	"no entries found",
	"the queried object does not exist",
	"is available for registration",
	"no matching record",
	"domain unknown",
	"nothing found",
	"object does not exist",
	"not registered",
	"no information was found",
	"el dominio no existe",
	"not exist",
}

// whoisRateLimitIndicators lists indicators across WHOIS servers denoting query rate-limiting.
var whoisRateLimitIndicators = []string{
	"limit exceeded",
	"query limit exceeded",
	"too many requests",
	"quota exceeded",
	"access denied",
	"connection reset by peer",
	"exceeded your access quota",
	"lookup quota exceeded",
	"rate limit",
	"rate-limit",
}

// Precompiled Regular Expressions
var (
	ReValidDomain    = regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)
	ValidDomainRegex = ReValidDomain

	ReWHOISReferral  = regexp.MustCompile(`(?im)^[ \t]*(?:Registrar WHOIS Server|Whois Server|ReferralServer|Registrar Whois|referral|whois)[ \t]*:[ \t]*(?:whois:\/\/)?([a-zA-Z0-9.-]+)(?::43)?[ \t]*$`)
	ReWHOISExpiry    = regexp.MustCompile(`(?m)^(?i)\s*(?:\[?(?:Registry Expiry Date|Registrar Registration Expiration Date|Expiration Date|Expiry Date|Expires on|Expires|paid-till|validity|Renewal Date|Record expires on|Domain Expiration Date|valid-date|Registry Expiration|Registry Expiry|expire|renewal-date)\]?)\s*[:\]]\s*([^\r\n]+)`)
	ReWHOISCreated   = regexp.MustCompile(`(?m)^(?i)\s*(?:\[?(?:Creation Date|Created on|Created|Registration Date|created|registered|created-date|Registered Date|Connected Date)\]?)\s*[:\]]\s*([^\r\n]+)`)
	ReWHOISUpdated   = regexp.MustCompile(`(?m)^(?i)\s*(?:\[?(?:Updated Date|Last Updated Date|Last Modified|changed|modified|updated-date|Last Update)\]?)\s*[:\]]\s*([^\r\n]+)`)
	ReWHOISRegistrar = regexp.MustCompile(`(?m)^(?i)\s*(?:\[?(?:Registrar Name|Sponsoring Registrar Organization|Sponsoring Registrar|registrar-name|Registrar|Organization|sponsoring-registrar|registrar)\]?)\s*[:\]]\s*([^\r\n]+)`)
	ReWHOISIANAID    = regexp.MustCompile(`(?m)^(?i)\s*(?:\[?(?:Registrar IANA ID|Sponsoring Registrar IANA ID|IANA ID|Registrar IANA ID Number)\]?)\s*[:\]]\s*([0-9]+)`)
	ReWHOISNS        = regexp.MustCompile(`(?m)^(?i)\s*(?:\[?(?:Name Server|nameserver|nserver|DNS|Name Server Name)\]?)\s*[:\]]\s*([a-zA-Z0-9.-]+)`)
	ReWHOISStatus    = regexp.MustCompile(`(?m)^(?i)\s*(?:\[?(?:Domain Status|Status|state|Domain State|Registration status)\]?)\s*[:\]]\s*([^\r\n]+)`)
	ReWHOISDNSSEC    = regexp.MustCompile(`(?m)^(?i)\s*(?:\[?(?:DNSSEC|dnssec)\]?)\s*[:\]]\s*([^\r\n]+)`)
)

// Stealth RDAP Seeds for ccTLDs not yet published in IANA bootstrap
var stealthSeeds = map[string][]string{
	"ac":               {"https://rdap.identitydigital.services/rdap/"},
	"af":               {"https://whois.nic.af/"},
	"ag":               {"https://rdap.identitydigital.services/rdap/"},
	"ai":               {"https://rdap.nic.ai/"},
	"am":               {"https://rdap.amnic.net/"},
	"app":              {"https://rdap.nic.google/"},
	"arpa":             {"https://rdap.iana.org/"},
	"aw":               {"https://rdap.nic.aw/"},
	"bh":               {"https://rdap.centralnic.com/bh/"},
	"bw":               {"https://rdap.nic.net.bw/"},
	"bz":               {"https://rdap.identitydigital.services/rdap/"},
	"ca":               {"https://rdap.ca.fury.ca/rdap/"},
	"ch":               {"https://rdap.nic.ch/"},
	"ci":               {"https://rdap.nic.ci/"},
	"co":               {"https://rdap.registry.co/co/"},
	"de":               {"https://rdap.denic.de/"},
	"dev":              {"https://rdap.nic.google/"},
	"dm":               {"https://rdap.dmdomains.dm/rdap/"},
	"eu":               {"https://rdap.eurid.eu/"},
	"fr":               {"https://rdap.nic.fr/"},
	"ga":               {"https://rdap.nic.ga/"},
	"gi":               {"https://rdap.identitydigital.services/rdap/"},
	"gl":               {"https://rdap.centralnic.com/gl/"},
	"in":               {"https://rdap.registry.in/"},
	"io":               {"https://rdap.identitydigital.services/rdap/"},
	"iq":               {"https://rdap.reg.iq/rdap/"},
	"is":               {"https://rdap.isnic.is/rdap/"},
	"it":               {"https://rdap.nic.it/"},
	"jp":               {"https://rdap.jprs.jp/"},
	"ki":               {"https://rdap.coccaregistry.org/"},
	"kz":               {"https://rdap.nic.kz/"},
	"lc":               {"https://rdap.identitydigital.services/rdap/"},
	"li":               {"https://rdap.nic.li/"},
	"me":               {"https://rdap.identitydigital.services/rdap/"},
	"mn":               {"https://rdap.identitydigital.services/rdap/"},
	"mr":               {"https://rdap.nic.mr/"},
	"mx":               {"https://rdap.nic.mx/"},
	"my":               {"https://rdap.mynic.my/rdap/"},
	"mz":               {"https://rdap.nic.mz/"},
	"nl":               {"https://rdap.sidn.nl/"},
	"nu":               {"https://rdap.iis.nu/"},
	"nz":               {"https://rdap.internetnz.nz/"},
	"om":               {"https://rdap.registry.om/"},
	"page":             {"https://rdap.nic.google/"},
	"pl":               {"https://rdap.dns.pl/"},
	"pr":               {"https://rdap.identitydigital.services/rdap/"},
	"ru":               {"https://cctld.ru/tci-ripn-rdap/"},
	"sb":               {"https://rdap.nic.sb/"},
	"sc":               {"https://rdap.identitydigital.services/rdap/"},
	"se":               {"https://rdap.iis.se/"},
	"sh":               {"https://rdap.identitydigital.services/rdap/"},
	"sk":               {"https://rdap.sk-nic.sk/sk/"},
	"so":               {"https://rdap.nic.so/"},
	"td":               {"https://rdap.nic.td/"},
	"tl":               {"https://rdap.nic.tl/"},
	"ua":               {"https://rdap.hostmaster.ua/"},
	"uk":               {"https://rdap.nominet.uk/"},
	"us":               {"https://rdap.nic.us/"},
	"uz":               {"https://rdap.cctld.uz/"},
	"vc":               {"https://rdap.identitydigital.services/rdap/"},
	"ve":               {"https://rdap.nic.ve/rdap/"},
	"vu":               {"https://rdap.dnrs.vu/"},
	"ws":               {"https://rdap.website.ws/"},
	"xn--kprw13d":      {"https://ccrdap.twnic.tw/taiwan/"},
	"xn--mgbcpq6gpa1a": {"https://rdap.centralnic.com/xn--mgbcpq6gpa1a/"},
	"xn--p1ai":         {"https://cctld.ru/tci-ripn-rdap/"},
	"za":               {"https://rdap.registry.net.za/"},
}

// Known ccTLD direct port-43 WHOIS server overrides for fallback resolution
var ccTLDWHOISServers = map[string]string{
	"ai":    "whois.nic.ai",
	"au":    "whois.auda.org.au",
	"ca":    "whois.cira.ca",
	"ch":    "whois.nic.ch",
	"co":    "whois.nic.co",
	"co.uk": "whois.nominet.uk",
	"de":    "whois.denic.de",
	"eu":    "whois.eu",
	"fr":    "whois.nic.fr",
	"in":    "whois.inregistry.net",
	"io":    "whois.nic.io",
	"is":    "whois.isnic.is",
	"it":    "whois.nic.it",
	"jp":    "whois.jprs.jp",
	"me":    "whois.nic.me",
	"mx":    "whois.mx",
	"nl":    "whois.domain-registry.nl",
	"nz":    "whois.srs.net.nz",
	"pl":    "whois.dns.pl",
	"ru":    "whois.tcinet.ru",
	"se":    "whois.iis.se",
	"tv":    "tvwhois.verisign-grs.com",
	"uk":    "whois.nominet.uk",
	"us":    "whois.nic.us",
	"za":    "whois.registry.net.za",
}

// Alert & Log Notification Messages
const (
	// Email Security Info
	MsgLogEmailUnknownProvider = "Unknown email provider '%s' for %s. Skipping MX hijack prevention."

	// WHOIS Info
	MsgLogWHOISFallback = "RDAP failed for %s, attempting WHOIS fallback..."
	MsgLogWHOISFailed   = "WHOIS fallback also failed for %s: %v"
	MsgLogWHOISSuccess  = "WHOIS fallback succeeded for %s"

	// System Info
	MsgLogStartup          = "Daemon initialized successfully. Domains: %d, DNS Records: %d"
	MsgLogHTTPAPI          = "HTTP API running on :%s (Endpoints: /health, /api/state)"
	MsgLogTelegramDisabled = "Telegram disabled: token and chat ID must both be configured."
	MsgLogShutdownSignal   = "Received signal: %v. Initiating graceful shutdown..."
	MsgLogShutdownComplete = "Daemon shutdown complete."

	// Internal Operational Logs
	MsgLogNtfyRequestFailed         = "Ntfy request creation failed"
	MsgLogNtfyDeliveryFailed        = "Ntfy delivery failed"
	MsgLogNtfyRequestError          = "Ntfy request error"
	MsgLogNotificationClientMissing = "Notification HTTP client is not configured"

	MsgErrDotSweepFetchFailed        = "dotsweep pricing request failed"
	MsgErrDotSweepParseError         = "dotsweep json parse error"
	MsgErrDotSweepNoData             = "no tld pricing data in dotsweep response"
	MsgLogPricingFetchFailed         = "Failed to resolve portfolio renewal pricing"
	MsgErrDomainNegativeRenewalPrice = "domain %s: renewal_price cannot be negative"
	MsgErrNoTierData                 = "no registry or registrar tier data available"

	MsgLogTelegramMarshalFailed    = "Telegram payload marshal failed"
	MsgLogTelegramRequestFailed    = "Telegram request creation failed"
	MsgLogTelegramDeliveryFailed   = "Telegram delivery failed"
	MsgLogTelegramRequestError     = "Telegram request error"
	MsgLogTelegramPayloadTooLarge  = "Telegram alert exceeds provider message budget"
	MsgLogTelegramRejected         = "Telegram rejected notification"
	MsgLogRDAPRefreshFailed        = "Failed to refresh RDAP bootstrap from IANA; falling back to cached registry"
	MsgLogRDAPRateLimited          = "RDAP rate limited, falling back to WHOIS"
	MsgLogWHOISRateLimitedRetry    = "WHOIS query rate limited, retrying"
	MsgLogWHOISUnregistered        = "WHOIS reports domain is unregistered (404)"
	MsgLogSkippingUnsafeRDAP       = "Skipping unsafe RDAP referral URL"
	MsgLogQueryingRegistrarRDAP    = "Querying registrar RDAP link"
	MsgLogRegistrarReferralInvalid = "Registrar RDAP referral could not be read"
	MsgLogRateLimitedRegistrarRDAP = "Rate limited by registrar RDAP"
	MsgLogFollowingWHOISReferral   = "Following WHOIS referral"
	MsgLogSkippingUnsafeWHOIS      = "Skipping unsafe WHOIS referral"
	MsgLogWHOISReferralFailed      = "WHOIS referral failed"
	MsgLogLoopIntervalBelowMin     = "loop_interval_days is below minimum (0.125 days / 3 hours); defaulting to 0.125"
	MsgLogLoopIntervalAboveMax     = "loop_interval_days exceeds maximum (365 days); defaulting to 365"

	MsgLogHTTPServerFailed  = "HTTP server failed"
	MsgLogStateTransition   = "State transition"
	MsgLogPanicDNSWorker    = "Recovered from unexpected panic in DNS check worker"
	MsgLogPanicDomainWorker = "Recovered from unexpected panic in Domain check worker"
	MsgLogPanicRDAP         = "Recovered from unexpected panic in RDAP evaluation"

	MsgLogStateMarshalFailed       = "Failed to encode monitoring state"
	MsgLogMonitoringCycleCompleted = "Monitoring cycle completed"

	MsgLogHTTPServerStopped               = "HTTP server stopped unexpectedly"
	MsgLogMonitoringEngineStopped         = "Monitoring engine stopped unexpectedly"
	MsgLogApplicationFailed               = "Application stopped with an error"
	MsgLogMonitoringEngineTimeout         = "Monitoring engine shutdown timed out"
	MsgLogNotificationWorkerTimeout       = "Notification worker shutdown timed out"
	MsgLogNetworkRetry                    = "Network request failed, retrying"
	MsgErrMonitoringEngineExited          = "stopped before shutdown"
	MsgErrMonitoringEngineShutdownTimeout = "did not finish within shutdown budget"
)

// Extracted Constants
const (
	JSONResponseStatusOK   = `{"status":"ok"}`
	JSONResponseStatusInit = `{"status":"initializing"}`
	DefaultMaxConcurrency  = 32
	DNSSECClockSkew        = int64(300)
)

// HTTP Routes & Query Params
const (
	RouteHealth   = "GET /health"
	RouteAPIState = "GET /api/state"

	RDAPObjectClassDomain  = "domain"
	ParamName              = "name"
	ParamType              = "type"
	ParamDO                = "do"
	ParamDOValue           = "1"
	RecordTypeDNSKEY       = "DNSKEY"
	FieldChatID            = "chat_id"
	FieldText              = "text"
	FieldParseMode         = "parse_mode"
	FieldError             = "error"
	FieldDomain            = "domain"
	FieldPriority          = "priority"
	FieldTag               = "tag"
	FieldPanic             = "panic"
	FieldBytes             = "bytes"
	FieldStatus            = "status"
	FieldRecord            = "record"
	FieldURL               = "url"
	FieldReferralServer    = "referral_server"
	FieldDurationMS        = "duration_ms"
	FieldDomainsChecked    = "domains_checked"
	FieldDNSRecordsChecked = "dns_records_checked"
	FieldPrev              = "prev"
	FieldCurrent           = "current"
	FieldCheck             = "check"
	FieldAttempt           = "attempt"
	FieldRetryIn           = "retry_in"
	FieldConfigured        = "configured"
	MIMEDNSJSON            = "application/dns-json"
	PathRDAPDomain         = "/domain/"
)

// Server Defaults & Subdirectories
const (
	DefaultIdleTimeout         = 120 * time.Second
	DefaultMaxHeaderValueCount = 100
	DefaultLogTimeFormat       = "2006-01-02 15:04:05 MST"
	LayoutCompactDateTime      = "20060102150405"
)

// Default DNS Resolvers
var defaultResolvers = [...]string{"1.1.1.1", "8.8.8.8", "9.9.9.9"}

// DefaultResolvers returns a defensive copy of the default DNS resolver addresses.
func DefaultResolvers() []string {
	return slices.Clone(defaultResolvers[:])
}

// Common Prefixes
const (
	PrefixBearer = "Bearer "
	PrefixBasic  = "Basic "
	PrefixAlias  = "alias:"
	PrefixAlgo   = "ALGO_"
)

// Provider & Component Names
const (
	NameNtfyProvider     = "Ntfy provider"
	NameTelegramProvider = "Telegram provider"

	NameOpMonitoringEngine = "Monitoring engine"
	NameOpDNSLookup        = "DNS lookup"
	NameOpDNSSECDoH        = "DNSSEC DoH"
	NameOpRDAPBootstrap    = "RDAP bootstrap"
	NameOpRegistryRDAP     = "registry RDAP"
	NameOpRegistrarRDAP    = "registrar RDAP"
	NameOpWHOIS            = "WHOIS"
	NameOpWHOISReferral    = "WHOIS referral"
	NameOpPricingCatalog   = "pricing catalog"
	CheckTypeRDAP          = "RDAP"
	CheckTypeDNS           = "DNS"
	CheckTypeEmail         = "Email"
	CheckTypeCAA           = "CAA"
	CheckTypeDNSSEC        = "DNSSEC"
	CheckTypeNSHealth      = "NSHealth"

	TargetKeyDomain      = "domain"
	TargetKeyRecord      = "record"
	FlagConfig           = "config"
	FlagConfigShort      = "c"
	FlagConfigUsage      = "Path to the JSON config file"
	FlagConfigShortUsage = "Path to the JSON config file (shorthand)"
)

// Notification Formatting & Delimiters
const (
	AlertConditionFormat         = "%s %s: %s %s (Since: %s)"
	AlertConditionRedactedFormat = "%s %s: %s (Since: %s)"
	AlertStatusSeparator         = ": "
	AlertSincePrefix             = " (Since: "
	AlertConditionFixedText      = " :  (Since: )"

	TelegramAlertHeader  = "⚠️ <b>Domain Monitor Alerts</b>\n\n"
	TelegramPrefixFormat = "<b>[%s]</b> "
	TelegramLineFormat   = "• %s%s\n"
	NtfyPrefixFormat     = "[%s] "
)

// Logging Formats
const (
	LogFormatLineWithAttrs = "%s [%s] %s (%s)\n"
	LogFormatLineNoAttrs   = "%s [%s] %s\n"
	LogFormatAttr          = "%s: %v"
	MsgLogRecoveredPanic   = "Recovered from unexpected panic"
)

// DNS Evaluation Reasons & Redacted Message Templates
const (
	MsgReasonPrefixNotFound      = "prefix \"%s\" not found in [%s]"
	MsgReasonSubstringNotFound   = "substring \"%s\" not found in [%s]"
	MsgReasonNoneMatched         = "none of expected [%s] matched found [%s]"
	MsgReasonMissingRecords      = "missing expected records: %s"
	MsgReasonUnauthorizedRecords = "unauthorized records: %s"
)

// Worker, Network & Internal Error Messages
const (
	MsgErrInternalDNSCheckPanic  = "internal check panic: %s"
	MsgErrDomainCheckPanic       = "domain check panicked: %s"
	MsgErrInternalRDAPCheckPanic = "internal rdap check panic: %s"

	MsgErrLookupEmptyResponse    = "lookup %s on %s: empty response"
	MsgErrLookupIDMismatch       = "lookup %s on %s: response ID mismatch"
	MsgErrLookupQuestionMismatch = "lookup %s on %s: response question mismatch or missing"
	MsgErrLookupServerError      = "lookup %s on %s: server error (%s)"
	MsgErrLookupServerErrorCode  = "lookup %s on %s: server returned error code %d"
	MsgErrNoIPRecordsForHost     = "no IP records found for host %s"
	MsgErrUnsupportedDNSType     = "unsupported DNS type: %s"

	MsgErrUnableToParseDate                  = "unable to parse date format: %s"
	MsgErrRDAPHTTPError                      = "rdap HTTP error: %d"
	MsgErrRDAPLookupFailedAllCandidates      = "rdap lookup failed across all candidate servers"
	MsgErrWHOISParsingFailed                 = "whois parsing failed to extract required domain fields"
	MsgErrStoppedAfterRedirects              = "stopped after 10 redirects"
	MsgErrInsecureRedirectURL                = "insecure or invalid redirect URL: %s"
	MsgErrNoRDAPServerForDomain              = "no rdap server found for domain %s"
	MsgErrBootstrapRegistryUnavailable       = "bootstrap registry unavailable"
	MsgErrBootstrapRequestError              = "bootstrap request error"
	MsgErrBootstrapFetchError                = "bootstrap fetch error"
	MsgErrBootstrapStatus                    = "bootstrap status %d"
	MsgErrBootstrapDecodeError               = "bootstrap decode error"
	MsgErrFailedToReadConfig                 = "failed to read config file"
	MsgErrJSONUnmarshalFailed                = "json unmarshal failed"
	MsgErrResolversExceedLimit               = "configured resolvers exceed maximum limit of 9"
	MsgErrDomainEmptyDomain                  = "domain entry at index %d has an empty domain"
	MsgErrDuplicateDomain                    = "duplicate domain %s; each domain entry must be unique"
	MsgErrDomainEmptyNameserver              = "domain %s has an empty nameserver hostname at index %d"
	MsgErrDomainInvalidNameserver            = "domain %s has invalid nameserver hostname %s"
	MsgErrDomainDuplicateNameserver          = "domain %s has duplicate nameserver %s"
	MsgErrDomainNeedsAnsweringNameserver     = "domain %s must configure at least one non-hidden nameserver"
	MsgErrDomainInvalidRootZone              = "domain %s has invalid root zone %s"
	MsgErrRemovedDomainConfig                = "domain %s uses removed configuration fields; update it to the current domain schema"
	MsgErrDomainMissingName                  = "domain %s is missing a mandatory 'name' field"
	MsgErrDuplicateDomainName                = "duplicate domain name %s; each domain must have a unique name"
	MsgErrMailProviderAndMXMutuallyExclusive = "domain %s has both email.provider and email.mx_records set; these are mutually exclusive"
	MsgErrDomainInvalidMX                    = "domain %s has invalid expected MX hostname %s"
	MsgErrDomainInvalidDKIMSelector          = "domain %s has invalid DKIM selector %s"
	MsgErrDNSEmptyHostname                   = "dns record at index %d has an empty hostname"
	MsgErrDNSMissingName                     = "dns record %s (%s) is missing a mandatory 'name' field"
	MsgErrDuplicateDNSName                   = "duplicate dns record name %s; each dns record must have a unique name"
	MsgErrDNSMissingType                     = "dns record %s is missing a type (e.g. A, CNAME)"

	MsgErrExpectedIPv6ForTypeA              = "dns record %s (%s): expected %s is an IPv6 address, but record type is A (requires IPv4)"
	MsgErrExpectedInvalidIPv4               = "dns record %s (%s): expected %s is not a valid IPv4 address for type A"
	MsgErrExpectedIPv4ForTypeAAAA           = "dns record %s (%s): expected %s is an IPv4 address, but record type is AAAA (requires IPv6)"
	MsgErrExpectedInvalidIPv6               = "dns record %s (%s): expected %s is not a valid IPv6 address for type AAAA"
	MsgErrExpectedNotValidIP                = "dns record %s (%s): expected %s is not a valid IPv4 or IPv6 address for composite type IP"
	MsgErrNtfyURLRequired                   = "ntfy and its URL are required"
	MsgErrNilStringListReceiver             = "nil StringList receiver"
	MsgErrInvalidResultCode                 = "invalid result code %d"
	MsgErrUnknownResultCode                 = "unknown result code %q"
	MsgErrInvalidFindingSeverity            = "invalid finding severity %d"
	MsgErrUnknownFindingSeverity            = "unknown finding severity %q"
	MsgErrAuthenticatedNtfyRequiresHTTPS    = "authenticated ntfy requires HTTPS"
	MsgErrNotificationRedirectChangedOrigin = "notification redirect changed origin"
	MsgErrIncompleteResolverEvidence        = "incomplete resolver evidence: %w"
	MsgErrResolverDisagreementFor           = "resolver disagreement for %s"
	MsgErrResolverDisagreement              = "resolver disagreement: %s and %s returned different answers"
	MsgCycleFindingsOmitted                 = "\n… %d additional findings omitted"
	MsgPrefixLookupOn                       = "lookup %s on %s"
	MsgPrefixLookupOnWithRcode              = "lookup %s on %s (%s)"
	MsgErrLookupFailedAandAAAA              = "lookup failed for A and AAAA"
	MsgErrInvalidNSAddress                  = "invalid nameserver address %s"
	MsgErrFailedToResolveIP                 = "failed to resolve IP"
	MsgErrNoRDAPServer                      = "no RDAP server"
	MsgErrWHOISQueryFailed                  = "whois query failed"
	MsgErrDSQueryFailed                     = "DS query failed: %s"
	MsgErrDNSKEYQueryFailed                 = "DNSKEY query failed: %s"
	MsgErrDSRecordDoesNotMatchDNSKEY        = "DS record does not match any DNSKEY"
	MsgErrRRSIGExpiredOrNotYetValid         = "dns.RRSIG is expired or not yet valid"
	MsgErrDNSSECLocalVerifiedDoHUnavailable = "Local DNSSEC records verified; upstream DoH chain integrity unavailable"
	MsgErrDNSSECUpstreamChainBroken         = "Upstream validating resolver returned AD=false (chain broken)"
	MsgErrDNSSECValidationFailed            = "DNSSEC Validation Failed"
	MsgErrValidateDNSSECNil                 = "validateDNSSEC returned nil"
	MsgErrDNSSECResolverNotConfigured       = "DNSSEC resolver is not configured"

	MsgErrPricingHTTPClientNotConfigured = "fetch DotSweep pricing: HTTP client is not configured"
	MsgErrSPFLookupError                 = "SPF lookup error: %s"
	MsgErrDMARCLookupError               = "DMARC lookup error: %s"
	MsgErrDKIMLookupError                = "DKIM lookup error: %s"
	MsgErrSOALookupFailed                = "SOA lookup failed: %w"
	MsgErrNSNotAuthoritative             = "Nameserver not authoritative (AA flag missing)"
	MsgErrNoSOARecordReturned            = "No SOA record returned in answer or authority sections"
	MsgErrRDAPAndWHOIS                   = "RDAP: %w | WHOIS: %w"
)

// registryDateLayouts specifies supported WHOIS/RDAP date format layouts for parseFlexibleDate.
var registryDateLayouts = [...]string{
	time.RFC3339,
	time.RFC3339Nano,
	"2006-01-02T15:04:05",
	"2006-01-02 15:04:05.999999999",
	"2006-01-02 15:04:05 -0700",
	"2006-01-02 15:04:05 -07:00",
	"2006-01-02 15:04:05 MST",
	"2006-01-02 15:04:05",
	"2006-01-02",
	"02-Jan-2006 15:04:05 -0700",
	"02-Jan-2006 15:04:05 -07:00",
	"02-Jan-2006 15:04:05 MST",
	"02-Jan-2006 15:04:05",
	"02-Jan-2006",
	"2006.01.02 15:04:05",
	"2006.01.02",
	"2006/01/02 15:04:05",
	"2006/01/02",
	"02/01/2006",
	"02.01.2006",
	time.UnixDate,
	"20060102",
}

// Auto-generated error and log constants
const (
	MsgErrIPv6ResolverTimeout            = "IPv6 resolver timeout"
	MsgErrResolverTimeout                = "resolver timeout"
	MsgErrMockDohError                   = "mock doh error"
	MsgErrMockDNSSECError                = "mock DNSSEC error"
	MsgErrResolutionFailed               = "resolution failed"
	MsgErrMockError                      = "mock error"
	MsgErrResolverErrorCNAMELoopDetected = "resolver error: CNAME loop detected"
	MsgErrTemporaryDNSFailure            = "temporary DNS failure"
	MsgErrDNSTimeout                     = "DNS timeout"

	MsgErrQueryDNSForOnTruncated        = "query DNS for %s on %s: truncated UDP answer and TCP resolver is not configured"
	MsgErrQueryDNSForOnTCP              = "query DNS for %s on %s: TCP answer is truncated"
	MsgErrExpectedOneMXRecordWith       = "%w: expected one MX record with preference 0 and the root exchange"
	MsgErrResolveExpectedAlias          = "resolve expected alias %s: %w"
	MsgErrInvalidDMARCPolicyAt          = "invalid DMARC policy at %s"
	MsgErrNameserverAddressDidNotReturn = "nameserver address %s did not return an authoritative SOA for %s"
	MsgErrNameserverAddressReturnedANil = "nameserver address %s returned a nil SOA response"
	MsgErrNilDnskeyResponseFor          = "nil DNSKEY response for %s"
	MsgErr                              = "%s: %w"
	MsgErrResolverUnavailable           = "resolver unavailable"

	MsgErrLoadConfiguration     = "load configuration: %w"
	MsgErrInitializeApplication = "initialize application: %w"
	MsgErrHTTPServerStopped     = "HTTP server stopped: %w"
	MsgErrOperationDetail       = "%s: %s"
	MsgErrShutDownHTTPServer    = "shut down HTTP server: %w"

	MsgErrRootCause                   = "root cause"
	MsgErrCustomError                 = "custom error"
	MsgLogTestErrorMessage            = "Test error message"
	MsgLogTestWarnMessage             = "Test warn message"
	MsgLogTestInfoMessage             = "Test info message"
	MsgLogSampleLocalizedMessage      = "Sample localized message"
	MsgLogTestInfof                   = "Test infof %s"
	MsgLogTestErrorf                  = "Test errorf %s"
	MsgLogTestWarnf                   = "Test warnf %d"
	MsgLogTestDebugMessage            = "Test debug message"
	MsgLogTestDebugf                  = "Test debugf %s"
	MsgErrInvalidServerPort           = "invalid server port: %w"
	MsgErrValidateConfiguredResolvers = "validate configured resolvers (%d): %s"
	MsgErrInvalidResolver             = "invalid resolver %q: %w"
	MsgErrInvalidDohURL               = "invalid DoH URL: %w"
	MsgErrValidateNotificationsNtfy   = "validate notifications.ntfy: %s"
	MsgErrInvalidNtfyURL              = "invalid ntfy URL: %w"
	MsgErrPortOutOfRange              = "port %q must be between 1 and 65535"
	MsgErrResolverEndpointIsEmpty     = "resolver endpoint %q is empty"
	MsgErrExpectedIPAddressOrHostPort = "expected an IP address or host:port: %w"
	MsgErrResolverEndpointInvalidHost = "resolver endpoint %q has an invalid host"
	MsgErrExpectedHTTPURLWithHost     = "expected an http(s) URL with a host"

	MsgErrInvalidMonitoredDomain               = "invalid monitored domain %q"
	MsgErrRootZoneIsNotA                       = "root zone %q is not a parent of delegated zone %q"
	MsgErrUnknownMailProviderFor               = "unknown mail provider %q for %s"
	MsgErrUnsupportedDNSRecordTypeFor          = "unsupported DNS record type %q for %s"
	MsgErrUnsupportedDNSMatchTypeFor           = "unsupported DNS match type %q for %s"
	MsgErrReservedDNSName                      = "dns record name %q uses reserved prefix %q"
	MsgErrMissingExpectedDNSRecordsFor         = "missing expected DNS records for %s"
	MsgErrInvalidCustomResolverFor             = "invalid custom resolver for %s: %w"
	MsgErrEmptyExpectedDNSRecordsFor           = "empty expected DNS records for %s with %s match"
	MsgErrInvalidExpectedCAAValueFor           = "invalid expected CAA value %q for %s: %w"
	MsgErrInvalidExpectedCAAValue              = "invalid expected CAA value %q for %s"
	MsgErrQueryWHOISForThroughInjected         = "query WHOIS for %s through injected client: %w"
	MsgErrWHOISTransportIsNotConfigured        = "WHOIS transport is not configured for %s"
	MsgErrWHOISDomainHasNoToplevel             = "WHOIS domain %q has no top-level label"
	MsgErrIANAWHOISResponseHasNo               = "IANA WHOIS response has no referral for %s"
	MsgErrResolveWHOISServer                   = "resolve WHOIS server %s: %w"
	MsgErrConnectToWHOISServer                 = "connect to WHOIS server %s: %w"
	MsgErrWHOISServerHasNoPermitted            = "WHOIS server %s has no permitted public address"
	MsgErrUnsafeWHOISServer                    = "unsafe WHOIS server: %q"
	MsgErrWaitForWHOISRequestTo                = "wait for WHOIS request to %s: %w"
	MsgErrInvalidWHOISQueryFor                 = "invalid WHOIS query for %s"
	MsgErrSetWHOISDeadlineFor                  = "set WHOIS deadline for %s: %w"
	MsgErrWriteWHOISQueryForTo                 = "write WHOIS query for %s to %s: %w"
	MsgErrReadWHOISResponseForFrom             = "read WHOIS response for %s from %s: %w"
	MsgErrWHOISResponseForExceedsBytes         = "WHOIS response for %s exceeds %d bytes"
	MsgErrRDAPHTTPClientNotConfigured          = "RDAP HTTP client is not configured for %s"
	MsgErrUnsafeRDAPURL                        = "unsafe RDAP URL: %q"
	MsgErrRDAPLookupFor                        = "RDAP lookup for %s: %s"
	MsgErrRDAPBootstrapIsUnavailableFor        = "RDAP bootstrap is unavailable for %s"
	MsgErrReadRDAPResponse                     = "read RDAP response: %w"
	MsgErrRDAPResponseExceedsBytes             = "RDAP response exceeds %d bytes"
	MsgErrParseRDAPResponse                    = "parse RDAP response: %w"
	MsgErrRDAPResponseForIsNot                 = "RDAP response for %s is not a domain object"
	MsgErrRDAPResponseForHasNo                 = "RDAP response for %s has no domain name"
	MsgErrRDAPResponseDomainDoesNot            = "RDAP response domain %q does not match requested %s"
	MsgErrReadRegistrarRDAPReferral            = "read registrar RDAP referral: %w"
	MsgErrRegistrarRDAPResponseExceedsBytes    = "registrar RDAP response exceeds %d bytes"
	MsgErrParseRegistrarRDAPReferral           = "parse registrar RDAP referral: %w"
	MsgErrParentNameserversForHaveNo           = "parent nameservers for %s have no usable address"
	MsgErrFailedToQueryNSRecords               = "failed to query NS records: %w"
	MsgLogPartialParentNameserverAddressLookup = "partial parent nameserver address lookup"
	MsgErrFetchRDAPBootstrapRegistry           = "fetch RDAP bootstrap registry: %w"
	MsgErrReadRDAPBootstrapResponse            = "read RDAP bootstrap response: %w"
	MsgErrRDAPBootstrapResponseExceedsBytes    = "RDAP bootstrap response exceeds %d bytes"
	MsgErrReadPricingResponse                  = "read pricing response: %w"
	MsgErrPricingResponseExceedsBytes          = "pricing response exceeds %d bytes"
	MsgErrInvalidCheckStatus                   = "invalid check status %d"
	MsgErrUnknownCheckStatus                   = "unknown check status %q"
	MsgErrInvalidAlertPriority                 = "invalid alert priority %d"
	MsgErrUnknownAlertPriority                 = "unknown alert priority %q"
	MsgErrMockHTTPError                        = "mock http error"
	MsgErrWHOISServerNotFound                  = "WHOIS server not found"
	MsgErrRDAPUnavailable                      = "RDAP unavailable"
	MsgErrFirstAddressUnavailable              = "first address unavailable"
	MsgErrConnectionRefused                    = "connection refused"
	MsgErrWHOISShouldNotBeQueried              = "WHOIS should not be queried"
	MsgErrMockRDAPRateLimitError               = "mock rdap rate limit error"
)

// Auto-generated String Literals
const (
	DateLayoutCompact           = "2006-01-02"
	StrAutoRenewGracePeriod     = "Auto-Renew Grace Period discrepancy: Registry expiration ("
	StrCacheAge                 = "cache_age"
	StrClientdeleteprohibited   = "clientdeleteprohibited"
	StrClienthold               = "clienthold"
	StrClientrenewprohibited    = "clientrenewprohibited"
	StrClienttransferprohibited = "clienttransferprohibited"
	StrClientupdateprohibited   = "clientupdateprohibited"
	StrConnectionRefused        = "connection refused"
	StrCreated                  = "created"

	StrDSQ                                = "%d %s %q"
	StrDate                               = "date"
	StrDelegationReturnedNoNameservers    = "delegation returned no nameservers"
	StrDeleteprohibited                   = "deleteprohibited"
	StrDKIM                               = "DKIM: "
	StrDMARC                              = "_dmarc."
	StrDMARCDiagnosticPrefix              = "DMARC: "
	StrDomain                             = "/domain/"
	StrDomainkey                          = "._domainkey."
	StrEmpty                              = ""
	StrError                              = "error"
	StrExample60InCAA                     = "example. 60 IN CAA "
	StrExpiration                         = "expiration"
	StrExpire                             = "expire"
	StrHold                               = "hold"
	StrHTTP                               = "http"
	StrHTTPS                              = "https"
	StrIOTimeout                          = "i/o timeout"
	StrIANA                               = "IANA "
	StrIANALower                          = "iana"
	StrIANARegistrarID                    = "iana registrar id"
	StrInternal                           = ".internal"
	StrInternalDNSCheckPanic              = "internal DNS check panic"
	StrInternalDomainCheckPanic           = "internal domain check panic"
	StrInternalRDAPCheckPanic             = "internal RDAP check panic"
	StrInternic                           = "internic"
	StrJustNow                            = "just now"
	StrLastChanged                        = "last changed"
	StrLastModified                       = "last modified"
	StrLimit                              = "limit"
	StrLocal                              = ".local"
	StrLocalhost                          = "localhost"
	DMARCPSDNo                            = "n"
	StrNameserverDesyncRegistryDelegation = "Nameserver desync: Registry delegation ["
	StrNoSuchHost                         = "no such host"
	StrNone                               = "none"
	StrNotApplicable                      = "not applicable"
	StrNp                                 = "np"
	StrNull                               = "null"
	StrOperation                          = "operation"
	StrOr                                 = " OR "
	StrPanic                              = "panic"
	StrPriority                           = "priority"
	StrProhibittransfer                   = "prohibittransfer"
	StrPsd                                = "psd"
	StrQueryFailed                        = "query failed"
	StrQuota                              = "quota"
	StrRN                                 = "\r\n"
	StrRegistrarConfiguration             = "] != Registrar configuration ["
	StrRegistrarIANA                      = "Registrar (IANA "
	StrRegistration                       = "registration"
	StrRenewprohibited                    = "renewprohibited"
	StrS0InDnskey                         = "%s 0 IN DNSKEY %s"
	StrServerdeleteprohibited             = "serverdeleteprohibited"
	StrServerhold                         = "serverhold"
	StrServerrenewprohibited              = "serverrenewprohibited"
	StrServertransferprohibited           = "servertransferprohibited"
	StrServerupdateprohibited             = "serverupdateprohibited"
	StrSp                                 = "sp"
	StrSPF                                = "SPF: "
	SymParenOpen                          = "("
	SymBrackets                           = "[]"
	SymPipeSpaced                         = " | "
	SymInvalidURLChars                    = " /?#@\\"
	SymSemicolonSpace                     = "; "
	SymSemicolon                          = ";"
	SymEquals                             = "="
	SymDoubleQuote                        = `"`
	SymQuoteSpace                         = `"' `
	SymHash                               = "#"
	SymParenClose                         = ")"
	SymCommaSpace                         = ", "
	SymBracketClose                       = "]"
	SymPercent                            = "%"
	SymURLControlChars                    = "/:@?#\\ "
	StrT                                  = "T"
	StrTRN                                = ")/;, \t\r\n"
	StrTag                                = "tag"
	StrTCP                                = "tcp"
	StrTemporaryFailure                   = "temporary failure"
	StrTerminationSignal                  = "termination signal"
	StrTooMany                            = "too many"
	StrU                                  = "u"
	StrTransferlock                       = "transferlock"
	StrTransferprohibited                 = "transferprohibited"
	StrUpdated                            = "updated"
	StrUpdateprohibited                   = "updateprohibited"
	StrValid                              = "valid"
	StrVsRegistrarExpiration              = ") vs Registrar expiration ("
	StrY                                  = "y"
	SymColon                              = ":"
	SymDot                                = "."
	SymHyphen                             = "-"
	SymPlus                               = "+"
	SymSlash                              = "/"
	SymSpace                              = " "
)

// Email provider initialization diagnostics.
const (
	MsgErrOpenEmbeddedEmailProviders   = "open embedded email providers: %w"
	MsgErrOpenEmailProviderDirectory   = "open email provider directory %s: %w"
	MsgErrLoadEmailProviders           = "load email providers from %s: %w"
	MsgErrTemporaryHTTPStatus          = "temporary HTTP status %d"
	MsgErrListEmailProviders           = "list email providers: %w"
	MsgErrInvalidEmailProviderName     = "invalid email provider name %q"
	MsgErrOpenEmailProvider            = "open email provider %s: %w"
	MsgErrReadEmailProvider            = "read email provider %s: %w"
	MsgErrEmailProviderExceedsBytes    = "email provider %s exceeds %d bytes"
	MsgErrDecodeEmailProvider          = "decode email provider %s: %w"
	MsgErrEmailProviderMissingMX       = "email provider %s has no MX records"
	MsgErrEmailProviderInvalidMX       = "email provider %s has invalid MX suffix %q"
	MsgErrEmailProviderInvalidSelector = "email provider %s has invalid DKIM selector %q"
)
