package main

import (
	"errors"
	"regexp"
	"slices"
	"time"

	"github.com/miekg/dns"
)

// System & Default Paths and Files
const (
	MaxPendingAlerts           = 256
	MaxAlertsPerFlush          = 32
	CTStateVersion             = 1
	MaxCTSeenIDs               = 1000
	MaxCTScanPages             = 10
	MaxCTPendingItems          = 256
	MaxCTPendingBytes          = 1 << 20
	DefaultConfigFile          = "config.json"
	DefaultServerPort          = "8080"
	DefaultDNSPort             = "53"
	DefaultDataDir             = "/app/data"
	DefaultLocalDataDir        = "./data"
	DefaultDoHURL              = "https://dns.google/resolve"
	DefaultCTLogsSubdir        = "ct_logs"
	DefaultUserAgent           = "DomainMonitor/1.0 (+https://github.com/domain-monitor)"
	MaxBootstrapResponseSize   = 8 << 20  // 8 MB
	MaxCTLogsResponseSize      = 16 << 20 // 16 MB
	MaxCTHistoryFileSize       = 8 << 20  // 8 MB
	MaxNotificationPayloadSize = 1 << 20  // 1 MB
	MaxPricingResponseSize     = 5 << 20  // 5 MB
)

// Standard Timeouts & Intervals
const (
	DefaultDNSTimeout           = 5 * time.Second
	DefaultHTTPTimeout          = 10 * time.Second
	DefaultPricingHTTPTimeout   = 15 * time.Second
	PricingCacheTTL             = 24 * time.Hour
	PricingMaxStaleAge          = 7 * 24 * time.Hour
	DefaultWHOISTimeout         = 10 * time.Second
	DefaultWHOISQueryTimeout    = 15 * time.Second
	MaxWHOISResponseBytes       = 1 << 20
	DefaultTCPKeepAlive         = 30 * time.Second
	ShutdownTimeout             = 5 * time.Second
	DefaultLoopDurationFallback = 6 * time.Hour
	RDAPRateLimitInterval       = 10 * time.Second
	CTLogsRateLimitInterval     = 5 * time.Second
	DefaultReferralRDAPTimeout  = 6 * time.Second
	DefaultAlertCooldown        = 24 * time.Hour
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
	MaxNotificationTags               = 5
	MaxCNAMEAliasTraversals           = 5
	DefaultRDAPExpiryWarningDays      = 30
	AutoRenewGracePeriodThresholdDays = 45.0
	DefaultLoopIntervalDays           = 0.25
	MinLoopIntervalDays               = 0.125
	MaxLoopIntervalDays               = 365.0
	MaxCTCertHistory                  = 1000
	MaxBodyDrainSize                  = 4096
	MaxAlertMessageRunes              = 1000
	MaxProviderMessageBytes           = 3500
	MaxTelegramAlertRunes             = 400
	MaxAlertNameRunes                 = 80
	AlertTruncationNotice             = " [truncated; see local state]"
	HoursPerDay                       = 24
	DirPermDefault                    = 0750
	FilePermSecret                    = 0600
	FilePermPublic                    = 0644
)

// Environment Variable Keys
const (
	EnvConfigPath     = "CONFIG_PATH"
	EnvPort           = "PORT"
	EnvResolvers      = "RESOLVERS"
	EnvDoHURL         = "DOH_URL"
	EnvNtfyAuth       = "NTFY_AUTH"
	EnvTelegramToken  = "TELEGRAM_TOKEN"
	EnvTelegramChatID = "TELEGRAM_CHAT_ID"
	EnvCTLogsAPIKey   = "CTLOGS_API_KEY" // #nosec G101 -- environment variable name, not a credential.
)

// HTTP Constants
const (
	DotSweepAPIEndpoint = "https://dotsweep.com/tlds"
)

// HTTP Headers & Media Types
const (
	HeaderContentType           = "Content-Type"
	HeaderCacheControl          = "Cache-Control"
	HeaderUserAgent             = "User-Agent"
	HeaderAuthorization         = "Authorization"
	HeaderAccept                = "Accept"
	HeaderNtfyTitle             = "Title"
	HeaderNtfyPriority          = "Priority"
	HeaderNtfyTags              = "Tags"
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
	RedactedAPIKeyPlaceholder = "[REDACTED_API_KEY]"        // #nosec G101 -- redaction marker, not a credential.
	DefaultUnknownCA          = "Unknown CA"
	NotificationAlertTitle    = "Domain Monitor Alert"

	PrefixHTTP      = "http://"
	PrefixHTTPS     = "https://"
	SchemeHTTPName  = "http"
	SchemeHTTPSName = "https"
)

// External API Endpoints
const (
	BootstrapURL                 = "https://data.iana.org/rdap/dns.json"
	BootstrapTTL                 = 24 * time.Hour
	BootstrapMaxAge              = 72 * time.Hour
	CTLogsAPIEndpoint            = "https://api.ctlogs.dev/v1/subdomains/"
	TelegramAPIEndpoint          = "https://api.telegram.org/bot%s/sendMessage"
	TelegramAPIBase              = "https://api.telegram.org/bot"
	TelegramAPISendMessageSuffix = "/sendMessage"
)

// Notification Alert Tags (Icons / Emojis)
const (
	TagRotatingLight AlertTag = "rotating_light"
	TagWarning       AlertTag = "warning"
	TagError         AlertTag = "x"
	TagLock          AlertTag = "lock"
	TagUnlock        AlertTag = "unlock"
	TagSkull         AlertTag = "skull"
	TagEnvelope      AlertTag = "envelope"
)

// DNS Record Types
const (
	RecordTypeA     = "A"
	RecordTypeAAAA  = "AAAA"
	RecordTypeCNAME = "CNAME"
	RecordTypeMX    = "MX"
	RecordTypeTXT   = "TXT"
	RecordTypeCAA   = "CAA"
	RecordTypeNS    = "NS"
	RecordTypeIP    = "IP"
	RecordTypeALIAS = "ALIAS"
)

// DNS Match Types
const (
	MatchExact    = "exact"
	MatchPrefix   = "prefix"
	MatchContains = "contains"
	MatchAnyOf    = "any_of"
)

// CAA Record Property Tags & Sentinels
const (
	CAATagIssue     = "issue"
	CAATagIssueWild = "issuewild"
	CAATagIssueMail = "issuemail"
	CAACriticalFlag = 0x80
	CAATagIODEF     = "iodef"
	CAADenyAll      = ";"
)

// Email Security & Protocol Sentinels
const (
	SPFPrefix             = "v=spf1"
	DMARCPrefix           = "v=dmarc1"
	DKIMPrefix            = "v=dkim1"
	DNSPolicyTagVersion   = "v"
	DNSPolicyTagPublicKey = "p"
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
	DNSSECSourceLocalOnly   = "local_only"
	DNSSECSourceLocal       = "local"
	DNSSECSourceDoH         = "doh"
	DNSSECSourceDoHFallback = "doh_fallback"
	DNSSECSourceLocalDoH    = "local+doh"
)

// Protocols
const (
	ProtocolRDAP        = "rdap"
	ProtocolWHOIS       = "whois"
	ProtocolWHOISFailed = "whois_failed"
	ProtocolHybrid      = "hybrid"
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

// Domain Suspension EPP Status Tokens
const (
	EPPStatusServerHold       = "serverhold"
	EPPStatusClientHold       = "clienthold"
	EPPStatusPendingDelete    = "pendingdelete"
	EPPStatusRedemptionPeriod = "redemptionperiod"
	EPPStatusInactive         = "inactive"
	EPPStatusHold             = "hold"
)

const (
	StatusUnknown CheckStatus = iota
	StatusPending
	StatusOK
	StatusFailed
	StatusMismatch
	StatusWarning
	StatusHijacked
)

const (
	PriorityDefault AlertPriority = iota
	PriorityWarning
	PriorityHigh
	PriorityUrgent
)

var checkStatusNames = [...]string{"", "pending", "ok", "failed", "mismatch", "warning", "hijacked"}
var alertPriorityNames = [...]string{"default", "warning", "high", "urgent"}

// ResultCode represents a typed, zero-allocation condition code for protocol-level evaluator verdicts.
type ResultCode int16

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
	CodeNSSOALags
	CodeNSDNSKEYMismatch
	CodeExpectedNSMissing
	CodeUnauthorizedNS

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

	// CT Logs
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

// resultCodeNames maps each ResultCode to its camelCase JSON string representation.
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
	CodeNSSOALags:          "nsSoaLags",
	CodeNSDNSKEYMismatch:   "nsDnskeyMismatch",
	CodeExpectedNSMissing:  "expectedNsMissing",
	CodeUnauthorizedNS:     "unauthorizedNs",

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

	// CT Logs
	CodeCTLogsVerified:       "ctLogsVerified",
	CodeCTLogsRateLimited:    "ctLogsRateLimited",
	CodeCTLogsHTTPError:      "ctLogsHttpError",
	CodeCTPersistenceFailed:  "ctPersistenceFailed",
	CodeCTCoverageIncomplete: "ctCoverageIncomplete",

	// App-level
	CodeCheckTimeout: "checkTimeout",
	CodeCheckPanic:   "checkPanic",
}

// String returns the camelCase JSON string representation of a ResultCode.
func (r ResultCode) String() string {
	if int(r) >= 0 && int(r) < len(resultCodeNames) {
		return resultCodeNames[r]
	}
	return ""
}

// System Errors
var (
	ErrDNSResolution          = errors.New("dns resolution failed")
	ErrNXDOMAIN               = errors.New("no such host (NXDOMAIN)")
	ErrSERVFAIL               = errors.New("server failure (SERVFAIL)")
	ErrRDAPNotFound           = errors.New("RDAP domain not found (404)")
	ErrRDAPRateLimited        = errors.New("RDAP rate limited (429)")
	ErrWHOISRateLimited       = errors.New("whois rate limited (429)")
	ErrDomainNotFound         = errors.New("domain not found in whois (404)")
	ErrNoResolvers            = errors.New("no resolvers configured")
	ErrEmptyDNSResponse       = errors.New("empty dns response")
	ErrInvalidNullMX          = errors.New("invalid null MX record")
	ErrNoPeerCertificates     = errors.New("no peer certificates returned")
	ErrRestrictedIP           = errors.New("connection to restricted IP blocked (SSRF)")
	ErrBootstrapClientNil     = errors.New("bootstrap client is nil")
	ErrNoRDAPServer           = errors.New("no rdap server found")
	ErrEmptyDate              = errors.New("empty date string")
	ErrEmptyBootstrapRegistry = errors.New("empty bootstrap registry")
	ErrCTLogsRateLimited      = errors.New("api.ctlogs.dev rate limit exceeded")
	ErrPricingManagerNil      = errors.New(MsgErrPricingManagerNil)
)

// DNSTypeMap maps record type string names to miekg/dns uint16 type constants.
var DNSTypeMap = map[string]uint16{
	RecordTypeA:     dns.TypeA,
	RecordTypeAAAA:  dns.TypeAAAA,
	RecordTypeCNAME: dns.TypeCNAME,
	RecordTypeMX:    dns.TypeMX,
	RecordTypeTXT:   dns.TypeTXT,
	RecordTypeCAA:   dns.TypeCAA,
	RecordTypeNS:    dns.TypeNS,
}

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

// EPPStatusMap maps raw or formatted EPP/RDAP tokens to canonical camelCase strings.
var EPPStatusMap = map[string]string{
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

// TZOffsets maps common global registrar and WHOIS timezone abbreviations to ISO numeric offsets.
var TZOffsets = map[string]string{
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

// WHOISNotFoundIndicators lists indicators across global registrars and registries denoting an unregistered domain.
var WHOISNotFoundIndicators = []string{
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

// WHOISRateLimitIndicators lists indicators across WHOIS servers denoting query rate-limiting.
var WHOISRateLimitIndicators = []string{
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
var StealthSeeds = map[string][]string{
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
var CCTLDWHOISServers = map[string]string{
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

// Mail Provider MX Suffix Map for Anti-Hijacking
var ProviderMXMap = map[string][]string{
	"google":     {"aspmx.l.google.com", "smtp.google.com", "googlemail.com", "google.com"},
	"microsoft":  {"mail.protection.outlook.com"},
	"fastmail":   {"messagingengine.com"},
	"proton":     {"protonmail.ch", "proton.me"},
	"protonmail": {"protonmail.ch", "proton.me"},
	"icloud":     {"icloud.com"},
	"zoho":       {"zoho.com", "zoho.in", "zoho.eu"},
	"aws":        {"amazonaws.com"},
	"mailgun":    {"mailgun.org"},
	"sendgrid":   {"sendgrid.net"},
	"postmark":   {"postmarkapp.com"},
	"yandex":     {"yandex.ru", "yandex.net"},
}

// Mail Provider Default DKIM Selectors
var ProviderDKIMMap = map[string][]string{
	"google":     {"google"},
	"microsoft":  {"selector1"},
	"fastmail":   {"fm1", "fm2", "fm3", "mesmtp"},
	"proton":     {"protonmail", "protonmail2", "protonmail3"},
	"protonmail": {"protonmail", "protonmail2", "protonmail3"},
	"icloud":     {"sig1"},
	"zoho":       {"zoho", "zmail"},
	"aws":        {"amazonses"},
	"mailgun":    {"pic", "k1", "smtp"},
	"sendgrid":   {"s1", "s2"},
	"postmark":   {"pm"},
	"yandex":     {"mail"},
}

// Alert & Log Notification Messages
const (
	// DNS Alerts
	MsgAlertDNSFailed       = "DNS Resolution Failed: %s (%s)"
	MsgAlertDNSMismatch     = "Mismatch on %s (%s)! Missing expected: %s. Found: [%s]"
	MsgAlertDNSUnauthorized = "Unauthorized record found on %s (%s): %s! Expected: [%s]"

	// DNS Info
	MsgLogDNSCustomResolverFailed = "Custom resolver %s failed for %s. Falling back to global pool."

	// DNSSEC Alerts
	MsgAlertDNSSECNetworkError = "DNSSEC Check Failed for %s: %s"
	MsgAlertDNSSECUnsigned     = "DNSSEC: Zone is completely unsigned (No DS or DNSKEY) for %s"
	MsgAlertDNSSECNoDS         = "DNSSEC: No DS record at parent for %s"
	MsgAlertDNSSECNoDNSKEY     = "DNSSEC: No DNSKEY records found for %s"
	MsgAlertDNSSECMismatch     = "DNSSEC: DS does not match any DNSKEY for %s"
	MsgAlertDNSSECRRSIGFailed  = "DNSSEC: dns.RRSIG verification failed for %s"
	MsgAlertDNSSECChainBroken  = "DNSSEC: Full chain of trust validation failed (AD flag missing) for %s"

	// CAA Alerts
	MsgAlertCAAMissing      = "CAA: No %s records found for %s"
	MsgAlertCAAUnauthorized = "CAA: Unauthorized CA '%s' in %s record for %s"
	MsgAlertCAAExpectedNA   = "CAA: Expected CA '%s' missing from %s record for %s"

	// CT Logs Alerts
	MsgAlertNewSSLCert = "New SSL Certificate issued for %s by %s. Match: %s"

	// Email Security Alerts
	MsgAlertEmailNoMX           = "Email Security: No MX records found for %s"
	MsgAlertEmailMXMissing      = "Email Security: Missing expected MX %s on %s. Found: [%s]"
	MsgAlertEmailMXUnauthorized = "Email Security: Unauthorized MX %s on %s! Expected: [%s]"
	MsgAlertEmailMXHijack       = "MX HIJACK DETECTED for %s! Expected provider %s infrastructure, found: [%s]"
	MsgAlertEmailNoSPF          = "Missing SPF record for %s"
	MsgAlertEmailMultiSPF       = "Multiple SPF records found for %s! This breaks email delivery."
	MsgAlertEmailMultiDMARC     = "Multiple DMARC records found for %s! This breaks email delivery."
	MsgAlertEmailNoDMARC        = "Missing DMARC record for %s (_dmarc.%s)"
	MsgAlertEmailNoDKIM         = "No valid DKIM records found for %s (checked: %s)"

	// Email Security Info
	MsgLogEmailUnknownProvider = "Unknown mail_provider '%s' for %s. Skipping MX hijack prevention."

	// RDAP Alerts
	MsgAlertRDAPExpiry                = "%s expires in %.0f days"
	MsgAlertRDAPExpired               = "Domain %s is EXPIRED! (expired %.0f days ago)"
	MsgAlertRDAPUnauthorizedNS        = "unauthorized ns on %s: %s"
	MsgAlertRDAPMissingNS             = "expected ns missing from %s: %s"
	MsgAlertRDAPSuspended             = "domain %s suspended! status: %s"
	MsgAlertRDAPUnlocked              = "%s is unlocked (missing transfer prohibitions)"
	MsgAlertRDAPDiscrepancy           = "Hierarchy discrepancy for %s: %s"
	MsgAlertRDAPRegistrarIDMismatch   = "Registrar mismatch for %s: expected IANA ID '%s', found '%s'"
	MsgAlertRDAPRegistrarNameMismatch = "Registrar mismatch for %s: expected registrar containing '%s', found '%s'"

	// Nameserver Health Alerts
	MsgAlertNSUnreachable      = "Nameserver %s unreachable for %s: %v"
	MsgAlertNSNonAuthoritative = "Nameserver %s not authoritative (AA flag missing) for %s"
	MsgAlertNSSOALag           = "Secondary nameserver %s SOA serial (%d) lags behind primary %s (%d) for %s"
	MsgAlertNSSOAMismatch      = "Secondary nameserver %s SOA serial (%d) differs from primary %s (%d) for %s"
	MsgAlertNSDNSKEYMissing    = "Secondary nameserver %s missing DNSKEY records present on primary for %s"
	MsgAlertNSDNSKEYMismatch   = "Secondary nameserver %s serves mismatched DNSKEY records for %s (dumb secondary must replicate primary keys, independent signing not supported)"
	MsgAlertNSDNSKEYUnexpected = "Secondary nameserver %s serves DNSKEY records for %s but primary is unsigned (dumb secondary must be unsigned)"
	MsgAlertNSMissingSOA       = "Nameserver %s did not return an SOA record for %s"

	// WHOIS Info
	MsgLogWHOISFallback = "RDAP failed for %s, attempting WHOIS fallback..."
	MsgLogWHOISFailed   = "WHOIS fallback also failed for %s: %v"
	MsgLogWHOISSuccess  = "WHOIS fallback succeeded for %s"
	MsgLogHierarchyWarn = "Hierarchy discrepancy detected for %s: %s"

	// Redacted Notification Messages
	MsgRedactedDNSSECFailedNetwork  = "DNSSEC query failed due to network error."
	MsgRedactedDNSSECDisabled       = "DNSSEC is completely disabled or stripped."
	MsgRedactedDNSSECDSNotFound     = "DNSSEC DS record is missing."
	MsgRedactedDNSSECDNSKEYNotFound = "DNSSEC DNSKEY record is missing."
	MsgRedactedDNSSECDSMismatch     = "DNSSEC DS does not match KSK."
	MsgRedactedDNSSECRRSIGFailed    = "DNSSEC dns.RRSIG verification failed or expired."
	MsgRedactedDNSSECChainFailed    = "DNSSEC Full chain of trust validation failed."

	MsgRedactedEmailNoMX           = "No MX records found. Email delivery is broken."
	MsgRedactedEmailMXMissing      = "Expected MX record is missing."
	MsgRedactedEmailMXUnauthorized = "Unauthorized MX record detected."
	MsgRedactedEmailMXHijack       = "MX records do not match the expected provider (Possible Hijack)."
	MsgRedactedEmailNoSPF          = "No valid SPF record found."
	MsgRedactedEmailMultiSPF       = "Multiple SPF records found (Invalid Configuration)."
	MsgRedactedEmailMultiDMARC     = "Multiple DMARC records found (Invalid Configuration)."
	MsgRedactedEmailNoDMARC        = "No valid DMARC record found."
	MsgRedactedEmailNoDKIM         = "No valid DKIM records found for expected selectors."

	MsgRedactedCAADenyAllMissing   = "Missing %s deny-all record (';')."
	MsgRedactedCAAUnauthorizedDeny = "Unauthorized CA '%s' in %s (expected deny all)."
	MsgRedactedCAAMissing          = "Missing %s records."
	MsgRedactedCAAExpectedMissing  = "Expected CA '%s' missing in %s."
	MsgRedactedCAAUnauthorized     = "Unauthorized CA '%s' in %s."

	MsgRedactedDNSResolutionFailed = "DNS Resolution Failed for %s (%s)."

	MsgRedactedRDAPExpired        = "Domain registration has EXPIRED."
	MsgRedactedRDAPExpiring       = "Domain is expiring in %d days."
	MsgRedactedRDAPSuspended      = "Domain suspended (Status: %s)."
	MsgRedactedRDAPUnlocked       = "Domain transfer lock is disabled."
	MsgRedactedRDAPRegistrarID    = "Registrar IANA ID mismatch (expected %s)."
	MsgRedactedRDAPRegistrarName  = "Registrar name mismatch (expected %s)."
	MsgRedactedRDAPUnauthorizedNS = "Unauthorized nameserver detected."
	MsgRedactedRDAPMissingNS      = "Expected nameserver is missing."

	MsgRedactedNewSSLCert = "New SSL Certificate issued by %s for %s."

	MsgRedactedNSUnreachablePrimary   = "Primary nameserver unreachable."
	MsgRedactedNSUnreachableSecondary = "Secondary nameserver unreachable."
	MsgRedactedNSNonAuthoritative     = "Nameserver missing AA flag."
	MsgRedactedNSMissingSOA           = "Nameserver missing SOA record."
	MsgRedactedNSSOALags              = "Secondary nameserver SOA serial lags behind primary."
	MsgRedactedNSSOADiffers           = "Secondary nameserver SOA serial differs from primary."
	MsgRedactedNSDNSKEYMissing        = "Secondary nameserver missing DNSKEY records present on primary."
	MsgRedactedNSDNSKEYMismatch       = "Secondary nameserver serves mismatched DNSKEY records."
	MsgRedactedNSDNSKEYUnexpected     = "Secondary nameserver serves DNSKEY records but primary is unsigned."

	// System Info
	MsgLogStartup          = "Daemon initialized successfully. Domains: %d, DNS Records: %d"
	MsgLogHTTPAPI          = "HTTP API running on :%s (Endpoints: /health, /api/state, /api/certs)"
	MsgLogTelegramConfig   = "Telegram notifications configured."
	MsgLogTelegramDisabled = "Telegram disabled: token and chat ID must both be configured."
	MsgLogShutdownSignal   = "Received signal: %v. Initiating graceful shutdown..."
	MsgLogShutdownComplete = "Daemon shutdown complete."

	// Internal Operational Logs
	MsgLogNtfyRequestFailed            = "Ntfy request creation failed"
	MsgLogNtfyDeliveryFailed           = "Ntfy delivery failed"
	MsgLogNtfyRequestError             = "Ntfy request error"
	MsgLogNotificationClientMissing    = "Notification HTTP client is not configured"
	MsgLogNotificationDeliveryDeferred = "Notification delivery deferred"
	MsgLogNotificationBacklogFull      = "Notification backlog full; deferring alert until the next cycle"
	MsgErrTelegramChatIDMissing        = "telegram chat_id is missing, cannot send notifications"
	MsgErrTelegramTokenMissing         = "telegram token is missing, cannot send notifications"
	MsgErrNoProvidersConfigured        = "no notification providers configured"

	MsgErrDotSweepFetchFailed        = "dotsweep pricing request failed"
	MsgErrDotSweepParseError         = "dotsweep json parse error"
	MsgErrDotSweepNoData             = "no tld pricing data in dotsweep response"
	MsgLogDotSweepFetchFailed        = "Failed to fetch TLD renewal pricing from DotSweep"
	MsgLogPricingFetchFailed         = "Failed to resolve portfolio renewal pricing"
	MsgErrPricingManagerNil          = "pricing manager is nil"
	MsgErrDomainNegativeRenewalPrice = "domain %s: renewal_price cannot be negative"
	MsgErrNoTierData                 = "no registry or registrar tier data available"

	MsgLogTelegramMarshalFailed           = "Telegram payload marshal failed"
	MsgLogTelegramRequestFailed           = "Telegram request creation failed"
	MsgLogTelegramDeliveryFailed          = "Telegram delivery failed"
	MsgLogTelegramRequestError            = "Telegram request error"
	MsgLogTelegramPayloadTooLarge         = "Telegram alert exceeds provider message budget"
	MsgLogTelegramRejected                = "Telegram rejected notification"
	MsgLogRDAPRefreshFailed               = "Failed to refresh RDAP bootstrap from IANA; falling back to cached registry"
	MsgLogWHOISPanicked                   = "WHOIS query panicked"
	MsgLogRDAPReturned404                 = "RDAP returned 404, attempting WHOIS fallback"
	MsgLogRDAPRateLimited                 = "RDAP rate limited, falling back to WHOIS"
	MsgLogWHOISRateLimitedRetry           = "WHOIS query rate limited, retrying"
	MsgLogWHOISUnregistered               = "WHOIS reports domain is unregistered (404)"
	MsgLogSkippingUnsafeRDAP              = "Skipping unsafe RDAP referral URL"
	MsgLogQueryingRegistrarRDAP           = "Querying registrar RDAP link"
	MsgLogRegistrarReferralInvalid        = "Registrar RDAP referral could not be read"
	MsgLogRateLimitedRegistrarRDAP        = "Rate limited by registrar RDAP"
	MsgLogFollowingWHOISReferral          = "Following WHOIS referral"
	MsgLogLoopIntervalBelowMin            = "loop_interval_days is below minimum (0.125 days / 3 hours); defaulting to 0.125"
	MsgLogLoopIntervalAboveMax            = "loop_interval_days exceeds maximum (365 days); defaulting to 365"
	MsgLogResolverUnreachable             = "Configured resolver unreachable during health check"
	MsgLogReadCTLogFailed                 = "Failed to read CT log history file"
	MsgLogHTTPServerFailed                = "HTTP server failed"
	MsgLogStateTransition                 = "State transition"
	MsgLogPanicDNSWorker                  = "Recovered from unexpected panic in DNS check worker"
	MsgLogPanicDomainWorker               = "Recovered from unexpected panic in Domain check worker"
	MsgLogPanicRDAP                       = "Recovered from unexpected panic in RDAP evaluation"
	MsgLogPanicCTLogs                     = "Recovered from unexpected panic in CT logs evaluation"
	MsgLogWriteCTStateFailed              = "Failed to write ct_state.json"
	MsgLogStateMarshalFailed              = "Failed to encode monitoring state"
	MsgLogCTAcknowledgementPending        = "CT notification acknowledgement remains pending"
	MsgLogMonitoringCycleCompleted        = "Monitoring cycle completed"
	MsgLogConfigError                     = "Configuration error"
	MsgLogInitError                       = "Initialization error"
	MsgLogDataDirEnsureFailed             = "Failed to ensure data directory exists (ensure directory is writable by UID 65532 or use :U volume mount)"
	MsgLogCTLogsDirEnsureFailed           = "Failed to ensure ct_logs directory exists (ensure directory is writable by UID 65532 or use :U volume mount)"
	MsgLogParseCTStateFailed              = "Failed to parse ct_state.json"
	MsgLogHTTPServerStopped               = "HTTP server stopped unexpectedly"
	MsgLogMonitoringEngineStopped         = "Monitoring engine stopped unexpectedly"
	MsgLogApplicationFailed               = "Application stopped with an error"
	MsgLogMonitoringEngineTimeout         = "Monitoring engine shutdown timed out"
	MsgErrMonitoringEngineExited          = "stopped before shutdown"
	MsgErrMonitoringEngineShutdownTimeout = "did not finish within shutdown budget"
	MsgLogCTLogsPollingFailed             = "CT logs polling failed"
	MsgLogDiscoveredNewCerts              = "Discovered new SSL certificates via CT logs"
	MsgLogSaveCTLogsFailed                = "Failed to save CT logs history"
	MsgLogCTLogsBackfillFailed            = "CT logs backfill failed"
	MsgLogSaveBackfilledCTLogsFailed      = "Failed to save backfilled CT logs"
	MsgLogUnmarshalCTLogFailed            = "Failed to unmarshal existing CT log history; continuing with empty list"
)

// Extracted Constants
const (
	JSONResponseInvalidDomain = `{"error": "invalid domain"}`
	JSONResponseStatusOK      = `{"status":"ok"}`
	JSONResponseStatusInit    = `{"status":"initializing"}`
	JSONResponseEmptyArray    = `[]`
	DefaultMaxConcurrency     = 32
	DNSSECClockSkew           = int64(300)
)

// HTTP Routes & Query Params
const (
	RouteHealth            = "GET /health"
	RouteAPIState          = "GET /api/state"
	RouteAPICerts          = "GET /api/certs"
	RouteAPICTLogs         = "GET /api/ctlogs/{domain}"
	ParamDomain            = "domain"
	RDAPObjectClassDomain  = "domain"
	ParamName              = "name"
	ParamType              = "type"
	ParamDO                = "do"
	ParamDOValue           = "1"
	ParamAfter             = "after"
	ParamRegistrars        = "registrars"
	RecordTypeDNSKEY       = "DNSKEY"
	FieldChatID            = "chat_id"
	FieldText              = "text"
	FieldParseMode         = "parse_mode"
	FieldCacheAge          = "cache_age"
	FieldError             = "error"
	FieldDomain            = "domain"
	FieldPriority          = "priority"
	FieldTag               = "tag"
	FieldPanic             = "panic"
	FieldOperation         = "operation"
	FieldPath              = "path"
	FieldCount             = "count"
	FieldBytes             = "bytes"
	FieldStatus            = "status"
	FieldResponse          = "response"
	FieldResolver          = "resolver"
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
	DoHQueryTemplate       = "?name=%s&type=DNSKEY&do=1"
	PathRDAPDomain         = "/domain/"
)

// Server Defaults & Subdirectories
const (
	DefaultIdleTimeout         = 120 * time.Second
	DefaultMaxHeaderValueCount = 100
	DefaultCTStateFileName     = "ct_state.json"
	DefaultLogTimeFormat       = "2006-01-02 15:04:05 MST"
	DefaultHTTPSPort           = "443"
	TestFqdn                   = "example.com"
	DirContainerApp            = "/app"
	CAAIssuerDenyAll           = ";"
	LayoutCompactDateTime      = "20060102150405"
	TempFilePattern            = ".tmp-*"
)

// Default DNS Resolvers
var defaultResolvers = [...]string{"1.1.1.1", "8.8.8.8", "9.9.9.9"}

// DefaultResolvers returns a defensive copy of the default DNS resolver addresses.
func DefaultResolvers() []string {
	return slices.Clone(defaultResolvers[:])
}

// Common Prefixes
const (
	PrefixBearer     = "Bearer "
	PrefixBasic      = "Basic "
	PrefixAlias      = "alias:"
	PrefixWildcard   = "*."
	PrefixWWW        = "www."
	PrefixAlgo       = "ALGO_"
	PrefixParamAfter = "?after="
)

// Delimiters & Separators
const (
	SeparatorErrorPipe = " | "
)

// Provider & Component Names
const (
	NameNtfyProvider       = "Ntfy provider"
	NameTelegramProvider   = "Telegram provider"
	NameOpMonitoringCycle  = "Monitoring cycle"
	NameOpRDAPCheckWorker  = "RDAP check worker"
	NameOpCTLogsWorker     = "CT logs worker"
	NameOpMonitoringEngine = "Monitoring engine"
	CheckTypeRDAP          = "RDAP"
	CheckTypeDNS           = "DNS"
	CheckTypeEmail         = "Email"
	CheckTypeCAA           = "CAA"
	CheckTypeDNSSEC        = "DNSSEC"
	CheckTypeNSHealth      = "NSHealth"
	CheckTypeCTLogs        = "CTLogs"
	TargetKeyDomain        = "domain"
	TargetKeyRecord        = "record"
	FlagConfig             = "config"
	FlagConfigShort        = "c"
	FlagConfigUsage        = "Path to the JSON config file"
	FlagConfigShortUsage   = "Path to the JSON config file (shorthand)"
)

// Notification Formatting & Delimiters
const (
	AlertConditionFormat         = "%s %s: %s %s (Since: %s)"
	AlertConditionRedactedFormat = "%s %s: %s (Since: %s)"
	AlertCTIdentityPrefix        = "CT:"
	AlertNewCertificatePrefix    = "New Cert Issued: "
	AlertNewCertificateRedacted  = "New Cert Issued"
	TelegramAlertHeader          = "⚠️ <b>Domain Monitor Alerts</b>\n\n"
	TelegramAlertHeaderCont      = "⚠️ <b>Domain Monitor Alerts (Cont.)</b>\n\n"
	TelegramBullet               = "• "
	TelegramPrefixFormat         = "<b>[%s]</b> "
	TelegramLineFormat           = "• %s%s\n"
	NtfyPrefixFormat             = "[%s] "
	TagSeparator                 = ","
	AlertChunkSeparator          = "\n\n"
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
	MsgRedactedDNSMismatchPrefix    = "Mismatch on %s (%s). Prefix not found."
	MsgRedactedDNSMismatchSubstring = "Mismatch on %s (%s). Expected substring not found."
	MsgRedactedDNSMismatchAnyOf     = "Mismatch on %s (%s). None of expected values matched."
	MsgRedactedDNSMismatchExact     = "Mismatch on %s (%s). Values aren't mapped as expected."
	MsgRedactedDNSUnauthorized      = "Unauthorized record found on %s (%s)."

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
	MsgErrInternalCTLogsPanic    = "internal ct logs panic: %s"
	MsgErrCheckTimeoutOrCanceled = "check timed out or canceled"
	MsgErrNilConnection          = "nil connection returned for %s"
	MsgErrNonTLSConnection       = "unexpected non-TLS connection for %s"
	MsgErrNoPeerCertsFound       = "no peer certificates found for %s"
	MsgErrLookupEmptyResponse    = "lookup %s on %s: empty response"
	MsgErrLookupQuestionMismatch = "lookup %s on %s: response question mismatch or missing"
	MsgErrLookupServerError      = "lookup %s on %s: server error (%s)"
	MsgErrLookupServerErrorCode  = "lookup %s on %s: server returned error code %d"
	MsgErrNoIPRecordsForHost     = "no IP records found for host %s"
	MsgErrUnsupportedDNSType     = "unsupported DNS type: %s"
	MsgErrNoMXRecordsFound       = "no MX records found"

	MsgErrUnableToParseDate                  = "unable to parse date format: %s"
	MsgErrRDAPHTTPError                      = "rdap HTTP error: %d"
	MsgErrRDAPLookupFailedAllCandidates      = "rdap lookup failed across all candidate servers"
	MsgErrWHOISParsingFailed                 = "whois parsing failed to extract required domain fields"
	MsgErrWHOISPanicked                      = "whois query panicked"
	MsgErrHistorySaveFailed                  = "History save failed: %s"
	MsgErrBackfillError                      = "Backfill error: %s"
	MsgErrBackfillSaveFailed                 = "Backfill save failed: %s"
	MsgErrAPIReturnedStatus                  = "API returned %d: %s"
	MsgErrJSONParse                          = "json parse error"
	MsgErrInvalidDomainCertsHistory          = "invalid domain for certs history: %s"
	MsgErrInvalidFilePathCertsHistory        = "invalid file path for certs history: %s"
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
	MsgErrDomainEmptyExpectedNS              = "domain %s has an empty entry in expected_ns at index %d"
	MsgErrDomainEmptySecondaryNS             = "domain %s has an empty entry in secondary_ns at index %d"
	MsgErrDomainMissingName                  = "domain %s is missing a mandatory 'name' field"
	MsgErrDuplicateDomainName                = "duplicate domain name %s; each domain must have a unique name"
	MsgErrSecondaryNSWithoutPrimary          = "domain %s has secondary_ns configured but no primary expected_ns configured"
	MsgErrVerifyNSHealthWithoutPrimary       = "domain %s has verify_ns_health enabled but no primary expected_ns configured"
	MsgErrDelegatedMissingRootZone           = "delegated domain %s is missing a mandatory 'root_zone' field"
	MsgErrMailProviderAndMXMutuallyExclusive = "domain %s has both mail_provider and mx_records set; these are mutually exclusive"
	MsgErrDNSEmptyHostname                   = "dns record at index %d has an empty hostname"
	MsgErrDNSMissingName                     = "dns record %s (%s) is missing a mandatory 'name' field"
	MsgErrDuplicateDNSName                   = "duplicate dns record name %s; each dns record must have a unique name"
	MsgErrDNSMissingType                     = "dns record %s is missing a type (e.g. A, CNAME)"

	MsgErrExpectedIPv6ForTypeA              = "dns record %s (%s): expected %s is an IPv6 address, but record type is A (requires IPv4)"
	MsgErrExpectedNotValidIPv4              = "dns record %s (%s): expected %s is not a valid IPv4 address for type A"
	MsgErrExpectedIPv4ForTypeAAAA           = "dns record %s (%s): expected %s is an IPv4 address, but record type is AAAA (requires IPv6)"
	MsgErrExpectedNotValidIPv6              = "dns record %s (%s): expected %s is not a valid IPv6 address for type AAAA"
	MsgErrExpectedNotValidIP                = "dns record %s (%s): expected %s is not a valid IPv4 or IPv6 address for composite type IP"
	MsgErrNtfyURLMandatory                  = "cannot initialize dependencies: notifications.ntfy.url is mandatory (primary notification mechanism)"
	MsgErrNtfyURLRequired                   = "ntfy and its URL are required"
	MsgErrFailedCreateNtfyRequest           = "failed to create ntfy request"
	MsgErrNtfyURLUnreachable                = "ntfy URL provided is unreachable"
	MsgErrAllResolversFailed                = "all configured resolvers failed health checks"
	MsgErrInitAppNil                        = "cannot initialize dependencies: app is nil"
	MsgErrInitConfigNil                     = "cannot initialize dependencies: config is nil"
	MsgErrInitNotifierNil                   = "cannot initialize dependencies: notifier is nil"
	MsgErrNilStringListReceiver             = "nil StringList receiver"
	MsgPrefixLookupOn                       = "lookup %s on %s"
	MsgPrefixLookupOnWithRcode              = "lookup %s on %s (%s)"
	MsgErrLookupFailedAandAAAA              = "lookup failed for A and AAAA"
	MsgErrMXQueryError                      = "MX query error"
	MsgErrInvalidNSAddress                  = "invalid nameserver address %s"
	MsgErrFailedToResolveIP                 = "failed to resolve IP"
	MsgErrNoRDAPServer                      = "no RDAP server"
	MsgErrWHOISQueryFailed                  = "whois query failed"
	MsgErrFailedToQueryCAA                  = "failed to query CAA"
	MsgErrInvalidEmptyDomainCAA             = "invalid empty domain for CAA"
	MsgErrFailedToQueryCAAPattern           = "Failed to query CAA for %s: %s"
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
	MsgErrSOALookupFailed                = "SOA lookup failed: %s"
	MsgErrPrimaryNSNotAuthoritative      = "Primary nameserver not authoritative (AA flag missing)"
	MsgErrSecondaryNSNotAuthoritative    = "Secondary nameserver not authoritative (AA flag missing)"
	MsgErrNoSOARecordReturned            = "No SOA record returned in answer or authority sections"
	MsgErrDomainNotFound404              = "Domain not found (404)"
	MsgErrRDAPAndWHOIS                   = "RDAP: %w | WHOIS: %w"
)

// RegistryDateLayouts specifies supported WHOIS/RDAP date format layouts for parseFlexibleDate.
var RegistryDateLayouts = [...]string{
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
	MsgErrTLS                                 = "tls: %w"
	MsgErrIPv6ResolverTimeout                 = "IPv6 resolver timeout"
	MsgErrResolverTimeout                     = "resolver timeout"
	MsgErrCNAMELookupTimedOut                 = "CNAME lookup timed out"
	MsgErrUntrustedChain                      = "untrusted chain"
	MsgErrMockDohError                        = "mock doh error"
	MsgErrMockDNSSECError                     = "mock DNSSEC error"
	MsgErrResolutionFailed                    = "resolution failed"
	MsgErrMockError                           = "mock error"
	MsgErrResolverErrorCNAMELoopDetected      = "resolver error: CNAME loop detected"
	MsgErrTemporaryDNSFailure                 = "temporary DNS failure"
	MsgErrDNSTimeout                          = "DNS timeout"
	MsgErrQuotaExceeded                       = "quota exceeded"
	MsgErrCommitFailed                        = "commit failed"
	MsgErrDiskFull                            = "disk full"
	MsgErrDiskUnavailable                     = "disk unavailable"
	MsgErrTLSDial                             = "TLS dial %s: %w"
	MsgErrTLSCertificateAt                    = "TLS certificate at %s: %w"
	MsgErrHostname                            = "hostname %s: %w: %w"
	MsgErrLeafCertificateIsOutsideIts         = "leaf certificate is outside its validity period: %w: %w"
	MsgErrSelfsignedServerCertificate         = "self-signed server certificate: %w: %w"
	MsgErrCertificateChain                    = "certificate chain: %w: %w"
	MsgErrQueryDNSForOnTruncated              = "query DNS for %s on %s: truncated UDP answer and TCP resolver is not configured"
	MsgErrQueryDNSForOnTCP                    = "query DNS for %s on %s: TCP answer is truncated"
	MsgErrExpectedOneMXRecordWith             = "%w: expected one MX record with preference 0 and the root exchange"
	MsgErrResolveExpectedAlias                = "resolve expected alias %s: %w"
	MsgErrInvalidDMARCPolicyAt                = "invalid DMARC policy at %s"
	MsgErrNameserverAddressDidNotReturn       = "nameserver address %s did not return an authoritative SOA for %s"
	MsgErrNameserverAddressReturnedANil       = "nameserver address %s returned a nil SOA response"
	MsgErrNilDnskeyResponseFor                = "nil DNSKEY response for %s"
	MsgErr                                    = "%s: %w"
	MsgErrDiskFailed                          = "disk failed"
	MsgErrResolverUnavailable                 = "resolver unavailable"
	MsgErrWHOISProviderUnavailable            = "WHOIS provider unavailable"
	MsgErrEncodeCTCheckpoint                  = "encode CT checkpoint: %w"
	MsgErrCTCheckpointExceedsBytes            = "CT checkpoint exceeds %d bytes"
	MsgErrDecodeCTCheckpoint                  = "decode CT checkpoint: %w"
	MsgErrCTCheckpointMustBeAn                = "CT checkpoint must be an object"
	MsgErrDecodeVersionedCTCheckpoint         = "decode versioned CT checkpoint: %w"
	MsgErrUnsupportedCTCheckpointVersion      = "unsupported CT checkpoint version %d"
	MsgErrCTCheckpointHasNoDomains            = "CT checkpoint has no domains object"
	MsgErrDecodeLegacyCTCheckpoint            = "decode legacy CT checkpoint: %w"
	MsgErrInvalidCTCheckpointDomain           = "invalid CT checkpoint domain %q"
	MsgErrCTCheckpointForExceedsRetention     = "CT checkpoint for %s exceeds retention bounds"
	MsgErrCTCheckpointForHasInvalid           = "CT checkpoint for %s has invalid seen IDs"
	MsgErrCTCheckpointForHasUntracked         = "CT checkpoint for %s has untracked pending discovery"
	MsgErrReadCTCheckpoint                    = "read CT checkpoint %s: %w"
	MsgErrLoadCTCheckpoint                    = "load CT checkpoint %s: %w"
	MsgErrBackUpLegacyCTCheckpoint            = "back up legacy CT checkpoint %s: %w"
	MsgErrMigrateLegacyCTCheckpoint           = "migrate legacy CT checkpoint %s: %w"
	MsgErrCommitCTNotificationAcknowledgement = "commit CT notification acknowledgement: %w"
	MsgErrCTScanCursorRepeatedFor             = "CT scan cursor repeated for %s"
	MsgErrCTHistoryWriterIsNot                = "CT history writer is not configured for %s"
	MsgErrSaveCTHistoryFor                    = "save CT history for %s: %w"
	MsgErrBuildCTCursorURLFor                 = "build CT cursor URL for %s: %w"
	MsgErrWaitForCTRequestRate                = "wait for CT request rate limit: %w"
	MsgErrCTHTTPClientIsNot                   = "CT HTTP client is not configured for %s"
	MsgErrCTAPIResponseExceedsBytes           = "CT API response exceeds %d bytes"
	MsgErrReadCTAPIErrorResponse              = "read CT API error response: %w"
	MsgErrCTPageClaimsANext                   = "CT page claims a next page without a cursor"
	MsgErrCTPageHasAMissing                   = "CT page has a missing or duplicate certificate ID"
	MsgErrParseCTHistoryFor                   = "parse CT history for %s: %w"
	MsgErrReadCTHistoryFor                    = "read CT history for %s: %w"
	MsgErrEncodeCTHistoryFor                  = "encode CT history for %s: %w"
	MsgErrCTHistoryForExceedsBytes            = "CT history for %s exceeds %d bytes"
	MsgErrOpenCTFile                          = "open CT file %s: %w"
	MsgErrReadCTFile                          = "read CT file %s: %w"
	MsgErrCTFileExceedsBytes                  = "CT file %s exceeds %d bytes"
	MsgErrCommitCTState                       = "commit CT state %s: %w"
	MsgErrLoadConfiguration                   = "load configuration: %w"
	MsgErrInitializeApplication               = "initialize application: %w"
	MsgErrHTTPServerStopped                   = "HTTP server stopped: %w"
	MsgErr2                                   = "%s: %s"
	MsgErrShutDownHTTPServer                  = "shut down HTTP server: %w"
	MsgErrCreateDataDirectory                 = "create data directory %s: %w"
	MsgErrCreateCTLogsDirectory               = "create CT logs directory %s: %w"
	MsgErrLoadCTState                         = "load CT state %s: %w"
	MsgErrRootCause                           = "root cause"
	MsgErrCustomError                         = "custom error"
	MsgLogTestErrorMessage                    = "Test error message"
	MsgLogTestWarnMessage                     = "Test warn message"
	MsgLogTestInfoMessage                     = "Test info message"
	MsgLogSampleLocalizedMessage              = "Sample localized message"
	MsgLogTestInfof                           = "Test infof %s"
	MsgLogTestErrorf                          = "Test errorf %s"
	MsgLogTestWarnf                           = "Test warnf %d"
	MsgLogTestDebugMessage                    = "Test debug message"
	MsgLogTestDebugf                          = "Test debugf %s"
	MsgErrInvalidServerPort                   = "invalid server port: %w"
	MsgErrValidateConfiguredResolvers         = "validate configured resolvers (%d): %s"
	MsgErrInvalidResolver                     = "invalid resolver %q: %w"
	MsgErrInvalidDohURL                       = "invalid DoH URL: %w"
	MsgErrValidateNotificationsntfy           = "validate notifications.ntfy: %s"
	MsgErrInvalidNtfyURL                      = "invalid ntfy URL: %w"
	MsgErrPortMustBeBetween1                  = "port %q must be between 1 and 65535"
	MsgErrResolverEndpointIsEmpty             = "resolver endpoint %q is empty"
	MsgErrExpectedAnIPAddressOr               = "expected an IP address or host:port: %w"
	MsgErrResolverEndpointHasAnInvalid        = "resolver endpoint %q has an invalid host"
	MsgErrExpectedAnHTTPSURLWith              = "expected an http(s) URL with a host"

	MsgErrInvalidMonitoredDomain               = "invalid monitored domain %q"
	MsgErrRootZoneIsNotA                       = "root zone %q is not a parent of delegated zone %q"
	MsgErrUnknownMailProviderFor               = "unknown mail provider %q for %s"
	MsgErrUnsupportedDNSRecordTypeFor          = "unsupported DNS record type %q for %s"
	MsgErrUnsupportedDNSMatchTypeFor           = "unsupported DNS match type %q for %s"
	MsgErrMissingExpectedDNSRecordsFor         = "missing expected DNS records for %s"
	MsgErrInvalidCustomResolverFor             = "invalid custom resolver for %s: %w"
	MsgErrEmptyExpectedDNSRecordsFor           = "empty expected DNS records for %s with %s match"
	MsgErrInvalidExpectedCAAValueFor           = "invalid expected CAA value %q for %s: %w"
	MsgErrInvalidExpectedCAAValueFor2          = "invalid expected CAA value %q for %s"
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
	MsgErrRDAPHTTPClientIsNot                  = "RDAP HTTP client is not configured for %s"
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
	Str20060102                           = "2006-01-02"
	StrAppStateIsNil                      = "app state is nil"
	StrAutoRenewGracePeriod               = "Auto-Renew Grace Period discrepancy: Registry expiration ("
	StrCAAAliasTraversalLimit             = "CAA alias traversal limit reached at %s"
	StrCacheAge                           = "cache_age"
	StrClientdeleteprohibited             = "clientdeleteprohibited"
	StrClienthold                         = "clienthold"
	StrClientrenewprohibited              = "clientrenewprohibited"
	StrClienttransferprohibited           = "clienttransferprohibited"
	StrClientupdateprohibited             = "clientupdateprohibited"
	StrConnectionRefused                  = "connection refused"
	StrCreated                            = "created"
	StrCT                                 = "CT:"
	StrCTBaselineBackfillIs               = "CT baseline backfill is still in progress"
	StrCTQuotaExhaustedDeferred           = "CT quota exhausted; deferred until next cycle"
	StrCTScanCoverageIs                   = "CT scan coverage is incomplete; scan, seen ID or pending budget reached"
	StrDSQ                                = "%d %s %q"
	StrDate                               = "date"
	StrDelegationReturnedNoNameservers    = "delegation returned no nameservers"
	StrDeleteprohibited                   = "deleteprohibited"
	StrDKIM                               = "DKIM: "
	StrDMARC                              = "_dmarc."
	StrDmarc2                             = "DMARC: "
	StrDomain                             = "/domain/"
	StrDomain2                            = "domain"
	StrDomainkey                          = "._domainkey."
	StrEmpty                              = ""
	StrError                              = "error"
	StrErrorCTHistoryIs                   = `{"error":"CT history is invalid"}`
	StrErrorCTHistoryReader               = `{"error":"CT history reader unavailable"}`
	StrErrorCTHistoryUnavailable          = `{"error":"CT history unavailable"}`
	StrErrorDomainIsNot                   = `{"error":"domain is not monitored"}`
	StrExample60InCAA                     = "example. 60 IN CAA "
	StrExpiration                         = "expiration"
	StrExpire                             = "expire"
	StrFailedToQueryCNAME                 = "failed to query CNAME for CAA at %s: %v"
	StrHold                               = "hold"
	StrHTTP                               = "http"
	StrHTTPS                              = "https"
	StrIOTimeout                          = "i/o timeout"
	StrIANA                               = "IANA "
	StrIana2                              = "iana"
	StrIANARegistrarID                    = "iana registrar id"
	StrIn                                 = " in "
	StrInternal                           = ".internal"
	StrInternalCTCheckPanic               = "internal CT check panic"
	StrInternalDNSCheckPanic              = "internal DNS check panic"
	StrInternalRDAPCheckPanic             = "internal RDAP check panic"
	StrInternic                           = "internic"
	StrInvalidOrCyclicCNAME               = "invalid or cyclic CNAME while searching CAA at %s"
	StrJSON                               = ".json"
	StrJustNow                            = "just now"
	StrLastChanged                        = "last changed"
	StrLastModified                       = "last modified"
	StrLegacyBak                          = ".legacy.bak"
	StrLimit                              = "limit"
	StrLocal                              = ".local"
	StrLocalhost                          = "localhost"
	StrN                                  = "\n"
	StrN2                                 = "n"
	StrNameserverDesyncRegistryDelegation = "Nameserver desync: Registry delegation ["
	StrNoCAAPolicyFound                   = "no CAA policy found"
	StrNoStore                            = "no-store"
	StrNoSuchHost                         = "no such host"
	StrNone                               = "none"
	StrNotApplicable                      = "not applicable"
	StrNp                                 = "np"
	StrNtfy                               = "ntfy|"
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
	SymComma                              = ","
	SymBrackets                           = "[]"
	SymDoubleDot                          = ".."
	SymPipeSpaced                         = " | "
	SymInvalidURLChars                    = " /?#@\\"
	SymQuote                              = "\""
	SymSemicolonSpace                     = "; "
	SymEquals                             = "="
	SymQuoteSpace                         = `"' `
	SymHash                               = "#"
	SymParenClose                         = ")"
	SymCommaSpace                         = ", "
	SymBracketClose                       = "]"
	SymPercent                            = "%"
	SymURLControlChars                    = "/:@?#\\ "
	SymPipe                               = "|"
	StrT                                  = "T"
	StrTRN                                = ")/;, \t\r\n"
	StrTag                                = "tag"
	StrTCP                                = "tcp"
	StrTelegram                           = "telegram|"
	StrTemporaryFailure                   = "temporary failure"
	StrTerminationSignal                  = "termination signal"
	StrTooMany                            = "too many"
	StrTransferlock                       = "transferlock"
	StrTransferprohibited                 = "transferprohibited"
	StrUnknownCriticalCAATags             = "unknown critical CAA tags: "
	StrUpdated                            = "updated"
	StrUpdateprohibited                   = "updateprohibited"
	StrValid                              = "valid"
	StrVersion                            = "version"
	StrVsRegistrarExpiration              = ") vs Registrar expiration ("
	StrY                                  = "y"
	SymColon                              = ":"
	SymDot                                = "."
	SymHyphen                             = "-"
	SymPlus                               = "+"
	SymSemicolon                          = ";"
	SymSlash                              = "/"
	SymSpace                              = " "
)
