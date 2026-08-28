package main

import (
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/miekg/dns"
)

// System & Default Paths
const (
	DefaultDataDir             = "/app/data"
	DefaultDoHURL              = "https://dns.google/resolve"
	DefaultCTLogsSubdir        = "ct_logs"
	MaxNotificationMessageLen  = 3500
)

// External API Endpoints
const (
	BootstrapURL        = "https://data.iana.org/rdap/dns.json"
	BootstrapTTL        = 24 * time.Hour
	BootstrapMaxAge     = 72 * time.Hour
	CTLogsAPIEndpoint   = "https://api.ctlogs.dev/v1/subdomains/"
	TelegramAPIEndpoint = "https://api.telegram.org/bot%s/sendMessage"
)

const (
	StatusPending  CheckStatus = "pending"
	StatusOk       CheckStatus = "ok"
	StatusFailed   CheckStatus = "failed"
	StatusMismatch CheckStatus = "mismatch"
	StatusWarning  CheckStatus = "warning"
	StatusHijacked CheckStatus = "hijacked"
)

const (
	PriorityUrgent  AlertPriority = "urgent"
	PriorityHigh    AlertPriority = "high"
	PriorityWarning AlertPriority = "warning"
	PriorityDefault AlertPriority = "default"
)

// SSL Expiration Sentinel Values
const (
	SSLDaysNotApplicable = -9999
	SSLDaysError         = -9998
)

// System Errors
var (
	ErrDNSResolution   = errors.New("dns resolution failed")
	ErrNXDOMAIN        = errors.New("no such host (NXDOMAIN)")
	ErrSERVFAIL        = errors.New("server failure (SERVFAIL)")
	ErrSSLValidation   = errors.New("ssl validation failed")
	ErrRDAPNotFound    = fmt.Errorf("RDAP domain not found (404)")
	ErrRDAPRateLimited = fmt.Errorf("RDAP rate limited (429)")
	ErrDomainNotFound  = errors.New("domain not found in whois (404)")
)

// DNSTypeMap maps record type string names to miekg/dns uint16 type constants.
var DNSTypeMap = map[string]uint16{
	"A":     dns.TypeA,
	"AAAA":  dns.TypeAAAA,
	"CNAME": dns.TypeCNAME,
	"MX":    dns.TypeMX,
	"TXT":   dns.TypeTXT,
	"CAA":   dns.TypeCAA,
	"NS":    dns.TypeNS,
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

// TZReplacements provides standard timezone abbreviation offsets for flexible date parsing.
var TZReplacements = map[string]string{
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
	" BST":  " +0100",
	" CET":  " +0100",
	" CEST": " +0200",
	" JST":  " +0900",
	" KST":  " +0900",
	" AEST": " +1000",
	" AEDT": " +1100",
}

// FlexibleDateFormats lists candidate layouts for parsing WHOIS and RDAP date strings.
var FlexibleDateFormats = []string{
	time.RFC3339,
	time.RFC3339Nano,
	time.RFC1123,
	time.RFC1123Z,
	time.RFC822,
	time.RFC822Z,
	time.RFC850,
	time.ANSIC,
	time.UnixDate,
	time.RubyDate,
	"2006-01-02T15:04:05Z",
	"2006-01-02T15:04:05.000Z",
	"2006-01-02T15:04:05-0700",
	"2006-01-02T15:04:05+0700",
	"2006-01-02T15:04:05-07:00",
	"2006-01-02T15:04:05+07:00",
	"2006-01-02 15:04:05 -0700",
	"2006-01-02 15:04:05 +0700",
	"2006-01-02 15:04:05-07:00",
	"2006-01-02 15:04:05+07:00",
	"2006-01-02 15:04:05 MST",
	"2006-01-02 15:04:05 UTC",
	"2006-01-02 15:04:05",
	"2006-01-02",
	"02-Jan-2006 15:04:05 -0700",
	"02-Jan-2006 15:04:05 +0700",
	"02-Jan-2006 15:04:05 MST",
	"02-Jan-2006 15:04:05 UTC",
	"02-Jan-2006 15:04:05",
	"02-Jan-2006",
	"02.01.2006 15:04:05",
	"02.01.2006",
	"2006.01.02 15:04:05",
	"2006.01.02",
	"2006/01/02 15:04:05",
	"2006/01/02",
	"02/01/2006 15:04:05",
	"02/01/2006",
	"01/02/2006 15:04:05",
	"01/02/2006",
	"Mon Jan 02 15:04:05 MST 2006",
	"Mon Jan 02 15:04:05 2006",
	"Mon Jan 2 15:04:05 MST 2006",
	"20060102",
	"20060102150405",
	"02-01-2006",
	"02-01-2006 15:04:05",
}

// WhoisNotFoundIndicators lists indicators across global registrars and registries denoting an unregistered domain.
var WhoisNotFoundIndicators = []string{
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

// Precompiled Regular Expressions
var (
	ValidDomainRegex = regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)

	ReWhoisReferral  = regexp.MustCompile(`(?i)(?:Registrar WHOIS Server|Whois Server|ReferralServer|Registrar Whois|referral|whois)\s*:\s*(?:whois:\/\/)?([a-zA-Z0-9.-]+)`)
	ReWhoisExpiry    = regexp.MustCompile(`(?i)(?:\[?(?:Registry Expiry Date|Registrar Registration Expiration Date|Expiration Date|Expiry Date|Expires on|Expires|paid-till|validity|Renewal Date|Record expires on|Domain Expiration Date|valid-date|Registry Expiration|Registry Expiry|expire|renewal-date)\]?)\s*[:\]]?\s*([^\r\n]+)`)
	ReWhoisCreated   = regexp.MustCompile(`(?i)(?:\[?(?:Creation Date|Created on|Created|Registration Date|created|registered|created-date|Registered Date|Connected Date)\]?)\s*[:\]]?\s*([^\r\n]+)`)
	ReWhoisUpdated   = regexp.MustCompile(`(?i)(?:\[?(?:Updated Date|Last Updated Date|Last Modified|changed|modified|updated-date|Last Update)\]?)\s*[:\]]?\s*([^\r\n]+)`)
	ReWhoisRegistrar = regexp.MustCompile(`(?i)(?:\[?(?:Registrar Name|Sponsoring Registrar Organization|Sponsoring Registrar|registrar-name|Registrar|Organization|sponsoring-registrar|registrar)\]?)\s*[:\]]?\s*([^\r\n]+)`)
	ReWhoisIANAID    = regexp.MustCompile(`(?i)(?:\[?(?:Registrar IANA ID|Sponsoring Registrar IANA ID|IANA ID|Registrar IANA ID Number)\]?)\s*[:\]]?\s*([0-9]+)`)
	ReWhoisNS        = regexp.MustCompile(`(?i)(?:\[?(?:Name Server|nameserver|nserver|DNS|Name Server Name)\]?)\s*[:\]]?\s*([a-zA-Z0-9.-]+)`)
	ReWhoisStatus    = regexp.MustCompile(`(?i)(?:\[?(?:Domain Status|Status|state|Domain State|Registration status)\]?)\s*[:\]]?\s*([^\r\n]+)`)
	ReWhoisDNSSEC    = regexp.MustCompile(`(?i)(?:\[?(?:DNSSEC|dnssec)\]?)\s*[:\]]?\s*([^\r\n]+)`)
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
var CCTLDWhoisServers = map[string]string{
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
	MsgAlertDNSFailed   = "DNS Resolution Failed: %s (%s)"
	MsgAlertDNSMismatch = "Mismatch on %s (%s)! Missing expected: %s. Found: [%s]"
	MsgAlertDNSUnauth   = "Unauthorized record found on %s (%s): %s! Expected: [%s]"

	// DNS Info
	MsgLogDNSCustomFail = "Custom resolver %s failed for %s. Falling back to global pool."

	// DNSSEC Alerts
	MsgAlertDNSSECNoDS        = "DNSSEC: No DS record at parent for %s"
	MsgAlertDNSSECNoDNSKEY    = "DNSSEC: No DNSKEY records found for %s"
	MsgAlertDNSSECMismatch    = "DNSSEC: DS does not match any DNSKEY for %s"
	MsgAlertDNSSECRRSIGFail   = "DNSSEC: RRSIG verification failed for %s"
	MsgAlertDNSSECChainBroken = "DNSSEC: Full chain of trust validation failed (AD flag missing) for %s"

	// CAA Alerts
	MsgAlertCAAMissing    = "CAA: No %s records found for %s"
	MsgAlertCAAUnauth     = "CAA: Unauthorized CA '%s' in %s record for %s"
	MsgAlertCAAExpectedNA = "CAA: Expected CA '%s' missing from %s record for %s"

	// CT Logs Alerts
	MsgAlertNewSSLCert = "New SSL Certificate issued for %s by %s. Match: %s"

	// Email Security Alerts
	MsgAlertEmailNoMX      = "Email Security: No MX records found for %s"
	MsgAlertEmailMXMissing = "Email Security: Missing expected MX %s on %s. Found: [%s]"
	MsgAlertEmailMXUnauth  = "Email Security: Unauthorized MX %s on %s! Expected: [%s]"
	MsgAlertEmailMXHijack  = "MX HIJACK DETECTED for %s! Expected provider %s infrastructure, found: [%s]"
	MsgAlertEmailNoSPF     = "Missing SPF record for %s"
	MsgAlertEmailMultiSPF  = "Multiple SPF records found for %s! This breaks email delivery."
	MsgAlertEmailNoDMARC   = "Missing DMARC record for %s (_dmarc.%s)"
	MsgAlertEmailNoDKIM    = "No valid DKIM records found for %s (checked: %s)"

	// Email Security Info
	MsgLogEmailUnknownProv = "Unknown mail_provider '%s' for %s. Skipping MX hijack prevention."

	// RDAP Alerts
	MsgAlertRDAPExpiry    = "%s expires in %.0f days"
	MsgAlertRDAPModified  = "registry record modified for %s! timestamp: %s"
	MsgAlertRDAPUnauthNS  = "unauthorized ns on %s: %s"
	MsgAlertRDAPMissingNS = "expected ns missing from %s: %s"
	MsgAlertRDAPSuspended = "domain %s suspended! status: %s"
	MsgAlertRDAPUnlocked  = "%s is unlocked (missing transfer prohibitions)"
	MsgAlertRDAPDiscrep   = "Hierarchy discrepancy for %s: %s"

	// RDAP Info
	MsgLogRDAPFail = "RDAP query failed for %s: %v"

	// WHOIS Info
	MsgLogWHOISFallback = "RDAP failed for %s, attempting WHOIS fallback..."
	MsgLogWHOISFail     = "WHOIS fallback also failed for %s: %v"
	MsgLogWHOISSuccess  = "WHOIS fallback succeeded for %s"
	MsgLogHierarchyWarn = "Hierarchy discrepancy detected for %s: %s"

	// System Info
	MsgLogStartup          = "Daemon initialized successfully. Domains: %d, DNS Records: %d"
	MsgLogHTTPAPI          = "HTTP API running on :%s (Endpoints: /health, /api/state, /api/certs)"
	MsgLogTelegramConfig   = "Telegram notifications configured."
	MsgLogShutdownSignal   = "Received signal: %v. Initiating graceful shutdown..."
	MsgLogShutdownComplete = "Daemon shutdown complete."
)
