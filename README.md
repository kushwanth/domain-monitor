# Domain & DNS Security Monitor

A robust, lightweight, and highly performant Go daemon designed for homelabs and infrastructure engineers to continuously monitor domain registrations (RDAP/WHOIS), verify DNS record integrity, detect nameserver hijacks, track SSL/TLS certificate expirations, validate email authentication security (SPF, DMARC, DKIM, MX), enforce DNSSEC and CAA policies, and monitor Certificate Transparency (CT) logs.

Built specifically for low-resource environments, this monitor uses a completely decoupled architecture, bounded worker pools, and advanced DNS load balancing to ensure your infrastructure is safe without triggering false positives or getting rate-limited by registries.

---

## Key Features

*   **Decoupled Worker Engines:** RDAP/WHOIS lookups, DNS record integrity, CT log monitoring, and email security checks run in independent, concurrent Goroutine worker pools scaled to your CPU core count with built-in panic recovery.
*   **Two-Tier RDAP & WHOIS Engine:** Zero-dependency IANA RDAP bootstrap engine with TTL caching and stealth ccTLD seeds. Automatically falls back to direct port-43 WHOIS on rate-limiting (429) or failures, synthesizing Registry and Registrar data to detect Auto-Renew Grace Period (ARGP) date discrepancies (>45 days) and nameserver desynchronizations.
*   **Comprehensive DNS Record Integrity:** Supports `A`, `AAAA`, `CNAME`, `MX`, `TXT`, `CAA`, `NS`, and composite `IP` types. Provides flexible validation matching strategies (`exact`, `prefix`, `contains`, `any_of`), CNAME flattening, and custom per-record DNS resolver overrides with automatic fallback to the global resolver pool.
*   **SSL/TLS Certificate Expiration Tracking:** Automatically initiates TLS handshakes on port 443 for web-facing records (`A`, `AAAA`, `IP`, `CNAME`) and alerts when certificates expire or approach expiration (<= 14 days), with optional support for self-signed certificates.
*   **Email Security Suite:** Enforces anti-hijacking protection across 11 major email providers (or custom MX servers), validates RFC 7208 single SPF record policies at the apex, ensures DMARC record presence, and checks provider default and custom DKIM selector keys.
*   **2-Tier DNSSEC Verification:** Validates local cryptographic chains (DS-to-KSK DNSKEY hash matching, RRSIG signature validity, and signature expiration) combined with upstream DNS-over-HTTPS (DoH) chain validation via the Authenticated Data (`AD`) flag.
*   **CAA Policy Enforcement & Tree Climbing:** Validates `issue`, `issuewild`, and `issuemail` tags with automatic DNS tree climbing (subdomain to parent zone) and support for explicit deny-all policies (`[]` or `[";"]`).
*   **Certificate Transparency (CT) Log Monitoring:** Real-time forward polling for newly issued SSL/TLS certificates via `api.ctlogs.dev`, incremental backfilling with state cursors, and local JSON history persistence.
*   **Consolidated Notification Engine & Privacy:** Buffers and throttles alerts to Ntfy and Telegram, deduplicates identical alerts for 24 hours, supports domain name privacy redaction in Telegram messages using human-readable names, and allows per-domain alert muting.
*   **Embedded Web Dashboard & REST API:** Responsive modern single-page dashboard with Dark (OLED) and Light modes pre-rendered server-side. The HTTP server starts instantly for Docker/K8s liveness probes (`/health`), while returning an initializing status on `/api/state` and `/` until the initial monitoring sweep completes, avoiding blocked connections or zero-state crashes.

---

## Configuration Guide (`config.jsonnet`)

The daemon uses Jsonnet for clean, variable-supported configuration.

```jsonnet
local default_ns = ["ns1.example.com", "ns2.example.com"];
local A = "A";
local AAAA = "AAAA";
local CNAME = "CNAME";
local MX = "MX";
local TXT = "TXT";
local IP = "IP";

{
  port: "8080",
  loop_interval: "6h",
  request_delay: "5s",
  whois_delay: "10s",

  // Directory where CT logs and state files are persisted
  data_dir: "./data",

  // Optional: ctlogs.dev API key for higher rate limits on CT log monitoring
  // ctlogs_api_key: "YOUR_CTLOGS_API_KEY",

  // DNS-over-HTTPS endpoint for upstream DNSSEC chain validation (default: https://dns.google/resolve)
  // doh_url: "https://dns.google/resolve",

  notifications: {
    ntfy: { url: "https://ntfy.sh/my_secret_topic", auth: "" },
    telegram: { token: "YOUR_BOT_TOKEN", chat_id: "YOUR_CHAT_ID" }
  },

  // Up to 9 custom global DNS resolvers (round-robin load balanced)
  resolvers: ["1.1.1.1", "8.8.8.8", "9.9.9.9", "208.67.222.222"], 

  domains: [
    // Standard Production Domain with Full Security Suite
    { 
      domain: "example.com", 
      name: "Prod Domain", 
      expected_ns: default_ns,
      // secondary_ns: ["slave.otherprovider.com"], // Optional: for dumb secondary DNS verification (must reuse primary DNSKEYs)
      expected_registrar_id: "292", // IANA ID (Priority 1: takes precedence; mutually exclusive in evaluation)
      // expected_registrar_name: "markmonitor", // Fallback substring (Priority 2: evaluated only if expected_registrar_id is omitted)
      domain_transfer_locked: true, // Verifies transfer lock is enabled in EPP status
      // verify_ns_health: true, // Direct SOA consistency & dumb DNSKEY sync checks between primary and secondary_ns
      check_email_security: true,
      mail_provider: "google",
      // mx_records: ["mx.custom.com"], // Mutually exclusive with mail_provider
      dkim_selectors: ["custom1", "custom2"],
      dnssec: true,
      monitor_ct_logs: true,
      caa: {
        issue: ["letsencrypt.org", "digicert.com"],
        issuewild: ["letsencrypt.org"]
      },
      suppress_alerts: false // Set to true to mute notifications for this domain
    },

    // Delegated Subdomain Zone (checks authoritative NS directly without RDAP)
    {
      domain: "api.example.com",
      name: "API Subzone",
      is_delegated_zone: true,
      root_zone: "example.com",
      expected_ns: ["ns1.example.net", "ns2.example.net"],
      check_email_security: false,
      dnssec: true,
      caa: { issue: ["letsencrypt.org"] },
      suppress_alerts: true
    }
  ],

  dns_records: [
    // Standard Exact Match & SSL Monitoring
    { hostname: "example.com", name: "Apex Web", type: A, expected: ["93.184.215.14"] },
    { hostname: "example.com", name: "Apex IPv6", type: AAAA, expected: ["2606:2800:21f:cb07:6820:80da:af6b:8b2c"] },
    
    // Composite IP Type (queries both A and AAAA)
    { hostname: "app.example.com", name: "App Dual-Stack", type: IP, expected: ["93.184.215.14", "2606:2800:21f:cb07:6820:80da:af6b:8b2c"] },

    // Prefix Matching (useful for dynamic/changing record suffixes)
    { hostname: "example.com", name: "SPF Record", type: TXT, expected: ["v=spf1 include:_spf.google.com"], match_type: "prefix" },

    // Substring / Contains Matching
    { hostname: "_dmarc.example.com", name: "DMARC Policy", type: TXT, expected: ["v=DMARC1; p=reject"], match_type: "contains" },

    // Any-Of Matching (passes if at least one expected value is found)
    { hostname: "cdn.example.com", name: "CDN Anycast", type: A, expected: ["104.16.132.229", "104.16.133.229"], match_type: "any_of" },

    // Custom Resolver Override (internal or split-horizon DNS)
    { hostname: "internal.example.com", name: "Internal Service", type: A, expected: ["10.0.0.5"], custom_resolver: "10.0.0.1" },

    // Self-Signed Certificate Acceptance
    { hostname: "homelab.example.com", name: "Homelab Router", type: A, expected: ["192.168.1.1"], accept_self_signed: true },

    // Skip SSL Certificate Validation (for plain HTTP / internal endpoints)
    { hostname: "plain.example.com", name: "Plain HTTP", type: A, expected: ["192.168.1.2"], skip_ssl: true }
  ]
}
```

---

## Configuration Reference

### Global Options

| Parameter | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `port` | string | `"8080"` | HTTP server listening port. |
| `loop_interval` | string | `"6h"` | Duration between monitoring cycles (e.g., `"1h"`, `"6h"`). Includes ±5% jitter. |
| `request_delay` | string | `"5s"` | Rate-limiting delay between Certificate Transparency queries. |
| `whois_delay` | string | `"10s"` | Rate-limiting delay between RDAP and WHOIS queries. |
| `data_dir` | string | `"/app/data"` | Path to persist CT log histories and state. |
| `resolvers` | array | `["1.1.1.1", "8.8.8.8", "9.9.9.9"]` | List of up to 9 custom global DNS resolver IPs (round-robin balanced). |
| `doh_url` | string | `"https://dns.google/resolve"` | Upstream DNS-over-HTTPS endpoint for DNSSEC chain validation. |
| `ctlogs_api_key` | string | `""` | Optional Bearer API key for `api.ctlogs.dev` rate limits. |
| `notifications` | object | `{}` | Notification provider configuration (`ntfy`, `telegram`). |

### Domain Options (`domains[]`)

| Parameter | Type | Required | Description |
| :--- | :--- | :---: | :--- |
| `domain` | string | **Yes** | Fully qualified domain name to monitor (e.g. `"example.com"`). |
| `name` | string | **Yes** | Human-readable identifier (used for privacy redaction in notifications). |
| `expected_ns` | array | No | Expected primary authoritative nameservers. Alerts on missing or unauthorized NS in RDAP/delegation. |
| `secondary_ns` | array | No | Optional dumb secondary nameservers replicating zone from primary. Evaluated if given; skipped if omitted. Must either be unsigned or reuse primary's exact DNSKEY keys (independent signing with distinct keys is rejected). |
| `is_delegated_zone`| bool | No | Set to `true` for subzones; queries authoritative NS directly without RDAP. |
| `root_zone` | string | Conditional | Mandatory when `is_delegated_zone: true` (e.g. `"example.com"`). |
| `check_email_security` | bool | No | Enables SPF, DMARC, DKIM, and MX integrity monitoring. |
| `mail_provider` | string | No | Pre-configured mail provider name (*mutually exclusive with `mx_records`*). |
| `mx_records` | array | No | Explicit expected MX records (*mutually exclusive with `mail_provider`*). |
| `dkim_selectors` | array | No | Custom DKIM selector prefixes to query (e.g. `["k1", "zendesk"]`). |
| `dnssec` | bool | No | Enables 2-tier local cryptographic and upstream DoH DNSSEC validation. |
| `monitor_ct_logs` | bool | No | Enables Certificate Transparency log polling and backfilling. |
| `caa` | object | No | CAA validation policy (`issue`, `issuewild`, `issuemail`). |
| `expected_registrar_id` | string | No | Expected IANA Registrar ID (numeric, e.g. `"292"`). **Priority 1** (takes precedence over `expected_registrar_name`). Evaluation is mutually exclusive. |
| `expected_registrar_name` | string | No | Expected registrar name substring (case-insensitive). **Priority 2** (evaluated only if `expected_registrar_id` is omitted). Mutually exclusive in evaluation. |
| `domain_transfer_locked` | bool | No | Set to `true` to alert if the domain transfer lock (`clientTransferProhibited` / `serverTransferProhibited`) is missing. |
| `verify_ns_health` | bool | No | Directly queries primary `expected_ns[0]` (`RD=0`) for reachability, authority (`AA`), and SOA serial. If `secondary_ns` is given, also validates secondary reachability, authority, SOA consistency, and dumb secondary DNSKEY replication; if `secondary_ns` is omitted, secondary checks are cleanly skipped. |
| `accept_self_signed` | bool | No | Allows self-signed certificates during TLS expiration checks. |
| `suppress_alerts` | bool | No | Mutes notification alerts for this domain while maintaining state tracking. |

### DNS Record Options (`dns_records[]`)

| Parameter | Type | Required | Description |
| :--- | :--- | :---: | :--- |
| `hostname` | string | **Yes** | Hostname / FQDN to query. |
| `name` | string | **Yes** | Human-readable identifier. |
| `type` | string | **Yes** | Record type (`A`, `AAAA`, `CNAME`, `ALIAS`, `MX`, `TXT`, `CAA`, `NS`, or `IP`). |
| `expected` | array | **Yes** | List of expected values. |
| `match_type` | string | No | Match strategy: `"exact"` (default), `"prefix"`, `"contains"`, or `"any_of"`. |
| `custom_resolver` | string | No | Custom resolver IP for this record (falls back to global resolvers on error). |
| `accept_self_signed` | bool | No | Accepts self-signed TLS certificates for SSL expiration monitoring. |
| `skip_ssl` | bool | No | Skip TLS/SSL certificate checks entirely for webserver record types (`A`, `AAAA`, `CNAME`, `ALIAS`, `IP`). Ideal for non-HTTPS services, plaintext HTTP, or internal infrastructure to prevent false alarms. |

---

## Environment Variables

All sensitive tokens and runtime paths can be configured via environment variables, making it ideal for container secret injection:

| Variable | Description | Default |
| :--- | :--- | :--- |
| `CONFIG_PATH` | Path to the `config.jsonnet` file | `"config.jsonnet"` |
| `DATA_DIR` | Directory for persistent state and CT logs | `"/app/data"` or `"./data"` |
| `PORT` | HTTP server listening port | `"8080"` |
| `NTFY_AUTH` | Authorization header/token for Ntfy (Bearer or Basic) | Config file value |
| `TELEGRAM_TOKEN` | Telegram Bot API token | Config file value |
| `TELEGRAM_CHAT_ID` | Telegram chat or channel ID | Config file value |
| `CTLOGS_API_KEY` | API token for `api.ctlogs.dev` | Config file value |
| `DOH_URL` | DNS-over-HTTPS endpoint for DNSSEC chain validation | `"https://dns.google/resolve"` |

---

## Deep-Dive Feature Modules

### 1. Two-Tier RDAP & WHOIS Engine
The monitor implements a native RFC 7480/9083 RDAP client with IANA bootstrap caching and stealth seeds for ccTLDs (e.g. `.ai`, `.de`, `.eu`, `.io`, `.me`, `.uk`, `.ca`):
* **Automatic Fallback:** If RDAP returns 429 (rate-limited) or fails, the engine automatically falls back to raw port-43 WHOIS queries using known ccTLD server mappings.
* **Two-Tier Synthesis:** Synthesizes Registry and Registrar data into a unified domain state.
* **Auto-Renew Grace Period (ARGP) Detection:** Detects discrepancies between Registry and Registrar expiration dates (>45 days), alerting you before unexpected renewals or expirations occur.
* **Nameserver Desynchronization:** Compares Registry delegation with Registrar configuration and fires alerts if they desynchronize.
* **Domain Lifecycle & Status Tracking:** Alerts on expiration (warning at <= 30 days, urgent at <= 7 days), missing/unauthorized nameservers, registry lock status (`clientTransferProhibited`), and suspension statuses (`serverHold`, `clientHold`, `redemptionPeriod`, `pendingDelete`).

### 2. DNS Record Integrity & SSL Expiration Monitoring
* **Direct Wire Protocol:** Direct UDP/TCP DNS exchanges using `miekg/dns`, bypassing host OS resolvers and caching.
* **Flexible Match Strategies (`match_type`):**
  * `exact`: All expected records must match live DNS records, and no unauthorized records may exist.
  * `prefix`: Expected values are matched as prefixes against live records.
  * `contains`: Expected values are verified as substrings within live records.
  * `any_of`: Passes if at least one of the expected values is present in live records.
* **CNAME Flattening:** Automatically resolves apex CNAME flattening and alias targets to their underlying IP addresses.
* **SSL/TLS Expiration Tracking:** Automatically queries port 443 for `A`, `AAAA`, `IP`, and `CNAME` records to track certificate validity, alerting when a certificate has expired (urgent) or expires in <= 14 days (high).

### 3. Email Security Suite (`check_email_security: true`)
* **MX Hijack Prevention (`mail_provider`):** Enforces that live MX records match the official mail infrastructure for 11 major providers:
  `google`, `microsoft`, `fastmail`, `protonmail`, `icloud`, `zoho`, `aws`, `mailgun`, `sendgrid`, `postmark`, and `yandex`. If DNS is hijacked and points elsewhere, a `[CRITICAL] MX HIJACK DETECTED` alert is fired immediately.
* **Custom MX Targets (`mx_records`):** If you run your own mail servers, specify `mx_records: ["mail.example.com"]` to strictly validate custom MX records. (*Note: `mail_provider` and `mx_records` are mutually exclusive.*)
* **SPF Validation:** Validates that exactly one `v=spf1` record exists at the apex and warns on missing or multiple SPF records (RFC 7208 violation).
* **DMARC Validation:** Validates that a `v=DMARC1` record exists at `_dmarc.<domain>`.
* **DKIM Discovery:** Automatically queries default DKIM selectors for configured mail providers and verifies any additional third-party selectors specified in `dkim_selectors`.

### 4. 2-Tier DNSSEC Verification (`dnssec: true`)
* **Tier 1 (Local Cryptography):** Validates that DS records at the parent zone match the zone's KSK (DNSKEY flag 257) digest, verifies RRSIG digital signatures against the DNSKEY RRset, and checks signature validity time windows and expiration.
* **Tier 2 (Upstream DoH Validation):** Queries a validating DNS-over-HTTPS endpoint (`doh_url`, default `https://dns.google/resolve`) with `do=1` to confirm that the full chain of trust from the root zone has the Authenticated Data (`AD`) bit set.

### 5. CAA Policy Enforcement (`caa: { ... }`)
* **Tag Validation:** Validates `issue`, `issuewild`, and `issuemail` tags against your allowed Certificate Authorities.
* **DNS Tree Climbing:** If CAA records are not set on a subdomain, the engine automatically climbs the DNS tree to validate parent zone policies.
* **Explicit Deny-All:** Setting `issue: []` or `issue: [";"]` enforces an explicit deny-all policy, alerting if any CA is authorized to issue certificates.

### 6. Certificate Transparency (CT) Log Monitoring (`monitor_ct_logs: true`)
* **Real-Time Discovery:** Periodically queries `api.ctlogs.dev` for newly issued certificates matching your domains.
* **Incremental Backfill:** Uses pagination cursors to backfill historical certificates without overloading external APIs.
* **State Persistence:** Saves historical certificate logs in `<data_dir>/ct_logs/<domain>.json` and persists pagination state in `<data_dir>/ct_state.json`.

### 7. Notification Engine & Privacy Redaction
* **Consolidated Chunking:** Alerts are buffered during each sweep cycle and dispatched in chunks (up to 3,500 characters) with a 1-second delay between chunks to prevent provider rate limits.
* **24-Hour Deduplication:** Identical alerts are suppressed for 24 hours to prevent notification fatigue.
* **Telegram Privacy Redaction:** In Telegram notifications, actual domain names are automatically replaced by the configured human-readable `name` (or `[Hidden Domain]`), keeping alerts private in shared or group channels.
* **Alert Muting (`suppress_alerts: true`):** Silences notifications for specific domains while continuing full state evaluation.

---

## Web Dashboard & API Endpoints

The daemon provides an embedded Web UI and JSON API:

*   **`GET /`:** Embedded interactive Web Dashboard with dark (OLED) and light mode themes. Displays real-time statuses for RDAP registrations, DNS records, SSL expirations, Email security, DNSSEC, CAA compliance, and CT logs.
*   **`GET /health`:** Lightweight HTTP 200 liveness probe (`{"status":"ok"}`) for Docker and Kubernetes health checks.
*   **`GET /api/state`:** Real-time JSON snapshot of the full monitoring evaluation state.
*   **`GET /api/certs?domain=example.com`:** Certificate Transparency history for a domain via query parameter.
*   **`GET /api/ctlogs/{domain}`:** Certificate Transparency history for a domain via path parameter.

> **Safe Startup Guarantee:** The HTTP server listens immediately so `/health` responds right away, while `/` and `/api/state` return a clear initializing status until the initial monitoring sweep completes, guaranteeing no deadlocks or zero-state crashes.

---

## Deployment

### Docker

Pre-built, multi-architecture Docker images (`amd64` and `arm64`) are available via the GitHub Container Registry (GHCR).

```bash
docker run -d \
  --name domain-monitor \
  --restart always \
  -p 8080:8080 \
  -v /path/to/your/config.jsonnet:/app/config.jsonnet:ro \
  -v /path/to/your/data:/app/data:rw \
  -e CONFIG_PATH=/app/config.jsonnet \
  -e DATA_DIR=/app/data \
  ghcr.io/your-github-username/your-repo-name:latest
```

> **Permissions Note:** The container runs as a non-root user with `UID 65532`. Ensure your host data directory (`/path/to/your/data`) has write permissions for UID 65532 (`chown -R 65532:65532 /path/to/your/data`).

### Systemd / Podman Quadlet

For systemd-managed Linux environments, deploy using the included `domain-monitor.container` Quadlet file:

1. Copy `domain-monitor.container` to `~/.config/containers/systemd/` (user mode) or `/etc/containers/systemd/` (root mode).
2. Store sensitive tokens securely using Podman Secrets:
   ```bash
   echo "YOUR_TELEGRAM_TOKEN" | podman secret create telegram-token -
   echo "YOUR_NTFY_AUTH" | podman secret create ntfy-auth -
   ```
3. Update `domain-monitor.container` volume mappings and environment variables.
4. Reload systemd and start the service:
   ```bash
   systemctl --user daemon-reload
   systemctl --user start domain-monitor.service
   ```

---

## Testing

This project maintains strict testing standards, including table-driven unit tests and continuous fuzzing:

*   **Run all tests:** `go test ./src/... -v -race`
*   **Unit Tests:** Located alongside source files (`notify_test.go`, `lookup_test.go`, `dns_test.go`, `config_test.go`, `bootstrap_test.go`, `extended_test.go`).
*   **Continuous Fuzzing:** Dedicated native Go fuzz suites (`FuzzFlexibleDateParsing` and `FuzzNormalizeEPPStatus` in `lookup_test.go`, `FuzzParseCAAIssuer` in `dns_test.go`). Run with `go test -fuzz=FuzzFlexibleDateParsing -fuzztime=30s ./src/`.

---

## References & Acknowledgements

*   [**lissy93/who-dat**](https://github.com/lissy93/who-dat) by Alicia Sykes: Reference implementation for unified WHOIS/RDAP JSON lookups and jCard data parsing.
*   [**likexian/whois**](https://github.com/likexian/whois) & [**likexian/whois-parser**](https://github.com/likexian/whois-parser) by Li Kexian: Raw port-43 WHOIS transport and schema parser.
*   [**RFC 7480 / RFC 9083 RDAP**](https://datatracker.ietf.org/doc/html/rfc9083): Native zero-dependency RDAP client engine with IANA bootstrapping and referral synthesis.
*   [**miekg/dns**](https://github.com/miekg/dns) by Miek Gieben: Complete DNS wire protocol and cryptographic DNSSEC verification library for Go.
*   [**google/go-jsonnet**](https://github.com/google/go-jsonnet): Official Go implementation of the Jsonnet data templating language.
*   [**api.ctlogs.dev**](https://api.ctlogs.dev): Certificate Transparency search API.

---

## Disclaimer: LLM Contribution

**Note:** This project is implemented with the assistance of a Large Language Model (LLM).