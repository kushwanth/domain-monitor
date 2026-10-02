# Domain & DNS Security Monitor

> **This project was developed and refactored with the assistance of a LLMs**

A self-hosted Go daemon that monitors domain registrations, DNS records, CAA policies, and published email security records.

It runs as one process with bounded concurrency, resource limits, an embedded dashboard, and alerts. Upstream failures and incomplete evidence remain visible.

---

## Key Features

*   **RDAP & WHOIS Monitoring:** IANA bootstrap discovery, registry-first RDAP, and safe registrar RDAP referrals for thin registry responses. WHOIS is used only when RDAP is unavailable or all applicable RDAP paths fail; successful or authoritative-not-found RDAP never triggers WHOIS.
*   **DNS Record Integrity:** Validates `A`, `AAAA`, `CNAME`, `MX`, `TXT`, `CAA`, `NS`, `IP`, and `ALIAS` records. Global checks compare two configured resolver observations when available. A per-record custom resolver is queried alone with no global fallback.
*   **CAA Publication Checks:** Compares configured issuer-tag values and supports explicit deny-all lists. This monitors DNS publication; it does not verify certificates or evaluate CA issuance policy.
*   **Email Security Suite:** Checks MX records against configured providers, discovers SPF and DMARC records, and checks configured DKIM selectors. It does not evaluate complete mail authentication policy. Bundled provider presets can be extended or overridden at startup using JSON files in `./data/email_providers/` or `email_providers_dir`. Both MX suffixes and DKIM selectors come from those files.
*   **2-Tier DNSSEC Verification:** Checks local DS/DNSKEY and RRSIG evidence and requires an authenticated DNS-over-HTTPS (DoH) response for a verified result.
*   **Notification Engine:** Ntfy is required and attempted first. Telegram is optional. Each successful cycle produces one bounded, deterministically ordered report and at most one request per provider, excluding bounded transient retries. Domain-name redaction remains supported.
*   **Embedded Web Dashboard:** A single-page dashboard with Dark and Light modes, periodic state polling, and a `/health` liveness endpoint. Provider quotas can still defer checks despite local rate limiting.

---

## Configuration

The daemon reads `config.json` once, applies environment overrides, validates it,
and initializes an owned configuration snapshot. Files are limited to 8 MiB.
Changes require a restart.

### Standard `config.json` Example

```json
{
  "port": "8080",
  "loop_interval_days": 0.25,
  "notifications": {
    "ntfy": {"url": "https://ntfy.sh/your-private-topic"}
  },
  "resolvers": ["1.1.1.1", "8.8.8.8", "9.9.9.9", "208.67.222.222"],
  "domains": [
    {
      "domain": "example.com",
      "name": "Prod Domain",
      "nameservers": [
        {"hostname": "ns1.example.com"},
        {"hostname": "hidden-ns.example.com", "hidden": true}
      ],
      "registrar": "292",
      "domain_transfer_locked": true,
      "email": {"provider": "google"},
      "dnssec": true
    }
  ],
  "dns_records": [
    {
      "hostname": "example.com",
      "name": "Apex Web",
      "type": "A",
      "expected": ["93.184.215.14"]
    }
  ]
}
```

---

## Configuration Reference

### Global Options

| Parameter | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `port` | string | `"8080"` | HTTP server listening port. |
| `loop_interval_days` | number | `0.25` | Days between monitoring cycles; values outside `0.125`–`365` are clamped to those bounds. |
| `email_providers_dir` | string | `./data/email_providers` | Optional startup directory of provider JSON files, overriding bundled presets by filename. A missing default directory uses bundled presets; an explicitly configured missing directory, malformed definition, or unknown configured provider fails startup. |
| `resolvers` | array | `["1.1.1.1"...]` | Global DNS resolver IPs. Checks compare the first two observations when available; additional entries remain available to protocol-specific failover paths. |
| `doh_url` | string | `"https://dns.google/resolve"` | Trusted upstream JSON DoH validator used to corroborate local DNSSEC evidence; this daemon is not an independent root-to-zone validator. |
| `notifications` | object | Required | Must contain `ntfy.url`, a valid HTTP(S) URL. Authenticated ntfy requires HTTPS. Optional Telegram is enabled only when both `token` and `chat_id` are nonempty. Cross-origin notification redirects are rejected. |

RDAP and public-metadata clients connect directly so proxy resolution cannot bypass destination policy. The operator-selected notification client may use environment proxy settings; credentials are never followed across origins.

### Runtime state

Configuration and resolver lists are owned at startup and shared read-only inside
the daemon; explicit snapshot access returns independent copies. Internal status
and priority values are byte enums, and condition codes are 16-bit enums. API and
result status names retain their string representation. Conditions are embedded
values with an explicit zero state. Condition history keeps only codes and start
times, avoiding retention of old error messages.

Domain names, DNS values and diagnostics still need strings; variable-sized
results need bounded slices/maps. Configuration snapshots own their CAA policy
slices. Active check lists store indices into the daemon's owned configuration,
without retaining pointers into backing arrays. A fixed pool of at most 32
workers gathers network evidence into one cycle-owned snapshot. Serial RDAP and
WHOIS evidence is evaluated first so newly expired or re-registered domains
select the correct dependent workload in the same cycle. Final evaluation
performs no network requests. Expected DNS values are copied once so returned
cycle state remains independent of configuration.
Completed cycles publish one immutable cached JSON snapshot; in-progress
changes do not affect HTTP readers.

Between cycles, the engine retains status/condition history and the latest JSON
snapshot rather than prior result trees. Bootstrap access returns independent
server lists. Pricing refreshes replace an immutable catalog; callers receive
scalar prices without copying or exposing its map. Existing catalog readers
remain stable across refreshes, with the same freshness and stale-data limits.
State, condition ages, pricing/bootstrap caches, and notification queues are
in memory only. Restarting rebuilds them; the daemon does not persist check
history or failed notification deliveries. HTTP gathering retries transient
transport failures and retryable statuses up to three total attempts with
context-aware exponential backoff and `Retry-After` support. DNS tries at most
three distinct resolvers or nameserver addresses. WHOIS uses conservative
rate-limited retries. Notifications are rendered after state publication as one
bounded, high-severity-first report. Each provider is isolated and receives one
request per report, with separate timeout and retry budgets.

Provider files use the filename as the provider name, for example `custom.json`:

```json
{
  "mx_records": ["mail.example.com"],
  "dkim_selectors": ["selector1", "selector2"]
}
```

MX entries are normalized hostname suffixes, matched at label boundaries. At
least one MX suffix is required. DKIM selectors may be omitted when no default
selector is known. Set `email.provider` to `custom` to use this definition. Provider
files are read once; changes require a restart.

### Domain Options (`domains[]`)

| Parameter | Type | Required | Description |
| :--- | :--- | :---: | :--- |
| `domain` | string | **Yes** | Valid domain name to monitor (e.g. `"example.com"`), normalized to ASCII and limited to 253 bytes. |
| `name` | string | **Yes** | Privacy-safe identifier used in notifications instead of sending the domain name to notification providers. |
| `nameservers` | array | No | Authoritative nameservers to validate and health-check. Each entry contains `hostname` and optional `hidden`; omitted `hidden` defaults to `false`. |
| `root_zone` | string | No | Parent zone for a delegated subzone. Its presence marks the domain as delegated and enables direct authoritative queries. |
| `email` | object | No | Its presence enables MX, SPF, DMARC, and DKIM monitoring. Optional fields are `provider`, `mx_records`, and `dkim_selectors`; use `{}` for baseline checks without an expected provider or MX set. `provider` and `mx_records` are mutually exclusive. |
| `dnssec` | bool | No | Enables 2-tier local cryptographic and upstream DoH DNSSEC validation. |
| `caa` | object | No | CAA validation policy (`issue`, `issuewild`, `issuemail`). |
| `registrar` | string | No | Expected registrar. A numeric value matches the IANA Registrar ID (e.g. `"292"`); any other value matches the registrar name. |
| `domain_transfer_locked` | bool | No | Alert if the domain transfer lock is missing. |
| `renewal_price` | float | No | Manual renewal price override (e.g. for premium domains or custom contracts). If omitted or `0`, the daemon looks for a renewal price in the DotSweep TLD catalog; unavailable prices remain unknown. |
| `allow_expiry` | bool | No | Allows the domain to expire without expiry alerts and keeps it in the separate Allowed to Expire dashboard section. The daemon continues gathering, displaying, and validating it normally until RDAP confirms expiration or absence, then suppresses its dependent checks and alerts. RDAP continues so re-registration reactivates the other checks. |
| `suppress_alerts` | bool | No | Mutes notification alerts for this domain. |

Email-security monitoring validates DNS publication posture: MX expectations,
SPF record presence and multiplicity, DMARC policy discovery, and configured
DKIM selector key usability. It is not an SMTP message authenticator: it does
not evaluate an individual sender IP against SPF mechanisms, validate message
signatures, determine identifier alignment, or generate DMARC reports.

When `nameservers` is non-empty, every entry is queried directly for authoritative
SOA and optional DNSKEY evidence. Non-hidden entries must appear in public
delegation; hidden entries must not. Public delegation containing an unconfigured
server also fails validation. At least one non-hidden server is required, and
hostnames must be unique. A differing SOA serial is reported as a synchronization
mismatch because the monitor does not infer primary/secondary roles or perform
zone transfers. When `dnssec` is enabled, every queried authoritative server must
return an authoritative, non-empty DNSKEY set and all sets must agree. Omit
`nameservers` to disable expected-delegation and direct
nameserver-health validation.

Unknown configuration members are rejected at every nesting level. Equivalent
v3 email, registrar, and `unused` settings are migrated to the current schema.
Fields whose behavior cannot be preserved safely—top-level `data_dir`, domain
`expected_ns`, `secondary_ns`, `verify_ns_health`, `is_delegated_zone`, and
`monitor_ct_logs`, plus DNS-record `skip_ssl`—stop startup with an actionable
upgrade error. Replace them deliberately using the current schema rather than
silently losing monitoring coverage.

CAA tag lists distinguish omission from explicit denial. For example,
`"caa": {"issue": ["ca.example"], "issuewild": []}` expects the configured issuer
and `0 issuewild ";"`. Omitted or null tags are unconstrained. An empty CAA
object adds no check. Only tags included in the policy constrain matching;
other observed tags remain visible without causing a mismatch.
Issuer domain names are compared case-insensitively; issuer-defined parameter
values retain their original case.

### DNS Record Options (`dns_records[]`)

| Parameter | Type | Required | Description |
| :--- | :--- | :---: | :--- |
| `hostname` | string | **Yes** | Hostname / FQDN to query. |
| `name` | string | **Yes** | Human-readable identifier; the `__caa__` prefix is reserved for generated domain policies. |
| `type` | string | **Yes** | Record type (`A`, `AAAA`, `CNAME`, `MX`, `TXT`, `CAA`, `NS`, `IP`, `ALIAS`). |
| `expected` | array | **Yes** | List of expected values. An explicit empty list with exact matching monitors for absence. Explicit CAA DNS tasks compare the full record set; omitted-tag relaxation applies only to domain `caa` policies. TXT values preserve case, punctuation, and literal `alias:` prefixes; surrounding whitespace is trimmed. |
| `match_type` | string | No | Strategy: `"exact"` (default), `"prefix"`, `"contains"`, `"any_of"`. |
| `custom_resolver` | string | No | Resolver IP used exclusively for this record. No global-resolver fallback occurs. |

---

## Environment Variables

Tokens and runtime paths can be configured via environment variables for easy container injection:

| Variable | Default | Description |
| :--- | :--- | :--- |
| `CONFIG_PATH` | `"config.json"` | Path to the `config.json` file |
| `PORT` | `"8080"` | HTTP server listening port |
| `NTFY_AUTH` | Config value | Authorization header/token for Ntfy |
| `TELEGRAM_TOKEN` | Config value | Telegram Bot API token |
| `TELEGRAM_CHAT_ID` | Config value | Telegram chat or channel ID |
| `DOH_URL` | `"https://dns.google/resolve"` | Upstream DNS-over-HTTPS endpoint |

---

## Web Dashboard & API

The daemon provides an embedded Web UI and JSON API:

*   **`GET /`:** Interactive Web Dashboard grouping checked domains into Healthy, Issues, and Allowed to Expire sections and DNS records into Matched and Not Matched sections. Empty sections are hidden; pending results appear after checks finish. Domain cards show days to expiry, and the sidebar shows annual and upcoming renewal costs.
*   **`GET /health`:** HTTP 200 liveness probe (`{"status":"ok"}`).
*   **`GET /api/state`:** Latest coherent JSON snapshot with deterministic check arrays and compact cycle attempt/freshness metadata. Pending checks are published at startup; a failed attempt retains prior evidence. Responses include an ETag, and matching `If-None-Match` requests return 304 without a body.

RDAP state sets `expiry_confirmed` only after a domain configured with
`allow_expiry` is confirmed expired or absent; that transition suppresses its
dependent checks until registration reappears.

---

## Domain Renewal Pricing & Privacy

The daemon tracks estimated annual domain renewal costs for your portfolio:

* **Automatic Standard TLD Pricing**: Standard domain extensions (e.g., `.com`, `.org`, `.co.uk`) are automatically priced using the open [DotSweep](https://dotsweep.com/tlds) TLD catalog.
* **Pricing catalog privacy**: The daemon queries `https://dotsweep.com/tlds` to download a public TLD catalog without sending portfolio domain names, TLD lists, or registrar identities in that request. Domain and DNS checks contact their configured upstream services separately.
* **Catalog caching**: Upstream catalog responses are cached in memory for 24 hours (`PricingCacheTTL`). Temporary upstream failures or unusable catalogs retain existing cached data for up to 7 days.
* **Premium Domains & Custom Overrides**: Because premium domains have custom renewal prices that cannot be inferred from standard TLD rates, you can specify `renewal_price` in `config.json` (e.g., `"renewal_price": 250.00`). A manual amount takes precedence. Monitored domain cards show the annual price or `Unknown`; delegated zones show `Not applicable`. Domains allowed to expire are excluded from the portfolio total, which is partial when some monitored prices are unknown.
* **Sidebar totals**: Minimum annual renewal cost sums known prices for monitored domains. Renewals due in the next 12 months sum known prices for monitored domains whose reported expiration date falls within the next 365 days. Unknown prices are marked as partial; domains without a known expiration date are excluded from the upcoming total.


---

## Deployment

### Docker

Pre-built multi-architecture Docker images are available via the GitHub Container Registry.

```bash
docker run -d \
  --name domain-monitor \
  --restart always \
  -p 8080:8080 \
  -v /path/to/your/config.json:/app/config.json:ro \
  -e CONFIG_PATH=/app/config.json \
  ghcr.io/your-github-username/your-repo-name@sha256:REPLACE_WITH_RELEASE_DIGEST
```

Replace `REPLACE_WITH_RELEASE_DIGEST` with the 64-character digest of the
reviewed release image. Using an immutable digest prevents an unattended image
update from changing runtime behavior or requiring an unreviewed configuration
migration.

To add custom email providers, mount their directory read-only at `/app/data/email_providers`. Bundled presets are used when this directory is absent.

### Local Execution

```bash
go build -o domain_monitor ./src/cmd/domain-monitor
./domain_monitor -config config.json
```

### Systemd / Podman Quadlet

Deploy using the included `domain-monitor.container` Quadlet file:

1. Copy `domain-monitor.container` to `~/.config/containers/systemd/` (user mode) or `/etc/containers/systemd/` (root mode).
2. Store sensitive tokens securely using Podman Secrets (`podman secret create`).
3. Reload systemd and start the service:
   ```bash
   systemctl --user daemon-reload
   systemctl --user start domain-monitor.service
   ```

---

## Acknowledgements

*   [**lissy93/who-dat**](https://github.com/lissy93/who-dat): Reference implementation for unified WHOIS/RDAP JSON lookups.
*   [**likexian/whois-parser**](https://github.com/likexian/whois-parser): WHOIS schema parser. Port-43 transport is implemented locally with context cancellation and response bounds.
*   [**miekg/dns**](https://github.com/miekg/dns): DNS wire protocol and cryptographic DNSSEC verification library for Go.
---

## Development & Testing

The [protocol reference](docs/protocols.md) links the RFCs and states which
parts the monitor uses. Durable behavior is documented here and in that scoped
reference, and enforced by regression tests alongside the affected code.

All Go source remains under `src/`: `src/cmd/domain-monitor` is the thin
executable entry point, `src/internal/monitor` owns daemon behavior and embedded
assets, and `src/internal/netpolicy` owns reusable outbound-target policy.
Maintained project documentation lives under `docs`.

The test suite uses injected clients, local HTTP/DNS fixtures, and a committed synthetic WHOIS corpus.

Enable the tracked pre-push hook once per clone:

```bash
git config core.hooksPath .githooks
```

Before every push, `.githooks/pre-push` runs formatting, race tests, the
recommended 90% coverage check, `go vet`, and `revive` as best-effort advisory
checks; it never blocks a push. On Arch Linux, install its tools with
`pacman -S go revive`. Release CI remains the strict enforcement boundary and
applies the complete pinned `.golangci.yml` suite. The scheduler owns an injectable clock/timer
seam for deterministic lifecycle tests; protocol clients and caches still use
wall-clock time internally.

Dashboard delivery, API integration, and embedded assets use deterministic
non-browser tests. Review interactive and visual behavior manually when changing
the dashboard.

Live tests are colocated with their protocol tests and skip unless explicitly
enabled: `DOMAIN_MONITOR_LIVE=1 go test ./src/internal/monitor -run '^TestLive' -count=1`.
The compact [assurance checklist](docs/protocols.md#assurance-checklist) defines
the supported-scope release gate; passing tests alone is not a bug-free guarantee.

For parser fuzzing, run `go test -fuzz=FuzzFlexibleDateParsing -fuzztime=30s ./src/internal/monitor`.

### CI/CD Pipeline

The GitHub Actions workflow only builds and publishes optimized multi-platform
containers for release tags on `main`; validation is owned by the local
pre-push hook.
