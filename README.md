# Domain & DNS Security Monitor

A small, self-hosted monitor for the domains and DNS records you look after.
It runs as a single Go process, serves its own dashboard, and sends concise
alerts through ntfy or Telegram.

> **Development note:** This project has been developed and refactored with
> LLM assistance. Changes are reviewed against the documented behavior and
> exercised by the repository test suite before release.

This project is intended for a personal server, homelab, or small domain
portfolio. It favors a plain configuration file, predictable resource use, and
visible failures over a multi-service stack. There are no external databases,
accounts, or hosted control planes to maintain.

This README is the primary setup and operator reference. For protocol-specific
scope, standards, and release assurance, see
[`docs/protocols.md`](docs/protocols.md).

## What it monitors

- **Domain registration:** Registry-first RDAP checks with safe registrar
  referrals and bounded WHOIS fallback when RDAP cannot provide an answer.
- **DNS records:** `A`, `AAAA`, `CNAME`, `MX`, `TXT`, `CAA`, `NS`, `IP`, and
  `ALIAS` expectations, including explicit absence checks and optional custom
  resolvers.
- **Nameservers and DNSSEC:** Public delegation, direct authoritative SOA and
  DNSKEY checks, and local DS/RRSIG evidence corroborated through trusted DoH.
- **Email DNS posture:** MX expectations, SPF publication, DMARC discovery, and
  configured DKIM selectors. This is publication monitoring, not per-message
  mail authentication.
- **CAA policy:** Expected issuer tags and explicit deny-all publication.
- **Renewal planning:** Expiration dates and estimated renewal costs using a
  cached public TLD price catalog, with manual overrides for premium domains.

The embedded dashboard provides light and dark themes, while each completed
cycle can send one bounded, deterministically ordered report. Network failures,
resolver disagreement, and incomplete evidence remain visible instead of being
silently treated as healthy.

## Quick start

1. Save the example below as `config.json` and replace its sample values.
2. Build and start the monitor:

   ```bash
   go build -o domain-monitor ./src/cmd/domain-monitor
   ./domain-monitor -config config.json
   ```

3. Open `http://localhost:8080`.

For an always-on homelab deployment, use the container or Podman Quadlet
instructions below.

## Configuration

The daemon reads `config.json` once, applies environment overrides, validates it,
and initializes an owned configuration snapshot. Files are limited to 8 MiB.
Changes require a restart.

### Example `config.json`

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
      "name": "Primary Domain",
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

## Configuration reference

### Global options

| Parameter | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `port` | string | `"8080"` | HTTP server listening port. |
| `loop_interval_days` | number | `0.25` | Days between monitoring cycles; values outside `0.125`–`365` are clamped to those bounds. |
| `email_providers_dir` | string | `./data/email_providers` | Optional startup directory of provider JSON files, overriding bundled presets by filename. A missing default directory uses bundled presets; an explicitly configured missing directory, malformed definition, or unknown configured provider fails startup. |
| `resolvers` | array | `["1.1.1.1"...]` | Global DNS resolver IPs. Checks compare the first two observations when available; additional entries remain available to protocol-specific failover paths. |
| `doh_url` | string | `"https://dns.google/resolve"` | Trusted upstream JSON DoH validator used to corroborate local DNSSEC evidence; this daemon is not an independent root-to-zone validator. |
| `notifications` | object | Required | Must contain `ntfy.url`, a valid HTTP(S) URL. Authenticated ntfy requires HTTPS. Optional Telegram is enabled only when both `token` and `chat_id` are nonempty. Cross-origin notification redirects are rejected. |

RDAP and public-metadata clients connect directly so proxy resolution cannot bypass destination policy. The operator-selected notification client may use environment proxy settings; credentials are never followed across origins.

### Runtime behavior

Configuration is loaded and validated once at startup; changes require a
restart. Each cycle gathers bounded network evidence, evaluates it locally, and
publishes one coherent JSON snapshot. Dashboard readers therefore see either
the previous completed cycle or the new one, never a half-written state.

The worker pool is capped at 32. Transient HTTP failures use bounded retries
with backoff and `Retry-After` support, while DNS and WHOIS use their own small
retry budgets. Resolver disagreement and partial results are reported as such.
Notifications are assembled after publication, ordered by severity, and sent
independently to each configured provider.

All state is kept in memory. A restart rebuilds condition ages, caches, and the
latest results; failed notification deliveries are not persisted. This keeps
the daemon simple to operate, but it is not intended to be a long-term history
or reporting database.

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

### Domain options (`domains[]`)

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

### DNS record options (`dns_records[]`)

| Parameter | Type | Required | Description |
| :--- | :--- | :---: | :--- |
| `hostname` | string | **Yes** | Hostname / FQDN to query. |
| `name` | string | **Yes** | Human-readable identifier; the `__caa__` prefix is reserved for generated domain policies. |
| `type` | string | **Yes** | Record type (`A`, `AAAA`, `CNAME`, `MX`, `TXT`, `CAA`, `NS`, `IP`, `ALIAS`). |
| `expected` | array | **Yes** | List of expected values. An explicit empty list with exact matching monitors for absence. Explicit CAA DNS tasks compare the full record set; omitted-tag relaxation applies only to domain `caa` policies. TXT values preserve case, punctuation, and literal `alias:` prefixes; surrounding whitespace is trimmed. |
| `match_type` | string | No | Strategy: `"exact"` (default), `"prefix"`, `"contains"`, `"any_of"`. |
| `custom_resolver` | string | No | Resolver IP used exclusively for this record. No global-resolver fallback occurs. |

## Environment variables

Tokens and runtime paths can be configured through environment variables for
container deployments:

| Variable | Default | Description |
| :--- | :--- | :--- |
| `CONFIG_PATH` | `"config.json"` | Path to the configuration file. |
| `PORT` | `"8080"` | HTTP server listening port. |
| `NTFY_AUTH` | Config value | Authorization header or token for ntfy. |
| `TELEGRAM_TOKEN` | Config value | Telegram Bot API token. |
| `TELEGRAM_CHAT_ID` | Config value | Telegram chat or channel ID. |
| `DOH_URL` | `"https://dns.google/resolve"` | Upstream DNS-over-HTTPS endpoint. |

## Web dashboard and API

The daemon provides an embedded web UI and JSON API:

- **`GET /`:** Dashboard grouping domains into Healthy, Issues, and Allowed to
  Expire, with separate matched and unmatched DNS records. Domain cards show
  expiry and renewal details.
- **`GET /health`:** HTTP 200 liveness probe (`{"status":"ok"}`).
- **`GET /api/state`:** Latest coherent JSON snapshot. Pending checks are
  published at startup, failed attempts retain prior evidence, and ETag support
  avoids sending unchanged responses.

RDAP state sets `expiry_confirmed` only after a domain configured with
`allow_expiry` is confirmed expired or absent; that transition suppresses its
dependent checks until registration reappears.

## Renewal pricing and privacy

The daemon tracks estimated annual domain renewal costs for your portfolio:

- **Standard TLD pricing:** Common extensions such as `.com`, `.org`, and
  `.co.uk` use the public [DotSweep](https://dotsweep.com/tlds) catalog.
- **Privacy:** The catalog request does not include your domain names, TLD list,
  or registrar identities. Domain checks still contact their relevant upstream
  services normally.
- **Caching:** The catalog is cached in memory for 24 hours. Usable stale data
  may be retained for up to seven days during an outage.
- **Manual prices:** Set `renewal_price` for premium domains or custom rates. A
  configured value always takes precedence.
- **Dashboard totals:** Known annual and upcoming renewal costs are summed.
  Totals are marked partial when some prices are unknown, and domains allowed
  to expire are excluded.

## Deployment

### Docker

Pre-built multi-architecture Docker images are available through GitHub
Container Registry.

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

To add custom email providers, mount their directory read-only at
`/app/data/email_providers`. Bundled presets are used when this directory is
absent.

### Local execution

```bash
go build -o domain-monitor ./src/cmd/domain-monitor
./domain-monitor -config config.json
```

### Podman Quadlet

Deploy using the included `domain-monitor.container` Quadlet file:

1. Copy `domain-monitor.container` to `~/.config/containers/systemd/` (user mode) or `/etc/containers/systemd/` (root mode).
2. Store sensitive tokens securely using Podman Secrets (`podman secret create`).
3. Reload systemd and start the service:
   ```bash
   systemctl --user daemon-reload
   systemctl --user start domain-monitor.service
   ```

## Project notes

Useful upstream projects:

- [lissy93/who-dat](https://github.com/lissy93/who-dat): Reference for unified
  WHOIS and RDAP lookups.
- [likexian/whois-parser](https://github.com/likexian/whois-parser): WHOIS
  response parser. The bounded port-43 transport is implemented locally.
- [miekg/dns](https://github.com/miekg/dns): DNS wire protocol and DNSSEC
  primitives for Go.

## Development and checks

The [protocol reference](docs/protocols.md) links the RFCs and states which
parts the monitor uses. Durable behavior is documented here and in that scoped
reference, and enforced by regression tests alongside the affected code.

All Go source remains under `src/`: `src/cmd/domain-monitor` is the thin
executable entry point, `src/internal/monitor` owns daemon behavior and embedded
assets, and `src/internal/netpolicy` owns reusable outbound-target policy.
Maintained project documentation lives under `docs`.

The test suite uses injected clients, local HTTP/DNS fixtures, and a committed
synthetic WHOIS corpus.

Enable the tracked pre-push hook once per clone:

```bash
git config core.hooksPath .githooks
```

Before every push, `.githooks/pre-push` runs formatting, race tests, the
recommended 90% coverage check, `go vet`, and `revive` as best-effort advisory
checks; it never blocks a push. On Arch Linux, install its tools with
`pacman -S go revive`. Release CI remains the strict enforcement boundary and
applies the complete pinned `.golangci.yml` suite. The scheduler owns an
injectable clock/timer seam for deterministic lifecycle tests; protocol clients
and caches still use wall-clock time internally.

Dashboard delivery, API integration, and embedded assets use deterministic
non-browser tests. Review interactive and visual behavior manually when changing
the dashboard.

Live tests are colocated with their protocol tests and skip unless explicitly
enabled: `DOMAIN_MONITOR_LIVE=1 go test ./src/internal/monitor -run '^TestLive' -count=1`.
The compact [assurance checklist](docs/protocols.md#assurance-checklist) defines
the supported-scope release gate; passing tests alone is not a bug-free guarantee.

For parser fuzzing, run `go test -fuzz=FuzzFlexibleDateParsing -fuzztime=30s ./src/internal/monitor`.

### Release checks

The local pre-push hook is intentionally advisory. Release tags run the strict
race, coverage, vet, formatting, diff-hygiene, and lint gates before the
multi-platform container is published.
