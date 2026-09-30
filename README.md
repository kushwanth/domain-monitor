# Domain & DNS Security Monitor

> **Disclaimer: LLM Contribution**
> This project was developed and refactored with the assistance of a Large Language Model (LLM).

A self-hosted Go daemon that monitors domain registrations, DNS records, CAA policies, and published email security records.

It runs as one process with bounded concurrency, resource limits, an embedded dashboard, and alerts. Upstream failures and incomplete evidence remain visible.

---

## Key Features

*   **RDAP & WHOIS Monitoring:** IANA RDAP bootstrap discovery with registry exceptions and fallback to port-43 WHOIS. Thin RDAP responses missing expiry or registrar data are supplemented from WHOIS; successful RDAP evidence survives WHOIS failures. Monitors registration, expiry and nameserver evidence.
*   **DNS Record Integrity:** Validates `A`, `AAAA`, `CNAME`, `MX`, `TXT`, `CAA`, `NS`, `IP`, and `ALIAS` records. Supports `exact`, `prefix`, `contains`, and `any_of` matching strategies, CNAME flattening, and per-record custom resolver overrides.
*   **CAA Publication Checks:** Compares configured issuer-tag values and supports explicit deny-all lists. This monitors DNS publication; it does not verify certificates or evaluate CA issuance policy.
*   **Email Security Suite:** Checks MX records against configured providers, discovers SPF and DMARC records, and checks configured DKIM selectors. It does not evaluate complete mail authentication policy. Bundled provider presets can be extended or overridden at startup using JSON files in `./data/email_providers/` or `email_providers_dir`. Both MX suffixes and DKIM selectors come from those files.
*   **2-Tier DNSSEC Verification:** Checks local DS/DNSKEY and RRSIG evidence and requires an authenticated DNS-over-HTTPS (DoH) response for a verified result.
*   **Notification Engine:** Ntfy is required and attempted first. Telegram is optional. Alerts are published through one lifecycle-bound worker, with domain-name redaction supported. Transient HTTP failures receive up to three attempts; persistent problems alert again on subsequent cycles.
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
      "expected_ns": ["ns1.example.com", "ns2.example.com"],
      "expected_registrar_id": "292",
      "domain_transfer_locked": true,
      "check_email_security": true,
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
| `resolvers` | array | `["1.1.1.1"...]` | List of up to 9 custom global DNS resolver IPs, retained for runtime failover. |
| `doh_url` | string | `"https://dns.google/resolve"` | Trusted upstream JSON DoH validator used to corroborate local DNSSEC evidence; this daemon is not an independent root-to-zone validator. |
| `notifications` | object | Required | Must contain `ntfy.url`, a valid HTTP(S) URL. Optional `ntfy.auth`. Telegram is enabled only when both `token` and `chat_id` are nonempty after config/environment overrides. Missing or incomplete credentials disable Telegram with a warning; Ntfy remains active. Reachability is checked during delivery. |

RDAP requests honor `HTTP_PROXY` and `HTTPS_PROXY`. With a proxy configured, the proxy resolves destination hostnames, so the daemon's local destination IP check applies to the proxy connection; use a trusted proxy with its own outbound restrictions.

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
WHOIS gathering follows the same phase. Evaluation begins only after all
gathering completes and performs no network requests. Expected DNS values are
copied once so returned cycle state remains independent of configuration.
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
rate-limited retries. Notifications are delivered after state publication in
descending priority order by one bounded worker, with separate provider
timeouts and retry budgets controlled by daemon cancellation.

Provider files use the filename as the provider name, for example `custom.json`:

```json
{
  "mx_records": ["mail.example.com"],
  "dkim_selectors": ["selector1", "selector2"]
}
```

MX entries are normalized hostname suffixes, matched at label boundaries. At
least one MX suffix is required. DKIM selectors may be omitted when no default
selector is known. Set `mail_provider` to `custom` to use this definition. Provider
files are read once; changes require a restart.

### Domain Options (`domains[]`)

| Parameter | Type | Required | Description |
| :--- | :--- | :---: | :--- |
| `domain` | string | **Yes** | Valid domain name to monitor (e.g. `"example.com"`), normalized to ASCII and limited to 253 bytes. |
| `name` | string | **Yes** | Human-readable identifier. |
| `expected_ns` | array | No | Expected primary authoritative nameservers, including redundant primaries. Every entry has the configured primary role. |
| `secondary_ns` | array | No | Explicit secondary (slave) nameservers expected to replicate the zone. Other primary entries are never inferred to be secondary. |
| `is_delegated_zone`| bool | No | Set to `true` for subzones; queries authoritative NS directly. |
| `root_zone` | string | Cond. | Mandatory when `is_delegated_zone: true`. |
| `check_email_security` | bool | No | Enables SPF, DMARC, DKIM, and MX integrity monitoring. |
| `mail_provider` | string | No | Pre-configured mail provider name. |
| `mx_records` | array | No | Explicit expected MX records. |
| `dkim_selectors` | array | No | Custom DKIM selector prefixes to query. |
| `dnssec` | bool | No | Enables 2-tier local cryptographic and upstream DoH DNSSEC validation. |
| `caa` | object | No | CAA validation policy (`issue`, `issuewild`, `issuemail`). |
| `expected_registrar_id` | string | No | Expected IANA Registrar ID (e.g. `"292"`). |
| `expected_registrar_name` | string | No | Expected registrar name when name matching is needed. |
| `domain_transfer_locked` | bool | No | Alert if the domain transfer lock is missing. |
| `renewal_price` | float | No | Manual renewal price override (e.g. for premium domains or custom contracts). If omitted or `0`, the daemon looks for a renewal price in the DotSweep TLD catalog; unavailable prices remain unknown. |
| `unused` | bool | No | If `true`, places the domain in the Unused section and skips all monitoring checks, alerts, and renewal pricing. Existing `allow_expiry: true` entries are treated as `unused: true` when loading older configs. |
| `verify_ns_health` | bool | No | Queries primary/secondary NS for reachability and SOA consistency. |
| `suppress_alerts` | bool | No | Mutes notification alerts for this domain. |

Nameserver roles come from configuration, not DNS responses or list order.
The first `expected_ns` is the comparison reference; additional entries remain
primaries. Only `secondary_ns` entries are labeled secondary (slave). If a server
appears in both lists, it is checked once as primary. Health checks compare
authority, SOA serials, and optional DNSKEY evidence; matching answers do not
prove that zone transfer or replication is working. The dashboard count is the
number of distinct configured nameservers queried, including failed attempts;
it does not count nameservers discovered from DNS.

CAA tag lists distinguish omission from explicit denial. For example,
`"caa": {"issue": ["ca.example"], "issuewild": []}` expects the configured issuer
and `0 issuewild ";"`. Omitted or null tags are unconstrained. An empty CAA
object adds no check. Only tags included in the policy constrain matching;
other observed tags remain visible without causing a mismatch.

### DNS Record Options (`dns_records[]`)

| Parameter | Type | Required | Description |
| :--- | :--- | :---: | :--- |
| `hostname` | string | **Yes** | Hostname / FQDN to query. |
| `name` | string | **Yes** | Human-readable identifier; the `__caa__` prefix is reserved for generated domain policies. |
| `type` | string | **Yes** | Record type (`A`, `AAAA`, `CNAME`, `MX`, `TXT`, `CAA`, `NS`, `IP`, `ALIAS`). |
| `expected` | array | **Yes** | List of expected values. An explicit empty list with exact matching monitors for absence. Explicit CAA DNS tasks compare the full record set; omitted-tag relaxation applies only to domain `caa` policies. TXT values preserve case, punctuation, and literal `alias:` prefixes; surrounding whitespace is trimmed. |
| `match_type` | string | No | Strategy: `"exact"` (default), `"prefix"`, `"contains"`, `"any_of"`. |
| `custom_resolver` | string | No | Custom resolver IP for this record. |

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

*   **`GET /`:** Interactive Web Dashboard grouping checked domains into Healthy, Issues, and Unused sections and DNS records into Matched and Not Matched sections. Empty sections are hidden; pending results appear after checks finish. Domain cards show days to expiry, and the sidebar shows annual and upcoming renewal costs.
*   **`GET /health`:** HTTP 200 liveness probe (`{"status":"ok"}`).
*   **`GET /api/state`:** Latest completed-cycle JSON snapshot; pending checks are published at startup. Responses include an ETag, and matching `If-None-Match` requests return 304 without a body.

---

## Domain Renewal Pricing & Privacy

The daemon tracks estimated annual domain renewal costs for your portfolio:

* **Automatic Standard TLD Pricing**: Standard domain extensions (e.g., `.com`, `.org`, `.co.uk`) are automatically priced using the open [DotSweep](https://dotsweep.com/tlds) TLD catalog.
* **Pricing catalog privacy**: The daemon queries `https://dotsweep.com/tlds` to download a public TLD catalog without sending portfolio domain names, TLD lists, or registrar identities in that request. Domain and DNS checks contact their configured upstream services separately.
* **Catalog caching**: Upstream catalog responses are cached in memory for 24 hours (`PricingCacheTTL`). Temporary upstream failures or unusable catalogs retain existing cached data for up to 7 days.
* **Premium Domains & Custom Overrides**: Because premium domains have custom renewal prices that cannot be inferred from standard TLD rates, you can specify `renewal_price` in `config.json` (e.g., `"renewal_price": 250.00`). A manual amount takes precedence. Monitored domain cards show the annual price or `Unknown`; delegated zones show `Not applicable`. Unused domains are excluded from the portfolio total, which is partial when some monitored prices are unknown.
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
  ghcr.io/your-github-username/your-repo-name:latest
```

To add custom email providers, mount their directory read-only at `/app/data/email_providers`. Bundled presets are used when this directory is absent.

### Local Execution

```bash
go build -o domain_monitor ./src
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

The single [protocol reference](src/docs/protocols.md) links the RFCs and states which parts the monitor uses.

The test suite uses injected clients, local HTTP/DNS fixtures, and a committed synthetic WHOIS corpus.

Run the local release checks from the repository root:

```bash
go test -race -coverprofile=coverage.out ./...
go vet ./...
golangci-lint run --config .golangci.yml
gofmt -l src
go tool cover -func=coverage.out
```

Require no formatting differences and at least 83% total statement coverage.
Install `golangci-lint` separately using a version built for the repository's Go
toolchain. The repository supplies its lint configuration but currently pins
no linter executable version. Clock-dependent code still uses system time;
full clock injection remains an architecture improvement.

The dashboard regression runs in headless Chromium when installed and skips
otherwise. Install Chromium when verifying dashboard behavior for a release.

Live tests are colocated with their protocol tests and skip unless explicitly
enabled: `DOMAIN_MONITOR_LIVE=1 go test ./src -run '^TestLive' -count=1`.
The compact [assurance checklist](src/docs/protocols.md#assurance-checklist) defines
the supported-scope release gate; passing tests alone is not a bug-free guarantee.

For parser fuzzing, run `go test -fuzz=FuzzFlexibleDateParsing -fuzztime=30s ./src/`.

### CI/CD Pipeline
The GitHub Actions workflow builds and publishes containers for release tags on `main`. Run race tests, `go vet`, the configured `golangci-lint`, formatting checks, and the 83% coverage gate locally before release; the current workflow does not enforce these checks.
