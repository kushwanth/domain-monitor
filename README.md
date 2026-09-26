# Domain & DNS Security Monitor

> **Disclaimer: LLM Contribution**
> This project was developed and refactored with the assistance of a Large Language Model (LLM).

A self-hosted Go daemon that monitors domain registrations, DNS records, TLS certificates, and published email security records.

It runs as one process with bounded concurrency, resource limits, an embedded dashboard, and alerts. Upstream failures and incomplete evidence remain visible.

---

## Key Features

*   **RDAP & WHOIS Monitoring:** IANA RDAP bootstrap discovery with registry exceptions and fallback to port-43 WHOIS. Monitors registration, expiry and nameserver evidence.
*   **DNS Record Integrity:** Validates `A`, `AAAA`, `CNAME`, `MX`, `TXT`, `CAA`, `NS`, `IP`, and `ALIAS` records. Supports `exact`, `prefix`, `contains`, and `any_of` matching strategies, CNAME flattening, and per-record custom resolver overrides.
*   **SSL/TLS Expiration Tracking:** Automatically performs TLS handshakes on web-facing records to track certificate validity, warning on approaching expirations (<= 14 days).
*   **Email Security Suite:** Checks MX records against configured providers, discovers SPF and DMARC records, and checks configured DKIM selectors. It does not evaluate complete mail authentication policy.
*   **2-Tier DNSSEC Verification:** Checks local DS/DNSKEY and RRSIG evidence and requires an authenticated DNS-over-HTTPS (DoH) response for a verified result.
*   **Certificate Transparency (CT) Logs:** Periodically rescans `api.ctlogs.dev`, stores a bounded local display history, and persists scan progress, seen IDs, and provider-specific pending alerts. Each cycle fetches one page; after a 10-page budget the scan warns and resumes from its saved cursor. State retains at most 1,000 seen IDs per domain and bounded pending alerts; exhausted retention budgets report incomplete coverage. The state API exposes poll/scan freshness and unacknowledged alerts. The API's validity-date ordering still prevents a guarantee that every late-indexed certificate will be found.
*   **Notification Engine:** Ntfy is required and attempted first. Telegram is optional. Alerts are deduplicated and throttled, with domain-name redaction supported.
*   **Embedded Web Dashboard:** A single-page dashboard with Dark and Light modes, periodic state polling, and a `/health` liveness endpoint. Provider quotas can still defer checks despite local rate limiting.

---

## Configuration

The daemon reads `config.json` once, applies environment overrides, validates it,
and initializes an owned configuration snapshot. Changes require a restart.

### Standard `config.json` Example

```json
{
  "port": "8080",
  "loop_interval_days": 0.25,
  "data_dir": "./data",
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
      "dnssec": true,
      "monitor_ct_logs": true,
      "caa": {
        "issue": ["letsencrypt.org", "digicert.com"]
      }
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
| `data_dir` | string | Container: `/app/data`; local: `./data` | Path to persist CT histories and state. `DATA_DIR` overrides it at startup. |
| `resolvers` | array | `["1.1.1.1"...]` | List of up to 9 custom global DNS resolver IPs, retained for runtime failover. |
| `doh_url` | string | `"https://dns.google/resolve"` | Trusted upstream JSON DoH validator used to corroborate local DNSSEC evidence; this daemon is not an independent root-to-zone validator. |
| `ctlogs_api_key` | string | `""` | Optional Bearer API key for `api.ctlogs.dev`. |
| `notifications` | object | Required | Must contain `ntfy.url`, a valid HTTP(S) URL. Optional `ntfy.auth`. Telegram is enabled only when both `token` and `chat_id` are nonempty after config/environment overrides. Missing or incomplete credentials disable Telegram with a warning; Ntfy remains active. Reachability is checked during delivery. |

Run one daemon instance per `data_dir`. CT state writes are atomic for process crashes; they do not provide a transaction across history and state files or a power-loss durability guarantee.

CT discoveries are committed before delivery. Provider acceptance is retained in memory until its acknowledgement is written successfully, avoiding repeat delivery during a temporary write failure. A crash after remote acceptance but before that write can still cause a duplicate on restart; delivery is not exactly once.
Disabling CT or removing a domain at restart stops its CT alerts and removes its
checkpoint at the next successful commit. Re-enabling starts a new baseline;
existing display history remains on disk.

RDAP requests honor `HTTP_PROXY` and `HTTPS_PROXY`. With a proxy configured, the proxy resolves destination hostnames, so the daemon's local destination IP check applies to the proxy connection; use a trusted proxy with its own outbound restrictions.

### Runtime state

Configuration and resolver lists are owned at startup and shared read-only inside
the daemon; explicit snapshot access returns independent copies. Internal status
and priority values are byte enums, and condition codes are 16-bit enums. API and
checkpoint status names retain their string representation. Condition history
keeps only codes and start times, avoiding retention of old error messages.

Domain names, DNS values and diagnostics still need strings; variable-sized
results and durable CT discoveries need bounded slices/maps. Optional condition
pointers avoid embedding large unused diagnostics in healthy results. Go's escape
analysis determines stack versus heap placement; the daemon does not promise that
all state lives on the stack. Completed cycles publish one cached JSON snapshot.
CT exports and committed checkpoints own their nested slices and conditions;
changing a returned cycle result cannot alter the restart checkpoint. Worker
results transfer ownership to the cycle collector; mutable cycle maps have one
owner. Bootstrap cache access returns a copy and pricing access returns values.

### Domain Options (`domains[]`)

| Parameter | Type | Required | Description |
| :--- | :--- | :---: | :--- |
| `domain` | string | **Yes** | Valid domain name to monitor (e.g. `"example.com"`), normalized to ASCII and limited to 253 bytes. |
| `name` | string | **Yes** | Human-readable identifier. |
| `expected_ns` | array | No | Expected primary authoritative nameservers. |
| `secondary_ns` | array | No | Optional secondary nameservers replicating the zone. |
| `is_delegated_zone`| bool | No | Set to `true` for subzones; queries authoritative NS directly. |
| `root_zone` | string | Cond. | Mandatory when `is_delegated_zone: true`. |
| `check_email_security` | bool | No | Enables SPF, DMARC, DKIM, and MX integrity monitoring. |
| `mail_provider` | string | No | Pre-configured mail provider name. |
| `mx_records` | array | No | Explicit expected MX records. |
| `dkim_selectors` | array | No | Custom DKIM selector prefixes to query. |
| `dnssec` | bool | No | Enables 2-tier local cryptographic and upstream DoH DNSSEC validation. |
| `monitor_ct_logs` | bool | No | Enables Certificate Transparency log polling. |
| `caa` | object | No | CAA validation policy (`issue`, `issuewild`, `issuemail`). |
| `expected_registrar_id` | string | No | Expected IANA Registrar ID (e.g. `"292"`). |
| `expected_registrar_name` | string | No | Expected registrar name when name matching is needed. |
| `domain_transfer_locked` | bool | No | Alert if the domain transfer lock is missing. |
| `renewal_price` | float | No | Manual renewal price override (e.g. for premium domains or custom contracts). If omitted or `0`, the daemon looks for a renewal price in the DotSweep TLD catalog; unavailable prices remain unknown. |
| `allow_expiry` | bool | No | If `true`, suppresses expiration warnings and excludes domain from renewal pricing calculations. |
| `verify_ns_health` | bool | No | Queries primary/secondary NS for reachability and SOA consistency. |
| `suppress_alerts` | bool | No | Mutes notification alerts for this domain. |

### DNS Record Options (`dns_records[]`)

| Parameter | Type | Required | Description |
| :--- | :--- | :---: | :--- |
| `hostname` | string | **Yes** | Hostname / FQDN to query. |
| `name` | string | **Yes** | Human-readable identifier. |
| `type` | string | **Yes** | Record type (`A`, `AAAA`, `CNAME`, `MX`, `TXT`, `CAA`, `NS`, `IP`, `ALIAS`). |
| `expected` | array | **Yes** | List of expected values. An explicit empty list with exact matching monitors for absence. TXT values preserve case, punctuation, and literal `alias:` prefixes; surrounding whitespace is trimmed. |
| `match_type` | string | No | Strategy: `"exact"` (default), `"prefix"`, `"contains"`, `"any_of"`. |
| `custom_resolver` | string | No | Custom resolver IP for this record. |

---

## Environment Variables

Tokens and runtime paths can be configured via environment variables for easy container injection:

| Variable | Default | Description |
| :--- | :--- | :--- |
| `CONFIG_PATH` | `"config.json"` | Path to the `config.json` file |
| `DATA_DIR` | Config value, otherwise `./data` | Directory for persistent state and CT logs; deployment examples set `/app/data` |
| `PORT` | `"8080"` | HTTP server listening port |
| `NTFY_AUTH` | Config value | Authorization header/token for Ntfy |
| `TELEGRAM_TOKEN` | Config value | Telegram Bot API token |
| `TELEGRAM_CHAT_ID` | Config value | Telegram chat or channel ID |
| `CTLOGS_API_KEY` | Config value | API token for `api.ctlogs.dev` |
| `DOH_URL` | `"https://dns.google/resolve"` | Upstream DNS-over-HTTPS endpoint |

---

## Web Dashboard & API

The daemon provides an embedded Web UI and JSON API:

*   **`GET /`:** Interactive Web Dashboard displaying the latest completed check and connection state. Domain cards show annual renewal prices when collapsed and expanded; CT issues appear as status badges, with certificate history on the Certificates page.
*   **`GET /health`:** HTTP 200 liveness probe (`{"status":"ok"}`).
*   **`GET /api/state`:** Real-time JSON snapshot of the full monitoring evaluation state.
*   **`GET /api/certs?domain=example.com`:** Certificate Transparency history for a domain.

---

## Domain Renewal Pricing & Privacy

The daemon tracks estimated annual domain renewal costs for your portfolio:

* **Automatic Standard TLD Pricing**: Standard domain extensions (e.g., `.com`, `.org`, `.co.uk`) are automatically priced using the open [DotSweep](https://dotsweep.com/tlds) TLD catalog.
* **Pricing catalog privacy**: The daemon queries `https://dotsweep.com/tlds` to download a public TLD catalog without sending portfolio domain names, TLD lists, or registrar identities in that request. Domain, DNS, and CT checks contact their configured upstream services separately.
* **Catalog caching**: Upstream catalog responses are cached in memory for 24 hours (`PricingCacheTTL`). Temporary upstream failures or unusable catalogs retain existing cached data for up to 7 days.
* **Premium Domains & Custom Overrides**: Because premium domains have custom renewal prices that cannot be inferred from standard TLD rates, you can specify `renewal_price` in `config.json` (e.g., `"renewal_price": 250.00`). A manual amount takes precedence. Domain cards show the annual price or `Unknown` in both states; domains being let go show `Not renewing`, and delegated zones show `Not applicable`. The portfolio total is partial when some prices are unknown.


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
  -v /path/to/your/data:/app/data:U \
  -e CONFIG_PATH=/app/config.json \
  -e DATA_DIR=/app/data \
  ghcr.io/your-github-username/your-repo-name:latest
```

*Note: Ensure your host data directory (`/path/to/your/data`) has write permissions for UID 65532.*

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
*   [**api.ctlogs.dev**](https://api.ctlogs.dev): Certificate Transparency search API.
---

## Development & Testing

The single [protocol reference](docs/protocols.md) links the RFCs and states which parts the monitor uses.

The test suite uses injected clients, local HTTP/DNS fixtures, and a committed synthetic WHOIS corpus.

To run the test suite:
```bash
go test -v -race ./src/...
```

A dashboard regression runs in headless Chromium when it is installed; it skips otherwise.

Live tests are colocated with their protocol tests and skip unless explicitly
enabled: `DOMAIN_MONITOR_LIVE=1 go test ./src -run '^TestLive' -count=1`.
The compact [assurance checklist](docs/protocols.md#assurance-checklist) defines
the supported-scope release gate; passing tests alone is not a bug-free guarantee.

For parser fuzzing, run `go test -fuzz=FuzzFlexibleDateParsing -fuzztime=30s ./src/`.

### CI/CD Pipeline
The GitHub Actions pipeline runs race tests, `go vet`, `golangci-lint`, a formatting check, and an 83% coverage gate on pull requests, pushes to `main`, and release tags. Container publication remains tag-only.
