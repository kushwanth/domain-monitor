# Domain & DNS Security Monitor

> **Disclaimer: LLM Contribution**
> This project was developed and refactored with the assistance of a Large Language Model (LLM).

A lightweight, high-performance Go daemon designed to continuously monitor domain registrations, DNS records, SSL/TLS certificates, and email authentication security (SPF, DMARC, DKIM). 

Built for infrastructure engineers and homelab environments, it uses a decoupled architecture with bounded concurrency to ensure your infrastructure is monitored efficiently without triggering rate limits or false positives.

---

## Key Features

*   **RDAP & WHOIS Monitoring:** Zero-dependency IANA RDAP bootstrap engine with stealth ccTLD seeds and automatic fallback to port-43 WHOIS. Detects Auto-Renew Grace Period (ARGP) discrepancies and nameserver desynchronization.
*   **DNS Record Integrity:** Validates `A`, `AAAA`, `CNAME`, `MX`, `TXT`, `CAA`, `NS`, and `IP` records. Supports `exact`, `prefix`, `contains`, and `any_of` matching strategies, CNAME flattening, and per-record custom resolver overrides.
*   **SSL/TLS Expiration Tracking:** Automatically performs TLS handshakes on web-facing records to track certificate validity, warning on approaching expirations (<= 14 days).
*   **Email Security Suite:** Enforces anti-hijacking protection by validating MX records against major providers. Validates strict RFC 7208 SPF policies, DMARC presence, and DKIM selector keys.
*   **2-Tier DNSSEC Verification:** Validates local cryptographic chains (DS-to-KSK matching, RRSIG signature validity) and upstream DNS-over-HTTPS (DoH) chain validation via the Authenticated Data (`AD`) flag.
*   **Certificate Transparency (CT) Logs:** Real-time polling for newly issued SSL/TLS certificates via `api.ctlogs.dev` with incremental backfilling and local state persistence.
*   **Notification Engine:** Deduplicates and throttles alerts to Ntfy and Telegram. Supports domain name privacy redaction in notifications.
*   **Embedded Web Dashboard:** Responsive single-page dashboard with Dark and Light modes. Provides real-time statuses and a `/health` endpoint for Docker/K8s liveness probes. Highly scalable decoupled UI architecture natively supports 1000s of domains smoothly by dynamically fetching and paginating state data via a JSON API. All external API polling rate limits are hardcoded safely (CT Logs: 5s, WHOIS/RDAP: 10s) ensuring you never get blocked by external providers regardless of configuration size.

---

## Configuration

The daemon is configured entirely via a standard JSON file (`config.json`). 



### Standard `config.json` Example

{
  "port": "8080",
  "loop_interval_days": 0.25,
  "data_dir": "./data",
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
| `loop_interval_days` | number | `0.25` | Duration in days between monitoring cycles (e.g., `0.25` for 6h). Minimum allowed is `0.125`. |
| `data_dir` | string | `"/app/data"` | Path to persist CT log histories and state. |
| `resolvers` | array | `["1.1.1.1"...]` | List of up to 9 custom global DNS resolver IPs. |
| `doh_url` | string | `"https://dns.google/resolve"` | Upstream DNS-over-HTTPS endpoint for DNSSEC chain validation. |
| `ctlogs_api_key` | string | `""` | Optional Bearer API key for `api.ctlogs.dev`. |
| `notifications` | object | `{}` | Notification provider configuration (`ntfy`, `telegram`). |

### Domain Options (`domains[]`)

| Parameter | Type | Required | Description |
| :--- | :--- | :---: | :--- |
| `domain` | string | **Yes** | Fully qualified domain name to monitor (e.g. `"example.com"`). |
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
| `domain_transfer_locked` | bool | No | Alert if the domain transfer lock is missing. |
| `renewal_price` | float | No | Manual renewal price override (e.g. for premium domains or custom contracts). If omitted or `0`, standard renewal pricing is resolved automatically via the private DotSweep TLD catalog. |
| `allow_expiry` | bool | No | If `true`, suppresses expiration warnings and excludes domain from renewal pricing calculations. |
| `verify_ns_health` | bool | No | Queries primary/secondary NS for reachability and SOA consistency. |
| `accept_self_signed` | bool | No | Allows self-signed certificates during TLS expiration checks. |
| `suppress_alerts` | bool | No | Mutes notification alerts for this domain. |

### DNS Record Options (`dns_records[]`)

| Parameter | Type | Required | Description |
| :--- | :--- | :---: | :--- |
| `hostname` | string | **Yes** | Hostname / FQDN to query. |
| `name` | string | **Yes** | Human-readable identifier. |
| `type` | string | **Yes** | Record type (`A`, `AAAA`, `CNAME`, `MX`, `TXT`, `CAA`, `NS`, `IP`). |
| `expected` | array | **Yes** | List of expected values. |
| `match_type` | string | No | Strategy: `"exact"` (default), `"prefix"`, `"contains"`, `"any_of"`. |
| `custom_resolver` | string | No | Custom resolver IP for this record. |
| `accept_self_signed` | bool | No | Accepts self-signed TLS certificates for SSL expiration monitoring. |
| `skip_ssl` | bool | No | Skips TLS/SSL certificate checks entirely. |

---

## Environment Variables

Tokens and runtime paths can be configured via environment variables for easy container injection:

| Variable | Default | Description |
| :--- | :--- | :--- |
| `CONFIG_PATH` | `"config.json"` | Path to the `config.json` file |
| `DATA_DIR` | `"/app/data"` | Directory for persistent state and CT logs |
| `PORT` | `"8080"` | HTTP server listening port |
| `NTFY_AUTH` | Config value | Authorization header/token for Ntfy |
| `TELEGRAM_TOKEN` | Config value | Telegram Bot API token |
| `TELEGRAM_CHAT_ID` | Config value | Telegram chat or channel ID |
| `CTLOGS_API_KEY` | Config value | API token for `api.ctlogs.dev` |
| `DOH_URL` | `"https://dns.google/resolve"` | Upstream DNS-over-HTTPS endpoint |

---

## Web Dashboard & API

The daemon provides an embedded Web UI and JSON API:

*   **`GET /`:** Interactive Web Dashboard displaying real-time statuses.
*   **`GET /health`:** HTTP 200 liveness probe (`{"status":"ok"}`).
*   **`GET /api/state`:** Real-time JSON snapshot of the full monitoring evaluation state.
*   **`GET /api/certs?domain=example.com`:** Certificate Transparency history for a domain.

---

## Domain Renewal Pricing & Privacy

The daemon tracks estimated annual domain renewal costs for your portfolio:

* **Automatic Standard TLD Pricing**: Standard domain extensions (e.g., `.com`, `.org`, `.co.uk`) are automatically priced using the open [DotSweep](https://dotsweep.com/tlds) TLD catalog.
* **100% Private Architecture**: The daemon queries `https://dotsweep.com/tlds` to download the public TLD pricing catalog. It makes a plain GET request with zero parameters—**no domain names, no TLD lists, and no registrar identities are ever sent over the network**. All matching against your domains is performed 100% locally in-memory.
* **Anti-DDoS & In-Memory Caching**: Upstream catalog responses are cached in-memory with a 24-hour TTL (`PricingCacheTTL`), preventing excessive upstream requests even with frequent monitoring intervals. If DotSweep experiences temporary outages, the cache gracefully falls back to existing data without interruption.
* **Premium Domains & Custom Overrides**: Because premium domains have custom registry-set renewal prices that cannot be inferred from standard TLD rates, you can specify `renewal_price` in `config.json` (e.g., `"renewal_price": 250.00`). If `renewal_price > 0`, that manual amount is used directly and external queries are bypassed entirely. If `renewal_price` is omitted or `0`, standard pricing is applied.


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

## Development & Testing

This project maintains strict testing standards, including table-driven unit tests and native Go fuzzing.

*   **Run all tests:** `go test ./src/... -v -race`
*   **Run fuzzing:** `go test -fuzz=FuzzFlexibleDateParsing -fuzztime=30s ./src/`

---

## Acknowledgements

*   [**lissy93/who-dat**](https://github.com/lissy93/who-dat): Reference implementation for unified WHOIS/RDAP JSON lookups.
*   [**likexian/whois**](https://github.com/likexian/whois) & [**likexian/whois-parser**](https://github.com/likexian/whois-parser): Raw port-43 WHOIS transport and schema parser.
*   [**miekg/dns**](https://github.com/miekg/dns): DNS wire protocol and cryptographic DNSSEC verification library for Go.
*   [**api.ctlogs.dev**](https://api.ctlogs.dev): Certificate Transparency search API.
---

## Development & Testing

This project leverages a zero-overhead **Dependency Injection (DI)** architecture to achieve high test coverage without relying on flaky live network calls or running background test servers. 
Network-bound functions (like DNS resolution, RDAP lookups) are injected as function pointers on the `AppState`, allowing deterministic offline mocking in tests.

To run the test suite:
```bash
go test -v -race ./src/...
```

### CI/CD Pipeline
The project uses a unified GitHub Actions pipeline (`.github/workflows/build-and-push.yml`) that strictly enforces:
- `golangci-lint` for code quality.
- Unit testing with the `-race` detector.
- A minimum test coverage threshold (currently 83%).

The pipeline will absolutely block the building and pushing of the Docker image to GHCR if any tests or linters fail.
