# Domain & DNS Security Monitor

A robust, lightweight, and highly performant Go daemon designed for homelabs to continuously monitor domain registrations (RDAP), verify DNS record integrity, and detect nameserver hijacks. 

Built specifically for low-resource environments, this monitor uses a completely decoupled architecture, advanced DNS load balancing, and smart Cloudflare API integration to ensure your infrastructure is safe without triggering false positives or getting IP-banned by registries.

---

## Key Features

*   **Decoupled Worker Engines:** RDAP checks, standard DNS lookups, and Provider APIs run in completely independent, concurrent Goroutine worker pools scaled to your CPU core count.
*   **Consolidated Notification Engine:** Alerts are buffered during each sweep and fired sequentially to prevent alert fatigue and network throttling.
*   **Smart Cloudflare Integration:** Uses the official Go SDK. Automatically fetches CF IP ranges daily. If a domain routes through Cloudflare, it dynamically pivots to the SDK to verify your unproxied backend origin.
*   **Strict Fail-Fast Security:** At startup, the daemon validates notification reachability, DNS resolver health, enforces mandatory `name` identifiers for privacy, and forcefully crashes if the provided Cloudflare token has write/edit/delete permissions.
*   **Safe K8s Bootstrapping:** The core backend HTTP server boots instantly for Docker/K8s liveness probes (`/health`), but gracefully blocks the `/api/state` endpoint until the very first execution sweep successfully populates the memory cache, guaranteeing no zero-state flashes.
*   **Advanced DNS Resolving:** Define up to 9 custom global DNS resolvers with round-robin load balancing. Override resolvers at the individual record level for internal/split-horizon DNS.
*   **Resilient Infrastructure:** Includes full Git pre-commit hooks, CI/CD GitHub Action pipelines, and a Dockerfile that natively blocks compilation if unit tests fail.

---

## Configuration Guide (`config.jsonnet`)

The daemon uses Jsonnet for clean, variable-supported configuration. 

```jsonnet
local default_ns = ["ns1.example.com", "ns2.example.com"];
local A = "A";
local TUNNEL = "TUNNEL";

{
  port: "8080",
  loop_interval: "6h",
  request_delay: "5s",

  notifications: {
    ntfy: { url: "https://ntfy.sh/my_secret_topic", auth: "" },
    telegram: { token: "YOUR_BOT_TOKEN", chat_id: "YOUR_CHAT_ID" }
  },

  providers: {
    cloudflare_token: "YOUR_CLOUDFLARE_TOKEN", 
  },
  
  resolvers: ["1.1.1.1", "8.8.8.8", "9.9.9.9", "208.67.222.222"], 

  domains: [
    { 
      domain: "example.com", 
      name: "Prod Domain", 
      expected_ns: default_ns,
      check_email_security: true,
      mail_provider: "google",
      // mx_records: ["mx.custom.com"], // Mutually exclusive with mail_provider
      dkim_selectors: ["custom1", "custom2"],
      suppress_alerts: true // Set to true to mute notifications for this domain
    }
  ],

  dns_records: [
    // Standard Resolution
    { hostname: "mail.example.com", name: "Mail Server", type: A, expected: ["192.0.2.100"] },
    
    // Direct API Bypass (Skips DNS)
    { hostname: "api.example.com", name: "API Backend", type: A, expected: ["192.0.2.200"], provider: "cloudflare" },
    
    // Cloudflare Tunnel Native Verification (requires provider: "cloudflare")
    { hostname: "app.example.com", name: "App Tunnel", type: TUNNEL, expected: ["my-tunnel-name"], provider: "cloudflare" },
    
    // Custom Resolver Override
    { hostname: "internal.example.com", name: "Internal DNS", type: A, expected: ["10.0.0.5"], custom_resolver: "10.0.0.1" }
  ]
}
```

---

## Email Security Monitor

The daemon can automatically validate your domain's SPF, DMARC, DKIM, and MX configurations without requiring complex manual `dns_records` entries. 

By adding `check_email_security: true` to a domain, you enable the following:

1. **Anti-Hijacking (`mail_provider`)**: If you set `mail_provider` (e.g., `"google"`, `"microsoft"`, `"fastmail"`), the daemon enforces that your live MX records actually belong to that provider. If an attacker hijacks your DNS and points your MX to another host, the daemon will instantly detect it and fire a `[CRITICAL] MX HIJACK DETECTED` alert.
2. **DKIM Auto-Discovery**: Based on your `mail_provider`, the daemon automatically queries the default DKIM selector keys for the top 11 major email providers (including Google, Microsoft, Fastmail, Protonmail, iCloud, Zoho, AWS, Mailgun, Sendgrid, Postmark, and Yandex).
3. **Third-Party Sender Support**: If you use third-party services (like Mailchimp or Zendesk), you can add their DKIM prefixes to `dkim_selectors: ["k1", "zendesk1"]`. The daemon will monitor these alongside your main provider's keys.
4. **SPF & DMARC**: It automatically validates that you have exactly one `v=spf1` record at the root and a `v=DMARC1` record at `_dmarc`.
5. **Custom MX Exclusivity**: If you run a custom mail server, you can provide `mx_records: ["mx.custom.com"]` instead of `mail_provider`. The daemon will strictly verify your custom MX target, but skip the SPF/DMARC/DKIM suite. *Note: `mail_provider` and `mx_records` are mutually exclusive.*

---
## Deployment

### Docker

The project provides pre-built, natively cross-compiled Docker images for `amd64` and `arm64` via the GitHub Container Registry (GHCR). 

```bash
docker run -d \
  --name domain-monitor \
  --restart always \
  -p 8080:8080 \
  -v /path/to/your/config.jsonnet:/app/config.jsonnet:ro \
  -e CONFIG_PATH=/app/config.jsonnet \
  ghcr.io/your-github-username/your-repo-name:latest
```

### Systemd / Podman Quadlet

For Linux environments, you can use the included `domain-monitor.container` file to deploy the daemon as a native systemd service using Podman Quadlet.

1. Copy `domain-monitor.container` to `~/.config/containers/systemd/` (or `/etc/containers/systemd/` for system-wide).
2. To avoid hardcoding sensitive tokens in your `config.jsonnet`, you can inject them securely using Podman Secrets. Create the secrets:
   ```bash
   echo "your_token" | podman secret create telegram-token -
   echo "your_token" | podman secret create cloudflare-token -
   ```
3. Update `domain-monitor.container` to map these secrets, and map non-sensitive configuration (like `TELEGRAM_CHAT_ID`) using standard `Environment=` fields.
4. Reload systemd and start the container:
   ```bash
   systemctl --user daemon-reload
   systemctl --user start domain-monitor.service
   ```

---

## Testing

This project maintains strict testing requirements. 
*   **Run all tests:** `go test ./src/... -v -race`
*   **Unit tests:** Located alongside source files (e.g., `src/notify_test.go`) to test internal state. Exhaustive, parallel, and table-driven.

---

## Endpoints

*   **`/api/state`:** Real-time JSON dump of the current evaluation state (powers the Web Dashboard). The HTTP server purposefully blocks and does not listen on its port until the first execution loop is finished, guaranteeing that no partial or empty states are ever served.
*   **`/health`:** Lightweight HTTP 200 liveness probe.

---

## Disclaimer: LLM Contribution

**Note:** This Project is refined with the assistance of a Large Language Model (LLM). All logic has been reviewed and tested to ensure it meets strict security and performance requirements.