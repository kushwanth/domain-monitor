local default_ns = [
  "ns1.example.com",
  "ns2.example.com",
];
local A = "A";
local AAAA = "AAAA";
local CNAME = "CNAME";
local MX = "MX";
local TXT = "TXT";

{
  port: "8080",
  loop_interval: "6h",
  request_delay: "5s",
  whois_delay: "10s",

  // The directory where state files (ct_logs/, ct_state.json, domain_snapshots.json) are persisted
  data_dir: "./data",

  // Optional: ctlogs.dev API key for higher rate limits on CT log monitoring
  // ctlogs_api_key: "",

  notifications: {
    // ntfy: { url: "https://ntfy.sh/my_secret_topic", auth: "" },
    // telegram: { token: "YOUR_BOT_TOKEN", chat_id: "YOUR_CHAT_ID" }
  },
  
  resolvers: ["1.1.1.1", "8.8.8.8", "9.9.9.9", "208.67.222.222"], 

  domains: [
    { 
      domain: "example.com", 
      name: "Example Prod Domain", 
      // Expected authoritative nameservers validated against RDAP & parent delegation:
      expected_ns: [
        "a.iana-servers.net",
      ],
      secondary_ns: [
        "b.iana-servers.net",
      ],
      verify_ns_health: true,
      // Config accepts both expected_registrar_id and expected_registrar_name:
      // Priority 1: expected_registrar_id (takes precedence; mutually exclusive in evaluation)
      // Priority 2: expected_registrar_name (evaluated only if expected_registrar_id is omitted)
      // expected_registrar_id: "376",          // IANA Registrar ID (e.g. 292 for MarkMonitor, 146 for GoDaddy)
      // expected_registrar_name: "markmonitor", // Fallback for ccTLDs without IANA ID (Priority 2)
      domain_transfer_locked: true,           // Verifies transfer lock is enabled in EPP status
      check_email_security: false,
      monitor_ct_logs: true,
      dnssec: true,
      caa: {
        issue: ["letsencrypt.org", "digicert.com"],
        // issuewild and issuemail omitted = only validate issue records
      },
      suppress_alerts: true
    },
    {
      domain: "api.example.com",
      name: "Example API Zone",
      is_delegated_zone: true,
      root_zone: "example.com",
      expected_ns: ["ns1.example.net", "ns2.example.net"],
      check_email_security: false,
      dnssec: true,
      caa: { issue: ["letsencrypt.org"] },
      suppress_alerts: true
    },
    { 
      domain: "example.net", 
      name: "Example Net Main", 
      expected_ns: ["a.iana-servers.net"],
      secondary_ns: ["b.iana-servers.net"],
      verify_ns_health: true,
      check_email_security: true,
      mail_provider: "google",
      monitor_ct_logs: true,
      dnssec: true,
      caa: {
        issue: ["digicert.com", "letsencrypt.org"],
        issuewild: ["digicert.com", "letsencrypt.org"]
      },
      suppress_alerts: true
    },
    { 
      domain: "example.org", 
      name: "Example Org Main", 
      expected_ns: ["a.iana-servers.net", "b.iana-servers.net"],
      check_email_security: true,
      mx_records: ["mail.example.org"],
      dkim_selectors: ["default"],
      monitor_ct_logs: true,
      dnssec: true,
      caa: {
        issue: ["letsencrypt.org"]
      },
      suppress_alerts: true
    },
    { 
      domain: "example.edu", 
      name: "Example Edu Fallback", 
      expected_ns: ["a.iana-servers.net", "b.iana-servers.net"],
      check_email_security: false,
      dnssec: false,
      suppress_alerts: true
    }
  ],

  dns_records: [
    { hostname: "example.com", name: "Example A", type: A, expected: ["93.184.215.14"] },
    { hostname: "example.com", name: "Example AAAA", type: AAAA, expected: ["2606:2800:21f:cb07:6820:80da:af6b:8b2c"] },
    { hostname: "www.example.com", name: "Example WWW", type: A, expected: ["93.184.215.14"] },
    { hostname: "example.net", name: "Example Net A", type: A, expected: ["93.184.215.14"] },
    { hostname: "example.net", name: "Example Net MX", type: MX, expected: ["smtp.example.net"] },
    { hostname: "example.net", name: "Example Net TXT", type: TXT, expected: ["v=spf1 include:_spf.example.net ~all"] },
    { hostname: "www.example.net", name: "Example Net WWW", type: A, expected: ["93.184.215.14"] },
    { hostname: "api.example.com", name: "Example API", type: A, expected: ["93.184.215.14"], skip_ssl: true }
  ]
}
