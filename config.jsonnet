local default_ns = ["ns1.example.com", "ns2.example.com"];
local A = "A";
local TUNNEL = "TUNNEL";

{
  port: "8080",
  loop_interval: "6h",
  request_delay: "5s",

  notifications: {
    ntfy: { url: "https://ntfy.sh/my_secret_topic", auth: "" },
    telegram: { token: "YOUR_BOT_TOKEN_HERE", chat_id: "YOUR_CHAT_ID_HERE" }
  },

  providers: {
    cloudflare_token: "YOUR_CLOUDFLARE_TOKEN_HERE", 
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
