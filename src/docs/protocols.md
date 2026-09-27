# Protocol scope

This daemon monitors domain configuration and published evidence. The RFCs below
define the protocols; matching rules, expiry thresholds and alert policy are
monitoring choices. These checks do not imply complete implementation of each RFC.

| Protocol | Standards | What the monitor checks and its limits |
| --- | --- | --- |
| DNS | [1034](https://www.rfc-editor.org/rfc/rfc1034.html), [1035](https://www.rfc-editor.org/rfc/rfc1035.html), [2308](https://www.rfc-editor.org/rfc/rfc2308.html), [5452](https://www.rfc-editor.org/rfc/rfc5452.html), [7766](https://www.rfc-editor.org/rfc/rfc7766.html) | A/AAAA/CNAME/MX/TXT/NS records, delegation, question/owner/class checks, negative responses and UDP-to-TCP fallback. `IP`, `ALIAS` and matching strategies are project rules. Successful resolver responses are not compared for consensus. |
| DNSSEC | [4033](https://www.rfc-editor.org/rfc/rfc4033.html), [4034](https://www.rfc-editor.org/rfc/rfc4034.html), [4035](https://www.rfc-editor.org/rfc/rfc4035.html), [6840](https://www.rfc-editor.org/rfc/rfc6840.html) | Local DS/DNSKEY linkage and DNSKEY RRSIG verification, corroborated by an authenticated matching answer from a trusted [JSON DoH validator](https://developers.google.com/speed/public-dns/docs/doh/json). No independent root-to-zone validator. The JSON API is separate from wire-format DoH in [8484](https://www.rfc-editor.org/rfc/rfc8484.html). |
| RDAP | [9224](https://www.rfc-editor.org/rfc/rfc9224.html), [9082](https://www.rfc-editor.org/rfc/rfc9082.html), [9083](https://www.rfc-editor.org/rfc/rfc9083.html), [7480](https://www.rfc-editor.org/rfc/rfc7480.html) | Bootstrap discovery, bounded HTTP/JSON, domain identity, expiry, registrar, nameservers and registration status. Selected registrar referrals supplement registry evidence; provider exceptions and grace-period interpretation are project heuristics. |
| EPP status evidence | [5730](https://www.rfc-editor.org/rfc/rfc5730.html) (replaces 4930), [5731 §2.3](https://www.rfc-editor.org/rfc/rfc5731.html#section-2.3), [3915](https://www.rfc-editor.org/rfc/rfc3915.html) | Typed domain and redemption lifecycle decisions from RDAP/WHOIS; unknown extensions remain visible. No EPP sessions, provisioning commands or numeric command-result processing. |
| WHOIS | [3912](https://www.rfc-editor.org/rfc/rfc3912.html) | Bounded port-43 transport, referrals and best-effort RDAP fallback. Registry text fields are not standardized; transport failure is not proof of an unregistered domain. |

| MX | [5321 §5](https://www.rfc-editor.org/rfc/rfc5321.html#section-5), [7505](https://www.rfc-editor.org/rfc/rfc7505.html) | Published exchanges against explicit values or provider presets. Null MX must be the sole exchange with preference zero. Requires published MX; no SMTP delivery or implicit-routing evaluation. |
| SPF | [7208](https://www.rfc-editor.org/rfc/rfc7208.html) | Detect missing or multiple SPF records. Publication check only: no recursive include/redirect analysis, sender-IP evaluation or complete syntax validation. |
| DKIM | [6376](https://www.rfc-editor.org/rfc/rfc6376.html), [8463](https://www.rfc-editor.org/rfc/rfc8463.html) | Query configured/preset selectors and check supported RSA/Ed25519 key material and basic tags. Selectors permit rotation; at least one usable key is required, while transient lookup failures remain visible. No message signature verification or complete optional-tag validation. |
| DMARC | [9989](https://www.rfc-editor.org/rfc/rfc9989.html) | Bounded eight-query policy discovery and supported policy-tag validation. Malformed child policy or transient lookup failure cannot silently inherit healthy parent evidence. No message alignment, receiver policy application or reporting. |


## Assurance checklist

The claim is **no known critical/high defects in the supported scope**, not a
bug-free guarantee. Apply all six gates to the same release commit:

1. Scope: RFC contracts and explicit limits are the table above.
2. Defects: fix false-healthy, state-loss, secret-disclosure and missed-alert findings with regressions; assess remaining defects before release.
3. Offline: valid/invalid/transient/stateful outcomes, race tests, vet, pinned lint, formatting and the 83% coverage floor pass.
4. End to end: fixtures verify evaluation, API JSON, alert identity/priority, write failures, cancellation, panics and recovery.
5. Interoperability: opt-in live tests plus independent DNS/RDAP/WHOIS observations agree for representative cases.
6. Soak/review: `TestDaemonSixCyclesRestartWriteFailureAndRateLimit` checks six cycles across restart; inspect outstanding defects and repeat affected evidence on the release commit.
