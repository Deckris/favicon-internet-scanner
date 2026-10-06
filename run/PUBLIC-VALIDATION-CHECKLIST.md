# Public validation shortlist (planned, not executed)

These are 20 named test endpoints published on the [badssl operator dashboard](https://badssl.com/), consulted 2026-10-05. They are suggestions for an approved validation plan, not discovered scan targets or authorization. Endpoint availability, exact ports, DNS/IP mappings and operator permission must be established within that approval before execution. No endpoint below was probed by this work.

| # | Published endpoint | Intended edge case and expected observation |
|---|---|---|
| 1 | sha256.badssl.com | Ordinary TLS certificate baseline; capture evidence and test hostname mapping. |
| 2 | expired.badssl.com | Expired certificate; record it without confusing expiry with missing HTTP service. |
| 3 | wrong.host.badssl.com | Certificate name mismatch; never label mismatched SNI as confirmed. |
| 4 | self-signed.badssl.com | Self-signed certificate; inventory may continue while trust remains unestablished. |
| 5 | untrusted-root.badssl.com | Unknown issuer; keep certificate evidence separate from trust. |
| 6 | revoked.badssl.com | Revocation case; scanner does not check revocation and must not imply that it does. |
| 7 | incomplete-chain.badssl.com | Incomplete chain; distinguish capture from trust-chain validation. |
| 8 | no-common-name.badssl.com | Missing CN; SAN parsing must still work. |
| 9 | no-subject.badssl.com | Missing subject; certificate parser must not crash. |
| 10 | 1000-sans.badssl.com | Large SAN list; bound candidate queries and report truncation. |
| 11 | 10000-sans.badssl.com | Very large SAN list; bounded processing, memory and output. |
| 12 | ecc256.badssl.com | ECDSA certificate with 256-bit key; capture or explicit compatibility outcome. |
| 13 | ecc384.badssl.com | ECDSA certificate with 384-bit key; capture or explicit compatibility outcome. |
| 14 | rsa8192.badssl.com | Large RSA key; bounded handshake duration. |
| 15 | client-cert-missing.badssl.com | Client certificate required; classify handshake failure, submit no credentials. |
| 16 | tls-v1-0.badssl.com | Legacy TLS 1.0; exact port requires operator documentation; unsupported is a valid result. |
| 17 | tls-v1-1.badssl.com | Legacy TLS 1.1; exact port requires operator documentation; unsupported is a valid result. |
| 18 | tls-v1-2.badssl.com | TLS 1.2 control; exact port requires operator documentation. |
| 19 | http.badssl.com | Plain HTTP; TLS-first failure must allow the HTTP fallback where appropriate. |
| 20 | mixed-favicon.badssl.com | HTTPS page with an HTTP icon; respect approved destination/port and record refusals. |

The dashboard labels define the proposed cases, not measured behavior. These names may share servers/IPs and belong to one operator. Twenty endpoints are not twenty independent hosting environments.

Complement them with approved institution-owned/consenting systems for strict SNI, shared virtual hosts, CDN names absent from the default certificate, HTTP on nonstandard ports, non-HTTP TLS, PTR-only names, DNS mismatches, absent PTR, CNAME loops, redirects, HTTP 429, slow headers, malformed images and tarpits. The isolated lab covers reproducible versions of many of these without public traffic.

## Claims boundary

Passing this checklist shows behavior on selected edge cases. It cannot support a claim of working on 99% of Internet hosts. A defensible population estimate needs a defined population, independent representative sample, frozen instrument, authorization, observation window, exclusions, manifest/checksums and uncertainty analysis. Hostname recovery and favicon acquisition are separate outcomes; an IP cannot reveal every virtual host on it. Even 20 independent representative successes would have a one-sided 95% binomial lower bound of only about 86.1%; these deliberately selected, correlated endpoints do not satisfy that sampling model.

## Per-endpoint evidence after approval

Record run/config/tool checksums, exact IP/hostname/port, timestamp and vantage, operator permission reference, origin of any supplied hostname, bare-IP TLS evidence, PTR/forward mapping, SNI match or mismatch, HTTP outcome, image decoding outcome, policy refusals and elapsed time. Operator-supplied names must not be counted as names discovered from IPs.
