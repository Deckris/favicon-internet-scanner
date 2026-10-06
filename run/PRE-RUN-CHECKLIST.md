# scanner pre-run checklist

Complete this before the first packet is sent, and again before any larger sample. Keep the signed copy with the run's manifest. The program enforces some of these points (marked **enforced**); the rest are decisions for people.

Operational controls follow the practice described in R. M. Yaben Lopezosa, *Identifying systemic cyber-security weaknesses in Internet-facing OT and consumer IoT networks* (DTU, 2026): identifiable and minimal traffic, an honoured opt-out list, bounded rates, coordination with the network owner, and restricted raw data.

## 1. Authorization

- [ ] The approving authority and the approval date are recorded, with a reference to the written approval. ______
- [ ] The institution's network or security team has approved the scan from this host and address. ______
- [ ] Ethics or data-protection review is complete, or a written statement says none is needed. ______
- [ ] The owner of the source address agrees to scanning from it (university network, not a VPN or rented address). ______
- [ ] The approval file matches the config: ports, rate, sample size, source address, operations and expiry. **enforced**

## 2. Identification

- [ ] An information page is live and states the purpose, ports and protocols, tools, the contact and how to opt out. URL: ______
- [ ] The contact address is monitored for the whole run by a named person. Name: ______
- [ ] The scanner's address has reverse DNS that points to the information page or the institution.
- [ ] The user agent carries the contact or the page URL. **enforced** A run without a contact and information page is refused.

## 3. Scope and exclusions

- [ ] The exclusion list comes from the network owner and covers government and military ranges, CERT/CSIRT and security-team ranges, network telescopes and research honeypots, and earlier opt-outs.
- [ ] The list's SHA-256 is in both the config and the approval. **enforced**
- [ ] Reserved and private IPv4 space is excluded. **enforced**
- [ ] Only the approved ports and protocols are used. **enforced**
- [ ] Off-host icon fetching stays off unless the approval names it. **enforced** The default is off.
- [ ] Requests are limited to GET of the page and its icon. The scanner sends no credentials, forms or exploits, and does not contact owners.

## 4. Rate, size and timing

- [ ] The rate is at or below the approved rate, and the first run uses the lowest rate that works. **enforced** up to the approved rate
- [ ] A completed pilot of about 3,700 targets per port or fewer exists and its manifest and report were reviewed. **enforced**
- [ ] The run window was announced to the network team. Window: ______
- [ ] The person who can stop the run is named and knows `scanner stop`. Name: ______
- [ ] The egress address guard, kill-switch file and disk guard are active. **enforced**

## 5. Data

- [ ] Raw tool output, certificates and IP lists stay on the scanner host, outside Git, with an access list. Who: ______
- [ ] A retention period and deletion date are set. Delete by: ______
- [ ] Results leave the host only as `scanner pack` archives without raw output, or as reviewed aggregates.
- [ ] IP addresses, hostnames and certificate names are treated as personal data. No IP lists in papers, repositories or slides.

## 6. After the run

- [ ] The manifest says `"complete": true`. If not, the output is reported as partial.
- [ ] Opt-out and abuse messages were answered, the sender's range was added to the exclusion list, and the new checksum is used from the next run on.
- [ ] A short log lists any complaint, any incident and any change made during the run.
- [ ] The manifest, report and checksums are archived with this checklist.

Signed: ______________________   Date: ______________
