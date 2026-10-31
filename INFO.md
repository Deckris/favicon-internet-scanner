# About this scan

If you are reading this, a connection to one of your servers probably carried a user agent that points here.

## What this is

A small research measurement of how web servers on the public Internet identify themselves and which favicon they serve. It is part of an academic Internet measurement project. The software is open source: https://github.com/Deckris/favicon-internet-scanner

## What it sends

For a seeded random sample of IPv4 addresses, visited in random order (a campaign repeats this over successive samples until the whole address space is covered), the scan sends at most 130,000 packets per second overall during the SYN sweeps, and waits at least 5 seconds between any two requests to one address, across ports and stages:

1. One TCP SYN to ports 80, 443, 8080, 8090 and 8443.
2. If a port answers: a TLS handshake (or a plain HTTP request where TLS is not spoken), then up to a few `GET /` and favicon requests with a user agent that names this page and the contact below.
3. DNS lookups through the recursive resolver of the network the scan runs from (not a third-party public resolver) for the host name found in the certificate or reverse DNS.

It sends no credentials, forms, exploits or guesses at paths beyond the page and its favicon. It does not contact the owners of what it finds and does not try to access anything that requires a login.

## Opt out

Either of these works:

- Write to the e-mail address in the `User-Agent` header of the requests you received (`contact ...`), with the address or range (CIDR) you want left out.
- Open an issue at https://github.com/Deckris/favicon-internet-scanner/issues titled "scan opt-out" that names the address or range. Please do not add personal details.

The range is added to the exclusion list and not contacted again. Abuse and incident reports go to the same places.

## Data

Results are kept on the researcher's machine, treated as personal data, and published only as reviewed aggregates.
