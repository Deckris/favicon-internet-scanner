# favicon-internet-scanner

A scanner for Internet-wide favicon measurements. It takes a seeded random sample of IPv4 addresses, finds responsive web ports with ZMap, characterises each endpoint with ZGrab2 (TLS first), collects hostname evidence (reverse DNS and certificate names), verifies it with ZDNS, and fetches the favicons over HTTP and HTTPS. It stops there: no matching, no verdicts.

It is built to be run responsibly: identifiable traffic, an exclusion list, a pause between requests to one address (15 s by default), a rate cap, a machine-readable approval file that must match the config, a kill switch, and a pilot-first rule for larger samples.

**Running it against the Internet needs the approvals your institution requires.** This repository does not grant any.

Start with [`run/QUICKSTART.md`](run/QUICKSTART.md).

```bash
bash run/scanner help                 # commands
bash run/scanner --docker build       # Docker image with pinned ZMap, ZGrab2 and ZDNS
bash run/scanner --docker verify      # offline tests, sends nothing
```

Layout: `scanner/internet/` pipeline and CLI, `scanner/` shared fetching and safety code, `run/` launcher, Dockerfile, installer, example config and docs, `tests/` offline test suite.

Licensed under the MIT License (see `LICENSE`). Security reports: see `SECURITY.md`.
