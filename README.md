# favicon-internet-scanner

A scanner for Internet-wide favicon measurements. It takes a seeded random sample of IPv4 addresses and, for each address that answers on a web port, collects what the host says about itself and fetches its favicon. It stops there: no matching and no verdicts.

> **Running it against the Internet needs the approvals your institution requires.** This repository does not grant any. The program refuses to send anything without an approval file that matches its config.

## What it does

```
ZMap          which sampled addresses answer on the web ports (80, 443, 8080, 8090, 8443 by default)
  -> ZGrab2   TLS handshake first; plain HTTP only where TLS is not spoken
  -> ZDNS     reverse DNS (PTR) and certificate names (SAN/CN), checked with forward lookups
  -> ZGrab2   SNI confirmation for names that verified
  -> favicons fetched over HTTP and HTTPS, from the scanned address only
```

Each result row says how a hostname was established (`final_hostname_status`: verified, resolved elsewhere, and so on). A name on a certificate does not prove the site is on that IP.

Built-in safeguards: identifiable traffic (contact and information page in the user agent), an exclusion list, a rate cap, a pause between requests to one address (15 s minimum), a kill switch, a pilot-first rule for larger samples, and no further probing of suspected tarpits.

## Before you run it

Do these first; the scanner enforces some of them and cannot check the rest.

1. **Get approval** from your institution (network or security team, and ethics or data protection where required). Record the reference and the expiry date.
2. **Use an address your institution owns** and has approved. Do not scan from a VPN or a rented address.
3. **Publish an information page** that says what the scan is, which ports and tools it uses, the contact, and how to opt out. Monitor the contact address for the whole run.
4. **Get an exclusion list** from the network owner, and add every opt-out you receive.
5. **Start with a pilot** (the default is about 3,700 targets per port). Larger samples are refused until a completed pilot exists.
6. Decide where the output lives and when it is deleted. IP addresses, host names and certificate names are personal data.

## Ways to run it

| | Docker | Native |
|---|---|---|
| Host | Linux x86-64 (or Windows with Docker Desktop and Git Bash) with Docker 24+ | Ubuntu 24.04 or Debian 13 (including WSL2), Python 3.11+, root once for the installer |
| Install | `bash run/scanner --docker build` | `sudo bash run/setup-wsl.sh` |
| Tools | Pinned inside the image | Pinned by the installer, built on the host |
| Privileges | Your user, only the raw-socket capability | `setcap` on ZMap, the pipeline runs unprivileged |

Both run the same Python program. Without any Internet traffic you can always run the offline test suite (`verify`).

## Quick start

On Windows run these in Git Bash, or use `run\scanner.cmd` in place of `bash run/scanner`. On Windows the Docker network is the Docker Desktop VM's, so run the `doctor` check and look at its egress lines before a real run.

```bash
git clone https://github.com/Deckris/favicon-internet-scanner.git scanner && cd scanner
S="bash $PWD/run/scanner"

$S help                                # all commands
$S --docker build                      # or: sudo bash run/setup-wsl.sh
$S --docker verify                     # offline tests, sends nothing (drop --docker for native)

E="$S --docker --workdir $HOME/scanner-work"      # the work folder: settings, exclusions, output
$E init --contact scan-optout@example.org --info-url https://example.org/scan \
        --egress-ip <public address of the scanner> --interface <nic> --resolver <resolver> \
        --exclusions <list from the network owner>
# edit ~/scanner-work/settings.yaml, set approval.status to approved when you really have approval
$E doctor                              # checks the host, the address, the tools and the approval
$E plan                                # shows the plan and a confirmation token; sends nothing
$E run --confirm <TOKEN>               # sends traffic; run it inside tmux or screen
```

The full walk-through, including opt-outs, stopping a run and packing results, is in [`run/QUICKSTART.md`](run/QUICKSTART.md).

## Choosing how much of the Internet to scan

The share of the Internet is not a command-line argument. It is one line in the work folder's `settings.yaml`:

```yaml
scope:
  sample_fraction: 0.000001    # share of routable IPv4 addresses to scan
approval:
  max_sample_fraction: 0.000001   # the most your approval allows
```

`sample_fraction` is a fraction, not a percentage. There are about 3.7 billion routable IPv4 addresses, and every port is scanned on the same sample:

| `sample_fraction` | Share of the Internet | Targets per port |
|---|---|---|
| `0.000001` (default) | 0.0001% | about 3,700 (the pilot) |
| `0.00001` | 0.001% | about 37,000 |
| `0.0001` | 0.01% | about 370,000 |
| `0.001` | 0.1% | about 3.7 million |

- `approval.max_sample_fraction` is copied from your real approval. A `sample_fraction` above it is rejected by `apply`, and so by `doctor`, `plan` and `run`.
- A sample larger than a pilot is refused until a completed pilot exists in the output folder (`--skip-pilot-check` overrides this on purpose).
- `seed` picks which addresses are in the sample. The same seed and fraction give the same addresses.
- `plan` prints the fraction, the number of targets per port and the ZMap time estimate before it gives you the confirmation token. Nothing is sent until you run with that token.

[`run/settings.example.yaml`](run/settings.example.yaml) is a copy of the file `init` writes, with every setting and its comment.

## Ports that are scanned

By default five TCP ports are scanned, all on the same sample of addresses:

| Port | Usually |
|---|---|
| 80 | HTTP |
| 443 | HTTPS |
| 8080 | alternative HTTP |
| 8090 | alternative HTTP |
| 8443 | alternative HTTPS |

ZMap sends one SYN to each sampled address on each port. Only addresses that answer are contacted further: a TLS handshake (or a plain HTTP request where TLS is not spoken), then the page and its favicon on that address and port.

To change the list, edit `scope.ports` in `settings.yaml` (for example `ports: [80, 443]`). The list goes into the generated approval, so make sure your approval covers the ports you scan. If you change it, also change the port line in [`INFO.md`](INFO.md), because network owners read that page to learn what touched their servers.

## Repository layout

| Path | What is in it |
|---|---|
| `run/` | The launcher `scanner`, the Dockerfile, the native installer `setup-wsl.sh`, `QUICKSTART.md` and example config files |
| `scanner/internet/` | The pipeline, the command-line program, settings handling, pacing and preflight checks |
| `scanner/` | Shared code: ZMap/ZGrab2/ZDNS wrappers, safe web fetching, certificate parsing, target safety policy |
| `pipeline/` | Approval-file loading and favicon hashing |
| `tests/` | The offline test suite; it uses loopback servers and fake tools and sends nothing |

You edit one file, `settings.yaml`, in your work folder. `config.yaml` and `approval.yaml` are generated from it and overwritten on every run.

## Output

Each run writes a folder under `runs/` in the work folder: `manifest.json` (settings, checksums, whether the run completed), `report/summary.md`, per-address results (`ip_results.csv`, `normalized/`), any stored favicons, and the raw tool output. `pack` makes an archive of the manifest and report only; per-address files and raw output are added only on request.

## Limits

- Tested offline and on loopback; it has not been run from an institutional scanner host.
- IPv4 only.
- ZMap 4.4.0 divides the target count across shards, so sharding is refused.
- Results describe one vantage point at one time.

Licensed under the MIT License (see `LICENSE`). Security reports: see `SECURITY.md`.
