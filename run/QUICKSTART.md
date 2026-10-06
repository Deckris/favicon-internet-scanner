# How to run the scanner

The scanner takes a seeded random sample of IPv4 addresses, finds responsive web ports with ZMap, characterises each endpoint with ZGrab2 (TLS first), collects hostname evidence (reverse DNS and certificate names), verifies it with ZDNS, and fetches favicons over HTTP and HTTPS. It stops there: no matching and no verdicts.

**This package does not authorize any measurement.** Running it against the Internet needs the approvals your institution requires. The program refuses to run without a machine-readable approval file that matches the config exactly.

## 1. Choose how to run it

| | Docker | Native |
|---|---|---|
| Needs | Docker 24+ on a Linux x86-64 host | Ubuntu 24.04 / Debian 13, root once for the installer, Python 3.11+ |
| Tool versions | Pinned inside the image | Pinned by the installer, built on the host |
| Network | `--network host` | Direct |
| Privileges | Runs as your user, all capabilities dropped except raw sockets | `setcap` on the ZMap binary, the pipeline runs unprivileged |

Both run the same Python program. Docker mode expects the work folder to be owned by you on a Linux filesystem; a folder mounted from Windows is not supported.

## 2. Get the code and install

```bash
git clone https://github.com/Deckris/favicon-internet-scanner.git scanner && cd scanner
S="bash $PWD/run/scanner"

$S --docker build          # Docker: builds the image scanner:1 from this checkout (downloads sources once)
# or
sudo bash run/setup-wsl.sh # Native
```

Then run the offline tests. They send nothing:

```bash
$S --docker verify         # drop --docker for native
```

## 3. Prepare a work folder

The work folder holds your settings, the exclusion list and the output. It is created if it does not exist.

```bash
E="$S --docker --workdir $HOME/scanner-work"       # drop --docker for native
$E init --contact scan-optout@example.org --info-url https://example.org/scan \
        --egress-ip <public address of the scanner> --interface <nic> --resolver <resolver> \
        --exclusions <list from the network owner>
```

`init` writes `settings.yaml` in the work folder. That is the one file to edit: the opt-out contact, the information page, the scanner's address, the exclusion list, ports, sample size, rate, the pause between requests to one address (default and minimum 15 s), and the approval details (reference, expiry, caps, data handling). Replace every `REPLACE_ME`. `$E apply` lists what is still missing.

`config.yaml` and `approval.yaml` are generated from `settings.yaml` before each `doctor`, `plan` and `run`; do not edit them, changes are overwritten.

The approval status starts as `blocked`. While it is `blocked`, `doctor`, `plan` and `run` refuse to start. Set `approved` only when the approving authority has signed off. The default values are conservative: 100 packets per second, a pilot-size sample, no off-host icon fetching.

If the address is on the host's own network card, the scanner compares the card's address with the approved one and asks no outside service. Behind NAT, set `host.source_ip`; the scanner then asks a public-IP service once. It does not look for a VPN.

To honour an opt-out: `$E exclusions --add 203.0.113.0/24` (or `--from-file FILE`), then `plan` again for a new token. The scanner is IPv4-only; IPv6 lines in an exclusion list are kept in the file and ignored.

Help: `$E help` lists the commands, `$E help run` explains one.

## 4. Run

```bash
$E doctor                       # checks the host, the egress address and the DNS resolver
$E plan                         # prints the plan and a confirmation token; nothing is sent
$E run --confirm <TOKEN>        # run inside tmux or screen; sends traffic
$E stop                         # from another terminal
$E summary runs/<run-dir>
$E favicons --source-run runs/<run-dir>     # optional: repeat image lookups and keep the images
$E pack runs/<run-dir>          # archive of the manifest and report
```

`run` refuses a second run of an identical config; `--allow-rerun` overrides that on purpose. A finished run has `manifest.json` with `"complete": true`; anything else is partial and says why.

`pack` puts only `manifest.json` and the aggregate report in the archive. `pack RUN_DIR --with-results` adds the per-address files (IP addresses, host names, certificate names); `--with-raw` adds the raw tool output as well.

## 5. What the program enforces

- The approval file must match the config: ports, rate, sample size, source address, operations, expiry, exclusion list checksum and the pause between requests to one address.
- The confirmation token is tied to the exact plan.
- The public egress address is checked before and during the run; a change stops it.
- A kill-switch file, a disk-space guard and an approval-expiry guard.
- Favicon fetches stay on the IP and port pairs that answered the scan; redirects and icon URLs elsewhere are refused.
- ZMap runs one port at a time, with the configured pause between port runs.
- A second run of an identical config is refused, and every run writes a manifest with checksums and its limits.

## 6. Responsible use

- **Identifiable traffic.** Publish an information page and a monitored contact, set reverse DNS on the scanner address, and put the contact in the user agent. A run without a contact and information page is refused.
- **Scale in steps.** A larger sample is refused until a completed pilot of about 3,700 targets per port or fewer exists in the output folder (`--skip-pilot-check` overrides it on purpose). Review each pilot's manifest and report before going larger.
- **Exclusions and opt-outs.** Use the list the network owner gives you. When someone opts out, add their range with `exclusions --add`.
- **Minimal requests.** GET of the page and its icon, bounded sizes and time, no credentials, forms or exploits.
- **Data.** Raw output and IP lists stay on the scanner host. Treat IP addresses, names and certificates as personal data, set a retention date, and publish only reviewed aggregates.
- **Source address.** Scan from an address your institution owns and has approved.

## 7. Known limits

- It has been tested offline (the test suite and loopback fixtures) and has not been run from an institutional scanner host.
- ZMap 4.4.0 divides the target count across shards, so sharding is refused for it.
- Results describe one vantage point at one time. A name on a certificate does not prove the site is on that IP; use the `final_hostname_status` column.
