# scanner: how to run it

scanner takes a seeded random sample of IPv4 addresses, finds responsive web ports with ZMap, characterises each endpoint with ZGrab2 (TLS first), collects hostname evidence (reverse DNS and certificate names), verifies it with ZDNS, and fetches favicons over HTTP and HTTPS. It stops there: no matching, no brand logic, no verdicts.

**This package does not authorize any measurement.** Running it against the Internet needs the approvals your institution requires. The program refuses to start without a machine-readable approval file that matches the config exactly. Read `run/PRE-RUN-CHECKLIST.md` first and complete it before the first run.

## 1. Choose how to run it

| | Docker | Native |
|---|---|---|
| Needs | Docker 24+ on Linux x86-64 | Ubuntu 24.04 / Debian 13, root once for the installer, Python 3.11+ |
| Tool versions | Pinned inside the image, identical for everyone | Pinned by the installer, built on the host |
| Network | `--network host`: no extra hop, no NAT, no bandwidth cost | Direct |
| Privileges | Container runs as your user, all capabilities dropped except raw sockets | `setcap` on the ZMap binary, pipeline runs unprivileged |
| Pick it when | Reproducibility matters, or the host should stay clean | Docker is not allowed on the scanner |

Both run the same Python program and give the same results.

## 2. Get the code

```bash
git clone https://github.com/Deckris/favicon-internet-scanner.git scanner && cd scanner
git rev-parse HEAD      # note the commit you are running
```

## 3. Install

```bash
bash run/scanner --docker build        # Docker: builds scanner:1 from this exact package (downloads sources once)
# or
sudo bash run/setup-wsl.sh          # Native
```

Then run the offline tests. They send nothing:

```bash
bash run/scanner --docker --workdir ~/scanner-work verify
```

## 4. Prepare a work directory

```bash
E="bash ~/scanner/internet/scanner --docker --workdir $HOME/scanner-work"    # drop --docker for native
mkdir -p ~/scanner-work
$E init --contact scan-optout@example.org --info-url https://example.org/scan         --egress-ip <public address of the scanner> --interface <nic> --resolver <resolver>         --exclusions <list from the network owner>
```

`init` writes `~/scanner-work/settings.yaml`. That is the one file to edit: the opt-out contact, the information page, the scanner's address, the exclusion list, ports, sample size, rate, the pause between probes to one address (default 15 s), and the approval details (reference, expiry, caps, data handling). Replace every `REPLACE_ME`. Keep `approval.status: blocked` until the approving authority has signed off, then set `approved`. The program makes `config.yaml` and `approval.yaml` from it before each `doctor`, `plan` and `run`; do not edit those two. `$E apply` shows what is still missing.

Defaults start conservative: 100 packets per second, a pilot-size sample, no off-host icon fetching. The scanner never checks for a VPN. With the address on the host's own network card it compares the card's address with the approved one and asks no outside service; behind NAT, set `host.source_ip` and it asks a public-IP service once.

To honour an opt-out: `$E exclusions --add 203.0.113.0/24` (or `--from-file FILE`), then `plan` again for the new token.

Help: `$E help` lists the commands, `$E help run` explains one.

## 5. Run

```bash
$E doctor                       # checks the host, the egress address and the DNS resolver
$E plan                         # prints the plan and a confirmation token; nothing is sent
$E run --confirm <TOKEN>        # run inside tmux or screen; sends traffic
$E stop                         # from another terminal: stops within about a second
$E summary runs/<run-dir>
$E favicons --source-run runs/<run-dir>     # optional: repeat image lookups and keep the images
$E pack runs/<run-dir>          # results archive plus SHA256SUMS, raw tool output left out
```

`run` refuses a second run of an identical config; `--allow-rerun` overrides that on purpose. A finished run has `manifest.json` with `"complete": true`. Anything else is partial and says why.

## 6. Does Docker cost bandwidth?

Not with `--network host`, which the script always uses. The container shares the host's network stack, so packets leave the same interface, the same way as a native run. There is no bridge, no NAT and no extra hop. Default Docker networking would be wrong for this tool, because ZMap sends raw frames and needs the real interface and gateway. The script therefore never uses it. The cost left is a negligible start-up time.

If you want to see it on your host, run `doctor`, then compare ZMap's reported send rate for a small approved sample natively and in Docker.

## 7. What the program enforces

- Approval file matched to the config: ports, rate, sample size, source address, operations, expiry.
- Confirmation token tied to the exact plan.
- Public egress address checked before and during the run; a change stops it.
- Kill-switch file, disk-space guard, approval-expiry guard.
- Fetches stay on IP and port pairs that answered the scan; redirects and icon URLs elsewhere are refused.
- Run-once guard, and every run writes a manifest with checksums and its limits.

## 8. Responsible use

- **Identifiable traffic.** Publish an information page and a monitored contact, set reverse DNS on the scanner address, and put the contact in the user agent. A run without a contact and information page is refused.
- **Scale in steps.** A sample above about 3,700 targets per port is refused until a completed pilot at or below that size exists in the output directory (`--skip-pilot-check` overrides it on purpose). Review each pilot's manifest and report before going larger.
- **Exclusions and opt-outs.** Use the list the network owner gives you. When someone opts out, add their range to the list, recompute its checksum, update the config and approval, and use the new files from the next run on.
- **Minimal requests.** GET of the page and its icon, bounded sizes and time, no credentials, forms or exploits. The scanner never contacts the owners of what it finds.
- **Data.** Raw output and IP lists stay on the scanner host. `pack` leaves raw output out. Treat IPs, names and certificates as personal data, set a retention date, and publish only reviewed aggregates.
- **Source address.** Scan from an address your institution owns and has approved, not from a VPN or a rented address.

## 9. Known limits

- Validated offline and with short live pilots from a laptop behind a VPN. A 0.01% sample (370,225 targets per port) ran to completion once. It has not been run from a university scanner.
- ZMap 4.4.0 divides the target count across shards, so the `shards` setting is not supported in this release. Run unsharded.
- Results describe one vantage point at one time. A name on a certificate does not prove the site is on that IP; use the `final_hostname_status` column.
