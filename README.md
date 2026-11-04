# favicon-internet-scanner

A scanner for Internet-wide favicon measurements. It takes a seeded random sample of IPv4 addresses and, for each address that answers on a web port, collects what the host says about itself and fetches its favicon. It stops there: no matching and no verdicts.

> **Running it against the Internet needs the approvals your institution requires.** This repository does not grant any. The program refuses to send anything without an approval file that matches its config.

## If this scanner contacted your network

The traffic is a research measurement of which favicons web servers serve. Each address receives one SYN per web port; an address that answers receives a TLS handshake or a plain HTTP request, a second handshake under a hostname from its certificate when that name resolves to the address, and requests for its home page and its favicon, with at least 5 s between any two requests to the same address. Nothing else is requested, no credentials are tried and no vulnerability is probed.

To have an address or range left out, write to the e-mail address in the user agent of the requests you saw, or open an issue in this repository with the address or CIDR range. The range is added to the exclusion list, which every sweep applies, and is not contacted again.

## What it does

```
ZMap          which sampled addresses answer on the web ports (80, 443, 8080, 8090, 8443 by default)
  -> ZGrab2   TLS handshake first; plain HTTP only where TLS is not spoken
  -> ZDNS     reverse DNS (PTR) and certificate names (SAN/CN), checked with forward lookups
  -> ZGrab2   SNI confirmation for names that verified
  -> favicons fetched over HTTP and HTTPS, from the scanned address only
```

Each result row says how a hostname was established (`final_hostname_status`: verified, resolved elsewhere, and so on). A name on a certificate does not prove the site is on that IP.

Built-in safeguards: identifiable traffic (contact and information page in the user agent), an exclusion list, a rate cap, a pause between requests to one address (at least 5 s between any two requests to one address, across ports and stages), a kill switch, a pilot-first rule for larger samples, and no further probing of suspected tarpits.

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

## Long campaigns

A full-Internet `campaign` runs for days on a small host. Run it inside tmux, in a systemd scope that caps memory, and start the watchdog beside it:

```bash
tmux new -s campaign
ulimit -n 65536
MALLOC_ARENA_MAX=2 systemd-run --scope -p MemoryHigh=2800M -p MemoryMax=3200M -p MemorySwapMax=1G \
  python -m scanner.internet campaign --config config.yaml --confirm <TOKEN>
```

In a second tmux window, give [`run/watchdog.sh`](run/watchdog.sh) the kill-switch file from `operations.kill_switch_file` and the files that should keep changing while the campaign works:

```bash
bash run/watchdog.sh -k <kill-switch file> -m 700 -s 30 -i 30 -l watchdog.log \
  -w 'campaign.log' -w 'runs/*/raw/favicon_records.jsonl' -p <campaign pid>
```

It touches the kill-switch file when `MemAvailable + SwapFree` drops below `-m` MiB, or when none of the `-w` paths (globs allowed) changed for `-s` minutes while no `zmap`, `zgrab2` or `zdns` is running. It writes a heartbeat line every few checks and exits when the kill switch exists or the campaign process is gone. The same file stops the campaign by hand: `bash run/scanner stop`, or `touch` it.

To stop between shards instead of mid-shard, create a file named `DRAIN` in the campaign directory (`<output dir>/campaign-<checksum prefix>/`): the shard in progress finishes, no further shard starts, and the command exits 0. Remove the file before resuming. A run that makes no progress for `operations.stall_minutes` (default 30, 0 = off) while no tool is running is aborted with `abort_reason: stalled`; `kill -USR1 <pid>` writes every thread's stack to `raw/stacks.txt` in the run directory.

Before it starts a shard, a campaign compares the free space on the output disk with `operations.min_free_gb_between_shards`. The default is twice the on-disk size of the largest finished shard plus 15 GB, or 20 GB before any shard has finished; a number in the config replaces it (GB are 2^30 bytes) and 0 turns the check off. If the space is not there, the shard does not start: the shards already running finish (with `--pipeline 2` as well), the message names the shortfall, and the command exits with code 6. Free space and run the same command again to resume. `operations.min_free_mib` still aborts a shard in progress as the last resort.

On a host with two CPUs the favicon stage (Python, hours per shard) leaves the network tools idle. `campaign --pipeline 2` runs each shard in its own process and starts the next shard's network stages while the previous shard is still in its favicon stage. Two lock files in the campaign directory keep the load per target unchanged: `phase-a.lock` is held from the start of a shard to the end of its network stages, so at most one ZMap sweep is on the wire and the packet rate never exceeds the approved rate; `phase-b.lock` is held from the start of the favicon stage to the end of the write-out, so at most one favicon stage runs at a time. Shards are disjoint slices of one seeded ZMap permutation (same seed, shard count and configuration, one sender thread), so two shards never contact the same address and the 5 s spacing per address holds across processes. For the same reason `--pipeline 2` is refused when `favicon.offhost_icons` is enabled, because an off-host fetch can reach an address in another shard's slice. At most two shards are in flight, the favicon stage runs at a lower priority, and the option is recorded in `campaign.json` and in each manifest. A kill switch, `DRAIN` or SIGTERM is passed on to both shards, a shard that fails stops further launches while the other one finishes, and resuming works as before. It needs POSIX file locks; elsewhere the shards run one after another.

The favicon stage can use several processes: `favicon.processes` (`scope.favicon_processes` in `settings.yaml`, default 1, at most 64) splits the favicon lookups by address into disjoint partitions, one worker process each. Every address belongs to one process, which has its own pacer, so the pause per address holds; the favicon workers and `max_active_requests` are divided between the processes (rounded down), so the total never exceeds the configured values. A process may only contact the endpoints of its own addresses, so a redirect to an address that another process owns is refused before any connection. The setting is refused above 1 when `favicon.offhost_icons` is enabled, and it cannot exceed `favicon.workers` or `favicon.max_active_requests`. Outputs are the same as with one process, except for those refused redirects.

For a plain-HTTP request to a bare address the favicon stage takes the page the HTTP stage already fetched instead of requesting it again (`favicon.reuse_http_document`, on by default). Pages that redirected, were compressed, were not 200 HTML or are close to the read limit are fetched as before, and HTTPS and name-based requests always fetch the page. Each row records `document_source` (`reused` or `fetched`) and, for a reused page, `direct_document_age_seconds`, counted from the time ZGrab2 made its request.

A stopped campaign is marked partial. To resume, delete the kill-switch file and run the same `campaign` command again with the same config and token; finished shards are kept and the rest are run. A shard that was interrupted is continued, not repeated: its next attempt reuses every ZMap port sweep, ZGrab2 batch and DNS batch the earlier attempt finished (recorded in `work/facts.sqlite` with the run identity and a hash of the batch's targets, and listed under `stage_counts.resume` in the manifest), runs the unit that was in flight again from scratch, and waits one full per-address pause before it contacts anything. `--no-resume` starts the shard from nothing instead. The campaign is identified by the checksum of the whole config, so any edit to the config (including `operations` or `output` settings) starts a new campaign instead of resuming; after a stop for disk space, free space and rerun the unchanged command.

### Several hosts, a second machine for the favicon stage, and an external disk

**Shard ranges.** `campaign --shards-from A --shards-to B` runs shards A up to, but not including, B (0-based; `--shards-from 50` alone runs 50 to the end). The configuration, its checksum, the confirmation token and the campaign directory name stay the same, so hosts that each take a disjoint range work on one campaign definition. The ranges must not overlap: each host keeps its own state file, and two hosts scanning the same shard would contact the same addresses twice. A range counts as complete when its own shards are.

**Network first, favicons elsewhere.** `campaign --stop-after-network` (or `run --stop-after-network`) ends each shard where the favicon stage would start. It writes the network-stage outputs and `normalized/http_documents.jsonl` as usual, keeps `work/facts.sqlite`, and records `network_done` in the manifest and in `campaign.json`. Such a shard is neither finished nor repeated by a later campaign. It does not combine with `--pipeline 2`. To run the favicon stage on a second machine:

1. `python -m scanner.internet export-network RUN_DIR OUT_DIR` copies the fact store, the stored pages, the tool job list, the manifest and the config snapshot, and writes `export_manifest.json` with a SHA-256 for each file.
2. Move `OUT_DIR` to the second machine and run `python -m scanner.internet favicon-stage OUT_DIR --config its-config.yaml --confirm TOKEN`. The config must match the campaign's apart from the vantage, output, operations and binaries sections and the locations of the exclusion and approval files; the second machine's source address has to be an approved one. The checksums are verified first, then the favicon lookups run (with `favicon.processes` as configured) without any network-stage traffic, and the shard is written out.
3. Back on the first machine, `python -m scanner.internet import-favicons RUN_DIR OUT_DIR` checks `raw/favicon_records.jsonl` and `favicons/` against the manifest of the second machine's run and copies them in (nothing is copied if one file fails), then `favicon-stage RUN_DIR --config config.yaml --confirm TOKEN` finishes the shard from the imported records. No request is sent, because every lookup is already recorded. `favicon-stage` on the original directory without the import runs the lookups from there. A favicon stage that is interrupted leaves the shard network-only and can be repeated. When `campaign.json` lists the shard, it is marked complete.

**Stage time limit.** `favicon.stage_max_seconds`, when the config does not set it, is derived from the number of lookups of the shard (at 180 lookups per second), at least 7200 s and at most 86400 s. A value in the config is used as written.

**External disk.** `python -m scanner.internet export-shard RUN_DIR DEST [--remove-source] [--config FILE]` copies a finished or compacted run into `DEST/<run name>`, reads every copy back, compares each file with `output_checksums` and the raw batches with the `raw_sha256` of the tool jobs, and writes `export_verification.json` beside the copy. Without `--remove-source` nothing is deleted. With it, the source files are deleted only after every check passed; the manifest, `report/` and `archive_record.json` stay, so the shard remains `complete`, a repeated campaign adopts it, and the merged totals still include it. Any failed check refuses the export and leaves the source untouched. `campaign --archive-to DEST [--archive-remove-source] [--archive-when-free-gb-below GB]` does this automatically for the oldest finished shards before a shard starts while the output disk is low (below the stated free space, or below what a shard start needs); the state entry gains `archived_to`. These options are not part of the config, so they do not change the campaign checksum.

To record CPU per core, per-process and per-thread CPU, memory (including the scope's cgroup counters), network and disk figures for tuning, run [`run/measure.sh`](run/measure.sh) next to the campaign, for example `bash run/measure.sh -o measure -m 'scanner.internet campaign' -u <scope name> -l campaign.log -i 10`. It writes CSV files that are sampled every `-i` seconds until the process exits or `measure/stop` appears, and logs the stage transitions found in the log. With `py-spy` installed, `--pyspy 30` also records a flame graph and a stack dump in the background at the start of each stage.

### Running the campaign as systemd services

[`run/systemd/`](run/systemd) holds templates for a decoupled campaign on one Linux host as two services: `scanner-limiterd.service` (the limiter daemon, `Restart=always`, protected from the OOM killer) and `scanner-coordinator.service` (`campaign --decoupled`, which starts the ZMap, network and favicon worker processes itself). `scanner.target` groups them. The coordinator wants and starts after the limiter but does not require it, so a limiter restart does not stop the campaign; the workers find the limiter through `SCANNER_LIMITER_SOCKET`. `KillMode=control-group` makes a stop signal every process of the coordinator, so no sender outlives it.

Install (or run [`run/bootstrap-host.sh`](run/bootstrap-host.sh), below):

1. Create the user the units run as (`User=scanner` in each unit) and the directories named in the env file.
2. `sudo cp run/systemd/*.service run/systemd/scanner.target /etc/systemd/system/`
3. `sudo install -D -m 0600 run/systemd/scanner.env.example /etc/scanner/scanner.env`, then replace every placeholder (paths, confirmation token, worker counts). systemd reads the file as root, so it can stay `root:root` and unreadable for the operator.
4. `sudo systemctl daemon-reload && sudo systemctl enable --now scanner.target`

Check with `systemctl status 'scanner-*'` and `python -m scanner.internet status <campaign dir> [--json]`. `status` prints shards per state and per stage, the queue per stage, the last heartbeat of each worker, the ZMap send rate when the state records one, free disk and the RSS of the scanner processes (read from `/proc`, so only on Linux; ZMap, ZGrab2 and ZDNS are matched by program name, and the value after `--confirm` is masked). It reads `campaign.json` and tolerates a per-shard `stages` mapping (`{stage: {status, attempts, owner_pid, heartbeat}}`).

To stop everything, either create the kill-switch file named in the config (`operations.kill_switch_file`; the workers stop, and remove the file before starting again), or run `sudo systemctl stop scanner.target`. A `DRAIN` file in the campaign directory stops between shards. Stopping the target does not disable it; `systemctl disable scanner.target` keeps it from starting at boot. The coordinator unit has `Restart=on-failure`: it comes back after a crash but not after the clean exit of a kill switch or a finished campaign.

`MemoryHigh` and `MemoryMax` sit on the coordinator unit and cover it and all its workers together; the example values suit 16 GiB, so size them from the host's RAM and leave headroom for the kernel, unbound and the limiter. A worker can bound its own growth with `scanner.internet.recycle.Recycler(max_shards, max_rss_mib)`: `after_shard()` after each shard (or `check()` at any time) exits the worker with code 75 once the shard count or the resident memory is over its limit, and the coordinator restarts that worker. The per-worker thresholds are set by the coordinator (to be wired) and must stay below the cgroup limits.

[`run/logrotate/scanner.example`](run/logrotate/scanner.example) rotates the campaign logs (`copytruncate`, so no restart is needed).

Certificates with a zero or negative serial number no longer flood the log with `CryptographyDeprecationWarning`; only that message is filtered, other warnings still appear, and `scanner.certificates.nonpositive_serial_count()` returns how many were parsed.

### Host bootstrap

One command turns a fresh Ubuntu 24.04+ or Debian 13 x86-64 host into a scanner host. Run it from a checkout of this repository, as root, naming the unprivileged user that will run the scan:

    sudo bash run/bootstrap-host.sh <user>

[`run/bootstrap-host.sh`](run/bootstrap-host.sh) is idempotent and can be repeated. `--dry-run` prints what it would change and changes nothing. `--no-upgrade`, `--no-toolchain`, `--no-sysctl`, `--no-unbound`, `--no-systemd` and `--no-logrotate` skip the matching parts. It never reboots the host and never enables or starts the campaign.

| Step | What it changes | How to undo |
| --- | --- | --- |
| Upgrade | `apt-get update` and `full-upgrade` keeping existing config files, then installs packages that only phased updates were holding back. Prints whether a reboot is required. | Not reversible; use `--no-upgrade` to skip. |
| Unattended reboots | `/etc/apt/apt.conf.d/52scanner-no-reboot` sets `Unattended-Upgrade::Automatic-Reboot "false"`. | Delete the file. |
| Toolchain | Runs `run/setup-wsl.sh`: pinned ZMap, ZGrab2, ZDNS and Go under `/opt`, `/usr/local/bin`, and the venv and `BUILD_INFO` in the user's home. | Remove `/opt/scanner`, `/opt/src`, `/usr/local/bin/zgrab2`, `/usr/local/bin/zdns` and the user's `scanner-venv` and `.scanner`. |
| Network sysctl | `/etc/sysctl.d/90-scanner.conf`: `ip_local_port_range = 10000 59999`, `tcp_tw_reuse = 1`, `tcp_fin_timeout = 15`. Ports 60000-65535 are left to the local resolver. | Delete the file and run `sysctl --system` or reboot. |
| Open files | `/etc/security/limits.d/90-scanner.conf` sets the user's soft and hard `nofile` to 65536; every unit also has `LimitNOFILE=65536`. | Delete the file. |
| Resolver | Installs `unbound` and writes [`run/unbound/scanner.conf`](run/unbound/scanner.conf) to `/etc/unbound/unbound.conf.d/scanner.conf`, with threads and slabs set to the largest power of two that is at most 8 and at most half the cores, the message cache at RAM / 32 (16m to 1g), the rrset cache at twice that (up to 2g) and `outgoing-range` at 5536 divided by the threads, so all threads fit the permitted source ports. Listens on 127.0.0.1:53 only, uses source ports 60000-65535 and runs `unbound-checkconf` before the restart. It stops with a message if another process listens on 0.0.0.0:53, [::]:53 or 127.0.0.1:53; the systemd-resolved stub on 127.0.0.53 and 127.0.0.54 does not conflict. `/etc/resolv.conf` is not changed. | Delete the file, `systemctl restart unbound`, or `systemctl disable --now unbound`. |
| systemd | Copies the two units and `scanner.target` to `/etc/systemd/system` with `User=` set to the operator (a unit edited locally is kept with a warning, and checksums of installed units are in `/etc/scanner/unit-checksums.sha256`; use `systemctl edit` drop-ins for changes), writes `/etc/scanner/scanner.env` as `root:root` 0600 from `scanner.env.example` (an existing env file is never overwritten), `/etc/tmpfiles.d/scanner.conf` for `/run/scanner`, and creates `/var/lib/scanner/work` and `/var/log/scanner`. Runs `daemon-reload`. | Delete the unit files, `/etc/scanner` and `/etc/tmpfiles.d/scanner.conf`, then `systemctl daemon-reload`. |
| Log rotation | Installs [`run/logrotate/scanner.example`](run/logrotate/scanner.example) as `/etc/logrotate.d/scanner` with the operator's user and group on the `su` line. | Delete the file. |

The summary at the end lists the toolchain versions, the sysctl values, the resolver status and whether a reboot is needed. Still to do by hand: write `settings.yaml` and `config.yaml`, record the approval, run a small pilot, put the confirmation token from `plan` into `/etc/scanner/scanner.env`, and only then `sudo systemctl enable --now scanner.target`.

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

The manifest records `output_schema` (2; a run without it is schema 1) and `compression`. In schema 2, `normalized/hostname_resolution.jsonl` holds only the key (`target_ip`, `port`, `hostname`) and the fields that belong to the name; the rest of each row is the endpoint's record in `normalized/endpoints.jsonl`, which `scanner.internet.outputs.iter_hostname_rows(run_dir)` joins back (it reads schema 1 runs as they are). The raw ZGrab2 and ZDNS files are stored as `.jsonl.zst` (zstd) and their checksums are over the compressed file; without the `zstandard` package they stay plain and the manifest says so. `hostname_resolution.csv` is no longer written: `scanner export-csv RUN_DIR [--out FILE]` produces it from the stored rows.

A shard that finished cleanly has its record files (`normalized/*.jsonl`, `raw/favicon_records.jsonl`, `ip_results.csv`) compressed to `.zst` (zstd level 12), which makes them roughly ten to twenty times smaller; set `output.compact: false` to keep them plain. Each copy is written under a temporary name, flushed, decompressed again and compared by SHA-256 with the original before the original is removed, so an interruption leaves the plain or the verified compressed file, and a resumed campaign finishes the job (`python -m scanner.internet compact RUN_DIR` does it for one run). An incomplete or aborted shard keeps its plain files, so a resume can use them. `output_checksums` in the manifest then lists the `.zst` files by the checksum of the stored bytes, and `compaction.files` holds for each one that checksum (`sha256`), the SHA-256 of the content (`content_sha256`) and both sizes (`bytes`, `content_bytes`). `export-csv`, `favicon-refetch --source-run` and the resume of a shard read either form; for other uses open the file with `zstd -d` or `scanner.internet.outputs.open_text(path)`, which accepts the plain name of a compacted file too.

To fit a long campaign on a smaller disk, `output.prune_raw_keep_every: N` (default 0, off) deletes the `raw/` directory (the raw tool output, about 260 MB per shard) of every compacted shard whose index is not a multiple of N, so N = 50 keeps `raw/` for shards 0, 50, 100 and so on as a sample. `raw/` is removed only when the manifest says the run is complete without stage errors, every file of its `compaction` block is on disk with the recorded SHA-256 (re-hashed), and `ip_results.csv`, `normalized/endpoints.jsonl`, `hostname_resolution.jsonl`, `tool_jobs.jsonl` and `policy_refusals.jsonl` are present; otherwise the campaign logs why it kept `raw/` and carries on. `python -m scanner.internet prune-raw RUN_DIR` does the same for one run (exit code 2 and `REFUSED` on stderr when it refuses). The manifest is not changed, so its checksum stays valid; `raw_pruned.json` in the run records when `raw/` was removed, how many files and bytes, and the checksums the manifest holds for them. This includes `raw/favicon_records.jsonl.zst`, which `favicon-refetch --source-run` reads, so keep `raw/` of runs you may want to refetch from. The key is part of the config, so adding it to a config that has already started a campaign starts a new campaign (see above); a config without it keeps its checksum.

## Limits

- Tested offline and on loopback; it has not been run from an institutional scanner host.
- IPv4 only.
- ZMap 4.4.0 divides the target count across shards, so with 4.4.0 sharding is allowed only for a full scan (`sample_fraction: 1.0`, plus `shards: N` under `scope` in `settings.yaml`, then `campaign`); each shard then covers a disjoint slice of the allowed space.
- Results describe one vantage point at one time.

Licensed under the MIT License (see `LICENSE`). Security reports: see `SECURITY.md`.
