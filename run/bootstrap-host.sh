#!/usr/bin/env bash
# Turns a fresh Ubuntu 24.04+ or Debian 13 x86-64 host into a scanner host.
# Usage: sudo bash run/bootstrap-host.sh [options] [operator-user]
# The operator user (default $SUDO_USER) runs the scan; it must already exist.
# Every step is idempotent. Nothing is enabled or started except unbound, and
# the host is never rebooted.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SYSCTL_FILE=/etc/sysctl.d/90-scanner.conf
LIMITS_FILE=/etc/security/limits.d/90-scanner.conf
APT_REBOOT_FILE=/etc/apt/apt.conf.d/52scanner-no-reboot
UNBOUND_CONF=/etc/unbound/unbound.conf.d/scanner.conf
TMPFILES_FILE=/etc/tmpfiles.d/scanner.conf
UNIT_DIR=/etc/systemd/system
ENV_FILE=/etc/scanner/scanner.env
UNIT_SUMS=/etc/scanner/unit-checksums.sha256
LOGROTATE_FILE=/etc/logrotate.d/scanner
# Source ports left to the local resolver (outgoing-port-permit in run/unbound/scanner.conf).
RESOLVER_PORTS=5536
NOFILE=65536

DRY_RUN=0
DO_UPGRADE=1
DO_UNBOUND=1
DO_SYSTEMD=1
DO_SYSCTL=1
DO_TOOLCHAIN=1
DO_LOGROTATE=1
OP_USER=""
OP_GROUP=""

usage() {
  cat <<'USAGE'
Usage: sudo bash run/bootstrap-host.sh [options] [operator-user]

  --dry-run       print what would change, change nothing
  --no-upgrade    skip apt update/full-upgrade and the unattended-upgrades drop-in
  --no-toolchain  skip run/setup-wsl.sh (ZMap, ZGrab2, ZDNS, Go, venv)
  --no-sysctl     skip the sysctl and open-file-limit drop-ins
  --no-unbound    skip the local resolver
  --no-systemd    skip the unit files, env file and directories
  --no-logrotate  skip the log rotation file
  -h, --help      this text
USAGE
}

log() { printf '%s bootstrap: %s\n' "$(date -u +%H:%M:%S)" "$*"; }
die() { printf 'bootstrap: ERROR: %s\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) DRY_RUN=1 ;;
    --no-upgrade) DO_UPGRADE=0 ;;
    --no-toolchain) DO_TOOLCHAIN=0 ;;
    --no-sysctl) DO_SYSCTL=0 ;;
    --no-unbound) DO_UNBOUND=0 ;;
    --no-systemd) DO_SYSTEMD=0 ;;
    --no-logrotate) DO_LOGROTATE=0 ;;
    -h|--help) usage; exit 0 ;;
    -*) usage >&2; die "unknown option: $1" ;;
    *) [ -z "$OP_USER" ] || die "more than one user given"; OP_USER="$1" ;;
  esac
  shift
done

[ "$(id -u)" -eq 0 ] || die "run as root: sudo bash $0 <user>"
[ "$(uname -m)" = "x86_64" ] || die "x86-64 only"
OP_USER="${OP_USER:-${SUDO_USER:-}}"
[ -n "$OP_USER" ] || die "give the operator user as an argument (or run through sudo)"
[ "$OP_USER" != "root" ] || die "the operator must be an unprivileged user, not root"
[[ "$OP_USER" =~ ^[a-z_][a-z0-9_-]*$ ]] || die "unusual user name: $OP_USER"
id "$OP_USER" >/dev/null 2>&1 || die "user does not exist: $OP_USER"
OP_GROUP="$(id -gn "$OP_USER")"
OP_HOME="$(getent passwd "$OP_USER" | cut -d: -f6)"
if [ "$DRY_RUN" -eq 1 ]; then log "dry run: nothing will be changed"; fi

# Run a command, or only print it in a dry run.
run() {
  if [ "$DRY_RUN" -eq 1 ]; then log "would run: $*"; else "$@"; fi
}

# write_file DEST MODE: install stdin as DEST when it differs from what is there.
write_file() {
  local dest="$1" mode="$2" tmp
  tmp="$(mktemp)"
  cat > "$tmp"
  if [ -f "$dest" ] && cmp -s "$tmp" "$dest"; then
    log "unchanged: $dest"
  elif [ "$DRY_RUN" -eq 1 ]; then
    log "would write $dest (mode $mode)"
  else
    install -D -m "$mode" "$tmp" "$dest"
    log "wrote $dest"
  fi
  rm -f "$tmp"
}

apt_get() {
  DEBIAN_FRONTEND=noninteractive apt-get -y -q \
    -o Dpkg::Options::=--force-confold -o Dpkg::Options::=--force-confdef "$@"
}

# Package names listed under "deferred due to phasing" in a simulated upgrade.
phased_packages() {
  { apt-get -s full-upgrade 2>/dev/null | awk '
    /deferred due to phasing/ { on = 1; next }
    on && /^  / { for (i = 1; i <= NF; i++) print $i; next }
    on { on = 0 }' | sort -u; } || true
}

step_upgrade() {
  local phased
  log "step 1: apt update and full-upgrade"
  if [ "$DRY_RUN" -eq 1 ]; then
    log "would run: apt-get update; apt-get full-upgrade (keeping existing config files)"
    phased="$(phased_packages | tr '\n' ' ')"
    log "packages deferred by phasing right now: ${phased:-none}"
  else
    apt-get update -q
    apt_get full-upgrade
    phased="$(phased_packages | tr '\n' ' ')"
    if [ -n "${phased// /}" ]; then
      log "installing packages held back only by phasing: $phased"
      # shellcheck disable=SC2086  # package names never contain spaces
      apt_get install --only-upgrade $phased
    else
      log "no packages held back by phasing"
    fi
  fi
  log "step 2: unattended-upgrades must never reboot on its own"
  write_file "$APT_REBOOT_FILE" 0644 <<'CONF'
// Written by the scanner host bootstrap: a long scan must not be interrupted by a reboot.
Unattended-Upgrade::Automatic-Reboot "false";
CONF
}

step_toolchain() {
  log "step 3: pinned toolchain and venv (run/setup-wsl.sh)"
  [ -f "$REPO_ROOT/run/setup-wsl.sh" ] || die "missing $REPO_ROOT/run/setup-wsl.sh"
  if [ "$DRY_RUN" -eq 1 ]; then
    log "would run: SUDO_USER=$OP_USER bash run/setup-wsl.sh"
  else
    SUDO_USER="$OP_USER" bash "$REPO_ROOT/run/setup-wsl.sh"
  fi
}

step_sysctl() {
  log "step 4: network sysctl drop-in"
  write_file "$SYSCTL_FILE" 0644 <<'CONF'
# Written by the scanner host bootstrap.
# The scanner's outgoing connections use 10000-59999. Ports 60000-65535 are
# left to the local resolver (unbound outgoing-port-permit), so the two never
# compete for source ports.
net.ipv4.ip_local_port_range = 10000 59999
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
CONF
  if [ "$DRY_RUN" -eq 1 ]; then
    log "would run: sysctl -p $SYSCTL_FILE"
  elif ! sysctl -p "$SYSCTL_FILE" >/dev/null; then
    log "WARNING: sysctl -p failed (container or restricted kernel?); the file is in place for the next boot"
  fi
  log "step 5: open-file limit for $OP_USER"
  write_file "$LIMITS_FILE" 0644 <<CONF
# Written by the scanner host bootstrap. Applies to login sessions (PAM); the
# systemd units set LimitNOFILE themselves.
$OP_USER soft nofile $NOFILE
$OP_USER hard nofile $NOFILE
CONF
}

# Largest power of two that is at most 8 and at most half the cores (minimum 1).
unbound_threads() {
  local half n=1
  half=$(( $(nproc) / 2 ))
  if [ "$half" -lt 1 ]; then half=1; fi
  while [ $(( n * 2 )) -le "$half" ] && [ "$n" -lt 8 ]; do n=$(( n * 2 )); done
  echo "$n"
}

# Message cache in MiB: RAM / 32, between 16 and 1024. The rrset cache is twice that (cap 2048).
unbound_msg_mib() {
  local kb mib
  kb="$(awk '/^MemTotal:/ { print $2 }' /proc/meminfo 2>/dev/null || true)"
  mib=$(( ${kb:-0} / 1024 / 32 ))
  if [ "$mib" -lt 16 ]; then mib=16; fi
  if [ "$mib" -gt 1024 ]; then mib=1024; fi
  echo "$mib"
}

# Listeners on local port 53 (TCP and UDP) with process names.
listeners_53() { ss -H -lntup 2>/dev/null | awk '$5 ~ /:53$/' || true; }

# Listeners that stop unbound from binding 127.0.0.1:53: wildcard and loopback addresses on port 53 that are
# not unbound itself. systemd-resolved's 127.0.0.53 and 127.0.0.54 are other addresses and do not match.
conflicts_53() {
  listeners_53 | awk '$5 ~ /^(0\.0\.0\.0|\*|\[::\]|127\.0\.0\.1|\[::1\])(%[^:]*)?:53$/ && $0 !~ /unbound/'
}

step_unbound() {
  local template="$REPO_ROOT/run/unbound/scanner.conf" busy threads msg rrset range ours="" i=0
  log "step 6: local resolver (unbound)"
  [ -f "$template" ] || die "missing $template"
  busy="$(conflicts_53)"
  if [ -n "$busy" ]; then
    die "port 53 is already in use by another process, so unbound cannot listen on 127.0.0.1:53:
$busy
Stop that service or move it to another address, then run this script again.
A stub on 127.0.0.53 (systemd-resolved) does not conflict."
  fi
  run env DEBIAN_FRONTEND=noninteractive apt-get install -y -q unbound
  threads="$(unbound_threads)"
  msg="$(unbound_msg_mib)"
  rrset=$(( msg * 2 ))
  # Each thread opens up to outgoing-range ports, so threads x range must fit the permitted port slice.
  range=$(( RESOLVER_PORTS / threads ))
  log "unbound: $threads threads, msg cache ${msg}m, rrset cache ${rrset}m, outgoing-range $range ($(nproc) cores)"
  sed -E -e "s/^([[:space:]]*(num-threads|msg-cache-slabs|rrset-cache-slabs|infra-cache-slabs|key-cache-slabs):[[:space:]]*)[0-9]+\$/\\1$threads/" \
         -e "s/^([[:space:]]*msg-cache-size:[[:space:]]*).*\$/\\1${msg}m/" \
         -e "s/^([[:space:]]*rrset-cache-size:[[:space:]]*).*\$/\\1${rrset}m/" \
         -e "s/^([[:space:]]*outgoing-range:[[:space:]]*).*\$/\\1$range/" \
         -e "s/^([[:space:]]*num-queries-per-thread:[[:space:]]*).*\$/\\1$(( range / 2 ))/" \
    "$template" | write_file "$UNBOUND_CONF" 0644
  if [ "$DRY_RUN" -eq 1 ]; then
    log "would run: unbound-checkconf; systemctl enable unbound; systemctl restart unbound; check that only loopback serves port 53"
    return 0
  fi
  unbound-checkconf >/dev/null || die "unbound-checkconf rejected the configuration"
  systemctl enable unbound >/dev/null 2>&1 || log "WARNING: could not enable unbound"
  systemctl restart unbound || die "unbound failed to start (see: journalctl -u unbound)"
  while [ "$i" -lt 10 ]; do
    ours="$(listeners_53 | grep unbound || true)"
    if [ -n "$ours" ]; then break; fi
    i=$(( i + 1 ))
    sleep 1
  done
  [ -n "$ours" ] || die "unbound is not listening on port 53"
  if printf '%s\n' "$ours" | awk '$5 !~ /^(127\.[0-9.]+|\[::1\]):53$/ { bad = 1 } END { exit !bad }'; then
    die "unbound listens on a non-loopback address:
$ours"
  fi
  log "unbound serves port 53 on loopback only"
}

# install_unit SRC: render a unit with the operator user and install it. A unit is replaced only while it is
# still what this script wrote earlier (checksum in $UNIT_SUMS) or already identical; a locally edited unit is
# kept and a warning points to drop-ins.
install_unit() {
  local src="$1" name dest tmp have want stored
  name="$(basename "$src")"
  dest="$UNIT_DIR/$name"
  tmp="$(mktemp)"
  sed -E "s/^User=.*/User=$OP_USER/" "$src" > "$tmp"
  want="$(sha256sum "$tmp" | cut -d' ' -f1)"
  if [ -f "$dest" ]; then
    have="$(sha256sum "$dest" | cut -d' ' -f1)"
    stored="$(awk -v n="$name" '$2 == n { print $1 }' "$UNIT_SUMS" 2>/dev/null || true)"
    if [ "$have" != "$want" ] && [ "$have" != "$stored" ]; then
      log "WARNING: $dest was edited locally and is kept. Put changes in a drop-in ('systemctl edit ${name%.*}') and delete the edited file to take the shipped unit."
      rm -f "$tmp"
      return 0
    fi
  fi
  write_file "$dest" 0644 < "$tmp"
  if [ "$DRY_RUN" -eq 0 ]; then
    install -d -m 0755 "$(dirname "$UNIT_SUMS")"
    { grep -v -F "  $name" "$UNIT_SUMS" 2>/dev/null || true; printf '%s  %s\n' "$want" "$name"; } > "$tmp"
    install -m 0644 "$tmp" "$UNIT_SUMS"
  fi
  rm -f "$tmp"
}

step_systemd() {
  local src="$REPO_ROOT/run/systemd" f
  log "step 7: systemd units, env file and directories"
  [ -d "$src" ] || die "missing $src"
  for f in "$src"/*.service "$src"/scanner.target; do
    install_unit "$f"
  done
  # systemd reads the env file as root, so it stays root:root 0600 (it holds the confirmation token).
  # The operator edits it with sudo.
  if [ -e "$ENV_FILE" ]; then
    log "kept existing $ENV_FILE"
  else
    sed -E -e "s|^SCANNER_HOME=.*|SCANNER_HOME=$REPO_ROOT|" \
           -e "s|^SCANNER_PYTHON=.*|SCANNER_PYTHON=$OP_HOME/scanner-venv/bin/python|" \
      "$src/scanner.env.example" | write_file "$ENV_FILE" 0600
  fi
  write_file "$TMPFILES_FILE" 0644 <<CONF
# Written by the scanner host bootstrap: runtime directory for the limiter socket.
d /run/scanner 0750 $OP_USER $OP_GROUP -
CONF
  run install -d -m 0750 -o "$OP_USER" -g "$OP_GROUP" /var/lib/scanner /var/lib/scanner/work /var/log/scanner
  run systemd-tmpfiles --create "$TMPFILES_FILE"
  run systemctl daemon-reload
  log "the target is not enabled or started"
}

step_logrotate() {
  local src="$REPO_ROOT/run/logrotate/scanner.example"
  log "step 7b: log rotation"
  [ -f "$src" ] || die "missing $src"
  sed -E "s/^([[:space:]]*su )[^[:space:]]+ [^[:space:]]+\$/\\1$OP_USER $OP_GROUP/" "$src" | write_file "$LOGROTATE_FILE" 0644
}

summary() {
  local info="$OP_HOME/.scanner/BUILD_INFO" v
  log "step 8: summary"
  echo "---- summary ----"
  echo "operator user: $OP_USER    repository: $REPO_ROOT"
  if [ -f "$info" ]; then sed 's/^/  /' "$info"; else echo "  toolchain: no BUILD_INFO yet"; fi
  if [ "$DRY_RUN" -eq 1 ]; then
    echo "dry run: no changes made"
    echo "-----------------"
    return 0
  fi
  if [ "$DO_SYSCTL" -eq 1 ]; then
    for v in net.ipv4.ip_local_port_range net.ipv4.tcp_tw_reuse net.ipv4.tcp_fin_timeout; do
      echo "  sysctl $v = $(sysctl -n "$v" 2>/dev/null || echo unknown)"
    done
  fi
  if [ "$DO_UNBOUND" -eq 1 ]; then
    echo "  unbound: $(systemctl is-active unbound 2>/dev/null || true) $(unbound -V 2>/dev/null | head -1 || true)"
    echo "  listeners on port 53:"
    listeners_53 | awk '{print "    " $1, $5}'
    echo "  /etc/resolv.conf was not changed; point the scan at 127.0.0.1 as its resolver"
  fi
  if [ -f /var/run/reboot-required ]; then
    echo "REBOOT REQUIRED (not done automatically): sudo reboot"
  else
    echo "no reboot required"
  fi
  cat <<NEXT
Still to do by the operator:
  1. Create settings.yaml and config.yaml in /var/lib/scanner/work from the run/*.example.yaml files and review them.
  2. Record the approval (approval.yaml) and the exclusion list.
  3. Run a small pilot and check its output.
  4. Put the confirmation token printed by 'plan' into $ENV_FILE (root:root 0600; edit it with sudo).
  5. Then start the campaign: sudo systemctl enable --now scanner.target
-----------------
NEXT
}

if [ "$DO_UPGRADE" -eq 1 ]; then step_upgrade; fi
if [ "$DO_TOOLCHAIN" -eq 1 ]; then step_toolchain; fi
if [ "$DO_SYSCTL" -eq 1 ]; then step_sysctl; fi
if [ "$DO_UNBOUND" -eq 1 ]; then step_unbound; fi
if [ "$DO_SYSTEMD" -eq 1 ]; then step_systemd; fi
if [ "$DO_LOGROTATE" -eq 1 ]; then step_logrotate; fi
summary
