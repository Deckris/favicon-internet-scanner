#!/usr/bin/env bash
# Touches the kill-switch file of a long campaign when memory runs low or the campaign stops producing output.
#
#   run/watchdog.sh -k KILL_FILE [-m MIB] [-w PATH_OR_GLOB]... [-s MINUTES] [-i SECONDS] [-l LOGFILE] [-p PID] [-n BEATS]
#
#   -k  kill-switch file (operations.kill_switch_file of the config; a relative path is relative to the config)   [required]
#   -m  stop when MemAvailable + SwapFree falls below this many MiB                                               [700]
#   -w  file or glob whose modification time shows progress (repeatable; the newest one counts)
#   -s  stop when none of the -w paths changed for this many minutes and no zmap, zgrab2 or zdns is running      [30]
#   -i  seconds between checks                                                                                    [30]
#   -l  log file (default: standard output)
#   -p  campaign process id; the watchdog exits when it is gone
#   -n  write a heartbeat line every N checks                                                                     [20]
#
# The same settings can come from the environment: KILL_SWITCH, MIN_MEM_MIB, WATCH (space separated), STALE_MIN,
# INTERVAL, LOG_FILE, CAMPAIGN_PID, HEARTBEAT_EVERY. WATCHDOG_MEMINFO replaces /proc/meminfo (for tests).
# WATCH is split on spaces; use -w for paths that contain spaces.
set -u

kill_file="${KILL_SWITCH:-}"
min_mem="${MIN_MEM_MIB:-700}"
stale_min="${STALE_MIN:-30}"
interval="${INTERVAL:-30}"
log_file="${LOG_FILE:-}"
pid="${CAMPAIGN_PID:-}"
beat_every="${HEARTBEAT_EVERY:-20}"
meminfo="${WATCHDOG_MEMINFO:-/proc/meminfo}"
watch=()
# shellcheck disable=SC2206
[ -n "${WATCH:-}" ] && watch=($WATCH)

usage() { sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//' >&2; exit "${1:-2}"; }

case "${1:-}" in --help) usage 0 ;; esac

while getopts "k:m:w:s:i:l:p:n:h" opt; do
  case "$opt" in
    k) kill_file="$OPTARG" ;;
    m) min_mem="$OPTARG" ;;
    w) watch+=("$OPTARG") ;;
    s) stale_min="$OPTARG" ;;
    i) interval="$OPTARG" ;;
    l) log_file="$OPTARG" ;;
    p) pid="$OPTARG" ;;
    n) beat_every="$OPTARG" ;;
    h) usage 0 ;;
    *) usage ;;
  esac
done

[ -n "$kill_file" ] || { echo "watchdog: a kill-switch file is required (-k)" >&2; usage; }
for v in min_mem stale_min interval beat_every; do
  case "${!v}" in ''|*[!0-9]*) echo "watchdog: $v must be a whole number" >&2; exit 2 ;; esac
done
for v in min_mem stale_min interval beat_every; do printf -v "$v" '%d' "$((10#${!v}))"; done   # "08" is 8, not bad octal
[ "$interval" -gt 0 ] || { echo "watchdog: interval must be positive" >&2; exit 2; }
[ "$beat_every" -gt 0 ] || beat_every=1

log() {
  local line
  line="$(date -u '+%Y-%m-%dT%H:%M:%SZ') watchdog: $*"
  if [ -n "$log_file" ]; then echo "$line" >> "$log_file"; else echo "$line"; fi
}

# MemAvailable + SwapFree in MiB; empty when the file cannot be read
free_mib() {
  awk '/^MemAvailable:/ {a=$2} /^SwapFree:/ {s=$2} END {if (a != "") printf "%d\n", (a + s) / 1024}' "$meminfo" 2>/dev/null
}

# newest modification time (epoch seconds) among the watched paths; 0 when none exist
newest_mtime() {
  local newest=0 p m
  for p in "${watch[@]+"${watch[@]}"}"; do
    # compgen expands the glob without splitting the path on spaces
    while IFS= read -r f; do
      [ -e "$f" ] || continue
      m="$(stat -c %Y "$f" 2>/dev/null || stat -f %m "$f" 2>/dev/null)" || continue
      case "$m" in ''|*[!0-9]*) continue ;; esac
      [ "$m" -gt "$newest" ] && newest="$m"
    done < <(compgen -G "$p" 2>/dev/null)
  done
  echo "$newest"
}

# Without pgrep nothing can be said about the tools: assume they are running, so a quiet spell never stops a live scan.
no_pgrep_warned=""
tools_running() {
  if ! command -v pgrep > /dev/null 2>&1; then
    [ -n "$no_pgrep_warned" ] || { log "pgrep not found; assuming scan tools may be running, the stale-output stop is disabled"; no_pgrep_warned=1; }
    return 0
  fi
  pgrep -x 'zmap|zgrab2|zdns' > /dev/null 2>&1
}

# Returns only when the kill-switch file could not be written; the caller retries on its next pass.
stop_now() {   # reason
  log "STOP: $1; touching $kill_file"
  if ! touch "$kill_file" 2> /dev/null; then
    log "ERROR: could not touch $kill_file; will retry"
    return 1
  fi
  exit 0
}

started="$(date +%s)"
beat=0
no_mem_warned=""
log "started: kill=$kill_file min_mem=${min_mem}MiB stale=${stale_min}min interval=${interval}s pid=${pid:-none} watch=${watch[*]-}"

while :; do
  if [ -e "$kill_file" ]; then log "kill switch already present, exiting"; exit 0; fi
  if [ -n "$pid" ] && ! kill -0 "$pid" 2>/dev/null; then log "campaign process $pid is gone, exiting"; exit 0; fi

  now="$(date +%s)"
  mem="$(free_mib)"
  if [ -z "$mem" ] && [ -z "$no_mem_warned" ]; then
    log "MemAvailable not found in $meminfo; the memory trigger is inactive"
    no_mem_warned=1
  fi
  if [ -n "$mem" ] && [ "$mem" -lt "$min_mem" ]; then
    stop_now "MemAvailable+SwapFree ${mem} MiB is below ${min_mem} MiB" || { sleep "$interval"; continue; }
  fi

  if [ "${#watch[@]}" -gt 0 ]; then
    newest="$(newest_mtime)"
    [ "$newest" -gt 0 ] || newest="$started"   # nothing to watch yet: count from the start of the watchdog
    idle=$(( (now - newest) / 60 ))
    if [ "$idle" -ge "$stale_min" ] && ! tools_running; then
      stop_now "nothing in the watched paths changed for ${idle} min and no zmap, zgrab2 or zdns is running" || { sleep "$interval"; continue; }
    fi
  fi

  beat=$((beat + 1))
  if [ $((beat % beat_every)) -eq 0 ]; then
    log "ok: ${mem:-unknown} MiB available, idle ${idle:-0} min"
  fi
  sleep "$interval"
done
