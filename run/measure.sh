#!/usr/bin/env bash
# Records CPU per core, per-process and per-thread CPU, memory, network and disk figures next to a scan, for tuning.
#
#   run/measure.sh -o OUTDIR (-p PID | -m PATTERN) [-u UNIT] [-i SECONDS] [-l LOGFILE] [--pyspy SECONDS] [--pyspy-every MINUTES]
#
#   -o, --out DIR          directory for the CSV files (created if missing)                                      [required]
#   -p, --pid PID          scanner process to follow
#   -m, --match PATTERN    follow the oldest process whose command line matches PATTERN (pgrep -f; waits up to --wait)
#   -u, --unit NAME        systemd scope or service whose cgroup v2 memory files are recorded (e.g. run-r1234.scope)
#   -i, --interval SEC     seconds between samples                                                                [10]
#   -l, --log FILE         scan log; lines like "[scanner LABEL] STAGE: start" are written to stages.csv
#       --pyspy SEC        with py-spy on PATH: at each new stage (or every --pyspy-every minutes) record a flame graph
#                          for SEC seconds and a stack dump in the background
#       --pyspy-every MIN  also sample with py-spy every MIN minutes, independent of the log                      [0 = off]
#       --stop-file FILE   stop when this file exists                                                             [OUTDIR/stop]
#       --wait SEC         with --match, how long to wait for the process to appear                               [30]
#   -h, --help
#
# Writes cpu.csv, procs.csv, threads.csv (top 5 threads per sample), mem.csv, net.csv, disk.csv and stages.csv to OUTDIR
# and stops when the process exits or the stop file appears. CPU and network figures are deltas per interval.
set -u

out=""; pid=""; match=""; unit=""; interval=10; log=""; pyspy_secs=0; pyspy_every=0; stop_file=""; wait_secs=30

usage() { sed -n '2,19p' "$0" | sed 's/^# \{0,1\}//'; }
die() { echo "measure.sh: $*" >&2; exit 2; }
need() { [ $# -ge 2 ] || die "option $1 needs a value"; }

while [ $# -gt 0 ]; do
  case "$1" in
    -o|--out) need "$@"; out="$2"; shift 2 ;;
    -p|--pid) need "$@"; pid="$2"; shift 2 ;;
    -m|--match) need "$@"; match="$2"; shift 2 ;;
    -u|--unit) need "$@"; unit="$2"; shift 2 ;;
    -i|--interval) need "$@"; interval="$2"; shift 2 ;;
    -l|--log) need "$@"; log="$2"; shift 2 ;;
    --pyspy) need "$@"; pyspy_secs="$2"; shift 2 ;;
    --pyspy-every) need "$@"; pyspy_every="$2"; shift 2 ;;
    --stop-file) need "$@"; stop_file="$2"; shift 2 ;;
    --wait) need "$@"; wait_secs="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; die "unknown argument: $1" ;;
  esac
done

[ -n "$out" ] || { usage >&2; die "-o is required"; }
[ -n "$pid" ] || [ -n "$match" ] || { usage >&2; die "give -p or -m"; }
[ -r /proc/stat ] || die "needs a Linux /proc"
case "$interval" in ''|*[!0-9.]*) die "bad interval: $interval" ;; esac
case "$pyspy_secs" in ''|*[!0-9]*) die "bad --pyspy value: $pyspy_secs" ;; esac
case "$pyspy_every" in ''|*[!0-9]*) die "bad --pyspy-every value: $pyspy_every" ;; esac
case "$wait_secs" in ''|*[!0-9]*) die "bad --wait value: $wait_secs" ;; esac
case "$pid" in *[!0-9]*) die "bad pid: $pid" ;; esac

mkdir -p "$out/.state" || die "cannot create $out"
[ -n "$stop_file" ] || stop_file="$out/stop"
state="$out/.state"
clk=$(getconf CLK_TCK 2>/dev/null || echo 100)
page_kb=$(( $(getconf PAGESIZE 2>/dev/null || echo 4096) / 1024 ))

now() { TZ=UTC printf -v "$1" '%(%Y-%m-%dT%H:%M:%SZ)T' -1; }

alive() {
  local l
  read -r l 2>/dev/null <"/proc/$pid/stat" || return 1
  l="${l##*) }"
  [ "${l%% *}" != "Z" ] && [ "${l%% *}" != "X" ]
}

if [ -z "$pid" ]; then
  waited=0
  while :; do
    for p in $(pgrep -f -- "$match" 2>/dev/null | sort -n); do
      [ "$p" = "$$" ] && continue
      pid="$p"; break
    done
    [ -n "$pid" ] && break
    [ "$waited" -ge "$wait_secs" ] && die "no process matches: $match"
    sleep 1; waited=$((waited + 1))
  done
fi
alive || die "process $pid is not running"

header() { [ -s "$out/$1" ] || echo "$2" >"$out/$1"; }
header cpu.csv "time,cpu,user_pct,system_pct,iowait_pct,steal_pct,idle_pct,busy_pct"
header procs.csv "time,pid,comm,cpu_pct,threads,rss_kb"
header threads.csv "time,pid,tid,comm,cpu_pct"
header mem.csv "time,mem_available_kb,swap_free_kb,pid,vmrss_kb,vmhwm_kb,threads,cg_current,cg_peak,cg_swap_current,cg_high,cg_max,cg_oom,cg_oom_kill,cg_anon,cg_file"
header net.csv "time,iface,rx_bytes,rx_packets,rx_drop,tx_bytes,tx_packets,tx_drop"
header disk.csv "time,free_kb,read_bytes,write_bytes,wchar"
header stages.csv "time,label,stage"

cg=""
find_cgroup() {
  cg=""
  if [ -n "$unit" ]; then
    local u c
    for u in "$unit" "$unit.scope" "$unit.service"; do
      c=$(find /sys/fs/cgroup -maxdepth 8 -type d -name "$u" 2>/dev/null | head -n 1)
      [ -n "$c" ] && { cg="$c"; return; }
    done
    c=$(sed -n 's/^0:://p' "/proc/$pid/cgroup" 2>/dev/null)
    [ -n "$c" ] && [ -r "/sys/fs/cgroup$c/memory.current" ] && cg="/sys/fs/cgroup$c"
  fi
}
[ -n "$unit" ] && find_cgroup
[ -n "$unit" ] && [ -z "$cg" ] && echo "measure.sh: no cgroup v2 memory files found for $unit" >&2

iface=""
default_iface() {
  iface=""
  [ -r /proc/net/route ] || return
  iface=$(awk 'NR > 1 && $2 == "00000000" { if (best == "" || $7 + 0 < m) { best = $1; m = $7 + 0 } } END { print best }' /proc/net/route)
}
default_iface

sample_cpu() {
  awk -v ts="$1" -v sf="$state/cpu" '
    BEGIN { while ((getline l < sf) > 0) { split(l, a, " "); for (i = 2; i <= 9; i++) prev[a[1], i] = a[i]; seen[a[1]] = 1 } close(sf) }
    /^cpu[0-9]*[ ]/ {
      name = $1
      if (name in seen) {
        t = 0
        for (i = 2; i <= 9; i++) { d[i] = $i - prev[name, i]; t += d[i] }
        if (t > 0) printf "%s,%s,%.1f,%.1f,%.1f,%.1f,%.1f,%.1f\n", ts, name, (d[2] + d[3]) * 100 / t, (d[4] + d[7] + d[8]) * 100 / t, d[6] * 100 / t, d[9] * 100 / t, d[5] * 100 / t, (t - d[5] - d[6]) * 100 / t
      }
      line = name; for (i = 2; i <= 9; i++) line = line " " $i
      print line > (sf ".new")
    }
    END { close(sf ".new") }
  ' /proc/stat >>"$out/cpu.csv" 2>/dev/null
  [ -f "$state/cpu.new" ] && mv -f "$state/cpu.new" "$state/cpu"
}

sample_procs() {
  local up p f t l pids tools
  read -r up _ </proc/uptime
  tools=$(pgrep -x 'zmap|zgrab2|zdns' 2>/dev/null)
  pids="$pid"
  for p in $tools; do [ "$p" != "$pid" ] && pids="$pids $p"; done
  {
    for p in $pids; do
      f="/proc/$p/stat"
      read -r l 2>/dev/null <"$f" && printf '%s %s\n' "$f" "$l"
      for t in /proc/$p/task/*/stat; do
        read -r l 2>/dev/null <"$t" && printf '%s %s\n' "$t" "$l"
      done
    done
  } | awk -v ts="$1" -v up="$up" -v clk="$clk" -v pkb="$page_kb" -v sf="$state/ticks" -v pf="$out/procs.csv" -v tf="$out/threads.csv" '
    BEGIN {
      while ((getline l < sf) > 0) { split(l, a, " "); prev[a[1]] = a[2] }
      close(sf)
      dt = up - prev["__up"]; if (dt <= 0) dt = 1
    }
    {
      path = $1; l = $0; sub(/^[^ ]+ /, "", l)
      i = index(l, "("); j = length(l)
      while (j > 0 && substr(l, j, 1) != ")") j--
      comm = substr(l, i + 1, j - i - 1); gsub(/[,"]/, "_", comm)
      n = split(substr(l, j + 2), r, " ")
      ticks = r[12] + r[13]
      split(path, a, "/")
      if (a[4] == "task") key = a[3] "/" a[5]; else key = a[3]
      cur[key] = ticks
      if (!(key in prev)) next
      pct = (ticks - prev[key]) * 100 / (clk * dt)
      if (a[4] == "task") { nt++; tp[nt] = a[3]; tt[nt] = a[5]; tc[nt] = comm; tv[nt] = pct }
      else printf "%s,%s,%s,%.1f,%d,%d\n", ts, a[3], comm, pct, r[18], r[22] * pkb >> pf
    }
    END {
      for (k = 0; k < 5 && k < nt; k++) {
        best = 0
        for (x = 1; x <= nt; x++) if (!used[x] && (best == 0 || tv[x] > tv[best])) best = x
        used[best] = 1
        printf "%s,%s,%s,%s,%.1f\n", ts, tp[best], tt[best], tc[best], tv[best] >> tf
      }
      print "__up " up > (sf ".new")
      for (k in cur) print k, cur[k] > (sf ".new")
      close(sf ".new")
    }
  ' 2>/dev/null
  [ -f "$state/ticks.new" ] && mv -f "$state/ticks.new" "$state/ticks"
}

cgv() { local v=""; [ -r "$cg/$1" ] && read -r v 2>/dev/null <"$cg/$1"; echo "$v"; }

sample_mem() {
  local files="/proc/meminfo" cur="" peak="" swap=""
  [ -r "/proc/$pid/status" ] && files="$files /proc/$pid/status"
  if [ -n "$cg" ]; then
    cur=$(cgv memory.current); peak=$(cgv memory.peak); swap=$(cgv memory.swap.current)
    [ -r "$cg/memory.events" ] && files="$files $cg/memory.events"
    [ -r "$cg/memory.stat" ] && files="$files $cg/memory.stat"
  fi
  # shellcheck disable=SC2086
  awk -v ts="$1" -v pid="$pid" -v cur="$cur" -v peak="$peak" -v swap="$swap" '
    FILENAME ~ /meminfo$/ { if ($1 == "MemAvailable:") ma = $2; if ($1 == "SwapFree:") sw = $2 }
    FILENAME ~ /status$/ { if ($1 == "VmRSS:") rss = $2; if ($1 == "VmHWM:") hwm = $2; if ($1 == "Threads:") thr = $2 }
    FILENAME ~ /memory\.events$/ { ev[$1] = $2 }
    FILENAME ~ /memory\.stat$/ { if ($1 == "anon") anon = $2; if ($1 == "file") file = $2 }
    END { printf "%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n", ts, ma, sw, pid, rss, hwm, thr, cur, peak, swap, ev["high"], ev["max"], ev["oom"], ev["oom_kill"], anon, file }
  ' $files >>"$out/mem.csv" 2>/dev/null
}

sample_net() {
  [ -n "$iface" ] || default_iface
  [ -n "$iface" ] || return
  awk -v ts="$1" -v ifc="$iface" -v sf="$state/net" '
    BEGIN { n = 0; if ((getline l < sf) > 0) { n = split(l, p, " ") } close(sf) }
    {
      line = $0; sub(/^[ ]+/, "", line); i = index(line, ":")
      if (i > 0 && substr(line, 1, i - 1) == ifc) {
        split(substr(line, i + 1), f, " ")
        if (n == 12) printf "%s,%s,%d,%d,%d,%d,%d,%d\n", ts, ifc, f[1] - p[1], f[2] - p[2], f[4] - p[4], f[9] - p[9], f[10] - p[10], f[12] - p[12]
        print f[1], f[2], f[3], f[4], f[5], f[6], f[7], f[8], f[9], f[10], f[11], f[12] > (sf ".new")
        close(sf ".new")
      }
    }
  ' /proc/net/dev >>"$out/net.csv" 2>/dev/null
  [ -f "$state/net.new" ] && mv -f "$state/net.new" "$state/net"
}

sample_disk() {
  local free k v rb="" wb="" wc=""
  free=$(df -Pk "$out" 2>/dev/null | awk 'NR == 2 { print $4 }')
  if [ -r "/proc/$pid/io" ]; then
    while read -r k v; do
      case "$k" in
        read_bytes:) rb="$v" ;;
        write_bytes:) wb="$v" ;;
        wchar:) wc="$v" ;;
      esac
    done <"/proc/$pid/io"
  fi
  echo "$1,$free,$rb,$wb,$wc" >>"$out/disk.csv"
}

log_off=0
new_stage=""
sample_stages() {
  new_stage=""
  [ -n "$log" ] && [ -r "$log" ] || return
  local size chunk
  size=$(stat -c %s "$log" 2>/dev/null) || return
  [ "$size" -lt "$log_off" ] && log_off=0
  [ "$size" -eq "$log_off" ] && return
  chunk=$(tail -c +$((log_off + 1)) "$log" 2>/dev/null | head -c $((size - log_off)))
  log_off="$size"
  [ -n "$chunk" ] || return
  new_stage=$(printf '%s\n' "$chunk" | awk -v ts="$1" -v f="$out/stages.csv" '
    /\[scanner [^]]*\] .*: start[ \t\r]*$/ {
      l = $0; sub(/^.*\[scanner /, "", l)
      j = index(l, "]"); label = substr(l, 1, j - 1); stage = substr(l, j + 2); sub(/: start[ \t\r]*$/, "", stage)
      gsub(/[,"]/, "_", label); gsub(/[,"]/, "_", stage)
      print ts "," label "," stage >> f; last = stage
    }
    END { print last }')
}

pyspy_job=""
pyspy_warned=0
run_pyspy() {
  [ "$pyspy_secs" -gt 0 ] || return
  if ! command -v py-spy >/dev/null 2>&1; then
    [ "$pyspy_warned" -eq 0 ] && echo "measure.sh: py-spy not on PATH, skipping" >&2
    pyspy_warned=1; return
  fi
  [ -n "$pyspy_job" ] && kill -0 "$pyspy_job" 2>/dev/null && return
  local stamp name
  TZ=UTC printf -v stamp '%(%Y%m%dT%H%M%S)T' -1
  name=$(printf '%s' "${1:-periodic}" | tr -c 'A-Za-z0-9._-' '_')
  (
    py-spy dump --nonblocking -p "$pid" >"$out/dump-$stamp.txt" 2>>"$out/pyspy.log"
    py-spy record --nonblocking --gil -d "$pyspy_secs" -o "$out/pyspy-$stamp-$name.svg" -p "$pid" >>"$out/pyspy.log" 2>&1
  ) </dev/null >/dev/null 2>&1 &
  pyspy_job=$!
}

finish() {
  [ -n "$pyspy_job" ] && wait "$pyspy_job" 2>/dev/null
  exit 0
}
trap finish INT TERM

next_pyspy=0
[ "$pyspy_every" -gt 0 ] && next_pyspy=$(( SECONDS + pyspy_every * 60 ))

while alive; do
  now ts
  sample_cpu "$ts"
  sample_procs "$ts"
  [ -n "$unit" ] && [ -z "$cg" ] && find_cgroup
  sample_mem "$ts"
  sample_net "$ts"
  sample_disk "$ts"
  sample_stages "$ts"
  [ -n "$new_stage" ] && run_pyspy "$new_stage"
  if [ "$pyspy_every" -gt 0 ] && [ "$SECONDS" -ge "$next_pyspy" ]; then
    run_pyspy "periodic"
    next_pyspy=$(( SECONDS + pyspy_every * 60 ))
  fi
  [ -e "$stop_file" ] && break
  sleep "$interval"
done
finish
