#!/bin/bash
# ============================================================
#  Spider-Recon v3.0  -  Bug Bounty Automation
#  By: Youssef Ashraf
# ============================================================
#  v3.0 changes:
#  - FFUF baseline check: filters soft-403 catch-all responses
#  - JS secrets: value-level dedup so repeated keys aren't overcounted
#  - Report: honesty labels — "UNVERIFIED PATTERN MATCHES" not "VULNERABILITY"
#  - Gxss skip: annotated in report when skipped for large sets
#  - Nuclei severity breakdown (critical/high/medium) in report
#  - subjs per-host timeout instead of single global timeout
#  - inprogress marker cleanup via trap for crash safety
#  - State file kept on completion (manual delete needed for full reset)
#  - Port scanning (naabu) REMOVED — low value for bug bounty recon and
#    triggers WAF/IP bans too easily
#  - Katana now also crawls passive URL sources (gau/wayback), not just live hosts
# ============================================================

set -o pipefail

# ===========================
#  GLOBAL SETTINGS
# ===========================
export PATH="$PATH:$(go env GOPATH 2>/dev/null)/bin:$HOME/.local/bin"

SLOW=false
DOMAIN=""
SCOPE_FILE=""
RATE_LIMIT=150
START_TIME=$(date +%s)
NUCLEI_UPDATE_PID=""
DEEP_PROBE=false
RUN_GOSPIDER=false
RUN_AMASS=false
RESET=false
STATE_FILE=""
LOCK_FILE=""
TOTAL_PHASES=9
TOTAL_PHASES_DONE=0
CURRENT_PHASE_NAME=""
CURRENT_ITEM=0
CURRENT_TOTAL=0

# Timing tracking per phase
declare -A PHASE_TIMES

# ===========================
#  COLORS
# ===========================
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

log()    { echo -e "${CYAN}[$(date +%H:%M:%S)]${NC} $1"; }
ok()     { echo -e "${GREEN}[+]${NC} $1"; }
warn()   { echo -e "${YELLOW}[!]${NC} $1"; }
err()    { echo -e "${RED}[-]${NC} $1"; }
phase()  { echo -e "\n${BLUE}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"; \
           echo -e "${BLUE}${BOLD}  $1${NC}"; \
           echo -e "${BLUE}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"; }

# ===========================
#  USAGE
# ===========================
usage() {
cat <<USAGE
Usage: $0 -d domain.com [options]

Options:
  -d   Target domain (required)
  -s   Slow mode (lower threads/rate, stealthier)
  -l   Scope file (in-scope domains, one per line) — skips the interactive prompt
  -x   Deep mode (extra httpx ports, katana depth 3, nuclei low severity)
  -g   Also run gospider alongside katana (extra coverage, slower)
  -a   Also run amass passive enum (slow, often redundant with subfinder -all)
  -r   Reset — ignore any saved checkpoint and start fully from scratch
  -h   Show this help

Note: if -l isn't given, the script will ask interactively whether you
have a scope list and let you type it in before starting.

Examples:
  $0 -d example.com
  $0 -d example.com -s -l scope.txt
  $0 -d example.com -x -g -a    # full deep scan, everything on
  $0 -d example.com             # run again with same domain -> auto-resumes
  $0 -d example.com -r          # force restart, ignore checkpoint
USAGE
exit 1
}

# ===========================
#  ARGUMENTS
# ===========================
while getopts "d:l:sxgarh" opt; do
  case $opt in
    d) DOMAIN=$OPTARG ;;
    l) SCOPE_FILE=$OPTARG ;;
    s) SLOW=true ;;
    x) DEEP_PROBE=true ;;
    g) RUN_GOSPIDER=true ;;
    a) RUN_AMASS=true ;;
    r) RESET=true ;;
    h) usage ;;
    *) usage ;;
  esac
done

[ -z "$DOMAIN" ] && usage

# ===========================
#  INTERACTIVE SCOPE INPUT
# ===========================
if [ -z "$SCOPE_FILE" ]; then
  read -rp "$(echo -e "${CYAN}[?]${NC} Do you have a scope list for ${BOLD}$DOMAIN${NC}? (y/n): ")" HAS_SCOPE
  if [[ "$HAS_SCOPE" =~ ^[Yy] ]]; then
    mkdir -p "output/$DOMAIN"
    SCOPE_FILE="output/$DOMAIN/scope.txt"
    echo -e "${CYAN}Enter in-scope domains/patterns, one per line (e.g. api.$DOMAIN, .$DOMAIN).${NC}"
    echo -e "${CYAN}Press ENTER on an empty line when you're done:${NC}"
    : > "$SCOPE_FILE"
    while true; do
      read -rp "  > " scope_entry
      [ -z "$scope_entry" ] && break
      echo "$scope_entry" >> "$SCOPE_FILE"
    done
    SCOPE_COUNT=$(grep -c "" "$SCOPE_FILE" 2>/dev/null || echo 0)
    if [ "$SCOPE_COUNT" -eq 0 ]; then
      echo -e "${YELLOW}[!]${NC} No scope entries entered — continuing without scope filtering."
      rm -f "$SCOPE_FILE"
      SCOPE_FILE=""
    else
      echo -e "${GREEN}[+]${NC} Scope saved: $SCOPE_COUNT entries -> $SCOPE_FILE"
    fi
  else
    echo -e "${CYAN}[i]${NC} No scope list — continuing without filtering."
  fi
fi

# ===========================
#  THREAD / RATE CONTROL
# ===========================
if $SLOW; then
  THREADS=20
  RATE_LIMIT=30
  MAX_HOSTS=3
  MAX_PARALLEL=2
  FFUF_THREADS=20
  FFUF_RATE=20
  JOB_TIMEOUT=90
else
  THREADS=80
  RATE_LIMIT=120
  MAX_HOSTS=5
  MAX_PARALLEL=3
  FFUF_THREADS=40
  FFUF_RATE=60
  JOB_TIMEOUT=120
fi

# ===========================
#  ROOT CHECK
# ===========================
if [ "$EUID" -ne 0 ]; then
  warn "Not running as root — some tools may need elevated privileges for certain features."
fi

# ===========================
#  HELPERS
# ===========================
count_lines() {
  if [ -f "$1" ]; then
    wc -l < "$1" 2>/dev/null | tr -d ' '
  else
    echo 0
  fi
}

# ===========================
#  STATE FILE (checkpoint) / RESUME / LOCK
# ===========================
CHECKPOINT_VERSION=2

ensure_jq() {
  if ! command -v jq &>/dev/null; then
    warn "jq not found (needed for state file) — installing..."
    (sudo apt-get install -y jq || apt-get install -y jq) &>/dev/null
    if ! command -v jq &>/dev/null; then
      err "Could not install jq automatically. Install it manually: sudo apt install jq"
      exit 1
    fi
  fi
  ok "jq ✓"
}

init_state() {
  STATE_FILE="$OUT/.state.json"
  LOCK_FILE="$OUT/.lock"

  if [ "$RESET" = true ]; then
    warn "Reset (-r) requested — clearing saved state, starting fresh."
    rm -f "$STATE_FILE" "$JS/.in_progress" "$VULN/.in_progress" \
          "$SUBS/live_detailed.txt.inprogress"
  fi

  if [ ! -f "$STATE_FILE" ]; then
    jq -n --argjson ver "$CHECKPOINT_VERSION" --arg sv "3.0" --arg d "$DOMAIN" --arg t "$(date -Iseconds)" \
      '{checkpoint_version:$ver, script_version:$sv, domain:$d, completed_phases:[], progress:{}, started_at:$t, updated_at:$t}' \
      > "$STATE_FILE"
    return
  fi

  local ver
  ver=$(jq -r '.checkpoint_version // 0' "$STATE_FILE" 2>/dev/null)
  if [ "$ver" != "$CHECKPOINT_VERSION" ]; then
    warn "State file format is old/incompatible (v$ver) — starting fresh (old file kept as .bak)."
    cp "$STATE_FILE" "${STATE_FILE}.v${ver}.bak" 2>/dev/null
    jq -n --argjson ver "$CHECKPOINT_VERSION" --arg sv "3.0" --arg d "$DOMAIN" --arg t "$(date -Iseconds)" \
      '{checkpoint_version:$ver, script_version:$sv, domain:$d, completed_phases:[], progress:{}, started_at:$t, updated_at:$t}' \
      > "$STATE_FILE"
  else
    ok "Found previous run for $DOMAIN — resuming from saved state."
    ok "  Completed so far: $(jq -r '.completed_phases | join(", ")' "$STATE_FILE" 2>/dev/null)"
  fi
}

state_set() {
  local jq_path="$1" jq_value="$2"
  local tmp
  tmp=$(mktemp)
  jq "$jq_path = $jq_value | .updated_at = \"$(date -Iseconds)\"" "$STATE_FILE" > "$tmp" 2>/dev/null && mv "$tmp" "$STATE_FILE"
}

state_get() {
  jq -r "$1 // empty" "$STATE_FILE" 2>/dev/null
}

acquire_lock() {
  if [ -f "$LOCK_FILE" ]; then
    local old_pid
    old_pid=$(cat "$LOCK_FILE" 2>/dev/null)
    if [ -n "$old_pid" ] && kill -0 "$old_pid" 2>/dev/null; then
      err "Another scan for $DOMAIN is already running (PID $old_pid)."
      err "If you're sure it's not, delete: $LOCK_FILE"
      exit 1
    else
      warn "Stale lock file found (process $old_pid not running) — removing it."
    fi
  fi
  echo $$ > "$LOCK_FILE"
}

release_lock() {
  [ -n "$LOCK_FILE" ] && rm -f "$LOCK_FILE" 2>/dev/null
}

is_phase_done() {
  local phase="$1"
  if jq -e --arg p "$phase" '.completed_phases | index($p) != null' "$STATE_FILE" >/dev/null 2>&1; then
    return 0
  fi
  case "$phase" in
    subdomains) [ -s "$SUBS/resolved_hosts.txt" ] ;;
    probe)      [ -s "$SUBS/live_detailed.txt" ] && [ ! -f "$SUBS/live_detailed.txt.inprogress" ] ;;
    urls)       [ -s "$URLS/all_urls.txt" ] ;;
    js)         [ -f "$JS/js_urls.txt" ] && [ ! -f "$JS/.in_progress" ] ;;
    filter)     [ -f "$URLS/params_urls.txt" ] ;;
    gf)         [ -f "$VULN/gf_sqli.txt" ] ;;
    nuclei)     [ -f "$VULN/nuclei.txt" ] ;;
    ffuf)       [ -f "$VULN/ffuf_all_found.txt" ] && [ ! -f "$VULN/.in_progress" ] ;;
    xss)        [ -f "$VULN/xss_dedup.txt" ] ;;
    *) return 1 ;;
  esac
}

mark_phase_done() {
  local phase="$1"
  local tmp
  tmp=$(mktemp)
  jq --arg p "$phase" --arg t "$(date -Iseconds)" \
    '.completed_phases = ((.completed_phases + [$p]) | unique) | .updated_at = $t' \
    "$STATE_FILE" > "$tmp" 2>/dev/null && mv "$tmp" "$STATE_FILE"
}

run_phase() {
  local name="$1"
  shift
  TOTAL_PHASES_DONE=$((TOTAL_PHASES_DONE + 1))
  CURRENT_PHASE_NAME="$name"
  if is_phase_done "$name"; then
    ok "⏭  [$TOTAL_PHASES_DONE/$TOTAL_PHASES] Skipping '$name' — already completed"
    mark_phase_done "$name"
    return
  fi
  log "${BOLD}[$TOTAL_PHASES_DONE/$TOTAL_PHASES] Starting '$name'...${NC}"
  "$@"
  mark_phase_done "$name"
}

BASH_SUPPORTS_WAIT_N=false
if (( BASH_VERSINFO[0] > 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] >= 3) )); then
  BASH_SUPPORTS_WAIT_N=true
fi

wait_jobs() {
  local max="${1:-$MAX_PARALLEL}"
  if [ "$BASH_SUPPORTS_WAIT_N" = true ]; then
    while [ "$(jobs -rp | wc -l)" -ge "$max" ]; do
      wait -n 2>/dev/null || break
    done
  else
    while true; do
      local running
      running=$(jobs -r 2>/dev/null | wc -l)
      [ "$running" -lt "$max" ] && break
      sleep 0.3
    done
  fi
}

# ===========================
#  CHUNKED SCAN (resume-safe)
# ===========================
run_chunked_scan() {
  local state_key="$1" input_file="$2" chunk_size="$3" out_file="$4" cmd_func="$5"
  local inprogress_marker="${out_file}.inprogress"

  local total_lines
  total_lines=$(count_lines "$input_file")
  if [ "$total_lines" -eq 0 ]; then
    touch "$out_file"
    return 0
  fi

  local total_chunks=$(( (total_lines + chunk_size - 1) / chunk_size ))
  local start_chunk
  start_chunk=$(state_get ".progress.${state_key}.last_chunk")
  [ -z "$start_chunk" ] && start_chunk=0

  if [ "$start_chunk" -eq 0 ]; then
    : > "$out_file"
  else
    log "  -> Resuming $state_key from chunk $start_chunk/$total_chunks"
  fi
  touch "$inprogress_marker"
  # Cleanup marker on ANY exit path from this function (normal, error, signal)
  trap 'rm -f "$inprogress_marker"' RETURN

  local tmp_dir
  tmp_dir=$(mktemp -d)
  split -l "$chunk_size" "$input_file" "$tmp_dir/${state_key}_chunk_"

  CURRENT_TOTAL=$total_chunks
  local chunk_num=0
  for chunk_file in "$tmp_dir/${state_key}_chunk_"*; do
    chunk_num=$((chunk_num + 1))
    if [ "$chunk_num" -le "$start_chunk" ]; then continue; fi
    CURRENT_ITEM=$chunk_num
    log "  -> [$state_key] chunk $chunk_num/$total_chunks ($(count_lines "$chunk_file") hosts)"
    "$cmd_func" "$chunk_file" "$out_file"
    state_set ".progress.${state_key}.last_chunk" "$chunk_num"
  done

  rm -rf "$tmp_dir"
}

phase_start() {
  PHASE_TIMES["${1}_start"]=$(date +%s)
}

phase_end() {
  local name="$1"
  local start="${PHASE_TIMES["${name}_start"]}"
  local end
  end=$(date +%s)
  PHASE_TIMES["${name}_dur"]=$(( end - start ))
  log "  Phase $name finished in ${PHASE_TIMES["${name}_dur"]}s"
}

in_scope() {
  local host="$1"
  if [ -z "$SCOPE_FILE" ] || [ ! -f "$SCOPE_FILE" ]; then
    echo "$host"
    return
  fi
  while IFS= read -r pattern; do
    [[ "$host" == *"$pattern" ]] && echo "$host" && return
  done < "$SCOPE_FILE"
}

# ===========================
#  TOOL CHECKER
# ===========================
check_tool() {
  local TOOL=$1
  local INSTALL_CMD=$2
  local FALLBACK_CMD=$3
  if ! command -v "$TOOL" &>/dev/null; then
    warn "$TOOL not found — installing (pinned version)..."
    if eval "$INSTALL_CMD" &>/dev/null; then
      ok "$TOOL installed."
    elif [ -n "$FALLBACK_CMD" ]; then
      warn "Pinned install failed for $TOOL — falling back to @latest..."
      eval "$FALLBACK_CMD" &>/dev/null \
        && ok "$TOOL installed (latest)." \
        || err "Failed to install $TOOL (continuing)."
    else
      err "Failed to install $TOOL (continuing)."
    fi
  else
    ok "$TOOL ✓"
  fi
}

install_dependencies() {
  phase "Dependency Check"

  check_tool subfinder   "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
  check_tool dnsx        "go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
  check_tool httpx       "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"
  check_tool gau         "go install github.com/lc/gau/v2/cmd/gau@latest"
  check_tool waybackurls "go install github.com/tomnomnom/waybackurls@latest"
  check_tool katana      "go install github.com/projectdiscovery/katana/cmd/katana@latest"
  check_tool gospider    "go install github.com/jaeles-project/gospider@latest"
  check_tool nuclei      "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
  check_tool ffuf         "go install github.com/ffuf/ffuf/v2@v2.1.0" "go install github.com/ffuf/ffuf/v2@latest"
  check_tool dalfox      "go install github.com/hahwul/dalfox/v2@latest"
  check_tool gf          "go install github.com/tomnomnom/gf@latest"
  check_tool qsreplace   "go install github.com/tomnomnom/qsreplace@latest"
  check_tool anew        "go install github.com/tomnomnom/anew@latest"
  check_tool unfurl      "go install github.com/tomnomnom/unfurl@latest"
  check_tool subjs       "go install github.com/lc/subjs@latest"
  check_tool Gxss        "go install github.com/KathanP19/Gxss@latest"

  # sublist3r (python tool, not a go install)
  if ! command -v sublist3r &>/dev/null; then
    warn "sublist3r not found — installing..."
    if pip install -q sublist3r &>/dev/null && command -v sublist3r &>/dev/null; then
      ok "sublist3r installed."
    else
      local SUB3_DIR="$HOME/.local/share/Sublist3r"
      if [ ! -d "$SUB3_DIR" ]; then
        git clone -q https://github.com/aboul3la/Sublist3r "$SUB3_DIR" &>/dev/null
      fi
      if [ -f "$SUB3_DIR/sublist3r.py" ]; then
        pip install -q -r "$SUB3_DIR/requirements.txt" &>/dev/null
        ok "sublist3r cloned to $SUB3_DIR (will be invoked via python3 sublist3r.py)"
      else
        err "Failed to install sublist3r (continuing)."
      fi
    fi
  else
    ok "sublist3r ✓"
  fi

  command -v paramspider &>/dev/null || pip install -q paramspider 2>/dev/null
  command -v arjun       &>/dev/null || pip install -q arjun 2>/dev/null
  command -v uro         &>/dev/null || pip install -q uro 2>/dev/null

  # gf patterns
  local GF_DIR="$HOME/.config/gf"
  if [ ! -d "$GF_DIR" ] || [ -z "$(ls -A "$GF_DIR"/*.json 2>/dev/null)" ]; then
    warn "gf patterns missing — downloading..."
    mkdir -p "$GF_DIR"
    local TMP; TMP=$(mktemp -d)

    git clone -q --depth=1 https://github.com/1ndianl33t/Gf-Patterns "$TMP/gf1" 2>/dev/null \
      && cp "$TMP/gf1"/*.json "$GF_DIR/" 2>/dev/null \
      && ok "Gf-Patterns loaded (1ndianl33t)"

    git clone -q --depth=1 https://github.com/tomnomnom/gf "$TMP/gf2" 2>/dev/null \
      && cp "$TMP/gf2/examples"/*.json "$GF_DIR/" 2>/dev/null \
      && ok "gf examples loaded (tomnomnom)"

    rm -rf "$TMP"
  else
    ok "gf patterns: $(ls "$GF_DIR"/*.json 2>/dev/null | wc -l) patterns"
  fi

  # nuclei templates background update
  if command -v nuclei &>/dev/null; then
    nuclei -update-templates -silent &>/dev/null &
    NUCLEI_UPDATE_PID=$!
    ok "Nuclei templates updating in background (PID $NUCLEI_UPDATE_PID)"
  fi
}

# ===========================
#  WORDLIST DETECTION
# ===========================
detect_wordlists() {
  WORDLIST=""
  for base in "/home/kali/SecLists" "/home/kali/seclists" \
              "/usr/share/seclists" "/opt/SecLists" \
              "$HOME/SecLists"; do
    if [ -d "$base" ]; then
      local candidates=(
        "$base/Discovery/Web-Content/common.txt"
        "$base/Discovery/Web-Content/raft-small-directories.txt"
        "$base/Discovery/Web-Content/raft-medium-directories.txt"
      )
      for wl in "${candidates[@]}"; do
        if [ -f "$wl" ]; then
          WORDLIST="$wl"
          ok "Wordlist: $WORDLIST ($(wc -l < "$WORDLIST") lines)"
          return
        fi
      done
    fi
  done

  for fb in "/usr/share/wordlists/dirb/common.txt" \
            "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt"; do
    if [ -f "$fb" ]; then
      WORDLIST="$fb"
      warn "Wordlist fallback: $WORDLIST"
      return
    fi
  done

  warn "No wordlist found — ffuf will be skipped."
}

# ===========================
#  BANNER
# ===========================
banner() {
cat << "EOF"
   _____       _     _              _____
  / ____|     (_)   | |            |  __ \
 | (___  _ __  _  __| | ___ _ __   | |__) |___  ___ ___  _ __
  \___ \| '_ \| |/ _` |/ _ \ '__|  |  _  // _ \/ __/ _ \| '_ \
  ____) | |_) | | (_| |  __/ |     | | \ \  __/ (_| (_) | | | |
 |_____/| .__/|_|\__,_|\___|_|     |_|  \_\___|\___\___/|_| |_|
        | |              v3.0  -  Bug Bounty Edition
        |_|              By: Youssef Ashraf
EOF
  echo ""
  echo -e "  Target : ${BOLD}$DOMAIN${NC}"
  echo -e "  Mode   : $([ "$SLOW" = true ] && echo 'Slow (Stealth)' || echo 'Normal')"
  [ -n "$SCOPE_FILE" ] && echo -e "  Scope  : $SCOPE_FILE"
  echo ""
}

# ===========================
#  OUTPUT STRUCTURE
# ===========================
setup_dirs() {
  OUT="output/$DOMAIN"
  SUBS="$OUT/subs"
  URLS="$OUT/urls"
  VULN="$OUT/vuln"
  JS="$OUT/js"
  mkdir -p "$SUBS" "$URLS" "$VULN" "$JS"

  init_state
  acquire_lock

  ok "Output directory: $OUT"
}

# ===========================
#  PHASE 1: SUBDOMAIN ENUMERATION
# ===========================
enum_subdomains() {
  phase "Phase 1: Subdomain Enumeration"
  phase_start "1"

  log "  -> Launching subfinder + sublist3r in parallel..."

  ( timeout 180 subfinder -d "$DOMAIN" -all -silent \
      -o "$SUBS/subfinder.txt" 2>/dev/null \
      || { warn "subfinder timed out"; touch "$SUBS/subfinder.txt"; } ) &
  local PID_SUB=$!

  (
    touch "$SUBS/sublist3r.txt"
    if command -v sublist3r &>/dev/null; then
      timeout 180 sublist3r -d "$DOMAIN" -o "$SUBS/sublist3r.txt" &>/dev/null \
        || warn "sublist3r timed out"
    else
      local SUB3_SCRIPT="$HOME/.local/share/Sublist3r/sublist3r.py"
      if [ -f "$SUB3_SCRIPT" ]; then
        timeout 180 python3 "$SUB3_SCRIPT" -d "$DOMAIN" -o "$SUBS/sublist3r.txt" &>/dev/null \
          || warn "sublist3r timed out"
      else
        warn "sublist3r not installed — skipping"
      fi
    fi
  ) &
  local PID_SUB3=$!

  wait "$PID_SUB" "$PID_SUB3" 2>/dev/null

  ok "subfinder: $(count_lines "$SUBS/subfinder.txt")  sublist3r: $(count_lines "$SUBS/sublist3r.txt")"

  cat "$SUBS"/*.txt 2>/dev/null \
    | grep -E "(^|\.)${DOMAIN}$" \
    | sed 's/^\*\.//' \
    | sort -u > "$SUBS/all_raw.txt"

  if [ -n "$SCOPE_FILE" ] && [ -f "$SCOPE_FILE" ]; then
    while IFS= read -r sub; do
      in_scope "$sub" >> "$SUBS/all.txt"
    done < "$SUBS/all_raw.txt"
    sort -u -o "$SUBS/all.txt" "$SUBS/all.txt"
    ok "Scope filtered: $(count_lines "$SUBS/all.txt") / $(count_lines "$SUBS/all_raw.txt") subdomains"
  else
    cp "$SUBS/all_raw.txt" "$SUBS/all.txt"
  fi

  ok "Total unique subdomains: $(count_lines "$SUBS/all.txt")"

  log "  -> DNSx resolution..."
  if [ -s "$SUBS/all.txt" ]; then
    timeout 300 dnsx \
      -l "$SUBS/all.txt" \
      -silent \
      -t "$THREADS" \
      -retry 2 \
      -resp \
      -o "$SUBS/resolved.txt" 2>/dev/null \
      || cp "$SUBS/all.txt" "$SUBS/resolved.txt"
    awk '{print $1}' "$SUBS/resolved.txt" | sort -u > "$SUBS/resolved_hosts.txt"
  else
    warn "No subdomains to resolve"
    touch "$SUBS/resolved.txt" "$SUBS/resolved_hosts.txt"
  fi

  ok "Resolved: $(count_lines "$SUBS/resolved_hosts.txt") hosts"
  phase_end "1"
}

# ===========================
#  PHASE 2: PROBE LIVE HOSTS
# ===========================
probe_hosts() {
  phase "Phase 2: Probing Live Hosts"
  phase_start "2"

  if [ ! -s "$SUBS/resolved_hosts.txt" ]; then
    warn "No resolved hosts to probe."
    touch "$SUBS/live.txt" "$SUBS/live_detailed.txt"
    phase_end "2"
    return
  fi

  local PORT_ARGS=()
  if [ "$DEEP_PROBE" = true ]; then
    log "  -> Deep probe: checking 80,443,8080,8443,8000,8888,3000"
    PORT_ARGS=(-ports "80,443,8080,8443,8000,8888,3000")
  else
    log "  -> Fast probe: checking 80,443 only (use -x for extra ports)"
  fi

  httpx_chunk_cmd() {
    local chunk_file="$1" out_file="$2"
    httpx \
      -l "$chunk_file" \
      "${PORT_ARGS[@]}" \
      -threads "$THREADS" \
      -rate-limit "$RATE_LIMIT" \
      -timeout 10 \
      -retries 2 \
      -silent \
      -title \
      -status-code \
      -tech-detect \
      -cdn \
      -follow-redirects \
      2>>"$SUBS/httpx_errors.txt" >> "$out_file"
  }

  run_chunked_scan "httpx" "$SUBS/resolved_hosts.txt" 30 "$SUBS/live_detailed.txt" httpx_chunk_cmd

  awk '{print $1}' "$SUBS/live_detailed.txt" \
    | grep -E "^https?://" \
    | sort -u > "$SUBS/live.txt"

  local LIVE_COUNT
  LIVE_COUNT=$(count_lines "$SUBS/live.txt")

  if [ "$LIVE_COUNT" -eq 0 ]; then
    warn "Zero live hosts — likely rate-limited by target's CDN. Retrying in 90s..."
    sleep 90
    state_set '.progress.httpx.last_chunk' 0
    run_chunked_scan "httpx" "$SUBS/resolved_hosts.txt" 30 "$SUBS/live_detailed.txt" httpx_chunk_cmd

    awk '{print $1}' "$SUBS/live_detailed.txt" \
      | grep -E "^https?://" \
      | sort -u > "$SUBS/live.txt"
    LIVE_COUNT=$(count_lines "$SUBS/live.txt")
  fi

  ok "Live hosts: $LIVE_COUNT"

  if [ "$LIVE_COUNT" -eq 0 ]; then
    warn "Zero live hosts detected!"
    warn "  Check: $SUBS/httpx_errors.txt"
    warn "  Check: $SUBS/resolved_hosts.txt ($(count_lines "$SUBS/resolved_hosts.txt") entries)"
    warn "  Manual test: httpx -u $DOMAIN -title -status-code"
  fi

  phase_end "2"
}

# ===========================
#  PHASE 3-5: URL COLLECTION
# ===========================
collect_urls() {
  phase "Phase 3: Passive URL Collection (gau + wayback)"
  phase_start "3"

  if [ -s "$SUBS/live.txt" ]; then
    cat "$SUBS/live.txt" \
      | timeout 180 gau --threads "$THREADS" --subs 2>/dev/null \
      | anew "$URLS/gau.txt" >/dev/null || true
    ok "GAU URLs: $(count_lines "$URLS/gau.txt")"
  else
    touch "$URLS/gau.txt"
    warn "No live hosts for GAU"
  fi

  cat "$SUBS/resolved_hosts.txt" \
    | timeout 120 waybackurls 2>/dev/null \
    | anew "$URLS/wayback.txt" >/dev/null || true
  ok "Wayback URLs: $(count_lines "$URLS/wayback.txt")"

  phase_end "3"

  phase "Phase 4: Active Crawling (katana)"
  phase_start "4"

  local KATANA_DEPTH=2
  [ "$DEEP_PROBE" = true ] && KATANA_DEPTH=3

  # Katana input: live hosts + whatever gau/wayback already found (passive URLs)
  # so katana also crawls known URLs directly, not just root hosts — this
  # surfaces JS/endpoints those tools didn't fully render.
  cat "$SUBS/live.txt" "$URLS/gau.txt" "$URLS/wayback.txt" 2>/dev/null \
    | grep -E "^https?://" | sort -u > "$URLS/katana_input.txt"

  if [ -s "$URLS/katana_input.txt" ]; then
    katana \
      -list "$URLS/katana_input.txt" \
      -d "$KATANA_DEPTH" \
      -jc \
      -kf all \
      -c "$THREADS" \
      -rl "$RATE_LIMIT" \
      -timeout 10 \
      -silent \
      -o "$URLS/katana.txt" 2>/dev/null || true
    ok "Katana URLs (depth $KATANA_DEPTH, $(count_lines "$URLS/katana_input.txt") seed URLs): $(count_lines "$URLS/katana.txt")"

    if [ "$RUN_GOSPIDER" = true ] && command -v gospider &>/dev/null; then
      log "  -> gospider (extra coverage, -g enabled)..."
      gospider \
        -S "$SUBS/live.txt" \
        -c 10 -d 2 \
        -t "$THREADS" \
        --js -q 2>/dev/null \
        | grep -oE 'https?://[^ ]+' \
        | anew "$URLS/gospider.txt" >/dev/null || true
      ok "GoSpider URLs: $(count_lines "$URLS/gospider.txt")"
    else
      touch "$URLS/gospider.txt"
    fi
  else
    touch "$URLS/katana.txt" "$URLS/gospider.txt"
    warn "No live hosts to crawl — skipping katana/gospider."
  fi

  phase_end "4"

  phase "Phase 5: Parameter Discovery (paramspider)"
  phase_start "5"

  if command -v paramspider &>/dev/null; then
    timeout 120 paramspider -d "$DOMAIN" -q 2>/dev/null
    local PARAM_RESULT
    for f in "results/$DOMAIN.txt" "output/$DOMAIN.txt"; do
      [ -f "$f" ] && PARAM_RESULT="$f" && break
    done
    if [ -n "$PARAM_RESULT" ]; then
      mv "$PARAM_RESULT" "$URLS/params.txt"
      rm -rf results/ output/ 2>/dev/null
      ok "ParamSpider URLs: $(count_lines "$URLS/params.txt")"
    else
      touch "$URLS/params.txt"
    fi
  else
    touch "$URLS/params.txt"
    warn "paramspider not found"
  fi

  cat "$URLS"/*.txt 2>/dev/null \
    | grep -E "^https?://" \
    | sort -u > "$URLS/all_urls.txt"
  ok "Total unique URLs: $(count_lines "$URLS/all_urls.txt")"

  phase_end "5"
}

# ===========================
#  PHASE 6: JS ANALYSIS
# ===========================
analyze_js() {
  phase "Phase 6: JavaScript Analysis"
  phase_start "6"

  # Collect JS URLs from URL corpus
  grep -iE "\.js(\?|$)" "$URLS/all_urls.txt" 2>/dev/null \
    | sort -u > "$JS/js_urls.txt"

  # subjs: per-host timeout to prevent one slow host from stalling all
  if [ -s "$SUBS/live.txt" ] && command -v subjs &>/dev/null; then
    while IFS= read -r host; do
      timeout 10 bash -c "echo '$host' | subjs" 2>/dev/null
    done < "$SUBS/live.txt" | anew "$JS/js_urls.txt" >/dev/null || true
  fi

  ok "JS files found: $(count_lines "$JS/js_urls.txt")"

  if [ -s "$JS/js_urls.txt" ]; then
    local TOTAL_JS
    TOTAL_JS=$(count_lines "$JS/js_urls.txt")
    [ "$TOTAL_JS" -gt 200 ] && TOTAL_JS=200
    CURRENT_TOTAL=$TOTAL_JS

    local START_INDEX
    START_INDEX=$(state_get '.progress.js.last_index')
    [ -z "$START_INDEX" ] && START_INDEX=0

    if [ "$START_INDEX" -eq 0 ]; then
      : > "$JS/endpoints.txt"
      : > "$JS/secrets.txt"
    else
      log "  -> Resuming JS analysis from item $START_INDEX/$TOTAL_JS"
    fi

    # inprogress marker with crash-safe cleanup
    touch "$JS/.in_progress"
    trap 'rm -f "$JS/.in_progress"' RETURN

    local JS_PARALLEL=10
    local SECRET_PATTERN='(api[_-]?key|apikey|secret[_-]?key|access[_-]?token|auth[_-]?token|bearer|aws[_-]?access|aws[_-]?secret|client[_-]?secret|password|passwd|private[_-]?key)["\s:=]+[A-Za-z0-9+/=_-]{10,}'

    fetch_js_one() {
      local jsurl="$1"
      local body
      body=$(curl -s -m 8 -L \
        -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64)" \
        "$jsurl" 2>/dev/null)

      if [ -n "$body" ]; then
        echo "$body" \
          | grep -oE '(https?://[a-zA-Z0-9._/?=&%#@:_-]+)' \
          >> "$JS/endpoints.txt"

        echo "$body" \
          | grep -ioE "$SECRET_PATTERN" \
          | sed "s|^|[JS] $jsurl  ->  |" \
          >> "$JS/secrets.txt"
      fi
    }
    export -f fetch_js_one 2>/dev/null

    local count=0
    while IFS= read -r jsurl; do
      (( count++ ))
      [ "$count" -gt 200 ] && break
      [ "$count" -le "$START_INDEX" ] && continue

      CURRENT_ITEM=$count
      printf "\r  -> JS fetch progress: %d/%d" "$count" "$TOTAL_JS"
      fetch_js_one "$jsurl" &

      if (( count % JS_PARALLEL == 0 )); then
        wait
        state_set '.progress.js.last_index' "$count"
      fi
    done < "$JS/js_urls.txt"
    wait
    echo ""
    state_set '.progress.js.last_index' "$count"

    [ -f "$JS/endpoints.txt" ] && sort -u -o "$JS/endpoints.txt" "$JS/endpoints.txt"
    [ -f "$JS/secrets.txt"   ] && sort -u -o "$JS/secrets.txt" "$JS/secrets.txt"

    # === VALUE-LEVEL DEDUP FOR SECRETS ===
    # secrets.txt has lines like:   [JS] https://x.com/b.js  ->  API_KEY=abc123
    # Line-level sort -u doesn't dedup the actual value across URLs.
    # Extract just the value portion, dedup that.
    if [ -s "$JS/secrets.txt" ]; then
      grep -oP '->\s*\K.*' "$JS/secrets.txt" | sed 's/^ *//' | sort -u > "$JS/secrets_values.txt"
      local RAW_COUNT UNIQUE_COUNT
      RAW_COUNT=$(count_lines "$JS/secrets.txt")
      UNIQUE_COUNT=$(count_lines "$JS/secrets_values.txt")
      ok "JS secrets — raw matches: $RAW_COUNT, unique values: $UNIQUE_COUNT"
      if [ "$UNIQUE_COUNT" -gt 0 ]; then
        warn "⚠ Review $JS/secrets_values.txt for the actual unique secrets"
      fi
    fi

    rm -f "$JS/.in_progress"
  fi

  phase_end "6"
}

# ===========================
#  PHASE 7: FILTER URLS
# ===========================
filter_urls() {
  phase "Phase 7: URL Filtering"
  phase_start "7"

  grep -iE "\.(php|asp|aspx|jsp|json|xml|do|action|cgi)(\?|$)" \
    "$URLS/all_urls.txt" 2>/dev/null \
    | sort -u > "$URLS/filtered.txt" || touch "$URLS/filtered.txt"

  grep -E "\?[a-zA-Z0-9_]+=." "$URLS/all_urls.txt" 2>/dev/null \
    | sort -u > "$URLS/has_params.txt" || touch "$URLS/has_params.txt"

  if command -v qsreplace &>/dev/null; then
    cat "$URLS/has_params.txt" \
      | qsreplace -a 2>/dev/null \
      | sort -u > "$URLS/params_urls.txt" || touch "$URLS/params_urls.txt"
  else
    cp "$URLS/has_params.txt" "$URLS/params_urls.txt"
  fi

  ok "Filtered (ext): $(count_lines "$URLS/filtered.txt") | Parameterized: $(count_lines "$URLS/params_urls.txt")"
  phase_end "7"
}

# ===========================
#  PHASE 8: GF PATTERNS
# ===========================
gf_patterns() {
  phase "Phase 8: GF Pattern Matching"
  phase_start "8"

  local GF_DIR="$HOME/.config/gf"
  local PATTERNS=(xss sqli ssrf lfi rce idor redirect ssti)

  if [ ! -s "$URLS/all_urls.txt" ]; then
    warn "all_urls.txt is empty — skipping gf"
    for pat in "${PATTERNS[@]}"; do touch "$VULN/gf_$pat.txt"; done
    phase_end "8"
    return
  fi

  if [ ! -d "$GF_DIR" ] || [ -z "$(ls -A "$GF_DIR"/*.json 2>/dev/null)" ]; then
    warn "gf patterns missing — run install step first"
    for pat in "${PATTERNS[@]}"; do touch "$VULN/gf_$pat.txt"; done
    phase_end "8"
    return
  fi

  local TOTAL=0
  for pat in "${PATTERNS[@]}"; do
    if gf "$pat" < /dev/null 2>&1 | grep -q "no such pattern"; then
      warn "Pattern '$pat' not found"
      touch "$VULN/gf_$pat.txt"
    else
      cat "$URLS/all_urls.txt" \
        | gf "$pat" 2>/dev/null \
        | sort -u > "$VULN/gf_$pat.txt"
      local c
      c=$(count_lines "$VULN/gf_$pat.txt")
      TOTAL=$((TOTAL + c))
    fi
  done

  ok "GF results — sqli:$(count_lines "$VULN/gf_sqli.txt") xss:$(count_lines "$VULN/gf_xss.txt") ssrf:$(count_lines "$VULN/gf_ssrf.txt") lfi:$(count_lines "$VULN/gf_lfi.txt") rce:$(count_lines "$VULN/gf_rce.txt") idor:$(count_lines "$VULN/gf_idor.txt")"

  if [ "$TOTAL" -eq 0 ]; then
    warn "All gf = 0. Possible causes:"
    warn "  1. URLs collected don't have parameters -> check params_urls.txt"
    warn "  2. gf patterns don't match your target's URL style"
    warn "  Manual: cat $URLS/all_urls.txt | grep '=' | head -5"
  fi

  phase_end "8"
}

# ===========================
#  PHASE 9: NUCLEI
# ===========================
run_nuclei() {
  phase "Phase 9: Nuclei Scanning"
  phase_start "9"

  if ! command -v nuclei &>/dev/null; then
    warn "nuclei not found, skipping."
    touch "$VULN/nuclei.txt"
    phase_end "9"
    return
  fi

  if [ -n "$NUCLEI_UPDATE_PID" ] && kill -0 "$NUCLEI_UPDATE_PID" 2>/dev/null; then
    log "  -> Waiting for nuclei templates update (max 60s)..."
    timeout 60 bash -c "wait $NUCLEI_UPDATE_PID" 2>/dev/null || true
  fi

  local TMPL_DIR="$HOME/nuclei-templates"
  if [ ! -d "$TMPL_DIR" ]; then
    log "  -> Downloading nuclei templates..."
    nuclei -update-templates -silent 2>/dev/null || true
  fi

  if [ ! -s "$SUBS/live.txt" ]; then
    warn "live.txt empty — skipping nuclei"
    touch "$VULN/nuclei.txt"
    phase_end "9"
    return
  fi

  local SEVERITY="medium,high,critical"
  [ "$DEEP_PROBE" = true ] && SEVERITY="low,medium,high,critical"

  log "  -> Running nuclei on $(count_lines "$SUBS/live.txt") targets (severity: $SEVERITY)..."

  nuclei \
    -l "$SUBS/live.txt" \
    -severity "$SEVERITY" \
    -rl "$RATE_LIMIT" \
    -c "$THREADS" \
    -timeout 10 \
    -retries 1 \
    -silent \
    -o "$VULN/nuclei.txt" \
    2>"$VULN/nuclei_errors.txt" || true

  local N_COUNT
  N_COUNT=$(count_lines "$VULN/nuclei.txt")
  ok "Nuclei findings: $N_COUNT"

  # Severity breakdown for report
  local N_CRIT=$(grep -cE '\[critical\]' "$VULN/nuclei.txt" 2>/dev/null || echo 0)
  local N_HIGH=$(grep -cE '\[high\]' "$VULN/nuclei.txt" 2>/dev/null || echo 0)
  local N_MED=$(grep -cE '\[medium\]' "$VULN/nuclei.txt" 2>/dev/null || echo 0)
  ok "  Critical: $N_CRIT | High: $N_HIGH | Medium: $N_MED"
  echo "$N_CRIT:$N_HIGH:$N_MED" > "$VULN/.nuclei_severity_counts"

  if [ "$N_COUNT" -eq 0 ]; then
    warn "Nuclei = 0. Debug:"
    warn "  nuclei -u \$(head -1 $SUBS/live.txt) -severity info -debug 2>&1 | head -30"
    warn "  Check errors: cat $VULN/nuclei_errors.txt | head -20"
  fi

  phase_end "9"
}

# ===========================
#  PHASE 10: FFUF
# ===========================
run_ffuf() {
  phase "Phase 10: Content Discovery (ffuf)"
  phase_start "10"

  if [ ! -f "$WORDLIST" ]; then
    warn "No wordlist found — skipping ffuf."
    phase_end "10"
    return
  fi

  if [ ! -s "$SUBS/live.txt" ]; then
    warn "No live hosts — skipping ffuf."
    phase_end "10"
    return
  fi

  local ACTIVE_WL="$WORDLIST"
  local WL_LINES
  WL_LINES=$(wc -l < "$WORDLIST" 2>/dev/null || echo 0)
  if [ "$WL_LINES" -gt 15000 ]; then
    local FAST_WL
    FAST_WL=$(dirname "$WORDLIST")/common.txt
    if [ -f "$FAST_WL" ]; then
      ACTIVE_WL="$FAST_WL"
      warn "Wordlist too large ($WL_LINES lines) -> using common.txt for speed"
    fi
  fi

  log "  -> ffuf: $MAX_HOSTS hosts, $MAX_PARALLEL parallel, $(basename "$ACTIVE_WL")"

  local START_INDEX
  START_INDEX=$(state_get '.progress.ffuf.last_index')
  [ -z "$START_INDEX" ] && START_INDEX=0
  [ "$START_INDEX" -gt 0 ] && log "  -> Resuming ffuf from host $START_INDEX/$MAX_HOSTS"

  # inprogress marker with crash-safe cleanup
  touch "$VULN/.in_progress"
  trap 'rm -f "$VULN/.in_progress"' RETURN

  CURRENT_TOTAL=$MAX_HOSTS
  local ffuf_count=0
  while IFS= read -r host; do
    (( ffuf_count++ ))
    [ "$ffuf_count" -le "$START_INDEX" ] && continue

    CURRENT_ITEM=$ffuf_count
    local safe
    safe=$(echo "$host" | sed 's|https\?://||; s|[/:?&=]|_|g')

    log "  -> [$ffuf_count/$MAX_HOSTS] ffuf: $host"

    # ============================================================
    # BASELINE CHECK: قبل ffuf بنعمل طلب لعنوان مش موجود عشان نعرف
    # إزاي الـ server بيرد على 404/403 حقيقي. بعدين بنصفي نتايج ffuf
    # من أي hits نفس response size/code بتاعة الـ baseline — ده بيشيل
    # soft-403 catch-all pages اللي بتظهر فجميع المسارات.
    # ============================================================
    (
      # Baseline request for soft-403 detection
      local BASELINE_RAND="SPIDER_RECON_BASELINE_$(date +%s)_$$_${ffuf_count}"
      local BASELINE_FILE
      BASELINE_FILE=$(mktemp)
      local BASELINE_CODE BASELINE_SIZE BASELINE_WORDS

      BASELINE_CODE=$(timeout 10 curl -s -L -o "$BASELINE_FILE" -w "%{http_code}" "${host}/${BASELINE_RAND}" 2>/dev/null)
      if [ -f "$BASELINE_FILE" ]; then
        BASELINE_SIZE=$(wc -c < "$BASELINE_FILE" 2>/dev/null || echo 0)
        BASELINE_WORDS=$(wc -w < "$BASELINE_FILE" 2>/dev/null || echo 0)
      fi
      rm -f "$BASELINE_FILE"

      ffuf \
        -u "${host}/FUZZ" \
        -w "$ACTIVE_WL" \
        -mc 200,204,301,302,307,401,403,405 \
        -t "$FFUF_THREADS" \
        -rate "$FFUF_RATE" \
        -maxtime-job "$JOB_TIMEOUT" \
        -ac \
        -p 0.1 \
        -of json \
        -o "$VULN/ffuf_${safe}.json" \
        -s \
        2>/dev/null

      # Filter out baseline-matching responses from the JSON
      if [ -f "$VULN/ffuf_${safe}.json" ] && [ "${BASELINE_CODE}" != "" ]; then
        local FILTERED
        FILTERED=$(mktemp)
        jq --argjson bc "${BASELINE_CODE:-0}" --argjson bs "${BASELINE_SIZE:-0}" --argjson bw "${BASELINE_WORDS:-0}" '
          .results |= map(select(
            .status != $bc or
            (.length != $bs and .words != $bw)
          ))
        ' "$VULN/ffuf_${safe}.json" > "$FILTERED" 2>/dev/null && mv "$FILTERED" "$VULN/ffuf_${safe}.json"
        rm -f "$FILTERED"
      fi
    ) &

    if (( ffuf_count % MAX_PARALLEL == 0 )); then
      wait
      state_set '.progress.ffuf.last_index' "$ffuf_count"
    fi

  done < <(head -n "$MAX_HOSTS" "$SUBS/live.txt")

  wait
  state_set '.progress.ffuf.last_index' "$ffuf_count"
  rm -f "$VULN/.in_progress"

  local FFUF_FILES
  FFUF_FILES=$(ls "$VULN"/ffuf_*.json 2>/dev/null | wc -l)
  ok "FFUF done — $FFUF_FILES result files in $VULN/"

  : > "$VULN/ffuf_all_found.txt"
  if [ "$FFUF_FILES" -gt 0 ]; then
    for f in "$VULN"/ffuf_*.json; do
      grep -oP '"url"\s*:\s*"\K[^"]+' "$f" 2>/dev/null
    done | sort -u > "$VULN/ffuf_all_found.txt"
    ok "FFUF unique paths found (baseline-filtered): $(count_lines "$VULN/ffuf_all_found.txt")"
  fi

  phase_end "10"
}

# ===========================
#  PHASE 11: XSS PREP
# ===========================
run_xss() {
  phase "Phase 11: XSS Prep (Gxss filter -> manual dalfox command)"
  phase_start "11"

  local SRC=""
  if [ -s "$VULN/gf_xss.txt" ]; then
    SRC="$VULN/gf_xss.txt"
    log "  -> Source: gf_xss.txt ($(count_lines "$SRC") URLs)"
  elif [ -s "$URLS/params_urls.txt" ]; then
    SRC="$URLS/params_urls.txt"
    log "  -> Fallback: params_urls.txt ($(count_lines "$SRC") URLs)"
  else
    warn "No parameterized URLs for XSS prep — skipping."
    phase_end "11"
    return
  fi

  if command -v uro &>/dev/null; then
    cat "$SRC" | uro 2>/dev/null | sort -u > "$VULN/xss_dedup.txt"
  else
    cat "$SRC" | sort -u > "$VULN/xss_dedup.txt"
  fi
  ok "After dedup: $(count_lines "$VULN/xss_dedup.txt") URLs"

  local GXSS_SKIP_THRESHOLD=5000

  if command -v Gxss &>/dev/null && [ -s "$VULN/xss_dedup.txt" ]; then
    local XSS_TOTAL
    XSS_TOTAL=$(count_lines "$VULN/xss_dedup.txt")

    if [ "$XSS_TOTAL" -gt "$GXSS_SKIP_THRESHOLD" ]; then
      warn "Gxss skipped: $XSS_TOTAL URLs > $GXSS_SKIP_THRESHOLD (Gxss is slow/unmaintained at this scale)."
      warn "  dalfox will do its own reflection check instead"
      cp "$VULN/xss_dedup.txt" "$VULN/xss_reflected.txt"
      touch "$VULN/.gxss_skipped"
    else
      log "  -> Running Gxss (reflection check) in batches..."
      local GXSS_BATCH=500
      local total_chunks=$(( (XSS_TOTAL + GXSS_BATCH - 1) / GXSS_BATCH ))
      local start_chunk
      start_chunk=$(state_get '.progress.gxss.last_chunk')
      [ -z "$start_chunk" ] && start_chunk=0

      if [ "$start_chunk" -eq 0 ]; then
        : > "$VULN/xss_reflected.txt"
      else
        log "  -> Resuming Gxss from batch $start_chunk/$total_chunks"
      fi

      local tmp_dir
      tmp_dir=$(mktemp -d)
      split -l "$GXSS_BATCH" "$VULN/xss_dedup.txt" "$tmp_dir/gxss_chunk_"

      local chunk_num=0
      for chunk_file in "$tmp_dir"/gxss_chunk_*; do
        chunk_num=$((chunk_num + 1))
        [ "$chunk_num" -le "$start_chunk" ] && continue
        CURRENT_ITEM=$chunk_num
        CURRENT_TOTAL=$total_chunks
        printf "\r  -> Gxss batch %d/%d" "$chunk_num" "$total_chunks"
        cat "$chunk_file" | timeout 120 Gxss -c 50 2>/dev/null >> "$VULN/xss_reflected.txt"
        state_set '.progress.gxss.last_chunk' "$chunk_num"
      done
      echo ""
      rm -rf "$tmp_dir"
      sort -u -o "$VULN/xss_reflected.txt" "$VULN/xss_reflected.txt"
      rm -f "$VULN/.gxss_skipped"
    fi
    ok "Gxss reflected URLs: $(count_lines "$VULN/xss_reflected.txt")"
  else
    cp "$VULN/xss_dedup.txt" "$VULN/xss_reflected.txt" 2>/dev/null || true
  fi

  local DALFOX_SRC="$VULN/xss_reflected.txt"
  [ ! -s "$DALFOX_SRC" ] && DALFOX_SRC="$VULN/xss_dedup.txt"

  cat > "$VULN/run_dalfox.sh" <<DALFOX_CMD
#!/bin/bash
# ============================================================
#  شغّل الكومند ده يدوي بعد ما تراجع الـ URLs
#  المقترح: اشتغل على أول 100 URL (أسرع وأكثر تركيز)
# ============================================================

# Option 1: أول 100 URL بس (موصى بيه)
head -100 "$DALFOX_SRC" | \\
  dalfox pipe \\
    --worker 20 \\
    --timeout 10 \\
    --delay 200 \\
    --skip-bav \\
    --skip-mining-all \\
    --silence \\
    -o "$VULN/xss_confirmed.txt"

# Option 2: كل الـ URLs (ممكن يأخد ساعات)
# dalfox file "$DALFOX_SRC" \\
#   --worker 20 --timeout 10 --delay 200 \\
#   --skip-bav --skip-mining-all --silence \\
#   -o "$VULN/xss_confirmed.txt"
DALFOX_CMD
  chmod +x "$VULN/run_dalfox.sh"

  ok "XSS prep done:"
  ok "  Reflected URLs : $(count_lines "$VULN/xss_reflected.txt")"
  ok "  Dalfox command : $VULN/run_dalfox.sh  <- شغّله يدوي"
  if [ -f "$VULN/.gxss_skipped" ]; then
    warn "  Gxss was SKIPPED (URLs > $GXSS_SKIP_THRESHOLD) — xss_reflected.txt is RAW, NOT reflection-checked"
  fi
  warn "  dalfox مش بتشتغل تلقائي — راجع الـ URLs الأول وبعدين شغّل run_dalfox.sh"

  phase_end "11"
}

# ===========================
#  FINAL REPORT
# ===========================
report() {
  phase "Final Report"
  local REPORT="$OUT/summary_report.txt"
  local ELAPSED=$(( $(date +%s) - START_TIME ))

  # Count nuclei severity
  local N_CRIT=0 N_HIGH=0 N_MED=0
  if [ -f "$VULN/.nuclei_severity_counts" ]; then
    IFS=':' read -r N_CRIT N_HIGH N_MED < "$VULN/.nuclei_severity_counts"
  fi

  # Count unique JS secret values (not raw line matches)
  local JS_SECRET_UNIQUE=0
  if [ -f "$JS/secrets_values.txt" ]; then
    JS_SECRET_UNIQUE=$(count_lines "$JS/secrets_values.txt")
  elif [ -f "$JS/secrets.txt" ]; then
    JS_SECRET_UNIQUE=$(count_lines "$JS/secrets.txt")
  fi

  {
    echo "================================================"
    echo "       SPIDER-RECON v3.0 — FINAL REPORT"
    echo "================================================"
    echo "Target   : $DOMAIN"
    echo "Date     : $(date)"
    echo "Duration : $((ELAPSED/60))m $((ELAPSED%60))s"
    echo "Output   : $OUT"
    echo ""
    echo "── PHASE TIMINGS ──────────────────────────────"
    for ph in 1 2 3 4 5 6 7 8 9 10 11; do
      local dur="${PHASE_TIMES["${ph}_dur"]}"
      [ -n "$dur" ] && printf "  Phase %-2s : %ss\n" "$ph" "$dur"
    done
    echo ""
    echo "── ASSET DISCOVERY ────────────────────────────"
    printf "  %-30s : %s\n" "Total Subdomains"       "$(count_lines "$SUBS/all.txt")"
    printf "  %-30s : %s\n" "Resolved Subdomains"    "$(count_lines "$SUBS/resolved_hosts.txt")"
    printf "  %-30s : %s\n" "Live Hosts (httpx)"     "$(count_lines "$SUBS/live.txt")"
    printf "  %-30s : %s\n" "Total URLs"             "$(count_lines "$URLS/all_urls.txt")"
    printf "  %-30s : %s\n" "Parameterized URLs"     "$(count_lines "$URLS/params_urls.txt")"
    printf "  %-30s : %s\n" "JS Files"               "$(count_lines "$JS/js_urls.txt")"
    printf "  %-30s : %s\n" "JS Unique Secrets"      "$JS_SECRET_UNIQUE"
    echo ""
    echo "── NUCLEI FINDINGS (by severity) ─────────────"
    printf "  %-30s : %s\n" "Nuclei — Critical"      "$N_CRIT"
    printf "  %-30s : %s\n" "Nuclei — High"          "$N_HIGH"
    printf "  %-30s : %s\n" "Nuclei — Medium"        "$N_MED"
    printf "  %-30s : %s\n" "Nuclei — Total"         "$(count_lines "$VULN/nuclei.txt")"
    echo ""
    echo "── UNVERIFIED PATTERN MATCHES (manual triage required) ──"
    echo "  These are REGEX matches only — none have been dynamically validated."
    echo "  Do not report or act on these without manual verification."
    echo ""
    printf "  %-30s : %s\n" "XSS (gf pattern)"        "$(count_lines "$VULN/gf_xss.txt")"
    printf "  %-30s : %s\n" "SQLi (gf pattern)"       "$(count_lines "$VULN/gf_sqli.txt")"
    printf "  %-30s : %s\n" "SSRF (gf pattern)"       "$(count_lines "$VULN/gf_ssrf.txt")"
    printf "  %-30s : %s\n" "LFI (gf pattern)"        "$(count_lines "$VULN/gf_lfi.txt")"
    printf "  %-30s : %s\n" "RCE (gf pattern)"        "$(count_lines "$VULN/gf_rce.txt")"
    printf "  %-30s : %s\n" "IDOR (gf pattern)"       "$(count_lines "$VULN/gf_idor.txt")"
    printf "  %-30s : %s\n" "Open Redirect (gf)"      "$(count_lines "$VULN/gf_redirect.txt")"
    printf "  %-30s : %s\n" "SSTI (gf pattern)"       "$(count_lines "$VULN/gf_ssti.txt")"
    echo ""
    printf "  %-30s : %s\n" "XSS reflected (Gxss)"    "$(count_lines "$VULN/xss_reflected.txt")"
    if [ -f "$VULN/.gxss_skipped" ]; then
      echo "  ⚠ Gxss was SKIPPED (URL count exceeded threshold) — XSS reflected count is RAW"
      echo "    (not reflection-checked; run dalfox for actual validation)"
    fi
    printf "  %-30s : %s\n" "FFUF paths (baseline-filtered)" "$(count_lines "$VULN/ffuf_all_found.txt")"
    echo ""
    echo "── NEXT STEPS (manual) ───────────────────────"
    [ "$N_CRIT" -gt 0 ] && echo "  Nuclei critical findings:"
    [ "$N_CRIT" -gt 0 ] && echo "    grep -E '\[critical\]' $VULN/nuclei.txt"
    [ "$N_HIGH" -gt 0 ] && echo "  Nuclei high findings:"
    [ "$N_HIGH" -gt 0 ] && echo "    grep -E '\[high\]' $VULN/nuclei.txt"
    [ "$(count_lines "$VULN/xss_reflected.txt")" -gt 0 ] && echo "  XSS verification: bash $VULN/run_dalfox.sh  (يدوي)"
    [ "$JS_SECRET_UNIQUE" -gt 0 ] && echo "  Review unique secrets: cat $JS/secrets_values.txt"
    [ "$(count_lines "$VULN/gf_sqli.txt")" -gt 0 ] && echo "  SQLi triage: cat $VULN/gf_sqli.txt | head -30  -> sqlmap"
    [ "$(count_lines "$VULN/gf_ssrf.txt")" -gt 0 ] && echo "  SSRF triage: cat $VULN/gf_ssrf.txt | head -30"
    [ "$(count_lines "$VULN/gf_lfi.txt")" -gt 0 ] && echo "  LFI triage: cat $VULN/gf_lfi.txt | head -30"
    [ "$(count_lines "$VULN/gf_rce.txt")" -gt 0 ] && echo "  RCE triage: cat $VULN/gf_rce.txt | head -30"
    [ "$(count_lines "$VULN/gf_idor.txt")" -gt 0 ] && echo "  IDOR triage: cat $VULN/gf_idor.txt | head -30"
    [ "$(count_lines "$VULN/ffuf_all_found.txt")" -gt 0 ] && echo "  FFUF paths: cat $VULN/ffuf_all_found.txt"
    echo ""
    echo "  State file kept at: $STATE_FILE"
    echo "  (Delete it manually to force a full fresh scan next run)"
    echo "================================================"
  } | tee "$REPORT"

  ok "Report saved: $REPORT"
}

# ===========================
#  MAIN
# ===========================
main() {
  trap '
    echo -e "\n${YELLOW}${BOLD}[!] Interrupted — saving checkpoint...${NC}"
    jobs -p | xargs -r kill 2>/dev/null
    echo -e "${YELLOW}  Phases completed : $TOTAL_PHASES_DONE/$TOTAL_PHASES"
    echo -e "  Current phase    : ${CURRENT_PHASE_NAME:-N/A}"
    if [ "${CURRENT_TOTAL:-0}" -gt 0 ] 2>/dev/null; then
      echo -e "  Current item     : $CURRENT_ITEM / $CURRENT_TOTAL"
    fi
    echo -e "${NC}\n${GREEN}Checkpoint saved.${NC}\nRun the exact same command again to resume.\n"
    release_lock
    exit 130
  ' INT

  trap 'release_lock' EXIT

  banner
  ensure_jq
  install_dependencies
  detect_wordlists
  setup_dirs

  run_phase "subdomains" enum_subdomains
  run_phase "probe"      probe_hosts
  run_phase "urls"       collect_urls
  run_phase "js"         analyze_js
  run_phase "filter"     filter_urls
  run_phase "gf"         gf_patterns
  run_phase "nuclei"     run_nuclei
  run_phase "ffuf"       run_ffuf
  run_phase "xss"        run_xss

  report
  # State file intentionally kept — delete manually for full fresh scan
  release_lock
  echo -e "\n${GREEN}${BOLD}[✔] Spider-Recon v3.0 done! Output: $OUT${NC}"
  echo -e "${CYAN}State file: $STATE_FILE (kept for resume; delete to force clean start)${NC}"
}

main
