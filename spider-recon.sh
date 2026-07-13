#!/bin/bash
# ============================================================
#  Spider-Recon v2.4  -  Bug Bounty Automation
#  By: Youssef Ashraf
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
TOTAL_PHASES=10
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
  -l   Scope file (in-scope domains, one per line)
  -x   Deep mode (extra httpx ports, katana depth 3, nuclei low severity)
  -g   Also run gospider alongside katana (extra coverage, slower)
  -a   Also run amass passive enum (slow, often redundant with subfinder -all)
  -r   Reset — ignore any saved checkpoint and start fully from scratch
  -h   Show this help

Examples:
  $0 -d example.com
  $0 -d example.com -s -l scope.txt
  $0 -d example.com -x -g -a    # full deep scan, everything on
  $0 -d example.com             # run again with same domain → auto-resumes
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
  warn "Not running as root — naabu may need sudo for SYN scan."
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
# كل حالة السكريبت (المراحل المخلصة + تقدم داخل المراحل الطويلة)
# متخزنة في ملف JSON واحد: output/<domain>/.state.json
# بدل ملفات متفرقة. بيحتوي على checkpoint_version عشان لو
# اتغيرت طريقة الحفظ مستقبلاً، السكريبت يعرف يتعامل مع
# state files قديمة بدل ما يكسر أو يقرأها غلط.
CHECKPOINT_VERSION=1

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
    rm -f "$STATE_FILE" "$JS/.in_progress" "$VULN/.in_progress"
  fi

  if [ ! -f "$STATE_FILE" ]; then
    jq -n --argjson ver "$CHECKPOINT_VERSION" --arg sv "2.9" --arg d "$DOMAIN" --arg t "$(date -Iseconds)" \
      '{checkpoint_version:$ver, script_version:$sv, domain:$d, completed_phases:[], progress:{}, started_at:$t, updated_at:$t}' \
      > "$STATE_FILE"
    return
  fi

  local ver
  ver=$(jq -r '.checkpoint_version // 0' "$STATE_FILE" 2>/dev/null)
  if [ "$ver" != "$CHECKPOINT_VERSION" ]; then
    warn "State file format is old/incompatible (v$ver) — starting fresh (old file kept as .bak)."
    cp "$STATE_FILE" "${STATE_FILE}.v${ver}.bak" 2>/dev/null
    jq -n --argjson ver "$CHECKPOINT_VERSION" --arg sv "2.9" --arg d "$DOMAIN" --arg t "$(date -Iseconds)" \
      '{checkpoint_version:$ver, script_version:$sv, domain:$d, completed_phases:[], progress:{}, started_at:$t, updated_at:$t}' \
      > "$STATE_FILE"
  else
    ok "Found previous run for $DOMAIN — resuming from saved state."
    ok "  Completed so far: $(jq -r '.completed_phases | join(", ")' "$STATE_FILE" 2>/dev/null)"
  fi
}

# state_set '.progress.js.last_index' 80   ← الـ value لازم تبقى JSON صحيح
state_set() {
  local jq_path="$1" jq_value="$2"
  local tmp
  tmp=$(mktemp)
  jq "$jq_path = $jq_value | .updated_at = \"$(date -Iseconds)\"" "$STATE_FILE" > "$tmp" 2>/dev/null && mv "$tmp" "$STATE_FILE"
}

state_get() {
  jq -r "$1 // empty" "$STATE_FILE" 2>/dev/null
}

# lock بسيط عشان تشغيلتين للسكريبت على نفس الدومين في نفس
# الوقت ميكتبوش على نفس الملفات مع بعض
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

# is_phase_done: أول حاجة بيشوفها هي الـ state file نفسه.
# لو مش لاقيها هناك (مثلاً الملف اتحذف بالغلط)، بيعمل "recovery"
# عن طريق فحص لو ملف النتيجة الحقيقي بتاع المرحلة موجود وغير
# فاضي — لو أيوه، يبقى المرحلة خلصت فعلاً ومفيش داعي تتعاد.
is_phase_done() {
  local phase="$1"
  if jq -e --arg p "$phase" '.completed_phases | index($p) != null' "$STATE_FILE" >/dev/null 2>&1; then
    return 0
  fi
  case "$phase" in
    subdomains) [ -s "$SUBS/resolved_hosts.txt" ] ;;
    ports)      [ -f "$PORTS/naabu.txt" ] ;;
    probe)      [ -s "$SUBS/live_detailed.txt" ] ;;
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
    mark_phase_done "$name"   # يسجلها لو كانت مكتشفة بالـ recovery بس مش مسجلة في الـ state
    return
  fi
  log "${BOLD}[$TOTAL_PHASES_DONE/$TOTAL_PHASES — $(( TOTAL_PHASES_DONE * 100 / TOTAL_PHASES ))%] Starting '$name'...${NC}"
  "$@"
  mark_phase_done "$name"
}

# إدارة parallel jobs: بنستخدم "wait -n" (بتستنى أول job يخلص بس،
# مش كلهم) لو bash بتاعنا بيدعمها (4.3+) — ده أسرع وأخف على
# المعالج من الـ polling loop القديم، وبيقلل احتمالية إن jobs
# تتعلق فاضية. لو bash قديمة، بيرجع للـ polling القديم كـ fallback.
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

# فلتر الـ scope لو اتعمل -l
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
  check_tool assetfinder "go install github.com/tomnomnom/assetfinder@latest"
  check_tool amass       "go install -v github.com/owasp-amass/amass/v4/...@master"
  check_tool dnsx        "go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
  check_tool httpx       "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"
  check_tool naabu       "go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
  check_tool gau         "go install github.com/lc/gau/v2/cmd/gau@latest"
  check_tool waybackurls "go install github.com/tomnomnom/waybackurls@latest"
  check_tool katana      "go install github.com/projectdiscovery/katana/cmd/katana@latest"
  check_tool gospider    "go install github.com/jaeles-project/gospider@latest"
  check_tool nuclei      "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
  check_tool ffuf        "go install github.com/ffuf/ffuf/v2@v2.1.0"
  check_tool dalfox      "go install github.com/hahwul/dalfox/v2@latest"
  check_tool gf          "go install github.com/tomnomnom/gf@latest"
  check_tool qsreplace   "go install github.com/tomnomnom/qsreplace@latest"
  check_tool anew        "go install github.com/tomnomnom/anew@latest"
  check_tool unfurl      "go install github.com/tomnomnom/unfurl@latest"
  check_tool subjs       "go install github.com/lc/subjs@latest"
  check_tool Gxss        "go install github.com/KathanP19/Gxss@latest"

  command -v paramspider &>/dev/null || pip install -q paramspider 2>/dev/null
  command -v arjun       &>/dev/null || pip install -q arjun 2>/dev/null
  command -v uro         &>/dev/null || pip install -q uro 2>/dev/null

  # -------------------------------------------------------
  # gf patterns — لازم تكون موجودة وإلا Phase 9 بتطلع صفر
  # -------------------------------------------------------
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

  # nuclei templates في الخلفية
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
      # نفضّل common.txt لأنه أسرع بكثير من raft-medium
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

  # fallback
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
        | |              v2.4  -  Bug Bounty Edition
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
  PORTS="$OUT/ports"
  mkdir -p "$SUBS" "$URLS" "$VULN" "$JS" "$PORTS"

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

  # -------------------------------------------------------
  # PERFORMANCE FIX: الأربع مصادر دي مستقلين عن بعض تمامًا،
  # فبدل ما نستناهم واحد واحد (180+90+135+240 = ~10 دقايق)
  # بنشغلهم كلهم في الخلفية مع بعض ونستنى أبطأ واحد بس.
  # ده لوحده بيقلل وقت المرحلة دي من ~10 دقايق لـ ~4 دقايق.
  # -------------------------------------------------------
  log "  → Launching subfinder + assetfinder + crt.sh + amass in parallel..."

  ( timeout 180 subfinder -d "$DOMAIN" -all -silent \
      -o "$SUBS/subfinder.txt" 2>/dev/null \
      || { warn "subfinder timed out"; touch "$SUBS/subfinder.txt"; } ) &
  local PID_SUB=$!

  ( timeout 90 assetfinder --subs-only "$DOMAIN" 2>/dev/null \
      > "$SUBS/assetfinder.txt" \
      || { warn "assetfinder timed out"; touch "$SUBS/assetfinder.txt"; } ) &
  local PID_ASSET=$!

  (
    touch "$SUBS/crtsh.txt"
    for attempt in 1 2 3; do
      RAW=$(timeout 45 curl -s -L \
        -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64)" \
        --retry 2 --retry-delay 3 \
        "https://crt.sh/?q=%25.$DOMAIN&output=json" 2>/dev/null)

      if echo "$RAW" | grep -q "name_value"; then
        echo "$RAW" \
          | grep -oP '"name_value"\s*:\s*"\K[^"]+' \
          | tr ',' '\n' \
          | sed 's/^\*\.//' \
          | grep -E "(^|\.)${DOMAIN}$" \
          | sort -u > "$SUBS/crtsh.txt"
        break
      fi
      sleep 5
    done
  ) &
  local PID_CRT=$!

  if [ "$RUN_AMASS" = true ]; then
    # amass ابطأ أداة في المجموعة دي بطبيعته (بيستخدم عدد كبير من
    # الـ data sources). بنديله وقت أكبر من الـ per-source timeout
    # اللي بنطلبه منه (-timeout 5) عشان الـ wrapper مايقفلوش قسرًا
    # قبل ما يخلص بشكل نضيف.
    log "  → amass enabled (-a): this can take several minutes, be patient"
    ( timeout 420 amass enum -passive -d "$DOMAIN" -timeout 5 -silent \
        2>/dev/null > "$SUBS/amass.txt" \
        || { warn "amass timed out after 7min — results so far still used"; } ) &
    local PID_AMASS=$!
  else
    log "  → amass skipped (subfinder -all already covers most passive sources; use -a to enable)"
    touch "$SUBS/amass.txt"
    local PID_AMASS=""
  fi

  wait "$PID_SUB" "$PID_ASSET" "$PID_CRT" ${PID_AMASS:+$PID_AMASS} 2>/dev/null

  ok "subfinder: $(count_lines "$SUBS/subfinder.txt")  assetfinder: $(count_lines "$SUBS/assetfinder.txt")  crt.sh: $(count_lines "$SUBS/crtsh.txt")  amass: $(count_lines "$SUBS/amass.txt")"

  # دمج + فلترة scope
  cat "$SUBS"/*.txt 2>/dev/null \
    | grep -E "(^|\.)${DOMAIN}$" \
    | sed 's/^\*\.//' \
    | sort -u > "$SUBS/all_raw.txt"

  # تطبيق scope لو موجود
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

  # DNSx resolution
  log "  → DNSx resolution..."
  if [ -s "$SUBS/all.txt" ]; then
    timeout 300 dnsx \
      -l "$SUBS/all.txt" \
      -silent \
      -t "$THREADS" \
      -retry 2 \
      -resp \
      -o "$SUBS/resolved.txt" 2>/dev/null \
      || cp "$SUBS/all.txt" "$SUBS/resolved.txt"
    # استخرج الأسماء فقط (بدون IP) من output dnsx
    awk '{print $1}' "$SUBS/resolved.txt" | sort -u > "$SUBS/resolved_hosts.txt"
  else
    warn "No subdomains to resolve"
    touch "$SUBS/resolved.txt" "$SUBS/resolved_hosts.txt"
  fi

  ok "Resolved: $(count_lines "$SUBS/resolved_hosts.txt") hosts"
  phase_end "1"
}

# ===========================
#  PHASE 2: PORT SCANNING
# ===========================
scan_ports() {
  phase "Phase 2: Port Scanning"
  phase_start "2"

  if ! command -v naabu &>/dev/null; then
    warn "naabu not found, skipping."
    touch "$PORTS/naabu.txt"
    phase_end "2"
    return
  fi

  if [ ! -s "$SUBS/resolved_hosts.txt" ]; then
    warn "No resolved hosts — skipping port scan."
    touch "$PORTS/naabu.txt"
    phase_end "2"
    return
  fi

  # top-100 ports بدل 1000 — أسرع بكثير
  naabu \
    -l "$SUBS/resolved_hosts.txt" \
    -top-ports 100 \
    -silent \
    -rate "$RATE_LIMIT" \
    -timeout 5 \
    -o "$PORTS/naabu.txt" 2>/dev/null || true

  ok "Open ports: $(count_lines "$PORTS/naabu.txt") entries"

  # -------------------------------------------------------
  # COOLDOWN: naabu SYN scan بمعدل عالي بيخلي مزودات CDN
  # زي Cloudflare تعمل temporary rate-limit/block للـ IP
  # بتاعنا. لو httpx اشتغل فورًا بعده على نفس الـ IPs هيرجع
  # صفر نتايج مش لأن فيه مشكلة، لكن لأنه لسه محظور مؤقتًا.
  # بنستنى شوية قبل ما ندخل على probe_hosts.
  # -------------------------------------------------------
  log "  → Cooldown 30s (يسمح لأي rate-limit مؤقت من CDN يزول قبل httpx)..."
  sleep 30

  phase_end "2"
}

# ===========================
#  PHASE 3: PROBE LIVE HOSTS
# ===========================
# PERFORMANCE FIX: كنا بنحدد 7 ports صريحة (80,443,8080,8443,
# 8000,8888,3000) لكل host، وده بيضاعف وقت الـ probing 7 مرات
# حتى لو أغلب الـ hosts شغالة بس على 80/443.
# دلوقتي: افتراضيًا بنسيب httpx يجرب 80/443 بس (سريع)،
# ولو عايز فحص الـ ports الإضافية استخدم -x (deep probe).
# ===========================
probe_hosts() {
  phase "Phase 3: Probing Live Hosts"
  phase_start "3"

  if [ ! -s "$SUBS/resolved_hosts.txt" ]; then
    warn "No resolved hosts to probe."
    touch "$SUBS/live.txt" "$SUBS/live_detailed.txt"
    phase_end "3"
    return
  fi

  local PORT_ARGS=()
  if [ "$DEEP_PROBE" = true ]; then
    log "  → Deep probe: checking 80,443,8080,8443,8000,8888,3000"
    PORT_ARGS=(-ports "80,443,8080,8443,8000,8888,3000")
  else
    log "  → Fast probe: checking 80,443 only (use -x for extra ports)"
  fi

  httpx \
    -l "$SUBS/resolved_hosts.txt" \
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
    -o "$SUBS/live_detailed.txt" \
    2>"$SUBS/httpx_errors.txt"

  # استخرج URLs فقط (العمود الأول)
  awk '{print $1}' "$SUBS/live_detailed.txt" \
    | grep -E "^https?://" \
    | sort -u > "$SUBS/live.txt"

  local LIVE_COUNT
  LIVE_COUNT=$(count_lines "$SUBS/live.txt")

  # -------------------------------------------------------
  # RETRY: لو رجع صفر رغم وجود resolved hosts، الاحتمال الأقوى
  # إن CDN (Cloudflare) لسه حاطط rate-limit مؤقت بسبب naabu.
  # بنستنى فترة أطول (90s) وبنعيد المحاولة مرة واحدة قبل
  # ما نستسلم ونكمل باقي الـ phases فاضية.
  # -------------------------------------------------------
  if [ "$LIVE_COUNT" -eq 0 ]; then
    warn "Zero live hosts — likely still rate-limited by target's CDN after naabu. Retrying in 90s..."
    sleep 90
    httpx \
      -l "$SUBS/resolved_hosts.txt" \
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
      -o "$SUBS/live_detailed.txt" \
      2>>"$SUBS/httpx_errors.txt"

    awk '{print $1}' "$SUBS/live_detailed.txt" \
      | grep -E "^https?://" \
      | sort -u > "$SUBS/live.txt"
    LIVE_COUNT=$(count_lines "$SUBS/live.txt")
  fi

  ok "Live hosts: $LIVE_COUNT"

  # تحذير لو صفر
  if [ "$LIVE_COUNT" -eq 0 ]; then
    warn "Zero live hosts detected!"
    warn "  Check: $SUBS/httpx_errors.txt"
    warn "  Check: $SUBS/resolved_hosts.txt ($(count_lines "$SUBS/resolved_hosts.txt") entries)"
    warn "  Manual test: httpx -u $DOMAIN -title -status-code"
  fi

  phase_end "3"
}

# ===========================
#  PHASE 4-6: URL COLLECTION
# ===========================
collect_urls() {
  phase "Phase 4: Passive URL Collection (gau + wayback)"
  phase_start "4"

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

  phase_end "4"

  phase "Phase 5: Active Crawling (katana)"
  phase_start "5"

  # -------------------------------------------------------
  # PERFORMANCE FIX: كانت -d 3 (عمق 3) + katana + gospider
  # شغالين على كل الـ live hosts، وده بيعمل تكرار مجهود لأن
  # الأداتين بيعملوا نفس الشغل (crawling) تقريبًا.
  # دلوقتي: katana بس بعمق 2 افتراضيًا (كافي لـ recon أولي)،
  # وgospider بقى اختياري (-g) لو محتاج تغطية إضافية.
  # لو عايز عمق أكبر استخدم -x (deep mode).
  # -------------------------------------------------------
  local KATANA_DEPTH=2
  [ "$DEEP_PROBE" = true ] && KATANA_DEPTH=3

  if [ -s "$SUBS/live.txt" ]; then
    katana \
      -list "$SUBS/live.txt" \
      -d "$KATANA_DEPTH" \
      -jc \
      -kf all \
      -c "$THREADS" \
      -rl "$RATE_LIMIT" \
      -timeout 10 \
      -silent \
      -o "$URLS/katana.txt" 2>/dev/null || true
    ok "Katana URLs (depth $KATANA_DEPTH): $(count_lines "$URLS/katana.txt")"

    if [ "$RUN_GOSPIDER" = true ] && command -v gospider &>/dev/null; then
      log "  → gospider (extra coverage, -g enabled)..."
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
    warn "No live hosts to crawl"
  fi

  phase_end "5"

  phase "Phase 6: Parameter Discovery (paramspider)"
  phase_start "6"

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

  # دمج كل URLs
  cat "$URLS"/*.txt 2>/dev/null \
    | grep -E "^https?://" \
    | sort -u > "$URLS/all_urls.txt"
  ok "Total unique URLs: $(count_lines "$URLS/all_urls.txt")"

  phase_end "6"
}

# ===========================
#  PHASE 7: JS ANALYSIS
# ===========================
# PERFORMANCE FIX: كان فيه loop بيعمل curl لكل ملف JS
# بالتتابع (sequential) — على 200 ملف بـ timeout 10s ده ممكن
# ياخد لحد 33 دقيقة. دلوقتي بنجيب الملفات بالتوازي (10 في
# نفس الوقت) عن طريق background jobs محكومة بـ wait_jobs،
# فالوقت بيقل من ~33 دقيقة لـ ~3-4 دقايق على نفس الـ 200 ملف.
# ===========================
analyze_js() {
  phase "Phase 7: JavaScript Analysis"
  phase_start "7"

  grep -iE "\.js(\?|$)" "$URLS/all_urls.txt" 2>/dev/null \
    | sort -u > "$JS/js_urls.txt"

  if [ -s "$SUBS/live.txt" ] && command -v subjs &>/dev/null; then
    cat "$SUBS/live.txt" \
      | timeout 60 subjs 2>/dev/null \
      | anew "$JS/js_urls.txt" >/dev/null || true
  fi

  ok "JS files found: $(count_lines "$JS/js_urls.txt")"

  if [ -s "$JS/js_urls.txt" ]; then
    local TOTAL_JS
    TOTAL_JS=$(count_lines "$JS/js_urls.txt")
    [ "$TOTAL_JS" -gt 200 ] && TOTAL_JS=200
    CURRENT_TOTAL=$TOTAL_JS

    # last_index في state.json = آخر عنصر اتأكدنا إنه خلص بالكامل
    # (بعد ما دفعة كاملة من الـ parallel jobs تخلص وnستنى wait).
    local START_INDEX
    START_INDEX=$(state_get '.progress.js.last_index')
    [ -z "$START_INDEX" ] && START_INDEX=0

    if [ "$START_INDEX" -eq 0 ]; then
      : > "$JS/endpoints.txt"
      : > "$JS/secrets.txt"
    else
      log "  → Resuming JS analysis from item $START_INDEX/$TOTAL_JS"
    fi
    touch "$JS/.in_progress"

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
      [ "$count" -le "$START_INDEX" ] && continue   # اتعالج خلاص في محاولة سابقة

      CURRENT_ITEM=$count
      printf "\r  → JS fetch progress: %d/%d" "$count" "$TOTAL_JS"
      fetch_js_one "$jsurl" &

      # كل JS_PARALLEL عنصر، نستنى الدفعة تخلص بالكامل (barrier)
      # وبعدين نسجل last_index — ده بيضمن إن الرقم المسجل دقيق
      # 100%، مش تخمين وسط شغل لسه جاري.
      if (( count % JS_PARALLEL == 0 )); then
        wait
        state_set '.progress.js.last_index' "$count"
      fi
    done < "$JS/js_urls.txt"
    wait
    echo ""   # سطر جديد بعد الـ progress counter
    state_set '.progress.js.last_index' "$count"

    [ -f "$JS/endpoints.txt" ] && sort -u -o "$JS/endpoints.txt" "$JS/endpoints.txt"
    [ -f "$JS/secrets.txt"   ] && sort -u -o "$JS/secrets.txt" "$JS/secrets.txt"
    rm -f "$JS/.in_progress"   # المرحلة خلصت بنجاح بالكامل

    local SECRET_COUNT
    SECRET_COUNT=$(count_lines "$JS/secrets.txt")
    if [ "$SECRET_COUNT" -gt 0 ]; then
      warn "⚠ Possible secrets: $SECRET_COUNT — review $JS/secrets.txt"
    fi
  fi

  phase_end "7"
}

# ===========================
#  PHASE 8: FILTER URLS
# ===========================
filter_urls() {
  phase "Phase 8: URL Filtering"
  phase_start "8"

  # URLs بامتدادات مهمة
  grep -iE "\.(php|asp|aspx|jsp|json|xml|do|action|cgi)(\?|$)" \
    "$URLS/all_urls.txt" 2>/dev/null \
    | sort -u > "$URLS/filtered.txt" || touch "$URLS/filtered.txt"

  # URLs بـ parameters فعلية
  grep -E "\?[a-zA-Z0-9_]+=." "$URLS/all_urls.txt" 2>/dev/null \
    | sort -u > "$URLS/has_params.txt" || touch "$URLS/has_params.txt"

  # dedup بـ qsreplace
  if command -v qsreplace &>/dev/null; then
    cat "$URLS/has_params.txt" \
      | qsreplace -a 2>/dev/null \
      | sort -u > "$URLS/params_urls.txt" || touch "$URLS/params_urls.txt"
  else
    cp "$URLS/has_params.txt" "$URLS/params_urls.txt"
  fi

  ok "Filtered (ext): $(count_lines "$URLS/filtered.txt") | Parameterized: $(count_lines "$URLS/params_urls.txt")"
  phase_end "8"
}

# ===========================
#  PHASE 9: GF PATTERNS
# ===========================
gf_patterns() {
  phase "Phase 9: GF Pattern Matching"
  phase_start "9"

  local GF_DIR="$HOME/.config/gf"
  local PATTERNS=(xss sqli ssrf lfi rce idor redirect ssti)

  # تأكد إن في URLs
  if [ ! -s "$URLS/all_urls.txt" ]; then
    warn "all_urls.txt is empty — skipping gf"
    for pat in "${PATTERNS[@]}"; do touch "$VULN/gf_$pat.txt"; done
    phase_end "9"
    return
  fi

  # تأكد من patterns
  if [ ! -d "$GF_DIR" ] || [ -z "$(ls -A "$GF_DIR"/*.json 2>/dev/null)" ]; then
    warn "gf patterns missing — run install step first"
    for pat in "${PATTERNS[@]}"; do touch "$VULN/gf_$pat.txt"; done
    phase_end "9"
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
    warn "  1. URLs collected don't have parameters → check params_urls.txt"
    warn "  2. gf patterns don't match your target's URL style"
    warn "  Manual: cat $URLS/all_urls.txt | grep '=' | head -5"
  fi

  phase_end "9"
}

# ===========================
#  PHASE 10: NUCLEI
# ===========================
# PERFORMANCE FIX: كان بيشغل severity من low لحد critical.
# low بتجيب noise كتير (info disclosure ضعيف، إلخ) من غير
# فايدة حقيقية في bug bounty. افتراضيًا بقى medium+ بس،
# واستخدم -x لو عايز full severity range.
# ===========================
run_nuclei() {
  phase "Phase 10: Nuclei Scanning"
  phase_start "10"

  if ! command -v nuclei &>/dev/null; then
    warn "nuclei not found, skipping."
    touch "$VULN/nuclei.txt"
    phase_end "10"
    return
  fi

  # انتظر template update
  if [ -n "$NUCLEI_UPDATE_PID" ] && kill -0 "$NUCLEI_UPDATE_PID" 2>/dev/null; then
    log "  → Waiting for nuclei templates update (max 60s)..."
    timeout 60 bash -c "wait $NUCLEI_UPDATE_PID" 2>/dev/null || true
  fi

  # تأكد من templates
  local TMPL_DIR="$HOME/nuclei-templates"
  if [ ! -d "$TMPL_DIR" ]; then
    log "  → Downloading nuclei templates..."
    nuclei -update-templates -silent 2>/dev/null || true
  fi

  if [ ! -s "$SUBS/live.txt" ]; then
    warn "live.txt empty — skipping nuclei"
    touch "$VULN/nuclei.txt"
    phase_end "10"
    return
  fi

  local SEVERITY="medium,high,critical"
  [ "$DEEP_PROBE" = true ] && SEVERITY="low,medium,high,critical"

  log "  → Running nuclei on $(count_lines "$SUBS/live.txt") targets (severity: $SEVERITY)..."

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

  if [ "$N_COUNT" -eq 0 ]; then
    warn "Nuclei = 0. Debug:"
    warn "  nuclei -u \$(head -1 $SUBS/live.txt) -severity info -debug 2>&1 | head -30"
    warn "  Check errors: cat $VULN/nuclei_errors.txt | head -20"
  fi

  phase_end "10"
}

# ===========================
#  PHASE 11: FFUF
# ===========================
run_ffuf() {
  phase "Phase 11: Content Discovery (ffuf)"
  phase_start "11"

  if [ ! -f "$WORDLIST" ]; then
    warn "No wordlist found — skipping ffuf."
    phase_end "11"
    return
  fi

  if [ ! -s "$SUBS/live.txt" ]; then
    warn "No live hosts — skipping ffuf."
    phase_end "11"
    return
  fi

  # اختر أسرع wordlist متاحة (common.txt مش raft-medium)
  local ACTIVE_WL="$WORDLIST"
  local WL_LINES
  WL_LINES=$(wc -l < "$WORDLIST" 2>/dev/null || echo 0)
  if [ "$WL_LINES" -gt 15000 ]; then
    local FAST_WL
    FAST_WL=$(dirname "$WORDLIST")/common.txt
    if [ -f "$FAST_WL" ]; then
      ACTIVE_WL="$FAST_WL"
      warn "Wordlist too large ($WL_LINES lines) → using common.txt for speed"
    fi
  fi

  log "  → ffuf: $MAX_HOSTS hosts, $MAX_PARALLEL parallel, $(basename "$ACTIVE_WL")"

  local START_INDEX
  START_INDEX=$(state_get '.progress.ffuf.last_index')
  [ -z "$START_INDEX" ] && START_INDEX=0
  [ "$START_INDEX" -gt 0 ] && log "  → Resuming ffuf from host $START_INDEX/$MAX_HOSTS"
  touch "$VULN/.in_progress"
  CURRENT_TOTAL=$MAX_HOSTS

  local ffuf_count=0
  while IFS= read -r host; do
    (( ffuf_count++ ))
    [ "$ffuf_count" -le "$START_INDEX" ] && continue   # اتفحص خلاص في محاولة سابقة

    CURRENT_ITEM=$ffuf_count
    local safe
    safe=$(echo "$host" | sed 's|https\?://||; s|[/:?&=]|_|g')

    log "  → [$ffuf_count/$MAX_HOSTS] ffuf: $host"

   (
  ffuf \
    -u "${host}/FUZZ" \
    -w "$ACTIVE_WL" \
    -mc 200,204,301,302,307,401,403,405 \
    -t "$FFUF_THREADS" \
    -rate "$FFUF_RATE" \
    -maxtime "$JOB_TIMEOUT" \
    -maxtime-job "$JOB_TIMEOUT" \
    -ac \
    -p 0.1 \
    -of json \
    -o "$VULN/ffuf_${safe}.json" \
    -s \
    2>/dev/null
) &

    # نفس فكرة الـ batch barrier اللي في Phase 7: نستنى دفعة
    # كاملة من MAX_PARALLEL تخلص وبعدين نسجل last_index دقيق.
    if (( ffuf_count % MAX_PARALLEL == 0 )); then
      wait
      state_set '.progress.ffuf.last_index' "$ffuf_count"
    fi

  done < <(head -n "$MAX_HOSTS" "$SUBS/live.txt")

  wait
  state_set '.progress.ffuf.last_index' "$ffuf_count"
  rm -f "$VULN/.in_progress"   # المرحلة خلصت بنجاح بالكامل

  local FFUF_FILES
  FFUF_FILES=$(ls "$VULN"/ffuf_*.json 2>/dev/null | wc -l)
  ok "FFUF done — $FFUF_FILES result files in $VULN/"

  # بننشئ الملف دايمًا (حتى لو فاضي) عشان يبقى مؤشر recovery
  # موثوق — لو مفيش نتايج، الملف بيتعمل فاضي بس موجود، فمرة
  # جاية السكريبت مش هيعتبر المرحلة "لسه محتاجة تتعمل".
  : > "$VULN/ffuf_all_found.txt"
  if [ "$FFUF_FILES" -gt 0 ]; then
    for f in "$VULN"/ffuf_*.json; do
      grep -oP '"url"\s*:\s*"\K[^"]+' "$f" 2>/dev/null
    done | sort -u > "$VULN/ffuf_all_found.txt"
    ok "FFUF unique paths found: $(count_lines "$VULN/ffuf_all_found.txt")"
  fi

  phase_end "11"
}

# ===========================
#  PHASE 12: XSS PREP
# ===========================
run_xss() {
  phase "Phase 12: XSS Prep (Gxss filter → manual dalfox command)"
  phase_start "12"

  local SRC=""
  if [ -s "$VULN/gf_xss.txt" ]; then
    SRC="$VULN/gf_xss.txt"
    log "  → Source: gf_xss.txt ($(count_lines "$SRC") URLs)"
  elif [ -s "$URLS/params_urls.txt" ]; then
    SRC="$URLS/params_urls.txt"
    log "  → Fallback: params_urls.txt ($(count_lines "$SRC") URLs)"
  else
    warn "No parameterized URLs for XSS prep — skipping."
    phase_end "12"
    return
  fi

  if command -v uro &>/dev/null; then
    cat "$SRC" | uro 2>/dev/null | sort -u > "$VULN/xss_dedup.txt"
  else
    cat "$SRC" | sort -u > "$VULN/xss_dedup.txt"
  fi
  ok "After dedup: $(count_lines "$VULN/xss_dedup.txt") URLs"

  if command -v Gxss &>/dev/null && [ -s "$VULN/xss_dedup.txt" ]; then
    log "  → Running Gxss (reflection check)..."
    cat "$VULN/xss_dedup.txt" \
      | Gxss -c 50 2>/dev/null \
      | sort -u > "$VULN/xss_reflected.txt"
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
  ok "  Dalfox command : $VULN/run_dalfox.sh  ← شغّله يدوي"
  warn "  dalfox مش بتشتغل تلقائي — راجع الـ URLs الأول وبعدين شغّل run_dalfox.sh"

  phase_end "12"
}

# ===========================
#  FINAL REPORT
# ===========================
report() {
  phase "Final Report"
  local REPORT="$OUT/summary_report.txt"
  local ELAPSED=$(( $(date +%s) - START_TIME ))

  {
    echo "================================================"
    echo "       SPIDER-RECON v2.5 — FINAL REPORT"
    echo "================================================"
    echo "Target   : $DOMAIN"
    echo "Date     : $(date)"
    echo "Duration : $((ELAPSED/60))m $((ELAPSED%60))s"
    echo "Output   : $OUT"
    echo ""
    echo "── PHASE TIMINGS ──────────────────────────────"
    for ph in 1 2 3 4 5 6 7 8 9 10 11 12; do
      local dur="${PHASE_TIMES["${ph}_dur"]}"
      [ -n "$dur" ] && printf "  Phase %-2s : %ss\n" "$ph" "$dur"
    done
    echo ""
    echo "── ASSET DISCOVERY ────────────────────────────"
    printf "  %-28s : %s\n" "Total Subdomains"    "$(count_lines "$SUBS/all.txt")"
    printf "  %-28s : %s\n" "Resolved Subdomains" "$(count_lines "$SUBS/resolved_hosts.txt")"
    printf "  %-28s : %s\n" "Live Hosts (httpx)"  "$(count_lines "$SUBS/live.txt")"
    printf "  %-28s : %s\n" "Open Ports (naabu)"  "$(count_lines "$PORTS/naabu.txt")"
    printf "  %-28s : %s\n" "Total URLs"          "$(count_lines "$URLS/all_urls.txt")"
    printf "  %-28s : %s\n" "Parameterized URLs"  "$(count_lines "$URLS/params_urls.txt")"
    printf "  %-28s : %s\n" "JS Files"            "$(count_lines "$JS/js_urls.txt")"
    printf "  %-28s : %s\n" "JS Possible Secrets" "$(count_lines "$JS/secrets.txt")"
    echo ""
    echo "── VULNERABILITY CANDIDATES ───────────────────"
    printf "  %-28s : %s\n" "Nuclei"               "$(count_lines "$VULN/nuclei.txt")"
    printf "  %-28s : %s\n" "XSS reflected (Gxss)" "$(count_lines "$VULN/xss_reflected.txt")"
    printf "  %-28s : %s\n" "XSS confirmed (dalfox)" "run $VULN/run_dalfox.sh manually"
    printf "  %-28s : %s\n" "SQLi (gf)"            "$(count_lines "$VULN/gf_sqli.txt")"
    printf "  %-28s : %s\n" "SSRF (gf)"     "$(count_lines "$VULN/gf_ssrf.txt")"
    printf "  %-28s : %s\n" "LFI (gf)"      "$(count_lines "$VULN/gf_lfi.txt")"
    printf "  %-28s : %s\n" "RCE (gf)"      "$(count_lines "$VULN/gf_rce.txt")"
    printf "  %-28s : %s\n" "IDOR (gf)"     "$(count_lines "$VULN/gf_idor.txt")"
    printf "  %-28s : %s\n" "Open Redirect" "$(count_lines "$VULN/gf_redirect.txt")"
    printf "  %-28s : %s\n" "SSTI (gf)"     "$(count_lines "$VULN/gf_ssti.txt")"
    printf "  %-28s : %s\n" "FFUF Paths"    "$(count_lines "$VULN/ffuf_all_found.txt")"
    echo ""
    echo "── NEXT STEPS ─────────────────────────────────"
    [ "$(count_lines "$VULN/nuclei.txt")"        -gt 0 ] && echo "  cat $VULN/nuclei.txt | grep -iE 'critical|high'"
    [ "$(count_lines "$VULN/xss_reflected.txt")" -gt 0 ] && echo "  bash $VULN/run_dalfox.sh  ← XSS verification (يدوي)"
    [ "$(count_lines "$JS/secrets.txt")"         -gt 0 ] && echo "  cat $JS/secrets.txt  ← review manually!"
    [ "$(count_lines "$VULN/gf_sqli.txt")"     -gt 0 ] && echo "  cat $VULN/gf_sqli.txt | head -20  → sqlmap"
    [ "$(count_lines "$VULN/gf_ssrf.txt")"     -gt 0 ] && echo "  cat $VULN/gf_ssrf.txt"
    [ "$(count_lines "$VULN/gf_idor.txt")"     -gt 0 ] && echo "  cat $VULN/gf_idor.txt"
    [ "$(count_lines "$VULN/gf_lfi.txt")"      -gt 0 ] && echo "  cat $VULN/gf_lfi.txt"
    [ "$(count_lines "$VULN/ffuf_all_found.txt")" -gt 0 ] && echo "  cat $VULN/ffuf_all_found.txt"
    echo "================================================"
  } | tee "$REPORT"

  ok "Report saved: $REPORT"
}

# ===========================
#  MAIN
# ===========================
main() {
  # لو المستخدم عمل Ctrl+C:
  #  1. نقفل أي background jobs لسه شغالة (عشان ما تفضلش processes معلقة)
  #  2. نطبعله تفاصيل واضحة: كام phase خلص، هو واقف فين بالظبط،
  #     وعلى أي عنصر بالظبط لو كان جوه phase فيها loop (JS/ffuf)
  #  3. نفك الـ lock عشان يقدر يشغل السكريبت تاني من غير ما يتقفل
  trap '
    echo -e "\n${YELLOW}${BOLD}[!] Interrupted — saving checkpoint...${NC}"
    jobs -p | xargs -r kill 2>/dev/null
    echo -e "${YELLOW}  Phases completed : $TOTAL_PHASES_DONE/$TOTAL_PHASES"
    echo -e "  Current phase    : ${CURRENT_PHASE_NAME:-N/A}"
    if [ "${CURRENT_TOTAL:-0}" -gt 0 ] 2>/dev/null; then
      echo -e "  Current item     : $CURRENT_ITEM / $CURRENT_TOTAL"
    fi
    echo -e "${NC}\n${GREEN}Checkpoint saved successfully.${NC}\nRun the exact same command again to resume.\n"
    release_lock
    exit 130
  ' INT

  # لو السكريبت اتقفل بأي طريقة تانية (error، kill عادي، إلخ)
  # برضو نفك الـ lock عشان تشغيلة جديدة متتقفلش من غير داعي
  trap 'release_lock' EXIT

  banner
  ensure_jq
  install_dependencies
  detect_wordlists
  setup_dirs

  run_phase "subdomains" enum_subdomains
  run_phase "ports"      scan_ports
  run_phase "probe"      probe_hosts
  run_phase "urls"       collect_urls
  run_phase "js"         analyze_js
  run_phase "filter"     filter_urls
  run_phase "gf"         gf_patterns
  run_phase "nuclei"     run_nuclei
  run_phase "ffuf"       run_ffuf
  run_phase "xss"        run_xss

  report
  rm -f "$STATE_FILE"   # خلص كل حاجة بنجاح → مرة جاية هتبقى scan جديد مش resume
  release_lock
  echo -e "\n${GREEN}${BOLD}[✔] Spider-Recon v2.9 done! Output: $OUT${NC}"
}

main
