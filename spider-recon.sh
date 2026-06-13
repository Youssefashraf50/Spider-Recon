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
  -h   Show this help

Examples:
  $0 -d example.com
  $0 -d example.com -s -l scope.txt
USAGE
exit 1
}

# ===========================
#  ARGUMENTS
# ===========================
while getopts "d:l:sh" opt; do
  case $opt in
    d) DOMAIN=$OPTARG ;;
    l) SCOPE_FILE=$OPTARG ;;
    s) SLOW=true ;;
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
  [ -f "$1" ] && grep -c "" "$1" 2>/dev/null || echo 0
}

# portable wait: استنى لحد ما عدد background jobs يقل عن MAX
wait_jobs() {
  local max="${1:-$MAX_PARALLEL}"
  while true; do
    local running
    running=$(jobs -r 2>/dev/null | wc -l)
    [ "$running" -lt "$max" ] && break
    sleep 0.3
  done
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
  if ! command -v "$TOOL" &>/dev/null; then
    warn "$TOOL not found — installing..."
    eval "$INSTALL_CMD" &>/dev/null \
      && ok "$TOOL installed." \
      || err "Failed to install $TOOL (continuing)."
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
  check_tool ffuf        "go install github.com/ffuf/ffuf/v2@latest"
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
  ok "Output directory: $OUT"
}

# ===========================
#  PHASE 1: SUBDOMAIN ENUMERATION
# ===========================
enum_subdomains() {
  phase "Phase 1: Subdomain Enumeration"
  phase_start "1"

  log "  → subfinder..."
  timeout 180 subfinder -d "$DOMAIN" -all -silent \
    -o "$SUBS/subfinder.txt" 2>/dev/null \
    || { warn "subfinder timed out"; touch "$SUBS/subfinder.txt"; }

  log "  → assetfinder..."
  timeout 90 assetfinder --subs-only "$DOMAIN" 2>/dev/null \
    > "$SUBS/assetfinder.txt" \
    || { warn "assetfinder timed out"; touch "$SUBS/assetfinder.txt"; }

  # crt.sh — retry x3
  log "  → crt.sh..."
  touch "$SUBS/crtsh.txt"
  for attempt in 1 2 3; do
    local RAW
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
      ok "crt.sh: $(count_lines "$SUBS/crtsh.txt") subdomains"
      break
    fi
    warn "crt.sh attempt $attempt failed, retrying..."
    sleep 5
  done

  # amass — passive فقط
  if [ "$SLOW" = false ]; then
    log "  → amass (passive, 4min timeout)..."
    timeout 240 amass enum -passive -d "$DOMAIN" -timeout 3 -silent \
      2>/dev/null > "$SUBS/amass.txt" \
      || { warn "amass timed out"; touch "$SUBS/amass.txt"; }
  else
    warn "  → amass skipped in slow mode"
    touch "$SUBS/amass.txt"
  fi

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
  phase_end "2"
}

# ===========================
#  PHASE 3: PROBE LIVE HOSTS
# ===========================
# FIX: المشكلة الأصلية كانت إن httpx بياخد http+https لكل subdomain
# وده بيضاعف الـ load ويخلي الـ results فيها تكرار.
# الحل: httpx بيجرب الاتنين لوحده لو مش اتحدد protocol.
# بس لازم نديه الأسماء بدون proto وهو يشوف.
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

  # httpx بياخد hostnames + ports صريحة
  # بدون -ports بيجرب 80 بس وده السبب في 0 live hosts
  httpx \
    -l "$SUBS/resolved_hosts.txt" \
    -ports 80,443,8080,8443,8000,8888,3000 \
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
      | gau --threads "$THREADS" --subs 2>/dev/null \
      | anew "$URLS/gau.txt" >/dev/null || true
    ok "GAU URLs: $(count_lines "$URLS/gau.txt")"
  else
    touch "$URLS/gau.txt"
    warn "No live hosts for GAU"
  fi

  cat "$SUBS/resolved_hosts.txt" \
    | waybackurls 2>/dev/null \
    | anew "$URLS/wayback.txt" >/dev/null || true
  ok "Wayback URLs: $(count_lines "$URLS/wayback.txt")"

  phase_end "4"

  phase "Phase 5: Active Crawling (katana + gospider)"
  phase_start "5"

  if [ -s "$SUBS/live.txt" ]; then
    katana \
      -list "$SUBS/live.txt" \
      -d 3 \
      -jc \
      -kf all \
      -c "$THREADS" \
      -rl "$RATE_LIMIT" \
      -timeout 10 \
      -silent \
      -o "$URLS/katana.txt" 2>/dev/null || true
    ok "Katana URLs: $(count_lines "$URLS/katana.txt")"

    if command -v gospider &>/dev/null; then
      gospider \
        -S "$SUBS/live.txt" \
        -c 10 -d 2 \
        -t "$THREADS" \
        --js -q 2>/dev/null \
        | grep -oE 'https?://[^ ]+' \
        | anew "$URLS/gospider.txt" >/dev/null || true
      ok "GoSpider URLs: $(count_lines "$URLS/gospider.txt")"
    fi
  else
    touch "$URLS/katana.txt" "$URLS/gospider.txt"
    warn "No live hosts to crawl"
  fi

  phase_end "5"

  phase "Phase 6: Parameter Discovery (paramspider)"
  phase_start "6"

  if command -v paramspider &>/dev/null; then
    paramspider -d "$DOMAIN" -q 2>/dev/null
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
analyze_js() {
  phase "Phase 7: JavaScript Analysis"
  phase_start "7"

  grep -iE "\.js(\?|$)" "$URLS/all_urls.txt" 2>/dev/null \
    | sort -u > "$JS/js_urls.txt"

  if [ -s "$SUBS/live.txt" ] && command -v subjs &>/dev/null; then
    cat "$SUBS/live.txt" \
      | subjs 2>/dev/null \
      | anew "$JS/js_urls.txt" >/dev/null || true
  fi

  ok "JS files found: $(count_lines "$JS/js_urls.txt")"

  if [ -s "$JS/js_urls.txt" ]; then
    local count=0
    while IFS= read -r jsurl; do
      (( count++ ))
      [ "$count" -gt 200 ] && break

      local body
      body=$(curl -s -m 10 -L \
        -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64)" \
        "$jsurl" 2>/dev/null)

      [ -z "$body" ] && continue

      # endpoints
      echo "$body" \
        | grep -oE '(https?://[a-zA-Z0-9._/?=&%#@:_-]+)' \
        >> "$JS/endpoints.txt"

      # secrets — patterns بدون trailing backslash
      local SECRET_PATTERN='(api[_-]?key|apikey|secret[_-]?key|access[_-]?token|auth[_-]?token|bearer|aws[_-]?access|aws[_-]?secret|client[_-]?secret|password|passwd|private[_-]?key)["\s:=]+[A-Za-z0-9+/=_-]{10,}'
      echo "$body" \
        | grep -ioE "$SECRET_PATTERN" \
        | sed "s|^|[JS] $jsurl  ->  |" \
        >> "$JS/secrets.txt"

    done < "$JS/js_urls.txt"

    [ -f "$JS/endpoints.txt" ] && sort -u -o "$JS/endpoints.txt" "$JS/endpoints.txt"
    [ -f "$JS/secrets.txt"   ] && sort -u -o "$JS/secrets.txt" "$JS/secrets.txt"

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
# FIX:
#   - انتظر templates update
#   - بيشتغل على live.txt مع limit معقول
#   - بيحدد severity
#   - بيكتب errors منفصلة
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

  log "  → Running nuclei on $(count_lines "$SUBS/live.txt") targets..."

  nuclei \
    -l "$SUBS/live.txt" \
    -severity low,medium,high,critical \
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
# FIX: المشكلة الأصلية:
#   - "wait -n" مش شغالة في bash < 4.3
#   - بياخد wordlist كبيرة حتى لو في خيار أصغر
#   - مفيش timeout على كل host بشكل صريح
#
# الحل:
#   - wait_jobs() portable بدون "wait -n"
#   - اختيار تلقائي لأصغر wordlist متاحة
#   - timeout واضح لكل job
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

  local ACTIVE_JOBS=0
  while IFS= read -r host; do
    local safe
    safe=$(echo "$host" | sed 's|https\?://||; s|[/:?&=]|_|g')

    log "  → ffuf: $host"

    (
      timeout "$JOB_TIMEOUT" ffuf \
        -u "${host}/FUZZ" \
        -w "$ACTIVE_WL" \
        -mc 200,204,301,302,307,401,403,405 \
        -t "$FFUF_THREADS" \
        -rate "$FFUF_RATE" \
        -maxtime-job "$((JOB_TIMEOUT - 10))" \
        -ac \
        -p 0.1 \
        -of json \
        -o "$VULN/ffuf_${safe}.json" \
        -s \
        2>/dev/null
    ) &

    ACTIVE_JOBS=$((ACTIVE_JOBS + 1))

    # wait_jobs portable — بدل "wait -n"
    if [ "$ACTIVE_JOBS" -ge "$MAX_PARALLEL" ]; then
      wait_jobs "$MAX_PARALLEL"
      # مش بنقلل ACTIVE_JOBS هنا لأن wait_jobs بتستنى لحد ما يقل
      ACTIVE_JOBS=$(jobs -r 2>/dev/null | wc -l)
    fi

  done < <(head -n "$MAX_HOSTS" "$SUBS/live.txt")

  # استنى كل background jobs
  wait

  local FFUF_FILES
  FFUF_FILES=$(ls "$VULN"/ffuf_*.json 2>/dev/null | wc -l)
  ok "FFUF done — $FFUF_FILES result files in $VULN/"

  # استخرج الـ paths الفعلية من JSON
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
# dalfox اتشالت من الأسكريبت عمداً:
#   - على 3000+ URL بتاخد ساعات بلا نهاية
#   - هي أداة verification مش discovery
#   - الأفضل تشغلها يدوي على subset مختار بعد ما تراجع gf_xss.txt
#
# الـ phase دي بتعمل:
#   1. dedup للـ URLs بـ uro
#   2. فلترة reflective بـ Gxss
#   3. كتابة command جاهز تشغله يدوي
# ===========================
run_xss() {
  phase "Phase 12: XSS Prep (Gxss filter → manual dalfox command)"
  phase_start "12"

  # مصدر الـ URLs
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

  # dedup بـ uro
  if command -v uro &>/dev/null; then
    cat "$SRC" | uro 2>/dev/null | sort -u > "$VULN/xss_dedup.txt"
  else
    cat "$SRC" | sort -u > "$VULN/xss_dedup.txt"
  fi
  ok "After dedup: $(count_lines "$VULN/xss_dedup.txt") URLs"

  # Gxss — فلتر اللي بيعكس input فعلاً (أسرع بكثير من dalfox)
  if command -v Gxss &>/dev/null && [ -s "$VULN/xss_dedup.txt" ]; then
    log "  → Running Gxss (reflection check)..."
    cat "$VULN/xss_dedup.txt" \
      | Gxss -c 50 2>/dev/null \
      | sort -u > "$VULN/xss_reflected.txt"
    ok "Gxss reflected URLs: $(count_lines "$VULN/xss_reflected.txt")"
  else
    cp "$VULN/xss_dedup.txt" "$VULN/xss_reflected.txt" 2>/dev/null || true
  fi

  # اكتب command جاهز للـ report
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
    echo "       SPIDER-RECON v2.3 — FINAL REPORT"
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
  banner
  install_dependencies
  detect_wordlists
  setup_dirs
  enum_subdomains
  scan_ports
  probe_hosts
  collect_urls
  analyze_js
  filter_urls
  gf_patterns
  run_nuclei
  run_ffuf
  run_xss
  report
  echo -e "\n${GREEN}${BOLD}[✔] Spider-Recon v2.3 done! Output: $OUT${NC}"
}

main
