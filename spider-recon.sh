#!/bin/bash
# ============================================================
#  Spider-Recon v2.1  -  Enhanced Bug Bounty Automation
#  By: Youssef Ashraf  (enhanced edition)
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

# ===========================
#  COLORS
# ===========================
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

log()  { echo -e "${CYAN}[$(date +%H:%M:%S)]${NC} $1"; }
ok()   { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[-]${NC} $1"; }

# ===========================
#  USAGE
# ===========================
usage() {
cat <<USAGE
Usage: $0 -d domain.com [options]

Options:
  -d   Target domain (required)
  -s   Slow mode (lower threads / rate-limit, stealthier)
  -l   Scope file (list of in-scope domains, one per line)
  -h   Show this help

Example:
  $0 -d example.com
  $0 -d example.com -s
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
  RATE_LIMIT=50
else
  THREADS=100
  RATE_LIMIT=150
fi

# ===========================
#  ROOT CHECK
# ===========================
if [ "$EUID" -ne 0 ]; then
  warn "Not running as root. Some tools (naabu) may need privileges."
fi

# ===========================
#  HELPERS
# ===========================
count_lines() { [ -f "$1" ] && wc -l < "$1" || echo 0; }

# ===========================
#  TOOL CHECKER
# ===========================
check_tool() {
  local TOOL=$1
  local INSTALL_CMD=$2
  if ! command -v "$TOOL" &>/dev/null; then
    warn "$TOOL not found. Installing..."
    eval "$INSTALL_CMD" &>/dev/null && ok "$TOOL installed." || err "Failed to install $TOOL (continuing)."
  else
    ok "$TOOL is installed."
  fi
}

install_dependencies() {
  log "${BOLD}Checking dependencies...${NC}"
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
  # تحديث nuclei templates في الخلفية
  command -v nuclei &>/dev/null && nuclei -update-templates -silent &>/dev/null &
}

# ===========================
#  WORDLIST DETECTION
# ===========================
detect_wordlists() {
  for base in "/home/kali/SecLists" "/home/kali/seclists" "/usr/share/seclists" "/opt/SecLists"; do
    if [ -d "$base" ]; then
      WORDLIST="$base/Discovery/Web-Content/raft-medium-directories.txt"
      [ -f "$WORDLIST" ] || WORDLIST="$base/Discovery/Web-Content/common.txt"
      return
    fi
  done
  WORDLIST="/usr/share/wordlists/dirb/common.txt"
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
        | |              v2.1  -  Bug Bounty Edition
        |_|              By: Youssef Ashraf
EOF
}

# ===========================
#  OUTPUT STRUCTURE
# ===========================
setup_dirs() {
  OUT="output/$DOMAIN"
  SUBS="$OUT/subs"; URLS="$OUT/urls"; VULN="$OUT/vuln"
  JS="$OUT/js"; PORTS="$OUT/ports"
  mkdir -p "$SUBS" "$URLS" "$VULN" "$JS" "$PORTS"
}

# ===========================
#  PHASE 1: SUBDOMAIN ENUMERATION
# ===========================
enum_subdomains() {
  log "${BOLD}Phase 1: Subdomain Enumeration${NC}"

  log "  → subfinder..."
  timeout 180 subfinder -d "$DOMAIN" -all -silent -o "$SUBS/subfinder.txt" 2>/dev/null || warn "subfinder timed out"

  log "  → assetfinder..."
  timeout 120 assetfinder --subs-only "$DOMAIN" 2>/dev/null > "$SUBS/assetfinder.txt" || warn "assetfinder timed out"

  log "  → crt.sh..."
  timeout 60 curl -s "https://crt.sh/?q=%25.$DOMAIN&output=json" 2>/dev/null \
    | grep -oE "[a-zA-Z0-9._-]+\.$DOMAIN" | sort -u > "$SUBS/crtsh.txt" 2>/dev/null || warn "crt.sh timed out (تخطّيناه)"

  if [ "$SLOW" = false ]; then
    log "  → amass (passive, max 5min)..."
    timeout 300 amass enum -passive -d "$DOMAIN" -silent 2>/dev/null > "$SUBS/amass.txt" || warn "amass timed out (تخطّيناه)"
  else
    warn "  → amass متخطّى في الوضع السريع"
    touch "$SUBS/amass.txt"
  fi

  cat "$SUBS"/*.txt 2>/dev/null | grep -E "\.?$DOMAIN$" | sort -u > "$SUBS/all.txt"
  ok "تم جمع $(count_lines "$SUBS/all.txt") subdomain"

  log "  → DNSx resolution..."
  if [ -s "$SUBS/all.txt" ]; then
    timeout 300 dnsx -l "$SUBS/all.txt" -silent -t "$THREADS" -o "$SUBS/resolved.txt" 2>/dev/null \
      || cp "$SUBS/all.txt" "$SUBS/resolved.txt"
  else
    touch "$SUBS/resolved.txt"
  fi

  ok "Total: $(count_lines "$SUBS/all.txt") | Resolved: $(count_lines "$SUBS/resolved.txt")"
}

# ===========================
#  PHASE 2: PORT SCANNING
# ===========================
scan_ports() {
  log "${BOLD}Phase 2: Port Scanning (top 1000)${NC}"
  if command -v naabu &>/dev/null; then
    naabu -l "$SUBS/resolved.txt" -top-ports 1000 -silent -rate "$RATE_LIMIT" \
      -o "$PORTS/naabu.txt" 2>/dev/null || true
    ok "Open ports saved to $PORTS/naabu.txt"
  else
    warn "naabu not available, skipping port scan."
  fi
}

# ===========================
#  PHASE 3: PROBE LIVE HOSTS
# ===========================
probe_hosts() {
  log "${BOLD}Phase 3: Probing Live Hosts${NC}"

  while read -r sub; do
    echo "http://$sub"
    echo "https://$sub"
  done < "$SUBS/resolved.txt" > "$SUBS/resolved_with_proto.txt"

  httpx -l "$SUBS/resolved_with_proto.txt" \
    -threads "$THREADS" \
    -rate-limit "$RATE_LIMIT" \
    -timeout 10 \
    -retries 2 \
    -silent \
    -title -status-code -tech-detect -cdn -follow-redirects \
    -o "$SUBS/live_detailed.txt" 2>/dev/null

  awk '{print $1}' "$SUBS/live_detailed.txt" | sort -u > "$SUBS/live.txt"
  ok "Live hosts: $(count_lines "$SUBS/live.txt")"
}

# ===========================
#  PHASE 4-6: URL COLLECTION
# ===========================
collect_urls() {
  log "${BOLD}Phase 4: URL Collection (passive)${NC}"
  cat "$SUBS/live.txt" | gau --threads "$THREADS" 2>/dev/null | anew "$URLS/gau.txt" >/dev/null || true
  cat "$SUBS/resolved.txt" | waybackurls 2>/dev/null | anew "$URLS/wayback.txt" >/dev/null || true

  log "${BOLD}Phase 5: Active Crawling${NC}"
  katana -list "$SUBS/live.txt" -d 3 -jc -kf all -c "$THREADS" -rl "$RATE_LIMIT" \
    -silent -o "$URLS/katana.txt" 2>/dev/null || true
  if command -v gospider &>/dev/null; then
    gospider -S "$SUBS/live.txt" -c 10 -d 2 -t "$THREADS" --js -q 2>/dev/null \
      | grep -oE 'https?://[^ ]+' | anew "$URLS/gospider.txt" >/dev/null || true
  fi

  log "${BOLD}Phase 6: Parameter Discovery${NC}"
  paramspider -d "$DOMAIN" 2>/dev/null
  [ -f "results/$DOMAIN.txt" ] && mv "results/$DOMAIN.txt" "$URLS/params.txt" && rm -rf results/
  [ -f "$URLS/params.txt" ] || touch "$URLS/params.txt"

  cat "$URLS"/*.txt 2>/dev/null | sort -u > "$URLS/all_urls.txt"
  ok "Total unique URLs: $(count_lines "$URLS/all_urls.txt")"
}

# ===========================
#  PHASE 7: JS ANALYSIS
# ===========================
analyze_js() {
  log "${BOLD}Phase 7: JavaScript Analysis (secrets/endpoints)${NC}"
  grep -iE "\.js(\?|$)" "$URLS/all_urls.txt" | sort -u > "$JS/js_urls.txt"
  cat "$SUBS/live.txt" | subjs 2>/dev/null | anew "$JS/js_urls.txt" >/dev/null || true

  if [ -s "$JS/js_urls.txt" ]; then
    while read -r jsurl; do
      body=$(curl -s -m 10 "$jsurl")
      echo "$body" | grep -oE "(https?://[a-zA-Z0-9./?=_-]+)" >> "$JS/endpoints.txt"
      echo "$body" | grep -ioE "(api[_-]?key|secret|token|passwd|password|aws_access|bearer)[\"':= ]+[A-Za-z0-9_\-]{8,}" \
        | sed "s|^|$jsurl  ->  |" >> "$JS/secrets.txt"
    done < <(head -n 200 "$JS/js_urls.txt")
    [ -f "$JS/endpoints.txt" ] && sort -u -o "$JS/endpoints.txt" "$JS/endpoints.txt"
    [ -f "$JS/secrets.txt" ] && warn "Possible secrets found: $(count_lines "$JS/secrets.txt") (review $JS/secrets.txt)"
  fi
}

# ===========================
#  PHASE 8: FILTER URLS
# ===========================
filter_urls() {
  log "${BOLD}Phase 8: Filtering Interesting URLs${NC}"
  grep -iE "\.(php|asp|aspx|jsp|json|do|action|cgi)(\?|$)" "$URLS/all_urls.txt" > "$URLS/filtered.txt" 2>/dev/null
  grep -E "\?[a-zA-Z0-9_]+=" "$URLS/all_urls.txt" | qsreplace -a 2>/dev/null | sort -u > "$URLS/params_urls.txt"
  ok "Filtered URLs: $(count_lines "$URLS/filtered.txt") | Parameterized: $(count_lines "$URLS/params_urls.txt")"
}

# ===========================
#  PHASE 9: GF PATTERNS
# ===========================
gf_patterns() {
  log "${BOLD}Phase 9: GF Pattern Matching${NC}"
  for pat in xss sqli ssrf lfi rce idor redirect ssti; do
    cat "$URLS/all_urls.txt" | gf "$pat" 2>/dev/null | sort -u > "$VULN/gf_$pat.txt"
  done
  ok "GF: sqli=$(count_lines "$VULN/gf_sqli.txt") xss=$(count_lines "$VULN/gf_xss.txt") ssrf=$(count_lines "$VULN/gf_ssrf.txt") lfi=$(count_lines "$VULN/gf_lfi.txt")"
}

# ===========================
#  PHASE 10: NUCLEI
# ===========================
run_nuclei() {
  log "${BOLD}Phase 10: Nuclei Scanning${NC}"
  if command -v nuclei &>/dev/null; then
    wait  # نتأكد إن الـ templates خلصت تحديث
    nuclei -l "$SUBS/live.txt" -severity low,medium,high,critical \
      -rl "$RATE_LIMIT" -c "$THREADS" -silent -o "$VULN/nuclei.txt" 2>/dev/null || true
    ok "Nuclei findings: $(count_lines "$VULN/nuclei.txt")"
  else
    warn "nuclei not available, skipping."
  fi
}

# ===========================
#  PHASE 11: FFUF CONTENT DISCOVERY
#  [PATCHED] timeout per host + max 5 hosts + maxtime-job
# ===========================
run_ffuf() {
  log "${BOLD}Phase 11: Content Discovery (ffuf)${NC}"
  if [ ! -f "$WORDLIST" ]; then
    warn "Wordlist not found at $WORDLIST, skipping FFUF."
    return
  fi

  # في الـ slow mode نشتغل على 3 hosts بس وrate أقل
  local MAX_HOSTS=5
  local FFUF_THREADS=50
  local FFUF_RATE=$RATE_LIMIT
  local JOB_TIMEOUT=90
  local HOST_TIMEOUT=120

  if $SLOW; then
    MAX_HOSTS=3
    FFUF_THREADS=20
    FFUF_RATE=30
    JOB_TIMEOUT=60
    HOST_TIMEOUT=80
  fi

  head -n "$MAX_HOSTS" "$SUBS/live.txt" | while read -r host; do
    safe=$(echo "$host" | sed 's|https\?://||; s|/|_|g')
    log "  → ffuf: $host"
    timeout "$HOST_TIMEOUT" ffuf \
      -u "${host}/FUZZ" \
      -w "$WORDLIST" \
      -mc 200,204,301,302,307,401,403,405 \
      -t "$FFUF_THREADS" \
      -rate "$FFUF_RATE" \
      -maxtime-job "$JOB_TIMEOUT" \
      -ac \
      -p 0.1 \
      -of json \
      -o "$VULN/ffuf_${safe}.json" \
      2>/dev/null || warn "  → ffuf timeout/skip: $host"
  done

  ok "FFUF results saved to $VULN/ffuf_*.json"
}

# ===========================
#  PHASE 12: XSS SCAN (Optimized Pipeline)
#  Gxss (reflection filter) -> uro (dedup) -> dalfox
# ===========================
run_xss() {
  log "${BOLD}Phase 12: XSS Scanning (Optimized: Gxss -> uro -> dalfox)${NC}"

  local SRC="$VULN/gf_xss.txt"
  [ -s "$SRC" ] || SRC="$URLS/params_urls.txt"

  if [ ! -s "$SRC" ]; then
    warn "No URLs with parameters to test for XSS, skipping."
    touch "$VULN/xss.txt"
    return
  fi

  if command -v uro &>/dev/null; then
    cat "$SRC" | uro 2>/dev/null | sort -u > "$VULN/xss_dedup.txt"
  else
    cat "$SRC" | qsreplace -a 2>/dev/null | sort -u > "$VULN/xss_dedup.txt"
  fi
  ok "بعد uro dedup: $(count_lines "$VULN/xss_dedup.txt") URLs"

  if command -v Gxss &>/dev/null; then
    cat "$VULN/xss_dedup.txt" | Gxss -c 50 2>/dev/null | sort -u > "$VULN/xss_reflected.txt"
    if [ -s "$VULN/xss_reflected.txt" ]; then
      cp "$VULN/xss_reflected.txt" "$VULN/xss_targets.txt"
    else
      cp "$VULN/xss_dedup.txt" "$VULN/xss_targets.txt"
    fi
  else
    cp "$VULN/xss_dedup.txt" "$VULN/xss_targets.txt"
  fi
  ok "Targets نهائية للـ dalfox: $(count_lines "$VULN/xss_targets.txt") URLs"

  dalfox file "$VULN/xss_targets.txt" \
    --worker 100 \
    --timeout 5 \
    --delay 0 \
    --skip-bav \
    --skip-mining-all \
    --silence \
    -o "$VULN/xss.txt" 2>/dev/null || true

  ok "XSS findings: $(count_lines "$VULN/xss.txt")"
}

# ===========================
#  FINAL REPORT
# ===========================
report() {
  REPORT_FILE="$OUT/summary_report.txt"
  ELAPSED=$(( $(date +%s) - START_TIME ))
  {
    echo "================================================"
    echo "          SPIDER-RECON v2.1 FINAL REPORT"
    echo "================================================"
    echo "Target Domain : $DOMAIN"
    echo "Scan Date     : $(date)"
    echo "Duration      : $((ELAPSED/60))m $((ELAPSED%60))s"
    echo "Output Folder : $OUT"
    echo "------------------------------------------------"
    echo "[+] ASSET DISCOVERY"
    echo "  - Total Subdomains     : $(count_lines "$SUBS/all.txt")"
    echo "  - Resolved Subdomains  : $(count_lines "$SUBS/resolved.txt")"
    echo "  - Live Hosts (httpx)   : $(count_lines "$SUBS/live.txt")"
    echo "  - Open Ports (naabu)   : $(count_lines "$PORTS/naabu.txt")"
    echo "  - Total URLs           : $(count_lines "$URLS/all_urls.txt")"
    echo "  - Filtered URLs        : $(count_lines "$URLS/filtered.txt")"
    echo "  - Parameterized URLs   : $(count_lines "$URLS/params_urls.txt")"
    echo "  - JS Files             : $(count_lines "$JS/js_urls.txt")"
    echo "  - Possible JS Secrets  : $(count_lines "$JS/secrets.txt")"
    echo "------------------------------------------------"
    echo "[!] VULNERABILITY CANDIDATES"
    echo "  - Nuclei Findings      : $(count_lines "$VULN/nuclei.txt")"
    echo "  - XSS (Dalfox)         : $(count_lines "$VULN/xss.txt")"
    echo "  - SQLi (gf)            : $(count_lines "$VULN/gf_sqli.txt")"
    echo "  - SSRF (gf)            : $(count_lines "$VULN/gf_ssrf.txt")"
    echo "  - LFI (gf)             : $(count_lines "$VULN/gf_lfi.txt")"
    echo "  - RCE (gf)             : $(count_lines "$VULN/gf_rce.txt")"
    echo "  - IDOR (gf)            : $(count_lines "$VULN/gf_idor.txt")"
    echo "  - Open Redirect (gf)   : $(count_lines "$VULN/gf_redirect.txt")"
    echo "  - SSTI (gf)            : $(count_lines "$VULN/gf_ssti.txt")"
    echo "================================================"
    echo ""
    echo "[>] NEXT STEPS — افحص بالترتيب ده:"
    [ "$(count_lines "$VULN/nuclei.txt")" -gt 0 ]      && echo "  1. cat $VULN/nuclei.txt | grep -iE 'critical|high'"
    [ "$(count_lines "$VULN/xss.txt")" -gt 0 ]         && echo "  2. cat $VULN/xss.txt"
    [ "$(count_lines "$JS/secrets.txt")" -gt 0 ]       && echo "  3. cat $JS/secrets.txt"
    [ "$(count_lines "$VULN/gf_sqli.txt")" -gt 0 ]     && echo "  4. cat $VULN/gf_sqli.txt | head -20  # test manually"
    [ "$(count_lines "$VULN/gf_ssrf.txt")" -gt 0 ]     && echo "  5. cat $VULN/gf_ssrf.txt"
    [ "$(count_lines "$VULN/gf_idor.txt")" -gt 0 ]     && echo "  6. cat $VULN/gf_idor.txt"
    [ "$(count_lines "$VULN/gf_lfi.txt")" -gt 0 ]      && echo "  7. cat $VULN/gf_lfi.txt"
    [ "$(count_lines "$VULN/gf_redirect.txt")" -gt 0 ] && echo "  8. cat $VULN/gf_redirect.txt"
    echo "================================================"
  } | tee "$REPORT_FILE"
  ok "Report saved to: $REPORT_FILE"
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
  echo -e "\n${GREEN}${BOLD}[✔] Spider-Recon finished!${NC}"
}

main
