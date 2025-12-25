#!/bin/bash

# ===========================
# GLOBAL SETTINGS
# ===========================
export PATH=$PATH:$(go env GOPATH)/bin
SLOW=false

# ===========================
# ARGUMENTS
# ===========================
DOMAIN=""
while getopts "d:s" opt; do
  case $opt in
    d) DOMAIN=$OPTARG ;;
    s) SLOW=true ;;
    *) echo "Usage: $0 -d domain.com [-s slow mode]"; exit 1 ;;
  esac
done

if [ -z "$DOMAIN" ]; then
    echo "Usage: $0 -d domain.com [-s slow mode]"
    exit 1
fi

# ===========================
# THREAD CONTROL
# ===========================
if $SLOW; then
    THREADS=20
else
    THREADS=100
fi

# ===========================
# ROOT CHECK
# ===========================
if [ "$EUID" -ne 0 ]; then
  echo "[!] Not running as root. Some tools may fail."
fi

# ===========================
# TOOL CHECKER
# ===========================
check_tool() {
    TOOL=$1
    INSTALL_CMD=$2

    if ! command -v $TOOL &> /dev/null; then
        echo "[!] $TOOL not found. Installing..."
        eval $INSTALL_CMD
    else
        echo "[+] $TOOL is installed."
    fi
}

# ===========================
# DEPENDENCIES
# ===========================
check_tool subfinder "apt install -y subfinder || go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
check_tool assetfinder "go install github.com/tomnomnom/assetfinder@latest"
check_tool httpx "go install github.com/projectdiscovery/httpx/cmd/httpx@latest"
check_tool gau "go install github.com/lc/gau@latest"
check_tool gauplus "go install github.com/bp0lr/gauplus@latest"
check_tool waybackurls "go install github.com/tomnomnom/waybackurls@latest"
check_tool katana "go install github.com/projectdiscovery/katana/cmd/katana@latest"
check_tool paramspider "pip install paramspider"
check_tool arjun "pip install arjun"
check_tool ffuf "apt install -y ffuf || go install github.com/ffuf/ffuf@latest"
check_tool dalfox "go install github.com/hahwul/dalfox/v2@latest"
check_tool gf "go install github.com/tomnomnom/gf@latest"

# ===========================
# BANNER
# ===========================
cat << "EOF"
███████╗██████╗ ██╗██████╗ ███████╗██████╗
██╔════╝██╔══██╗██║██╔══██╗██╔════╝██╔══██╗
███████╗██████╔╝██║██║  ██║█████╗  ██████╔╝
╚════██║██╔═══╝ ██║██║  ██║██╔══╝  ██╔══██╗
███████║██║     ██║██████╔╝███████╗██║  ██║
╚══════╝╚═╝     ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝

██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
Spider-Recon
By: Youssef Ashraf
------------------------------------------------
EOF

# ===========================
# OUTPUT STRUCTURE
# ===========================
OUT="output/$DOMAIN"
SUBS="$OUT/subs"
URLS="$OUT/urls"
VULN="$OUT/vuln"

mkdir -p "$SUBS" "$URLS" "$VULN"

# ===========================
# RECON
# ===========================
echo "[+] Subdomain Enumeration"
subfinder -d $DOMAIN -o $SUBS/subfinder.txt -silent
assetfinder --subs-only $DOMAIN > $SUBS/assetfinder.txt
cat $SUBS/*.txt | sort -u > $SUBS/all.txt

echo "[+] Probing Live Hosts"
httpx -l $SUBS/all.txt -threads $THREADS -silent -o $SUBS/live.txt

echo "[+] Collecting URLs"
gau $DOMAIN > $URLS/gau.txt
gauplus -t $THREADS $DOMAIN > $URLS/gauplus.txt
waybackurls $DOMAIN > $URLS/wayback.txt

echo "[+] Crawling"
katana -list $SUBS/live.txt -silent -o $URLS/katana.txt

echo "[+] Parameters Discovery"
paramspider -d $DOMAIN --quiet -o $URLS/paramspider
cat $URLS/paramspider/*.txt > $URLS/params.txt

echo "[+] Arjun"
arjun -i $URLS/gau.txt -oT $URLS/arjun.txt

echo "[+] Merge URLs"
cat $URLS/*.txt | sort -u > $URLS/all_urls.txt

echo "[+] Filtering Interesting URLs"
grep -E "\.php|\.asp|\.aspx|\.jsp|\.js|\.json" $URLS/all_urls.txt > $URLS/filtered.txt

# ===========================
# VULNERABILITY
# ===========================
echo "[+] FFUF Bruteforce"
ffuf -u https://$DOMAIN/FUZZ \
-w /usr/share/seclists/Discovery/Web-Content/common.txt \
-mc 200,301,302,401,403 \
-t $THREADS \
-o $VULN/ffuf.json >/dev/null

echo "[+] XSS Scan (Dalfox)"
dalfox file $URLS/filtered.txt -o $VULN/xss.txt

echo "[+] SQLi / SSRF / LFI candidates"
cat $URLS/all_urls.txt | gf sqli > $VULN/sqli.txt
cat $URLS/all_urls.txt | gf ssrf > $VULN/ssrf.txt
cat $URLS/all_urls.txt | gf lfi > $VULN/lfi.txt

echo "------------------------------------------------"
echo "[+] FINISHED"
echo "[+] Results saved in: $OUT"
