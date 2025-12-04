#!/bin/bash

# ===========================
# TOOL CHECKER FUNCTION
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
# CHECK REQUIRED TOOLS
# ===========================
check_tool subfinder "apt install -y subfinder || go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
check_tool assetfinder "go install github.com/tomnomnom/assetfinder@latest"
check_tool httpx "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"
check_tool gau "go install github.com/lc/gau@latest"
check_tool gauplus "go install github.com/bp0lr/gauplus@latest"
check_tool waybackurls "go install github.com/tomnomnom/waybackurls@latest"
check_tool katana "go install github.com/projectdiscovery/katana/cmd/katana@latest"
check_tool paramspider "pip install paramspider"
check_tool arjun "pip install arjun"
check_tool ffuf "apt install -y ffuf || go install github.com/ffuf/ffuf@latest"
check_tool dalfox "go install github.com/hahwul/dalfox/v2@latest"

# ===========================
# ORIGINAL SCRIPT STARTS HERE
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
------------------------------------------------
EOF

#------------------------------------------------
# RECON_TOOL
DOMAIN=$1
if [ -z "$DOMAIN" ]; then
    echo "Usage: $0 domain.com"
    exit 1
fi

OUT="output/$DOMAIN"
SUBS_OUT="$OUT/subs"
URLS_OUT="$OUT/urls"
VULN_OUT="$OUT/vuln"

mkdir -p "$SUBS_OUT" "$URLS_OUT" "$VULN_OUT"

echo "[+] Gathering Subdomains…"
subfinder -d $DOMAIN -o $SUBS_OUT/subfinder.txt >/dev/null 2>&1
assetfinder --subs-only $DOMAIN > $SUBS_OUT/assetfinder.txt 2>/dev/null
cat $SUBS_OUT/*.txt | sort -u > $SUBS_OUT/all_subs.txt

echo "[+] Probing Live Subdomains…"
httpx -l $SUBS_OUT/all_subs.txt -o $SUBS_OUT/live.txt -threads 100 -silent >/dev/null 2>&1

echo "[+] Collecting URLs (GAU / Wayback)…"
gau $DOMAIN > $URLS_OUT/gau.txt 2>/dev/null
gauplus -t 50 $DOMAIN > $URLS_OUT/gauplus.txt 2>/dev/null
waybackurls $DOMAIN > $URLS_OUT/wayback.txt 2>/dev/null

echo "[+] Crawling with Katana…"
katana -list $SUBS_OUT/live.txt -o $URLS_OUT/katana.txt >/dev/null 2>&1

echo "[+] Running ParamSpider…"
paramspider -d $DOMAIN --quiet -o $URLS_OUT/paramspider >/dev/null 2>&1
cat $URLS_OUT/paramspider/*.txt 2>/dev/null > $URLS_OUT/paramspider.txt

echo "[+] Running Arjun (text mode)…"
arjun -i $URLS_OUT/gau.txt -oT $URLS_OUT/arjun.txt >/dev/null 2>&1

echo "[+] Merging URLs…"
cat $URLS_OUT/*.txt | sort -u > $URLS_OUT/all_urls.txt

echo "[+] Filtering URLs…"
grep -E "\.php|\.js|\.json|\.asp|\.aspx|\.jsp" $URLS_OUT/all_urls.txt > $URLS_OUT/filtered_urls.txt

echo "[+] Running FFUF Directory Bruteforce…"
ffuf -u https://$DOMAIN/FUZZ \
     -w /usr/share/seclists/Discovery/Web-Content/common.txt \
     -mc 200,301,302,403,401 \
     -t 50 -o $VULN_OUT/ffuf.json >/dev/null 2>&1

echo "[+] Running Dalfox for XSS…"
dalfox file $URLS_OUT/filtered_urls.txt -o $VULN_OUT/dalfox.txt >/dev/null 2>&1

echo "------------------------------------------------"
echo "[+] FINISHED! All results saved in: $OUT"
