<p align="center">
  <img src="https://i.postimg.cc/VvXKkJXJ/Chat-GPT-Image-Jun-3-2026-05-30-46-PM.png" width="600">
</p>

# Spider-Recon 🕷️

A complete automated recon tool for gathering information about web domains. It checks for all required tools and installs any missing dependencies automatically.

---

## 🚀 How to Use

Follow these steps to get the script up and running on your system:

### 1. Clone or Create the Script
Make sure the script is saved on your system (e.g., `spider-recon.sh`).

### 2. Give Execution Permissions
Before running the script for the first time, you need to give it execution permissions using `chmod`:
```bash
chmod +x spider-recon.sh
```
# Run the Script

## Fast mode
```bash
./spider-recon.sh -d target.com
```
## Slow mode
```bash
./spider-recon.sh -d target.com -s
```

# 📌 Features:

### 🔧 Setup
• Automatic dependency check and installation
• Output neatly organized into per-target folders
• Slow/stealth mode (-s) to avoid rate-limits and bans

🌐 Asset Discovery
• Subdomain enumeration using multiple tools
  (Subfinder, Assetfinder, Amass, crt.sh)
  
• DNS resolution validation via DNSx

• Port scanning with Naabu (top 1000 ports)

• Live host probing with tech-detection (HTTPX)

🔗 URL Collection
• Passive URL gathering from GAU & Waybackurls
• Active crawling with Katana & GoSpider
• Parameter extraction using ParamSpider + Arjun
• Smart filtering for important file types (php, asp, jsp, json, js)

📜 JavaScript Analysis
• JS file extraction & analysis
• Secret hunting (API keys, tokens, credentials)
• Hidden endpoint discovery

🛡️ Vulnerability Scanning
• Full Nuclei scanning (CVEs & misconfigurations)
• Lightning-fast XSS pipeline: Gxss → uro → Dalfox (10x faster)
• GF pattern matching for:
  SQLi · SSRF · LFI · RCE · IDOR · Open Redirect · SSTI
• Directory & file brute-forcing with FFUF

📊 Reporting
• Clean final summary report with all findings & scan duration

# 📦 Requirements:
🌟Note: Automatic installation is already included inside the script.
