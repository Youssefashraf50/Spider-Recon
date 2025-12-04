# Spider-Recon
🕷️ Spider Recon Toolkit

A complete automated recon tool for gathering information about web domains. It checks for all required tools and installs any missing dependencies automatically.

# 🚀 Features:

• Automatic dependency check and installation

• Subdomain enumeration using multiple tools

• Live subdomain probing via HTTPX

• URL collection from GAU, Wayback, Katana, etc.

• Parameter extraction using ParamSpider + Arjun

• URL filtering for important file types

• Automatic Dalfox XSS scanning

• FFUF directory brute-forcing

• Output neatly organized into folders

# 📦 Requirements:

Termux:
pkg update && pkg upgrade
pkg install git python python-pip golang
pip install paramspider arjun

GO Tools:
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/tomnomnom/assetfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/lc/gau@latest
go install github.com/bp0lr/gauplus@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/ffuf/ffuf@latest
go install github.com/hahwul/dalfox/v2@latest

🌟Note: Automatic installation is already included inside the script.
