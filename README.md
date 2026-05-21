<p align="center">
  <img src="Spider Recon.png" alt="Spider Recon Logo" width="300">
</p>

# Spider-Recon
🕷️ Spider Recon Toolkit

A complete automated recon tool for gathering information about web domains. It checks for all required tools and installs any missing dependencies automatically.

## 🚀 How to Use

Follow these steps to get the script up and running on your system:

### 1. Clone or Create the Script
Make sure the script is saved on your system (e.g., `spider-recon.sh`).

### 2. Give Execution Permissions
Before running the script for the first time, you need to give it execution permissions using `chmod`:
```bash
chmod +x spider-recon.sh
## run the script
./spider-recon.sh -d target.com

## 🚀 Features:

• Automatic dependency check and installation

• Subdomain enumeration using multiple tools

• Live subdomain probing via HTTPX

• URL collection from GAU, Wayback, Katana, etc.

• Parameter extraction using ParamSpider + Arjun

• URL filtering for important file types

• Automatic Dalfox XSS scanning

• FFUF directory brute-forcing

• Output neatly organized into folders

## 📦 Requirements:
🌟Note: Automatic installation is already included inside the script.
