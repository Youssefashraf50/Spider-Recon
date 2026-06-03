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
Before running the script for the first time, you need to give it execution permissions using `chmod`:```bash
chmod +x spider-recon.sh

# Run the Script

## Fast mode
```bash
./spider-recon.sh -d target.com ```
## Slow mode
./spider-recon.sh -d example.com -s

# 📌 Features:

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
🌟Note: Automatic installation is already included inside the script.
