<p align="center">
  <img src="https://i.postimg.cc/VvXKkJXJ/Chat-GPT-Image-Jun-3-2026-05-30-46-PM.png" width="600">
</p>

# Spider-Recon v3.0 — Bug Bounty Automation

A Bash script that automates the bug bounty reconnaissance pipeline — from subdomain enumeration all the way to a final summary report. It's built to be fully **resumable**: if any phase gets interrupted (crash, network drop, Ctrl+C), you can rerun the exact same command and it will pick up right where it left off instead of starting over.

## Overview

The script runs 11 sequential phases against a target domain, each one feeding off the previous phase's output:

| # | Phase | What it does |
|---|-------|---------------|
| 1 | Subdomain Enumeration | Runs `subfinder` + `sublist3r` in parallel, filters by scope (if provided), and resolves hosts with `dnsx` |
| 2 | Probing Live Hosts | Runs `httpx` on resolved hosts (title, status code, tech-detect, CDN) — chunked for resumability |
| 3–5 | URL Collection | Gathers URLs via `gau` + `waybackurls` (passive), actively crawls with `katana` (optionally `gospider`), and discovers parameters with `paramspider` |
| 6 | JavaScript Analysis | Collects JS files, fetches them, and extracts endpoints plus potential secret matches (API keys, tokens, etc.), with dedup at the value level |
| 7 | URL Filtering | Filters URLs by relevant extensions (php, asp, json, etc.) and URLs containing parameters |
| 8 | GF Pattern Matching | Runs all URLs through `gf` patterns (xss, sqli, ssrf, lfi, rce, idor, redirect, ssti) |
| 9 | Nuclei Scanning | Scans live hosts with `nuclei` (severity: medium/high/critical, or +low with `-x`) |
| 10 | Content Discovery (FFUF) | Fuzzes a subset of hosts, with a **baseline check** that filters out soft-403 catch-all responses |
| 11 | XSS Prep | Prepares candidate URLs for XSS (dedup via `uro`, reflection filtering via `Gxss`), and generates a manual `run_dalfox.sh` script for final confirmation |

At the end, it prints and saves a **final report** (`summary_report.txt`) containing: asset discovery counts, Nuclei findings broken down by severity, and — importantly — a separate section labeled **"UNVERIFIED PATTERN MATCHES"** that makes clear the gf/XSS results are just regex matches still requiring manual verification, not confirmed vulnerabilities.

## Usage

```bash
./spider-recon.sh -d example.com                  # normal run (prompts for scope if not provided)
./spider-recon.sh -d example.com -s -l scope.txt   # stealth mode + pre-made scope file
./spider-recon.sh -d example.com -x -g -a          # deep scan: extra ports + gospider + amass
./spider-recon.sh -d example.com                   # rerun on the same domain -> auto-resumes
./spider-recon.sh -d example.com -r                # full reset (ignore any saved checkpoint)
```

### Options

- `-d` Target domain (required)
- `-s` Slow/stealth mode (lower threads/rate, less likely to trip a WAF)
- `-l` Scope file (in-scope domains) — if omitted, the script asks interactively
- `-x` Deep mode (extra httpx ports, deeper katana crawl depth, low severity in nuclei)
- `-g` Also run gospider alongside katana for extra coverage
- `-a` Also run amass (slow, often redundant with subfinder)
- `-r` Full reset — ignores any previously saved checkpoint
- `-h` Show help

## Resume / Checkpoint Mechanism

- Progress is saved to `output/<domain>/.state.json` (a JSON file with a checkpoint version, completed phases, and per-phase partial progress like the last completed chunk or index).
- Long-running phases (httpx probing, JS analysis, ffuf, gxss) are split into chunks, and the last finished chunk is saved so the phase can resume from there.
- `.in_progress` / `.inprogress` marker files flag "still running" state, and are automatically cleaned up (via `trap ... RETURN`) on crash, keeping the state file consistent.
- A PID-based `.lock` file prevents the same scan from running twice at once.
- The state file is **not deleted automatically after completion** — delete it manually or use `-r` to force a full restart.

## Output Structure

```
output/<domain>/
├── subs/     # subdomains, resolved hosts, live hosts (httpx)
├── urls/     # all collected and filtered URLs
├── js/       # JS URLs, endpoints, secrets
├── vuln/     # gf patterns, nuclei, ffuf, xss prep
└── summary_report.txt
```

## Required Tools

The script checks for and attempts to auto-install: `subfinder, dnsx, httpx, gau, waybackurls, katana, gospider, nuclei, ffuf, dalfox, gf, qsreplace, anew, unfurl, subjs, Gxss, sublist3r, paramspider, arjun, uro, jq`. It also downloads gf patterns and nuclei templates if they're missing.

## Important Notes

- Port scanning (`naabu`) was **removed** in v3.0 — low value for bug bounty recon and it triggers WAF/IP bans too easily.
- `gf` and `XSS reflected` results are always "unverified" — they're text/pattern matches only and require manual verification (e.g. via `run_dalfox.sh`) before being reported as findings.
- The script is intended for use only against domains that are explicitly in-scope for a bug bounty program — use `-l` to define scope and avoid testing anything you're not authorized to test.
