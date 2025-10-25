# NEXA — Intelligent Port Scanner 🔎✨

![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge\&logo=python\&logoColor=white)
![License: MIT](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Active-success?style=for-the-badge)

```
 ______  _______ _    _        
|  ___ \(_______) \  / /  /\   
| |   | |_____   \ \/ /  /  \  
| |   | |  ___)   )  (  / /\ \ 
| |   | | |_____ / /\ \| |__| |
|_|   |_|_______)_/  \_\______|
                               
      Intelligent Port Scanner

```

**NEXA** is a fast, opinionated, Python-based network scanner that merges asynchronous TCP connect scanning with optional Nmap enrichment and Gemini-CLI (AI) analysis to produce compact, intelligible security reports. NEXA focuses on producing actionable, reproducible artifacts (scan summaries, JSON reports) and an AI-generated remediation summary.

> **Note:** NEXA is a reconnaissance tool. Use it only against hosts/networks you own or have explicit permission to test. Misuse may be illegal.

---

## ✨ Key Features

* High-speed asynchronous TCP connect scanning (configurable concurrency & timeout)
* Banner grabbing for common services (HTTP, FTP, SSH, mail)
* Optional Nmap enrichment (`-sS -sV -O`) parsed from Nmap XML output
* WHOIS & DNS contextual enrichment + HTTP header capture
* Pipes merged data to **Gemini-CLI** for an intelligence-style report (requires `/usr/bin/gemini-cli` or equivalent on PATH)
* Colorized, compact terminal output (OPEN + relevant FILTERED ports only)
* Graceful fallbacks when optional dependencies are missing
* Aggressive mode for faster scanning (higher concurrency / lower timeout)

---

## ⚙️ Installation

*Note: instructions below assume a Kali/ Debian-like environment.*

### 1. System packages (recommended)

Install required OS-level tools (nmap/curl/whois used by enrichment):

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip nmap curl whois dnsutils
```

### 2. Create a Python virtual environment (recommended)

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
```

### 3. Install Python dependencies

```bash
pip install tqdm prettytable colorama requests
```

> If you prefer system-wide installs on Kali, use `apt` packaged versions as suggested by the distro.

### 4. Make the script executable

```bash
chmod +x nexa.py
```

### 5. Gemini-CLI (optional but recommended)

On Kali, Gemini may be available as `gemini-cli`. NEXA will try `/usr/bin/gemini-cli` and other typical locations. Ensure Gemini is installed and accessible if you want AI analysis.

---

## 🚀 Usage

Basic usage:

```bash
./nexa.py <target>
# Example:
./nexa.py example.com
```

Options:

```
usage: nexa.py target [--ports 1-1024] [--concurrency 200] [--timeout 2.0]
                         [--no-nmap] [--gemini-path /usr/bin/gemini-cli] [--debug]
```

Examples:

* Quick default scan (ports 1–1024):

```bash
./nexa.py example.com
```

* Aggressive scan (higher concurrency, shorter timeout):

```bash
./nexa.py example.com --aggressive
```

* Force using a specific Gemini binary:

```bash
./nexa.py example.com --gemini-path /usr/bin/gemini-cli
```

* Skip Nmap enrichment (faster, but less version detail):

```bash
./nexa.py example.com --no-nmap
```

* Debug mode (prints internal diagnostics):

```bash
./nexa.py example.com --debug
```

---

## 🛡️ Security & Responsible Use

* NEXA can surface potentially dangerous vulnerabilities. The project intentionally **does not** automate exploit execution.
* Do **not** run NEXA against targets you do not have explicit authorization to test.
* Use the `--no-nmap` flag if you cannot run privileged Nmap scans (SYN scans require root).
* Gemini output may contain suggestions — review and redact any sensitive exploit steps before sharing.

---

## 🧩 Dependencies (optional features)

* `nmap` — for service/version OS enrichment
* `curl` — for HTTP header enrichment
* `whois`, `host` (`dnsutils`) — OSINT enrichment
* Python packages: `tqdm`, `prettytable`, `colorama`, `requests`
* `gemini-cli` — Gemini AI integration (optional)

NEXA will run without some of these, but functionality will be reduced (e.g., no nmap enrichment, no Gemini analysis).

---

## 📝 Troubleshooting

* **"gemini not found"** — Provide `--gemini-path /usr/bin/gemini-cli` or install Gemini into your PATH.
* **Color missing** — Install `colorama` (or run in a terminal that supports ANSI color).
* **Permission for nmap** — For SYN scans, run with `sudo` (or use `--no-nmap`).
* **Deprecation warnings about f-strings / escapes** — If you see a banner escape warning, ensure the ASCII banner uses an `fr"""..."""` literal (the repo already handles this).

---

## 📜 License

**MIT License** — feel free to fork, improve and contribute back.

---

## ⚡ Credits

* Built with Python for scanning, with optional Nmap & Gemini-CLI integration.
* Inspired by tools like Nmap, Masscan and AI-assisted analysis workflows.
