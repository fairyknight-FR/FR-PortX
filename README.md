# ⚡ FR-PortX — TCP Port Scanner

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/Tool-Port%20Scanner-red?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/Threading-Concurrent-orange?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/Multi--Host-Supported-blueviolet?style=for-the-badge"/>
</p>

> A fast, concurrent TCP port scanner built with Python — supports **single host, comma-separated multi-host, and file-based host list** scanning, with custom port ranges, banner grabbing, and file logging. Built for **authorized penetration testing and security assessments only**.

---

## 📸 Preview

```
  ███████╗██████╗     ██████╗  ██████╗ ██████╗ ████████╗██╗  ██╗
  ██╔════╝██╔══██╗    ██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝╚██╗██╔╝
  █████╗  ██████╔╝    ██████╔╝██║   ██║██████╔╝   ██║    ╚███╔╝ 
  ██╔══╝  ██╔══██╗    ██╔═══╝ ██║   ██║██╔══██╗   ██║    ██╔██╗ 
  ██║     ██║  ██║    ██║     ╚██████╔╝██║  ██║   ██║   ██╔╝ ██╗
  ╚═╝     ╚═╝  ╚═╝    ╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝

  fr-portx :: FR PORTX v2.0.0  |  by Alshifa Shaikh  |  multi-host edition

  [*] Loaded 3 host(s) from file: hosts.txt

  ── Host 1/3 ──
  Target   : scanme.nmap.org  (45.33.32.156)
  Ports    : 5 ports  (22–8080)
  Threads  : 200

[OPEN  ]  22      SSH    » SSH-2.0-OpenSSH_6.6.1p1
[OPEN  ]  80      HTTP   » Apache/2.4.7

  ══════════════════════════════════════════════════════════════
  MULTI-HOST SCAN COMPLETE — 3 hosts
  ══════════════════════════════════════════════════════════════

  scanme.nmap.org          (45.33.32.156)    2 open port(s)  [22, 80]
  example.com              (93.184.216.34)   1 open port(s)  [443]
  192.168.1.1              (192.168.1.1)     0 open port(s)
```

---

## ✨ Features

- 🚀 **Concurrent scanning** using `ThreadPoolExecutor` (up to 500 threads)
- 🌐 **Multi-host scanning** — scan a single host, a comma-separated list, or a file with one host per line
- 🎯 **Flexible port input** — single ports, lists, ranges, or mixed
- 🏷️ **Banner grabbing** — auto-fetches service banners on open ports
- 🗂️ **Service detection** — identifies 25+ common services (SSH, HTTP, MySQL, RDP, etc.)
- 📋 **File logging** — saves results with timestamps via Python's `logging` module
- 🎨 **Colored terminal output** — ANSI colors for quick visual parsing
- 📊 **Live progress bar** — real-time scan progress per host
- ✅ **Combined summary table** — all hosts and their open ports at a glance after a multi-host run
- ⚠️ **Graceful DNS failure handling** — one unresolvable host won't stop the rest of the scan
- 🛡️ **Exception handling** — handles timeouts, OS errors, and keyboard interrupts gracefully

---

## 🛠️ Requirements

- Python **3.10+** (uses `list[int]` type hints — for 3.9 replace with `List[int]`)
- No external libraries required — uses only Python standard library:
  - `socket` — TCP connections
  - `concurrent.futures` — thread pool
  - `logging` — file/console logging
  - `argparse` — CLI argument parsing

---

## 🚀 Installation

```bash
# 1. Clone the repository
git clone https://github.com/fairyknight-FR/FR-PortX.git

# 2. Navigate into the folder
cd fr-portx

# 3. (Optional) Create a virtual environment
python -m venv venv
source venv/bin/activate        # Linux / macOS
venv\Scripts\activate           # Windows

# 4. Run directly — no pip install needed
python port_scanner.py --help
```

---

## 📖 Usage

### Basic Syntax

```bash
python port_scanner.py -H <host|hosts|file> -p <ports> [options]
```

### Arguments

| Argument | Description | Example |
|---|---|---|
| `-H`, `--host` | Single IP/hostname, comma-separated list, or path to a hosts file | `-H 192.168.1.1` |
| `-p`, `--ports` | Port(s) to scan | `-p 22,80,443` or `-p 1-1024` |
| `-t`, `--threads` | Number of threads (default: 200) | `-t 100` |
| `--timeout` | Socket timeout in seconds (default: 1.0) | `--timeout 0.5` |
| `--log` | Log results to a file | `--log results.log` |
| `-v`, `--verbose` | Show closed and timeout ports too | `-v` |

---

## 💡 Examples

### Single host
```bash
python port_scanner.py -H 192.168.1.1 -p 22,80,443,3306,8080
```

### Multiple hosts — comma-separated
```bash
python port_scanner.py -H "scanme.nmap.org,example.com,192.168.1.1" -p 22,80,443
```

### Multiple hosts — from a file
```bash
python port_scanner.py -H hosts.txt -p 22,80,443
```

### Scan a port range
```bash
python port_scanner.py -H 10.0.0.1 -p 1-1024
```

### Mixed port list + range
```bash
python port_scanner.py -H target.com -p 22,80,1000-2000,8080,8443
```

### Full scan with logging + verbose
```bash
python port_scanner.py -H hosts.txt -p 1-65535 -t 500 --timeout 0.5 --log scan.log -v
```

### Web application ports across multiple targets
```bash
python port_scanner.py -H "webapp1.com,webapp2.com" -p 80,443,8080,8443,3000,5000
```

### Database ports from a host list file
```bash
python port_scanner.py -H db_targets.txt -p 1433,1521,3306,5432,6379,27017
```

---

## 📂 hosts.txt Format

When using a file with `-H`, put one host per line. Lines starting with `#` and blank lines are skipped automatically:

```
# Internal servers
192.168.1.1
192.168.1.2

# External targets
scanme.nmap.org
example.com
```

---

## 📂 Project Structure

```
fr-portx/
├── port_scanner.py     # Main scanner script
├── hosts.txt           # (Optional) Host list file — one host per line
├── README.md           # Documentation
├── .gitignore          # Git ignore rules
└── logs/               # Auto-created when --log is used
    └── scan_results.log
```

---

## 🧠 How It Works

```
1. Parse CLI arguments
        ↓
2. Parse host argument
   ├── File path?    → read hosts.txt line by line (skip # comments)
   ├── Comma list?   → split into multiple hosts
   └── Single host?  → wrap in a list
        ↓
3. For each host:
   a. Resolve hostname → IP (socket.gethostbyname)
      └── DNS failure? → log error, skip host, continue
   b. Parse port string → list of integers
   c. Spawn ThreadPoolExecutor (N threads)
   d. Each thread: socket.connect_ex(host, port, timeout)
      ├── 0       → OPEN  (try banner grab)
      ├── timeout → TIMEOUT
      └── other   → CLOSED
   e. Print colored output + live progress bar
   f. Print per-host summary
        ↓
4. Print combined multi-host summary table
        ↓
5. Write all results to log file (if --log used)
```

---

## 📊 Output Example

### Per-host output
```
────────────────────────────────────────────────────────────
  PORT    STATUS    SERVICE
────────────────────────────────────────────────────────────

[OPEN  ]  22      SSH       » SSH-2.0-OpenSSH_8.9p1 Ubuntu
[OPEN  ]  80      HTTP      » Apache/2.4.52 (Ubuntu)
[OPEN  ]  443     HTTPS     » nginx/1.22.0
[OPEN  ]  3306    MySQL     » MySQL 8.0.32

  ████████████████████████████████████████  100/100

  ⏱  Elapsed  : 3.42s
  ✅ Open     : 4
  🔒 Closed   : 94
  ⏳ Timeout  : 2
  ⚠  Errors   : 0
```

### Multi-host summary table
```
  ══════════════════════════════════════════════════════════════
  MULTI-HOST SCAN COMPLETE — 3 hosts
  ══════════════════════════════════════════════════════════════

  scanme.nmap.org          (45.33.32.156)    2 open port(s)  [22, 80]
  example.com              (93.184.216.34)   1 open port(s)  [443]
  192.168.1.1              (192.168.1.1)     0 open port(s)
```

---

## 📝 Log File Format

When `--log` is used, results are saved in this format:

```
2025-08-01 14:32:01  INFO      Scan started → host=192.168.1.1 (192.168.1.1), ports=1024, threads=200
2025-08-01 14:32:01  DEBUG     host=192.168.1.1 port=22 status=open service=SSH
2025-08-01 14:32:01  DEBUG     host=192.168.1.1 port=80 status=open service=HTTP
2025-08-01 14:32:04  INFO      host=192.168.1.1 done → open=4, elapsed=3.42s
```

---

## ⚙️ Supported Services (Auto-detected)

| Port | Service | Port | Service |
|------|---------|------|---------|
| 21 | FTP | 3306 | MySQL |
| 22 | SSH | 3389 | RDP |
| 23 | Telnet | 5432 | PostgreSQL |
| 25 | SMTP | 5900 | VNC |
| 53 | DNS | 6379 | Redis |
| 80 | HTTP | 8080 | HTTP-Alt |
| 443 | HTTPS | 8443 | HTTPS-Alt |
| 445 | SMB | 9200 | Elasticsearch |
| 1433 | MSSQL | 27017 | MongoDB |

---

## ⚠️ Legal Disclaimer

> This tool is intended **only for authorized security testing and educational purposes**.
> Scanning systems without explicit permission is **illegal** and unethical.
> The author takes no responsibility for misuse of this tool.
> Always obtain written authorization before scanning any network or host.

---

## 👤 Author

**Alshifa Shaikh**
- LinkedIn: [linkedin.com/in/alshifa-shaikh-695923303](https://linkedin.com/in/alshifa-shaikh-695923303)
- Certifications: eWPTXv3 · CRTA · MCRTA · CNSP · CCEP · CPPS · CCSC

---

## 📄 License

This project is licensed under the **MIT License** — feel free to use, modify, and distribute with attribution.

---

<p align="center">Made with ❤️ by Alshifa Shaikh for the cybersecurity community</p>
