# ⚡ recon-x — TCP Port Scanner

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/Tool-Port%20Scanner-red?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/Threading-Concurrent-orange?style=for-the-badge"/>
</p>

> A fast, concurrent TCP port scanner built with Python — supports single host scanning, custom port ranges, banner grabbing, and file logging. Built for **authorized penetration testing and security assessments only**.

---

## 📸 Preview

```
  ██████╗  ██████╗ ██████╗ ████████╗    ███████╗ ██████╗ █████╗ ███╗   ██╗
  ██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝    ██╔════╝██╔════╝██╔══██╗████╗  ██║
  ██████╔╝██║   ██║██████╔╝   ██║       ███████╗██║     ███████║██╔██╗ ██║
  ██╔═══╝ ██║   ██║██╔══██╗   ██║       ╚════██║██║     ██╔══██║██║╚██╗██║
  ██║     ╚██████╔╝██║  ██║   ██║       ███████║╚██████╗██║  ██║██║ ╚████║
  ╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝       ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝

  recon-x :: TCP Port Scanner v1.0.0  |  by Alshifa Shaikh

  Target   : scanme.nmap.org  (45.33.32.156)
  Ports    : 100 ports  (1–1024)
  Threads  : 200

[OPEN  ]  22      SSH    » SSH-2.0-OpenSSH_6.6.1p1
[OPEN  ]  80      HTTP   » Apache/2.4.7
```

---

## ✨ Features

- 🚀 **Concurrent scanning** using `ThreadPoolExecutor` (up to 500 threads)
- 🎯 **Flexible port input** — single ports, lists, ranges, or mixed
- 🏷️ **Banner grabbing** — auto-fetches service banners on open ports
- 🗂️ **Service detection** — identifies 25+ common services (SSH, HTTP, MySQL, RDP, etc.)
- 📋 **File logging** — saves results with timestamps via Python's `logging` module
- 🎨 **Colored terminal output** — ANSI colors for quick visual parsing
- 📊 **Live progress bar** — real-time scan progress
- ⚠️ **Exception handling** — handles timeouts, OS errors, and keyboard interrupts gracefully

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
git clone https://github.com/YOUR_USERNAME/recon-x.git

# 2. Navigate into the folder
cd recon-x

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
python port_scanner.py -H <host> -p <ports> [options]
```

### Arguments

| Argument | Description | Example |
|---|---|---|
| `-H`, `--host` | Target host (IP or hostname) | `-H 192.168.1.1` |
| `-p`, `--ports` | Port(s) to scan | `-p 22,80,443` or `-p 1-1024` |
| `-t`, `--threads` | Number of threads (default: 200) | `-t 100` |
| `--timeout` | Socket timeout in seconds (default: 1.0) | `--timeout 0.5` |
| `--log` | Log results to a file | `--log results.log` |
| `-v`, `--verbose` | Show closed and timeout ports too | `-v` |

---

## 💡 Examples

### Scan common ports
```bash
python port_scanner.py -H 192.168.1.1 -p 22,80,443,3306,8080
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
python port_scanner.py -H 192.168.1.100 -p 1-65535 -t 500 --timeout 0.5 --log scan.log -v
```

### Web application ports only
```bash
python port_scanner.py -H webapp.target.com -p 80,443,8080,8443,3000,5000
```

### Database ports
```bash
python port_scanner.py -H db.internal -p 1433,1521,3306,5432,6379,27017
```

---

## 📂 Project Structure

```
recon-x/
├── port_scanner.py     # Main scanner script
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
2. Resolve hostname → IP (socket.gethostbyname)
        ↓
3. Parse port string → list of integers
        ↓
4. Spawn ThreadPoolExecutor (N threads)
        ↓
5. Each thread: socket.connect_ex(host, port, timeout)
        |
        ├── 0       → OPEN  (try banner grab)
        ├── timeout → TIMEOUT
        └── other   → CLOSED
        ↓
6. Collect results, print colored output, update progress bar
        ↓
7. Print summary + write to log file
```

---

## 📊 Output Example

```
────────────────────────────────────────────────────────────
  PORT    STATUS    SERVICE
────────────────────────────────────────────────────────────

[OPEN  ]  22      SSH       » SSH-2.0-OpenSSH_8.9p1 Ubuntu
[OPEN  ]  80      HTTP      » Apache/2.4.52 (Ubuntu)
[OPEN  ]  443     HTTPS     » nginx/1.22.0
[OPEN  ]  3306    MySQL     » MySQL 8.0.32

  ████████████████████████████████████████  100/100

────────────────────────────────────────────────────────────

  SCAN COMPLETE
  ⏱  Elapsed  : 3.42s
  ✅ Open     : 4
  🔒 Closed   : 94
  ⏳ Timeout  : 2
  ⚠  Errors   : 0
```

---

## 📝 Log File Format

When `--log` is used, results are saved in this format:

```
2025-08-01 14:32:01  INFO      Scan started → host=192.168.1.1, ports=1024, threads=200
2025-08-01 14:32:01  DEBUG     port=22 status=open service=SSH
2025-08-01 14:32:01  DEBUG     port=80 status=open service=HTTP
2025-08-01 14:32:04  INFO      Scan complete → open=4, closed=94, timeout=2, elapsed=3.42s
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

<p align="center">Made with ❤️ for the cybersecurity community</p>
