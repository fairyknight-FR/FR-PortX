#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════╗
║            fr-portx :: TCP Port Scanner               ║
║   Author  : Alshifa Shaikh                           ║
║   Version : 1.0.0                                    ║
╚══════════════════════════════════════════════════════╝

Usage:
  python port_scanner.py -H 192.168.1.1 -p 1-1000
  python port_scanner.py -H scanme.nmap.org -p 22,80,443,3306
  python port_scanner.py -H 10.0.0.1 -p 1-65535 -t 300 --log results.txt
"""

import socket
import argparse
import logging
import sys
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# ─── ANSI Colors ────────────────────────────────────────────────────────────
class C:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    CYAN    = "\033[96m"
    GREY    = "\033[90m"
    MAGENTA = "\033[95m"
    WHITE   = "\033[97m"

# ─── Banner ──────────────────────────────────────────────────────────────────
BANNER = f"""
{C.CYAN}{C.BOLD}
  ███████╗██████╗     ██████╗  ██████╗ ██████╗ ████████╗██╗  ██╗
  ██╔════╝██╔══██╗    ██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝╚██╗██╔╝
  █████╗  ██████╔╝    ██████╔╝██║   ██║██████╔╝   ██║    ╚███╔╝ 
  ██╔══╝  ██╔══██╗    ██╔═══╝ ██║   ██║██╔══██╗   ██║    ██╔██╗ 
  ██║     ██║  ██║    ██║     ╚██████╔╝██║  ██║   ██║   ██╔╝ ██╗
  ╚═╝     ╚═╝  ╚═╝    ╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝
{C.RESET}{C.GREY}  fr-portx :: FR PORTX v1.0.0  |  by Alshifa Shaikh{C.RESET}
"""

# ─── Common Port Services ────────────────────────────────────────────────────
COMMON_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPC", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 587: "SMTP-TLS",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    9200: "Elasticsearch", 27017: "MongoDB",
}

# ─── Port Parser ─────────────────────────────────────────────────────────────
def parse_ports(port_arg: str) -> list[int]:
    """Parse port string: '22,80,443' or '1-1024' or '22,80,1000-2000'"""
    ports = []
    try:
        for part in port_arg.split(","):
            part = part.strip()
            if "-" in part:
                start, end = part.split("-", 1)
                start, end = int(start.strip()), int(end.strip())
                if not (1 <= start <= 65535 and 1 <= end <= 65535):
                    raise ValueError(f"Port range out of bounds: {start}-{end}")
                if start > end:
                    raise ValueError(f"Start port > end port: {start}-{end}")
                ports.extend(range(start, end + 1))
            else:
                p = int(part)
                if not (1 <= p <= 65535):
                    raise ValueError(f"Port out of bounds: {p}")
                ports.append(p)
    except ValueError as e:
        print(f"{C.RED}[!] Invalid port specification: {e}{C.RESET}")
        sys.exit(1)
    return sorted(set(ports))  # deduplicate

# ─── Resolve Host ─────────────────────────────────────────────────────────────
def resolve_host(host: str) -> str:
    """Resolve hostname to IP, or validate IP"""
    try:
        ip = socket.gethostbyname(host)
        return ip
    except socket.gaierror as e:
        print(f"{C.RED}[!] Could not resolve host '{host}': {e}{C.RESET}")
        sys.exit(1)

# ─── Single Port Scan ─────────────────────────────────────────────────────────
def scan_port(host: str, port: int, timeout: float) -> dict:
    """
    Scan a single TCP port.
    Returns: {'port': int, 'status': 'open'|'closed'|'timeout', 'service': str}
    """
    result = {
        "port": port,
        "status": "closed",
        "service": COMMON_SERVICES.get(port, "unknown"),
        "banner": None,
    }
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            conn = s.connect_ex((host, port))
            if conn == 0:
                result["status"] = "open"
                # Try banner grabbing
                try:
                    s.settimeout(1.0)
                    banner = s.recv(1024).decode("utf-8", errors="ignore").strip()
                    if banner:
                        result["banner"] = banner[:80]  # truncate long banners
                except Exception:
                    pass
            else:
                result["status"] = "closed"
    except socket.timeout:
        result["status"] = "timeout"
    except OSError as e:
        result["status"] = "error"
        result["error"] = str(e)
    return result

# ─── Logger Setup ─────────────────────────────────────────────────────────────
def setup_logger(log_file: str | None) -> logging.Logger:
    logger = logging.getLogger("port_scanner")
    logger.setLevel(logging.DEBUG)
    fmt = logging.Formatter("%(asctime)s  %(levelname)-8s  %(message)s",
                            datefmt="%Y-%m-%d %H:%M:%S")
    # Console handler (WARNING+ only — we handle INFO ourselves for coloured output)
    ch = logging.StreamHandler()
    ch.setLevel(logging.WARNING)
    ch.setFormatter(fmt)
    logger.addHandler(ch)
    # File handler
    if log_file:
        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(fmt)
        logger.addHandler(fh)
    return logger

# ─── Print Result ─────────────────────────────────────────────────────────────
def print_result(res: dict, verbose: bool = False):
    port    = res["port"]
    status  = res["status"]
    service = res["service"]
    banner  = res.get("banner")

    if status == "open":
        tag = f"{C.GREEN}[OPEN  ]{C.RESET}"
        line = f"{tag}  {C.WHITE}{port:<6}{C.RESET}  {C.CYAN}{service}{C.RESET}"
        if banner:
            line += f"  {C.GREY}» {banner}{C.RESET}"
        print(line)
    elif status == "timeout" and verbose:
        print(f"{C.YELLOW}[TIMEOUT]{C.RESET}  {port:<6}  {service}")
    elif status == "closed" and verbose:
        print(f"{C.GREY}[CLOSED ]{C.RESET}  {port:<6}  {service}")
    elif status == "error" and verbose:
        print(f"{C.RED}[ERROR  ]{C.RESET}  {port:<6}  {res.get('error','')}")

# ─── Main Scanner ─────────────────────────────────────────────────────────────
def run_scan(args):
    print(BANNER)

    host    = args.host
    ports   = parse_ports(args.ports)
    timeout = args.timeout
    threads = args.threads
    verbose = args.verbose
    log_file= args.log

    logger = setup_logger(log_file)
    ip = resolve_host(host)

    total = len(ports)
    start_time = datetime.now()

    print(f"{C.BOLD}  Target   :{C.RESET} {C.MAGENTA}{host}{C.RESET}  ({ip})")
    print(f"{C.BOLD}  Ports    :{C.RESET} {total} ports  "
          f"({min(ports)}–{max(ports)})")
    print(f"{C.BOLD}  Threads  :{C.RESET} {threads}")
    print(f"{C.BOLD}  Timeout  :{C.RESET} {timeout}s per port")
    if log_file:
        print(f"{C.BOLD}  Log File :{C.RESET} {log_file}")
    print(f"\n{C.GREY}{'─'*60}{C.RESET}")
    print(f"  {'PORT':<8}{'STATUS':<10}{'SERVICE'}")
    print(f"{C.GREY}{'─'*60}{C.RESET}\n")

    logger.info(f"Scan started → host={host} ({ip}), ports={total}, "
                f"threads={threads}, timeout={timeout}s")

    results = {"open": [], "closed": [], "timeout": [], "error": []}
    completed = 0

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(scan_port, ip, port, timeout): port
            for port in ports
        }
        for future in as_completed(futures):
            completed += 1
            try:
                res = future.result()
            except Exception as e:
                port = futures[future]
                res = {"port": port, "status": "error", "service": "unknown",
                       "error": str(e)}

            status = res["status"]
            results[status].append(res)

            # Print progress
            print_result(res, verbose)
            logger.debug(f"port={res['port']} status={status} "
                         f"service={res['service']}")

            # Live progress bar (overwrite same line)
            pct = int((completed / total) * 40)
            bar = f"[{'█'*pct}{'░'*(40-pct)}] {completed}/{total}"
            print(f"\r{C.GREY}  {bar}{C.RESET}", end="", flush=True)

    elapsed = (datetime.now() - start_time).total_seconds()
    open_ports = results["open"]

    print(f"\n\n{C.GREY}{'─'*60}{C.RESET}")
    print(f"\n{C.BOLD}{C.GREEN}  SCAN COMPLETE{C.RESET}")
    print(f"  ⏱  Elapsed  : {elapsed:.2f}s")
    print(f"  ✅ Open     : {C.GREEN}{len(open_ports)}{C.RESET}")
    print(f"  🔒 Closed   : {C.GREY}{len(results['closed'])}{C.RESET}")
    print(f"  ⏳ Timeout  : {C.YELLOW}{len(results['timeout'])}{C.RESET}")
    print(f"  ⚠  Errors   : {C.RED}{len(results['error'])}{C.RESET}")

    if open_ports:
        print(f"\n{C.BOLD}  Open Ports Summary:{C.RESET}")
        for r in sorted(open_ports, key=lambda x: x["port"]):
            svc = r["service"]
            banner = f"  → {r['banner']}" if r.get("banner") else ""
            print(f"    {C.GREEN}●{C.RESET}  {r['port']:<6} {C.CYAN}{svc}{C.RESET}{C.GREY}{banner}{C.RESET}")

    if log_file:
        print(f"\n{C.GREY}  Results logged → {log_file}{C.RESET}")

    logger.info(f"Scan complete → open={len(open_ports)}, "
                f"closed={len(results['closed'])}, "
                f"timeout={len(results['timeout'])}, "
                f"elapsed={elapsed:.2f}s")

    return results

# ─── CLI ──────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        prog="port_scanner.py",
        description="recon-x :: TCP Port Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python port_scanner.py -H 192.168.1.1 -p 1-1000
  python port_scanner.py -H scanme.nmap.org -p 22,80,443,3306,8080
  python port_scanner.py -H 10.0.0.1 -p 1-65535 -t 500 --log scan.log -v
        """
    )
    parser.add_argument("-H", "--host",    required=True,
                        help="Target host (IP or hostname)")
    parser.add_argument("-p", "--ports",   required=True,
                        help="Ports: single (80), list (22,80,443), range (1-1024), mixed (22,80,1000-2000)")
    parser.add_argument("-t", "--threads", type=int, default=200,
                        help="Number of threads (default: 200)")
    parser.add_argument("--timeout",       type=float, default=1.0,
                        help="Socket timeout in seconds (default: 1.0)")
    parser.add_argument("--log",           metavar="FILE",
                        help="Log results to a file")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show closed and timeout ports too")

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)

    args = parser.parse_args()
    try:
        run_scan(args)
    except KeyboardInterrupt:
        print(f"\n\n{C.YELLOW}[!] Scan interrupted by user.{C.RESET}")
        sys.exit(0)

if __name__ == "__main__":
    main()
