import argparse
import concurrent.futures
import csv
import ipaddress
import json
import logging
import platform
import socket
import subprocess
import sys
from typing import Iterable, List, Dict, Union, Optional, Tuple

DEFAULT_PORTS = [22, 23, 80, 443, 9443]


def parse_ports(port_args: List[str]) -> List[int]:
    """Parse a list of port strings, handling ranges like '80-100'."""
    ports = set()
    for part in port_args:
        if "-" in part:
            try:
                start, end = map(int, part.split("-"))
                if start > end:
                    raise ValueError(f"Invalid range: {part}")
                ports.update(range(start, end + 1))
            except ValueError as e:
                logging.error("Error parsing port range '%s': %s", part, e)
                sys.exit(1)
        else:
            try:
                ports.add(int(part))
            except ValueError:
                logging.error("Invalid port number: %s", part)
                sys.exit(1)
    return sorted(list(ports))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Scan IPs via ICMP ping and TCP ports.")
    
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("start_ip", nargs="?", help="Starting IP address of the range (inclusive)")
    group.add_argument("--network", "-n", help="CIDR network notation (e.g., 192.168.1.0/24)")
    
    parser.add_argument("end_ip", nargs="?", help="Ending IP address of the range (inclusive)")
    
    parser.add_argument(
        "-p",
        "--ports",
        nargs="+",
        default=[str(p) for p in DEFAULT_PORTS],
        help="TCP ports to probe. Can be single ports (80) or ranges (80-100). Default: 22, 23, 80, 443, 9443",
    )
    parser.add_argument(
        "-o",
        "--output",
        default="scan_results.csv",
        help="File to write results to (CSV or JSON based on extension or flag)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Force JSON output format",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=1.0,
        help="Timeout in seconds for ping and TCP connections",
    )
    parser.add_argument(
        "-w",
        "--workers",
        type=int,
        default=20,
        help="Number of concurrent workers for scanning hosts",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose debug logging",
    )
    parser.add_argument(
        "--no-resolve",
        action="store_true",
        help="Disable hostname resolution",
    )
    
    args = parser.parse_args()
    
    if args.network and (args.start_ip or args.end_ip):
        parser.error("Cannot specify both --network and start/end IPs")
    if not args.network and not (args.start_ip and args.end_ip):
        # Allow single IP scanning if only start_ip is provided? 
        # The original script required both. Let's stick to requiring both or network.
        # But wait, if I want to scan one IP, start=end is annoying.
        # Let's handle: if start_ip is given but end_ip is not, assume single IP.
        if args.start_ip and not args.end_ip:
            args.end_ip = args.start_ip
        elif not args.start_ip:
             parser.error("Must specify either start_ip/end_ip or --network")

    return args


def ip_range(start_ip: Optional[str], end_ip: Optional[str], network: Optional[str]) -> Iterable[str]:
    if network:
        try:
            net = ipaddress.ip_network(network, strict=False)
            for ip in net.hosts():
                yield str(ip)
            # Include network and broadcast if they are valid IPs? usually we scan hosts.
            # ip_network.hosts() excludes network and broadcast addresses.
        except ValueError as e:
            logging.error("Invalid network CIDR: %s", e)
            sys.exit(1)
    else:
        try:
            start = ipaddress.ip_address(start_ip)
            end = ipaddress.ip_address(end_ip)
            if start.version != end.version:
                raise ValueError("Start and end IP versions do not match")
            if int(start) > int(end):
                raise ValueError("Start IP must be less than or equal to end IP")
            for i in range(int(start), int(end) + 1):
                yield str(ipaddress.ip_address(i))
        except ValueError as e:
            logging.error("Invalid IP range: %s", e)
            sys.exit(1)


def ping(ip: str, timeout: float) -> bool:
<<<<<<< HEAD
    """Ping an IP address with platform-aware flags.

    Windows uses different flags and expects timeout in milliseconds, while
    Linux/macOS use ``-c``/``-W`` with whole-second timeouts. This keeps the
    interface consistent across platforms so ICMP results are reliable for
    Windows users.
    """

    if platform.system().lower().startswith("win"):
        # Windows: -n (count), -w (timeout in ms)
        timeout_ms = max(int(timeout * 1000), 1)
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    else:
        # Unix-like: -c (count), -W (timeout in seconds)
        cmd = ["ping", "-c", "1", "-W", str(int(max(timeout, 1))), ip]
    logging.debug("Pinging %s with timeout %ss", ip, timeout)
    proc = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    reachable = proc.returncode == 0
=======
    param = "-n" if platform.system().lower() == "windows" else "-c"
    timeout_param = "-w" if platform.system().lower() == "windows" else "-W"
    # Windows timeout is in milliseconds, Unix in seconds (usually)
    # Actually, macOS ping -W is in milliseconds, Linux ping -W is in seconds.
    # This is tricky. Let's assume standard Linux ping for Unix.
    # Wait, macOS ping man page: -W waittime (in msec).
    # Linux ping man page: -W timeout (in seconds).
    # To be safe, we can use a generous timeout or try to detect OS flavor more granularly.
    # Or just use a standard subprocess timeout.
    
    # Let's rely on subprocess.run timeout for the execution limit, 
    # and pass a flag that works for "wait for reply".
    
    cmd = ["ping", param, "1", ip]
    
    # Adjusting command for timeout is messy across platforms. 
    # Let's just trust the subprocess timeout to kill it if it hangs, 
    # but we need the ping command itself to fail fast if unreachable.
    
    if platform.system().lower() != "windows":
         # On Unix, -W 1 is usually 1 second.
         cmd.extend(["-W", str(int(max(timeout, 1)))])
    else:
         # On Windows, -w 1000 is 1000ms.
         cmd.extend(["-w", str(int(timeout * 1000))])

    logging.debug("Pinging %s", ip)
    try:
        proc = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=timeout + 1)
        reachable = proc.returncode == 0
    except subprocess.TimeoutExpired:
        reachable = False
        
>>>>>>> 57e1436 (update)
    logging.debug("Ping %s: %s", ip, "reachable" if reachable else "unreachable")
    return reachable


def get_banner(sock: socket.socket) -> str:
    try:
        # Send a dummy byte to trigger a response from some protocols
        # sock.send(b'\r\n') 
        # Actually, many services send a banner on connect (SSH, SMTP, FTP).
        # HTTP needs a request.
        # Let's just peek/recv.
        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        return banner
    except Exception:
        return ""


def scan_port(ip: str, port: int, timeout: float) -> Tuple[bool, str]:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        try:
            sock.connect((ip, port))
            logging.debug("Port %s:%s open", ip, port)
            
            # Try to grab banner
            banner = ""
            try:
                # Set a short timeout for banner grabbing
                sock.settimeout(0.5)
                banner = get_banner(sock)
            except:
                pass
                
            return True, banner
        except (socket.timeout, ConnectionRefusedError, OSError):
            logging.debug("Port %s:%s closed or filtered", ip, port)
            return False, ""


def resolve_hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return ""


def scan_host(ip: str, ports: List[int], timeout: float, resolve: bool) -> Dict[str, Union[str, bool, Dict]]:
    logging.info("Scanning host %s", ip)
    
    hostname = ""
    if resolve:
        hostname = resolve_hostname(ip)
        
    icmp_result = ping(ip, timeout)
    
    tcp_results = {}
    banners = {}
    
    # If ICMP fails, should we skip TCP? 
    # Often firewalls block ICMP but allow TCP. Let's scan TCP anyway unless user wants optimization.
    # For this script, we scan everything.
    
    for port in ports:
        is_open, banner = scan_port(ip, port, timeout)
        tcp_results[port] = is_open
        if is_open and banner:
            banners[port] = banner

    logging.info(
        "Finished %s (%s) | ICMP: %s | Open Ports: %s",
        ip,
        hostname if hostname else "N/A",
        "reachable" if icmp_result else "no reply",
        ", ".join(str(p) for p, open in tcp_results.items() if open),
    )
    
    return {
        "ip": ip,
        "hostname": hostname,
        "icmp": icmp_result,
        "tcp": tcp_results,
        "banners": banners
    }


def write_results_csv(results: List[Dict], ports: List[int], output_file: str) -> None:
    # Flatten structure for CSV
    # ip, hostname, icmp, tcp_22, banner_22, tcp_80, banner_80...
    fieldnames = ["ip", "hostname", "icmp"]
    for p in ports:
        fieldnames.append(f"tcp_{p}")
        fieldnames.append(f"banner_{p}")
        
    with open(output_file, "w", newline="") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for row in results:
            flat_row = {
                "ip": row["ip"],
                "hostname": row["hostname"],
                "icmp": row["icmp"],
            }
            for p in ports:
                flat_row[f"tcp_{p}"] = row["tcp"].get(p, False)
                flat_row[f"banner_{p}"] = row["banners"].get(p, "")
            writer.writerow(flat_row)


def write_results_json(results: List[Dict], output_file: str) -> None:
    # We can dump the results directly, maybe clean up keys for readability
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)


def main() -> None:
    args = parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )
    
    ports = parse_ports(args.ports)
    
    all_ips = list(ip_range(args.start_ip, args.end_ip, args.network))
    logging.info(
        "Starting scan of %d host(s) across %d ports with %d worker(s)",
        len(all_ips),
        len(ports),
        args.workers,
    )

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
        future_to_ip = {
            executor.submit(scan_host, ip, ports, args.timeout, not args.no_resolve): ip 
            for ip in all_ips
        }
        for future in concurrent.futures.as_completed(future_to_ip):
            results.append(future.result())

    results.sort(key=lambda row: ipaddress.ip_address(row["ip"]))
    
    is_json = args.json or args.output.lower().endswith(".json")
    
    if is_json:
        write_results_json(results, args.output)
    else:
        write_results_csv(results, ports, args.output)
        
    logging.info("Scan complete. Results saved to %s", args.output)


if __name__ == "__main__":
    main()
