import argparse
import concurrent.futures
import csv
import ipaddress
import json
import logging
import platform
import socket
import ssl
import subprocess
import sys
from typing import Iterable, List, Dict, Union, Optional, Tuple

# Added 5480 (vCenter Appliance), 9440 (Nutanix Prism)
DEFAULT_PORTS = [22, 23, 80, 443, 5480, 9440, 9443]


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
        help="TCP ports to probe. Can be single ports (80) or ranges (80-100). Default: " + ", ".join(map(str, DEFAULT_PORTS)),
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
    param = "-n" if platform.system().lower() == "windows" else "-c"
    
    cmd = ["ping", param, "1", ip]
    
    if platform.system().lower() != "windows":
         cmd.extend(["-W", str(int(max(timeout, 1)))])
    else:
         cmd.extend(["-w", str(int(timeout * 1000))])

    logging.debug("Pinging %s", ip)
    try:
        proc = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=timeout + 1)
        reachable = proc.returncode == 0
    except subprocess.TimeoutExpired:
        reachable = False
        
    logging.debug("Ping %s: %s", ip, "reachable" if reachable else "unreachable")
    return reachable


def get_banner(ip: str, port: int, sock: socket.socket, timeout: float) -> str:
    """Attempt to retrieve a banner. Supports SSH, basic HTTP(S) details."""
    try:
        sock.settimeout(timeout)
        
        # Check if port is typically SSL/TLS
        is_ssl = port in [443, 9443, 5480, 9440]
        
        # 1. Try raw recv first (for SSH, FTP, etc.)
        if not is_ssl:
            try:
                # Peek or short recv
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                if banner and "SSH" in banner:
                    return banner
                # If not SSH, we might still want to try HTTP if it looks like garbage or empty
            except socket.timeout:
                pass
            except Exception:
                pass

        # 2. If it's HTTP/HTTPS or we got no banner, try sending a request
        # Wrap socket if SSL
        target_sock = sock
        context = None
        if is_ssl:
            try:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                target_sock = context.wrap_socket(sock, server_hostname=ip)
            except Exception as e:
                logging.debug("SSL wrap failed for %s:%s: %s", ip, port, e)
                return ""

        # Send HTTP GET
        request = f"GET / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n"
        target_sock.sendall(request.encode())
        
        response = b""
        while True:
            try:
                data = target_sock.recv(4096)
                if not data:
                    break
                response += data
                # Stop if we have <title> or enough data
                if len(response) > 15000:
                    break
            except socket.timeout:
                break
            except Exception:
                break
                
        decoded = response.decode('utf-8', errors='ignore')
        if not decoded:
            return ""

        # Parse interesting bits
        import re
        parts = []
        
        # Status Line
        status_match = re.match(r'HTTP/\d\.\d\s+(\d{3})', decoded)
        if status_match:
            parts.append(f"HTTP {status_match.group(1)}")
            
        # Server
        server_match = re.search(r'Server: (.*?)\r\n', decoded, re.IGNORECASE)
        if server_match:
            parts.append(f"Server: {server_match.group(1).strip()}")
            
        # Location (if redirect)
        loc_match = re.search(r'Location: (.*?)\r\n', decoded, re.IGNORECASE)
        if loc_match:
            parts.append(f"Location: {loc_match.group(1).strip()}")

        # Title
        title_match = re.search(r'<title>(.*?)</title>', decoded, re.IGNORECASE | re.DOTALL)
        if title_match:
            # Clean up newlines/tabs in title
            clean_title = " ".join(title_match.group(1).strip().split())
            parts.append(f"Title: {clean_title}")
            
        return " | ".join(parts)

    except Exception as e:
        logging.debug("Banner grab failed for %s:%s: %s", ip, port, e)
        return ""


def scan_port(ip: str, port: int, timeout: float) -> Tuple[bool, str]:
    # Use simple socket for connection test first
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        try:
            sock.connect((ip, port))
            logging.debug("Port %s:%s open", ip, port)
            
            # Try to grab banner
            banner = ""
            try:
                # We need to clone/re-use socket or just use the connected one. 
                # get_banner might wrap it in SSL, so let's pass it.
                # NOTE: Wrapping closes the original fd if we are not careful, 
                # but we are in a with block.
                banner = get_banner(ip, port, sock, 1.5) # slightly longer timeout for banner
            except Exception as e:
                logging.debug("Banner grab outer logic failed: %s", e)
                
            return True, banner
        except (socket.timeout, ConnectionRefusedError, OSError):
            logging.debug("Port %s:%s closed or filtered", ip, port)
            return False, ""


def resolve_hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return ""


def classify_device(ip: str, tcp_results: Dict[int, bool], banners: Dict[int, str]) -> str:
    """Classify device based on ports and banners."""
    
    combined_banners = " ".join(banners.values()).lower()

    # 1. Nutanix Prism (9440)
    if tcp_results.get(9440):
        return "Nutanix Prism"
        
    # 2. vCenter
    # Check 5480 banner for "appliance" or redirect to port 5480
    if tcp_results.get(5480):
        banner_5480 = banners.get(5480, "").lower()
        if "appliance" in banner_5480 or "vcenter" in banner_5480: 
             return "VMware vCenter Appliance"
        return "VMware vCenter (Likely)"
    
    if "vsphere client" in combined_banners or "visphere client" in combined_banners:
        return "VMware vCenter"
        
    if "vcenter" in combined_banners:
        return "VMware vCenter"

    # 3. ESXi
    if "esxi" in combined_banners:
        return "VMware ESXi"
    if "vmware" in combined_banners and "id_esx" in combined_banners: # Check for common VMware cookies/headers
        return "VMware ESXi"

    # 4. Cisco CIMC
    if "cisco integrated management controller" in combined_banners or "cimc" in combined_banners:
        return "Cisco CIMC"

    # 5. Nexus Switch
    ssh_banner = banners.get(22, "").lower()
    if "cisco" in ssh_banner or "nx-os" in ssh_banner or "nexus" in ssh_banner:
        return "Cisco Nexus/IOS"
        
    # Generic Fallbacks
    if "vmware" in combined_banners:
        return "VMware Device"
    if "cisco" in combined_banners:
        return "Cisco Device"
    if "jetty" in combined_banners: # Often embedded devices
        return "Embedded Device (Jetty)"
    
    return "Unknown"


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

    device_type = classify_device(ip, tcp_results, banners)

    logging.info(
        "Finished %s (%s) [%s] | ICMP: %s | Open Ports: %s",
        ip,
        hostname if hostname else "N/A",
        device_type,
        "reachable" if icmp_result else "no reply",
        ", ".join(str(p) for p, open in tcp_results.items() if open),
    )
    
    return {
        "ip": ip,
        "hostname": hostname,
        "device_type": device_type,
        "icmp": icmp_result,
        "tcp": tcp_results,
        "banners": banners
    }


def write_results_csv(results: List[Dict], ports: List[int], output_file: str) -> None:
    # Flatten structure for CSV
    # ip, hostname, device_type, icmp, tcp_22, banner_22, ...
    fieldnames = ["ip", "hostname", "device_type", "icmp"]
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
                "device_type": row["device_type"],
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
