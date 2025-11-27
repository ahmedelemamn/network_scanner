import argparse
import concurrent.futures
import csv
import ipaddress
import logging
import socket
import subprocess
from typing import Iterable, List, Dict

DEFAULT_PORTS = [80, 443, 9443]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Scan IPs via ICMP ping and TCP ports.")
    parser.add_argument("start_ip", help="Starting IP address of the range (inclusive)")
    parser.add_argument("end_ip", help="Ending IP address of the range (inclusive)")
    parser.add_argument(
        "-p",
        "--ports",
        type=int,
        nargs="+",
        default=DEFAULT_PORTS,
        help="TCP ports to probe (default: %(default)s)",
    )
    parser.add_argument(
        "-o",
        "--output",
        default="scan_results.csv",
        help="CSV file to write results to",
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
    return parser.parse_args()


def ip_range(start_ip: str, end_ip: str) -> Iterable[str]:
    start = ipaddress.ip_address(start_ip)
    end = ipaddress.ip_address(end_ip)
    if start.version != end.version:
        raise ValueError("Start and end IP versions do not match")
    if int(start) > int(end):
        raise ValueError("Start IP must be less than or equal to end IP")
    for i in range(int(start), int(end) + 1):
        yield str(ipaddress.ip_address(i))


def ping(ip: str, timeout: float) -> bool:
    cmd = ["ping", "-c", "1", "-W", str(int(max(timeout, 0.1))), ip]
    logging.debug("Pinging %s with timeout %ss", ip, timeout)
    proc = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    reachable = proc.returncode == 0
    logging.debug("Ping %s: %s", ip, "reachable" if reachable else "unreachable")
    return reachable


def scan_port(ip: str, port: int, timeout: float) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        try:
            sock.connect((ip, port))
            logging.debug("Port %s:%s open", ip, port)
            return True
        except (socket.timeout, ConnectionRefusedError, OSError):
            logging.debug("Port %s:%s closed or filtered", ip, port)
            return False


def scan_host(ip: str, ports: List[int], timeout: float) -> Dict[str, bool]:
    logging.info("Scanning host %s", ip)
    results = {"icmp": ping(ip, timeout)}
    for port in ports:
        results[f"tcp_{port}"] = scan_port(ip, port, timeout)
    logging.info(
        "Finished %s | ICMP: %s | TCP: %s",
        ip,
        "reachable" if results["icmp"] else "no reply",
        ", ".join(f"{port}:{'open' if results[f'tcp_{port}'] else 'closed'}" for port in ports),
    )
    return results


def write_results(rows: List[Dict[str, str]], ports: List[int], output: str) -> None:
    fieldnames = ["ip", "icmp"] + [f"tcp_{p}" for p in ports]
    with open(output, "w", newline="") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def main() -> None:
    args = parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )
    ports = sorted(set(args.ports))

    results: List[Dict[str, str]] = []
    all_ips = list(ip_range(args.start_ip, args.end_ip))
    logging.info(
        "Starting scan of %d host(s) across ports %s with %d worker(s)",
        len(all_ips),
        ", ".join(str(p) for p in ports),
        args.workers,
    )

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
        future_to_ip = {executor.submit(scan_host, ip, ports, args.timeout): ip for ip in all_ips}
        for future in concurrent.futures.as_completed(future_to_ip):
            ip = future_to_ip[future]
            host_result = future.result()
            results.append({"ip": ip, **host_result})

    results.sort(key=lambda row: ipaddress.ip_address(row["ip"]))
    write_results(results, ports, args.output)
    logging.info("Scan complete. Results saved to %s", args.output)


if __name__ == "__main__":
    main()
