import argparse
import csv
import ipaddress
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
    proc = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return proc.returncode == 0


def scan_port(ip: str, port: int, timeout: float) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        try:
            sock.connect((ip, port))
            return True
        except (socket.timeout, ConnectionRefusedError, OSError):
            return False


def scan_host(ip: str, ports: List[int], timeout: float) -> Dict[str, bool]:
    results = {"icmp": ping(ip, timeout)}
    for port in ports:
        results[f"tcp_{port}"] = scan_port(ip, port, timeout)
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
    ports = sorted(set(args.ports))

    results: List[Dict[str, str]] = []
    for ip in ip_range(args.start_ip, args.end_ip):
        host_result = scan_host(ip, ports, args.timeout)
        results.append({"ip": ip, **host_result})

    write_results(results, ports, args.output)
    print(f"Scan complete. Results saved to {args.output}")


if __name__ == "__main__":
    main()
