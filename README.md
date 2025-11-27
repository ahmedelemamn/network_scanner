# network_scanner

Simple Python script to scan a range of IP addresses using ICMP ping and TCP port probes.

## Requirements
- Python 3.8+
- Access to the `ping` command (used for ICMP checks)

## Usage
```
python network_scan.py <start_ip> <end_ip> [-p PORT [PORT ...]] [-o OUTPUT] [-t TIMEOUT] [-w WORKERS] [-v]
```

Examples:
- Scan a small range with default ports 22 (SSH), 23 (Telnet), 80, 443, and 9443:
  ```
  python network_scan.py 192.168.1.1 192.168.1.20
  ```
- Scan custom ports and save to a specific CSV file:
  ```
  python network_scan.py 10.0.0.1 10.0.0.50 -p 80 443 8080 -o my_scan.csv
  ```
- Run with more workers and verbose logging for faster, chatty scanning:
  ```
  python network_scan.py 10.0.0.1 10.0.0.254 -w 50 -v
  ```

The script outputs a CSV sheet where each row represents an IP and columns indicate whether ICMP responded and whether each TCP port accepted a connection. Logging reports progress per host, and `-v` enables debug details for each probe.

## Suggestions
- Run the script from a machine on the target network for reliable reachability tests.
- Adjust the timeout (`-t`) for high-latency networks.
- Pair the results with vulnerability scans or HTTP title grabs for richer context.
