import unittest
from unittest.mock import patch, MagicMock
import ipaddress
import sys
import os

# Ensure we can import the module
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
import network_scan

class TestNetworkScan(unittest.TestCase):

    def test_parse_ports_single(self):
        self.assertEqual(network_scan.parse_ports(["80", "443"]), [80, 443])

    def test_parse_ports_range(self):
        self.assertEqual(network_scan.parse_ports(["80-82"]), [80, 81, 82])

    def test_parse_ports_mixed(self):
        self.assertEqual(network_scan.parse_ports(["22", "80-81"]), [22, 80, 81])

    def test_parse_ports_invalid(self):
        with self.assertRaises(SystemExit):
            network_scan.parse_ports(["80-abc"])

    def test_ip_range_cidr(self):
        ips = list(network_scan.ip_range(None, None, "192.168.1.0/30"))
        # 192.168.1.0/30 has 4 IPs, but hosts() returns usable IPs: .1, .2
        expected = ["192.168.1.1", "192.168.1.2"]
        self.assertEqual(sorted(ips), sorted(expected))

    def test_ip_range_start_end(self):
        ips = list(network_scan.ip_range("192.168.1.1", "192.168.1.3", None))
        expected = ["192.168.1.1", "192.168.1.2", "192.168.1.3"]
        self.assertEqual(sorted(ips), sorted(expected))

    @patch("subprocess.run")
    def test_ping_success(self, mock_run):
        mock_run.return_value.returncode = 0
        self.assertTrue(network_scan.ping("127.0.0.1", 1.0))

    @patch("subprocess.run")
    def test_ping_failure(self, mock_run):
        mock_run.return_value.returncode = 1
        self.assertFalse(network_scan.ping("127.0.0.1", 1.0))

    @patch("socket.socket")
    def test_scan_port_open(self, mock_socket):
        mock_sock_instance = MagicMock()
        mock_socket.return_value.__enter__.return_value = mock_sock_instance
        
        # Mock successful connect
        mock_sock_instance.connect.return_value = None
        # Mock banner recv
        mock_sock_instance.recv.return_value = b"SSH-2.0-OpenSSH\n"
        
        is_open, banner = network_scan.scan_port("127.0.0.1", 22, 1.0)
        self.assertTrue(is_open)
        self.assertEqual(banner, "SSH-2.0-OpenSSH")

    @patch("socket.socket")
    def test_scan_port_closed(self, mock_socket):
        mock_sock_instance = MagicMock()
        mock_socket.return_value.__enter__.return_value = mock_sock_instance
        
        # Mock connection refused
        mock_sock_instance.connect.side_effect = ConnectionRefusedError
        
        is_open, banner = network_scan.scan_port("127.0.0.1", 22, 1.0)
        self.assertFalse(is_open)
        self.assertEqual(banner, "")

    def test_classify_nutanix(self):
        tcp = {9440: True}
        banners = {}
        self.assertEqual(network_scan.classify_device("1.2.3.4", tcp, banners), "Nutanix Prism")

    def test_classify_esxi(self):
        tcp = {443: True, 80: True}
        banners = {80: "HTTP 302 | Location: https://1.2.3.4/ui", 443: "HTTP 200 | Title: VMware ESXi"}
        self.assertEqual(network_scan.classify_device("1.2.3.4", tcp, banners), "VMware ESXi")
    
    def test_classify_vcenter(self):
        tcp = {5480: True}
        banners = {}
        self.assertEqual(network_scan.classify_device("1.2.3.4", tcp, banners), "VMware vCenter (Likely)")
        
        tcp = {443: True}
        banners = {443: "HTTP 200 | Title: vSphere Client"}
        self.assertEqual(network_scan.classify_device("1.2.3.4", tcp, banners), "VMware vCenter")

    def test_classify_cimc(self):
        tcp = {443: True}
        banners = {443: "HTTP 200 | Title: Cisco Integrated Management Controller"}
        self.assertEqual(network_scan.classify_device("1.2.3.4", tcp, banners), "Cisco CIMC")

    def test_classify_nexus(self):
        tcp = {22: True}
        banners = {22: "SSH-2.0-Cisco-1.25"}
        self.assertEqual(network_scan.classify_device("1.2.3.4", tcp, banners), "Cisco Nexus/IOS")
        
        banners = {22: "SSH-2.0-NX-OS"}
        self.assertEqual(network_scan.classify_device("1.2.3.4", tcp, banners), "Cisco Nexus/IOS")

    def test_classify_unknown(self):
        tcp = {80: True}
        banners = {80: "HTTP 200 | Server: Apache"}
        self.assertEqual(network_scan.classify_device("1.2.3.4", tcp, banners), "Unknown")

if __name__ == "__main__":
    unittest.main()
