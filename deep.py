import os
import socket
import subprocess
import threading
import time
import struct
import random
import re
import json
import hashlib
import secrets
import shutil
from datetime import datetime
from flask import Flask, request, jsonify, render_template, make_response, send_from_directory
from concurrent.futures import ThreadPoolExecutor, as_completed
import ipaddress

def check_and_install_tools():
    """Check for required tools and install if missing (for dev environments)"""
    tools_needed = []
    
    if not shutil.which('ping'):
        tools_needed.append('iputils-ping')
    if not shutil.which('traceroute'):
        tools_needed.append('traceroute')
    
    if tools_needed:
        print(f"⚠️  Missing tools: {', '.join(tools_needed)}")
        print("   Attempting to install...")
        try:
            # Try with sudo first (common in dev environments)
            subprocess.run(
                ['sudo', 'apt-get', 'update', '-qq'],
                capture_output=True,
                timeout=60
            )
            subprocess.run(
                ['sudo', 'apt-get', 'install', '-y', '-qq'] + tools_needed,
                capture_output=True,
                timeout=120
            )
            print(f"   ✓ Installed: {', '.join(tools_needed)}")
        except:
            try:
                # Try without sudo
                subprocess.run(
                    ['apt-get', 'update', '-qq'],
                    capture_output=True,
                    timeout=60
                )
                subprocess.run(
                    ['apt-get', 'install', '-y', '-qq'] + tools_needed,
                    capture_output=True,
                    timeout=120
                )
                print(f"   ✓ Installed: {', '.join(tools_needed)}")
            except Exception as e:
                print(f"   ✗ Could not install tools: {e}")
                print("   Note: Ping/traceroute will use TCP fallback methods")

# Check tools on startup
check_and_install_tools()

app = Flask(__name__)

# Security: Rate limiting and consent tracking
rate_limit_store = {}  # IP -> {count, first_request_time}
rate_limit_lock = threading.Lock()
consent_tokens = {}  # token -> {ip, timestamp}
consent_lock = threading.Lock()

# Rate limit settings
MAX_SCANS_PER_HOUR = 10
RATE_LIMIT_WINDOW = 3600  # 1 hour in seconds
CONSENT_TOKEN_EXPIRY = 3600  # 1 hour
SECRET_KEY = secrets.token_hex(32)  # For signing tokens

# Scan queue system - only 1 scan at a time
from queue import Queue
import collections

scan_queue = Queue()
queue_order = collections.deque()  # Track queue order for position
queue_lock = threading.Lock()
current_scan_ip = None  # Track which IP is currently being scanned

def queue_worker():
    """Background worker that processes scans one at a time"""
    global current_scan_ip
    while True:
        scan_job = scan_queue.get()
        if scan_job is None:
            break
        
        scan_id, target, config, resolved_ip = scan_job
        
        with queue_lock:
            current_scan_ip = resolved_ip
            if resolved_ip in queue_order:
                queue_order.remove(resolved_ip)
        
        try:
            config['_validated_ip'] = resolved_ip
            scanner = DeepScanner(target, config)
            results = scanner.run_scan()
            with scan_lock:
                scan_results[scan_id] = results
        except Exception as e:
            with scan_lock:
                scan_results[scan_id] = {
                    'status': 'error',
                    'error': str(e)
                }
        finally:
            with queue_lock:
                current_scan_ip = None
            scan_queue.task_done()

# Start the queue worker thread
queue_thread = threading.Thread(target=queue_worker, daemon=True)
queue_thread.start()

# Scanner implementation
class DeepScanner:
    def __init__(self, target, config):
        self.target = target
        self.config = config
        self.ip_address = None
        self. hostname = None
        self.os_guess = "Unknown"
        self.ports = []
        self.alive = False
        self.latency = None
        self.start_time = None
        
        # Common ports - includes game servers, Minecraft, etc.
        self.top_100_tcp = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 
                            1723, 3306, 3389, 5900, 8080, 8443, 20, 69, 137, 138, 161, 162, 389,
                            636, 1433, 1434, 1521, 2049, 2121, 3268, 5432, 5800, 5901, 6379, 8000,
                            8008, 8081, 8888, 9000, 9090, 9100, 9200, 9300, 10000, 27017, 50000,
                            515, 548, 631, 873, 902, 1080, 1194, 1352, 1433, 1720, 2082, 2083,
                            2222, 3000, 3128, 3690, 4443, 4444, 4567, 5000, 5001, 5060, 5222,
                            5269, 5357, 5432, 5555, 5672, 5985, 5986, 6000, 6001, 6379, 6666,
                            7001, 7070, 7777, 8001, 8009, 8042, 8069, 8082, 8083, 8181, 8200,
                            8300, 8500, 8600, 8834, 9001, 9080, 9081, 9418, 9999, 11211, 27018,
                            # Game servers
                            25565, 25566, 25567,  # Minecraft Java
                            19132, 19133,  # Minecraft Bedrock (also UDP)
                            27015, 27016,  # Source games (CS, TF2, etc.)
                            7777, 7778,  # Terraria, Ark, Unreal
                            2456, 2457, 2458,  # Valheim
                            6567,  # Starbound
                            28015, 28016,  # Rust
                            16261, 16262,  # Project Zomboid
                            34197,  # Factorio
                            11211,  # Memcached
                            ]
        
        self.top_100_udp = [53, 67, 68, 69, 123, 135, 137, 138, 139, 161, 162, 445, 500, 514, 520,
                            631, 1434, 1900, 4500, 49152, 49153, 49154, 5353, 1701, 1812, 1813,
                            2049, 3478, 5060, 5353, 10000, 17185, 20031, 33434, 47808, 49156,
                            111, 177, 427, 497, 512, 513, 518, 626, 996, 997, 998, 1023, 1025,
                            1026, 1027, 1028, 1029, 1030, 1645, 1646, 1718, 1719, 2000, 2223,
                            3283, 3456, 4000, 5000, 5001, 5004, 5005, 5351, 6346, 9200, 10080,
                            11487, 16464, 16465, 16470, 16471, 17185, 19283, 19682, 20031, 26000,
                            26262, 30120, 31337, 32768, 32769, 32770, 32771, 32772, 32773, 32774,
                            32775, 33281, 41524, 44818, 49152, 49153, 49154, 54321, 57621, 58002,
                            # Game servers
                            19132, 19133,  # Minecraft Bedrock
                            27015, 27016,  # Source games (CS, TF2)
                            7777, 7778,  # Ark, Unreal
                            2456, 2457, 2458,  # Valheim
                            34197,  # Factorio
                            ]

    def resolve_target(self):
        """Resolve hostname to IP"""
        # Use pre-validated IP if available (from security check)
        if self.config.get('_validated_ip'):
            self.ip_address = self.config['_validated_ip']
            try:
                self.hostname = socket.gethostbyaddr(self.ip_address)[0]
            except:
                self.hostname = self.target
            return
        
        try:
            ipaddress.ip_address(self.target)
            self.ip_address = self.target
            try:
                self.hostname = socket.gethostbyaddr(self.target)[0]
            except: 
                self.hostname = self.target
        except ValueError:
            try:
                self.ip_address = socket.gethostbyname(self.target)
                self.hostname = self.target
            except socket.gaierror:
                raise Exception(f"Could not resolve: {self.target}")

    def check_alive(self):
        """Check if host is alive and measure latency using TCP connect"""
        if not self.config.get('check_alive', True):
            self.alive = True
            self.latency = None
            return
        
        if not self.ip_address:
            self.alive = False
            self.latency = None
            return
        
        # Use TCP connect as primary method (works when ICMP is blocked)
        self.alive = False
        self.latency = None
        
        for test_port in [80, 443, 53, 22, 21, 25, 8080]:
            try:
                start = time.time()
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((self.ip_address, test_port))
                elapsed = time.time() - start
                sock.close()
                
                if result == 0:
                    latency_ms = round(elapsed * 1000, 1)
                    self.alive = True
                    self.latency = f"{latency_ms}ms"
                    return
            except:
                pass
        
        # Fallback: try ICMP ping if TCP failed
        try:
            param = '-n' if os.name == 'nt' else '-c'
            result = subprocess.run(
                ['ping', param, '1', '-W', '2', self.ip_address],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                self.alive = True
                # Parse actual RTT from ping output
                output = result.stdout
                match = re.search(r'time[=<](\d+\.?\d*)\s*ms', output, re.IGNORECASE)
                if match:
                    self.latency = f"{match.group(1)}ms"
        except:
            pass

    def scan_tcp_port(self, port):
        """Scan single TCP port - optimized for speed"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)  # Faster timeout
            result = sock.connect_ex((self.ip_address, port))
            sock.close()
            
            if result == 0:
                return {'port': port, 'protocol': 'tcp', 'state': 'open'}
        except:
            pass
        return None

    def scan_udp_port(self, port):
        """Scan single UDP port - only return if we get an actual response"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3)
            
            # Send protocol-specific probes for better detection
            probe = self.get_udp_probe(port)
            sock.sendto(probe, (self.ip_address, port))
            
            try:
                data, _ = sock.recvfrom(1024)
                sock.close()
                # Only return if we got actual data back - this is a confirmed open port
                if data:
                    return {'port': port, 'protocol': 'udp', 'state': 'open'}
            except socket.timeout:
                # No response - could be open, closed, or filtered
                # Don't report these as they're unreliable
                sock.close()
                return None
        except:
            pass
        return None
    
    def get_udp_probe(self, port):
        """Get protocol-specific UDP probe for better detection"""
        # Build Minecraft Bedrock probe dynamically
        mc_bedrock_probe = b'\x01' + struct.pack('>Q', int(time.time() * 1000)) + b'\x00\xff\xff\x00\xfe\xfe\xfe\xfe\xfd\xfd\xfd\xfd\x12\x34\x56\x78' + b'\x00' * 8
        
        probes = {
            53: self.build_dns_query('google.com'),  # Real DNS query for google.com
            123: b'\x1b' + b'\x00' * 47,  # NTP request
            161: b'\x30\x26\x02\x01\x01\x04\x06public\xa0\x19\x02\x04\x00\x00\x00\x00\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00',  # SNMP
            137: b'\x80\xf0\x00\x10\x00\x01\x00\x00\x00\x00\x00\x00\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01',  # NetBIOS
            1900: b'M-SEARCH * HTTP/1.1\r\nHost:239.255.255.250:1900\r\nST:ssdp:all\r\nMan:"ssdp:discover"\r\nMX:3\r\n\r\n',  # SSDP
            5353: b'\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x09_services\x07_dns-sd\x04_udp\x05local\x00\x00\x0c\x00\x01',  # mDNS
            # Minecraft Bedrock - Unconnected Ping packet (RakNet)
            19132: mc_bedrock_probe,
            19133: mc_bedrock_probe,
            # Source engine query
            27015: b'\xff\xff\xff\xffTSource Engine Query\x00',
            27016: b'\xff\xff\xff\xffTSource Engine Query\x00',
        }
        return probes.get(port, b'\x00')
    
    def build_dns_query(self, domain):
        """Build a proper DNS query packet for a domain"""
        # Transaction ID (random)
        packet = struct.pack('>H', random.randint(0, 65535))
        # Flags: standard query
        packet += struct.pack('>H', 0x0100)
        # Questions: 1, Answers: 0, Authority: 0, Additional: 0
        packet += struct.pack('>HHHH', 1, 0, 0, 0)
        # Query name
        for part in domain.split('.'):
            packet += struct.pack('B', len(part)) + part.encode()
        packet += b'\x00'  # End of name
        # Type: A record (1), Class: IN (1)
        packet += struct.pack('>HH', 1, 1)
        return packet
    
    def detect_dns_service(self, protocol):
        """Detect DNS server by actually querying it"""
        try:
            # Test with a real DNS query to google.com
            query = self.build_dns_query('google.com')
            
            if protocol == 'tcp':
                # TCP DNS uses length prefix
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((self.ip_address, 53))
                # Send with 2-byte length prefix for TCP DNS
                sock.send(struct.pack('>H', len(query)) + query)
                # Read response length
                length_data = sock.recv(2)
                if length_data:
                    resp_len = struct.unpack('>H', length_data)[0]
                    response = sock.recv(resp_len)
                else:
                    response = None
                sock.close()
            else:
                # UDP DNS
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(5)
                sock.sendto(query, (self.ip_address, 53))
                response, _ = sock.recvfrom(512)
                sock.close()
            
            if response and len(response) > 12:
                # Got a valid DNS response!
                # Try to detect DNS server type from response
                product, version = self.identify_dns_server(response)
                return 'DNS Response OK', product, version
                
        except socket.timeout:
            return 'DNS (no response)', None, None
        except Exception as e:
            pass
        return None, None, None
    
    def identify_dns_server(self, response):
        """Try to identify DNS server from response"""
        # Most DNS servers don't reveal themselves in regular queries
        # We'd need to do a CHAOS TXT query for version.bind to detect
        # For now, return generic DNS server
        try:
            # Try a CHAOS TXT version.bind query
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3)
            
            # Build version.bind query
            packet = struct.pack('>H', random.randint(0, 65535))  # Transaction ID
            packet += struct.pack('>H', 0x0100)  # Standard query
            packet += struct.pack('>HHHH', 1, 0, 0, 0)  # 1 question
            # version.bind
            packet += b'\x07version\x04bind\x00'
            # Type TXT (16), Class CHAOS (3)
            packet += struct.pack('>HH', 16, 3)
            
            sock.sendto(packet, (self.ip_address, 53))
            version_resp, _ = sock.recvfrom(512)
            sock.close()
            
            if len(version_resp) > 12:
                # Try to extract version string from response
                version_str = self.parse_dns_txt_response(version_resp)
                if version_str:
                    # Identify server from version string
                    version_lower = version_str.lower()
                    if 'bind' in version_lower or 'named' in version_lower:
                        match = re.search(r'(\d+\.\d+\.?\d*)', version_str)
                        return 'BIND', match.group(1) if match else None
                    elif 'dnsmasq' in version_lower:
                        match = re.search(r'(\d+\.\d+)', version_str)
                        return 'dnsmasq', match.group(1) if match else None
                    elif 'unbound' in version_lower:
                        return 'Unbound', None
                    elif 'powerdns' in version_lower:
                        return 'PowerDNS', None
                    else:
                        return 'DNS Server', version_str[:20]
                        
        except:
            pass
        
        return 'DNS Server', None
    
    def parse_dns_txt_response(self, response):
        """Parse TXT record from DNS response"""
        try:
            # Skip header (12 bytes) and question section
            pos = 12
            # Skip question name
            while pos < len(response) and response[pos] != 0:
                if response[pos] & 0xc0 == 0xc0:  # Pointer
                    pos += 2
                    break
                pos += response[pos] + 1
            else:
                pos += 1
            # Skip question type and class
            pos += 4
            
            # Parse answer
            if pos + 12 < len(response):
                # Skip answer name (could be pointer)
                if response[pos] & 0xc0 == 0xc0:
                    pos += 2
                else:
                    while pos < len(response) and response[pos] != 0:
                        pos += response[pos] + 1
                    pos += 1
                
                # Skip type, class, TTL
                pos += 8
                # Read data length
                if pos + 2 <= len(response):
                    rdlength = struct.unpack('>H', response[pos:pos+2])[0]
                    pos += 2
                    if pos + rdlength <= len(response):
                        # TXT format: length byte + string
                        txt_len = response[pos]
                        if pos + 1 + txt_len <= len(response):
                            return response[pos+1:pos+1+txt_len].decode('utf-8', errors='ignore')
        except:
            pass
        return None

    def get_service_name(self, port, protocol):
        """Get service name for port"""
        # Check custom services FIRST for better naming
        services = {
            80: 'http', 443: 'https', 22: 'ssh', 21: 'ftp', 23: 'telnet',
            25: 'smtp', 53: 'dns', 67: 'dhcp', 68: 'dhcp', 110: 'pop3', 143: 'imap', 3306: 'mysql',
            5432: 'postgresql', 6379: 'redis', 27017: 'mongodb', 3389: 'rdp',
            5900: 'vnc', 8080: 'http-proxy', 8443: 'https-alt', 445: 'smb',
            139: 'netbios', 389: 'ldap', 636: 'ldaps', 1433: 'mssql', 
            8000: 'http-alt', 9200: 'elasticsearch', 5672: 'amqp', 1521: 'oracle',
            # Game servers
            25565: 'minecraft', 25566: 'minecraft', 25567: 'minecraft',
            19132: 'minecraft-bedrock', 19133: 'minecraft-bedrock',
            27015: 'source-server', 27016: 'source-server',
            7777: 'game-server', 7778: 'game-server',
            2456: 'valheim', 2457: 'valheim', 2458: 'valheim',
            6567: 'starbound',
            28015: 'rust', 28016: 'rust-rcon',
            16261: 'zomboid', 16262: 'zomboid',
            34197: 'factorio',
        }
        if port in services:
            return services[port]
        
        # Fall back to system lookup
        try:
            return socket.getservbyport(port, protocol)
        except:
            return 'unknown'

    def detect_service(self, port, protocol):
        """Detect service and version with improved banner grabbing"""
        
        # Special handling for DNS on port 53
        if port == 53:
            return self.detect_dns_service(protocol)
        
        if protocol != 'tcp': 
            return None, None, None
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((self.ip_address, port))
            
            banner = ""
            
            # Try different probes based on port
            if port in [80, 8080, 8000, 8443, 443, 8888, 3000, 5000]:
                # HTTP probe
                request = f"HEAD / HTTP/1.1\r\nHost: {self.ip_address}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
                sock.send(request.encode())
                try:
                    banner = sock.recv(4096).decode('utf-8', errors='ignore')
                except:
                    pass
            elif port in [25565, 25566, 25567]:
                # Minecraft Java - send Server List Ping
                try:
                    # Handshake packet
                    host = (self.ip_address or '').encode('utf-8')
                    handshake = b'\x00'  # Packet ID
                    handshake += b'\xff\x05'  # Protocol version (vanilla)
                    handshake += bytes([len(host)]) + host  # Server address
                    handshake += struct.pack('>H', port)  # Port
                    handshake += b'\x01'  # Next state (status)
                    
                    # Wrap in length prefix
                    packet = bytes([len(handshake)]) + handshake
                    sock.send(packet)
                    
                    # Status request
                    sock.send(b'\x01\x00')
                    
                    # Read response
                    banner = sock.recv(4096).decode('utf-8', errors='ignore')
                except:
                    banner = 'Minecraft Server'
            elif port == 21:
                # FTP - just wait for banner
                try:
                    banner = sock.recv(1024).decode('utf-8', errors='ignore')
                except:
                    pass
            elif port == 22:
                # SSH - just wait for banner
                try:
                    banner = sock.recv(1024).decode('utf-8', errors='ignore')
                except:
                    pass
            elif port == 25 or port == 587:
                # SMTP - wait for greeting
                try:
                    banner = sock.recv(1024).decode('utf-8', errors='ignore')
                except:
                    pass
            elif port == 3306:
                # MySQL - wait for greeting
                try:
                    banner = sock.recv(1024).decode('utf-8', errors='ignore')
                except:
                    pass
            else:
                # Generic - send newline and wait
                try:
                    sock.send(b"\r\n")
                    banner = sock.recv(2048).decode('utf-8', errors='ignore')
                except:
                    pass
            
            sock.close()
            
            # Parse banner for product/version
            product, version = self.parse_banner(banner, port)
            return banner[:100] if banner else None, product, version
            
        except Exception as e:
            return None, None, None

    def parse_banner(self, banner, port):
        """Parse banner for product and version"""
        if not banner:
            return None, None
            
        product = None
        version = None
        
        banner_lower = banner.lower()
        
        # HTTP servers
        if 'server:' in banner_lower:
            match = re.search(r'server:\s*([^\r\n]+)', banner, re.IGNORECASE)
            if match: 
                server_info = match.group(1).strip()
                # Parse server string
                if '/' in server_info:
                    parts = server_info.split('/')
                    product = parts[0].strip()
                    if len(parts) > 1:
                        version = parts[1].split()[0].strip()
                else:
                    product = server_info.split()[0] if server_info else None
        
        # Check for common products in banner
        product_patterns = [
            (r'nginx[/\s]*([\d\.]+)?', 'nginx'),
            (r'apache[/\s]*([\d\.]+)?', 'Apache'),
            (r'uvicorn', 'Uvicorn'),
            (r'gunicorn[/\s]*([\d\.]+)?', 'Gunicorn'),
            (r'openssh[_\-\s]*([\d\.p]+)?', 'OpenSSH'),
            (r'ssh-([\d\.]+)', 'SSH'),
            (r'proftpd\s*([\d\.a-z]+)?', 'ProFTPD'),
            (r'vsftpd\s*([\d\.]+)?', 'vsftpd'),
            (r'pure-ftpd', 'Pure-FTPd'),
            (r'filezilla', 'FileZilla'),
            (r'microsoft-iis[/\s]*([\d\.]+)?', 'IIS'),
            (r'postfix', 'Postfix'),
            (r'exim', 'Exim'),
            (r'sendmail', 'Sendmail'),
            (r'mysql', 'MySQL'),
            (r'mariadb', 'MariaDB'),
            (r'postgresql', 'PostgreSQL'),
            (r'redis', 'Redis'),
            (r'mongodb', 'MongoDB'),
            (r'node\.?js', 'Node.js'),
            (r'express', 'Express'),
            (r'flask', 'Flask'),
            (r'django', 'Django'),
            (r'tomcat[/\s]*([\d\.]+)?', 'Tomcat'),
            (r'jetty[/\s]*([\d\.]+)?', 'Jetty'),
            # Game servers
            (r'minecraft', 'Minecraft'),
            (r'spigot', 'Spigot'),
            (r'paper', 'Paper'),
            (r'bukkit', 'Bukkit'),
            (r'forge', 'Minecraft Forge'),
            (r'fabric', 'Minecraft Fabric'),
        ]
        
        if not product:
            for pattern, name in product_patterns:
                match = re.search(pattern, banner_lower)
                if match:
                    product = name
                    if match.lastindex and match.group(1):
                        version = match.group(1)
                    break
        
        # Special handling for Minecraft JSON response
        if not product and ('version' in banner_lower and 'players' in banner_lower):
            try:
                # Try to parse Minecraft server response JSON
                json_match = re.search(r'\{.*"version".*\}', banner)
                if json_match:
                    mc_data = json.loads(json_match.group())
                    if 'version' in mc_data:
                        product = 'Minecraft'
                        if isinstance(mc_data['version'], dict):
                            version = mc_data['version'].get('name')
                        else:
                            version = str(mc_data['version'])
            except:
                product = 'Minecraft'
        
        return product, version

    def detect_os(self):
        """Detect operating system using multiple methods"""
        os_hints = []
        
        # Method 1: TTL from ping
        try:
            if self.ip_address:
                param = '-n' if os.name == 'nt' else '-c'
                result = subprocess.run(
                    ['ping', param, '1', self.ip_address],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                
                # Try multiple TTL patterns
                ttl_match = re.search(r'ttl[=:\s]+(\d+)', result.stdout.lower())
                if ttl_match:
                    ttl = int(ttl_match.group(1))
                    if ttl <= 64:
                        os_hints.append(('Linux/Unix', 3))
                    elif ttl <= 128:
                        os_hints.append(('Windows', 3))
                    else:
                        os_hints.append(('Network Device', 2))
        except:
            pass
        
        # Method 2: Port-based fingerprinting
        tcp_ports = set(p['port'] for p in self.ports if p['protocol'] == 'tcp' and p['state'] == 'open')
        
        # Windows indicators
        if 3389 in tcp_ports:
            os_hints.append(('Windows', 4))
        if 445 in tcp_ports and 139 in tcp_ports:
            os_hints.append(('Windows', 3))
        if 135 in tcp_ports:
            os_hints.append(('Windows', 2))
            
        # Linux indicators
        if 22 in tcp_ports:
            os_hints.append(('Linux/Unix', 2))
        if 111 in tcp_ports:  # portmapper
            os_hints.append(('Linux/Unix', 2))
            
        # Web server - check service banners
        for p in self.ports:
            if p.get('product'):
                product_lower = p.get('product', '').lower()
                if 'iis' in product_lower or 'microsoft' in product_lower:
                    os_hints.append(('Windows', 4))
                elif 'apache' in product_lower or 'nginx' in product_lower:
                    os_hints.append(('Linux/Unix', 2))
                elif 'uvicorn' in product_lower or 'gunicorn' in product_lower:
                    os_hints.append(('Linux/Unix', 2))
        
        # Calculate most likely OS
        if os_hints:
            os_scores: dict[str, int] = {}
            for os_name, weight in os_hints:
                os_scores[os_name] = os_scores.get(os_name, 0) + weight
            
            best_os = max(os_scores.keys(), key=lambda x: os_scores[x])
            self.os_guess = best_os
        else:
            self.os_guess = 'Unknown'

    def get_ports_to_scan(self):
        """Get list of ports to scan"""
        port_range = self.config.get('ports', 'top100')
        
        if port_range == 'top100': 
            return self.top_100_tcp, self.top_100_udp[: 50]
        elif port_range == 'top1000':
            return list(range(1, 1001)), self.top_100_udp
        elif port_range == 'all':
            return list(range(1, 65536)), self.top_100_udp
        elif '-' in str(port_range):
            start, end = map(int, port_range.split('-'))
            tcp_ports = list(range(start, end + 1))
            udp_ports = [p for p in self.top_100_udp if start <= p <= end]
            return tcp_ports, udp_ports
        else:
            return self.top_100_tcp, self.top_100_udp[: 50]

    def run_traceroute(self):
        """Run traceroute to target"""
        hops = []
        try:
            if not self.ip_address:
                return hops
            
            # Use traceroute command
            cmd = ['traceroute', '-n', '-m', '20', '-w', '2', self.ip_address]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            lines = result.stdout.strip().split('\n')
            for line in lines[1:]:  # Skip header
                parts = line.split()
                if len(parts) >= 2:
                    hop_num = parts[0]
                    try:
                        hop_num = int(hop_num)
                    except:
                        continue
                    
                    # Parse IP and latency
                    hop_ip = None
                    latencies = []
                    
                    for part in parts[1:]:
                        if part == '*':
                            continue
                        elif re.match(r'\d+\.\d+\.\d+\.\d+', part):
                            hop_ip = part
                        elif part.replace('.', '').replace('ms', '').isdigit() or 'ms' in part:
                            try:
                                lat = float(part.replace('ms', ''))
                                latencies.append(lat)
                            except:
                                pass
                    
                    avg_latency = round(sum(latencies) / len(latencies), 2) if latencies else None
                    
                    # Try to get hostname for hop
                    hop_hostname = None
                    if hop_ip:
                        try:
                            hop_hostname = socket.gethostbyaddr(hop_ip)[0]
                        except:
                            pass
                    
                    hops.append({
                        'hop': hop_num,
                        'ip': hop_ip or '*',
                        'hostname': hop_hostname,
                        'latency': f"{avg_latency}ms" if avg_latency else '*'
                    })
        except subprocess.TimeoutExpired:
            hops.append({'hop': 0, 'ip': 'Timeout', 'hostname': None, 'latency': '*'})
        except Exception as e:
            hops.append({'hop': 0, 'ip': f'Error: {str(e)[:30]}', 'hostname': None, 'latency': '*'})
        
        return hops

    def scan_ports(self):
        """Scan all ports - optimized for speed"""
        tcp_ports, udp_ports = self.get_ports_to_scan()
        
        results = []
        
        # TCP Scan - use 500 workers for fast scanning
        if self.config.get('scan_tcp', True):
            # For full scans, use more workers
            num_workers = 500 if len(tcp_ports) > 1000 else 200
            with ThreadPoolExecutor(max_workers=num_workers) as executor:
                futures = {executor.submit(self.scan_tcp_port, port): port for port in tcp_ports}
                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        results.append(result)
        
        # UDP Scan
        if self.config.get('scan_udp', True):
            with ThreadPoolExecutor(max_workers=100) as executor:
                futures = {executor.submit(self.scan_udp_port, port): port for port in udp_ports}
                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        results.append(result)
        
        self.ports = results

    def enrich_ports(self):
        """Add service detection to ports"""
        for port_info in self.ports:
            service_name = self.get_service_name(port_info['port'], port_info['protocol'])
            port_info['service'] = service_name
            
            if port_info['state'] == 'open' and self.config.get('detect_service', True):
                # Special handling for DNS port 53 (works for both TCP and UDP)
                if port_info['port'] == 53:
                    banner, product, version = self.detect_dns_service(port_info['protocol'])
                    port_info['product'] = product if product else 'DNS Server'
                    port_info['version'] = version if version else '-'
                    port_info['details'] = banner[:50] if banner else '-'
                    port_info['banner'] = banner if banner else None
                elif port_info['protocol'] == 'tcp':
                    banner, product, version = self.detect_service(port_info['port'], port_info['protocol'])
                    port_info['product'] = product if product else '-'
                    port_info['version'] = version if version else '-'
                    port_info['details'] = banner[:50] if banner else '-'
                    # Include raw banner for unknown services
                    if service_name == 'unknown' and banner:
                        port_info['banner'] = banner.strip()[:200]
                    else:
                        port_info['banner'] = None
                else:
                    port_info['product'] = '-'
                    port_info['version'] = '-'
                    port_info['details'] = '-'
                    port_info['banner'] = None
            else:
                port_info['product'] = '-'
                port_info['version'] = '-'
                port_info['details'] = '-'
                port_info['banner'] = None

    def run_scan(self):
        """Execute full scan"""
        self.start_time = time.time()
        results = {
            'status': 'running',
            'target': self.target,
            'step': 'Starting scan.. .'
        }
        
        try:
            # Step 1: Resolve
            results['step'] = 'Resolving target...'
            self.resolve_target()
            results['ip_address'] = self.ip_address
            results['hostname'] = self.hostname
            
            # Step 2: Check alive
            results['step'] = 'Checking if host is alive...'
            self. check_alive()
            results['is_alive'] = self.alive
            
            # Step 3: Scan ports
            results['step'] = 'Scanning ports (this may take several minutes)...'
            self.scan_ports()
            
            # Step 4: Service detection
            results['step'] = 'Detecting services...'
            self.enrich_ports()
            
            # Step 5: OS detection
            if self.config.get('detect_os', True):
                results['step'] = 'Detecting operating system...'
                self.detect_os()
            
            # Step 6: Traceroute (if enabled)
            traceroute_data = []
            if self.config.get('traceroute', False):
                results['step'] = 'Running traceroute...'
                traceroute_data = self.run_traceroute()
            
            # Final results
            duration = round(time.time() - self.start_time, 2)
            results['status'] = 'completed'
            results['step'] = 'Scan complete!'
            results['ports'] = sorted(self.ports, key=lambda x: x['port'])
            results['os_guess'] = self.os_guess
            results['scan_duration'] = f"{duration}s"
            results['scan_type'] = 'Deep Scan'
            results['protocols'] = []
            if self.config.get('scan_tcp'): results['protocols'].append('TCP')
            if self.config.get('scan_udp'): results['protocols'].append('UDP')
            results['protocols'] = '/'.join(results['protocols'])
            results['port_range'] = self.config.get('ports', 'top100')
            results['check_alive'] = self.config.get('check_alive', True)
            results['detect_service'] = self.config.get('detect_service', True)
            results['detect_os'] = self.config.get('detect_os', True)
            results['traceroute'] = self.config.get('traceroute', False)
            results['traceroute_data'] = traceroute_data
            results['latency'] = self.latency
            
        except Exception as e:
            results['status'] = 'error'
            results['error'] = str(e)
        
        return results

# Flask routes
scan_results = {}
scan_lock = threading.Lock()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/scan', methods=['POST'])
def start_scan():
    data = request.json
    target = data.get('target')
    
    if not target: 
        return jsonify({'error': 'Target required'}), 400
    
    # Basic input validation for security
    target = target.strip()
    if len(target) > 255:
        return jsonify({'error': 'Target too long'}), 400
    
    # Security: Verify consent token
    consent_token = request.cookies.get('scan_consent')
    if not consent_token:
        return jsonify({'error': 'You must agree to the terms before scanning. Please refresh the page and accept the consent.'}), 403
    
    with consent_lock:
        token_data = consent_tokens.get(consent_token)
        if not token_data:
            return jsonify({'error': 'Invalid consent token. Please refresh the page and accept the consent again.'}), 403
        
        # Check if token is expired
        if time.time() - token_data['timestamp'] > CONSENT_TOKEN_EXPIRY:
            del consent_tokens[consent_token]
            return jsonify({'error': 'Consent expired. Please refresh the page and accept again.'}), 403
        
        # Verify token is from same IP (prevent token sharing)
        if token_data['ip'] != request.remote_addr:
            return jsonify({'error': 'Consent token mismatch. Please refresh and consent again.'}), 403
    
    # Security: Rate limiting
    client_ip = request.remote_addr
    with rate_limit_lock:
        now = time.time()
        if client_ip in rate_limit_store:
            rate_data = rate_limit_store[client_ip]
            # Reset if window has passed
            if now - rate_data['first_request'] > RATE_LIMIT_WINDOW:
                rate_limit_store[client_ip] = {'count': 1, 'first_request': now}
            else:
                if rate_data['count'] >= MAX_SCANS_PER_HOUR:
                    remaining = int(RATE_LIMIT_WINDOW - (now - rate_data['first_request']))
                    return jsonify({
                        'error': f'Rate limit exceeded. Maximum {MAX_SCANS_PER_HOUR} scans per hour. Try again in {remaining // 60} minutes.'
                    }), 429
                rate_data['count'] += 1
        else:
            rate_limit_store[client_ip] = {'count': 1, 'first_request': now}
    
    # Security: Resolve and validate target is a GLOBAL (public) IP
    try:
        resolved_ip = resolve_and_validate_global_ip(target)
    except Exception as e:
        return jsonify({'error': str(e)}), 403
    
    scan_id = f"{resolved_ip}_{int(time.time())}"
    
    # Check if this IP is already being scanned or in queue
    with queue_lock:
        if current_scan_ip == resolved_ip:
            return jsonify({'error': 'This IP is already being scanned. Please wait for it to complete.'}), 409
        if resolved_ip in queue_order:
            position = list(queue_order).index(resolved_ip) + 1
            return jsonify({'error': f'This IP is already in queue at position {position}. Please wait.'}), 409
    
    # Get queue position
    with queue_lock:
        queue_position = len(queue_order) + 1
        queue_order.append(resolved_ip)
    
    # Store initial status BEFORE adding to queue
    with scan_lock:
        scan_results[scan_id] = {
            'status': 'queued',
            'target': target,
            'ip_address': resolved_ip,
            'queue_position': queue_position,
            'step': f'In queue (position {queue_position})...' if queue_position > 1 else 'Starting scan...'
        }
    
    # Add to queue (will be processed by worker)
    scan_queue.put((scan_id, target, data.copy(), resolved_ip))
    
    return jsonify({'scan_id': scan_id, 'status': 'queued', 'queue_position': queue_position})

@app.route('/api/results/<scan_id>')
def get_results(scan_id):
    with scan_lock:
        results = scan_results.get(scan_id)
    if not results:
        return jsonify({'error': 'Scan not found'}), 404
    
    # Update queue position if still queued
    if results.get('status') == 'queued':
        with queue_lock:
            ip = results.get('ip_address')
            if ip and ip in queue_order:
                pos = list(queue_order).index(ip) + 1
                results['queue_position'] = pos
                results['step'] = f'In queue (position {pos})...' if pos > 1 else 'Starting soon...'
            elif current_scan_ip == ip:
                results['status'] = 'running'
                results['step'] = 'Scanning...'
    
    return jsonify(results)


@app.route('/api/queue-status')
def queue_status():
    """Get current queue status"""
    with queue_lock:
        return jsonify({
            'queue_length': len(queue_order),
            'current_scan': current_scan_ip,
            'queued_ips': list(queue_order)
        })


def resolve_and_validate_global_ip(hostname: str) -> str:
    """Resolve hostname and validate it resolves to a global (public) IP only"""
    try:
        # First check if it's already an IP address
        try:
            ip_obj = ipaddress.ip_address(hostname)
            if not ip_obj.is_global:
                raise Exception(f"Target IP {ip_obj} is not a public/global address. Only public IPs can be scanned.")
            return str(ip_obj)
        except ValueError:
            pass  # Not an IP, try to resolve as hostname
        
        # Resolve ALL A/AAAA answers and reject any non-global
        infos = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        ips = []
        for info in infos:
            ip = info[4][0]
            try:
                ip_obj = ipaddress.ip_address(ip)
                ips.append(ip_obj)
            except ValueError:
                continue
        
        if not ips:
            raise Exception(f"Could not resolve hostname: {hostname}")
        
        # Check ALL resolved IPs - reject if ANY are non-global
        for ip_obj in ips:
            if not ip_obj.is_global:
                raise Exception(
                    f"Hostname '{hostname}' resolves to non-public IP ({ip_obj}). "
                    f"Only public/global IPs can be scanned for security reasons."
                )
        
        # Return the first valid global IP
        return str(ips[0])
        
    except socket.gaierror as e:
        raise Exception(f"Could not resolve hostname: {hostname}")


@app.route('/api/consent', methods=['POST'])
def accept_consent():
    """User accepts consent to scan - generates a signed token"""
    client_ip = request.remote_addr
    
    # Generate secure token
    token = secrets.token_urlsafe(32)
    
    with consent_lock:
        # Clean up old tokens periodically
        now = time.time()
        expired = [k for k, v in consent_tokens.items() if now - v['timestamp'] > CONSENT_TOKEN_EXPIRY]
        for k in expired:
            del consent_tokens[k]
        
        # Store new token
        consent_tokens[token] = {
            'ip': client_ip,
            'timestamp': now
        }
    
    response = make_response(jsonify({'status': 'consent_accepted'}))
    response.set_cookie(
        'scan_consent', 
        token, 
        max_age=CONSENT_TOKEN_EXPIRY,
        httponly=True,
        samesite='Strict'
    )
    return response


@app.route('/api/my-ip')
def get_my_ip():
    """Return the user's public IP address"""
    # Get the real client IP (considering proxies)
    client_ip = request.headers.get('X-Forwarded-For')
    if client_ip:
        # X-Forwarded-For can contain multiple IPs, take the first one
        client_ip = client_ip.split(',')[0].strip()
    else:
        client_ip = request.remote_addr or '0.0.0.0'
    
    return jsonify({'ip': client_ip})


@app.route('/api/rate-limit-status')
def rate_limit_status():
    """Check current rate limit status for the user"""
    client_ip = request.remote_addr
    with rate_limit_lock:
        now = time.time()
        if client_ip in rate_limit_store:
            rate_data = rate_limit_store[client_ip]
            if now - rate_data['first_request'] > RATE_LIMIT_WINDOW:
                remaining = MAX_SCANS_PER_HOUR
                reset_in = 0
            else:
                remaining = MAX_SCANS_PER_HOUR - rate_data['count']
                reset_in = int(RATE_LIMIT_WINDOW - (now - rate_data['first_request']))
        else:
            remaining = MAX_SCANS_PER_HOUR
            reset_in = 0
    
    return jsonify({
        'remaining_scans': remaining,
        'max_scans_per_hour': MAX_SCANS_PER_HOUR,
        'reset_in_seconds': reset_in
    })


@app.route('/health')
def health():
    """Health check endpoint for deployment platforms"""
    return jsonify({'status': 'healthy'}), 200


# Serve static files from root (favicons, manifest, etc.)
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))

@app.route('/favicon.ico')
def favicon():
    return send_from_directory(ROOT_DIR, 'favicon.ico', mimetype='image/x-icon')

@app.route('/favicon.svg')
def favicon_svg():
    return send_from_directory(ROOT_DIR, 'favicon.svg', mimetype='image/svg+xml')

@app.route('/favicon-<size>.png')
def favicon_png(size):
    return send_from_directory(ROOT_DIR, f'favicon-{size}.png', mimetype='image/png')

@app.route('/icon-<size>.png')
def icon_png(size):
    return send_from_directory(ROOT_DIR, f'icon-{size}.png', mimetype='image/png')

@app.route('/site.webmanifest')
def manifest():
    return send_from_directory(ROOT_DIR, 'site.webmanifest', mimetype='application/manifest+json')

if __name__ == '__main__': 
    port = int(os.environ.get('PORT', 5000))
    
    print("=" * 70)
    print("🔍 DEEP NETWORK SCANNER")
    print("=" * 70)
    print(f"Server running on: http://0.0.0.0:{port}")
    print("Features:")
    print("  ✓ TCP & UDP port scanning")
    print("  ✓ Service detection and banner grabbing")
    print("  ✓ OS fingerprinting")
    print("  ✓ All 65,535 ports supported")
    print("  ✓ Professional tabular results display")
    print("=" * 70)
    print(f"\nOpen http://localhost:{port} in your browser\n")
    
    app.run(host='0.0.0.0', port=port, debug=False, threaded=True)
