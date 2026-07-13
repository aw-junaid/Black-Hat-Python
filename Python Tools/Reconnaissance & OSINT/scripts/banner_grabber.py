#!/usr/bin/env python3
"""
Advanced Banner Grabbing & Service Enumeration
For authorized security testing only
"""
import socket
import ssl
import sys
import json
import struct
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict

class BannerGrabber:
    def __init__(self, timeout=5):
        self.timeout = timeout
        self.results = defaultdict(dict)
        
        # Service-specific probes
        self.probes = {
            21: self.grab_ftp,
            22: self.grab_ssh,
            23: self.grab_telnet,
            25: self.grab_smtp,
            53: self.grab_dns,
            80: self.grab_http,
            110: self.grab_pop3,
            143: self.grab_imap,
            443: self.grab_https,
            445: self.grab_smb,
            993: self.grab_imaps,
            995: self.grab_pop3s,
            1433: self.grab_mssql,
            1521: self.grab_oracle,
            3306: self.grab_mysql,
            3389: self.grab_rdp,
            5432: self.grab_postgresql,
            5900: self.grab_vnc,
            6379: self.grab_redis,
            8080: self.grab_http,
            8443: self.grab_https,
            9200: self.grab_elasticsearch,
            27017: self.grab_mongodb
        }
    
    def create_socket(self, ip, port):
        """Create a socket connection"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        
        try:
            sock.connect((ip, port))
            return sock
        except:
            return None
    
    def grab_ftp(self, ip, port):
        """Grab FTP banner"""
        sock = self.create_socket(ip, port)
        if not sock:
            return None
        
        try:
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()
            return {'service': 'FTP', 'banner': banner.strip()}
        except:
            return None
    
    def grab_ssh(self, ip, port):
        """Grab SSH banner"""
        sock = self.create_socket(ip, port)
        if not sock:
            return None
        
        try:
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()
            
            # Parse SSH version
            if 'SSH' in banner:
                version = banner.split('SSH-')[1].split()[0] if 'SSH-' in banner else 'Unknown'
                return {
                    'service': 'SSH',
                    'banner': banner.strip(),
                    'version': version
                }
            return {'service': 'SSH', 'banner': banner.strip()}
        except:
            return None
    
    def grab_telnet(self, ip, port):
        """Grab Telnet banner"""
        sock = self.create_socket(ip, port)
        if not sock:
            return None
        
        try:
            # Send Telnet options
            sock.send(b'\xff\xfb\x01\xff\xfb\x03\xff\xfd\x18\xff\xfd\x1f')
            time.sleep(0.5)
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()
            return {'service': 'Telnet', 'banner': banner.strip()}
        except:
            return None
    
    def grab_smtp(self, ip, port):
        """Grab SMTP banner and test for open relay"""
        sock = self.create_socket(ip, port)
        if not sock:
            return None
        
        try:
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            
            # Send EHLO
            sock.send(b'EHLO test\r\n')
            time.sleep(0.5)
            ehlo_response = sock.recv(1024).decode('utf-8', errors='ignore')
            
            # Check for open relay
            is_open_relay = False
            sock.send(b'MAIL FROM:<test@test.com>\r\n')
            time.sleep(0.2)
            mail_response = sock.recv(1024).decode('utf-8', errors='ignore')
            
            if '250' in mail_response:
                sock.send(b'RCPT TO:<test@external.com>\r\n')
                time.sleep(0.2)
                rcpt_response = sock.recv(1024).decode('utf-8', errors='ignore')
                
                if '250' in rcpt_response:
                    is_open_relay = True
            
            sock.close()
            
            return {
                'service': 'SMTP',
                'banner': banner.strip(),
                'ehlo': ehlo_response.strip(),
                'open_relay': is_open_relay
            }
        except:
            return None
    
    def grab_dns(self, ip, port):
        """Test DNS service"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.timeout)
        
        try:
            # Simple DNS query for version
            query = b'\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03'
            sock.sendto(query, (ip, port))
            response, _ = sock.recvfrom(1024)
            sock.close()
            
            return {
                'service': 'DNS',
                'response_length': len(response),
                'responded': True
            }
        except:
            return {'service': 'DNS', 'responded': False}
    
    def grab_http(self, ip, port, ssl_enabled=False):
        """Grab HTTP banner and headers"""
        sock = self.create_socket(ip, port)
        if not sock:
            return None
        
        try:
            if ssl_enabled:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(sock, server_hostname=ip)
            
            request = f"GET / HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: Banner-Grabber/1.0\r\nConnection: close\r\n\r\n"
            sock.send(request.encode())
            
            response = b''
            while True:
                try:
                    data = sock.recv(4096)
                    if not data:
                        break
                    response += data
                except:
                    break
            
            sock.close()
            
            response_str = response.decode('utf-8', errors='ignore')
            headers = {}
            if '\r\n\r\n' in response_str:
                header_part = response_str.split('\r\n\r\n')[0]
                for line in header_part.split('\r\n')[1:]:
                    if ':' in line:
                        key, value = line.split(':', 1)
                        headers[key.strip()] = value.strip()
            
            return {
                'service': 'HTTPS' if ssl_enabled else 'HTTP',
                'status_line': response_str.split('\r\n')[0] if response_str else '',
                'headers': headers,
                'server': headers.get('Server', 'Unknown'),
                'content_type': headers.get('Content-Type', 'Unknown')
            }
        except:
            return None
    
    def grab_https(self, ip, port):
        """Grab HTTPS banner"""
        return self.grab_http(ip, port, ssl_enabled=True)
    
    def grab_pop3(self, ip, port, ssl_enabled=False):
        """Grab POP3 banner"""
        sock = self.create_socket(ip, port)
        if not sock:
            return None
        
        try:
            if ssl_enabled:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(sock)
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()
            
            return {
                'service': 'POP3S' if ssl_enabled else 'POP3',
                'banner': banner.strip()
            }
        except:
            return None
    
    def grab_pop3s(self, ip, port):
        """Grab POP3S banner"""
        return self.grab_pop3(ip, port, ssl_enabled=True)
    
    def grab_imap(self, ip, port, ssl_enabled=False):
        """Grab IMAP banner"""
        sock = self.create_socket(ip, port)
        if not sock:
            return None
        
        try:
            if ssl_enabled:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(sock)
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()
            
            return {
                'service': 'IMAPS' if ssl_enabled else 'IMAP',
                'banner': banner.strip()
            }
        except:
            return None
    
    def grab_imaps(self, ip, port):
        """Grab IMAPS banner"""
        return self.grab_imap(ip, port, ssl_enabled=True)
    
    def grab_smb(self, ip, port):
        """Grab SMB information"""
        sock = self.create_socket(ip, port)
        if not sock:
            return None
        
        try:
            # SMB Negotiate Protocol Request
            smb_negotiate = bytes([
                0x00, 0x00, 0x00, 0x54,  # NetBIOS Session Message
                0xFF, 0x53, 0x4D, 0x42,  # SMB Magic
                0x72, 0x00, 0x00, 0x00,  # Negotiate Protocol Command
                0x00, 0x18, 0x01, 0x20,  # Flags
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0xFF, 0xFE, 0x00, 0x00, 0x00, 0x00
            ])
            
            sock.send(smb_negotiate)
            response = sock.recv(1024)
            sock.close()
            
            if len(response) >= 73:
                # Extract dialect
                dialect_index = response[73:75]
                
                return {
                    'service': 'SMB',
                    'response_length': len(response),
                    'responded': True
                }
            
            return {'service': 'SMB', 'responded': True}
        except:
            return None
    
    def grab_mssql(self, ip, port):
        """Grab MSSQL information"""
        sock = self.create_socket(ip, port)
        if not sock:
            return None
        
        try:
            # MSSQL Pre-Login Message
            prelogin = bytes([
                0x12, 0x01, 0x00, 0x34, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x15, 0x00, 0x06, 0x01, 0x00, 0x1B,
                0x00, 0x01, 0x02, 0x00, 0x1C, 0x00, 0x0C, 0x03,
                0x00, 0x28, 0x00, 0x04, 0xFF, 0x08, 0x00, 0x01,
                0x55, 0x00, 0x00, 0x00
            ])
            
            sock.send(prelogin)
            response = sock.recv(1024)
            sock.close()
            
            if len(response) > 0:
                return {
                    'service': 'MSSQL',
                    'responded': True,
                    'response_length': len(response)
                }
            
            return None
        except:
            return None
    
    def grab_mysql(self, ip, port):
        """Grab MySQL banner"""
        sock = self.create_socket(ip, port)
        if not sock:
            return None
        
        try:
            banner = sock.recv(1024)
            sock.close()
            
            if len(banner) >= 5:
                # Parse MySQL greeting packet
                protocol_version = banner[4]
                version_end = banner.find(b'\x00', 5)
                version = banner[5:version_end].decode('utf-8', errors='ignore')
                
                return {
                    'service': 'MySQL',
                    'protocol': protocol_version,
                    'version': version
                }
            
            return {'service': 'MySQL', 'banner': banner.decode('utf-8', errors='ignore')}
        except:
            return None
    
    def grab_postgresql(self, ip, port):
        """Grab PostgreSQL banner"""
        sock = self.create_socket(ip, port)
        if not sock:
            return None
        
        try:
            # PostgreSQL SSL request
            length = struct.pack('!I', 8)
            request = struct.pack('!I', 80877103)
            sock.send(length + request)
            
            response = sock.recv(1024)
            sock.close()
            
            if response:
                return {
                    'service': 'PostgreSQL',
                    'responded': True,
                    'response': response.decode('utf-8', errors='ignore')[:100]
                }
            
            return None
        except:
            return None
    
    def grab_rdp(self, ip, port):
        """Grab RDP information"""
        sock = self.create_socket(ip, port)
        if not sock:
            return None
        
        try:
            # RDP Negotiation Request
            request = b'\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00'
            sock.send(request)
            response = sock.recv(1024)
            sock.close()
            
            if response:
                return {
                    'service': 'RDP',
                    'responded': True,
                    'response_hex': response.hex()[:100]
                }
            
            return None
        except:
            return None
    
    def grab_vnc(self, ip, port):
        """Grab VNC banner"""
        sock = self.create_socket(ip, port)
        if not sock:
            return None
        
        try:
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()
            
            if banner.startswith('RFB'):
                version = banner.strip()
                return {
                    'service': 'VNC',
                    'version': version,
                    'banner': banner.strip()
                }
            
            return None
        except:
            return None
    
    def grab_redis(self, ip, port):
        """Grab Redis information"""
        sock = self.create_socket(ip, port)
        if not sock:
            return None
        
        try:
            # Send PING command
            sock.send(b'PING\r\n')
            response = sock.recv(1024).decode('utf-8', errors='ignore')
            
            if '+PONG' in response:
                # Try INFO command
                sock.send(b'INFO\r\n')
                time.sleep(0.5)
                info = sock.recv(4096).decode('utf-8', errors='ignore')
                
                sock.close()
                
                # Parse version
                version = 'Unknown'
                for line in info.split('\r\n'):
                    if line.startswith('redis_version:'):
                        version = line.split(':')[1]
                        break
                
                return {
                    'service': 'Redis',
                    'version': version,
                    'authenticated': True,  # No auth required
                    'info': info[:500]
                }
            
            sock.close()
            return None
        except:
            return None
    
    def grab_elasticsearch(self, ip, port):
        """Grab Elasticsearch information"""
        sock = self.create_socket(ip, port)
        if not sock:
            return None
        
        try:
            request = f"GET / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n"
            sock.send(request.encode())
            
            response = b''
            while True:
                try:
                    data = sock.recv(4096)
                    if not data:
                        break
                    response += data
                except:
                    break
            
            sock.close()
            
            response_str = response.decode('utf-8', errors='ignore')
            
            if 'cluster_name' in response_str or 'tagline' in response_str:
                # Parse JSON response
                try:
                    json_start = response_str.index('{')
                    json_end = response_str.rindex('}') + 1
                    json_data = json.loads(response_str[json_start:json_end])
                    
                    return {
                        'service': 'Elasticsearch',
                        'version': json_data.get('version', {}).get('number', 'Unknown'),
                        'cluster_name': json_data.get('cluster_name', 'Unknown'),
                        'tagline': json_data.get('tagline', '')
                    }
                except:
                    pass
            
            return None
        except:
            return None
    
    def grab_mongodb(self, ip, port):
        """Grab MongoDB information"""
        sock = self.create_socket(ip, port)
        if not sock:
            return None
        
        try:
            # MongoDB isMaster command
            # This is a simplified version
            request = bytes.fromhex(
                '3f000000' +  # Message length
                '00000000' +  # Request ID
                '00000000' +  # Response to
                'd4070000' +  # Op code (query)
                '00000000' +  # Flags
                '61646d696e2e24636d6400' +  # admin.$cmd
                '00000000' +  # Skip
                '01000000' +  # Limit
                '15000000' +  # Document length
                '10' +  # Type: int32
                '69736d617374657200' +  # isMaster
                '01000000'  # Value: 1
            )
            
            sock.send(request)
            response = sock.recv(4096)
            sock.close()
            
            if response:
                return {
                    'service': 'MongoDB',
                    'responded': True,
                    'response_length': len(response)
                }
            
            return None
        except:
            return None
    
    def grab_oracle(self, ip, port):
        """Grab Oracle database information"""
        sock = self.create_socket(ip, port)
        if not sock:
            return None
        
        try:
            # Oracle TNS packet
            request = bytes.fromhex(
                '00c6000001' +
                '0000000001' +
                '3800000008' +
                '414d41435f' +
                '414d4143' +
                '0000000000' +
                '0000000000' +
                '0000000000' +
                '0000000000' +
                '0000000000'
            )
            
            sock.send(request)
            response = sock.recv(1024)
            sock.close()
            
            if response:
                return {
                    'service': 'Oracle',
                    'responded': True,
                    'response_hex': response.hex()[:100]
                }
            
            return None
        except:
            return None
    
    def grab_service(self, ip, port):
        """Grab banner for specific service"""
        if port in self.probes:
            return self.probes[port](ip, port)
        
        # Generic banner grab
        sock = self.create_socket(ip, port)
        if not sock:
            return None
        
        try:
            time.sleep(0.5)
            sock.send(b'\r\n')
            time.sleep(0.5)
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()
            
            if banner:
                return {
                    'service': f'Unknown-{port}',
                    'banner': banner.strip()[:200]
                }
        except:
            pass
        
        return None
    
    def scan_host(self, ip, ports):
        """Scan multiple ports on a host"""
        print(f"[*] Scanning {ip} - {len(ports)} ports")
        
        results = {}
        
        def scan_port(port):
            result = self.grab_service(ip, port)
            if result:
                print(f"    [+] Port {port}: {result.get('service', 'Unknown')}")
                return port, result
            return None
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(scan_port, port): port for port in ports}
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    port, banner = result
                    results[port] = banner
        
        self.results[ip] = results
        return results
    
    def generate_report(self):
        """Generate scan report"""
        report = {
            'hosts_scanned': len(self.results),
            'results': dict(self.results)
        }
        
        with open('banner_grab_report.json', 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n[+] Report saved to banner_grab_report.json")
        return report

def main():
    if len(sys.argv) < 3:
        print("Usage: python banner_grabber.py <target> <ports>")
        print("Example: python banner_grabber.py 192.168.1.1 22,80,443,3306")
        print("Example: python banner_grabber.py example.com 1-1000")
        sys.exit(1)
    
    target = sys.argv[1]
    port_arg = sys.argv[2]
    
    # Parse ports
    ports = []
    for part in port_arg.split(','):
        if '-' in part:
            start, end = part.split('-')
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))
    
    # Resolve hostname to IP
    try:
        ip = socket.gethostbyname(target)
    except:
        print(f"[-] Could not resolve: {target}")
        sys.exit(1)
    
    print(f"[*] Target: {target} ({ip})")
    print(f"[*] Ports: {len(ports)}")
    
    print("[!] WARNING: Only use for authorized security testing!")
    
    grabber = BannerGrabber(timeout=5)
    grabber.scan_host(ip, ports)
    grabber.generate_report()

if __name__ == "__main__":
    main()
