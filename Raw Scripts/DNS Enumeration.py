#!/usr/bin/env python3
"""
DNS Enumeration (Subdomains) Tool
A comprehensive utility for discovering subdomains using various techniques
including dictionary attacks, brute force, zone transfers, and certificate transparency logs.
For authorized security testing and reconnaissance only.
"""

import argparse
import sys
import os
import time
import threading
import logging
import socket
import re
import json
import csv
from datetime import datetime
from typing import List, Dict, Set, Optional, Tuple, Union
from collections import defaultdict
import queue
import random
import string

# DNS resolution libraries
try:
    import dns.resolver
    import dns.zone
    import dns.query
    import dns.reversename
    DNS_PYTHON_AVAILABLE = True
except ImportError:
    DNS_PYTHON_AVAILABLE = False

try:
    import aiodns
    import asyncio
    AIODNS_AVAILABLE = True
except ImportError:
    AIODNS_AVAILABLE = False

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
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    from concurrent.futures import ThreadPoolExecutor, as_completed
    CONCURRENT_FUTURES_AVAILABLE = True
except ImportError:
    CONCURRENT_FUTURES_AVAILABLE = False


class DNSRecordTypes:
    """DNS record types for enumeration"""
    
    A = 'A'
    AAAA = 'AAAA'
    CNAME = 'CNAME'
    MX = 'MX'
    NS = 'NS'
    TXT = 'TXT'
    SOA = 'SOA'
    PTR = 'PTR'
    SRV = 'SRV'
    CAA = 'CAA'
    DNAME = 'DNAME'
    
    ALL_TYPES = [A, AAAA, CNAME, MX, NS, TXT, SOA, PTR, SRV, CAA, DNAME]
    
    # Common SRV services
    SRV_SERVICES = [
        '_http._tcp', '_https._tcp', '_ldap._tcp', '_ldaps._tcp',
        '_kerberos._tcp', '_kerberos._udp', '_kpasswd._tcp', '_kpasswd._udp',
        '_sip._tcp', '_sips._tcp', '_xmpp-client._tcp', '_xmpp-server._tcp',
        '_imap._tcp', '_imaps._tcp', '_pop3._tcp', '_pop3s._tcp',
        '_smtp._tcp', '_submission._tcp', '_caldav._tcp', '_carddav._tcp'
    ]


class SubdomainEnumerator:
    """
    Main class for subdomain enumeration
    Implements multiple discovery techniques
    """
    
    def __init__(self, domain: str, wordlist: str = None,
                 threads: int = 10, timeout: int = 5,
                 recursive: bool = False, depth: int = 2,
                 verbose: bool = False, output_file: str = None,
                 resolvers: List[str] = None, dns_servers: List[str] = None):
        """
        Initialize subdomain enumerator
        
        Args:
            domain: Target domain
            wordlist: Path to subdomain wordlist
            threads: Number of threads
            timeout: DNS timeout in seconds
            recursive: Perform recursive enumeration
            depth: Recursion depth
            verbose: Enable verbose output
            output_file: Output file path
            resolvers: List of DNS resolvers to use
            dns_servers: List of DNS servers to query
        """
        if not DNS_PYTHON_AVAILABLE:
            raise ImportError(
                "dnspython module is required. Install with: pip install dnspython"
            )
        
        self.domain = domain.lower().strip()
        self.wordlist = wordlist
        self.threads = threads
        self.timeout = timeout
        self.recursive = recursive
        self.depth = depth
        self.verbose = verbose
        self.output_file = output_file
        
        # DNS resolvers
        self.resolvers = resolvers or ['8.8.8.8', '8.8.4.4', '1.1.1.1']
        self.dns_servers = dns_servers or ['8.8.8.8', '8.8.4.4', '1.1.1.1']
        
        # Results storage
        self.subdomains = set()
        self.resolved_ips = defaultdict(set)
        self.record_types = defaultdict(set)
        self.additional_records = defaultdict(list)
        self.cname_chain = defaultdict(list)
        self.wildcard_detected = False
        self.wildcard_ip = None
        
        # Statistics
        self.stats = {
            'queries': 0,
            'found': 0,
            'errors': 0,
            'wildcard': False,
            'start_time': None,
            'end_time': None
        }
        
        # Locks for thread safety
        self.lock = threading.Lock()
        self.print_lock = threading.Lock()
        
        # Setup logging
        self.setup_logging()
        
        # Load wordlist
        self.wordlist_words = self.load_wordlist()
        
        # Initialize DNS resolver
        self.resolver = self.setup_resolver()
        
        # Test for wildcard DNS
        self.test_wildcard()
    
    def setup_logging(self):
        """Configure logging with optional colors"""
        self.logger = logging.getLogger('DNSEnum')
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
    
    def setup_resolver(self) -> dns.resolver.Resolver:
        """Configure DNS resolver"""
        resolver = dns.resolver.Resolver()
        resolver.nameservers = self.resolvers
        resolver.timeout = self.timeout
        resolver.lifetime = self.timeout * 2
        return resolver
    
    def load_wordlist(self) -> List[str]:
        """Load subdomain wordlist from file"""
        if not self.wordlist:
            # Use built-in common subdomains
            return self.get_builtin_wordlist()
        
        try:
            with open(self.wordlist, 'r', encoding='utf-8', errors='ignore') as f:
                words = [line.strip().lower() for line in f if line.strip()]
            self.logger.info(f"[+] Loaded {len(words)} words from {self.wordlist}")
            return words
        except Exception as e:
            self.logger.error(f"[-] Error loading wordlist: {e}")
            return self.get_builtin_wordlist()
    
    def get_builtin_wordlist(self) -> List[str]:
        """Get built-in common subdomains"""
        common = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
            'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'm', 'imap', 'test',
            'ns', 'blog', 'pop3', 'dev', 'www2', 'admin', 'forum', 'news', 'vpn',
            'ns3', 'mail2', 'new', 'mysql', 'old', 'lists', 'support', 'mobile',
            'mx', 'static', 'docs', 'beta', 'shop', 'sql', 'secure', 'demo',
            'cp', 'calendar', 'wiki', 'web', 'media', 'email', 'images', 'img',
            'download', 'dns', 'piwik', 'stats', 'analytics', 'stats', 'survey',
            'portal', 'start', 'ir', 'chat', 'js', 'css', 'client', 'mssql',
            'host', 'server', 'ldap', 'radius', 'api', 'app', 'stage', 'staging',
            'backup', 'adminer', 'phpmyadmin', 'phpPgAdmin', 'pma', 'myadmin',
            'pgadmin', 'admin-console', 'console', 'jenkins', 'gitlab', 'git',
            'svn', 'cvs', 'trac', 'redmine', 'bugzilla', 'jira', 'confluence',
            'wiki', 'mediawiki', 'dokuwiki', 'moodle', 'phpBB', 'wordpress',
            'joomla', 'drupal', 'magento', 'shopify', 'woocommerce', 'prestashop',
            'zencart', 'oscommerce', 'vbulletin', 'simplemachines', 'punbb',
            'mybb', 'phpwind', 'discuz', 'discourse', 'nodebb', 'flarum'
        ]
        return common
    
    def test_wildcard(self):
        """Test for wildcard DNS records"""
        try:
            # Generate random subdomain
            random_sub = ''.join(random.choices(string.ascii_lowercase, k=10))
            test_domain = f"{random_sub}.{self.domain}"
            
            answers = self.resolver.resolve(test_domain, 'A')
            if answers:
                self.wildcard_detected = True
                self.wildcard_ip = str(answers[0])
                self.logger.warning(
                    f"[!] Wildcard DNS detected: *.{self.domain} -> {self.wildcard_ip}"
                )
                self.stats['wildcard'] = True
        except Exception:
            self.logger.info("[+] No wildcard DNS detected")
    
    def is_wildcard(self, ip: str) -> bool:
        """Check if IP matches wildcard"""
        return self.wildcard_detected and ip == self.wildcard_ip
    
    def resolve_subdomain(self, subdomain: str, record_type: str = 'A') -> Optional[List[str]]:
        """
        Resolve subdomain for specific record type
        
        Args:
            subdomain: Subdomain to resolve
            record_type: DNS record type
        
        Returns:
            List of resolved values or None
        """
        try:
            answers = self.resolver.resolve(subdomain, record_type)
            results = [str(r) for r in answers]
            
            with self.lock:
                self.stats['queries'] += 1
            
            return results
            
        except dns.resolver.NoAnswer:
            return None
        except dns.resolver.NXDOMAIN:
            return None
        except dns.resolver.Timeout:
            with self.lock:
                self.stats['errors'] += 1
            return None
        except Exception as e:
            with self.lock:
                self.stats['errors'] += 1
            if self.verbose:
                self.logger.debug(f"Resolution error for {subdomain}: {e}")
            return None
    
    def enumerate_subdomain(self, subdomain: str) -> bool:
        """
        Enumerate a single subdomain
        
        Args:
            subdomain: Subdomain to check
        
        Returns:
            True if subdomain exists
        """
        # Skip if already found
        if subdomain in self.subdomains:
            return False
        
        # Check A record
        ips = self.resolve_subdomain(subdomain, 'A')
        
        if ips:
            # Filter out wildcard
            if self.wildcard_detected and all(self.is_wildcard(ip) for ip in ips):
                return False
            
            # Add to results
            with self.lock:
                self.subdomains.add(subdomain)
                self.resolved_ips[subdomain].update(ips)
                self.record_types[subdomain].add('A')
                self.stats['found'] += 1
            
            # Display result
            with self.print_lock:
                if COLORAMA_AVAILABLE:
                    print(f"{Fore.GREEN}[+] Found: {subdomain} -> {', '.join(ips)}{Style.RESET_ALL}")
                else:
                    print(f"[+] Found: {subdomain} -> {', '.join(ips)}")
            
            # Check other record types
            self.check_additional_records(subdomain)
            
            return True
        
        return False
    
    def check_additional_records(self, subdomain: str):
        """Check additional DNS record types for subdomain"""
        for record_type in DNSRecordTypes.ALL_TYPES[1:]:  # Skip A record
            if record_type == 'A':
                continue
            
            values = self.resolve_subdomain(subdomain, record_type)
            if values:
                with self.lock:
                    self.record_types[subdomain].add(record_type)
                    self.additional_records[subdomain].extend(
                        [(record_type, v) for v in values]
                    )
                
                # Handle CNAME specially for chaining
                if record_type == 'CNAME' and values:
                    self.cname_chain[subdomain] = values
                    # Recursively resolve CNAME target
                    self.follow_cname(subdomain, values[0])
    
    def follow_cname(self, source: str, target: str, depth: int = 0):
        """Follow CNAME chain"""
        if depth > 5:  # Prevent infinite loops
            return
        
        # Resolve target
        ips = self.resolve_subdomain(target, 'A')
        if ips:
            with self.lock:
                self.resolved_ips[source].update(ips)
    
    def dictionary_attack(self):
        """Perform dictionary-based subdomain enumeration"""
        self.logger.info(f"[*] Starting dictionary attack with {len(self.wordlist_words)} words")
        
        total = len(self.wordlist_words)
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []
            
            for word in self.wordlist_words:
                subdomain = f"{word}.{self.domain}"
                futures.append(executor.submit(self.enumerate_subdomain, subdomain))
            
            # Monitor progress
            if TQDM_AVAILABLE:
                with tqdm(total=total, desc="Enumerating") as pbar:
                    for future in as_completed(futures):
                        pbar.update(1)
            else:
                for i, future in enumerate(as_completed(futures)):
                    if (i + 1) % 100 == 0:
                        self.logger.info(f"[*] Progress: {i+1}/{total}")
    
    def brute_force_permutations(self, permutations: List[str]):
        """Brute force with permutations of found subdomains"""
        self.logger.info(f"[*] Trying {len(permutations)} permutations")
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []
            
            for perm in permutations:
                subdomain = f"{perm}.{self.domain}"
                futures.append(executor.submit(self.enumerate_subdomain, subdomain))
            
            for future in as_completed(futures):
                pass
    
    def zone_transfer_attack(self) -> List[str]:
        """
        Attempt DNS zone transfer (AXFR)
        
        Returns:
            List of subdomains from zone transfer
        """
        self.logger.info("[*] Attempting DNS zone transfer (AXFR)...")
        
        zone_subdomains = []
        
        try:
            # Get NS records
            ns_servers = self.resolve_subdomain(self.domain, 'NS')
            
            if not ns_servers:
                self.logger.info("[-] No NS records found")
                return zone_subdomains
            
            for ns in ns_servers:
                try:
                    # Remove trailing dot
                    ns = ns.rstrip('.')
                    
                    # Perform zone transfer
                    zone = dns.zone.from_xfr(dns.query.xfr(ns, self.domain, timeout=self.timeout))
                    
                    if zone:
                        self.logger.info(f"[+] Zone transfer successful from {ns}")
                        
                        for name, node in zone.nodes.items():
                            subdomain = str(name) + ('.' + self.domain if name != '@' else '')
                            subdomain = subdomain.rstrip('.')
                            
                            if subdomain != self.domain:
                                zone_subdomains.append(subdomain)
                                
                                with self.print_lock:
                                    if COLORAMA_AVAILABLE:
                                        print(f"{Fore.YELLOW}[Zone] Found: {subdomain}{Style.RESET_ALL}")
                                    else:
                                        print(f"[Zone] Found: {subdomain}")
                        
                        break  # Stop after first successful transfer
                        
                except Exception as e:
                    self.logger.debug(f"Zone transfer failed from {ns}: {e}")
                    continue
            
        except Exception as e:
            self.logger.debug(f"Zone transfer error: {e}")
        
        return zone_subdomains
    
    def certificate_transparency_enum(self) -> Set[str]:
        """
        Enumerate subdomains using Certificate Transparency logs (crt.sh)
        
        Returns:
            Set of subdomains from CT logs
        """
        if not REQUESTS_AVAILABLE:
            self.logger.warning("[-] requests module required for CT enumeration")
            return set()
        
        self.logger.info("[*] Querying Certificate Transparency logs (crt.sh)...")
        
        ct_subdomains = set()
        
        try:
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            response = requests.get(url, timeout=self.timeout)
            
            if response.status_code == 200:
                data = response.json()
                
                for entry in data:
                    name = entry.get('name_value', '')
                    if name:
                        # Split multiple names (some entries have multiple)
                        for sub in name.split('\n'):
                            sub = sub.strip().lower()
                            if sub.endswith(self.domain) and sub != self.domain:
                                # Remove wildcard
                                if sub.startswith('*.'):
                                    sub = sub[2:]
                                ct_subdomains.add(sub)
                
                self.logger.info(f"[+] Found {len(ct_subdomains)} subdomains from CT logs")
                
                # Display found subdomains
                for sub in list(ct_subdomains)[:10]:  # Show first 10
                    if COLORAMA_AVAILABLE:
                        print(f"{Fore.CYAN}[CT] Found: {sub}{Style.RESET_ALL}")
                    else:
                        print(f"[CT] Found: {sub}")
                
                if len(ct_subdomains) > 10:
                    print(f"    ... and {len(ct_subdomains) - 10} more")
                
            else:
                self.logger.warning(f"[-] crt.sh returned status code: {response.status_code}")
                
        except Exception as e:
            self.logger.debug(f"CT enumeration error: {e}")
        
        return ct_subdomains
    
    def search_engines_enum(self) -> Set[str]:
        """
        Enumerate subdomains using search engines (Google, Bing)
        Note: Requires API keys for production use
        """
        # This is a placeholder - real implementation would use search APIs
        self.logger.info("[*] Search engine enumeration placeholder")
        return set()
    
    def reverse_dns_enum(self, ip_range: str = None) -> Set[str]:
        """
        Reverse DNS enumeration over IP range
        
        Args:
            ip_range: CIDR range to scan (e.g., 192.168.1.0/24)
        
        Returns:
            Set of hostnames from reverse DNS
        """
        if not ip_range:
            return set()
        
        self.logger.info(f"[*] Reverse DNS enumeration over {ip_range}")
        
        reverse_subdomains = set()
        
        try:
            import ipaddress
            network = ipaddress.ip_network(ip_range, strict=False)
            
            total_ips = network.num_addresses
            self.logger.info(f"[*] Scanning {total_ips} IPs")
            
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = []
                
                for ip in network.hosts():
                    futures.append(executor.submit(self.reverse_lookup, str(ip)))
                
                # Monitor progress
                if TQDM_AVAILABLE:
                    with tqdm(total=total_ips, desc="Reverse DNS") as pbar:
                        for future in as_completed(futures):
                            result = future.result()
                            if result:
                                reverse_subdomains.add(result)
                            pbar.update(1)
                else:
                    for i, future in enumerate(as_completed(futures)):
                        result = future.result()
                        if result:
                            reverse_subdomains.add(result)
                        if (i + 1) % 100 == 0:
                            self.logger.info(f"[*] Progress: {i+1}/{total_ips}")
            
        except Exception as e:
            self.logger.error(f"[-] Reverse DNS error: {e}")
        
        return reverse_subdomains
    
    def reverse_lookup(self, ip: str) -> Optional[str]:
        """Perform reverse DNS lookup for IP"""
        try:
            rev_name = dns.reversename.from_address(ip)
            answers = self.resolver.resolve(rev_name, 'PTR')
            
            if answers:
                ptr = str(answers[0]).rstrip('.')
                if ptr.endswith(self.domain):
                    return ptr
                    
        except Exception:
            pass
        
        return None
    
    def brute_force_numeric(self, start: int = 1, end: int = 100):
        """
        Brute force numeric subdomains (e.g., server1, server2)
        
        Args:
            start: Start number
            end: End number
        """
        self.logger.info(f"[*] Brute forcing numeric subdomains {start}-{end}")
        
        templates = ['server{}', 'web{}', 'mail{}', 'app{}', 'dev{}', 'test{}',
                     'node{}', 'host{}', 'vm{}', 'box{}', 'srv{}', 'backup{}']
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []
            
            for template in templates:
                for num in range(start, end + 1):
                    sub = template.format(num)
                    subdomain = f"{sub}.{self.domain}"
                    futures.append(executor.submit(self.enumerate_subdomain, subdomain))
            
            for future in as_completed(futures):
                pass
    
    def brute_force_common_ports(self):
        """
        Check for common subdomains based on port names
        """
        port_subdomains = [
            '80', '443', '8080', '8443', '21', '22', '23', '25', '53',
            '110', '111', '135', '139', '143', '389', '443', '445', '465',
            '514', '636', '993', '995', '1433', '1521', '3306', '3389',
            '5432', '5900', '5901', '5985', '5986', '6379', '8080', '8443',
            '9090', '9200', '9300', '11211', '27017', '28017'
        ]
        
        self.logger.info(f"[*] Checking {len(port_subdomains)} port-based subdomains")
        
        for port in port_subdomains:
            self.enumerate_subdomain(port)
            self.enumerate_subdomain(f"{port}.tcp")
    
    def recursive_enumeration(self, current_depth: int = 1):
        """
        Perform recursive enumeration on found subdomains
        
        Args:
            current_depth: Current recursion depth
        """
        if current_depth > self.depth:
            return
        
        self.logger.info(f"[*] Recursive enumeration depth {current_depth}/{self.depth}")
        
        current_subdomains = list(self.subdomains)
        
        for sub in current_subdomains:
            # Extract prefix (e.g., from api.example.com get "api")
            prefix = sub.replace(f".{self.domain}", "")
            
            # Try permutations
            permutations = []
            
            # Add common prefixes
            for p in ['dev', 'test', 'stage', 'staging', 'prod', 'production',
                     'backup', 'old', 'new', 'beta', 'alpha', 'demo']:
                permutations.append(f"{p}-{prefix}")
                permutations.append(f"{prefix}-{p}")
                permutations.append(f"{p}{prefix}")
                permutations.append(f"{prefix}{p}")
            
            # Try permutations
            for perm in permutations:
                self.enumerate_subdomain(f"{perm}.{self.domain}")
            
            # Recurse
            if current_depth < self.depth:
                self.recursive_enumeration(current_depth + 1)
    
    def generate_permutations(self, word: str) -> List[str]:
        """Generate common permutations of a word"""
        perms = set()
        perms.add(word)
        
        # Common number suffixes
        for i in range(1, 10):
            perms.add(f"{word}{i}")
            perms.add(f"{word}-{i}")
        
        # Common prefixes
        for p in ['dev', 'test', 'stage', 'old', 'new', 'backup', 'beta']:
            perms.add(f"{p}-{word}")
            perms.add(f"{word}-{p}")
        
        # Common suffixes
        for s in ['api', 'app', 'web', 'admin', 'portal', 'service']:
            perms.add(f"{word}-{s}")
            perms.add(f"{s}-{word}")
        
        return list(perms)
    
    def enumerate_all(self):
        """Run all enumeration techniques"""
        self.stats['start_time'] = datetime.now()
        
        print(f"\n{'='*60}")
        print(f"DNS Subdomain Enumeration for: {self.domain}")
        print(f"{'='*60}\n")
        
        # Zone transfer attempt
        zone_subs = self.zone_transfer_attack()
        for sub in zone_subs:
            self.subdomains.add(sub)
            if self.verbose:
                print(f"[Zone] {sub}")
        
        # Certificate transparency
        ct_subs = self.certificate_transparency_enum()
        for sub in ct_subs:
            self.subdomains.add(sub)
        
        # Dictionary attack
        if self.wordlist_words:
            self.dictionary_attack()
        
        # Common port names
        self.brute_force_common_ports()
        
        # Numeric brute force
        self.brute_force_numeric(1, 10)
        
        # Recursive enumeration
        if self.recursive and self.subdomains:
            self.recursive_enumeration()
        
        self.stats['end_time'] = datetime.now()
        
        # Display results
        self.display_results()
        
        # Save output
        if self.output_file:
            self.save_results()
    
    def display_results(self):
        """Display enumeration results"""
        elapsed = (self.stats['end_time'] - self.stats['start_time']).total_seconds()
        
        print(f"\n{'='*60}")
        print(f"Enumeration Results for: {self.domain}")
        print(f"{'='*60}")
        print(f"Time elapsed: {elapsed:.2f} seconds")
        print(f"DNS queries: {self.stats['queries']:,}")
        print(f"Subdomains found: {len(self.subdomains)}")
        print(f"Errors: {self.stats['errors']}")
        print(f"Wildcard detected: {self.wildcard_detected}")
        if self.wildcard_detected:
            print(f"Wildcard IP: {self.wildcard_ip}")
        print(f"{'='=60}\n")
        
        if self.subdomains:
            # Sort subdomains alphabetically
            sorted_subs = sorted(self.subdomains)
            
            print(f"Found Subdomains ({len(sorted_subs)}):")
            print("-" * 40)
            
            for sub in sorted_subs:
                ips = self.resolved_ips.get(sub, [])
                records = self.record_types.get(sub, set())
                records_str = ','.join(sorted(records)) if records else 'A'
                
                if ips:
                    ip_str = ', '.join(ips)
                    print(f"  {sub:<40} {records_str:<10} {ip_str}")
                else:
                    print(f"  {sub:<40} {records_str:<10}")
            
            print()
            
            # Show additional records
            if self.additional_records:
                print("Additional Records:")
                print("-" * 40)
                for sub, records in self.additional_records.items():
                    for rtype, value in records:
                        print(f"  {sub:<30} {rtype:<6} {value}")
                print()
    
    def save_results(self):
        """Save results to file"""
        if not self.output_file:
            return
        
        ext = os.path.splitext(self.output_file)[1].lower()
        
        data = {
            'domain': self.domain,
            'timestamp': datetime.now().isoformat(),
            'stats': self.stats,
            'wildcard': {
                'detected': self.wildcard_detected,
                'ip': self.wildcard_ip
            },
            'subdomains': []
        }
        
        for sub in sorted(self.subdomains):
            sub_data = {
                'subdomain': sub,
                'ips': list(self.resolved_ips.get(sub, [])),
                'record_types': list(self.record_types.get(sub, [])),
                'additional_records': [
                    {'type': rtype, 'value': value}
                    for rtype, value in self.additional_records.get(sub, [])
                ]
            }
            data['subdomains'].append(sub_data)
        
        try:
            if ext == '.json':
                with open(self.output_file, 'w') as f:
                    json.dump(data, f, indent=2)
            elif ext == '.csv':
                with open(self.output_file, 'w', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow(['Subdomain', 'IPs', 'Record Types', 'Additional Records'])
                    for sub in data['subdomains']:
                        writer.writerow([
                            sub['subdomain'],
                            ';'.join(sub['ips']),
                            ';'.join(sub['record_types']),
                            ';'.join([f"{r['type']}:{r['value']}" for r in sub['additional_records']])
                        ])
            else:
                with open(self.output_file, 'w') as f:
                    for sub in sorted(self.subdomains):
                        f.write(f"{sub}\n")
            
            self.logger.info(f"[+] Results saved to {self.output_file}")
            
        except Exception as e:
            self.logger.error(f"[-] Error saving results: {e}")


class AsyncSubdomainEnumerator:
    """
    Asynchronous subdomain enumerator using aiodns
    For faster enumeration with many subdomains
    """
    
    def __init__(self, domain: str, wordlist: List[str], 
                 concurrent: int = 100, timeout: int = 5):
        if not AIODNS_AVAILABLE:
            raise ImportError("aiodns module required for async enumeration")
        
        self.domain = domain
        self.wordlist = wordlist
        self.concurrent = concurrent
        self.timeout = timeout
        self.found = set()
    
    async def query(self, subdomain: str, loop):
        """Async DNS query"""
        try:
            resolver = aiodns.DNSResolver(loop=loop)
            result = await resolver.query(subdomain, 'A')
            if result:
                return subdomain
        except Exception:
            pass
        return None
    
    async def worker(self, queue, loop):
        """Worker coroutine"""
        while True:
            try:
                subdomain = await queue.get()
                result = await self.query(subdomain, loop)
                if result:
                    self.found.add(subdomain)
                    print(f"[+] Found: {subdomain}")
                queue.task_done()
            except Exception as e:
                break
    
    async def enumerate(self):
        """Run async enumeration"""
        queue = asyncio.Queue()
        
        # Fill queue
        for word in self.wordlist:
            subdomain = f"{word}.{self.domain}"
            await queue.put(subdomain)
        
        # Create workers
        loop = asyncio.get_event_loop()
        workers = []
        for _ in range(self.concurrent):
            task = asyncio.create_task(self.worker(queue, loop))
            workers.append(task)
        
        # Wait for completion
        await queue.join()
        
        # Cancel workers
        for worker in workers:
            worker.cancel()


def banner():
    """Display tool banner"""
    banner_text = f"""
{'='*60}
    DNS Enumeration (Subdomains) Tool
    For authorized security testing and reconnaissance
    Techniques: Dictionary, Zone Transfer, CT Logs, Reverse DNS
{'='*60}
    """
    if COLORAMA_AVAILABLE:
        print(f"{Fore.CYAN}{banner_text}{Style.RESET_ALL}")
    else:
        print(banner_text)


def main():
    """Main function for command-line interface"""
    parser = argparse.ArgumentParser(
        description='DNS Subdomain Enumeration Tool - Discover subdomains using multiple techniques',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic enumeration with default wordlist
  python dns_enum.py --domain example.com
  
  # Use custom wordlist
  python dns_enum.py --domain example.com --wordlist subdomains.txt
  
  # Increase threads for faster enumeration
  python dns_enum.py --domain example.com --wordlist subdomains.txt --threads 50
  
  # Include zone transfer attempt
  python dns_enum.py --domain example.com --zone-transfer
  
  # Use certificate transparency logs
  python dns_enum.py --domain example.com --ct-logs
  
  # Reverse DNS enumeration over IP range
  python dns_enum.py --domain example.com --reverse 192.168.1.0/24
  
  # Recursive enumeration
  python dns_enum.py --domain example.com --recursive --depth 3
  
  # Save results to file
  python dns_enum.py --domain example.com --output results.json
  
  # All techniques combined
  python dns_enum.py --domain example.com --wordlist subdomains.txt \\
                     --zone-transfer --ct-logs --recursive --output all.json
        """
    )
    
    # Required arguments
    parser.add_argument('--domain', '-d', required=True, help='Target domain')
    
    # Wordlist options
    parser.add_argument('--wordlist', '-w', help='Subdomain wordlist file')
    parser.add_argument('--builtin', action='store_true', help='Use built-in wordlist')
    
    # Enumeration techniques
    parser.add_argument('--zone-transfer', '-z', action='store_true',
                       help='Attempt DNS zone transfer (AXFR)')
    parser.add_argument('--ct-logs', '-c', action='store_true',
                       help='Query Certificate Transparency logs (crt.sh)')
    parser.add_argument('--reverse', metavar='CIDR',
                       help='Reverse DNS enumeration over IP range')
    parser.add_argument('--recursive', '-r', action='store_true',
                       help='Recursive enumeration on found subdomains')
    parser.add_argument('--depth', type=int, default=2,
                       help='Recursion depth (default: 2)')
    
    # Performance options
    parser.add_argument('--threads', '-t', type=int, default=10,
                       help='Number of threads (default: 10)')
    parser.add_argument('--timeout', type=int, default=5,
                       help='DNS timeout in seconds (default: 5)')
    parser.add_argument('--resolvers', help='Custom DNS resolvers (comma-separated)')
    
    # Output options
    parser.add_argument('--output', '-o', help='Output file for results')
    parser.add_argument('--format', choices=['txt', 'json', 'csv'], default='txt',
                       help='Output format (default: txt)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    
    # Async mode
    parser.add_argument('--async-mode', action='store_true',
                       help='Use async DNS (faster, experimental)')
    
    args = parser.parse_args()
    
    # Display banner
    banner()
    
    # Check for dnspython
    if not DNS_PYTHON_AVAILABLE:
        print("[!] dnspython module required. Install with: pip install dnspython")
        sys.exit(1)
    
    # Parse resolvers
    resolvers = None
    if args.resolvers:
        resolvers = [r.strip() for r in args.resolvers.split(',')]
    
    try:
        # Async mode
        if args.async_mode:
            if not AIODNS_AVAILABLE:
                print("[!] aiodns module required for async mode. Install with: pip install aiodns")
                sys.exit(1)
            
            # Load wordlist
            if args.wordlist:
                with open(args.wordlist, 'r') as f:
                    words = [line.strip() for line in f if line.strip()]
            else:
                enum = SubdomainEnumerator(args.domain)
                words = enum.get_builtin_wordlist()
            
            print(f"[*] Starting async enumeration with {len(words)} words")
            
            async_enum = AsyncSubdomainEnumerator(
                domain=args.domain,
                wordlist=words,
                concurrent=args.threads * 10,
                timeout=args.timeout
            )
            
            loop = asyncio.get_event_loop()
            loop.run_until_complete(async_enum.enumerate())
            
            print(f"\n[+] Found {len(async_enum.found)} subdomains")
            
        else:
            # Standard enumeration
            enum = SubdomainEnumerator(
                domain=args.domain,
                wordlist=args.wordlist,
                threads=args.threads,
                timeout=args.timeout,
                recursive=args.recursive,
                depth=args.depth,
                verbose=args.verbose,
                output_file=args.output,
                resolvers=resolvers
            )
            
            # Perform zone transfer if requested
            if args.zone_transfer:
                zone_subs = enum.zone_transfer_attack()
                for sub in zone_subs:
                    enum.subdomains.add(sub)
            
            # Query CT logs if requested
            if args.ct_logs:
                ct_subs = enum.certificate_transparency_enum()
                for sub in ct_subs:
                    enum.subdomains.add(sub)
            
            # Reverse DNS enumeration
            if args.reverse:
                rev_subs = enum.reverse_dns_enum(args.reverse)
                for sub in rev_subs:
                    enum.subdomains.add(sub)
            
            # Dictionary attack
            if enum.wordlist_words:
                enum.dictionary_attack()
            
            # Common port names
            enum.brute_force_common_ports()
            
            # Numeric brute force
            enum.brute_force_numeric(1, 10)
            
            # Recursive enumeration
            if args.recursive and enum.subdomains:
                enum.recursive_enumeration()
            
            # Display results
            enum.display_results()
            
            # Save output
            if args.output:
                enum.output_file = args.output
                enum.save_results()
            
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
