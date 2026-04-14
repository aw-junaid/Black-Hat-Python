#!/usr/bin/env python3
"""
WHOIS Lookup Automation Tool
A comprehensive utility for performing WHOIS lookups on domains, IP addresses,
and AS numbers. Supports bulk lookups, data parsing, export functionality,
and integration with multiple WHOIS servers.
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
from typing import List, Dict, Optional, Tuple, Union, Any
from collections import defaultdict
import queue
import ipaddress

# Try importing python-whois with fallback
try:
    import whois
    WHOIS_LIB_AVAILABLE = True
except ImportError:
    WHOIS_LIB_AVAILABLE = False

# Try importing socket-based whois
try:
    import asyncwhois
    ASYNCWHOIS_AVAILABLE = True
except ImportError:
    ASYNCWHOIS_AVAILABLE = False

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
    import pandas as pd
    PANDAS_AVAILABLE = True
except ImportError:
    PANDAS_AVAILABLE = False


class WHOISParser:
    """
    WHOIS data parser for extracting structured information
    """
    
    # Common WHOIS field patterns
    FIELD_PATTERNS = {
        'Domain Name': [r'Domain Name:\s*(.+)', r'domain:\s*(.+)', r'Domain:\s*(.+)'],
        'Registry Domain ID': [r'Registry Domain ID:\s*(.+)', r'Domain ID:\s*(.+)'],
        'Registrar': [r'Registrar:\s*(.+)', r'Registrar Name:\s*(.+)'],
        'Registrar IANA ID': [r'Registrar IANA ID:\s*(.+)', r'Registrar ID:\s*(.+)'],
        'Registrar WHOIS Server': [r'Registrar WHOIS Server:\s*(.+)'],
        'Registrar URL': [r'Registrar URL:\s*(.+)', r'URL:\s*(.+)'],
        'Updated Date': [r'Updated Date:\s*(.+)', r'Last Updated:\s*(.+)', r'Changed:\s*(.+)'],
        'Creation Date': [r'Creation Date:\s*(.+)', r'Created On:\s*(.+)', r'Created:\s*(.+)'],
        'Registry Expiry Date': [r'Registry Expiry Date:\s*(.+)', r'Expiration Date:\s*(.+)', 
                                 r'Expires:\s*(.+)', r'Expiry:\s*(.+)'],
        'Registrant Name': [r'Registrant Name:\s*(.+)', r'Registrant:\s*(.+)'],
        'Registrant Organization': [r'Registrant Organization:\s*(.+)', r'Organization:\s*(.+)'],
        'Registrant Street': [r'Registrant Street:\s*(.+)', r'Street:\s*(.+)'],
        'Registrant City': [r'Registrant City:\s*(.+)', r'City:\s*(.+)'],
        'Registrant State/Province': [r'Registrant State/Province:\s*(.+)', r'State:\s*(.+)'],
        'Registrant Postal Code': [r'Registrant Postal Code:\s*(.+)', r'Postal Code:\s*(.+)'],
        'Registrant Country': [r'Registrant Country:\s*(.+)', r'Country:\s*(.+)'],
        'Registrant Phone': [r'Registrant Phone:\s*(.+)', r'Phone:\s*(.+)'],
        'Registrant Email': [r'Registrant Email:\s*(.+)', r'Email:\s*(.+)'],
        'Name Server': [r'Name Server:\s*(.+)', r'Nameserver:\s*(.+)', r'nserver:\s*(.+)'],
        'DNSSEC': [r'DNSSEC:\s*(.+)', r'dnssec:\s*(.+)'],
        'Status': [r'Status:\s*(.+)', r'Domain Status:\s*(.+)']
    }
    
    # IP WHOIS patterns
    IP_PATTERNS = {
        'inetnum': [r'inetnum:\s*(.+)', r'inetnum:\s*(.+)'],
        'netname': [r'netname:\s*(.+)', r'NetName:\s*(.+)'],
        'descr': [r'descr:\s*(.+)', r'Organization:\s*(.+)'],
        'country': [r'country:\s*(.+)', r'Country:\s*(.+)'],
        'admin-c': [r'admin-c:\s*(.+)', r'Admin Contact:\s*(.+)'],
        'tech-c': [r'tech-c:\s*(.+)', r'Tech Contact:\s*(.+)'],
        'status': [r'status:\s*(.+)', r'Status:\s*(.+)'],
        'mnt-by': [r'mnt-by:\s*(.+)', r'Maintainer:\s*(.+)'],
        'source': [r'source:\s*(.+)', r'Source:\s*(.+)']
    }
    
    @staticmethod
    def parse_domain_whois(whois_text: str) -> Dict[str, Any]:
        """
        Parse domain WHOIS text into structured data
        
        Args:
            whois_text: Raw WHOIS text
        
        Returns:
            Dictionary with parsed fields
        """
        result = {}
        
        # Try each field pattern
        for field, patterns in WHOISParser.FIELD_PATTERNS.items():
            for pattern in patterns:
                match = re.search(pattern, whois_text, re.IGNORECASE | re.MULTILINE)
                if match:
                    value = match.group(1).strip()
                    
                    # Handle multiple name servers
                    if field == 'Name Server' and field in result:
                        if isinstance(result[field], list):
                            result[field].append(value)
                        else:
                            result[field] = [result[field], value]
                    else:
                        result[field] = value
                    break
        
        # Extract name servers separately (they often appear multiple times)
        ns_matches = re.findall(r'Name Server:\s*(.+)', whois_text, re.IGNORECASE)
        if ns_matches:
            result['Name Servers'] = [ns.strip() for ns in ns_matches]
        
        # Extract domain status
        status_matches = re.findall(r'Domain Status:\s*(.+)', whois_text, re.IGNORECASE)
        if status_matches:
            result['Domain Status'] = [status.strip() for status in status_matches]
        
        return result
    
    @staticmethod
    def parse_ip_whois(whois_text: str) -> Dict[str, Any]:
        """
        Parse IP WHOIS text into structured data
        
        Args:
            whois_text: Raw WHOIS text
        
        Returns:
            Dictionary with parsed fields
        """
        result = {}
        
        for field, patterns in WHOISParser.IP_PATTERNS.items():
            for pattern in patterns:
                match = re.search(pattern, whois_text, re.IGNORECASE | re.MULTILINE)
                if match:
                    result[field] = match.group(1).strip()
                    break
        
        # Extract route information
        route_match = re.search(r'route:\s*(.+)', whois_text, re.IGNORECASE)
        if route_match:
            result['route'] = route_match.group(1).strip()
        
        route6_match = re.search(r'route6:\s*(.+)', whois_text, re.IGNORECASE)
        if route6_match:
            result['route6'] = route6_match.group(1).strip()
        
        return result
    
    @staticmethod
    def parse_as_whois(whois_text: str) -> Dict[str, Any]:
        """
        Parse AS number WHOIS text into structured data
        
        Args:
            whois_text: Raw WHOIS text
        
        Returns:
            Dictionary with parsed fields
        """
        result = {}
        
        patterns = {
            'as-number': [r'ASNumber:\s*(.+)', r'aut-num:\s*(.+)'],
            'as-name': [r'ASName:\s*(.+)', r'as-name:\s*(.+)'],
            'descr': [r'descr:\s*(.+)', r'Organization:\s*(.+)'],
            'country': [r'country:\s*(.+)', r'Country:\s*(.+)'],
            'admin-c': [r'admin-c:\s*(.+)', r'Admin Contact:\s*(.+)'],
            'tech-c': [r'tech-c:\s*(.+)', r'Tech Contact:\s*(.+)'],
            'mnt-by': [r'mnt-by:\s*(.+)', r'Maintainer:\s*(.+)'],
            'source': [r'source:\s*(.+)', r'Source:\s*(.+)']
        }
        
        for field, field_patterns in patterns.items():
            for pattern in field_patterns:
                match = re.search(pattern, whois_text, re.IGNORECASE | re.MULTILINE)
                if match:
                    result[field] = match.group(1).strip()
                    break
        
        return result


class WHOISLookup:
    """
    Main class for WHOIS lookups
    Supports domains, IPs, and AS numbers
    """
    
    # WHOIS servers by TLD
    WHOIS_SERVERS = {
        'com': 'whois.verisign-grs.com',
        'net': 'whois.verisign-grs.com',
        'org': 'whois.pir.org',
        'info': 'whois.afilias.net',
        'biz': 'whois.biz',
        'name': 'whois.nic.name',
        'mobi': 'whois.dotmobiregistry.net',
        'asia': 'whois.nic.asia',
        'tel': 'whois.nic.tel',
        'jobs': 'whois.nic.jobs',
        'xxx': 'whois.nic.xxx',
        'aero': 'whois.aero',
        'cat': 'whois.nic.cat',
        'coop': 'whois.nic.coop',
        'museum': 'whois.nic.museum',
        'travel': 'whois.nic.travel',
        'pro': 'whois.nic.pro',
        'edu': 'whois.educause.edu',
        'gov': 'whois.nic.gov',
        'mil': 'whois.nic.mil',
        'int': 'whois.iana.org'
    }
    
    # Regional Internet Registries (RIRs) for IP WHOIS
    RIR_SERVERS = {
        'arin': 'whois.arin.net',
        'ripe': 'whois.ripe.net',
        'apnic': 'whois.apnic.net',
        'lacnic': 'whois.lacnic.net',
        'afrinic': 'whois.afrinic.net'
    }
    
    def __init__(self, timeout: int = 10, verbose: bool = False,
                 use_cache: bool = True, cache_file: str = None):
        """
        Initialize WHOIS lookup tool
        
        Args:
            timeout: Connection timeout in seconds
            verbose: Enable verbose output
            use_cache: Enable result caching
            cache_file: Cache file path
        """
        self.timeout = timeout
        self.verbose = verbose
        self.use_cache = use_cache
        self.cache_file = cache_file or os.path.expanduser('~/.whois_cache.json')
        
        # Cache storage
        self.cache = self.load_cache() if use_cache else {}
        
        # Statistics
        self.stats = {
            'lookups': 0,
            'cache_hits': 0,
            'errors': 0,
            'start_time': None
        }
        
        # Setup logging
        self.setup_logging()
    
    def setup_logging(self):
        """Configure logging with optional colors"""
        self.logger = logging.getLogger('WHOISLookup')
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
    
    def load_cache(self) -> Dict:
        """Load cache from file"""
        try:
            if os.path.exists(self.cache_file):
                with open(self.cache_file, 'r') as f:
                    return json.load(f)
        except Exception as e:
            self.logger.debug(f"Cache load error: {e}")
        return {}
    
    def save_cache(self):
        """Save cache to file"""
        if not self.use_cache:
            return
        
        try:
            with open(self.cache_file, 'w') as f:
                json.dump(self.cache, f, indent=2)
        except Exception as e:
            self.logger.debug(f"Cache save error: {e}")
    
    def get_cache_key(self, query: str) -> str:
        """Generate cache key for query"""
        return f"{query.lower()}_{datetime.now().strftime('%Y%m%d')}"
    
    def get_from_cache(self, query: str) -> Optional[Dict]:
        """Get cached result if available and not expired"""
        if not self.use_cache:
            return None
        
        key = self.get_cache_key(query)
        if key in self.cache:
            self.stats['cache_hits'] += 1
            return self.cache[key].get('data')
        
        return None
    
    def add_to_cache(self, query: str, data: Dict):
        """Add result to cache"""
        if not self.use_cache:
            return
        
        key = self.get_cache_key(query)
        self.cache[key] = {
            'timestamp': datetime.now().isoformat(),
            'query': query,
            'data': data
        }
    
    def identify_query_type(self, query: str) -> str:
        """
        Identify the type of WHOIS query
        
        Args:
            query: Query string
        
        Returns:
            Query type: 'domain', 'ip', 'asn', or 'unknown'
        """
        query = query.strip().lower()
        
        # Check if it's an AS number
        if query.startswith('as') and query[2:].isdigit():
            return 'asn'
        if query.isdigit() and len(query) < 10:
            return 'asn'
        
        # Check if it's an IP address
        try:
            ipaddress.ip_address(query)
            return 'ip'
        except Exception:
            pass
        
        # Check if it's an IP range
        if '/' in query:
            try:
                ipaddress.ip_network(query, strict=False)
                return 'ip'
            except Exception:
                pass
        
        # Check if it's a domain
        if '.' in query and not query.startswith('http'):
            return 'domain'
        
        return 'unknown'
    
    def get_tld(self, domain: str) -> str:
        """Extract TLD from domain"""
        parts = domain.lower().split('.')
        if len(parts) > 1:
            return parts[-1]
        return ''
    
    def get_whois_server(self, query: str, query_type: str) -> str:
        """
        Determine appropriate WHOIS server
        
        Args:
            query: Query string
            query_type: Type of query
        
        Returns:
            WHOIS server address
        """
        if query_type == 'domain':
            tld = self.get_tld(query)
            return self.WHOIS_SERVERS.get(tld, 'whois.verisign-grs.com')
        
        elif query_type == 'ip':
            # For IPs, use ARIN as default (they will refer to correct RIR)
            return 'whois.arin.net'
        
        elif query_type == 'asn':
            return 'whois.arin.net'
        
        return 'whois.iana.org'
    
    def socket_whois(self, query: str, server: str = None) -> Optional[str]:
        """
        Perform WHOIS lookup using raw socket connection
        
        Args:
            query: Query string
            server: WHOIS server to use
        
        Returns:
            Raw WHOIS text or None
        """
        try:
            if not server:
                query_type = self.identify_query_type(query)
                server = self.get_whois_server(query, query_type)
            
            # Create socket connection
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((server, 43))
            
            # Send query
            sock.send(f"{query}\r\n".encode())
            
            # Receive response
            response = b''
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                response += data
            
            sock.close()
            
            return response.decode('utf-8', errors='ignore')
            
        except Exception as e:
            self.logger.error(f"Socket WHOIS error for {query}: {e}")
            self.stats['errors'] += 1
            return None
    
    def python_whois(self, query: str) -> Optional[Dict]:
        """
        Perform WHOIS lookup using python-whois library
        
        Args:
            query: Domain query
        
        Returns:
            Parsed WHOIS data or None
        """
        if not WHOIS_LIB_AVAILABLE:
            return None
        
        try:
            w = whois.whois(query)
            return dict(w)
        except Exception as e:
            self.logger.debug(f"python-whois error: {e}")
            return None
    
    def lookup_domain(self, domain: str) -> Dict:
        """
        Perform WHOIS lookup for domain
        
        Args:
            domain: Domain name
        
        Returns:
            WHOIS data dictionary
        """
        # Check cache first
        cached = self.get_from_cache(domain)
        if cached:
            if self.verbose:
                self.logger.debug(f"[*] Cache hit for {domain}")
            return cached
        
        if self.verbose:
            self.logger.info(f"[*] Looking up domain: {domain}")
        
        result = {
            'query': domain,
            'type': 'domain',
            'timestamp': datetime.now().isoformat(),
            'data': {},
            'raw': None
        }
        
        # Try python-whois first if available
        if WHOIS_LIB_AVAILABLE:
            w = self.python_whois(domain)
            if w:
                result['data'] = w
                self.add_to_cache(domain, result)
                return result
        
        # Fall back to socket WHOIS
        raw = self.socket_whois(domain)
        if raw:
            result['raw'] = raw
            result['data'] = WHOISParser.parse_domain_whois(raw)
            self.add_to_cache(domain, result)
        else:
            result['error'] = 'WHOIS lookup failed'
        
        return result
    
    def lookup_ip(self, ip: str) -> Dict:
        """
        Perform WHOIS lookup for IP address
        
        Args:
            ip: IP address or CIDR
        
        Returns:
            WHOIS data dictionary
        """
        cached = self.get_from_cache(ip)
        if cached:
            if self.verbose:
                self.logger.debug(f"[*] Cache hit for {ip}")
            return cached
        
        if self.verbose:
            self.logger.info(f"[*] Looking up IP: {ip}")
        
        result = {
            'query': ip,
            'type': 'ip',
            'timestamp': datetime.now().isoformat(),
            'data': {},
            'raw': None
        }
        
        # Try ARIN first
        raw = self.socket_whois(ip, 'whois.arin.net')
        
        # Check for referral
        if raw and 'whois.' in raw:
            # Extract referral server
            refer_match = re.search(r'ReferralServer:\s*whois://([^\s]+)', raw)
            if refer_match:
                refer_server = refer_match.group(1)
                raw = self.socket_whois(ip, refer_server)
        
        if raw:
            result['raw'] = raw
            result['data'] = WHOISParser.parse_ip_whois(raw)
            self.add_to_cache(ip, result)
        else:
            result['error'] = 'IP WHOIS lookup failed'
        
        return result
    
    def lookup_asn(self, asn: str) -> Dict:
        """
        Perform WHOIS lookup for AS number
        
        Args:
            asn: AS number (e.g., 'AS15169' or '15169')
        
        Returns:
            WHOIS data dictionary
        """
        # Normalize ASN format
        if asn.isdigit():
            asn_query = f"AS{asn}"
        else:
            asn_query = asn
        
        cached = self.get_from_cache(asn_query)
        if cached:
            if self.verbose:
                self.logger.debug(f"[*] Cache hit for {asn_query}")
            return cached
        
        if self.verbose:
            self.logger.info(f"[*] Looking up ASN: {asn_query}")
        
        result = {
            'query': asn_query,
            'type': 'asn',
            'timestamp': datetime.now().isoformat(),
            'data': {},
            'raw': None
        }
        
        raw = self.socket_whois(asn_query, 'whois.arin.net')
        
        if raw:
            result['raw'] = raw
            result['data'] = WHOISParser.parse_as_whois(raw)
            self.add_to_cache(asn_query, result)
        else:
            result['error'] = 'ASN WHOIS lookup failed'
        
        return result
    
    def lookup(self, query: str) -> Dict:
        """
        Perform WHOIS lookup based on query type
        
        Args:
            query: Domain, IP, or ASN
        
        Returns:
            WHOIS data dictionary
        """
        self.stats['lookups'] += 1
        
        query_type = self.identify_query_type(query)
        
        if query_type == 'domain':
            return self.lookup_domain(query)
        elif query_type == 'ip':
            return self.lookup_ip(query)
        elif query_type == 'asn':
            return self.lookup_asn(query)
        else:
            return {
                'query': query,
                'type': 'unknown',
                'timestamp': datetime.now().isoformat(),
                'error': f'Unknown query type: {query}'
            }
    
    def bulk_lookup(self, queries: List[str], threads: int = 5,
                   delay: float = 0.5) -> List[Dict]:
        """
        Perform bulk WHOIS lookups
        
        Args:
            queries: List of queries
            threads: Number of threads
            delay: Delay between lookups
        
        Returns:
            List of WHOIS results
        """
        self.logger.info(f"[*] Starting bulk lookup of {len(queries)} queries")
        
        results = []
        result_queue = queue.Queue()
        
        def worker(query_list):
            for q in query_list:
                result = self.lookup(q)
                result_queue.put(result)
                
                if self.verbose:
                    self.logger.info(f"[+] Completed: {q}")
                
                time.sleep(delay)
        
        # Split queries among threads
        chunk_size = max(1, len(queries) // threads)
        chunks = [queries[i:i + chunk_size] for i in range(0, len(queries), chunk_size)]
        
        thread_list = []
        for chunk in chunks:
            t = threading.Thread(target=worker, args=(chunk,))
            t.daemon = True
            t.start()
            thread_list.append(t)
        
        # Collect results
        with tqdm(total=len(queries), desc="WHOIS Lookups", 
                  disable=not TQDM_AVAILABLE) as pbar:
            completed = 0
            while completed < len(queries):
                try:
                    result = result_queue.get(timeout=1)
                    results.append(result)
                    completed += 1
                    pbar.update(1)
                except queue.Empty:
                    pass
        
        # Wait for threads
        for t in thread_list:
            t.join(timeout=2)
        
        return results
    
    def export_results(self, results: List[Dict], format: str, output_file: str):
        """
        Export WHOIS results to file
        
        Args:
            results: List of WHOIS results
            format: Export format (json, csv, txt)
            output_file: Output file path
        """
        if format == 'json':
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2, default=str)
        
        elif format == 'csv':
            # Flatten data for CSV
            flat_results = []
            for r in results:
                flat = {'query': r['query'], 'type': r['type'], 'timestamp': r['timestamp']}
                if 'error' in r:
                    flat['error'] = r['error']
                else:
                    flat.update(r.get('data', {}))
                flat_results.append(flat)
            
            if flat_results:
                with open(output_file, 'w', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=flat_results[0].keys())
                    writer.writeheader()
                    writer.writerows(flat_results)
        
        elif format == 'txt':
            with open(output_file, 'w') as f:
                for r in results:
                    f.write(f"\n{'='*60}\n")
                    f.write(f"Query: {r['query']}\n")
                    f.write(f"Type: {r['type']}\n")
                    f.write(f"Timestamp: {r['timestamp']}\n")
                    f.write(f"{'='*60}\n")
                    
                    if 'error' in r:
                        f.write(f"ERROR: {r['error']}\n")
                    else:
                        for key, value in r.get('data', {}).items():
                            f.write(f"{key}: {value}\n")
                    
                    if 'raw' in r and r['raw']:
                        f.write(f"\n--- RAW DATA ---\n")
                        f.write(r['raw'][:500])
                        if len(r['raw']) > 500:
                            f.write("... (truncated)")
                    f.write("\n")
        
        self.logger.info(f"[+] Results exported to {output_file}")
    
    def show_statistics(self):
        """Display lookup statistics"""
        print(f"\n{'='*60}")
        print(f"WHOIS Lookup Statistics")
        print(f"{'='*60}")
        print(f"Total lookups: {self.stats['lookups']}")
        print(f"Cache hits: {self.stats['cache_hits']}")
        print(f"Errors: {self.stats['errors']}")
        print(f"Cache size: {len(self.cache)} entries")
        print(f"{'='=60}\n")


class WHOISMonitor:
    """
    WHOIS monitoring for domain changes
    """
    
    def __init__(self, check_interval: int = 86400, verbose: bool = False):
        """
        Initialize WHOIS monitor
        
        Args:
            check_interval: Check interval in seconds (default: 24 hours)
            verbose: Enable verbose output
        """
        self.check_interval = check_interval
        self.verbose = verbose
        self.setup_logging()
    
    def setup_logging(self):
        """Configure logging"""
        self.logger = logging.getLogger('WHOISMonitor')
        handler = logging.StreamHandler()
        
        if COLORAMA_AVAILABLE:
            formatter = logging.Formatter(
                f'{Fore.CYAN}%(asctime)s{Style.RESET_ALL} - %(message)s'
            )
        else:
            formatter = logging.Formatter('%(asctime)s - %(message)s')
        
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
    
    def monitor_domain(self, domain: str, duration: int = None):
        """
        Monitor domain for WHOIS changes
        
        Args:
            domain: Domain to monitor
            duration: Monitoring duration in seconds (None = forever)
        """
        self.logger.info(f"[*] Monitoring domain: {domain}")
        
        lookup = WHOISLookup(verbose=self.verbose)
        previous = lookup.lookup_domain(domain)
        
        if 'error' in previous:
            self.logger.error(f"[-] Initial lookup failed: {previous['error']}")
            return
        
        self.logger.info(f"[+] Initial data captured for {domain}")
        
        start_time = time.time()
        check_count = 0
        
        try:
            while True:
                if duration and (time.time() - start_time) > duration:
                    self.logger.info(f"[*] Monitoring duration reached")
                    break
                
                time.sleep(self.check_interval)
                check_count += 1
                
                self.logger.info(f"[*] Check #{check_count} for {domain}")
                
                current = lookup.lookup_domain(domain)
                
                if 'error' in current:
                    self.logger.warning(f"[-] Lookup failed: {current['error']}")
                    continue
                
                # Compare key fields
                changes = []
                
                for key in ['Creation Date', 'Registry Expiry Date', 
                           'Registrar', 'Name Servers']:
                    if key in previous['data'] and key in current['data']:
                        if previous['data'][key] != current['data'][key]:
                            changes.append(f"{key}: {previous['data'][key]} -> {current['data'][key]}")
                
                if changes:
                    self.logger.warning(f"[!] Changes detected for {domain}:")
                    for change in changes:
                        self.logger.warning(f"    {change}")
                    
                    # Update previous data
                    previous = current
                else:
                    self.logger.info(f"[*] No changes detected")
                
        except KeyboardInterrupt:
            self.logger.info("\n[*] Monitoring stopped")


def banner():
    """Display tool banner"""
    banner_text = f"""
{'='*60}
    WHOIS Lookup Automation Tool
    For domain, IP, and ASN intelligence gathering
    Supports bulk lookups and data export
{'='*60}
    """
    if COLORAMA_AVAILABLE:
        print(f"{Fore.GREEN}{banner_text}{Style.RESET_ALL}")
    else:
        print(banner_text)


def main():
    """Main function for command-line interface"""
    parser = argparse.ArgumentParser(
        description='WHOIS Lookup Automation Tool - Domain, IP, and ASN intelligence',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Single domain lookup
  python whois_lookup.py --domain example.com
  
  # Single IP lookup
  python whois_lookup.py --ip 8.8.8.8
  
  # ASN lookup
  python whois_lookup.py --asn 15169
  
  # Bulk lookup from file
  python whois_lookup.py --file domains.txt --output results.json --format json
  
  # Export to CSV
  python whois_lookup.py --file domains.txt --output results.csv --format csv
  
  # Verbose output with cache
  python whois_lookup.py --domain example.com --verbose --no-cache
  
  # Monitor domain for changes
  python whois_lookup.py --monitor example.com --interval 3600 --duration 86400
  
  # Use specific WHOIS server
  python whois_lookup.py --domain example.com --server whois.verisign-grs.com
  
  # Multiple queries with delay
  python whois_lookup.py --file domains.txt --threads 3 --delay 1.0
        """
    )
    
    # Query options
    parser.add_argument('--domain', help='Domain name to lookup')
    parser.add_argument('--ip', help='IP address to lookup')
    parser.add_argument('--asn', help='AS number to lookup')
    parser.add_argument('--file', '-f', help='File containing queries (one per line)')
    
    # Server options
    parser.add_argument('--server', help='Specific WHOIS server to use')
    parser.add_argument('--timeout', type=int, default=10, help='Connection timeout (default: 10)')
    
    # Bulk options
    parser.add_argument('--threads', type=int, default=5, help='Threads for bulk lookup')
    parser.add_argument('--delay', type=float, default=0.5, help='Delay between lookups')
    
    # Cache options
    parser.add_argument('--no-cache', action='store_true', help='Disable caching')
    parser.add_argument('--cache-file', help='Cache file path')
    
    # Output options
    parser.add_argument('--output', '-o', help='Output file')
    parser.add_argument('--format', choices=['json', 'csv', 'txt'], default='json',
                       help='Output format (default: json)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    
    # Monitoring
    parser.add_argument('--monitor', help='Monitor domain for changes')
    parser.add_argument('--interval', type=int, default=86400,
                       help='Monitor interval in seconds (default: 86400)')
    parser.add_argument('--duration', type=int, help='Monitor duration in seconds')
    
    args = parser.parse_args()
    
    # Display banner
    banner()
    
    # Initialize WHOIS lookup
    lookup = WHOISLookup(
        timeout=args.timeout,
        verbose=args.verbose,
        use_cache=not args.no_cache,
        cache_file=args.cache_file
    )
    
    try:
        # Monitor mode
        if args.monitor:
            monitor = WHOISMonitor(
                check_interval=args.interval,
                verbose=args.verbose
            )
            monitor.monitor_domain(args.monitor, args.duration)
            return
        
        # Collect queries
        queries = []
        
        if args.domain:
            queries.append(args.domain)
        if args.ip:
            queries.append(args.ip)
        if args.asn:
            queries.append(args.asn)
        
        if args.file:
            try:
                with open(args.file, 'r') as f:
                    file_queries = [line.strip() for line in f if line.strip()]
                    queries.extend(file_queries)
            except Exception as e:
                print(f"[-] Error reading file: {e}")
                sys.exit(1)
        
        if not queries:
            print("[-] No queries specified")
            parser.print_help()
            sys.exit(1)
        
        # Perform lookups
        results = []
        
        if len(queries) == 1 and not args.file:
            # Single lookup
            result = lookup.lookup(queries[0])
            results.append(result)
            
            # Display result
            print(f"\n{'='*60}")
            print(f"WHOIS Result for: {result['query']}")
            print(f"{'='*60}")
            
            if 'error' in result:
                print(f"ERROR: {result['error']}")
            else:
                for key, value in result.get('data', {}).items():
                    if value:
                        if isinstance(value, list):
                            print(f"{key}:")
                            for item in value:
                                print(f"  - {item}")
                        else:
                            print(f"{key}: {value}")
            
            if args.verbose and 'raw' in result and result['raw']:
                print(f"\n--- RAW DATA ---")
                print(result['raw'][:1000])
                if len(result['raw']) > 1000:
                    print("... (truncated)")
            print()
            
        else:
            # Bulk lookup
            results = lookup.bulk_lookup(queries, args.threads, args.delay)
            
            # Display summary
            success = len([r for r in results if 'error' not in r])
            failed = len([r for r in results if 'error' in r])
            
            print(f"\n[+] Bulk lookup complete")
            print(f"    Success: {success}")
            print(f"    Failed: {failed}")
        
        # Export results
        if args.output and results:
            lookup.export_results(results, args.format, args.output)
        
        # Show statistics
        lookup.show_statistics()
        
        # Save cache
        if not args.no_cache:
            lookup.save_cache()
        
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
    except Exception as e:
        print(f"[!] Error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()


if __name__ == "__main__":
    main()
