#!/usr/bin/env python3
"""
Google Dorking Automation Tool
A comprehensive utility for automating Google searches using advanced operators (dorks)
to discover sensitive information, exposed files, vulnerabilities, and hidden resources.
For authorized security testing and OSINT gathering only.
"""

import argparse
import sys
import os
import time
import re
import json
import csv
import urllib.parse
from datetime import datetime
from typing import List, Dict, Set, Optional, Tuple, Any
from collections import defaultdict
import random
import string

# HTTP request libraries
try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

# Parsing libraries
try:
    from bs4 import BeautifulSoup
    BEAUTIFULSOUP_AVAILABLE = True
except ImportError:
    BEAUTIFULSOUP_AVAILABLE = False

try:
    from googlesearch import search
    GOOGLESEARCH_AVAILABLE = True
except ImportError:
    GOOGLESEARCH_AVAILABLE = False

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
    import pandas as pd
    PANDAS_AVAILABLE = True
except ImportError:
    PANDAS_AVAILABLE = False


class GoogleDorkLibrary:
    """
    Comprehensive library of Google dorks categorized by purpose
    """
    
    # File type dorks
    FILE_TYPES = {
        'pdf': 'filetype:pdf',
        'doc': 'filetype:doc OR filetype:docx',
        'xls': 'filetype:xls OR filetype:xlsx',
        'ppt': 'filetype:ppt OR filetype:pptx',
        'txt': 'filetype:txt',
        'csv': 'filetype:csv',
        'json': 'filetype:json',
        'xml': 'filetype:xml',
        'sql': 'filetype:sql',
        'db': 'filetype:db OR filetype:sqlite',
        'log': 'filetype:log',
        'conf': 'filetype:conf OR filetype:config',
        'ini': 'filetype:ini',
        'env': 'filetype:env',
        'bak': 'filetype:bak OR filetype:backup',
        'old': 'filetype:old',
        'swp': 'filetype:swp',
        'kdbx': 'filetype:kdbx',  # KeePass
        'pem': 'filetype:pem',      # Private keys
        'key': 'filetype:key',       # SSH keys
        'p12': 'filetype:p12',       # PKCS12
        'pfx': 'filetype:pfx'        # PKCS12
    }
    
    # Sensitive information dorks
    SENSITIVE_INFO = {
        'passwords': 'intext:password | intext:passwd | intext:credentials',
        'api_keys': 'intext:api_key | intext:apikey | intext:api-key',
        'aws_keys': 'intext:AWS_ACCESS_KEY_ID | intext:AWS_SECRET_ACCESS_KEY',
        'private_keys': 'intext:PRIVATE KEY | intext:BEGIN RSA PRIVATE KEY',
        'database': 'intext:mysql_connect | intext:pg_connect | intext:mongodb',
        'connection_strings': 'intext:connectionString | intext:connectionstring',
        'tokens': 'intext:bearer | intext:JWT | intext:oauth',
        'firebase': 'inurl:firebaseio.com | intext:firebase',
        'slack_tokens': 'intext:xoxb- | intext:xoxp-',
        'stripe_keys': 'intext:sk_live | intext:pk_live',
        'twilio': 'intext:ACCOUNT_SID | intext:ACCOUNT_TOKEN'
    }
    
    # Vulnerability dorks
    VULNERABILITIES = {
        'sql_injection': 'inurl:?id= | inurl:?page=',
        'xss': 'intext:<script> | intext:javascript:',
        'lfi': 'inurl:file= | inurl:document=',
        'rfi': 'inurl:http:// | inurl:https://',
        'open_redirect': 'inurl:redirect= | inurl:return=',
        'phpinfo': 'filetype:php intext:phpinfo()',
        'debug_mode': 'intext:debug | intext:stacktrace | intext:exception',
        'directory_listing': 'intitle:index.of',
        'backup_files': 'filetype:bak | filetype:old | filetype:backup',
        'sensitive_folders': 'inurl:admin | inurl:backup | inurl:private'
    }
    
    # Login panels and admin interfaces
    ADMIN_PANELS = {
        'admin_login': 'inurl:admin/login | inurl:admin | intitle:admin',
        'cpanel': 'inurl:cpanel | intitle:cpanel',
        'webmail': 'inurl:webmail | intitle:webmail',
        'phpmyadmin': 'inurl:phpmyadmin | intitle:phpmyadmin',
        'wordpress_admin': 'inurl:wp-admin | inurl:wp-login',
        'joomla_admin': 'inurl:administrator',
        'drupal_admin': 'inurl:user/login',
        'magento_admin': 'inurl:admin | inurl:index.php/admin',
        'tomcat_manager': 'inurl:manager/html',
        'jenkins': 'inurl:jenkins | intitle:jenkins'
    }
    
    # Exposed devices and services
    EXPOSED_DEVICES = {
        'cameras': 'intitle:"Live View / - AXIS" | inurl:view/view.shtml',
        'routers': 'intitle:"Router Status" | intitle:"Router Configuration"',
        'printers': 'intitle:"HP LaserJet" | intitle:"Printer Status"',
        'network_storage': 'intitle:"NAS" | intitle:"Network Storage"',
        'webcams': 'intitle:webcam | intitle:webcamxp',
        'dvr': 'intitle:DVR | intitle:"Network Video Recorder"',
        'voip': 'intitle:"VoIP" | intitle:"Phone System"',
        'industrial': 'intitle:"SCADA" | intitle:"PLC" | intitle:"HMI"'
    }
    
    # Cloud storage and file sharing
    CLOUD_STORAGE = {
        'google_drive': 'site:drive.google.com',
        'dropbox': 'site:dropbox.com/s/',
        'onedrive': 'site:onedrive.live.com',
        'amazon_s3': 'site:s3.amazonaws.com',
        'firebase': 'site:firebaseio.com',
        'box': 'site:app.box.com',
        'sharepoint': 'site:sharepoint.com',
        'nextcloud': 'inurl:nextcloud | inurl:owncloud'
    }
    
    # Code repositories
    CODE_REPOS = {
        'github': 'site:github.com | site:github.io',
        'gitlab': 'site:gitlab.com',
        'bitbucket': 'site:bitbucket.org',
        'sourceforge': 'site:sourceforge.net',
        'pastebin': 'site:pastebin.com',
        'gist': 'site:gist.github.com',
        'codeberg': 'site:codeberg.org'
    }
    
    @classmethod
    def get_all_dorks(cls) -> Dict[str, str]:
        """Get all dorks in a single dictionary"""
        all_dorks = {}
        categories = [
            cls.FILE_TYPES,
            cls.SENSITIVE_INFO,
            cls.VULNERABILITIES,
            cls.ADMIN_PANELS,
            cls.EXPOSED_DEVICES,
            cls.CLOUD_STORAGE,
            cls.CODE_REPOS
        ]
        
        for category in categories:
            all_dorks.update(category)
        
        return all_dorks


class GoogleDorker:
    """
    Main class for Google dorking automation
    """
    
    # Google search URL
    GOOGLE_SEARCH_URL = "https://www.google.com/search"
    
    # User agents to rotate
    USER_AGENTS = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Safari/605.1.15',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/91.0.864.59',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    ]
    
    def __init__(self, target: str = None, dork_file: str = None,
                 output_file: str = None, output_format: str = 'json',
                 max_results: int = 100, delay: float = 2.0,
                 proxies: List[str] = None, verbose: bool = False,
                 use_selenium: bool = False, headless: bool = True,
                 respect_robots: bool = True, timeout: int = 10):
        """
        Initialize Google dorker
        
        Args:
            target: Target domain or keyword (e.g., example.com)
            dork_file: File containing custom dorks
            output_file: Output file path
            output_format: Output format (json, csv, txt)
            max_results: Maximum results per dork
            delay: Delay between requests (to avoid rate limiting)
            proxies: List of proxies to rotate
            verbose: Enable verbose output
            use_selenium: Use Selenium for JavaScript rendering
            headless: Run Selenium in headless mode
            respect_robots: Respect robots.txt
            timeout: Request timeout
        """
        if not REQUESTS_AVAILABLE:
            raise ImportError("requests module required. Install with: pip install requests")
        
        self.target = target
        self.dork_file = dork_file
        self.output_file = output_file
        self.output_format = output_format
        self.max_results = max_results
        self.delay = delay
        self.proxies = proxies or []
        self.verbose = verbose
        self.use_selenium = use_selenium
        self.headless = headless
        self.respect_robots = respect_robots
        self.timeout = timeout
        
        # Session management
        self.session = self.create_session()
        self.proxy_cycle = itertools.cycle(self.proxies) if self.proxies else None
        
        # Results storage
        self.results = []
        self.all_urls = set()
        
        # Statistics
        self.stats = {
            'dorks_processed': 0,
            'total_results': 0,
            'unique_urls': 0,
            'errors': 0,
            'start_time': None,
            'end_time': None
        }
        
        # Setup logging
        self.setup_logging()
        
        # Load dorks
        self.dorks = self.load_dorks()
    
    def setup_logging(self):
        """Configure logging with optional colors"""
        self.logger = logging.getLogger('GoogleDorker')
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
    
    def create_session(self) -> requests.Session:
        """Create requests session with retry strategy"""
        session = requests.Session()
        
        # Configure retries
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        return session
    
    def get_headers(self) -> Dict[str, str]:
        """Get random headers for request"""
        return {
            'User-Agent': random.choice(self.USER_AGENTS),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }
    
    def get_proxy(self) -> Optional[Dict[str, str]]:
        """Get next proxy from cycle"""
        if not self.proxy_cycle:
            return None
        
        proxy = next(self.proxy_cycle)
        return {
            'http': proxy,
            'https': proxy
        }
    
    def load_dorks(self) -> List[Dict[str, str]]:
        """
        Load dorks from file or use built-in library
        
        Returns:
            List of dork dictionaries
        """
        dorks = []
        
        if self.dork_file:
            # Load custom dorks from file
            try:
                with open(self.dork_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            # Parse name and dork (format: name|dork)
                            if '|' in line:
                                name, dork = line.split('|', 1)
                                dorks.append({
                                    'name': name.strip(),
                                    'dork': dork.strip(),
                                    'category': 'custom'
                                })
                            else:
                                dorks.append({
                                    'name': f"custom_{len(dorks)}",
                                    'dork': line,
                                    'category': 'custom'
                                })
                self.logger.info(f"[+] Loaded {len(dorks)} custom dorks from {self.dork_file}")
            except Exception as e:
                self.logger.error(f"[-] Error loading dork file: {e}")
        
        # Add built-in dorks
        if not dorks or self.verbose:
            builtin_dorks = []
            
            # Add target if specified
            target_suffix = f" site:{self.target}" if self.target else ""
            
            # File type dorks
            for name, dork in GoogleDorkLibrary.FILE_TYPES.items():
                builtin_dorks.append({
                    'name': f"file_{name}",
                    'dork': dork + target_suffix,
                    'category': 'file_types'
                })
            
            # Sensitive info dorks
            for name, dork in GoogleDorkLibrary.SENSITIVE_INFO.items():
                builtin_dorks.append({
                    'name': f"info_{name}",
                    'dork': dork + target_suffix,
                    'category': 'sensitive_info'
                })
            
            # Vulnerability dorks
            for name, dork in GoogleDorkLibrary.VULNERABILITIES.items():
                builtin_dorks.append({
                    'name': f"vuln_{name}",
                    'dork': dork + target_suffix,
                    'category': 'vulnerabilities'
                })
            
            # Admin panels
            for name, dork in GoogleDorkLibrary.ADMIN_PANELS.items():
                builtin_dorks.append({
                    'name': f"admin_{name}",
                    'dork': dork + target_suffix,
                    'category': 'admin_panels'
                })
            
            # Exposed devices
            for name, dork in GoogleDorkLibrary.EXPOSED_DEVICES.items():
                builtin_dorks.append({
                    'name': f"device_{name}",
                    'dork': dork + target_suffix,
                    'category': 'exposed_devices'
                })
            
            # Cloud storage
            for name, dork in GoogleDorkLibrary.CLOUD_STORAGE.items():
                builtin_dorks.append({
                    'name': f"cloud_{name}",
                    'dork': dork + target_suffix,
                    'category': 'cloud_storage'
                })
            
            # Code repositories
            for name, dork in GoogleDorkLibrary.CODE_REPOS.items():
                builtin_dorks.append({
                    'name': f"repo_{name}",
                    'dork': dork + target_suffix,
                    'category': 'code_repos'
                })
            
            dorks.extend(builtin_dorks)
            self.logger.info(f"[+] Loaded {len(builtin_dorks)} built-in dorks")
        
        return dorks
    
    def build_search_url(self, dork: str, start: int = 0) -> str:
        """Build Google search URL with parameters"""
        params = {
            'q': dork,
            'start': start,
            'num': 10  # Results per page
        }
        
        return f"{self.GOOGLE_SEARCH_URL}?{urllib.parse.urlencode(params)}"
    
    def parse_search_results(self, html: str) -> Tuple[List[str], int]:
        """
        Parse Google search results from HTML
        
        Args:
            html: HTML content
        
        Returns:
            Tuple of (list of URLs, number of results)
        """
        urls = []
        total_results = 0
        
        if not BEAUTIFULSOUP_AVAILABLE:
            # Fallback to regex
            url_pattern = r'<a href="(/url\?q=|/search\?q=)([^"]+)"'
            matches = re.findall(url_pattern, html)
            
            for match in matches:
                url = match[1]
                # Decode URL
                url = urllib.parse.unquote(url)
                # Extract actual URL
                if '&' in url:
                    url = url.split('&')[0]
                if url.startswith('http'):
                    urls.append(url)
        else:
            soup = BeautifulSoup(html, 'html.parser')
            
            # Try to find result count
            result_stats = soup.find('div', {'id': 'result-stats'})
            if result_stats:
                stats_text = result_stats.get_text()
                numbers = re.findall(r'[\d,]+', stats_text)
                if numbers:
                    total_results = int(numbers[0].replace(',', ''))
            
            # Find result links
            for div in soup.find_all('div'):
                if div.get('class') and ('g' in div.get('class') or 'rc' in div.get('class')):
                    link = div.find('a')
                    if link and link.get('href'):
                        href = link['href']
                        if href.startswith('/url?q='):
                            href = href.split('/url?q=')[1].split('&')[0]
                            href = urllib.parse.unquote(href)
                        if href.startswith('http'):
                            urls.append(href)
        
        return urls, total_results
    
    def google_search(self, dork: str, dork_info: Dict) -> List[Dict]:
        """
        Perform Google search for a single dork
        
        Args:
            dork: Search query
            dork_info: Dork metadata
        
        Returns:
            List of result dictionaries
        """
        results = []
        start = 0
        page = 1
        
        self.logger.info(f"[*] Searching: {dork_info['name']} - {dork}")
        
        while len(results) < self.max_results:
            try:
                # Build URL
                url = self.build_search_url(dork, start)
                
                # Make request
                headers = self.get_headers()
                proxies = self.get_proxy()
                
                response = self.session.get(
                    url,
                    headers=headers,
                    proxies=proxies,
                    timeout=self.timeout
                )
                
                if response.status_code == 200:
                    # Parse results
                    page_urls, total_est = self.parse_search_results(response.text)
                    
                    for page_url in page_urls:
                        if page_url not in self.all_urls:
                            self.all_urls.add(page_url)
                            
                            result = {
                                'url': page_url,
                                'title': self.extract_title(response.text, page_url),
                                'snippet': self.extract_snippet(response.text, page_url),
                                'dork_name': dork_info['name'],
                                'dork_query': dork,
                                'category': dork_info.get('category', 'unknown'),
                                'timestamp': datetime.now().isoformat()
                            }
                            
                            results.append(result)
                            
                            if self.verbose:
                                if COLORAMA_AVAILABLE:
                                    print(f"{Fore.GREEN}[+] {page_url}{Style.RESET_ALL}")
                                else:
                                    print(f"[+] {page_url}")
                            
                            if len(results) >= self.max_results:
                                break
                    
                    # Check if more pages available
                    if len(page_urls) < 10 or 'Next' not in response.text:
                        break
                    
                    start += 10
                    page += 1
                    
                    # Random delay between pages
                    time.sleep(self.delay + random.uniform(0.5, 1.5))
                    
                elif response.status_code == 429:
                    self.logger.warning("[-] Rate limited. Waiting longer...")
                    time.sleep(self.delay * 5)
                else:
                    self.logger.warning(f"[-] HTTP {response.status_code}")
                    break
                    
            except Exception as e:
                self.logger.debug(f"Search error: {e}")
                self.stats['errors'] += 1
                break
        
        return results
    
    def extract_title(self, html: str, url: str) -> str:
        """Extract page title from HTML"""
        if BEAUTIFULSOUP_AVAILABLE:
            soup = BeautifulSoup(html, 'html.parser')
            title_tag = soup.find('title')
            if title_tag:
                return title_tag.get_text().strip()
        
        # Fallback
        return url
    
    def extract_snippet(self, html: str, url: str) -> str:
        """Extract snippet for URL from search results"""
        if BEAUTIFULSOUP_AVAILABLE:
            soup = BeautifulSoup(html, 'html.parser')
            
            # Find the result div containing this URL
            for div in soup.find_all('div'):
                link = div.find('a')
                if link and link.get('href') and url in link['href']:
                    # Look for description
                    desc = div.find('div', {'class': 'IsZvec'})
                    if desc:
                        return desc.get_text().strip()
        
        return ""
    
    def run_dorks(self):
        """Run all dorks"""
        self.stats['start_time'] = datetime.now()
        
        self.logger.info(f"\n{'='*60}")
        self.logger.info(f"Google Dorking Automation Started")
        self.logger.info(f"{'='*60}")
        self.logger.info(f"Target: {self.target or 'No target (global search)'}")
        self.logger.info(f"Dorks: {len(self.dorks)}")
        self.logger.info(f"Max results per dork: {self.max_results}")
        self.logger.info(f"Delay: {self.delay}s")
        self.logger.info(f"{'='=60}\n")
        
        # Progress bar
        if TQDM_AVAILABLE:
            dork_iterator = tqdm(self.dorks, desc="Processing dorks")
        else:
            dork_iterator = self.dorks
        
        for dork_info in dork_iterator:
            # Process each dork
            results = self.google_search(dork_info['dork'], dork_info)
            
            self.results.extend(results)
            self.stats['dorks_processed'] += 1
            self.stats['total_results'] += len(results)
            
            # Display progress
            if not TQDM_AVAILABLE:
                self.logger.info(f"[*] Found {len(results)} results for {dork_info['name']}")
            
            # Random delay between dorks
            if self.delay > 0:
                time.sleep(self.delay + random.uniform(1, 3))
        
        self.stats['end_time'] = datetime.now()
        self.stats['unique_urls'] = len(self.all_urls)
        
        self.display_summary()
        
        if self.output_file:
            self.save_results()
    
    def display_summary(self):
        """Display execution summary"""
        elapsed = (self.stats['end_time'] - self.stats['start_time']).total_seconds()
        
        print(f"\n{'='*60}")
        print(f"Google Dorking Summary")
        print(f"{'='*60}")
        print(f"Target: {self.target or 'Global'}")
        print(f"Time elapsed: {elapsed:.2f} seconds")
        print(f"Dorks processed: {self.stats['dorks_processed']}")
        print(f"Total results: {self.stats['total_results']}")
        print(f"Unique URLs: {self.stats['unique_urls']}")
        print(f"Errors: {self.stats['errors']}")
        print(f"{'='=60}\n")
        
        # Show top categories
        if self.results:
            categories = defaultdict(int)
            for r in self.results:
                categories[r['category']] += 1
            
            print("Results by category:")
            for cat, count in sorted(categories.items(), key=lambda x: x[1], reverse=True):
                print(f"  {cat}: {count}")
            print()
    
    def save_results(self):
        """Save results to file"""
        if not self.results:
            self.logger.warning("[-] No results to save")
            return
        
        try:
            if self.output_format == 'json':
                with open(self.output_file, 'w') as f:
                    json.dump({
                        'target': self.target,
                        'timestamp': datetime.now().isoformat(),
                        'stats': self.stats,
                        'results': self.results
                    }, f, indent=2)
            
            elif self.output_format == 'csv':
                with open(self.output_file, 'w', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow(['URL', 'Title', 'Dork Name', 'Category', 'Timestamp'])
                    for r in self.results:
                        writer.writerow([
                            r['url'],
                            r['title'],
                            r['dork_name'],
                            r['category'],
                            r['timestamp']
                        ])
            
            elif self.output_format == 'txt':
                with open(self.output_file, 'w') as f:
                    f.write(f"Google Dorking Results for {self.target}\n")
                    f.write(f"Generated: {datetime.now().isoformat()}\n")
                    f.write("=" * 60 + "\n\n")
                    
                    for r in self.results:
                        f.write(f"URL: {r['url']}\n")
                        f.write(f"Title: {r['title']}\n")
                        f.write(f"Dork: {r['dork_name']}\n")
                        f.write(f"Category: {r['category']}\n")
                        f.write("-" * 40 + "\n")
            
            self.logger.info(f"[+] Results saved to {self.output_file}")
            
        except Exception as e:
            self.logger.error(f"[-] Error saving results: {e}")
    
    def analyze_results(self) -> Dict:
        """Analyze results for patterns and insights"""
        analysis = {
            'total_urls': len(self.results),
            'unique_domains': set(),
            'file_types': defaultdict(int),
            'categories': defaultdict(int),
            'top_domains': [],
            'sensitive_findings': []
        }
        
        for r in self.results:
            # Extract domain
            try:
                from urllib.parse import urlparse
                domain = urlparse(r['url']).netloc
                analysis['unique_domains'].add(domain)
            except:
                pass
            
            # Count by category
            analysis['categories'][r['category']] += 1
            
            # Check file extensions
            if '.' in r['url']:
                ext = r['url'].split('.')[-1].split('/')[0].lower()
                if len(ext) < 5:
                    analysis['file_types'][ext] += 1
            
            # Flag sensitive findings
            if r['category'] in ['sensitive_info', 'vulnerabilities']:
                analysis['sensitive_findings'].append(r['url'])
        
        # Top domains
        domain_counts = defaultdict(int)
        for r in self.results:
            try:
                from urllib.parse import urlparse
                domain = urlparse(r['url']).netloc
                domain_counts[domain] += 1
            except:
                pass
        
        analysis['top_domains'] = sorted(
            domain_counts.items(),
            key=lambda x: x[1],
            reverse=True
        )[:10]
        
        analysis['unique_domains'] = len(analysis['unique_domains'])
        
        return analysis


class DorkBuilder:
    """
    Interactive dork builder utility
    """
    
    @staticmethod
    def build_dork() -> str:
        """Interactive dork builder"""
        print("\nInteractive Dork Builder")
        print("=" * 40)
        
        components = []
        
        # Basic operators
        print("\nBasic Operators:")
        print("1. site: (limit to domain)")
        print("2. filetype: (limit to file type)")
        print("3. intitle: (word in title)")
        print("4. inurl: (word in URL)")
        print("5. intext: (word in text)")
        print("6. link: (pages linking to URL)")
        print("7. related: (related pages)")
        print("8. cache: (cached version)")
        print("9. info: (summary)")
        
        while True:
            choice = input("\nSelect operator (or 'done'): ").strip()
            
            if choice.lower() == 'done':
                break
            
            if choice == '1':
                domain = input("Enter domain (e.g., example.com): ").strip()
                components.append(f"site:{domain}")
            elif choice == '2':
                ftype = input("Enter file type (e.g., pdf, doc): ").strip()
                components.append(f"filetype:{ftype}")
            elif choice == '3':
                word = input("Enter title word: ").strip()
                components.append(f"intitle:{word}")
            elif choice == '4':
                word = input("Enter URL word: ").strip()
                components.append(f"inurl:{word}")
            elif choice == '5':
                word = input("Enter text word: ").strip()
                components.append(f"intext:{word}")
            elif choice == '6':
                url = input("Enter URL: ").strip()
                components.append(f"link:{url}")
        
        # Combine with AND/OR
        if components:
            print("\nCombine operators with:")
            print("1. AND (all conditions)")
            print("2. OR (any condition)")
            
            combine = input("Choose (1/2): ").strip()
            
            if combine == '1':
                dork = ' '.join(components)
            else:
                dork = ' OR '.join(components)
            
            # Add keywords
            keywords = input("\nEnter keywords (space-separated): ").strip()
            if keywords:
                dork = f"{keywords} {dork}"
            
            return dork
        
        return ""


def banner():
    """Display tool banner"""
    banner_text = f"""
{'='*60}
    Google Dorking Automation Tool
    For authorized security testing and OSINT gathering
    Categories: Files, Sensitive Info, Vulns, Admin, Devices
{'='*60}
    """
    if COLORAMA_AVAILABLE:
        print(f"{Fore.YELLOW}{banner_text}{Style.RESET_ALL}")
    else:
        print(banner_text)


def main():
    """Main function for command-line interface"""
    parser = argparse.ArgumentParser(
        description='Google Dorking Automation Tool - Discover sensitive information via Google',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic domain search
  python google_dork.py --target example.com
  
  # Specific file types
  python google_dork.py --target example.com --dork-category file_types --max-results 50
  
  # Sensitive information
  python google_dork.py --target example.com --dork-category sensitive_info
  
  # Custom dorks from file
  python google_dork.py --target example.com --dork-file mydorks.txt
  
  # Export results
  python google_dork.py --target example.com --output results.json --format json
  
  # Global search (no target)
  python google_dork.py --dork-file global_dorks.txt
  
  # With proxy rotation
  python google_dork.py --target example.com --proxies proxies.txt --delay 5
  
  # List all available dork categories
  python google_dork.py --list-categories
  
  # Interactive dork builder
  python google_dork.py --builder
        """
    )
    
    # Target options
    parser.add_argument('--target', '-t', help='Target domain or keyword')
    parser.add_argument('--dork-file', '-f', help='File containing custom dorks')
    parser.add_argument('--dork-category', choices=[
        'file_types', 'sensitive_info', 'vulnerabilities', 'admin_panels',
        'exposed_devices', 'cloud_storage', 'code_repos', 'all'
    ], default='all', help='Dork category to use')
    
    # Output options
    parser.add_argument('--output', '-o', help='Output file path')
    parser.add_argument('--format', choices=['json', 'csv', 'txt'], default='json',
                       help='Output format (default: json)')
    parser.add_argument('--max-results', type=int, default=100,
                       help='Max results per dork (default: 100)')
    
    # Request options
    parser.add_argument('--delay', type=float, default=2.0,
                       help='Delay between requests (default: 2.0)')
    parser.add_argument('--proxies', help='File containing proxies (one per line)')
    parser.add_argument('--timeout', type=int, default=10,
                       help='Request timeout (default: 10)')
    
    # Utility options
    parser.add_argument('--list-categories', action='store_true',
                       help='List available dork categories')
    parser.add_argument('--builder', action='store_true',
                       help='Interactive dork builder')
    parser.add_argument('--analyze', action='store_true',
                       help='Analyze results (requires --output)')
    
    # Misc options
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    parser.add_argument('--respect-robots', action='store_true',
                       help='Respect robots.txt')
    
    args = parser.parse_args()
    
    # Display banner
    banner()
    
    # List categories
    if args.list_categories:
        print("\nAvailable Dork Categories:")
        print("=" * 40)
        print("file_types      - Document and file type searches")
        print("sensitive_info  - Passwords, API keys, credentials")
        print("vulnerabilities - SQLi, XSS, LFI, etc.")
        print("admin_panels    - Login pages and admin interfaces")
        print("exposed_devices - Cameras, routers, printers")
        print("cloud_storage   - Google Drive, Dropbox, S3")
        print("code_repos      - GitHub, GitLab, Pastebin")
        print("all             - All categories")
        sys.exit(0)
    
    # Interactive builder
    if args.builder:
        dork = DorkBuilder.build_dork()
        if dork:
            print(f"\nYour dork: {dork}")
            save = input("Save to file? (y/n): ").strip().lower()
            if save == 'y':
                filename = input("Filename: ").strip()
                with open(filename, 'w') as f:
                    f.write(dork)
                print(f"[+] Dork saved to {filename}")
        sys.exit(0)
    
    # Check for requests module
    if not REQUESTS_AVAILABLE:
        print("[!] requests module required. Install with: pip install requests")
        sys.exit(1)
    
    # Load proxies if specified
    proxies = []
    if args.proxies:
        try:
            with open(args.proxies, 'r') as f:
                proxies = [line.strip() for line in f if line.strip()]
            print(f"[+] Loaded {len(proxies)} proxies")
        except Exception as e:
            print(f"[-] Error loading proxies: {e}")
            sys.exit(1)
    
    try:
        # Initialize dorker
        dorker = GoogleDorker(
            target=args.target,
            dork_file=args.dork_file,
            output_file=args.output,
            output_format=args.format,
            max_results=args.max_results,
            delay=args.delay,
            proxies=proxies,
            verbose=args.verbose,
            respect_robots=args.respect_robots,
            timeout=args.timeout
        )
        
        # Run dorks
        dorker.run_dorks()
        
        # Analyze results
        if args.analyze and dorker.results:
            analysis = dorker.analyze_results()
            
            print("\n" + "=" * 60)
            print("Analysis Results")
            print("=" * 60)
            print(f"Total URLs: {analysis['total_urls']}")
            print(f"Unique Domains: {analysis['unique_domains']}")
            print(f"\nTop Domains:")
            for domain, count in analysis['top_domains']:
                print(f"  {domain}: {count}")
            
            if analysis['file_types']:
                print(f"\nFile Types:")
                for ftype, count in sorted(analysis['file_types'].items(), 
                                           key=lambda x: x[1], reverse=True)[:10]:
                    print(f"  .{ftype}: {count}")
            
            if analysis['sensitive_findings']:
                print(f"\nSensitive Findings ({len(analysis['sensitive_findings'])}):")
                for url in analysis['sensitive_findings'][:5]:
                    print(f"  {url}")
                if len(analysis['sensitive_findings']) > 5:
                    print(f"  ... and {len(analysis['sensitive_findings']) - 5} more")
        
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
    import itertools
    main()
