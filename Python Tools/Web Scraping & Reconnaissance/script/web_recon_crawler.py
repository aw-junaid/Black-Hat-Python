#!/usr/bin/env python3
"""
Advanced Web Scraper & Crawler for Reconnaissance
For authorized security testing only
"""
import requests
import sys
import re
import time
import json
import hashlib
import threading
from queue import Queue
from urllib.parse import urlparse, urljoin, urldefrag
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    from bs4 import BeautifulSoup
except ImportError:
    print("[-] BeautifulSoup4 required: pip install beautifulsoup4 lxml")
    sys.exit(1)

try:
    from selenium import webdriver
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.common.exceptions import TimeoutException, WebDriverException
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False
    print("[!] Selenium not available - JavaScript rendering disabled")

class WebReconCrawler:
    def __init__(self, start_url, config=None):
        self.start_url = start_url
        self.config = config or {}
        
        # Default configuration
        self.max_depth = self.config.get('max_depth', 3)
        self.max_pages = self.config.get('max_pages', 100)
        self.threads = self.config.get('threads', 5)
        self.timeout = self.config.get('timeout', 10)
        self.delay = self.config.get('delay', 0.5)
        self.use_js_rendering = self.config.get('js_rendering', False)
        self.extract_forms = self.config.get('extract_forms', True)
        self.extract_comments = self.config.get('extract_comments', True)
        self.extract_emails = self.config.get('extract_emails', True)
        self.extract_js_files = self.config.get('extract_js_files', True)
        self.extract_endpoints = self.config.get('extract_endpoints', True)
        self.follow_redirects = self.config.get('follow_redirects', True)
        
        # Parse start URL
        parsed = urlparse(start_url)
        self.base_domain = parsed.netloc
        self.base_scheme = parsed.scheme
        self.base_url = f"{self.base_scheme}://{self.base_domain}"
        
        # State management
        self.visited_urls = set()
        self.url_queue = Queue()
        self.url_lock = threading.Lock()
        self.results = defaultdict(list)
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        # Initialize Selenium if needed
        self.driver = None
        if self.use_js_rendering and SELENIUM_AVAILABLE:
            self.init_selenium()
        
        # Regex patterns
        self.patterns = {
            'email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            'phone': r'[\+]?[(]?[0-9]{3}[)]?[-\s\.]?[0-9]{3}[-\s\.]?[0-9]{4,6}',
            'api_endpoint': r'(?:api|v\d)/[\w/-]+',
            'aws_key': r'AKIA[0-9A-Z]{16}',
            'github_token': r'gh[pousr]_[A-Za-z0-9_]{36,}',
            'jwt_token': r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}',
            'ip_address': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
            's3_bucket': r'[a-zA-Z0-9.-]+\.s3\.amazonaws\.com',
            'comment': r'<!--(.*?)-->',
            'js_var': r'(?:var|let|const)\s+(\w+)\s*=\s*["\']([^"\']+)["\']',
            'hidden_input': r'<input[^>]+type=["\']hidden["\'][^>]*>'
        }

    def init_selenium(self):
        """Initialize Selenium WebDriver"""
        try:
            options = webdriver.ChromeOptions()
            options.add_argument('--headless')
            options.add_argument('--no-sandbox')
            options.add_argument('--disable-dev-shm-usage')
            options.add_argument('--disable-gpu')
            options.add_argument(f'user-agent={self.session.headers["User-Agent"]}')
            
            self.driver = webdriver.Chrome(options=options)
            self.driver.set_page_load_timeout(self.timeout)
            print("[+] Selenium WebDriver initialized")
        except Exception as e:
            print(f"[-] Failed to initialize Selenium: {e}")
            self.use_js_rendering = False

    def normalize_url(self, url):
        """Normalize and validate URL"""
        try:
            # Remove fragment
            url, _ = urldefrag(url)
            
            # Parse URL
            parsed = urlparse(url)
            
            # Make absolute if relative
            if not parsed.netloc:
                url = urljoin(self.base_url, url)
                parsed = urlparse(url)
            
            # Only crawl same domain
            if self.base_domain not in parsed.netloc:
                return None
            
            # Normalize scheme
            if parsed.scheme not in ['http', 'https']:
                return None
            
            # Remove default ports
            netloc = parsed.netloc
            if ':80' in netloc or ':443' in netloc:
                netloc = netloc.split(':')[0]
            
            # Reconstruct URL
            normalized = f"{parsed.scheme}://{netloc}{parsed.path}"
            if parsed.query:
                normalized += f"?{parsed.query}"
            
            # Filter out non-web resources
            skip_extensions = ['.pdf', '.jpg', '.jpeg', '.png', '.gif', '.css', 
                             '.ico', '.svg', '.woff', '.woff2', '.ttf', '.eot']
            if any(normalized.lower().endswith(ext) for ext in skip_extensions):
                return None
            
            return normalized
            
        except Exception as e:
            return None

    def extract_urls(self, html, current_url):
        """Extract all URLs from HTML content"""
        urls = set()
        
        try:
            soup = BeautifulSoup(html, 'lxml')
            
            # Extract from <a> tags
            for tag in soup.find_all('a', href=True):
                url = self.normalize_url(tag['href'])
                if url:
                    urls.add(url)
            
            # Extract from <link> tags
            for tag in soup.find_all('link', href=True):
                url = self.normalize_url(tag['href'])
                if url:
                    urls.add(url)
            
            # Extract from <script> tags
            if self.extract_js_files:
                for tag in soup.find_all('script', src=True):
                    url = self.normalize_url(tag['src'])
                    if url:
                        urls.add(url)
                        self.results['javascript_files'].append(url)
            
            # Extract from <img> tags
            for tag in soup.find_all('img', src=True):
                url = self.normalize_url(tag['src'])
                if url:
                    urls.add(url)
            
            # Extract from <iframe> tags
            for tag in soup.find_all('iframe', src=True):
                url = self.normalize_url(tag['src'])
                if url:
                    urls.add(url)
            
            # Extract from inline JavaScript
            if self.extract_endpoints:
                for script in soup.find_all('script'):
                    if script.string:
                        endpoints = self.extract_api_endpoints(script.string)
                        for endpoint in endpoints:
                            full_url = urljoin(self.base_url, endpoint)
                            self.results['api_endpoints'].append(full_url)
            
        except Exception as e:
            print(f"[-] Error extracting URLs: {e}")
        
        return urls

    def extract_api_endpoints(self, js_code):
        """Extract API endpoints from JavaScript code"""
        endpoints = []
        
        patterns = [
            r'["\'](/api/[\w/-]+)["\']',
            r'["\'](/v\d/[\w/-]+)["\']',
            r'fetch\(["\']([\w/-]+)["\']',
            r'axios\.(?:get|post|put|delete)\(["\']([\w/-]+)["\']',
            r'\.ajax\({[^}]*url:\s*["\']([\w/-]+)["\']',
            r'baseURL:\s*["\']([\w/-]+)["\']',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, js_code, re.IGNORECASE)
            endpoints.extend(matches)
        
        return list(set(endpoints))

    def extract_metadata(self, html, url):
        """Extract metadata from HTML"""
        try:
            soup = BeautifulSoup(html, 'lxml')
            
            # Title
            title = soup.title.string if soup.title else None
            if title:
                self.results['pages'].append({
                    'url': url,
                    'title': title.strip(),
                    'status': 'success'
                })
            
            # Meta tags
            meta_tags = {}
            for meta in soup.find_all('meta'):
                name = meta.get('name', meta.get('property', ''))
                content = meta.get('content', '')
                if name and content:
                    meta_tags[name] = content
                    self.results['meta_tags'].append({
                        'url': url,
                        'name': name,
                        'content': content
                    })
            
            # Forms
            if self.extract_forms:
                forms = self.extract_form_details(soup, url)
                if forms:
                    self.results['forms'].extend(forms)
            
            # Comments
            if self.extract_comments:
                comments = re.findall(self.patterns['comment'], html, re.DOTALL)
                if comments:
                    for comment in comments:
                        self.results['comments'].append({
                            'url': url,
                            'comment': comment.strip()[:500]
                        })
            
            # Emails
            if self.extract_emails:
                emails = re.findall(self.patterns['email'], html)
                if emails:
                    for email in set(emails):
                        self.results['emails'].append({
                            'url': url,
                            'email': email
                        })
            
            # Hidden inputs
            hidden_inputs = re.findall(self.patterns['hidden_input'], html)
            if hidden_inputs:
                for inp in hidden_inputs:
                    name_match = re.search(r'name=["\']([^"\']+)["\']', inp)
                    value_match = re.search(r'value=["\']([^"\']*)["\']', inp)
                    if name_match:
                        self.results['hidden_inputs'].append({
                            'url': url,
                            'name': name_match.group(1),
                            'value': value_match.group(1) if value_match else ''
                        })
            
            # Secrets and keys
            secrets = self.extract_secrets(html)
            if secrets:
                self.results['secrets'].extend(secrets)
            
            # Technologies
            tech = self.detect_technologies(soup, html)
            if tech:
                self.results['technologies'].extend(tech)
            
        except Exception as e:
            print(f"[-] Error extracting metadata: {e}")

    def extract_form_details(self, soup, url):
        """Extract form details"""
        forms = []
        
        for form in soup.find_all('form'):
            form_data = {
                'url': url,
                'action': form.get('action', ''),
                'method': form.get('method', 'GET').upper(),
                'id': form.get('id', ''),
                'inputs': []
            }
            
            # Extract all inputs
            for inp in form.find_all(['input', 'select', 'textarea']):
                input_data = {
                    'type': inp.get('type', 'text'),
                    'name': inp.get('name', ''),
                    'id': inp.get('id', ''),
                    'placeholder': inp.get('placeholder', ''),
                    'value': inp.get('value', '')
                }
                form_data['inputs'].append(input_data)
            
            forms.append(form_data)
        
        return forms

    def extract_secrets(self, html):
        """Extract potential secrets and API keys"""
        secrets = []
        
        secret_patterns = [
            (r'(?:api[_-]?key|apikey)["\s:=]+["\']([A-Za-z0-9_\-]{20,})["\']', 'API Key'),
            (r'(?:secret|password|passwd)["\s:=]+["\']([^"\']{8,})["\']', 'Password'),
            (r'(?:token|auth)["\s:=]+["\']([A-Za-z0-9_\-\.]{20,})["\']', 'Token'),
            (r'AKIA[0-9A-Z]{16}', 'AWS Access Key'),
            (r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----', 'Private Key'),
        ]
        
        for pattern, secret_type in secret_patterns:
            matches = re.findall(pattern, html, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    match = match[0]
                secrets.append({
                    'type': secret_type,
                    'value': match[:50] + '...' if len(match) > 50 else match
                })
        
        return secrets

    def detect_technologies(self, soup, html):
        """Detect technologies used by the website"""
        technologies = []
        
        # Server headers
        # (handled separately)
        
        # JavaScript libraries
        js_libs = {
            'jquery': r'jquery[.-](\d+\.\d+\.\d+)',
            'react': r'react[.-](\d+\.\d+\.\d+)',
            'angular': r'angular[.-](\d+\.\d+\.\d+)',
            'vue': r'vue[.-](\d+\.\d+\.\d+)',
            'bootstrap': r'bootstrap[.-](\d+\.\d+\.\d+)',
        }
        
        for script in soup.find_all('script', src=True):
            src = script.get('src', '')
            for lib, pattern in js_libs.items():
                match = re.search(pattern, src, re.IGNORECASE)
                if match:
                    technologies.append({
                        'type': 'JavaScript Library',
                        'name': lib,
                        'version': match.group(1)
                    })
        
        # Meta generators
        for meta in soup.find_all('meta'):
            if meta.get('name', '').lower() == 'generator':
                technologies.append({
                    'type': 'CMS/Generator',
                    'name': meta.get('content', 'Unknown')
                })
        
        return technologies

    def fetch_page(self, url):
        """Fetch page content with fallback to JavaScript rendering"""
        try:
            # Try regular request first
            response = self.session.get(url, timeout=self.timeout, allow_redirects=self.follow_redirects)
            
            if response.status_code == 200:
                html = response.text
                
                # Check if JavaScript rendering is needed
                if self.use_js_rendering and self.driver and self.needs_js_rendering(html):
                    print(f"[*] Using JavaScript rendering for: {url}")
                    html = self.fetch_with_selenium(url)
                
                # Extract server headers
                server = response.headers.get('Server', '')
                if server:
                    self.results['server_headers'].append({
                        'url': url,
                        'header': 'Server',
                        'value': server
                    })
                
                # Extract cookies
                cookies = response.headers.get('Set-Cookie', '')
                if cookies:
                    self.results['cookies'].append({
                        'url': url,
                        'cookie': cookies
                    })
                
                return html
            
        except requests.exceptions.Timeout:
            print(f"[-] Timeout fetching: {url}")
        except requests.exceptions.ConnectionError:
            print(f"[-] Connection error: {url}")
        except Exception as e:
            print(f"[-] Error fetching {url}: {e}")
        
        return None

    def fetch_with_selenium(self, url):
        """Fetch page using Selenium for JavaScript rendering"""
        try:
            self.driver.get(url)
            WebDriverWait(self.driver, 5).until(
                EC.presence_of_element_located((By.TAG_NAME, "body"))
            )
            time.sleep(2)  # Wait for JS to execute
            return self.driver.page_source
        except TimeoutException:
            print(f"[-] Selenium timeout: {url}")
        except WebDriverException as e:
            print(f"[-] Selenium error: {e}")
        
        return None

    def needs_js_rendering(self, html):
        """Check if page likely needs JavaScript rendering"""
        js_indicators = [
            '<noscript>',
            'react-root',
            'ng-app',
            'vue-app',
            'app-root',
            'loading...',
            'spinner',
            'skeleton'
        ]
        
        html_lower = html.lower()
        return any(indicator in html_lower for indicator in js_indicators)

    def crawl_page(self, url, depth=0):
        """Crawl a single page"""
        if depth > self.max_depth or len(self.visited_urls) >= self.max_pages:
            return
        
        with self.url_lock:
            if url in self.visited_urls:
                return
            self.visited_urls.add(url)
        
        print(f"[*] Crawling [{depth}]: {url}")
        
        # Fetch page
        html = self.fetch_page(url)
        if not html:
            return
        
        # Extract metadata
        self.extract_metadata(html, url)
        
        # Extract URLs
        urls = self.extract_urls(html, url)
        
        # Add new URLs to queue
        for new_url in urls:
            with self.url_lock:
                if new_url not in self.visited_urls:
                    self.url_queue.put((new_url, depth + 1))
        
        time.sleep(self.delay)  # Be polite

    def worker(self):
        """Worker thread for crawling"""
        while True:
            try:
                url, depth = self.url_queue.get(timeout=5)
                self.crawl_page(url, depth)
                self.url_queue.task_done()
            except:
                break

    def start_crawl(self):
        """Start the crawling process"""
        print(f"[*] Starting crawl of {self.start_url}")
        print(f"[*] Max depth: {self.max_depth}, Max pages: {self.max_pages}")
        print(f"[*] Threads: {self.threads}")
        
        # Add start URL to queue
        self.url_queue.put((self.start_url, 0))
        
        # Start worker threads
        threads = []
        for _ in range(self.threads):
            t = threading.Thread(target=self.worker)
            t.daemon = True
            t.start()
            threads.append(t)
        
        # Wait for all threads to complete
        self.url_queue.join()
        
        # Clean up
        if self.driver:
            self.driver.quit()
        
        print(f"\n[*] Crawl complete!")
        print(f"[*] Visited: {len(self.visited_urls)} pages")
        
        return self.generate_report()

    def generate_report(self):
        """Generate reconnaissance report"""
        print("\n[*] Generating reconnaissance report...")
        
        report = {
            'target': self.start_url,
            'base_domain': self.base_domain,
            'pages_crawled': len(self.visited_urls),
            'findings': {}
        }
        
        # Organize findings
        if self.results['pages']:
            report['findings']['pages'] = {
                'count': len(self.results['pages']),
                'data': self.results['pages'][:20]  # Top 20
            }
        
        if self.results['api_endpoints']:
            unique_endpoints = list(set(self.results['api_endpoints']))
            report['findings']['api_endpoints'] = {
                'count': len(unique_endpoints),
                'data': unique_endpoints[:50]
            }
        
        if self.results['emails']:
            report['findings']['emails'] = {
                'count': len(self.results['emails']),
                'data': self.results['emails']
            }
        
        if self.results['forms']:
            report['findings']['forms'] = {
                'count': len(self.results['forms']),
                'data': self.results['forms']
            }
        
        if self.results['comments']:
            report['findings']['comments'] = {
                'count': len(self.results['comments']),
                'data': self.results['comments'][:20]
            }
        
        if self.results['secrets']:
            report['findings']['secrets'] = {
                'count': len(self.results['secrets']),
                'data': self.results['secrets']
            }
        
        if self.results['technologies']:
            report['findings']['technologies'] = {
                'count': len(self.results['technologies']),
                'data': self.results['technologies']
            }
        
        if self.results['javascript_files']:
            report['findings']['javascript_files'] = {
                'count': len(set(self.results['javascript_files'])),
                'data': list(set(self.results['javascript_files']))[:20]
            }
        
        # Save detailed report
        with open('recon_report.json', 'w') as f:
            json.dump({
                'summary': report,
                'full_data': dict(self.results)
            }, f, indent=2)
        
        # Print summary
        self.print_summary(report)
        
        return report

    def print_summary(self, report):
        """Print reconnaissance summary"""
        print("\n" + "="*60)
        print("RECONNAISSANCE REPORT SUMMARY")
        print("="*60)
        print(f"Target: {report['target']}")
        print(f"Domain: {report['base_domain']}")
        print(f"Pages Crawled: {report['pages_crawled']}")
        print("\nFindings:")
        
        for finding_type, data in report['findings'].items():
            print(f"  - {finding_type.replace('_', ' ').title()}: {data['count']}")
        
        print("\n[!] Detailed report saved to recon_report.json")

def main():
    if len(sys.argv) < 2:
        print("Usage: python web_recon_crawler.py <URL> [options]")
        print("\nOptions:")
        print("  --depth <n>        Maximum crawl depth (default: 3)")
        print("  --pages <n>        Maximum pages to crawl (default: 100)")
        print("  --threads <n>      Number of threads (default: 5)")
        print("  --js-rendering     Enable JavaScript rendering")
        print("  --delay <n>        Delay between requests in seconds (default: 0.5)")
        print("\nExample:")
        print("  python web_recon_crawler.py https://example.com")
        print("  python web_recon_crawler.py https://example.com --depth 2 --js-rendering")
        sys.exit(1)
    
    url = sys.argv[1]
    
    # Parse options
    config = {
        'max_depth': 3,
        'max_pages': 100,
        'threads': 5,
        'delay': 0.5,
        'js_rendering': False
    }
    
    args = sys.argv[2:]
    for i, arg in enumerate(args):
        if arg == '--depth' and i + 1 < len(args):
            config['max_depth'] = int(args[i + 1])
        elif arg == '--pages' and i + 1 < len(args):
            config['max_pages'] = int(args[i + 1])
        elif arg == '--threads' and i + 1 < len(args):
            config['threads'] = int(args[i + 1])
        elif arg == '--delay' and i + 1 < len(args):
            config['delay'] = float(args[i + 1])
        elif arg == '--js-rendering':
            config['js_rendering'] = True
    
    print("[!] WARNING: Only use on systems you own or have explicit permission to test!")
    
    crawler = WebReconCrawler(url, config)
    crawler.start_crawl()

if __name__ == "__main__":
    main()
