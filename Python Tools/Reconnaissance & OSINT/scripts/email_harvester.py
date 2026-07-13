#!/usr/bin/env python3
"""
Email Harvester - Multi-source email and subdomain enumeration
For authorized security testing only
"""
import sys
import re
import json
import time
import requests
from urllib.parse import quote_plus
from concurrent.futures import ThreadPoolExecutor, as_completed

class EmailHarvester:
    def __init__(self, domain, limit=100):
        self.domain = domain
        self.limit = limit
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        self.emails = set()
        self.subdomains = set()
        self.hosts = set()
        self.ips = set()
        
        # Search engines
        self.search_engines = {
            'google': 'https://www.google.com/search?q=',
            'bing': 'https://www.bing.com/search?q=',
            'yahoo': 'https://search.yahoo.com/search?p=',
            'duckduckgo': 'https://html.duckduckgo.com/html/?q='
        }
        
        # API endpoints for various services
        self.apis = {
            'crtsh': 'https://crt.sh/?q=%25.{}&output=json',
            'certspotter': 'https://api.certspotter.com/v1/issuances?domain={}&expand=dns_names',
            'hackertarget': 'https://api.hackertarget.com/hostsearch/?q={}',
            'threatminer': 'https://api.threatminer.org/v2/domain.php?q={}&rt=5',
            'alienvault': 'https://otx.alienvault.com/api/v1/indicators/domain/{}/passive_dns',
            'urlscan': 'https://urlscan.io/api/v1/search/?q=domain:{}'
        }
        
    def search_google(self):
        """Search Google for emails"""
        print("[*] Searching Google...")
        
        queries = [
            f'@{self.domain}',
            f'"{self.domain}" email',
            f'site:{self.domain} "@{self.domain}"',
            f'intext:"@{self.domain}"'
        ]
        
        for query in queries:
            try:
                url = f"{self.search_engines['google']}{quote_plus(query)}&num=100"
                response = self.session.get(url, timeout=10)
                
                # Extract emails
                email_pattern = rf'[a-zA-Z0-9._%+-]+@{self.domain}'
                found = set(re.findall(email_pattern, response.text, re.IGNORECASE))
                
                self.emails.update(found)
                print(f"    Found {len(found)} emails")
                
                time.sleep(1)
                
            except Exception as e:
                print(f"[-] Google search error: {e}")
    
    def search_bing(self):
        """Search Bing for emails"""
        print("[*] Searching Bing...")
        
        queries = [
            f'@{self.domain}',
            f'"{self.domain}" email'
        ]
        
        for query in queries:
            try:
                url = f"{self.search_engines['bing']}{quote_plus(query)}"
                response = self.session.get(url, timeout=10)
                
                email_pattern = rf'[a-zA-Z0-9._%+-]+@{self.domain}'
                found = set(re.findall(email_pattern, response.text, re.IGNORECASE))
                
                self.emails.update(found)
                print(f"    Found {len(found)} emails")
                
                time.sleep(1)
                
            except Exception as e:
                print(f"[-] Bing search error: {e}")
    
    def query_crtsh(self):
        """Query crt.sh for subdomains"""
        print("[*] Querying crt.sh...")
        
        try:
            url = self.apis['crtsh'].format(self.domain)
            response = self.session.get(url, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                
                for entry in data:
                    name_value = entry.get('name_value', '')
                    for host in name_value.split('\n'):
                        host = host.strip().lower()
                        if self.domain in host:
                            self.subdomains.add(host)
                
                print(f"    Found {len(self.subdomains)} subdomains")
            
        except Exception as e:
            print(f"[-] crt.sh error: {e}")
    
    def query_certspotter(self):
        """Query CertSpotter for certificates"""
        print("[*] Querying CertSpotter...")
        
        try:
            url = self.apis['certspotter'].format(self.domain)
            response = self.session.get(url, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                
                for cert in data:
                    dns_names = cert.get('dns_names', [])
                    for name in dns_names:
                        if self.domain in name.lower():
                            self.subdomains.add(name.lower())
                
                print(f"    Found {len(self.subdomains)} subdomains")
            
        except Exception as e:
            print(f"[-] CertSpotter error: {e}")
    
    def query_hackertarget(self):
        """Query HackerTarget for hostnames"""
        print("[*] Querying HackerTarget...")
        
        try:
            url = self.apis['hackertarget'].format(self.domain)
            response = self.session.get(url, timeout=30)
            
            if response.status_code == 200:
                lines = response.text.strip().split('\n')
                
                for line in lines:
                    if ',' in line:
                        host, ip = line.split(',', 1)
                        host = host.strip().lower()
                        if self.domain in host:
                            self.subdomains.add(host)
                            self.ips.add(ip.strip())
                
                print(f"    Found {len(self.subdomains)} subdomains")
            
        except Exception as e:
            print(f"[-] HackerTarget error: {e}")
    
    def query_alienvault(self):
        """Query AlienVault OTX"""
        print("[*] Querying AlienVault OTX...")
        
        try:
            url = self.apis['alienvault'].format(self.domain)
            headers = {'X-OTX-API-KEY': 'YOUR_API_KEY'}  # Optional
            response = self.session.get(url, headers=headers, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                
                for entry in data.get('passive_dns', []):
                    hostname = entry.get('hostname', '').lower()
                    if self.domain in hostname:
                        self.subdomains.add(hostname)
                    
                    address = entry.get('address', '')
                    if address:
                        self.ips.add(address)
                
                print(f"    Found {len(self.subdomains)} subdomains")
            
        except Exception as e:
            print(f"[-] AlienVault error: {e}")
    
    def query_urlscan(self):
        """Query URLScan.io"""
        print("[*] Querying URLScan.io...")
        
        try:
            url = self.apis['urlscan'].format(self.domain)
            response = self.session.get(url, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                
                for result in data.get('results', []):
                    page = result.get('page', {})
                    domain_name = page.get('domain', '').lower()
                    
                    if self.domain in domain_name:
                        self.subdomains.add(domain_name)
                
                print(f"    Found {len(self.subdomains)} subdomains")
            
        except Exception as e:
            print(f"[-] URLScan error: {e}")
    
    def search_social_media(self):
        """Search social media for emails"""
        print("[*] Searching social media...")
        
        platforms = {
            'linkedin': f'site:linkedin.com "{self.domain}"',
            'twitter': f'site:twitter.com "{self.domain}"',
            'github': f'site:github.com "{self.domain}"',
            'reddit': f'site:reddit.com "{self.domain}"'
        }
        
        for platform, query in platforms.items():
            try:
                url = f"{self.search_engines['google']}{quote_plus(query)}"
                response = self.session.get(url, timeout=10)
                
                email_pattern = rf'[a-zA-Z0-9._%+-]+@{self.domain}'
                found = set(re.findall(email_pattern, response.text, re.IGNORECASE))
                
                self.emails.update(found)
                print(f"    {platform}: Found {len(found)} emails")
                
                time.sleep(1)
                
            except Exception as e:
                print(f"[-] {platform} search error: {e}")
    
    def search_paste_sites(self):
        """Search paste sites for emails"""
        print("[*] Searching paste sites...")
        
        paste_sites = [
            'pastebin.com',
            'pastie.org',
            'ghostbin.com'
        ]
        
        for site in paste_sites:
            query = f'site:{site} "{self.domain}"'
            
            try:
                url = f"{self.search_engines['google']}{quote_plus(query)}"
                response = self.session.get(url, timeout=10)
                
                email_pattern = rf'[a-zA-Z0-9._%+-]+@{self.domain}'
                found = set(re.findall(email_pattern, response.text, re.IGNORECASE))
                
                self.emails.update(found)
                print(f"    {site}: Found {len(found)} emails")
                
                time.sleep(1)
                
            except Exception as e:
                print(f"[-] {site} search error: {e}")
    
    def extract_from_websites(self):
        """Extract emails from discovered websites"""
        print("[*] Extracting from websites...")
        
        test_subdomains = list(self.subdomains)[:20]  # First 20 subdomains
        
        def fetch_site(subdomain):
            for protocol in ['https', 'http']:
                try:
                    url = f"{protocol}://{subdomain}"
                    response = self.session.get(url, timeout=5)
                    
                    if response.status_code == 200:
                        email_pattern = rf'[a-zA-Z0-9._%+-]+@{self.domain}'
                        found = set(re.findall(email_pattern, response.text, re.IGNORECASE))
                        return found
                except:
                    continue
            return set()
        
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {executor.submit(fetch_site, sub): sub for sub in test_subdomains}
            
            for future in as_completed(futures):
                try:
                    emails = future.result()
                    self.emails.update(emails)
                except:
                    continue
        
        print(f"    Found {len(self.emails)} total emails")
    
    def generate_report(self):
        """Generate harvest report"""
        report = {
            'domain': self.domain,
            'total_emails': len(self.emails),
            'total_subdomains': len(self.subdomains),
            'total_ips': len(self.ips),
            'emails': sorted(list(self.emails)),
            'subdomains': sorted(list(self.subdomains)),
            'ips': sorted(list(self.ips))
        }
        
        # Save report
        with open(f'{self.domain}_harvest.json', 'w') as f:
            json.dump(report, f, indent=2)
        
        # Save email list
        with open(f'{self.domain}_emails.txt', 'w') as f:
            for email in sorted(self.emails):
                f.write(f"{email}\n")
        
        # Save subdomain list
        with open(f'{self.domain}_subdomains.txt', 'w') as f:
            for subdomain in sorted(self.subdomains):
                f.write(f"{subdomain}\n")
        
        print(f"\n[+] Reports saved:")
        print(f"    - {self.domain}_harvest.json")
        print(f"    - {self.domain}_emails.txt")
        print(f"    - {self.domain}_subdomains.txt")
        
        return report
    
    def harvest(self):
        """Run all harvesting methods"""
        print(f"[*] Starting email harvest for: {self.domain}")
        
        # Run all search methods
        methods = [
            self.search_google,
            self.search_bing,
            self.query_crtsh,
            self.query_certspotter,
            self.query_hackertarget,
            self.query_alienvault,
            self.query_urlscan,
            self.search_social_media,
            self.search_paste_sites,
            self.extract_from_websites
        ]
        
        for method in methods:
            try:
                method()
            except Exception as e:
                print(f"[-] Method error: {e}")
        
        # Print summary
        print(f"\n{'='*50}")
        print(f"[*] Harvest Complete!")
        print(f"[+] Emails found: {len(self.emails)}")
        print(f"[+] Subdomains found: {len(self.subdomains)}")
        print(f"[+] IPs found: {len(self.ips)}")
        
        # Print sample emails
        if self.emails:
            print("\n[*] Sample emails:")
            for email in list(self.emails)[:10]:
                print(f"    - {email}")
        
        return self.generate_report()

def main():
    if len(sys.argv) < 2:
        print("Usage: python email_harvester.py <domain> [limit]")
        print("Example: python email_harvester.py example.com 200")
        sys.exit(1)
    
    domain = sys.argv[1]
    limit = int(sys.argv[2]) if len(sys.argv) > 2 else 100
    
    print("[!] WARNING: Only use for authorized security testing!")
    
    harvester = EmailHarvester(domain, limit)
    harvester.harvest()

if __name__ == "__main__":
    main()
