#!/usr/bin/env python3
"""
Shodan API Integration for Advanced Reconnaissance
For authorized security testing only
"""
import sys
import json
import time
import requests
from datetime import datetime
from collections import defaultdict

class ShodanRecon:
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = "https://api.shodan.io"
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Shodan-Recon/1.0'
        })
        self.results = defaultdict(list)
        
    def search(self, query, page=1, facets=None):
        """Search Shodan with query"""
        try:
            params = {
                'key': self.api_key,
                'query': query,
                'page': page
            }
            
            if facets:
                params['facets'] = ','.join(facets)
            
            response = self.session.get(
                f"{self.base_url}/shodan/host/search",
                params=params,
                timeout=30
            )
            
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 429:
                print("[-] Rate limit reached. Waiting 60 seconds...")
                time.sleep(60)
                return self.search(query, page, facets)
            else:
                print(f"[-] Error: {response.status_code} - {response.text}")
                return None
                
        except Exception as e:
            print(f"[-] Search error: {e}")
            return None
    
    def host_info(self, ip):
        """Get detailed information about a host"""
        try:
            response = self.session.get(
                f"{self.base_url}/shodan/host/{ip}",
                params={'key': self.api_key},
                timeout=30
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                print(f"[-] Error getting host info: {response.status_code}")
                return None
                
        except Exception as e:
            print(f"[-] Host info error: {e}")
            return None
    
    def search_exploits(self, query, page=1):
        """Search for exploits"""
        try:
            response = self.session.get(
                f"{self.base_url}/api/search",
                params={
                    'key': self.api_key,
                    'query': query,
                    'page': page
                },
                timeout=30
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                print(f"[-] Exploit search error: {response.status_code}")
                return None
                
        except Exception as e:
            print(f"[-] Exploit search error: {e}")
            return None
    
    def dns_resolve(self, hostnames):
        """Resolve hostnames to IPs"""
        try:
            response = self.session.get(
                f"{self.base_url}/dns/resolve",
                params={
                    'key': self.api_key,
                    'hostnames': ','.join(hostnames)
                },
                timeout=30
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                print(f"[-] DNS resolve error: {response.status_code}")
                return None
                
        except Exception as e:
            print(f"[-] DNS error: {e}")
            return None
    
    def reverse_dns(self, ips):
        """Reverse DNS lookup"""
        try:
            response = self.session.get(
                f"{self.base_url}/dns/reverse",
                params={
                    'key': self.api_key,
                    'ips': ','.join(ips)
                },
                timeout=30
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                print(f"[-] Reverse DNS error: {response.status_code}")
                return None
                
        except Exception as e:
            print(f"[-] Reverse DNS error: {e}")
            return None
    
    def get_api_info(self):
        """Get API plan information"""
        try:
            response = self.session.get(
                f"{self.base_url}/api-info",
                params={'key': self.api_key},
                timeout=30
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                print(f"[-] API info error: {response.status_code}")
                return None
                
        except Exception as e:
            print(f"[-] API info error: {e}")
            return None
    
    def search_organization(self, org_name):
        """Search by organization"""
        print(f"[*] Searching organization: {org_name}")
        
        results = self.search(f'org:"{org_name}"', facets=['port', 'country', 'org'])
        
        if results:
            print(f"[+] Found {results.get('total', 0)} results")
            
            for match in results.get('matches', [])[:10]:
                ip = match.get('ip_str')
                port = match.get('port')
                org = match.get('org', 'Unknown')
                hostnames = match.get('hostnames', [])
                
                print(f"    {ip}:{port} - {org} - {', '.join(hostnames[:3])}")
                
                self.results['organization_hosts'].append({
                    'ip': ip,
                    'port': port,
                    'org': org,
                    'hostnames': hostnames,
                    'data': match.get('data', '')[:200]
                })
        
        return results
    
    def search_technology(self, tech_name, limit=20):
        """Search for specific technology"""
        print(f"[*] Searching technology: {tech_name}")
        
        queries = [
            f'product:"{tech_name}"',
            f'server:"{tech_name}"',
            f'"{tech_name}"'
        ]
        
        for query in queries:
            results = self.search(query)
            
            if results and results.get('matches'):
                print(f"[+] Query '{query}' found {results['total']} results")
                
                for match in results.get('matches', [])[:limit]:
                    ip = match.get('ip_str')
                    port = match.get('port')
                    product = match.get('product', 'Unknown')
                    version = match.get('version', '')
                    
                    print(f"    {ip}:{port} - {product} {version}")
                    
                    self.results['technology_hosts'].append({
                        'ip': ip,
                        'port': port,
                        'product': product,
                        'version': version,
                        'timestamp': match.get('timestamp')
                    })
        
        return self.results['technology_hosts']
    
    def search_vulnerabilities(self, service, version=None):
        """Search for vulnerabilities in specific service"""
        print(f"[*] Searching vulnerabilities for: {service} {version or ''}")
        
        query = f"{service}"
        if version:
            query += f" {version}"
        
        results = self.search_exploits(query)
        
        if results and results.get('matches'):
            print(f"[+] Found {results['total']} potential exploits")
            
            for match in results.get('matches', [])[:10]:
                cve = match.get('cve', ['Unknown'])[0]
                description = match.get('description', 'No description')[:100]
                
                print(f"    {cve}: {description}")
                
                self.results['vulnerabilities'].append({
                    'cve': cve,
                    'description': description,
                    'service': service,
                    'version': version
                })
        
        return results
    
    def enumerate_network(self, cidr):
        """Enumerate network range"""
        print(f"[*] Enumerating network: {cidr}")
        
        results = self.search(f'net:"{cidr}"')
        
        if results and results.get('matches'):
            print(f"[+] Found {results['total']} hosts in network")
            
            # Group by port
            port_map = defaultdict(list)
            for match in results.get('matches', []):
                port_map[match.get('port')].append(match)
            
            print("\n[*] Service Distribution:")
            for port, hosts in sorted(port_map.items())[:20]:
                print(f"    Port {port}: {len(hosts)} hosts")
            
            self.results['network_enumeration'] = {
                'cidr': cidr,
                'total_hosts': results['total'],
                'port_distribution': {str(k): len(v) for k, v in port_map.items()},
                'hosts': results.get('matches', [])[:50]
            }
        
        return results
    
    def search_iot_devices(self, device_type):
        """Search for IoT devices"""
        print(f"[*] Searching IoT devices: {device_type}")
        
        queries = [
            f'"{device_type}"',
            f'product:"{device_type}"',
            f'"{device_type}" default password'
        ]
        
        for query in queries:
            results = self.search(query)
            
            if results and results.get('matches'):
                print(f"[+] Found {results['total']} devices with query: {query}")
                
                countries = defaultdict(int)
                for match in results.get('matches', []):
                    country = match.get('location', {}).get('country_name', 'Unknown')
                    countries[country] += 1
                
                print("    Top Countries:")
                for country, count in sorted(countries.items(), key=lambda x: x[1], reverse=True)[:5]:
                    print(f"        {country}: {count}")
                
                self.results['iot_devices'].append({
                    'query': query,
                    'total': results['total'],
                    'countries': dict(countries),
                    'devices': results.get('matches', [])[:20]
                })
        
        return self.results['iot_devices']
    
    def search_exposed_databases(self):
        """Search for exposed databases"""
        print("[*] Searching for exposed databases...")
        
        db_queries = [
            ('MongoDB', 'product:"MongoDB" port:27017'),
            ('Redis', 'product:"Redis"'),
            ('Elasticsearch', 'product:"Elasticsearch" port:9200'),
            ('MySQL', 'product:"MySQL"'),
            ('PostgreSQL', 'product:"PostgreSQL" port:5432'),
            ('Cassandra', 'product:"Cassandra"'),
            ('CouchDB', 'product:"CouchDB"')
        ]
        
        for db_name, query in db_queries:
            results = self.search(query)
            
            if results and results.get('matches'):
                print(f"[+] {db_name}: {results['total']} exposed instances")
                
                # Check for authentication
                auth_bypass = 0
                for match in results.get('matches', []):
                    data = match.get('data', '').lower()
                    if 'authentication' not in data and 'auth' not in data:
                        auth_bypass += 1
                
                print(f"    Potentially unauthenticated: {auth_bypass}")
                
                self.results['exposed_databases'].append({
                    'database': db_name,
                    'total': results['total'],
                    'potentially_unauth': auth_bypass,
                    'instances': results.get('matches', [])[:10]
                })
        
        return self.results['exposed_databases']
    
    def generate_report(self):
        """Generate comprehensive report"""
        report = {
            'scan_time': datetime.now().isoformat(),
            'api_info': self.get_api_info(),
            'results': dict(self.results)
        }
        
        with open('shodan_recon_report.json', 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n[+] Report saved to shodan_recon_report.json")
        print(f"[*] Total findings: {sum(len(v) for v in self.results.values())}")
        
        return report

def main():
    if len(sys.argv) < 2:
        print("Usage: python shodan_recon.py <API_KEY> [options]")
        print("\nOptions:")
        print("  --org <name>           Search by organization")
        print("  --tech <name>          Search by technology")
        print("  --network <CIDR>       Enumerate network range")
        print("  --iot <device>         Search for IoT devices")
        print("  --databases            Search for exposed databases")
        print("  --ip <IP>              Get host information")
        print("  --vuln <service>       Search vulnerabilities")
        print("\nExamples:")
        print("  python shodan_recon.py YOUR_API_KEY --org 'Example Corp'")
        print("  python shodan_recon.py YOUR_API_KEY --tech nginx --databases")
        print("  python shodan_recon.py YOUR_API_KEY --network 192.168.0.0/24")
        sys.exit(1)
    
    api_key = sys.argv[1]
    shodan = ShodanRecon(api_key)
    
    # Check API info
    api_info = shodan.get_api_info()
    if api_info:
        print(f"[+] API Plan: {api_info.get('plan', 'Unknown')}")
        print(f"[+] Query Credits: {api_info.get('query_credits', 'Unknown')}")
    
    # Parse commands
    args = sys.argv[2:]
    i = 0
    while i < len(args):
        if args[i] == '--org' and i + 1 < len(args):
            shodan.search_organization(args[i + 1])
            i += 2
        elif args[i] == '--tech' and i + 1 < len(args):
            shodan.search_technology(args[i + 1])
            i += 2
        elif args[i] == '--network' and i + 1 < len(args):
            shodan.enumerate_network(args[i + 1])
            i += 2
        elif args[i] == '--iot' and i + 1 < len(args):
            shodan.search_iot_devices(args[i + 1])
            i += 2
        elif args[i] == '--ip' and i + 1 < len(args):
            shodan.host_info(args[i + 1])
            i += 2
        elif args[i] == '--vuln' and i + 1 < len(args):
            shodan.search_vulnerabilities(args[i + 1])
            i += 2
        elif args[i] == '--databases':
            shodan.search_exposed_databases()
            i += 1
        else:
            i += 1
    
    # Generate report
    shodan.generate_report()

if __name__ == "__main__":
    print("[!] WARNING: Only use for authorized security testing!")
    main()
