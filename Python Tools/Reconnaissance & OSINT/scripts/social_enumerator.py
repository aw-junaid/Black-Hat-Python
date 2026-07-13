#!/usr/bin/env python3
"""
Username & Social Media Enumeration Tool
For authorized security testing only
"""
import sys
import json
import time
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import quote

class SocialEnumerator:
    def __init__(self, timeout=10):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        self.results = {}
        
        # Social media platforms to check
        self.platforms = {
            'github': {
                'url': 'https://github.com/{}',
                'method': 'GET',
                'status_check': [200],
                'not_found': ['Not Found', 'not found here']
            },
            'twitter': {
                'url': 'https://twitter.com/{}',
                'method': 'GET',
                'status_check': [200],
                'not_found': ['This account doesn\'t exist', 'page doesn\'t exist']
            },
            'instagram': {
                'url': 'https://www.instagram.com/{}/',
                'method': 'GET',
                'status_check': [200],
                'not_found': ['Page Not Found', 'Sorry, this page']
            },
            'facebook': {
                'url': 'https://www.facebook.com/{}',
                'method': 'GET',
                'status_check': [200],
                'not_found': ['Page Not Found', 'not found']
            },
            'linkedin': {
                'url': 'https://www.linkedin.com/in/{}',
                'method': 'GET',
                'status_check': [200],
                'not_found': ['Page not found', 'could not be found']
            },
            'youtube': {
                'url': 'https://www.youtube.com/@{}',
                'method': 'GET',
                'status_check': [200],
                'not_found': ['This channel doesn\'t', '404 Not Found']
            },
            'reddit': {
                'url': 'https://www.reddit.com/user/{}',
                'method': 'GET',
                'status_check': [200],
                'not_found': ['page not found', 'not found on Reddit']
            },
            'medium': {
                'url': 'https://medium.com/@{}',
                'method': 'GET',
                'status_check': [200],
                'not_found': ['Page not found', '404']
            },
            'devto': {
                'url': 'https://dev.to/{}',
                'method': 'GET',
                'status_check': [200],
                'not_found': ['Not Found', 'not found']
            },
            'pinterest': {
                'url': 'https://www.pinterest.com/{}',
                'method': 'GET',
                'status_check': [200],
                'not_found': ['Page not found', 'not available']
            },
            'tumblr': {
                'url': 'https://{}.tumblr.com',
                'method': 'GET',
                'status_check': [200],
                'not_found': ['Not found', 'not registered']
            },
            'tiktok': {
                'url': 'https://www.tiktok.com/@{}',
                'method': 'GET',
                'status_check': [200],
                'not_found': ['Couldn\'t find this account', 'not found']
            },
            'telegram': {
                'url': 'https://t.me/{}',
                'method': 'GET',
                'status_check': [200],
                'not_found': ['not found', 'doesn\'t exist']
            },
            'twitch': {
                'url': 'https://www.twitch.tv/{}',
                'method': 'GET',
                'status_check': [200],
                'not_found': ['Sorry. Unless you\'re', 'not found']
            },
            'spotify': {
                'url': 'https://open.spotify.com/user/{}',
                'method': 'GET',
                'status_check': [200],
                'not_found': ['Page not found', 'not found']
            },
            'stackoverflow': {
                'url': 'https://stackoverflow.com/users/{}',
                'method': 'GET',
                'status_check': [200],
                'not_found': ['Page not found', 'User not found']
            },
            'hackernews': {
                'url': 'https://news.ycombinator.com/user?id={}',
                'method': 'GET',
                'status_check': [200],
                'not_found': ['No such user', 'not found']
            },
            'gitlab': {
                'url': 'https://gitlab.com/{}',
                'method': 'GET',
                'status_check': [200],
                'not_found': ['Not Found', 'not found']
            },
            'bitbucket': {
                'url': 'https://bitbucket.org/{}/',
                'method': 'GET',
                'status_check': [200],
                'not_found': ['Not Found', 'not found']
            },
            'keybase': {
                'url': 'https://keybase.io/{}',
                'method': 'GET',
                'status_check': [200],
                'not_found': ['Not Found', 'not found']
            }
        }
    
    def check_username(self, username, platform_name, platform_info):
        """Check if username exists on a platform"""
        try:
            url = platform_info['url'].format(quote(username))
            
            response = self.session.get(
                url,
                timeout=self.timeout,
                allow_redirects=True
            )
            
            # Check if profile exists
            if response.status_code in platform_info['status_check']:
                # Check for not found indicators
                page_text = response.text.lower()
                
                if any(indicator.lower() in page_text for indicator in platform_info['not_found']):
                    return None  # Profile doesn't exist
                
                # Profile exists
                return {
                    'platform': platform_name,
                    'url': url,
                    'status': response.status_code,
                    'exists': True
                }
            
            return None
            
        except Exception as e:
            return None
    
    def enumerate_username(self, username):
        """Check username across all platforms"""
        print(f"[*] Enumerating username: {username}")
        
        results = {}
        
        def check_platform(platform_name, platform_info):
            result = self.check_username(username, platform_name, platform_info)
            if result:
                return platform_name, result
            return None
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {
                executor.submit(check_platform, name, info): name
                for name, info in self.platforms.items()
            }
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    platform_name, data = result
                    results[platform_name] = data
                    print(f"    [+] {platform_name}: {data['url']}")
        
        self.results[username] = results
        return results
    
    def enumerate_email(self, email):
        """Enumerate email across platforms"""
        print(f"[*] Enumerating email: {email}")
        
        # Extract username from email if possible
        username = email.split('@')[0] if '@' in email else email
        
        # Check email-based platforms
        email_platforms = {
            'gravatar': f'https://www.gravatar.com/{self._hash_email(email)}',
            'haveibeenpwned': f'https://haveibeenpwned.com/api/v3/breachedaccount/{email}',
            'spycloud': f'https://api.spycloud.io/public/v2/breach/data/email/{email}'
        }
        
        results = {}
        
        for platform, url in email_platforms.items():
            try:
                response = self.session.get(url, timeout=self.timeout)
                
                if response.status_code == 200:
                    results[platform] = {
                        'platform': platform,
                        'url': url,
                        'exists': True
                    }
                    print(f"    [+] {platform}: Profile found")
            
            except Exception as e:
                continue
        
        # Also check username-based platforms
        username_results = self.enumerate_username(username)
        results.update(username_results)
        
        self.results[email] = results
        return results
    
    def enumerate_fullname(self, first_name, last_name):
        """Enumerate full name across platforms"""
        full_name = f"{first_name} {last_name}"
        print(f"[*] Enumerating name: {full_name}")
        
        # Create username variations
        variations = self.generate_username_variations(first_name, last_name)
        
        results = {'variations': variations, 'platforms': {}}
        
        # Check each variation
        for variation in variations[:5]:  # Limit to 5 variations
            print(f"\n[*] Testing variation: {variation}")
            platform_results = self.enumerate_username(variation)
            results['platforms'][variation] = platform_results
        
        self.results[full_name] = results
        return results
    
    def generate_username_variations(self, first_name, last_name):
        """Generate common username variations"""
        first = first_name.lower()
        last = last_name.lower()
        first_initial = first[0] if first else ''
        last_initial = last[0] if last else ''
        
        variations = [
            first,
            last,
            f"{first}{last}",
            f"{first}.{last}",
            f"{first}_{last}",
            f"{first}-{last}",
            f"{first}{last_initial}",
            f"{first_initial}{last}",
            f"{first_initial}.{last}",
            f"{first}{last_initial}",
            f"{first_initial}{last_initial}",
            f"{last}{first}",
            f"{last}.{first}",
            f"{last}_{first}",
            f"{first[0:3]}{last}",
            f"{first}{last[0:3]}",
            f"{first}_{last}",
            f"its{first}",
            f"mr{first}",
            f"{first}dev",
            f"{first}codes",
            f"real{first}{last}",
            f"official{first}{last}",
        ]
        
        return list(dict.fromkeys(variations))  # Remove duplicates while preserving order
    
    def _hash_email(self, email):
        """Hash email for Gravatar"""
        import hashlib
        return hashlib.md5(email.lower().encode()).hexdigest()
    
    def search_pastes(self, query):
        """Search paste sites for mentions"""
        print(f"[*] Searching pastes for: {query}")
        
        paste_results = []
        
        # Search in known paste sites
        paste_queries = [
            f'site:pastebin.com "{query}"',
            f'site:pastie.org "{query}"',
            f'site:ghostbin.com "{query}"',
            f'site:hastebin.com "{query}"'
        ]
        
        for search_query in paste_queries:
            try:
                url = f"https://www.google.com/search?q={quote(search_query)}"
                response = self.session.get(url, timeout=self.timeout)
                
                if response.status_code == 200:
                    # Extract URLs (simplified)
                    import re
                    urls = re.findall(r'https?://[^\s"]+', response.text)
                    
                    for found_url in urls:
                        if any(site in found_url for site in ['pastebin', 'pastie', 'ghostbin']):
                            paste_results.append(found_url)
            
            except Exception as e:
                continue
        
        return paste_results
    
    def generate_report(self):
        """Generate enumeration report"""
        report = {
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'total_queries': len(self.results),
            'results': {}
        }
        
        for query, data in self.results.items():
            platforms_found = len(data) if isinstance(data, dict) else 0
            report['results'][query] = {
                'platforms_found': platforms_found,
                'details': data
            }
        
        # Save report
        with open('social_enum_report.json', 'w') as f:
            json.dump(report, f, indent=2)
        
        # Print summary
        print(f"\n{'='*50}")
        print(f"[*] Enumeration Complete")
        print(f"[+] Queries: {len(self.results)}")
        
        for query, data in self.results.items():
            if isinstance(data, dict):
                platforms = [k for k, v in data.items() if isinstance(v, dict) and v.get('exists')]
                if platforms:
                    print(f"\n[+] {query}: Found on {len(platforms)} platforms")
                    for platform in platforms:
                        print(f"    - {platform}")
        
        print(f"\n[+] Report saved to social_enum_report.json")
        
        return report

def main():
    if len(sys.argv) < 2:
        print("Usage: python social_enumerator.py <username|email|full_name>")
        print("Examples:")
        print("  python social_enumerator.py johndoe")
        print("  python social_enumerator.py john@example.com")
        print("  python social_enumerator.py \"John Doe\"")
        sys.exit(1)
    
    target = sys.argv[1]
    
    print("[!] WARNING: Only use for authorized security testing!")
    
    enumerator = SocialEnumerator()
    
    # Determine type of target
    if '@' in target:
        enumerator.enumerate_email(target)
    elif ' ' in target:
        parts = target.split()
        first_name = parts[0]
        last_name = parts[-1] if len(parts) > 1 else ''
        enumerator.enumerate_fullname(first_name, last_name)
    else:
        enumerator.enumerate_username(target)
    
    enumerator.generate_report()

if __name__ == "__main__":
    main()
