# Web Reconnaissance & API Fuzzing Tools

Advanced Python tools for web reconnaissance and REST API security testing. Part of the Red Team Web Security Testing Toolkit.

## DISCLAIMER

**FOR AUTHORIZED SECURITY TESTING ONLY**

These tools are designed exclusively for:
- Authorized penetration testing engagements
- Red team operations with written permission
- Bug bounty programs within scope
- Security research on owned systems
- Educational purposes in controlled environments

**Unauthorized use against systems you don't own or have explicit permission to test is ILLEGAL and may result in criminal prosecution.**

## 📋 Tools Overview

| # | Tool | Category | Purpose |
|---|------|----------|---------|
| 01 | `web_recon_crawler.py` | Reconnaissance | Automated web crawling, metadata extraction, and reconnaissance |
| 02 | `rest_api_fuzzer.py` | API Testing | REST API endpoint discovery, fuzzing, and vulnerability detection |

---

## 🚀 Installation

### Prerequisites

- **Python 3.8+** (3.10+ recommended)
- **pip** (latest version)
- **Git** (for cloning)

### Quick Install

```bash
# Clone the toolkit repository
git clone https://github.com/your-repo/redteam-web-toolkit.git
cd redteam-web-toolkit

# Install core dependencies
pip install -r requirements.txt

# Install optional dependencies for advanced features
pip install -r requirements-optional.txt
```

### Manual Installation

#### Step 1: Core Dependencies

```bash
# Required for both tools
pip install requests>=2.28.0
pip install beautifulsoup4>=4.11.0
pip install lxml>=4.9.0
pip install urllib3>=1.26.0
```

#### Step 2: Web Recon Crawler Dependencies

```bash
# Basic crawling (required)
pip install beautifulsoup4 lxml

# JavaScript rendering (optional)
pip install selenium>=4.8.0
pip install webdriver-manager>=3.8.0

# Install Chrome/Chromium browser
# Ubuntu/Debian:
sudo apt-get install chromium-browser chromium-chromedriver

# macOS:
brew install chromium chromedriver

# Windows:
# Download ChromeDriver from https://chromedriver.chromium.org/

# OR use Playwright (alternative to Selenium)
pip install playwright>=1.30.0
playwright install chromium
```

#### Step 3: REST API Fuzzer Dependencies

```bash
# Core fuzzing (required)
pip install requests>=2.28.0

# Additional payload generation (optional)
pip install faker>=15.0.0
pip install pyyaml>=6.0
```

### Complete Requirements Files

#### `requirements.txt` (Core)
```txt
# Core dependencies for both tools
requests>=2.28.0
beautifulsoup4>=4.11.0
lxml>=4.9.0
urllib3>=1.26.5,<2.0
colorama>=0.4.6
```

#### `requirements-optional.txt` (Advanced Features)
```txt
# Browser automation
selenium>=4.8.0
webdriver-manager>=3.8.0
playwright>=1.30.0

# Enhanced fuzzing
faker>=15.0.0
pyyaml>=6.0

# Utilities
tqdm>=4.64.0
rich>=13.0.0
```

### Verify Installation

```bash
# Test imports
python -c "import requests; from bs4 import BeautifulSoup; print('Core OK')"

# Test Selenium (optional)
python -c "from selenium import webdriver; print('Selenium OK')"

# Full verification
python -c "
import requests
import json
import re
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
print('All dependencies installed successfully!')
"
```

---

## 📖 Tool 01: Web Recon Crawler

### Purpose
Comprehensive web reconnaissance crawler that maps website structure, extracts metadata, discovers endpoints, and identifies potential security issues through automated crawling.

### Key Capabilities

#### 🔍 Discovery & Enumeration
- **Multi-threaded crawling** with configurable depth and page limits
- **JavaScript rendering** support via Selenium for SPAs
- **Same-domain restriction** to prevent crawling out of scope
- **Duplicate URL detection** to avoid redundant crawling
- **Smart filtering** of non-web resources (images, fonts, etc.)

#### 📊 Metadata Extraction
- Page titles and meta descriptions
- HTML comments (often contain sensitive info)
- Hidden form inputs and their values
- Email addresses and phone numbers
- API endpoints in JavaScript files
- Technology stack fingerprinting

#### 🔐 Security Reconnaissance
- **API endpoint discovery** from JavaScript files
- **Form analysis** including input fields and methods
- **Secret detection** (API keys, tokens, passwords)
- **Cookie analysis** from response headers
- **Server header enumeration**
- **Technology detection** (jQuery, React, Angular, etc.)

#### 📈 Reporting
- **JSON reports** with categorized findings
- **Severity classification** for security issues
- **Detailed crawl statistics**
- **Exportable data** for further analysis

### Usage

#### Basic Usage

```bash
# Simple crawl with default settings
python web_recon_crawler.py https://example.com

# Crawl with custom depth
python web_recon_crawler.py https://example.com --depth 2

# Limit number of pages
python web_recon_crawler.py https://example.com --pages 50

# Enable JavaScript rendering
python web_recon_crawler.py https://example.com --js-rendering

# Adjust delay between requests (be polite)
python web_recon_crawler.py https://example.com --delay 1.0

# Increase threads for faster crawling
python web_recon_crawler.py https://example.com --threads 10
```

#### Advanced Usage

```bash
# Full featured crawl
python web_recon_crawler.py https://example.com \
    --depth 3 \
    --pages 200 \
    --threads 8 \
    --js-rendering \
    --delay 0.5
```

#### Configuration Options

| Option | Description | Default | Example |
|--------|-------------|---------|---------|
| `--depth` | Maximum crawl depth | 3 | `--depth 5` |
| `--pages` | Maximum pages to crawl | 100 | `--pages 200` |
| `--threads` | Number of concurrent threads | 5 | `--threads 10` |
| `--js-rendering` | Enable JavaScript rendering | false | `--js-rendering` |
| `--delay` | Delay between requests (seconds) | 0.5 | `--delay 1.0` |

### Expected Output

#### Console Output
```
[*] Starting crawl of https://example.com
[*] Max depth: 3, Max pages: 100
[*] Threads: 5
[*] Crawling [0]: https://example.com
[*] Crawling [1]: https://example.com/about
[*] Crawling [1]: https://example.com/contact
[*] Crawling [2]: https://example.com/api/users
[+] Found API endpoint: /api/users
[+] Found email: admin@example.com
[*] Crawling [2]: https://example.com/products
[+] Found form: login (POST)
[*] Crawl complete!
[*] Visited: 45 pages

============================================================
RECONNAISSANCE REPORT SUMMARY
============================================================
Target: https://example.com
Domain: example.com
Pages Crawled: 45

Findings:
  - Pages: 45
  - Api Endpoints: 12
  - Emails: 3
  - Forms: 5
  - Comments: 8
  - Secrets: 2
  - Technologies: 7
  - Javascript Files: 15

[!] Detailed report saved to recon_report.json
```

#### JSON Report Structure (`recon_report.json`)
```json
{
  "summary": {
    "target": "https://example.com",
    "base_domain": "example.com",
    "pages_crawled": 45,
    "findings": {
      "pages": {
        "count": 45,
        "data": [
          {
            "url": "https://example.com",
            "title": "Example Domain",
            "status": "success"
          }
        ]
      },
      "api_endpoints": {
        "count": 12,
        "data": [
          "https://example.com/api/v1/users",
          "https://example.com/api/v1/products"
        ]
      },
      "emails": {
        "count": 3,
        "data": [
          {
            "url": "https://example.com/contact",
            "email": "admin@example.com"
          }
        ]
      },
      "secrets": {
        "count": 2,
        "data": [
          {
            "type": "API Key",
            "value": "sk_live_abc123..."
          }
        ]
      }
    }
  },
  "full_data": {
    "pages": [...],
    "api_endpoints": [...],
    "emails": [...],
    "forms": [...],
    "comments": [...],
    "secrets": [...],
    "technologies": [...],
    "javascript_files": [...]
  }
}
```

### Use Cases

1. **Pre-engagement Reconnaissance**
   - Map target website structure
   - Identify all public-facing endpoints
   - Discover technology stack

2. **API Discovery**
   - Find undocumented API endpoints
   - Extract API documentation
   - Identify API versions

3. **Information Gathering**
   - Collect email addresses
   - Find exposed secrets
   - Map form inputs

4. **Attack Surface Mapping**
   - Identify all user inputs
   - Find hidden functionality
   - Discover admin panels

---

## 📖 Tool 02: REST API Fuzzer

### Purpose
Advanced REST API security testing tool that discovers endpoints, fuzzes parameters with various attack payloads, and automatically detects vulnerabilities through response analysis.

### Key Capabilities

#### 🔍 Endpoint Discovery
- **Common endpoint enumeration** (50+ built-in paths)
- **API documentation detection** (Swagger, OpenAPI)
- **Method discovery** (GET, POST, PUT, DELETE, PATCH)
- **Content negotiation testing**
- **Sensitive file detection** (.env, .git, etc.)

#### 💉 Fuzzing Capabilities
- **SQL Injection** - Error-based and blind detection
- **Cross-Site Scripting (XSS)** - Reflected XSS detection
- **Command Injection** - OS command injection testing
- **Path Traversal** - Directory traversal attacks
- **NoSQL Injection** - MongoDB injection payloads
- **JSON Injection** - Prototype pollution attacks
- **Numeric Fuzzing** - Boundary and overflow testing
- **String Fuzzing** - Unicode, null bytes, long strings

#### 🛡️ Authentication Testing
- **Missing authentication** detection
- **Token bypass** attempts
- **JWT manipulation** testing
- **Basic auth** brute force
- **Token validation** bypass

#### ⚡ Performance Testing
- **Rate limiting** detection
- **Timeout** analysis
- **DoS** vulnerability identification
- **Response time** monitoring

#### 📊 Automated Analysis
- **Vulnerability pattern** detection
- **Severity classification** (Critical/High/Medium/Low)
- **Evidence collection** for reporting
- **Response comparison** for blind vulnerabilities

### Usage

#### Basic Usage

```bash
# Basic API fuzzing
python rest_api_fuzzer.py https://api.example.com

# Fuzzing with authentication
python rest_api_fuzzer.py https://api.example.com --token eyJhbGciOi...

# Custom delay between requests
python rest_api_fuzzer.py https://api.example.com --delay 0.5

# Custom timeout
python rest_api_fuzzer.py https://api.example.com --timeout 15
```

#### Advanced Usage

```bash
# Full featured fuzzing
python rest_api_fuzzer.py https://api.example.com \
    --token "Bearer eyJhbGciOiJIUzI1NiIs..." \
    --delay 0.2 \
    --timeout 10
```

#### Configuration Options

| Option | Description | Default | Example |
|--------|-------------|---------|---------|
| `--token` | Bearer token for authentication | None | `--token eyJhbGciOi...` |
| `--delay` | Delay between requests (seconds) | 0.1 | `--delay 0.5` |
| `--timeout` | Request timeout (seconds) | 10 | `--timeout 15` |

### Expected Output

#### Console Output
```
[*] Starting API fuzzing of https://api.example.com
[*] Timeout: 10s, Delay: 0.1s
[*] Discovering API endpoints...

[+] Found: https://api.example.com/api (200)
[+] Found: https://api.example.com/api/v1 (200)
[+] Found: https://api.example.com/api/users (200)
[+] Found: https://api.example.com/api/auth/login (200)
[+] Found: https://api.example.com/swagger.json (200)
[!] API documentation found: https://api.example.com/swagger.json

[*] Fuzzing 5 endpoints...

[*] Fuzzing: https://api.example.com/api/users
  [GET] 200
  [POST] 201
  [PUT] 405
  [DELETE] 401

[+] SQL_INJECTION vulnerability found!
    Endpoint: https://api.example.com/api/users
    Parameter: id
    Payload: ' OR '1'='1
    Severity: Critical

[+] XSS vulnerability found!
    Endpoint: https://api.example.com/api/users
    Parameter: name
    Payload: <script>alert(1)</script>
    Severity: High

[*] Testing authentication bypass...
[+] Authentication bypass possible: Bearer null

[*] Testing rate limiting...
[!] No rate limiting detected (50 requests succeeded)

============================================================
API FUZZING REPORT SUMMARY
============================================================
Target: https://api.example.com
Endpoints Discovered: 5
Vulnerabilities Found: 8

Severity Breakdown:
  Critical: 2
  High: 3
  Medium: 2
  Low: 1

[!] Top Vulnerabilities:
  - sql_injection: SQL syntax error in response (Critical)
  - authentication_bypass: Missing authentication on endpoint (Critical)
  - reflected_xss: Payload reflected in response (High)
  - missing_rate_limiting: No rate limiting detected (Medium)

[!] Detailed report saved to api_fuzzer_report.json
```

#### JSON Report Structure (`api_fuzzer_report.json`)
```json
{
  "target": "https://api.example.com",
  "endpoints_discovered": 5,
  "vulnerabilities_found": 8,
  "vulnerabilities": [
    {
      "type": "sql_injection",
      "parameter": "id",
      "payload": "' OR '1'='1",
      "severity": "Critical",
      "evidence": "You have an error in your SQL syntax..."
    },
    {
      "type": "reflected_xss",
      "parameter": "name",
      "payload": "<script>alert(1)</script>",
      "severity": "High",
      "evidence": "Payload reflected in response"
    },
    {
      "type": "authentication_bypass",
      "token": "Bearer null",
      "status": 200,
      "severity": "Critical"
    }
  ],
  "summary": {
    "critical": 2,
    "high": 3,
    "medium": 2,
    "low": 1
  }
}
```

### Fuzzing Payloads Included

#### SQL Injection (10 payloads)
```
' OR '1'='1
' OR 1=1--
admin' --
' UNION SELECT NULL--
1' AND '1'='1
' OR '1'='1' #
1' ORDER BY 1--
```

#### XSS (7 payloads)
```
<script>alert(1)</script>
<img src=x onerror=alert(1)>
"><script>alert(1)</script>
<svg/onload=alert(1)>
```

#### Command Injection (8 payloads)
```
; ls -la
| cat /etc/passwd
$(whoami)
`id`
```

#### Path Traversal (5 payloads)
```
../../../etc/passwd
..\..\..\windows\win.ini
%2e%2e%2f%2e%2e%2fetc%2fpasswd
```

#### NoSQL Injection (9 payloads)
```
{"$gt": ""}
{$ne: null}
{"$where": "1==1"}
{"$regex": ".*"}
```

#### And many more...
- Numeric fuzzing (10 payloads)
- String fuzzing (14 payloads)
- JSON injection (9 payloads)
- Header injection (8 payloads)
- Special characters (10 payloads)

### Use Cases

1. **API Security Assessment**
   - Test for common API vulnerabilities
   - Identify injection points
   - Validate input sanitization

2. **Authentication Testing**
   - Test token validation
   - Identify bypass techniques
   - Check for missing authentication

3. **Rate Limiting Testing**
   - Determine if rate limiting exists
   - Test DoS resilience
   - Identify throttling thresholds

4. **Input Validation Testing**
   - Test boundary conditions
   - Identify type confusion issues
   - Find injection vulnerabilities

---

## 🔧 Advanced Configuration

### Custom Headers

Both tools support custom headers through configuration:

```python
# Web Recon Crawler
from web_recon_crawler import WebReconCrawler

config = {
    'headers': {
        'User-Agent': 'Custom Bot/1.0',
        'X-Custom-Header': 'value'
    }
}
crawler = WebReconCrawler('https://example.com', config)

# REST API Fuzzer
from rest_api_fuzzer import RESTAPIFuzzer

config = {
    'headers': {
        'Content-Type': 'application/json',
        'X-API-Key': 'your-api-key'
    }
}
fuzzer = RESTAPIFuzzer('https://api.example.com', config)
```

### Proxy Configuration

```bash
# Use with Burp Suite or other proxy
export HTTP_PROXY="http://127.0.0.1:8080"
export HTTPS_PROXY="http://127.0.0.1:8080"

# Then run normally
python web_recon_crawler.py https://example.com
python rest_api_fuzzer.py https://api.example.com
```

### Authentication Methods

```bash
# Bearer Token
python rest_api_fuzzer.py https://api.example.com --token "eyJhbGciOi..."

# API Key (modify script)
config = {
    'headers': {
        'X-API-Key': 'your-api-key'
    }
}

# Basic Auth (modify script)
config = {
    'auth': ('username', 'password')
}
```

---

## 📊 Comparison of Tools

| Feature | Web Recon Crawler | REST API Fuzzer |
|---------|-------------------|-----------------|
| **Primary Purpose** | Website mapping | API testing |
| **JavaScript Rendering** | ✅ (optional) | ❌ |
| **Multi-threading** | ✅ | ❌ (sequential) |
| **Endpoint Discovery** | ✅ | ✅ |
| **Form Analysis** | ✅ | ❌ |
| **Email Extraction** | ✅ | ❌ |
| **Secret Detection** | ✅ | ❌ |
| **SQL Injection Testing** | ❌ | ✅ |
| **XSS Testing** | ❌ | ✅ |
| **Command Injection** | ❌ | ✅ |
| **Authentication Testing** | ❌ | ✅ |
| **Rate Limiting Testing** | ❌ | ✅ |
| **Depth Control** | ✅ | ❌ |
| **Technology Detection** | ✅ | ❌ |

---

## 🛡️ Defense Recommendations

### For Web Applications

1. **Information Disclosure**
   - Remove sensitive data from HTML comments
   - Disable directory listing
   - Implement proper error handling
   - Use generic error messages

2. **API Security**
   - Implement proper authentication
   - Use rate limiting
   - Validate all inputs
   - Implement CORS properly

3. **Crawling Protection**
   - Implement robots.txt
   - Use CAPTCHAs for sensitive pages
   - Monitor for unusual traffic patterns
   - Implement request throttling

### For APIs

1. **Input Validation**
   - Validate all input parameters
   - Use parameterized queries
   - Implement type checking
   - Sanitize user input

2. **Authentication**
   - Use strong token validation
   - Implement token expiration
   - Use HTTPS only
   - Rotate secrets regularly

3. **Rate Limiting**
   - Implement per-user rate limits
   - Use exponential backoff
   - Monitor for abuse patterns
   - Block suspicious IPs

---

## 🐛 Troubleshooting

### Common Issues

#### 1. SSL Certificate Errors
```bash
# Solution 1: Environment variable
export PYTHONHTTPSVERIFY=0

# Solution 2: Modify script temporarily
requests.get(url, verify=False)

# Solution 3: Install certificates
pip install --upgrade certifi
```

#### 2. Selenium WebDriver Issues
```bash
# ChromeDriver version mismatch
pip install webdriver-manager

# Then in script:
from webdriver_manager.chrome import ChromeDriverManager
driver = webdriver.Chrome(ChromeDriverManager().install())

# Or specify path manually
driver = webdriver.Chrome('/path/to/chromedriver')
```

#### 3. Rate Limiting Blocks
```bash
# Increase delay between requests
python web_recon_crawler.py https://example.com --delay 2.0
python rest_api_fuzzer.py https://api.example.com --delay 1.0

# Reduce threads
python web_recon_crawler.py https://example.com --threads 1
```

#### 4. Memory Issues with Large Crawls
```bash
# Limit pages and depth
python web_recon_crawler.py https://example.com --pages 50 --depth 2

# Run with more memory
python -Xms512m -Xmx2048m web_recon_crawler.py https://example.com
```

#### 5. JavaScript-Heavy Sites Not Crawling
```bash
# Enable JS rendering
python web_recon_crawler.py https://spa-example.com --js-rendering

# Increase wait time for JS execution
# Modify script: time.sleep(3)  # Increase from 2 to 3 seconds
```

#### 6. API Returning Only 401/403
```bash
# Verify token
curl -H "Authorization: Bearer YOUR_TOKEN" https://api.example.com

# Test without authentication
python rest_api_fuzzer.py https://api.example.com

# Check token expiration
python -c "import jwt; jwt.decode('YOUR_TOKEN', verify=False)"
```

---

## 📝 Integration Examples

### Combining Both Tools

```bash
# Step 1: Crawl website to find API endpoints
python web_recon_crawler.py https://example.com --depth 3

# Step 2: Extract API endpoints from report
cat recon_report.json | jq '.full_data.api_endpoints[]'

# Step 3: Fuzz discovered APIs
python rest_api_fuzzer.py https://api.example.com --token "obtained_token"
```

### Automation Script

```bash
#!/bin/bash
# automated_recon.sh

TARGET="https://example.com"

echo "[*] Starting automated reconnaissance of $TARGET"

# Phase 1: Web Crawling
echo "[*] Phase 1: Web Crawling"
python web_recon_crawler.py "$TARGET" --depth 2 --pages 100

# Phase 2: Extract API endpoints
echo "[*] Phase 2: Extracting APIs"
python -c "
import json
with open('recon_report.json') as f:
    data = json.load(f)
    apis = data['full_data'].get('api_endpoints', [])
    for api in set(apis[:5]):  # First 5 unique APIs
        print(api)
" > discovered_apis.txt

# Phase 3: Fuzz each API
echo "[*] Phase 3: Fuzzing APIs"
while read api; do
    echo "[*] Fuzzing: $api"
    python rest_api_fuzzer.py "$api" --delay 0.2
done < discovered_apis.txt

echo "[*] Reconnaissance complete!"
```

---

## 📈 Performance Optimization

### Web Recon Crawler

```python
# Optimize for speed
config = {
    'threads': 10,        # More concurrent threads
    'delay': 0.1,         # Minimal delay
    'max_pages': 1000,    # More pages
    'js_rendering': False # Disable JS for speed
}

# Optimize for stealth
config = {
    'threads': 1,         # Single thread
    'delay': 2.0,         # Long delay
    'max_pages': 50,      # Fewer pages
    'js_rendering': True  # Render JS properly
}
```

### REST API Fuzzer

```python
# Fast fuzzing (may trigger rate limits)
config = {
    'delay': 0.05,        # Very fast
    'timeout': 5,         # Short timeout
    'threads': 1
}

# Thorough fuzzing (stealthy)
config = {
    'delay': 1.0,         # Slow and steady
    'timeout': 15,        # Longer timeout
    'threads': 1
}
```

---

## 🤝 Contributing

### Adding Custom Payloads

```python
# Add to rest_api_fuzzer.py
self.payloads['custom_attacks'] = [
    '${7*7}',                    # SSTI
    '{{7*7}}',                   # Template injection
    'O:8:"stdClass":0:{}',       # PHP deserialization
    '__proto__[admin]=true',     # Prototype pollution
]
```

### Adding Custom Endpoint Patterns

```python
# Add to web_recon_crawler.py
self.patterns['custom'] = [
    r'/api/internal/.*',
    r'/admin/.*',
    r'/backup/.*',
]
```

---

## 📄 License

MIT License - See LICENSE file for details.

## 🙏 Acknowledgments

- OWASP for API Security Top 10
- PortSwigger Research Team
- Web Security Academy
- All security researchers who contributed techniques

## 📚 Additional Resources

- [OWASP API Security Project](https://owasp.org/www-project-api-security/)
- [REST API Security Best Practices](https://restfulapi.net/security-essentials/)
- [Web Crawling Ethics](https://www.robotstxt.org/)
- [API Security Testing Guide](https://github.com/OWASP/wstg)
