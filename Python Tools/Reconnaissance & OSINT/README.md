# Reconnaissance & Enumeration Toolkit

Advanced Python scripts for network reconnaissance, service enumeration, and information gathering. Part of the Red Team Web Security Testing Toolkit.

## ⚠️ DISCLAIMER

**FOR AUTHORIZED SECURITY TESTING ONLY**

These tools are designed exclusively for:
- Authorized penetration testing engagements
- Red team operations with written permission
- Bug bounty programs within scope
- Security research on owned systems
- Educational purposes in controlled environments

**Unauthorized use against systems you don't own or have explicit permission to test is ILLEGAL and may result in criminal prosecution.**

---

## 📋 Tools Overview

| # | Tool | Category | Purpose |
|---|------|----------|---------|
| 15 | `shodan_recon.py` | OSINT | Shodan API integration for internet-wide reconnaissance |
| 16 | `email_harvester.py` | OSINT | Multi-source email and subdomain harvesting |
| 17 | `banner_grabber.py` | Network | Service fingerprinting and banner grabbing |
| 18 | `snmp_enumerator.py` | Network | SNMP v1/v2c/v3 enumeration and brute force |
| 19 | `smb_enumerator.py` | Network | SMB share, user, and policy enumeration |
| 20 | `netbios_poisoner.py` | Network | NetBIOS/LLMNR poisoning and hash capture |
| 21 | `exif_extractor.py` | OSINT | EXIF metadata extraction from images and documents |
| 22 | `social_enumerator.py` | OSINT | Username and social media account enumeration |

---

## 🚀 Installation

### Prerequisites

- **Python 3.8+** (3.10+ recommended)
- **pip** (latest version)
- **Root/Administrator privileges** (for network tools)

### Quick Install

```bash
# Clone the toolkit repository
git clone https://github.com/your-repo/redteam-web-toolkit.git
cd redteam-web-toolkit

# Install all dependencies
pip install -r requirements-recon.txt
```

### Tool-Specific Dependencies

#### Shodan Recon (`shodan_recon.py`)
```bash
pip install requests
# Requires Shodan API key (free tier available)
```

#### Email Harvester (`email_harvester.py`)
```bash
pip install requests beautifulsoup4 lxml
```

#### Banner Grabber (`banner_grabber.py`)
```bash
# Core dependencies only
pip install requests

# For SSL/TLS support
pip install pyOpenSSL cryptography
```

#### SNMP Enumerator (`snmp_enumerator.py`)
```bash
# Basic installation
pip install pysnmp

# Alternative (if pysnmp fails)
pip install pysnmp-lextudio
pip install pyasn1 pyasn1-modules
```

#### SMB Enumerator (`smb_enumerator.py`)
```bash
# Impacket for SMB enumeration
pip install impacket

# Alternative installation methods:
# From source:
git clone https://github.com/SecureAuthCorp/impacket.git
cd impacket
pip install .

# On Kali Linux:
sudo apt-get install python3-impacket
```

#### NetBIOS Poisoner (`netbios_poisoner.py`)
```bash
# Core dependencies only (built-in sockets)
# No additional pip packages required

# Requires root/admin privileges for:
# - Binding to ports < 1024
# - Multicast socket operations
```

#### EXIF Extractor (`exif_extractor.py`)
```bash
# Image metadata
pip install Pillow

# PDF parsing
pip install PyPDF2

# Office document parsing
pip install python-docx openpyxl
```

#### Social Enumerator (`social_enumerator.py`)
```bash
pip install requests
```

### Complete Requirements File

Create `requirements-recon.txt`:

```txt
# Core dependencies
requests>=2.28.0
beautifulsoup4>=4.11.0
lxml>=4.9.0
urllib3>=1.26.5

# Shodan
shodan>=1.28.0

# SNMP
pysnmp>=4.4.12
pysnmp-lextudio>=5.0.0
pyasn1>=0.4.8
pyasn1-modules>=0.2.8

# SMB (Impacket)
impacket>=0.10.0
pyOpenSSL>=23.0.0
cryptography>=39.0.0

# EXIF & Documents
Pillow>=9.4.0
PyPDF2>=3.0.0
python-docx>=0.8.11
openpyxl>=3.1.0

# Utilities
colorama>=0.4.6
tqdm>=4.64.0
```

### Platform-Specific Setup

#### Linux (Ubuntu/Debian)
```bash
# System dependencies
sudo apt-get update
sudo apt-get install -y \
    python3 python3-pip python3-dev \
    build-essential libssl-dev libffi-dev \
    libsnmp-dev snmp-mibs-downloader \
    libpcap-dev

# Install Python packages
pip install -r requirements-recon.txt

# Download SNMP MIBs (optional)
sudo download-mibs
```

#### macOS
```bash
# Using Homebrew
brew install python3
brew install openssl
brew install net-snmp

# Install Python packages
pip3 install -r requirements-recon.txt
```

#### Windows
```bash
# Install Python from python.org
# Run as Administrator for network tools

# Install dependencies
pip install -r requirements-recon.txt

# Note: SMB enumeration may require additional setup
```

---

## 📖 Tool 15: Shodan API Integration

### Purpose
Leverage Shodan's API for internet-wide reconnaissance, technology discovery, and vulnerability identification.

### Key Capabilities

- **Organization search** - Find all hosts belonging to an organization
- **Technology search** - Discover services running specific software
- **Network enumeration** - Map entire CIDR ranges
- **IoT device discovery** - Find exposed IoT devices
- **Database exposure** - Identify unsecured databases
- **Vulnerability search** - Find systems with known CVEs
- **DNS resolution** - Forward and reverse DNS lookups

### Usage

```bash
# Basic API key check
python shodan_recon.py YOUR_API_KEY

# Search organization
python shodan_recon.py YOUR_API_KEY --org "Example Corp"

# Search for specific technology
python shodan_recon.py YOUR_API_KEY --tech nginx

# Enumerate network range
python shodan_recon.py YOUR_API_KEY --network 192.168.0.0/24

# Find exposed databases
python shodan_recon.py YOUR_API_KEY --databases

# Search for IoT devices
python shodan_recon.py YOUR_API_KEY --iot "webcam"

# Get host information
python shodan_recon.py YOUR_API_KEY --ip 8.8.8.8

# Search for vulnerabilities
python shodan_recon.py YOUR_API_KEY --vuln "Apache 2.4"

# Combined search
python shodan_recon.py YOUR_API_KEY --org "Target Inc" --databases --tech mongodb
```

### Expected Output

```
[+] API Plan: dev
[+] Query Credits: 100

[*] Searching organization: Example Corp
[+] Found 245 results
    192.168.1.1:443 - Example Corp - www.example.com
    192.168.1.2:80 - Example Corp - api.example.com
    192.168.1.3:22 - Example Corp - git.example.com

[*] Searching for exposed databases...
[+] MongoDB: 1,234 exposed instances
    Potentially unauthenticated: 567
[+] Redis: 8,901 exposed instances
    Potentially unauthenticated: 3,456

[+] Report saved to shodan_recon_report.json
[*] Total findings: 1,245
```

### Getting a Shodan API Key

1. Register at [https://account.shodan.io/register](https://account.shodan.io/register)
2. Get your API key from [https://account.shodan.io/](https://account.shodan.io/)
3. Free tier: Limited queries, basic functionality
4. Paid tiers: More queries, advanced filters

---

## 📖 Tool 16: Email Harvester

### Purpose
Multi-source email and subdomain harvesting tool similar to theHarvester, collecting information from search engines, certificate transparency logs, and various APIs.

### Key Capabilities

- **Search engine scraping** - Google, Bing, Yahoo, DuckDuckGo
- **Certificate transparency** - crt.sh, CertSpotter
- **DNS intelligence** - HackerTarget, AlienVault OTX
- **Social media search** - LinkedIn, Twitter, GitHub, Reddit
- **Paste site search** - Pastebin, Pastie, Ghostbin
- **Subdomain enumeration** - From multiple sources
- **Email extraction** - From discovered websites

### Usage

```bash
# Basic email harvesting
python email_harvester.py example.com

# With result limit
python email_harvester.py example.com 200

# The tool will automatically:
# 1. Search search engines for emails
# 2. Query certificate transparency logs
# 3. Check DNS intelligence platforms
# 4. Search social media platforms
# 5. Check paste sites
# 6. Extract emails from discovered websites
```

### Expected Output

```
[*] Starting email harvest for: example.com
[*] Searching Google...
    Found 5 emails
[*] Searching Bing...
    Found 3 emails
[*] Querying crt.sh...
    Found 23 subdomains
[*] Querying CertSpotter...
    Found 15 subdomains
[*] Searching social media...
    linkedin: Found 2 emails
    github: Found 4 emails
[*] Searching paste sites...
    pastebin.com: Found 1 emails

==================================================
[*] Harvest Complete!
[+] Emails found: 15
[+] Subdomains found: 38
[+] IPs found: 12

[*] Sample emails:
    - admin@example.com
    - john.doe@example.com
    - support@example.com

[+] Reports saved:
    - example.com_harvest.json
    - example.com_emails.txt
    - example.com_subdomains.txt
```

### Output Files

| File | Content |
|------|---------|
| `domain_harvest.json` | Complete JSON report |
| `domain_emails.txt` | Email list (one per line) |
| `domain_subdomains.txt` | Subdomain list (one per line) |

---

## 📖 Tool 17: Banner Grabber

### Purpose
Advanced service fingerprinting tool that connects to network services and extracts banner information for version identification and vulnerability assessment.

### Key Capabilities

- **20+ service probes** - Specialized handlers for common services
- **SSL/TLS support** - HTTPS, POP3S, IMAPS, SMTPS
- **Version detection** - Parse service versions from banners
- **Security checks** - Open relay detection, null authentication
- **Multi-threaded scanning** - Fast concurrent port scanning
- **Service-specific probes**:
  - FTP, SSH, Telnet
  - SMTP (with open relay test)
  - HTTP/HTTPS (with header extraction)
  - MySQL, PostgreSQL, MSSQL, Oracle
  - Redis, MongoDB, Elasticsearch
  - SMB, RDP, VNC

### Usage

```bash
# Scan specific ports
python banner_grabber.py 192.168.1.1 22,80,443,3306

# Scan port range
python banner_grabber.py 192.168.1.1 1-1000

# Scan hostname
python banner_grabber.py example.com 80,443,8080,8443
```

### Expected Output

```
[*] Target: 192.168.1.1 (192.168.1.1)
[*] Ports: 5
[*] Scanning 192.168.1.1 - 5 ports
    [+] Port 22: SSH
        Version: OpenSSH 8.2p1 Ubuntu
    [+] Port 80: HTTP
        Server: Apache/2.4.41 (Ubuntu)
    [+] Port 443: HTTPS
        Server: nginx/1.18.0
    [+] Port 3306: MySQL
        Version: 8.0.28-0ubuntu0.20.04.3
    [+] Port 8080: HTTP
        Server: Apache Tomcat/9.0.58

[+] Report saved to banner_grab_report.json
```

### Service Detection Details

| Service | Port | Detection Method |
|---------|------|------------------|
| SSH | 22 | Version string parsing |
| SMTP | 25 | EHLO command + open relay test |
| HTTP | 80/8080 | GET request + header analysis |
| MySQL | 3306 | Greeting packet parsing |
| Redis | 6379 | PING/INFO commands |
| MongoDB | 27017 | isMaster command |
| Elasticsearch | 9200 | REST API query |

---

## 📖 Tool 18: SNMP Enumerator

### Purpose
Comprehensive SNMP v1/v2c/v3 enumeration tool for extracting system information, network configuration, and user accounts through SNMP protocol.

### Key Capabilities

- **Community string brute force** - Test common community strings
- **System enumeration** - OS, hostname, contact, location
- **Network enumeration** - Interfaces, IP addresses, routes, TCP/UDP tables
- **Process enumeration** - Running processes and installed software
- **User enumeration** - User accounts and service accounts
- **Vendor-specific enumeration** - Cisco CDP/VLANs, Microsoft shares
- **SNMP walk** - Recursive OID tree walking

### Usage

```bash
# Basic enumeration
python snmp_enumerator.py 192.168.1.1

# With custom community strings
python snmp_enumerator.py 192.168.1.1 public,private,admin,cisco

# The tool will automatically:
# 1. Brute force community strings
# 2. Enumerate system information
# 3. Extract network configuration
# 4. List running processes
# 5. Discover user accounts
# 6. Query vendor-specific OIDs
```

### Expected Output

```
[*] Starting SNMP enumeration of 192.168.1.1
[*] Brute forcing community strings...
[+] Valid community: public
    System: Linux server01 5.4.0-91-generic #102-Ubuntu
[+] Valid community: private

[*] Using community: public

[*] Enumerating system information...
    sysDescr: Linux server01 5.4.0-91-generic
    sysName: server01
    sysLocation: Data Center A
    sysContact: admin@example.com

[*] Enumerating network information...
    Interfaces: 3
    Interface descriptions: 3 found
    IP Addresses: 3 found
      - 192.168.1.1
      - 10.0.0.1
      - 172.16.0.1
    TCP Connections: 45

[*] Enumerating processes...
    Running processes: 234
      - /sbin/init
      - /usr/sbin/sshd
      - /usr/sbin/apache2
      - /usr/sbin/mysqld

[+] Report saved to snmp_192.168.1.1.json
```

### Common Community Strings

| Category | Examples |
|----------|----------|
| Default | public, private, internal |
| Management | manager, admin, root |
| Vendor | cisco, netgear, dlink |
| Read-only | read, monitor, snmp |
| Read-write | write, secret, security |
| Custom | network, system, trap |

### Sensitive OIDs

| Information | OID |
|-------------|-----|
| System Description | 1.3.6.1.2.1.1.1.0 |
| Running Processes | 1.3.6.1.2.1.25.4.2.1.2 |
| TCP Connections | 1.3.6.1.2.1.6.13.1.3 |
| User Accounts | 1.3.6.1.4.1.77.1.2.25.1.1 |
| Installed Software | 1.3.6.1.2.1.25.6.3.1.2 |

---

## 📖 Tool 19: SMB Enumerator

### Purpose
Windows/SMB network enumeration tool using Impacket library to extract shares, users, groups, and password policies from SMB services.

### Key Capabilities

- **Null session testing** - Check for anonymous access
- **Share enumeration** - List and check access to SMB shares
- **User enumeration** - Extract domain users via SAMR
- **Group enumeration** - List domain groups and members
- **Password policy** - Extract password complexity requirements
- **SMB signing check** - Identify relay attack opportunities
- **SMB version detection** - Check for vulnerable SMBv1
- **Share content listing** - Recursive file enumeration

### Usage

```bash
# Anonymous enumeration
python smb_enumerator.py 192.168.1.1

# Authenticated enumeration
python smb_enumerator.py 192.168.1.1 administrator Password123 WORKGROUP

# Domain enumeration
python smb_enumerator.py 192.168.1.1 jdoe password123 example.com
```

### Expected Output

```
[*] Starting SMB enumeration of 192.168.1.1

[*] Checking SMB version...
    SMB Version: SMBv2

[*] Checking null session...
[+] Null session allowed!

[*] Checking SMB signing...
[!] SMB signing not required (vulnerable to relay)

[*] Enumerating shares...
    [+] ADMIN$ - Remote Admin (ACCESSIBLE)
    [+] C$ - Default share (ACCESSIBLE)
    [+] IPC$ - Remote IPC (ACCESSIBLE)
    [-] Shared - Company shared files
    [+] Users - User directories (ACCESSIBLE)

[*] Enumerating users via SAMR...
    [+] Administrator (RID: 500)
    [+] Guest (RID: 501)
    [+] jdoe (RID: 1001)
    [+] msmith (RID: 1002)

[*] Enumerating groups...
    [+] Domain Admins (RID: 512)
    [+] Domain Users (RID: 513)
    [+] Domain Guests (RID: 514)

[*] Enumerating password policy...
    Min Password Length: 8
    Password History: 24
    Max Password Age: 42 days

[+] Report saved to smb_192.168.1.1.json
```

### Security Implications

| Finding | Risk | Attack |
|---------|------|--------|
| Null session | High | Anonymous enumeration |
| No SMB signing | Critical | NTLM relay attack |
| SMBv1 enabled | Critical | EternalBlue exploit |
| Weak password policy | Medium | Password spraying |
| Accessible ADMIN$ | High | Remote code execution |

---

## 📖 Tool 20: NetBIOS/LLMNR Poisoner

### Purpose
Network poisoning tool that responds to NetBIOS Name Service (NBNS) and Link-Local Multicast Name Resolution (LLMNR) queries to capture NTLM hashes.

### Key Capabilities

- **NBNS poisoning** - Respond to NetBIOS name queries
- **LLMNR poisoning** - Respond to multicast name resolution
- **HTTP capture server** - Capture NTLM authentication attempts
- **SMB capture server** - Capture SMB authentication
- **WPAD spoofing** - Respond to proxy auto-discovery
- **Hash collection** - Capture and store NTLM hashes
- **Statistics tracking** - Monitor poisoning effectiveness

### Usage

```bash
# Start poisoning (requires root/admin)
sudo python netbios_poisoner.py 192.168.1.100

# The tool will start four services:
# - NBNS responder on UDP 137
# - LLMNR responder on UDP 5355
# - HTTP server on TCP 80
# - SMB server on TCP 445
```

### Expected Output

```
[*] Starting NetBIOS/LLMNR Poisoner
[*] Interface: 192.168.1.100
[*] Responder IP: 192.168.1.100

[*] Starting NBNS poisoner on 192.168.1.100
[*] Starting LLMNR poisoner on 192.168.1.100
[*] HTTP capture server on 192.168.1.100:80
[*] SMB capture server on 192.168.1.100:445

[*] Poisoning active! Press Ctrl+C to stop
[*] NBNS: 137, LLMNR: 5355
[*] HTTP: 80, SMB: 445

[+] NBNS Query: FILESERVER from 192.168.1.50
[+] LLMNR Query: wpad from 192.168.1.75
[+] NBNS Query: PRINTER from 192.168.1.60
[+] SMB connection from 192.168.1.50
[!] Captured NTLM hash from 192.168.1.50

[*] Stats - NBNS: 12, LLMNR: 5, Hashes: 3

^C
[*] Stopping poisoner...
[+] 3 hashes saved to captured_hashes.json
```

### Captured Hash Format

```json
[
    {
        "ip": "192.168.1.50",
        "type": "NTLM",
        "hash": "NTLM TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw==",
        "timestamp": 1647123456.789
    }
]
```

### Attack Scenario

1. Victim tries to access `\\FILESERVER\share`
2. DNS fails to resolve `FILESERVER`
3. Windows falls back to NBNS/LLMNR broadcast
4. Poisoner responds with attacker's IP
5. Victim connects and sends NTLM hash
6. Attacker captures hash for offline cracking

---

## 📖 Tool 21: EXIF Metadata Extractor

### Purpose
Extract and analyze metadata from images, documents, and files to discover sensitive information like GPS coordinates, author details, and software versions.

### Key Capabilities

- **Image metadata** - EXIF, GPS, camera details, timestamps
- **PNG metadata** - Text chunks, creation info
- **PDF metadata** - Author, creator, dates
- **Office documents** - Creator, company, revision info
- **GPS extraction** - Coordinates with Google Maps links
- **Sensitive information detection** - Flag sensitive metadata
- **Batch processing** - Scan entire directories
- **File hashing** - MD5 and SHA256 for file identification

### Usage

```bash
# Analyze single file
python exif_extractor.py photo.jpg

# Scan entire directory
python exif_extractor.py /path/to/images/

# The tool automatically:
# 1. Detects file type
# 2. Extracts all metadata
# 3. Identifies sensitive information
# 4. Extracts GPS coordinates
# 5. Generates Google Maps links
```

### Expected Output

```
[*] Analyzing: photo.jpg
    [!] Found 5 sensitive metadata items
    [+] GPS: 37.7749, -122.4194
    [+] Maps: https://maps.google.com/?q=37.7749,-122.4194

[*] Analyzing: document.pdf
    [!] Found 3 sensitive metadata items
    Author: John Doe

==================================================
[*] Metadata Extraction Complete
[+] Files analyzed: 45
[+] File types: {'JPEG': 30, 'PDF': 10, 'PNG': 5}
[+] GPS locations found: 12
[+] Sensitive findings: 18

[!] GPS Locations Found:
    IMG_001.jpg: 37.7749, -122.4194
    https://maps.google.com/?q=37.7749,-122.4194
    IMG_002.jpg: 40.7128, -74.0060
    https://maps.google.com/?q=40.7128,-74.0060

[+] Report saved to exif_report.json
```

### Sensitive Metadata Tags

| Category | Tags | Risk |
|----------|------|------|
| Location | GPSLatitude, GPSLongitude | High |
| Identity | Artist, Author, Creator | Medium |
| Device | Make, Model, SerialNumber | Medium |
| Software | Software, CreatorTool | Low |
| Dates | DateTimeOriginal, CreateDate | Low |

### Supported File Types

| Type | Extensions | Metadata Source |
|------|------------|-----------------|
| JPEG | .jpg, .jpeg | EXIF tags |
| PNG | .png | tEXt, iTXt chunks |
| GIF | .gif | Comment extensions |
| PDF | .pdf | Document properties |
| Office | .docx, .xlsx, .pptx | XML properties |

---

## 📖 Tool 22: Social Media Enumerator

### Purpose
Enumerate username presence across 20+ social media platforms to map a target's online footprint and discover additional attack vectors.

### Key Capabilities

- **Username enumeration** - Check 20+ platforms simultaneously
- **Email enumeration** - Check email-based services (Gravatar, HIBP)
- **Full name enumeration** - Generate and test username variations
- **20+ platforms supported**:
  - GitHub, GitLab, Bitbucket (development)
  - Twitter, Facebook, Instagram, LinkedIn (social)
  - Reddit, HackerNews, Medium, Dev.to (communities)
  - YouTube, TikTok, Twitch (media)
  - StackOverflow (professional)
  - Keybase, Telegram (messaging)
- **Username variation generation** - 20+ common patterns
- **Paste site search** - Find credentials in pastes
- **Multi-threaded** - Fast parallel checking

### Usage

```bash
# Enumerate username
python social_enumerator.py johndoe

# Enumerate email
python social_enumerator.py john@example.com

# Enumerate full name (generates variations)
python social_enumerator.py "John Doe"
```

### Expected Output

```
[*] Enumerating username: johndoe
    [+] github: https://github.com/johndoe
    [+] twitter: https://twitter.com/johndoe
    [+] linkedin: https://www.linkedin.com/in/johndoe
    [+] reddit: https://www.reddit.com/user/johndoe
    [+] stackoverflow: https://stackoverflow.com/users/johndoe
    [+] medium: https://medium.com/@johndoe

==================================================
[*] Enumeration Complete
[+] Queries: 1

[+] johndoe: Found on 6 platforms
    - github
    - twitter
    - linkedin
    - reddit
    - stackoverflow
    - medium

[+] Report saved to social_enum_report.json
```

### Username Variations Generated

For "John Doe", the tool generates:

```
johndoe          john.doe         john_doe
john-doe         johnd            jdoe
j.doe            johndoe          jd
doejohn          doe.john         john
doe              itsjohn          mrjohn
johndev          johncodes        realjohndoe
officialjohndoe
```

### Platforms Checked

| Category | Platforms |
|----------|-----------|
| Social | Twitter, Facebook, Instagram, LinkedIn |
| Development | GitHub, GitLab, Bitbucket, Dev.to |
| Professional | StackOverflow, Medium |
| Media | YouTube, TikTok, Twitch, Spotify |
| Community | Reddit, HackerNews, Tumblr |
| Messaging | Telegram, Keybase |
| Design | Pinterest, Dribbble |

---

## 🔧 Advanced Configuration

### Proxy Setup

```bash
# All tools support proxy via environment variables
export HTTP_PROXY="http://127.0.0.1:8080"
export HTTPS_PROXY="http://127.0.0.1:8080"

# Or modify in script
proxies = {
    'http': 'http://127.0.0.1:8080',
    'https': 'http://127.0.0.1:8080'
}
```

### Rate Limiting

```bash
# Most tools have built-in delays
# Adjust in script or via parameters

# Banner Grabber
python banner_grabber.py 192.168.1.1 1-1000
# Default timeout: 5 seconds per port

# Email Harvester
python email_harvester.py example.com
# Default delay: 1 second between searches

# Social Enumerator
python social_enumerator.py johndoe
# Default timeout: 10 seconds per platform
```

### Output Integration

All tools output JSON for easy integration:

```bash
# Chain tools together
python email_harvester.py example.com
python social_enumerator.py $(cat example.com_emails.txt | head -1)
python exif_extractor.py /path/to/downloaded/images/

# Parse results with jq
cat shodan_recon_report.json | jq '.results.exposed_databases'
cat banner_grab_report.json | jq '.results[] | select(.service == "MySQL")'
```

---

## 🛡️ Defense Recommendations

### Against Shodan Discovery
- Implement proper firewall rules
- Use VPNs for sensitive services
- Regularly scan your own IP ranges
- Monitor Shodan for your organization

### Against Email Harvesting
- Use email obfuscation on websites
- Implement CAPTCHAs for contact pages
- Monitor for data breaches
- Use email aliases for public-facing addresses

### Against Banner Grabbing
- Customize service banners
- Use port knocking
- Implement fail2ban
- Keep services updated and patched

### Against SNMP Enumeration
- Change default community strings
- Use SNMPv3 with encryption
- Implement ACLs for SNMP access
- Disable SNMP if not needed

### Against SMB Enumeration
- Disable SMBv1
- Enable SMB signing
- Restrict anonymous access
- Use strong password policies

### Against NetBIOS/LLMNR Poisoning
- Disable NetBIOS and LLMNR
- Enable SMB signing
- Use Kerberos authentication
- Implement network segmentation

### Against Metadata Leakage
- Strip metadata before publishing
- Use metadata removal tools
- Implement DLP policies
- Train users on metadata risks

### Against Social Media Enumeration
- Use unique usernames per platform
- Enable privacy settings
- Limit public profile information
- Monitor for impersonation accounts

---

## 📊 Comparison Matrix

| Tool | Speed | Stealth | Complexity | Privilege Required |
|------|-------|---------|------------|-------------------|
| Shodan Recon | Fast | High | Low | No |
| Email Harvester | Medium | Medium | Low | No |
| Banner Grabber | Fast | Low | Low | No |
| SNMP Enumerator | Fast | Low | Medium | No |
| SMB Enumerator | Fast | Low | Medium | No |
| NetBIOS Poisoner | Continuous | Very Low | High | **Yes (Root)** |
| EXIF Extractor | Fast | Very High | Low | No |
| Social Enumerator | Medium | High | Low | No |

---

## 🐛 Troubleshooting

### Common Issues

#### 1. Impacket Installation Fails
```bash
# Solution 1: Install from GitHub
pip install git+https://github.com/SecureAuthCorp/impacket.git

# Solution 2: Use system package
sudo apt-get install python3-impacket  # Kali/Ubuntu

# Solution 3: Install in virtual environment
python -m venv venv
source venv/bin/activate
pip install impacket
```

#### 2. pysnmp Issues
```bash
# Alternative SNMP library
pip install pysnmp-lextudio

# Or use system SNMP tools
sudo apt-get install snmp snmp-mibs-downloader
```

#### 3. Permission Denied (NetBIOS Poisoner)
```bash
# Run with sudo/root
sudo python netbios_poisoner.py 192.168.1.100

# Or use capabilities (Linux)
sudo setcap cap_net_raw+ep /usr/bin/python3
```

#### 4. PIL/Pillow Not Found
```bash
# Reinstall Pillow
pip uninstall Pillow PIL
pip install Pillow

# On Ubuntu/Debian
sudo apt-get install python3-pil python3-pil.imagetk
```

#### 5. SSL Certificate Errors
```bash
# Disable SSL verification (not recommended for production)
export PYTHONHTTPSVERIFY=0

# Or update certificates
pip install --upgrade certifi
```

#### 6. Rate Limiting (Social Media)
```bash
# Increase delays
time.sleep(2)  # Add to check_username function

# Use proxies
proxies = {'https': 'http://proxy:8080'}
```

---

## 📝 Integration Examples

### Full Reconnaissance Workflow

```bash
#!/bin/bash
# full_recon.sh - Complete reconnaissance workflow

TARGET_DOMAIN="example.com"
TARGET_IP="192.168.1.1"
SHODAN_KEY="your_api_key"

echo "[*] Starting full reconnaissance of $TARGET_DOMAIN"

# Phase 1: Passive Reconnaissance
echo "[Phase 1] Passive Reconnaissance"
python email_harvester.py "$TARGET_DOMAIN"
python social_enumerator.py "admin@${TARGET_DOMAIN}"
python shodan_recon.py "$SHODAN_KEY" --org "$TARGET_DOMAIN"

# Phase 2: Active Reconnaissance
echo "[Phase 2] Active Reconnaissance"
python banner_grabber.py "$TARGET_IP" 1-1000
python snmp_enumerator.py "$TARGET_IP"
python smb_enumerator.py "$TARGET_IP"

# Phase 3: Metadata Analysis
echo "[Phase 3] Metadata Analysis"
python exif_extractor.py ./discovered_files/

echo "[*] Reconnaissance complete!"
echo "[*] Check individual reports for findings"
```

### Automated Reporting

```python
#!/usr/bin/env python3
# generate_master_report.py

import json
import glob
from datetime import datetime

def merge_reports():
    master_report = {
        'timestamp': datetime.now().isoformat(),
        'findings': {}
    }
    
    # Merge all JSON reports
    for report_file in glob.glob('*_report.json'):
        with open(report_file) as f:
            data = json.load(f)
            tool_name = report_file.replace('_report.json', '')
            master_report['findings'][tool_name] = data
    
    # Save master report
    with open('master_recon_report.json', 'w') as f:
        json.dump(master_report, f, indent=2)
    
    # Generate summary
    print(f"[*] Master report generated")
    print(f"[*] Tools: {len(master_report['findings'])}")
    
    for tool, data in master_report['findings'].items():
        print(f"    - {tool}")

if __name__ == "__main__":
    merge_reports()
```

---

## 🤝 Contributing

### Adding New Platforms (Social Enumerator)

```python
# Add to platforms dictionary
'new_platform': {
    'url': 'https://newplatform.com/user/{}',
    'method': 'GET',
    'status_check': [200],
    'not_found': ['User not found', 'does not exist']
}
```

### Adding New Service Probes (Banner Grabber)

```python
# Add to probes dictionary
PORT: self.grab_new_service,

def grab_new_service(self, ip, port):
    """Grab banner from new service"""
    sock = self.create_socket(ip, port)
    if not sock:
        return None
    
    try:
        # Send probe
        sock.send(b'PROBE_COMMAND\r\n')
        response = sock.recv(1024)
        sock.close()
        
        return {
            'service': 'NewService',
            'banner': response.decode('utf-8', errors='ignore')
        }
    except:
        return None
```

---

## 📄 License

MIT License - See LICENSE file for details.

## 🙏 Acknowledgments

- Shodan for API access
- SecureAuth for Impacket library
- Python community for excellent libraries
- Security researchers who discovered these techniques

## 📚 Resources

- [Shodan API Documentation](https://developer.shodan.io/)
- [Impacket Documentation](https://www.secureauth.com/labs/open-source-tools/impacket/)
- [EXIF Specification](https://www.exif.org/)
- [SNMP MIB Reference](http://www.oidview.com/mibs/detail.html)

