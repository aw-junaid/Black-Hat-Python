#!/usr/bin/env python3
"""
BloodHound Data Collector & SMB Share Enumerator
For authorized security testing only
"""
import sys
import os
import json
import time
import subprocess
from datetime import datetime
from collections import defaultdict

class BloodHoundCollector:
    def __init__(self, domain, username, password, dc_ip, collection_method='All'):
        self.domain = domain
        self.username = username
        self.password = password
        self.dc_ip = dc_ip
        self.collection_method = collection_method
        self.results = {
            'collection_status': False,
            'output_file': None,
            'errors': []
        }

    def collect_with_python(self):
        """Use BloodHound.py for collection"""
        print("[*] Collecting data with BloodHound.py...")
        
        try:
            # BloodHound.py command
            cmd = [
                'bloodhound-python',
                '-d', self.domain,
                '-u', self.username,
                '-p', self.password,
                '-ns', self.dc_ip,
                '-c', self.collection_method,
                '--zip'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                print(f"[+] Collection successful!")
                
                # Find output file
                import glob
                zip_files = glob.glob('*.zip')
                if zip_files:
                    self.results['output_file'] = zip_files[0]
                    self.results['collection_status'] = True
                    print(f"    Output: {zip_files[0]}")
            else:
                print(f"[-] Collection failed: {result.stderr}")
                self.results['errors'].append(result.stderr)
        
        except FileNotFoundError:
            print("[-] BloodHound.py not installed")
            print("[*] Install: pip install bloodhound")
            self.results['errors'].append('BloodHound.py not found')
        except Exception as e:
            print(f"[-] Collection error: {e}")
            self.results['errors'].append(str(e))

    def collect_with_sharphound(self):
        """Use SharpHound (Windows) for collection"""
        print("[*] SharpHound collection requires Windows execution")
        print("[*] Use BloodHound.py instead for Linux")

    def run(self):
        """Run BloodHound collection"""
        print(f"[*] BloodHound Data Collection")
        print(f"[*] Domain: {self.domain}")
        print(f"[*] Method: {self.collection_method}")
        
        self.collect_with_python()
        
        return self.results


class SMBShareEnumerator:
    def __init__(self, target, username='', password='', domain=''):
        self.target = target
        self.username = username
        self.password = password
        self.domain = domain
        self.results = {
            'shares': [],
            'accessible_shares': [],
            'files': defaultdict(list),
            'permissions': {},
            'errors': []
        }

    def enumerate_shares_smbmap(self):
        """Use SMBMap for share enumeration"""
        print("[*] Enumerating shares with SMBMap...")
        
        try:
            cmd = ['smbmap']
            
            if self.username:
                cmd.extend(['-u', self.username])
            if self.password:
                cmd.extend(['-p', self.password])
            if self.domain:
                cmd.extend(['-d', self.domain])
            
            cmd.extend(['-H', self.target, '--no-banner'])
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                shares = self.parse_smbmap_output(result.stdout)
                self.results['shares'] = shares
                print(f"    Found {len(shares)} shares")
                
                # Test access
                for share in shares:
                    if share.get('permission') != 'NO ACCESS':
                        self.results['accessible_shares'].append(share)
                        print(f"    [+] {share['name']}: {share['permission']}")
            else:
                print(f"[-] SMBMap failed: {result.stderr}")
                self.results['errors'].append(result.stderr)
        
        except FileNotFoundError:
            print("[-] SMBMap not installed")
            self.results['errors'].append('SMBMap not found')
        except Exception as e:
            print(f"[-] SMBMap error: {e}")

    def parse_smbmap_output(self, output):
        """Parse SMBMap output"""
        shares = []
        
        try:
            for line in output.split('\n'):
                if line.strip() and '\\' in line:
                    parts = line.split()
                    if len(parts) >= 3:
                        share_name = parts[0].strip()
                        permission = parts[-1].strip()
                        
                        shares.append({
                            'name': share_name,
                            'permission': permission
                        })
        except:
            pass
        
        return shares

    def enumerate_shares_manual(self):
        """Manual SMB share enumeration"""
        print("[*] Enumerating shares manually...")
        
        try:
            from impacket.smbconnection import SMBConnection
            
            conn = SMBConnection(self.target, self.target)
            
            if self.username and self.password:
                conn.login(self.username, self.password, self.domain)
            else:
                conn.login('', '')  # Null session
            
            # List shares
            shares = conn.listShares()
            
            for share in shares:
                share_name = share['shi1_netname'][:-1]
                share_type = share['shi1_type']
                share_remark = share['shi1_remark'][:-1] if share['shi1_remark'] else ''
                
                # Check access
                accessible = False
                try:
                    conn.connectTree(share_name)
                    accessible = True
                except:
                    pass
                
                share_info = {
                    'name': share_name,
                    'type': share_type,
                    'remark': share_remark,
                    'accessible': accessible
                }
                
                self.results['shares'].append(share_info)
                
                if accessible:
                    self.results['accessible_shares'].append(share_info)
                    print(f"    [+] {share_name}: ACCESSIBLE")
                    
                    # List contents
                    if share_name not in ['IPC$', 'print$']:
                        self.list_share_contents(conn, share_name)
            
            conn.close()
            
        except ImportError:
            print("[-] Impacket required for manual enumeration")
        except Exception as e:
            print(f"[-] Enumeration error: {e}")

    def list_share_contents(self, conn, share_name, path='', depth=0):
        """List files in accessible share"""
        if depth > 2:
            return
        
        try:
            conn.connectTree(share_name)
            files = conn.listPath(share_name, path + '*')
            
            for file_info in files:
                file_name = file_info.get_longname()
                
                if file_name in ['.', '..']:
                    continue
                
                full_path = f"{share_name}\\{path}{file_name}"
                
                if file_info.is_directory():
                    self.results['files'][share_name].append({
                        'path': full_path,
                        'type': 'directory'
                    })
                    
                    # Recurse into directory
                    if depth < 2:
                        self.list_share_contents(
                            conn, share_name, 
                            path + file_name + '\\', 
                            depth + 1
                        )
                else:
                    file_size = file_info.get_filesize()
                    self.results['files'][share_name].append({
                        'path': full_path,
                        'type': 'file',
                        'size': file_size
                    })
                    
                    # Check for interesting files
                    if self.is_interesting_file(file_name):
                        print(f"        [!] {full_path} ({file_size} bytes)")
        
        except Exception as e:
            pass

    def is_interesting_file(self, filename):
        """Check if file is interesting"""
        interesting_extensions = [
            '.kdbx', '.ovpn', '.rdp', '.ps1', '.bat',
            '.config', '.conf', '.ini', '.xml', '.sql',
            '.bak', '.backup', '.old', '.pem', '.key',
            'passwords', 'secret', 'credential', 'account'
        ]
        
        filename_lower = filename.lower()
        return any(ext in filename_lower for ext in interesting_extensions)

    def enumerate_with_smbclient(self):
        """Use smbclient for enumeration"""
        print("[*] Enumerating with smbclient...")
        
        try:
            cmd = ['smbclient', '-L', f'//{self.target}', '-N']
            
            if self.username:
                cmd = ['smbclient', '-L', f'//{self.target}', 
                      '-U', f'{self.username}%{self.password}']
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if 'Disk' in line and '\\' not in line:
                        parts = line.split()
                        if parts:
                            share_name = parts[0].strip()
                            self.results['shares'].append({
                                'name': share_name,
                                'type': 'Disk',
                                'accessible': True
                            })
                            print(f"    [+] {share_name}")
        
        except FileNotFoundError:
            print("[-] smbclient not installed")
        except Exception as e:
            print(f"[-] smbclient error: {e}")

    def search_sensitive_files(self):
        """Search for sensitive files in shares"""
        print("[*] Searching for sensitive files...")
        
        sensitive_patterns = [
            '*password*', '*credential*', '*secret*', '*.kdbx',
            '*id_rsa*', '*.pem', '*.key', '*.ovpn',
            '*backup*', '*.bak', '*.sql', '*.dump',
            'web.config', 'app.config', '*.env',
            'unattend.xml', 'sysprep.xml', 'group.xml'
        ]
        
        for share_name in self.results['accessible_shares']:
            share_name = share_name['name']
            
            try:
                cmd = ['smbmap', '-H', self.target, '-R', share_name]
                
                if self.username:
                    cmd.extend(['-u', self.username, '-p', self.password])
                
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
                
                for pattern in sensitive_patterns:
                    if pattern.replace('*', '') in result.stdout.lower():
                        print(f"    [!] Sensitive file found in {share_name}")
                        # Extract filename
                        for line in result.stdout.split('\n'):
                            if pattern.replace('*', '') in line.lower():
                                print(f"        {line.strip()[:100]}")
            
            except Exception as e:
                continue

    def generate_report(self):
        """Generate SMB enumeration report"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'target': self.target,
            'total_shares': len(self.results['shares']),
            'accessible_shares': len(self.results['accessible_shares']),
            'shares': self.results['shares'],
            'files': {k: v[:50] for k, v in self.results['files'].items()},
            'errors': self.results['errors']
        }
        
        with open('smb_enum_report.json', 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        print(f"\n[+] SMB report saved to smb_enum_report.json")
        return report

    def run_all(self):
        """Run all enumeration methods"""
        print(f"[*] SMB Share Enumeration")
        print(f"[*] Target: {self.target}")
        print()
        
        # Try SMBMap first
        self.enumerate_shares_smbmap()
        
        # Try manual if SMBMap failed
        if not self.results['shares']:
            self.enumerate_shares_manual()
        
        # Try smbclient as fallback
        if not self.results['shares']:
            self.enumerate_with_smbclient()
        
        # Search for sensitive files
        if self.results['accessible_shares']:
            self.search_sensitive_files()
        
        return self.generate_report()


def main():
    if len(sys.argv) < 2:
        print("Usage: python ad_collector.py <command> [options]")
        print("\nCommands:")
        print("  bloodhound  - Collect BloodHound data")
        print("  smb         - Enumerate SMB shares")
        print("\nBloodHound Usage:")
        print("  python ad_collector.py bloodhound <domain> <username> <password> <dc_ip>")
        print("\nSMB Usage:")
        print("  python ad_collector.py smb <target> [username] [password] [domain]")
        sys.exit(1)
    
    command = sys.argv[1]
    
    print("[!] WARNING: Only use on systems you own or have explicit permission to test!\n")
    
    if command == 'bloodhound':
        if len(sys.argv) < 6:
            print("Usage: python ad_collector.py bloodhound <domain> <username> <password> <dc_ip>")
            sys.exit(1)
        
        domain = sys.argv[2]
        username = sys.argv[3]
        password = sys.argv[4]
        dc_ip = sys.argv[5]
        
        collector = BloodHoundCollector(domain, username, password, dc_ip)
        collector.run()
    
    elif command == 'smb':
        if len(sys.argv) < 3:
            print("Usage: python ad_collector.py smb <target> [username] [password] [domain]")
            sys.exit(1)
        
        target = sys.argv[2]
        username = sys.argv[3] if len(sys.argv) > 3 else ''
        password = sys.argv[4] if len(sys.argv) > 4 else ''
        domain = sys.argv[5] if len(sys.argv) > 5 else ''
        
        enumerator = SMBShareEnumerator(target, username, password, domain)
        enumerator.run_all()

if __name__ == "__main__":
    main()
