#!/usr/bin/env python3
"""
SMB Enumeration Tool - Shares, Users, Policies
For authorized security testing only
"""
import sys
import json
import socket
import struct
from datetime import datetime

try:
    from impacket.smbconnection import SMBConnection
    from impacket.smb import SMB_DIALECT
    from impacket.dcerpc.v5 import transport, srvs, scmr, samr, wkst, epm
    IMPACKET_AVAILABLE = True
except ImportError:
    IMPACKET_AVAILABLE = False
    print("[!] impacket not installed: pip install impacket")

class SMBEnumerator:
    def __init__(self, target, username='', password='', domain=''):
        self.target = target
        self.username = username
        self.password = password
        self.domain = domain
        self.results = {}
        
        # Common SMB shares to look for
        self.interesting_shares = [
            'ADMIN$', 'C$', 'IPC$', 'NETLOGON', 'SYSVOL',
            'Users', 'Shared', 'Public', 'Downloads', 'Backup',
            'wwwroot', 'inetpub', 'web', 'data', 'home'
        ]
    
    def check_null_session(self):
        """Check if null session is allowed"""
        print("[*] Checking null session...")
        
        try:
            conn = SMBConnection(self.target, self.target, timeout=10)
            conn.login('', '')
            
            print("[+] Null session allowed!")
            self.results['null_session'] = True
            return conn
            
        except Exception as e:
            print(f"[-] Null session not allowed: {e}")
            self.results['null_session'] = False
            return None
    
    def connect_with_creds(self):
        """Connect with provided credentials"""
        try:
            conn = SMBConnection(self.target, self.target, timeout=10)
            
            if self.username and self.password:
                conn.login(self.username, self.password, self.domain)
            else:
                conn.login('', '')
            
            return conn
            
        except Exception as e:
            print(f"[-] Connection failed: {e}")
            return None
    
    def enumerate_shares(self, conn):
        """Enumerate SMB shares"""
        print("[*] Enumerating shares...")
        
        shares = []
        
        try:
            share_list = conn.listShares()
            
            for share in share_list:
                share_name = share['shi1_netname'][:-1]  # Remove null terminator
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
                
                shares.append(share_info)
                
                if accessible:
                    print(f"    [+] {share_name} - {share_remark} (ACCESSIBLE)")
                else:
                    print(f"    [-] {share_name} - {share_remark}")
            
            self.results['shares'] = shares
            
        except Exception as e:
            print(f"[-] Share enumeration failed: {e}")
        
        return shares
    
    def enumerate_share_content(self, conn, share_name, depth=0, max_depth=2):
        """Enumerate files in a share"""
        if depth > max_depth:
            return []
        
        files = []
        
        try:
            conn.connectTree(share_name)
            file_list = conn.listPath(share_name, '*')
            
            for file_info in file_list:
                file_name = file_info.get_longname()
                
                if file_name in ['.', '..']:
                    continue
                
                is_dir = file_info.is_directory()
                
                file_data = {
                    'name': file_name,
                    'type': 'directory' if is_dir else 'file',
                    'size': file_info.get_filesize(),
                    'created': datetime.fromtimestamp(file_info.get_ctime()).isoformat(),
                    'modified': datetime.fromtimestamp(file_info.get_mtime()).isoformat()
                }
                
                files.append(file_data)
                
                # Recurse into directories
                if is_dir and depth < max_depth:
                    sub_files = self.enumerate_share_content(
                        conn, f"{share_name}\\{file_name}", depth + 1, max_depth
                    )
                    files.extend(sub_files)
            
        except Exception as e:
            pass
        
        return files
    
    def enumerate_users(self, conn):
        """Enumerate users via SAMR"""
        print("[*] Enumerating users via SAMR...")
        
        users = []
        
        try:
            # Connect to SAMR
            rpctransport = transport.SMBTransport(
                self.target, 445, r'\samr',
                self.username, self.password, self.domain
            )
            
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(samr.MSRPC_UUID_SAMR)
            
            # Enumerate users
            samr_handle = samr.hSamrConnect(dce)
            domain_handle = samr.hSamrLookupDomain(dce, samr_handle, self.domain or '')
            
            user_enum = samr.hSamrEnumerateUsersInDomain(dce, domain_handle)
            
            for user in user_enum['Buffer']['Buffer']:
                user_info = {
                    'username': user['Name'],
                    'rid': user['RelativeId']
                }
                users.append(user_info)
                print(f"    [+] {user['Name']} (RID: {user['RelativeId']})")
            
            dce.disconnect()
            
        except Exception as e:
            print(f"[-] User enumeration failed: {e}")
        
        self.results['users'] = users
        return users
    
    def enumerate_groups(self, conn):
        """Enumerate groups"""
        print("[*] Enumerating groups...")
        
        groups = []
        
        try:
            rpctransport = transport.SMBTransport(
                self.target, 445, r'\samr',
                self.username, self.password, self.domain
            )
            
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(samr.MSRPC_UUID_SAMR)
            
            samr_handle = samr.hSamrConnect(dce)
            domain_handle = samr.hSamrLookupDomain(dce, samr_handle, self.domain or '')
            
            group_enum = samr.hSamrEnumerateGroupsInDomain(dce, domain_handle)
            
            for group in group_enum['Buffer']['Buffer']:
                group_info = {
                    'name': group['Name'],
                    'rid': group['RelativeId']
                }
                groups.append(group_info)
                print(f"    [+] {group['Name']} (RID: {group['RelativeId']})")
            
            dce.disconnect()
            
        except Exception as e:
            print(f"[-] Group enumeration failed: {e}")
        
        self.results['groups'] = groups
        return groups
    
    def enumerate_password_policy(self, conn):
        """Enumerate password policy"""
        print("[*] Enumerating password policy...")
        
        policy = {}
        
        try:
            rpctransport = transport.SMBTransport(
                self.target, 445, r'\samr',
                self.username, self.password, self.domain
            )
            
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(samr.MSRPC_UUID_SAMR)
            
            samr_handle = samr.hSamrConnect(dce)
            domain_handle = samr.hSamrLookupDomain(dce, samr_handle, self.domain or '')
            
            # Get domain password policy
            policy_info = samr.hSamrQueryInformationDomain2(dce, domain_handle)
            
            policy = {
                'min_password_length': policy_info['MinPasswordLength'],
                'password_history_length': policy_info['PasswordHistoryLength'],
                'password_properties': policy_info['PasswordProperties'],
                'max_password_age': policy_info['MaxPasswordAge'],
                'min_password_age': policy_info['MinPasswordAge']
            }
            
            print(f"    Min Password Length: {policy['min_password_length']}")
            print(f"    Password History: {policy['password_history_length']}")
            print(f"    Max Password Age: {policy['max_password_age']}")
            
            dce.disconnect()
            
        except Exception as e:
            print(f"[-] Policy enumeration failed: {e}")
        
        self.results['password_policy'] = policy
        return policy
    
    def check_signing(self):
        """Check SMB signing configuration"""
        print("[*] Checking SMB signing...")
        
        signing_info = {
            'required': False,
            'enabled': False
        }
        
        try:
            # Connect without signing
            conn = SMBConnection(self.target, self.target, timeout=10)
            conn.login(self.username, self.password, self.domain)
            
            # If we connected without signing, it's not required
            signing_info['enabled'] = True
            signing_info['required'] = False
            
            print("[!] SMB signing not required (vulnerable to relay)")
            
        except Exception as e:
            if 'STATUS_ACCESS_DENIED' in str(e):
                signing_info['required'] = True
                print("[*] SMB signing required")
            else:
                print(f"[-] Could not determine signing: {e}")
        
        self.results['smb_signing'] = signing_info
        return signing_info
    
    def check_smb_version(self):
        """Check SMB version"""
        print("[*] Checking SMB version...")
        
        try:
            conn = SMBConnection(self.target, self.target, timeout=10)
            conn.login(self.username, self.password, self.domain)
            
            dialect = conn.getDialect()
            print(f"    SMB Version: {dialect}")
            
            self.results['smb_version'] = dialect
            
            # Check for SMBv1
            if 'SMBv1' in str(dialect) or 'NT LM 0.12' in str(dialect):
                print("[!] SMBv1 enabled (vulnerable to EternalBlue)")
                self.results['smbv1_enabled'] = True
            
            conn.close()
            
        except Exception as e:
            print(f"[-] Could not determine SMB version: {e}")
    
    def generate_report(self):
        """Generate enumeration report"""
        report = {
            'target': self.target,
            'timestamp': datetime.now().isoformat(),
            'smb_version': self.results.get('smb_version'),
            'smb_signing': self.results.get('smb_signing'),
            'null_session': self.results.get('null_session'),
            'shares': self.results.get('shares', []),
            'users': self.results.get('users', []),
            'groups': self.results.get('groups', []),
            'password_policy': self.results.get('password_policy', {})
        }
        
        with open(f'smb_{self.target}.json', 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n[+] Report saved to smb_{self.target}.json")
        return report
    
    def enumerate(self):
        """Run full SMB enumeration"""
        print(f"[*] Starting SMB enumeration of {self.target}")
        
        if not IMPACKET_AVAILABLE:
            print("[-] Impacket required for full enumeration")
            return None
        
        # Check SMB version
        self.check_smb_version()
        
        # Check null session
        conn = self.check_null_session()
        
        # Connect with credentials if null session failed
        if not conn and (self.username or self.password):
            conn = self.connect_with_creds()
        
        if not conn:
            print("[-] Could not establish SMB connection")
            return None
        
        # Enumerate
        self.check_signing()
        self.enumerate_shares(conn)
        self.enumerate_users(conn)
        self.enumerate_groups(conn)
        self.enumerate_password_policy(conn)
        
        # Enumerate share contents for accessible shares
        if self.results.get('shares'):
            print("[*] Enumerating share contents...")
            for share in self.results['shares']:
                if share['accessible'] and share['name'] not in ['IPC$']:
                    print(f"    Enumerating {share['name']}...")
                    content = self.enumerate_share_content(conn, share['name'])
                    if content:
                        print(f"      Found {len(content)} items")
        
        conn.close()
        
        return self.generate_report()

def main():
    if len(sys.argv) < 2:
        print("Usage: python smb_enumerator.py <target> [username] [password] [domain]")
        print("Example: python smb_enumerator.py 192.168.1.1")
        print("Example: python smb_enumerator.py 192.168.1.1 admin password WORKGROUP")
        sys.exit(1)
    
    target = sys.argv[1]
    username = sys.argv[2] if len(sys.argv) > 2 else ''
    password = sys.argv[3] if len(sys.argv) > 3 else ''
    domain = sys.argv[4] if len(sys.argv) > 4 else ''
    
    print("[!] WARNING: Only use for authorized security testing!")
    
    enumerator = SMBEnumerator(target, username, password, domain)
    enumerator.enumerate()

if __name__ == "__main__":
    main()
