#!/usr/bin/env python3
"""
Advanced LDAP Enumeration Tool
For authorized security testing only
"""
import sys
import json
import re
from datetime import datetime, timedelta
from collections import defaultdict

try:
    from ldap3 import Server, Connection, ALL, NTLM, SIMPLE, SUBTREE, LEVEL, BASE
    from ldap3.core.exceptions import LDAPException, LDAPBindError
    LDAP3_AVAILABLE = True
except ImportError:
    LDAP3_AVAILABLE = False
    print("[!] ldap3 required: pip install ldap3")

class LDAPEnumerator:
    def __init__(self, server, domain, username=None, password=None, use_ssl=False):
        self.server = server
        self.domain = domain
        self.username = username
        self.password = password
        self.use_ssl = use_ssl
        self.conn = None
        
        # Build base DN
        self.base_dn = ','.join([f'DC={dc}' for dc in domain.split('.')])
        
        self.results = {
            'domain_info': {},
            'users': [],
            'groups': [],
            'computers': [],
            'service_accounts': [],
            'domain_admins': [],
            'gpos': [],
            'ous': [],
            'trusts': [],
            'interesting_acl': [],
            'vulnerabilities': []
        }
        
        # Interesting attributes to enumerate
        self.user_attributes = [
            'sAMAccountName', 'userPrincipalName', 'displayName',
            'mail', 'title', 'department', 'company',
            'memberOf', 'primaryGroupID', 'userAccountControl',
            'pwdLastSet', 'lastLogon', 'lastLogonTimestamp',
            'logonCount', 'badPwdCount', 'badPasswordTime',
            'whenCreated', 'whenChanged', 'description',
            'servicePrincipalName', 'userWorkstations',
            'adminCount', 'objectSid', 'objectGUID'
        ]
        
        self.computer_attributes = [
            'sAMAccountName', 'dNSHostName', 'operatingSystem',
            'operatingSystemVersion', 'operatingSystemServicePack',
            'servicePrincipalName', 'memberOf', 'lastLogonTimestamp',
            'whenCreated', 'description', 'location'
        ]
        
        # Sensitive group SIDs
        self.sensitive_groups = {
            'S-1-5-21domain-512': 'Domain Admins',
            'S-1-5-21domain-518': 'Schema Admins',
            'S-1-5-21domain-519': 'Enterprise Admins',
            'S-1-5-21domain-520': 'Group Policy Creator Owners',
            'S-1-5-32-544': 'Administrators',
            'S-1-5-32-548': 'Account Operators',
            'S-1-5-32-549': 'Server Operators',
            'S-1-5-32-550': 'Print Operators',
            'S-1-5-32-551': 'Backup Operators',
            'S-1-5-32-552': 'Replicators'
        }

    def connect(self):
        """Establish LDAP connection"""
        print(f"[*] Connecting to {self.server}...")
        
        try:
            if self.use_ssl:
                server = Server(self.server, port=636, use_ssl=True, get_info=ALL)
            else:
                server = Server(self.server, get_info=ALL)
            
            if self.username and self.password:
                # Authenticated connection
                self.conn = Connection(
                    server,
                    user=f'{self.domain}\\{self.username}',
                    password=self.password,
                    authentication=NTLM,
                    auto_bind=True
                )
            else:
                # Anonymous bind
                self.conn = Connection(server, auto_bind=True)
            
            print(f"[+] Connected successfully")
            print(f"    Server: {server.info}")
            
            return True
            
        except LDAPBindError as e:
            print(f"[-] Authentication failed: {e}")
            return False
        except Exception as e:
            print(f"[-] Connection error: {e}")
            return False

    def enumerate_domain_info(self):
        """Enumerate domain information"""
        print("[*] Enumerating domain information...")
        
        try:
            # Get domain controllers
            self.conn.search(
                self.base_dn,
                '(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))',
                attributes=['dNSHostName', 'operatingSystem']
            )
            
            domain_controllers = []
            for entry in self.conn.entries:
                domain_controllers.append({
                    'name': str(entry.dNSHostName),
                    'os': str(entry.operatingSystem) if entry.operatingSystem else 'Unknown'
                })
            
            # Get domain policy
            self.conn.search(
                self.base_dn,
                '(objectClass=domainDNS)',
                attributes=['lockoutDuration', 'lockOutObservationWindow',
                          'lockoutThreshold', 'maxPwdAge', 'minPwdAge',
                          'minPwdLength', 'pwdHistoryLength', 'pwdProperties']
            )
            
            policy = {}
            if self.conn.entries:
                entry = self.conn.entries[0]
                policy = {
                    'maxPwdAge': str(entry.maxPwdAge) if entry.maxPwdAge else 'Not Set',
                    'minPwdLength': str(entry.minPwdLength) if entry.minPwdLength else 'Not Set',
                    'lockoutThreshold': str(entry.lockoutThreshold) if entry.lockoutThreshold else 'Not Set',
                    'pwdHistoryLength': str(entry.pwdHistoryLength) if entry.pwdHistoryLength else 'Not Set'
                }
            
            self.results['domain_info'] = {
                'domain': self.domain,
                'base_dn': self.base_dn,
                'domain_controllers': domain_controllers,
                'password_policy': policy
            }
            
            print(f"    Domain Controllers: {len(domain_controllers)}")
            for dc in domain_controllers:
                print(f"        - {dc['name']} ({dc['os']})")
            
        except Exception as e:
            print(f"    [-] Domain info error: {e}")

    def enumerate_users(self):
        """Enumerate all domain users"""
        print("[*] Enumerating users...")
        
        try:
            self.conn.search(
                self.base_dn,
                '(objectClass=user)',
                attributes=self.user_attributes,
                search_scope=SUBTREE
            )
            
            for entry in self.conn.entries:
                user = self.parse_user_entry(entry)
                self.results['users'].append(user)
            
            # Categorize users
            for user in self.results['users']:
                # Check if service account
                if user.get('servicePrincipalName'):
                    self.results['service_accounts'].append(user)
                
                # Check if admin
                if 'adminCount' in user and user['adminCount'] == 1:
                    self.results['domain_admins'].append(user)
            
            print(f"    Total Users: {len(self.results['users'])}")
            print(f"    Service Accounts: {len(self.results['service_accounts'])}")
            print(f"    Admin Accounts: {len(self.results['domain_admins'])}")
            
            # Find privileged users
            self.find_privileged_users()
            
        except Exception as e:
            print(f"    [-] User enumeration error: {e}")

    def parse_user_entry(self, entry):
        """Parse LDAP user entry"""
        user = {}
        
        for attr in self.user_attributes:
            try:
                value = getattr(entry, attr, None)
                if value:
                    if isinstance(value, list):
                        user[attr] = [str(v) for v in value]
                    else:
                        user[attr] = str(value)
            except:
                continue
        
        # Parse UserAccountControl flags
        if 'userAccountControl' in user:
            uac = int(user['userAccountControl'])
            user['account_disabled'] = bool(uac & 2)
            user['password_never_expires'] = bool(uac & 65536)
            user['dont_require_preauth'] = bool(uac & 4194304)
        
        # Parse timestamps
        if 'pwdLastSet' in user:
            try:
                user['pwdLastSet_date'] = datetime.fromtimestamp(
                    int(user['pwdLastSet']) / 10000000 - 11644473600
                ).isoformat()
            except:
                pass
        
        if 'lastLogonTimestamp' in user:
            try:
                user['lastLogon_date'] = datetime.fromtimestamp(
                    int(user['lastLogonTimestamp']) / 10000000 - 11644473600
                ).isoformat()
            except:
                pass
        
        return user

    def find_privileged_users(self):
        """Find users with privileged group membership"""
        print("[*] Finding privileged users...")
        
        privileged_groups = [
            'Domain Admins', 'Enterprise Admins', 'Schema Admins',
            'Administrators', 'Account Operators', 'Server Operators',
            'Backup Operators', 'Print Operators'
        ]
        
        for user in self.results['users']:
            if 'memberOf' in user:
                for group_dn in user['memberOf']:
                    for priv_group in privileged_groups:
                        if priv_group.lower() in group_dn.lower():
                            if user not in self.results['domain_admins']:
                                self.results['domain_admins'].append(user)
                            break

    def enumerate_groups(self):
        """Enumerate all groups"""
        print("[*] Enumerating groups...")
        
        try:
            self.conn.search(
                self.base_dn,
                '(objectClass=group)',
                attributes=['sAMAccountName', 'member', 'memberOf',
                          'description', 'adminCount', 'groupType',
                          'whenCreated', 'managedBy'],
                search_scope=SUBTREE
            )
            
            for entry in self.conn.entries:
                group = {
                    'name': str(entry.sAMAccountName) if entry.sAMAccountName else 'Unknown',
                    'description': str(entry.description) if entry.description else '',
                    'adminCount': str(entry.adminCount) if entry.adminCount else '0',
                    'member_count': len(entry.member) if entry.member else 0,
                    'members': [str(m) for m in entry.member] if entry.member else []
                }
                
                self.results['groups'].append(group)
            
            print(f"    Total Groups: {len(self.results['groups'])}")
            
            # Find administrative groups
            admin_groups = [g for g in self.results['groups'] 
                          if g.get('adminCount') == '1']
            print(f"    Admin Groups: {len(admin_groups)}")
            
        except Exception as e:
            print(f"    [-] Group enumeration error: {e}")

    def enumerate_computers(self):
        """Enumerate domain computers"""
        print("[*] Enumerating computers...")
        
        try:
            self.conn.search(
                self.base_dn,
                '(objectClass=computer)',
                attributes=self.computer_attributes,
                search_scope=SUBTREE
            )
            
            for entry in self.conn.entries:
                computer = {}
                for attr in self.computer_attributes:
                    try:
                        value = getattr(entry, attr, None)
                        if value:
                            computer[attr] = str(value)
                    except:
                        continue
                
                self.results['computers'].append(computer)
            
            print(f"    Total Computers: {len(self.results['computers'])}")
            
            # Group by OS
            os_count = defaultdict(int)
            for comp in self.results['computers']:
                if 'operatingSystem' in comp:
                    os_count[comp['operatingSystem']] += 1
            
            for os_name, count in sorted(os_count.items()):
                print(f"        {os_name}: {count}")
            
        except Exception as e:
            print(f"    [-] Computer enumeration error: {e}")

    def enumerate_gpos(self):
        """Enumerate Group Policy Objects"""
        print("[*] Enumerating GPOs...")
        
        try:
            self.conn.search(
                self.base_dn,
                '(objectClass=groupPolicyContainer)',
                attributes=['displayName', 'gPCFileSysPath', 'whenCreated',
                          'whenChanged', 'gPCMachineExtensionNames',
                          'gPCUserExtensionNames'],
                search_scope=SUBTREE
            )
            
            for entry in self.conn.entries:
                gpo = {
                    'name': str(entry.displayName) if entry.displayName else 'Unknown',
                    'path': str(entry.gPCFileSysPath) if entry.gPCFileSysPath else '',
                    'created': str(entry.whenCreated) if entry.whenCreated else '',
                    'modified': str(entry.whenChanged) if entry.whenChanged else ''
                }
                
                self.results['gpos'].append(gpo)
            
            print(f"    Total GPOs: {len(self.results['gpos'])}")
            
        except Exception as e:
            print(f"    [-] GPO enumeration error: {e}")

    def enumerate_ous(self):
        """Enumerate Organizational Units"""
        print("[*] Enumerating OUs...")
        
        try:
            self.conn.search(
                self.base_dn,
                '(objectClass=organizationalUnit)',
                attributes=['ou', 'name', 'description', 'whenCreated'],
                search_scope=SUBTREE
            )
            
            for entry in self.conn.entries:
                ou = {
                    'name': str(entry.ou) if entry.ou else str(entry.name),
                    'description': str(entry.description) if entry.description else '',
                    'created': str(entry.whenCreated) if entry.whenCreated else ''
                }
                
                self.results['ous'].append(ou)
            
            print(f"    Total OUs: {len(self.results['ous'])}")
            
        except Exception as e:
            print(f"    [-] OU enumeration error: {e}")

    def enumerate_trusts(self):
        """Enumerate domain trusts"""
        print("[*] Enumerating domain trusts...")
        
        try:
            self.conn.search(
                self.base_dn,
                '(objectClass=trustedDomain)',
                attributes=['trustPartner', 'trustDirection',
                          'trustType', 'trustAttributes',
                          'flatName', 'whenCreated'],
                search_scope=SUBTREE
            )
            
            for entry in self.conn.entries:
                trust = {
                    'partner': str(entry.trustPartner) if entry.trustPartner else 'Unknown',
                    'direction': str(entry.trustDirection) if entry.trustDirection else '',
                    'type': str(entry.trustType) if entry.trustType else '',
                    'attributes': str(entry.trustAttributes) if entry.trustAttributes else ''
                }
                
                self.results['trusts'].append(trust)
            
            print(f"    Total Trusts: {len(self.results['trusts'])}")
            
            for trust in self.results['trusts']:
                print(f"        - {trust['partner']} (Direction: {trust['direction']})")
            
        except Exception as e:
            print(f"    [-] Trust enumeration error: {e}")

    def find_delegation_issues(self):
        """Find unconstrained delegation issues"""
        print("[*] Checking delegation...")
        
        try:
            # Find computers with unconstrained delegation
            self.conn.search(
                self.base_dn,
                '(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))',
                attributes=['dNSHostName', 'sAMAccountName'],
                search_scope=SUBTREE
            )
            
            for entry in self.conn.entries:
                self.results['vulnerabilities'].append({
                    'type': 'unconstrained_delegation',
                    'severity': 'High',
                    'computer': str(entry.dNSHostName),
                    'description': 'Computer configured for unconstrained delegation'
                })
                print(f"    [!] Unconstrained Delegation: {entry.dNSHostName}")
            
        except Exception as e:
            print(f"    [-] Delegation check error: {e}")

    def find_asrep_roastable(self):
        """Find users without Kerberos pre-authentication"""
        print("[*] Finding AS-REP roastable users...")
        
        try:
            self.conn.search(
                self.base_dn,
                '(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))',
                attributes=['sAMAccountName', 'userPrincipalName'],
                search_scope=SUBTREE
            )
            
            for entry in self.conn.entries:
                self.results['vulnerabilities'].append({
                    'type': 'asrep_roastable',
                    'severity': 'Medium',
                    'user': str(entry.sAMAccountName),
                    'description': 'User does not require Kerberos pre-authentication'
                })
                print(f"    [!] AS-REP Roastable: {entry.sAMAccountName}")
            
        except Exception as e:
            print(f"    [-] AS-REP check error: {e}")

    def generate_report(self):
        """Generate comprehensive LDAP report"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'domain': self.domain,
            'server': self.server,
            'domain_info': self.results['domain_info'],
            'summary': {
                'total_users': len(self.results['users']),
                'service_accounts': len(self.results['service_accounts']),
                'domain_admins': len(self.results['domain_admins']),
                'total_groups': len(self.results['groups']),
                'total_computers': len(self.results['computers']),
                'total_gpos': len(self.results['gpos']),
                'total_ous': len(self.results['ous']),
                'total_trusts': len(self.results['trusts']),
                'vulnerabilities': len(self.results['vulnerabilities'])
            },
            'vulnerabilities': self.results['vulnerabilities'],
            'users': self.results['users'][:100],  # Limit for report size
            'groups': self.results['groups'][:50],
            'computers': self.results['computers'][:50],
            'gpos': self.results['gpos'],
            'trusts': self.results['trusts']
        }
        
        # Save full results separately
        with open('ldap_enum_report.json', 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        # Save user list
        with open('domain_users.txt', 'w') as f:
            for user in self.results['users']:
                if 'sAMAccountName' in user:
                    f.write(f"{user['sAMAccountName']}\n")
        
        # Save computer list
        with open('domain_computers.txt', 'w') as f:
            for comp in self.results['computers']:
                if 'dNSHostName' in comp:
                    f.write(f"{comp['dNSHostName']}\n")
        
        print(f"\n[+] Reports saved:")
        print(f"    - ldap_enum_report.json")
        print(f"    - domain_users.txt")
        print(f"    - domain_computers.txt")
        
        return report

    def run_all(self):
        """Run complete LDAP enumeration"""
        print(f"[*] Starting LDAP Enumeration")
        print(f"[*] Domain: {self.domain}")
        print(f"[*] Server: {self.server}")
        print()
        
        if not LDAP3_AVAILABLE:
            print("[-] ldap3 required!")
            return None
        
        if not self.connect():
            return None
        
        # Run enumeration
        self.enumerate_domain_info()
        self.enumerate_users()
        self.enumerate_groups()
        self.enumerate_computers()
        self.enumerate_gpos()
        self.enumerate_ous()
        self.enumerate_trusts()
        
        # Security checks
        self.find_delegation_issues()
        self.find_asrep_roastable()
        
        # Generate report
        return self.generate_report()

def main():
    if len(sys.argv) < 3:
        print("Usage: python ldap_enumerator.py <domain> <dc_ip> [username] [password]")
        print("\nExamples:")
        print("  python ldap_enumerator.py domain.local 192.168.1.10")
        print("  python ldap_enumerator.py domain.local 192.168.1.10 user pass")
        sys.exit(1)
    
    domain = sys.argv[1]
    server = sys.argv[2]
    username = sys.argv[3] if len(sys.argv) > 3 else None
    password = sys.argv[4] if len(sys.argv) > 4 else None
    
    print("[!] WARNING: Only use on systems you own or have explicit permission to test!\n")
    
    enumerator = LDAPEnumerator(server, domain, username, password)
    enumerator.run_all()

if __name__ == "__main__":
    main()
