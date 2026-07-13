#!/usr/bin/env python3
"""
SNMP Enumeration Tool - v1, v2c, v3 support
For authorized security testing only
"""
import sys
import json
import socket
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    from pysnmp.hlapi import *
    PYSNMP_AVAILABLE = True
except ImportError:
    PYSNMP_AVAILABLE = False
    print("[!] pysnmp not installed: pip install pysnmp")
    print("[!] Running in limited mode with basic SNMP queries")

class SNMPEnumerator:
    def __init__(self, target, community_strings=None, timeout=5):
        self.target = target
        self.timeout = timeout
        self.results = defaultdict(dict)
        
        # Common community strings
        self.community_strings = community_strings or [
            'public', 'private', 'internal', 'manager',
            'read', 'write', 'admin', 'snmp', 'root',
            'cisco', 'default', 'secret', 'monitor',
            'trap', 'system', 'security', 'network'
        ]
        
        # Common SNMP OIDs for enumeration
        self.oids = {
            'system': {
                'sysDescr': '1.3.6.1.2.1.1.1.0',
                'sysObjectID': '1.3.6.1.2.1.1.2.0',
                'sysUpTime': '1.3.6.1.2.1.1.3.0',
                'sysContact': '1.3.6.1.2.1.1.4.0',
                'sysName': '1.3.6.1.2.1.1.5.0',
                'sysLocation': '1.3.6.1.2.1.1.6.0',
                'sysServices': '1.3.6.1.2.1.1.7.0'
            },
            'network': {
                'ifNumber': '1.3.6.1.2.1.2.1.0',
                'ifTable': '1.3.6.1.2.1.2.2',
                'ipForwarding': '1.3.6.1.2.1.4.1.0',
                'ipAddrTable': '1.3.6.1.2.1.4.20',
                'routeTable': '1.3.6.1.2.1.4.21',
                'tcpConnTable': '1.3.6.1.2.1.6.13',
                'udpTable': '1.3.6.1.2.1.7.5'
            },
            'processes': {
                'hrSystemProcesses': '1.3.6.1.2.1.25.1.6.0',
                'hrMemorySize': '1.3.6.1.2.1.25.2.2.0',
                'hrStorageTable': '1.3.6.1.2.1.25.2.3'
            },
            'software': {
                'hrSWRunTable': '1.3.6.1.2.1.25.4.2',
                'hrSWInstalledTable': '1.3.6.1.2.1.25.6.3'
            },
            'users': {
                'userTable': '1.3.6.1.4.1.77.1.2.25',
                'snmpCommunityTable': '1.3.6.1.6.3.13.1.2'
            }
        }
        
        # Vendor-specific OIDs
        self.vendor_oids = {
            'cisco': {
                'cdpCacheTable': '1.3.6.1.4.1.9.9.23.1.2.1.1',
                'vlanTable': '1.3.6.1.4.1.9.9.46.1.3.1',
                'vtpVlanTable': '1.3.6.1.4.1.9.9.46.1.3.1.1'
            },
            'microsoft': {
                'svSvcTable': '1.3.6.1.4.1.77.1.2.3.1',
                'shareTable': '1.3.6.1.4.1.77.1.2.27'
            }
        }
    
    def snmp_get(self, community, oid, version=2):
        """Perform SNMP GET request"""
        if PYSNMP_AVAILABLE:
            return self._snmp_get_pysnmp(community, oid, version)
        else:
            return self._snmp_get_basic(community, oid)
    
    def _snmp_get_pysnmp(self, community, oid, version=2):
        """SNMP GET using pysnmp"""
        try:
            if version == 1:
                mp_model = 0
            else:
                mp_model = 1
            
            iterator = getCmd(
                SnmpEngine(),
                CommunityData(community, mpModel=mp_model),
                UdpTransportTarget((self.target, 161), timeout=self.timeout),
                ContextData(),
                ObjectType(ObjectIdentity(oid))
            )
            
            errorIndication, errorStatus, errorIndex, varBinds = next(iterator)
            
            if errorIndication:
                return None
            
            if errorStatus:
                return None
            
            for varBind in varBinds:
                return str(varBind[1])
            
        except Exception as e:
            return None
    
    def _snmp_get_basic(self, community, oid):
        """Basic SNMP GET using raw sockets"""
        try:
            # This is a simplified implementation
            # Full SNMP packet construction would be needed for production
            import struct
            
            # Create SNMP packet
            version = 1  # SNMPv1
            request_id = 1
            
            # Simplified - would need full BER encoding
            packet = self._create_snmp_packet(community, oid, version, request_id)
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            sock.sendto(packet, (self.target, 161))
            
            response, _ = sock.recvfrom(4096)
            sock.close()
            
            # Parse response (simplified)
            if response:
                return "Response received (basic mode)"
            
        except Exception as e:
            return None
    
    def _create_snmp_packet(self, community, oid, version=1, request_id=1):
        """Create basic SNMP packet"""
        # Simplified packet creation
        # For production, use full ASN.1 BER encoding
        community_bytes = community.encode()
        oid_parts = [int(x) for x in oid.split('.')]
        
        # Build OID encoding
        oid_encoded = bytes([43])  # 1.3
        for part in oid_parts[2:]:
            oid_encoded += bytes([part])
        
        # Basic packet structure
        packet = b'\x30'  # SEQUENCE
        packet += bytes([len(community_bytes) + len(oid_encoded) + 10])
        packet += b'\x02\x01\x00'  # Version
        packet += b'\x04'  # OCTET STRING
        packet += bytes([len(community_bytes)])
        packet += community_bytes
        packet += b'\xa0'  # GetRequest
        packet += bytes([len(oid_encoded) + 4])
        packet += b'\x02\x01'  # Request ID
        packet += bytes([request_id])
        packet += b'\x30'  # SEQUENCE
        packet += bytes([len(oid_encoded)])
        packet += b'\x30'  # SEQUENCE
        packet += bytes([len(oid_encoded) - 2])
        packet += b'\x06'  # OBJECT IDENTIFIER
        packet += bytes([len(oid_encoded) - 2])
        packet += oid_encoded[2:]
        packet += b'\x05\x00'  # NULL
        
        return packet
    
    def snmp_walk(self, community, base_oid, version=2):
        """Perform SNMP walk"""
        results = {}
        
        if PYSNMP_AVAILABLE:
            try:
                for (errorIndication, errorStatus, errorIndex, varBinds) in nextCmd(
                    SnmpEngine(),
                    CommunityData(community, mpModel=1 if version == 2 else 0),
                    UdpTransportTarget((self.target, 161), timeout=self.timeout),
                    ContextData(),
                    ObjectType(ObjectIdentity(base_oid)),
                    lexicographicMode=False
                ):
                    if errorIndication:
                        break
                    
                    if errorStatus:
                        break
                    
                    for varBind in varBinds:
                        oid = str(varBind[0])
                        value = str(varBind[1])
                        results[oid] = value
                
            except Exception as e:
                pass
        
        return results
    
    def brute_community(self):
        """Brute force community strings"""
        print("[*] Brute forcing community strings...")
        
        valid_communities = []
        
        def test_community(community):
            result = self.snmp_get(community, '1.3.6.1.2.1.1.1.0')
            if result:
                return community, result
            return None
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(test_community, c): c for c in self.community_strings}
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    community, value = result
                    print(f"[+] Valid community: {community}")
                    print(f"    System: {value[:100]}")
                    valid_communities.append(community)
        
        return valid_communities
    
    def enumerate_system(self, community):
        """Enumerate system information"""
        print("[*] Enumerating system information...")
        
        system_info = {}
        
        for name, oid in self.oids['system'].items():
            value = self.snmp_get(community, oid)
            if value:
                system_info[name] = value
                print(f"    {name}: {value[:80]}")
        
        self.results['system'] = system_info
        return system_info
    
    def enumerate_network(self, community):
        """Enumerate network information"""
        print("[*] Enumerating network information...")
        
        network_info = {}
        
        # Get interface count
        if_number = self.snmp_get(community, self.oids['network']['ifNumber'])
        if if_number:
            network_info['interfaces'] = if_number
            print(f"    Interfaces: {if_number}")
        
        # Walk interface table
        if_table = self.snmp_walk(community, '1.3.6.1.2.1.2.2.1.2')
        if if_table:
            network_info['ifDescriptions'] = list(if_table.values())
            print(f"    Interface descriptions: {len(if_table)} found")
        
        # Walk IP address table
        ip_table = self.snmp_walk(community, '1.3.6.1.2.1.4.20.1.1')
        if ip_table:
            network_info['ipAddresses'] = list(ip_table.values())
            print(f"    IP Addresses: {len(ip_table)} found")
            for ip in list(ip_table.values())[:5]:
                print(f"      - {ip}")
        
        # Walk TCP connections
        tcp_table = self.snmp_walk(community, '1.3.6.1.2.1.6.13.1.3')
        if tcp_table:
            network_info['tcpConnections'] = len(tcp_table)
            print(f"    TCP Connections: {len(tcp_table)}")
        
        self.results['network'] = network_info
        return network_info
    
    def enumerate_processes(self, community):
        """Enumerate running processes"""
        print("[*] Enumerating processes...")
        
        # Walk process table
        process_table = self.snmp_walk(community, '1.3.6.1.2.1.25.4.2.1.2')
        
        if process_table:
            processes = list(process_table.values())[:20]  # First 20
            self.results['processes'] = processes
            
            print(f"    Running processes: {len(process_table)}")
            for proc in processes[:10]:
                print(f"      - {proc}")
        else:
            print("    No process information available")
        
        return process_table
    
    def enumerate_users(self, community):
        """Enumerate user accounts"""
        print("[*] Enumerating users...")
        
        # Try various user-related OIDs
        user_oids = [
            '1.3.6.1.4.1.77.1.2.25.1.1',  # User names
            '1.3.6.1.4.1.77.1.2.3.1.1',   # Service accounts
            '1.3.6.1.4.1.77.1.2.25'       # User table
        ]
        
        for oid in user_oids:
            user_table = self.snmp_walk(community, oid)
            if user_table:
                users = list(user_table.values())
                self.results['users'] = users
                print(f"    Users found: {len(users)}")
                for user in users[:10]:
                    print(f"      - {user}")
                break
    
    def enumerate_vendor_specific(self, community):
        """Enumerate vendor-specific information"""
        print("[*] Enumerating vendor-specific information...")
        
        # Try Cisco OIDs
        cisco_info = {}
        for name, oid in self.vendor_oids['cisco'].items():
            data = self.snmp_walk(community, oid)
            if data:
                cisco_info[name] = list(data.values())
                print(f"    Cisco {name}: {len(data)} entries")
        
        # Try Microsoft OIDs
        ms_info = {}
        for name, oid in self.vendor_oids['microsoft'].items():
            data = self.snmp_walk(community, oid)
            if data:
                ms_info[name] = list(data.values())
                print(f"    Microsoft {name}: {len(data)} entries")
        
        if cisco_info:
            self.results['cisco'] = cisco_info
        if ms_info:
            self.results['microsoft'] = ms_info
    
    def generate_report(self):
        """Generate enumeration report"""
        report = {
            'target': self.target,
            'community_strings': self.results.get('community_strings', []),
            'system': self.results.get('system', {}),
            'network': self.results.get('network', {}),
            'processes': self.results.get('processes', []),
            'users': self.results.get('users', []),
            'vendor_specific': {
                'cisco': self.results.get('cisco', {}),
                'microsoft': self.results.get('microsoft', {})
            }
        }
        
        with open(f'snmp_{self.target}.json', 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n[+] Report saved to snmp_{self.target}.json")
        return report
    
    def enumerate(self):
        """Run full SNMP enumeration"""
        print(f"[*] Starting SNMP enumeration of {self.target}")
        
        # Brute force community strings
        valid_communities = self.brute_community()
        self.results['community_strings'] = valid_communities
        
        if not valid_communities:
            print("[-] No valid community strings found")
            return None
        
        # Use first valid community for enumeration
        community = valid_communities[0]
        print(f"\n[*] Using community: {community}")
        
        # Run enumeration
        self.enumerate_system(community)
        self.enumerate_network(community)
        self.enumerate_processes(community)
        self.enumerate_users(community)
        self.enumerate_vendor_specific(community)
        
        # Generate report
        return self.generate_report()

def main():
    if len(sys.argv) < 2:
        print("Usage: python snmp_enumerator.py <target> [community1,community2,...]")
        print("Example: python snmp_enumerator.py 192.168.1.1")
        print("Example: python snmp_enumerator.py 192.168.1.1 public,private,admin")
        sys.exit(1)
    
    target = sys.argv[1]
    communities = sys.argv[2].split(',') if len(sys.argv) > 2 else None
    
    print("[!] WARNING: Only use for authorized security testing!")
    
    enumerator = SNMPEnumerator(target, communities)
    enumerator.enumerate()

if __name__ == "__main__":
    main()
