#!/usr/bin/env python3
"""
Password Hash Cracking Tool
A versatile utility for cracking password hashes using various methods including
dictionary attacks, brute force, and Hashcat integration.
"""

import hashlib
import argparse
import itertools
import string
import time
import os
import subprocess
import sys
from typing import Optional, List, Generator
from pathlib import Path
import concurrent.futures
from datetime import datetime

class HashCracker:
    """Main class for password hash cracking operations"""
    
    # Supported hash algorithms
    SUPPORTED_ALGORITHMS = {
        'md5': hashlib.md5,
        'sha1': hashlib.sha1,
        'sha224': hashlib.sha224,
        'sha256': hashlib.sha256,
        'sha384': hashlib.sha384,
        'sha512': hashlib.sha512
    }
    
    # Hashcat mode mappings (hash type to hashcat mode number)
    HASHCAT_MODES = {
        'md5': 0,
        'sha1': 100,
        'sha256': 1400,
        'sha384': 10800,
        'sha512': 1700
    }
    
    def __init__(self, hash_value: str, hash_type: str = 'md5', wordlist: Optional[str] = None):
        """
        Initialize the hash cracker
        
        Args:
            hash_value: The hash to crack
            hash_type: Type of hash (md5, sha1, sha256, etc.)
            wordlist: Path to wordlist file for dictionary attack
        """
        self.hash_value = hash_value.lower().strip()
        self.hash_type = hash_type.lower()
        self.wordlist = wordlist
        self.found_password = None
        self.attempts = 0
        self.start_time = None
        
        # Validate hash type
        if self.hash_type not in self.SUPPORTED_ALGORITHMS:
            raise ValueError(f"Unsupported hash type. Supported: {list(self.SUPPORTED_ALGORITHMS.keys())}")
        
        # Validate hash format
        self.hash_lengths = {
            'md5': 32,
            'sha1': 40,
            'sha224': 56,
            'sha256': 64,
            'sha384': 96,
            'sha512': 128
        }
        
        expected_length = self.hash_lengths.get(self.hash_type)
        if expected_length and len(self.hash_value) != expected_length:
            raise ValueError(f"Invalid {self.hash_type} hash length. Expected {expected_length} characters")
    
    def compute_hash(self, password: str) -> str:
        """Compute hash for a given password"""
        hash_func = self.SUPPORTED_ALGORITHMS[self.hash_type]
        return hash_func(password.encode('utf-8')).hexdigest()
    
    def dictionary_attack(self, max_workers: int = 4) -> Optional[str]:
        """
        Perform dictionary attack using wordlist
        
        Args:
            max_workers: Number of parallel threads
        
        Returns:
            Found password or None
        """
        if not self.wordlist or not os.path.exists(self.wordlist):
            print(f"[!] Wordlist not found: {self.wordlist}")
            return None
        
        print(f"[*] Starting dictionary attack with {max_workers} threads")
        print(f"[*] Using wordlist: {self.wordlist}")
        
        def check_password(password: str) -> Optional[str]:
            """Check if password matches the hash"""
            self.attempts += 1
            if self.attempts % 10000 == 0:
                elapsed = time.time() - self.start_time
                print(f"[*] Attempts: {self.attempts:,} | Speed: {self.attempts/elapsed:.2f} hashes/sec")
            
            if self.compute_hash(password.strip()) == self.hash_value:
                return password.strip()
            return None
        
        self.start_time = time.time()
        
        try:
            with open(self.wordlist, 'r', encoding='utf-8', errors='ignore') as f:
                passwords = f.readlines()
            
            print(f"[*] Loaded {len(passwords):,} passwords")
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                future_to_password = {executor.submit(check_password, pwd): pwd for pwd in passwords}
                
                for future in concurrent.futures.as_completed(future_to_password):
                    result = future.result()
                    if result:
                        self.found_password = result
                        return result
            
        except Exception as e:
            print(f"[!] Error during dictionary attack: {e}")
        
        return None
    
    def brute_force_attack(self, max_length: int = 4, chars: str = string.ascii_lowercase + string.digits) -> Optional[str]:
        """
        Perform brute force attack
        
        Args:
            max_length: Maximum password length to try
            chars: Character set to use
        
        Returns:
            Found password or None
        """
        print(f"[*] Starting brute force attack (max length: {max_length})")
        print(f"[*] Character set: {chars} ({len(chars)} characters)")
        
        self.start_time = time.time()
        
        for length in range(1, max_length + 1):
            print(f"[*] Trying length: {length}")
            
            for combination in itertools.product(chars, repeat=length):
                password = ''.join(combination)
                self.attempts += 1
                
                if self.attempts % 100000 == 0:
                    elapsed = time.time() - self.start_time
                    print(f"[*] Attempts: {self.attempts:,} | Current: {password} | Speed: {self.attempts/elapsed:.2f} hashes/sec")
                
                if self.compute_hash(password) == self.hash_value:
                    self.found_password = password
                    return password
        
        return None
    
    def hashcat_attack(self, hashcat_path: str = 'hashcat', attack_mode: str = 'dictionary', 
                       extra_args: Optional[List[str]] = None) -> Optional[str]:
        """
        Integrate with Hashcat for faster cracking
        
        Args:
            hashcat_path: Path to hashcat executable
            attack_mode: 'dictionary' or 'bruteforce'
            extra_args: Additional hashcat arguments
        
        Returns:
            Found password or None
        """
        if self.hash_type not in self.HASHCAT_MODES:
            print(f"[!] Hash type {self.hash_type} not supported by hashcat")
            return None
        
        # Check if hashcat is available
        try:
            subprocess.run([hashcat_path, '--version'], capture_output=True, check=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            print("[!] Hashcat not found. Please install hashcat or check the path.")
            return None
        
        # Prepare hash file
        hash_file = f"hash_{int(time.time())}.txt"
        with open(hash_file, 'w') as f:
            f.write(self.hash_value)
        
        hashcat_mode = self.HASHCAT_MODES[self.hash_type]
        
        # Build hashcat command
        cmd = [hashcat_path, '-m', str(hashcat_mode), '-a', '0' if attack_mode == 'dictionary' else '3']
        cmd.append(hash_file)
        
        if attack_mode == 'dictionary' and self.wordlist:
            cmd.append(self.wordlist)
        elif attack_mode == 'bruteforce':
            cmd.append('?a?a?a?a')  # Default mask for 4-character brute force
        
        if extra_args:
            cmd.extend(extra_args)
        
        cmd.extend(['-o', 'hashcat_output.txt', '--show'])
        
        print(f"[*] Running hashcat command: {' '.join(cmd)}")
        
        try:
            # Run hashcat
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            # Check output
            if os.path.exists('hashcat_output.txt'):
                with open('hashcat_output.txt', 'r') as f:
                    output = f.read().strip()
                    if ':' in output:
                        self.found_password = output.split(':', 1)[1]
                        return self.found_password
            
            print("[*] Hashcat output:")
            print(result.stdout)
            
        except Exception as e:
            print(f"[!] Error running hashcat: {e}")
        finally:
            # Cleanup
            for f in [hash_file, 'hashcat_output.txt']:
                if os.path.exists(f):
                    os.remove(f)
        
        return None
    
    def save_results(self, output_file: str):
        """Save cracking results to file"""
        with open(output_file, 'w') as f:
            f.write(f"Hash Cracking Results\n")
            f.write(f"{'='*40}\n")
            f.write(f"Hash: {self.hash_value}\n")
            f.write(f"Type: {self.hash_type}\n")
            f.write(f"Found: {self.found_password if self.found_password else 'Not found'}\n")
            f.write(f"Attempts: {self.attempts:,}\n")
            if self.start_time:
                elapsed = time.time() - self.start_time
                f.write(f"Time: {elapsed:.2f} seconds\n")
        
        print(f"[*] Results saved to: {output_file}")

def main():
    """Main function to handle command line interface"""
    parser = argparse.ArgumentParser(description='Password Hash Cracking Tool')
    parser.add_argument('hash', help='Hash value to crack')
    parser.add_argument('-t', '--type', default='md5', choices=HashCracker.SUPPORTED_ALGORITHMS.keys(),
                       help='Hash type (default: md5)')
    parser.add_argument('-w', '--wordlist', help='Wordlist file for dictionary attack')
    parser.add_argument('-b', '--bruteforce', type=int, metavar='MAX_LENGTH',
                       help='Perform brute force attack up to MAX_LENGTH')
    parser.add_argument('-c', '--charset', default=string.ascii_lowercase + string.digits,
                       help='Character set for brute force (default: lowercase+digits)')
    parser.add_argument('--hashcat', action='store_true', help='Use hashcat for cracking')
    parser.add_argument('--hashcat-path', default='hashcat', help='Path to hashcat executable')
    parser.add_argument('--threads', type=int, default=4, help='Number of threads for dictionary attack')
    parser.add_argument('-o', '--output', help='Output file for results')
    
    args = parser.parse_args()
    
    # Validate arguments
    if not args.wordlist and not args.bruteforce and not args.hashcat:
        parser.error("Either --wordlist, --bruteforce, or --hashcat must be specified")
    
    try:
        # Initialize cracker
        cracker = HashCracker(args.hash, args.type, args.wordlist)
        
        print(f"\n{'='*50}")
        print(f"Hash Cracking Tool")
        print(f"{'='*50}")
        print(f"Target Hash: {args.hash}")
        print(f"Hash Type: {args.type}")
        print(f"{'='*50}\n")
        
        # Perform cracking based on arguments
        found = None
        
        if args.hashcat:
            print("[*] Using hashcat for cracking...")
            attack_mode = 'dictionary' if args.wordlist else 'bruteforce'
            found = cracker.hashcat_attack(args.hashcat_path, attack_mode)
        
        elif args.wordlist:
            found = cracker.dictionary_attack(args.threads)
        
        elif args.bruteforce:
            found = cracker.brute_force_attack(args.bruteforce, args.charset)
        
        # Display results
        print(f"\n{'='*50}")
        if found:
            print(f"[+] SUCCESS! Password found: {found}")
        else:
            print("[-] Failed to crack the hash")
        print(f"[*] Total attempts: {cracker.attempts:,}")
        if cracker.start_time:
            elapsed = time.time() - cracker.start_time
            print(f"[*] Time elapsed: {elapsed:.2f} seconds")
        print(f"{'='*50}\n")
        
        # Save results if requested
        if args.output and found:
            cracker.save_results(args.output)
        
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
