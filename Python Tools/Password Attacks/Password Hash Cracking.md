# Password Hash Cracking Script

````python name=hash_cracker.py
"""
Password Hash Cracking Script
==============================
Educational demonstration of hash cracking techniques using hashlib.

IMPORTANT: This script is for educational purposes and authorized security testing only.
Unauthorized access to computer systems is illegal.

Features:
- Multiple hash algorithm support (MD5, SHA1, SHA256, SHA512)
- Dictionary attack
- Brute force attack
- Rainbow table simulation
- Salt handling
- Performance metrics
"""

import hashlib
import itertools
import string
import time
from typing import Optional, List, Tuple
import os


class HashCracker:
    """
    A comprehensive hash cracking tool supporting multiple algorithms and attack methods.
    """
    
    # Supported hash algorithms
    SUPPORTED_ALGORITHMS = {
        'md5': hashlib.md5,
        'sha1': hashlib.sha1,
        'sha256': hashlib.sha256,
        'sha512': hashlib.sha512,
        'sha224': hashlib.sha224,
        'sha384': hashlib.sha384
    }
    
    def __init__(self, hash_type: str = 'md5'):
        """
        Initialize the hash cracker with specified algorithm.
        
        Args:
            hash_type: Hash algorithm to use (md5, sha1, sha256, etc.)
        """
        if hash_type.lower() not in self.SUPPORTED_ALGORITHMS:
            raise ValueError(f"Unsupported hash type. Choose from: {list(self.SUPPORTED_ALGORITHMS.keys())}")
        
        self.hash_type = hash_type.lower()
        self.hash_function = self.SUPPORTED_ALGORITHMS[self.hash_type]
        self.attempts = 0
        self.start_time = None
    
    def hash_password(self, password: str, salt: str = '') -> str:
        """
        Generate hash for a given password with optional salt.
        
        Args:
            password: Plain text password to hash
            salt: Optional salt to add to password
            
        Returns:
            Hexadecimal hash string
        """
        # Combine password with salt
        salted_password = (salt + password).encode('utf-8')
        
        # Create hash object and return hex digest
        hash_obj = self.hash_function(salted_password)
        return hash_obj.hexdigest()
    
    def dictionary_attack(self, target_hash: str, wordlist_path: str, salt: str = '') -> Optional[str]:
        """
        Perform dictionary attack using a wordlist file.
        
        Args:
            target_hash: The hash to crack
            wordlist_path: Path to wordlist file
            salt: Optional salt used in hashing
            
        Returns:
            Cracked password or None if not found
        """
        print(f"\n[*] Starting Dictionary Attack")
        print(f"[*] Target Hash: {target_hash}")
        print(f"[*] Hash Type: {self.hash_type.upper()}")
        print(f"[*] Wordlist: {wordlist_path}")
        print(f"[*] Salt: {'Yes' if salt else 'No'}\n")
        
        self.start_time = time.time()
        self.attempts = 0
        
        try:
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as wordlist:
                for line in wordlist:
                    # Strip whitespace and try password
                    password = line.strip()
                    self.attempts += 1
                    
                    # Generate hash for current password
                    current_hash = self.hash_password(password, salt)
                    
                    # Display progress every 10000 attempts
                    if self.attempts % 10000 == 0:
                        elapsed = time.time() - self.start_time
                        rate = self.attempts / elapsed if elapsed > 0 else 0
                        print(f"[*] Attempts: {self.attempts:,} | Rate: {rate:,.0f} hash/sec | Current: {password[:20]}")
                    
                    # Check if hash matches
                    if current_hash == target_hash:
                        self._print_success(password)
                        return password
            
            self._print_failure()
            return None
            
        except FileNotFoundError:
            print(f"[!] Error: Wordlist file '{wordlist_path}' not found")
            return None
        except Exception as e:
            print(f"[!] Error during dictionary attack: {str(e)}")
            return None
    
    def brute_force_attack(self, target_hash: str, max_length: int = 4, 
                          charset: str = None, salt: str = '') -> Optional[str]:
        """
        Perform brute force attack trying all possible combinations.
        
        Args:
            target_hash: The hash to crack
            max_length: Maximum password length to try
            charset: Character set to use (default: lowercase letters + digits)
            salt: Optional salt used in hashing
            
        Returns:
            Cracked password or None if not found
        """
        # Default charset: lowercase letters and digits
        if charset is None:
            charset = string.ascii_lowercase + string.digits
        
        print(f"\n[*] Starting Brute Force Attack")
        print(f"[*] Target Hash: {target_hash}")
        print(f"[*] Hash Type: {self.hash_type.upper()}")
        print(f"[*] Max Length: {max_length}")
        print(f"[*] Character Set: {charset}")
        print(f"[*] Charset Size: {len(charset)}")
        print(f"[*] Salt: {'Yes' if salt else 'No'}\n")
        
        self.start_time = time.time()
        self.attempts = 0
        
        # Try all lengths from 1 to max_length
        for length in range(1, max_length + 1):
            print(f"[*] Trying passwords of length {length}...")
            
            # Generate all combinations of current length
            for combination in itertools.product(charset, repeat=length):
                password = ''.join(combination)
                self.attempts += 1
                
                # Generate hash for current password
                current_hash = self.hash_password(password, salt)
                
                # Display progress every 10000 attempts
                if self.attempts % 10000 == 0:
                    elapsed = time.time() - self.start_time
                    rate = self.attempts / elapsed if elapsed > 0 else 0
                    print(f"[*] Attempts: {self.attempts:,} | Rate: {rate:,.0f} hash/sec | Current: {password}")
                
                # Check if hash matches
                if current_hash == target_hash:
                    self._print_success(password)
                    return password
        
        self._print_failure()
        return None
    
    def rainbow_table_attack(self, target_hash: str, rainbow_table: dict) -> Optional[str]:
        """
        Perform rainbow table attack using pre-computed hashes.
        
        Args:
            target_hash: The hash to crack
            rainbow_table: Dictionary of {hash: password} pairs
            
        Returns:
            Cracked password or None if not found
        """
        print(f"\n[*] Starting Rainbow Table Attack")
        print(f"[*] Target Hash: {target_hash}")
        print(f"[*] Hash Type: {self.hash_type.upper()}")
        print(f"[*] Rainbow Table Size: {len(rainbow_table):,} entries\n")
        
        self.start_time = time.time()
        
        # Simple lookup in pre-computed table
        if target_hash in rainbow_table:
            password = rainbow_table[target_hash]
            elapsed = time.time() - self.start_time
            print(f"[+] SUCCESS! Password cracked in {elapsed:.4f} seconds")
            print(f"[+] Password: {password}\n")
            return password
        else:
            print(f"[-] Hash not found in rainbow table\n")
            return None
    
    def generate_rainbow_table(self, wordlist: List[str], salt: str = '') -> dict:
        """
        Generate rainbow table from a list of passwords.
        
        Args:
            wordlist: List of passwords to pre-compute
            salt: Optional salt to use
            
        Returns:
            Dictionary mapping hashes to passwords
        """
        print(f"[*] Generating rainbow table...")
        print(f"[*] Passwords to process: {len(wordlist):,}")
        
        rainbow_table = {}
        start_time = time.time()
        
        for i, password in enumerate(wordlist):
            hash_value = self.hash_password(password, salt)
            rainbow_table[hash_value] = password
            
            if (i + 1) % 10000 == 0:
                print(f"[*] Processed: {i + 1:,}/{len(wordlist):,}")
        
        elapsed = time.time() - start_time
        print(f"[+] Rainbow table generated in {elapsed:.2f} seconds")
        print(f"[+] Table size: {len(rainbow_table):,} entries\n")
        
        return rainbow_table
    
    def _print_success(self, password: str):
        """Print success message with statistics."""
        elapsed = time.time() - self.start_time
        rate = self.attempts / elapsed if elapsed > 0 else 0
        
        print(f"\n{'='*60}")
        print(f"[+] SUCCESS! Password cracked!")
        print(f"{'='*60}")
        print(f"[+] Password: {password}")
        print(f"[+] Attempts: {self.attempts:,}")
        print(f"[+] Time: {elapsed:.2f} seconds")
        print(f"[+] Rate: {rate:,.0f} hashes/second")
        print(f"{'='*60}\n")
    
    def _print_failure(self):
        """Print failure message with statistics."""
        elapsed = time.time() - self.start_time
        rate = self.attempts / elapsed if elapsed > 0 else 0
        
        print(f"\n{'='*60}")
        print(f"[-] Password not found")
        print(f"{'='*60}")
        print(f"[-] Attempts: {self.attempts:,}")
        print(f"[-] Time: {elapsed:.2f} seconds")
        print(f"[-] Rate: {rate:,.0f} hashes/second")
        print(f"{'='*60}\n")


def create_sample_wordlist(filename: str = 'wordlist.txt'):
    """
    Create a sample wordlist file for testing.
    
    Args:
        filename: Name of wordlist file to create
    """
    common_passwords = [
        'password', '123456', '12345678', 'qwerty', 'abc123',
        'monkey', '1234567', 'letmein', 'trustno1', 'dragon',
        'baseball', 'iloveyou', 'master', 'sunshine', 'ashley',
        'bailey', 'passw0rd', 'shadow', '123123', '654321',
        'superman', 'qazwsx', 'michael', 'Football', 'welcome',
        'jesus', 'ninja', 'mustang', 'password1', 'hello',
        'admin', 'secret', 'test', 'demo', 'user'
    ]
    
    with open(filename, 'w') as f:
        for password in common_passwords:
            f.write(password + '\n')
    
    print(f"[+] Sample wordlist created: {filename}")
    print(f"[+] Contains {len(common_passwords)} passwords\n")


def demo_hash_cracking():
    """
    Demonstration of various hash cracking techniques.
    """
    print("\n" + "="*70)
    print(" PASSWORD HASH CRACKING DEMONSTRATION")
    print(" Educational purposes only - Authorized testing only!")
    print("="*70 + "\n")
    
    # Create sample wordlist
    wordlist_file = 'wordlist.txt'
    create_sample_wordlist(wordlist_file)
    
    # Initialize cracker with MD5
    cracker = HashCracker('md5')
    
    # Example 1: Hash a known password
    print("\n" + "-"*70)
    print("EXAMPLE 1: Creating Password Hashes")
    print("-"*70)
    
    test_password = "password123"
    test_salt = "mysalt"
    
    hash_no_salt = cracker.hash_password(test_password)
    hash_with_salt = cracker.hash_password(test_password, test_salt)
    
    print(f"Password: {test_password}")
    print(f"MD5 Hash (no salt): {hash_no_salt}")
    print(f"MD5 Hash (with salt '{test_salt}'): {hash_with_salt}")
    
    # Example 2: Dictionary Attack
    print("\n" + "-"*70)
    print("EXAMPLE 2: Dictionary Attack")
    print("-"*70)
    
    target_password = "shadow"
    target_hash = cracker.hash_password(target_password)
    print(f"Attempting to crack hash: {target_hash}")
    
    result = cracker.dictionary_attack(target_hash, wordlist_file)
    
    # Example 3: Brute Force Attack (short password)
    print("\n" + "-"*70)
    print("EXAMPLE 3: Brute Force Attack")
    print("-"*70)
    
    short_password = "abc"
    short_hash = cracker.hash_password(short_password)
    print(f"Attempting to crack hash: {short_hash}")
    
    result = cracker.brute_force_attack(short_hash, max_length=3, 
                                       charset=string.ascii_lowercase)
    
    # Example 4: Rainbow Table Attack
    print("\n" + "-"*70)
    print("EXAMPLE 4: Rainbow Table Attack")
    print("-"*70)
    
    # Generate rainbow table from wordlist
    with open(wordlist_file, 'r') as f:
        wordlist = [line.strip() for line in f]
    
    rainbow_table = cracker.generate_rainbow_table(wordlist)
    
    # Try to crack using rainbow table
    target_password = "ninja"
    target_hash = cracker.hash_password(target_password)
    print(f"Attempting to crack hash: {target_hash}")
    
    result = cracker.rainbow_table_attack(target_hash, rainbow_table)
    
    # Example 5: Different Hash Algorithms
    print("\n" + "-"*70)
    print("EXAMPLE 5: Multiple Hash Algorithms")
    print("-"*70)
    
    test_password = "secure123"
    
    for algo in ['md5', 'sha1', 'sha256', 'sha512']:
        cracker = HashCracker(algo)
        hash_value = cracker.hash_password(test_password)
        print(f"{algo.upper():8} : {hash_value}")
    
    # Example 6: Salted Hash Cracking
    print("\n" + "-"*70)
    print("EXAMPLE 6: Cracking Salted Hash")
    print("-"*70)
    
    cracker = HashCracker('sha256')
    salt = "randomsalt123"
    target_password = "admin"
    target_hash = cracker.hash_password(target_password, salt)
    
    print(f"Attempting to crack salted hash: {target_hash}")
    print(f"Salt: {salt}")
    
    result = cracker.dictionary_attack(target_hash, wordlist_file, salt=salt)
    
    # Cleanup
    if os.path.exists(wordlist_file):
        os.remove(wordlist_file)
        print(f"\n[*] Cleaned up: {wordlist_file}")
    
    print("\n" + "="*70)
    print(" DEMONSTRATION COMPLETE")
    print("="*70 + "\n")


def interactive_mode():
    """
    Interactive mode for custom hash cracking.
    """
    print("\n" + "="*70)
    print(" INTERACTIVE HASH CRACKING MODE")
    print("="*70 + "\n")
    
    # Get hash algorithm
    print("Available algorithms:")
    for i, algo in enumerate(HashCracker.SUPPORTED_ALGORITHMS.keys(), 1):
        print(f"  {i}. {algo.upper()}")
    
    algo_choice = input("\nSelect algorithm (1-6) [default: 1]: ").strip() or "1"
    algorithms = list(HashCracker.SUPPORTED_ALGORITHMS.keys())
    hash_type = algorithms[int(algo_choice) - 1]
    
    cracker = HashCracker(hash_type)
    
    # Get target hash
    target_hash = input("\nEnter target hash to crack: ").strip()
    
    # Check if salted
    use_salt = input("Is the hash salted? (y/n) [default: n]: ").strip().lower() == 'y'
    salt = input("Enter salt: ").strip() if use_salt else ''
    
    # Choose attack method
    print("\nAttack methods:")
    print("  1. Dictionary Attack")
    print("  2. Brute Force Attack")
    print("  3. Rainbow Table Attack")
    
    method = input("\nSelect method (1-3): ").strip()
    
    if method == '1':
        wordlist_path = input("Enter wordlist path: ").strip()
        cracker.dictionary_attack(target_hash, wordlist_path, salt)
    
    elif method == '2':
        max_length = int(input("Maximum password length [default: 4]: ").strip() or "4")
        print(f"\nDefault charset: lowercase + digits")
        custom = input("Use custom charset? (y/n) [default: n]: ").strip().lower() == 'y'
        
        if custom:
            charset = input("Enter charset: ").strip()
        else:
            charset = string.ascii_lowercase + string.digits
        
        cracker.brute_force_attack(target_hash, max_length, charset, salt)
    
    elif method == '3':
        wordlist_path = input("Enter wordlist path for rainbow table: ").strip()
        with open(wordlist_path, 'r') as f:
            wordlist = [line.strip() for line in f]
        
        rainbow_table = cracker.generate_rainbow_table(wordlist, salt)
        cracker.rainbow_table_attack(target_hash, rainbow_table)


if __name__ == "__main__":
    import sys
    
    print("""
    ╔════════════════════════════════════════════════════════════════╗
    ║           PASSWORD HASH CRACKING TOOL                         ║
    ║           Educational & Security Testing Only                 ║
    ╚════════════════════════════════════════════════════════════════╝
    
    WARNING: This tool is for educational purposes and authorized
    security testing only. Unauthorized access is illegal.
    """)
    
    if len(sys.argv) > 1 and sys.argv[1] == '--interactive':
        interactive_mode()
    else:
        demo_hash_cracking()
        
        print("\nTip: Run with --interactive flag for custom hash cracking")
        print("Example: python hash_cracker.py --interactive\n")
````

---

## Code Explanation

### **Class Structure: `HashCracker`**

The script is built around a main class that handles all hash cracking operations:

#### **1. Initialization (`__init__`)**
- Sets up the hash algorithm (MD5, SHA1, SHA256, etc.)
- Initializes performance tracking variables (attempts, timing)

#### **2. Hash Generation (`hash_password`)**
```python
def hash_password(self, password: str, salt: str = '') -> str:
```
- Takes a plaintext password and optional salt
- Combines them and generates a hash using the selected algorithm
- Returns hexadecimal hash string

#### **3. Dictionary Attack (`dictionary_attack`)**
- Reads passwords from a wordlist file
- Hashes each password and compares with target hash
- Shows progress every 10,000 attempts
- Returns cracked password if found

#### **4. Brute Force Attack (`brute_force_attack`)**
- Tries all possible combinations of characters
- Starts with length 1 and goes up to `max_length`
- Uses `itertools.product()` to generate combinations
- Much slower than dictionary attack but guaranteed to find password (if within length limit)

#### **5. Rainbow Table Attack (`rainbow_table_attack`)**
- Uses pre-computed hash-to-password mappings
- Instant lookup (O(1) complexity)
- Trades storage space for speed
- Only works if hash exists in table

#### **6. Rainbow Table Generation (`generate_rainbow_table`)**
- Pre-computes hashes for a list of passwords
- Stores in dictionary for fast lookup
- One-time computational cost

### **Key Features**

1. **Multiple Hash Algorithms**: Supports MD5, SHA1, SHA256, SHA512, and more
2. **Salt Support**: Can crack both salted and unsalted hashes
3. **Performance Metrics**: Tracks attempts, time, and hashes per second
4. **Progress Indicators**: Shows real-time progress during cracking
5. **Flexible Attack Methods**: Dictionary, brute force, and rainbow table

---

## How to Run

### **Method 1: Demo Mode (Recommended for Learning)**

```bash
# Run the demonstration
python hash_cracker.py
```

This will:
- Create a sample wordlist
- Demonstrate all attack types
- Show different hash algorithms
- Clean up temporary files

**Output Example:**
```
[*] Starting Dictionary Attack
[*] Target Hash: 5f4dcc3b5aa765d61d8327deb882cf99
[*] Attempts: 10,000 | Rate: 50,000 hash/sec
[+] SUCCESS! Password cracked!
[+] Password: password
[+] Time: 0.15 seconds
```

### **Method 2: Interactive Mode**

```bash
# Run in interactive mode
python hash_cracker.py --interactive
```

This allows you to:
1. Choose hash algorithm
2. Enter target hash to crack
3. Specify salt (if any)
4. Select attack method
5. Configure attack parameters

**Interactive Example:**
```
Select algorithm (1-6): 1
Enter target hash to crack: 5f4dcc3b5aa765d61d8327deb882cf99
Is the hash salted? (y/n): n
Select method (1-3): 1
Enter wordlist path: /usr/share/wordlists/rockyou.txt
```

### **Method 3: Custom Python Script**

Create your own script using the class:

```python
from hash_cracker import HashCracker

# Initialize cracker
cracker = HashCracker('md5')

# Generate a hash
my_hash = cracker.hash_password('mypassword')
print(f"Hash: {my_hash}")

# Crack it using dictionary attack
result = cracker.dictionary_attack(my_hash, 'wordlist.txt')

if result:
    print(f"Cracked: {result}")
```

### **Method 4: Command-Line Hash Cracking**

Here's a quick one-liner example:

```python
# Create quick_crack.py
from hash_cracker import HashCracker
import sys

if len(sys.argv) < 3:
    print("Usage: python quick_crack.py <hash> <wordlist>")
    sys.exit(1)

cracker = HashCracker('md5')
cracker.dictionary_attack(sys.argv[1], sys.argv[2])
```

```bash
# Run it
python quick_crack.py 5f4dcc3b5aa765d61d8327deb882cf99 wordlist.txt
```

---

## Common Use Cases

### **1. Crack MD5 Hash**
```python
cracker = HashCracker('md5')
cracker.dictionary_attack('5f4dcc3b5aa765d61d8327deb882cf99', 'rockyou.txt')
```

### **2. Crack SHA256 with Salt**
```python
cracker = HashCracker('sha256')
cracker.dictionary_attack(
    'ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f',
    'wordlist.txt',
    salt='mysalt'
)
```

### **3. Brute Force Short Password**
```python
cracker = HashCracker('md5')
cracker.brute_force_attack(
    target_hash='900150983cd24fb0d6963f7d28e17f72',
    max_length=3,
    charset=string.ascii_lowercase
)
```

### **4. Generate and Use Rainbow Table**
```python
# Create rainbow table
with open('wordlist.txt', 'r') as f:
    passwords = [line.strip() for line in f]

rainbow = cracker.generate_rainbow_table(passwords)

# Use it for instant lookups
cracker.rainbow_table_attack(target_hash, rainbow)
```

---

## Performance Tips

1. **Dictionary Attack**: Most efficient for common passwords
2. **Rainbow Tables**: Best for repeated cracking of multiple hashes
3. **Brute Force**: Only practical for very short passwords (≤6 characters)
4. **Use PyPy**: Run with PyPy instead of CPython for 2-5x speed boost

```bash
pypy3 hash_cracker.py
```

---
