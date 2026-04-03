<<<<<<< HEAD
# Rudra-512

A high-performance 512-bit cryptographic hash function implemented in C++ with Python and Node.js bindings.

[![npm version](https://badge.fury.io/js/rudra-512-hash.svg)](https://www.npmjs.com/package/rudra-512-hash)
[![PyPI version](https://badge.fury.io/py/rudra-512-hash.svg)](https://pypi.org/project/rudra-512-hash/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

## Overview

Rudra-512 is a custom cryptographic hash function that produces a 512-bit (128-character hexadecimal) digest. Built with a focus on performance and security, it features configurable rounds, salt support, and cross-platform compatibility.

### Key Features

- ⚡ **Fast** — Native C++ core for maximum performance(but made intentionally slow to decrease speed to show down gpu attacks)
- 🔐 **512-bit output** — Strong cryptographic size
- 🔄 **High avalanche effect** (~50%)
- 🧂 **Salt support** — Optional salt parameter for added security
- 🔁 **Configurable rounds** — Adjust security/performance tradeoff (default: 32)
- 📁 **File hashing support** — Built-in file hashing capabilities
- 🖥️ **CLI tools** — Command-line interface for quick hashing
- 🌐 **Multi-language** — Available for Python and Node.js

## Installation

### Python

```bash
pip install rudra-512-hash
```

**Requirements**: Python 3.7+

### Node.js

```bash
npm install -g rudra-512-hash
```

**Requirements**: Node.js 12+

## Quick Start

### Python

```python
from rudra512 import hash_string, hash_file

# Hash a string
digest = hash_string("hello", 32)
print(digest)

# Hash with salt
salted_hash = hash_string("hello", 32, "mysalt")
print(salted_hash)

# Hash a file
file_hash = hash_file("example.txt", 32)
print(file_hash)

# File hash with salt
file_salted = hash_file("example.txt", 32, "mysalt")
print(file_salted)
```

### Node.js

```javascript
const rudra = require("rudra-512-hash");

// Hash a string
const digest = rudra.hash("hello", 32);
console.log(digest);

// Hash with salt
const saltedHash = rudra.hash("hello", 32, "mysalt");
console.log(saltedHash);

// Hash a file (manual read)
const fs = require("fs");
const fileData = fs.readFileSync("example.txt", "utf-8");
const fileHash = rudra.hash(fileData, 32);
console.log(fileHash);
```

## API Reference

### Python API

#### `hash_string(input, rounds, salt="")`

Compute hash of a string.

**Parameters:**
- `input` (str): The string to hash
- `rounds` (int): Number of compression rounds (default: 32)
- `salt` (str, optional): Optional salt for added security (default: "")

**Returns:** 128-character hexadecimal string

**Example:**
```python
from rudra512 import hash_string

# Basic hashing
hash1 = hash_string("hello", 32)

# With salt
hash2 = hash_string("hello", 32, "mysalt")

# Higher security with more rounds
hash3 = hash_string("sensitive", 64)
```

---

#### `hash_file(filepath, rounds, salt="")`

Hash a file directly from disk.

**Parameters:**
- `filepath` (str): Path to the file
- `rounds` (int): Number of compression rounds (default: 32)
- `salt` (str, optional): Optional salt for added security (default: "")

**Returns:** 128-character hexadecimal string

**Example:**
```python
from rudra512 import hash_file

# Hash a file
file_hash = hash_file("document.pdf", 32)

# Hash file with salt
salted = hash_file("document.pdf", 32, "mysalt")
```

---

### Node.js API

#### `rudra.hash(input, rounds, salt="")`

Compute hash of a string.

**Parameters:**
- `input` (string): The string to hash
- `rounds` (number): Number of compression rounds (default: 32)
- `salt` (string, optional): Optional salt for added security (default: "")

**Returns:** 128-character hexadecimal string

**Example:**
```javascript
const rudra = require("rudra-512-hash");

// Basic hashing
const hash1 = rudra.hash("hello", 32);

// With salt
const hash2 = rudra.hash("hello", 32, "mysalt");

// Higher security with more rounds
const hash3 = rudra.hash("sensitive", 64);

// Hash file content (manual read)
const fs = require("fs");
const data = fs.readFileSync("example.txt", "utf-8");
const fileHash = rudra.hash(data, 32);
```

## Command-Line Usage

Both Python and Node.js packages include a CLI tool named `rudra`.

### Basic Usage

```bash
# Hash a string
rudra hello

# Custom rounds
rudra hello --rounds 64

# With salt
rudra hello --salt abc

# Hash a file
rudra --file example.txt

# Combine options
rudra --file example.txt --rounds 64 --salt mysalt
```

### CLI Options

| Option          | Description                    |
| --------------- | ------------------------------ |
| `-r, --rounds`  | Number of rounds (default: 32) |
| `-s, --salt`    | Optional salt                  |
| `-f, --file`    | Hash a file                    |
| `-v, --version` | Show version                   |
| `-h, --help`    | Show help                      |

### Examples

```bash
# Version information
rudra -v

# Help menu
rudra -h

# Quick hash
rudra "my password"

# Secure hash with 128 rounds
rudra "sensitive data" --rounds 128

# File integrity check
rudra --file backup.zip --rounds 64 > checksum.txt
```

## Performance Considerations

### Rounds Configuration

The `rounds` parameter controls the number of compression rounds:

- **Default (32 rounds)**: Balanced security and performance
- **Lower rounds (8-16)**: Faster hashing, suitable for non-cryptographic use
- **Higher rounds (64-128)**: Increased security, slower performance

### Performance Tips

- **Python**: Use `hash_file()` for files to avoid loading entire file into memory
- **Node.js**: For large files, read in chunks if memory is limited
- More rounds = more security but slower computation
- Salt adds minimal performance overhead

## Use Cases

- **Data integrity verification**: Checksum generation for file transfers
- **Digital signatures**: Hash documents before signing
- **Password hashing**: Generate secure password digests (use high rounds)
- **Content addressing**: Create unique identifiers for data
- **Deduplication**: Identify duplicate files or data blocks
- **Blockchain applications**: Custom hash functions for consensus
- **Cache keys**: Generate deterministic cache identifiers

## Benchmark Results

| Algorithm | Frequency | Runs | Entropy | Avalanche | Speed (hashes/sec) | Collisions |
|-----------|-----------|------|---------|-----------|-------------------|------------|
| **Rudra-512** | 49.8906% | 0.500557 | 0.999997 | 50.1801% | 117,536 | None |
| SHA-512 | 49.7148% | 0.499805 | 0.999977 | 49.7192% | 459,841 | None |
| SHA3-512 | 49.8125% | 0.499873 | 0.999990 | 50.1404% | 427,948 | None |

**Test Metrics:**
- **Frequency**: Measures bit distribution balance (closer to 50% is better)
- **Runs**: Tests randomness of bit sequences (closer to 0.5 is ideal)
- **Entropy**: Measures unpredictability (closer to 1.0 is better)
- **Avalanche**: Tests output sensitivity to input changes (closer to 50% is ideal)
- **Speed**: Hash computation throughput
- **Collisions**: Hash collision detection across test inputs

## Examples

### Hash Comparison

**Python:**
```python
from rudra512 import hash_string

# Same input = same hash
hash1 = hash_string("test", 32)
hash2 = hash_string("test", 32)
assert hash1 == hash2

# Different input = different hash
hash3 = hash_string("test2", 32)
assert hash1 != hash3

# Same input, different salt = different hash
hash4 = hash_string("test", 32, "salt1")
hash5 = hash_string("test", 32, "salt2")
assert hash4 != hash5
```

**Node.js:**
```javascript
const rudra = require("rudra-512-hash");

// Same input = same hash
const hash1 = rudra.hash("test", 32);
const hash2 = rudra.hash("test", 32);
console.assert(hash1 === hash2);

// Different input = different hash
const hash3 = rudra.hash("test2", 32);
console.assert(hash1 !== hash3);

// Same input, different salt = different hash
const hash4 = rudra.hash("test", 32, "salt1");
const hash5 = rudra.hash("test", 32, "salt2");
console.assert(hash4 !== hash5);
```

### File Integrity Check

**Python:**
```python
from rudra512 import hash_file
import json

# Generate checksums
checksums = {
    "file1.txt": hash_file("file1.txt", 32),
    "file2.pdf": hash_file("file2.pdf", 32),
    "file3.zip": hash_file("file3.zip", 64, "project_salt"),
}

# Save checksums
with open("checksums.json", "w") as f:
    json.dump(checksums, f, indent=2)

# Later: verify integrity
with open("checksums.json", "r") as f:
    saved_checksums = json.load(f)

for filepath, expected_hash in saved_checksums.items():
    current_hash = hash_file(filepath, 32)
    if current_hash == expected_hash:
        print(f"✓ {filepath} - OK")
    else:
        print(f"✗ {filepath} - MODIFIED!")
```

**Node.js:**
```javascript
const rudra = require("rudra-512-hash");
const fs = require("fs");

// Generate checksums
const checksums = {};
const files = ["file1.txt", "file2.pdf", "file3.zip"];

files.forEach(file => {
    const data = fs.readFileSync(file, "utf-8");
    checksums[file] = rudra.hash(data, 32);
});

// Save checksums
fs.writeFileSync("checksums.json", JSON.stringify(checksums, null, 2));

// Later: verify integrity
const savedChecksums = JSON.parse(fs.readFileSync("checksums.json", "utf-8"));

Object.entries(savedChecksums).forEach(([filepath, expectedHash]) => {
    const data = fs.readFileSync(filepath, "utf-8");
    const currentHash = rudra.hash(data, 32);
    
    if (currentHash === expectedHash) {
        console.log(`✓ ${filepath} - OK`);
    } else {
        console.log(`✗ ${filepath} - MODIFIED!`);
    }
});
```

### Password Hashing (Example)

**Python:**
```python
from rudra512 import hash_string
import secrets

def hash_password(password, rounds=64):
    """Hash a password with a random salt"""
    salt = secrets.token_hex(16)
    hashed = hash_string(password, rounds, salt)
    # Store both hash and salt (separated by :)
    return f"{salt}:{hashed}"

def verify_password(password, stored, rounds=64):
    """Verify a password against stored hash"""
    salt, expected_hash = stored.split(":")
    actual_hash = hash_string(password, rounds, salt)
    return actual_hash == expected_hash

# Usage
password = "my_secure_password"
stored_hash = hash_password(password)
print(f"Stored: {stored_hash[:50]}...")

# Verification
is_valid = verify_password("my_secure_password", stored_hash)
print(f"Valid: {is_valid}")  # True

is_valid = verify_password("wrong_password", stored_hash)
print(f"Valid: {is_valid}")  # False
```

**Node.js:**
```javascript
const rudra = require("rudra-512-hash");
const crypto = require("crypto");

function hashPassword(password, rounds = 64) {
    // Hash a password with a random salt
    const salt = crypto.randomBytes(16).toString("hex");
    const hashed = rudra.hash(password, rounds, salt);
    // Store both hash and salt (separated by :)
    return `${salt}:${hashed}`;
}

function verifyPassword(password, stored, rounds = 64) {
    // Verify a password against stored hash
    const [salt, expectedHash] = stored.split(":");
    const actualHash = rudra.hash(password, rounds, salt);
    return actualHash === expectedHash;
}

// Usage
const password = "my_secure_password";
const storedHash = hashPassword(password);
console.log(`Stored: ${storedHash.substring(0, 50)}...`);

// Verification
console.log(`Valid: ${verifyPassword("my_secure_password", storedHash)}`);  // true
console.log(`Valid: ${verifyPassword("wrong_password", storedHash)}`);      // false
```

## Security Notes

⚠️ **Important**: Rudra-512 is a custom hash function. While designed with cryptographic principles, it has not undergone extensive third-party cryptanalysis. For production security-critical applications, consider using established standards like SHA-2, SHA-3, or BLAKE2.

**Best Practices:**
- Use 32+ rounds for cryptographic applications
- Use 64+ rounds for password hashing
- Always use salt for password hashing
- For password storage, consider dedicated KDF functions like Argon2, bcrypt, or scrypt
- Deterministic output: same input + rounds + salt = same hash
- Not yet formally audited for security vulnerabilities

## Algorithm Details

Rudra-512 uses:
- 512-bit state (8 × 64-bit words)
- Configurable compression rounds (default: 32)
- Optional salt integration
- Strong avalanche effect (~50%)
- Optimized bitwise operations
- Native C++ implementation for performance

## Development

### Building from Source

**Python:**
```bash
git clone https://github.com/Developer-Ayush/rudra512
cd rudra512
pip install -e .
```

**Node.js:**
```bash
git clone https://github.com/Developer-Ayush/rudra512
cd rudra512/bindings/js
npm install
npm link
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

### Development Setup

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run tests to ensure everything works
5. Commit your changes (`git commit -m 'Add amazing feature'`)
6. Push to the branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

```
Copyright 2024 Developer-Ayush

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

## Author

**Ayush Anand**  
📧 developerayushanand@gmail.com

## Links

- **GitHub Repository**: https://github.com/Developer-Ayush/rudra512
- **Python Package (PyPI)**: https://pypi.org/project/rudra-512-hash/
- **Node.js Package (npm)**: https://www.npmjs.com/package/rudra-512-hash
- **Issues**: https://github.com/Developer-Ayush/rudra512/issues

## Changelog

### Version 1.0.0
- Initial release
- Python package with pybind11 bindings (`hash_string`, `hash_file`)
- Node.js package with native C++ addon (`hash` function)
- Salt support for all hash functions
- Configurable rounds (default: 32)
- CLI tools for both platforms
- File hashing support
- Cross-platform compatibility

## Acknowledgments

- Built with modern C++ for performance
- Python bindings via pybind11
- Node.js native addon for maximum speed
- Strong cryptographic properties with ~50% avalanche effect

## Support

If you encounter any issues or have questions:
- Open an issue on [GitHub](https://github.com/Developer-Ayush/rudra512/issues)
- Check existing issues for solutions
- Review the API documentation above
- Contact: developerayushanand@gmail.com

---

**⭐ If you find this project useful, please consider giving it a star on GitHub!**
=======
<div align="center">

# ⚡ Rudra-512

**A modern 512-bit cryptographic hash function inspired by Lord Rudra (Shiva)**

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Language](https://img.shields.io/badge/Language-C%2B%2B17-00599C?logo=c%2B%2B)](https://isocpp.org/)
[![Output Size](https://img.shields.io/badge/Output-512--bit-orange)]()
[![Rounds](https://img.shields.io/badge/Rounds-32-red)]()
[![Collisions](https://img.shields.io/badge/Collisions%20(50k%20trials)-None%20Detected-brightgreen)]()

> *Named after Lord Rudra — the cosmic force of transformation — Rudra-512 channels that energy into a hash function built for security, entropy, and real-world resilience.*

</div>

---

## 📖 Overview

**Rudra-512** is a custom 512-bit cryptographic hash function designed from the ground up for high diffusion, strong avalanche properties, and balanced performance. It is not a SHA variant — it is an independent design using a Mixture of Experts (MoE) mixing strategy, nonlinear permutation rounds, and cross-state XOR blending.

The algorithm produces a **128-character hexadecimal digest** (512 bits / 64 bytes) from an arbitrary-length byte message. It is intentionally tuned to be fast enough for industrial use, yet computationally expensive enough to resist brute-force and preimage attacks.

---

## ✨ Features

| Property | Value |
|---|---|
| Output size | 512 bits (64 bytes / 128 hex chars) |
| Permutation rounds | 32 |
| Mixing strategy | MoE (Mixture of Experts) |
| Avalanche effect | ~49.826% (near-ideal 50%) |
| Entropy | ~1 (near-perfect) |
| Collision resistance | No collisions in 50,000 random trials |
| Throughput | ~70k hashes/sec |
| Language | C++17 |

---

## 🔬 How It Works

Rudra-512 processes messages through three core stages:

### 1. State Initialization
The input message is absorbed into an 8-element state of 64-bit words (`uint64_t`). Each byte is XORed into the state using positional bit-shifting.

```
state[i % 8] ^= (byte << ((i % 8) * 8))
```

### 2. MoE Mixing (`mix()`)
Each 64-bit word is transformed through a **Mixture of Experts**-inspired nonlinear function:
- Left rotate by 17 bits, XOR
- Right rotate by 13 bits, XOR
- XOR with right shift by 32
- Multiply by prime constant `0xd6e8feb86659fd93`
- XOR with right shift by 29
- Left rotate by 23, XOR
- Multiply by constant `0x9e3779b185ebca87`

### 3. Permutation (`permute()`)
The 8-word state is permuted over **32 rounds**, each applying:
1. `mix()` to every state word
2. Cross-XOR: `state[i] ^= state[(i+3) % 8]`
3. Round-dependent bit rotation: `rotl(state[i], (i*7 + r) % 64)`
4. Swap operations: `state[1] ↔ state[5]`, `state[2] ↔ state[6]`
5. Round constant injection: `state[0] ^= r`

---

## 📊 Benchmarks

Rudra-512 was benchmarked head-to-head against industry-standard algorithms:

## Comparison with SHA-512 and SHA3-512

| Algorithm       | Frequency (%) | Runs     | Entropy    | Avalanche (%) | Speed (hashes/sec) | Collision |
|-----------------|---------------|----------|------------|---------------|--------------------|-----------|
| **Rudra-512**   | 49.96         | 0.500166 | 1          | 49.826        | 70,140.5           | No        |
| **SHA-512**     | 50.0439       | 0.500527 | 0.999999   | 49.7192       | 215,228            | No        |
| **SHA3-512**    | 50.209        | 0.497998 | 0.999987   | 50.1404       | 224,111            | No        |

> **Note:** All benchmarks were run on a single environment at a time.  
> Rudra-512 is intentionally slower.
> While SHA-512 and SHA3-512 are faster in raw hashes/sec, **Rudra-512 maintains superior avalanche effect and entropy uniformity**, making it ideal for secure data hashing.

---

## 🛠️ Installation & Usage

### Prerequisites

- **C++17** compatible compiler (GCC 7+, Clang 5+, MSVC 2017+)
- **OpenSSL** (only required for the benchmark/comparison program)

```bash
# Ubuntu / Debian
sudo apt install libssl-dev g++

# macOS (Homebrew)
brew install openssl
```

### Clone the Repository

```bash
git clone https://github.com/Developer-Ayush/rudra-512.git
cd rudra-512
```

### Compile & Run the Interactive Hasher

```bash
g++ -std=c++17 Rudra512.cpp -o rudra512
./rudra512
```

```
Enter message: Hello, World!
Rudra512: 3f9a2c1e...  (128 hex chars)
```

### Compile & Run the Benchmark

Requires OpenSSL for SHA-512 and SHA3-512 comparisons:

```bash
g++ -std=c++17 comparison.cpp -lssl -lcrypto -o benchmark
./benchmark
```

### Use as a Library

Include `Rudra512.cpp` directly in your project and call `rudra_512()`:

```cpp
#include "Rudra512.cpp"
#include <iostream>
#include <vector>

int main() {
    std::string input = "Hello, World!";
    std::vector<uint8_t> msg(input.begin(), input.end());

    std::string hash = rudra_512(msg);
    std::cout << "Rudra-512: " << hash << std::endl;

    return 0;
}
```

**Function signature:**
```cpp
std::string rudra_512(const std::vector<uint8_t>& msg, int rounds = 32);
```

| Parameter | Type | Default | Description |
|---|---|---|---|
| `msg` | `const vector<uint8_t>&` | — | Input message as bytes |
| `rounds` | `int` | `32` | Number of permutation rounds |

### Hash a File

Rudra-512 accepts any binary data, making it straightforward to hash entire files:

```cpp
#include "Rudra512.cpp"
#include <fstream>
#include <iostream>
#include <vector>

int main() {
    // Open file in binary mode
    std::ifstream file("example.txt", std::ios::binary);
    if (!file) {
        std::cerr << "Error: could not open file.\n";
        return 1;
    }

    // Read full file contents into a byte vector
    std::vector<uint8_t> data(
        (std::istreambuf_iterator<char>(file)),
        std::istreambuf_iterator<char>()
    );

    std::string hash = rudra_512(data);
    std::cout << "Rudra-512: " << hash << std::endl;

    return 0;
}
```

> **Tip:** This works for any file type — text, images, binaries, PDFs, etc. — since the input is read as raw bytes.

---

## 📁 Repository Structure

```
rudra-512/
├── Rudra512.cpp       # Core hash function implementation
├── comparison.cpp     # Benchmark: Rudra-512 vs SHA-512 vs SHA3-512
├── LICENSE            # Apache 2.0 License
├── NOTICE             # Attribution notices
└── README.md          # This file
```

---

## 🔐 Security Considerations

- Rudra-512 is a **research and educational** hash function. It has not undergone formal cryptanalysis or third-party security audits.
- For production security-critical systems, use established standards like **SHA-512** or **SHA3-512** (NIST-approved).
- Rudra-512 is suitable for non-critical hashing, experimentation, learning, and as a foundation for further cryptographic research.
- No known collisions have been found across 50,000 random trials, but this does not constitute a formal collision-resistance proof.

---

## 🙏 Inspiration

The name and design philosophy are inspired by **Lord Rudra (Shiva)** — the Hindu deity of transformation, destruction of the old, and creation of the new. Just as Rudra transforms existence at a cosmic scale, Rudra-512 transforms arbitrary input into a fixed, unpredictable, and uniformly distributed digest — a small reflection of that infinite cosmic energy.

> *"From chaos, Rudra forges order. From data, Rudra-512 forges entropy."*

---

## 📄 License

This project is licensed under the **Apache License 2.0**. See [LICENSE](LICENSE) for details.

---

## 👤 Author

**Ayush** — [@Developer-Ayush](https://github.com/Developer-Ayush)

---

<div align="center">

⭐ If you find this project interesting, consider giving it a star!

</div>
>>>>>>> e5adf8a3dc53f57c9950b009f4b4c65f5063bc7b
