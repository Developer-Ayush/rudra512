<div align="center">

# ॐ Rudra-512

**A 512-bit cryptographic hash function — inspired by Lord Shiva, built in C++**

[![npm version](https://badge.fury.io/js/rudra-512-hash.svg)](https://www.npmjs.com/package/rudra-512-hash)
[![PyPI version](https://badge.fury.io/py/rudra-512-hash.svg)](https://pypi.org/project/rudra-512-hash/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![C++](https://img.shields.io/badge/Core-C%2B%2B-blue)](https://github.com/Developer-Ayush/rudra512)
[![Python](https://img.shields.io/badge/Python-3.7%2B-yellow)](https://pypi.org/project/rudra-512-hash/)
[![Node.js](https://img.shields.io/badge/Node.js-12%2B-green)](https://www.npmjs.com/package/rudra-512-hash)

</div>

---

## Overview

Rudra-512 is a custom cryptographic hash function that produces a **512-bit (128-character hexadecimal) digest**. Named after the fierce form of Lord Shiva, it is designed for strong, reliable hashing with excellent statistical properties — and is intentionally tuned to resist GPU-based brute-force attacks.

```
Input:  "hello"
Output: a3f1c8...e92b14  (128 hex characters)
```

### Key Features

| Feature | Detail |
|---|---|
| ⚡ **Native C++ core** | High-performance implementation with Python & Node.js bindings |
| 🐢 **GPU-resistant** | Intentionally rate-limited to slow down GPU-accelerated attacks |
| 🔐 **512-bit output** | 128-character hex digest for strong collision resistance |
| 🌊 **High avalanche effect** | ~50% bit change on any input modification |
| 🧂 **Salt support** | Optional per-hash salt for added uniqueness |
| 🔁 **Configurable rounds** | Tune the security/performance tradeoff (default: 32) |
| 📁 **File hashing** | Built-in support for hashing files directly from disk |
| 🖥️ **CLI tool** | `rudra` command available for quick terminal use |
| 🌐 **Multi-language** | Available for Python and Node.js |

---

## Installation

### Python

```bash
pip install rudra-512-hash
```

> Requires Python 3.7+

### Node.js

```bash
npm install rudra-512-hash
# or globally:
npm install -g rudra-512-hash
```

> Requires Node.js 12+

---

## Quick Start

### Python

```python
from rudra512 import hash_string, hash_file

# Hash a string
digest = hash_string("hello", 32)
print(digest)
# → 128-character hex string

# Hash with salt
salted = hash_string("hello", 32, "mysalt")
print(salted)

# Hash a file
file_hash = hash_file("document.pdf", 32)
print(file_hash)

# File hash with salt
file_salted = hash_file("document.pdf", 32, "mysalt")
print(file_salted)
```

### Node.js

```javascript
const rudra = require("rudra-512-hash");

// Hash a string
const digest = rudra.hash("hello", 32);
console.log(digest);

// Hash with salt
const salted = rudra.hash("hello", 32, "mysalt");
console.log(salted);

// Hash file contents
const fs = require("fs");
const data = fs.readFileSync("document.pdf");
const fileHash = rudra.hash(data, 32);
console.log(fileHash);
```

---

## API Reference

### Python

#### `hash_string(input, rounds, salt="")`

Hashes a string and returns a 128-character hex digest.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `input` | `str` | — | The string to hash |
| `rounds` | `int` | `32` | Number of compression rounds |
| `salt` | `str` | `""` | Optional salt for added security |

```python
from rudra512 import hash_string

hash_string("hello", 32)             # basic
hash_string("hello", 32, "mysalt")   # with salt
hash_string("sensitive", 64)         # higher security
```

---

#### `hash_file(filepath, rounds, salt="")`

Hashes a file directly from disk without loading it fully into memory.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `filepath` | `str` | — | Path to the target file |
| `rounds` | `int` | `32` | Number of compression rounds |
| `salt` | `str` | `""` | Optional salt |

```python
from rudra512 import hash_file

hash_file("document.pdf", 32)
hash_file("document.pdf", 32, "mysalt")
```

---

### Node.js

#### `rudra.hash(input, rounds, salt="")`

Hashes a string (or Buffer) and returns a 128-character hex digest.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `input` | `string` | — | The data to hash |
| `rounds` | `number` | `32` | Number of compression rounds |
| `salt` | `string` | `""` | Optional salt |

```javascript
const rudra = require("rudra-512-hash");

rudra.hash("hello", 32);
rudra.hash("hello", 32, "mysalt");
rudra.hash("sensitive", 64);
```

---

## Command-Line Usage

Both packages install a `rudra` CLI tool.

```bash
# Hash a string
rudra hello

# With custom rounds
rudra hello --rounds 64

# With salt
rudra hello --salt mysecret

# Hash a file
rudra --file document.pdf

# Combined
rudra --file document.pdf --rounds 64 --salt mysecret

# File integrity checksum
rudra --file backup.zip --rounds 64 > checksum.txt
```

### CLI Options

| Option | Short | Description |
|---|---|---|
| `--rounds` | `-r` | Number of rounds (default: 32) |
| `--salt` | `-s` | Optional salt string |
| `--file` | `-f` | Hash a file instead of a string |
| `--version` | `-v` | Show version |
| `--help` | `-h` | Show help |

---

## Rounds Configuration

The `rounds` parameter is the primary knob for balancing speed and security:

| Rounds | Use Case |
|---|---|
| 8–16 | Non-cryptographic checksums, fast deduplication |
| **32 (default)** | General-purpose cryptographic hashing |
| 64 | Password hashing, sensitive data |
| 128+ | Maximum security, high-value secrets |

> ℹ️ Salt adds negligible performance overhead but significantly improves security against precomputed attacks.

---

## Benchmark Results

Tested against SHA-512 and SHA3-512 across frequency, entropy, avalanche, and speed:

| Algorithm | Frequency | Entropy | Avalanche | Speed (hashes/sec) | Collisions |
|---|---|---|---|---|---|
| **Rudra-512** | 49.89% | 0.999997 | **50.18%** | 117,536 | None |
| SHA-512 | 49.71% | 0.999977 | 49.72% | 459,841 | None |
| SHA3-512 | 49.81% | 0.999990 | 50.14% | 427,948 | None |

**Metric guide:**

- **Frequency** — Bit distribution balance. Ideal: 50%
- **Entropy** — Output unpredictability. Ideal: 1.0
- **Avalanche** — Sensitivity to input changes. Ideal: 50%
- **Speed** — Raw throughput. Rudra-512 is intentionally slower than SHA-512 to resist GPU attacks.

---

## Examples

### File Integrity Verification

**Python:**
```python
from rudra512 import hash_file
import json

files = ["file1.txt", "file2.pdf", "archive.zip"]

# Generate and save checksums
checksums = {f: hash_file(f, 32) for f in files}
with open("checksums.json", "w") as out:
    json.dump(checksums, out, indent=2)

# Verify later
with open("checksums.json") as f:
    saved = json.load(f)

for path, expected in saved.items():
    status = "✓ OK" if hash_file(path, 32) == expected else "✗ MODIFIED"
    print(f"{status} — {path}")
```

**Node.js:**
```javascript
const rudra = require("rudra-512-hash");
const fs = require("fs");

const files = ["file1.txt", "file2.pdf", "archive.zip"];

// Generate and save checksums
const checksums = Object.fromEntries(
    files.map(f => [f, rudra.hash(fs.readFileSync(f, "utf-8"), 32)])
);
fs.writeFileSync("checksums.json", JSON.stringify(checksums, null, 2));

// Verify later
const saved = JSON.parse(fs.readFileSync("checksums.json", "utf-8"));
for (const [path, expected] of Object.entries(saved)) {
    const current = rudra.hash(fs.readFileSync(path, "utf-8"), 32);
    console.log(`${current === expected ? "✓ OK" : "✗ MODIFIED"} — ${path}`);
}
```

---

### Password Hashing

**Python:**
```python
from rudra512 import hash_string
import secrets

def hash_password(password, rounds=64):
    salt = secrets.token_hex(16)
    digest = hash_string(password, rounds, salt)
    return f"{salt}:{digest}"

def verify_password(password, stored, rounds=64):
    salt, expected = stored.split(":", 1)
    return hash_string(password, rounds, salt) == expected

stored = hash_password("my_secure_password")
print(verify_password("my_secure_password", stored))  # True
print(verify_password("wrong_password", stored))      # False
```

**Node.js:**
```javascript
const rudra = require("rudra-512-hash");
const crypto = require("crypto");

function hashPassword(password, rounds = 64) {
    const salt = crypto.randomBytes(16).toString("hex");
    return `${salt}:${rudra.hash(password, rounds, salt)}`;
}

function verifyPassword(password, stored, rounds = 64) {
    const [salt, expected] = stored.split(":");
    return rudra.hash(password, rounds, salt) === expected;
}

const stored = hashPassword("my_secure_password");
console.log(verifyPassword("my_secure_password", stored)); // true
console.log(verifyPassword("wrong_password", stored));     // false
```

> ⚠️ For production password storage, prefer dedicated KDFs like **Argon2**, **bcrypt**, or **scrypt**, which are formally audited and purpose-built for this task.

---

## Security Notes

> ⚠️ **Rudra-512 is a custom hash function.** It has not undergone formal third-party cryptanalysis. For production security-critical systems, established standards like SHA-2, SHA-3, or BLAKE3 are recommended.

**Best practices:**
- Use **32+ rounds** for general cryptographic use
- Use **64+ rounds** for password hashing
- **Always salt** password hashes
- Output is fully **deterministic**: same input + rounds + salt → same hash
- Not yet formally audited for vulnerabilities

---

## Algorithm Details

Rudra-512 is built on:

- **512-bit internal state** — 8 × 64-bit words
- **Configurable compression rounds** — default: 32
- **Optional salt integration** — prepended before hashing
- **Optimized bitwise operations** — rotations, XOR mixing, modular additions
- **Native C++ implementation** — with pybind11 (Python) and N-API (Node.js) bindings

---

## Building from Source

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

---

## Contributing

Contributions are welcome! For significant changes, please open an issue first to discuss your proposal.

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Make and test your changes
4. Commit: `git commit -m 'Add your feature'`
5. Push: `git push origin feature/your-feature`
6. Open a Pull Request

---

## Use Cases

- **Data integrity** — Checksum generation for file transfers and backups
- **Digital signatures** — Hash content before signing
- **Password hashing** — Secure digest generation (use 64+ rounds + salt)
- **Content addressing** — Deterministic unique IDs for data blobs
- **Deduplication** — Identify duplicate files efficiently
- **Cache keys** — Stable, collision-resistant cache identifiers
- **Blockchain / consensus** — Custom hash functions for experimental chains

---

## Links

| Resource | URL |
|---|---|
| GitHub | https://github.com/Developer-Ayush/rudra512 |
| PyPI | https://pypi.org/project/rudra-512-hash/ |
| npm | https://www.npmjs.com/package/rudra-512-hash |
| Issues | https://github.com/Developer-Ayush/rudra512/issues |

---

## Changelog

### v1.0.0
- Initial release
- Python bindings via pybind11 (`hash_string`, `hash_file`)
- Node.js native addon via N-API (`hash`)
- Salt and configurable rounds support
- CLI tool (`rudra`) for both platforms
- File hashing support
- Cross-platform compatibility

---

## License

Licensed under the [Apache License 2.0](LICENSE).

```
Copyright 2024 Ayush Anand

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
```

---

## Author

**Ayush Anand**  
📧 developerayushanand@gmail.com  
🐙 [github.com/Developer-Ayush](https://github.com/Developer-Ayush)

---

<div align="center">

**⭐ If Rudra-512 is useful to you, consider starring the repo!**

</div>
