<div align="center">

# ॐ Rudra-512

**A 512-bit cryptographic hash function — inspired by Lord Shiva, built in C++**

[![npm version](https://badge.fury.io/js/rudra-512-hash.svg)](https://www.npmjs.com/package/rudra-512-hash)
[![Live Demo](https://img.shields.io/badge/Web-Visualizer-purple)](https://rudra-512-hash.vercel.app/)
[![C++](https://img.shields.io/badge/Core-C%2B%2B17-blue)](https://github.com/Developer-Ayush/rudra512)
[![PyPI version](https://badge.fury.io/py/rudra-512-hash.svg)](https://pypi.org/project/rudra-512-hash/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)


</div>

---

## Overview

Rudra-512 is a custom cryptographic hash function that produces a **512-bit (128-character hexadecimal) digest**. Named after the fierce form of Lord Shiva, it is designed for strong, reliable hashing with excellent statistical properties — and is intentionally tunable to resist GPU-based brute-force attacks via configurable rounds.

```
Input:  "hello"
Output: a3f1c8...e92b14  (128 hex characters, always)
```

---

## 🌐 Web Demo

A simple interactive visualizer to see how Rudra-512 works step by step.

🔗 **Live Demo:** [Rudra](https://rudra-512-hash.vercel.app)

- Step-by-step rounds
- Internal state updates
- Bit-level changes (avalanche effect)

---

## Key Features

| Feature | Detail |
|---|---|
| ⚡ **Native C++ core** | High-performance implementation with Python & Node.js bindings |
| 🐢 **GPU-resistant** | Configurable rounds let you dial up resistance to GPU-accelerated brute-force |
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

> Requires Python 3.8+

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

# Hash a string (rounds defaults to 32)
digest = hash_string("hello")
print(digest)
# → 128-character hex string

# Hash with custom rounds
digest64 = hash_string("hello", 64)

# Hash with salt
salted = hash_string("hello", salt="mysalt")
print(salted)

# Hash a file
file_hash = hash_file("document.pdf")
print(file_hash)

# File hash with salt and custom rounds
file_salted = hash_file("document.pdf", 64, "mysalt")
print(file_salted)
```

### Node.js

```javascript
const rudra = require("rudra-512-hash");

// Hash a string (rounds defaults to 32)
const digest = rudra.hash("hello");
console.log(digest);

// Hash with custom rounds
const digest64 = rudra.hash("hello", 64);

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

#### `hash_string(input, rounds=32, salt="")`

Hashes a string and returns a 128-character hex digest.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `input` | `str` | — | The string to hash |
| `rounds` | `int` | `32` | Number of compression rounds |
| `salt` | `str` | `""` | Optional salt for added security |

**Returns:** `str` — 128-character hexadecimal string

```python
from rudra512 import hash_string

hash_string("hello")                   # default 32 rounds
hash_string("hello", 64)              # higher security
hash_string("hello", salt="mysalt")   # with salt
hash_string("hello", 64, "mysalt")    # rounds + salt
```

---

#### `hash_file(filepath, rounds=32, salt="")`

Hashes a file directly from disk. Memory-efficient — does not load the entire file at once.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `filepath` | `str` | — | Path to the target file |
| `rounds` | `int` | `32` | Number of compression rounds |
| `salt` | `str` | `""` | Optional salt |

**Returns:** `str` — 128-character hexadecimal string

```python
from rudra512 import hash_file

hash_file("document.pdf")               # default rounds
hash_file("document.pdf", 64, "salt")  # rounds + salt
```

---

### Node.js

#### `rudra.hash(input, rounds=32, salt="")`

Hashes a string or Buffer and returns a 128-character hex digest.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `input` | `string` | — | The data to hash |
| `rounds` | `number` | `32` | Number of compression rounds |
| `salt` | `string` | `""` | Optional salt |

**Returns:** `string` — 128-character hexadecimal string

```javascript
const rudra = require("rudra-512-hash");

rudra.hash("hello");                    // default rounds
rudra.hash("hello", 64);               // higher security
rudra.hash("hello", 32, "mysalt");     // with salt
```

---

## Command-Line Usage

Both packages install a `rudra` CLI tool.

```bash
# Hash a string (default 32 rounds)
rudra hello

# Custom rounds
rudra hello --rounds 64

# With salt
rudra hello --salt mysecret

# Hash a file
rudra --file document.pdf

# Combined options
rudra --file document.pdf --rounds 64 --salt mysecret
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

The `rounds` parameter is the primary knob for tuning Rudra-512 between raw speed and GPU-brute-force resistance.

**How it works:** Each round adds one full compression pass over the internal 512-bit state. More rounds = more CPU work per hash. For a legitimate user hashing one password, the difference between 32 and 128 rounds is milliseconds. For a GPU cluster attempting billions of guesses per second, it's the difference between a feasible attack and an infeasible one.

> **Rule of thumb:** Use fewer rounds for speed-critical, non-secret data. Use more rounds wherever a hash could be attacked offline (passwords, secrets, credentials).

### Quick Reference

| Rounds | Label | Approx. Speed | GPU Brute-Force Risk | Recommended For |
|---|---|---|---|---|
| **4–8** | Ultra Fast | ~800K hashes/sec | 🔴 Very High | Non-security checksums only |
| **16–24** | Fast | ~350K hashes/sec | 🟠 High | Non-critical integrity checks |
| **32** ⭐ | **Default** | ~117K hashes/sec | 🟡 Moderate | General-purpose cryptographic hashing |
| **64** | High Security | ~58K hashes/sec | 🟢 Low | Passwords, sensitive credentials |
| **128+** | Maximum | ~29K hashes/sec | 🟢 Very Low | High-value secrets, maximum GPU resistance |

> ⭐ Default. Speed figures are approximate and vary by CPU, OS, and compiler.

---

### 4–8 Rounds — Ultra Fast

Best for non-security use cases where you need speed and collision resistance, but a brute-force attack against the hash is not a concern (because there is nothing secret to recover).

**When to use:**

- **Cache busting** — Generate fast cache keys for CDN assets or API responses where collision risk is negligible.
- **Content deduplication** — Identify duplicate files or blobs in a local content-addressable store (images, chunks, logs).
- **Build artifact fingerprinting** — Tag compiled output files with fast fingerprints during development CI builds.
- **Unit test fixtures** — Hash test vector inputs to detect accidental fixture mutations without cryptographic guarantees.
- **Log aggregation** — Fingerprint log lines to group repeated errors; collision risk is acceptable here.

```python
# Fast deduplication — speed matters, not GPU resistance
digest = hash_string(file_contents, 8)
```

```javascript
const digest = rudra.hash(fileContents, 8);
```

---

### 16–24 Rounds — Fast

A step up from ultra-fast. Good for integrity checks where you want more collision confidence than 8 rounds provides, but still don't need cryptographic GPU resistance.

**When to use:**

- **File deduplication** — Identify and remove duplicate files in local storage, backups, or media libraries.
- **URL shortener tokens** — Hash long URLs to stable short tokens without needing cryptographic strength.
- **Message deduplication** — Detect duplicate messages in queues (Kafka, SQS) by fingerprinting payloads.
- **Peer ID generation** — Generate stable peer identifiers in P2P networks from public keys.
- **Docker layer IDs** — Content-address container layers for efficient distribution.
- **CDN cache busting** — Append a short hash to asset URLs to bust CDN cache on deploy.

```python
# Non-critical integrity — faster than default, safer than 8 rounds
digest = hash_string(payload, 16)
```

```javascript
const token = rudra.hash(longUrl, 16).slice(0, 10);
```

---

### 32 Rounds — Default ⭐

The default. Balances strong cryptographic properties with practical throughput. Suitable for any general hashing need where you don't specifically need password-level GPU resistance.

**When to use:**

- **File integrity verification** — Verify downloads, backups, and file transfers haven't been tampered with or corrupted.
- **Digital signatures** — Hash document content before RSA/ECDSA signing in document authenticity workflows.
- **API key hashing** — Hash random secrets to produce stable, non-reversible API tokens stored in your database.
- **Content addressing** — Assign deterministic IDs to data blobs in content-addressable storage systems.
- **Blockchain / consensus** — Custom hash function for experimental chains, Merkle trees, and proof-of-work systems.
- **Commit fingerprinting** — Hash source code snapshots or config files for audit logs and change detection.
- **CSRF tokens** — Deterministic tokens tied to session and time window.
- **Audit log sealing** — Chain log entries by hashing each entry with the previous hash so tampering is detectable.
- **Transaction fingerprinting** — Unique transaction IDs for double-spend detection in payment or ledger systems.
- **Config change detection** — Fingerprint config files in CI/CD pipelines to detect unexpected changes.

```python
# General-purpose — the right default for most use cases
digest = hash_string(data, 32)
file_digest = hash_file("document.pdf", 32)
```

```javascript
const digest = rudra.hash(data, 32);
```

---

### 64 Rounds — High Security

Doubles the work per hash compared to the default. At this level, GPU-based offline brute-force attacks become significantly more expensive. Use whenever a hash could be attacked offline by someone who obtains your database or storage.

**When to use:**

- **Password hashing** — Hash user passwords with a per-user salt before storing in your database. (See Password Hashing example below.)
- **Session token derivation** — Derive session identifiers from user credentials + entropy that resist offline cracking if the session store leaks.
- **PII tokenization** — Irreversibly tokenize emails, SSNs, or phone numbers for pseudonymous analytics without storing raw PII.
- **Financial audit trails** — Hash transaction records with a salt for tamper-evident, non-reversible audit logs.
- **Secret derivation** — Derive sub-keys or HMAC-like secrets from a master key without exposing the master.
- **Recovery code hashing** — Hash one-time recovery codes before storing so they can't be recovered from the DB.
- **Email unsubscribe links** — Stateless one-click links derived from user ID + secret that resist forgery.

```python
# High security — GPU brute-force is now significantly harder
digest = hash_string(password, 64, salt=user_salt)
```

```javascript
const digest = rudra.hash(password, 64, userSalt);
```

---

### 128+ Rounds — Maximum

At 128+ rounds, each hash is slow enough that offline GPU attacks become practically infeasible for any normally motivated attacker. Use for your highest-value secrets where latency is acceptable.

**When to use:**

- **Root key protection** — Protect master encryption keys or certificate authority secrets at rest.
- **High-value credential hashing** — Admin passwords, hardware security module seeds, or recovery master keys.
- **Air-gapped systems** — Hash secrets on air-gapped machines where brute-force resistance justifies latency.
- **Cryptanalysis research** — Deliberately slow hashing for academic security margin studies.
- **Escrow / vault secrets** — Long-lived secrets that will never be rotated and must survive future hardware advances.

```python
# Maximum resistance — use where latency is acceptable and the secret is critical
digest = hash_string(master_secret, 128, salt=hsm_salt)
```

```javascript
const digest = rudra.hash(masterSecret, 128, hsmSalt);
```

---

## Benchmark Results

> ⚠️ **Note:** Results below were recorded on a single system at a specific point in time. Performance varies by CPU, OS, system load, and compiler version. These numbers are provided for relative comparison only — run `benchmark.py` to get results for your own environment.

| Algorithm |Runs| Frequency | Entropy | Avalanche | Speed (hashes/sec) | Collisions |
|-----------|----|-----------|---------|-----------|----------------------|----------|
| **Rudra-512** |**0.500270**| **50.0254%** | **1.000000** | **50.1301%** | **161,973** | **None** |
| SHA-512 |0.502109| 49.7373% | 0.999980 | 49.7192% | 860,149 | None |
| SHA3-512 |0.496582| 49.6582% | 1.000000 | 50.1404% | 653,170 | None |

**Metric guide:**

- **Frequency** — Bit distribution balance. Closer to 50% is better.
- **Entropy** — Output unpredictability. Closer to 1.0 is better.
- **Avalanche** — How much the output changes when one input bit flips. Ideal: 50%.
- **Speed** — Raw throughput. Rudra-512 at 32 rounds is intentionally slower than SHA-512; increase rounds further to widen the gap against GPU attackers.

To reproduce on your machine:

```bash
python benchmark.py
```

---

## Use Cases

Rudra-512 covers a wide range of hashing scenarios. The recommended round count is noted for each.

### 🔐 Security & Authentication

| Use Case | Rounds | Notes |
|---|---|---|
| **Password storage** | 64 | Always combine with a per-user salt. 64+ rounds makes GPU cracking impractical. |
| **Session token derivation** | 64 | Derive tokens from credentials + entropy; resistant to offline cracking if session store leaks. |
| **API key hashing** | 32 | Store only the hash; compare on each request. No GPU risk since keys are random. |
| **PII tokenization** | 64 | Irreversibly pseudonymize emails, SSNs, or phone numbers for analytics. |
| **Recovery code hashing** | 64 | Hash one-time recovery/backup codes before storing so they can't be recovered from the DB. |
| **Secret derivation** | 64 | Derive sub-keys or HMAC-like secrets from a master key. |
| **CSRF tokens** | 32 | Deterministic tokens tied to session ID and time window. |

---

### 📁 File & Data Integrity

| Use Case | Rounds | Notes |
|---|---|---|
| **File checksum / verification** | 32 | Verify files after download, transfer, or backup restoration. |
| **File deduplication** | 8–16 | Identify duplicate files fast — cryptographic GPU resistance is not needed. |
| **Tamper detection** | 32 | Store hashes of critical records alongside them for audit and integrity checking. |
| **Config change detection** | 32 | Fingerprint config files in CI/CD pipelines to alert on unexpected changes. |
| **Audit log sealing** | 32 | Chain each log entry hash with the previous one so retroactive tampering is detectable. |
| **Build artifact fingerprinting** | 8 | Tag compiled output files with fast fingerprints during development builds. |

---

### ⛓️ Blockchain & Distributed Systems

| Use Case | Rounds | Notes |
|---|---|---|
| **Merkle tree nodes** | 32 | Combine child hashes to build tamper-evident tree structures. |
| **Block header hashing** | 32 | Hash block metadata for experimental proof-of-work or proof-of-authority chains. |
| **Transaction fingerprinting** | 32 | Unique transaction IDs for double-spend detection in ledger systems. |
| **Peer ID generation** | 16 | Generate stable peer identifiers in P2P networks from public keys. |
| **Commit / state hashing** | 32 | Hash VM state or contract storage roots for state channel proofs. |

---

### 🏗️ Infrastructure & DevOps

| Use Case | Rounds | Notes |
|---|---|---|
| **Build cache keys** | 8 | Fast cache invalidation in CI — no security requirement, pure speed. |
| **Docker / OCI layer IDs** | 16 | Content-address container layers for efficient distribution and deduplication. |
| **CDN cache busting** | 8 | Append short hash to asset URLs (JS, CSS) to bust CDN cache on every deploy. |
| **Deployment verification** | 32 | Hash deployment packages and compare against signed manifests before execution. |
| **Secret scanning baseline** | 32 | Hash known-safe file states so future scans can quickly detect new sensitive content. |

---

### 🧩 Application Features

| Use Case | Rounds | Notes |
|---|---|---|
| **URL shortener tokens** | 16 | Short, stable tokens from long URLs — speed over security. |
| **Email unsubscribe links** | 64 | Stateless one-click links derived from user ID + secret; resistant to forgery. |
| **Message deduplication** | 8–16 | Fingerprint queue messages (Kafka, SQS, RabbitMQ) to detect and drop duplicates. |
| **Content addressing** | 32 | Deterministic unique IDs for media blobs, documents, or data chunks. |
| **Avatar / Identicon generation** | 16 | Hash a username or email to a stable value that drives a deterministic visual. |
| **Rate limit keys** | 16 | Hash IP + endpoint into a stable bucket key for rate limiter lookups. |
| **Feature flag hashing** | 16 | Hash user ID to a stable 0–100 bucket for gradual feature rollouts. |

---

### 🔬 Research & Experimental

| Use Case | Rounds | Notes |
|---|---|---|
| **Cryptanalysis / security research** | 128+ | Deliberately slow hashing for studying security margins. |
| **Custom proof-of-work** | 32–64 | Tunable difficulty via rounds; increase rounds to raise the cost of a valid proof. |
| **Educational hash demos** | 8–32 | Visualize avalanche effect, entropy, and state evolution at low cost. |
| **Fuzzing harness fingerprinting** | 8 | Ultra-fast corpus deduplication in coverage-guided fuzzers. |

---

## Examples

### File Integrity Verification

**Python:**

```python
from rudra512 import hash_file
import json

files = ["file1.txt", "file2.pdf", "archive.zip"]

# Generate and save checksums (32 rounds — default, good for integrity)
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

// Generate and save checksums (32 rounds)
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

Use **64 rounds** minimum for passwords. Each user gets a unique random salt so that identical passwords produce different digests, and precomputed rainbow tables are useless.

**Python:**

```python
from rudra512 import hash_string
import secrets

def hash_password(password, rounds=64):
    salt = secrets.token_hex(16)          # 32-char random salt per user
    digest = hash_string(password, rounds, salt)
    return f"{salt}:{digest}"             # store both together

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

> ⚠️ For production password storage, prefer dedicated KDFs like **Argon2**, **bcrypt**, or **scrypt** — they are formally audited and purpose-built for this use case.

---

### Fast Deduplication (Low Rounds)

When you only need to identify duplicate content and there is no secret to recover, low rounds give you dramatically higher throughput.

**Python:**

```python
from rudra512 import hash_file
import os

def find_duplicates(directory, rounds=8):
    seen = {}
    duplicates = []
    for filename in os.listdir(directory):
        path = os.path.join(directory, filename)
        digest = hash_file(path, rounds)   # 8 rounds — fast, no GPU risk needed
        if digest in seen:
            duplicates.append((path, seen[digest]))
        else:
            seen[digest] = path
    return duplicates

dupes = find_duplicates("./images")
for dup, original in dupes:
    print(f"Duplicate: {dup}  (same as {original})")
```

---

### Merkle Tree (Blockchain / Distributed Systems)

**Python:**

```python
from rudra512 import hash_string

def merkle_root(leaves, rounds=32):
    """Build a Merkle root from a list of leaf data strings."""
    layer = [hash_string(leaf, rounds) for leaf in leaves]
    while len(layer) > 1:
        if len(layer) % 2 == 1:
            layer.append(layer[-1])   # duplicate last node if odd
        layer = [
            hash_string(layer[i] + layer[i + 1], rounds)
            for i in range(0, len(layer), 2)
        ]
    return layer[0]

transactions = ["tx1_data", "tx2_data", "tx3_data", "tx4_data"]
root = merkle_root(transactions)
print(f"Merkle root: {root}")
```

---

## Security Notes

> ⚠️ **Rudra-512 is a custom, experimental hash function.** It has not undergone formal third-party cryptanalysis. For production security-critical systems, consider established standards like SHA-2, SHA-3, or BLAKE3.

**Best practices:**

- Use **32+ rounds** for general cryptographic use
- Use **64+ rounds** for password hashing and anything that could be attacked offline
- Use **128+ rounds** for your highest-value, long-lived secrets
- **Always use salt** for password hashes — prevents rainbow table attacks
- Output is fully **deterministic**: same input + rounds + salt → same hash always
- Not yet formally audited for cryptographic vulnerabilities

---

## Algorithm Details

Rudra-512 is built on:

- **512-bit internal state** — 8 × 64-bit words
- **Configurable compression rounds** — default: 32
- **Optional salt integration** — mixed in before the first round
- **Optimized bitwise operations** — rotations, XOR mixing, modular additions
- **Native C++17 implementation** — with pybind11 (Python) and N-API (Node.js) bindings

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

**C++ CLI only (via CMake):**

```bash
git clone https://github.com/Developer-Ayush/rudra512
cd rudra512
cmake -B build
cmake --build build
./build/rudra hello
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

## Changelog

### v4.0.0

- Initial release
- Python bindings via pybind11 (`hash_string`, `hash_file`)
- Node.js native addon via N-API (`hash`)
- Salt and configurable rounds support (all parameters optional, defaults to 32 rounds)
- CLI tool (`rudra`) for both platforms
- File hashing support
- Cross-platform compatibility (Linux, macOS, Windows)

---

## Links

| Resource | URL |
|---|---|
| GitHub | https://github.com/Developer-Ayush/rudra512 |
| PyPI | https://pypi.org/project/rudra-512-hash/ |
| npm | https://www.npmjs.com/package/rudra-512-hash |
| Issues | https://github.com/Developer-Ayush/rudra512/issues |

---

## License

Licensed under the [Apache License 2.0](LICENSE).

```
Copyright 2026 Ayush Anand

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
