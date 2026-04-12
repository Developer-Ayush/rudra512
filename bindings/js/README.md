# RUDRA512 (Node.js)

**RUDRA512** is a 512-bit cryptographic hash function implemented in C++ with Node.js bindings, designed as a **research-oriented construction** for experimental analysis.

> ⚠️ **Warning:** This implementation is intended for **research and experimentation only**. It is **not a production-ready cryptographic primitive** and should not be used in security-critical applications.

---

## 🚀 Features

* 512-bit hash output
* Native C++ core via Node.js addon
* Deterministic hashing
* Configurable rounds
* Optional salt support
* File hashing support
* Command Line Interface (CLI)

---

## 📦 Installation

```bash
npm install -g rudra-512-hash
```

---

## 🧠 Usage (JavaScript)

```js
const rudra = require("rudra-512-hash");

// Hash a string
console.log(rudra.hash("hello", 32));

// Hash a file
const fs = require("fs");
const data = fs.readFileSync("example.txt", "utf-8");
console.log(rudra.hash(data, 32));
```

---

## ⚙️ Parameters

| Parameter | Type   | Description      |
| --------- | ------ | ---------------- |
| input     | string | Input string     |
| rounds    | number | Number of rounds |
| salt      | string | Optional salt    |

---

## 🖥️ CLI Usage

```bash
rudra hello
```

---

### 📌 Examples

```bash
# Basic hashing
rudra hello

# Custom rounds
rudra hello --rounds 64

# With salt
rudra hello --salt abc

# File hashing
rudra --file example.txt

# Version
rudra -v

# Help
rudra -h
```

---

## 🔁 CLI Options

| Option          | Description                    |
| --------------- | ------------------------------ |
| `-r, --rounds`  | Number of rounds (default: 32) |
| `-s, --salt`    | Optional salt                  |
| `-f, --file`    | Hash a file                    |
| `-v, --version` | Show version                   |
| `-h, --help`    | Show help                      |

---

## 🧪 Example Output

```
Input: "hello"
Output:
9f2c7a... (512-bit hex string)
```

---

## 🔬 Design Overview

RUDRA512 combines:

* ARX-based mixing (addition, rotation, XOR)
* Structured preprocessing
* Tokenisation-based transformation
* Data-dependent input scattering

The construction is intended to explore alternative hash design approaches.

---

## 📚 Specification & Paper

Full specification and analysis available in the research paper:

**“RUDRA512: A Structured 512-bit Hash Function with Tokenisation and Input Scattering”**

(Insert ePrint link after publication)

---

## 🔁 Reproducibility

* This release corresponds to version **11.10.11**
* Matches the reference version described in the paper
* Deterministic across platforms

---

## 🔐 Security Notes

* No formal security proof
* No complete differential or linear cryptanalysis
* Not independently audited

👉 This project is intended to encourage **community cryptanalysis and research discussion**.

---

## ⚡ Performance Notes

* Implemented in C++ for efficiency
* May be slower than established hash functions such as SHA-512 and BLAKE2b

---

## 📁 Project Structure

```
bindings/js/
├── index.js
├── cli.js
├── rudra.cpp
├── binding.gyp
├── package.json
```

---

## 📜 License

Licensed under the Apache License 2.0.

---

## 👤 Author

Ayush Anand
[developerayushanand@gmail.com](mailto:developerayushanand@gmail.com)

---

## 🌐 Links

GitHub: https://github.com/Developer-Ayush/rudra512
Issues: https://github.com/Developer-Ayush/rudra512/issues

---

## 🚀 Version

Current version: **11.10.11**
