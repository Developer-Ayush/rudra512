# Rudra-512 (Python)

**Rudra-512** is a high-performance 512-bit cryptographic hash function implemented in C++ with Python bindings for maximum speed and usability.

---

## 🚀 Features

* ⚡ **Fast** — Native C++ core via pybind11
* 🔐 **512-bit output** — Strong cryptographic size
* 🔄 **High avalanche effect** (~50%)
* 🧂 **Salt support**
* 🔁 **Configurable rounds**
* 📁 **File hashing support**
* 🖥️ **Command Line Interface (CLI)**

---

## 📦 Installation

```bash
pip install rudra-512-hash
```

---

## 🧠 Usage (Python)

```python
from rudra512 import hash_string, hash_file

# Hash a string
print(hash_string("hello", 32))

# Hash a file
print(hash_file("example.txt", 32))
```

---

## ⚙️ Parameters

| Parameter | Type | Description               |
| --------- | ---- | ------------------------- |
| input     | str  | Input string              |
| rounds    | int  | Number of rounds          |
| salt      | str  | Optional salt             |

---

## 🖥️ CLI Usage

After installation:

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

## ⚡ Performance

* Native C++ backend
* Optimized bitwise operations
* Faster than pure Python implementations

---

## 📁 Project Structure

```
rudra512/
├── __init__.py
├── cli.py
├── __main__.py
├── _rudra512.pyd
```

---

## 🔐 Security Notes

* Designed for strong avalanche properties
* Deterministic output for same input + rounds + salt
* Not yet formally audited

---

## 📜 License

Licensed under the Apache License 2.0.

---

## 👤 Author

**Ayush Anand**
📧 [developerayushanand@gmail.com](mailto:developerayushanand@gmail.com)

---

## 🌐 Links

* GitHub: https://github.com/Developer-Ayush/rudra512
* Issues: https://github.com/Developer-Ayush/rudra512/issues

---

## 🚀 Version

Current version: **3.0.0**
