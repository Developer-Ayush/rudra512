# RUDRA512

RUDRA512 is a 512-bit cryptographic hash function designed as a **research-oriented construction** combining ARX-based mixing with structured preprocessing, including tokenisation and input scattering.

> ⚠️ **Warning:** This implementation is intended for **research and experimentation only**. It is **not a production-ready cryptographic primitive** and should not be used in security-critical applications.

---

## ✨ Features

* 512-bit hash output
* ARX (Add-Rotate-XOR) based internal mixing
* Structured preprocessing pipeline
* BPE-based tokenisation (fixed vocabulary)
* Data-dependent input scattering
* Deterministic and reproducible design

---

## 📦 Installation

Install via pip:

```bash
pip install rudra512
```

Or install locally:

```bash
git clone https://github.com/Developer-Ayush/rudra512.git
cd rudra512
pip install .
```

---

## 🚀 Usage

### Basic Example

```python
from rudra512 import rudra512

hash_value = rudra512("hello world")
print(hash_value)
```

---

### CLI Usage (if supported)

```bash
python -m rudra512 "hello world"
```

---

## 🧪 Test Vectors

```
"" → <hash_output_here>
"abc" → <hash_output_here>
"hello world" → <hash_output_here>
```

(Replace with actual outputs from your implementation)

---

## 🔒 Design Overview

RUDRA512 consists of:

1. **Tokenisation Layer**

   * Uses a fixed BPE vocabulary
   * Vocabulary is frozen and versioned

2. **Input Scattering**

   * Data-dependent permutation of token sequence
   * Reduces structured input control

3. **ARX Mixing Core**

   * Multi-round transformation
   * Combines addition, rotation, and XOR

4. **Finalisation**

   * Produces a 512-bit digest

---

## 📚 Specification & Paper

Full specification and analysis available in the paper:

* *RUDRA512: A Structured 512-bit Hash Function with Tokenisation and Input Scattering*

(Include your ePrint link after submission)

---

## 🔁 Reproducibility

* The BPE vocabulary is **fixed** and included in the repository
* SHA-256 hash of vocabulary file is provided in the paper
* Implementation is deterministic across platforms

---

## ⚠️ Security Notice

* No formal security proof
* No full differential or linear cryptanalysis
* Performance significantly slower than standard hash functions such as SHA-512 and BLAKE2b

👉 This project is intended to encourage **community cryptanalysis and research discussion**.

---

## 🤝 Contributing

Contributions, feedback, and cryptanalysis are welcome.

---

## 📄 License

This project is licensed under the **Apache-2.0**.

---

## 👤 Author

Ayush Anand
Independent Researcher

---

## ⭐ Acknowledgment

This work is released to encourage exploration of alternative hash function design approaches.
