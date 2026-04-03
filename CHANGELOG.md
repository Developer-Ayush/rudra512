# Changelog

All notable changes to Rudra-512 are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/).

---

## [1.0.0] — 2026

### Added
- Core C++17 512-bit hash implementation (`Rudra512.cpp`)
- 512-bit internal state using 8 × 64-bit words
- Configurable compression rounds (default: 32)
- Optional salt support for all hash functions
- Python bindings via pybind11 — `hash_string()`, `hash_file()`
- Node.js native addon via N-API — `hash()`
- CLI tool (`rudra`) for both Python and Node.js packages
- Website also available
- File hashing support (memory-efficient, no full load)
- Benchmark script (`benchmark.py`) comparing against SHA-512 and SHA3-512
- Cross-platform support: Linux, macOS, Windows
- Apache 2.0 license

---

<!-- 
Template for future releases:

## [X.Y.Z] — YYYY-MM-DD

### Added
- 

### Changed
- 

### Fixed
- 

### Removed
- 
-->
