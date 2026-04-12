# CHANGELOG — RUDRA512

All notable changes to RUDRA512 are documented here.
This project follows a research-oriented development model.

---

## [11.10.11] — Paper Reference Release

### Summary

This version represents the **reference implementation** described in the RUDRA512 research paper.

It consolidates prior iterations into a unified design featuring structured preprocessing,
state initialization hardening, and configurable round-based permutation.

> ⚠️ This release is intended for **research and experimental analysis only**.
> It is not a production-ready cryptographic primitive.

---

### Added

* Tokenisation-based input preprocessing (variable-length segmentation)
* Embedded Salt Positioning (ESP) for structured salt integration
* Pre-absorption state whitening step
* Asymmetric rotation schedule in permutation rounds
* Block index obfuscation during absorption
* Extended domain separation constants:

  * Rounds domain constant
  * Salt/ESP domain constant
  * Tokenisation domain constant
* File hashing path aligned with full preprocessing pipeline
* CLI support for hashing operations
* Python and Node.js bindings

---

### Changed

* Input processing redesigned from direct byte absorption → structured preprocessing pipeline
* Initial state construction now incorporates salt-dependent variation
* Rotation schedule updated to include round and position-dependent variation
* Absorption logic modified to reduce direct structural exposure of input sequence
* File hashing now follows same pipeline as string hashing

---

### Removed

* Fixed salt prefix encoding strategy (replaced by ESP)
* Direct sequential block indexing (replaced by obfuscated indexing)

---

### Security Notes

The following design changes aim to address structural concerns observed in earlier iterations:

* Reduced predictability of input structure via preprocessing
* Increased variability in state evolution through asymmetric rotation
* Reduced direct exposure of block ordering
* Additional mixing prior to first absorption

> These changes are **heuristic design improvements** and do not constitute formal security guarantees.

---

## [3.x] — Hardened Iteration Series

### Summary

Introduced multiple structural modifications to input handling, state initialization,
and permutation behavior.

### Key Changes

* Tokenisation-inspired preprocessing
* Embedded salt positioning (ESP)
* State whitening prior to absorption
* Asymmetric rotation schedule
* Block index obfuscation

> These changes informed the final 11.10.11 design.

---

## [2.x] — Snapshot Permutation Series

### Key Changes

* Snapshot-based permutation (full state copy per round)
* Non-linear absorption tweaks
* Rotation schedule improvements
* Domain separation for round counts
* Salt encoding with prefix structure
* File hashing support

---

## [1.x] — Early Design Iterations

### Key Changes

* Initial ARX-based permutation design
* Fixed 512-bit state (8 × 64-bit words)
* Basic absorption and mixing
* Introduction of salt handling

---

## Notes

* Version **11.10.11** is the canonical reference for the research paper.
* Earlier versions are retained for historical and developmental context.
* Future changes will increment versions beyond 11.10.11 and will not modify this release.

---
