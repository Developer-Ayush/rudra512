# CHANGELOG — Rudra-512

All notable changes to the Rudra-512 cryptographic hash function are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [v3] — Hardened — Current

### Summary

v3 introduces five new cryptographic hardening mechanisms targeting structural weaknesses
identified in v2's input handling, state initialization, and rotation schedule. The overall
threat model is extended to cover prefix attacks, IV-recovery attacks, block reordering
attacks, and bit-pattern manipulation attacks. All v2 tests continue to pass.

---

### Added

#### [NC4] BPE-Inspired Tokenization
- Input is now tokenized before absorption using a variable-length chunking scheme
  inspired by Byte-Pair Encoding (BPE).
- Token length is derived from `simple_hash(input)` seeded with `TOKEN_DOMAIN_CONST`
  (`0x6c15b6c9aa27a8a4` — `frac(sqrt(2))`), producing token sizes in `[1, 16]` bytes.
- **Why:** Prevents trivial bit-pattern manipulation attacks where the input structure
  is directly observable in the byte stream fed to the absorber.

#### [NC5] Embedded Salt Positioning (ESP)
- Salt is no longer prepended to input as a fixed prefix.
- Salt is now embedded at a deterministic position computed as:
  ```
  pos = (hash(salt) + hash(input)) % (total_length - salt_length)
  ```
- **Why:** Eliminates three attack surfaces present in v2's prepend strategy:
  - Prefix attacks where altering the salt prefix is locally isolated
  - Dictionary attacks on common or short salts
  - TOCTOU-style race conditions in padding construction
- `compute_salt_position()` and `build_embedded_message()` replace `build_salt_prefix()`.

#### [NC6] State Whitening
- After `make_init_state()` and before the first block is absorbed, the state undergoes
  two rounds of `permute()` via a new `whiten_state()` call.
- **Why:** Ensures that the initialized state diverges in a way that is independent of
  any specific input. Prevents IV-recovery attacks that exploit predictable post-init state.

#### [NC7] Asymmetric Rotation Schedule
- The per-word rotation inside `permute()` now includes a word-index and round-index
  dependent offset:
  ```cpp
  int asym_rot = (ROUND_ROT[(i * 5 + r * 9) % 64] + (i ^ r)) % 64;
  ```
- **Why:** The previous schedule used a fixed lookup with no dependence on the current
  word or round combination. Adding `(i ^ r)` makes each word's rotation unique per
  round, increasing the diffusion rate and breaking any symmetry a cryptanalyst could
  exploit across rounds.

#### [NC8] Variable Block Absorption Order (Block Index Obfuscation)
- Block indices are XORed with `salt_hash` before being used in the absorption tweak:
  ```cpp
  uint64_t obf_idx = block_idx ^ salt_hash;
  ```
- **Why:** In v2, sequential block indices were used directly. This allowed block
  reordering attacks and gave an attacker structural information about which position in
  the stream each block was absorbed from. Obfuscation removes that signal.

#### New Domain Constant — `TOKEN_DOMAIN_CONST`
- `0x6c15b6c9aa27a8a4` (`frac(sqrt(2))`) added for tokenization seeding.
- Joins the existing `ROUNDS_DOMAIN_CONST` (`frac(π)`) and `ESP_DOMAIN_CONST` (`frac(e)`).

#### New Helper Functions
| Function | Purpose |
|---|---|
| `simple_hash()` | Lightweight 64-bit hash for tokenization and salt hashing |
| `tokenize()` | BPE-inspired input tokenization |
| `hash_salt()` | Derives `salt_hash` used in ESP, block obfuscation, and init state |
| `compute_salt_position()` | Computes ESP embedding position |
| `build_embedded_message()` | Constructs message stream with salt embedded at ESP position |
| `whiten_state()` | Two-round pre-absorption state permutation |
| `obfuscate_block_idx()` | XOR-based block index obfuscation |

---

### Changed

#### `make_init_state()` — Extended Salt Encoding
- In v2, only `rounds` was encoded into the IV via `ROUNDS_DOMAIN_CONST`.
- In v3, `salt_hash` is also encoded:
  ```cpp
  s[1] ^= salt_hash ^ ESP_DOMAIN_CONST;
  s[6] ^= rotl64(salt_hash ^ ESP_DOMAIN_CONST, 32);
  ```
- This ensures the initial state diverges based on both the round count and the salt,
  before any input is absorbed.

#### `permute()` — Asymmetric Rotation (see NC7)
- Rotation expression changed from:
  ```cpp
  // v2
  v = rotl64(v, ROUND_ROT[(i * 5 + r * 9) % 64]);
  ```
  to:
  ```cpp
  // v3
  int asym_rot = (ROUND_ROT[(i * 5 + r * 9) % 64] + (i ^ r)) % 64;
  v = rotl64(v, asym_rot);
  ```

#### `absorb_block()` — Block Index Obfuscation (see NC8)
- Tweak computation now uses obfuscated index:
  ```cpp
  // v2
  uint64_t tweak = rotl64(block_index + j + s[j], ROT[j % 8]);
  // v3
  uint64_t obf_idx = obfuscate_block_idx(block_index, salt_hash);
  uint64_t tweak   = rotl64(obf_idx + j + s[j], ROT[j % 8]);
  ```

#### `stream_engine()` — Whitening Step Inserted
- `whiten_state(state)` is now called immediately after initial state construction,
  before the block feed loop begins.

#### `hash_file()` — ESP Applied to Files
- File content is now loaded into a buffer and passed through `build_embedded_message()`
  before absorption, matching the string path's ESP behaviour.
- v2 used a simpler sequential read without embedded salt positioning.

#### Website (3D Edition)
- Visual redesign: full 3D background via Three.js (1,800 particles, wireframe icosahedron, torus ring)
- Mouse parallax on 3D scene
- Panel hover: CSS `perspective` 3D tilt on all cards
- Step cards animate with `translateZ` on hover
- State word pulse animation runs in 3D
- Scanline sweep overlay added
- Floating badge animation added
- Hash output glow effects
- "How It Works" updated from 6 steps (v2) to 8 steps (v3)
- Stepper flow diagram now annotates `[NC7] asym rot=N` per step
- Benchmark table updated with v3 throughput figures

---

### Removed

#### `build_salt_prefix()` — Replaced by ESP
- v2 encoded salt as `[len_BE4][salt_bytes][0x01]` prepended to input.
- This entire encoding scheme is removed in v3 and replaced by `build_embedded_message()`.
- The `0x00` absent-salt sentinel is also removed; absent salt is now handled by
  checking `salt_hash == 0` throughout.

---

### Security Notes

| Threat | v2 | v3 |
|---|---|---|
| Prefix attack on salt | Vulnerable (prepend) | Mitigated (ESP) |
| IV-recovery attack | Possible (predictable post-init) | Mitigated (whitening) |
| Block reordering | Possible (sequential indices) | Mitigated (NC8 obfuscation) |
| Bit-pattern manipulation | Possible (direct input) | Mitigated (tokenization) |
| Rotation symmetry across rounds | Present (fixed schedule) | Broken (asymmetric NC7) |
| Dictionary attack on salt | Possible (prefix isolation) | Mitigated (ESP position mixing) |

> **Disclaimer:** Rudra-512 remains a custom, research-grade construction. It has not
> undergone independent cryptanalysis or formal security proofs. For production use cases,
> audited standards such as BLAKE3, SHA-3, or Argon2 are recommended.

---

## [v2] — Snapshot Permutation — Previous Stable

### Added
- [C1] Non-linear state-dependent tweak in `absorb_block`: `s[j]` placed inside the
  `rotl64()` argument, making the tweak algebraically non-cancellable
- [C2] Final permutation uses full round count (min 1)
- [C3] Full state snapshot per round eliminates sequential-update asymmetry
- [C4] Period-64 rotation schedule (`ROUND_ROT[64]`) with `gcd(9, 64) = 1` stride
- [C5] Initialization constants verified as `floor(frac(sqrt(p)) * 2^64)` for
  `p ∈ {23, 29, 31, 37, 41, 43, 47, 53}` — confirmed distinct from all NIST primitives
- [C6] Salt encoding: `[len_BE4][salt][0x01]` for present salt, `[0x00]` for absent
- [C7] All arithmetic uses explicit `uint64_t` casts
- [H5] Rounds encoded into IV via `ROUNDS_DOMAIN_CONST = frac(π)`
- `ESP_DOMAIN_CONST = frac(e)` introduced (used in v3's full ESP scheme)
- `validate_rounds()` enforcing range `[1, 512]`
- `hash_file()` streaming engine with chunked reads

### Changed
- Permutation snapshot changed from in-place sequential update to full `old[]` copy
  before each round
- Rotation constants updated to avoid complementary pairs; all odd, all in `[1, 63]`

### Removed
- Simple linear absorption tweak (replaced by non-linear state-dependent tweak)

---

## [v1] — Hardened Core — Legacy

### Added
- Snapshot-based permutation (initial version)
- Non-linear absorb tweak (initial version)
- `ROUND_ROT` period-64 lookup table (initial version)
- IV constants updated to `frac(sqrt(p))` family
- Salt domain separation with length-prefix encoding

### Changed
- State size fixed at 8 × 64-bit words
- Default rounds set to 32

---

## [v1] — Initial Release — Legacy

- Basic ARX permutation, 512-bit output
- Fixed 8-word state, no salt support
- Simple sequential word XOR absorption
- No domain separation between round counts
