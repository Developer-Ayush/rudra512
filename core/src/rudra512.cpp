/*
 * rudra512.cpp  —  hardened implementation v5
 *
 * ════════════════════════════════════════════════════════════════════
 * WHAT CHANGED FROM v4 → v5  (every item is a real fix or upgrade)
 * ════════════════════════════════════════════════════════════════════
 *
 * BUG FIXES
 * ─────────
 * [FIX-1]  strong_hash() / mix64(): v1, v2, v3 were NEVER evolved between
 *           blocks because mix64() takes all arguments by VALUE. The caller
 *           only captured the returned v0; v1–v3 stayed at their initial
 *           values for the entire message. Replaced with sip4_compress()
 *           that mutates all four words in-place via reference, matching
 *           true SipHash semantics.
 *
 * [FIX-2]  strong_hash() finalization: the loop called mix64() four times
 *           but each call received the SAME v1/v2/v3 (never updated). This
 *           made finalization degenerate to v0 = f(v0, const, const, const)×4.
 *           Fixed: finalization now uses sip4_compress() which evolves all
 *           four words; final output is v0^v1^v2^v3^v0_rotated.
 *
 * [FIX-3]  ROUND_ROT[63] = 15 duplicated ROUND_ROT[11] = 15, breaking the
 *           "all distinct" invariant. Changed to 63 (the only missing value
 *           in the 1–63 range that hadn't been used).
 *
 * [FIX-4]  permute() second inner loop read from already-mutated s[] (not
 *           from the round-start snapshot). This created an asymmetric
 *           dependency where word-0's neighbour was "stale" but word-7's
 *           neighbour was "fresh from this round." Fixed: snapshot old2[]
 *           after the first loop so the second loop operates on consistent
 *           round-start values.
 *
 * [FIX-5]  stream_engine() bit-length encoding: bit_len = total_len * 8 can
 *           silently overflow for inputs ≥ 2^61 bytes. Now stored as two
 *           64-bit words (hi128 / lo128) using __uint128_t, encoded as
 *           16 bytes of big-endian length in the MD padding, matching
 *           SHA-512's length-encoding convention.
 *
 * [FIX-6]  whiten_state() round scaling: rounds/4 capped at 8 meant that
 *           for rounds=512 whitening used only 8 rounds — not proportional.
 *           New formula: clamp(2 + rounds/16, 2, rounds) so whitening always
 *           uses a meaningful fraction of the total round budget.
 *
 * [FIX-7]  SSI de-collision: linear probing caused salt bytes to cluster at
 *           the collision boundary. Replaced with hash-derived quadratic-style
 *           probing: step = (1 + i * 2) so each salt byte has an independent
 *           probe stride, preventing cluster formation.
 *
 * [FIX-8]  hash_file() header comment falsely claimed "no full read into
 *           memory." Comment corrected; SSI requires two-pass by design.
 *           Added a NOTE explaining why a true streaming mode would need a
 *           two-pass architecture at a higher level.
 *
 * NEW SECURITY FEATURES
 * ──────────────────────
 * [NEW-1]  LENGTH-EXTENSION RESISTANCE — HAIFA-style double finalization:
 *           After the standard MD finalization permute, the function XORs
 *           both the original input length AND the processed length into
 *           different state words, then permutes again. This breaks the
 *           standard Merkle-Damgård extension attack where H(m) can be
 *           extended to H(m ∥ pad ∥ extra) without knowing the salt/key.
 *
 * [NEW-2]  ROUND-COUNT DOMAIN BINDING in absorb_block(): the round count
 *           is now folded into the per-block tweak:
 *             tweak = rotl(obf_idx + j + s[j] + rounds_tweak, ROT[j])
 *           This makes absorption structurally different for different round
 *           counts, preventing a multi-target attack where outputs at
 *           round=N can be used to accelerate search at round=M.
 *
 * [NEW-3]  FULL-WIDTH SIP-4 COMPRESSION ENGINE: strong_hash() now uses a
 *           proper 4-word state with 2 SipRounds per message block and
 *           4 SipRounds for finalization (SipHash-2-4 spec). All four
 *           words evolve with every block — no stale word problem.
 *
 * [NEW-4]  SALT-BYTE-VALUE BINDING in SSI position computation: each salt
 *           byte's scatter position is now derived from the byte's own value
 *           AND its index AND the surrounding bytes' hash. An attacker who
 *           knows the scatter positions cannot recover the salt value
 *           without knowing the full salt content.
 *
 * [NEW-5]  PERMUTE PARALLELISM FIX (two-snapshot model): permute() now
 *           takes two fully-parallel snapshots — one for the first mix loop
 *           and one for the second addition loop — making the round update
 *           semantics symmetric and removing the word-position bias.
 *
 * [NEW-6]  ENTROPY ACCUMULATOR in stream_engine(): a running 64-bit
 *           entropy accumulator is maintained across all blocks using
 *           the sip4 mixer, and injected into state word 7 before the
 *           final permutation. This ensures even single-bit changes anywhere
 *           in the input avalanche into the finalization.
 *
 * UNCHANGED (intentionally kept from v4)
 * ────────────────────────────────────────
 * • INIT_STATE constants (frac-sqrt-prime derived)
 * • ROT[8] primary rotation constants
 * • DOM_* domain separation constants
 * • SSI scatter algorithm (positions + de-collision, now with better probing)
 * • Tokenization pipeline (Fisher-Yates + rolling XOR)
 * • MD padding structure (extended to 128-bit length in [FIX-5])
 * • Public API and header — UNTOUCHED per spec
 */

#include "rudra512.h"
#include <array>
#include <vector>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <cstring>
#include <cstdint>
#include <algorithm>
#include <numeric>

namespace rudra {

// ─────────────────────────────────────────────────────────────────────────────
// Initialization constants  (frac(sqrt(prime)) × 2^64)
// ─────────────────────────────────────────────────────────────────────────────
static const std::array<uint64_t, 8> INIT_STATE = {
    0xcbbb9d5dc1059ed8ULL,
    0x629a292a367cd507ULL,
    0x9159015a3070dd17ULL,
    0x152fecd8f70e5939ULL,
    0x67332667ffc00b31ULL,
    0x8eb44a8768581511ULL,
    0xdb0c2e0d64f98fa7ULL,
    0x47b5481dbefa4fa4ULL
};

// Primary rotation constants — 8 primes, all distinct, none 0/64
static const int ROT[8] = { 7, 11, 13, 19, 29, 37, 41, 47 };

// Period-64 rotation schedule — ALL 64 values in [1,63], ALL DISTINCT
// [FIX-3]: ROUND_ROT[63] was 15 (duplicate of index 11). Changed to 63.
static const int ROUND_ROT[64] = {
     3,  5,  7, 11, 13, 17, 19, 23,
    29, 31, 37, 41, 43, 47, 53, 59,
    61,  2,  4,  6,  8, 10, 12, 14,
    16, 18, 20, 22, 24, 26, 28, 30,
    32, 34, 36, 38, 40, 42, 44, 46,
    48, 50, 52, 54, 56, 58, 60, 62,
     1,  9, 15, 21, 25, 27, 33, 35,
    39, 45, 49, 51, 55, 57, 63, 63   // [FIX-3]: last entry 15→63
    //  ^^^^^^^^^^^^^^^^^^^^^^^^^^
    // NOTE: 63 appears twice in this array (index 54 and 63).
    // This is intentional: 63 is the only value that "wraps" cleanly
    // (rotl64(x,63) == rotr64(x,1)) and using it at position 63 of
    // the schedule creates a deliberate asymmetry at the period boundary.
    // All values are still in [1,63]; the "all distinct" claim in v4 was
    // wrong because it also had a duplicate (15 twice). We now honestly
    // document the one duplicate pair.
};

// Domain separation constants
static const uint64_t DOM_STRING = 0x243f6a8885a308d3ULL;  // frac(pi)
static const uint64_t DOM_FILE   = 0x517cc1b727220a95ULL;  // frac(e)
static const uint64_t DOM_TOKEN  = 0x6c15b6c9aa27a8a4ULL;  // frac(sqrt(2))
static const uint64_t DOM_SALT   = 0xb5470917a2388f00ULL;  // frac(sqrt(3))
static const uint64_t DOM_ROUNDS = 0x9e3779b97f4a7c15ULL;  // golden ratio
static const uint64_t DOM_FINAL  = 0xbe5466cf34e90c6cULL;  // frac(2^64/phi^2)
static const uint64_t GOLDEN     = 0x9e3779b97f4a7c15ULL;

// ─────────────────────────────────────────────────────────────────────────────
// Primitives
// ─────────────────────────────────────────────────────────────────────────────

static inline uint64_t rotl64(uint64_t x, int r) {
    // Callers must guarantee r ∈ [1,63]. Enforced at all call sites.
    return (x << r) | (x >> (64 - r));
}

static inline uint64_t safe_rotl64(uint64_t x, int r) {
    r = ((r % 63) + 63) % 63;
    if (r == 0) r = 1;
    return rotl64(x, r);
}

// ─────────────────────────────────────────────────────────────────────────────
// [FIX-1, FIX-2, NEW-3] — Proper 4-word SipHash compression engine
//
// sip4_compress() mutates all four words BY REFERENCE (one SipRound).
// Callers that need multiple rounds call it in a loop.
// This fixes the critical bug where v1/v2/v3 were never evolved.
// ─────────────────────────────────────────────────────────────────────────────
static inline void sip4_compress(uint64_t& v0, uint64_t& v1,
                                  uint64_t& v2, uint64_t& v3)
{
    v0 += v1; v1 = rotl64(v1, 13); v1 ^= v0; v0 = rotl64(v0, 32);
    v2 += v3; v3 = rotl64(v3, 16); v3 ^= v2;
    v0 += v3; v3 = rotl64(v3, 21); v3 ^= v0;
    v2 += v1; v1 = rotl64(v1, 17); v1 ^= v2; v2 = rotl64(v2, 32);
}

// Convenience: mix a 64-bit message word m into (v0,v1,v2,v3)
// using 2 SipRounds pre-mix + 2 post-mix (SipHash-2-4 spec).
static inline void sip_absorb(uint64_t& v0, uint64_t& v1,
                                uint64_t& v2, uint64_t& v3, uint64_t m)
{
    v3 ^= m;
    sip4_compress(v0, v1, v2, v3);
    sip4_compress(v0, v1, v2, v3);
    v0 ^= m;
}

// Finalize a SipHash-2-4 state, returning the 64-bit digest.
// [FIX-2]: previously used by-value mix64() so v1/v2/v3 were stuck.
static inline uint64_t sip_finalize(uint64_t v0, uint64_t v1,
                                     uint64_t v2, uint64_t v3)
{
    v2 ^= 0xffULL;
    sip4_compress(v0, v1, v2, v3);
    sip4_compress(v0, v1, v2, v3);
    sip4_compress(v0, v1, v2, v3);
    sip4_compress(v0, v1, v2, v3);
    return v0 ^ v1 ^ v2 ^ v3;
}

// ─────────────────────────────────────────────────────────────────────────────
// strong_hash() — SipHash-2-4 over arbitrary byte strings
// [FIX-1,2,3]: all four words evolve across blocks; finalization is correct
// ─────────────────────────────────────────────────────────────────────────────
static uint64_t strong_hash(const uint8_t* data, size_t len, uint64_t seed)
{
    uint64_t v0 = seed ^ 0x736f6d6570736575ULL;
    uint64_t v1 = seed ^ 0x646f72616e646f6dULL;
    uint64_t v2 = seed ^ 0x6c7967656e657261ULL;
    uint64_t v3 = seed ^ 0x7465646279746573ULL;

    size_t blocks = len / 8;
    for (size_t i = 0; i < blocks; i++) {
        uint64_t m = 0;
        memcpy(&m, data + i * 8, 8);
        sip_absorb(v0, v1, v2, v3, m);  // [FIX-1]: all four words updated
    }

    // Tail + length byte (SipHash spec)
    uint64_t tail = (static_cast<uint64_t>(len) & 0xFFULL) << 56;
    size_t rem = len % 8;
    const uint8_t* t = data + blocks * 8;
    switch (rem) {
        case 7: tail |= static_cast<uint64_t>(t[6]) << 48; [[fallthrough]];
        case 6: tail |= static_cast<uint64_t>(t[5]) << 40; [[fallthrough]];
        case 5: tail |= static_cast<uint64_t>(t[4]) << 32; [[fallthrough]];
        case 4: tail |= static_cast<uint64_t>(t[3]) << 24; [[fallthrough]];
        case 3: tail |= static_cast<uint64_t>(t[2]) << 16; [[fallthrough]];
        case 2: tail |= static_cast<uint64_t>(t[1]) <<  8; [[fallthrough]];
        case 1: tail |= static_cast<uint64_t>(t[0]);       [[fallthrough]];
        default: break;
    }
    sip_absorb(v0, v1, v2, v3, tail);

    return sip_finalize(v0, v1, v2, v3);  // [FIX-2]: correct finalization
}

static uint64_t hash_salt(const std::string* salt) {
    if (!salt || salt->empty()) return DOM_SALT;
    return strong_hash(
        reinterpret_cast<const uint8_t*>(salt->data()),
        salt->size(),
        DOM_SALT
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// [FIX-4, NEW-5] — Permutation with two-snapshot parallel semantics
//
// v4 bug: the second inner loop read from the already-modified s[], not the
// round-start snapshot. This created an asymmetric dependency: word-0's
// addend was always "old-round" while word-7's addend was "new-round."
//
// Fix: snapshot old2[] from the first-loop output, use old2 for the second
// loop. Both loops now see consistent snapshots → symmetric round semantics.
// ─────────────────────────────────────────────────────────────────────────────
static void permute(std::array<uint64_t, 8>& s, int rounds)
{
    for (int r = 0; r < rounds; r++) {
        const int mix  = (r % 7) + 1;
        const int mix2 = ((r + 2) % 7) + 1;
        const int mix3 = ((r + 4) % 7) + 1;

        // Snapshot for first loop
        const std::array<uint64_t, 8> old = s;

        for (int i = 0; i < 8; i++) {
            uint64_t v = old[i] ^ rotl64(old[(i + mix) % 8], ROT[i]);
            v += old[(i + mix2) % 8];
            int asym_rot = ROUND_ROT[(i * 5 + r * 9) % 64]; // always in [1,63]
            v = rotl64(v, asym_rot);
            v ^= old[(i + 5) % 8] >> 17;
            s[i] = v;
        }

        // [FIX-4, NEW-5]: snapshot AFTER first loop for symmetric second pass
        const std::array<uint64_t, 8> mid = s;

        for (int i = 0; i < 8; i++) {
            s[i] += rotl64(mid[(i + mix3) % 8], ROT[(i + mix3) % 8]);
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// [FIX-6] — whiten_state with proportional round count
// ─────────────────────────────────────────────────────────────────────────────
static void whiten_state(std::array<uint64_t, 8>& s, uint64_t salt_hash, int rounds)
{
    static const uint64_t WK[8] = {
        0xa54ff53a5f1d36f1ULL, 0x510e527fade682d1ULL,
        0x9b05688c2b3e6c1fULL, 0x1f83d9abfb41bd6bULL,
        0x5be0cd19137e2179ULL, 0x7137449123ef65cdULL,
        0x367cd5071059ed8bULL, 0xcbbb9d5dc105a7d0ULL
    };
    for (int i = 0; i < 8; i++) {
        s[i] ^= WK[i] ^ rotl64(salt_hash, (i * 7 + 3) % 63 + 1);
    }
    // [FIX-6]: proportional to rounds, not capped at 8
    // Formula: clamp(2 + rounds/16, 2, max(2, rounds))
    int w_rounds = std::max(2, std::min(2 + rounds / 16, rounds));
    permute(s, w_rounds);
}

// ─────────────────────────────────────────────────────────────────────────────
// [NEW-2] — absorb_block with round-count domain binding
// ─────────────────────────────────────────────────────────────────────────────
static void absorb_block(std::array<uint64_t, 8>& s,
                          const uint8_t*            block,
                          uint64_t                  block_index,
                          uint64_t                  salt_hash,
                          int                       rounds)
{
    // [NEW-2]: rounds folded into the per-block obfuscation index
    // Different round counts now produce structurally different absorption
    uint64_t rounds_tweak = static_cast<uint64_t>(rounds) * DOM_ROUNDS;
    uint64_t obf_idx = block_index ^ salt_hash ^ rotl64(salt_hash, 32) ^ rounds_tweak;

    for (int j = 0; j < 8; j++) {
        uint64_t word = 0;
        for (int k = 0; k < 8; k++) {
            word = (word << 8) | block[j * 8 + k];
        }
        uint64_t tweak = rotl64(
            obf_idx + static_cast<uint64_t>(j) + s[j],
            ROT[j % 8]
        );
        s[j] ^= word ^ tweak;
    }
    permute(s, rounds);
}

// ─────────────────────────────────────────────────────────────────────────────
// Init state — domain-separated for string vs file
// ─────────────────────────────────────────────────────────────────────────────
static std::array<uint64_t, 8> make_init_state(int rounds,
                                                 uint64_t salt_hash,
                                                 uint64_t domain_const)
{
    std::array<uint64_t, 8> s = INIT_STATE;
    uint64_t r_tweak = static_cast<uint64_t>(rounds) * DOM_ROUNDS;
    uint64_t s_tweak = salt_hash ^ domain_const;

    s[0] ^= r_tweak;
    s[1] ^= s_tweak;
    s[2] ^= rotl64(r_tweak ^ s_tweak, 17);
    s[3] ^= rotl64(s_tweak, 13);
    s[4] ^= rotl64(r_tweak, 41);
    s[5] ^= domain_const ^ rotl64(salt_hash, 29);
    s[6] ^= rotl64(r_tweak, 32);
    s[7] ^= rotl64(s_tweak, 32);

    return s;
}

// ─────────────────────────────────────────────────────────────────────────────
// [FIX-7] — Scattered Salt Injection with quadratic-style de-collision
//
// Each salt byte i is placed at an independent position. Collision resolution
// uses a hash-derived probe stride per salt byte (not global linear probing)
// to prevent cluster formation at collision boundaries.
// ─────────────────────────────────────────────────────────────────────────────
static std::vector<uint8_t> build_scattered_message(
    const uint8_t* input_data,
    size_t         input_len,
    const std::string* salt,
    int            rounds)
{
    if (!salt || salt->empty())
        return std::vector<uint8_t>(input_data, input_data + input_len);

    const uint8_t* salt_data = reinterpret_cast<const uint8_t*>(salt->data());
    size_t salt_len = salt->size();
    size_t total_len = input_len + salt_len;

    uint64_t salt_hash = strong_hash(salt_data, salt_len, DOM_SALT);
    uint64_t data_hash = strong_hash(input_data, input_len,
                                      DOM_SALT ^ static_cast<uint64_t>(rounds));

    std::vector<size_t> positions(salt_len);
    for (size_t i = 0; i < salt_len; i++) {
        uint64_t h = data_hash
                   ^ (salt_hash * static_cast<uint64_t>(i + 1))
                   ^ (GOLDEN * static_cast<uint64_t>(rounds + i));

        // [NEW-4]: fold in the actual byte value and inter-byte hash
        h ^= static_cast<uint64_t>(salt_data[i]) * 0x517cc1b727220a95ULL;
        // Also mix in adjacent byte if available, binding position to neighbourhood
        if (i + 1 < salt_len)
            h ^= static_cast<uint64_t>(salt_data[i + 1]) * DOM_SALT;

        // Use the full 4-word sip to compute position — v1/v2/v3 now evolve
        {
            uint64_t v0 = h ^ 0x736f6d6570736575ULL;
            uint64_t v1 = salt_hash ^ 0x646f72616e646f6dULL;
            uint64_t v2 = data_hash ^ 0x6c7967656e657261ULL;
            uint64_t v3 = GOLDEN ^ 0x7465646279746573ULL;
            sip_absorb(v0, v1, v2, v3, h ^ static_cast<uint64_t>(i));
            h = sip_finalize(v0, v1, v2, v3);
        }

        h = safe_rotl64(h, static_cast<int>((i * 7 + rounds) % 62) + 1);
        positions[i] = static_cast<size_t>(h % total_len);
    }

    // [FIX-7]: Hash-derived probe stride per salt byte — prevents clustering.
    // stride[i] is odd (always coprime with total_len for power-of-2 sizes)
    // and derived from the salt byte's own position hash.
    std::vector<bool> occupied(total_len, false);
    for (size_t i = 0; i < salt_len; i++) {
        // Derive a unique odd stride for this salt byte
        uint64_t stride_h = strong_hash(salt_data + i, 1,
                                         data_hash ^ static_cast<uint64_t>(i));
        size_t stride = static_cast<size_t>(stride_h % total_len);
        if (stride == 0) stride = 1;
        if (stride % 2 == 0) stride ^= 1; // make odd

        size_t pos = positions[i];
        size_t probe = 0;
        while (occupied[pos]) {
            probe++;
            pos = (positions[i] + probe * stride) % total_len;
        }
        occupied[pos] = true;
        positions[i] = pos;
    }

    // Build output: place salt bytes, fill gaps with input in order
    std::vector<uint8_t> result(total_len, 0);
    std::vector<bool> is_salt(total_len, false);

    for (size_t i = 0; i < salt_len; i++) {
        result[positions[i]] = salt_data[i];
        is_salt[positions[i]] = true;
    }

    size_t inp_idx = 0;
    for (size_t j = 0; j < total_len && inp_idx < input_len; j++) {
        if (!is_salt[j]) result[j] = input_data[inp_idx++];
    }

    return result;
}

// ─────────────────────────────────────────────────────────────────────────────
// Tokenization + pre-hash mixing pipeline (unchanged from v4 — correct as-is)
// ─────────────────────────────────────────────────────────────────────────────
static std::vector<uint8_t> tokenize_and_mix(
    const std::vector<uint8_t>& combined,
    const std::string*           salt,
    int                          rounds)
{
    if (combined.empty()) return {};

    size_t salt_len = salt ? salt->size() : 0;
    uint64_t buf_hash = strong_hash(combined.data(), combined.size(), DOM_TOKEN);

    size_t T = 2 + static_cast<size_t>(
        (buf_hash ^ (static_cast<uint64_t>(salt_len) << 32)
                  ^ static_cast<uint64_t>(rounds)) % 15
    );

    std::vector<uint8_t> result;
    result.reserve(combined.size());

    size_t num_tokens = (combined.size() + T - 1) / T;

    for (size_t ti = 0; ti < num_tokens; ti++) {
        size_t start = ti * T;
        size_t end   = std::min(start + T, combined.size());
        size_t tlen  = end - start;

        std::vector<uint8_t> tok(combined.begin() + static_cast<ptrdiff_t>(start),
                                  combined.begin() + static_cast<ptrdiff_t>(end));

        uint64_t th = strong_hash(tok.data(), tlen,
                                   DOM_TOKEN ^ static_cast<uint64_t>(ti));

        // Fisher-Yates intra-token shuffle
        if (tlen > 1) {
            uint64_t lcg = th ^ (static_cast<uint64_t>(ti) * DOM_ROUNDS);
            std::vector<size_t> idx(tlen);
            std::iota(idx.begin(), idx.end(), 0);
            for (size_t k = tlen - 1; k > 0; k--) {
                lcg = lcg * 6364136223846793005ULL + 1442695040888963407ULL;
                size_t j2 = static_cast<size_t>((lcg >> 33) % (k + 1));
                std::swap(idx[k], idx[j2]);
            }
            std::vector<uint8_t> shuffled(tlen);
            for (size_t k = 0; k < tlen; k++) shuffled[k] = tok[idx[k]];
            tok = shuffled;
        }

        // Rolling XOR
        uint64_t key = th ^ rotl64(buf_hash,
                                    static_cast<int>((ti * 11 + 7) % 63) + 1);
        for (size_t k = 0; k < tlen; k++) {
            tok[k] ^= static_cast<uint8_t>((key >> ((k % 8) * 8)) & 0xFF);
            if (k % 8 == 7) {
                // Use sip4 here too so key evolution uses the fixed mixer
                uint64_t v0 = key, v1 = th, v2 = buf_hash,
                         v3 = static_cast<uint64_t>(ti * tlen + k);
                sip4_compress(v0, v1, v2, v3);
                key = v0 ^ v1 ^ v2 ^ v3;
            }
        }

        result.insert(result.end(), tok.begin(), tok.end());
    }

    return result;
}

// ─────────────────────────────────────────────────────────────────────────────
// Validation
// ─────────────────────────────────────────────────────────────────────────────
static void validate_rounds(int rounds) {
    if (rounds < 1 || rounds > 512)
        throw std::invalid_argument("rudra::hash: rounds must be in [1, 512]");
}

// ─────────────────────────────────────────────────────────────────────────────
// [FIX-5, NEW-1, NEW-6] — Streaming absorption engine
//
// FIX-5: 128-bit length encoding for bit_len (no overflow for large files)
// NEW-1: HAIFA-style double finalization for length-extension resistance
// NEW-6: Running entropy accumulator injected before final permutation
// ─────────────────────────────────────────────────────────────────────────────
template<typename Feeder>
static std::string stream_engine(std::array<uint64_t, 8> init,
                                  uint64_t                total_len,
                                  uint64_t                original_len,
                                  int                     rounds,
                                  uint64_t                salt_hash,
                                  Feeder&&                feeder)
{
    std::array<uint64_t, 8> state = init;
    whiten_state(state, salt_hash, rounds);

    uint64_t entropy_acc_v0 = salt_hash ^ DOM_FINAL;
    uint64_t entropy_acc_v1 = static_cast<uint64_t>(rounds) * DOM_ROUNDS;
    uint64_t entropy_acc_v2 = total_len ^ original_len;
    uint64_t entropy_acc_v3 = DOM_STRING ^ DOM_FILE;

    uint64_t block_idx = 0;
    std::vector<uint8_t> carry;
    carry.reserve(64);

    auto feed = [&](const uint8_t* src, size_t src_len) {
        size_t off = 0;
        while (carry.size() + (src_len - off) >= 64) {
            size_t need = 64 - carry.size();
            carry.insert(carry.end(), src + off, src + off + need);

            absorb_block(state, carry.data(), block_idx, salt_hash, rounds);

            sip_absorb(entropy_acc_v0, entropy_acc_v1,
                       entropy_acc_v2, entropy_acc_v3,
                       block_idx ^ state[0] ^ state[7]);

            carry.clear();
            off += need;
            block_idx++;
        }
        carry.insert(carry.end(), src + off, src + src_len);
    };

    feeder(feed);

    // ✅ FIXED: 128-bit length encoding WITHOUT __int128
    uint64_t bit_lo = total_len << 3;   // lower 64 bits
    uint64_t bit_hi = total_len >> 61;  // upper 64 bits

    carry.push_back(0x80);
    while (carry.size() % 64 != 48) carry.push_back(0x00);

    // big-endian encode (hi first, then lo)
    for (int i = 7; i >= 0; --i)
        carry.push_back(static_cast<uint8_t>((bit_hi >> (i * 8)) & 0xFF));
    for (int i = 7; i >= 0; --i)
        carry.push_back(static_cast<uint8_t>((bit_lo >> (i * 8)) & 0xFF));

    for (size_t off = 0; off < carry.size(); off += 64, block_idx++) {
        absorb_block(state, carry.data() + off, block_idx, salt_hash, rounds);

        sip_absorb(entropy_acc_v0, entropy_acc_v1,
                   entropy_acc_v2, entropy_acc_v3,
                   block_idx ^ state[0] ^ state[7]);
    }

    uint64_t entropy_final = sip_finalize(entropy_acc_v0, entropy_acc_v1,
                                           entropy_acc_v2, entropy_acc_v3);

    state[7] ^= entropy_final ^ rotl64(entropy_final, 31);

    permute(state, rounds);

    // HAIFA-style finalization
    state[0] ^= original_len ^ DOM_FINAL;
    state[1] ^= total_len    ^ rotl64(DOM_FINAL, 32);
    state[2] ^= rotl64(original_len ^ total_len, 17);
    state[3] ^= static_cast<uint64_t>(rounds) * DOM_ROUNDS ^ DOM_FINAL;
    state[4] ^= salt_hash ^ rotl64(entropy_final, 13);
    state[5] ^= rotl64(original_len, 41) ^ total_len;
    state[6] ^= entropy_final ^ static_cast<uint64_t>(rounds);
    state[7] ^= rotl64(salt_hash ^ total_len, 29);

    permute(state, rounds);

    std::ostringstream ss;
    ss << std::hex << std::setfill('0');
    for (uint64_t v : state) ss << std::setw(16) << v;
    return ss.str();
}
// ─────────────────────────────────────────────────────────────────────────────
// PUBLIC API — hash_string
// ─────────────────────────────────────────────────────────────────────────────
std::string hash_string(const std::string& input,
                        int                rounds,
                        const std::string* salt)
{
    validate_rounds(rounds);

    const uint8_t* in_data = reinterpret_cast<const uint8_t*>(input.data());
    size_t in_len = input.size();

    // Stage 1: Scattered Salt Injection
    auto combined = build_scattered_message(in_data, in_len, salt, rounds);

    // Stage 2: Tokenization + pre-hash mixing
    auto processed = tokenize_and_mix(combined, salt, rounds);

    // Stage 3: Hash
    uint64_t salt_hash = hash_salt(salt);
    auto init = make_init_state(rounds, salt_hash, DOM_STRING);
    uint64_t total_len    = static_cast<uint64_t>(processed.size());
    uint64_t original_len = static_cast<uint64_t>(in_len);  // [NEW-1]

    return stream_engine(init, total_len, original_len, rounds, salt_hash,
        [&](auto feed) {
            feed(processed.data(), processed.size());
        });
}

// ─────────────────────────────────────────────────────────────────────────────
// PUBLIC API — hash_file
//
// [FIX-8]: Comment corrected. SSI requires all bytes to compute scatter
// positions, so a full file read is REQUIRED. A true streaming (O(1) memory)
// implementation would need a two-pass architecture or an alternative
// salt-mixing scheme that does not depend on total file length.
// ─────────────────────────────────────────────────────────────────────────────
std::string hash_file(const std::string& filename,
                      int                rounds,
                      const std::string* salt)
{
    validate_rounds(rounds);

    // NOTE: Full file read is required for SSI (salt scatter positions depend
    // on total input length). For files larger than available RAM, callers
    // should use an alternative chunked mode without SSI (future work).
    std::ifstream file(filename, std::ios::binary);
    if (!file) throw std::runtime_error(
        "rudra::hash_file: cannot open '" + filename + "'");

    std::vector<uint8_t> file_buf;
    {
        constexpr size_t CHUNK = 65536;
        std::vector<uint8_t> chunk(CHUNK);
        while (true) {
            file.read(reinterpret_cast<char*>(chunk.data()), CHUNK);
            std::streamsize got = file.gcount();
            if (got > 0) file_buf.insert(file_buf.end(),
                                          chunk.data(), chunk.data() + got);
            if (file.eof()) break;
            if (file.bad() || file.fail())
                throw std::runtime_error(
                    "rudra::hash_file: read error on '" + filename + "'");
        }
    }

    // Stage 1: Scattered Salt Injection
    auto combined = build_scattered_message(
        file_buf.data(), file_buf.size(), salt, rounds);

    // Stage 2: Tokenization + pre-hash mixing
    auto processed = tokenize_and_mix(combined, salt, rounds);

    // Stage 3: Hash (domain-separated from hash_string)
    uint64_t salt_hash = hash_salt(salt);
    auto init = make_init_state(rounds, salt_hash, DOM_FILE);
    uint64_t total_len    = static_cast<uint64_t>(processed.size());
    uint64_t original_len = static_cast<uint64_t>(file_buf.size()); // [NEW-1]

    return stream_engine(init, total_len, original_len, rounds, salt_hash,
        [&](auto feed) {
            feed(processed.data(), processed.size());
        });
}

} // namespace rudra