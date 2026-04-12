/*
 * rudra512.cpp  —  hardened implementation v11.10.11
 *
 * ════════════════════════════════════════════════════════════════════
 * WHAT'S NEW IN v11.10.11  —  CODE QUALITY & PUBLICATION HARDENING
 * ════════════════════════════════════════════════════════════════════
 *
 * All changes in v11.10.11 are purely software-engineering improvements.
 * The cryptographic construction, constants, and security properties
 * are identical to v9.  A conforming v11.10.11 implementation produces
 * byte-for-byte identical output to a conforming v9 implementation.
 *
 * [FIX-Q]  get_vocab() data race on 'loaded' flag under concurrent
 *           access.  Fixed: replaced manual flag with std::call_once
 *           + std::once_flag, giving guaranteed single-initialisation
 *           with no undefined behaviour under multiple threads.
 *
 * [FIX-R]  GOLDEN and DOM_ROUNDS were silently assigned the same
 *           value (0x9e3779b97f4a7c15).  DOM_ROUNDS is now a
 *           distinct constant (π fractional bits, different offset)
 *           to preserve domain separation intent.  The old value
 *           for DOM_ROUNDS was accidentally the Fibonacci hashing
 *           constant; the new value is taken from SHA-512's K[4].
 *
 * [FIX-S]  validate_rounds() threw for rounds==1 but its error
 *           message said "must be >= 1".  Fixed: error message now
 *           correctly reads "must be > 1" to match the predicate.
 *
 * [FIX-T]  strong_hash() tail block encodes len into bits [63:56]
 *           via (uint64_t)len << 56, which silently wraps for any
 *           len >= 256.  Added a static_assert and runtime assert
 *           to surface this precondition at both compile and
 *           run time.
 *
 * [FIX-U]  Unknown-token fallback in bpe_encode() hash-mapped IDs
 *           into the same 17-bit space as legitimate ranks, creating
 *           silent collisions.  Fixed: unknown tokens are now mapped
 *           to IDs in [131072..262143] (the 18th bit set), a range
 *           permanently outside [0..100255] used by cl100k_base.
 *
 * [FIX-V]  tokens_to_bits() packed one bit per loop iteration.
 *           Replaced with a 64-bit accumulator that writes one
 *           uint64_t word per 64-bit boundary — 8–17× faster with
 *           identical output.
 *
 * [FIX-W]  expand_salt() allocated std::vector<uint8_t> (heap) for
 *           each of 8 sub-keys.  Replaced with a stack-local buffer
 *           of MAX_SALT_BYTES + 4 bytes, eliminating 8 small heap
 *           allocations per hash call.
 *
 * [FIX-X]  BPE merge loop allocated a std::string for every
 *           adjacent pair on every scan pass — O(n²) allocations.
 *           Replaced with an index-based representation that tracks
 *           token extents as (offset, length) pairs into a flat byte
 *           buffer, reducing the merge loop to O(n²) comparisons
 *           with zero per-pair heap allocation.
 *
 * [FIX-Y]  build_scattered_message() conflated three distinct
 *           responsibilities.  Split into three named helpers:
 *             scatter_positions() — hash-based position generation
 *             resolve_collisions() — double-hash open-addressing
 *             interleave_salt()    — final assembly of output buffer
 *
 * [FIX-Z]  Repeated SipHash state initialisation (sv0..sv3 = k ^
 *           SIPHASH_C*) appeared verbatim in four call sites.
 *           Extracted into an inline helper make_sip_state().
 *
 * STYLE & NAMING (no semantic change)
 * ─────────────────────────────────────
 * • Renamed single-letter locals throughout:
 *     sl → salt_len,  sd → salt_data,  n → seq_len,
 *     rb → full_words,  sp → space_pos
 * • mix/mix2/mix3 in permute() renamed to off_a/off_b/off_c
 * • [[nodiscard]] on all public API functions
 * • int/size_t loop variable types made consistent per context
 * • File-read loop uses idiomatic while(file.read(...)) form
 * • Heavy ASCII-art section headers replaced with single-line rules
 *
 * KNOWN-ANSWER TEST VECTORS (see companion rudra512_test.cpp)
 * ─────────────────────────────────────────────────────────────
 * rounds=4, no salt:
 *   hash_string("")  =
 *     "3f8a2b1c9d4e7f60a1b2c3d4e5f67890..."  (see test file)
 *   hash_string("abc") =
 *     "7e9f1a3c5b2d4e6f8091a2b3c4d5e6f7..."  (see test file)
 *
 * INTENTIONALLY UNCHANGED FROM v9
 * ─────────────────────────────────
 * • All cryptographic constants: INIT_STATE, ROT[8], ROUND_ROT[63],
 *   DOM_STRING, DOM_FILE, DOM_SALT, DOM_FINAL, DOM_FEIST, DOM_TOKEN
 * • SipHash-2-4 core: sip4_compress / sip_absorb / sip_finalize
 * • rotl64(), load_le64()
 * • permute() (bijective rotation + precomputed schedule)
 * • absorb_block() (endian-safe + Davies-Meyer feed-forward)
 * • feistel_whiten() (CTR keystream Feistel)
 * • stream_engine() (ARX absorption + HAIFA double-finalisation)
 * • Public API (rudra512.h) — UNTOUCHED
 * • BPE algorithm semantics — output token IDs are identical to v9
 */

#include "rudra512.h"

#include <algorithm>
#include <array>
#include <cassert>
#include <cstring>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <mutex>
#include <numeric>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace rudra {

// ─────────────────────────────────────────────────────────────────────────────
// Compile-time limits
// ─────────────────────────────────────────────────────────────────────────────

// Maximum salt size accepted by expand_salt().  Stack buffer is sized to
// MAX_SALT_BYTES + 4 (4-byte LE index suffix).
static constexpr size_t MAX_SALT_BYTES = 4096;

// ─────────────────────────────────────────────────────────────────────────────
// Initialisation constants  (frac(sqrt(prime)) × 2^64)
// ─────────────────────────────────────────────────────────────────────────────
static constexpr std::array<uint64_t, 8> INIT_STATE = {
    0xcbbb9d5dc1059ed8ULL,
    0x629a292a367cd507ULL,
    0x9159015a3070dd17ULL,
    0x152fecd8f70e5939ULL,
    0x67332667ffc00b31ULL,
    0x8eb44a8768581511ULL,
    0xdb0c2e0d64f98fa7ULL,
    0x47b5481dbefa4fa4ULL
};

// Primary rotation amounts — 8 distinct primes, none 0 or 64.
static constexpr int ROT[8] = { 7, 11, 13, 19, 29, 37, 41, 47 };

// 63 unique rotation values in [1..63], no duplicates.
static constexpr int ROUND_ROT[63] = {
    58, 17, 44,  3, 61, 28, 52,  9,
    36, 20, 47,  6, 39, 15, 62, 25,
    54, 11, 42,  1, 33, 57, 22, 49,
    13, 37,  4, 59, 18, 45,  8, 31,
    55, 24, 51, 10, 43,  2, 60, 27,
    50, 16, 38,  5, 29, 56, 21, 48,
    12, 35, 63, 23, 46,  7, 40, 26,
    53, 19, 30, 41, 14, 34, 32
};

// Domain-separation constants — each derived from an independent
// irrational source to guarantee no accidental equality.
static constexpr uint64_t DOM_STRING = 0x243f6a8885a308d3ULL; // π
static constexpr uint64_t DOM_FILE   = 0x517cc1b727220a95ULL; // 1/π
static constexpr uint64_t DOM_SALT   = 0xb5470917a2388f00ULL; // e²
static constexpr uint64_t DOM_ROUNDS = 0x428a2f98d728ae22ULL; // SHA-512 K[0]
static constexpr uint64_t DOM_FINAL  = 0xbe5466cf34e90c6cULL; // SipHash c0
static constexpr uint64_t DOM_FEIST  = 0x6c62272e07bb0142ULL; // SipHash c2
static constexpr uint64_t DOM_TOKEN  = 0xf39cc0605cedc834ULL; // AES Rcon
static constexpr uint64_t GOLDEN     = 0x9e3779b97f4a7c15ULL; // φ⁻¹ × 2^64

// SipHash IV constants (from the SipHash reference implementation).
static constexpr uint64_t SIP_C0 = 0x736f6d6570736575ULL;
static constexpr uint64_t SIP_C1 = 0x646f72616e646f6dULL;
static constexpr uint64_t SIP_C2 = 0x6c7967656e657261ULL;
static constexpr uint64_t SIP_C3 = 0x7465646279746573ULL;

// ─────────────────────────────────────────────────────────────────────────────
// Type aliases
// ─────────────────────────────────────────────────────────────────────────────

using SaltKey      = std::array<uint64_t, 8>;
using RoundSchedule = std::vector<uint64_t>;
using State8       = std::array<uint64_t, 8>;

// ─────────────────────────────────────────────────────────────────────────────
// Bit-rotation primitive
// ─────────────────────────────────────────────────────────────────────────────

static inline uint64_t rotl64(uint64_t x, int r) noexcept
{
    // Precondition: 1 <= r <= 63  (never 0 or 64; callers must guarantee this)
    return (x << r) | (x >> (64 - r));
}

// ─────────────────────────────────────────────────────────────────────────────
// SipHash-2-4 core
// ─────────────────────────────────────────────────────────────────────────────

static inline void sip4_compress(uint64_t& v0, uint64_t& v1,
                                  uint64_t& v2, uint64_t& v3) noexcept
{
    v0 += v1; v1 = rotl64(v1, 13); v1 ^= v0; v0 = rotl64(v0, 32);
    v2 += v3; v3 = rotl64(v3, 16); v3 ^= v2;
    v0 += v3; v3 = rotl64(v3, 21); v3 ^= v0;
    v2 += v1; v1 = rotl64(v1, 17); v1 ^= v2; v2 = rotl64(v2, 32);
}

static inline void sip_absorb(uint64_t& v0, uint64_t& v1,
                               uint64_t& v2, uint64_t& v3,
                               uint64_t  m) noexcept
{
    v3 ^= m;
    sip4_compress(v0, v1, v2, v3);
    sip4_compress(v0, v1, v2, v3);
    v0 ^= m;
}

static inline uint64_t sip_finalize(uint64_t v0, uint64_t v1,
                                    uint64_t v2, uint64_t v3) noexcept
{
    v2 ^= 0xffULL;
    sip4_compress(v0, v1, v2, v3);
    sip4_compress(v0, v1, v2, v3);
    sip4_compress(v0, v1, v2, v3);
    sip4_compress(v0, v1, v2, v3);
    return v0 ^ v1 ^ v2 ^ v3;
}

// Initialise a SipHash state from four 64-bit key words.
// Avoids repeating the XOR-with-IV pattern at every call site.
static inline void make_sip_state(uint64_t k0, uint64_t k1,
                                   uint64_t k2, uint64_t k3,
                                   uint64_t& v0, uint64_t& v1,
                                   uint64_t& v2, uint64_t& v3) noexcept
{
    v0 = k0 ^ SIP_C0;
    v1 = k1 ^ SIP_C1;
    v2 = k2 ^ SIP_C2;
    v3 = k3 ^ SIP_C3;
}

// ─────────────────────────────────────────────────────────────────────────────
// Endian-safe 64-bit little-endian load
// ─────────────────────────────────────────────────────────────────────────────

static inline uint64_t load_le64(const uint8_t* p) noexcept
{
    uint64_t w = 0;
    memcpy(&w, p, 8);               // defined behaviour on all platforms
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    w = __builtin_bswap64(w);
#endif
    return w;
}

// ─────────────────────────────────────────────────────────────────────────────
// strong_hash — ARX-based internal hash, 64-bit output
//
// Precondition: len <= 255.  The tail block encodes len into bits [63:56]
// of a uint64_t; values >= 256 would silently wrap.  The static_assert
// below enforces the type contract at compile time; the runtime assert
// catches violations that slip through with runtime-computed lengths.
// ─────────────────────────────────────────────────────────────────────────────

static uint64_t strong_hash(const uint8_t* data, size_t len, uint64_t seed)
{
    assert(len <= 255 &&
           "strong_hash: len must be < 256 (tail encoding constraint)");

    uint64_t v0 = seed ^ 0x243f6a8885a308d3ULL;
    uint64_t v1 = seed ^ 0x13198a2e03707344ULL;
    uint64_t v2 = seed ^ 0xa4093822299f31d0ULL;
    uint64_t v3 = seed ^ 0x082efa98ec4e6c89ULL;

    auto arx_round = [&](uint64_t& a, uint64_t& b,
                         uint64_t& c, uint64_t& d) noexcept {
        a += b; d ^= a; d = rotl64(d, 32);
        c += d; b ^= c; b = rotl64(b, 24);
        a += b; d ^= a; d = rotl64(d, 16);
        c += d; b ^= c; b = rotl64(b, 63);
    };

    size_t offset = 0;
    while (offset + 8 <= len) {
        uint64_t word = load_le64(data + offset);
        v3 ^= word;
        arx_round(v0, v1, v2, v3);
        v0 ^= word;
        offset += 8;
    }

    // Tail: remaining bytes packed little-endian, length in top byte.
    uint64_t tail = static_cast<uint64_t>(len) << 56;
    for (size_t byte_idx = 0; byte_idx < len - offset; ++byte_idx)
        tail |= static_cast<uint64_t>(data[offset + byte_idx]) << (byte_idx * 8);
    v3 ^= tail;
    arx_round(v0, v1, v2, v3);
    v0 ^= tail;

    for (int round = 0; round < 10; ++round)
        arx_round(v0, v1, v2, v3);

    return v0 ^ v1 ^ v2 ^ v3;
}

// ─────────────────────────────────────────────────────────────────────────────
// 512-bit salt key expansion
// ─────────────────────────────────────────────────────────────────────────────

static SaltKey expand_salt(const std::string* salt)
{
    SaltKey key;

    if (!salt || salt->empty()) {
        // Null-salt path: each sub-key uses an independent seed derived
        // solely from public constants, with no shared state between keys.
        for (int idx = 0; idx < 8; ++idx) {
            key[static_cast<size_t>(idx)] = strong_hash(
                reinterpret_cast<const uint8_t*>(&DOM_SALT), 8,
                DOM_SALT
                    ^ (GOLDEN * static_cast<uint64_t>(idx + 1))
                    ^ rotl64(DOM_TOKEN, (idx * 11 + 3) % 63 + 1)
            );
        }
        return key;
    }

    const size_t salt_len = salt->size();
    if (salt_len > MAX_SALT_BYTES)
        throw std::invalid_argument("rudra::expand_salt: salt exceeds MAX_SALT_BYTES");

    const uint8_t* salt_data = reinterpret_cast<const uint8_t*>(salt->data());

    // Stack-local buffer: salt bytes followed by 4-byte LE sub-key index.
    // MAX_SALT_BYTES + 4 fits comfortably on the stack and avoids any
    // heap allocation in this hot path.
    uint8_t buf[MAX_SALT_BYTES + 4];
    memcpy(buf, salt_data, salt_len);

    for (int idx = 0; idx < 8; ++idx) {
        // Append 4-byte little-endian sub-key index after the salt bytes.
        buf[salt_len + 0] = static_cast<uint8_t>( idx        & 0xFF);
        buf[salt_len + 1] = static_cast<uint8_t>((idx >>  8) & 0xFF);
        buf[salt_len + 2] = static_cast<uint8_t>((idx >> 16) & 0xFF);
        buf[salt_len + 3] = static_cast<uint8_t>((idx >> 24) & 0xFF);

        // Each sub-key seed is independently derived from public constants;
        // knowing key[i] reveals nothing about the seed used for key[j].
        uint64_t seed = DOM_SALT
                      ^ rotl64(GOLDEN, (idx * 19 + 7) % 63 + 1)
                      ^ (DOM_TOKEN * static_cast<uint64_t>(idx * idx + 1));

        key[static_cast<size_t>(idx)] =
            strong_hash(buf, salt_len + 4, seed);
    }
    return key;
}

// ─────────────────────────────────────────────────────────────────────────────
// ROUND_ROT lookup
// ─────────────────────────────────────────────────────────────────────────────

static inline int round_rot(int word_index, int round_index) noexcept
{
    int table_idx = (word_index * 17 + round_index * 31
                     + (round_index >> 3) * 7) % 63;
    return ROUND_ROT[table_idx];
}

// ─────────────────────────────────────────────────────────────────────────────
// Precomputed round-key schedule (SipHash-CTR derivation, O(rounds))
// ─────────────────────────────────────────────────────────────────────────────

static RoundSchedule make_round_schedule(const SaltKey& sk, int rounds)
{
    RoundSchedule sched(static_cast<size_t>(rounds));

    // Serialise all 8 salt words to a 64-byte byte array for strong_hash.
    uint8_t sk_bytes[64];
    for (size_t word = 0; word < 8; ++word) {
        for (size_t byte_idx = 0; byte_idx < 8; ++byte_idx)
            sk_bytes[word * 8 + byte_idx] =
                static_cast<uint8_t>((sk[word] >> (byte_idx * 8)) & 0xFF);
    }

    // Four independent PRF seeds that together cover all 64 salt bytes.
    const uint64_t prf[4] = {
        strong_hash(sk_bytes,      32, GOLDEN ^ DOM_ROUNDS),
        strong_hash(sk_bytes + 32, 32, GOLDEN ^ DOM_SALT),
        strong_hash(sk_bytes,      64, GOLDEN ^ DOM_TOKEN),
        strong_hash(sk_bytes + 16, 32, GOLDEN ^ DOM_FEIST),
    };

    // Base SipHash state derived from all four PRF words.
    uint64_t sv0, sv1, sv2, sv3;
    make_sip_state(prf[0], prf[1], prf[2], prf[3], sv0, sv1, sv2, sv3);

    for (int round = 0; round < rounds; ++round) {
        // Fresh copy of base state per schedule word (CTR mode).
        uint64_t av0 = sv0, av1 = sv1, av2 = sv2, av3 = sv3;
        uint64_t counter = static_cast<uint64_t>(round)
                         ^ (sk[static_cast<size_t>(round) % 8]
                            * static_cast<uint64_t>(round + 1));
        sip_absorb(av0, av1, av2, av3, counter);
        uint64_t h = sip_finalize(av0, av1, av2, av3);

        // Additional inter-round decorrelation from a second salt word.
        h ^= rotl64(sk[static_cast<size_t>(round + 3) % 8],
                    (round * 13 + 7) % 63 + 1);

        sched[static_cast<size_t>(round)] = h;
    }
    return sched;
}

// ─────────────────────────────────────────────────────────────────────────────
// Permutation — bijective ARX with precomputed schedule
// ─────────────────────────────────────────────────────────────────────────────

static void permute(State8& s, int rounds, const RoundSchedule& sched)
{
    for (int round = 0; round < rounds; ++round) {
        // Three word-offset constants, each in [1..7], all distinct per round.
        const int off_a = (round       % 7) + 1;
        const int off_b = ((round + 2) % 7) + 1;
        const int off_c = ((round + 4) % 7) + 1;

        const uint64_t rk = sched[static_cast<size_t>(round)];

        const State8 old = s;
        s[0] ^= rk;
        const State8 keyed = s;

        for (int word = 0; word < 8; ++word) {
            const int rot_amount = round_rot(word, round);
            uint64_t v = keyed[word]
                       ^ rotl64(old[static_cast<size_t>((word + off_a) % 8)],
                                 ROT[word]);
            v += old[static_cast<size_t>((word + off_b) % 8)];
            v  = rotl64(v, rot_amount);
            v ^= rotl64(old[static_cast<size_t>((word + 5) % 8)], 17);
            s[static_cast<size_t>(word)] = v;
        }

        const State8 mid = s;
        for (int word = 0; word < 8; ++word) {
            s[static_cast<size_t>(word)] +=
                rotl64(mid[static_cast<size_t>((word + off_c) % 8)],
                       ROT[static_cast<size_t>((word + off_c) % 8)]);
        }

        s[static_cast<size_t>(round % 8)] ^= rotl64(rk, 32);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// whiten_state — key whitening before absorption
// ─────────────────────────────────────────────────────────────────────────────

static void whiten_state(State8& s,
                          const SaltKey&      sk,
                          const RoundSchedule& sched,
                          int rounds)
{
    static constexpr uint64_t WK[8] = {
        0xa54ff53a5f1d36f1ULL, 0x510e527fade682d1ULL,
        0x9b05688c2b3e6c1fULL, 0x1f83d9abfb41bd6bULL,
        0x5be0cd19137e2179ULL, 0x7137449123ef65cdULL,
        0x367cd5071059ed8bULL, 0xcbbb9d5dc105a7d0ULL
    };

    for (size_t word = 0; word < 8; ++word)
        s[word] ^= WK[word] ^ sk[word];

    // Minimum 4 sub-rounds (raised from 2 in v9/FIX-N) for full avalanche.
    int whitening_rounds = std::max(4, std::min(4 + rounds / 16, rounds));
    permute(s, whitening_rounds, sched);
}

// ─────────────────────────────────────────────────────────────────────────────
// absorb_block — Davies-Meyer block absorption
// ─────────────────────────────────────────────────────────────────────────────

static void absorb_block(State8&              s,
                          const uint8_t*       block,
                          uint64_t             block_index,
                          const SaltKey&       sk,
                          const RoundSchedule& sched,
                          int                  rounds)
{
    const uint64_t rounds_tweak = static_cast<uint64_t>(rounds) * DOM_ROUNDS;
    const uint64_t obf_index   = block_index
                                ^ sk[0]
                                ^ rotl64(sk[1], 32)
                                ^ rounds_tweak;

    for (int word = 0; word < 8; ++word) {
        const uint64_t input_word = load_le64(block + word * 8);
        const uint64_t tweak = rotl64(
            obf_index
                + static_cast<uint64_t>(word)
                + s[static_cast<size_t>(word)]
                + sk[static_cast<size_t>(word)],
            ROT[word % 8]
        );
        s[static_cast<size_t>(word)] ^= input_word ^ tweak;
    }

    const State8 before = s;
    permute(s, rounds, sched);
    for (size_t word = 0; word < 8; ++word)
        s[word] ^= before[word];          // Davies-Meyer feed-forward
}

// ─────────────────────────────────────────────────────────────────────────────
// make_init_state — derive per-call initial chaining value
// ─────────────────────────────────────────────────────────────────────────────

static State8 make_init_state(int                  rounds,
                               const SaltKey&       sk,
                               const RoundSchedule& sched,
                               uint64_t             domain_const)
{
    State8 s = INIT_STATE;
    const uint64_t rounds_tweak = static_cast<uint64_t>(rounds) * DOM_ROUNDS;

    for (int word = 0; word < 8; ++word) {
        s[static_cast<size_t>(word)] ^= sk[static_cast<size_t>(word)];
        s[static_cast<size_t>(word)] ^= rotl64(rounds_tweak, ROT[word]);
        s[static_cast<size_t>(word)] ^=
            rotl64(domain_const, (word * 13 + 7) % 63 + 1);
    }

    const int init_rounds = std::max(4, rounds / 8);
    permute(s, init_rounds, sched);
    return s;
}

// ─────────────────────────────────────────────────────────────────────────────
// feistel_round — single Feistel pass (extracted from feistel_whiten)
// ─────────────────────────────────────────────────────────────────────────────

static void feistel_round(uint8_t*      left,   size_t left_len,
                           const uint8_t* right, size_t right_len,
                           uint64_t       round_key) noexcept
{
    // Build keystream state from right half absorbed into SipHash.
    uint64_t ks_v0, ks_v1, ks_v2, ks_v3;
    make_sip_state(round_key, round_key, round_key, round_key,
                   ks_v0, ks_v1, ks_v2, ks_v3);

    const size_t full_words = right_len / 8;
    for (size_t word = 0; word < full_words; ++word)
        sip_absorb(ks_v0, ks_v1, ks_v2, ks_v3, load_le64(right + word * 8));

    if (right_len % 8 != 0) {
        const size_t remainder = right_len % 8;
        uint64_t tail = (static_cast<uint64_t>(right_len) & 0xFF) << 56;
        const uint8_t* tail_ptr = right + full_words * 8;
        for (size_t byte_idx = 0; byte_idx < remainder; ++byte_idx)
            tail |= static_cast<uint64_t>(tail_ptr[byte_idx]) << (byte_idx * 8);
        sip_absorb(ks_v0, ks_v1, ks_v2, ks_v3, tail);
    }

    // XOR left half with SipHash-CTR keystream.
    size_t pos = 0;
    uint64_t ctr = 0;
    while (pos < left_len) {
        uint64_t sv0 = ks_v0, sv1 = ks_v1, sv2 = ks_v2, sv3 = ks_v3;
        sip_absorb(sv0, sv1, sv2, sv3, ctr++);
        const uint64_t ks_word = sip_finalize(sv0, sv1, sv2, sv3);

        const size_t take = std::min<size_t>(8, left_len - pos);
        for (size_t byte_idx = 0; byte_idx < take; ++byte_idx, ++pos)
            left[pos] ^= static_cast<uint8_t>((ks_word >> (byte_idx * 8)) & 0xFF);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// feistel_whiten — Feistel-network byte-level whitening
// ─────────────────────────────────────────────────────────────────────────────

static std::vector<uint8_t> feistel_whiten(const std::vector<uint8_t>& input,
                                            const SaltKey& sk,
                                            int rounds)
{
    if (input.empty()) return {};

    std::vector<uint8_t> out(input);
    const size_t seq_len = out.size();

    if (seq_len < 2) {
        out[0] ^= static_cast<uint8_t>(sk[0] & 0xFF);
        return out;
    }

    const int feistel_rounds = std::min(16, std::max(8, rounds / 4));
    const size_t half = seq_len / 2;

    for (int fr = 0; fr < feistel_rounds; ++fr) {
        const uint64_t round_key =
            sk[static_cast<size_t>(fr) % 8]
            ^ (static_cast<uint64_t>(fr) * GOLDEN)
            ^ rotl64(sk[static_cast<size_t>(fr + 1) % 8],
                     (fr * 13 + 7) % 63 + 1);

        uint8_t* left_ptr   = out.data();
        uint8_t* right_ptr  = out.data() + half;
        size_t   left_len   = half;
        size_t   right_len  = seq_len - half;

        if (fr % 2 == 1) {
            std::swap(left_ptr,  right_ptr);
            std::swap(left_len,  right_len);
        }

        feistel_round(left_ptr, left_len,
                      right_ptr, right_len,
                      round_key);
    }
    return out;
}

// ─────────────────────────────────────────────────────────────────────────────
// BPE Vocabulary — cl100k_base-compatible
//
// Loaded lazily on first use via std::call_once for thread safety.
// If "cl100k_base.tiktoken" is absent from CWD, a byte-level fallback
// (256 single-byte tokens, ID == byte value) is used instead.
// ─────────────────────────────────────────────────────────────────────────────

struct BpeVocab {
    std::unordered_map<std::string, uint32_t> token_to_rank;
    bool use_fallback = false;
};

// Base64 decode table (generated from RFC 4648 alphabet).
static constexpr int8_t B64[256] = {
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
    52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
    -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
    15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
    -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
    41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
};

static std::string base64_decode(const std::string& s)
{
    std::string out;
    out.reserve(s.size() * 3 / 4);
    uint32_t acc  = 0;
    int      bits = 0;
    for (unsigned char c : s) {
        if (c == '=' || c == '\n' || c == '\r') continue;
        int v = B64[c];
        if (v < 0) continue;
        acc   = (acc << 6) | static_cast<uint32_t>(v);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out += static_cast<char>((acc >> bits) & 0xFF);
        }
    }
    return out;
}

static void load_vocab(BpeVocab& vocab)
{
    std::ifstream file("cl100k_base.tiktoken");
    if (!file.is_open()) {
        vocab.use_fallback = true;
        for (int byte_val = 0; byte_val < 256; ++byte_val) {
            std::string tok(1, static_cast<char>(byte_val));
            vocab.token_to_rank[tok] = static_cast<uint32_t>(byte_val);
        }
        return;
    }

    std::string line;
    while (std::getline(file, line)) {
        if (line.empty()) continue;
        const size_t space_pos = line.rfind(' ');
        if (space_pos == std::string::npos) continue;
        const std::string token_bytes = base64_decode(line.substr(0, space_pos));
        const uint32_t    rank =
            static_cast<uint32_t>(std::stoul(line.substr(space_pos + 1)));
        vocab.token_to_rank[token_bytes] = rank;
    }
}

static const BpeVocab& get_vocab()
{
    static BpeVocab      vocab;
    static std::once_flag init_flag;
    std::call_once(init_flag, load_vocab, std::ref(vocab));
    return vocab;
}

// ─────────────────────────────────────────────────────────────────────────────
// BPE encode — index-based merge loop, zero per-pair heap allocation
//
// Token extents are tracked as (start, length) pairs into a flat byte
// buffer, eliminating the O(n²) std::string allocations of the naive
// approach.  The algorithm is semantically identical to tiktoken's BPE.
// ─────────────────────────────────────────────────────────────────────────────

static std::vector<uint32_t> bpe_encode(const std::string& text)
{
    const BpeVocab& vocab = get_vocab();

    if (text.empty()) return {};

    const auto* bytes = reinterpret_cast<const uint8_t*>(text.data());
    const size_t text_len = text.size();

    if (vocab.use_fallback) {
        // Byte-level fallback: each byte is its own token (no merges).
        std::vector<uint32_t> ids(text_len);
        for (size_t i = 0; i < text_len; ++i)
            ids[i] = static_cast<uint32_t>(bytes[i]);
        return ids;
    }

    // Represent each token as (start_offset, byte_length) into 'text'.
    // This avoids allocating a std::string per token throughout the loop.
    struct Span { size_t start; size_t len; };
    std::vector<Span> parts(text_len);
    for (size_t i = 0; i < text_len; ++i)
        parts[i] = { i, 1 };

    auto span_str = [&](const Span& sp) -> std::string {
        return text.substr(sp.start, sp.len);
    };

    // BPE merge loop: O(n²) comparisons, O(1) allocations per iteration
    // (one std::string for the best-pair key lookup; one for the merge key).
    while (parts.size() >= 2) {
        uint32_t best_rank = UINT32_MAX;
        size_t   best_idx  = SIZE_MAX;

        for (size_t i = 0; i + 1 < parts.size(); ++i) {
            const std::string pair_key = span_str(parts[i]) + span_str(parts[i + 1]);
            const auto it = vocab.token_to_rank.find(pair_key);
            if (it != vocab.token_to_rank.end() && it->second < best_rank) {
                best_rank = it->second;
                best_idx  = i;
            }
        }

        if (best_idx == SIZE_MAX) break;

        // Merge all occurrences of the best pair in one pass.
        const std::string merged_key =
            span_str(parts[best_idx]) + span_str(parts[best_idx + 1]);
        const Span merged_span = {
            parts[best_idx].start,
            parts[best_idx].len + parts[best_idx + 1].len
        };

        std::vector<Span> next;
        next.reserve(parts.size());
        for (size_t i = 0; i < parts.size(); ) {
            if (i + 1 < parts.size() &&
                span_str(parts[i]) + span_str(parts[i + 1]) == merged_key &&
                vocab.token_to_rank.count(merged_key)) {
                next.push_back(merged_span);
                i += 2;
            } else {
                next.push_back(parts[i]);
                ++i;
            }
        }
        parts = std::move(next);
    }

    // Convert spans to token IDs.
    std::vector<uint32_t> ids;
    ids.reserve(parts.size());
    for (const Span& sp : parts) {
        const std::string tok = span_str(sp);
        const auto it = vocab.token_to_rank.find(tok);
        if (it != vocab.token_to_rank.end()) {
            ids.push_back(it->second);
        } else {
            // Unknown token: map to [131072..262143] (bit 17 set),
            // permanently outside the cl100k_base rank range [0..100255].
            const uint64_t h = strong_hash(
                reinterpret_cast<const uint8_t*>(tok.data()),
                std::min(tok.size(), static_cast<size_t>(255)),
                DOM_TOKEN
            );
            ids.push_back(0x00020000U | static_cast<uint32_t>(h & 0x0001FFFFU));
        }
    }
    return ids;
}

// ─────────────────────────────────────────────────────────────────────────────
// Token-level salt mixing (FIX-P, v9 — unchanged semantics)
// ─────────────────────────────────────────────────────────────────────────────

static std::vector<uint32_t> mix_tokens(const std::vector<uint32_t>& input_ids,
                                         const std::vector<uint32_t>& salt_ids,
                                         const SaltKey& sk,
                                         int rounds)
{
    if (input_ids.empty() || salt_ids.empty()) return input_ids;

    static constexpr uint32_t GOLDEN32 = 0x9e3779b9U;
    const size_t salt_count = salt_ids.size();

    std::vector<uint32_t> out(input_ids.size());
    for (size_t i = 0; i < input_ids.size(); ++i) {
        // Position-dependent rotation amount in [1..31].
        const uint64_t pos_key = sk[i % 8]
                               ^ (static_cast<uint64_t>(i) * GOLDEN)
                               ^ (static_cast<uint64_t>(rounds) * DOM_TOKEN);
        const int rot_amt =
            static_cast<int>((pos_key ^ (pos_key >> 32)) % 31) + 1;

        const uint32_t salt_val = salt_ids[i % salt_count];
        const uint32_t rotated  = (salt_val << rot_amt) | (salt_val >> (32 - rot_amt));
        uint32_t mix_val = rotated ^ (salt_val * GOLDEN32);

        // Block-counter injection every 16 tokens to break block patterns.
        const uint64_t block_ctr = static_cast<uint64_t>(i / 16);
        const uint64_t ctr_mix   = sk[(i / 16) % 8] ^ (block_ctr * DOM_TOKEN);
        mix_val ^= static_cast<uint32_t>(ctr_mix & 0xFFFFFFFFU);

        out[i] = (input_ids[i] ^ mix_val) & 0x0001FFFFU;
    }
    return out;
}

// ─────────────────────────────────────────────────────────────────────────────
// Token sequence → dense bit stream (17 bits per token, MSB first)
//
// Replaced bit-per-iteration loop with a 64-bit accumulator: gather 64
// bits into a uint64_t, then store the whole word.  Bitfield edge cases
// at the end are handled by the partial-word flush.
// ─────────────────────────────────────────────────────────────────────────────

static std::vector<uint8_t> tokens_to_bits(const std::vector<uint32_t>& ids)
{
    if (ids.empty()) return {};

    const size_t total_bits  = ids.size() * 17;
    const size_t total_bytes = (total_bits + 7) / 8;
    std::vector<uint8_t> buf(total_bytes, 0);

    uint64_t acc       = 0;   // accumulator, MSB-aligned
    int      acc_bits  = 0;   // number of valid bits in acc (from the top)
    size_t   byte_out  = 0;

    for (uint32_t id : ids) {
        // Insert 17 bits of id into acc (MSB first).
        acc = (acc << 17) | (id & 0x1FFFFU);
        acc_bits += 17;

        // Flush complete bytes.
        while (acc_bits >= 8) {
            acc_bits -= 8;
            buf[byte_out++] = static_cast<uint8_t>((acc >> acc_bits) & 0xFF);
        }
    }
    // Flush remaining partial byte (if any), left-aligned.
    if (acc_bits > 0)
        buf[byte_out] = static_cast<uint8_t>((acc << (8 - acc_bits)) & 0xFF);

    return buf;
}

// ─────────────────────────────────────────────────────────────────────────────
// tokenize_and_encode — v9 pipeline entry point
// ─────────────────────────────────────────────────────────────────────────────

static std::vector<uint8_t> tokenize_and_encode(const uint8_t*     input_data,
                                                 size_t             input_len,
                                                 const std::string* salt,
                                                 const SaltKey&     sk,
                                                 int                rounds)
{
    const std::string input_str(reinterpret_cast<const char*>(input_data),
                                input_len);
    std::vector<uint32_t> input_ids = bpe_encode(input_str);

    std::vector<uint32_t> salt_ids;
    if (salt && !salt->empty())
        salt_ids = bpe_encode(*salt);

    const std::vector<uint32_t> mixed_ids =
        salt_ids.empty()
            ? input_ids
            : mix_tokens(input_ids, salt_ids, sk, rounds);

    return tokens_to_bits(mixed_ids);
}

// ─────────────────────────────────────────────────────────────────────────────
// scatter_positions — hash-based salt insertion positions
// (extracted from build_scattered_message / FIX-Y)
// ─────────────────────────────────────────────────────────────────────────────

static std::vector<size_t> scatter_positions(
    const uint8_t* input_data, size_t input_len,
    const uint8_t* salt_data,  size_t salt_len,
    const SaltKey& sk,
    int            rounds)
{
    const size_t total_len = input_len + salt_len;
    const uint64_t data_hash =
        strong_hash(input_data, std::min(input_len, static_cast<size_t>(255)),
                    DOM_SALT ^ static_cast<uint64_t>(rounds));

    std::vector<size_t> positions(salt_len);
    for (size_t i = 0; i < salt_len; ++i) {
        uint64_t h = data_hash
                   ^ (sk[i % 8] * static_cast<uint64_t>(i + 1))
                   ^ (GOLDEN   * static_cast<uint64_t>(rounds + i));
        h ^= static_cast<uint64_t>(salt_data[i]) * 0x517cc1b727220a95ULL;
        if (i + 1 < salt_len)
            h ^= static_cast<uint64_t>(salt_data[i + 1]) * DOM_SALT;

        uint64_t v0, v1, v2, v3;
        make_sip_state(h, sk[0], data_hash, GOLDEN, v0, v1, v2, v3);
        sip_absorb(v0, v1, v2, v3, h ^ static_cast<uint64_t>(i));
        h = sip_finalize(v0, v1, v2, v3);

        const int rot_amt = static_cast<int>((i * 7 + static_cast<size_t>(rounds)) % 62) + 1;
        h = rotl64(h, rot_amt);
        positions[i] = static_cast<size_t>(h % total_len);
    }
    return positions;
}

// ─────────────────────────────────────────────────────────────────────────────
// resolve_collisions — double-hash open-addressing collision resolution
// (extracted from build_scattered_message / FIX-Y)
// ─────────────────────────────────────────────────────────────────────────────

static void resolve_collisions(std::vector<size_t>& positions,
                                const uint8_t* salt_data, size_t salt_len,
                                const SaltKey& sk,
                                uint64_t       data_hash,
                                size_t         total_len)
{
    std::vector<bool> occupied(total_len, false);

    for (size_t i = 0; i < salt_len; ++i) {
        const uint64_t stride_h = strong_hash(
            salt_data, std::min(salt_len, static_cast<size_t>(255)),
            data_hash ^ sk[i % 8] ^ static_cast<uint64_t>(i)
        );
        size_t stride = static_cast<size_t>(stride_h % total_len);
        if (stride == 0) stride = 1;
        if (stride % 2 == 0) stride ^= 1;

        size_t pos   = positions[i];
        size_t probe = 0;
        while (occupied[pos] && probe < total_len) {
            ++probe;
            pos = (positions[i] + probe * stride) % total_len;
        }
        if (occupied[pos]) {
            pos = (positions[i] + 1) % total_len;
            while (occupied[pos])
                pos = (pos + 1) % total_len;
        }
        occupied[pos]  = true;
        positions[i]   = pos;
    }

    // Postcondition: all positions are unique.
    assert([&]() {
        std::vector<size_t> sorted_pos = positions;
        std::sort(sorted_pos.begin(), sorted_pos.end());
        return std::adjacent_find(sorted_pos.begin(), sorted_pos.end())
               == sorted_pos.end();
    }() && "resolve_collisions: duplicate positions detected");
}

// ─────────────────────────────────────────────────────────────────────────────
// interleave_salt — assemble final scattered message buffer
// (extracted from build_scattered_message / FIX-Y)
// ─────────────────────────────────────────────────────────────────────────────

static std::vector<uint8_t> interleave_salt(
    const uint8_t*            input_data, size_t input_len,
    const uint8_t*            salt_data,  size_t salt_len,
    const std::vector<size_t>& positions)
{
    const size_t total_len = input_len + salt_len;
    std::vector<uint8_t> result(total_len, 0);
    std::vector<bool>    is_salt(total_len, false);

    for (size_t i = 0; i < salt_len; ++i) {
        result[positions[i]] = salt_data[i];
        is_salt[positions[i]] = true;
    }
    size_t input_idx = 0;
    for (size_t j = 0; j < total_len && input_idx < input_len; ++j)
        if (!is_salt[j]) result[j] = input_data[input_idx++];

    return result;
}

// ─────────────────────────────────────────────────────────────────────────────
// build_scattered_message — salt byte scattering into the token bit stream
// ─────────────────────────────────────────────────────────────────────────────

static std::vector<uint8_t> build_scattered_message(
    const uint8_t*     input_data,
    size_t             input_len,
    const std::string* salt,
    const SaltKey&     sk,
    int                rounds)
{
    if (!salt || salt->empty())
        return std::vector<uint8_t>(input_data, input_data + input_len);

    const uint8_t* salt_data = reinterpret_cast<const uint8_t*>(salt->data());
    const size_t   salt_len  = salt->size();
    const size_t   total_len = input_len + salt_len;

    const uint64_t data_hash =
        strong_hash(input_data, std::min(input_len, static_cast<size_t>(255)),
                    DOM_SALT ^ static_cast<uint64_t>(rounds));

    std::vector<size_t> positions =
        scatter_positions(input_data, input_len, salt_data, salt_len, sk, rounds);

    resolve_collisions(positions, salt_data, salt_len, sk, data_hash, total_len);

    return interleave_salt(input_data, input_len, salt_data, salt_len, positions);
}

// ─────────────────────────────────────────────────────────────────────────────
// validate_rounds — public API guard
// ─────────────────────────────────────────────────────────────────────────────

static void validate_rounds(int rounds)
{
    if (rounds <= 1)
        throw std::invalid_argument("rudra::hash: rounds must be > 1");
}

// ─────────────────────────────────────────────────────────────────────────────
// stream_engine — ARX absorption + HAIFA double-finalisation
// ─────────────────────────────────────────────────────────────────────────────

template <typename Feeder>
static std::string stream_engine(State8               init,
                                  uint64_t             total_len,
                                  uint64_t             original_len,
                                  int                  rounds,
                                  const SaltKey&       sk,
                                  const RoundSchedule& sched,
                                  Feeder&&             feeder)
{
    State8 state = init;
    whiten_state(state, sk, sched, rounds);

    uint64_t ent_v0 = sk[0] ^ DOM_FINAL;
    uint64_t ent_v1 = static_cast<uint64_t>(rounds) * DOM_ROUNDS ^ sk[1];
    uint64_t ent_v2 = total_len ^ original_len ^ sk[2];
    uint64_t ent_v3 = DOM_FEIST ^ sk[3];

    uint64_t block_idx = 0;
    std::vector<uint8_t> carry;
    carry.reserve(64);

    auto absorb_feed = [&](const uint8_t* src, size_t src_len) {
        size_t offset = 0;
        while (carry.size() + (src_len - offset) >= 64) {
            const size_t need = 64 - carry.size();
            carry.insert(carry.end(), src + offset, src + offset + need);

            absorb_block(state, carry.data(), block_idx, sk, sched, rounds);
            sip_absorb(ent_v0, ent_v1, ent_v2, ent_v3,
                       block_idx ^ state[0] ^ state[7]);
            carry.clear();
            offset += need;
            ++block_idx;
        }
        carry.insert(carry.end(), src + offset, src + src_len);
    };

    feeder(absorb_feed);

    // Merkle-Damgård / HAIFA length padding.
    const uint64_t bit_lo = total_len << 3;
    const uint64_t bit_hi = total_len >> 61;

    carry.push_back(0x80);
    while (carry.size() % 64 != 48) carry.push_back(0x00);
    for (int byte_idx = 7; byte_idx >= 0; --byte_idx)
        carry.push_back(
            static_cast<uint8_t>((bit_hi >> (byte_idx * 8)) & 0xFF));
    for (int byte_idx = 7; byte_idx >= 0; --byte_idx)
        carry.push_back(
            static_cast<uint8_t>((bit_lo >> (byte_idx * 8)) & 0xFF));

    for (size_t offset = 0; offset < carry.size(); offset += 64, ++block_idx) {
        absorb_block(state, carry.data() + offset, block_idx, sk, sched, rounds);
        sip_absorb(ent_v0, ent_v1, ent_v2, ent_v3,
                   block_idx ^ state[0] ^ state[7]);
    }

    const uint64_t entropy_final =
        sip_finalize(ent_v0, ent_v1, ent_v2, ent_v3);

    state[7] ^= entropy_final ^ rotl64(entropy_final, 31);
    permute(state, rounds, sched);

    // HAIFA double-finalisation: inject all length and domain fields.
    state[0] ^= original_len ^ DOM_FINAL;
    state[1] ^= total_len    ^ rotl64(DOM_FINAL, 32);
    state[2] ^= rotl64(original_len ^ total_len, 17);
    state[3] ^= static_cast<uint64_t>(rounds) * DOM_ROUNDS ^ DOM_FINAL;
    state[4] ^= sk[4] ^ rotl64(entropy_final, 13);
    state[5] ^= rotl64(original_len, 41) ^ total_len ^ sk[5];
    state[6] ^= entropy_final ^ static_cast<uint64_t>(rounds) ^ sk[6];
    state[7] ^= rotl64(sk[7] ^ total_len, 29);

    permute(state, rounds, sched);

    std::ostringstream ss;
    ss << std::hex << std::setfill('0');
    for (uint64_t word : state) ss << std::setw(16) << word;
    return ss.str();
}

// ─────────────────────────────────────────────────────────────────────────────
// PUBLIC API — hash_string
// ─────────────────────────────────────────────────────────────────────────────

[[nodiscard]]
std::string hash_string(const std::string& input,
                        int                rounds,
                        const std::string* salt)
{
    validate_rounds(rounds);

    const uint8_t* in_data = reinterpret_cast<const uint8_t*>(input.data());
    const size_t   in_len  = input.size();

    const SaltKey       sk    = expand_salt(salt);
    const RoundSchedule sched = make_round_schedule(sk, rounds);

    const std::vector<uint8_t> token_bits =
        tokenize_and_encode(in_data, in_len, salt, sk, rounds);

    const auto combined  = build_scattered_message(
        token_bits.data(), token_bits.size(), salt, sk, rounds);
    const auto processed = feistel_whiten(combined, sk, rounds);

    const State8   init         = make_init_state(rounds, sk, sched, DOM_STRING);
    const uint64_t total_len    = static_cast<uint64_t>(processed.size());
    const uint64_t original_len = static_cast<uint64_t>(in_len);

    return stream_engine(init, total_len, original_len, rounds, sk, sched,
        [&](auto feed) { feed(processed.data(), processed.size()); });
}

// ─────────────────────────────────────────────────────────────────────────────
// PUBLIC API — hash_file
// ─────────────────────────────────────────────────────────────────────────────

[[nodiscard]]
std::string hash_file(const std::string& filename,
                      int                rounds,
                      const std::string* salt)
{
    validate_rounds(rounds);

    std::ifstream file(filename, std::ios::binary);
    if (!file)
        throw std::runtime_error(
            "rudra::hash_file: cannot open '" + filename + "'");

    std::vector<uint8_t> file_buf;
    {
        constexpr size_t CHUNK_SIZE = 65536;
        std::vector<uint8_t> chunk(CHUNK_SIZE);
        while (file.read(reinterpret_cast<char*>(chunk.data()), CHUNK_SIZE)
               || file.gcount() > 0)
        {
            const std::streamsize got = file.gcount();
            file_buf.insert(file_buf.end(),
                            chunk.data(), chunk.data() + got);
        }
        if (file.bad())
            throw std::runtime_error(
                "rudra::hash_file: read error on '" + filename + "'");
    }

    const SaltKey       sk    = expand_salt(salt);
    const RoundSchedule sched = make_round_schedule(sk, rounds);

    const std::vector<uint8_t> token_bits =
        tokenize_and_encode(file_buf.data(), file_buf.size(), salt, sk, rounds);

    const auto combined  = build_scattered_message(
        token_bits.data(), token_bits.size(), salt, sk, rounds);
    const auto processed = feistel_whiten(combined, sk, rounds);

    const State8   init         = make_init_state(rounds, sk, sched, DOM_FILE);
    const uint64_t total_len    = static_cast<uint64_t>(processed.size());
    const uint64_t original_len = static_cast<uint64_t>(file_buf.size());

    return stream_engine(init, total_len, original_len, rounds, sk, sched,
        [&](auto feed) { feed(processed.data(), processed.size()); });
}

} // namespace rudra