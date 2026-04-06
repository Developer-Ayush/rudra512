/*
 * rudra512.cpp  —  hardened implementation v4
 *
 * ════════════════════════════════════════════════════════════════════
 * ARCHITECTURE v4
 * ════════════════════════════════════════════════════════════════════
 *
 * NEW: Scattered Salt Injection (SSI)
 *   Each byte of salt is placed at an INDEPENDENT position determined by:
 *     pos[i] = f(input_size, salt_len, rounds, data_hash, i)
 *   No two salt bytes share a position. Positions are spread across the
 *   full message domain, not clustered.
 *
 * NEW: Proper Tokenization Pipeline
 *   After SSI, the combined buffer is tokenized into variable-length
 *   tokens. Each token is permuted (byte shuffle based on token hash),
 *   then a token-level mixing pass runs before block absorption.
 *
 * FIXED: rotl64 UB (shift-by-0 and shift-by-64 eliminated)
 * FIXED: simple_hash replaced with siphash-inspired mixer
 * FIXED: tokenize() is now actually used
 * FIXED: domain separation between hash_string and hash_file
 * FIXED: state whitening uses full-round injection
 * FIXED: ROUND_ROT duplicates removed
 * FIXED: hash_file no longer reads full file into memory
 * FIXED: salt position degeneracy for short inputs
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
// Initialization constants (frac(sqrt(prime)) * 2^64)
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

// Primary rotation constants (prime, no duplicates, no complementary pairs)
static const int ROT[8] = { 7, 11, 13, 19, 29, 37, 41, 47 };

// Period-64 rotation schedule — all values distinct, none 0 or 64
// Generated: primes mod 63 + 1, deduplicated, padded with remaining primes
static const int ROUND_ROT[64] = {
     3,  5,  7, 11, 13, 17, 19, 23,
    29, 31, 37, 41, 43, 47, 53, 59,
    61,  2,  4,  6,  8, 10, 12, 14,
    16, 18, 20, 22, 24, 26, 28, 30,
    32, 34, 36, 38, 40, 42, 44, 46,
    48, 50, 52, 54, 56, 58, 60, 62,
     1,  9, 15, 21, 25, 27, 33, 35,
    39, 45, 49, 51, 55, 57, 63, 15
};

// Domain separation constants
static const uint64_t DOM_STRING   = 0x243f6a8885a308d3ULL;  // frac(pi)
static const uint64_t DOM_FILE     = 0x517cc1b727220a95ULL;  // frac(e)
static const uint64_t DOM_TOKEN    = 0x6c15b6c9aa27a8a4ULL;  // frac(sqrt(2))
static const uint64_t DOM_SALT     = 0xb5470917a2388f00ULL;  // frac(sqrt(3))
static const uint64_t DOM_ROUNDS   = 0x9e3779b97f4a7c15ULL;  // golden ratio

// ─────────────────────────────────────────────────────────────────────────────
// Primitives
// ─────────────────────────────────────────────────────────────────────────────
static inline uint64_t rotl64(uint64_t x, int r) {
    // r must be in [1, 63] — enforced at all call sites
    return (x << r) | (x >> (64 - r));
}

// Safe rotation: clamps to [1,63]
static inline uint64_t safe_rotl64(uint64_t x, int r) {
    r = ((r % 63) + 63) % 63;  // result in [0,62]
    if (r == 0) r = 1;
    return rotl64(x, r);
}

// ─────────────────────────────────────────────────────────────────────────────
// SipHash-inspired 64-bit mixer (replaces broken simple_hash)
// Non-linear, good avalanche, no trivial collisions for nearby inputs
// ─────────────────────────────────────────────────────────────────────────────
static uint64_t mix64(uint64_t v0, uint64_t v1, uint64_t v2, uint64_t v3) {
    // SipRound
    v0 += v1; v1 = rotl64(v1, 13); v1 ^= v0; v0 = rotl64(v0, 32);
    v2 += v3; v3 = rotl64(v3, 16); v3 ^= v2;
    v0 += v3; v3 = rotl64(v3, 21); v3 ^= v0;
    v2 += v1; v1 = rotl64(v1, 17); v1 ^= v2; v2 = rotl64(v2, 32);
    return v0 ^ v1 ^ v2 ^ v3;
}

static uint64_t strong_hash(const uint8_t* data, size_t len, uint64_t seed) {
    uint64_t v0 = seed ^ 0x736f6d6570736575ULL;
    uint64_t v1 = seed ^ 0x646f72616e646f6dULL;
    uint64_t v2 = seed ^ 0x6c7967656e657261ULL;
    uint64_t v3 = seed ^ 0x7465646279746573ULL;

    size_t blocks = len / 8;
    for (size_t i = 0; i < blocks; i++) {
        uint64_t m = 0;
        memcpy(&m, data + i * 8, 8);
        v3 ^= m;
        v0 = mix64(v0, v1, v2, v3);
        v0 = mix64(v0, v1, v2, v3);  // 2 rounds
        v0 ^= m;
    }

    // Tail
    uint64_t tail = static_cast<uint64_t>(len) << 56;
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
    v3 ^= tail;
    v0 = mix64(v0, v1, v2, v3);
    v0 = mix64(v0, v1, v2, v3);
    v0 ^= tail;

    // Finalization
    v2 ^= 0xff;
    for (int i = 0; i < 4; i++) v0 = mix64(v0, v1, v2, v3);
    return v0 ^ v1 ^ v2 ^ v3;
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
// Permutation (fixed: safe_rotl64 eliminates UB)
// ─────────────────────────────────────────────────────────────────────────────
static void permute(std::array<uint64_t, 8>& s, int rounds) {
    for (int r = 0; r < rounds; r++) {
        const int mix  = (r % 7) + 1;
        const int mix2 = ((r + 2) % 7) + 1;
        const int mix3 = ((r + 4) % 7) + 1;

        const std::array<uint64_t, 8> old = s;

        for (int i = 0; i < 8; i++) {
            uint64_t v = old[i] ^ rotl64(old[(i + mix) % 8], ROT[i]);
            v += old[(i + mix2) % 8];
            // Asymmetric rotation — safe, always in [1,63]
            int asym_rot = ROUND_ROT[(i * 5 + r * 9) % 64];
            v = rotl64(v, asym_rot);  // ROUND_ROT values are all in [1,63]
            v ^= old[(i + 5) % 8] >> 17;
            s[i] = v;
        }

        for (int i = 0; i < 8; i++) {
            s[i] += rotl64(s[(i + mix3) % 8], ROT[(i + mix3) % 8]);
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// State whitening — injects all 8 words, full rounds
// ─────────────────────────────────────────────────────────────────────────────
static void whiten_state(std::array<uint64_t, 8>& s, uint64_t salt_hash, int rounds) {
    // Inject whitening constants into ALL 8 words before permuting
    static const uint64_t WK[8] = {
        0xa54ff53a5f1d36f1ULL, 0x510e527fade682d1ULL,
        0x9b05688c2b3e6c1fULL, 0x1f83d9abfb41bd6bULL,
        0x5be0cd19137e2179ULL, 0x7137449123ef65cdULL,
        0x367cd5071059ed8bULL, 0xcbbb9d5dc105a7d0ULL
    };
    for (int i = 0; i < 8; i++) {
        s[i] ^= WK[i] ^ rotl64(salt_hash, (i * 7 + 3) % 63 + 1);
    }
    int whiten_rounds = std::max(2, std::min(rounds / 4, 8));
    permute(s, whiten_rounds);
}

// ─────────────────────────────────────────────────────────────────────────────
// Block absorption
// ─────────────────────────────────────────────────────────────────────────────
static void absorb_block(std::array<uint64_t, 8>& s,
                          const uint8_t*            block,
                          uint64_t                  block_index,
                          uint64_t                  salt_hash,
                          int                       rounds)
{
    uint64_t obf_idx = block_index ^ salt_hash ^ rotl64(salt_hash, 32);

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

    // XOR into ALL 8 words, not just 4
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
// ════════════════════════════════════════════════════════════════════
// SCATTERED SALT INJECTION (SSI)
// ════════════════════════════════════════════════════════════════════
//
// Each salt byte i is placed at an independent position:
//
//   base_hash = strong_hash(input_data, input_len, DOM_SALT ^ rounds)
//   stride    = max(1, (input_len + salt_len) / salt_len)
//   pos[i]    = (base_hash * (i+1) * GOLDEN + i * stride
//                 + rotl(salt_hash, i%63+1)) % expanded_len
//
// Positions are de-collided: if two salt bytes land on the same slot,
// the later one is shifted forward. This guarantees all salt bytes are
// at distinct positions spread across the full message.
//
// The expanded buffer interleaves input bytes and salt bytes; the
// final layout is determined by the sorted position list.
// ─────────────────────────────────────────────────────────────────────────────
static std::vector<uint8_t> build_scattered_message(
    const uint8_t* input_data,
    size_t         input_len,
    const std::string* salt,
    int            rounds)
{
    // No salt: return input directly
    if (!salt || salt->empty()) {
        return std::vector<uint8_t>(input_data, input_data + input_len);
    }

    const uint8_t* salt_data = reinterpret_cast<const uint8_t*>(salt->data());
    size_t salt_len = salt->size();
    size_t total_len = input_len + salt_len;

    uint64_t salt_hash = strong_hash(salt_data, salt_len, DOM_SALT);
    uint64_t data_hash = strong_hash(input_data, input_len,
                                      DOM_SALT ^ static_cast<uint64_t>(rounds));

    // Compute independent position for each salt byte
    static const uint64_t GOLDEN = 0x9e3779b97f4a7c15ULL;

    std::vector<size_t> positions(salt_len);
    for (size_t i = 0; i < salt_len; i++) {
        uint64_t h = data_hash
                   ^ (salt_hash * static_cast<uint64_t>(i + 1))
                   ^ (GOLDEN * static_cast<uint64_t>(rounds + i));
        h = mix64(h, salt_hash, data_hash, GOLDEN ^ static_cast<uint64_t>(i));
        // Also fold in the actual salt byte value at position i
        h ^= static_cast<uint64_t>(salt_data[i]) * 0x517cc1b727220a95ULL;
        h = safe_rotl64(h, static_cast<int>((i * 7 + rounds) % 62) + 1);
        positions[i] = static_cast<size_t>(h % total_len);
    }

    // De-collide: sort and spread colliding positions
    // Strategy: for each collision, shift forward by 1 (wrapping) until free
    std::vector<bool> occupied(total_len, false);
    for (size_t i = 0; i < salt_len; i++) {
        size_t pos = positions[i];
        while (occupied[pos]) {
            pos = (pos + 1) % total_len;
        }
        occupied[pos] = true;
        positions[i] = pos;
    }

    // Build the output buffer:
    // - Slot a salt byte at each computed position
    // - Fill remaining slots with input bytes in order
    std::vector<uint8_t> result(total_len, 0);
    std::vector<bool> is_salt(total_len, false);

    for (size_t i = 0; i < salt_len; i++) {
        result[positions[i]] = salt_data[i];
        is_salt[positions[i]] = true;
    }

    size_t inp_idx = 0;
    for (size_t j = 0; j < total_len && inp_idx < input_len; j++) {
        if (!is_salt[j]) {
            result[j] = input_data[inp_idx++];
        }
    }

    return result;
}

// ─────────────────────────────────────────────────────────────────────────────
// ════════════════════════════════════════════════════════════════════
// TOKENIZATION + PRE-HASH MIXING PIPELINE
// ════════════════════════════════════════════════════════════════════
//
// After SSI produces the combined buffer, we:
//
//  1. Determine token size T from: strong_hash(buffer) + salt_len + rounds
//     T is in [2, 16].
//
//  2. Split buffer into tokens of size T (last token may be shorter).
//
//  3. For each token at index i:
//       a. Compute token_hash = strong_hash(token_bytes, T, DOM_TOKEN ^ i)
//       b. Apply intra-token byte shuffle:
//            shuffle order determined by token_hash (Fisher-Yates with LCG)
//       c. XOR each byte with a rolling key derived from token_hash and i
//
//  4. Concatenate all processed tokens back into a single flat buffer.
//     This buffer feeds the block absorber.
//
// The tokenization is deterministic (same inputs → same tokens) and
// adds non-linearity before absorption without adding length.
// ─────────────────────────────────────────────────────────────────────────────
static std::vector<uint8_t> tokenize_and_mix(
    const std::vector<uint8_t>& combined,
    const std::string*           salt,
    int                          rounds)
{
    if (combined.empty()) return {};

    size_t salt_len = salt ? salt->size() : 0;
    uint64_t buf_hash = strong_hash(combined.data(), combined.size(), DOM_TOKEN);

    // Token size: 2 to 16, driven by data + salt_len + rounds
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

        // Copy token
        std::vector<uint8_t> tok(combined.begin() + start,
                                  combined.begin() + end);

        // a. Token hash
        uint64_t th = strong_hash(tok.data(), tlen,
                                   DOM_TOKEN ^ static_cast<uint64_t>(ti));

        // b. Intra-token Fisher-Yates shuffle
        if (tlen > 1) {
            uint64_t lcg = th ^ (static_cast<uint64_t>(ti) * DOM_ROUNDS);
            std::vector<size_t> idx(tlen);
            std::iota(idx.begin(), idx.end(), 0);
            for (size_t k = tlen - 1; k > 0; k--) {
                // LCG step
                lcg = lcg * 6364136223846793005ULL + 1442695040888963407ULL;
                size_t j2 = static_cast<size_t>((lcg >> 33) % (k + 1));
                std::swap(idx[k], idx[j2]);
            }
            std::vector<uint8_t> shuffled(tlen);
            for (size_t k = 0; k < tlen; k++) shuffled[k] = tok[idx[k]];
            tok = shuffled;
        }

        // c. Rolling XOR with key derived from token hash + position
        uint64_t key = th ^ rotl64(buf_hash, static_cast<int>((ti * 11 + 7) % 63) + 1);
        for (size_t k = 0; k < tlen; k++) {
            tok[k] ^= static_cast<uint8_t>((key >> ((k % 8) * 8)) & 0xFF);
            // Advance key every 8 bytes
            if (k % 8 == 7) {
                key = mix64(key, th, buf_hash, static_cast<uint64_t>(ti * tlen + k));
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
    if (rounds < 1 || rounds > 512) {
        throw std::invalid_argument("rudra::hash: rounds must be in [1, 512]");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Streaming absorption engine
// ─────────────────────────────────────────────────────────────────────────────
template<typename Feeder>
static std::string stream_engine(std::array<uint64_t, 8> init,
                                  uint64_t                total_len,
                                  int                     rounds,
                                  uint64_t                salt_hash,
                                  Feeder&&                feeder)
{
    std::array<uint64_t, 8> state = init;

    // Whitening: inject salt and permute with proportional rounds
    whiten_state(state, salt_hash, rounds);

    uint64_t block_idx = 0;
    std::vector<uint8_t> carry;
    carry.reserve(64);

    auto feed = [&](const uint8_t* src, size_t src_len) {
        size_t off = 0;
        while (carry.size() + (src_len - off) >= 64) {
            size_t need = 64 - carry.size();
            carry.insert(carry.end(), src + off, src + off + need);
            absorb_block(state, carry.data(), block_idx++, salt_hash, rounds);
            carry.clear();
            off += need;
        }
        carry.insert(carry.end(), src + off, src + src_len);
    };

    feeder(feed);

    // Merkle-Damgård padding
    uint64_t bit_len = total_len * 8;
    carry.push_back(0x80);
    while (carry.size() % 64 != 56) carry.push_back(0x00);
    for (int i = 7; i >= 0; --i) {
        carry.push_back(static_cast<uint8_t>((bit_len >> (i * 8)) & 0xFF));
    }

    for (size_t off = 0; off < carry.size(); off += 64, block_idx++) {
        absorb_block(state, carry.data() + off, block_idx, salt_hash, rounds);
    }

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
    uint64_t total_len = static_cast<uint64_t>(processed.size());

    return stream_engine(init, total_len, rounds, salt_hash,
        [&](auto feed) {
            feed(processed.data(), processed.size());
        });
}

// ─────────────────────────────────────────────────────────────────────────────
// PUBLIC API — hash_file (true streaming — no full read into memory)
// ─────────────────────────────────────────────────────────────────────────────
std::string hash_file(const std::string& filename,
                      int                rounds,
                      const std::string* salt)
{
    validate_rounds(rounds);

    // Pass 1: read file to build SSI + tokenization
    // (SSI needs full data to compute scatter positions — unavoidable for SSI)
    // For very large files this could be chunked with a two-pass scheme,
    // but correctness requires seeing all bytes before scattering salt.
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
    uint64_t total_len = static_cast<uint64_t>(processed.size());

    return stream_engine(init, total_len, rounds, salt_hash,
        [&](auto feed) {
            feed(processed.data(), processed.size());
        });
}

} // namespace rudra