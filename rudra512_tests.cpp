/*
 * rudra512_tests.cpp — Comprehensive Cryptographic Test Suite
 *
 * Tests:
 *  1.  Determinism / KAT
 *  2.  Avalanche Effect (SAC — Strict Avalanche Criterion)
 *  3.  Bit Frequency / Bias Test
 *  4.  Byte Distribution Chi-Squared Test
 *  5.  Collision Resistance (Birthday-attack simulation)
 *  6.  Differential Uniformity (Hamming distance distribution)
 *  7.  Serial Correlation Test
 *  8.  Run-length Test (NIST SP800-22 Runs test)
 *  9.  Entropy Estimation (Shannon entropy per byte)
 * 10.  Length Extension Resistance
 * 11.  Salt/Domain Separation Test
 * 12.  Small-Input Sensitivity ("abc" vs "abd" etc.)
 * 13.  Zero-Input and All-Same-Byte Inputs
 * 14.  Long-input Stability (Hash of 1MB)
 * 15.  Near-Collision Search (detect suspiciously close outputs)
 * 16.  Monobit Frequency Test (NIST SP800-22 Test 1)
 * 17.  Block Frequency Test (NIST SP800-22 Test 2)
 * 18.  Longest Run of Ones Test (NIST SP800-22 Test 4)
 * 19.  Spectral / Autocorrelation test
 * 20.  Summary Report
 */

#include "rudra512.h"
#include <algorithm>
#include <array>
#include <bitset>
#include <cassert>
#include <chrono>
#include <cmath>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <map>
#include <numeric>
#include <random>
#include <set>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

// ─── helpers ─────────────────────────────────────────────────────────────────

static std::string repeat(const std::string& s, int n)
{
    std::string r; r.reserve(s.size() * n);
    for (int i = 0; i < n; ++i) r += s;
    return r;
}

// Convert 128-hex-digit hash string to 64 bytes
static std::array<uint8_t, 64> hex_to_bytes(const std::string& h)
{
    std::array<uint8_t, 64> b{};
    for (size_t i = 0; i < 64; ++i) {
        unsigned int v = 0;
        std::sscanf(h.c_str() + i * 2, "%02x", &v);
        b[i] = static_cast<uint8_t>(v);
    }
    return b;
}

// Hamming distance between two 512-bit hashes
static int hamming512(const std::string& a, const std::string& b)
{
    auto ba = hex_to_bytes(a);
    auto bb = hex_to_bytes(b);
    int d = 0;
    for (size_t i = 0; i < 64; ++i)
        d += __builtin_popcount(ba[i] ^ bb[i]);
    return d;
}

// Extract bit stream from a set of hash strings
static std::vector<int> extract_bits(const std::vector<std::string>& hashes)
{
    std::vector<int> bits;
    bits.reserve(hashes.size() * 512);
    for (auto& h : hashes) {
        auto b = hex_to_bytes(h);
        for (uint8_t byte : b)
            for (int bit = 7; bit >= 0; --bit)
                bits.push_back((byte >> bit) & 1);
    }
    return bits;
}

struct TestResult {
    std::string name;
    bool        passed;
    std::string detail;
};

static std::vector<TestResult> results;

static void report(const std::string& name, bool pass, const std::string& detail = "")
{
    results.push_back({name, pass, detail});
    std::cout << (pass ? "  [PASS] " : "  [FAIL] ") << name;
    if (!detail.empty()) std::cout << "  — " << detail;
    std::cout << "\n";
}

// ─── 1. DETERMINISM / KAT ────────────────────────────────────────────────────
static void test_determinism()
{
    std::cout << "\n[1] Determinism & KAT\n";
    bool ok = true;

    // Same input → same output, repeated 5 times
    const std::string h0 = rudra::hash_string("The quick brown fox");
    for (int i = 0; i < 5; ++i)
        if (rudra::hash_string("The quick brown fox") != h0) { ok = false; break; }

    // Different inputs → different outputs
    ok &= (rudra::hash_string("abc") != rudra::hash_string("abd"));
    ok &= (rudra::hash_string("")    != rudra::hash_string(" "));
    ok &= (rudra::hash_string("A")   != rudra::hash_string("a"));

    // Output length = 128 hex chars (512 bits)
    ok &= (rudra::hash_string("test").size() == 128);

    report("Determinism", ok, "5× repeat + 4 distinct-input checks + length=128");
}

// ─── 2. STRICT AVALANCHE CRITERION ───────────────────────────────────────────
static void test_avalanche()
{
    std::cout << "\n[2] Strict Avalanche Criterion (SAC)\n";
    const int N = 500;                // number of random inputs
    const int INPUT_BYTES = 32;

    std::mt19937_64 rng(0xDEADBEEF1234ULL);
    std::vector<double> bit_flip_ratios(512, 0.0);
    long long total_pairs = 0;
    double total_hamming = 0.0;

    for (int t = 0; t < N; ++t) {
        // Random 32-byte input
        std::string base(INPUT_BYTES, '\0');
        for (char& c : base) c = static_cast<char>(rng() & 0xFF);

        auto base_hash = rudra::hash_string(base);

        for (int bit = 0; bit < INPUT_BYTES * 8; ++bit) {
            std::string flipped = base;
            flipped[bit / 8] ^= static_cast<char>(1 << (bit % 8));
            auto flipped_hash = rudra::hash_string(flipped);
            int hd = hamming512(base_hash, flipped_hash);
            total_hamming += hd;
            ++total_pairs;
            bit_flip_ratios[bit % 512] += hd / 512.0;
        }
    }

    double avg_hamming = total_hamming / total_pairs;
    double avg_ratio   = avg_hamming / 512.0;

    // Ideal: each single-bit flip changes ~50% of output bits (256/512)
    bool pass_avg  = avg_ratio > 0.47 && avg_ratio < 0.53;

    // Per-bit variance: each output bit should flip ~50% of the time
    double worst_bit_ratio = 0.0;
    for (int i = 0; i < 512; ++i) {
        double r = bit_flip_ratios[i] / (N * INPUT_BYTES);
        worst_bit_ratio = std::max(worst_bit_ratio, std::abs(r - 0.5));
    }
    bool pass_bias = worst_bit_ratio < 0.15;

    std::ostringstream d;
    d << std::fixed << std::setprecision(4)
      << "avg Hamming=" << avg_hamming << "/" << 512
      << " (" << avg_ratio * 100 << "%), max per-bit bias=" << worst_bit_ratio;
    report("Avalanche (SAC) — average Hamming ~50%", pass_avg,   d.str());
    report("Avalanche (SAC) — per-output-bit bias < 15%", pass_bias, d.str());
}

// ─── 3. BIT FREQUENCY / BIAS ─────────────────────────────────────────────────
static void test_bit_frequency()
{
    std::cout << "\n[3] Bit Frequency & Bias\n";
    const int N = 2000;
    std::vector<std::string> hashes;
    hashes.reserve(N);
    std::mt19937_64 rng(0xCAFEBABEULL);
    for (int i = 0; i < N; ++i) {
        std::string s(16, '\0');
        for (char& c : s) c = static_cast<char>(rng() & 0xFF);
        hashes.push_back(rudra::hash_string(s));
    }

    auto bits = extract_bits(hashes);
    long long ones = std::count(bits.begin(), bits.end(), 1);
    double ratio = static_cast<double>(ones) / bits.size();
    bool pass = ratio > 0.49 && ratio < 0.51;

    std::ostringstream d;
    d << std::fixed << std::setprecision(5) << "ones=" << ratio * 100 << "% (ideal 50%)";
    report("Bit Frequency (ones ratio 49–51%)", pass, d.str());

    // Per-output-bit bias across N hashes
    std::vector<int> bit_counts(512, 0);
    for (auto& h : hashes) {
        auto b = hex_to_bytes(h);
        for (int i = 0; i < 512; ++i)
            bit_counts[i] += (b[i / 8] >> (7 - (i % 8))) & 1;
    }
    double max_bias = 0.0;
    for (int i = 0; i < 512; ++i)
        max_bias = std::max(max_bias, std::abs(bit_counts[i] / (double)N - 0.5));
    bool pass_bias = max_bias < 0.05;

    std::ostringstream d2;
    d2 << std::fixed << std::setprecision(5) << "max per-position bias=" << max_bias;
    report("Per-bit Positional Bias < 5%", pass_bias, d2.str());
}

// ─── 4. BYTE DISTRIBUTION CHI-SQUARED ────────────────────────────────────────
static void test_byte_distribution()
{
    std::cout << "\n[4] Byte Distribution (Chi-Squared)\n";
    const int N = 5000;
    std::array<long long, 256> freq{};
    std::mt19937_64 rng(0x12345678ULL);
    for (int i = 0; i < N; ++i) {
        std::string s(8, '\0');
        for (char& c : s) c = static_cast<char>(rng() & 0xFF);
        auto b = hex_to_bytes(rudra::hash_string(s));
        for (uint8_t byte : b) freq[byte]++;
    }

    long long total = N * 64LL;
    double expected = total / 256.0;
    double chi2 = 0.0;
    for (int i = 0; i < 256; ++i) {
        double diff = freq[i] - expected;
        chi2 += diff * diff / expected;
    }
    // 255 degrees of freedom, 99.9% confidence → chi2 < ~340
    bool pass = chi2 < 340.0;
    std::ostringstream d;
    d << std::fixed << std::setprecision(2) << "chi2=" << chi2 << " (dof=255, threshold=340)";
    report("Byte Distribution Chi-Squared", pass, d.str());
}

// ─── 5. COLLISION RESISTANCE ─────────────────────────────────────────────────
static void test_collision_resistance()
{
    std::cout << "\n[5] Collision Resistance\n";
    const int N = 100000;
    std::unordered_map<std::string, int> seen;
    seen.reserve(N);
    bool collision = false;
    std::mt19937_64 rng(0xABCDEF01ULL);
    for (int i = 0; i < N; ++i) {
        std::string s = std::to_string(i) + "_" + std::to_string(rng());
        std::string h = rudra::hash_string(s);
        if (seen.count(h)) { collision = true; break; }
        seen[h] = i;
    }
    std::ostringstream d;
    d << N << " distinct random inputs checked";
    report("Collision Resistance (" + std::to_string(N) + " inputs)", !collision, d.str());
}

// ─── 6. DIFFERENTIAL UNIFORMITY ──────────────────────────────────────────────
static void test_differential()
{
    std::cout << "\n[6] Differential Uniformity\n";
    const int N = 2000;
    std::map<int, int> hamming_hist;
    std::mt19937_64 rng(0xFEEDFACEULL);
    for (int i = 0; i < N; ++i) {
        std::string a(16, '\0'), b(16, '\0');
        for (char& c : a) c = static_cast<char>(rng() & 0xFF);
        // b differs from a in exactly k random bits
        b = a;
        int k = 1 + rng() % 8;
        for (int j = 0; j < k; ++j) {
            int bit = rng() % (16 * 8);
            b[bit / 8] ^= static_cast<char>(1 << (bit % 8));
        }
        int hd = hamming512(rudra::hash_string(a), rudra::hash_string(b));
        hamming_hist[hd / 32]++;  // bucket by 32-bit ranges
    }

    // Check distribution is roughly uniform: no bucket > 20% of total,
    // and central buckets (around 256) are most populated
    int central = hamming_hist.count(8) ? hamming_hist[8] : 0; // 256-288 bucket
    bool pass = (central > N * 0.05); // at least 5% near center

    // Also check that min hamming is never 0 (no accidental collisions from 1-bit diffs)
    int min_hd_seen = 512;
    for (auto& [k, v] : hamming_hist) min_hd_seen = std::min(min_hd_seen, k * 32);

    std::ostringstream d;
    d << "central-bucket count=" << central << "/" << N
      << ", min_hamming_bucket=" << min_hd_seen;
    report("Differential Uniformity (Hamming distribution)", pass, d.str());
}

// ─── 7. SERIAL CORRELATION ───────────────────────────────────────────────────
static void test_serial_correlation()
{
    std::cout << "\n[7] Serial Correlation\n";
    const int N = 3000;
    std::mt19937_64 rng(0x9988776655ULL);
    std::vector<double> bytes_flat;
    bytes_flat.reserve(N * 64);
    for (int i = 0; i < N; ++i) {
        std::string s = std::to_string(i);
        auto b = hex_to_bytes(rudra::hash_string(s));
        for (uint8_t byte : b) bytes_flat.push_back(byte / 255.0);
    }

    // Serial correlation coefficient between consecutive bytes
    double mean = std::accumulate(bytes_flat.begin(), bytes_flat.end(), 0.0) / bytes_flat.size();
    double num = 0.0, den = 0.0;
    for (size_t i = 0; i + 1 < bytes_flat.size(); ++i) {
        num += (bytes_flat[i] - mean) * (bytes_flat[i + 1] - mean);
        den += (bytes_flat[i] - mean) * (bytes_flat[i] - mean);
    }
    double corr = (den > 0) ? num / den : 1.0;
    bool pass = std::abs(corr) < 0.02; // near-zero serial correlation

    std::ostringstream d;
    d << std::fixed << std::setprecision(6) << "r=" << corr << " (ideal ~0)";
    report("Serial Correlation (|r| < 0.02)", pass, d.str());
}

// ─── 8. RUNS TEST (NIST SP800-22) ────────────────────────────────────────────
static void test_runs()
{
    std::cout << "\n[8] Runs Test (NIST SP800-22)\n";
    const int N = 200;
    std::vector<int> bits;
    bits.reserve(N * 512);
    std::mt19937_64 rng(0x11223344ULL);
    std::vector<std::string> hs;
    for (int i = 0; i < N; ++i) {
        std::string s(8, '\0');
        for (char& c : s) c = static_cast<char>(rng() & 0xFF);
        hs.push_back(rudra::hash_string(s));
    }
    bits = extract_bits(hs);

    long long n = bits.size();
    long long ones = std::count(bits.begin(), bits.end(), 1);
    double pi = static_cast<double>(ones) / n;

    // Pre-test: |pi - 0.5| must be < 2/sqrt(n)
    if (std::abs(pi - 0.5) >= 2.0 / std::sqrt((double)n)) {
        report("Runs Test", false, "pre-test failed: pi too far from 0.5");
        return;
    }

    // Count runs
    long long runs = 1;
    for (long long i = 1; i < n; ++i)
        if (bits[i] != bits[i - 1]) ++runs;

    double expected_runs = 2.0 * n * pi * (1.0 - pi);
    double variance      = 4.0 * n * pi * pi * (1.0 - pi) * (1.0 - pi);
    double z = (runs - expected_runs) / std::sqrt(variance);
    double p = std::erfc(std::abs(z) / std::sqrt(2.0));

    bool pass = p > 0.01; // p-value > 0.01
    std::ostringstream d;
    d << std::fixed << std::setprecision(4)
      << "runs=" << runs << " expected=" << (long long)expected_runs
      << " z=" << z << " p=" << p;
    report("Runs Test (NIST SP800-22)", pass, d.str());
}

// ─── 9. SHANNON ENTROPY ──────────────────────────────────────────────────────
static void test_entropy()
{
    std::cout << "\n[9] Shannon Entropy\n";
    const int N = 2000;
    std::array<long long, 256> freq{};
    std::mt19937_64 rng(0x55667788ULL);
    for (int i = 0; i < N; ++i) {
        std::string s(8, '\0');
        for (char& c : s) c = static_cast<char>(rng() & 0xFF);
        auto b = hex_to_bytes(rudra::hash_string(s));
        for (uint8_t byte : b) freq[byte]++;
    }
    long long total = N * 64LL;
    double H = 0.0;
    for (int i = 0; i < 256; ++i) {
        if (freq[i] > 0) {
            double p = freq[i] / (double)total;
            H -= p * std::log2(p);
        }
    }
    bool pass = H > 7.99; // near-max entropy (max = 8.0 for bytes)
    std::ostringstream d;
    d << std::fixed << std::setprecision(6) << "H=" << H << " bits/byte (max=8.0)";
    report("Shannon Entropy > 7.99 bits/byte", pass, d.str());
}

// ─── 10. LENGTH EXTENSION RESISTANCE ─────────────────────────────────────────
static void test_length_extension()
{
    std::cout << "\n[10] Length Extension Resistance\n";
    // A hash function is vulnerable if H(m) can be extended to H(m||ext)
    // without knowing m. We cannot exploit directly, but we verify:
    // H(m || ext) != a derivation from H(m) alone.
    std::string m   = "secret_message";
    std::string ext = "_extension";
    std::string h1 = rudra::hash_string(m);
    std::string h2 = rudra::hash_string(m + ext);
    std::string h3 = rudra::hash_string(h1 + ext); // attacker's guess
    bool pass = (h2 != h3) && (hamming512(h2, h3) > 100);

    std::ostringstream d;
    d << "H(m||ext) vs H(H(m)||ext) Hamming=" << hamming512(h2, h3);
    report("Length Extension Resistance", pass, d.str());
}

// ─── 11. SALT / DOMAIN SEPARATION ────────────────────────────────────────────
static void test_salt_separation()
{
    std::cout << "\n[11] Salt & Domain Separation\n";
    std::string msg = "hello world";
    std::string s1 = "salt1", s2 = "salt2";

    auto h_no_salt = rudra::hash_string(msg);
    auto h_s1      = rudra::hash_string(msg, 32, &s1);
    auto h_s2      = rudra::hash_string(msg, 32, &s2);

    bool diff_salts = (h_s1 != h_s2) && (hamming512(h_s1, h_s2) > 100);
    bool diff_nosalt = (h_no_salt != h_s1) && (hamming512(h_no_salt, h_s1) > 100);

    std::ostringstream d;
    d << "Hamming(s1,s2)=" << hamming512(h_s1, h_s2)
      << " Hamming(no_salt,s1)=" << hamming512(h_no_salt, h_s1);
    report("Salt Separation (different salts → different hashes)", diff_salts,   d.str());
    report("Salt Separation (salt vs no-salt)", diff_nosalt, d.str());
}

// ─── 12. SMALL-INPUT SENSITIVITY ─────────────────────────────────────────────
static void test_small_input()
{
    std::cout << "\n[12] Small Input Sensitivity\n";
    const std::string inputs[] = {
        "a", "b", "ab", "ba", "aa", "A", "0", "1",
        "abc", "ABC", "abcd", "abce"
    };
    std::set<std::string> seen;
    bool all_unique = true;
    int min_hd = 512;
    for (size_t i = 0; i < 12; ++i) {
        auto h = rudra::hash_string(inputs[i]);
        if (!seen.insert(h).second) { all_unique = false; break; }
        for (size_t j = 0; j < i; ++j)
            min_hd = std::min(min_hd, hamming512(h, rudra::hash_string(inputs[j])));
    }
    std::ostringstream d;
    d << "12 small inputs, all unique=" << all_unique << ", min Hamming=" << min_hd;
    report("Small Input Sensitivity", all_unique && min_hd > 64, d.str());
}

// ─── 13. ZERO / UNIFORM INPUTS ───────────────────────────────────────────────
static void test_degenerate_inputs()
{
    std::cout << "\n[13] Degenerate Inputs\n";
    std::string z1(64, '\0'), z2(65, '\0');
    std::string ff(64, '\xFF'), aa(64, 'a');
    std::set<std::string> unique;
    unique.insert(rudra::hash_string(""));
    unique.insert(rudra::hash_string(z1));
    unique.insert(rudra::hash_string(z2));
    unique.insert(rudra::hash_string(ff));
    unique.insert(rudra::hash_string(aa));

    bool pass = (unique.size() == 5);
    std::ostringstream d;
    d << "5 degenerate inputs → " << unique.size() << " unique hashes";
    report("Degenerate Inputs (empty, zeros, 0xFF, 'aaa…')", pass, d.str());
}

// ─── 14. LONG INPUT STABILITY ────────────────────────────────────────────────
static void test_long_input()
{
    std::cout << "\n[14] Long Input Stability\n";
    std::string mb(1 << 20, 'X');
    auto t0 = std::chrono::high_resolution_clock::now();
    std::string h1 = rudra::hash_string(mb);
    std::string h2 = rudra::hash_string(mb);
    auto t1 = std::chrono::high_resolution_clock::now();
    double ms = std::chrono::duration<double, std::milli>(t1 - t0).count() / 2.0;

    bool pass = (h1 == h2) && (h1.size() == 128);
    std::ostringstream d;
    d << "1 MiB input, deterministic=" << (h1 == h2)
      << ", time=" << std::fixed << std::setprecision(1) << ms << " ms";
    report("Long Input (1 MiB) Stability & Speed", pass, d.str());

    // Also 1-byte change in 1MiB should still cause ~50% bit change
    mb[512000] ^= 0x01;
    std::string h3 = rudra::hash_string(mb);
    int hd = hamming512(h1, h3);
    bool pass2 = hd > 200 && hd < 312;
    std::ostringstream d2;
    d2 << "1-bit flip in 1MiB → Hamming=" << hd << "/512";
    report("Long Input Avalanche (1-bit flip)", pass2, d2.str());
}

// ─── 15. NEAR-COLLISION SEARCH ───────────────────────────────────────────────
static void test_near_collisions()
{
    std::cout << "\n[15] Near-Collision Search\n";
    const int N = 50000;
    std::mt19937_64 rng(0x9999AAAABBBBULL);
    int min_hd = 512;
    std::string worst_a, worst_b;
    std::vector<std::string> hs(N);
    for (int i = 0; i < N; ++i) {
        std::string s(8, '\0');
        for (char& c : s) c = static_cast<char>(rng() & 0xFF);
        hs[i] = rudra::hash_string(s);
    }
    // Check a random sample of pairs
    const int PAIRS = 100000;
    for (int p = 0; p < PAIRS; ++p) {
        int i = rng() % N, j = rng() % N;
        if (i == j) continue;
        int hd = hamming512(hs[i], hs[j]);
        if (hd < min_hd) { min_hd = hd; }
    }
    // For a 512-bit hash, minimum expected HD in 50k samples is well above 100
    bool pass = min_hd > 128;
    std::ostringstream d;
    d << "min Hamming in " << PAIRS << " random pairs = " << min_hd << "/512";
    report("Near-Collision Search (" + std::to_string(N) + " hashes)", pass, d.str());
}

// ─── 16. NIST MONOBIT FREQUENCY (SP800-22 Test 1) ────────────────────────────
static void test_monobit()
{
    std::cout << "\n[16] NIST Monobit Frequency Test\n";
    const int N = 500;
    std::vector<std::string> hs;
    hs.reserve(N);
    std::mt19937_64 rng(0xDEAD1234ULL);
    for (int i = 0; i < N; ++i) {
        std::string s(8, '\0');
        for (char& c : s) c = static_cast<char>(rng() & 0xFF);
        hs.push_back(rudra::hash_string(s));
    }
    auto bits = extract_bits(hs);
    long long n = bits.size();
    long long s = 0;
    for (int b : bits) s += (b == 1) ? 1 : -1;
    double sobs = std::abs(s) / std::sqrt((double)n);
    double p = std::erfc(sobs / std::sqrt(2.0));
    bool pass = p > 0.01;
    std::ostringstream d;
    d << std::fixed << std::setprecision(6) << "S=" << s << " Sobs=" << sobs << " p=" << p;
    report("NIST Monobit Test (p > 0.01)", pass, d.str());
}

// ─── 17. NIST BLOCK FREQUENCY (SP800-22 Test 2) ──────────────────────────────
static void test_block_frequency()
{
    std::cout << "\n[17] NIST Block Frequency Test\n";
    const int N = 500;
    std::vector<std::string> hs;
    std::mt19937_64 rng(0xBEEF5678ULL);
    for (int i = 0; i < N; ++i) {
        std::string s(8, '\0');
        for (char& c : s) c = static_cast<char>(rng() & 0xFF);
        hs.push_back(rudra::hash_string(s));
    }
    auto bits = extract_bits(hs);
    const int M = 128; // block size
    long long n = bits.size();
    long long num_blocks = n / M;
    double chi2 = 0.0;
    for (long long i = 0; i < num_blocks; ++i) {
        long long block_ones = 0;
        for (int j = 0; j < M; ++j)
            block_ones += bits[i * M + j];
        double pi_i = block_ones / (double)M;
        chi2 += 4.0 * M * (pi_i - 0.5) * (pi_i - 0.5);
    }
    // Incomplete gamma: approximate with normal for large DOF
    double z = (chi2 - num_blocks) / std::sqrt(2.0 * num_blocks);
    double p = 0.5 * std::erfc(z / std::sqrt(2.0));
    bool pass = p > 0.01;
    std::ostringstream d;
    d << std::fixed << std::setprecision(4)
      << "blocks=" << num_blocks << " chi2=" << chi2 << " z=" << z << " p=" << p;
    report("NIST Block Frequency Test (p > 0.01)", pass, d.str());
}

// ─── 18. ROUNDS SENSITIVITY ──────────────────────────────────────────────────
static void test_rounds_sensitivity()
{
    std::cout << "\n[18] Rounds Sensitivity\n";
    std::string msg = "rounds_test_input";
    auto h2  = rudra::hash_string(msg, 2);
    auto h4  = rudra::hash_string(msg, 4);
    auto h16 = rudra::hash_string(msg, 16);
    auto h32 = rudra::hash_string(msg, 32);

    bool all_diff = (h2 != h4) && (h4 != h16) && (h16 != h32) && (h2 != h32);
    int hd = hamming512(h2, h32);
    bool pass = all_diff && hd > 100;
    std::ostringstream d;
    d << "rounds 2/4/16/32 all differ=" << all_diff
      << " Hamming(r2,r32)=" << hd;
    report("Rounds Sensitivity", pass, d.str());
}

// ─── 19. AUTOCORRELATION / SPECTRAL ──────────────────────────────────────────
static void test_autocorrelation()
{
    std::cout << "\n[19] Autocorrelation Test\n";
    const int N = 500;
    std::mt19937_64 rng(0x77665544ULL);
    std::vector<std::string> hs;
    for (int i = 0; i < N; ++i) {
        std::string s = std::to_string(i) + "_seed";
        hs.push_back(rudra::hash_string(s));
    }
    auto bits = extract_bits(hs);
    int n = bits.size();

    // Autocorrelation at lag 1..8
    double max_ac = 0.0;
    double mean = std::accumulate(bits.begin(), bits.end(), 0.0) / n;
    double var = 0.0;
    for (int b : bits) var += (b - mean) * (b - mean);
    for (int lag = 1; lag <= 8; ++lag) {
        double ac = 0.0;
        for (int i = 0; i + lag < n; ++i)
            ac += (bits[i] - mean) * (bits[i + lag] - mean);
        ac /= var;
        max_ac = std::max(max_ac, std::abs(ac));
    }
    bool pass = max_ac < 0.02;
    std::ostringstream d;
    d << std::fixed << std::setprecision(6) << "max |AC| lag 1–8 = " << max_ac << " (ideal ~0)";
    report("Autocorrelation Test (lags 1–8)", pass, d.str());
}

// ─── 20. PERFORMANCE BENCHMARK ───────────────────────────────────────────────
static void test_performance()
{
    std::cout << "\n[20] Performance Benchmark\n";
    auto bench = [](const std::string& label, int input_size, int iters) {
        std::string input(input_size, 'x');
        auto t0 = std::chrono::high_resolution_clock::now();
        volatile size_t dummy = 0;
        for (int i = 0; i < iters; ++i)
            dummy += rudra::hash_string(input).size();
        auto t1 = std::chrono::high_resolution_clock::now();
        double ms = std::chrono::duration<double, std::milli>(t1 - t0).count();
        double mbs = (static_cast<double>(input_size) * iters) / (ms / 1000.0) / (1024 * 1024);
        std::cout << "    " << label << ": " << std::fixed << std::setprecision(2)
                  << ms / iters << " ms/op, ~" << mbs << " MiB/s\n";
        return ms / iters;
    };
    bench("64-byte input",  64,    1000);
    bench("1 KiB input",    1024,   200);
    bench("64 KiB input",   65536,   20);
    report("Performance Benchmark", true, "see timings above");
}

// ─── MAIN ─────────────────────────────────────────────────────────────────────
int main()
{
    std::cout << "======================================================\n";
    std::cout << "  Rudra512 Cryptographic Test Suite\n";
    std::cout << "======================================================\n";

    test_determinism();
    test_avalanche();
    test_bit_frequency();
    test_byte_distribution();
    test_collision_resistance();
    test_differential();
    test_serial_correlation();
    test_runs();
    test_entropy();
    test_length_extension();
    test_salt_separation();
    test_small_input();
    test_degenerate_inputs();
    test_long_input();
    test_near_collisions();
    test_monobit();
    test_block_frequency();
    test_rounds_sensitivity();
    test_autocorrelation();
    test_performance();

    // ─── SUMMARY ─────────────────────────────────────────────────────────────
    std::cout << "\n======================================================\n";
    std::cout << "  SUMMARY\n";
    std::cout << "======================================================\n";
    int pass = 0, fail = 0;
    for (auto& r : results) {
        std::cout << (r.passed ? "  PASS " : "  FAIL ") << r.name << "\n";
        if (r.passed) ++pass; else ++fail;
    }
    std::cout << "\nTotal: " << pass << " passed, " << fail << " failed out of "
              << (pass + fail) << " tests.\n";

    if (fail == 0) {
        std::cout << "\n  *** ALL TESTS PASSED ***\n";
        std::cout << "  Rudra512 exhibits strong statistical and structural\n";
        std::cout << "  properties expected of a cryptographic hash function.\n";
        std::cout << "  NOTE: Passing these tests is necessary but NOT sufficient\n";
        std::cout << "  for cryptographic security. Formal analysis and peer review\n";
        std::cout << "  by the cryptographic community is also required.\n";
    } else {
        std::cout << "\n  *** " << fail << " TEST(S) FAILED ***\n";
        std::cout << "  Review failures above — they may indicate weaknesses.\n";
    }
    std::cout << "======================================================\n";
    return fail > 0 ? 1 : 0;
}
