#include "rudra512.h"

#include <array>
#include <vector>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <stdexcept>

namespace rudra {

// -------------------------
// Bit rotation
// -------------------------
static inline uint64_t rotl(uint64_t x, int r) {
    return (x << r) | (x >> (64 - r));
}

// -------------------------
// Permutation
// -------------------------
static void permute(std::array<uint64_t, 8>& state, int rounds) {
    for (int r = 0; r < rounds; r++) {
        for (int i = 0; i < 8; i++) {
            state[i] ^= rotl(state[(i + 1) % 8], (i + 1) * 7);
            state[i] += state[(i + 2) % 8];
            state[i] = rotl(state[i], 17);
        }
    }
}

// -------------------------
// Padding (64-byte blocks)
// -------------------------
static std::vector<uint8_t> pad(const std::vector<uint8_t>& msg) {
    std::vector<uint8_t> padded = msg;

    uint64_t bit_len = static_cast<uint64_t>(msg.size()) * 8;

    padded.push_back(0x80);

    while ((padded.size() % 64) != 56) {
        padded.push_back(0x00);
    }

    for (int i = 0; i < 8; i++) {
        padded.push_back((bit_len >> (8 * i)) & 0xFF);
    }

    return padded;
}

// -------------------------
// Core hash
// -------------------------
static std::string hash_internal(const std::vector<uint8_t>& input, int rounds) {

    if (rounds < 1 || rounds > 1000) {
        throw std::invalid_argument("Rounds must be between 1 and 1000");
    }

    std::array<uint64_t, 8> state = {
        0x123456789abcdef0ULL, 0xfedcba9876543210ULL,
        0x0f0f0f0f0f0f0f0fULL, 0xf0f0f0f0f0f0f0f0ULL,
        0xaaaaaaaaaaaaaaaaULL, 0x5555555555555555ULL,
        0x1122334455667788ULL, 0x8877665544332211ULL
    };

    std::vector<uint8_t> padded = pad(input);

    for (size_t i = 0; i < padded.size(); i += 64) {

        for (int j = 0; j < 8; j++) {
            uint64_t word = 0;

            for (int k = 0; k < 8; k++) {
                word |= static_cast<uint64_t>(padded[i + j * 8 + k]) << (k * 8);
            }

            state[j] ^= word;
        }

        permute(state, rounds);
    }

    permute(state, rounds / 2);

    std::stringstream ss;
    for (uint64_t v : state) {
        ss << std::hex << std::setw(16) << std::setfill('0') << v;
    }

    return ss.str();
}

// -------------------------
// PUBLIC API (WITH SALT)
// -------------------------

std::string hash_string(
    const std::string& input,
    int rounds,
    const std::string* salt
) {
    std::vector<uint8_t> data;

    // 👉 NO SALT
    if (salt == nullptr) {
        data = std::vector<uint8_t>(input.begin(), input.end());
    }
    // 👉 WITH SALT
    else {
        std::string combined = *salt + input;
        data = std::vector<uint8_t>(combined.begin(), combined.end());
    }

    return hash_internal(data, rounds);
}

// -------------------------
// FILE HASH
// -------------------------

std::string hash_file(
    const std::string& filename,
    int rounds,
    const std::string* salt
) {
    std::ifstream file(filename, std::ios::binary);

    if (!file) {
        throw std::runtime_error("Cannot open file");
    }

    std::vector<uint8_t> data(
        (std::istreambuf_iterator<char>(file)),
        std::istreambuf_iterator<char>()
    );

    // Apply salt same way
    if (salt != nullptr) {
        std::vector<uint8_t> salted(
            salt->begin(), salt->end()
        );
        salted.insert(salted.end(), data.begin(), data.end());
        return hash_internal(salted, rounds);
    }

    return hash_internal(data, rounds);
}

}
