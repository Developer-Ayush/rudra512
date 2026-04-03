import random
import math
import time
import hashlib
from rudra512 import hash_string


# =========================
# HEX → BITS
# =========================
def hex_to_bits(hex_str):
    bits = []
    for c in hex_str:
        v = int(c, 16)
        for i in range(3, -1, -1):
            bits.append((v >> i) & 1)
    return bits


# =========================
# STAT TESTS
# =========================
def frequency(bits):
    ones = sum(bits)
    return ones / len(bits) * 100


def runs(bits):
    r = 1
    for i in range(1, len(bits)):
        if bits[i] != bits[i - 1]:
            r += 1
    return r / len(bits)


def entropy(bits):
    ones = sum(bits)
    p = ones / len(bits)
    if p == 0 or p == 1:
        return 0
    return -p * math.log2(p) - (1 - p) * math.log2(1 - p)


# =========================
# HASH FUNCTIONS
# =========================
def rudra_hash(msg):
    return hash_string(msg.hex())


def sha512_hash(msg):
    return hashlib.sha512(msg).hexdigest()


def sha3_512_hash(msg):
    return hashlib.sha3_512(msg).hexdigest()


# =========================
# AVALANCHE
# =========================
def avalanche(H):
    msg = bytearray(b"A" * 32)
    base = H(msg)
    base_bits = hex_to_bits(base)

    total = 0

    for i in range(64):
        m = bytearray(msg)
        m[i // 8] ^= (1 << (i % 8))

        bits = hex_to_bits(H(m))

        diff = sum(b1 != b2 for b1, b2 in zip(bits, base_bits))
        total += diff / len(bits) * 100

    return total / 64


# =========================
# COLLISION
# =========================
def collision(H):
    seen = set()

    for _ in range(50000):
        m = bytes([random.randint(0, 255) for _ in range(32)])
        h = H(m)

        if h in seen:
            print("Collision Found!")
            return

        seen.add(h)

    print("No Collision")


# =========================
# SPEED
# =========================
def speed(H):
    m = b"\x7b" * 32
    N = 20000

    start = time.time()
    for _ in range(N):
        H(m)
    end = time.time()

    return int(N / (end - start))


# =========================
# RUN ALL
# =========================
def run_all(H, name):
    print(f"\n===== {name} =====")

    bits = []

    for _ in range(200):
        m = bytes([random.randint(0, 255) for _ in range(32)])
        b = hex_to_bits(H(m))
        bits.extend(b)

    print(f"Frequency: {frequency(bits):.4f}%")
    print(f"Runs: {runs(bits):.6f}")
    print(f"Entropy: {entropy(bits):.6f}")
    print(f"Avalanche: {avalanche(H):.4f}%")
    print(f"Speed: {speed(H)} hashes/sec")

    collision(H)


# =========================
# MAIN
# =========================
if __name__ == "__main__":
    run_all(rudra_hash, "Rudra-512")
    run_all(sha512_hash, "SHA-512")
    run_all(sha3_512_hash, "SHA3-512")
