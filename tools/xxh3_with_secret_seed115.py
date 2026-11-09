"""Model of the node #115 XXH3 one-shot short branches with a caller secret
and with a seed: ROCKSDB_XXH3_64bits_withSecret (0x61db940) and
ROCKSDB_XXH3_64bits_withSeed (0x61dc0c0).

Both entry points are the public XXH3_64bits one-shot with the seed folded
into the secret instead of a custom-secret array: withSecret runs the
len_0to16 branches with (caller secret, seed 0); withSeed runs them with
(the default 192-byte secret, seed). Only lengths 0..16 are modelled here,
the same scope as the default-secret short branches reconstructed for the
type-4 arm of ComputeBuiltinChecksumWithLastByte (0x616bd60); the
17..128, 129..240 and >240 branches delegate to the len_17to128 /
len_129to240 / hashLong helpers and are out of scope for this packet.

What the disassembly pins, per branch (seed is the withSeed argument;
withSecret always uses seed 0):

- len 0: XXH64_avalanche(seed ^ (secret[56:64] ^ secret[64:72])).
  withSeed folds the two default-secret words into the immediate
  0x8726f9105dc21ddc (verified: kSecret words 7 and 8 xor to it).
- len 1..3: combined = data[len-1] | data[0]<<16 | len<<8 | data[len>>1]<<24;
  bitflip = (read32(secret) ^ read32(secret+4)) + seed;
  XXH64_avalanche(combined ^ bitflip). withSeed folds the word xor into
  the immediate 0x87275a9b (verified against kSecret word 0).
- len 4..8: seed ^= swap32(seed as u32) << 32 (the public len_4to8 seed
  transform, confirmed against the published xxh3.h source after an
  early draft misread the packing); input64 = read32(data+len-4) +
  (read32(data) << 32); bitflip = (read64(secret+8) ^ read64(secret+16))
  - seed; rrmxmx(input64 ^ bitflip, len). withSeed folds the secret-word
  xor into the immediate 0xc73ab174c5ecd5a2 (verified: kSecret words 1
  and 2 xor to it).
- len 9..16: bitflip1 = (secret[24] ^ secret[32]) + seed;
  bitflip2 = (secret[40] ^ secret[48]) - seed; lo = read64(data) ^
  bitflip1; hi = read64(data+len-8) ^ bitflip2;
  XXH3_avalanche(len + bswap64(lo) + hi + mul128_fold64(lo, hi)).
  withSeed folds the word xors into the immediates 0x6782737bea4239b9
  (+ seed) and 0xaf56bc3b0996523a (- seed), both verified against the
  default secret words. The withSecret body reads the same four secret
  offsets (0x18/0x20 and 0x28/0x30) from its caller-supplied secret.

The 4th argument of withSecret (secretSize) is not read on the len<=16
path; it is only carried into the >240 hashLong path. No minimum-size
check is visible on the short path.

Grounding: the generator authenticates work/hl-node-115.bin against the
provenance digest, hashes both function bodies (file offset VA-0x1000
for .text) against the vendor-census targets, and byte-compares the
192-byte default secret at file offset 0x97ec80 (.rodata, file offset
== VA) against the published xxHash kSecret. The 2,400 deterministic
cases compare this transliteration against an independent reference
written from the published xxh3.h formulas; the published anchors
XXH3_64bits(b"", 0) = 0x2d06800538d394c2 and XXH3_64bits(b"a", 0) =
0xe6c632b61e964e1f are checked for both entry points with the default
secret / seed 0.
"""

import argparse
import hashlib
import json
import random
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / "work" / "hl-node-115.bin"
ARTIFACT_DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

M64 = (1 << 64) - 1
M32 = (1 << 32) - 1
PRIME64_1 = 0x9E3779B185EBCA87
PRIME64_2 = 0xC2B2AE3D27D4EB4F
PRIME64_3 = 0x165667B19E3779F9
PRIME_MX1 = 0x165667919E3779F9
PRIME_MX2 = 0x9FB21C651E98DF25

# Published xxHash default secret (192 bytes, xxh3.h kSecret). The binary
# slice at file offset 0x97ec80 is byte-compared against this constant.
KSECRET = bytes.fromhex(
    "b8fe6c3923a44bbe7c01812cf721ad1c"
    "ded46de9839097db7240a4a4b7b3671f"
    "cb79e64eccc0e578825ad07dccff7221"
    "b8084674f743248ee03590e6813a264c"
    "3c2852bb91c300cb88d0658b1b532ea3"
    "71644897a20df94e3819ef46a9deacd8"
    "a8fa763fe39c343ff9dcbbc7c70b4f1d"
    "8a51e04bcdb45931c89f7ec9d9787364"
    "eac5ac8334d3ebc3c581a0fffa1363eb"
    "170ddd51b7f0da49d316552629d4689e"
    "2b16be587d47a1fc8ff8b8d17ad031ce"
    "45cb3a8f95160428afd7fbcabb4b407e"
)

FUNCTIONS = [
    ("withSecret", 0x61DB940, 0x61DC0BC,
     "af7eebcfc41edea9d250273df385394d8ab58bb4a3bca1d9acae4e3e545ada58"),
    ("withSeed", 0x61DC0C0, 0x61DC401,
     "781a95efaa091e8581fa6cc2cda7770a5b3aa356678e40a07f33ec7922fd088f"),
]
KSECRET_VA = 0x97EC80


def _u64(buf, off):
    return struct.unpack_from("<Q", buf, off)[0]


def _u32(buf, off):
    return struct.unpack_from("<I", buf, off)[0]


def _rotl64(x, r):
    return ((x << r) | (x >> (64 - r))) & M64


def _bswap64(x):
    return struct.unpack("<Q", struct.pack(">Q", x))[0]


def _swap32(x):
    return struct.unpack("<I", struct.pack(">I", x & M32))[0]


def _mul128_fold64(a, b):
    p = a * b
    return (p & M64) ^ (p >> 64)


def _xxh64_avalanche(h):
    h &= M64
    h ^= h >> 33
    h = (h * PRIME64_2) & M64
    h ^= h >> 29
    h = (h * PRIME64_3) & M64
    h ^= h >> 32
    return h


def _xxh3_avalanche(h):
    h &= M64
    h ^= h >> 37
    h = (h * PRIME_MX1) & M64
    h ^= h >> 32
    return h


def _rrmxmx(h, length):
    h &= M64
    h ^= _rotl64(h, 49) ^ _rotl64(h, 24)
    h = (h * PRIME_MX2) & M64
    h ^= ((h >> 35) + length) & M64
    h = (h * PRIME_MX2) & M64
    h ^= h >> 28
    return h


# --- Transliteration: follows the disassembly op order. ---

def xxh3_with_secret(data, secret):
    """ROCKSDB_XXH3_64bits_withSecret(data, len, secret) for len <= 16."""
    n = len(data)
    if n > 16:
        raise ValueError("len > 16 out of scope (delegates to len_17to128+ helpers)")
    if n == 0:
        return _xxh64_avalanche(_u64(secret, 56) ^ _u64(secret, 64))
    if n <= 3:
        combined = (data[n - 1] | (data[0] << 16) | (n << 8)
                    | (data[n >> 1] << 24))
        bitflip = _u32(secret, 0) ^ _u32(secret, 4)
        return _xxh64_avalanche(combined ^ bitflip)
    if n <= 8:
        input1 = _u32(data, 0)
        input2 = _u32(data, n - 4)
        input64 = (input2 + (input1 << 32)) & M64
        bitflip = _u64(secret, 8) ^ _u64(secret, 16)
        return _rrmxmx(input64 ^ bitflip, n)
    lo = _u64(data, 0) ^ (_u64(secret, 24) ^ _u64(secret, 32))
    hi = _u64(data, n - 8) ^ (_u64(secret, 40) ^ _u64(secret, 48))
    acc = (n + _bswap64(lo) + hi + _mul128_fold64(lo, hi)) & M64
    return _xxh3_avalanche(acc)


def xxh3_with_seed(data, seed):
    """ROCKSDB_XXH3_64bits_withSeed(data, len, seed) for len <= 16."""
    n = len(data)
    seed &= M64
    if n > 16:
        raise ValueError("len > 16 out of scope (delegates to len_17to128+ helpers)")
    if n == 0:
        return _xxh64_avalanche(seed ^ (_u64(KSECRET, 56) ^ _u64(KSECRET, 64)))
    if n <= 3:
        combined = (data[n - 1] | (data[0] << 16) | (n << 8)
                    | (data[n >> 1] << 24))
        bitflip = ((_u32(KSECRET, 0) ^ _u32(KSECRET, 4)) + seed) & M64
        return _xxh64_avalanche(combined ^ bitflip)
    if n <= 8:
        seed_t = (seed ^ (_swap32(seed) << 32)) & M64
        input1 = _u32(data, 0)
        input2 = _u32(data, n - 4)
        input64 = (input2 + (input1 << 32)) & M64
        bitflip = ((_u64(KSECRET, 8) ^ _u64(KSECRET, 16)) - seed_t) & M64
        return _rrmxmx(input64 ^ bitflip, n)
    bitflip1 = ((_u64(KSECRET, 24) ^ _u64(KSECRET, 32)) + seed) & M64
    bitflip2 = ((_u64(KSECRET, 40) ^ _u64(KSECRET, 48)) - seed) & M64
    lo = _u64(data, 0) ^ bitflip1
    hi = _u64(data, n - 8) ^ bitflip2
    acc = (n + _bswap64(lo) + hi + _mul128_fold64(lo, hi)) & M64
    return _xxh3_avalanche(acc)


# --- Independent reference: written from the published xxh3.h formulas. ---

def _ref_len_0to16(data, secret, seed):
    n = len(data)
    seed &= M64
    if n == 0:
        return _xxh64_avalanche(seed ^ (_u64(secret, 56) ^ _u64(secret, 64)))
    if n <= 3:
        combined = (data[n - 1] | (data[0] << 16) | (n << 8)
                    | (data[n >> 1] << 24))
        bitflip = ((_u32(secret, 0) ^ _u32(secret, 4)) + seed) & M64
        return _xxh64_avalanche(combined ^ bitflip)
    if n <= 8:
        seed2 = (seed ^ (_swap32(seed) << 32)) & M64
        input64 = (_u32(data, n - 4) + (_u32(data, 0) << 32)) & M64
        bitflip = ((_u64(secret, 8) ^ _u64(secret, 16)) - seed2) & M64
        return _rrmxmx(input64 ^ bitflip, n)
    bitflip1 = ((_u64(secret, 24) ^ _u64(secret, 32)) + seed) & M64
    bitflip2 = ((_u64(secret, 40) ^ _u64(secret, 48)) - seed) & M64
    lo = _u64(data, 0) ^ bitflip1
    hi = _u64(data, n - 8) ^ bitflip2
    acc = (n + _bswap64(lo) + hi + _mul128_fold64(lo, hi)) & M64
    return _xxh3_avalanche(acc)


def ref_with_secret(data, secret):
    return _ref_len_0to16(data, secret, 0)


def ref_with_seed(data, seed):
    return _ref_len_0to16(data, KSECRET, seed)


# --- Binary grounding. ---

def _read_binary():
    blob = BINARY.read_bytes()
    if hashlib.sha256(blob).hexdigest() != ARTIFACT_DIGEST:
        raise ValueError("binary digest mismatch: %s" % BINARY)
    return blob


def verify_binary(blob):
    """Hash both bodies and byte-compare the default secret table."""
    for name, start, end, target in FUNCTIONS:
        body = blob[start - 0x1000:end - 0x1000]
        got = hashlib.sha256(body).hexdigest()
        if got != target:
            raise ValueError("%s body hash mismatch: %s" % (name, got))
    secret = blob[KSECRET_VA:KSECRET_VA + 192]
    if secret != KSECRET:
        raise ValueError("default secret table mismatch at 0x%x" % KSECRET_VA)
    # Folded immediates in the withSeed body must equal the kSecret words.
    _, s0, e0, _ = FUNCTIONS[1]
    body = blob[s0 - 0x1000:e0 - 0x1000]
    for const in (0x6782737BEA4239B9, 0xAF56BC3B0996523A,
                  0xC73AB174C5ECD5A2, 0x8726F9105DC21DDC):
        if struct.pack("<Q", const) not in body:
            raise ValueError("folded immediate %016x not in withSeed body" % const)
    if struct.pack("<I", 0x87275A9B) not in body:
        raise ValueError("folded immediate 87275a9b not in withSeed body")
    return True


# --- Deterministic cases. ---

def generate_cases():
    rng = random.Random(0x11561DB9)
    secrets = [KSECRET]
    for _ in range(7):
        secrets.append(bytes(rng.randrange(256) for _ in range(192)))
    seeds = [0, 1, 2, PRIME64_1, 0xFFFFFFFFFFFFFFFF, 0x123456789ABCDEF0]
    for _ in range(6):
        seeds.append(rng.getrandbits(64))
    cases = []
    for i in range(2400):
        length = i % 17
        if i < 34:
            if length == 0:
                data = b""
            elif i % 4 == 0:
                data = bytes(length)
            elif i % 4 == 1:
                data = b"\xff" * length
            elif i % 4 == 2:
                data = bytes((j * 7 + 3) & 0xFF for j in range(length))
            else:
                data = bytes(rng.randrange(256) for _ in range(length))
        else:
            data = bytes(rng.randrange(256) for _ in range(length))
        if i % 2 == 0:
            secret = secrets[(i // 2) % len(secrets)]
            cases.append({"function": "withSecret", "length": length,
                          "input_hex": data.hex(),
                          "secret_id": "kSecret" if secret is KSECRET else "rand%d" % ((i // 2) % len(secrets)),
                          "secret_hex": secret.hex(),
                          "expected_hex": "%016x" % xxh3_with_secret(data, secret)})
        else:
            seed = seeds[(i // 2) % len(seeds)]
            cases.append({"function": "withSeed", "length": length,
                          "input_hex": data.hex(),
                          "seed_hex": "%016x" % seed,
                          "expected_hex": "%016x" % xxh3_with_seed(data, seed)})
    return cases


def verify():
    blob = _read_binary()
    verify_binary(blob)
    cases = generate_cases()
    mismatches = 0
    for case in cases:
        data = bytes.fromhex(case["input_hex"])
        if case["function"] == "withSecret":
            got = xxh3_with_secret(data, bytes.fromhex(case["secret_hex"]))
            ref = ref_with_secret(data, bytes.fromhex(case["secret_hex"]))
        else:
            seed = int(case["seed_hex"], 16)
            got = xxh3_with_seed(data, seed)
            ref = ref_with_seed(data, seed)
        if got != ref or ("%016x" % got) != case["expected_hex"]:
            mismatches += 1
    checks = {
        "withSecret(b'', kSecret)": "%016x" % xxh3_with_secret(b"", KSECRET),
        "withSecret(b'a', kSecret)": "%016x" % xxh3_with_secret(b"a", KSECRET),
        "withSeed(b'', 0)": "%016x" % xxh3_with_seed(b"", 0),
        "withSeed(b'a', 0)": "%016x" % xxh3_with_seed(b"a", 0),
        "withSeed(b'abc', 0)": "%016x" % xxh3_with_seed(b"abc", 0),
        "withSeed(b'123456789', 0)": "%016x" % xxh3_with_seed(b"123456789", 0),
    }
    published = {"withSecret(b'', kSecret)": "2d06800538d394c2",
                 "withSecret(b'a', kSecret)": "e6c632b61e964e1f",
                 "withSeed(b'', 0)": "2d06800538d394c2",
                 "withSeed(b'a', 0)": "e6c632b61e964e1f"}
    for key, want in published.items():
        if checks[key] != want:
            raise ValueError("published anchor mismatch: %s = %s" % (key, checks[key]))
    print("%d cases agree (%d mismatches)" % (len(cases), mismatches))
    for key, value in checks.items():
        print("  %s = 0x%s" % (key, value))
    return mismatches


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    if args.verify:
        raise SystemExit(1 if verify() else 0)
    if args.out is not None:
        blob = _read_binary()
        verify_binary(blob)
        cases = generate_cases()
        mismatches = 0
        for case in cases:
            data = bytes.fromhex(case["input_hex"])
            if case["function"] == "withSecret":
                ref = ref_with_secret(data, bytes.fromhex(case["secret_hex"]))
            else:
                ref = ref_with_seed(data, int(case["seed_hex"], 16))
            if ("%016x" % ref) != case["expected_hex"]:
                mismatches += 1
        result = {
            "artifact": "node115",
            "artifact_sha256": ARTIFACT_DIGEST,
            "functions": [
                {"name": name, "start": "0x%x" % s, "end": "0x%x" % e,
                 "body_sha256": t, "scope": "length 0..16 only"}
                for name, s, e, t in FUNCTIONS
            ],
            "cases": cases,
            "total_cases": len(cases),
            "mismatches": mismatches,
            "check_values": {
                "withSecret(b'', kSecret)": "%016x" % xxh3_with_secret(b"", KSECRET),
                "withSecret(b'a', kSecret)": "%016x" % xxh3_with_secret(b"a", KSECRET),
                "withSeed(b'', 0)": "%016x" % xxh3_with_seed(b"", 0),
                "withSeed(b'a', 0)": "%016x" % xxh3_with_seed(b"a", 0),
                "withSeed(b'abc', 0)": "%016x" % xxh3_with_seed(b"abc", 0),
                "withSeed(b'123456789', 0)": "%016x" % xxh3_with_seed(b"123456789", 0),
            },
        }
        args.out.mkdir(parents=True, exist_ok=True)
        (args.out / "result.json").write_text(json.dumps(result, indent=1) + "\n")
        print("wrote %s (%d cases, %d mismatches)"
              % (args.out / "result.json", len(cases), mismatches))
        raise SystemExit(1 if mismatches else 0)
    parser.print_help()
    raise SystemExit(2)


if __name__ == "__main__":
    main()
