"""Model of the node #115 XXH3 64-bit hashLong helpers:
XXH3_hashLong_64b_default at 0x61d8510 (FDE 0x61d8510..0x61d8a53, 1347
bytes, census id node115-vendor-61d8510, body SHA-256
56fac98e9537653843403355bc80a6c5e389fffcacabf142817df13110f7c195) and
XXH3_hashLong_64b_withSeed at 0x61d9090 (FDE 0x61d9090..0x61d9bb6, 2854
bytes, census id node115-vendor-61d9090, body SHA-256
ade028011ceabba51d386110d42c6441eb91a66b1e5da2a7db9d9abe6896e64b).

They are the len > 240 branch of both 64-bit one-shots:
ROCKSDB_XXH3_64bits (0x61db650) tail-jumps to the default helper at
0x61db6d6 with seed 0 (dispatch cmp $0xf0 at 0x61db6c9), and
ROCKSDB_XXH3_64bits_withSeed (0x61dc0c0) tail-jumps to the withSeed
helper at 0x61dc14e with the seed argument (dispatch cmp $0xf0 at
0x61dc141); both pass the default 192-byte kSecret (0x97ec80). The
64-bit one-shot withSecret (0x61db940) does NOT call these helpers:
its len > 240 branch is an inline SIMD hashLong at 0x61db9ff, because
it runs against a caller-supplied secret. Signature of the default
helper: (input=rdi, len=rsi); of the withSeed helper: (input=rdi,
len=rsi, seed=rdx). Both return the 64-bit hash in %rax.

What the disassembly pins:

- Eight 64-bit accumulators, initialised to XXH3_INIT_ACC =
  {PRIME32_3, PRIME64_1, PRIME64_2, PRIME64_3, PRIME64_4, PRIME32_2,
  PRIME64_5, PRIME32_1} (the four 16-byte constants at .rodata
  0x455960/0x455950/0x453a30/0x4525e0; acc[5] is 0x85EBCA77, PRIME32_2,
  the same value the merged streaming packet uses for ACC_INIT[5]).
- Full blocks of 16 stripes (1024 bytes): nbBlocks = (len-1) >> 10.
  Each stripe is one accumulate_512 over 64 input bytes against a
  64-byte secret window sliding 8 bytes per stripe (secret + s*8 for
  stripe s, restarting at the default secret each block). After each
  block, scrambleAcc with the secret + 128 window (the four .rodata
  constants 0x454220/0x451ad0/0x451150/0x455970 are byte-identical to
  kSecret[128:192]).
- Remaining stripes: ((len-1) & 0x3ff) >> 6 stripes from the block
  boundary, secret restarting at kSecret + 0.
- Last stripe (always runs): accumulate_512 over input[len-64..len)
  against secret + 121 (the four .rodata constants
  0x450ae0/0x4562d0/0x454520/0x451160 are byte-identical to
  kSecret[121:185]).
- Result = mergeAcc(acc, secret + 11, len * PRIME64_1), where mergeAcc
  folds four 128-bit products (acc[2i] ^ secret[16i]) *
  (acc[2i+1] ^ secret[16i+8]) low ^ high, then XXH3_avalanche. All
  eight merge-window words appear as movabs immediates in the default
  body (and in the withSeed seed==0 path): the window reads kSecret +
  11, 19, 27, 35, 43, 51, 59, 67. The len * PRIME64_1 term is formed
  by an imul at 0x61d89bc (default) and 0x61d953c (withSeed seed==0).
  This is the same body as the 128-bit hashLong pair (PR #5598) with
  only the low64 merge kept and the high64 merge dropped.
- withSeed with seed != 0 builds a 192-byte custom secret on the stack
  (rsp + 0x40): word 2i is kSecret[2i] + seed, word 2i+1 is
  kSecret[2i+1] - seed (the twelve 16-byte .rodata constants at
  0x454530/0x455670/0x451170/0x452fc0/0x455fa0/0x450af0/0x4517e0/
  0x454540/0x454220/0x451ad0/0x451150/0x455970 are byte-identical to
  the twelve kSecret chunks), then runs the identical loop against
  that secret: the last stripe reads the custom secret at
  rsp+0x40+121 (stack offsets 0xb9/0xc9/0xd9/0xe9) and the merge words
  are loaded from the stack secret at secret+11..67 (stack offsets
  0x4b/0x53/0x5b/0x63/0x6b/0x73/0x7b/0x83). With seed == 0 it runs the
  default path (the same block loop, remaining-stripes loop and merge
  immediates as the default helper); the nbBlocks == 0 continuations
  live in cold blocks at 0x61d9b58 (seed 0, jumps to the
  remaining-stripes entry 0x61d930a) and 0x61d9b88 (seed != 0, jumps
  to 0x61d98ba). Both paths share the avalanche epilogue at 0x61d9b10.

Grounding: the generator authenticates work/hl-node-115.bin against
the provenance digest, hashes both function bodies (file offset
VA-0x1000 for .text) against the vendor-census targets, and
byte-compares the 192-byte default secret at file offset 0x97ec80
(.rodata, file offset == VA) against the published xxHash kSecret.
The 2,400 deterministic cases compare this transliteration against an
independent reference written from the decoded model in loop form;
the check values below are confirmed against the system libxxhash
0.8.2 oracle at the 64-bit entry points (XXH3_64bits /
XXH3_64bits_withSeed, lengths 241..5000). The same body shape was
additionally checked by native execution of the extracted bytes for
the 128-bit pair (PR #5598); no native-execution check was repeated
for the 64-bit pair -- the oracle check at the entry points exercises
these exact helpers through their tail-jump dispatch, and the
committed cross-check is the Python reference.
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
PRIME64_4 = 0x85EBCA77C2B2AE63
PRIME64_5 = 0x27D4EB2F165667C5
PRIME32_1 = 0x9E3779B1
PRIME32_2 = 0x85EBCA77
PRIME32_3 = 0xC2B2AE3D
AVALANCHE_MULT = 0x165667919E3779F9
MERGE_START = 11
SECRET_LIMIT = 128
LASTACC_START = 7

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

INIT_ACC = [PRIME32_3, PRIME64_1, PRIME64_2, PRIME64_3,
            PRIME64_4, PRIME32_2, PRIME64_5, PRIME32_1]

# Twelve 16-byte .rodata constants the withSeed helper folds with the
# seed to build its custom secret; each must equal a kSecret chunk.
CUSTOM_SECRET_CONSTS = [
    0x454530, 0x455670, 0x451170, 0x452FC0, 0x455FA0, 0x450AF0,
    0x4517E0, 0x454540, 0x454220, 0x451AD0, 0x451150, 0x455970,
]

FUNCTIONS = [
    ("hashlong_64b_default", 0x61D8510, 0x61D8A53,
     "56fac98e9537653843403355bc80a6c5e389fffcacabf142817df13110f7c195"),
    ("hashlong_64b_withSeed", 0x61D9090, 0x61D9BB6,
     "ade028011ceabba51d386110d42c6441eb91a66b1e5da2a7db9d9abe6896e64b"),
]
KSECRET_VA = 0x97EC80


def _u64(buf, off):
    return struct.unpack_from("<Q", buf, off)[0]


def _mul128_fold64(a, b):
    p = (a & M64) * (b & M64)
    return ((p & M64) ^ (p >> 64)) & M64


def _xxh3_avalanche(h):
    h &= M64
    h ^= h >> 37
    h = (h * AVALANCHE_MULT) & M64
    h ^= h >> 32
    return h & M64


def _accumulate_512(acc, stripe, secret64):
    """One 64-byte stripe. Per lane i: acc[i] += lo32(key) * hi32(key)
    + data[i ^ 1], where key = data[i] ^ secret[i]."""
    data = [_u64(stripe, 8 * i) for i in range(8)]
    for i in range(8):
        key = data[i] ^ _u64(secret64, 8 * i)
        acc[i] = (acc[i] + (key & M32) * (key >> 32)
                  + data[i ^ 1]) & M64


def _scramble_acc(acc, secret64):
    """acc[i] = (acc[i] ^ (acc[i] >> 47) ^ secret[i]) * 0x9E3779B1."""
    for i in range(8):
        acc[i] = (((acc[i] ^ (acc[i] >> 47) ^ _u64(secret64, 8 * i))
                   & M64) * PRIME32_1) & M64


def _merge_acc(acc, secret, start, off=MERGE_START):
    """mergeAcc: four 128-bit products folded, plus start, avalanched.
    The secret window starts at secret + off (11 for the 64-bit
    hashLong)."""
    result = start & M64
    for i in range(4):
        a = acc[2 * i] ^ _u64(secret, off + 16 * i)
        b = acc[2 * i + 1] ^ _u64(secret, off + 16 * i + 8)
        result = (result + _mul128_fold64(a, b)) & M64
    return _xxh3_avalanche(result)


def _init_custom_secret(seed):
    """XXH3_initCustomSecret: word 2i += seed, word 2i+1 -= seed."""
    out = bytearray(192)
    for i in range(12):
        struct.pack_into("<Q", out, 16 * i,
                         (_u64(KSECRET, 16 * i) + seed) & M64)
        struct.pack_into("<Q", out, 16 * i + 8,
                         (_u64(KSECRET, 16 * i + 8) - seed) & M64)
    return bytes(out)


def _hashlong_64b(data, secret):
    """The shared hashLong body: blocks, remaining stripes, last stripe,
    one merge. Lengths > 240 only. Returns the 64-bit hash."""
    n = len(data)
    if n <= 240:
        raise ValueError("len out of scope >240")
    acc = list(INIT_ACC)
    nb_blocks = (n - 1) >> 10
    for b in range(nb_blocks):
        for s in range(16):
            _accumulate_512(acc, data[b * 1024 + s * 64: b * 1024 + s * 64 + 64],
                            secret[s * 8: s * 8 + 64])
        _scramble_acc(acc, secret[SECRET_LIMIT:SECRET_LIMIT + 64])
    rem = ((n - 1) & 0x3FF) >> 6
    base = nb_blocks * 1024
    for s in range(rem):
        _accumulate_512(acc, data[base + s * 64: base + s * 64 + 64],
                        secret[s * 8: s * 8 + 64])
    _accumulate_512(acc, data[n - 64:],
                    secret[SECRET_LIMIT - LASTACC_START:
                           SECRET_LIMIT - LASTACC_START + 64])
    return _merge_acc(acc, secret, (n * PRIME64_1) & M64, MERGE_START)


def hashlong_64b_default(data):
    """XXH3_hashLong_64b_default(data, len): default secret, seed 0."""
    return _hashlong_64b(data, KSECRET)


def hashlong_64b_with_seed(data, seed=0):
    """XXH3_hashLong_64b_withSeed(data, len, seed)."""
    seed &= M64
    if seed == 0:
        return _hashlong_64b(data, KSECRET)
    return _hashlong_64b(data, _init_custom_secret(seed))


# --- Independent reference: same model, loop form. ---

def _ref_accumulate(acc, stripe, secret):
    data = [_u64(stripe, 8 * i) for i in range(8)]
    key = [data[i] ^ _u64(secret, 8 * i) for i in range(8)]
    for i in range(8):
        acc[i] = (acc[i] + (key[i] & M32) * (key[i] >> 32)
                  + data[i ^ 1]) & M64


def _ref_merge(acc, secret, start, off):
    result = start & M64
    for i in range(4):
        a = acc[2 * i] ^ _u64(secret, off + 16 * i)
        b = acc[2 * i + 1] ^ _u64(secret, off + 16 * i + 8)
        result = (result + _mul128_fold64(a, b)) & M64
    return _xxh3_avalanche(result)


def _ref_hashlong_64b(data, secret):
    n = len(data)
    if n <= 240:
        raise ValueError("len out of scope >240")
    acc = list(INIT_ACC)
    # Stripes counted as (len-1)//64, consumed 16 at a time with a
    # scramble after each full block; the secret window restarts at
    # each block boundary.
    nb = (n - 1) // 64
    pos = 0
    while nb >= 16:
        for s in range(16):
            _ref_accumulate(acc, data[pos + s * 64: pos + s * 64 + 64],
                            secret[s * 8: s * 8 + 64])
        for i in range(8):
            acc[i] = (((acc[i] ^ (acc[i] >> 47)
                        ^ _u64(secret, 128 + 8 * i)) & M64)
                      * PRIME32_1) & M64
        pos += 1024
        nb -= 16
    for s in range(nb):
        _ref_accumulate(acc, data[pos + s * 64: pos + s * 64 + 64],
                        secret[s * 8: s * 8 + 64])
    _ref_accumulate(acc, data[n - 64:],
                    secret[121:185])
    return _ref_merge(acc, secret, (n * PRIME64_1) & M64, 11)


def ref_hashlong_64b_default(data):
    return _ref_hashlong_64b(data, KSECRET)


def ref_hashlong_64b_with_seed(data, seed=0):
    seed &= M64
    if seed == 0:
        return _ref_hashlong_64b(data, KSECRET)
    return _ref_hashlong_64b(data, _init_custom_secret(seed))


# --- Binary grounding. ---

def _read_binary():
    blob = BINARY.read_bytes()
    if hashlib.sha256(blob).hexdigest() != ARTIFACT_DIGEST:
        raise ValueError("binary digest mismatch: %s" % BINARY)
    return blob


def verify_binary(blob):
    """Hash both bodies, byte-compare the default secret table and the
    twelve custom-secret constants, and check the merge-window
    immediates are present in the bodies."""
    for name, start, end, target in FUNCTIONS:
        body = blob[start - 0x1000:end - 0x1000]
        got = hashlib.sha256(body).hexdigest()
        if got != target:
            raise ValueError("%s body hash mismatch: %s" % (name, got))
    secret = blob[KSECRET_VA:KSECRET_VA + 192]
    if secret != KSECRET:
        raise ValueError("default secret table mismatch at 0x%x" % KSECRET_VA)
    for i, const_va in enumerate(CUSTOM_SECRET_CONSTS):
        if blob[const_va:const_va + 16] != KSECRET[i * 16:(i + 1) * 16]:
            raise ValueError("custom-secret const 0x%x != kSecret chunk %d"
                             % (const_va, i))
    # The eight merge-window words appear as movabs immediates in the
    # default body (secret+11..67); the withSeed seed==0 path carries
    # the same set.
    for name, start, end, _target in FUNCTIONS:
        body = blob[start - 0x1000:end - 0x1000]
        for off in range(11, 75, 8):
            if struct.pack("<Q", _u64(KSECRET, off)) not in body:
                raise ValueError("%s: merge word at secret+%d not in body"
                                 % (name, off))
    for const in (PRIME64_1, AVALANCHE_MULT):
        if struct.pack("<Q", const) not in blob[
                FUNCTIONS[0][1] - 0x1000:FUNCTIONS[0][2] - 0x1000]:
            raise ValueError("immediate %016x not in default body" % const)
    return True


# --- Deterministic cases. ---

def generate_cases():
    rng = random.Random(0x11564B0)
    seeds = [0, 1, 2, PRIME64_1, 0xFFFFFFFFFFFFFFFF, 0x123456789ABCDEF0,
             0x8000000000000000, 42, 0xDEADBEEF, 0x9E3779B97F4A7C15,
             0x6A09E667F3BCC908, 0xBB67AE8584CAA73B]
    cases = []
    for i in range(2400):
        if i % 2 == 0:
            length = 241 + (i % 1808)
            seed = 0
        else:
            length = 241 + ((i * 7) % 1808)
            seed = seeds[(i // 2) % len(seeds)]
        if i < 200:
            if i % 5 == 0:
                data = bytes(length)
            elif i % 5 == 1:
                data = b"\xff" * length
            elif i % 5 == 2:
                data = bytes((j * 7 + 3) & 0xFF for j in range(length))
            elif i % 5 == 3:
                data = bytes(j & 0xFF for j in range(length))
            else:
                data = bytes(rng.randrange(256) for _ in range(length))
        else:
            data = bytes(rng.randrange(256) for _ in range(length))
        value = (hashlong_64b_default(data) if seed == 0
                 else hashlong_64b_with_seed(data, seed))
        cases.append({"function": "hashlong_64b_default"
                      if seed == 0 else "hashlong_64b_withSeed",
                      "length": length,
                      "input_hex": data.hex(),
                      "seed_hex": "%016x" % seed,
                      "expected_hex": "%016x" % value})
    return cases


def check_values():
    return {
        "len241_zeros_seed0": hashlong_64b_default(bytes(241)),
        "len241_a_seed0": hashlong_64b_default(b"a" * 241),
        "len512_pattern_seed0": hashlong_64b_default(
            bytes((j * 7 + 3) & 0xFF for j in range(512))),
        "len1024_seq_seedP1": hashlong_64b_with_seed(
            bytes(j & 0xFF for j in range(1024)), PRIME64_1),
        "len241_zeros_seed1": hashlong_64b_with_seed(bytes(241), 1),
        "len2048_seq_seed7": hashlong_64b_with_seed(
            bytes(j & 0xFF for j in range(2048)), 7),
        "len300_pattern_seedDEAD": hashlong_64b_with_seed(
            bytes((j * 13 + 5) & 0xFF for j in range(300)), 0xDEADBEEF),
    }


def verify():
    blob = _read_binary()
    verify_binary(blob)
    cases = generate_cases()
    mismatches = 0
    for case in cases:
        data = bytes.fromhex(case["input_hex"])
        seed = int(case["seed_hex"], 16)
        got = (hashlong_64b_default(data) if seed == 0
               else hashlong_64b_with_seed(data, seed))
        ref = (ref_hashlong_64b_default(data) if seed == 0
               else ref_hashlong_64b_with_seed(data, seed))
        if got != ref or ("%016x" % got) != case["expected_hex"]:
            mismatches += 1
    checks = check_values()
    print("%d cases agree (%d mismatches)" % (len(cases), mismatches))
    for key, value in checks.items():
        print("  %s = 0x%016x" % (key, value))
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
            seed = int(case["seed_hex"], 16)
            ref = (ref_hashlong_64b_default(data) if seed == 0
                   else ref_hashlong_64b_with_seed(data, seed))
            if ("%016x" % ref) != case["expected_hex"]:
                mismatches += 1
        result = {
            "artifact": "node115",
            "artifact_sha256": ARTIFACT_DIGEST,
            "functions": [
                {"name": name, "start": "0x%x" % s, "end": "0x%x" % e,
                 "body_sha256": t, "scope": "length > 240 only"}
                for name, s, e, t in FUNCTIONS
            ],
            "cases": cases,
            "total_cases": len(cases),
            "mismatches": mismatches,
            "check_values": {
                key: "%016x" % value
                for key, value in check_values().items()
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
