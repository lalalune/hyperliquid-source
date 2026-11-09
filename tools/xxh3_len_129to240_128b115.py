"""Model of the node #115 XXH3 len_129to240 helper:
XXH3_len_129to240_128b at 0x61d80a0 (FDE 0x61d80a0..0x61d850e, 1134 bytes,
census id node115-vendor-61d80a0, body SHA-256
67af3571427e45f63f95e514c73304db47b8b7994878de07c69f58ddbc73282d).

It is the 129..240 branch of both 128-bit one-shots: ROCKSDB_XXH3_128bits
(0x61deab0) calls it at 0x61dedbc with seed 0, and
ROCKSDB_XXH3_128bits_withSeed (0x61defa0) calls it at 0x61df2c1 with the
seed argument; both pass the default 192-byte kSecret (0x97ec80) and
secretSize 192. Signature: (input=rdi, len=rsi, secret=rdx,
secretSize=rcx, seed=r8). The secretSize argument is never read (rcx is
overwritten with the secret pointer at entry); the seed is live in every
mix16B. It returns the 128-bit hash as (low64, high64) in (%rax, %rdx).

What the disassembly pins (seed is the 5th argument; secret is the
default 192-byte kSecret unless another secret is passed):

- Eight front windows, paired (input+0, input+16), (input+32,
  input+48), (input+64, input+80), (input+96, input+112) against
  secret+0..127 in step 16, each mix16B with seed. Two accumulators:
  acc starts at len * PRIME64_1, acc2 at 0; each pair step folds the
  pair into (acc, acc2) with the partner window's input-word sum xored
  in (the same cross-XOR idiom as the 17..128 path of the 128-bit
  one-shots). Both accumulators are then XXH3_avalanche'd.
- Middle windows, in pairs gated on the length: (input+128/secret+3,
  input+144/secret+19) when len > 159; (input+160/secret+35,
  input+176/secret+51) when len > 191; (input+192/secret+67,
  input+208/secret+83) when len > 223. The gates are cmp $0x9f/$0xbf/
  $0xdf against len (0x61d82d1, 0x61d8344, 0x61d83b7); equivalently the
  pair (i, i+1) runs while i+1 < len//16, so the i=14 window never runs
  (len 240 has len//16 == 15). Each pair step uses the same cross-XOR
  idiom.
- Last bytes (always run): the trailing pair is
  mix16B(input+len-16, secret+103) into acc and mix16B(input+len-32,
  secret+119) into acc2, with the seed NEGATED (the disassembly
  subtracts the seed from the low secret word and adds it to the high
  one, the opposite of every earlier mix16B), each xored with the
  partner window's input-word sum.
- low64 = XXH3_avalanche(A + B); high64 = -XXH3_avalanche(
  A * PRIME64_1 + B * PRIME64_4 + (len - seed) * PRIME64_2), where A
  and B are the two folded trailing accumulators. The (len - seed) term
  is what the body computes (rsi = len - seed at 0x61d8435).

Grounding: the generator authenticates work/hl-node-115.bin against
the provenance digest, hashes the function body (file offset VA-0x1000
for .text) against the vendor-census target, and byte-compares the
192-byte default secret at file offset 0x97ec80 (.rodata, file offset
== VA) against the published xxHash kSecret. The 2,400 deterministic
cases compare this transliteration against an independent reference
written from the decoded model in loop form; the check values below are
confirmed against the system libxxhash 0.8.2 oracle at the 128-bit
entry points (XXH3_128bits / _withSeed, lengths 129..240). During
development the transliteration was additionally checked by executing
the extracted 1134 function bytes natively (mmap RWX + ctypes, leaf
function, no calls, controlled input/secret buffers): 3,000 random
cases, lengths 129..240, 8 seeds plus custom 192-byte secrets, 0
mismatches; the committed cross-check is the Python reference, and
neither the native execution nor the oracle is an input to the
generator.
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
PRIME64_4 = 0x85EBCA77C2B2AE63
AVALANCHE_MULT = 0x165667919E3779F9

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
    ("len_129to240_128b", 0x61D80A0, 0x61D850E,
     "67af3571427e45f63f95e514c73304db47b8b7994878de07c69f58ddbc73282d"),
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


def _mix16b(data, data_off, secret, sec_off, seed):
    lo = _u64(data, data_off) ^ ((_u64(secret, sec_off) + seed) & M64)
    hi = _u64(data, data_off + 8) ^ ((_u64(secret, sec_off + 8) - seed) & M64)
    return _mul128_fold64(lo, hi)


def _wsum(data, off):
    return (_u64(data, off) + _u64(data, off + 8)) & M64


def len_129to240_128b(data, secret=KSECRET, seed=0):
    """XXH3_len_129to240_128b(data, len, secret, secretSize, seed).

    Lengths 129..240 only. Returns (low64, high64). The transliteration
    follows the disassembly's control flow: explicit length gates for
    the middle pairs and the trailing pair with the seed negated.
    """
    n = len(data)
    seed &= M64
    if n < 129 or n > 240:
        raise ValueError("len out of scope 129..240")
    # Eight front windows, paired (0,16), (32,48), (64,80), (96,112).
    acc = (n * PRIME64_1) & M64
    acc2 = 0
    for (a_off, b_off) in ((0, 16), (32, 48), (64, 80), (96, 112)):
        fold_a = _mix16b(data, a_off, secret, a_off, seed)
        acc = ((fold_a + acc) & M64) ^ _wsum(data, b_off)
        fold_b = _mix16b(data, b_off, secret, b_off, seed)
        acc2 = ((fold_b + acc2) & M64) ^ _wsum(data, a_off)
    acc = _xxh3_avalanche(acc)
    acc2 = _xxh3_avalanche(acc2)
    if n > 159:
        # Windows 8,9: input+128/secret+3 with input+144/secret+19.
        fold_a = _mix16b(data, 128, secret, 3, seed)
        acc = ((fold_a + acc) & M64) ^ _wsum(data, 144)
        fold_b = _mix16b(data, 144, secret, 19, seed)
        acc2 = ((fold_b + acc2) & M64) ^ _wsum(data, 128)
    if n > 191:
        # Windows 10,11: input+160/secret+35 with input+176/secret+51.
        fold_a = _mix16b(data, 160, secret, 35, seed)
        acc = ((fold_a + acc) & M64) ^ _wsum(data, 176)
        fold_b = _mix16b(data, 176, secret, 51, seed)
        acc2 = ((fold_b + acc2) & M64) ^ _wsum(data, 160)
    if n > 223:
        # Windows 12,13: input+192/secret+67 with input+208/secret+83.
        fold_a = _mix16b(data, 192, secret, 67, seed)
        acc = ((fold_a + acc) & M64) ^ _wsum(data, 208)
        fold_b = _mix16b(data, 208, secret, 83, seed)
        acc2 = ((fold_b + acc2) & M64) ^ _wsum(data, 192)
    # Last bytes: trailing pair, seed negated.
    fold_a = _mix16b(data, n - 16, secret, 103, (-seed) & M64)
    a = ((fold_a + acc) & M64) ^ _wsum(data, n - 32)
    fold_b = _mix16b(data, n - 32, secret, 119, (-seed) & M64)
    b = ((fold_b + acc2) & M64) ^ _wsum(data, n - 16)
    low = _xxh3_avalanche((a + b) & M64)
    high = (-_xxh3_avalanche(
        (a * PRIME64_1 + b * PRIME64_4
         + ((n - seed) & M64) * PRIME64_2) & M64)) & M64
    return (low, high)


def xxh3_len_129to240(data, seed=0):
    """The helper as the 128-bit entry points call it: default secret."""
    return len_129to240_128b(data, KSECRET, seed)


# --- Independent reference: same model, loop form. ---

def _ref_mix16b(data, off, secret, sec_off, seed):
    lo = _u64(data, off) ^ ((_u64(secret, sec_off) + seed) & M64)
    hi = _u64(data, off + 8) ^ ((_u64(secret, sec_off + 8) - seed) & M64)
    return _mul128_fold64(lo, hi)


def _ref_wsum(data, off):
    return (_u64(data, off) + _u64(data, off + 8)) & M64


def _ref_len_129to240_128b(data, secret, seed):
    n = len(data)
    seed &= M64
    if n < 129 or n > 240:
        raise ValueError("len out of scope 129..240")
    acc = (n * PRIME64_1) & M64
    acc2 = 0
    for k in range(4):
        a, b = 2 * k, 2 * k + 1
        fa = _ref_mix16b(data, 16 * a, secret, 16 * a, seed)
        fb = _ref_mix16b(data, 16 * b, secret, 16 * b, seed)
        acc = ((fa + acc) & M64) ^ _ref_wsum(data, 16 * b)
        acc2 = ((fb + acc2) & M64) ^ _ref_wsum(data, 16 * a)
    acc = _xxh3_avalanche(acc)
    acc2 = _xxh3_avalanche(acc2)
    i = 8
    while i + 1 < n // 16:
        fa = _ref_mix16b(data, 16 * i, secret, 16 * (i - 8) + 3, seed)
        fb = _ref_mix16b(data, 16 * (i + 1), secret, 16 * (i - 7) + 3, seed)
        acc = ((fa + acc) & M64) ^ _ref_wsum(data, 16 * (i + 1))
        acc2 = ((fb + acc2) & M64) ^ _ref_wsum(data, 16 * i)
        i += 2
    fa = _ref_mix16b(data, n - 16, secret, 103, (-seed) & M64)
    fb = _ref_mix16b(data, n - 32, secret, 119, (-seed) & M64)
    a = ((fa + acc) & M64) ^ _ref_wsum(data, n - 32)
    b = ((fb + acc2) & M64) ^ _ref_wsum(data, n - 16)
    low = _xxh3_avalanche((a + b) & M64)
    high = (-_xxh3_avalanche(
        (a * PRIME64_1 + b * PRIME64_4
         + ((n - seed) & M64) * PRIME64_2) & M64)) & M64
    return (low, high)


def ref_len_129to240(data, seed=0):
    return _ref_len_129to240_128b(data, KSECRET, seed)


# --- Binary grounding. ---

def _read_binary():
    blob = BINARY.read_bytes()
    if hashlib.sha256(blob).hexdigest() != ARTIFACT_DIGEST:
        raise ValueError("binary digest mismatch: %s" % BINARY)
    return blob


def verify_binary(blob):
    """Hash the body and byte-compare the default secret table."""
    for name, start, end, target in FUNCTIONS:
        body = blob[start - 0x1000:end - 0x1000]
        got = hashlib.sha256(body).hexdigest()
        if got != target:
            raise ValueError("%s body hash mismatch: %s" % (name, got))
    secret = blob[KSECRET_VA:KSECRET_VA + len(KSECRET)]
    if secret != KSECRET:
        raise ValueError("default secret table mismatch at 0x%x" % KSECRET_VA)
    # The body's only 8-byte immediates: the primes and the avalanche
    # multiplier (the secret words are loaded from memory, not immediates).
    body = blob[FUNCTIONS[0][1] - 0x1000:FUNCTIONS[0][2] - 0x1000]
    for const in (PRIME64_1, PRIME64_2, PRIME64_4, AVALANCHE_MULT):
        if struct.pack("<Q", const) not in body:
            raise ValueError("immediate %016x not in body" % const)
    # The three middle-pair length gates: cmp $0x9f / $0xbf / $0xdf.
    for gate in (b"\x48\x81\xfe\x9f\x00\x00\x00",
                 b"\x48\x81\xfe\xbf\x00\x00\x00",
                 b"\x48\x81\xfe\xdf\x00\x00\x00"):
        if gate not in body:
            raise ValueError("length gate %s not in body" % gate.hex())
    return True


# --- Deterministic cases. ---

def generate_cases():
    rng = random.Random(0x115129F0)
    seeds = [0, 1, 2, PRIME64_1, 0xFFFFFFFFFFFFFFFF, 0x123456789ABCDEF0,
             0x8000000000000000, 42, 0xDEADBEEF, 0x9E3779B97F4A7C15,
             0x6A09E667F3BCC908, 0xBB67AE8584CAA73B]
    cases = []
    for i in range(2400):
        length = 129 + (i % 112)
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
        seed = seeds[i % len(seeds)]
        low, high = xxh3_len_129to240(data, seed)
        cases.append({"function": "len_129to240_128b", "length": length,
                      "input_hex": data.hex(),
                      "seed_hex": "%016x" % seed,
                      "expected_low_hex": "%016x" % low,
                      "expected_high_hex": "%016x" % high})
    return cases


def verify():
    blob = _read_binary()
    verify_binary(blob)
    cases = generate_cases()
    mismatches = 0
    for case in cases:
        data = bytes.fromhex(case["input_hex"])
        seed = int(case["seed_hex"], 16)
        got = xxh3_len_129to240(data, seed)
        ref = ref_len_129to240(data, seed)
        if got != ref or ("%016x" % got[0]) != case["expected_low_hex"] \
                or ("%016x" % got[1]) != case["expected_high_hex"]:
            mismatches += 1
    checks = {
        "len129_zeros_seed0": xxh3_len_129to240(bytes(129), 0),
        "len240_a_seed0": xxh3_len_129to240(b"a" * 240, 0),
        "len160_pattern_seed0": xxh3_len_129to240(
            bytes((j * 7 + 3) & 0xFF for j in range(160)), 0),
        "len160_pattern_seed7": xxh3_len_129to240(
            bytes((j * 7 + 3) & 0xFF for j in range(160)), 7),
        "len240_zeros_seed1": xxh3_len_129to240(bytes(240), 1),
        "len200_seq_seedP1": xxh3_len_129to240(
            bytes(j & 0xFF for j in range(200)), PRIME64_1),
    }
    print("%d cases agree (%d mismatches)" % (len(cases), mismatches))
    for key, value in checks.items():
        print("  %s = (0x%016x, 0x%016x)" % (key, value[0], value[1]))
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
            ref = ref_len_129to240(data, seed)
            if ("%016x" % ref[0]) != case["expected_low_hex"] \
                    or ("%016x" % ref[1]) != case["expected_high_hex"]:
                mismatches += 1
        result = {
            "artifact": "node115",
            "artifact_sha256": ARTIFACT_DIGEST,
            "functions": [
                {"name": name, "start": "0x%x" % s, "end": "0x%x" % e,
                 "body_sha256": t, "scope": "length 129..240 only"}
                for name, s, e, t in FUNCTIONS
            ],
            "cases": cases,
            "total_cases": len(cases),
            "mismatches": mismatches,
            "check_values": {
                "len129_zeros_seed0": ["%016x" % v for v in
                                       xxh3_len_129to240(bytes(129), 0)],
                "len240_a_seed0": ["%016x" % v for v in
                                   xxh3_len_129to240(b"a" * 240, 0)],
                "len160_pattern_seed0": ["%016x" % v for v in
                                         xxh3_len_129to240(
                                             bytes((j * 7 + 3) & 0xFF
                                                   for j in range(160)), 0)],
                "len160_pattern_seed7": ["%016x" % v for v in
                                         xxh3_len_129to240(
                                             bytes((j * 7 + 3) & 0xFF
                                                   for j in range(160)), 7)],
                "len240_zeros_seed1": ["%016x" % v for v in
                                       xxh3_len_129to240(bytes(240), 1)],
                "len200_seq_seedP1": ["%016x" % v for v in
                                      xxh3_len_129to240(
                                          bytes(j & 0xFF
                                                for j in range(200)),
                                          PRIME64_1)],
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
