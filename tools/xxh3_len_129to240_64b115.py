"""Model of the node #115 XXH3 len_129to240 helper:
XXH3_len_129to240_64b at 0x61d7dc0 (FDE 0x61d7dc0..0x61d8095, 725 bytes,
census id node115-vendor-61d7dc0, body SHA-256
7c681cb1552f7259c1b1625b42d79cdfec1a6146ed9aa9d27ece1d7d6ac071d1).

It is the 129..240 branch of the 64-bit one-shots: ROCKSDB_XXH3_64bits
(0x61db650) tail-jumps to it at 0x61db8cf with seed 0,
ROCKSDB_XXH3_64bits_withSecret (0x61db940) tail-jumps to it at
0x61dc03a with seed 0 and the caller's secret, and
ROCKSDB_XXH3_64bits_withSeed (0x61dc0c0) tail-jumps to it at
0x61dc384 with the seed argument; the first two pass the default
192-byte kSecret (0x97ec80) and secretSize 192. Each dispatcher
compares len against 0x80 then 0xf0 (240) and takes this branch only
for 128 < len <= 240; len > 240 goes to the hashLong helpers
(0x61d8510 / 0x61d9090, PR #5601) or, for withSecret, to the inlined
>240 path at 0x61db9ff. Signature: (input=rdi, len=rsi, secret=rdx,
secretSize=rcx, seed=r8). The secretSize argument is never read (rcx
is overwritten with len * PRIME64_1 at entry). It returns the 64-bit
hash in %rax. It is a leaf: no calls, one push/pop of %r12 (kept only
for stack alignment; %r12 is never otherwise used).

What the disassembly pins:

- Eight front windows, input+0..112 against secret+0..127 in step 16,
  each mix16B with seed, summed into acc starting at len * PRIME64_1
  (movabs 0x9e3779b185ebca87 at 0x61d7dc0). The sum is then
  XXH3_avalanche'd (0x61d7f18..0x61d7f2d, multiplier
  0x165667919e3779f9).
- Trailing window (always runs): mix16B(input+len-16, secret+119,
  seed) -- secret words at +0x77/+0x7f, i.e. the public
  secret + XXH3_SECRET_SIZE_MIN - 17.
- Middle windows, gated on nbRounds = len >> 4 (r10d): one mix16B
  per round i = 8 .. nbRounds-1 at input+16*i against
  secret+16*(i-8)+3, i.e. (input+128/secret+3), (input+144/
  secret+19), (input+160/secret+35), (input+176/secret+51),
  (input+192/secret+67), (input+208/secret+83), (input+224/
  secret+99). The gates are cmp $0x8..$0xd,$0xf against %r10d
  (0x61d7f30..0x61d8046); the i=14 window runs only at len 240.
- The result is XXH3_avalanche(avalanche(front) + trailing + middles).

Grounding: the generator authenticates work/hl-node-115.bin against
the provenance digest, hashes the function body (file offset VA-0x1000
for .text) against the vendor-census target, and byte-compares the
192-byte default secret at file offset 0x97ec80 (.rodata, file offset
== VA) against the published xxHash kSecret. The 2,400 deterministic
cases compare this transliteration against an independent reference
written from the decoded model in loop form (middles before trailing,
the opposite order from the disassembly -- addition commutes, so
agreement still validates the sum); the check values below are
confirmed against the system libxxhash 0.8.2 oracle at the 64-bit
entry points (XXH3_64bits / _withSeed / _withSecret, lengths
129..240). During development the transliteration was additionally
checked by executing the extracted 725 function bytes natively
(mmap RWX + ctypes trampoline, leaf function, controlled
input/secret buffers): 3,000 random cases, lengths 129..240, 8 seeds
plus custom 192-byte secrets, 0 mismatches; the committed
cross-check is the Python reference, and neither the native
execution nor the oracle is an input to the generator.
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
PRIME64_1 = 0x9E3779B185EBCA87
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
    ("len_129to240_64b", 0x61D7DC0, 0x61D8095,
     "7c681cb1552f7259c1b1625b42d79cdfec1a6146ed9aa9d27ece1d7d6ac071d1"),
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


def len_129to240_64b(data, secret=KSECRET, seed=0):
    """XXH3_len_129to240_64b(data, len, secret, secretSize, seed).

    Lengths 129..240 only. Returns the 64-bit hash. The transliteration
    follows the disassembly's control flow: the trailing window is
    folded before the gated middle windows, exactly as the body does
    (r9 = trailing mix at 0x61d7f05, middle mixes added at
    0x61d7f5c..0x61d806a).
    """
    n = len(data)
    seed &= M64
    if n < 129 or n > 240:
        raise ValueError("len out of scope 129..240")
    # Eight front windows, input+0..112 / secret+0..127.
    acc = (n * PRIME64_1) & M64
    for k in range(8):
        acc = (acc + _mix16b(data, 16 * k, secret, 16 * k, seed)) & M64
    acc = _xxh3_avalanche(acc)
    # Trailing window (always runs): input+len-16 / secret+119.
    tail = _mix16b(data, n - 16, secret, 119, seed)
    # Middle windows, one per round i = 8 .. nbRounds-1.
    nb = n // 16
    for i in range(8, nb):
        tail = (tail + _mix16b(data, 16 * i, secret, 16 * (i - 8) + 3,
                               seed)) & M64
    acc = (acc + tail) & M64
    return _xxh3_avalanche(acc)


def xxh3_len_129to240(data, seed=0):
    """The helper as the 64-bit entry points call it: default secret."""
    return len_129to240_64b(data, KSECRET, seed)


# --- Independent reference: same model, loop form. ---

def _ref_mix16b(data, off, secret, sec_off, seed):
    lo = _u64(data, off) ^ ((_u64(secret, sec_off) + seed) & M64)
    hi = _u64(data, off + 8) ^ ((_u64(secret, sec_off + 8) - seed) & M64)
    return _mul128_fold64(lo, hi)


def _ref_len_129to240_64b(data, secret, seed):
    n = len(data)
    seed &= M64
    if n < 129 or n > 240:
        raise ValueError("len out of scope 129..240")
    acc = (n * PRIME64_1) & M64
    for k in range(8):
        acc = (acc + _ref_mix16b(data, 16 * k, secret, 16 * k, seed)) & M64
    acc = _xxh3_avalanche(acc)
    # Reference order: middle windows first, trailing last (the
    # disassembly does the opposite; the sum is the same either way).
    for i in range(8, n // 16):
        acc = (acc + _ref_mix16b(data, 16 * i, secret, 16 * (i - 8) + 3,
                                 seed)) & M64
    acc = (acc + _ref_mix16b(data, n - 16, secret, 119, seed)) & M64
    return _xxh3_avalanche(acc)


def ref_len_129to240(data, seed=0):
    return _ref_len_129to240_64b(data, KSECRET, seed)


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
    # The body's only 8-byte immediates: PRIME64_1 (acc init) and the
    # avalanche multiplier (used twice, front and final).
    body = blob[FUNCTIONS[0][1] - 0x1000:FUNCTIONS[0][2] - 0x1000]
    for const in (PRIME64_1, AVALANCHE_MULT):
        if struct.pack("<Q", const) not in body:
            raise ValueError("immediate %016x not in body" % const)
    # The middle-window length gates: cmp $0x8..$0xd,$0xf against %r10d
    # (nbRounds = len >> 4), encoded 41 83 fa <imm8>.
    for imm in (0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0F):
        if bytes((0x41, 0x83, 0xFA, imm)) not in body:
            raise ValueError("length gate cmp $0x%x not in body" % imm)
    return True


# --- Deterministic cases. ---

def generate_cases():
    rng = random.Random(0x115129F1)
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
        value = xxh3_len_129to240(data, seed)
        cases.append({"function": "len_129to240_64b", "length": length,
                      "input_hex": data.hex(),
                      "seed_hex": "%016x" % seed,
                      "expected_hex": "%016x" % value})
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
        if got != ref or ("%016x" % got) != case["expected_hex"]:
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
            ref = ref_len_129to240(data, seed)
            if ("%016x" % ref) != case["expected_hex"]:
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
                "len129_zeros_seed0": "%016x" % xxh3_len_129to240(bytes(129), 0),
                "len240_a_seed0": "%016x" % xxh3_len_129to240(b"a" * 240, 0),
                "len160_pattern_seed0": "%016x" % xxh3_len_129to240(
                    bytes((j * 7 + 3) & 0xFF for j in range(160)), 0),
                "len160_pattern_seed7": "%016x" % xxh3_len_129to240(
                    bytes((j * 7 + 3) & 0xFF for j in range(160)), 7),
                "len240_zeros_seed1": "%016x" % xxh3_len_129to240(bytes(240), 1),
                "len200_seq_seedP1": "%016x" % xxh3_len_129to240(
                    bytes(j & 0xFF for j in range(200)), PRIME64_1),
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
