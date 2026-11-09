"""Model of the node #115 XXH3 64-bit hashLong withSecret inline path:
the len > 240 branch of ROCKSDB_XXH3_64bits_withSecret at 0x61db940
(FDE 0x61db940..0x61dc0bc, 1916 bytes, census id node115-vendor-61db940,
body SHA-256 af7eebcfc41edea9d250273df385394d8ab58bb4a3bca1d9acae4e3e545ada58),
inlined at 0x61db9ff..0x61dbeac (1197 bytes, SHA-256
995aac1662f7d20f60d96a1662f22a1cc8a9ca583ece958af4930aca4ed937db).

Unlike the default and withSeed one-shots, withSecret does NOT call the
hashLong helpers at 0x61d8510/0x61d9090 (PR #5601): it runs against a
caller-supplied secret, so its len > 240 branch is an inline SIMD
hashLong inside the entry point itself. Signature: (input=rdi, len=rsi,
secret=rdx, secretSize=rcx); returns the 64-bit hash in %rax. Dispatch
inside the entry point: len <= 16 takes the short branches (PR #5449);
17..128 runs the mix16B sweep at 0x61dbf10 (PR #5449); 129..240 tail-jumps
to the len_129to240_64b helper at 0x61d7dc0 (PR #5606, E9 at 0x61dc03a
after cmp $0xf0 at 0x61db9f2); len > 240 falls into the inline path at
0x61db9ff. With this packet the withSecret entry point -- and therefore
all three 64-bit one-shots -- is reconstructed for every length.

What the disassembly pins:

- Eight 64-bit accumulators, initialised to XXH3_INIT_ACC =
  {PRIME32_3, PRIME64_1, PRIME64_2, PRIME64_3, PRIME64_4, PRIME32_2,
  PRIME64_5, PRIME32_1} (the four 16-byte constants at .rodata
  0x455960/0x455950/0x453a30/0x4525e0, the same addresses the default
  helper loads; acc[5] is 0x85EBCA77, PRIME32_2).
- The secret limit is secretSize - 64 (lea -0x40(%rcx),%rcx at
  0x61db9ff; rbp keeps the raw secretSize for the last-stripe windows).
  nbStripesPerBlock = secretLimit >> 3, blockBytes =
  nbStripesPerBlock << 6 (for the standard 192-byte secret: 16 stripes,
  1024 bytes, exactly the default helper's geometry). nbBlocks =
  (len-1) / blockBytes (div %r12 at 0x61dba48).
- Full blocks: each stripe is one accumulate_512 over 64 input bytes
  against a 64-byte secret window sliding 8 bytes per stripe (secret +
  s*8 for stripe s, restarting at the caller secret each block). After
  each block, scrambleAcc with the secret + secretLimit window (the
  four window words are loaded from secret + secretLimit at 0x61dba6b..
  0x61dba82; the multiplier is the .rodata constant at 0x4562c0, four
  copies of PRIME32_1 0x9E3779B1).
- Remaining stripes: ((len-1) % blockBytes) >> 6 stripes from the block
  boundary (loop at 0x61dbc70), secret restarting at secret + 0.
- Last stripe (always runs): accumulate_512 over input[len-64..len)
  against secret + secretLimit - 7 (the four windows sit at
  secret + secretSize - 71/-55/-39/-23, i.e. secretLimit - 7 + 16k).
- Result = mergeAcc(acc, secret + 11, len * PRIME64_1), where mergeAcc
  folds four 128-bit products (acc[2i] ^ secret[16i]) *
  (acc[2i+1] ^ secret[16i+8]) low ^ high, then XXH3_avalanche. Unlike
  the default helper, the eight merge-window words are NOT movabs
  immediates: they are loaded from the caller secret at r9+11, 19, 27,
  35, 43, 51, 59, 67 (xor disp(%r9) at 0x61dbdb2/0x61dbdf1/0x61dbe0f/
  0x61dbe18/0x61dbe53/0x61dbe6e/0x61dbe8d/0x61dbe99). The len * PRIME64_1
  term is formed by an imul at 0x61dbe5b. The avalanche epilogue at
  0x61db9a3 is shared with the 9..16 branch (shr $0x25, xor, imul
  0x165667919E3779F9, shr $0x20, xor); the inline path reaches it by
  the jmp at 0x61dbea7. This is the same body as the 64-bit hashLong
  pair (PR #5601) with the secret parameterised instead of fixed to
  kSecret, and the same low64 merge as the 128-bit pair (PR #5598).
- Scope: lengths > 240 only, and secretSize >= 136 (the public
  XXH3_SECRET_SIZE_MIN; the binary does not check, but below 136 the
  secret windows would run past the supplied secret). No in-binary
  caller: a whole-.text E8/lea scan finds no call site or reference
  to 0x61db940 (the binary is stripped).

Grounding: the generator authenticates work/hl-node-115.bin against
the provenance digest, hashes the parent body and the inline range
(file offset VA-0x1000 for .text) against the census targets, and
byte-compares the INIT_ACC constants and the scramble multiplier
against the .rodata values. The 2,400 deterministic cases compare this
transliteration against an independent reference written from the
decoded model in loop form; the check values below are confirmed
against the system libxxhash 0.8.2 oracle at the withSecret entry
point (XXH3_64bits_withSecret, lengths 241..5000, several secret
sizes). No native-execution check was repeated for this path: the
oracle check at the entry point exercises this exact inline path
through its dispatch, and the committed cross-check is the Python
reference (the same body shape was natively executed for the 128-bit
pair, PR #5598).
"""

import argparse
import hashlib
import json
import random
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / "artifacts" / "node" / "115" / "hl-node"
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
LASTACC_START = 7
SECRET_SIZE_MIN = 136

INIT_ACC = [PRIME32_3, PRIME64_1, PRIME64_2, PRIME64_3,
            PRIME64_4, PRIME32_2, PRIME64_5, PRIME32_1]

# 16-byte .rodata constants holding INIT_ACC, in load order.
INIT_ACC_CONSTS = [0x455960, 0x455950, 0x453A30, 0x4525E0]
# .rodata constant holding four copies of PRIME32_1 (scramble multiplier).
SCRAMBLE_CONST_VA = 0x4562C0

# Parent entry point and the inline >240 range inside it.
WITHSECRET_START = 0x61DB940
WITHSECRET_END = 0x61DC0BC
WITHSECRET_BODY_SHA256 = (
    "af7eebcfc41edea9d250273df385394d8ab58bb4a3bca1d9acae4e3e545ada58")
INLINE_START = 0x61DB9FF
INLINE_END = 0x61DBEAC
INLINE_BODY_SHA256 = (
    "995aac1662f7d20f60d96a1662f22a1cc8a9ca583ece958af4930aca4ed937db")

# Published xxHash default secret (192 bytes, xxh3.h kSecret). Used as
# one of the test secrets and as the cross-check against PR #5601's
# default-helper values; the binary slice at file offset 0x97ec80 is
# byte-compared against this constant.
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


def _secret_limit(secret):
    return len(secret) - 64


def _hashlong_64b_with_secret(data, secret):
    """The withSecret inline >240 path: blocks, remaining stripes, last
    stripe, one merge. Lengths > 240 only, secretSize >= 136."""
    n = len(data)
    if n <= 240:
        raise ValueError("len out of scope >240")
    if len(secret) < SECRET_SIZE_MIN:
        raise ValueError("secretSize out of scope <136")
    secret_limit = _secret_limit(secret)
    nb_per_block = secret_limit >> 3
    block_bytes = nb_per_block << 6
    acc = list(INIT_ACC)
    nb_blocks = (n - 1) // block_bytes
    for b in range(nb_blocks):
        for s in range(nb_per_block):
            _accumulate_512(acc, data[b * block_bytes + s * 64:
                                     b * block_bytes + s * 64 + 64],
                            secret[s * 8: s * 8 + 64])
        _scramble_acc(acc, secret[secret_limit:secret_limit + 64])
    rem = ((n - 1) % block_bytes) >> 6
    base = nb_blocks * block_bytes
    for s in range(rem):
        _accumulate_512(acc, data[base + s * 64: base + s * 64 + 64],
                        secret[s * 8: s * 8 + 64])
    _accumulate_512(acc, data[n - 64:],
                    secret[secret_limit - LASTACC_START:
                           secret_limit - LASTACC_START + 64])
    return _merge_acc(acc, secret, (n * PRIME64_1) & M64, MERGE_START)


def hashlong_64b_with_secret(data, secret):
    """XXH3_hashLong_64b_withSecret(data, len, secret, secretSize)."""
    return _hashlong_64b_with_secret(data, secret)


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


def _ref_hashlong_64b_with_secret(data, secret):
    n = len(data)
    if n <= 240:
        raise ValueError("len out of scope >240")
    if len(secret) < SECRET_SIZE_MIN:
        raise ValueError("secretSize out of scope <136")
    secret_limit = len(secret) - 64
    nb_per_block = secret_limit // 8
    block_bytes = nb_per_block * 64
    acc = list(INIT_ACC)
    # Stripes counted as (len-1)//64, consumed nb_per_block at a time
    # with a scramble after each full block; the secret window restarts
    # at each block boundary.
    nb = (n - 1) // 64
    pos = 0
    while nb >= nb_per_block:
        for s in range(nb_per_block):
            _ref_accumulate(acc, data[pos + s * 64: pos + s * 64 + 64],
                            secret[s * 8: s * 8 + 64])
        for i in range(8):
            acc[i] = (((acc[i] ^ (acc[i] >> 47)
                        ^ _u64(secret, secret_limit + 8 * i)) & M64)
                      * PRIME32_1) & M64
        pos += block_bytes
        nb -= nb_per_block
    for s in range(nb):
        _ref_accumulate(acc, data[pos + s * 64: pos + s * 64 + 64],
                        secret[s * 8: s * 8 + 64])
    _ref_accumulate(acc, data[n - 64:],
                    secret[secret_limit - LASTACC_START:
                           secret_limit - LASTACC_START + 64])
    return _ref_merge(acc, secret, (n * PRIME64_1) & M64, 11)


def ref_hashlong_64b_with_secret(data, secret):
    return _ref_hashlong_64b_with_secret(data, secret)


# --- Binary grounding. ---

def _read_binary():
    blob = BINARY.read_bytes()
    if hashlib.sha256(blob).hexdigest() != ARTIFACT_DIGEST:
        raise ValueError("binary digest mismatch: %s" % BINARY)
    return blob


# The eight merge-window words are loaded from the caller secret with
# xor disp(%r9); the byte patterns below are those instructions.
_MERGE_LOAD_PATTERNS = [
    bytes.fromhex("4933410b"),  # xor 0xb(%r9),%rax
    bytes.fromhex("49337113"),  # xor 0x13(%r9),%rsi
    bytes.fromhex("4933511b"),  # xor 0x1b(%r9),%rdx
    bytes.fromhex("49334123"),  # xor 0x23(%r9),%rax
    bytes.fromhex("4933792b"),  # xor 0x2b(%r9),%rdi
    bytes.fromhex("49334133"),  # xor 0x33(%r9),%rax
    bytes.fromhex("4933413b"),  # xor 0x3b(%r9),%rax
    bytes.fromhex("49337943"),  # xor 0x43(%r9),%rdi
]


def verify_binary(blob):
    """Hash the parent body and the inline range, byte-compare the
    INIT_ACC constants and the scramble multiplier, and check the
    dispatch immediates and merge-word loads are present."""
    parent = blob[WITHSECRET_START - 0x1000:WITHSECRET_END - 0x1000]
    got = hashlib.sha256(parent).hexdigest()
    if got != WITHSECRET_BODY_SHA256:
        raise ValueError("withSecret body hash mismatch: %s" % got)
    inline = blob[INLINE_START - 0x1000:INLINE_END - 0x1000]
    got = hashlib.sha256(inline).hexdigest()
    if got != INLINE_BODY_SHA256:
        raise ValueError("inline range hash mismatch: %s" % got)
    secret = blob[KSECRET_VA:KSECRET_VA + 192]
    if secret != KSECRET:
        raise ValueError("default secret table mismatch at 0x%x" % KSECRET_VA)
    expected_init = b"".join(struct.pack("<Q", w) for w in INIT_ACC)
    for i, const_va in enumerate(INIT_ACC_CONSTS):
        if blob[const_va:const_va + 16] != expected_init[i * 16:(i + 1) * 16]:
            raise ValueError("INIT_ACC const 0x%x mismatch" % const_va)
    if blob[SCRAMBLE_CONST_VA:SCRAMBLE_CONST_VA + 16] != \
            struct.pack("<QQ", PRIME32_1 | (PRIME32_1 << 32),
                        PRIME32_1 | (PRIME32_1 << 32)):
        raise ValueError("scramble const 0x%x mismatch" % SCRAMBLE_CONST_VA)
    # Dispatch immediates in the parent body: cmp $0x80 (17..128),
    # cmp $0xf0 (129..240), the E9 to the len_129to240 helper at
    # 0x61d7dc0, the inline entry lea, the PRIME64_1 imul immediate
    # and the avalanche multiplier.
    for needle in (bytes.fromhex("4881fe80000000"),
                   bytes.fromhex("4881fef0000000"),
                   bytes.fromhex("e981bdffff"),
                   bytes.fromhex("488d49c0"),
                   struct.pack("<Q", PRIME64_1),
                   struct.pack("<Q", AVALANCHE_MULT)):
        if needle not in parent:
            raise ValueError("dispatch/immediate %s not in withSecret body"
                             % needle.hex())
    for pattern in _MERGE_LOAD_PATTERNS:
        if pattern not in inline:
            raise ValueError("merge load %s not in inline range"
                             % pattern.hex())
    return True


# --- Deterministic cases. ---

def _case_secrets():
    rng = random.Random(0x1155EC)
    secrets = [("ksecret", KSECRET)]
    for i in range(11):
        secrets.append(("rand192_%d" % i,
                        bytes(rng.randrange(256) for _ in range(192))))
    for size in (136, 144, 160, 176, 200, 208, 224, 256):
        secrets.append(("rand%d" % size,
                        bytes(rng.randrange(256) for _ in range(size))))
    return secrets


def generate_cases():
    rng = random.Random(0x11564B5)
    secrets = _case_secrets()
    cases = []
    for i in range(2400):
        if i % 4 == 0:
            secret = KSECRET
            secret_name = "ksecret"
        elif i % 4 == 1:
            secret_name, secret = secrets[1 + (i // 4) % 11]
        elif i % 4 == 2:
            secret_name, secret = secrets[12 + (i // 4) % 8]
        else:
            secret_name, secret = secrets[1 + ((i * 3) // 4) % 11]
        length = 241 + ((i * 7) % 1808)
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
        value = hashlong_64b_with_secret(data, secret)
        cases.append({"function": "hashlong_64b_withSecret",
                      "length": length,
                      "input_hex": data.hex(),
                      "secret_name": secret_name,
                      "secret_size": len(secret),
                      "secret_hex": secret.hex(),
                      "expected_hex": "%016x" % value})
    return cases


def _secret_136():
    return bytes((j * 11 + 5) & 0xFF for j in range(136))


def _secret_160():
    return bytes((j * 13 + 7) & 0xFF for j in range(160))


def _secret_256():
    return bytes((j * 17 + 3) & 0xFF for j in range(256))


def check_values():
    return {
        "len241_zeros_ksecret": hashlong_64b_with_secret(bytes(241), KSECRET),
        "len241_a_ksecret": hashlong_64b_with_secret(b"a" * 241, KSECRET),
        "len512_pattern_ksecret": hashlong_64b_with_secret(
            bytes((j * 7 + 3) & 0xFF for j in range(512)), KSECRET),
        "len1024_seq_secret136": hashlong_64b_with_secret(
            bytes(j & 0xFF for j in range(1024)), _secret_136()),
        "len2048_seq_secret256": hashlong_64b_with_secret(
            bytes(j & 0xFF for j in range(2048)), _secret_256()),
        "len300_pattern_secret160": hashlong_64b_with_secret(
            bytes((j * 13 + 5) & 0xFF for j in range(300)), _secret_160()),
        "len1024_zeros_secret160": hashlong_64b_with_secret(
            bytes(1024), _secret_160()),
    }


def verify():
    blob = _read_binary()
    verify_binary(blob)
    cases = generate_cases()
    mismatches = 0
    for case in cases:
        data = bytes.fromhex(case["input_hex"])
        secret = bytes.fromhex(case["secret_hex"])
        got = hashlong_64b_with_secret(data, secret)
        ref = ref_hashlong_64b_with_secret(data, secret)
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
            secret = bytes.fromhex(case["secret_hex"])
            ref = ref_hashlong_64b_with_secret(data, secret)
            if ("%016x" % ref) != case["expected_hex"]:
                mismatches += 1
        result = {
            "artifact": "node115",
            "artifact_sha256": ARTIFACT_DIGEST,
            "functions": [
                {"name": "ROCKSDB_XXH3_64bits_withSecret",
                 "start": "0x%x" % WITHSECRET_START,
                 "end": "0x%x" % WITHSECRET_END,
                 "body_sha256": WITHSECRET_BODY_SHA256,
                 "scope": "length > 240 only"},
                {"name": "hashlong_64b_withSecret_inline",
                 "start": "0x%x" % INLINE_START,
                 "end": "0x%x" % INLINE_END,
                 "body_sha256": INLINE_BODY_SHA256,
                 "scope": "length > 240 only, inline range"},
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
