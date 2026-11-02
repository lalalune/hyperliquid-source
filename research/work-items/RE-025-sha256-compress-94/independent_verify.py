#!/usr/bin/env python3
"""RE-025 independent verifier. Imports only hashlib, pathlib, struct.

Re-derives from the pinned node #94 binary: carve hash, key instruction bytes,
dispatch branch targets, the 64 FIPS 180-4 K constants (computed here from the
first 64 primes) as imm32 in the plain body and as SHA-NI rip loads, the GOT
RELA, the caller ff15 slot, and the two caller Locations. Checks the FIPS
digests pinned in the packet against hashlib, the packet JSON hash and
MANIFEST.sha256. Does not emulate. Prints PASS or FAIL; exit 0 or 1.
"""
import hashlib
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BINARY = ROOT / "artifacts" / "node" / "94" / "hl-node"
SHA256 = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"
PACKET_JSON = HERE / "sha256-compress.json"
JSON_SHA256 = "9dd7fda7ac294318790f69c971d3caaa1fef82abe09b0637897834692b0d9d27"
FN = 0x4EC9230
FN_RET = 0x4ECBECA
PLAIN_BODY = 0x4EC9323
CARVED_SHA256 = "937e311f6fb2fce19b5ae40389811bffebc67d1942a30be0f61fa2246f93bab9"
GOT_SLOT = 0x576F7A8
LOCATION_PATH_VA = 0x1EE0B7
LOCATION_PATH_LEN = 93
LOCATION_PATH_SHA256 = "7577f1e5bfb01538dd9b8450739561ef53be63f6448ce3083a3a996b0b665243"
LOCATION_PATH_SUFFIX = b"sha2-0.10.8/src/core_api.rs"
LOCATIONS = [(0x566BFF0, 0x145C312, 62, 54), (0x566C008, 0x145C31F, 62, 23)]

KEY_INSNS = [
    (0x4EC9230, "554157415641554154534881ec58010000"),
    (0x4EC924C, "0fb6052ad68b00"),
    (0x4EC9253, "3cff"),
    (0x4EC9255, "740d"),
    (0x4EC9257, "3c01"),
    (0x4EC9259, "0f8499000000"),
    (0x4EC925F, "e9bf000000"),
    (0x4EC926F, "e87c2c0000"),
    (0x4EC927C, "e84f2c0000"),
    (0x4EC9297, "e884ffffff"),
    (0x4EC92EC, "40882d8ad58b00"),
    (0x4EC9314, "e9f72b0000"),
    (0x4EC9323, "488b8424e8000000"),
    (0x4ECBECA, "c3"),
    (0x4EC9220, "31c90f01d0"),
    (0x4ECBEF0, "b80100000031c9"),
    (0x4ECBED0, "b80700000031c9"),
    (0x4ECBF8E, "660ffe05ea8633fb"),
    (0x4ECBF9B, "410f38cbdd"),
    (0x145C299, "ff1509353104"),
    (0x145C312, "488d3dd7fc2004"),
    (0x145C31F, "488d3de2fc2004"),
]
# (insn VA, len, displacement offset, expected target)
BRANCHES = [
    (0x4EC924C, 7, 3, 0x578687D),
    (0x4EC925F, 5, 1, PLAIN_BODY),
    (0x4EC9314, 5, 1, 0x4ECBF10),
    (0x4EC926F, 5, 1, 0x4ECBEF0),
    (0x4EC927C, 5, 1, 0x4ECBED0),
    (0x4EC9297, 5, 1, 0x4EC9220),
    (0x145C299, 6, 2, GOT_SLOT),
]
SHANI_K_LOADS = [
    (0x4ECBF8E, 8, 0), (0x4ECBFB3, 8, 1), (0x4ECBFD1, 8, 2), (0x4ECBFF7, 8, 3),
    (0x4ECC02D, 8, 4), (0x4ECC063, 8, 5), (0x4ECC09C, 8, 6), (0x4ECC0CC, 9, 7),
    (0x4ECC103, 8, 8), (0x4ECC155, 8, 9), (0x4ECC187, 8, 10), (0x4ECC1C3, 8, 11),
    (0x4ECC219, 8, 12), (0x4ECBF4F, 9, 13), (0x4ECBF58, 9, 14), (0x4ECBF61, 9, 15),
]
DIGESTS = {
    b"abc": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq":
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
    b"": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
}


def k_constants():
    primes, n = [], 2
    while len(primes) < 64:
        if all(n % p for p in primes):
            primes.append(n)
        n += 1
    out = []
    for p in primes:
        lo, hi = 0, 1 << 48
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if mid ** 3 <= p << 96:
                lo = mid
            else:
                hi = mid - 1
        out.append(lo & 0xFFFFFFFF)
    return out


def segments(data):
    e_phoff = struct.unpack_from("<Q", data, 32)[0]
    e_phentsize, e_phnum = struct.unpack_from("<HH", data, 54)
    out = []
    for i in range(e_phnum):
        o = e_phoff + i * e_phentsize
        if struct.unpack_from("<I", data, o)[0] != 1:
            continue
        p_offset, p_vaddr = struct.unpack_from("<QQ", data, o + 8)
        p_filesz = struct.unpack_from("<Q", data, o + 32)[0]
        out.append((p_vaddr, p_offset, p_filesz))
    return out


def read_va(data, segs, va, n):
    for base, off, filesz in segs:
        if base <= va < base + filesz:
            o = off + va - base
            return data[o : o + n]
    raise KeyError(hex(va))


def rela_dyn(data):
    e_shoff = struct.unpack_from("<Q", data, 40)[0]
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", data, 58)
    shstr_off, shstr_sz = struct.unpack_from("<QQ", data, e_shoff + e_shstrndx * e_shentsize + 24)
    shstr = data[shstr_off : shstr_off + shstr_sz]
    for i in range(e_shnum):
        o = e_shoff + i * e_shentsize
        name_off, sh_type = struct.unpack_from("<II", data, o)
        if shstr[name_off : shstr.find(bytes([0]), name_off)] == b".rela.dyn" and sh_type != 8:
            off, size = struct.unpack_from("<QQ", data, o + 24)
            return {struct.unpack_from("<Q", data, off + k * 24)[0]:
                    struct.unpack_from("<QQq", data, off + k * 24) for k in range(size // 24)}
    return {}


# The manifest pins the packet's own files plus the
# ../..-relative tool and test files the packet binds.
PACKET_FILES = frozenset({
    "../../../tests/test_crypto_emulation_guard.py",
    "../../../tests/test_crypto_static_scan_bounds.py",
    "../../../tools/crypto_emulation_guard.py",
    "README.md",
    "REVIEW.md",
    "independent_verify.py",
    "pr-body.md",
    "sha256-compress.json",
    "verify.py",
})


def main():
    failures = []
    data = BINARY.read_bytes()
    if hashlib.sha256(data).hexdigest() != SHA256:
        failures.append("binary sha256")
    segs = segments(data)
    if hashlib.sha256(read_va(data, segs, FN, FN_RET - FN + 1)).hexdigest() != CARVED_SHA256:
        failures.append("carved sha256")
    for va, hx in KEY_INSNS:
        if read_va(data, segs, va, len(hx) // 2).hex() != hx:
            failures.append("insn " + hex(va))
    for va, ilen, at, want in BRANCHES:
        insn = read_va(data, segs, va, ilen)
        if va + ilen + struct.unpack_from("<i", insn, at)[0] != want:
            failures.append("branch " + hex(va))
    k = k_constants()
    plain = read_va(data, segs, PLAIN_BODY, FN_RET - PLAIN_BODY + 1)
    if any(struct.pack("<I", c) not in plain for c in k):
        failures.append("plain K imm32")
    groups = set()
    for va, ilen, group in SHANI_K_LOADS:
        insn = read_va(data, segs, va, ilen)
        tgt = va + ilen + struct.unpack_from("<i", insn, ilen - 4)[0]
        if read_va(data, segs, tgt, 16) == struct.pack("<4I", *k[4 * group : 4 * group + 4]):
            groups.add(group)
    if groups != set(range(16)):
        failures.append("SHA-NI K loads")
    rela = rela_dyn(data)
    r = rela.get(GOT_SLOT)
    if r is None or (r[1] & 0xFFFFFFFF) != 8 or r[2] != FN:
        failures.append("GOT rela")
    for loc, lea, line, col in LOCATIONS:
        insn = read_va(data, segs, lea, 7)
        r = rela.get(loc)
        plen, l_line, l_col = struct.unpack_from("<QII", read_va(data, segs, loc, 24), 8)
        if (lea + 7 + struct.unpack_from("<i", insn, 3)[0] != loc or r is None
                or r[2] != LOCATION_PATH_VA or plen != LOCATION_PATH_LEN or (l_line, l_col) != (line, col)):
            failures.append("location " + hex(loc))
    path = read_va(data, segs, LOCATION_PATH_VA, LOCATION_PATH_LEN)
    if hashlib.sha256(path).hexdigest() != LOCATION_PATH_SHA256 or not path.endswith(LOCATION_PATH_SUFFIX):
        failures.append("location path")
    pkt = PACKET_JSON.read_text()
    for msg, hx in DIGESTS.items():
        if hashlib.sha256(msg).hexdigest() != hx:
            failures.append("hashlib vector")
        if pkt.count('"emulated_digest_hex": "' + hx + '"') != 1:
            failures.append("packet emulated digest " + hx[:8])
    if hashlib.sha256(PACKET_JSON.read_bytes()).hexdigest() != JSON_SHA256:
        failures.append("json sha256")
    # Admission: hashing each listed row is not enough. It cannot see
    # a duplicated row, a listed file replaced by a symlink
    # (read_bytes follows it, so the evidence can point outside the
    # packet), an unlisted file in the packet directory, or an
    # evidence file deleted together with its row. Pin the listed set
    # and compare it against the packet contents, mirroring the RE-005
    # verifier and the node-inventory verifiers.
    listed = {}
    for line in (HERE / "MANIFEST.sha256").read_text().splitlines():
        if not line.strip():
            continue
        digest, sep, rel = line.partition("  ")
        if not sep or len(digest) != 64:
            failures.append("malformed manifest line: " + line.strip())
            continue
        if rel in listed:
            failures.append("manifest lists " + rel + " twice")
            continue
        listed[rel] = digest
    if set(listed) != PACKET_FILES:
        failures.append("manifest file set differs from pinned packet files")
    present = set()
    for entry in sorted(HERE.iterdir()):
        if entry.is_symlink():
            failures.append("packet entry is a symlink: " + entry.name)
        elif entry.is_dir():
            if entry.name != "__pycache__" or not all(
                    child.name.endswith(".pyc") and not child.is_symlink()
                    for child in entry.iterdir()):
                failures.append("unexpected directory in packet: " + entry.name)
        else:
            present.add(entry.name)
    in_packet = {rel for rel in listed if not rel.startswith("..")}
    if present - {"MANIFEST.sha256"} != in_packet:
        failures.append("packet contents differ from manifest")
    for rel, digest in listed.items():
        path = HERE / rel
        if path.is_symlink() or not path.is_file():
            failures.append("manifest entry is a symlink or not a file: " + rel)
            continue
        if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            failures.append("manifest " + rel)
    if failures:
        print("FAIL:", ", ".join(failures))
        return 1
    print("PASS: key_insns=%d branches=%d k_groups=16 vectors=%d failures=0"
          % (len(KEY_INSNS), len(BRANCHES), len(DIGESTS)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
