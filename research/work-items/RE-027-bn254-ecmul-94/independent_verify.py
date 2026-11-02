#!/usr/bin/env python3
"""RE-027 independent verifier. Imports only hashlib, pathlib, struct.

Re-derives from the pinned node #94 binary: the run_mul carve hash, key
instruction bytes, call/slot targets, the bn254 field constants (p and the
scalar-field order r computed here from the BN parameter u, the Fq and Fr
Montgomery inverses, R mod p and R^2 mod r) as imm64 in run_mul, the GOT and
precompile-table RELAs, an exact scan of rip-relative ff15/ff25/mov references
to GOT 0x5776f08 and of direct e8/e9 calls to run_mul. Recomputes every ok
vector with its own double-and-add and checks the emulated outputs recorded in
the packet, then the packet JSON hash and MANIFEST.sha256. Does not emulate.
Prints PASS or FAIL; exit 0 or 1.
"""
import hashlib
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BINARY = ROOT / "artifacts" / "node" / "94" / "hl-node"
SHA256 = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"
PACKET_JSON = HERE / "bn254-ecmul.json"
JSON_SHA256 = "ae212bc9791ccdd53cc48dff1446aec74f07693be008b62746d83a601af3b980"
FN = 0x4E96CF0
FN_END = 0x4E973D2
CARVED_SHA256 = "fa3a57aef72db21e765e20e83db52a3c7ffb825112c2780fc3a7406406d942a5"
TEXT_LOAD_VA = 0x1343C80
GOT_SLOT = 0x5776F08
U = 4965661367192848881

KEY_INSNS = [
    (0x4E96CF0, "554157415641554154534881ec88020000"),
    (0x4E96D01, "4889fb4c39c17613"),
    (0x4E96D09, "48b80000000000000080"),
    (0x4E96D1C, "4883fa5f"),
    (0x4E96D5C, "ff157e728d00"),
    (0x4E96DDA, "e801f4ffff"),
    (0x4E96E12, "49bf29a031e1724e6430"),
    (0x4E96E9E, "49bd5d588181b64550b8"),
    (0x4E96EE1, "48b8e3595ce3b13afe53"),
    (0x4E96EF3, "48b8a76d21ae45e6b81b"),
    (0x4E96F05, "48b8a5444e7fb1d01602"),
    (0x4E96F17, "48b88580bb533d83498c"),
    (0x4E96F29, "48b89170b97948e83328"),
    (0x4E96F38, "48b8010000f093f5e143"),
    (0x4E96F63, "48b9ffffffef93f5e1c2"),
    (0x4E96F6D, "49b8b311694c4b868665"),
    (0x4E96F77, "ff157bff8d00"),
    (0x4E96FB8, "e8a3eb0700"),
    (0x4E96FC8, "e8f3f00700"),
    (0x4E9704E, "48b88dca7168916a8197"),
    (0x4E9705D, "48b847fd7cd8168c203c"),
    (0x4E97075, "488b2d7cfe8d00"),
    (0x4E9708F, "49bc896386e48207d287"),
    (0x4E97099, "49bec96aca1e657dde9e"),
    (0x4E970A9, "ffd5"),
    (0x4E970C8, "48b83d0bc7f528eb780a"),
    (0x4E97327, "bf40000000"),
    (0x4E9732C, "ff15a66c8d00"),
    (0x4E97392, "48c7431040000000"),
    (0x4E973A1, "488b842448010000"),
    (0x4E973A9, "48894320"),
    (0x4E973C1, "c3"),
    (0x4E973C2, "bf01000000be40000000"),
    (0x4E973CC, "ff15e66b8d00"),
    (0x4E973D2, "cccccccccccccccccccccccccccc"),
    (0x4E98A7F, "b9409c0000"),
    (0x4E98A87, "ff157be48d00"),
    (0x4E98B0F, "b970170000"),
    (0x4E98B17, "ff15ebe38d00"),
    (0x54C06B0, "f30f1efa4881ff00100000"),
]
# (insn VA, len, displacement offset, expected target)
BRANCHES = [
    (0x4E96DDA, 5, 1, 0x4E961E0),
    (0x4E96FB8, 5, 1, 0x4F15B60),
    (0x4E96FC8, 5, 1, 0x4F160C0),
    (0x4E96F77, 6, 2, 0x5776EF8),
    (0x4E97075, 7, 3, 0x5776EF8),
    (0x4E96D5C, 6, 2, 0x576DFE0),
    (0x4E9732C, 6, 2, 0x576DFD8),
    (0x4E973CC, 6, 2, 0x576DFB8),
    (0x4E98A87, 6, 2, GOT_SLOT),
    (0x4E98B17, 6, 2, GOT_SLOT),
]
# (slot, r_type, addend)
RELAS = [
    (GOT_SLOT, 8, FN),
    (0x574F050, 8, 0x4E98B00),
    (0x574F110, 8, 0x4E98A70),
    (0x576DFD8, 8, 0x54C06B0),
    (0x5776EF8, 8, 0x4F1F9C0),
]


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


def ec_add(p, a, b):
    if a == (0, 0):
        return b
    if b == (0, 0):
        return a
    if a[0] == b[0] and (a[1] + b[1]) % p == 0:
        return (0, 0)
    if a == b:
        lam = 3 * a[0] * a[0] * pow(2 * a[1], p - 2, p) % p
    else:
        lam = (b[1] - a[1]) * pow((b[0] - a[0]) % p, p - 2, p) % p
    x = (lam * lam - a[0] - b[0]) % p
    return (x, (lam * (a[0] - x) - a[1]) % p)


def ec_mul(p, pt, k):
    acc, q = (0, 0), pt
    while k:
        if k & 1:
            acc = ec_add(p, acc, q)
        q = ec_add(p, q, q)
        k >>= 1
    return acc


def json_str(text, key, after):
    i = text.index('"' + key + '": "', after) + len(key) + 5
    return text[i : text.index('"', i)]


# The manifest pins the packet's own files plus the
# ../..-relative tool and test files the packet binds.
PACKET_FILES = frozenset({
    "README.md",
    "REVIEW.md",
    "bn254-ecmul.json",
    "independent_verify.py",
    "pr-body.md",
    "review-evidence/ancestry.json",
    "review-evidence/corrected-independent.log",
    "review-evidence/corrected-normal.log",
    "review-evidence/corrected-optimized.log",
    "review-evidence/corrected-python310.log",
    "review-evidence/corrected-verify.log",
    "review-evidence/current-static.json",
    "review-evidence/final-live-head.json",
    "review-evidence/light-gates.log",
    "review-evidence/log-normalization.json",
    "review-evidence/native-4e961e0.txt",
    "review-evidence/native-4e96cf0.txt",
    "review-evidence/native-4e98a70.txt",
    "review-evidence/native-4e98b00.txt",
    "review-evidence/native-4f15b60.txt",
    "review-evidence/native-4f160c0.txt",
    "review-evidence/native-4f168d0.txt",
    "review-evidence/native-4f1b0f0.txt",
    "review-evidence/native-4f1dea0.txt",
    "review-evidence/native-4f1f8e0.txt",
    "review-evidence/native-4f1f9c0.txt",
    "review-evidence/native-4f20020.txt",
    "review-evidence/native-4f200f0.txt",
    "review-evidence/native-54c06b0.txt",
    "review-evidence/native-final.log",
    "review-evidence/native-review.json",
    "review-evidence/original-independent.log",
    "review-evidence/original-static-tests.log",
    "review-evidence/safe-controls-final-optimized.log",
    "review-evidence/safe-controls-final-python310.log",
    "review-evidence/safe-controls-final.log",
    "review-evidence/safe-controls.log",
    "review-evidence/validation.json",
    "review-original/SOURCE.json",
    "review-original/research/work-items/RE-027-bn254-ecmul-94/MANIFEST.sha256",
    "review-original/research/work-items/RE-027-bn254-ecmul-94/README.md",
    "review-original/research/work-items/RE-027-bn254-ecmul-94/bn254-ecmul.json",
    "review-original/research/work-items/RE-027-bn254-ecmul-94/independent_verify.py",
    "review-original/research/work-items/RE-027-bn254-ecmul-94/pr-body.md",
    "review-original/research/work-items/RE-027-bn254-ecmul-94/verify.py",
    "review-original/tests/test_bn254_ecmul.py",
    "review-original/tools/bn254_ecmul.py",
    "review_native.py",
    "verify.py",
})


def main():
    failures = []
    data = BINARY.read_bytes()
    if hashlib.sha256(data).hexdigest() != SHA256:
        failures.append("binary sha256")
    segs = segments(data)
    carved = read_va(data, segs, FN, FN_END - FN)
    if len(carved) != 1762 or hashlib.sha256(carved).hexdigest() != CARVED_SHA256:
        failures.append("carved sha256")
    for va, hx in KEY_INSNS:
        if read_va(data, segs, va, len(hx) // 2).hex() != hx:
            failures.append("insn " + hex(va))
    for va, ilen, at, want in BRANCHES:
        insn = read_va(data, segs, va, ilen)
        if va + ilen + struct.unpack_from("<i", insn, at)[0] != want:
            failures.append("branch " + hex(va))

    p = 36 * U**4 + 36 * U**3 + 24 * U**2 + 6 * U + 1
    r = 36 * U**4 + 36 * U**3 + 18 * U**2 + 6 * U + 1
    if pow(2, p - 1, p) != 1 or p.bit_length() != 254:
        failures.append("p shape")
    if pow(2, r - 1, r) != 1 or r.bit_length() != 254:
        failures.append("r shape")
    m64 = 2**64 - 1
    inv_p = (-pow(p, -1, 2**128)) % 2**128
    inv_r = (-pow(r, -1, 2**128)) % 2**128
    r_mod_p = 2**256 % p
    r2_mod_r = 2**512 % r

    def counts(code, v, n):
        return [code.count(struct.pack("<Q", (v >> (64 * i)) & m64)) for i in range(n)]

    if counts(carved, p, 4) != [4, 4, 1, 3]:
        failures.append("p limbs in run_mul")
    if counts(carved, r, 4) != [1, 1, 1, 3]:
        failures.append("r limbs in run_mul")
    if counts(carved, inv_p, 2) != [1, 1]:
        failures.append("Fq Montgomery inverse in run_mul")
    if counts(carved, inv_r, 2) != [1, 1]:
        failures.append("Fr Montgomery inverse in run_mul")
    if counts(carved, r_mod_p, 4) != [2, 2, 2, 2]:
        failures.append("R mod p in run_mul")
    if counts(carved, r2_mod_r, 4) != [1, 1, 1, 1]:
        failures.append("R^2 mod r in run_mul")

    rela = rela_dyn(data)
    for slot, rtype, addend in RELAS:
        rr = rela.get(slot)
        if rr is None or (rr[1] & 0xFFFFFFFF) != rtype or rr[2] != addend:
            failures.append("rela " + hex(slot))
    for obj in (0x574F050, 0x574F110):  # Address field at +0x10 (#550 layout)
        if read_va(data, segs, obj + 0x10, 20) != bytes(19) + bytes([7]):
            failures.append("table address " + hex(obj))
    rr = rela.get(0x576DFE0)
    if rr is None or (rr[1] & 0xFFFFFFFF) != 6:
        failures.append("memcpy GLOB_DAT")

    for base, off, filesz in segs:
        if base == TEXT_LOAD_VA:
            text = data[off : off + filesz]
    refs, direct = [], 0
    for i in range(len(text) - 7):
        b0, b1 = text[i], text[i + 1]
        if b0 == 0xFF and b1 in (0x15, 0x25):
            if TEXT_LOAD_VA + i + 6 + struct.unpack_from("<i", text, i + 2)[0] == GOT_SLOT:
                refs.append((b1, TEXT_LOAD_VA + i))
        elif b0 in (0x48, 0x4C) and b1 == 0x8B and (text[i + 2] & 0xC7) == 0x05:
            if TEXT_LOAD_VA + i + 7 + struct.unpack_from("<i", text, i + 3)[0] == GOT_SLOT:
                refs.append((0x8B, TEXT_LOAD_VA + i))
        if b0 in (0xE8, 0xE9) and TEXT_LOAD_VA + i + 5 + struct.unpack_from("<i", text, i + 1)[0] == FN:
            direct += 1
    if refs != [(0x15, 0x4E98A87), (0x15, 0x4E98B17)]:
        failures.append("GOT slot refs")
    if direct != 0:
        failures.append("direct calls")
    for pat in (bytes([0x0F, 0xA2]), bytes([0x0F, 0x01, 0xD0]), bytes([0x66, 0x0F, 0x38, 0xF6]),
                bytes([0xF3, 0x0F, 0x38, 0xF6])):
        if pat in carved:
            failures.append("feature pattern " + pat.hex())

    if read_va(data, segs, 0x4E973C1, 1) != b"\xc3":
        failures.append("primary ret")
    if read_va(data, segs, 0x4E973D2, 14) != b"\xcc" * 14:
        failures.append("int3 padding")

    pkt = PACKET_JSON.read_text()
    oks = 0
    pos = pkt.index('"vectors"')
    while True:
        k = pkt.find('"expected_kind": "ok"', pos)
        if k < 0:
            break
        start = pkt.rfind('"emu": {', 0, k)
        inp = bytes.fromhex(json_str(pkt, "input_hex", start))
        pt = (int.from_bytes(inp[0:32], "big"), int.from_bytes(inp[32:64], "big"))
        scalar = int.from_bytes(inp[64:96], "big")
        x, y = ec_mul(p, pt, scalar)
        want = (x.to_bytes(32, "big") + y.to_bytes(32, "big")).hex()
        if json_str(pkt, "output_hex", start) != want or json_str(pkt, "expected", start) != want:
            failures.append("vector at %d" % start)
        oks += 1
        pos = k + 1
    if oks != 6:
        failures.append("ok vector count %d" % oks)
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
    # This packet legitimately keeps evidence in subdirectories
    # (review-evidence/, review-original/), so instead of rejecting
    # directories the contents comparison walks the whole tree:
    # every file under the packet must be listed, and no entry
    # anywhere in the tree may be a symlink.
    present = set()
    for path in sorted(HERE.rglob("*")):
        rel = path.relative_to(HERE).as_posix()
        if path.is_symlink():
            failures.append("packet entry is a symlink: " + rel)
        elif path.is_file():
            if "__pycache__" in path.parts:
                if path.suffix != ".pyc":
                    failures.append(
                        "unexpected __pycache__ entry in packet: " + rel)
                continue
            present.add(rel)
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
    print("PASS: key_insns=%d branches=%d relas=%d ok_vectors=%d failures=0"
          % (len(KEY_INSNS), len(BRANCHES), len(RELAS), oks))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
