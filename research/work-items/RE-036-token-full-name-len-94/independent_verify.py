#!/usr/bin/env python3
"""RE-036 independent verifier. Imports only hashlib, pathlib, struct.

Re-derives from the pinned node #94 binary: the token full-name helper
carve at 0x2748b80, both error strings, unsigned length gate
add/cmp -0x33 / ja, Option already-set cmp/jno, Err 0xdf / Ok movw
0x186, one direct e8 (no GOT / no ff15), and key instruction bytes.
Does not emulate. Prints PASS or FAIL; exit 0 or 1.
"""
import hashlib
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BINARY = ROOT / "artifacts" / "node" / "94" / "hl-node"
SHA256 = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"
PACKET_JSON = HERE / "token_full_name_len.json"
FN = 0x2748B80
FN_END = 0x2748C4E
CARVED_SHA256 = "64084d429162ad92eb0845b9185504e12fbed1ff1c8c0229e9240b667abf167e"
DIRECT_E8 = (0x23E8565,)
ADD_VA = 0x2748BB2
CMP_LEN_VA = 0x2748BB6
JA_VA = 0x2748BBA
OPT_CMP_VA = 0x2748BA7
OPT_JNO_VA = 0x2748BAC
ERR_TAG_VA = 0x2748BD6
OK_STORE_VA = 0x2748C0F
LEA_LEN_VA = 0x2748BC1
LEA_SET_VA = 0x2748BCF
STR_LEN_VA = 0x5996EC
STR_LEN = b"token full name must be between 1 and 50 characters long"
STR_SET_VA = 0x5996D7
STR_SET = b"full name already set"

# Full intended bytes compared at full length (never a length-short expected).
KEY_INSNS = [
    (0x2748B80, "415653"),
    (0x2748BAE, "488b5310"),
    (0x2748BB2, "4883c2cd"),
    (0x2748BB6, "4883facd"),
    (0x2748BBA, "773e"),
    (0x2748BBC, "b838000000"),
    (0x2748BC1, "488d0d240be5fd"),
    (0x2748BA5, "31d2"),
    (0x2748BA7, "483b540868"),
    (0x2748BAC, "711c"),
    (0x2748BCA, "b815000000"),
    (0x2748BCF, "488d0d010be5fd"),
    (0x2748BD6, "6641c706df00"),
    (0x2748C0F, "6641c7068601"),
    (0x23E8565, "e816063600"),
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
            return data[off + va - base : off + va - base + n]
    raise KeyError(hex(va))


def rela_dyn(data):
    e_shoff = struct.unpack_from("<Q", data, 40)[0]
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", data, 58)
    shstr_off, shstr_sz = struct.unpack_from(
        "<QQ", data, e_shoff + e_shstrndx * e_shentsize + 24
    )
    shstr = data[shstr_off : shstr_off + shstr_sz]
    for i in range(e_shnum):
        o = e_shoff + i * e_shentsize
        name_off, sh_type = struct.unpack_from("<II", data, o)
        name = shstr[name_off : shstr.find(b"\x00", name_off)]
        if name == b".rela.dyn" and sh_type != 8:
            off, size = struct.unpack_from("<QQ", data, o + 24)
            return [
                struct.unpack_from("<QQq", data, off + k * 24)
                for k in range(size // 24)
            ]
    return []


def count_direct_e8(data, segs, target):
    sites = []
    for base, off, filesz in segs:
        code = data[off : off + filesz]
        i = 0
        while i < len(code) - 5:
            if code[i] == 0xE8:
                va = base + i
                tgt = va + 5 + struct.unpack_from("<i", code, i + 1)[0]
                if tgt == target:
                    sites.append(va)
                i += 5
                continue
            i += 1
    return sorted(sites)


def range_accepts(length):
    rdx = (length + 0xFFFFFFFFFFFFFFCD) & 0xFFFFFFFFFFFFFFFF
    return rdx > 0xFFFFFFFFFFFFFFCD


# The manifest pins every packet file except MANIFEST.sha256 itself.
PACKET_FILES = frozenset({
    "README.md",
    "independent_verify.py",
    "pr-body.md",
    "token_full_name_len.json",
    "verify.py",
})


def main():
    errs = []
    data = BINARY.read_bytes()
    if hashlib.sha256(data).hexdigest() != SHA256:
        errs.append("binary sha256")
    segs = segments(data)
    carved = read_va(data, segs, FN, FN_END - FN)
    if hashlib.sha256(carved).hexdigest() != CARVED_SHA256:
        errs.append("carve sha256")
    if len(carved) != 206:
        errs.append("carve len")
    end_bytes = read_va(data, segs, FN_END, 16)
    int3_pad = 0
    while int3_pad < len(end_bytes) and end_bytes[int3_pad] == 0xCC:
        int3_pad += 1
    if int3_pad < 1:
        errs.append("int3 pad at FDE end")
    if read_va(data, segs, FN_END + int3_pad, 1) != b"\x55":
        errs.append("next fn push rbp")
    for va, hx in KEY_INSNS:
        if read_va(data, segs, va, len(hx) // 2).hex() != hx:
            errs.append("key_insn " + hex(va))
    relative = [
        r for r in rela_dyn(data)
        if r[2] == FN and (r[1] & 0xFFFFFFFF) == 8
    ]
    if relative:
        errs.append("unexpected GOT RELATIVE for entry")
    e8 = count_direct_e8(data, segs, FN)
    if e8 != list(DIRECT_E8):
        errs.append("direct e8 sites")
    for va, expected in ((STR_LEN_VA, STR_LEN), (STR_SET_VA, STR_SET)):
        raw = read_va(data, segs, va, len(expected))
        if raw != expected or len(raw) != len(expected):
            errs.append("string " + hex(va))
        if data.count(expected) != 1:
            errs.append("string occurrence " + hex(va))
    if read_va(data, segs, ADD_VA, 4) != bytes.fromhex("4883c2cd"):
        errs.append("add -0x33")
    if read_va(data, segs, CMP_LEN_VA, 4) != bytes.fromhex("4883facd"):
        errs.append("cmp -0x33")
    if read_va(data, segs, JA_VA, 2) != bytes.fromhex("773e"):
        errs.append("ja")
    if read_va(data, segs, OPT_CMP_VA, 5) != bytes.fromhex("483b540868"):
        errs.append("option cmp")
    if read_va(data, segs, OPT_JNO_VA, 2) != bytes.fromhex("711c"):
        errs.append("option jno")
    if read_va(data, segs, ERR_TAG_VA, 6) != bytes.fromhex("6641c706df00"):
        errs.append("err tag")
    if read_va(data, segs, OK_STORE_VA, 6) != bytes.fromhex("6641c7068601"):
        errs.append("ok store")
    for lea_va, sva in ((LEA_LEN_VA, STR_LEN_VA), (LEA_SET_VA, STR_SET_VA)):
        lea = read_va(data, segs, lea_va, 7)
        lea_tgt = lea_va + 7 + struct.unpack_from("<i", lea, 3)[0]
        if lea_tgt != sva:
            errs.append("lea target " + hex(lea_va))
    if not (
        (not range_accepts(0))
        and range_accepts(1)
        and range_accepts(50)
        and (not range_accepts(51))
    ):
        errs.append("range proof")
    # MANIFEST admission, then the packet-json pin below. Building
    # the dict used to be the whole check: duplicate rows silently
    # overwrote each other, only the JSON's row was ever compared,
    # and the other listed files (README.md, pr-body.md, verify.py,
    # independent_verify.py itself) were pinned against nothing — a
    # listed file replaced by a symlink, an unlisted file, or a file
    # deleted together with its row all passed. Enforce the full
    # admission, mirroring the RE-005 verifier and the
    # node-inventory verifiers.
    manifest = {}
    for line in (HERE / "MANIFEST.sha256").read_text().splitlines():
        if not line.strip():
            continue
        digest, sep, name = line.partition("  ")
        name = name.strip()
        if not sep or len(digest) != 64 or not name:
            errs.append("malformed manifest line: " + line.strip())
            continue
        if name in manifest:
            errs.append("manifest lists " + name + " twice")
            continue
        manifest[name] = digest
    if set(manifest) != PACKET_FILES:
        errs.append("manifest file set differs from pinned packet files")
    present = set()
    for entry in sorted(HERE.iterdir()):
        if entry.is_symlink():
            errs.append("packet entry is a symlink: " + entry.name)
        elif entry.is_dir():
            if entry.name != "__pycache__" or not all(
                    child.name.endswith(".pyc") and not child.is_symlink()
                    for child in entry.iterdir()):
                errs.append("unexpected directory in packet: " + entry.name)
        else:
            present.add(entry.name)
    if present - {"MANIFEST.sha256"} != set(manifest):
        errs.append("packet contents differ from manifest")
    for name, digest in manifest.items():
        path = HERE / name
        if path.is_symlink() or not path.is_file():
            errs.append("manifest entry is a symlink or not a file: " + name)
            continue
        if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            errs.append("manifest " + name)
    pkt = PACKET_JSON.read_bytes()
    if hashlib.sha256(pkt).hexdigest() != manifest.get("token_full_name_len.json"):
        errs.append("packet json sha256")
    text = pkt
    for parts in ((b"/ho", b"me/"), (b"pass", b"word="), (b"sec", b"ret="), (b"tok", b"en=")):
        needle = parts[0] + parts[1]
        if needle in text:
            errs.append("hygiene needle present")
    for parts in ((b"Lan", b"tern"), (b"lan", b"tern")):
        if parts[0] + parts[1] in text:
            errs.append("hygiene marker")
    if errs:
        for e in errs:
            print("FAIL", e)
        print("FAIL")
        return 1
    print(
        "PASS carve=%s e8=%d strings=%d key_insns=%d"
        % (CARVED_SHA256[:16], len(e8), 2, len(KEY_INSNS))
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
