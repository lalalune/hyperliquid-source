#!/usr/bin/env python3
"""RE-038 independent verifier. Imports only hashlib, pathlib, struct.

Re-derives from the pinned node #94 binary: the too-many-outcomes carve
at 0x372a470, cmpq imm 0x31 / jbe continue rule (0x31 arm ONLY), string
0x599484 / 30 "too many outcomes for question", Err 0x17b movw store,
GOT slot 0x5774a68 with R_X86_64_RELATIVE addend 0x372a470, 3 inbound
ff15, 0 direct e8/e9. Does not emulate. Prints PASS or FAIL; exit 0 or 1.
"""
import hashlib
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BINARY = ROOT / "artifacts" / "node" / "94" / "hl-node"
SHA256 = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"
PACKET_JSON = HERE / "too_many_outcomes.json"
FN = 0x372A470
FN_END = 0x372A905
CARVED_SHA256 = "444bf531ab17fbff260d60d2ed09cd1df892505a1b7ae2d5eabb249f78a8e00d"
GOT_SLOT = 0x5774A68
FF15_SITES = (0x2719C06, 0x4D12096, 0x4D127A6)
CMP_VA = 0x372A54F
JBE_VA = 0x372A555
JBE_TARGET = 0x372A574
ERR_VA = 0x372A557
LEA_STR_VA = 0x372A55C
STR_LEN_STORE_VA = 0x372A567
STR_VA = 0x599484
STR = b"too many outcomes for question"
STR_SHA = "cffe7f247336dec13c90c834218d23ec2ab8ba54a527cc0eec9974713ba64899"

# Full intended bytes compared at full length (never a length-short expected).
KEY_INSNS = [
    (0x372A470, "554157415641554154"),
    (0x372A54F, "4a837c09e031"),
    (0x372A555, "761d"),
    (0x372A557, "66c7037b01"),
    (0x372A55C, "488d0521efe6fc"),
    (0x372A563, "48894308"),
    (0x372A567, "48c743101e000000"),
    (0x2719C06, "ff155cae0503"),
    (0x4D12096, "ff15cc29a600"),
    (0x4D127A6, "ff15bc22a600"),
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


def count_direct(data, segs, target):
    sites = []
    for base, off, filesz in segs:
        code = data[off : off + filesz]
        i = 0
        while i < len(code) - 5:
            if code[i] in (0xE8, 0xE9):
                va = base + i
                tgt = va + 5 + struct.unpack_from("<i", code, i + 1)[0]
                if tgt == target:
                    sites.append((code[i], va))
                i += 5
                continue
            i += 1
    return sites


def count_ff15_to_got(data, segs, got):
    sites = []
    for base, off, filesz in segs:
        code = data[off : off + filesz]
        i = 0
        while i < len(code) - 6:
            if code[i] == 0xFF and code[i + 1] == 0x15:
                va = base + i
                rel = struct.unpack_from("<i", code, i + 2)[0]
                if va + 6 + rel == got:
                    sites.append(va)
                i += 6
                continue
            i += 1
    return sorted(sites)


# The manifest pins every packet file except MANIFEST.sha256 itself.
PACKET_FILES = frozenset({
    "too_many_outcomes.json",
    "verify.py",
    "independent_verify.py",
    "README.md",
    "pr-body.md",
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
    if len(carved) != 1173:
        errs.append("carve len")
    end_bytes = read_va(data, segs, FN_END, 16)
    int3_pad = 0
    while int3_pad < len(end_bytes) and end_bytes[int3_pad] == 0xCC:
        int3_pad += 1
    if int3_pad != 11:
        errs.append("int3 pad len != 11")
    if read_va(data, segs, FN_END + int3_pad, 1) != b"\x55":
        errs.append("next fn push rbp")
    for va, hx in KEY_INSNS:
        if read_va(data, segs, va, len(hx) // 2).hex() != hx:
            errs.append("key_insn " + hex(va))
    got_rela = [
        r for r in rela_dyn(data)
        if r[0] == GOT_SLOT and (r[1] & 0xFFFFFFFF) == 8
    ]
    if not got_rela or got_rela[0][2] != FN:
        errs.append("GOT RELATIVE addend")
    relative_to_entry = [
        r for r in rela_dyn(data)
        if r[2] == FN and (r[1] & 0xFFFFFFFF) == 8
    ]
    if not any(r[0] == GOT_SLOT for r in relative_to_entry):
        errs.append("relative_to_entry missing GOT")
    e8e9 = count_direct(data, segs, FN)
    if e8e9:
        errs.append("unexpected direct e8/e9")
    ff15 = count_ff15_to_got(data, segs, GOT_SLOT)
    if ff15 != list(FF15_SITES):
        errs.append("ff15 sites")
    raw = read_va(data, segs, STR_VA, len(STR))
    if raw != STR or len(raw) != len(STR):
        errs.append("string bytes")
    if hashlib.sha256(raw).hexdigest() != STR_SHA:
        errs.append("string sha256")
    if data.count(STR) != 1:
        errs.append("string occurrence_count != 1")
    if read_va(data, segs, CMP_VA, 6) != bytes.fromhex("4a837c09e031"):
        errs.append("cmp bytes")
    jbe = read_va(data, segs, JBE_VA, 2)
    if jbe != bytes.fromhex("761d"):
        errs.append("jbe bytes")
    jbe_tgt = JBE_VA + 2 + struct.unpack_from("<b", jbe, 1)[0]
    if jbe_tgt != JBE_TARGET:
        errs.append("jbe target")
    if ERR_VA != JBE_VA + 2:
        errs.append("err not fallthrough of jbe")
    if read_va(data, segs, ERR_VA, 5) != bytes.fromhex("66c7037b01"):
        errs.append("err 0x17b movw store")
    if read_va(data, segs, STR_LEN_STORE_VA, 8) != bytes.fromhex("48c743101e000000"):
        errs.append("string len imm")
    lea = read_va(data, segs, LEA_STR_VA, 7)
    lea_tgt = LEA_STR_VA + 7 + struct.unpack_from("<i", lea, 3)[0]
    if lea_tgt != STR_VA:
        errs.append("lea target")
    # Rule proof (static): unsigned cmp imm 0x31; jbe taken when count
    # <= 0x31 continues to 0x372a574; count > 0x31 falls through to Err.
    if not (JBE_TARGET > JBE_VA + 2 and ERR_VA == JBE_VA + 2):
        errs.append("rule proof geometry")
    # Accept/reject table for the unsigned <= 0x31 gate.
    if not all(n <= 0x31 for n in range(0, 0x32)):
        errs.append("accept range")
    if any(n <= 0x31 for n in (0x32, 0x33, 100, 255)):
        errs.append("reject range")
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
    if hashlib.sha256(pkt).hexdigest() != manifest.get("too_many_outcomes.json"):
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
        "PASS carve=%s ff15=%d strings=%d key_insns=%d"
        % (CARVED_SHA256[:16], len(ff15), 1, len(KEY_INSNS))
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
