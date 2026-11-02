#!/usr/bin/env python3
"""RE-033 independent verifier. Imports only hashlib, pathlib, struct.

Re-derives from the pinned node #94 binary: the sub-deployer set-guard
carve, GOT RELA + three ff15 refs, the three error strings (duplicate /
cannot-set / too-many), early-reject cmpb $0x3 -> Err 0xe3, Err 0xe0 /
Ok 0x186, sibling carve + call, and key instruction bytes. Does not
emulate. Prints PASS or FAIL; exit 0 or 1.
"""
import hashlib
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BINARY = ROOT / "artifacts" / "node" / "94" / "hl-node"
SHA256 = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"
PACKET_JSON = HERE / "sub_deployer_guards.json"
FN = 0x37186D0
FN_END = 0x3718E27
CARVED_SHA256 = "62308cdc40af8382651f100f74eb14b98514ab7f57812950d06d7fc02b23b2d0"
GOT_SLOT = 0x5774BC8
FF15 = (0x2740D6B, 0x4D52EF5, 0x4D58915)
SIBLING = 0x394CE40
SIBLING_END = 0x394D5B6
SIBLING_SHA256 = "881764365124024b493d0de1c7eae86b4f17d522401d13a7352af311623286d5"
CALL_SIBLING_VA = 0x3718BF9
OK_TAG_VA = 0x3718C40
ERR_DUP_VA = 0x3718C97
EARLY_ERR_VA = 0x37186F0
EARLY_CMP_VA = 0x37186E7

# Full intended bytes compared at full length (never a length-short expected).
STRINGS = [
    (0x59900B, b"duplicate sub-deployer"),
    (0x599021, b"cannot set deployer as sub-deployer"),
    (0x5A80B4, b"too many sub-deployers"),
]

KEY_INSNS = [
    (0x37186D0, "554157415641554154534881ec580100"),
    (0x37186E7, "80be3002000003"),
    (0x37186F0, "6641c706e300"),
    (0x3718BF9, "e842422300"),
    (0x3718C40, "6641c7068601"),
    (0x3718C7F, "0f10058503e8fc"),
    (0x3718C97, "6641c706e000"),
    (0x3718C9D, "49c7460816000000"),
    (0x3718D63, "0f1005b702e8fc"),
    (0x3718D74, "6641c706e000"),
    (0x3718D7A, "49c7460823000000"),
    (0x394CE40, "554157415641554154534881ecb80000"),
    (0x394D522, "0f10058babc5fc"),
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


def slot_refs(data, segs, slot):
    refs = []
    for base, off, filesz in segs:
        code = data[off : off + filesz]
        i = 0
        while i < len(code) - 6:
            va = base + i
            if code[i] == 0xFF and code[i + 1] == 0x15:
                tgt = va + 6 + struct.unpack_from("<i", code, i + 2)[0]
                if tgt == slot:
                    refs.append(va)
                i += 6
                continue
            i += 1
    return refs


# The manifest pins every packet file except MANIFEST.sha256 itself.
PACKET_FILES = frozenset({
    "README.md",
    "sub_deployer_guards.json",
    "independent_verify.py",
    "pr-body.md",
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
    if len(carved) != 1879:
        errs.append("carve len")
    end_bytes = read_va(data, segs, FN_END, 16)
    int3_pad = 0
    while int3_pad < len(end_bytes) and end_bytes[int3_pad] == 0xCC:
        int3_pad += 1
    if int3_pad < 1:
        errs.append("int3 pad at FDE end")
    if read_va(data, segs, FN_END + int3_pad, 2) != b"\x41\x57":
        errs.append("next fn push r15")
    for va, hx in KEY_INSNS:
        if read_va(data, segs, va, len(hx) // 2).hex() != hx:
            errs.append("key_insn " + hex(va))
    rela = {r[0]: r for r in rela_dyn(data)}
    r = rela.get(GOT_SLOT)
    if r is None or (r[1] & 0xFFFFFFFF) != 8 or r[2] != FN:
        errs.append("got rela")
    refs = sorted(slot_refs(data, segs, GOT_SLOT))
    if refs != list(FF15):
        errs.append("ff15 sites")
    for va, s in STRINGS:
        got = read_va(data, segs, va, len(s))
        if got != s:
            errs.append("string " + hex(va))
        if len(got) != len(s):
            errs.append("string len " + hex(va))
    if read_va(data, segs, EARLY_CMP_VA, 7) != bytes.fromhex("80be3002000003"):
        errs.append("early cmp")
    if read_va(data, segs, EARLY_ERR_VA, 6) != bytes.fromhex("6641c706e300"):
        errs.append("early err tag")
    if read_va(data, segs, ERR_DUP_VA, 6) != bytes.fromhex("6641c706e000"):
        errs.append("err tag")
    if read_va(data, segs, OK_TAG_VA, 6) != bytes.fromhex("6641c7068601"):
        errs.append("ok tag")
    sib = read_va(data, segs, SIBLING, SIBLING_END - SIBLING)
    if hashlib.sha256(sib).hexdigest() != SIBLING_SHA256:
        errs.append("sibling carve")
    call_bytes = read_va(data, segs, CALL_SIBLING_VA, 5)
    call_tgt = CALL_SIBLING_VA + 5 + struct.unpack_from("<i", call_bytes, 1)[0]
    if call_bytes[0] != 0xE8 or call_tgt != SIBLING:
        errs.append("sibling call")
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
    if hashlib.sha256(pkt).hexdigest() != manifest.get("sub_deployer_guards.json"):
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
        "PASS carve=%s refs=%d strings=%d key_insns=%d"
        % (CARVED_SHA256[:16], len(refs), len(STRINGS), len(KEY_INSNS))
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
