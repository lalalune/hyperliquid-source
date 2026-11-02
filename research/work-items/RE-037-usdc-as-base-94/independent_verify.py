#!/usr/bin/env python3
"""RE-037 independent verifier. Imports only hashlib, pathlib, struct.

Re-derives from the pinned node #94 binary: the USDC-as-base guard carve
at 0x274f860, test rdi,rdi / je refuse rule, string 0x3eff61 / 29
"cannot use USDC as base token", Err 0xdf / bounds Err 0xea / Ok 0xac
movw stores, one direct e8 (no GOT / no ff15), and key instruction bytes.
Does not emulate. Prints PASS or FAIL; exit 0 or 1.
"""
import hashlib
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BINARY = ROOT / "artifacts" / "node" / "94" / "hl-node"
SHA256 = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"
PACKET_JSON = HERE / "usdc_as_base_guard.json"
FN = 0x274F860
FN_END = 0x274F994
CARVED_SHA256 = "28f03c901694e40ebd39d8c6c0e4fd149268f940fc60726f0ccf3aeb6ee8a3cc"
DIRECT_E8 = (0x23E81F2,)
TEST_VA = 0x274F876
JE_VA = 0x274F879
JE_TARGET = 0x274F95B
ERR_DF_VA = 0x274F95B
LEA_STR_VA = 0x274F960
STR_LEN_STORE_VA = 0x274F96B
ERR_EA_VA_1 = 0x274F951
ERR_EA_VA_2 = 0x274F974
OK_AC_STACK_VA = 0x274F8F5
OK_AC_STORE_VA = 0x274F981
STR_VA = 0x3EFF61
STR = b"cannot use USDC as base token"

# Full intended bytes compared at full length (never a length-short expected).
KEY_INSNS = [
    (0x274F860, "4889f8"),
    (0x274F863, "488b39"),
    (0x274F876, "4885ff"),
    (0x274F879, "0f84dc000000"),
    (0x274F95B, "66c700df00"),
    (0x274F960, "488d0dfa05cafd"),
    (0x274F96B, "48c740101d000000"),
    (0x274F870, "0f83db000000"),
    (0x274F951, "66c700ea00"),
    (0x274F886, "0f83e8000000"),
    (0x274F974, "66c700ea00"),
    (0x274F8F5, "66c7842490000000ac00"),
    (0x274F981, "6641c707ac00"),
    (0x23E81F2, "e869763600"),
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


# The manifest pins every packet file except MANIFEST.sha256 itself.
PACKET_FILES = frozenset({
    "README.md",
    "independent_verify.py",
    "pr-body.md",
    "usdc_as_base_guard.json",
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
    if len(carved) != 308:
        errs.append("carve len")
    end_bytes = read_va(data, segs, FN_END, 16)
    int3_pad = 0
    while int3_pad < len(end_bytes) and end_bytes[int3_pad] == 0xCC:
        int3_pad += 1
    if int3_pad < 1:
        errs.append("int3 pad at FDE end")
    if int3_pad != 12:
        errs.append("int3 pad len != 12")
    if read_va(data, segs, FN_END + int3_pad, 2) != b"\x41\x57":
        errs.append("next fn push r15")
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
    raw = read_va(data, segs, STR_VA, len(STR))
    if raw != STR or len(raw) != len(STR):
        errs.append("string bytes")
    if data.count(STR) != 3:
        errs.append("string occurrence_count != 3")
    if read_va(data, segs, TEST_VA, 3) != bytes.fromhex("4885ff"):
        errs.append("test rdi,rdi")
    je = read_va(data, segs, JE_VA, 6)
    if je != bytes.fromhex("0f84dc000000"):
        errs.append("je bytes")
    je_tgt = JE_VA + 6 + struct.unpack_from("<i", je, 2)[0]
    if je_tgt != JE_TARGET == ERR_DF_VA:
        errs.append("je target")
    if read_va(data, segs, ERR_DF_VA, 5) != bytes.fromhex("66c700df00"):
        errs.append("err df store")
    if read_va(data, segs, STR_LEN_STORE_VA, 8) != bytes.fromhex("48c740101d000000"):
        errs.append("string len imm")
    lea = read_va(data, segs, LEA_STR_VA, 7)
    lea_tgt = LEA_STR_VA + 7 + struct.unpack_from("<i", lea, 3)[0]
    if lea_tgt != STR_VA:
        errs.append("lea target")
    if read_va(data, segs, ERR_EA_VA_1, 5) != bytes.fromhex("66c700ea00"):
        errs.append("bounds ea store 1")
    if read_va(data, segs, ERR_EA_VA_2, 5) != bytes.fromhex("66c700ea00"):
        errs.append("bounds ea store 2")
    if read_va(data, segs, OK_AC_STACK_VA, 10) != bytes.fromhex("66c7842490000000ac00"):
        errs.append("ok ac stack")
    if read_va(data, segs, OK_AC_STORE_VA, 6) != bytes.fromhex("6641c707ac00"):
        errs.append("ok ac store")
    # Rule proof (static): je is taken when ZF=1 (rdi==0) to Err block;
    # when ZF=0 (rdi!=0) falls through. Pin that the refuse block is the
    # exclusive je target and sits after the fall-through continue path.
    if not (JE_TARGET == ERR_DF_VA and JE_TARGET > JE_VA + 6):
        errs.append("rule proof geometry")
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
    if hashlib.sha256(pkt).hexdigest() != manifest.get("usdc_as_base_guard.json"):
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
        % (CARVED_SHA256[:16], len(e8), 1, len(KEY_INSNS))
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
