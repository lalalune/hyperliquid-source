#!/usr/bin/env python3
"""RE-040 independent verifier. Imports only hashlib, pathlib, struct.

Re-derives from the pinned node #94 binary: the cannot-revoke-token-freeze
carve at 0x27506c0, the privilege-set / frozen-users-non-zero fall-through
to Err 0xdf + string 0x5999c1 / 64 "cannot revoke token freeze privilege
when there are frozen users", exactly one direct e8 inbound at 0x23e804f,
no RELATIVE reloc to the entry. Ok 0x186 store observed but not claimed.
Does not emulate. Prints PASS or FAIL; exit 0 or 1.
"""
import hashlib
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BINARY = ROOT / "artifacts" / "node" / "94" / "hl-node"
SHA256 = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"
PACKET_JSON = HERE / "cannot_revoke_freeze.json"
FN = 0x27506C0
FN_END = 0x27507CE
CARVED_SHA256 = "0fbf9cf933af697d974cfde82054ba4bb70d6fdb8e18d5acc1b4786390d8fe4f"
E8_SITES = [0x23E804F]
CMP_PRIV_VA = 0x27506ED
JNE_PRIV_VA = 0x27506F2
CLEAR_VA = 0x2750793
CMP_FROZEN_VA = 0x27506F8
JE_FROZEN_VA = 0x27506FE
DRAIN_VA = 0x275071D
ERR_VA = 0x2750700
LEA_STR_VA = 0x2750705
STR_LEN_STORE_VA = 0x2750710
JMP_RET_VA = 0x2750718
EPILOGUE_VA = 0x27507A1
STR_VA = 0x5999C1
STR = b"cannot revoke token freeze privilege when there are frozen users"
STR_SHA = "f2ad5057034d6fec797811f9716cad4e3b84a0c2d5694c29535f957db15043a4"
NOT_CLAIMED_LEAS = (0x4D74065, 0x4D74175)
OK_186_VA = 0x275079C

# Full intended bytes compared at full length.
KEY_INSNS = [
    (0x27506C0, "4157"),
    (0x27506CB, "483b9618020000"),
    (0x27506D2, "0f83d8000000"),
    (0x27506E2, "4869cae8000000"),
    (0x27506ED, "837c081001"),
    (0x27506F2, "0f859b000000"),
    (0x27506F8, "49837c242800"),
    (0x27506FE, "741d"),
    (0x2750700, "66c703df00"),
    (0x2750705, "488d05b592e4fd"),
    (0x275070C, "48894308"),
    (0x2750710, "48c7431040000000"),
    (0x2750718, "e984000000"),
    (0x2750786, "e8f516c600"),
    (0x2750793, "49c744241000000000"),
    (0x275079C, "66c7038601"),
    (0x27507B7, "ff15b3dc0103"),
    (0x23E804F, "e86c863600"),
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


def direct_sites(data, segs, target):
    """Scan executable bytes for e8/e9 rel32 whose target is `target`."""
    out = []
    for base, off, filesz in segs:
        code = data[off : off + filesz]
        for op in (0xE8, 0xE9):
            start = 0
            while True:
                i = code.find(bytes([op]), start)
                if i < 0 or i > len(code) - 5:
                    break
                va = base + i
                if va + 5 + struct.unpack_from("<i", code, i + 1)[0] == target:
                    out.append((op, va))
                start = i + 1
    return sorted(out)


def main():
    errs = []
    data = BINARY.read_bytes()
    if hashlib.sha256(data).hexdigest() != SHA256:
        errs.append("binary sha256")
    segs = segments(data)
    carved = read_va(data, segs, FN, FN_END - FN)
    if hashlib.sha256(carved).hexdigest() != CARVED_SHA256:
        errs.append("carve sha256")
    if len(carved) != 270:
        errs.append("carve len")
    end_bytes = read_va(data, segs, FN_END, 16)
    pad = 0
    while pad < len(end_bytes) and end_bytes[pad] == 0xCC:
        pad += 1
    if pad != 2:
        errs.append("int3 pad len != 2")
    if read_va(data, segs, FN_END + pad, 1) != b"\x55":
        errs.append("next fn push rbp")
    for va, hx in KEY_INSNS:
        if read_va(data, segs, va, len(hx) // 2).hex() != hx:
            errs.append("key_insn " + hex(va))
    if [r for r in rela_dyn(data) if r[2] == FN and (r[1] & 0xFFFFFFFF) == 8]:
        errs.append("unexpected RELATIVE reloc to entry")
    sites = direct_sites(data, segs, FN)
    if [va for op, va in sites if op == 0xE8] != E8_SITES:
        errs.append("direct e8 sites")
    if [va for op, va in sites if op == 0xE9]:
        errs.append("unexpected direct e9")
    raw = read_va(data, segs, STR_VA, len(STR))
    if raw != STR:
        errs.append("string bytes")
    if hashlib.sha256(raw).hexdigest() != STR_SHA:
        errs.append("string sha256")
    if data.count(STR) != 1:
        errs.append("string occurrence_count != 1")
    jne = read_va(data, segs, JNE_PRIV_VA, 6)
    if JNE_PRIV_VA + 6 + struct.unpack_from("<i", jne, 2)[0] != CLEAR_VA:
        errs.append("jne priv target")
    je = read_va(data, segs, JE_FROZEN_VA, 2)
    if JE_FROZEN_VA + 2 + struct.unpack_from("<b", je, 1)[0] != DRAIN_VA:
        errs.append("je frozen target")
    # Rule geometry: both guards fall through, in order, onto the Err store.
    if not (JNE_PRIV_VA + 6 == CMP_FROZEN_VA and JE_FROZEN_VA + 2 == ERR_VA):
        errs.append("rule fall-through geometry")
    lea = read_va(data, segs, LEA_STR_VA, 7)
    if LEA_STR_VA + 7 + struct.unpack_from("<i", lea, 3)[0] != STR_VA:
        errs.append("lea target")
    imm = struct.unpack_from("<I", read_va(data, segs, STR_LEN_STORE_VA, 8), 4)[0]
    if imm != len(STR):
        errs.append("string len imm")
    jmp = read_va(data, segs, JMP_RET_VA, 5)
    if JMP_RET_VA + 5 + struct.unpack_from("<i", jmp, 1)[0] != EPILOGUE_VA:
        errs.append("err jmp target")
    if read_va(data, segs, OK_186_VA, 5) != bytes.fromhex("66c7038601"):
        errs.append("ok 186 store bytes")
    for lea_va in NOT_CLAIMED_LEAS:
        if FN <= lea_va < FN_END:
            errs.append("not-claimed lea inside carve " + hex(lea_va))
        lb = read_va(data, segs, lea_va, 7)
        if not (lb[0] in (0x48, 0x4C) and lb[1] == 0x8D):
            errs.append("not-claimed lea opcode " + hex(lea_va))
            continue
        if lea_va + 7 + struct.unpack_from("<i", lb, 3)[0] != STR_VA:
            errs.append("not-claimed lea target " + hex(lea_va))
    manifest = {}
    for line in (HERE / "MANIFEST.sha256").read_text().splitlines():
        digest, name = line.split(None, 1)
        manifest[name.strip()] = digest
    pkt = PACKET_JSON.read_bytes()
    if hashlib.sha256(pkt).hexdigest() != manifest.get("cannot_revoke_freeze.json"):
        errs.append("packet json sha256")
    for parts in ((b"/ho", b"me/"), (b"pass", b"word="), (b"sec", b"ret="), (b"tok", b"en=")):
        if parts[0] + parts[1] in pkt:
            errs.append("hygiene needle present")
    if errs:
        for e in errs:
            print("FAIL", e)
        print("FAIL")
        return 1
    print(
        "PASS carve=%s e8=%d strings=%d key_insns=%d"
        % (CARVED_SHA256[:16], len(E8_SITES), 1, len(KEY_INSNS))
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
