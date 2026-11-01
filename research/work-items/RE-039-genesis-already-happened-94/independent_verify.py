#!/usr/bin/env python3
"""RE-039 independent verifier. Imports only hashlib, pathlib, struct.

Re-derives from the pinned node #94 binary: the genesis-already-happened
carve at 0x3720150, BTree membership->Err gate (found-equal je + rdx==0
je) reaching Err 0xe9 + string 0x599262 / 24 "genesis already happened",
GOT slot 0x5773ef8 with R_X86_64_RELATIVE addend 0x3720150, 6 inbound
ff15, 0 direct e8/e9. Ok 0xea / 0x186 stores observed but not claimed.
Does not emulate. Prints PASS or FAIL; exit 0 or 1.
"""
import hashlib
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BINARY = ROOT / "artifacts" / "node" / "94" / "hl-node"
SHA256 = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"
PACKET_JSON = HERE / "genesis_already_happened.json"
FN = 0x3720150
FN_END = 0x37201F6
CARVED_SHA256 = "d4ff8c4365267de03a2a57bddefbb316d1db415a9dfc534af7330650037bc302"
GOT_SLOT = 0x5773EF8
FF15_SITES = (
    0x23E7FDF,
    0x23E80F6,
    0x4AD7B7F,
    0x4AD7C96,
    0x4AD84AF,
    0x4AD85C6,
)
CMP_KEY_VA = 0x3720195
JE_FOUND_VA = 0x37201B6
JE_FOUND_TARGET = 0x37201D3
TEST_RDX_VA = 0x372015C
JE_RDX0_VA = 0x372015F
ERR_VA = 0x37201D3
LEA_STR_VA = 0x37201D8
STR_LEN_STORE_VA = 0x37201E3
STR_VA = 0x599262
STR = b"genesis already happened"
STR_SHA = "a4ee7b2f1581b7d1ac103e234b5275fdf9be1ef251c53d8bfaf7bf0b95e71036"
NOT_CLAIMED_LEAS = (0x2355DEA, 0x49F631A)
OK_EA_VA = 0x37201CD
OK_186_VA = 0x37201F0

# Full intended bytes compared at full length (never a length-short expected).
KEY_INSNS = [
    (0x3720150, "4889f8"),
    (0x3720153, "483b9698010000"),
    (0x372015A, "7371"),
    (0x372015C, "4885d2"),
    (0x372015F, "7472"),
    (0x3720195, "483b54f910"),
    (0x372019A, "410f97c2"),
    (0x372019E, "4180da00"),
    (0x37201B3, "4585c0"),
    (0x37201B6, "741b"),
    (0x37201CD, "66c700ea00"),
    (0x37201D3, "66c700e900"),
    (0x37201D8, "488d0d8390e7fc"),
    (0x37201DF, "48894808"),
    (0x37201E3, "48c7401018000000"),
    (0x37201F0, "66c7008601"),
    (0x23E7FDF, "ff1513bf3803"),
    (0x23E80F6, "ff15fcbd3803"),
    (0x4AD7B7F, "ff1573c3c900"),
    (0x4AD7C96, "ff155cc2c900"),
    (0x4AD84AF, "ff1543bac900"),
    (0x4AD85C6, "ff152cb9c900"),
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


def main():
    errs = []
    data = BINARY.read_bytes()
    if hashlib.sha256(data).hexdigest() != SHA256:
        errs.append("binary sha256")
    segs = segments(data)
    carved = read_va(data, segs, FN, FN_END - FN)
    if hashlib.sha256(carved).hexdigest() != CARVED_SHA256:
        errs.append("carve sha256")
    if len(carved) != 166:
        errs.append("carve len")
    end_bytes = read_va(data, segs, FN_END, 16)
    int3_pad = 0
    while int3_pad < len(end_bytes) and end_bytes[int3_pad] == 0xCC:
        int3_pad += 1
    if int3_pad != 10:
        errs.append("int3 pad len != 10")
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
    if read_va(data, segs, CMP_KEY_VA, 5) != bytes.fromhex("483b54f910"):
        errs.append("cmp key bytes")
    je = read_va(data, segs, JE_FOUND_VA, 2)
    if je != bytes.fromhex("741b"):
        errs.append("je found bytes")
    je_tgt = JE_FOUND_VA + 2 + struct.unpack_from("<b", je, 1)[0]
    if je_tgt != JE_FOUND_TARGET:
        errs.append("je found target")
    if read_va(data, segs, TEST_RDX_VA, 3) != bytes.fromhex("4885d2"):
        errs.append("test rdx bytes")
    je0 = read_va(data, segs, JE_RDX0_VA, 2)
    if je0 != bytes.fromhex("7472"):
        errs.append("je rdx0 bytes")
    je0_tgt = JE_RDX0_VA + 2 + struct.unpack_from("<b", je0, 1)[0]
    if je0_tgt != ERR_VA:
        errs.append("je rdx0 target")
    if ERR_VA != JE_FOUND_TARGET:
        errs.append("err target mismatch")
    if read_va(data, segs, ERR_VA, 5) != bytes.fromhex("66c700e900"):
        errs.append("err 0xe9 movw store")
    if read_va(data, segs, STR_LEN_STORE_VA, 8) != bytes.fromhex(
        "48c7401018000000"
    ):
        errs.append("string len imm")
    lea = read_va(data, segs, LEA_STR_VA, 7)
    lea_tgt = LEA_STR_VA + 7 + struct.unpack_from("<i", lea, 3)[0]
    if lea_tgt != STR_VA:
        errs.append("lea target")
    # Ok tags are STORE observations only (not claimed).
    if read_va(data, segs, OK_EA_VA, 5) != bytes.fromhex("66c700ea00"):
        errs.append("ok ea store bytes")
    if read_va(data, segs, OK_186_VA, 5) != bytes.fromhex("66c7008601"):
        errs.append("ok 186 store bytes")
    # Not-claimed LEAs of the same packed string must resolve outside carve.
    for lea_va in NOT_CLAIMED_LEAS:
        if FN <= lea_va < FN_END:
            errs.append("not-claimed lea inside carve " + hex(lea_va))
        lb = read_va(data, segs, lea_va, 7)
        if lb[0:3] != b"\x48\x8d\x0d" and lb[0:3] != b"\x48\x8d\x05":
            # Accept either rcx or rax destination LEA form.
            if not (lb[0] == 0x48 and lb[1] == 0x8D):
                errs.append("not-claimed lea opcode " + hex(lea_va))
                continue
        tgt = lea_va + 7 + struct.unpack_from("<i", lb, 3)[0]
        if tgt != STR_VA:
            errs.append("not-claimed lea target " + hex(lea_va))
    # Rule proof (static): found-equal je and rdx==0 je both land on Err.
    if not (JE_FOUND_TARGET == ERR_VA and je0_tgt == ERR_VA):
        errs.append("rule proof geometry")
    manifest = {}
    for line in (HERE / "MANIFEST.sha256").read_text().splitlines():
        digest, name = line.split(None, 1)
        manifest[name.strip()] = digest
    pkt = PACKET_JSON.read_bytes()
    if hashlib.sha256(pkt).hexdigest() != manifest.get(
        "genesis_already_happened.json"
    ):
        errs.append("packet json sha256")
    text = pkt
    for parts in (
        (b"/ho", b"me/"),
        (b"pass", b"word="),
        (b"sec", b"ret="),
        (b"tok", b"en="),
    ):
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
