#!/usr/bin/env python3
"""RE-025: SHA-256 compress at 0x4ec9230 (node #94), plain path + GOT wiring.

Standalone. From the pinned node #94 binary only, it recovers:
  * compress entry 0x4ec9230 (FDE 0x4ec9230..0x4ecbecb, ret at 0x4ecbeca);
    the emulated carve 0x4ec9230..0x4ecbeca is sha256-pinned;
  * ABI (rdi=8x u32 LE state, rsi=64-byte blocks, rdx=nblocks);
  * the inline CPU-feature dispatch on the byte at 0x578687d:
    0xff -> detection (cpuid helpers 0x4ecbef0 / 0x4ecbed0, xgetbv 0x4ec9220),
    1 -> epilogue then jmp 0x4ecbf10 (SHA-NI body, static only),
    other -> jmp 0x4ec9323 (plain-code compress, emulated);
  * all 64 FIPS 180-4 SHA-256 round constants as imm32 in the plain body, and
    the 16 rip-relative 16-byte K loads in the SHA-NI body (K[0..3] at 0x204680);
  * wiring: R_X86_64_RELATIVE addend 0x4ec9230 at GOT slot 0x576f7a8, the
    caller at 0x145c299 (ff15 call *[rip] -> slot), and an exact count of
    rip-relative ff15/ff25/mov references to the slot in the main text load;
  * caller panic Locations 0x566bff0 / 0x566c008 (string+shape evidence only);
  * behavioural proof: Unicorn on PT_LOAD maps with the feature byte forced to
    0 (plain path) for FIPS 180-4 abc / two-block / empty digests.

Output is sorted, deterministic JSON. Every expected value is pinned exactly.
Imports only the Python standard library plus optional unicorn for emulation
(no objdump, no pyelftools).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path
from crypto_emulation_guard import run_bounded

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "artifacts" / "node" / "94" / "hl-node"
BINARY_SHA256 = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"

FN = 0x4EC9230
FN_END = 0x4ECBECB
FN_RET = 0x4ECBECA
PLAIN_BODY = 0x4EC9323
CARVED_SHA256 = "937e311f6fb2fce19b5ae40389811bffebc67d1942a30be0f61fa2246f93bab9"
CARVED_LEN = FN_RET - FN + 1

FLAG_VA = 0x578687D
SHANI = 0x4ECBF10
SHANI_END = 0x4ECC2CC
SHANI_JMP = 0x4EC9314
PLAIN_JMP = 0x4EC925F
CPUID_LEAF1 = 0x4ECBEF0
CPUID_LEAF7 = 0x4ECBED0
XGETBV = 0x4EC9220
K_TABLE = 0x204680
K_PADDD = 0x4ECBF8E
# SHA-NI rip-relative 16-byte K loads: (insn VA, insn len, K group index 0..15).
SHANI_K_LOADS = [
    (0x4ECBF8E, 8, 0), (0x4ECBFB3, 8, 1), (0x4ECBFD1, 8, 2), (0x4ECBFF7, 8, 3),
    (0x4ECC02D, 8, 4), (0x4ECC063, 8, 5), (0x4ECC09C, 8, 6), (0x4ECC0CC, 9, 7),
    (0x4ECC103, 8, 8), (0x4ECC155, 8, 9), (0x4ECC187, 8, 10), (0x4ECC1C3, 8, 11),
    (0x4ECC219, 8, 12), (0x4ECBF4F, 9, 13), (0x4ECBF58, 9, 14), (0x4ECBF61, 9, 15),
]
SHANI_BSWAP_LOAD = 0x4ECBF47  # movdqa xmm5,[rip] -> 0x2078c0 byte-swap mask
BSWAP_MASK_HEX = "03020100070605040b0a09080f0e0d0c"

GOT_SLOT = 0x576F7A8
R_X86_64_RELATIVE = 8
CALLER_FN = 0x145C1D0
CALLER_CALL = 0x145C299
TEXT_LOAD_VA = 0x1343C80
SLOT_REFS_EXPECTED = {"call": 18, "jmp": 0, "mov": 15}

LOCATIONS = [  # (Location VA, lea VA, line, col)
    (0x566BFF0, 0x145C312, 62, 54),
    (0x566C008, 0x145C31F, 62, 23),
]
LOCATION_PATH_VA = 0x1EE0B7
LOCATION_PATH_LEN = 93
LOCATION_PATH_SHA256 = "7577f1e5bfb01538dd9b8450739561ef53be63f6448ce3083a3a996b0b665243"
LOCATION_PATH_SUFFIX = "sha2-0.10.8/src/core_api.rs"

# TOKEN rule: printed as key_insns, never the banned equals-form.
KEY_INSNS = [
    (0x4EC9230, "554157415641554154534881ec58010000", "push rbp..rbx; sub rsp,0x158"),
    (0x4EC924C, "0fb6052ad68b00", "movzx eax,byte [rip] -> 0x578687d"),
    (0x4EC9253, "3cff", "cmp al,0xff"),
    (0x4EC9255, "740d", "je detection 0x4ec9264"),
    (0x4EC9257, "3c01", "cmp al,1"),
    (0x4EC9259, "0f8499000000", "je SHA-NI epilogue 0x4ec92f8"),
    (0x4EC925F, "e9bf000000", "jmp plain body 0x4ec9323"),
    (0x4EC926F, "e87c2c0000", "call cpuid leaf1 helper 0x4ecbef0"),
    (0x4EC927C, "e84f2c0000", "call cpuid leaf7 helper 0x4ecbed0"),
    (0x4EC9297, "e884ffffff", "call xgetbv helper 0x4ec9220"),
    (0x4EC92EC, "40882d8ad58b00", "mov [rip] 0x578687d,bpl (cache store)"),
    (0x4EC9314, "e9f72b0000", "jmp SHA-NI 0x4ecbf10"),
    (0x4EC9323, "488b8424e8000000", "plain body: reload state ptr"),
    (0x4ECBECA, "c3", "plain ret"),
    (0x4EC9220, "31c90f01d0", "xgetbv helper"),
    (0x4ECBEF0, "b80100000031c9", "cpuid leaf 1 helper"),
    (0x4ECBED0, "b80700000031c9", "cpuid leaf 7 helper"),
    (0x4ECBF8E, "660ffe05ea8633fb", "SHA-NI paddd xmm0,[rip] -> K 0x204680"),
    (0x4ECBF9B, "410f38cbdd", "SHA-NI sha256rnds2 xmm3,xmm13"),
    (0x145C299, "ff1509353104", "caller call *[rip] -> GOT 0x576f7a8"),
    (0x145C312, "488d3dd7fc2004", "caller lea rdi,Location 0x566bff0"),
    (0x145C31F, "488d3de2fc2004", "caller lea rdi,Location 0x566c008"),
]


def _k():
    # FIPS 180-4 4.2.2: first 32 bits of the fractional cube roots of the first 64 primes.
    primes, n = [], 2
    while len(primes) < 64:
        if all(n % p for p in primes):
            primes.append(n)
        n += 1
    out = []
    for p in primes:
        lo, hi = 0, 1 << 48
        while lo < hi:  # integer cube root of p * 2^96
            mid = (lo + hi + 1) // 2
            if mid ** 3 <= p << 96:
                lo = mid
            else:
                hi = mid - 1
        out.append(lo & 0xFFFFFFFF)
    return out


SHA256_K = _k()
SHA256_IV = [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
             0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19]
SHA256_IV_LE = struct.pack("<8I", *SHA256_IV)

TWO_BLOCK_MSG = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
# FIPS 180-4 published digests, pinned literally (not recomputed).
VECTORS = {
    "abc": (b"abc", 1, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
    "two_block": (TWO_BLOCK_MSG, 2, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"),
    "empty": (b"", 1, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
}


def pad(msg: bytes) -> bytes:
    out = bytearray(msg) + b"\x80"
    while (len(out) + 8) % 64:
        out.append(0)
    return bytes(out) + (len(msg) * 8).to_bytes(8, "big")


def segments(data):
    if data[:4] != b"\x7fELF":
        raise ValueError("not ELF")
    e_phoff = struct.unpack_from("<Q", data, 32)[0]
    e_phentsize, e_phnum = struct.unpack_from("<HH", data, 54)
    out = []
    for i in range(e_phnum):
        o = e_phoff + i * e_phentsize
        if struct.unpack_from("<I", data, o)[0] != 1:
            continue
        p_offset, p_vaddr = struct.unpack_from("<QQ", data, o + 8)
        p_filesz, p_memsz = struct.unpack_from("<QQ", data, o + 32)
        out.append((p_vaddr, p_offset, p_filesz, p_memsz))
    return out


def va_to_off(segs, va):
    for base, off, filesz, _memsz in segs:
        if base <= va < base + filesz:
            return off + (va - base)
    raise KeyError(hex(va))


def read_va(data, segs, va, n):
    o = va_to_off(segs, va)
    return data[o : o + n]


def rela_dyn(data):
    e_shoff = struct.unpack_from("<Q", data, 40)[0]
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", data, 58)
    shstr_hdr = e_shoff + e_shstrndx * e_shentsize
    shstr_off, shstr_sz = struct.unpack_from("<QQ", data, shstr_hdr + 24)
    shstr = data[shstr_off : shstr_off + shstr_sz]
    for i in range(e_shnum):
        o = e_shoff + i * e_shentsize
        name_off, sh_type = struct.unpack_from("<II", data, o)
        name = shstr[name_off : shstr.find(b"\x00", name_off)]
        if name == b".rela.dyn":
            if sh_type == 8:  # SHT_NOBITS: no file bytes to read
                raise ValueError(".rela.dyn is NOBITS")
            off, size = struct.unpack_from("<QQ", data, o + 24)
            return [struct.unpack_from("<QQq", data, off + k * 24) for k in range(size // 24)]
    raise KeyError(".rela.dyn")


def slot_refs(data, segs):
    """Rip-relative references to GOT_SLOT in the main text load, by kind."""
    for base, off, filesz, _m in segs:
        if base == TEXT_LOAD_VA:
            text = data[off : off + filesz]
            break
    else:
        raise KeyError("text load")
    refs = []
    for i in range(len(text) - 5):
        b0, b1 = text[i], text[i + 1]
        if b0 == 0xFF and b1 in (0x15, 0x25):
            if TEXT_LOAD_VA + i + 6 + struct.unpack_from("<i", text, i + 2)[0] == GOT_SLOT:
                refs.append(("call" if b1 == 0x15 else "jmp", TEXT_LOAD_VA + i))
        elif i + 7 <= len(text) and b0 in (0x48, 0x4C) and b1 == 0x8B and (text[i + 2] & 0xC7) == 0x05:
            if TEXT_LOAD_VA + i + 7 + struct.unpack_from("<i", text, i + 3)[0] == GOT_SLOT:
                refs.append(("mov", TEXT_LOAD_VA + i))
    return refs


def unicorn_available():
    import importlib.util

    return importlib.util.find_spec("unicorn") is not None


def emulate_compress(data, segs, blocks: bytes, nblocks: int, state=SHA256_IV_LE, flag=0):
    """Run 0x4ec9230 with the feature byte forced to `flag`; return BE digest bytes."""
    if type(nblocks) is not int or not 0 <= nblocks <= 2:
        raise ValueError("fixture block count must be 0..2")
    if len(state) != 32 or len(blocks) % 64 or not 64 * nblocks <= len(blocks) <= 128:
        raise ValueError("fixture state/block lengths outside bounds")
    if flag not in (0, 1):
        raise ValueError("fixture permits plain mode or bounded SHA-NI rejection only")
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_PROT_ALL, UcError
    from unicorn.x86_const import UC_X86_REG_RDI, UC_X86_REG_RDX, UC_X86_REG_RSI, UC_X86_REG_RSP

    mu = Uc(UC_ARCH_X86, UC_MODE_64)
    page = 0x1000

    def map_span(va, size):
        start = va & ~(page - 1)
        end = (va + size + page - 1) & ~(page - 1)
        try:
            mu.mem_map(start, end - start, UC_PROT_ALL)
        except UcError:
            for p in range(start, end, page):
                try:
                    mu.mem_map(p, page, UC_PROT_ALL)
                except UcError:
                    pass

    for base, off, filesz, memsz in segs:
        map_span(base, memsz)
        mu.mem_write(base, data[off : off + filesz] + bytes(max(0, memsz - filesz)))
    mu.mem_write(FLAG_VA, bytes([flag]))

    STACK, SCRATCH, STOP = 0x7FFF00000000, 0x70000000, 0x600000000
    map_span(STACK, 0x100000)
    map_span(SCRATCH, 0x10000)
    map_span(STOP, 0x1000)
    mu.mem_write(STOP, b"\xf4")
    STATE, BLOCKS = SCRATCH + 0x100, SCRATCH + 0x200
    mu.mem_write(STATE, state)
    mu.mem_write(BLOCKS, blocks)
    rsp = STACK + 0x100000 - 0x2000 - 8
    mu.mem_write(rsp, struct.pack("<Q", STOP))
    mu.reg_write(UC_X86_REG_RSP, rsp)
    mu.reg_write(UC_X86_REG_RDI, STATE)
    mu.reg_write(UC_X86_REG_RSI, BLOCKS)
    mu.reg_write(UC_X86_REG_RDX, nblocks)
    run_bounded(mu, FN, STOP,
                code_ranges=((FN, 0x4EC9264), (PLAIN_BODY, FN_END)),
                writable_ranges=((STACK, STACK + 0x100000), (STATE, STATE + 32)),
                timeout=30_000_000, count=50_000_000)
    st = bytes(mu.mem_read(STATE, 32))
    # sha2 keeps state as native u32 words; FIPS digests are BE word bytes.
    return b"".join(struct.pack(">I", w) for w in struct.unpack("<8I", st))


def analyse(data, check_sha=True, run_emu=False):
    if check_sha:
        got = hashlib.sha256(data).hexdigest()
        if got != BINARY_SHA256:
            raise ValueError("binary sha256 mismatch: " + got)
    segs = segments(data)
    carved = read_va(data, segs, FN, CARVED_LEN)
    plain = read_va(data, segs, PLAIN_BODY, FN_RET - PLAIN_BODY + 1)

    key_bytes = []
    for va, hx, note in KEY_INSNS:
        raw = read_va(data, segs, va, len(hx) // 2)
        key_bytes.append({"va": hex(va), "bytes": raw.hex(), "expected": hx,
                          "match": raw.hex() == hx, "note": note})

    def rel32_target(va, ilen, disp_at):
        insn = read_va(data, segs, va, ilen)
        return va + ilen + struct.unpack_from("<i", insn, disp_at)[0]

    branches = {
        "flag_load_target": hex(rel32_target(0x4EC924C, 7, 3)),
        "plain_jmp_target": hex(rel32_target(PLAIN_JMP, 5, 1)),
        "shani_jmp_target": hex(rel32_target(SHANI_JMP, 5, 1)),
        "cpuid_leaf1_target": hex(rel32_target(0x4EC926F, 5, 1)),
        "cpuid_leaf7_target": hex(rel32_target(0x4EC927C, 5, 1)),
        "xgetbv_target": hex(rel32_target(0x4EC9297, 5, 1)),
        "flag_store_target": hex(rel32_target(0x4EC92EC, 7, 3)),
        "k_paddd_target": hex(rel32_target(K_PADDD, 8, 4)),
        "caller_call_slot": hex(rel32_target(CALLER_CALL, 6, 2)),
    }
    branches_expected = {
        "flag_load_target": hex(FLAG_VA), "plain_jmp_target": hex(PLAIN_BODY),
        "shani_jmp_target": hex(SHANI), "cpuid_leaf1_target": hex(CPUID_LEAF1),
        "cpuid_leaf7_target": hex(CPUID_LEAF7), "xgetbv_target": hex(XGETBV),
        "flag_store_target": hex(FLAG_VA), "k_paddd_target": hex(K_TABLE),
        "caller_call_slot": hex(GOT_SLOT),
    }

    k_imm_missing = [i for i, k in enumerate(SHA256_K) if struct.pack("<I", k) not in plain]
    shani_k = []
    for va, ilen, group in SHANI_K_LOADS:
        tgt = rel32_target(va, ilen, ilen - 4)
        raw = read_va(data, segs, tgt, 16)
        shani_k.append({"insn_va": hex(va), "target": hex(tgt), "k_group": group,
                        "match": raw == struct.pack("<4I", *SHA256_K[4 * group : 4 * group + 4])})
    k_groups_covered = sorted({e["k_group"] for e in shani_k if e["match"]})
    bswap_tgt = rel32_target(SHANI_BSWAP_LOAD, 8, 4)
    bswap_match = read_va(data, segs, bswap_tgt, 16).hex() == BSWAP_MASK_HEX
    shani = read_va(data, segs, SHANI, SHANI_END - SHANI)
    shani_rnds2 = shani.count(b"\x0f\x38\xcb")

    rela = rela_dyn(data)
    got_rela = None
    for r_offset, r_info, r_addend in rela:
        if r_offset == GOT_SLOT:
            got_rela = {"r_offset": hex(r_offset), "r_info": hex(r_info), "r_addend": hex(r_addend)}
    rela_by_off = {}
    for r in rela:
        if r[0] in rela_by_off:
            raise ValueError(f"duplicate relocation offset {r[0]:#x}")
        rela_by_off[r[0]] = r

    locations = []
    for loc, lea, line, col in LOCATIONS:
        r = rela_by_off.get(loc)
        raw = read_va(data, segs, loc, 24)
        plen, l_line, l_col = struct.unpack_from("<QII", raw, 8)
        locations.append({
            "va": hex(loc), "lea_va": hex(lea),
            "lea_target": hex(rel32_target(lea, 7, 3)),
            "path_ptr_rela_addend": hex(r[2]) if r else None,
            "path_len": plen, "line": l_line, "col": l_col,
            "match": bool(r) and r[2] == LOCATION_PATH_VA and plen == LOCATION_PATH_LEN
            and (l_line, l_col) == (line, col) and rel32_target(lea, 7, 3) == loc,
        })
    loc_raw = read_va(data, segs, LOCATION_PATH_VA, LOCATION_PATH_LEN)
    loc_sha = hashlib.sha256(loc_raw).hexdigest()
    loc_match = (loc_sha == LOCATION_PATH_SHA256
                 and loc_raw.decode("ascii", errors="replace").endswith(LOCATION_PATH_SUFFIX))

    refs = slot_refs(data, segs)
    ref_counts = {k: sum(1 for kind, _ in refs if kind == k) for k in ("call", "jmp", "mov")}
    direct = 0
    for base, off, filesz, _m in segs:
        if base == TEXT_LOAD_VA:
            text = data[off : off + filesz]
            for i in range(len(text) - 4):
                if text[i] in (0xE8, 0xE9) and TEXT_LOAD_VA + i + 5 + struct.unpack_from("<i", text, i + 1)[0] == FN:
                    direct += 1

    want_emu = bool(run_emu)
    if want_emu and not unicorn_available():
        raise RuntimeError("Unicorn is required for explicitly requested captured emulation")
    do_emu = want_emu and unicorn_available()
    vectors_out = {}
    for name, (msg, nblocks, digest) in sorted(VECTORS.items()):
        padded = pad(msg)
        entry = {"message_hex": msg.hex(), "padded_hex": padded.hex(), "nblocks": nblocks,
                 "padded_nblocks_match": len(padded) == 64 * nblocks,
                 "expected_digest_hex": digest}
        if do_emu:
            out = emulate_compress(data, segs, padded, nblocks).hex()
            entry["emulated_digest_hex"] = out
            entry["emulated_match"] = out == digest
        elif want_emu:
            entry["emulated_skipped"] = True
        vectors_out[name] = entry

    return {
        "abi": {
            "rdi": "32-byte SHA-256 state (8 x u32 little-endian)",
            "rsi": "pointer to contiguous 64-byte blocks",
            "rdx": "nblocks (u64)",
            "side_effect": "state overwritten with post-compress words",
            "emulated_path": "plain code only (feature byte forced to 0)",
            "shani_path": "static disassembly only; not executed",
        },
        "binary_sha256": BINARY_SHA256,
        "branches": branches,
        "branches_match": branches == branches_expected,
        "caller_call_va": hex(CALLER_CALL),
        "caller_fn": hex(CALLER_FN),
        "carved_end_inclusive": hex(FN_RET),
        "carved_len": len(carved),
        "carved_sha256": hashlib.sha256(carved).hexdigest(),
        "carved_start": hex(FN),
        "direct_e8_e9_to_fn": direct,
        "emu_ran": do_emu,
        "emu_skipped": want_emu and not do_emu,
        "fde_end": hex(FN_END),
        "flag_va": hex(FLAG_VA),
        "fn": hex(FN),
        "got_rela": got_rela,
        "got_slot": hex(GOT_SLOT),
        "got_slot_refs": {"by_kind": ref_counts, "total": len(refs),
                          "vas": [kind + "@" + hex(va) for kind, va in refs]},
        "k_imm32_in_plain_body_missing": k_imm_missing,
        "shani_bswap_mask": {"insn_va": hex(SHANI_BSWAP_LOAD), "target": hex(bswap_tgt), "match": bswap_match},
        "shani_k_groups_covered": k_groups_covered,
        "shani_k_loads": shani_k,
        "key_bytes": key_bytes,
        "key_insns_count": len(key_bytes),
        "location_path_len": LOCATION_PATH_LEN,
        "location_path_match": loc_match,
        "location_path_sha256": loc_sha,
        "location_path_suffix": LOCATION_PATH_SUFFIX,
        "location_path_va": hex(LOCATION_PATH_VA),
        "locations": locations,
        "plain_body_start": hex(PLAIN_BODY),
        "shani_extent": [hex(SHANI), hex(SHANI_END)],
        "shani_sha256rnds2_count": shani_rnds2,
        "vectors": vectors_out,
    }


def expectation_errors(result):
    errs = []
    if result["carved_sha256"] != CARVED_SHA256:
        errs.append("carved_sha256 mismatch")
    if result["carved_len"] != CARVED_LEN:
        errs.append("carved_len mismatch")
    for kb in result["key_bytes"]:
        if not kb["match"]:
            errs.append("key_insn mismatch at " + kb["va"])
    if not result["branches_match"]:
        errs.append("branch target mismatch")
    if result["k_imm32_in_plain_body_missing"] != []:
        errs.append("K imm32 missing from plain body")
    if result["shani_k_groups_covered"] != list(range(16)):
        errs.append("SHA-NI K loads do not cover all 64 constants")
    if not result["shani_bswap_mask"]["match"]:
        errs.append("SHA-NI byte-swap mask mismatch")
    if result["shani_sha256rnds2_count"] != 32:
        errs.append("sha256rnds2 count != 32")
    want_rela = {"r_offset": hex(GOT_SLOT), "r_info": hex(R_X86_64_RELATIVE), "r_addend": hex(FN)}
    if result["got_rela"] != want_rela:
        errs.append("GOT RELA mismatch")
    if result["got_slot_refs"]["by_kind"] != SLOT_REFS_EXPECTED:
        errs.append("GOT slot ref counts mismatch")
    if result["direct_e8_e9_to_fn"] != 0:
        errs.append("unexpected direct e8/e9 to fn")
    if not result["location_path_match"]:
        errs.append("location path mismatch")
    for loc in result["locations"]:
        if not loc["match"]:
            errs.append("location mismatch at " + loc["va"])
    for name, (_msg, _n, digest) in VECTORS.items():
        v = result["vectors"][name]
        if v["expected_digest_hex"] != digest or not v["padded_nblocks_match"]:
            errs.append(name + " vector drift")
        if result["emu_ran"] and not v.get("emulated_match"):
            errs.append(name + " emu mismatch")
    return errs


def render(result):
    return json.dumps(result, sort_keys=True, indent=2) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--emulate", action="store_true", help="run captured code only after separate explicit authorization")
    ap.add_argument("--no-emu", action="store_true", help="skip Unicorn behavioural proof")
    ap.add_argument("-o", "--output", type=Path, help="write JSON to path")
    args = ap.parse_args(argv)
    result = analyse(TARGET.read_bytes(), run_emu=args.emulate and not args.no_emu)
    text = render(result)
    errors = expectation_errors(result)
    if args.output:
        args.output.write_text(text)
    else:
        sys.stdout.write(text)
    for e in errors:
        print("FAIL", e, file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
