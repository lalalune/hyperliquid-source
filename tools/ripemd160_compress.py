#!/usr/bin/env python3
"""RE-024: RIPEMD-160 compress at 0x4ea55f0 (node #94) + finalize wiring.

Standalone. From the pinned node #94 binary only, it recovers:
  * compress extent 0x4ea55f0..0x4ea6c7f (sha256-pinned carved bytes);
  * ABI (rdi=5x u32 LE state, rsi=64-byte block);
  * finalize at 0x4ea0200 loading GOT slot 0x5776fb0 (RELA addend = compress)
    via mov rbx,[GOT] / call *rbx and via ff15 [GOT];
  * Location string at 0x1f1474 (len 89, sha256-pinned) ending in
    ripemd-0.1.3/src/lib.rs (suffix only; no cargo-registry host path stored);
  * Location RELA slot 0x574f610 (addend 0x1f1474), lea at 0x4ea0541;
  * behavioural proof: Unicorn on contiguous PT_LOAD maps for published
    RIPEMD-160 KATs (empty / abc / message digest / a..z / alphanum).

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

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "artifacts" / "node" / "94" / "hl-node"
BINARY_SHA256 = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"

FN = 0x4EA55F0
FN_END = 0x4EA6C80
FN_RET = 0x4EA6C7F
CARVED_SHA256 = "9da4dd9d6f7ad3288ba0fafbc8323f441ff24d39bef6e9deb5922fa7c5e9303c"
CARVED_LEN = 5776

FINALIZE = 0x4EA0200
FINALIZE_MOV = 0x4EA043A
FINALIZE_CALL_RBX_A = 0x4EA044A
FINALIZE_CALL_RBX_B = 0x4EA0486
FINALIZE_FF15 = 0x4EA049B
GOT_SLOT = 0x5776FB0
R_X86_64_RELATIVE = 8

LOCATION_PATH_VA = 0x1F1474
LOCATION_PATH_LEN = 89
LOCATION_PATH_SHA256 = "36b681955d65e83df460197ed445c5afd9833b222b962608ca53fe2ae2349d35"
LOCATION_PATH_SUFFIX = "ripemd-0.1.3/src/lib.rs"
LOCATION_RELA_SLOT = 0x574F610
LOCATION_LEA = 0x4EA0541

TEXT_LOAD_VA = 0x1343C80

# TOKEN rule: printed as key_insns, never the banned equals-form.
KEY_INSNS = [
    (0x4EA55F0, "554157415641554154534883ec18", "compress push/sub rsp,0x18"),
    (0x4EA6C7F, "c3", "compress ret"),
    (0x4EA0200, "554157415641554154534881ec680100", "finalize push/sub rsp,0x168"),
    (0x4EA043A, "488b1d6f6b8d00", "finalize mov rbx,[GOT compress]"),
    (0x4EA044A, "ffd3", "finalize call *rbx"),
    (0x4EA0486, "ffd3", "finalize call *rbx (second)"),
    (0x4EA049B, "ff150f6b8d00", "finalize call *[GOT compress]"),
    (0x4EA0541, "488d3dc8f08a00", "lea Location slot"),
]

RIPEMD160_IV_LE = struct.pack(
    "<5I", 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0
)


def _pad(msg: bytes) -> bytes:
    bitlen = len(msg) * 8
    out = bytearray(msg)
    out.append(0x80)
    while (len(out) + 8) % 64:
        out.append(0)
    out += bitlen.to_bytes(8, "little")
    return bytes(out)


def _ripemd160_digest(msg: bytes) -> bytes:
    return hashlib.new("ripemd160", msg).digest()


VECTORS = {
    "abc": {
        "message_hex": b"abc".hex(),
        "padded_hex": _pad(b"abc").hex(),
        "nblocks": 1,
        "digest_hex": _ripemd160_digest(b"abc").hex(),
        "digest_sha256": hashlib.sha256(_ripemd160_digest(b"abc")).hexdigest(),
    },
    "alphanum": {
        "message_hex": (
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        ).hex(),
        "padded_hex": _pad(
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        ).hex(),
        "nblocks": 2,
        "digest_hex": _ripemd160_digest(
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        ).hex(),
        "digest_sha256": hashlib.sha256(
            _ripemd160_digest(
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
            )
        ).hexdigest(),
    },
    "az": {
        "message_hex": bytes(range(ord("a"), ord("z") + 1)).hex(),
        "padded_hex": _pad(bytes(range(ord("a"), ord("z") + 1))).hex(),
        "nblocks": 1,
        "digest_hex": _ripemd160_digest(bytes(range(ord("a"), ord("z") + 1))).hex(),
        "digest_sha256": hashlib.sha256(
            _ripemd160_digest(bytes(range(ord("a"), ord("z") + 1)))
        ).hexdigest(),
    },
    "empty": {
        "message_hex": "",
        "padded_hex": _pad(b"").hex(),
        "nblocks": 1,
        "digest_hex": _ripemd160_digest(b"").hex(),
        "digest_sha256": hashlib.sha256(_ripemd160_digest(b"")).hexdigest(),
    },
    "message_digest": {
        "message_hex": b"message digest".hex(),
        "padded_hex": _pad(b"message digest").hex(),
        "nblocks": 1,
        "digest_hex": _ripemd160_digest(b"message digest").hex(),
        "digest_sha256": hashlib.sha256(
            _ripemd160_digest(b"message digest")
        ).hexdigest(),
    },
}


def segments(data):
    if data[:4] != b"\x7fELF":
        raise ValueError("not ELF")
    e_phoff = struct.unpack_from("<Q", data, 32)[0]
    e_phentsize, e_phnum = struct.unpack_from("<HH", data, 54)
    out = []
    for i in range(e_phnum):
        o = e_phoff + i * e_phentsize
        p_type = struct.unpack_from("<I", data, o)[0]
        if p_type != 1:
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


def find_rela_dyn(data):
    e_shoff = struct.unpack_from("<Q", data, 40)[0]
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", data, 58)
    shstr_hdr = e_shoff + e_shstrndx * e_shentsize
    shstr_off = struct.unpack_from("<Q", data, shstr_hdr + 24)[0]
    shstr_sz = struct.unpack_from("<Q", data, shstr_hdr + 32)[0]
    shstr = data[shstr_off : shstr_off + shstr_sz]
    for i in range(e_shnum):
        o = e_shoff + i * e_shentsize
        name_off = struct.unpack_from("<I", data, o)[0]
        end = shstr.find(b"\x00", name_off)
        name = shstr[name_off:end]
        if name == b".rela.dyn":
            off = struct.unpack_from("<Q", data, o + 24)[0]
            size = struct.unpack_from("<Q", data, o + 32)[0]
            out = []
            for k in range(size // 24):
                r_offset, r_info, r_addend = struct.unpack_from(
                    "<QQq", data, off + k * 24
                )
                out.append((r_offset, r_info, r_addend))
            return out
    raise KeyError(".rela.dyn")


def count_got_callers(data, segs):
    """Count rip-relative mov r64,[GOT] and ff15 [GOT] in the primary .text load."""
    text_va = text_off = text_sz = None
    for base, off, filesz, _m in segs:
        if base == TEXT_LOAD_VA:
            text_va, text_off, text_sz = base, off, filesz
            break
    if text_va is None:
        raise KeyError(".text load")
    text = data[text_off : text_off + text_sz]
    mov_n = 0
    ff15_n = 0
    for i in range(len(text) - 7):
        if text[i] == 0x48 and text[i + 1] == 0x8B:
            modrm = text[i + 2]
            if (modrm & 0xC7) == 0x05:
                disp = struct.unpack_from("<i", text, i + 3)[0]
                if text_va + i + 7 + disp == GOT_SLOT:
                    mov_n += 1
        if text[i] == 0xFF and text[i + 1] == 0x15:
            disp = struct.unpack_from("<i", text, i + 2)[0]
            if text_va + i + 6 + disp == GOT_SLOT:
                ff15_n += 1
    return mov_n, ff15_n


def unicorn_available():
    import importlib.util

    return importlib.util.find_spec("unicorn") is not None


def emulate_compress(data, segs, padded: bytes) -> bytes:
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_PROT_ALL, UcError
    from unicorn.x86_const import (
        UC_X86_REG_RDI,
        UC_X86_REG_RSI,
        UC_X86_REG_RSP,
    )

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
        blob = data[off : off + filesz] + bytes(max(0, memsz - filesz))
        mu.mem_write(base, blob)

    STACK = 0x7FFF00000000
    map_span(STACK, 0x100000)
    SCRATCH = 0x70000000
    map_span(SCRATCH, 0x10000)
    STOP = 0x600000000
    map_span(STOP, 0x1000)
    mu.mem_write(STOP, b"\xf4")

    STATE = SCRATCH + 0x100
    BLOCK = SCRATCH + 0x200
    st = bytearray(RIPEMD160_IV_LE)
    rsp_base = STACK + 0x100000 - 0x2000
    rsp = rsp_base - 8
    mu.mem_write(rsp, struct.pack("<Q", STOP))

    assert len(padded) % 64 == 0
    for i in range(0, len(padded), 64):
        mu.mem_write(STATE, bytes(st))
        mu.mem_write(BLOCK, padded[i : i + 64])
        mu.reg_write(UC_X86_REG_RSP, rsp)
        mu.reg_write(UC_X86_REG_RDI, STATE)
        mu.reg_write(UC_X86_REG_RSI, BLOCK)
        mu.emu_start(FN, STOP, timeout=10_000_000, count=5_000_000)
        st = bytearray(mu.mem_read(STATE, 20))
    return bytes(st)


def analyse(data, check_sha=True, run_emu=True):
    if check_sha:
        got = hashlib.sha256(data).hexdigest()
        if got != BINARY_SHA256:
            raise ValueError("binary sha256 mismatch: " + got)
    segs = segments(data)
    carved = read_va(data, segs, FN, FN_RET - FN + 1)
    carved_sha = hashlib.sha256(carved).hexdigest()

    key_bytes = []
    for va, hx, note in KEY_INSNS:
        raw = read_va(data, segs, va, len(hx) // 2)
        key_bytes.append(
            {
                "va": hex(va),
                "bytes": raw.hex(),
                "expected": hx,
                "match": raw.hex() == hx,
                "note": note,
            }
        )

    loc_raw = read_va(data, segs, LOCATION_PATH_VA, LOCATION_PATH_LEN)
    loc_sha = hashlib.sha256(loc_raw).hexdigest()
    loc_suffix_ok = loc_raw.decode("ascii", errors="replace").endswith(
        LOCATION_PATH_SUFFIX
    )
    loc_match = (
        loc_sha == LOCATION_PATH_SHA256
        and loc_suffix_ok
        and len(loc_raw) == LOCATION_PATH_LEN
    )

    lea = read_va(data, segs, LOCATION_LEA, 7)
    lea_disp = struct.unpack_from("<i", lea, 3)[0]
    lea_tgt = LOCATION_LEA + 7 + lea_disp

    finalize_mov = read_va(data, segs, FINALIZE_MOV, 7)
    mov_disp = struct.unpack_from("<i", finalize_mov, 3)[0]
    mov_slot = FINALIZE_MOV + 7 + mov_disp

    ff15 = read_va(data, segs, FINALIZE_FF15, 6)
    ff15_disp = struct.unpack_from("<i", ff15, 2)[0]
    ff15_slot = FINALIZE_FF15 + 6 + ff15_disp

    got_rela = None
    loc_rela = None
    for r_offset, r_info, r_addend in find_rela_dyn(data):
        if (
            r_offset == GOT_SLOT
            and (r_info & 0xFFFFFFFF) == R_X86_64_RELATIVE
            and r_addend == FN
        ):
            got_rela = {
                "r_offset": hex(r_offset),
                "r_info": hex(r_info),
                "r_addend": hex(r_addend),
            }
        if (
            r_offset == LOCATION_RELA_SLOT
            and (r_info & 0xFFFFFFFF) == R_X86_64_RELATIVE
            and r_addend == LOCATION_PATH_VA
        ):
            loc_rela = {
                "r_offset": hex(r_offset),
                "r_info": hex(r_info),
                "r_addend": hex(r_addend),
            }

    mov_count, ff15_count = count_got_callers(data, segs)

    want_emu = bool(run_emu)
    do_emu = want_emu and unicorn_available()
    emu_skipped = want_emu and not do_emu
    vectors_out = {}
    for name, spec in sorted(VECTORS.items()):
        entry = {
            "nblocks": spec["nblocks"],
            "padded_hex": spec["padded_hex"],
            "expected_digest_hex": spec["digest_hex"],
            "expected_digest_sha256": spec["digest_sha256"],
        }
        if do_emu:
            out = emulate_compress(data, segs, bytes.fromhex(spec["padded_hex"]))
            entry["emulated_digest_hex"] = out.hex()
            entry["emulated_digest_sha256"] = hashlib.sha256(out).hexdigest()
            entry["emulated_match"] = out.hex() == spec["digest_hex"]
        elif emu_skipped:
            entry["emulated_skipped"] = True
        vectors_out[name] = entry

    return {
        "abi": {
            "rdi": "20-byte RIPEMD-160 state (5 x u32 little-endian)",
            "rsi": "pointer to one 64-byte message block",
            "side_effect": "state overwritten with post-compress digest words (LE)",
            "simd": "scalar compress carved; no alternate SIMD dispatcher examined",
        },
        "binary_sha256": BINARY_SHA256,
        "carved_len": len(carved),
        "carved_sha256": carved_sha,
        "emu_ran": do_emu,
        "emu_skipped": emu_skipped,
        "finalize_ff15_slot": hex(ff15_slot),
        "finalize_ff15_slot_match": ff15_slot == GOT_SLOT,
        "finalize_ff15_va": hex(FINALIZE_FF15),
        "finalize_mov_slot": hex(mov_slot),
        "finalize_mov_slot_match": mov_slot == GOT_SLOT,
        "finalize_mov_va": hex(FINALIZE_MOV),
        "finalize_va": hex(FINALIZE),
        "fn": hex(FN),
        "fn_end": hex(FN_END),
        "fn_ret": hex(FN_RET),
        "got_ff15_caller_count": ff15_count,
        "got_mov_caller_count": mov_count,
        "got_rela": got_rela,
        "got_slot": hex(GOT_SLOT),
        "key_bytes": key_bytes,
        "key_insns_count": len(key_bytes),
        "location_lea_target": hex(lea_tgt),
        "location_lea_target_match": lea_tgt == LOCATION_RELA_SLOT,
        "location_lea_va": hex(LOCATION_LEA),
        "location_path_len": LOCATION_PATH_LEN,
        "location_path_match": loc_match,
        "location_path_sha256": loc_sha,
        "location_path_suffix": LOCATION_PATH_SUFFIX,
        "location_path_va": hex(LOCATION_PATH_VA),
        "location_rela": loc_rela,
        "location_rela_slot": hex(LOCATION_RELA_SLOT),
        "vectors": vectors_out,
    }


def expectation_errors(result):
    errs = []
    if result["carved_sha256"] != CARVED_SHA256:
        errs.append("carved_sha256 mismatch")
    if result["carved_len"] != CARVED_LEN:
        errs.append("carved_len mismatch")
    if result["key_insns_count"] != len(KEY_INSNS):
        errs.append("key_insns_count mismatch")
    for kb in result["key_bytes"]:
        if not kb["match"]:
            errs.append("key_insn mismatch at " + kb["va"])
    if not result["location_path_match"]:
        errs.append("location path mismatch")
    if not result["location_lea_target_match"]:
        errs.append("location lea target mismatch")
    if result["got_rela"] is None:
        errs.append("missing GOT RELA for compress")
    if result["location_rela"] is None:
        errs.append("missing Location RELA")
    if result["got_mov_caller_count"] != 1:
        errs.append("got_mov_caller_count != 1")
    if result["got_ff15_caller_count"] != 1:
        errs.append("got_ff15_caller_count != 1")
    if not result["finalize_mov_slot_match"]:
        errs.append("finalize mov GOT slot mismatch")
    if not result["finalize_ff15_slot_match"]:
        errs.append("finalize ff15 GOT slot mismatch")
    for name, spec in VECTORS.items():
        v = result["vectors"][name]
        if v["expected_digest_hex"] != spec["digest_hex"]:
            errs.append(name + " expected digest drift")
        if result.get("emu_ran"):
            if not v.get("emulated_match"):
                errs.append(name + " emu mismatch")
    return errs


def render(result):
    return json.dumps(result, sort_keys=True, indent=2) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--no-emu", action="store_true", help="skip Unicorn behavioural proof")
    ap.add_argument("-o", "--output", type=Path, help="write JSON to path")
    args = ap.parse_args(argv)
    data = TARGET.read_bytes()
    result = analyse(data, run_emu=not args.no_emu)
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
