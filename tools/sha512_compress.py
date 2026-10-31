#!/usr/bin/env python3
"""RE-023: SHA-512 soft compress at 0x4ec4a40 (node #94) + update/finalize wiring.

Standalone. From the pinned node #94 binary only, it recovers:
  * soft compress extent 0x4ec4a40..0x4ec857a (sha256-pinned carved bytes);
  * ABI (rdi=8x u64 LE state, rsi=blocks, rdx=nblocks; rdx=0 is a no-op);
  * CPU-feature dispatcher at 0x4ec9170 (flag 0x578687c); soft path e9-tails
    to the carved compress; AVX path at 0x4ec8590 is not claimed;
  * sha2 update at 0x4ec4900 (GOT slot 0x57708d0, RELA addend) and finalize
    at 0x4ec47d0, both e8-calling the dispatcher;
  * one real GOT consumer at 0x158f8d1 (mov rbx,[GOT]; call *rbx = update);
  * Location string at 0x1fd941 (len 90, sha256-pinned) ending in
    sha2-0.9.9/src/sha512.rs (suffix only; no cargo-registry host path stored);
  * behavioural proof: Unicorn on contiguous PT_LOAD maps for FIPS 180-4
    empty / abc / two-block padded messages against known digests.

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

FN = 0x4EC4A40
FN_END = 0x4EC857B
FN_RET = 0x4EC857A
CARVED_SHA256 = "88b5bbdb2171f51f7102d46e8411c4a7c6099e62f2bf0ee3e7339da7f54ce57c"
CARVED_LEN = 15163

DISPATCHER = 0x4EC9170
DISPATCHER_E9 = 0x4EC9183
FLAG_VA = 0x578687C
AVX_PATH = 0x4EC8590

UPDATE = 0x4EC4900
UPDATE_CALL_A = 0x4EC49B2
UPDATE_CALL_B = 0x4EC49CC
FINALIZE = 0x4EC47D0
FINALIZE_CALL = 0x4EC4809
GOT_SLOT = 0x57708D0
R_X86_64_RELATIVE = 8
CALLER_MOV = 0x158F8D1
CALLER_CALL_RBX = 0x158F8E5
CALLER_CALL_FINALIZE = 0x158F94A

LOCATION_PATH_VA = 0x1FD941
LOCATION_PATH_LEN = 90
LOCATION_PATH_SHA256 = "5e5b8e29cd580d42368242a335b46c412944e3d4d387730d5b2ec41cb082c4b1"
LOCATION_PATH_SUFFIX = "sha2-0.9.9/src/sha512.rs"

# TOKEN rule: printed as key_insns, never the banned equals-form.
KEY_INSNS = [
    (0x4EC4A40, "554157415641554154534881ecf80000", "compress push/sub rsp,0xf8"),
    (0x4EC857A, "c3", "compress ret"),
    (0x4EC9170, "0fb60505d78b00", "dispatcher movzx eax,[rip] flag"),
    (0x4EC9177, "3cff", "dispatcher cmp al,0xff"),
    (0x4EC9179, "740d", "dispatcher je init"),
    (0x4EC917B, "3c01", "dispatcher cmp al,1"),
    (0x4EC917D, "0f840df4ffff", "dispatcher je AVX 0x4ec8590"),
    (0x4EC9183, "e9b8b8ffff", "dispatcher e9 soft compress"),
    (0x4EC4900, "4157415641554154", "update push r15..r12"),
    (0x4EC49B2, "e8b9470000", "update e8 dispatcher"),
    (0x4EC49CC, "e89f470000", "update e8 dispatcher (tail)"),
    (0x4EC47D0, "4157415641554154", "finalize push r15..r12"),
    (0x4EC4809, "e862490000", "finalize e8 dispatcher"),
    (0x158F8D1, "488b1df80f1e04", "caller mov rbx,[GOT update]"),
    (0x158F8E5, "ffd3", "caller call *rbx"),
]

SHA512_IV_LE = bytes.fromhex(
    "08c9bcf367e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5"
    "d182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b"
)


def _pad(msg: bytes) -> bytes:
    bitlen = len(msg) * 8
    out = bytearray(msg)
    out.append(0x80)
    while (len(out) + 16) % 128:
        out.append(0)
    out += bitlen.to_bytes(16, "big")
    return bytes(out)


def _fips_digest(msg: bytes) -> bytes:
    return hashlib.sha512(msg).digest()


# FIPS 180-4 single-block / two-block padded messages fed to compress.
VECTORS = {
    "empty": {
        "message_hex": "",
        "padded_hex": _pad(b"").hex(),
        "nblocks": 1,
        "digest_hex": _fips_digest(b"").hex(),
        "digest_sha256": hashlib.sha256(_fips_digest(b"")).hexdigest(),
    },
    "abc": {
        "message_hex": b"abc".hex(),
        "padded_hex": _pad(b"abc").hex(),
        "nblocks": 1,
        "digest_hex": _fips_digest(b"abc").hex(),
        "digest_sha256": hashlib.sha256(_fips_digest(b"abc")).hexdigest(),
    },
    "two_block": {
        "message_hex": (
            b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"
            b"ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
        ).hex(),
        "padded_hex": _pad(
            b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"
            b"ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
        ).hex(),
        "nblocks": 2,
        "digest_hex": _fips_digest(
            b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"
            b"ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
        ).hex(),
        "digest_sha256": hashlib.sha256(
            _fips_digest(
                b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"
                b"ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
            )
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
                r_offset, r_info, r_addend = struct.unpack_from("<QQq", data, off + k * 24)
                out.append((r_offset, r_info, r_addend))
            return out
    raise KeyError(".rela.dyn")


def count_got_mov_callers(data, segs):
    """Count rip-relative `mov r64, [GOT_SLOT]` in the primary .text load."""
    text_va = text_off = text_sz = None
    for base, off, filesz, _m in segs:
        if base == 0x1343C80:
            text_va, text_off, text_sz = base, off, filesz
            break
    if text_va is None:
        raise KeyError(".text load")
    text = data[text_off : text_off + text_sz]
    n = 0
    for i in range(len(text) - 7):
        if text[i] == 0x48 and text[i + 1] == 0x8B:
            modrm = text[i + 2]
            if (modrm & 0xC7) == 0x05:
                disp = struct.unpack_from("<i", text, i + 3)[0]
                if text_va + i + 7 + disp == GOT_SLOT:
                    n += 1
    return n


def unicorn_available():
    import importlib.util

    return importlib.util.find_spec("unicorn") is not None


def emulate_compress(data, segs, padded: bytes, nblocks: int) -> bytes:
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_PROT_ALL, UcError
    from unicorn.x86_const import (
        UC_X86_REG_RDI,
        UC_X86_REG_RSI,
        UC_X86_REG_RDX,
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
    BLOCKS = SCRATCH + 0x200
    mu.mem_write(STATE, SHA512_IV_LE)
    mu.mem_write(BLOCKS, padded)

    mu.reg_write(UC_X86_REG_RSP, STACK + 0x100000 - 0x2000)
    rsp = mu.reg_read(UC_X86_REG_RSP) - 8
    mu.mem_write(rsp, struct.pack("<Q", STOP))
    mu.reg_write(UC_X86_REG_RSP, rsp)
    mu.reg_write(UC_X86_REG_RDI, STATE)
    mu.reg_write(UC_X86_REG_RSI, BLOCKS)
    mu.reg_write(UC_X86_REG_RDX, nblocks)
    mu.emu_start(FN, STOP, timeout=30_000_000, count=50_000_000)
    st = bytes(mu.mem_read(STATE, 64))
    # sha2 stores state words LE; FIPS digests are BE word bytes.
    return b"".join(struct.pack(">Q", w) for w in struct.unpack("<8Q", st))


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
    loc_suffix_ok = loc_raw.decode("ascii", errors="replace").endswith(LOCATION_PATH_SUFFIX)
    loc_match = loc_sha == LOCATION_PATH_SHA256 and loc_suffix_ok and len(loc_raw) == LOCATION_PATH_LEN

    e9 = read_va(data, segs, DISPATCHER_E9, 5)
    e9_tgt = DISPATCHER_E9 + 5 + struct.unpack_from("<i", e9, 1)[0]

    update_calls = []
    for va in (UPDATE_CALL_A, UPDATE_CALL_B, FINALIZE_CALL):
        insn = read_va(data, segs, va, 5)
        rel = struct.unpack_from("<i", insn, 1)[0]
        tgt = va + 5 + rel
        update_calls.append(
            {
                "va": hex(va),
                "bytes": insn.hex(),
                "target": hex(tgt),
                "target_match": tgt == DISPATCHER,
            }
        )

    caller_mov = read_va(data, segs, CALLER_MOV, 7)
    caller_disp = struct.unpack_from("<i", caller_mov, 3)[0]
    caller_slot = CALLER_MOV + 7 + caller_disp

    got_rela = None
    for r_offset, r_info, r_addend in find_rela_dyn(data):
        if r_offset == GOT_SLOT and (r_info & 0xFFFFFFFF) == R_X86_64_RELATIVE and r_addend == UPDATE:
            got_rela = {
                "r_offset": hex(r_offset),
                "r_info": hex(r_info),
                "r_addend": hex(r_addend),
            }
            break

    mov_count = count_got_mov_callers(data, segs)

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
            out = emulate_compress(
                data, segs, bytes.fromhex(spec["padded_hex"]), spec["nblocks"]
            )
            entry["emulated_digest_hex"] = out.hex()
            entry["emulated_digest_sha256"] = hashlib.sha256(out).hexdigest()
            entry["emulated_match"] = out.hex() == spec["digest_hex"]
        elif emu_skipped:
            entry["emulated_skipped"] = True
        vectors_out[name] = entry

    return {
        "abi": {
            "rdi": "64-byte SHA-512 state (8 x u64 little-endian)",
            "rsi": "pointer to contiguous 128-byte blocks",
            "rdx": "nblocks (u64); rdx==0 is a no-op",
            "side_effect": "state overwritten with post-compress digest words",
            "simd": "soft scalar path carved; AVX dispatcher branch not claimed",
        },
        "binary_sha256": BINARY_SHA256,
        "caller_call_rbx_va": hex(CALLER_CALL_RBX),
        "caller_got_slot": hex(caller_slot),
        "caller_got_slot_match": caller_slot == GOT_SLOT,
        "caller_mov_va": hex(CALLER_MOV),
        "carved_len": len(carved),
        "carved_sha256": carved_sha,
        "dispatcher_e9_target": hex(e9_tgt),
        "dispatcher_e9_target_match": e9_tgt == FN,
        "dispatcher_e9_va": hex(DISPATCHER_E9),
        "dispatcher_va": hex(DISPATCHER),
        "emu_ran": do_emu,
        "emu_skipped": emu_skipped,
        "finalize_va": hex(FINALIZE),
        "fn": hex(FN),
        "fn_end": hex(FN_END),
        "fn_ret": hex(FN_RET),
        "got_mov_caller_count": mov_count,
        "got_rela": got_rela,
        "got_slot": hex(GOT_SLOT),
        "key_bytes": key_bytes,
        "key_insns_count": len(key_bytes),
        "location_path_len": LOCATION_PATH_LEN,
        "location_path_match": loc_match,
        "location_path_sha256": loc_sha,
        "location_path_suffix": LOCATION_PATH_SUFFIX,
        "location_path_va": hex(LOCATION_PATH_VA),
        "update_calls": update_calls,
        "update_va": hex(UPDATE),
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
    if not result["dispatcher_e9_target_match"]:
        errs.append("dispatcher e9 target mismatch")
    if not result["location_path_match"]:
        errs.append("location path mismatch")
    if result["got_rela"] is None:
        errs.append("missing GOT RELA for update")
    if result["got_mov_caller_count"] != 1:
        errs.append("got_mov_caller_count != 1")
    if not result["caller_got_slot_match"]:
        errs.append("caller GOT slot mismatch")
    for uc in result["update_calls"]:
        if not uc["target_match"]:
            errs.append("update/finalize call target mismatch at " + uc["va"])
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
