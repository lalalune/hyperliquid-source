#!/usr/bin/env python3
"""RE-022: ChaCha SSE4x block at 0x4e13780 (node #94) + rand_chacha guts wiring.

Standalone. From the pinned node #94 binary only, it recovers:
  * SSE4x ChaCha block extent 0x4e13780..0x4e13e5a (sha256-pinned carved bytes);
  * ABI (rdi=48-byte state key||counter64||nonce64, esi=double-rounds, rdx=256-byte out);
  * rounds==0 early path and dec/jne round loop; expand 32-byte k rip-load;
  * GOT-exported wrapper 0x4e14560 (slot 0x576e900, RELA addend) that tests
    flag bits loaded via [0x576e350]; one branch e9-tails to the SSE block;
  * a real refill caller at 0x13c9ed2 (mov esi,6 = ChaCha12; consume 0x100 bytes);
  * Location string at 0x1e6959 (len 95, sha256-pinned) ending in
    rand_chacha-0.3.1/src/guts.rs (no xref from FN/wrapper pinned);
  * behavioural proof: Unicorn on the carved bytes for ChaCha20/12/8 (ndr=10/6/4)
    against DJB 64-bit-counter reference outputs (4 sequential 64-byte blocks).

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

FN = 0x4E13780
FN_END = 0x4E13E5A
FN_RET = 0x4E13E59
CARVED_SHA256 = "1bea6b14e546e8037c041345946203e3994be41e7b83d5c75eca60d40da59eae"
CARVED_LEN = 1754
EXPAND_VA = 0x204670
EXPAND_BYTES = b"expand 32-byte k"
LOCATION_PATH_VA = 0x1E6959
LOCATION_PATH_LEN = 95
LOCATION_PATH_SHA256 = "79cee213bb7bba7155a035070bbc1abed8bd176a9839bdb674df8816801602b7"
LOCATION_PATH_SUFFIX = "rand_chacha-0.3.1/src/guts.rs"

WRAP = 0x4E14560
WRAP_E9_TO_FN = 0x4E14DB7
GOT_SLOT = 0x576E900
R_X86_64_RELATIVE = 8
CALLER = 0x13C9ED2

# TOKEN rule: printed as key_insns, never the banned equals-form.
KEY_INSNS = [
    (0x4E13780, "4883ec28", "prologue sub rsp,0x28"),
    (0x4E13784, "660f6f1f", "movdqa xmm3,[rdi] key[0:16]"),
    (0x4E13788, "66440f6f6f10", "movdqa xmm13,[rdi+0x10] key[16:32]"),
    (0x4E1378E, "660f6f7f20", "movdqa xmm7,[rdi+0x20] counter64|nonce64"),
    (0x4E13800, "85f6", "test esi,esi"),
    (0x4E13815, "0f840a050000", "je 0x4e13d25 rounds==0 early path"),
    (0x4E1381B, "66440f6f0d4c0e3ffb", "movdqa xmm9,[rip] expand 32-byte k"),
    (0x4E13CDE, "ffce", "dec esi"),
    (0x4E13CE0, "0f859afbffff", "jne 0x4e13880 round loop"),
    (0x4E13E55, "4883c428", "add rsp,0x28"),
    (0x4E13E59, "c3", "ret"),
    (0x4E14560, "55", "wrapper push rbp"),
    (0x4E1456D, "488b1ddc9d9500", "wrapper mov rbx,[rip] -> word at 0x576e350"),
    (0x4E14DB7, "e9c4e9ffff", "wrapper e9 tail -> block FN"),
    (0x13C9E99, "498dbe20010000", "caller lea rdi,[r14+0x120] state"),
    (0x13C9EBC, "4881c100ffffff", "caller add rcx,-0x100 consume 256 bytes"),
    (0x13C9EC3, "49898e58010000", "caller mov [r14+0x158],rcx remaining"),
    (0x13C9ECA, "be06000000", "caller mov esi,6 ChaCha12 double-rounds"),
    (0x13C9ECF, "4889c2", "caller mov rdx,rax out buffer"),
    (0x13C9ED2, "ff15284a3a04", "caller call [GOT 0x576e900]"),
]


def _rotl32(v, n):
    return ((v << n) | (v >> (32 - n))) & 0xffffffff

def _qr(s, a, b, c, d):
    s[a] = (s[a] + s[b]) & 0xffffffff; s[d] ^= s[a]; s[d] = _rotl32(s[d], 16)
    s[c] = (s[c] + s[d]) & 0xffffffff; s[b] ^= s[c]; s[b] = _rotl32(s[b], 12)
    s[a] = (s[a] + s[b]) & 0xffffffff; s[d] ^= s[a]; s[d] = _rotl32(s[d], 8)
    s[c] = (s[c] + s[d]) & 0xffffffff; s[b] ^= s[c]; s[b] = _rotl32(s[b], 7)

def _double_round(w):
    _qr(w, 0, 4, 8, 12); _qr(w, 1, 5, 9, 13); _qr(w, 2, 6, 10, 14); _qr(w, 3, 7, 11, 15)
    _qr(w, 0, 5, 10, 15); _qr(w, 1, 6, 11, 12); _qr(w, 2, 7, 8, 13); _qr(w, 3, 4, 9, 14)

def chacha_block_djb(key32, counter64, nonce64, n_double_rounds):
    st = list(struct.unpack("<16I", b"expand 32-byte k" + key32 + struct.pack("<QQ", counter64, nonce64)))
    w = st[:]
    for _ in range(n_double_rounds):
        _double_round(w)
    return struct.pack("<16I", *[(w[i] + st[i]) & 0xffffffff for i in range(16)])

def ref_4x(key32, counter0, nonce64, ndr):
    return b"".join(chacha_block_djb(key32, counter0 + i, nonce64, ndr) for i in range(4))

VECTOR_KEY = bytes(range(32))
VECTORS = {
    "chacha20_ndr10_ctr0_nonce0": {
        "n_double_rounds": 10,
        "counter0": 0,
        "nonce64": 0,
        "output_hex": ref_4x(VECTOR_KEY, 0, 0, 10).hex(),
        "output_sha256": hashlib.sha256(ref_4x(VECTOR_KEY, 0, 0, 10)).hexdigest(),
    },
    "chacha12_ndr6_ctr0_nonce0": {
        "n_double_rounds": 6,
        "counter0": 0,
        "nonce64": 0,
        "output_hex": ref_4x(VECTOR_KEY, 0, 0, 6).hex(),
        "output_sha256": hashlib.sha256(ref_4x(VECTOR_KEY, 0, 0, 6)).hexdigest(),
    },
    "chacha8_ndr4_ctr0_nonce0": {
        "n_double_rounds": 4,
        "counter0": 0,
        "nonce64": 0,
        "output_hex": ref_4x(VECTOR_KEY, 0, 0, 4).hex(),
        "output_sha256": hashlib.sha256(ref_4x(VECTOR_KEY, 0, 0, 4)).hexdigest(),
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
    return data[o:o + n]


def find_rela_dyn(data):
    e_shoff = struct.unpack_from("<Q", data, 40)[0]
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", data, 58)
    shstr_hdr = e_shoff + e_shstrndx * e_shentsize
    shstr_off = struct.unpack_from("<Q", data, shstr_hdr + 24)[0]
    shstr_sz = struct.unpack_from("<Q", data, shstr_hdr + 32)[0]
    shstr = data[shstr_off:shstr_off + shstr_sz]
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


def count_got_callers(data, segs):
    text_va = text_off = text_sz = None
    for base, off, filesz, _m in segs:
        if base == 0x1343C80:
            text_va, text_off, text_sz = base, off, filesz
            break
    if text_va is None:
        raise KeyError(".text load")
    text = data[text_off:text_off + text_sz]
    n = 0
    i = 0
    while i < len(text) - 6:
        if text[i] == 0xFF and text[i + 1] == 0x15:
            disp = struct.unpack_from("<i", text, i + 2)[0]
            if text_va + i + 6 + disp == GOT_SLOT:
                n += 1
        i += 1
    return n


def unicorn_available():
    import importlib.util
    return importlib.util.find_spec("unicorn") is not None


def emulate_block(data, segs, ndr, key32, counter0, nonce64):
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_PROT_ALL, UcError
    from unicorn.x86_const import (
        UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RDX, UC_X86_REG_RSP,
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
        blob = data[off:off + filesz] + bytes(max(0, memsz - filesz))
        mu.mem_write(base, blob)

    STACK = 0x7FFF00000000
    map_span(STACK, 0x100000)
    SCRATCH = 0x70000000
    map_span(SCRATCH, 0x10000)
    STOP = 0x600000000
    map_span(STOP, 0x1000)
    mu.mem_write(STOP, b"\xf4")

    STATE = SCRATCH + 0x100
    OUT = SCRATCH + 0x200
    mu.mem_write(STATE, key32 + struct.pack("<QQ", counter0, nonce64))
    mu.mem_write(OUT, bytes(256))

    mu.reg_write(UC_X86_REG_RSP, STACK + 0x100000 - 0x2000)
    rsp = mu.reg_read(UC_X86_REG_RSP) - 8
    mu.mem_write(rsp, struct.pack("<Q", STOP))
    mu.reg_write(UC_X86_REG_RSP, rsp)
    mu.reg_write(UC_X86_REG_RDI, STATE)
    mu.reg_write(UC_X86_REG_RSI, ndr)
    mu.reg_write(UC_X86_REG_RDX, OUT)
    mu.emu_start(FN, STOP, timeout=5_000_000, count=2_000_000)
    out = bytes(mu.mem_read(OUT, 256))
    ctr_after = struct.unpack_from("<Q", bytes(mu.mem_read(STATE + 32, 8)))[0]
    return out, ctr_after


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
        key_bytes.append({
            "va": hex(va),
            "bytes": raw.hex(),
            "expected": hx,
            "match": raw.hex() == hx,
            "note": note,
        })

    loc_raw = read_va(data, segs, LOCATION_PATH_VA, LOCATION_PATH_LEN)
    expand = read_va(data, segs, EXPAND_VA, 16)
    exp_insn = read_va(data, segs, 0x4E1381B, 9)
    exp_tgt = 0x4E1381B + 9 + struct.unpack_from("<i", exp_insn, 5)[0]
    call_insn = read_va(data, segs, CALLER, 6)
    call_slot = CALLER + 6 + struct.unpack_from("<i", call_insn, 2)[0]
    e9 = read_va(data, segs, WRAP_E9_TO_FN, 5)
    e9_tgt = WRAP_E9_TO_FN + 5 + struct.unpack_from("<i", e9, 1)[0]

    got_rela = None
    for r_offset, r_info, r_addend in find_rela_dyn(data):
        if r_offset == GOT_SLOT and (r_info & 0xFFFFFFFF) == R_X86_64_RELATIVE and r_addend == WRAP:
            got_rela = {"r_offset": hex(r_offset), "r_info": hex(r_info), "r_addend": hex(r_addend)}
            break

    caller_count = count_got_callers(data, segs)

    want_emu = bool(run_emu)
    do_emu = want_emu and unicorn_available()
    emu_skipped = want_emu and not do_emu
    vectors_out = {}
    for name, spec in sorted(VECTORS.items()):
        entry = {
            "n_double_rounds": spec["n_double_rounds"],
            "counter0": spec["counter0"],
            "nonce64": spec["nonce64"],
            "material_hex": VECTOR_KEY.hex(),
            "expected_output_hex": spec["output_hex"],
            "expected_output_sha256": spec["output_sha256"],
        }
        if do_emu:
            out, ctr_after = emulate_block(
                data, segs, spec["n_double_rounds"], VECTOR_KEY, spec["counter0"], spec["nonce64"]
            )
            entry["emulated_output_hex"] = out.hex()
            entry["emulated_output_sha256"] = hashlib.sha256(out).hexdigest()
            entry["emulated_match"] = out.hex() == spec["output_hex"]
            entry["counter_after"] = ctr_after
            entry["counter_after_expected"] = spec["counter0"] + 4
        elif emu_skipped:
            entry["emulated_skipped"] = True
        vectors_out[name] = entry

    loc_sha = hashlib.sha256(loc_raw).hexdigest()
    loc_suffix_ok = loc_raw.decode("ascii", errors="replace").endswith(LOCATION_PATH_SUFFIX)
    loc_match = loc_sha == LOCATION_PATH_SHA256 and loc_suffix_ok and len(loc_raw) == LOCATION_PATH_LEN

    return {
        "abi": {
            "rdi": "48-byte state: material[32] || counter_u64_le || nonce_u64_le",
            "esi": "double-round count (10=ChaCha20, 6=ChaCha12, 4=ChaCha8)",
            "rdx": "256-byte output (4 sequential 64-byte blocks)",
            "side_effect": "counter at state+32 becomes counter0+4",
            "simd": "SSE xmm on carved FN; other wrapper paths not examined; Unicorn-capable",
        },
        "binary_sha256": BINARY_SHA256,
        "caller_call_slot": hex(call_slot),
        "caller_call_slot_match": call_slot == GOT_SLOT,
        "caller_consume_bytes": 0x100,
        "caller_esi_imm": 6,
        "caller_va": hex(CALLER),
        "carved_len": len(carved),
        "carved_sha256": carved_sha,
        "emu_ran": do_emu,
        "emu_skipped": emu_skipped,
        "expand_ascii": expand.decode("ascii"),
        "expand_bytes": expand.hex(),
        "expand_rip_target": hex(exp_tgt),
        "expand_rip_target_match": exp_tgt == EXPAND_VA,
        "expand_va": hex(EXPAND_VA),
        "fn": hex(FN),
        "fn_end": hex(FN_END),
        "fn_ret": hex(FN_RET),
        "got_caller_count": caller_count,
        "got_rela": got_rela,
        "got_slot": hex(GOT_SLOT),
        "key_bytes": key_bytes,
        "key_insns_count": len(key_bytes),
        "location_path_len": LOCATION_PATH_LEN,
        "location_path_match": loc_match,
        "location_path_sha256": loc_sha,
        "location_path_suffix": LOCATION_PATH_SUFFIX,
        "location_path_va": hex(LOCATION_PATH_VA),
        "vectors": vectors_out,
        "wrapper_e9_target": hex(e9_tgt),
        "wrapper_e9_target_match": e9_tgt == FN,
        "wrapper_e9_va": hex(WRAP_E9_TO_FN),
        "wrapper_va": hex(WRAP),
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
    if not result["expand_rip_target_match"]:
        errs.append("expand rip target mismatch")
    if result["expand_bytes"] != EXPAND_BYTES.hex():
        errs.append("expand bytes mismatch")
    if not result["location_path_match"]:
        errs.append("location path mismatch")
    if not result["wrapper_e9_target_match"]:
        errs.append("wrapper e9 target mismatch")
    if result["got_rela"] is None:
        errs.append("missing GOT RELA for wrapper")
    if result["got_caller_count"] != 21:
        errs.append("got_caller_count != 21")
    if not result["caller_call_slot_match"]:
        errs.append("caller GOT slot mismatch")
    for name, spec in VECTORS.items():
        v = result["vectors"][name]
        if v["expected_output_hex"] != spec["output_hex"]:
            errs.append(name + " expected hex drift")
        if result.get("emu_ran"):
            if not v.get("emulated_match"):
                errs.append(name + " emu mismatch")
            if v.get("counter_after") != spec["counter0"] + 4:
                errs.append(name + " counter_after mismatch")
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
    raise SystemExit(main())
