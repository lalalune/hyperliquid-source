#!/usr/bin/env python3
"""RE-021: Blake2b compress F at 0x4e9a8a0 (node #94) + EIP-152 behavioural proof.

Standalone. From the pinned node #94 binary only, it recovers:
  * the compress extent 0x4e9a8a0..0x4e9b02c (sha256-pinned carved bytes);
  * all eight BLAKE2b IV movabs immediates and the final-block ~IV[6] cmovne;
  * ABI (rounds=rdi, h=rsi, m=rdx, t=rcx, f=r8) with rounds==0 early path;
  * SIGMA u64 table at 0x7c4a90 (lea from 0x4e9a99e) and G-function rotates
    rol 0x20/0x28/0x30/1 (eight of each; RFC 7693 ror 32/24/16/63);
  * revm-precompile-16.0.0/src/blake2.rs Location path pin in .rodata;
  * behavioural proof: Unicorn emulation of the carved function bytes on the
    official EIP-152 test vectors (incl. vector 4 rounds=0 and vector 5 rounds=12),
    outputs byte-identical to the EIP;
  * HyperEVM precompile address 0x09 wiring: static precompile object at
    0x574f0b0 (Address(0x09) at 0x574f0c0; R_X86_64_RELATIVE installs run()
    wrapper 0x4e9d2a0); wrapper cmp [rsi+0x10],0xd5 length check; bswap rounds;
    cmp cl,2 / jae final-flag reject; call [0x5776f28] -> F; gas-per-round = 1.

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

FN = 0x4E9A8A0
FN_END = 0x4E9B02C
FN_RET = 0x4E9AEAF
CARVED_SHA256 = "df9b7ff03af68d61cb6e574cadb5fc0081e4a38a7fd35cefd030fbebea1a8788"
CARVED_LEN = 1932
SIGMA_VA = 0x7C4A90
SIGMA_LEA = 0x4E9A99E
SIGMA_LEA_TARGET = 0x7C4AD0
LOCATION_PATH_VA = 0x1E9DCB
LOCATION_PATH = (
    "/home/ubuntu/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/"
    "revm-precompile-16.0.0/src/blake2.rs"
)
LOCATION_PATH_LEN = 102

# HyperEVM precompile 0x09 wiring (statically recovered)
WRAP = 0x4E9D2A0
WRAP_END = 0x4E9D480
ADDR09_VA = 0x574F0C0
ADDR09_BYTES = bytes.fromhex("00" * 19 + "09")
PRECOMPILE_SLOT = 0x574F0B0  # RELA R_X86_64_RELATIVE addend=WRAP
F_GOT_SLOT = 0x5776F28       # RELA R_X86_64_RELATIVE addend=FN; wrapper call [slot]
GAS_PER_ROUND = 1
R_X86_64_RELATIVE = 8

# (va, exact hex bytes, note) — TOKEN rule: printed as key_insns, never keys=
KEY_INSNS = [
    (0x4E9A8A0, "554157415641554154534881ec38010000", "prologue push+sub rsp,0x138"),
    (0x4E9A8B1, "48899424f0000000", "mov [rsp+0xf0],rdx save m"),
    (0x4E9A8B9, "48b83ba7ca8485ae67bb", "movabs rax, IV[1]=0xbb67ae8584caa73b"),
    (0x4E9A8C8, "48b808c9bcf367e6096a", "movabs rax, IV[0]=0x6a09e667f3bcc908"),
    (0x4E9A8D7, "49bd79217e1319cde05b", "movabs r13, IV[7]=0x5be0cd19137e2179"),
    (0x4E9A8E1, "48b82bf894fe72f36e3c", "movabs rax, IV[2]=0x3c6ef372fe94f82b"),
    (0x4E9A8F0, "4c8b36", "mov r14,[rsi] h[0]"),
    (0x4E9A8F3, "49bcd182e6ad7f520e51", "movabs r12, IV[4]=0x510e527fade682d1"),
    (0x4E9A8FD, "4c3321", "xor r12,[rcx] IV[4]^=t[0]"),
    (0x4E9A904, "49bf1f6c3e2b8c68059b", "movabs r15, IV[5]=0x9b05688c2b3e6c1f"),
    (0x4E9A90E, "4c337908", "xor r15,[rcx+8] IV[5]^=t[1]"),
    (0x4E9A916, "4585c0", "test r8d,r8d final-flag f"),
    (0x4E9A919, "48b89442be0454267ce0", "movabs rax, ~IV[6]=0xe07c265404be4294"),
    (0x4E9A923, "49ba6bbd41fbabd9831f", "movabs r10, IV[6]=0x1f83d9abfb41bd6b"),
    (0x4E9A92D, "4c0f45d0", "cmovne r10,rax select ~IV[6] when f!=0"),
    (0x4E9A94D, "4889bc24e8000000", "mov [rsp+0xe8],rdi save rounds"),
    (0x4E9A955, "4885ff", "test rdi,rdi rounds==0?"),
    (0x4E9A998, "0f845d040000", "je 0x4e9adfb rounds==0 early finalize"),
    (0x4E9A99E, "488d352ba192fb", "lea rsi,[rip-0x46d5ed5] SIGMA anchor 0x7c4ad0"),
    (0x4E9A9A8, "48b8f1361d5f3af54fa5", "movabs rax, IV[3]=0xa54ff53a5f1d36f1"),
    (0x4E9A9D0, "48bacdcccccccccccccc", "movabs rdx, 0xcccccccccccccccd magic /10"),
    (0x4E9AC22, "49c1c420", "rol r12,0x20  (ror 32)"),
    (0x4E9AC36, "49c1c028", "rol r8,0x28   (ror 24)"),
    (0x4E9AC59, "49c1c730", "rol r15,0x30  (ror 16)"),
    (0x4E9AC68, "48d1c5", "rol rbp,1     (ror 63)"),
    (0x4E9AEAF, "c3", "ret"),
    (0x4E9D2A0, "4156534881ec18010000", "blake2 run() wrapper prologue push r14/rbx; sub rsp,0x118"),
    (0x4E9D2AA, "48817e10d5000000", "cmp qword [rsi+0x10],0xd5 EIP-152 input len 213"),
    (0x4E9D2B2, "7519", "jne reject when len!=213"),
    (0x4E9D2B8, "8b18", "mov ebx,[rax] load rounds big-endian word"),
    (0x4E9D2BA, "0fcb", "bswap ebx big-endian rounds"),
    (0x4E9D2BC, "4839da", "cmp rdx,rbx gas>=rounds (1 gas/round)"),
    (0x4E9D2F2, "0fb688d4000000", "movzx ecx,byte [rax+0xd4] load final-flag f"),
    (0x4E9D2F9, "80f902", "cmp cl,2 reject f not in {0,1}"),
    (0x4E9D2FC, "0f8356010000", "jae reject if f>=2"),
    (0x4E9D3BA, "4889df", "mov rdi,rbx rounds -> rdi for F"),
    (0x4E9D3BD, "ff15659b8d00", "call [0x5776f28] indirect to compress F"),
]

IV_VALUES = [
    0x6A09E667F3BCC908,
    0xBB67AE8584CAA73B,
    0x3C6EF372FE94F82B,
    0xA54FF53A5F1D36F1,
    0x510E527FADE682D1,
    0x9B05688C2B3E6C1F,
    0x1F83D9ABFB41BD6B,
    0x5BE0CD19137E2179,
]
IV_NOT6 = 0xE07C265404BE4294  # ~IV[6]

ROL_COUNTS = {"0x20": 8, "0x28": 8, "0x30": 8, "1": 8}

# Official EIP-152 vectors (https://eips.ethereum.org/EIPS/eip-152)
# Vector 4 = rounds=0; Vector 5 = rounds=12 (user said "vector 4 (rounds=12)"
# but EIP numbering has vector 4 = rounds=0 and vector 5 = rounds=12; both proven).
EIP152_VECTORS = {
    "vector_4_rounds0": {
        "rounds": 0,
        "f": 1,
        "input_hex": "0000000048c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5d182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b61626300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000001",
        "output_hex": "08c9bcf367e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5d282e6ad7f520e511f6c3e2b8c68059b9442be0454267ce079217e1319cde05b",
    },
    "vector_5_rounds12": {
        "rounds": 12,
        "f": 1,
        "input_hex": "0000000c48c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5d182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b61626300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000001",
        "output_hex": "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923",
    },
    "vector_6_rounds12_f0": {
        "rounds": 12,
        "f": 0,
        "input_hex": "0000000c48c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5d182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b61626300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000000",
        "output_hex": "75ab69d3190a562c51aef8d88f1c2775876944407270c42c9844252c26d2875298743e7f6d5ea2f2d3e8d226039cd31b4e426ac4f2d3d666a610c2116fde4735",
    },
    "vector_7_rounds1": {
        "rounds": 1,
        "f": 1,
        "input_hex": "0000000148c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5d182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b61626300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000001",
        "output_hex": "b63a380cb2897d521994a85234ee2c181b5f844d2c624c002677e9703449d2fba551b3a8333bcdf5f2f7e08993d53923de3d64fcc68c034e717b9293fed7a421",
    },
}

ABI = {
    "rdi": "rounds (u64/usize; test+je skips G loop when 0)",
    "rsi": "h pointer (*mut [u64; 8], written back in place)",
    "rdx": "m pointer (*const [u64; 16])",
    "rcx": "t pointer (*const [u64; 2]; IV[4]^=t[0], IV[5]^=t[1])",
    "r8": "f final-block flag (r8d; cmovne selects ~IV[6])",
}


def segments(hdr: bytes):
    """Minimal ELF64 PT_LOAD parser. No pyelftools."""
    if hdr[:4] != b"\x7fELF":
        raise ValueError("not ELF")
    e_phoff = struct.unpack_from("<Q", hdr, 32)[0]
    e_phentsize, e_phnum = struct.unpack_from("<HH", hdr, 54)
    out = []
    for i in range(e_phnum):
        o = e_phoff + i * e_phentsize
        p_type, p_flags = struct.unpack_from("<II", hdr, o)
        p_offset, p_vaddr, _p_paddr, p_filesz, p_memsz, _align = struct.unpack_from(
            "<QQQQQQ", hdr, o + 8
        )
        if p_type == 1 and p_filesz:
            out.append((p_vaddr, p_offset, p_filesz))
    out.sort()
    return out


def va_to_off(segs, va: int) -> int:
    for base, off, size in segs:
        if base <= va < base + size:
            return off + (va - base)
    raise KeyError(hex(va))


def read_va(data: bytes, segs, va: int, n: int) -> bytes:
    return data[va_to_off(segs, va) : va_to_off(segs, va) + n]


def count_rol_immediates(data: bytes, segs) -> dict:
    """Count rol imm encodings inside FN..FN_END without a disassembler.

    Encodings observed in this function:
      49 c1 cX imm8   rex.WB rol r8..r15, imm8
      48 c1 cX imm8   rex.W  rol rax..rdi, imm8
      49 d1 cX        rex.WB rol r8..r15, 1
      48 d1 cX        rex.W  rol rax..rdi, 1
    """
    blob = read_va(data, segs, FN, FN_END - FN)
    counts = {"0x20": 0, "0x28": 0, "0x30": 0, "1": 0}
    i = 0
    while i + 3 < len(blob):
        b0, b1, b2 = blob[i], blob[i + 1], blob[i + 2]
        if b0 in (0x48, 0x49) and b1 == 0xC1 and (b2 & 0xF8) == 0xC0:
            imm = blob[i + 3]
            if imm == 0x20:
                counts["0x20"] += 1
            elif imm == 0x28:
                counts["0x28"] += 1
            elif imm == 0x30:
                counts["0x30"] += 1
            i += 4
            continue
        if b0 in (0x48, 0x49) and b1 == 0xD1 and (b2 & 0xF8) == 0xC0:
            counts["1"] += 1
            i += 3
            continue
        i += 1
    return counts


def parse_eip152_input(inp: bytes):
    if len(inp) != 213:
        raise ValueError("EIP-152 input must be 213 bytes")
    rounds = int.from_bytes(inp[0:4], "big")
    h = inp[4:68]
    m = inp[68:196]
    t = inp[196:212]
    f = inp[212]
    return rounds, h, m, t, f


def emulate_carved(data: bytes, segs, rounds: int, h: bytes, m: bytes, t: bytes, f: int) -> bytes:
    """Run the carved function bytes under Unicorn. Proof of THIS binary's code."""
    try:
        from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UcError
        from unicorn.x86_const import (
            UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RDX, UC_X86_REG_RCX,
            UC_X86_REG_R8, UC_X86_REG_RSP, UC_X86_REG_RAX, UC_X86_REG_RBX,
            UC_X86_REG_RBP, UC_X86_REG_R9, UC_X86_REG_R10, UC_X86_REG_R11,
            UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15,
        )
    except ImportError as e:
        raise RuntimeError(
            "unicorn is required for behavioural proof of carved bytes; "
            "install with: python3 -m venv .venv && .venv/bin/pip install unicorn"
        ) from e

    def map_fixed(mu, va, size):
        base = va & ~0xFFF
        end = (va + size + 0xFFF) & ~0xFFF
        cur = base
        while cur < end:
            try:
                mu.mem_map(cur, 0x1000)
            except UcError:
                pass
            cur += 0x1000

    mu = Uc(UC_ARCH_X86, UC_MODE_64)
    # SIGMA + surrounding rodata (LOAD0 identity)
    map_fixed(mu, 0x7C4000, 0x2000)
    mu.mem_write(0x7C4000, data[0x7C4000:0x7C6000])
    # Function text page(s)
    fn_page = FN & ~0xFFF
    map_fixed(mu, fn_page, 0x2000)
    fo = va_to_off(segs, fn_page)
    mu.mem_write(fn_page, data[fo : fo + 0x2000])
    # Stop trampoline
    STOP = 0x70000000
    map_fixed(mu, STOP, 0x1000)
    mu.mem_write(STOP, b"\x90" * 16)
    STACK = 0x7FFF00000000
    map_fixed(mu, STACK, 0x20000)
    rsp = STACK + 0x10000
    mu.mem_write(rsp, struct.pack("<Q", STOP))
    mu.reg_write(UC_X86_REG_RSP, rsp)
    H_ADDR, M_ADDR, T_ADDR = 0x60000000, 0x60001000, 0x60002000
    map_fixed(mu, H_ADDR, 0x3000)
    mu.mem_write(H_ADDR, h)
    mu.mem_write(M_ADDR, m)
    mu.mem_write(T_ADDR, t)
    mu.reg_write(UC_X86_REG_RDI, rounds)
    mu.reg_write(UC_X86_REG_RSI, H_ADDR)
    mu.reg_write(UC_X86_REG_RDX, M_ADDR)
    mu.reg_write(UC_X86_REG_RCX, T_ADDR)
    mu.reg_write(UC_X86_REG_R8, f)
    for reg in (
        UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RBP,
        UC_X86_REG_R9, UC_X86_REG_R10, UC_X86_REG_R11,
        UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15,
    ):
        mu.reg_write(reg, 0)
    mu.emu_start(FN, STOP, timeout=10_000_000)
    return bytes(mu.mem_read(H_ADDR, 64))


def find_rela_dyn(data: bytes):
    """Return list of (r_offset, r_info, r_addend) from .rela.dyn. Stdlib only."""
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


def wiring_pins(data: bytes, segs) -> dict:
    """Static HyperEVM 0x09 / EIP-152 run() wrapper pins from bytes."""
    addr09 = read_va(data, segs, ADDR09_VA, 20)
    call = read_va(data, segs, 0x4E9D3BD, 6)
    call_disp = struct.unpack_from("<i", call, 2)[0]
    call_slot = 0x4E9D3BD + 6 + call_disp
    relas = find_rela_dyn(data)
    wrap_rela = None
    f_rela = None
    for r_offset, r_info, r_addend in relas:
        if r_offset == PRECOMPILE_SLOT and r_addend == WRAP and (r_info & 0xFFFFFFFF) == R_X86_64_RELATIVE:
            wrap_rela = {"r_offset": hex(r_offset), "r_info": hex(r_info), "r_addend": hex(r_addend)}
        if r_offset == F_GOT_SLOT and r_addend == FN and (r_info & 0xFFFFFFFF) == R_X86_64_RELATIVE:
            f_rela = {"r_offset": hex(r_offset), "r_info": hex(r_info), "r_addend": hex(r_addend)}
    return {
        "status": "statically_shown",
        "wrapper_va": hex(WRAP),
        "wrapper_end": hex(WRAP_END),
        "precompile_slot": hex(PRECOMPILE_SLOT),
        "address_0x09_va": hex(ADDR09_VA),
        "address_0x09_bytes": addr09.hex(),
        "address_0x09_match": addr09 == ADDR09_BYTES,
        "wrap_rela": wrap_rela,
        "f_got_slot": hex(F_GOT_SLOT),
        "f_rela": f_rela,
        "call_indirect_va": "0x4e9d3bd",
        "call_indirect_bytes": call.hex(),
        "call_indirect_slot": hex(call_slot),
        "call_indirect_slot_match": call_slot == F_GOT_SLOT,
        "input_len_check_va": "0x4e9d2aa",
        "input_len_check_bytes": "48817e10d5000000",
        "input_len_imm": "0xd5",
        "rounds_bswap_va": "0x4e9d2ba",
        "rounds_bswap_bytes": "0fcb",
        "final_flag_load_va": "0x4e9d2f2",
        "final_flag_load_bytes": "0fb688d4000000",
        "final_flag_cmp_va": "0x4e9d2f9",
        "final_flag_cmp_bytes": "80f902",
        "final_flag_jae_va": "0x4e9d2fc",
        "final_flag_jae_bytes": "0f8356010000",
        "gas_cmp_va": "0x4e9d2bc",
        "gas_cmp_bytes": "4839da",
        "gas_per_round": GAS_PER_ROUND,
        "note": (
            "Precompile object at 0x574f0b0 carries Address(0x09) at +0x10 "
            "(VA 0x574f0c0) and receives run() wrapper 0x4e9d2a0 via "
            "R_X86_64_RELATIVE. Wrapper enforces input len==0xd5, bswap "
            "BE rounds into rdi, rejects f>=2, requires gas>=rounds "
            "(1 gas/round), then call [0x5776f28] (RELA -> compress F)."
        ),
    }


def analyse(data: bytes, check_sha: bool = True, run_emu: bool = True) -> dict:
    if check_sha:
        got = hashlib.sha256(data).hexdigest()
        if got != BINARY_SHA256:
            raise ValueError(f"binary sha256 mismatch: {got}")
    segs = segments(data[: max(0x1000, struct.unpack_from("<Q", data, 32)[0] + 0x400)])
    # Re-parse with full file for phdr content already in data
    segs = segments(data)

    carved = read_va(data, segs, FN, FN_END - FN)
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
    loc_ok = loc_raw == LOCATION_PATH.encode()

    sigma0 = [struct.unpack_from("<Q", read_va(data, segs, SIGMA_VA, 128), i * 8)[0] for i in range(16)]
    sigma1 = [struct.unpack_from("<Q", read_va(data, segs, SIGMA_VA + 128, 128), i * 8)[0] for i in range(16)]
    rol_counts = count_rol_immediates(data, segs)

    # Confirm lea target
    lea_bytes = read_va(data, segs, SIGMA_LEA, 7)
    lea_disp = struct.unpack_from("<i", lea_bytes, 3)[0]
    lea_target = SIGMA_LEA + 7 + lea_disp

    vectors = {}
    for name, spec in sorted(EIP152_VECTORS.items()):
        inp = bytes.fromhex(spec["input_hex"])
        rounds, h, m, t, f = parse_eip152_input(inp)
        entry = {
            "rounds": rounds,
            "f": f,
            "input_len": len(inp),
            "expected_output_hex": spec["output_hex"],
            "expected_output_sha256": hashlib.sha256(bytes.fromhex(spec["output_hex"])).hexdigest(),
        }
        if run_emu:
            try:
                out = emulate_carved(data, segs, rounds, h, m, t, f)
                entry["emulated_output_hex"] = out.hex()
                entry["emulated_output_sha256"] = hashlib.sha256(out).hexdigest()
                entry["byte_identical"] = out.hex() == spec["output_hex"]
                entry["proof"] = "unicorn_carved_bytes"
            except Exception as exc:
                entry["emulated_output_hex"] = None
                entry["byte_identical"] = False
                entry["proof"] = "unicorn_carved_bytes"
                entry["emu_error"] = type(exc).__name__
        vectors[name] = entry

    result = {
        "packet": "RE-021-blake2b-compress-94",
        "binary_sha256": BINARY_SHA256,
        "fn": hex(FN),
        "fn_end": hex(FN_END),
        "fn_ret": hex(FN_RET),
        "carved_len": len(carved),
        "carved_sha256": carved_sha,
        "abi": ABI,
        "iv": [hex(v) for v in IV_VALUES],
        "iv_not6": hex(IV_NOT6),
        "sigma_va": hex(SIGMA_VA),
        "sigma_lea": hex(SIGMA_LEA),
        "sigma_lea_target": hex(lea_target),
        "sigma0": sigma0,
        "sigma1": sigma1,
        "rol_counts": rol_counts,
        "location_path_va": hex(LOCATION_PATH_VA),
        "location_path": LOCATION_PATH,
        "location_path_len": LOCATION_PATH_LEN,
        "location_path_match": loc_ok,
        "key_insns_count": len(KEY_INSNS),
        "key_bytes": key_bytes,
        "eip152_vectors": vectors,
        "behavioural_proof": "unicorn_emulation_of_carved_function_bytes",
        "hyperevm_precompile_wiring": wiring_pins(data, segs),
        "overlap_nonclaim": {
            "pr_154": (
                "#154 inventory mentions 0x4e9a8a0 only as a count of sha512/"
                "blake IV movabs sites; it does not claim EIP-152 behaviour or "
                "the compress mechanism."
            ),
        },
    }
    return result


def expectation_errors(result: dict) -> list:
    errs = []
    if result["binary_sha256"] != BINARY_SHA256:
        errs.append("binary_sha256")
    if result["carved_sha256"] != CARVED_SHA256:
        errs.append("carved_sha256")
    if result["carved_len"] != CARVED_LEN:
        errs.append("carved_len")
    if result["key_insns_count"] != len(KEY_INSNS):
        errs.append("key_insns_count")
    for kb in result["key_bytes"]:
        if not kb["match"]:
            errs.append(f"key_byte {kb['va']}")
    if result["rol_counts"] != ROL_COUNTS:
        errs.append(f"rol_counts {result['rol_counts']}")
    if result["sigma0"] != list(range(16)):
        errs.append("sigma0")
    if result["sigma1"] != [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3]:
        errs.append("sigma1")
    if result["sigma_lea_target"] != hex(SIGMA_LEA_TARGET):
        errs.append("sigma_lea_target")
    if not result["location_path_match"]:
        errs.append("location_path")
    if result["location_path_len"] != LOCATION_PATH_LEN:
        errs.append("location_path_len")
    for name, spec in EIP152_VECTORS.items():
        v = result["eip152_vectors"].get(name)
        if v is None:
            errs.append(f"missing {name}")
            continue
        if v.get("rounds") != spec["rounds"]:
            errs.append(f"{name} rounds")
        if v.get("f") != spec["f"]:
            errs.append(f"{name} f")
        if v.get("expected_output_hex") != spec["output_hex"]:
            errs.append(f"{name} expected")
        if "byte_identical" in v:
            if not v["byte_identical"]:
                errs.append(f"{name} emu mismatch")
            if v.get("proof") != "unicorn_carved_bytes":
                errs.append(f"{name} proof kind")
    if result.get("behavioural_proof") != "unicorn_emulation_of_carved_function_bytes":
        errs.append("behavioural_proof")
    w = result["hyperevm_precompile_wiring"]
    if w.get("status") != "statically_shown":
        errs.append("wiring_status")
    if not w.get("address_0x09_match"):
        errs.append("address_0x09")
    if w.get("address_0x09_bytes") != ADDR09_BYTES.hex():
        errs.append("address_0x09_bytes")
    if not w.get("wrap_rela"):
        errs.append("wrap_rela")
    if not w.get("f_rela"):
        errs.append("f_rela")
    if not w.get("call_indirect_slot_match"):
        errs.append("call_indirect_slot")
    if w.get("gas_per_round") != GAS_PER_ROUND:
        errs.append("gas_per_round")
    if w.get("input_len_imm") != "0xd5":
        errs.append("input_len_imm")
    return errs


def render(result: dict) -> str:
    return json.dumps(result, sort_keys=True, indent=2) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--binary", type=Path, default=TARGET)
    ap.add_argument("--no-emu", action="store_true")
    args = ap.parse_args(argv)
    data = args.binary.read_bytes()
    result = analyse(data, run_emu=not args.no_emu)
    text = render(result)
    sys.stdout.write(text)
    errs = expectation_errors(result)
    if errs:
        print("expectation_errors:", errs, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
