#!/usr/bin/env python3
"""RE-027: bn254 ecMul (EVM precompile 0x07, EIP-196) at 0x4e96cf0 (node #94).

Static analysis uses the standard library. From pinned node #94 bytes it recovers:
  * run_mul entry 0x4e96cf0 (FDE 0x4e96cf0..0x4e973d2 exclusive, the whole FDE
    is the sha256-pinned carve; primary ret at 0x4e973c1; noreturn alloc-error
    tail 0x4e973c2..0x4e973d1; int3 padding 0x4e973d2..0x4e973df is outside it);
  * ABI: rdi=out (40-byte result), rsi/rdx=input ptr/len, rcx=gas cost,
    r8=gas limit (revm-precompile 16.0.0 bn128.rs run_mul);
  * identity: the bn254 base-field modulus p as movabs limbs inside run_mul
    (checked against p = 36u^4+36u^3+24u^2+6u+1), the Fq Montgomery constant
    -p^-1 mod 2^128, R mod p, and the scalar-field modulus r with its own
    Montgomery constant and R^2 mod r (scalar to Montgomery form);
  * wiring: R_X86_64_RELATIVE addend 0x4e96cf0 at GOT slot 0x5776f08, exactly
    2 ff15 calls to the slot (gas wrappers 0x4e98a70 = 40000 Byzantium and
    0x4e98b00 = 6000 Istanbul), 0 direct e8/e9 calls, and the precompile table
    objects 0x574f110 / 0x574f050 whose RELA addends are those wrappers and
    whose Address field (+0x10) is 0x..07;
  * no listed feature-opcode byte patterns in the originally listed callees;
    this limited scan is not a complete instruction/feature inventory;
  * the only external call on the success path is malloc(0x40) at 0x4e9732c
    through GOT 0x576dfd8 (RELA -> jemalloc malloc 0x54c06b0), stubbed in the
    emulation as a bump allocator;
  * retained author emulation records for fixed scalar-mul vectors. New runs
    require explicit opt-in and remain bounded experiments, not equivalence proof.

Output is sorted, deterministic JSON. Every expected value is pinned exactly.
Optional execution also imports Unicorn and the repository crypto_emulation_guard
(no objdump or pyelftools in this generator).
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

FN = 0x4E96CF0
FN_END = 0x4E973D2  # FDE end, exclusive; carve is the whole FDE
FN_RET = 0x4E973C1  # primary ret
NORETURN_TAIL = (0x4E973C2, 0x4E973D2)  # alloc-error path, ends in a noreturn call
PAD = (0x4E973D2, 0x4E973E0)  # int3 padding before run_pair, outside the FDE
CARVED_LEN = FN_END - FN
CARVED_SHA256 = "fa3a57aef72db21e765e20e83db52a3c7ffb825112c2780fc3a7406406d942a5"

DECODER = 0x4E961E0  # G1 point decoder (FDE 0x4e961e0..0x4e9660f), shared with run_add
DECODER_END = 0x4E9660F
# Original selected callee inventory, preserved for output reproducibility.
# EXECUTION_RANGES below also includes two transitive field helpers.
CALLEES = [
    (0x4E961E0, 0x4E9660F, "G1 point decode"),
    (0x4F168D0, 0x4F16B7A, "decoder curve check"),
    (0x4F15B60, 0x4F15E02, "scalar mul (double-and-add)"),
    (0x4F1DEA0, 0x4F1E70C, "projective double (from 0x4f15b60)"),
    (0x4F1B0F0, 0x4F1BF31, "projective add (from 0x4f15b60)"),
    (0x4F160C0, 0x4F164D5, "to-affine helper"),
    (0x4F200F0, 0x4F206EA, "field inverse (via GOT 0x5777640 from 0x4f160c0)"),
    (0x4F1F9C0, 0x4F1FF86, "Montgomery mul (via GOT 0x5776ef8)"),
]

P = 0x30644E72E131A029B85045B68181585D97816A916871CA8D3C208C16D87CFD47
R_ORDER = 0x30644E72E131A029B85045B68181585D2833E84879B9709143E1F593F0000001
BN_U = 4965661367192848881
M64 = 2**64 - 1
P_LIMBS = [(P >> (64 * i)) & M64 for i in range(4)]
R_LIMBS = [(R_ORDER >> (64 * i)) & M64 for i in range(4)]
INV128 = (-pow(P, -1, 2**128)) % 2**128
INV128_R = (-pow(R_ORDER, -1, 2**128)) % 2**128
R_MOD_P = 2**256 % P
R2_MOD_R = 2**512 % R_ORDER

GOT_SLOT = 0x5776F08
R_X86_64_RELATIVE = 8
R_X86_64_GLOB_DAT = 6
TEXT_LOAD_VA = 0x1343C80
SLOT_REFS_EXPECTED = {"call": 2, "jmp": 0, "mov": 0}
FQMUL_SLOT = 0x5776EF8
FQMUL = 0x4F1F9C0

# (wrapper VA, call VA, gas imm, precompile table object, fork); ordered by call VA
WRAPPERS = [
    (0x4E98A70, 0x4E98A87, 40000, 0x574F110, "Byzantium"),
    (0x4E98B00, 0x4E98B17, 6000, 0x574F050, "Istanbul"),
]
# Precompile object layout (0x30 stride, Address at +0x10) as described in #550.
PRECOMPILE_ADDRESS = "00" * 19 + "07"
# Sibling bn128 entries (context only, static): (fn, GOT slot)
SIBLINGS = [(0x4E96610, 0x5776F00, "run_add"), (0x4E973E0, 0x5776F10, "run_pair")]

MALLOC = 0x54C06B0
MALLOC_SLOT = 0x576DFD8
MALLOC_CALL = 0x4E9732C
MALLOC_RET = MALLOC_CALL + 6
MALLOC_SIZE = 0x40
MEMCPY_SLOT = 0x576DFE0  # GLOB_DAT memcpy, used only for input len < 0x60
MEMCPY_CALL = 0x4E96D5C
ALLOC_ERR_SLOT = 0x576DFB8
ALLOC_ERR_CALL = 0x4E973CC
BYTES_VTABLE_SLOTS = (0x576E140, 0x576E148)

# TOKEN rule: printed as key_insns, never the banned equals-form.
KEY_INSNS = [
    (0x4E96CF0, "554157415641554154534881ec88020000", "push rbp..rbx; sub rsp,0x288"),
    (0x4E96D01, "4889fb4c39c17613", "mov rbx,rdi; cmp rcx,r8; jbe (gas ok)"),
    (0x4E96D09, "48b80000000000000080", "movabs rax,0x8000000000000000 (OutOfGas)"),
    (0x4E96D1C, "4883fa5f", "cmp rdx,0x5f (input >= 96 bytes?)"),
    (0x4E96D5C, "ff157e728d00", "call *[rip] -> GOT 0x576dfe0 memcpy (short input)"),
    (0x4E96DDA, "e801f4ffff", "call decoder 0x4e961e0 (point)"),
    (0x4E96E12, "49bf29a031e1724e6430", "movabs p/r limb3 (shared)"),
    (0x4E96E9E, "49bd5d588181b64550b8", "movabs p/r limb2 (shared)"),
    (0x4E96EE1, "48b8e3595ce3b13afe53", "movabs R^2 mod r limb1"),
    (0x4E96EF3, "48b8a76d21ae45e6b81b", "movabs R^2 mod r limb0"),
    (0x4E96F05, "48b8a5444e7fb1d01602", "movabs R^2 mod r limb3"),
    (0x4E96F17, "48b88580bb533d83498c", "movabs R^2 mod r limb2"),
    (0x4E96F29, "48b89170b97948e83328", "movabs r limb1"),
    (0x4E96F38, "48b8010000f093f5e143", "movabs r limb0"),
    (0x4E96F63, "48b9ffffffef93f5e1c2", "movabs Fr Montgomery inv lo"),
    (0x4E96F6D, "49b8b311694c4b868665", "movabs Fr Montgomery inv hi"),
    (0x4E96F77, "ff157bff8d00", "call *[rip] -> GOT 0x5776ef8 (Montgomery mul, scalar to Fr form)"),
    (0x4E96FB8, "e8a3eb0700", "call 0x4f15b60 (scalar mul)"),
    (0x4E96FC8, "e8f3f00700", "call 0x4f160c0 (to affine)"),
    (0x4E9704E, "48b88dca7168916a8197", "movabs p limb1"),
    (0x4E9705D, "48b847fd7cd8168c203c", "movabs p limb0"),
    (0x4E97075, "488b2d7cfe8d00", "mov rbp,[rip] -> GOT 0x5776ef8 (Montgomery mul)"),
    (0x4E9708F, "49bc896386e48207d287", "movabs Fq Montgomery inv lo"),
    (0x4E97099, "49bec96aca1e657dde9e", "movabs Fq Montgomery inv hi"),
    (0x4E970A9, "ffd5", "call rbp (Fq mul)"),
    (0x4E970C8, "48b83d0bc7f528eb780a", "movabs R mod p limb1"),
    (0x4E97327, "bf40000000", "mov edi,0x40 (alloc size)"),
    (0x4E9732C, "ff15a66c8d00", "call *[rip] -> GOT 0x576dfd8 malloc"),
    (0x4E97392, "48c7431040000000", "out.len = 0x40"),
    (0x4E973A1, "488b842448010000", "reload gas cost"),
    (0x4E973A9, "48894320", "out.gas_used = gas cost"),
    (0x4E973C1, "c3", "ret (primary)"),
    (0x4E973C2, "bf01000000be40000000", "alloc-error args (align 1, size 0x40)"),
    (0x4E973CC, "ff15e66b8d00", "call *[rip] -> GOT 0x576dfb8 alloc error (noreturn)"),
    (0x4E973D2, "cccccccccccccccccccccccccccc", "int3 padding after FDE end"),
    (0x4E98A7F, "b9409c0000", "wrapper ecx = 40000"),
    (0x4E98A87, "ff157be48d00", "wrapper call *[rip] -> GOT 0x5776f08"),
    (0x4E98B0F, "b970170000", "wrapper ecx = 6000"),
    (0x4E98B17, "ff15ebe38d00", "wrapper call *[rip] -> GOT 0x5776f08"),
    (0x54C06B0, "f30f1efa4881ff00100000", "malloc: endbr64; cmp rdi,0x1000 (stubbed)"),
]

G = (1, 2)
C3_OFFSETS = ["0x4e973c1"]  # the only c3 byte in the carve is the primary ret
FIELD_COUNTS = {"p_limbs_in_run_mul": [4, 4, 1, 3], "r_limbs_in_run_mul": [1, 1, 1, 3], "inv_limbs_in_run_mul": [1, 1], "inv_r_limbs_in_run_mul": [1, 1], "r_mod_p_limbs_in_run_mul": [2, 2, 2, 2], "r2_mod_r_limbs_in_run_mul": [1, 1, 1, 1]}  # r limb2/limb3 equal p limb2/limb3


def enc(*xs):
    return b"".join(x.to_bytes(32, "big") for x in xs)


def h(x):
    return bytes.fromhex(x)


ZERO64 = "00" * 64
# Error payload at out+0x10 (24 bytes): niche tag 0x8000000000000000 | variant.
# Variant order matches upstream PrecompileError: 0 OutOfGas,
# 6 Bn128FieldPointNotAMember, 7 Bn128AffineGFailedToCreate.
ERR_OOG = struct.pack("<Q", 0x8000000000000000).hex() + "00" * 16
ERR_FIELD = struct.pack("<Q", 0x8000000000000006).hex() + "00" * 16
ERR_AFFINE = struct.pack("<Q", 0x8000000000000007).hex() + "00" * 16
# Published vectors: go-ethereum core/vm/testdata/precompiles/bn256ScalarMul.json
# (EIP-196 scalar-mul tests; last file commit 918aed4e314f1db27191c0b0611ff02d3759122c).
GETH = {
    "chfast1": ("2bd3e6d0f3b142924f5ca7b49ce5b9d54c4703d7ae5648e61d02268b1a0a9fb721611ce0a6af85915e2f1d70300909ce2e49dfad4a4619c8390cae66cefdb20400000000000000000000000000000000000000000000000011138ce750fa15c2",
                "070a8d6a982153cae4be29d434e8faef8a47b274a053f5a4ee2a6c9c13c31e5c031b8ce914eba3a9ffb989f9cdd5b0f01943074bf4f0f315690ec3cec6981afc"),
    "chfast2": ("070a8d6a982153cae4be29d434e8faef8a47b274a053f5a4ee2a6c9c13c31e5c031b8ce914eba3a9ffb989f9cdd5b0f01943074bf4f0f315690ec3cec6981afc30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd46",
                "025a6f4181d2b4ea8b724290ffb40156eb0adb514c688556eb79cdea0752c2bb2eff3f31dea215f1eb86023a133a996eb6300b44da664d64251d05381bb8a02e"),
    "cdetrio1": ("1a87b0584ce92f4593d161480614f2989035225609f08058ccfa3d0f940febe31a2f3c951f6dadcc7ee9007dff81504b0fcd6d7cf59996efdc33d92bf7f9f8f6ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                 "2cde5879ba6f13c0b5aa4ef627f159a3347df9722efce88a9afbb20b763b4c411aa7e43076f6aee272755a7f9b84832e71559ba0d2e0b17d5f9f01755e5b0d11"),
    "zeroScalar": ("039730ea8dff1254c0fee9c0ea777d29a9c710b7e616683f194f18c43b43b869073a5ffcc6fc7a28c30723d6e58ce577356982d65b833a5a5c15bf9024b43d980000000000000000000000000000000000000000000000000000000000000000",
                   ZERO64),
}
# name -> (input, gas cost, gas limit, expected kind, expected output hex or error payload)
VECTORS = {
    "geth_chfast1": (h(GETH["chfast1"][0]), 6000, 6000, "ok", GETH["chfast1"][1]),
    "geth_chfast2": (h(GETH["chfast2"][0]), 6000, 6000, "ok", GETH["chfast2"][1]),
    "geth_cdetrio1": (h(GETH["cdetrio1"][0]), 6000, 6000, "ok", GETH["cdetrio1"][1]),
    "geth_zero_scalar": (h(GETH["zeroScalar"][0]), 6000, 6000, "ok", GETH["zeroScalar"][1]),
    "g_times_order_infinity": (enc(1, 2, R_ORDER), 6000, 6000, "ok", ZERO64),
    "zero_input": (bytes(96), 6000, 6000, "ok", ZERO64),
    "off_curve": (enc(1, 3, 2), 6000, 6000, "err", ERR_AFFINE),
    "x_not_in_field": (enc(P, 0, 2), 6000, 6000, "err", ERR_FIELD),
    "out_of_gas": (enc(1, 2, 2), 6000, 5999, "err", ERR_OOG),
}


def ref_add(a, b):
    """Independent affine add over Fp (EIP-196); (0,0) is infinity."""
    if a == (0, 0):
        return b
    if b == (0, 0):
        return a
    if a[0] == b[0] and (a[1] + b[1]) % P == 0:
        return (0, 0)
    if a == b:
        lam = 3 * a[0] * a[0] * pow(2 * a[1], -1, P) % P
    else:
        lam = (b[1] - a[1]) * pow(b[0] - a[0], -1, P) % P
    x = (lam * lam - a[0] - b[0]) % P
    return (x, (lam * (a[0] - x) - a[1]) % P)


def ref_mul(pt, k):
    """Independent double-and-add over the affine add above."""
    acc, q = (0, 0), pt
    while k:
        if k & 1:
            acc = ref_add(acc, q)
        q = ref_add(q, q)
        k >>= 1
    return acc


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


def text_bytes(data, segs):
    for base, off, filesz, _m in segs:
        if base == TEXT_LOAD_VA:
            return data[off : off + filesz]
    raise KeyError("text load")


def slot_refs(text, slot):
    """Rip-relative references to `slot` in the main text load, by kind."""
    refs = []
    for i in range(len(text) - 7):
        b0, b1 = text[i], text[i + 1]
        if b0 == 0xFF and b1 in (0x15, 0x25):
            if TEXT_LOAD_VA + i + 6 + struct.unpack_from("<i", text, i + 2)[0] == slot:
                refs.append(("call" if b1 == 0x15 else "jmp", TEXT_LOAD_VA + i))
        elif b0 in (0x48, 0x4C) and b1 == 0x8B and (text[i + 2] & 0xC7) == 0x05:
            if TEXT_LOAD_VA + i + 7 + struct.unpack_from("<i", text, i + 3)[0] == slot:
                refs.append(("mov", TEXT_LOAD_VA + i))
    return refs


def direct_calls(text, target):
    n = 0
    for i in range(len(text) - 5):
        if text[i] in (0xE8, 0xE9) and TEXT_LOAD_VA + i + 5 + struct.unpack_from("<i", text, i + 1)[0] == target:
            n += 1
    return n


SIMD_PATTERNS = {  # byte patterns for feature probes / ADX / BMI2 mulx
    "cpuid": b"\x0f\xa2",
    "xgetbv": b"\x0f\x01\xd0",
    "adcx": b"\x66\x0f\x38\xf6",
    "adox": b"\xf3\x0f\x38\xf6",
}


def simd_hits(code):
    hits = {k: code.count(v) for k, v in SIMD_PATTERNS.items()}
    # mulx: VEX3 c4 (RXB.00010) (W.vvvv.L.11) f6
    hits["mulx_vex"] = sum(1 for i in range(len(code) - 3)
                           if code[i] == 0xC4 and code[i + 1] & 0x1F == 0x02
                           and code[i + 2] & 0x03 == 0x03 and code[i + 3] == 0xF6)
    return hits


def unicorn_available():
    import importlib.util

    return importlib.util.find_spec("unicorn") is not None


HEAP = 0x70000000
STUB_HEAP_STEP = 0x40
STACK, IO, STOP, TLS = 0x7FFF00000000, 0x60000000, 0x600000000, 0x7F0000000000
STACK_SIZE, HEAP_SIZE = 0x100000, 0x10000
OUT, INP = IO + 0x100, IO + 0x1000
# Exact FDEs from the authenticated native review; malloc's first ENDBR64
# instruction is intercepted, never its allocator body. Panic/memcpy targets
# are deliberately outside this closure and must fail the execution guard.
EXECUTION_RANGES = ((FN, FN_END),) + tuple((a, b) for a, b, _ in CALLEES) + (
    (0x4F1F8E0, 0x4F1F9B1),  # field add/reduce, GOT 0x5777658
    (0x4F20020, 0x4F200E3),  # field subtract/reduce, GOT 0x5777668
    (MALLOC, MALLOC + 4),
)


def validate_run(data, segs, rela, inp, gas, limit, stub, allow_execution):
    """Reject scope escapes before importing or constructing an emulator."""
    if allow_execution is not True:
        raise PermissionError("captured-code emulation requires explicit allow_execution=True")
    if stub is not True:
        raise ValueError("only the reviewed malloc stub is permitted")
    if not isinstance(inp, bytes) or len(inp) != 96:
        raise ValueError("only 96-byte inputs are covered; short-input memcpy is excluded")
    if any(type(v) is not int or not 0 <= v <= M64 for v in (gas, limit)):
        raise ValueError("gas and limit must be unsigned 64-bit integers")
    if HEAP not in (0x70000000, 0x71000000):
        raise ValueError("heap must be one of the two reviewed nonoverlapping placements")
    if hashlib.sha256(data).hexdigest() != BINARY_SHA256:
        raise ValueError("emulation requires the unchanged authenticated node94")
    if segs != segments(data) or rela != rela_dyn(data):
        raise ValueError("mapping/relocation metadata must match the authenticated ELF")


def validate_malloc(sp, ret, req, allocation_count):
    if not STACK <= sp <= STACK + STACK_SIZE - 8 or sp % 8:
        raise RuntimeError("malloc return slot is outside the synthetic stack")
    if ret != MALLOC_RET or req != MALLOC_SIZE or allocation_count != 0:
        raise RuntimeError("malloc requires the single reviewed 64-byte call and return")


def validate_result(q, allocs, gas):
    """Validate the complete result header before dereferencing guest pointers."""
    if q[0] == 0:
        if q[1] != 0 or allocs:
            raise RuntimeError("invalid error result header or unexpected allocation")
    elif q != (0x5670AE8, HEAP, MALLOC_SIZE, HEAP | 1, gas) or allocs != [
            {"ret": hex(MALLOC_RET), "size": MALLOC_SIZE}]:
        raise RuntimeError("result escaped the reviewed allocation/header contract")


def emulate(data, segs, rela, inp: bytes, gas: int, limit: int, stub=True, *, allow_execution=False):
    """Explicitly authorized bounded run; the actual allocator is excluded."""
    validate_run(data, segs, rela, inp, gas, limit, stub, allow_execution)
    from crypto_emulation_guard import run_bounded
    from unicorn import UC_ARCH_X86, UC_HOOK_CODE, UC_MODE_64, UC_PROT_ALL, Uc, UcError
    from unicorn.x86_const import (UC_X86_REG_FS_BASE, UC_X86_REG_R8, UC_X86_REG_RAX,
                                   UC_X86_REG_RCX, UC_X86_REG_RDI, UC_X86_REG_RDX,
                                   UC_X86_REG_RIP, UC_X86_REG_RSI, UC_X86_REG_RSP)

    mu = Uc(UC_ARCH_X86, UC_MODE_64)
    page = 0x1000
    mapped = set()

    def map_span(va, size):
        start = va & ~(page - 1)
        end = (va + size + page - 1) & ~(page - 1)
        try:
            mu.mem_map(start, end - start, UC_PROT_ALL)
            mapped.update(range(start, end, page))
        except UcError:
            for p in range(start, end, page):
                if p not in mapped:
                    mu.mem_map(p, page, UC_PROT_ALL)
                    mapped.add(p)

    for base, off, filesz, memsz in segs:
        map_span(base, memsz)
        mu.mem_write(base, data[off : off + filesz] + bytes(max(0, memsz - filesz)))
    relocs = 0
    for r_offset, r_info, r_addend in rela:
        if r_info & 0xFFFFFFFF == R_X86_64_RELATIVE:
            mu.mem_write(r_offset, struct.pack("<Q", r_addend))
            relocs += 1

    map_span(STACK, 0x100000)
    map_span(IO, 0x10000)
    map_span(HEAP, 0x10000)
    map_span(STOP, 0x1000)
    map_span(TLS, 0x2000)
    mu.reg_write(UC_X86_REG_FS_BASE, TLS + 0x1000)
    mu.mem_write(STOP, b"\xf4")
    mu.mem_write(INP, inp)
    rsp = STACK + 0x100000 - 0x2000 - 8
    mu.mem_write(rsp, struct.pack("<Q", STOP))
    mu.reg_write(UC_X86_REG_RSP, rsp)
    mu.reg_write(UC_X86_REG_RDI, OUT)
    mu.reg_write(UC_X86_REG_RSI, INP)
    mu.reg_write(UC_X86_REG_RDX, len(inp))
    mu.reg_write(UC_X86_REG_RCX, gas)
    mu.reg_write(UC_X86_REG_R8, limit)

    allocs = []

    def on_malloc(uc, address, size, _user):
        sp = uc.reg_read(UC_X86_REG_RSP)
        # Validate the stack address before any guest-pointer read.
        if not STACK <= sp <= STACK + STACK_SIZE - 8 or sp % 8:
            raise RuntimeError("malloc return slot is outside the synthetic stack")
        ret = struct.unpack("<Q", uc.mem_read(sp, 8))[0]
        req = uc.reg_read(UC_X86_REG_RDI)
        validate_malloc(sp, ret, req, len(allocs))
        allocs.append({"ret": hex(ret), "size": req})
        uc.reg_write(UC_X86_REG_RAX, HEAP)
        uc.reg_write(UC_X86_REG_RSP, sp + 8)
        uc.reg_write(UC_X86_REG_RIP, ret)

    stub_hook = mu.hook_add(UC_HOOK_CODE, on_malloc, begin=MALLOC, end=MALLOC)
    try:
        run_bounded(mu, FN, STOP, code_ranges=EXECUTION_RANGES,
                    writable_ranges=((STACK, STACK + STACK_SIZE),
                                     (OUT, OUT + 0x28), (HEAP, HEAP + MALLOC_SIZE)),
                    timeout=60_000_000, count=50_000_000)
    finally:
        mu.hook_del(stub_hook)
    fault = None
    rip = mu.reg_read(UC_X86_REG_RIP)
    out = bytes(mu.mem_read(OUT, 0x28))
    q = struct.unpack("<5Q", out)
    validate_result(q, allocs, gas)
    res = {"allocs": allocs, "fault": fault, "relocs_applied": relocs,
           "returned": fault is None and rip == STOP, "out_hex": out.hex()}
    if q[0] != 0:  # Ok(PrecompileOutput{bytes, gas_used})
        res["kind"] = "ok"
        res["vtable"] = hex(q[0])
        res["data_ptr"] = hex(q[1])
        res["len"] = q[2]
        res["gas_used"] = q[4]
        res["output_hex"] = bytes(mu.mem_read(q[1], q[2])).hex()
    else:
        res["kind"] = "err"
        res["err_payload_hex"] = out[0x10:0x28].hex()
    return res


def analyse(data, check_sha=True, run_emu=False, *, allow_execution=False):
    if run_emu and allow_execution is not True:
        raise PermissionError("captured-code emulation requires explicit allow_execution=True")
    if run_emu and not unicorn_available():
        raise RuntimeError("explicit emulation requested but Unicorn is unavailable")
    if check_sha:
        got = hashlib.sha256(data).hexdigest()
        if got != BINARY_SHA256:
            raise ValueError("binary sha256 mismatch: " + got)
    segs = segments(data)
    carved = read_va(data, segs, FN, CARVED_LEN)
    text = text_bytes(data, segs)
    rela = rela_dyn(data)
    rela_by_off = {}
    for r in rela:
        if r[0] in rela_by_off:
            raise ValueError(f"duplicate relocation offset {r[0]:#x}")
        rela_by_off[r[0]] = r

    def rela_of(slot):
        r = rela_by_off.get(slot)
        if r is None:
            return None
        return {"r_offset": hex(r[0]), "r_info": hex(r[1]), "r_addend": hex(r[2])}

    key_bytes = []
    for va, hx, note in KEY_INSNS:
        raw = read_va(data, segs, va, len(hx) // 2)
        key_bytes.append({"va": hex(va), "bytes": raw.hex(), "expected": hx,
                          "match": raw.hex() == hx, "note": note})

    def rel32_target(va, ilen, disp_at):
        insn = read_va(data, segs, va, ilen)
        return va + ilen + struct.unpack_from("<i", insn, disp_at)[0]

    branches = {
        "decoder_call": hex(rel32_target(0x4E96DDA, 5, 1)),
        "scalar_mul_call": hex(rel32_target(0x4E96FB8, 5, 1)),
        "to_affine_call": hex(rel32_target(0x4E96FC8, 5, 1)),
        "fr_mul_call_slot": hex(rel32_target(0x4E96F77, 6, 2)),
        "fqmul_slot_load": hex(rel32_target(0x4E97075, 7, 3)),
        "memcpy_call_slot": hex(rel32_target(MEMCPY_CALL, 6, 2)),
        "malloc_call_slot": hex(rel32_target(MALLOC_CALL, 6, 2)),
        "alloc_err_call_slot": hex(rel32_target(ALLOC_ERR_CALL, 6, 2)),
        "wrapper_byzantium_call_slot": hex(rel32_target(WRAPPERS[0][1], 6, 2)),
        "wrapper_istanbul_call_slot": hex(rel32_target(WRAPPERS[1][1], 6, 2)),
    }
    branches_expected = {
        "decoder_call": hex(DECODER), "scalar_mul_call": hex(0x4F15B60),
        "to_affine_call": hex(0x4F160C0), "fr_mul_call_slot": hex(FQMUL_SLOT),
        "fqmul_slot_load": hex(FQMUL_SLOT), "memcpy_call_slot": hex(MEMCPY_SLOT),
        "malloc_call_slot": hex(MALLOC_SLOT), "alloc_err_call_slot": hex(ALLOC_ERR_SLOT),
        "wrapper_byzantium_call_slot": hex(GOT_SLOT), "wrapper_istanbul_call_slot": hex(GOT_SLOT),
    }

    def imm_count(code, v):
        return code.count(struct.pack("<Q", v))

    def limbs(v, n=4):
        return [(v >> (64 * i)) & M64 for i in range(n)]

    pad = read_va(data, segs, PAD[0], PAD[1] - PAD[0])
    field = {
        "p_hex": hex(P),
        "p_from_bn_u": 36 * BN_U**4 + 36 * BN_U**3 + 24 * BN_U**2 + 6 * BN_U + 1 == P,
        "r_hex": hex(R_ORDER),
        "r_from_bn_u": 36 * BN_U**4 + 36 * BN_U**3 + 18 * BN_U**2 + 6 * BN_U + 1 == R_ORDER,
        "p_limbs_in_run_mul": [imm_count(carved, v) for v in P_LIMBS],
        "r_limbs_in_run_mul": [imm_count(carved, v) for v in R_LIMBS],
        "inv128_hex": hex(INV128),
        "inv_limbs_in_run_mul": [imm_count(carved, v) for v in limbs(INV128, 2)],
        "inv_check": (P * INV128 + 1) % 2**128 == 0,
        "inv128_r_hex": hex(INV128_R),
        "inv_r_limbs_in_run_mul": [imm_count(carved, v) for v in limbs(INV128_R, 2)],
        "inv_r_check": (R_ORDER * INV128_R + 1) % 2**128 == 0,
        "r_mod_p_limbs_in_run_mul": [imm_count(carved, v) for v in limbs(R_MOD_P)],
        "r2_mod_r_limbs_in_run_mul": [imm_count(carved, v) for v in limbs(R2_MOD_R)],
    }
    extent = {
        "fde_start": hex(FN), "fde_end_exclusive": hex(FN_END), "primary_ret": hex(FN_RET),
        "primary_ret_byte": read_va(data, segs, FN_RET, 1).hex(),
        "c3_offsets_in_carve": [hex(FN + i) for i, b in enumerate(carved) if b == 0xC3],
        "noreturn_tail": [hex(NORETURN_TAIL[0]), hex(NORETURN_TAIL[1])],
        "padding": [hex(PAD[0]), hex(PAD[1])],
        "padding_all_int3": pad == b"\xcc" * len(pad),
        "next_fn": hex(PAD[1]),
    }

    refs = slot_refs(text, GOT_SLOT)
    ref_counts = {k: sum(1 for kind, _ in refs if kind == k) for k in ("call", "jmp", "mov")}
    wrappers = []
    for wva, cva, gas, tslot, fork in WRAPPERS:
        r = rela_of(tslot)
        imm = struct.unpack("<I", read_va(data, segs, cva - 8 + 1, 4))[0]
        addr = read_va(data, segs, tslot + 0x10, 20).hex()
        wrappers.append({"wrapper": hex(wva), "call_va": hex(cva), "gas_imm": imm,
                         "fork": fork, "table_slot": hex(tslot), "table_rela": r,
                         "table_address_va": hex(tslot + 0x10), "table_address_hex": addr,
                         "match": imm == gas and r is not None and r["r_addend"] == hex(wva)
                         and r["r_info"] == hex(R_X86_64_RELATIVE) and addr == PRECOMPILE_ADDRESS})
    siblings = [{"fn": hex(f), "slot": hex(s), "name": n, "rela": rela_of(s)} for f, s, n in SIBLINGS]

    simd = {"run_mul": simd_hits(carved)}
    for va, end, _note in CALLEES:
        simd[hex(va)] = simd_hits(read_va(data, segs, va, end - va))

    want_emu = bool(run_emu)
    do_emu = want_emu and unicorn_available()
    vectors_out = {}
    for name, (inp, gas, limit, kind, expect) in sorted(VECTORS.items()):
        entry = {"input_hex": inp.hex(), "gas_cost": gas, "gas_limit": limit,
                 "expected_kind": kind, "expected": expect}
        if kind == "ok":
            pt = (int.from_bytes(inp[0:32], "big"), int.from_bytes(inp[32:64], "big"))
            entry["reference_hex"] = enc(*ref_mul(pt, int.from_bytes(inp[64:96], "big"))).hex()
            entry["reference_match"] = entry["reference_hex"] == expect
        if do_emu:
            r = emulate(data, segs, rela, inp, gas, limit, allow_execution=allow_execution)
            entry["emu"] = r
            if kind == "ok":
                entry["emulated_match"] = (r["returned"] and r["kind"] == "ok" and r["output_hex"] == expect
                                           and r["len"] == 0x40 and r["gas_used"] == gas
                                           and r["allocs"] == [{"ret": hex(MALLOC_RET), "size": MALLOC_SIZE}])
            else:
                entry["emulated_match"] = (r["returned"] and r["kind"] == "err"
                                           and r["err_payload_hex"] == expect and r["allocs"] == [])
        elif want_emu:
            entry["emulated_skipped"] = True
        vectors_out[name] = entry

    return {
        "abi": {
            "rdi": "out: 40-byte Result<PrecompileOutput, PrecompileError>",
            "rsi": "input pointer", "rdx": "input length",
            "rcx": "gas cost (40000 Byzantium / 6000 Istanbul, set by wrapper)",
            "r8": "gas limit",
            "ok_layout": "[0] bytes vtable, [8] data ptr, [0x10] len 0x40, [0x18] tagged data, [0x20] gas_used",
            "err_layout": "[0..0x10] zero, [0x10..0x28] error payload",
            "emulated_with": "malloc 0x54c06b0 stubbed (bump allocator); RELATIVE relocations applied",
        },
        "alloc": {
            "malloc_va": hex(MALLOC), "malloc_slot": hex(MALLOC_SLOT),
            "malloc_slot_rela": rela_of(MALLOC_SLOT),
            "call_va": hex(MALLOC_CALL), "return_va": hex(MALLOC_RET), "size": MALLOC_SIZE,
            "stub": "UC_HOOK_CODE at 0x54c06b0: rax = bump pointer (heap 0x70000000, 16-byte steps), pop return address, jump to it",
            "memcpy_slot": hex(MEMCPY_SLOT), "memcpy_call_va": hex(MEMCPY_CALL),
            "memcpy_slot_rela_type": (rela_by_off[MEMCPY_SLOT][1] & 0xFFFFFFFF) if MEMCPY_SLOT in rela_by_off else None,
            "alloc_err_call_va": hex(ALLOC_ERR_CALL),
            "alloc_err_slot_rela": rela_of(ALLOC_ERR_SLOT),
            "bytes_vtable_slots": [rela_of(s) for s in BYTES_VTABLE_SLOTS],
        },
        "binary_sha256": BINARY_SHA256,
        "branches": branches,
        "branches_match": branches == branches_expected,
        "callees": [{"va": hex(a), "fde_end": hex(b), "note": n} for a, b, n in CALLEES],
        "carved_end_exclusive": hex(FN_END),
        "carved_len": len(carved),
        "carved_sha256": hashlib.sha256(carved).hexdigest(),
        "carved_start": hex(FN),
        "direct_e8_e9_to_fn": direct_calls(text, FN),
        "emu_ran": do_emu,
        "emu_skipped": want_emu and not do_emu,
        "extent": extent,
        "field": field,
        "fn": hex(FN),
        "fn_ret": hex(FN_RET),
        "fqmul_slot_rela": rela_of(FQMUL_SLOT),
        "got_rela": rela_of(GOT_SLOT),
        "got_slot": hex(GOT_SLOT),
        "got_slot_refs": {"by_kind": ref_counts, "total": len(refs),
                          "vas": [kind + "@" + hex(va) for kind, va in refs]},
        "key_bytes": key_bytes,
        "key_insns_count": len(key_bytes),
        "siblings": siblings,
        "simd_scan": simd,
        "vector_source": "go-ethereum core/vm/testdata/precompiles/bn256ScalarMul.json @ 918aed4e314f1db27191c0b0611ff02d3759122c",
        "vectors": vectors_out,
        "wrappers": wrappers,
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
    x = result["extent"]
    if not (x["primary_ret_byte"] == "c3" and x["padding_all_int3"]):
        errs.append("extent mismatch")
    if C3_OFFSETS is not None and x["c3_offsets_in_carve"] != C3_OFFSETS:
        errs.append("c3 byte offsets mismatch")
    f = result["field"]
    if not (f["p_from_bn_u"] and f["r_from_bn_u"] and f["inv_check"] and f["inv_r_check"]):
        errs.append("field derivation failed")
    for k, want in FIELD_COUNTS.items():
        if f[k] != want:
            errs.append(k + " mismatch")
    want_rela = {"r_offset": hex(GOT_SLOT), "r_info": hex(R_X86_64_RELATIVE), "r_addend": hex(FN)}
    if result["got_rela"] != want_rela:
        errs.append("GOT RELA mismatch")
    if result["fqmul_slot_rela"] != {"r_offset": hex(FQMUL_SLOT), "r_info": hex(R_X86_64_RELATIVE), "r_addend": hex(FQMUL)}:
        errs.append("Fq mul slot RELA mismatch")
    if result["got_slot_refs"]["by_kind"] != SLOT_REFS_EXPECTED:
        errs.append("GOT slot ref counts mismatch")
    if result["got_slot_refs"]["vas"] != ["call@" + hex(w[1]) for w in WRAPPERS]:
        errs.append("GOT slot ref sites mismatch")
    if result["direct_e8_e9_to_fn"] != 0:
        errs.append("unexpected direct e8/e9 to fn")
    for w in result["wrappers"]:
        if not w["match"]:
            errs.append("wrapper mismatch at " + w["wrapper"])
    a = result["alloc"]
    if a["malloc_slot_rela"] != {"r_offset": hex(MALLOC_SLOT), "r_info": hex(R_X86_64_RELATIVE), "r_addend": hex(MALLOC)}:
        errs.append("malloc slot RELA mismatch")
    if a["memcpy_slot_rela_type"] != R_X86_64_GLOB_DAT:
        errs.append("memcpy slot not GLOB_DAT")
    for name, s in result["simd_scan"].items():
        if any(s.values()):
            errs.append("SIMD/feature pattern in " + name)
    for name, (_i, _g, _l, kind, expect) in VECTORS.items():
        v = result["vectors"][name]
        if v["expected"] != expect or v["expected_kind"] != kind:
            errs.append(name + " vector drift")
        if kind == "ok" and not v["reference_match"]:
            errs.append(name + " reference mismatch")
        if result["emu_ran"] and not v.get("emulated_match"):
            errs.append(name + " emu mismatch")
    return errs


def render(result):
    return json.dumps(result, sort_keys=True, indent=2) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--emulate", action="store_true",
                      help="explicit opt-in to bounded captured-code execution; requires prior authorization")
    mode.add_argument("--no-emu", action="store_true", help="static only (the default)")
    ap.add_argument("-o", "--output", type=Path, help="write JSON to path")
    args = ap.parse_args(argv)
    result = analyse(TARGET.read_bytes(), run_emu=args.emulate, allow_execution=args.emulate)
    text = render(result)
    errors = expectation_errors(result)
    for e in errors:
        print("FAIL", e, file=sys.stderr)
    # Completed comparison records remain useful evidence even when mismatched.
    # Preserve the raw record and signal failure separately through the exit code.
    if args.output:
        with args.output.open("x") as handle:
            handle.write(text)
    else:
        sys.stdout.write(text)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
