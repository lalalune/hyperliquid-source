#!/usr/bin/env python3
"""RE-026: bn254 ecAdd (EVM precompile 0x06, EIP-196) at 0x4e96610 (node #94).

Standalone. From the pinned node #94 binary only, it recovers:
  * run_add entry 0x4e96610 (FDE 0x4e96610..0x4e96cee, the whole FDE is the
    sha256-pinned carve; ret at 0x4e967eb, alloc-error tail call at 0x4e96ce8);
  * ABI: rdi=out (40-byte result), rsi/rdx=input ptr/len, rcx=gas cost,
    r8=gas limit (revm-precompile 16.0.0 bn128.rs run_add);
  * identity: the bn254 base-field modulus p as four movabs limbs inside
    run_add, checked against p = 36u^4+36u^3+24u^2+6u+1 (u = 4965661367192848881),
    the Montgomery constant -p^-1 mod 2^128 (0x9ede7d651eca6ac9:0x87d20782e4866389),
    R mod p limbs in run_add and R^2 mod p limbs in the point decoder 0x4e961e0;
  * wiring: R_X86_64_RELATIVE addend 0x4e96610 at GOT slot 0x5776f00, exactly
    2 ff15 calls to the slot (gas wrappers 0x4e98a40 = 150 Istanbul and
    0x4e98ad0 = 500 Byzantium), 0 direct e8/e9 calls, and the precompile table
    objects 0x574f020 / 0x574f0e0 whose RELA addends are those wrappers and
    whose Address field (+0x10) is 0x..06;
  * selected opcode-pattern counts in the listed bodies, not absence of SIMD
    (these bodies contain XMM instructions) or complete feature-dispatch closure;
  * the only external call on the success path is malloc(0x40) at 0x4e96c5c
    through GOT 0x576dfd8 (RELA -> jemalloc malloc 0x54c06b0), stubbed in the
    emulation as a bump allocator;
  * module Location 0x574f258 (bn128.rs:169) referenced from run_pair, not
    run_add: string+shape evidence only;
  * optional, separately authorized Unicorn comparison on fixed vectors. The
    original recorded emulator JSON remains historical until reproduced.

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

FN = 0x4E96610
FN_END = 0x4E96CEE  # FDE end, exclusive; carve is the whole FDE
FN_RET = 0x4E967EB
CARVED_LEN = FN_END - FN
CARVED_SHA256 = "89f39d1b63955c1db57a998837ca6f826d190682a1c6ad8db722e37f707bad39"

DECODER = 0x4E961E0  # G1 point decoder (FDE 0x4e961e0..0x4e9660f)
DECODER_END = 0x4E9660F
# Callees on the run_add path, with their FDE extents (for the SIMD scan).
CALLEES = [
    (0x4E961E0, 0x4E9660F, "G1 point decode"),
    (0x4F1B0F0, 0x4F1BF31, "projective add"),
    (0x4F160C0, 0x4F164D5, "is-zero / to-affine helper"),
    (0x4F168D0, 0x4F16B7A, "decoder curve check"),
    (0x4F1F9C0, 0x4F1FF86, "Fq Montgomery mul (via GOT 0x5776ef8)"),
]

P = 0x30644E72E131A029B85045B68181585D97816A916871CA8D3C208C16D87CFD47
BN_U = 4965661367192848881
P_LIMBS = [(P >> (64 * i)) & (2**64 - 1) for i in range(4)]
INV128 = (-pow(P, -1, 2**128)) % 2**128
R_MOD_P = 2**256 % P
R2_MOD_P = 2**512 % P

GOT_SLOT = 0x5776F00
R_X86_64_RELATIVE = 8
R_X86_64_GLOB_DAT = 6
TEXT_LOAD_VA = 0x1343C80
SLOT_REFS_EXPECTED = {"call": 2, "jmp": 0, "mov": 0}
FQMUL_SLOT = 0x5776EF8
FQMUL = 0x4F1F9C0

# (wrapper VA, call VA, gas imm, precompile table slot, fork)
WRAPPERS = [
    (0x4E98A40, 0x4E98A57, 150, 0x574F020, "Istanbul"),
    (0x4E98AD0, 0x4E98AE7, 500, 0x574F0E0, "Byzantium"),
]
# Precompile object layout (0x30 stride, Address at +0x10) as described in #550.
PRECOMPILE_ADDRESS = "00" * 19 + "06"
# Sibling bn128 entries (context only, static): (fn, GOT slot)
SIBLINGS = [(0x4E96CF0, 0x5776F08, "run_mul"), (0x4E973E0, 0x5776F10, "run_pair")]

MALLOC = 0x54C06B0
MALLOC_SLOT = 0x576DFD8
MALLOC_CALL = 0x4E96C5C
MALLOC_RET = MALLOC_CALL + 6
MALLOC_SIZE = 0x40
MEMCPY_SLOT = 0x576DFE0  # GLOB_DAT memcpy, used only for input len < 0x80
MEMCPY_CALL = 0x4E96686
ALLOC_ERR_SLOT = 0x576DFB8
ALLOC_ERR_CALL = 0x4E96CE8
BYTES_VTABLE_SLOTS = (0x576E140, 0x576E148)

LOCATION = 0x574F258
LOCATION_LEAS = [0x4E989A3, 0x4E989B0]  # inside run_pair FDE 0x4e973e0..0x4e98a3f
LOCATION_LINE, LOCATION_COL = 169, 20
LOCATION_PATH_VA = 0x1FEB5E
LOCATION_PATH_LEN = 101
LOCATION_PATH_SHA256 = "a36d5efeadaf197094d34d1742918772b052f93db555af81e21e1369194c874d"
LOCATION_PATH_SUFFIX = "revm-precompile-16.0.0/src/bn128.rs"

# TOKEN rule: printed as key_insns, never the banned equals-form.
KEY_INSNS = [
    (0x4E96610, "554157415641554154534881eca8020000", "push rbp..rbx; sub rsp,0x2a8"),
    (0x4E96621, "4889fb4c39c17613", "mov rbx,rdi; cmp rcx,r8; jbe (gas ok)"),
    (0x4E96629, "48b80000000000000080", "movabs rax,0x8000000000000000 (OutOfGas)"),
    (0x4E9663C, "4883fa7f", "cmp rdx,0x7f (input >= 128 bytes?)"),
    (0x4E96686, "ff1554798d00", "call *[rip] -> GOT 0x576dfe0 memcpy (short input)"),
    (0x4E9671E, "e8bdfaffff", "call decoder 0x4e961e0 (point 1)"),
    (0x4E967A4, "e837faffff", "call decoder 0x4e961e0 (point 2)"),
    (0x4E967EB, "c3", "ret"),
    (0x4E968CD, "e81e480800", "call 0x4f1b0f0 (add)"),
    (0x4E968D8, "e8e3f70700", "call 0x4f160c0"),
    (0x4E9694E, "48b88dca7168916a8197", "movabs p limb1"),
    (0x4E9695D, "48b847fd7cd8168c203c", "movabs p limb0"),
    (0x4E9696B, "49bd29a031e1724e6430", "movabs p limb3"),
    (0x4E9697A, "48bd5d588181b64550b8", "movabs p limb2"),
    (0x4E96989, "4c8b2568058e00", "mov r12,[rip] -> GOT 0x5776ef8 (Fq mul)"),
    (0x4E969A3, "49be896386e48207d287", "movabs Montgomery inv lo"),
    (0x4E969AD, "49bfc96aca1e657dde9e", "movabs Montgomery inv hi"),
    (0x4E969BD, "41ffd4", "call r12 (Fq mul)"),
    (0x4E96C57, "bf40000000", "mov edi,0x40 (alloc size)"),
    (0x4E96C5C, "ff1576738d00", "call *[rip] -> GOT 0x576dfd8 malloc"),
    (0x4E96CBE, "48c7431040000000", "out.len = 0x40"),
    (0x4E96CCD, "488b8424e8000000", "reload gas cost"),
    (0x4E96CD5, "48894320", "out.gas_used = gas cost"),
    (0x4E96CE8, "ff15ca728d00", "call *[rip] -> GOT 0x576dfb8 alloc error"),
    (0x4E98A4F, "b996000000", "wrapper ecx = 150"),
    (0x4E98A57, "ff15a3e48d00", "wrapper call *[rip] -> GOT 0x5776f00"),
    (0x4E98ADF, "b9f4010000", "wrapper ecx = 500"),
    (0x4E98AE7, "ff1513e48d00", "wrapper call *[rip] -> GOT 0x5776f00"),
    (0x54C06B0, "f30f1efa4881ff00100000", "malloc: endbr64; cmp rdi,0x1000 (stubbed)"),
]

G = (1, 2)
TWO_G = (0x030644E72E131A029B85045B68181585D97816A916871CA8D3C208C16D87CFD3,
         0x15ED738C0E0A7C92E7845F96B2AE9C0A68A6A449E3538FC7FF3EBF7A5A18A2C4)


def enc(*xs):
    return b"".join(x.to_bytes(32, "big") for x in xs)


ZERO64 = "00" * 64
# Historical zero-initialized harness snapshots at out+0x10 (24 bytes).
# Only the first qword is the selected raw error tag. In particular OutOfGas
# leaves out+0x18..0x28 unchanged; trailing zero bytes are not initialized ABI.
# Variant order matches upstream PrecompileError: 0 OutOfGas,
# 6 Bn128FieldPointNotAMember, 7 Bn128AffineGFailedToCreate.
ERR_OOG = struct.pack("<Q", 0x8000000000000000).hex() + "00" * 16
ERR_FIELD = struct.pack("<Q", 0x8000000000000006).hex() + "00" * 16
ERR_AFFINE = struct.pack("<Q", 0x8000000000000007).hex() + "00" * 16
# name -> (input, gas cost, gas limit, expected kind, expected output hex or error payload)
VECTORS = {
    "g_plus_g": (enc(1, 2, 1, 2), 150, 1000, "ok", enc(*TWO_G).hex()),
    "neg_p_infinity": (enc(1, 2, 1, P - 2), 150, 1000, "ok", ZERO64),
    "zero_input": (bytes(128), 150, 1000, "ok", ZERO64),
    "off_curve": (enc(1, 3, 1, 2), 150, 1000, "err", ERR_AFFINE),
    "x_not_in_field": (enc(P, 0, 1, 2), 150, 1000, "err", ERR_FIELD),
    "out_of_gas": (enc(1, 2, 1, 2), 150, 149, "err", ERR_OOG),
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
    """Raw encoding candidates, including the final fitting byte offset.

    This remains an unaligned byte scan; native decoding validates actual sites.
    """
    refs = []
    for prefix, kind, size, displacement in [(b"\xff\x15","call",6,2),
                                             (b"\xff\x25","jmp",6,2),
                                             (b"\x48\x8b","mov",7,3),
                                             (b"\x4c\x8b","mov",7,3)]:
        i = text.find(prefix)
        while i >= 0:
            if i + size <= len(text) and (kind != "mov" or text[i + 2] & 0xC7 == 0x05):
                if TEXT_LOAD_VA + i + size + struct.unpack_from("<i", text, i + displacement)[0] == slot:
                    refs.append((kind, TEXT_LOAD_VA + i))
            i = text.find(prefix, i + 1)
    return sorted(refs, key=lambda item: item[1])


def direct_calls(text, target):
    n = 0
    for prefix in (b"\xe8", b"\xe9"):
        i = text.find(prefix)
        while i >= 0:
            if i + 5 <= len(text) and TEXT_LOAD_VA + i + 5 + struct.unpack_from("<i", text, i + 1)[0] == target:
                n += 1
            i = text.find(prefix, i + 1)
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
STUB_HEAP_STEP = 0x40  # bump step; every allocation is 16-byte aligned

# Actual FDEs authenticated in the review packet. Error/unwind/import paths are
# outside this allowlist; encountering one fails the bounded comparison.
EXECUTION_RANGES = (
    (FN, FN_END), (DECODER, DECODER_END),
    (0x4F1B0F0, 0x4F1BF31), (0x4F160C0, 0x4F164D5),
    (0x4F168D0, 0x4F16B7A), (0x4F1F9C0, 0x4F1FF86),
    (0x4F1DEA0, 0x4F1E70C), (0x4F1F8E0, 0x4F1F9B1),
    (0x4F20020, 0x4F200E3), (0x4F200F0, 0x4F206EA),
)

# Only the two original, separately authorized negative experiments. These
# hashes cover the entire ELF, not just the changed instruction or an allowlist
# of unchecked offsets: combining either change with anything else is rejected.
EMULATION_INPUT_SHA256 = frozenset((
    BINARY_SHA256,
    "3d64ad390742cc3d0859ace9cdc1da76a83d73a14101a80e7be424953bc77d12",  # VA 0x4e9696d: 29 -> 28
    "52079b92d958c0f645280503cdfe7b06b9b584d6ce04262eb96532cec752a07c",  # VA 0x4e96cc2: 40 -> 41
))


def validate_run(data, segs, rela, inp, gas, limit, stub, allow_execution):
    """Authenticate code and mapping metadata before importing the backend."""
    if allow_execution is not True:
        raise ValueError("captured-code emulation requires explicit authorization and opt-in")
    if not isinstance(inp, bytes) or len(inp) != 128 or any(
            type(v) is not int or not 0 <= v < 2**64 for v in (gas, limit)):
        raise ValueError("bounded harness requires 128-byte input and u64 gas values")
    if type(stub) is not bool or HEAP not in (0x70000000, 0x71000000):
        raise ValueError("only the reviewed stub modes and heap placements are permitted")
    if not isinstance(data, bytes) or hashlib.sha256(data).hexdigest() not in EMULATION_INPUT_SHA256:
        raise ValueError("emulation requires authenticated node94 or one exact reviewed mutation")
    if segs != segments(data) or rela != rela_dyn(data):
        raise ValueError("mapping/relocation metadata must match the authenticated ELF")


def validate_result(q, allocs, gas):
    """Validate the target-grounded header before reading any guest pointer."""
    if q[0] == 0:
        if q[1] != 0 or allocs or q[2] not in ((1 << 63), (1 << 63) | 6, (1 << 63) | 7):
            raise ValueError("invalid error result header or unexpected allocation")
        # Error-path trailing bytes can be uninitialized; they remain a raw
        # snapshot, not a claimed initialized part of the native error ABI.
    elif q != (0x5670AE8, HEAP, MALLOC_SIZE, HEAP | 1, gas) or allocs != [
            {"ret": hex(MALLOC_RET), "size": MALLOC_SIZE}]:
        raise ValueError("result escaped the reviewed allocation/header contract")


def checked_span(address, size, base, length, label):
    if size <= 0 or not base <= address <= base + length - size:
        raise ValueError(label + " outside synthetic memory")


def malloc_request(sp, ret, request, bump, stack, heap):
    """Validate host callback inputs before producing a synthetic allocation."""
    checked_span(sp, 8, stack, 0x100000, "malloc stack")
    if ret != MALLOC_RET or request != MALLOC_SIZE:
        raise ValueError("unexpected malloc call site or size")
    checked_span(bump, MALLOC_SIZE, heap, 0x10000, "malloc heap")
    if bump % 16:
        raise ValueError("unaligned malloc heap")
    return bump + MALLOC_SIZE


def emulate(data, segs, rela, inp: bytes, gas: int, limit: int, stub=True,
            *, allow_execution=False):
    """Run run_add; malloc 0x54c06b0 replaced by a bump allocator. Returns dict."""
    validate_run(data, segs, rela, inp, gas, limit, stub, allow_execution)
    from crypto_emulation_guard import run_bounded
    from unicorn import UC_ARCH_X86, UC_HOOK_CODE, UC_MODE_64, UC_PROT_ALL, Uc, UcError
    from unicorn.x86_const import (UC_X86_REG_FS_BASE, UC_X86_REG_R8, UC_X86_REG_RAX,
                                   UC_X86_REG_RCX, UC_X86_REG_RDI, UC_X86_REG_RDX,
                                   UC_X86_REG_RIP, UC_X86_REG_RSI, UC_X86_REG_RSP)

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
    relocs = 0
    for r_offset, r_info, r_addend in rela:
        if r_info & 0xFFFFFFFF == R_X86_64_RELATIVE:
            mu.mem_write(r_offset, struct.pack("<Q", r_addend))
            relocs += 1

    STACK, IO, STOP, TLS = 0x7FFF00000000, 0x60000000, 0x600000000, 0x7F0000000000
    map_span(STACK, 0x100000)
    map_span(IO, 0x10000)
    map_span(HEAP, 0x10000)
    map_span(STOP, 0x1000)
    map_span(TLS, 0x2000)
    mu.reg_write(UC_X86_REG_FS_BASE, TLS + 0x1000)
    mu.mem_write(STOP, b"\xf4")
    OUT, INP = IO + 0x100, IO + 0x1000
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
    bump = [HEAP]

    def on_malloc(uc, address, size, _user):
        sp = uc.reg_read(UC_X86_REG_RSP)
        checked_span(sp, 8, STACK, 0x100000, "malloc stack")
        if sp % 8 or allocs:
            raise ValueError("malloc requires one aligned return slot and a single allocation")
        ret = struct.unpack("<Q", uc.mem_read(sp, 8))[0]
        req = uc.reg_read(UC_X86_REG_RDI)
        next_bump = malloc_request(sp, ret, req, bump[0], STACK, HEAP)
        allocs.append({"ret": hex(ret), "size": req})
        p = bump[0]
        bump[0] = next_bump
        uc.reg_write(UC_X86_REG_RAX, p)
        uc.reg_write(UC_X86_REG_RSP, sp + 8)
        uc.reg_write(UC_X86_REG_RIP, ret)

    malloc_hook = mu.hook_add(UC_HOOK_CODE, on_malloc, begin=MALLOC, end=MALLOC) if stub else None
    fault = None
    try:
        run_bounded(mu, FN, STOP,
                    code_ranges=EXECUTION_RANGES + ((MALLOC, MALLOC + 4),),
                    writable_ranges=((STACK, STACK + 0x100000),
                                     (OUT, OUT + 0x28), (HEAP, HEAP + MALLOC_SIZE)),
                    timeout=60_000_000, count=50_000_000)
    except (UcError, ValueError) as e:
        fault = str(e)
    finally:
        if malloc_hook is not None:
            mu.hook_del(malloc_hook)
    rip = mu.reg_read(UC_X86_REG_RIP)
    out = bytes(mu.mem_read(OUT, 0x28))
    q = struct.unpack("<5Q", out)
    if fault is None:
        try:
            if rip != STOP:
                raise ValueError("emulation stopped before the return sentinel")
            validate_result(q, allocs, gas)
        except ValueError as e:
            fault = str(e)
    res = {"allocs": allocs, "fault": fault, "relocs_applied": relocs,
           "returned": fault is None and rip == STOP, "out_hex": out.hex()}
    if q[0] != 0:  # Ok(PrecompileOutput{bytes, gas_used})
        res["kind"] = "ok"
        res["vtable"] = hex(q[0])
        res["data_ptr"] = hex(q[1])
        res["len"] = q[2]
        res["gas_used"] = q[4]
        # Failed/incomplete runs retain the raw header and diagnostic but never
        # expose a pointer-derived output as a successful comparison candidate.
        res["output_hex"] = bytes(mu.mem_read(q[1], q[2])).hex() if res["returned"] else None
    else:
        res["kind"] = "err"
        res["err_payload_hex"] = out[0x10:0x28].hex()
    return res


def analyse(data, check_sha=True, run_emu=False):
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
        "decoder_call_1": hex(rel32_target(0x4E9671E, 5, 1)),
        "decoder_call_2": hex(rel32_target(0x4E967A4, 5, 1)),
        "add_call": hex(rel32_target(0x4E968CD, 5, 1)),
        "helper_call": hex(rel32_target(0x4E968D8, 5, 1)),
        "fqmul_slot_load": hex(rel32_target(0x4E96989, 7, 3)),
        "memcpy_call_slot": hex(rel32_target(MEMCPY_CALL, 6, 2)),
        "malloc_call_slot": hex(rel32_target(MALLOC_CALL, 6, 2)),
        "alloc_err_call_slot": hex(rel32_target(ALLOC_ERR_CALL, 6, 2)),
        "wrapper_istanbul_call_slot": hex(rel32_target(WRAPPERS[0][1], 6, 2)),
        "wrapper_byzantium_call_slot": hex(rel32_target(WRAPPERS[1][1], 6, 2)),
    }
    branches_expected = {
        "decoder_call_1": hex(DECODER), "decoder_call_2": hex(DECODER),
        "add_call": hex(0x4F1B0F0), "helper_call": hex(0x4F160C0),
        "fqmul_slot_load": hex(FQMUL_SLOT), "memcpy_call_slot": hex(MEMCPY_SLOT),
        "malloc_call_slot": hex(MALLOC_SLOT), "alloc_err_call_slot": hex(ALLOC_ERR_SLOT),
        "wrapper_istanbul_call_slot": hex(GOT_SLOT), "wrapper_byzantium_call_slot": hex(GOT_SLOT),
    }

    # Field identity: p limbs, Montgomery inv, R, R^2 as imm64 bytes.
    def imm_count(code, v):
        return code.count(struct.pack("<Q", v))

    decoder = read_va(data, segs, DECODER, DECODER_END - DECODER)
    field = {
        "p_hex": hex(P),
        "p_from_bn_u": 36 * BN_U**4 + 36 * BN_U**3 + 24 * BN_U**2 + 6 * BN_U + 1 == P,
        "p_limbs_in_run_add": [imm_count(carved, v) for v in P_LIMBS],
        "inv128_hex": hex(INV128),
        "inv_limbs_in_run_add": [imm_count(carved, (INV128 >> (64 * i)) & (2**64 - 1)) for i in range(2)],
        "inv_check": (P * INV128 + 1) % 2**128 == 0,
        "r_limbs_in_run_add": [imm_count(carved, (R_MOD_P >> (64 * i)) & (2**64 - 1)) for i in range(4)],
        "r2_limbs_in_decoder": [imm_count(decoder, (R2_MOD_P >> (64 * i)) & (2**64 - 1)) for i in range(4)],
        "p_limbs_in_decoder": [imm_count(decoder, v) for v in P_LIMBS],
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

    simd = {"run_add": simd_hits(carved)}
    for va, end, _note in CALLEES:
        simd[hex(va)] = simd_hits(read_va(data, segs, va, end - va))

    loc_raw = read_va(data, segs, LOCATION, 24)
    plen, l_line, l_col = struct.unpack_from("<QII", loc_raw, 8)
    lr = rela_by_off.get(LOCATION)
    path_raw = read_va(data, segs, LOCATION_PATH_VA, LOCATION_PATH_LEN)
    loc_sha = hashlib.sha256(path_raw).hexdigest()
    location = {
        "va": hex(LOCATION),
        "path_ptr_rela_addend": hex(lr[2]) if lr else None,
        "path_len": plen, "line": l_line, "col": l_col,
        "lea_vas": [hex(v) for v in LOCATION_LEAS],
        "lea_targets": [hex(rel32_target(v, 7, 3)) for v in LOCATION_LEAS],
        "lea_in_run_pair_fde": all(0x4E973E0 <= v < 0x4E98A3F for v in LOCATION_LEAS),
        "lea_in_run_add_carve": any(FN <= v < FN_END for v in LOCATION_LEAS),
        "path_sha256": loc_sha,
        "path_suffix": LOCATION_PATH_SUFFIX,
    }
    location["match"] = (bool(lr) and lr[2] == LOCATION_PATH_VA and plen == LOCATION_PATH_LEN
                         and (l_line, l_col) == (LOCATION_LINE, LOCATION_COL)
                         and location["lea_targets"] == [hex(LOCATION)] * 2
                         and loc_sha == LOCATION_PATH_SHA256
                         and path_raw.decode("ascii", errors="replace").endswith(LOCATION_PATH_SUFFIX))

    want_emu = bool(run_emu)
    do_emu = want_emu and unicorn_available()
    vectors_out = {}
    for name, (inp, gas, limit, kind, expect) in sorted(VECTORS.items()):
        entry = {"input_hex": inp.hex(), "gas_cost": gas, "gas_limit": limit,
                 "expected_kind": kind, "expected": expect}
        if kind == "ok":
            pts = [tuple(int.from_bytes(inp[i : i + 32], "big") for i in (o, o + 32)) for o in (0, 64)]
            entry["reference_hex"] = enc(*ref_add(*pts)).hex()
            entry["reference_match"] = entry["reference_hex"] == expect
        if do_emu:
            r = emulate(data, segs, rela, inp, gas, limit, allow_execution=True)
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
            "rcx": "gas cost (150 Istanbul / 500 Byzantium, set by wrapper)",
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
            "memcpy_slot": hex(MEMCPY_SLOT),
            "memcpy_slot_rela_type": (rela_by_off[MEMCPY_SLOT][1] & 0xFFFFFFFF) if MEMCPY_SLOT in rela_by_off else None,
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
        "location": location,
        "siblings": siblings,
        "simd_scan": simd,
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
    f = result["field"]
    if not (f["p_from_bn_u"] and f["inv_check"]):
        errs.append("field derivation failed")
    if f["p_limbs_in_run_add"] != [4, 4, 1, 3]:
        errs.append("p limbs count in run_add mismatch")
    if f["inv_limbs_in_run_add"] != [1, 1]:
        errs.append("Montgomery inv count mismatch")
    if f["r_limbs_in_run_add"] != [2, 2, 2, 2]:
        errs.append("R mod p limbs count mismatch")
    if f["r2_limbs_in_decoder"] != [2, 2, 2, 2]:
        errs.append("R^2 mod p limbs in decoder mismatch")
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
    if not result["location"]["match"] or not result["location"]["lea_in_run_pair_fde"] or result["location"]["lea_in_run_add_carve"]:
        errs.append("location mismatch")
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
    mode.add_argument("--no-emu", action="store_true", help="static only (the default)")
    mode.add_argument("--emulate", action="store_true", help="run captured-code vectors only after explicit authorization")
    ap.add_argument("-o", "--output", type=Path, help="write JSON to path")
    args = ap.parse_args(argv)
    result = analyse(TARGET.read_bytes(), run_emu=args.emulate)
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
