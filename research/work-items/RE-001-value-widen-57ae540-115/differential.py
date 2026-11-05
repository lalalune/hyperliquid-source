"""Unicorn differential for the RE-001-value-widen-57ae540-115
packet: run the real 258-byte body at 0x57ae540 in emulation
and compare the output slot and the rax residue against
tools/value_widen_57ae540.py on directed and randomized inputs.

Usage (from the repository root), with a Python that has the
unicorn package (the committed pure tests need only the
standard library; this differential is the lane-side check
whose recorded result is in the packet README):

    python3 research/work-items/RE-001-value-widen-57ae540-115/differential.py

The work binary must be materialized first (rm any LFS
pointer/symlink at work/hl-node-115.bin, then copy the
canonical artifact there as a regular file); its SHA-256 is
checked before any emulation.  Only two pages of the binary
are mapped: the page holding the body and the page holding
the jump table at 0x931abc, both copied verbatim.  Input and
output slots live in scratch pages; the input slot must come
back byte-identical and the output slot past byte 24 must
keep its sentinel fill.
"""

import hashlib
import random
import struct
import sys
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]
BINARY = ROOT / "work" / "hl-node-115.bin"
DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

sys.path.insert(0, str(ROOT))
from tools.value_widen_57ae540 import widen  # noqa: E402

from unicorn import Uc, UC_ARCH_X86, UC_MODE_64  # noqa: E402
from unicorn.x86_const import (  # noqa: E402
    UC_X86_REG_RAX, UC_X86_REG_RDI, UC_X86_REG_RIP,
    UC_X86_REG_RSI, UC_X86_REG_RSP,
)

BODY = 0x57AE540
BODY_PAGE = 0x57AE000
TABLE_PAGE = 0x931000
IN_ADDR = 0x70000000
OUT_ADDR = 0x70010000
STACK_ADDR = 0x70100000
RET_ADDR = 0x70200000
PAGE = 0x1000


def voff(data, vaddr):
    e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
    e_phentsize, e_phnum = struct.unpack_from("<HH", data, 0x36)
    for i in range(e_phnum):
        p_type, _, p_offset, p_vaddr, _, p_filesz, _, _ = \
            struct.unpack_from(
                "<IIQQQQII", data, e_phoff + i * e_phentsize)
        if p_type == 1 and p_vaddr <= vaddr < p_vaddr + p_filesz:
            return vaddr - p_vaddr + p_offset
    raise ValueError("vaddr %#x not in any LOAD" % vaddr)


def run_one(data, inp, fill):
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    uc.mem_map(BODY_PAGE, PAGE)
    uc.mem_write(BODY_PAGE, data[voff(data, BODY_PAGE):
                                 voff(data, BODY_PAGE) + PAGE])
    uc.mem_map(TABLE_PAGE, PAGE)
    uc.mem_write(TABLE_PAGE, data[voff(data, TABLE_PAGE):
                                   voff(data, TABLE_PAGE) + PAGE])
    uc.mem_map(IN_ADDR, PAGE)
    uc.mem_map(OUT_ADDR, PAGE)
    uc.mem_map(STACK_ADDR, PAGE)
    uc.mem_map(RET_ADDR, PAGE)
    uc.mem_write(IN_ADDR, bytes(inp) + bytes(64 - len(inp)))
    uc.mem_write(OUT_ADDR, bytes([fill] * 64))
    rsp = STACK_ADDR + PAGE - 0x100
    uc.mem_write(rsp, struct.pack("<Q", RET_ADDR))
    uc.reg_write(UC_X86_REG_RSP, rsp)
    uc.reg_write(UC_X86_REG_RDI, OUT_ADDR)
    uc.reg_write(UC_X86_REG_RSI, IN_ADDR)
    uc.emu_start(BODY, RET_ADDR, count=64)
    if uc.reg_read(UC_X86_REG_RIP) != RET_ADDR:
        raise AssertionError("did not return to the sentinel address")
    out = uc.mem_read(OUT_ADDR, 64)
    in_after = uc.mem_read(IN_ADDR, 64)
    rax = uc.reg_read(UC_X86_REG_RAX)
    return bytes(out), bytes(in_after), rax


def directed_payloads():
    base = bytearray(32)
    yield bytes(base)
    yield bytes([0xFF] * 32)
    yield bytes(range(32))
    p = bytearray(32)
    for off in (1, 2, 4, 8, 16):
        p[off] = 0x80
    yield bytes(p)
    p = bytearray(32)
    struct.pack_into("<f", p, 4, float("nan"))
    struct.pack_into("<d", p, 8, float("inf"))
    yield bytes(p)
    p = bytearray(32)
    struct.pack_into("<I", p, 4, 0x7FC0BEEF)   # f32 qNaN payload
    struct.pack_into("<I", p, 4 + 20, 0x7F800001)  # f32 sNaN in tail window
    yield bytes(p)
    p = bytearray(32)
    struct.pack_into("<f", p, 4, -0.0)
    struct.pack_into("<d", p, 8, -0.0)
    yield bytes(p)
    p = bytearray(32)
    struct.pack_into("<i", p, 4, -2147483648)
    struct.pack_into("<Q", p, 8, 0xFFFFFFFFFFFFFFFF)
    yield bytes(p)


def main():
    data = BINARY.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != DIGEST:
        raise SystemExit("work binary digest mismatch: %s" % digest)
    rng = random.Random(0x57AE540)
    runs = 0
    for tag in range(22):
        payloads = list(directed_payloads())
        payloads += [bytes(rng.randrange(256) for _ in range(32))
                     for _ in range(500)]
        for payload in payloads:
            inp = bytearray(payload)
            inp[0] = tag
            fill = 0xA5
            out, in_after, rax = run_one(data, bytes(inp), fill)
            model_out = bytearray([fill] * 24)
            model_rax = widen(bytes(inp), model_out)
            if out[:24] != bytes(model_out):
                raise AssertionError(
                    "tag %d payload %s: binary out %s != model %s"
                    % (tag, bytes(inp).hex(), out[:24].hex(),
                       bytes(model_out).hex()))
            if out[24:] != bytes([fill] * 40):
                raise AssertionError(
                    "tag %d: bytes past the 24-byte output slot written"
                    % tag)
            if in_after != bytes(inp) + bytes(32):
                raise AssertionError("tag %d: input slot mutated" % tag)
            if rax != model_rax:
                raise AssertionError(
                    "tag %d payload %s: rax %#x != model %#x"
                    % (tag, bytes(inp).hex(), rax, model_rax))
            runs += 1
    print("%d differential runs, 0 mismatches" % runs)
    return 0


if __name__ == "__main__":
    sys.exit(main())
