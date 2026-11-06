"""Unicorn differential for the RE-001-mem-mapping-destructor-d4f70-115
packet: run the real 33 bytes of routine 0x60d4f70 from the
digest-verified work binary against the Python model
(tools/mem_mapping_destructor_d4f70_115.py) over the pair's
decision space.

The routine's own bytes run natively under emulation. Its
only callee does not: the tail jump at 0x60d4f83 lands on the
munmap PLT stub at 0x63f0c00, which the harness intercepts
and answers with the same recording contract function the
model uses. That is exactly the packet's claim boundary:
0x60d4f70's own instructions -- the null guard on the
pointer word, the length load on the non-null path only,
the argument move into rdi/rsi and the tail jump itself --
are what is being differentially tested; munmap's body is
by contract only.

Per case the harness builds one window holding the pair,
runs the model on a copy and the real bytes on the original
layout under Unicorn, then compares:

  * the ordered callee event log (at most one munmap, with
    the pair's two words as its arguments);
  * the return value (0 on the null path, the munmap
    stub's answer passed through on the non-null path);
  * the whole window, byte for byte (the routine must not
    write any memory, the pair included);
  * the callee-saved registers and the stack pointer,
    which the routine must preserve.

Two cases place the pair flush against the end of the
mapped window: one with a null pointer (the length word
sits in unmapped memory and must stay unread) and one
with a non-null pointer whose length word ends exactly
at the page end (any read past +0x10 would fault).

Run with a Python that has unicorn available, from the
repository root:

    python3 research/work-items/RE-001-mem-mapping-destructor-d4f70-115/differential.py

Prints the case count and DIFFERENTIAL PASSED on success.
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

sys.path.insert(0, str(ROOT / "tools"))
from mem_mapping_destructor_d4f70_115 import (  # noqa: E402
    mem_mapping_release,
)

from unicorn import Uc, UC_ARCH_X86, UC_HOOK_CODE, UC_MODE_64  # noqa: E402
from unicorn.x86_const import (  # noqa: E402
    UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RCX, UC_X86_REG_RDX,
    UC_X86_REG_RSI, UC_X86_REG_RDI, UC_X86_REG_RBP, UC_X86_REG_RSP,
    UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_R10, UC_X86_REG_R11,
    UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15,
    UC_X86_REG_RIP,
)

ROUTINE = 0x60D4F70
ROUTINE_SIZE = 33
CODE_BASE = 0x60D4000
PLT = 0x63F0C00
PLT_PAGE = 0x63F0000

WIN_BASE, WIN_SIZE = 0x40000000, 0x1000
STACK_BASE, STACK_SIZE = 0x7F000000, 0x1000
SENTINEL = 0x90000000

PAIR = WIN_BASE + 0x100

CALLEE_SAVED = [UC_X86_REG_RBX, UC_X86_REG_RBP, UC_X86_REG_R12,
                UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15]
GP_FILL = [UC_X86_REG_RAX, UC_X86_REG_RCX, UC_X86_REG_RDX,
           UC_X86_REG_RSI, UC_X86_REG_R8, UC_X86_REG_R9,
           UC_X86_REG_R10, UC_X86_REG_R11]


class Env:
    """Recording munmap stub answering a preset result,
    shared by both sides."""

    def __init__(self, result):
        self.result = result
        self.events = []

    def munmap(self, ptr, length):
        self.events.append(("munmap", ptr, length))
        return self.result


class SliceMem:
    """Slice-addressed memory over the window image, in
    the shape the model's _rd64 helper uses. Reads and
    writes outside the pair's own window raise."""

    def __init__(self, img):
        self._img = img

    def __getitem__(self, sl):
        if sl.start < WIN_BASE or sl.stop > WIN_BASE + WIN_SIZE:
            raise AssertionError(
                "model read outside window: %#x" % sl.start)
        return bytes(self._img[sl.start - WIN_BASE:sl.stop - WIN_BASE])

    def __setitem__(self, sl, data):
        raise AssertionError("model wrote memory: %#x" % sl.start)


def run_native(code_page, plt_page, img, pair, result, reg_fill):
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    for base, size in ((CODE_BASE, 0x1000), (PLT_PAGE, 0x1000),
                       (WIN_BASE, WIN_SIZE), (STACK_BASE, STACK_SIZE),
                       (SENTINEL, 0x1000)):
        uc.mem_map(base, size)
    uc.mem_write(CODE_BASE, code_page)
    uc.mem_write(PLT_PAGE, plt_page)
    uc.mem_write(WIN_BASE, bytes(img))
    stack_top = STACK_BASE + STACK_SIZE - 0x10
    uc.mem_write(stack_top, struct.pack("<Q", SENTINEL))
    env = Env(result)

    def hook(uc_, address, size, _data):
        if address == PLT:
            ret = env.munmap(uc_.reg_read(UC_X86_REG_RDI),
                             uc_.reg_read(UC_X86_REG_RSI))
            uc_.reg_write(UC_X86_REG_RAX, ret)
            rsp = uc_.reg_read(UC_X86_REG_RSP)
            target = struct.unpack("<Q", uc_.mem_read(rsp, 8))[0]
            uc_.reg_write(UC_X86_REG_RSP, rsp + 8)
            uc_.reg_write(UC_X86_REG_RIP, target)

    uc.hook_add(UC_HOOK_CODE, hook)
    for reg, value in reg_fill.items():
        uc.reg_write(reg, value)
    uc.reg_write(UC_X86_REG_RDI, pair)
    uc.reg_write(UC_X86_REG_RSP, stack_top)
    uc.emu_start(ROUTINE, SENTINEL)
    out_img = bytearray(uc.mem_read(WIN_BASE, WIN_SIZE))
    saved = {reg: uc.reg_read(reg) for reg in CALLEE_SAVED}
    return out_img, env, uc.reg_read(UC_X86_REG_RAX), saved, \
        uc.reg_read(UC_X86_REG_RSP)


def run_case(code_page, plt_page, ptr, length, result, pair, label, rng):
    img = bytearray(rng.getrandbits(8) for _ in range(WIN_SIZE))
    img[pair - WIN_BASE:pair - WIN_BASE + 8] = \
        (ptr & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")
    if pair + 16 <= WIN_BASE + WIN_SIZE:
        img[pair - WIN_BASE + 8:pair - WIN_BASE + 16] = \
            (length & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")
    exp_env = Env(result)
    model_ret = mem_mapping_release(SliceMem(img), pair, exp_env)
    reg_fill = {reg: rng.getrandbits(64)
                for reg in CALLEE_SAVED + GP_FILL}
    act_img, act_env, act_ret, saved, rsp = run_native(
        code_page, plt_page, img, pair, result, reg_fill)
    if act_env.events != exp_env.events:
        raise AssertionError(
            "%s: event mismatch\n  native: %s\n  model:  %s"
            % (label, act_env.events, exp_env.events))
    if act_ret != model_ret:
        raise AssertionError(
            "%s: return mismatch %#x vs %#x" % (label, act_ret, model_ret))
    if act_img != img:
        diff = [i for i in range(WIN_SIZE) if act_img[i] != img[i]]
        raise AssertionError(
            "%s: window written at offsets %s"
            % (label, [hex(WIN_BASE + d) for d in diff[:8]]))
    for reg in CALLEE_SAVED:
        if saved[reg] != reg_fill[reg]:
            raise AssertionError(
                "%s: callee-saved register not preserved" % label)
    # emu_start stops after the routine's ret (or the tail
    # jump's emulated ret) has popped the sentinel, so a
    # balanced stack shows stack_top + 8.
    if rsp != STACK_BASE + STACK_SIZE - 0x10 + 8:
        raise AssertionError("%s: stack pointer not restored" % label)


def main():
    data = BINARY.read_bytes()
    if hashlib.sha256(data).hexdigest() != DIGEST:
        raise SystemExit("work binary digest mismatch")
    code_page = data[CODE_BASE - 0x1000:CODE_BASE - 0x1000 + 0x1000]
    plt_page = data[PLT_PAGE - 0x1000:PLT_PAGE - 0x1000 + 0x1000]
    routine = data[ROUTINE - 0x1000:ROUTINE - 0x1000 + ROUTINE_SIZE]
    if len(routine) != ROUTINE_SIZE or routine[:4] != bytes.fromhex(
            "f30f1efa"):
        raise SystemExit("routine bytes mismatch")
    rng = random.Random(0x60D4F70)
    results = [0, 0xFFFFFFFFFFFFFFFF, 0x1234]
    count = 0
    structured = [
        (0, 0), (0, 1), (0, 0x1000), (0, 0xFFFFFFFFFFFFFFFF),
        (0x7F0000001000, 0), (0x7F0000001000, 1),
        (0x7F0000001000, 0x1000), (0x1000, 0x8000000000000000),
        (0xDEADBEEF0000, 0xFFFFFFFFFFFFFFFF), (PAIR, 0x2000),
        (0x41414141000, 0x7FFFFFFFFFFFFFFF),
    ]
    for i, (ptr, length) in enumerate(structured):
        run_case(code_page, plt_page, ptr, length,
                 results[i % len(results)], PAIR,
                 "structured ptr=%#x len=%#x" % (ptr, length), rng)
        count += 1
    # Pair flush at the window end, length word unread on
    # the null path (it sits in unmapped memory).
    run_case(code_page, plt_page, 0, 0, 0, WIN_BASE + WIN_SIZE - 8,
             "flush null", rng)
    count += 1
    # Pair flush at the window end, length word ending
    # exactly at the page end on the non-null path.
    run_case(code_page, plt_page, 0x7F0000003000, 0x5000, 0,
             WIN_BASE + WIN_SIZE - 16, "flush non-null", rng)
    count += 1
    for i in range(48):
        ptr = 0 if rng.random() < 0.3 else rng.getrandbits(64)
        run_case(code_page, plt_page, ptr, rng.getrandbits(64),
                 rng.getrandbits(64), PAIR, "random %d" % i, rng)
        count += 1
    print("%d cases, 0 mismatches" % count)
    print("DIFFERENTIAL PASSED")


if __name__ == "__main__":
    main()
