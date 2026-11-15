"""Unicorn differential for the RE-001-error-wrap-dispatch-50df400-115
packet: run the real 182 bytes of routine 0x50df400 from the
digest-verified work binary against the Python model
(tools/error_wrap_dispatch_50df400_115.py) over the tag
word's full decision space.

The routine's own bytes run natively under emulation. Its
callees do not: the wrap call at 0x50df438, the
discriminant-0 drop call at 0x50df477 and the GOT-resolved
tagged drop (GOT slot 0x64df4a0, pre-filled with a stub
address, exactly as the R_X86_64_RELATIVE record resolves
it to 0x635de30 in the real binary) are intercepted and
answered with the same recording contract functions the
model uses. That is exactly the packet's claim boundary:
0x50df400's own instructions -- the stack descriptor it
builds (including the GOT-loaded fourth word, read from a
slot pre-filled with the relocation's resolved value
0x5c3f000), the discriminant arithmetic, the branch
structure and the call-site register setup -- are what is
being differentially tested; the callees' bodies are by
contract only.

Per case the harness builds one value image (tag word,
two payload words), runs the model on a copy and the real
bytes on the original layout under Unicorn, then compares:

  * the ordered callee event log (wrap once, with the
    descriptor's four words read from the native stack;
    then at most one drop, with its exact arguments);
  * the return value (the wrap stub's answer, passed
    through);
  * the whole value window, byte for byte (the routine
    must not write through either pointer);
  * the callee-saved registers and the stack pointer,
    which the routine must restore.

Run with a Python that has unicorn available, from the
repository root:

    python3 research/work-items/RE-001-error-wrap-dispatch-50df400-115/differential.py

Prints the case count and DIFFERENTIAL PASSED on success.
"""

import hashlib
import random
import struct
import sys
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]
BINARY = ROOT / "artifacts" / "node" / "115" / "hl-node"
DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

sys.path.insert(0, str(ROOT / "tools"))
from error_wrap_dispatch_50df400_115 import (  # noqa: E402
    DESCRIPTOR_FN,
    error_wrap,
)

from unicorn import Uc, UC_ARCH_X86, UC_HOOK_CODE, UC_MODE_64  # noqa: E402
from unicorn.x86_const import (  # noqa: E402
    UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RCX, UC_X86_REG_RDX,
    UC_X86_REG_RSI, UC_X86_REG_RDI, UC_X86_REG_RBP, UC_X86_REG_RSP,
    UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_R10, UC_X86_REG_R11,
    UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15,
    UC_X86_REG_RIP,
)

ROUTINE = 0x50DF400
ROUTINE_SIZE = 182
CODE_BASE = 0x50DF000
WRAP = 0x5101070
WRAP_PAGE = 0x5101000
DROP_B = 0x50F0580
DROP_PAGE = 0x50F0000
GOT_A_PAGE = 0x64DF000
GOT_B_PAGE = 0x64E0000
TAGGED_SLOT = 0x64DF4A0
FN_SLOT = 0x64E0A48

WIN_BASE, WIN_SIZE = 0x40000000, 0x1000
STACK_BASE, STACK_SIZE = 0x7F000000, 0x1000
SENTINEL = 0x90000000
STUB_PAGE = 0x91000000
TAGGED_STUB = STUB_PAGE

VALUE = WIN_BASE + 0x100
OUT = WIN_BASE + 0x800

CALLEE_SAVED = [UC_X86_REG_RBX, UC_X86_REG_RBP, UC_X86_REG_R12,
                UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15]
GP_FILL = [UC_X86_REG_RAX, UC_X86_REG_RCX, UC_X86_REG_R8,
           UC_X86_REG_R9, UC_X86_REG_R10, UC_X86_REG_R11]


class Env:
    """Recording callee environment shared by both sides:
    wrap answers a preset result; all three callees log
    their arguments in order."""

    def __init__(self, result):
        self.result = result
        self.events = []

    def wrap(self, desc_id, descriptor):
        self.events.append(("wrap", desc_id, tuple(descriptor)))
        return self.result

    def drop_b(self, word):
        self.events.append(("drop_b", word))

    def drop_tagged(self, word, tag, zero):
        self.events.append(("drop_tagged", word, tag, zero))


class SliceMem:
    """Slice-addressed memory over a read/write backend, in
    the shape the model's _rd64 helper uses."""

    def __init__(self, read, write):
        self._read = read
        self._write = write

    def __getitem__(self, sl):
        return self._read(sl.start, sl.stop - sl.start)

    def __setitem__(self, sl, data):
        self._write(sl.start, bytes(data))


def window_backend(img):
    def read(addr, n):
        if WIN_BASE <= addr and addr + n <= WIN_BASE + WIN_SIZE:
            return bytes(img[addr - WIN_BASE:addr - WIN_BASE + n])
        raise AssertionError("model read outside window: %#x" % addr)

    def write(addr, data):
        raise AssertionError("model wrote memory: %#x" % addr)

    return SliceMem(read, write)


def wr64(img, base, addr, value):
    img[addr - base:addr - base + 8] = \
        (value & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")


def run_native(code_page, img, result, reg_fill):
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    for base, size in ((CODE_BASE, 0x1000), (WRAP_PAGE, 0x1000),
                       (DROP_PAGE, 0x1000), (GOT_A_PAGE, 0x1000),
                       (GOT_B_PAGE, 0x1000), (WIN_BASE, WIN_SIZE),
                       (STACK_BASE, STACK_SIZE), (SENTINEL, 0x1000),
                       (STUB_PAGE, 0x1000)):
        uc.mem_map(base, size)
    uc.mem_write(CODE_BASE, code_page)
    uc.mem_write(WIN_BASE, bytes(img))
    uc.mem_write(TAGGED_SLOT, struct.pack("<Q", TAGGED_STUB))
    uc.mem_write(FN_SLOT, struct.pack("<Q", DESCRIPTOR_FN))
    stack_top = STACK_BASE + STACK_SIZE - 0x10
    uc.mem_write(stack_top, struct.pack("<Q", SENTINEL))
    env = Env(result)

    def ret_from_call():
        rsp = uc.reg_read(UC_X86_REG_RSP)
        target = struct.unpack("<Q", uc.mem_read(rsp, 8))[0]
        uc.reg_write(UC_X86_REG_RSP, rsp + 8)
        uc.reg_write(UC_X86_REG_RIP, target)

    def hook(uc_, address, size, _data):
        if address == WRAP:
            desc_ptr = uc_.reg_read(UC_X86_REG_RSI)
            desc = struct.unpack(
                "<QQQQ", uc_.mem_read(desc_ptr, 32))
            ret = env.wrap(uc_.reg_read(UC_X86_REG_RDI), desc)
            uc_.reg_write(UC_X86_REG_RAX, ret)
            ret_from_call()
        elif address == DROP_B:
            env.drop_b(uc_.reg_read(UC_X86_REG_RDI))
            ret_from_call()
        elif address == TAGGED_STUB:
            env.drop_tagged(uc_.reg_read(UC_X86_REG_RDI),
                            uc_.reg_read(UC_X86_REG_RSI),
                            uc_.reg_read(UC_X86_REG_RDX))
            ret_from_call()

    uc.hook_add(UC_HOOK_CODE, hook)
    for reg, value in reg_fill.items():
        uc.reg_write(reg, value)
    uc.reg_write(UC_X86_REG_RDI, OUT)
    uc.reg_write(UC_X86_REG_RSI, VALUE)
    uc.reg_write(UC_X86_REG_RSP, stack_top)
    uc.emu_start(ROUTINE, SENTINEL)
    out_img = bytearray(uc.mem_read(WIN_BASE, WIN_SIZE))
    saved = {reg: uc.reg_read(reg) for reg in CALLEE_SAVED}
    return out_img, env, uc.reg_read(UC_X86_REG_RAX), saved, \
        uc.reg_read(UC_X86_REG_RSP)


def run_case(code_page, tag, word_a, word_b, result, label, rng):
    img = bytearray(rng.getrandbits(8) for _ in range(WIN_SIZE))
    wr64(img, WIN_BASE, VALUE, tag)
    wr64(img, WIN_BASE, VALUE + 0x08, word_a)
    wr64(img, WIN_BASE, VALUE + 0x10, word_b)
    exp_env = Env(result)
    model_ret = error_wrap(window_backend(img), OUT, VALUE, exp_env)
    reg_fill = {reg: rng.getrandbits(64)
                for reg in CALLEE_SAVED + GP_FILL}
    act_img, act_env, act_ret, saved, rsp = run_native(
        code_page, img, result, reg_fill)
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
            "%s: value window written at offsets %s"
            % (label, [hex(WIN_BASE + d) for d in diff[:8]]))
    for reg in CALLEE_SAVED:
        if saved[reg] != reg_fill[reg]:
            raise AssertionError(
                "%s: callee-saved register not preserved" % label)
    # emu_start stops after the routine's ret has popped the
    # sentinel, so a balanced stack shows stack_top + 8.
    if rsp != STACK_BASE + STACK_SIZE - 0x10 + 8:
        raise AssertionError("%s: stack pointer not restored" % label)


def main():
    data = BINARY.read_bytes()
    if hashlib.sha256(data).hexdigest() != DIGEST:
        raise SystemExit("work binary digest mismatch")
    code_page = data[CODE_BASE - 0x1000:CODE_BASE - 0x1000 + 0x1000]
    routine = data[ROUTINE - 0x1000:ROUTINE - 0x1000 + ROUTINE_SIZE]
    if len(routine) != ROUTINE_SIZE or routine[:2] != bytes.fromhex(
            "4156"):
        raise SystemExit("routine bytes mismatch")
    rng = random.Random(0x50DF400)
    sign = 0x8000000000000000
    tags = [
        0, 1, 2, 3, 4, 0x10, 0x7FFFFFFFFFFFFFFF,
        sign, sign | 1, sign | 2, sign | 3, sign | 4, sign | 5,
        sign | 0x1000, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFE,
    ]
    results = [0, 1, 0xDEADBEEFCAFE, sign, 0xFFFFFFFFFFFFFFFF]
    count = 0
    for i, tag in enumerate(tags):
        run_case(code_page, tag, rng.getrandbits(64),
                 rng.getrandbits(64), results[i % len(results)],
                 "tag %#x" % tag, rng)
        count += 1
    for i in range(24):
        run_case(code_page, rng.getrandbits(64), rng.getrandbits(64),
                 rng.getrandbits(64), rng.getrandbits(64),
                 "random %d" % i, rng)
        count += 1
    print("%d cases, 0 mismatches" % count)
    print("DIFFERENTIAL PASSED")


if __name__ == "__main__":
    main()
