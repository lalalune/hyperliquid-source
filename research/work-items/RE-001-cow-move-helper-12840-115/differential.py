"""Unicorn differential for the RE-001-cow-move-helper-12840-115
packet: run the real 358 bytes of routine 0x5f12840 from the
digest-verified work binary against the Python model
(tools/cow_move_helper_12840_115.py) on structured list images
and randomised ones.

The routine's own bytes run natively under emulation. Its
callees do not: the two call sites to the list-copy helper
0x5f12320 and the two PLT calls in the surplus-node delete
loop (_List_node_base::_M_unhook and operator delete) are
intercepted and answered with the same contract functions the
model uses (list_copy_range / list_unhook from the model, and
a free that only records). That is exactly the packet's claim
boundary: 0x5f12840's own instructions -- prologue writes,
branch structure, payload bumps, count arithmetic, call-site
register setup -- are what is being differentially tested;
the helper's body is by contract only.

Per case the harness builds one memory image (destination
object, source object, list-node arena, payload arena, bump
heap), runs the model on a copy and the real bytes on the
original layout under Unicorn, then compares byte for byte:

  * the whole object/node/payload window and the whole heap
    window (so the unwritten +0x34 dword, orphaned preloaded
    nodes and stale freed-node bytes are all compared);
  * the allocator state (next free address, freed list);
  * the callee-saved registers and the stack pointer, which
    the routine must restore.

Run with a Python that has unicorn available, from the
repository root:

    python3 research/work-items/RE-001-cow-move-helper-12840-115/differential.py

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
from cow_move_helper_12840_115 import (  # noqa: E402
    NODE_SIZE,
    cow_move_helper,
    list_copy_range,
    list_unhook,
)

from unicorn import Uc, UC_ARCH_X86, UC_HOOK_CODE, UC_MODE_64  # noqa: E402
from unicorn.x86_const import (  # noqa: E402
    UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RCX, UC_X86_REG_RDX,
    UC_X86_REG_RSI, UC_X86_REG_RDI, UC_X86_REG_RBP, UC_X86_REG_RSP,
    UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_R10, UC_X86_REG_R11,
    UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15,
    UC_X86_REG_RIP,
)

ROUTINE = 0x5F12840
ROUTINE_SIZE = 358
CODE_BASE = 0x5F12000
HELPER = 0x5F12320
PLT_PAGE = 0x63F1000
UNHOOK_PLT = 0x63F10A0
DELETE_PLT = 0x63F0D80

WIN1_BASE, WIN1_SIZE = 0x40000000, 0x50000
HEAP_BASE, HEAP_SIZE = 0x50000000, 0x10000
STACK_BASE, STACK_SIZE = 0x7F000000, 0x1000
SENTINEL = 0x90000000

THIS = WIN1_BASE + 0x0000
OLD = WIN1_BASE + 0x10000
NODE_ARENA = WIN1_BASE + 0x20000
PAYLOAD_ARENA = WIN1_BASE + 0x40000
REFS = WIN1_BASE + 0x8000

CALLEE_SAVED = [UC_X86_REG_RBX, UC_X86_REG_RBP, UC_X86_REG_R12,
                UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15]
GP_FILL = [UC_X86_REG_RAX, UC_X86_REG_RCX, UC_X86_REG_R8,
           UC_X86_REG_R9, UC_X86_REG_R10, UC_X86_REG_R11]


class BumpAlloc:
    def __init__(self):
        self.next = HEAP_BASE
        self.freed = []

    def alloc(self, size):
        addr = self.next
        self.next += size
        return addr

    def free(self, addr, size):
        self.freed.append((addr, size))


class SliceMem:
    """Slice-addressed memory over a read/write backend, in the
    shape the model's _rd64/_wr64 helpers use."""

    def __init__(self, read, write):
        self._read = read
        self._write = write

    def __getitem__(self, sl):
        return self._read(sl.start, sl.stop - sl.start)

    def __setitem__(self, sl, data):
        self._write(sl.start, bytes(data))


def window_backend(img1, img2):
    def read(addr, n):
        if WIN1_BASE <= addr and addr + n <= WIN1_BASE + WIN1_SIZE:
            return bytes(img1[addr - WIN1_BASE:addr - WIN1_BASE + n])
        if HEAP_BASE <= addr and addr + n <= HEAP_BASE + HEAP_SIZE:
            return bytes(img2[addr - HEAP_BASE:addr - HEAP_BASE + n])
        raise AssertionError("model read outside windows: %#x" % addr)

    def write(addr, data):
        if WIN1_BASE <= addr and addr + len(data) <= WIN1_BASE + WIN1_SIZE:
            img1[addr - WIN1_BASE:addr - WIN1_BASE + len(data)] = data
            return
        if HEAP_BASE <= addr and addr + len(data) <= HEAP_BASE + HEAP_SIZE:
            img2[addr - HEAP_BASE:addr - HEAP_BASE + len(data)] = data
            return
        raise AssertionError("model write outside windows: %#x" % addr)

    return SliceMem(read, write)


def wr64(img, base, addr, value):
    img[addr - base:addr - base + 8] = \
        (value & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")


def wr32(img, base, addr, value):
    img[addr - base:addr - base + 4] = \
        (value & 0xFFFFFFFF).to_bytes(4, "little")


def build_list(img, obj, header_off, payloads, arena_slot):
    header = obj + header_off
    nodes = []
    for i, payload in enumerate(payloads):
        node = NODE_ARENA + (arena_slot + i) * NODE_SIZE
        wr64(img, WIN1_BASE, node + 0x10, payload)
        nodes.append(node)
    prev = header
    for node in nodes:
        wr64(img, WIN1_BASE, prev, node)
        wr64(img, WIN1_BASE, node + 8, prev)
        prev = node
    wr64(img, WIN1_BASE, prev, header)
    wr64(img, WIN1_BASE, header, nodes[0] if nodes else header)
    wr64(img, WIN1_BASE, header + 8, prev)
    wr64(img, WIN1_BASE, obj + header_off + 0x10, len(nodes))
    return nodes


def build_case(rng, spec):
    """Return (img1, img2, this, old) for one case."""
    img1 = bytearray(rng.getrandbits(8) for _ in range(WIN1_SIZE))
    img2 = bytearray([0xAA]) * HEAP_SIZE
    l1, l2, preload = spec
    payloads = {}
    slot = 0

    def payload(counter):
        nonlocal slot
        addr = PAYLOAD_ARENA + slot * 0x100
        slot += 1
        for i in range(0x80):
            img1[addr - WIN1_BASE + i] = rng.getrandbits(8)
        wr32(img1, WIN1_BASE, addr + 0x70, counter)
        payloads[addr] = counter
        return addr

    old_l1 = [payload(c) for c in l1]
    old_l2 = [payload(c) for c in l2]
    pre = [payload(c) for c in preload]
    build_list(img1, OLD, 0x00, old_l1, 0)
    build_list(img1, OLD, 0x18, old_l2, 16)
    build_list(img1, THIS, 0x18, pre, 32)
    wr32(img1, WIN1_BASE, OLD + 0x30, rng.getrandbits(32))
    img1[OLD - WIN1_BASE + 0x38:OLD - WIN1_BASE + 0x40] = \
        rng.getrandbits(64).to_bytes(8, "little")
    wr32(img1, WIN1_BASE, THIS + 0x34, 0xCAFEBABE)
    return img1, img2


def run_native(code_page, img1, img2, reg_fill):
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    uc.mem_map(CODE_BASE, 0x1000)
    uc.mem_map(PLT_PAGE, 0x1000)
    uc.mem_map(WIN1_BASE, WIN1_SIZE)
    uc.mem_map(HEAP_BASE, HEAP_SIZE)
    uc.mem_map(STACK_BASE, STACK_SIZE)
    uc.mem_map(SENTINEL, 0x1000)
    uc.mem_write(CODE_BASE, code_page)
    uc.mem_write(WIN1_BASE, bytes(img1))
    uc.mem_write(HEAP_BASE, bytes(img2))
    stack_top = STACK_BASE + STACK_SIZE - 0x10
    uc.mem_write(stack_top, struct.pack("<Q", SENTINEL))
    alloc = BumpAlloc()

    def uc_read(addr, n):
        return uc.mem_read(addr, n)

    def uc_write(addr, data):
        uc.mem_write(addr, data)

    mem = SliceMem(uc_read, uc_write)

    def ret_from_call():
        rsp = uc.reg_read(UC_X86_REG_RSP)
        target = struct.unpack("<Q", uc.mem_read(rsp, 8))[0]
        uc.reg_write(UC_X86_REG_RSP, rsp + 8)
        uc.reg_write(UC_X86_REG_RIP, target)

    def hook(uc_, address, size, _data):
        if address == HELPER:
            list_copy_range(mem,
                            uc_.reg_read(UC_X86_REG_RDI),
                            uc_.reg_read(UC_X86_REG_RSI),
                            uc_.reg_read(UC_X86_REG_RDX),
                            uc_.reg_read(UC_X86_REG_RCX),
                            alloc)
            ret_from_call()
        elif address == UNHOOK_PLT:
            list_unhook(mem, uc_.reg_read(UC_X86_REG_RDI))
            ret_from_call()
        elif address == DELETE_PLT:
            alloc.free(uc_.reg_read(UC_X86_REG_RDI),
                       uc_.reg_read(UC_X86_REG_RSI))
            ret_from_call()

    uc.hook_add(UC_HOOK_CODE, hook)
    for reg, value in reg_fill.items():
        uc.reg_write(reg, value)
    uc.reg_write(UC_X86_REG_RDI, THIS)
    uc.reg_write(UC_X86_REG_RSI, REFS)
    uc.reg_write(UC_X86_REG_RDX, OLD)
    uc.reg_write(UC_X86_REG_RSP, stack_top)
    uc.emu_start(ROUTINE, SENTINEL)
    out1 = bytearray(uc.mem_read(WIN1_BASE, WIN1_SIZE))
    out2 = bytearray(uc.mem_read(HEAP_BASE, HEAP_SIZE))
    saved = {reg: uc.reg_read(reg) for reg in CALLEE_SAVED}
    return out1, out2, alloc, saved, uc.reg_read(UC_X86_REG_RSP)


def run_case(code_page, spec, label, rng):
    img1, img2 = build_case(rng, spec)
    exp1, exp2 = bytearray(img1), bytearray(img2)
    model_alloc = BumpAlloc()
    model_mem = window_backend(exp1, exp2)
    cow_move_helper(model_mem, THIS, REFS, OLD, model_alloc)
    reg_fill = {reg: rng.getrandbits(64)
                for reg in CALLEE_SAVED + GP_FILL}
    act1, act2, native_alloc, saved, rsp = run_native(
        code_page, img1, img2, reg_fill)
    if act1 != exp1:
        diff = [i for i in range(WIN1_SIZE) if act1[i] != exp1[i]]
        raise AssertionError(
            "%s: window1 mismatch at offsets %s"
            % (label, [hex(WIN1_BASE + d) for d in diff[:8]]))
    if act2 != exp2:
        diff = [i for i in range(HEAP_SIZE) if act2[i] != exp2[i]]
        raise AssertionError(
            "%s: heap mismatch at offsets %s"
            % (label, [hex(HEAP_BASE + d) for d in diff[:8]]))
    if (native_alloc.next, native_alloc.freed) \
            != (model_alloc.next, model_alloc.freed):
        raise AssertionError("%s: allocator state mismatch" % label)
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
    if len(routine) != ROUTINE_SIZE or routine[:4] != bytes.fromhex(
            "f30f1efa"):
        raise SystemExit("routine bytes mismatch")
    rng = random.Random(0x12840)
    cases = [
        ("empty/empty", ([], [], [])),
        ("l1 only", ([5], [], [])),
        ("l2 only", ([], [7, 8], [])),
        ("both", ([1, 2, 3], [4, 5], [])),
        ("wrap counters", ([0xFFFFFFFF], [0xFFFFFFFE], [])),
        ("preload shorter", ([1], [2, 3, 4], [9, 9])),
        ("preload longer", ([1], [2], [9, 9, 9])),
        ("preload, l1 empty", ([], [2, 3], [9])),
        ("preload exact", ([1], [2, 3], [9, 9])),
    ]
    count = 0
    for label, spec in cases:
        run_case(code_page, spec, label, rng)
        count += 1
    # Self-copy: destination and source are the same object.
    img1 = bytearray(rng.getrandbits(8) for _ in range(WIN1_SIZE))
    img2 = bytearray([0xAA]) * HEAP_SIZE
    p = PAYLOAD_ARENA
    wr32(img1, WIN1_BASE, p + 0x70, 7)
    build_list(img1, OLD, 0x00, [p], 0)
    build_list(img1, OLD, 0x18, [p], 16)
    exp1, exp2 = bytearray(img1), bytearray(img2)
    model_alloc = BumpAlloc()
    cow_move_helper(window_backend(exp1, exp2), OLD, REFS, OLD,
                    model_alloc)
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    uc.mem_map(CODE_BASE, 0x1000)
    uc.mem_map(PLT_PAGE, 0x1000)
    uc.mem_map(WIN1_BASE, WIN1_SIZE)
    uc.mem_map(HEAP_BASE, HEAP_SIZE)
    uc.mem_map(STACK_BASE, STACK_SIZE)
    uc.mem_map(SENTINEL, 0x1000)
    uc.mem_write(CODE_BASE, code_page)
    uc.mem_write(WIN1_BASE, bytes(img1))
    uc.mem_write(HEAP_BASE, bytes(img2))
    stack_top = STACK_BASE + STACK_SIZE - 0x10
    uc.mem_write(stack_top, struct.pack("<Q", SENTINEL))
    uc.reg_write(UC_X86_REG_RDI, OLD)
    uc.reg_write(UC_X86_REG_RSI, REFS)
    uc.reg_write(UC_X86_REG_RDX, OLD)
    uc.reg_write(UC_X86_REG_RSP, stack_top)
    uc.emu_start(ROUTINE, SENTINEL)
    if bytearray(uc.mem_read(WIN1_BASE, WIN1_SIZE)) != exp1:
        raise AssertionError("self-copy: window mismatch")
    count += 1
    # Randomised shapes.
    for i in range(48):
        spec = (
            [rng.getrandbits(32) for _ in range(rng.randrange(0, 6))],
            [rng.getrandbits(32) for _ in range(rng.randrange(0, 6))],
            [rng.getrandbits(32) for _ in range(rng.randrange(0, 4))],
        )
        run_case(code_page, spec, "random %d" % i, rng)
        count += 1
    print("%d cases, 0 mismatches" % count)
    print("DIFFERENTIAL PASSED")


if __name__ == "__main__":
    main()
