"""Unicorn differential for the RE-001-list-copy-insert-12320-115
packet: run the real 243 bytes of routine 0x5f12320 from the
digest-verified work binary against the Python model
(tools/list_copy_insert_12320_115.py) on structured list images
and randomised ones.

The routine's own bytes run natively under emulation. Its
callees do not: the four PLT calls in the body (operator new,
_List_node_base::_M_hook, _List_node_base::_M_transfer and
sized operator delete) are intercepted and answered with the
libstdc++ semantics those library primitives are documented to
have -- the same contract functions the model is driven with.
That is exactly the packet's claim boundary: 0x5f12320's own
instructions -- entry compare, copy loop, payload store, count
arithmetic, the transfer call's argument setup, the size add's
placement after the transfer, and the post-transfer drain loop
-- are what is being differentially tested; the two list
primitives are library code, pinned by their own contracts.

One case answers _M_transfer with a no-op, which is the only
way the body's drain loop becomes observable: the transfer's
postcondition (temp list empty) is then false, and both sides
must delete the stranded temp copies in chain order while the
destination size still grows. In that case the heap images are
compared with the two temp-header addresses (the native stack
frame's and the model's scratch header) masked to a token,
because the stranded copies' boundary links hold them.

Per case the harness builds one memory image (destination
object, source object, node arena), runs the model on a copy
and the real bytes on the original layout under Unicorn, then
compares byte for byte:

  * the whole data window and the whole heap window;
  * the allocator state (next free address, freed list);
  * the callee-saved registers and the stack pointer, which
    the routine must restore.

The exception path is not emulated (Unicorn has no unwinder);
it is pinned by the model tests and the LSDA reading in the
packet README.

Run with a Python that has unicorn available, from the
repository root:

    python3 research/work-items/RE-001-list-copy-insert-12320-115/differential.py

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
from list_copy_insert_12320_115 import ListCopyInsert  # noqa: E402

from unicorn import Uc, UC_ARCH_X86, UC_HOOK_CODE, UC_MODE_64  # noqa: E402
from unicorn.x86_const import (  # noqa: E402
    UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RCX, UC_X86_REG_RDX,
    UC_X86_REG_RSI, UC_X86_REG_RDI, UC_X86_REG_RBP, UC_X86_REG_RSP,
    UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_R10, UC_X86_REG_R11,
    UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15,
    UC_X86_REG_RIP,
)

ROUTINE = 0x5F12320
ROUTINE_SIZE = 0xF3
CODE_BASE = 0x5F12000
NEW_PLT = 0x63F0DD0
HOOK_PLT = 0x63F1090
TRANSFER_PLT = 0x63F13C0
DELETE_PLT = 0x63F0D80
CHKFAIL_PLT = 0x63F0D70
UNWIND_PLT = 0x63F0A50
PLT_PAGES = (0x63F0000, 0x63F1000)

WIN_BASE, WIN_SIZE = 0x40000000, 0x50000
HEAP_BASE, HEAP_SIZE = 0x50000000, 0x10000
STACK_BASE, STACK_SIZE = 0x7F000000, 0x1000
SENTINEL = 0x90000000
TMP_BASE = 0x60000000           # model-side temp header scratch
CANARY = 0x1122334455667788

DEST = WIN_BASE + 0x0000
SRC = WIN_BASE + 0x1000
NODE_ARENA = WIN_BASE + 0x20000
NODE = 0x18

STACK_TOP = STACK_BASE + STACK_SIZE - 0x8
NATIVE_TMP = STACK_TOP - 0x48   # the frame's temp header address

CALLEE_SAVED = [UC_X86_REG_RBX, UC_X86_REG_RBP, UC_X86_REG_R12,
                UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15]
GP_FILL = [UC_X86_REG_RAX, UC_X86_REG_R8, UC_X86_REG_R9,
           UC_X86_REG_R10, UC_X86_REG_R11]


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


class Mem:
    """Byte-addressed memory in the shape the model uses
    (``mem.get(addr, 0)`` reads, ``mem[addr] = byte`` writes),
    backed by the two compared windows plus a scratch dict for
    the model-side temp header."""

    def __init__(self, win, heap):
        self.win = win
        self.heap = heap
        self.extra = {}

    def get(self, addr, default=0):
        if WIN_BASE <= addr < WIN_BASE + WIN_SIZE:
            return self.win[addr - WIN_BASE]
        if HEAP_BASE <= addr < HEAP_BASE + HEAP_SIZE:
            return self.heap[addr - HEAP_BASE]
        return self.extra.get(addr, default)

    def __setitem__(self, addr, value):
        if WIN_BASE <= addr < WIN_BASE + WIN_SIZE:
            self.win[addr - WIN_BASE] = value
        elif HEAP_BASE <= addr < HEAP_BASE + HEAP_SIZE:
            self.heap[addr - HEAP_BASE] = value
        else:
            self.extra[addr] = value


def qword(mem, addr):
    value = 0
    for i in range(8):
        value |= mem.get(addr + i, 0) << (8 * i)
    return value


def store_qword(mem, addr, value):
    for i in range(8):
        mem[addr + i] = (value >> (8 * i)) & 0xFF


def hook_semantics(mem, node, pos):
    """_List_node_base::_M_hook, verbatim."""
    store_qword(mem, node + 0x00, pos)
    store_qword(mem, node + 0x08, qword(mem, pos + 0x08))
    store_qword(mem, qword(mem, pos + 0x08) + 0x00, node)
    store_qword(mem, pos + 0x08, node)


def transfer_semantics(mem, pos, first, last):
    """_List_node_base::_M_transfer, verbatim."""
    if pos == last:
        return
    store_qword(mem, qword(mem, last + 0x08) + 0x00, pos)
    store_qword(mem, qword(mem, first + 0x08) + 0x00, last)
    store_qword(mem, qword(mem, pos + 0x08) + 0x00, first)
    tmp = qword(mem, pos + 0x08)
    store_qword(mem, pos + 0x08, qword(mem, last + 0x08))
    store_qword(mem, last + 0x08, qword(mem, first + 0x08))
    store_qword(mem, first + 0x08, tmp)


class ModelSide:
    """Drive the packet model with primitives over the shared
    image, mirroring the harness in the model tests."""

    def __init__(self, mem, alloc, transfer_moves=True):
        self.mem = mem
        self.alloc_obj = alloc
        self.transfer_moves = transfer_moves
        self.machine = None
        store_qword(mem, TMP_BASE, TMP_BASE)
        store_qword(mem, TMP_BASE + 0x08, TMP_BASE)

    def alloc(self, size):
        return self.alloc_obj.alloc(size)

    def free(self, addr, size):
        self.alloc_obj.free(addr, size)

    def hook(self, node, position):
        hook_semantics(self.mem, node, TMP_BASE)
        self.machine.temp_link(node)

    def transfer(self, position, first, last):
        if not self.transfer_moves:
            return
        first_node = qword(self.mem, TMP_BASE)
        moved = []
        cur = first_node
        while cur != TMP_BASE:
            moved.append(cur)
            cur = qword(self.mem, cur)
        transfer_semantics(self.mem, position, first_node, TMP_BASE)
        for node in moved:
            self.machine.temp_unlink(node)

    def run(self, dest, position, first, last):
        self.machine = ListCopyInsert(
            self.mem, self.alloc, self.free, self.hook, self.transfer)
        self.machine.run(dest, position, first, last)


def wr64(img, base, addr, value):
    img[addr - base:addr - base + 8] = \
        (value & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")


def build_list(img, obj, payloads, arena_slot):
    header = obj
    nodes = []
    for i, payload in enumerate(payloads):
        node = NODE_ARENA + (arena_slot + i) * NODE
        wr64(img, WIN_BASE, node + 0x10, payload)
        nodes.append(node)
    prev = header
    for node in nodes:
        wr64(img, WIN_BASE, prev, node)
        wr64(img, WIN_BASE, node + 8, prev)
        prev = node
    wr64(img, WIN_BASE, prev, header)
    wr64(img, WIN_BASE, header, nodes[0] if nodes else header)
    wr64(img, WIN_BASE, header + 8, prev)
    wr64(img, WIN_BASE, obj + 0x10, len(nodes))
    return nodes


def build_case(rng, spec):
    """spec: (dest payloads, src payloads, first idx, last idx,
    position idx) with indices len(list) meaning the header.
    Returns (img1, img2, (dest, position, first, last))."""
    dest_p, src_p, i, j, pos_idx = spec
    img1 = bytearray(rng.getrandbits(8) for _ in range(WIN_SIZE))
    img2 = bytearray([0xAA]) * HEAP_SIZE
    dnodes = build_list(img1, DEST, dest_p, 0)
    snodes = build_list(img1, SRC, src_p, 64)
    first = snodes[i] if i < len(snodes) else SRC
    last = snodes[j] if j < len(snodes) else SRC
    position = dnodes[pos_idx] if pos_idx < len(dnodes) else DEST
    return img1, img2, (DEST, position, first, last)


def run_native(code_page, img1, img2, args, reg_fill, transfer_moves):
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    uc.mem_map(0, 0x1000)
    uc.mem_write(0x28, struct.pack("<Q", CANARY))
    uc.mem_map(CODE_BASE, 0x1000)
    for page in PLT_PAGES:
        uc.mem_map(page, 0x1000)
    uc.mem_map(WIN_BASE, WIN_SIZE)
    uc.mem_map(HEAP_BASE, HEAP_SIZE)
    uc.mem_map(STACK_BASE, STACK_SIZE)
    uc.mem_map(SENTINEL, 0x1000)
    uc.mem_write(CODE_BASE, code_page)
    uc.mem_write(WIN_BASE, bytes(img1))
    uc.mem_write(HEAP_BASE, bytes(img2))
    uc.mem_write(STACK_TOP, struct.pack("<Q", SENTINEL))
    alloc = BumpAlloc()

    def uq(addr):
        return struct.unpack("<Q", uc.mem_read(addr, 8))[0]

    def usw(addr, value):
        uc.mem_write(addr, struct.pack("<Q", value))

    class UcMem:
        def get(self, addr, default=0):
            return uc.mem_read(addr, 1)[0]

        def __setitem__(self, addr, value):
            uc.mem_write(addr, bytes([value]))

    uc_mem = UcMem()

    def ret_from_call():
        rsp = uc.reg_read(UC_X86_REG_RSP)
        target = struct.unpack("<Q", uc.mem_read(rsp, 8))[0]
        uc.reg_write(UC_X86_REG_RSP, rsp + 8)
        uc.reg_write(UC_X86_REG_RIP, target)

    def hook(uc_, address, size, _data):
        if address == NEW_PLT:
            uc_.reg_write(UC_X86_REG_RAX,
                          alloc.alloc(uc_.reg_read(UC_X86_REG_RDI)))
            ret_from_call()
        elif address == HOOK_PLT:
            hook_semantics(uc_mem, uc_.reg_read(UC_X86_REG_RDI),
                           uc_.reg_read(UC_X86_REG_RSI))
            ret_from_call()
        elif address == TRANSFER_PLT:
            if transfer_moves:
                transfer_semantics(uc_mem,
                                   uc_.reg_read(UC_X86_REG_RDI),
                                   uc_.reg_read(UC_X86_REG_RSI),
                                   uc_.reg_read(UC_X86_REG_RDX))
            ret_from_call()
        elif address == DELETE_PLT:
            alloc.free(uc_.reg_read(UC_X86_REG_RDI),
                       uc_.reg_read(UC_X86_REG_RSI))
            ret_from_call()
        elif address in (CHKFAIL_PLT, UNWIND_PLT):
            raise AssertionError(
                "unexpected call to %#x" % address)

    uc.hook_add(UC_HOOK_CODE, hook)
    for reg, value in reg_fill.items():
        uc.reg_write(reg, value)
    dest, position, first, last = args
    uc.reg_write(UC_X86_REG_RDI, dest)
    uc.reg_write(UC_X86_REG_RSI, position)
    uc.reg_write(UC_X86_REG_RDX, first)
    uc.reg_write(UC_X86_REG_RCX, last)
    uc.reg_write(UC_X86_REG_RSP, STACK_TOP)
    uc.emu_start(ROUTINE, SENTINEL)
    out1 = bytearray(uc.mem_read(WIN_BASE, WIN_SIZE))
    out2 = bytearray(uc.mem_read(HEAP_BASE, HEAP_SIZE))
    saved = {reg: uc.reg_read(reg) for reg in CALLEE_SAVED}
    return out1, out2, alloc, saved, uc.reg_read(UC_X86_REG_RSP)


def mask_header(img, header_addr):
    needle = struct.pack("<Q", header_addr)
    token = struct.pack("<Q", 0xEEEEEEEEEEEEEEEE)
    out = bytearray(img)
    start = 0
    while True:
        hit = out.find(needle, start)
        if hit < 0:
            return bytes(out)
        out[hit:hit + 8] = token
        start = hit + 8


def run_case(code_page, spec, label, rng, transfer_moves=True):
    img1, img2, args = build_case(rng, spec)
    exp1, exp2 = bytearray(img1), bytearray(img2)
    model_alloc = BumpAlloc()
    side = ModelSide(Mem(exp1, exp2), model_alloc, transfer_moves)
    side.run(*args)
    reg_fill = {reg: rng.getrandbits(64)
                for reg in CALLEE_SAVED + GP_FILL}
    act1, act2, native_alloc, saved, rsp = run_native(
        code_page, img1, img2, args, reg_fill, transfer_moves)
    if not transfer_moves:
        act2 = bytearray(mask_header(act2, NATIVE_TMP))
        exp2 = bytearray(mask_header(exp2, TMP_BASE))
    if act1 != exp1:
        diff = [i for i in range(WIN_SIZE) if act1[i] != exp1[i]]
        raise AssertionError(
            "%s: window mismatch at offsets %s"
            % (label, [hex(WIN_BASE + d) for d in diff[:8]]))
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
    if rsp != STACK_TOP + 8:
        raise AssertionError("%s: stack pointer not restored" % label)


def main():
    data = BINARY.read_bytes()
    if hashlib.sha256(data).hexdigest() != DIGEST:
        raise SystemExit("work binary digest mismatch")
    code_page = data[CODE_BASE - 0x1000:CODE_BASE - 0x1000 + 0x1000]
    routine = data[ROUTINE - 0x1000:ROUTINE - 0x1000 + ROUTINE_SIZE]
    if len(routine) != ROUTINE_SIZE or routine[:2] != bytes.fromhex("4156"):
        raise SystemExit("routine bytes mismatch")
    rng = random.Random(0x12320)
    cases = [
        ("empty range at node", ([0xD0], [0xA], 0, 0, 1)),
        ("empty range at header", ([0xD0], [0xA], 1, 1, 1)),
        ("single into empty", ([], [0x1111], 0, 1, 0)),
        ("append three", ([0xD0, 0xD1], [0xA, 0xB, 0xC], 0, 3, 2)),
        ("insert middle", ([0xD0, 0xD1, 0xD2], [0xA, 0xB], 0, 2, 1)),
        ("partial range", ([], [0xA, 0xB, 0xC, 0xD], 1, 3, 0)),
        ("range to header end", ([0xD0], [0xA, 0xB], 0, 2, 1)),
    ]
    count = 0
    for label, spec in cases:
        run_case(code_page, spec, label, rng)
        count += 1
    # The drain case: a no-op transfer strands the temp copies.
    run_case(code_page, ([0xD0], [0xA, 0xB], 0, 2, 1),
             "no-op transfer drain", rng, transfer_moves=False)
    count += 1
    # Randomised cases: random list sizes, random (possibly
    # empty) ranges, random insertion positions, random payload
    # qwords over a random-filled window.
    for k in range(40):
        dn = rng.randrange(0, 5)
        sn = rng.randrange(0, 7)
        dest_p = [rng.getrandbits(64) for _ in range(dn)]
        src_p = [rng.getrandbits(64) for _ in range(sn)]
        i = rng.randrange(0, sn + 1)
        j = rng.randrange(i, sn + 1)
        pos = rng.randrange(0, dn + 1)
        run_case(code_page, (dest_p, src_p, i, j, pos),
                 "random %d" % k, rng)
        count += 1
    print("%d cases, 0 mismatches" % count)
    print("DIFFERENTIAL PASSED")


if __name__ == "__main__":
    main()
