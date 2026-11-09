#!/usr/bin/env python3
"""Reconstruct the node #115 MessagePack header writers over a growable byte vector.

Seven machine-code bodies form one call graph that serialises into a
`Vec<u8>` (fields: cap at +0, pointer at +8, length at +0x10):

  0x4787da0  finish_grow(out, old_cap, ptr, new_cap, align, elem_size)
  0x4787e90  reserve(vec, len, additional, align, elem_size)
  0x4787d30  grow_one for 32-byte elements
  0x477bd40  write_marker(&mut &mut Vec, marker, payload)
  0x477be60  write_map_len(out, &mut &mut Vec, len)
  0x47789c0  write_uint(out, &mut &mut Vec, value)
  0x4778560  write_str(&mut &mut Vec, data, len)

The tool holds a Python reconstruction of every body, runs the real bytes of
the binary on a small x86-64 evaluator (the shared evaluator of
`decimal_scaled_u64`) with allocator and memcpy replaced by deterministic
stubs, and compares the two for every generated case.  Nothing is executed
natively.
"""
import argparse
import hashlib
import json
import pathlib
import struct
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import decimal_scaled_u64 as core  # noqa: E402

BINARY = ROOT / "artifacts" / "node" / "115" / "hl-node"
SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
M64 = (1 << 64) - 1
ERR = 0x2600000003          # the io::Error payload every failed write returns
HEAP = 0x7200_0000
VEC = 0x7300_0000
CELL = 0x7300_0100          # holds the address of the vec: the `&mut &mut Vec`
OUT = 0x7300_0200
SCRATCH = 0x7300_0400       # model-side stand-in for the callee's stack slot
DATA = 0x7400_0000
FAKE_BUF = 0x7500_0000
ALLOC_LIMIT = 1 << 24       # the stub allocator refuses anything larger
SENTINEL_MEMCPY = 0x7fff_0000

FN = {"finish_grow": 0x4787da0, "reserve": 0x4787e90, "grow_one32": 0x4787d30,
      "marker": 0x477bd40, "map_len": 0x477be60, "uint": 0x47789c0, "str": 0x4778560}
SLOTS = {0x64df480: "malloc", 0x64df498: "handle_error", 0x64df508: "memcpy",
         0x64df580: "realloc_aligned", 0x64df588: "realloc", 0x64df590: "alloc_aligned"}
CALLEE_SAVED = {core.RBX: 0x1111_2222_3333_4444, core.RBP: 0x2222_3333_4444_5555,
                core.R12: 0x3333_4444_5555_6666, core.R13: 0x4444_5555_6666_7777,
                core.R14: 0x5555_6666_7777_8888, core.R15: 0x6666_7777_8888_9999}


class Halt(Exception):
    """A noreturn call (the allocation-error handler) was reached."""


def rd(mem, at, size):
    return int.from_bytes(bytes(mem[at + i] for i in range(size)), "little")


def wr(mem, at, size, value):
    for i in range(size):
        mem[at + i] = (value >> (8 * i)) & 0xff


def tzcnt(value):
    return 64 if value == 0 else (value & -value).bit_length() - 1


class Env:
    """Deterministic allocator, memcpy and error-handler stand-ins shared by model and machine."""

    def __init__(self, fail_at=()):
        self.next = HEAP
        self.blocks = {}
        self.log = []
        self.calls = 0
        self.fail_at = set(fail_at)

    def _new(self, size):
        n = self.calls
        self.calls += 1
        if n in self.fail_at or size > ALLOC_LIMIT:
            return 0
        ptr = self.next
        self.next += ((size + 15) & ~15) + 16
        self.blocks[ptr] = size
        return ptr

    def register(self, mem, size, content):
        ptr = self.next
        self.next += ((size + 15) & ~15) + 16
        self.blocks[ptr] = size
        for i, byte in enumerate(content):
            mem[ptr + i] = byte
        return ptr

    def _move(self, mem, old, size):
        new = self._new(size)
        if new:
            for i in range(min(self.blocks.get(old, 0), size)):
                if old + i in mem:
                    mem[new + i] = mem[old + i]
        return new

    def malloc(self, mem, size):
        self.log.append(("malloc", size))
        return self._new(size)

    def alloc_aligned(self, mem, size, shift):
        self.log.append(("alloc_aligned", size, shift))
        return self._new(size)

    def realloc(self, mem, old, size):
        self.log.append(("realloc", old, size))
        return self._move(mem, old, size)

    def realloc_aligned(self, mem, old, size, shift):
        self.log.append(("realloc_aligned", old, size, shift))
        return self._move(mem, old, size)

    def memcpy(self, mem, dst, src, count):
        self.log.append(("memcpy", dst, src, count))
        for i in range(count):
            if src + i in mem:
                mem[dst + i] = mem[src + i]
            else:
                mem.pop(dst + i, None)
        return dst

    def handle_error(self, first, second):
        self.log.append(("handle_error", first, second))
        raise Halt


# ---------------------------------------------------------------------------
# Reconstruction of the seven bodies.  Every function takes the shared memory
# dict and the Env, so the model allocates exactly like the machine.
# ---------------------------------------------------------------------------

K = {"min_cap": 8, "dbl": 2, "str_mark8": 0xd9, "str_mark16": 0xda, "str_mark32": 0xdb,
     "uint8": 0xcc, "uint16": 0xcd, "uint32": 0xce, "uint64": 0xcf,
     "map16": 0xde, "map32": 0xdf, "fix_str": 0xa0, "fix_arr": 0x90, "fix_map": 0x80,
     "fix_str_mask": 0x1f, "fix_nib_mask": 0xf, "str_fix_limit": 0x20, "str8_limit": 0x100,
     "str16_limit": 0x10000, "map_fix_limit": 0x10, "map16_limit": 0x10000,
     "uint_pos_limit": 0x80, "uint8_limit": 0x100, "uint16_limit": 0x10000,
     "uint32_limit": 1 << 32, "elem_small": 0x401, "min_small": 4, "min_big": 1,
     "grow32_min": 4, "grow32_elem": 0x20, "grow32_align": 8, "marker_lo": 0xc0,
     "marker_hi": 0xdf, "layout_cap": 1 << 63, "byte_align": 1, "small_align": 0x11}


def finish_grow(env, mem, out, old_cap, ptr, new_cap, align, elem):
    prod = elem * new_cap
    low = prod & M64
    if prod > M64 or low > ((K["layout_cap"] - align) & M64):
        wr(mem, out + 8, 8, 0)
        wr(mem, out, 8, 1)
        return
    plain = (align < K["small_align"] and align <= low) or tzcnt(align) == 0
    if old_cap != 0:
        res = env.realloc(mem, ptr, low) if plain else env.realloc_aligned(mem, ptr, low, tzcnt(align))
    elif low == 0:
        res = align
    else:
        res = env.malloc(mem, low) if plain else env.alloc_aligned(mem, low, tzcnt(align))
    if res == 0:
        wr(mem, out + 8, 8, align)
        wr(mem, out + 0x10, 8, low)
        wr(mem, out, 8, 1)
        return
    wr(mem, out + 8, 8, res)
    wr(mem, out + 0x10, 8, low)
    wr(mem, out, 8, 0)


def error_halt(env, mem, out, length_hint):
    first = rd(mem, out + 8, 8)
    second = rd(mem, out + 0x10, 8) if (out + 0x10) in mem else None
    env.handle_error(first, second)


def reserve(env, mem, vec, length, add, align, elem):
    if elem == 0:
        env.handle_error(0, length)
    need = length + add
    if need > M64:
        env.handle_error(0, length)
    cap = rd(mem, vec, 8)
    new = max(need, (K["dbl"] * cap) & M64)
    floor = K["min_cap"] if elem == K["byte_align"] else (K["min_small"] if elem < K["elem_small"] else K["min_big"])
    new = max(new, floor)
    for i in range(24):
        mem.pop(SCRATCH + i, None)
    finish_grow(env, mem, SCRATCH, cap, rd(mem, vec + 8, 8), new, align, elem)
    if rd(mem, SCRATCH, 4) == 1:
        error_halt(env, mem, SCRATCH, 0)
    wr(mem, vec + 8, 8, rd(mem, SCRATCH + 8, 8))
    wr(mem, vec, 8, new)


def grow_one32(env, mem, vec):
    cap = rd(mem, vec, 8)
    new = (K["dbl"] * cap) & M64
    if new < K["grow32_min"] + 1:
        new = K["grow32_min"]
    for i in range(24):
        mem.pop(SCRATCH + i, None)
    finish_grow(env, mem, SCRATCH, cap, rd(mem, vec + 8, 8), new, K["grow32_align"], K["grow32_elem"])
    if rd(mem, SCRATCH, 4) == 1:
        error_halt(env, mem, SCRATCH, 0)
    wr(mem, vec + 8, 8, rd(mem, SCRATCH + 8, 8))
    wr(mem, vec, 8, new)


class Writer:
    """The `&mut &mut Vec<u8>` plumbing that every header writer repeats."""

    def __init__(self, env, mem):
        self.env, self.mem = env, mem
        self.vec = rd(mem, CELL, 8)

    def cap(self):
        return rd(self.mem, self.vec, 8)

    def length(self):
        return rd(self.mem, self.vec + 0x10, 8)

    def grow(self, new):
        """finish_grow into the vec; False when the allocator or layout check refused."""
        mem = self.mem
        for i in range(24):
            mem.pop(SCRATCH + i, None)
        cap = self.cap()
        finish_grow(self.env, mem, SCRATCH, cap, rd(mem, self.vec + 8, 8), new, 1, 1)
        if rd(mem, SCRATCH, 1) != 0:
            return False
        wr(mem, self.vec + 8, 8, rd(mem, SCRATCH + 8, 8))
        wr(mem, self.vec, 8, new)
        return True

    def push(self, byte):
        """One byte at the end, doubling (minimum 8) when full."""
        cap, length = self.cap(), self.length()
        if cap == length:
            if not self.grow(max((K["dbl"] * cap) & M64, K["min_cap"])):
                return False
        wr(self.mem, rd(self.mem, self.vec + 8, 8) + length, 1, byte)
        wr(self.mem, self.vec + 0x10, 8, length + 1)
        return True

    def room_for(self, count, extra=0):
        """Make `count` more bytes fit; False on overflow or allocator refusal."""
        cap, length = self.cap(), self.length()
        if ((cap - length) & M64) >= count:
            return True
        total = length + count
        if total > M64:
            return False
        return self.grow(max((K["dbl"] * cap) & M64, total, K["min_cap"]))

    def put(self, data):
        ptr, length = rd(self.mem, self.vec + 8, 8), self.length()
        for i, byte in enumerate(data):
            wr(self.mem, ptr + length + i, 1, byte)
        wr(self.mem, self.vec + 0x10, 8, length + len(data))


def model_marker(env, mem, marker, payload):
    w = Writer(env, mem)
    if K["marker_lo"] <= marker <= K["marker_hi"]:
        byte = marker
    elif marker <= 0x8f:
        byte = payload if marker == 0 else (payload & K["fix_nib_mask"]) | K["fix_map"]
    elif marker == 0x90:
        byte = (payload & K["fix_nib_mask"]) | K["fix_arr"]
    elif marker == 0xa0:
        byte = (payload & K["fix_str_mask"]) | K["fix_str"]
    else:
        byte = payload
    return (0 if w.push(byte) else ERR,)


def be(value, size):
    return (value & ((1 << (8 * size)) - 1)).to_bytes(size, "big")


def write_ok(mem, out, marker_word, tail=None):
    wr(mem, out, 8, 2)
    wr(mem, out + 8, 8, marker_word)
    if tail is not None:
        wr(mem, out + 9, 1, tail)


def write_err(mem, out, tag):
    wr(mem, out, 8, tag)
    wr(mem, out + 8, 8, ERR)


def model_map_len(env, mem, out, length):
    w = Writer(env, mem)
    length &= 0xffffffff
    if length < K["map_fix_limit"]:
        if not w.push(length | K["fix_map"]):
            return write_err(mem, out, 0)
        wr(mem, out, 8, 2)
        wr(mem, out + 8, 1, K["fix_map"])
        wr(mem, out + 9, 1, length & 0xff)
        return
    marker, size, field = (K["map16"], 2, "map16") if length < K["map16_limit"] else (K["map32"], 4, "map32")
    if not w.push(marker):
        return write_err(mem, out, 0)
    if not w.room_for(size):
        return write_err(mem, out, 1)
    w.put(be(length, size))
    wr(mem, out, 8, 2)
    wr(mem, out + 8, 1, marker)
    wr(mem, out + 9, 1, (length >> 8) & 0xff if size == 2 else (length >> 24) & 0xff)


def model_uint(env, mem, out, value):
    w = Writer(env, mem)
    if value < K["uint_pos_limit"]:
        if not w.push(value):
            return write_err(mem, out, 0)
        wr(mem, out, 8, 2)
        wr(mem, out + 8, 1, 0)
        wr(mem, out + 9, 1, value & 0xff)
        return
    if value < K["uint8_limit"]:
        marker, size = K["uint8"], 1
    elif value < K["uint16_limit"]:
        marker, size = K["uint16"], 2
    elif value < K["uint32_limit"]:
        marker, size = K["uint32"], 4
    else:
        marker, size = K["uint64"], 8
    if not w.push(marker):
        return write_err(mem, out, 0)
    if not w.room_for(size):
        return write_err(mem, out, 1)
    w.put(be(value, size))
    wr(mem, out, 8, 2)
    wr(mem, out + 8, 8, marker)


def model_str(env, mem, src, length):
    """Returns (rax, rdx): 2/0 success, 0 marker failure, 1 data failure."""
    w = Writer(env, mem)
    low = length & 0xffffffff
    if low < K["str_fix_limit"]:
        if not w.push((low & K["fix_str_mask"]) | K["fix_str"]):
            return (0, ERR)
    elif low < K["str8_limit"]:
        if not w.push(K["str_mark8"]):
            return (0, ERR)
        if not w.room_for(1):
            return (1, ERR)
        w.put(be(low, 1))
    elif low < K["str16_limit"]:
        if not w.push(K["str_mark16"]):
            return (0, ERR)
        if not w.room_for(2):
            return (1, ERR)
        w.put(be(low, 2))
    else:
        if not w.push(K["str_mark32"]):
            return (0, ERR)
        if not w.room_for(4):
            return (1, ERR)
        w.put(be(low, 4))
    if not w.room_for(length):
        return (1, ERR)
    if length:
        env.memcpy(mem, rd(mem, w.vec + 8, 8) + w.length(), src, length)
    wr(mem, w.vec + 0x10, 8, w.length() + length)
    return (2, 0)


# ---------------------------------------------------------------------------
# Machine side
# ---------------------------------------------------------------------------

class RMachine(core.Machine):
    """The shared evaluator plus bswap, with allocator/memcpy/error slots bound to an Env."""

    def __init__(self, image, env):
        super().__init__(image)
        self.env = env
        self.roles = {}
        for slot, role in SLOTS.items():
            target = image.slots.get(slot)
            if target is None:
                target = SENTINEL_MEMCPY
                image.slots[slot] = target
            self.roles[target] = role

    def call(self, target, where):
        role = self.roles.get(target)
        if role is None:
            super().call(target, where)
            return
        args = [self.get(r, 64) for r in (core.RDI, core.RSI, core.RDX)]
        env, mem = self.env, self.mem
        if role == "malloc":
            result = env.malloc(mem, args[0])
        elif role == "alloc_aligned":
            result = env.alloc_aligned(mem, args[0], args[1])
        elif role == "realloc":
            result = env.realloc(mem, args[0], args[1])
        elif role == "realloc_aligned":
            result = env.realloc_aligned(mem, args[0], args[1], args[2])
        elif role == "memcpy":
            result = env.memcpy(mem, args[0], args[1], args[2])
        else:
            try:
                env.handle_error(args[0], args[1])
            except Halt:
                raise core.Done("handle_error", where)
        for reg in core.CALLER_SAVED:
            self.put(reg, 64, None)
        self.flags = [None, None, None, None]
        self.set_reg(core.RAX, result)

    def shift(self, kind, value, count, bits):
        if kind in (0, 1) and value is not None and count is not None:
            count &= 63 if bits == 64 else 31
            if count % bits:
                step = count % bits if kind == 0 else (bits - count % bits)
                mask = (1 << bits) - 1
                value = ((value << step) | (value >> (bits - step))) & mask
            self.flags = [None, None, None, None]
            return value
        return super().shift(kind, value, count, bits)

    def two_byte(self, insn, key, bits, rexr, here):
        if len(key) == 2 and 0xc8 <= key[1] <= 0xcf:
            reg = (key[1] & 7) | ((insn.rex & 1) << 3)
            value = self.get(reg, bits)
            size = bits // 8
            self.put(reg, bits, int.from_bytes(value.to_bytes(size, "little"), "big"))
            return
        super().two_byte(insn, key, bits, rexr, here)


def new_image(patches=()):
    data = bytearray(BINARY.read_bytes())
    image = core.Image(data)
    for off, value in patches:
        data[off] = value
    image.cache.clear()
    return image


def build_state(spec):
    """Memory + Env for one case spec; the vec buffer is a registered heap block."""
    env = Env(spec.get("fail_at", ()))
    mem = {}
    cap, length = spec["cap"], spec["len"]
    content = bytes((i * 7 + 3) & 0xff for i in range(length))
    if cap == 0:
        ptr = 1
    elif spec.get("fake_ptr"):
        ptr = FAKE_BUF
    else:
        ptr = env.register(mem, cap, content)
    wr(mem, VEC, 8, cap)
    wr(mem, VEC + 8, 8, ptr)
    wr(mem, VEC + 0x10, 8, length)
    wr(mem, CELL, 8, VEC)
    for i in range(32):
        mem[OUT + i] = 0xa5
    data = spec.get("data", b"")
    for i, byte in enumerate(data):
        mem[DATA + i] = byte
    return env, mem


def run_model(spec):
    env, mem = build_state(spec)
    fn, a = spec["fn"], spec["arg"]
    ret = ()
    try:
        if fn == "finish_grow":
            old_cap, ptr, new_cap, align, elem = a
            finish_grow(env, mem, OUT, old_cap, ptr, new_cap, align, elem)
        elif fn == "reserve":
            reserve(env, mem, VEC, *a)
        elif fn == "grow_one32":
            grow_one32(env, mem, VEC)
        elif fn == "marker":
            ret = model_marker(env, mem, *a)
        elif fn == "map_len":
            model_map_len(env, mem, OUT, a[0])
        elif fn == "uint":
            model_uint(env, mem, OUT, a[0])
        else:
            ret = model_str(env, mem, DATA, a[0])
        how = "ret"
    except Halt:
        how = "halt"
    return snapshot(env, mem, how, ret)


def run_machine(spec, image, keep=None):
    env, mem = build_state(spec)
    m = RMachine(image, env)
    m.mem = mem
    sp = core.STACK
    m.store(sp, 8, core.RETURN_MARK)
    m.set_reg(core.RSP, sp)
    for reg, value in CALLEE_SAVED.items():
        m.set_reg(reg, value)
    fn, a = spec["fn"], spec["arg"]
    regs = {}
    if fn == "finish_grow":
        regs = {core.RDI: OUT, core.RSI: a[0], core.RDX: a[1], core.RCX: a[2], core.R8: a[3], core.R9: a[4]}
    elif fn == "reserve":
        regs = {core.RDI: VEC, core.RSI: a[0], core.RDX: a[1], core.RCX: a[2], core.R8: a[3]}
    elif fn == "grow_one32":
        regs = {core.RDI: VEC}
    elif fn == "marker":
        regs = {core.RDI: CELL, core.RSI: a[0], core.RDX: a[1]}
    elif fn in ("map_len", "uint"):
        regs = {core.RDI: OUT, core.RSI: CELL, core.RDX: a[0]}
    else:
        regs = {core.RDI: CELL, core.RSI: DATA, core.RDX: a[0]}
    for reg, value in regs.items():
        m.set_reg(reg, value)
    try:
        m.run(FN[fn])
        how = "?"
    except core.Done as done:
        how = "ret" if done.how == "ret" else "halt"
    ret = ()
    if how == "ret":
        for reg, value in CALLEE_SAVED.items():
            if m.get(reg, 64) != value:
                how = "clobbered"
        if fn == "marker":
            ret = (m.get(core.RAX, 64),)
        elif fn == "str":
            ret = (m.get(core.RAX, 64), m.get(core.RDX, 64))
    if keep is not None:
        keep["mem"] = mem
    return snapshot(env, mem, how, ret), m.seen


def machine_bytes(spec, image):
    """The bytes the real code left in the vector (prefix included) for one case spec."""
    keep = {}
    run_machine(fix_spec(spec), image, keep)
    mem = keep["mem"]
    ptr, length = rd(mem, VEC + 8, 8), rd(mem, VEC + 0x10, 8)
    return bytes(mem[ptr + i] for i in range(length))


def snapshot(env, mem, how, ret):
    cap, ptr, length = (rd(mem, VEC + o, 8) for o in (0, 8, 0x10))
    body = bytes(mem.get(ptr + i, 0x100) & 0xff if (ptr + i) in mem else 0xee for i in range(min(length, 1 << 17)))
    out = bytes(mem.get(OUT + i, 0x100) & 0xff for i in range(32))
    return (how, ret, cap, ptr, length, hashlib.sha256(body).hexdigest()[:16], out.hex(), tuple(env.log))


# ---------------------------------------------------------------------------
# Cases
# ---------------------------------------------------------------------------

class Lcg:
    def __init__(self, seed):
        self.state = seed

    def next(self, bound):
        self.state = (self.state * 6364136223846793005 + 1442695040888963407) & M64
        return (self.state >> 33) % bound


STATES = [(0, 0), (1, 0), (1, 1), (2, 1), (2, 2), (3, 2), (7, 7), (8, 0), (8, 7), (8, 8), (9, 9), (15, 15),
          (16, 3), (16, 16), (31, 30), (64, 64), (100, 98), (300, 299)]
FAILS = [(), (0,), (1,)]


def gen_cases():
    rng = Lcg(115)
    for cap, length in STATES:
        for fail in FAILS:
            for marker in list(range(0, 256, 3)) + [0x8f, 0x90, 0xa0, 0xc0, 0xdf, 0xe0, 0xff]:
                if (cap + length + marker) % 2 == 0 or fail == ():
                    yield {"fn": "marker", "cap": cap, "len": length, "fail_at": fail,
                           "arg": (marker, rng.next(256))}
    map_lens = [0, 1, 2, 15, 16, 17, 255, 256, 0xffff, 0x10000, 0x10001, 0xffffff, 0x1000000, 0xffffffff,
                0x1_0000_0005, 3, 8, 14]
    for cap, length in STATES:
        for fail in FAILS:
            for n in map_lens:
                yield {"fn": "map_len", "cap": cap, "len": length, "fail_at": fail, "arg": (n,)}
    values = [0, 1, 0x7f, 0x80, 0xff, 0x100, 0x1234, 0xffff, 0x10000, 0xdeadbeef, 0xffffffff, 0x100000000,
              0x1122334455667788, M64, 5, 99, 200, 70000]
    for cap, length in STATES:
        for fail in FAILS:
            for v in values:
                yield {"fn": "uint", "cap": cap, "len": length, "fail_at": fail, "arg": (v,)}
    for cap, length in STATES:
        for fail in FAILS:
            for n in [0, 1, 5, 31, 32, 33, 100, 255, 256, 257, 1000, 0xffff, 0x10000, 0x10001, 70000,
                      0x1_0000_0005, 0x1_0000_0100, 1 << 40]:
                if n > 300 and (cap + length + n) % 5:
                    continue
                data = bytes((i * 31 + 7) & 0xff for i in range(n)) if n <= 70000 else b""
                yield {"fn": "str", "cap": cap, "len": length, "fail_at": fail, "arg": (n,), "data": data}
    for cap, length in STATES:
        for fail in FAILS:
            yield {"fn": "grow_one32", "cap": cap, "len": length, "fail_at": fail, "arg": ()}
    for cap, length in STATES[:12]:
        for fail in FAILS:
            for add in [1, 2, 8, 100, 5000, M64 - length, M64]:
                for align, elem in [(1, 1), (1, 2), (8, 8), (4, 4), (16, 32), (64, 1024), (32, 1025), (1, 0),
                                    (2, 24), (8, 4096)]:
                    if (add + align + elem + cap) % 3 == 0 or add in (M64, M64 - length):
                        yield {"fn": "reserve", "cap": cap, "len": length, "fail_at": fail,
                               "arg": (length, add, align, elem)}
    for cap, length in STATES:
        for fail in FAILS:
            for new_cap, align, elem in [(8, 1, 1), (16, 8, 8), (4, 4, 4), (100, 16, 3), (0, 1, 1), (0, 8, 8),
                                         (1 << 62, 1, 1), (1 << 63, 1, 1), ((1 << 63) - 1, 1, 1),
                                         ((1 << 63) - 7, 8, 1), (1 << 32, 1, 1 << 33), (24, 0, 1), (5, 32, 1),
                                         (3, 64, 7)]:
                yield {"fn": "finish_grow", "cap": cap, "len": length, "fail_at": fail,
                       "arg": (cap, 0, new_cap, align, elem), "fix_ptr": True}
    for _ in range(2400):
        cap = rng.next(40)
        length = rng.next(cap + 1)
        fn = ("marker", "map_len", "uint", "str")[rng.next(4)]
        fail = FAILS[rng.next(3)] if rng.next(3) == 0 else ()
        if fn == "marker":
            arg = (rng.next(256), rng.next(256))
        elif fn == "map_len":
            arg = (rng.next(1 << (1 + rng.next(33))),)
        elif fn == "uint":
            arg = (rng.next(1 << (1 + rng.next(63))),)
        else:
            arg = (rng.next(1 + rng.next(2000)),)
        spec = {"fn": fn, "cap": cap, "len": length, "fail_at": fail, "arg": arg}
        if fn == "str":
            spec["data"] = bytes((i * 17 + 5) & 0xff for i in range(arg[0]))
        yield spec


def spec_text(spec):
    return "%s cap=%d len=%d fail=%s arg=%s" % (spec["fn"], spec["cap"], spec["len"],
                                                ",".join(map(str, spec.get("fail_at", ()))) or "-",
                                                ",".join(hex(x) for x in spec["arg"]) or "-")


def fix_spec(spec):
    """finish_grow needs the live pointer of the registered block as its argument."""
    if spec.get("fix_ptr"):
        env, mem = build_state(spec)
        spec = dict(spec)
        a = list(spec["arg"])
        a[1] = rd(mem, VEC + 8, 8)
        spec["arg"] = tuple(a)
        spec["fix_ptr"] = False
    return spec


def compare(spec, image):
    spec = fix_spec(spec)
    expected = run_model(spec)
    got, seen = run_machine(spec, image)
    return expected, got, spec, seen


# Negative controls: each is a model mutation (constant changed) or a corrupted
# byte of the binary; both must make at least one case of the probe set differ.

MODEL_MUTATIONS = [
    ("min_cap", 4), ("dbl", 3), ("str_mark8", 0xd8), ("str_mark16", 0xdb), ("str_mark32", 0xda),
    ("uint8", 0xcd), ("uint16", 0xce), ("uint32", 0xcf), ("uint64", 0xcc), ("map16", 0xdf), ("map32", 0xde),
    ("fix_str", 0xb0), ("fix_arr", 0xa0), ("fix_map", 0x90), ("fix_str_mask", 0x0f), ("fix_nib_mask", 0x1f),
    ("str_fix_limit", 0x21), ("str8_limit", 0xff), ("str16_limit", 0x10001), ("map_fix_limit", 0x11),
    ("map16_limit", 0xffff), ("uint_pos_limit", 0x81), ("uint8_limit", 0x101), ("uint16_limit", 0xffff),
    ("uint32_limit", 1 << 31), ("elem_small", 0x400), ("min_small", 8), ("min_big", 4), ("grow32_min", 8),
    ("grow32_elem", 0x28), ("grow32_align", 16), ("marker_lo", 0xc1), ("marker_hi", 0xde),
    ("layout_cap", 1 << 62), ("small_align", 0x10),
]


def binary_patches(image):
    """Single-byte corruptions at fixed addresses of the executed code (immediate or jump opcode)."""
    rows = []

    def at(va, delta, value, label):
        rows.append((label, va, image.file_offset(va) + delta, value))
    at(0x47785b0, 3, 0xd8, "write_str str8 marker immediate")
    at(0x4778a48, 3, 0xcc, "write_uint u16 marker immediate")
    at(0x4778b33, 3, 0xcf, "write_uint u32 marker immediate")
    at(0x477bea2, 3, 0xdd, "write_map_len map16 marker immediate")
    at(0x477bfa3, 3, 0xde, "write_map_len map32 marker immediate")
    at(0x4778c0e, 3, 0xcd, "write_uint u8 marker immediate")
    at(0x4778c62, 3, 0xce, "write_uint u64 marker immediate")
    at(0x477bd4a, 2, 0x21, "write_marker range width")
    at(0x4787ebf, 3, 0x00, "reserve element threshold (low byte)")
    at(0x4787ec9, 2, 0x02, "reserve element==1 compare")
    at(0x4787dec, 2, 0x10, "finish_grow small-align bound")
    at(0x4787d41, 2, 0x06, "grow_one32 minimum capacity compare")
    at(0x4787d56, 1, 0x10, "grow_one32 alignment argument")
    at(0x4787d5c, 1, 0x28, "grow_one32 element size argument")
    at(0x4778577, 2, 0x21, "write_str fixstr limit")
    at(0x4778584, 2, 0x01, "write_str str8 limit")
    at(0x4778651, 3, 0x01, "write_str str16 limit (byte 1)")
    at(0x47789d0, 3, 0x01, "write_uint u8 limit (byte 1)")
    at(0x4778a1b, 3, 0x02, "write_uint u16 limit (byte 2)")
    at(0x477be6d, 2, 0x11, "write_map_len fix limit")
    at(0x477be76, 3, 0x01, "write_map_len map16 limit")
    at(0x4787ec2, 0, 0x00, "reserve element threshold dword")
    return rows


PROBE = None


def probe_specs():
    rng = Lcg(7)
    specs = []
    for cap, length in [(0, 0), (1, 1), (2, 1), (8, 8), (9, 0), (16, 3), (64, 64), (300, 299)]:
        for fail in [(), (0,), (1,)]:
            for m in [0, 1, 0x7f, 0x80, 0x8f, 0x90, 0xa0, 0xc0, 0xcc, 0xdf, 0xe0]:
                specs.append({"fn": "marker", "cap": cap, "len": length, "fail_at": fail, "arg": (m, 0xff)})
            for n in [0, 5, 15, 16, 255, 256, 0xffff, 0x10000, 0x20000]:
                specs.append({"fn": "map_len", "cap": cap, "len": length, "fail_at": fail, "arg": (n,)})
            for v in [0, 0x7f, 0x80, 0xff, 0x100, 0xffff, 0x10000, 0xffffffff, 0x100000000]:
                specs.append({"fn": "uint", "cap": cap, "len": length, "fail_at": fail, "arg": (v,)})
            for n in [0, 3, 31, 32, 255, 256, 0xffff, 0x10000]:
                specs.append({"fn": "str", "cap": cap, "len": length, "fail_at": fail, "arg": (n,),
                              "data": bytes((i * 3) & 0xff for i in range(n))})
            specs.append({"fn": "grow_one32", "cap": cap, "len": length, "fail_at": fail, "arg": ()})
            for align, elem in [(1, 1), (8, 8), (4, 2), (16, 32), (1, 1025), (1, 0), (2, 1024)]:
                specs.append({"fn": "reserve", "cap": cap, "len": length, "fail_at": fail,
                              "arg": (length, 3, align, elem)})
            for new_cap, align, elem in [(8, 1, 1), (16, 8, 8), (100, 16, 3), (0, 8, 8), (1 << 63, 1, 1),
                                         (3, 64, 7), ((1 << 63) - 7, 8, 1), (5, 32, 1), (1 << 62, 1, 1)]:
                specs.append({"fn": "finish_grow", "cap": cap, "len": length, "fail_at": fail,
                              "arg": (cap, 0, new_cap, align, elem), "fix_ptr": True})
    return specs


def detects(image, mutate_model=None):
    """True when the model/machine pair disagrees on at least one probe case."""
    saved = dict(K)
    try:
        if mutate_model:
            K[mutate_model[0]] = mutate_model[1]
        for spec in probe_specs():
            try:
                expected, got, _, _ = compare(spec, image)
            except (core.ToolError, KeyError):
                return True
            if expected != got:
                return True
        return False
    finally:
        K.clear()
        K.update(saved)


def run_controls():
    rows = []
    base = new_image()
    for name, value in MODEL_MUTATIONS:
        rows.append(("model", "%s=%#x" % (name, value), detects(base, (name, value))))
    for label, va, off, value in binary_patches(base):
        image = new_image([(off, value)])
        rows.append(("binary", "%s @%#x byte %#x" % (label, va, value), detects(image)))
    return rows


def coverage_rows(image, executed):
    """Per function: instruction count, executed count and the contiguous unexecuted runs."""
    rows = []
    for name, va in sorted(FN.items(), key=lambda kv: kv[1]):
        start, end = image.fde_of(va)
        insns = []
        at = start
        while at < end:
            insn = image.fetch(at)
            insns.append(insn)
            at += insn.size
        runs, current = [], None
        for insn in insns:
            if insn.va in executed or insn.key == 0xcc:
                if current:
                    runs.append(current)
                current = None
            elif current:
                current[1] = insn.va + insn.size
            else:
                current = [insn.va, insn.va + insn.size]
        if current:
            runs.append(current)
        for run in runs:
            pad = any(i.key == 0xe8 and i.target == FN["reserve"] and run[0] <= i.va < run[1] for i in insns)
            run.append("reserve-pad" if pad else "other")
        live = sum(1 for insn in insns if insn.va in executed)
        rows.append((name, start, end - start, len(insns), live, runs))
    return rows


EQUIVALENT_REASON = {}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    if hashlib.sha256(BINARY.read_bytes()).hexdigest() != SHA256:
        raise SystemExit("binary digest differs from node #115")
    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    image = new_image()
    counts = {}
    mismatches = 0
    executed = set()
    outcomes = {}
    lines = ["id\tcase\tresult"]
    n = 0
    for spec in gen_cases():
        expected, got, spec, seen = compare(spec, image)
        n += 1
        executed.update(seen)
        key = (spec["fn"], got[0], got[1][0] if got[1] else -1)
        outcomes[key] = outcomes.get(key, 0) + 1
        counts[spec["fn"]] = counts.get(spec["fn"], 0) + 1
        if expected != got:
            mismatches += 1
        if n % 2 == 0:
            digest = hashlib.sha256(repr(expected).encode()).hexdigest()[:12]
            lines.append("%d\t%s\t%s:cap%d:len%d:body%s:%s" % (n, spec_text(spec), got[0], expected[2], expected[4],
                                                           expected[5][:8], digest))
    (out / "cases.tsv").write_text("\n".join(lines) + "\n")
    (out / "outcomes.tsv").write_text("function\ttermination\treturn_word\tcases\n" + "".join(
        "%s\t%s\t%d\t%d\n" % (f, how, ret, c) for (f, how, ret), c in sorted(outcomes.items())))
    cov_lines = ["function\tstart\tbytes\tinstructions\texecuted\tunexecuted_runs"]
    for name, start, size, total, live, runs in coverage_rows(image, executed):
        cov_lines.append("%s\t%#x\t%d\t%d\t%d\t%s" % (name, start, size, total, live,
                         ",".join("%x-%x:%s" % (a, b, kind) for a, b, kind in runs) or "-"))
    (out / "coverage.tsv").write_text("\n".join(cov_lines) + "\n")
    controls = run_controls()
    detected = sum(1 for row in controls if row[2])
    equivalent = [row for row in controls if not row[2]]
    (out / "controls.tsv").write_text("kind\tmutation\tdetected\n" + "".join(
        "%s\t%s\t%d\n" % (kind, label, 1 if hit else 0) for kind, label, hit in controls if hit))
    (out / "equivalent-mutants.tsv").write_text("mutation\treason\n" + "".join(
        "%s\t%s\n" % (label, EQUIVALENT_REASON.get(label, "no executed path depends on it"))
        for kind, label, hit in equivalent))
    summary = {"cases": n, "mismatches": mismatches, "negative_controls": len(controls),
               "negative_detected": detected, "equivalent": len(equivalent), "per_function": counts}
    (out / "measure.json").write_text(json.dumps(summary, indent=1, sort_keys=True) + "\n")
    print(json.dumps(summary, sort_keys=True))
    return 0 if mismatches == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
