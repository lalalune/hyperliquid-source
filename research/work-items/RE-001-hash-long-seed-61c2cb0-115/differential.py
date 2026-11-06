"""Unicorn differential for the RE-001-hash-long-seed-61c2cb0-115
packet: run the real 1393 bytes of routine 0x61c2cb0 from the
digest-verified work binary against the Python model
(tools/hash_long_seed_61c2cb0_115.py) over the length/seed
space the parent dispatch delegates here.

The routine's own bytes run natively under emulation. Its
two callees do not: the merge call at 0x61c31fc (target
0x61c27f0) and the seed==0 delegation jump at 0x61c2cf3
(target 0x61c2890) are intercepted and answered with the
same recording contract functions the model uses. That is
exactly the packet's claim boundary: 0x61c2cb0's own
instructions -- the custom-secret construction from the
.rodata constants (the real constant pages are mapped, so
the native side reads the same bytes the model pins), the
accumulator init, the three accumulate loops, the scramble,
the merge hand-off arguments -- are what is being
differentially tested; the callees' bodies are by contract
only.

Per case the harness fills one input window, runs the
model on it and the real bytes on the same bytes under
Unicorn, then compares:

  * the ordered callee event log (one delegate event with
    the untouched arguments on the seed == 0 path; one
    merge event with the final accumulator tuple, the 64
    secret bytes at custom secret + 11, and
    start = length * PRIME64_1 on the seed != 0 path);
  * the return value (the contract answer, passed
    through);
  * the native stack frame after the run: the accumulator
    array at frame +0x00..+0x40 and the custom secret at
    frame +0x40..+0x100 against the model's;
  * the whole input window, byte for byte (the routine
    must not write through the data pointer);
  * the callee-saved registers and the stack pointer,
    which the routine must restore.

Run with a Python that has unicorn available, from the
repository root:

    python3 research/work-items/RE-001-hash-long-seed-61c2cb0-115/differential.py

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
from hash_long_seed_61c2cb0_115 import (  # noqa: E402
    MERGE_SECRET_OFFSET,
    PRIME64_1,
    custom_secret,
    hash_long_seed,
    merge_accs,
    secret_bytes,
)

from unicorn import Uc, UC_ARCH_X86, UC_HOOK_CODE, UC_MODE_64  # noqa: E402
from unicorn.x86_const import (  # noqa: E402
    UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RDX,
    UC_X86_REG_RSI, UC_X86_REG_RDI, UC_X86_REG_RBP, UC_X86_REG_RSP,
    UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_R10, UC_X86_REG_R11,
    UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15,
    UC_X86_REG_RIP,
)

ROUTINE = 0x61C2CB0
ROUTINE_SIZE = 1393
MERGE = 0x61C27F0
DELEGATE = 0x61C2890
STACK_CHK_PLT = 0x63F0D70
CODE_PAGES = (0x61C2000, 0x61C3000)
RODATA_PAGES = tuple(0x450000 + 0x1000 * i for i in range(7))

DATA_BASE, DATA_SIZE = 0x40000000, 0x10000
STACK_BASE, STACK_SIZE = 0x7F000000, 0x2000
SENTINEL = 0x90000000
FRAME_SIZE = 0x118

CALLEE_SAVED = [UC_X86_REG_RBX, UC_X86_REG_RBP, UC_X86_REG_R12,
                UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15]
GP_FILL = [UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_R10,
           UC_X86_REG_R11]


class Env:
    """Recording callee environment shared by both sides:
    delegate answers a preset result; merge answers with
    the packet's merge contract function."""

    def __init__(self, result):
        self.result = result
        self.events = []

    def delegate(self, data, length):
        self.events.append(("delegate", data, length, 0))
        return self.result

    def merge(self, acc, secret, start):
        window = secret[MERGE_SECRET_OFFSET:MERGE_SECRET_OFFSET + 64]
        self.events.append(("merge", acc, window, start))
        return merge_accs(acc, window, start)


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
        if DATA_BASE <= addr and addr + n <= DATA_BASE + DATA_SIZE:
            return bytes(img[addr - DATA_BASE:addr - DATA_BASE + n])
        raise AssertionError("model read outside window: %#x" % addr)

    def write(addr, data):
        raise AssertionError("model wrote memory: %#x" % addr)

    return SliceMem(read, write)


def run_native(data, img, length, seed, result, reg_fill):
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    uc.mem_map(0, 0x1000)  # %fs:0x28 canary cell (fs base is 0)
    uc.mem_write(0x28, struct.pack("<Q", 0xC0FFEE1234567890))
    for page in CODE_PAGES:
        uc.mem_map(page, 0x1000)
        uc.mem_write(page, data[page - 0x1000:page - 0x1000 + 0x1000])
    for page in RODATA_PAGES:
        uc.mem_map(page, 0x1000)
        uc.mem_write(page, data[page:page + 0x1000])
    uc.mem_map(DATA_BASE, DATA_SIZE)
    uc.mem_write(DATA_BASE, bytes(img))
    uc.mem_map(STACK_BASE, STACK_SIZE)
    uc.mem_map(SENTINEL, 0x1000)
    stack_top = STACK_BASE + STACK_SIZE - 0x10
    uc.mem_write(stack_top, struct.pack("<Q", SENTINEL))
    env = Env(result)
    state = {}

    def ret_from_call():
        rsp = uc.reg_read(UC_X86_REG_RSP)
        target = struct.unpack("<Q", uc.mem_read(rsp, 8))[0]
        uc.reg_write(UC_X86_REG_RSP, rsp + 8)
        uc.reg_write(UC_X86_REG_RIP, target)

    def hook(uc_, address, size, _data):
        if address == MERGE:
            acc_ptr = uc_.reg_read(UC_X86_REG_RDI)
            sec_ptr = uc_.reg_read(UC_X86_REG_RSI)
            start = uc_.reg_read(UC_X86_REG_RDX)
            acc = struct.unpack("<QQQQQQQQ", uc_.mem_read(acc_ptr, 64))
            window = bytes(uc_.mem_read(sec_ptr, 64))
            env.events.append(("merge", acc, window, start))
            uc_.reg_write(UC_X86_REG_RAX,
                          merge_accs(acc, window, start))
            ret_from_call()
        elif address == DELEGATE:
            state["delegate_rsp"] = uc_.reg_read(UC_X86_REG_RSP)
            env.events.append(("delegate",
                               uc_.reg_read(UC_X86_REG_RDI),
                               uc_.reg_read(UC_X86_REG_RSI),
                               uc_.reg_read(UC_X86_REG_RDX)))
            uc_.reg_write(UC_X86_REG_RAX, result)
            ret_from_call()
        elif address == STACK_CHK_PLT:
            raise AssertionError("stack_chk_fail reached")

    uc.hook_add(UC_HOOK_CODE, hook)
    for reg, value in reg_fill.items():
        uc.reg_write(reg, value)
    uc.reg_write(UC_X86_REG_RDI, DATA_BASE)
    uc.reg_write(UC_X86_REG_RSI, length)
    uc.reg_write(UC_X86_REG_RDX, seed)
    uc.reg_write(UC_X86_REG_RSP, stack_top)
    uc.emu_start(ROUTINE, SENTINEL)
    out_img = bytearray(uc.mem_read(DATA_BASE, DATA_SIZE))
    frame = bytes(uc.mem_read(stack_top - FRAME_SIZE, 0x100))
    saved = {reg: uc.reg_read(reg) for reg in CALLEE_SAVED}
    return out_img, env, uc.reg_read(UC_X86_REG_RAX), saved, \
        uc.reg_read(UC_X86_REG_RSP), frame, state


def run_case(data, img, length, seed, result, label, rng):
    exp_env = Env(result)
    model_ret = hash_long_seed(window_backend(img), DATA_BASE,
                               length, seed, exp_env)
    reg_fill = {reg: rng.getrandbits(64)
                for reg in CALLEE_SAVED + GP_FILL}
    act_img, act_env, act_ret, saved, rsp, frame, state = \
        run_native(data, img, length, seed, result, reg_fill)
    if act_env.events != exp_env.events:
        raise AssertionError(
            "%s: event mismatch\n  native: %s\n  model:  %s"
            % (label, act_env.events, exp_env.events))
    if act_ret != model_ret:
        raise AssertionError(
            "%s: return mismatch %#x vs %#x" % (label, act_ret, model_ret))
    if act_img != img:
        diff = [i for i in range(DATA_SIZE) if act_img[i] != img[i]]
        raise AssertionError(
            "%s: input window written at offsets %s"
            % (label, [hex(DATA_BASE + d) for d in diff[:8]]))
    for reg in CALLEE_SAVED:
        if saved[reg] != reg_fill[reg]:
            raise AssertionError(
                "%s: callee-saved register not preserved" % label)
    if rsp != STACK_BASE + STACK_SIZE - 0x10 + 8:
        raise AssertionError("%s: stack pointer not restored" % label)
    if seed == 0:
        if state.get("delegate_rsp") != STACK_BASE + STACK_SIZE - 0x10:
            raise AssertionError(
                "%s: delegation with unrestored stack" % label)
    else:
        acc, secret = None, None
        for event in exp_env.events:
            if event[0] == "merge":
                acc = event[1]
        secret = secret_bytes(custom_secret(seed))
        want_frame = b"".join(w.to_bytes(8, "little") for w in acc) \
            + secret
        if frame != want_frame:
            raise AssertionError(
                "%s: stack frame mismatch (acc/secret)" % label)


def make_img(rng, length, pattern):
    img = bytearray(rng.getrandbits(8) for _ in range(DATA_SIZE))
    body = bytearray(length)
    if pattern == "random":
        body = bytearray(rng.getrandbits(8) for _ in range(length))
    elif pattern == "zeros":
        body = bytearray(length)
    elif pattern == "ones":
        body = bytearray(b"\xff" * length)
    elif pattern == "count":
        body = bytearray(i & 0xFF for i in range(length))
    img[0:length] = body
    return img


def main():
    data = BINARY.read_bytes()
    if hashlib.sha256(data).hexdigest() != DIGEST:
        raise SystemExit("work binary digest mismatch")
    routine = data[ROUTINE - 0x1000:ROUTINE - 0x1000 + ROUTINE_SIZE]
    if len(routine) != ROUTINE_SIZE or routine[:7] != bytes.fromhex(
            "4881ec18010000"):
        raise SystemExit("routine bytes mismatch")
    rng = random.Random(0x61C2CB0)
    count = 0
    # Seed == 0: delegation only, arguments untouched.
    for length in (241, 242, 1024, 3000):
        img = make_img(rng, length, "random")
        run_case(data, img, length, 0, rng.getrandbits(64),
                 "seed 0 len %d" % length, rng)
        count += 1
    # Length decision edges x seed variety.
    lengths = [241, 242, 247, 248, 255, 256, 257, 300, 319, 320,
               321, 383, 384, 385, 448, 511, 512, 513, 640, 767,
               768, 960, 1000, 1023, 1024, 1025, 1087, 1088, 1089,
               1152, 1536, 1984, 2047, 2048, 2049, 2112, 3000,
               4095, 4096, 5000]
    seeds = [1, 2, 3, 0xDEADBEEF, 0xFFFFFFFFFFFFFFFF,
             0x8000000000000000, PRIME64_1, 0x0123456789ABCDEF]
    patterns = ["random", "zeros", "ones", "count"]
    for i, length in enumerate(lengths):
        seed = seeds[i % len(seeds)]
        img = make_img(rng, length, patterns[i % len(patterns)])
        run_case(data, img, length, seed, rng.getrandbits(64),
                 "len %d seed %#x" % (length, seed), rng)
        count += 1
    # Random sweep.
    for i in range(120):
        length = rng.randrange(241, 5200)
        seed = rng.getrandbits(64) or 1
        img = make_img(rng, length, "random")
        run_case(data, img, length, seed, rng.getrandbits(64),
                 "random %d (len %d)" % (i, length), rng)
        count += 1
    print("%d cases, 0 mismatches" % count)
    print("DIFFERENTIAL PASSED")


if __name__ == "__main__":
    main()
