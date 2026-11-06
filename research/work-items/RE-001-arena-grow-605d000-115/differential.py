"""Unicorn differential for RE-001-arena-grow-605d000-115.

Runs the real binary window 0x605d000 (with its real helper
windows) under Unicorn against the digest-verified work binary,
with the PLT externals replaced by deterministic oracles, and
compares the observable outcome with the Python model in
tools/arena_grow_115.py: return value or thrown exception kind,
the ordered external-effect log (mmap / munmap / operator new /
operator delete / wake / throw / resume), the arena object fields,
the deque map slots, the descriptor contents of every chunk, the
accumulated counter and the notify tracker state.

Run with a Python that has unicorn installed:
    python3 research/work-items/RE-001-arena-grow-605d000-115/differential.py
Prints a per-case line and a summary; exit status 1 on any mismatch.
"""

import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "tools"))

from arena_grow_115 import (  # noqa: E402
    ArenaGrow,
    BadAlloc,
    BadArrayNewLength,
    Hooks,
    LengthError,
    NotifyTracker,
)

BIN_PATH = os.path.join(ROOT, "work", "hl-node-115.bin")
DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

GROW = 0x605D000
PAD = 0x605D395
WAKE = 0x606A0C0
EXC = 0xDEAD0000
RET_ADDR = 0x64FF000

OBJ = 0x10080000
MAPB = 0x10000000
CHUNK_BASE = 0x10100000
TRACKER = 0x10090000
HEAD = 0x100A0000
STACK_TOP = 0x7F0FF008
FS_BASE = 0x20000000
REGION_BASE = 0x40000000
ALLOC_BASE = 0x41000000

PLT = {
    0x63F15A0: "mmap",
    0x63F0C00: "munmap",
    0x63F0DD0: "new",
    0x63F0D80: "delete",
    0x63F0A70: "memmove",
    0x63F0DE0: "throw_length",
    0x63F0ED0: "throw_badalloc",
    0x63F0EC0: "throw_badarray",
    0x63F0D70: "stack_chk",
    0x63F0A50: "resume",
}

OFF = {
    "map": 0x868, "map_size": 0x870,
    "start_cur": 0x878, "start_first": 0x880, "start_last": 0x888,
    "start_node": 0x890, "finish_cur": 0x898,
    "finish_first": 0x8A0, "finish_last": 0x8A8,
    "finish_node": 0x8B0, "used": 0x8E0, "notify": 0x8E8,
}


class Oracle:
    """Deterministic external-effect oracle shared by both sides."""

    def __init__(self, fail_mmap=False, fail_new_at=None,
                 wake_throws=False):
        self.log = []
        self.fail_mmap = fail_mmap
        self.fail_new_at = fail_new_at
        self.wake_throws = wake_throws
        self.new_calls = 0
        self.region_count = 0
        self.alloc_next = ALLOC_BASE

    def region(self):
        addr = REGION_BASE + self.region_count * 0x100000
        self.region_count += 1
        return addr

    def alloc(self, nbytes):
        addr = self.alloc_next
        self.alloc_next += max(0x1000, (nbytes + 0xFFF) & ~0xFFF)
        return addr


def build_spec(node_counts, map_size=None, start_index=0, start_skip=0,
               used=0, notify=None, **extra):
    spec = {
        "node_counts": node_counts, "map_size": map_size,
        "start_index": start_index, "start_skip": start_skip,
        "used": used, "notify": notify,
    }
    spec.update(extra)
    return spec


def spec_geometry(spec):
    counts = spec["node_counts"]
    n = len(counts)
    map_size = spec["map_size"] if spec["map_size"] is not None else n
    chunks = [CHUNK_BASE + 0x10000 * i for i in range(n)]
    slots = [0] * map_size
    for i in range(n):
        slots[spec["start_index"] + i] = chunks[i]
    return chunks, slots, map_size


def model_run(spec, size, oracle):
    chunks, slots, map_size = spec_geometry(spec)
    counts = spec["node_counts"]
    start_index = spec["start_index"]
    finish_index = start_index + len(counts) - 1

    def mmap(sz, prot, flags):
        oracle.log.append(("mmap", sz, prot, flags))
        return (1 << 64) - 1 if oracle.fail_mmap else oracle.region()

    def munmap(addr, length):
        oracle.log.append(("munmap", addr, length))

    def operator_new(nbytes):
        oracle.log.append(("new", nbytes))
        oracle.new_calls += 1
        if oracle.fail_new_at == oracle.new_calls:
            raise BadAlloc("bad_alloc")
        return oracle.alloc(nbytes)

    def operator_delete(addr, nbytes):
        oracle.log.append(("delete", addr, nbytes))

    def wake(head):
        oracle.log.append(("wake", head))
        if oracle.wake_throws:
            raise RuntimeError("wake")

    hooks = Hooks(mmap=mmap, munmap=munmap, operator_new=operator_new,
                  operator_delete=operator_delete, wake=wake)
    notify = None
    if spec["notify"] is not None:
        notify = NotifyTracker(head=HEAD, counter=spec["notify"][2],
                               head_first=spec["notify"][0],
                               head_late=spec["notify"][1])
    arena = ArenaGrow(
        hooks, map_address=MAPB, map_slots=slots,
        map_size_field=spec.get("map_size_field"),
        start_node_index=start_index,
        start_cur=chunks[0] + spec["start_skip"] * 16,
        start_first=chunks[0], start_last=chunks[0] + 0x200,
        finish_node_index=finish_index,
        finish_cur=chunks[-1] + counts[-1] * 16,
        finish_first=chunks[-1], finish_last=chunks[-1] + 0x200,
        used=spec["used"], notify=notify)
    for i, count in enumerate(counts):
        base = spec["start_skip"] if i == 0 else 0
        for k in range(base, count):
            arena.chunks.setdefault(chunks[i], {})[k * 16] = (
                0xABC000 + i * 0x100 + k, 0x1000)
    raw_fields = spec.get("raw_fields")
    if raw_fields:
        for name, value in raw_fields.items():
            setattr(arena, name, value)
    outcome = None
    try:
        outcome = ("return", arena.grow(size))
    except LengthError:
        outcome = ("throw", "length_error")
    except BadArrayNewLength:
        outcome = ("throw", "bad_array_new_length")
    except BadAlloc:
        outcome = ("throw", "bad_alloc")
    except RuntimeError:
        outcome = ("throw", "wake")
    if outcome[0] == "throw":
        # The pad's munmap of the region (when it still owned one)
        # is the hook entry right after the throw point in native
        # order; normalise the model log to native order:
        # throw, [munmap], resume.
        log = oracle.log
        mun = None
        if log and log[-1][0] == "munmap":
            mun = log.pop()
        log.append(("throw", outcome[1]))
        if mun:
            log.append(mun)
        log.append(("resume", EXC))
    state = {
        "map": arena.map_address, "map_size": arena.map_size,
        "slots": list(arena.map_slots),
        "start_node": arena.start_node, "start_cur": arena.start_cur,
        "start_first": arena.start_first, "start_last": arena.start_last,
        "finish_node": arena.finish_node, "finish_cur": arena.finish_cur,
        "finish_first": arena.finish_first,
        "finish_last": arena.finish_last,
        "used": arena.used,
        "notify_counter": None if notify is None else notify.counter,
        "elements": None if raw_fields else arena.elements(),
        "chunks": {a: dict(c) for a, c in arena.chunks.items()},
    }
    return outcome, oracle.log, state


class Emu:
    def __init__(self, data):
        from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE
        from unicorn.x86_const import (UC_X86_REG_FS_BASE)
        self.UC_X86_REG_FS_BASE = UC_X86_REG_FS_BASE
        uc = Uc(UC_ARCH_X86, UC_MODE_64)
        uc.mem_map(0x0, 0x6800000)
        # PT_LOAD segments (offset, vaddr, filesz) of the target ELF:
        # file offsets and virtual addresses differ per segment.
        for off, va, sz in ((0x0, 0x0, 0x1418254),
                            (0x1418300, 0x1419300, 0x4FD88A0),
                            (0x63F0BA0, 0x63F2BA0, 0x0FBE80),
                            (0x64ECA20, 0x64EFA20, 0x0103E8)):
            for k in range(0, sz, 0x100000):
                uc.mem_write(va + k, data[off + k:off + k + 0x100000])
        uc.mem_map(0x10000000, 0x200000)
        uc.mem_map(0x20000000, 0x10000)
        uc.mem_map(0x40000000, 0x2000000)
        uc.mem_map(0x7F000000, 0x100000)
        uc.mem_write(FS_BASE + 0x28, struct.pack("<Q", 0xC0FFEE))
        uc.reg_write(UC_X86_REG_FS_BASE, FS_BASE)
        uc.hook_add(UC_HOOK_CODE, self._hook)
        self.uc = uc
        self.status = None

    def _ret(self, uc):
        from unicorn.x86_const import UC_X86_REG_RSP, UC_X86_REG_RIP
        rsp = uc.reg_read(UC_X86_REG_RSP)
        (target,) = struct.unpack("<Q", uc.mem_read(rsp, 8))
        uc.reg_write(UC_X86_REG_RSP, rsp + 8)
        uc.reg_write(UC_X86_REG_RIP, target)

    def _throw(self, uc, kind):
        from unicorn.x86_const import (UC_X86_REG_RAX, UC_X86_REG_RIP,
                                       UC_X86_REG_RSP)
        self.oracle.log.append(("throw", kind))
        rsp = uc.reg_read(UC_X86_REG_RSP)
        uc.reg_write(UC_X86_REG_RSP, rsp + 8)  # undo the call push
        uc.reg_write(UC_X86_REG_RAX, EXC)
        uc.reg_write(UC_X86_REG_RIP, PAD)
        self.thrown = kind

    def _hook(self, uc, address, size, _):
        from unicorn.x86_const import (UC_X86_REG_RAX, UC_X86_REG_RDI,
                                       UC_X86_REG_RSI, UC_X86_REG_RDX,
                                       UC_X86_REG_RCX, UC_X86_REG_RIP)
        if address == RET_ADDR:
            self.status = ("return", uc.reg_read(UC_X86_REG_RAX))
            uc.emu_stop()
            return
        if address == WAKE:
            head = uc.reg_read(UC_X86_REG_RDI)
            self.oracle.log.append(("wake", head))
            if self.oracle.wake_throws:
                self._throw(uc, "wake")
                return
            self._ret(uc)
            return
        name = PLT.get(address)
        if name is None:
            return
        rdi = uc.reg_read(UC_X86_REG_RDI)
        rsi = uc.reg_read(UC_X86_REG_RSI)
        rdx = uc.reg_read(UC_X86_REG_RDX)
        rcx = uc.reg_read(UC_X86_REG_RCX)
        if name == "mmap":
            self.oracle.log.append(("mmap", rsi, rdx, rcx))
            uc.reg_write(UC_X86_REG_RAX,
                         ((1 << 64) - 1) if self.oracle.fail_mmap
                         else self.oracle.region())
            self._ret(uc)
        elif name == "munmap":
            self.oracle.log.append(("munmap", rdi, rsi))
            uc.reg_write(UC_X86_REG_RAX, 0)
            self._ret(uc)
        elif name == "new":
            self.oracle.log.append(("new", rdi))
            self.oracle.new_calls += 1
            if self.oracle.fail_new_at == self.oracle.new_calls:
                self._throw(uc, "bad_alloc")
                return
            uc.reg_write(UC_X86_REG_RAX, self.oracle.alloc(rdi))
            self._ret(uc)
        elif name == "delete":
            self.oracle.log.append(("delete", rdi, rsi))
            self._ret(uc)
        elif name == "memmove":
            uc.mem_write(rdi, bytes(uc.mem_read(rsi, rdx)))
            uc.reg_write(UC_X86_REG_RAX, rdi)
            self._ret(uc)
        elif name == "throw_length":
            raw = bytes(uc.mem_read(rdi, 64))
            msg = raw.split(b"\0")[0].decode()
            self.oracle.log.append(("length_message", msg))
            self._throw(uc, "length_error")
        elif name == "throw_badalloc":
            self._throw(uc, "bad_alloc")
        elif name == "throw_badarray":
            self._throw(uc, "bad_array_new_length")
        elif name == "stack_chk":
            self.status = ("stack_chk_fail", None)
            uc.emu_stop()
        elif name == "resume":
            self.oracle.log.append(("resume", rdi))
            self.status = ("throw", getattr(self, "thrown", "?"))
            uc.emu_stop()

    def run(self, spec, size, oracle):
        from unicorn.x86_const import (UC_X86_REG_RDI, UC_X86_REG_RSI,
                                       UC_X86_REG_RSP, UC_X86_REG_RIP,
                                       UC_X86_REG_RAX, UC_X86_REG_RBX,
                                       UC_X86_REG_R12)
        uc = self.uc
        self.oracle = oracle
        self.thrown = None
        self.status = None
        # wipe mutable regions
        uc.mem_write(0x10000000, bytes(0x200000))
        uc.mem_write(0x40000000, bytes(0x2000000))
        uc.mem_write(0x7F000000, bytes(0x100000))
        chunks, slots, map_size = spec_geometry(spec)
        counts = spec["node_counts"]

        def w64(addr, value):
            uc.mem_write(addr, struct.pack("<Q", value & (1 << 64) - 1))

        for i, slot in enumerate(slots):
            w64(MAPB + 8 * i, slot)
        fields = {
            "map": MAPB, "map_size": spec.get("map_size_field", map_size),
            "start_cur": chunks[0] + spec["start_skip"] * 16,
            "start_first": chunks[0], "start_last": chunks[0] + 0x200,
            "start_node": MAPB + 8 * spec["start_index"],
            "finish_cur": chunks[-1] + counts[-1] * 16,
            "finish_first": chunks[-1],
            "finish_last": chunks[-1] + 0x200,
            "finish_node": MAPB + 8 * (spec["start_index"]
                                       + len(counts) - 1),
            "used": spec["used"],
            "notify": 0 if spec["notify"] is None else TRACKER,
        }
        raw = spec.get("raw_fields_emu")
        if raw:
            fields.update(raw)
        for name, value in fields.items():
            w64(OBJ + OFF[name], value)
        for i, count in enumerate(counts):
            base = spec["start_skip"] if i == 0 else 0
            for k in range(base, count):
                w64(chunks[i] + k * 16, 0xABC000 + i * 0x100 + k)
                w64(chunks[i] + k * 16 + 8, 0x1000)
        if spec["notify"] is not None:
            w64(TRACKER + 0, HEAD)
            w64(TRACKER + 8, spec["notify"][2])
            w64(HEAD + 0, spec["notify"][0])
            w64(HEAD + 0x20, spec["notify"][1])
        from unicorn.x86_const import (UC_X86_REG_RCX, UC_X86_REG_RDX,
                                       UC_X86_REG_RBP, UC_X86_REG_R8,
                                       UC_X86_REG_R9, UC_X86_REG_R10,
                                       UC_X86_REG_R11, UC_X86_REG_R13,
                                       UC_X86_REG_R14, UC_X86_REG_R15,
                                       UC_X86_REG_RIP)
        uc.reg_write(UC_X86_REG_RSP, STACK_TOP)
        w64(STACK_TOP, RET_ADDR)
        uc.reg_write(UC_X86_REG_RDI, OBJ)
        uc.reg_write(UC_X86_REG_RSI, size)
        for reg in (UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RCX,
                    UC_X86_REG_RDX, UC_X86_REG_RBP, UC_X86_REG_R8,
                    UC_X86_REG_R9, UC_X86_REG_R10, UC_X86_REG_R11,
                    UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14,
                    UC_X86_REG_R15):
            uc.reg_write(reg, 0)
        try:
            uc.emu_start(GROW, RET_ADDR, count=2000000)
        except Exception as exc:  # unicorn fault ~ native fault
            self.status = ("fault", str(exc))
        if self.status is None and \
                uc.reg_read(UC_X86_REG_RIP) == RET_ADDR:
            self.status = ("return", uc.reg_read(UC_X86_REG_RAX))
        state = {}
        for name, off in OFF.items():
            (value,) = struct.unpack("<Q", uc.mem_read(OBJ + off, 8))
            state[name] = value
        n_slots = min(state["map_size"], 64)
        state["slots"] = [struct.unpack("<Q", uc.mem_read(
            state["map"] + 8 * i, 8))[0] for i in range(n_slots)]
        state["notify_counter"] = None
        if spec["notify"] is not None:
            (state["notify_counter"],) = struct.unpack(
                "<Q", uc.mem_read(TRACKER + 8, 8))
        # chunk contents: for every chunk address referenced by the
        # initial or final maps plus oracle allocations, read 32
        # descriptor slots
        addrs = set(slots) | set(state["slots"])
        addrs.discard(0)
        state["chunks"] = {}
        for addr in sorted(addrs):
            if not (0x10000000 <= addr < 0x10200000 or
                    0x40000000 <= addr < 0x42000000):
                continue
            contents = {}
            for k in range(32):
                a, ln = struct.unpack("<QQ", uc.mem_read(
                    addr + k * 16, 16))
                if (a, ln) != (0, 0):
                    contents[k * 16] = (a, ln)
            state["chunks"][addr] = contents
        log = [e for e in oracle.log if e[0] != "length_message"]
        msgs = [e[1] for e in oracle.log if e[0] == "length_message"]
        return self.status, log, state, msgs


def _view(state):
    return {
        "map": state["map"], "map_size": state["map_size"],
        "slots": state["slots"],
        "start_node": state["start_node"], "start_cur": state["start_cur"],
        "start_first": state["start_first"],
        "start_last": state["start_last"],
        "finish_node": state["finish_node"],
        "finish_cur": state["finish_cur"],
        "finish_first": state["finish_first"],
        "finish_last": state["finish_last"],
        "used": state["used"],
        "notify_counter": state["notify_counter"],
        # empty chunks carry no observable content on either side
        "chunks": {a: c for a, c in state["chunks"].items() if c},
    }


def model_state_view(state):
    return _view(state)


def emu_state_view(state):
    return _view(state)


def cases():
    base = build_spec([5], used=100)
    yield "fast append", base, 0x2000, {}
    yield "mmap failure", base, 0x2000, {"fail_mmap": True}
    yield "size zero", base, 0, {}
    yield "fast at 30", build_spec([30]), 0x100, {}
    yield "aux slack", build_spec([31], map_size=4), 0x800, {}
    yield "aux slack fail new", build_spec([31], map_size=4), 0x800, \
        {"fail_new_at": 1}
    yield "aux recenter", build_spec([32, 32, 31], map_size=16,
                                     start_index=13), 0x800, {}
    yield "aux new map x1", build_spec([31], map_size=1), 0x800, {}
    yield "aux new map x1 fail", build_spec([31], map_size=1), 0x800, \
        {"fail_new_at": 1}
    yield "aux new map x2", build_spec([31], map_size=2,
                                       start_index=1), 0x800, {}
    yield "start skip fast", build_spec([20, 5], map_size=6,
                                        start_index=1, start_skip=20), \
        0x800, {}
    yield "multi node fast", build_spec([32, 32, 7], map_size=8,
                                        start_index=2), 0x800, {}
    yield "notify active first", build_spec([3], notify=(1, 0, 10)), \
        0x800, {}
    yield "notify active late", build_spec([3], notify=(0, 7, 0)), \
        0x40, {}
    yield "notify dormant", build_spec([3], notify=(0, 0, 10)), 0x800, {}
    yield "notify wake throws", build_spec([3], notify=(1, 0, 0)), \
        0x800, {"wake_throws": True}
    # fabricated: deque size hits max_size exactly
    chunk = CHUNK_BASE
    yield "length error", build_spec(
        [31], raw_fields={
            "start_cur": chunk + 0x200,
            "finish_node": MAPB + (1 << 54) * 8,
            "finish_cur": chunk + 31 * 16,
        }, raw_fields_emu={
            "start_cur": chunk + 0x200,
            "finish_node": MAPB + (1 << 54) * 8,
            "finish_cur": chunk + 31 * 16,
        }), 0x800, {}
    # fabricated: map growth overflow discrimination
    for field, label in (((1 << 59) - 1, "bad_alloc"),
                         ((1 << 60) - 1, "bad_array_new_length")):
        yield "overflow " + label, build_spec(
            [31], raw_fields={
                "finish_node": MAPB + (field - 1) * 8,
                "finish_cur": chunk + 31 * 16,
            }, raw_fields_emu={
                "finish_node": MAPB + (field - 1) * 8,
                "finish_cur": chunk + 31 * 16,
            }, map_size_field=field), 0x800, {}
    # parameter sweep: fast path across every finish fill level
    for count in range(0, 31):
        yield "sweep fast count=%d" % count, build_spec(
            [count], used=count * 7), 0x100 + 16 * count, {}
    # parameter sweep: aux with map slack, varying map sizes
    for map_size in range(3, 9):
        yield "sweep aux slack map=%d" % map_size, build_spec(
            [31], map_size=map_size), 0x800, {}
    # parameter sweep: aux new map, varying old map sizes
    for map_size in (1, 2, 3):
        yield "sweep aux newmap map=%d" % map_size, build_spec(
            [31], map_size=map_size,
            start_index=map_size - 1), 0x800, {}
    # parameter sweep: recenter with spans 1..3 at the map tail
    for span in (1, 2, 3):
        counts = [32] * (span - 1) + [31]
        yield "sweep recenter span=%d" % span, build_spec(
            counts, map_size=16, start_index=16 - span), 0x800, {}
    # parameter sweep: multi-node fast path with start consumption
    for skip in (0, 1, 17, 31):
        yield "sweep skip=%d" % skip, build_spec(
            [32, 9], map_size=6, start_index=2, start_skip=skip), \
            0x800, {}


def main():
    import hashlib
    data = open(BIN_PATH, "rb").read()
    if hashlib.sha256(data).hexdigest() != DIGEST:
        print("FAIL: binary digest mismatch")
        return 1
    emu = Emu(data)
    total = 0
    failed = 0
    for name, spec, size, oracle_kw in cases():
        total += 1
        size_spec = dict(spec)
        m_oracle = Oracle(**oracle_kw)
        m_outcome, m_log, m_state = model_run(size_spec, size, m_oracle)
        e_oracle = Oracle(**oracle_kw)
        e_outcome, e_log, e_state, msgs = emu.run(spec, size, e_oracle)
        problems = []
        if m_outcome != e_outcome:
            problems.append("outcome model=%r emu=%r" % (m_outcome,
                                                         e_outcome))
        if m_log != e_log:
            problems.append("log model=%r emu=%r" % (m_log, e_log))
        if spec.get("raw_fields"):
            # fabricated states: compare only the object fields
            keys = ("map_size", "used", "finish_cur", "start_cur")
            for k in keys:
                if model_state_view(m_state)[k] != \
                        emu_state_view(e_state)[k]:
                    problems.append("field %s model=%r emu=%r" % (
                        k, model_state_view(m_state)[k],
                        emu_state_view(e_state)[k]))
        else:
            mv, ev = model_state_view(m_state), emu_state_view(e_state)
            if mv != ev:
                for k in mv:
                    if mv[k] != ev[k]:
                        problems.append("state %s model=%r emu=%r"
                                        % (k, mv[k], ev[k]))
        if e_outcome == ("throw", "length_error") and \
                msgs != ["cannot create std::deque larger than "
                         "max_size()"]:
            problems.append("length_error message %r" % (msgs,))
        if problems:
            failed += 1
            print("FAIL", name)
            for p in problems:
                print("   ", p)
        else:
            print("PASS", name)
    print("differential: %d cases, %d failed" % (total, failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
