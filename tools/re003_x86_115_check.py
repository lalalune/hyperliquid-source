#!/usr/bin/env python3
"""Check the shared node #115 x86-64 interpreter (tools/x86_115.py) against the interpreters of five merged evidence tools.

Four comparisons, all offline on the ELF bytes (the binary is never executed):

1. decode survey: every FDE function sampled at a fixed stride is decoded by the shared decoder; instruction counts, the first
   undecodable instruction of each function and the opcode forms that stop the sweep are tabulated.
2. decode equivalence: for each merged tool, the shared decoder and the tool's own decoder are compared field by field on every
   instruction the tool's cases execute and on a linear sweep of every FDE function those instructions sit in.
3. execution equivalence: each merged tool's own case generator is run once with its own Machine and once with the shared Machine
   (the module globals Machine, Memory, decode are rebound); for each case the run results, all registers, the instruction count and a
   digest of every memory write must be identical, and the shared run must still agree with the tool's written rule list.
4. negative controls: textual mutations of the shared interpreter (flag conditions, widths, sign extension, carries, decode fields) are
   rebuilt as modules and run against the reference digests of 2 and 3. Every mutation is listed; a mutation nothing detects is
   listed with the reason it cannot change behaviour.

    python3 tools/re003_x86_115_check.py --out <dir>
"""

import argparse
import collections
import contextlib
import hashlib
import importlib
import json
import pathlib
import struct
import sys
import types

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import x86_115 as X  # noqa: E402

SURVEY_STRIDE = 8
CASE_ROW_EVERY = 40
ALL_TOOLS_STRIDE = 500
SURVEY_ROWS = 300
TOOLS = (       # tool, cases run (the generated count for the stateful funding harnesses, which run every case in order), ordered
    ("staking_admission_gate115", 4000, False),
    ("staking_listed_set115", 1200, False),
    ("staking_validator_snapshot115", 400, False),
    ("funding_rate115", 3000, True),
    ("funding_premium115", 3000, True),
)
DETECT_ORDER = ("staking_admission_gate115", "funding_rate115", "funding_premium115", "staking_listed_set115", "staking_validator_snapshot115")
BATTERY = 160            # cases per tool re-run for every mutated interpreter
ALIAS = {"shrdi": "shrd"}
SHARED_NAMES = ("Machine", "Memory", "decode", "decode_range")
RAISED = ("Halt", "EvidenceError", "Panicked")


class CheckError(Exception):
    pass


# --------------------------------------------------------------------------------------------------------------------------------
# instruction views
# --------------------------------------------------------------------------------------------------------------------------------

def canon(row):
    return (row.va, row.size, ALIAS.get(row.op, row.op), row.a, row.b, row.width, row.cc, row.target, row.next, row.imm_at,
            row.imm_size, row.rip_at)


def try_decode(function, read, va):
    try:
        return canon(function(read, va)), None
    except (X.EvidenceError, IndexError, struct.error, KeyError) as problem:
        return None, type(problem).__name__


def code_reader(image, start, end):
    base = image.offset(start)
    code = image.blob[base:base + (end - start) + 16]
    return lambda va, count: code[va - start:va - start + count]


def prefix_key(window):
    pos = 0
    while window[pos] in (0x66, 0xF3, 0xF2, 0xF0, 0x2E):
        pos += 1
    if 0x40 <= window[pos] <= 0x4F:
        pos += 1
    return window[pos:pos + 3].hex()


# --------------------------------------------------------------------------------------------------------------------------------
# 1. decode survey
# --------------------------------------------------------------------------------------------------------------------------------

def survey(image, decode=X.decode):
    totals = collections.Counter()
    ops = collections.Counter()
    stops = collections.Counter()
    rows = []
    sample = image.starts[::SURVEY_STRIDE]
    every = max(1, len(sample) // SURVEY_ROWS)
    for index, start in enumerate(sample):
        end = image.fde_ends[start]
        read = code_reader(image, start, end)
        va, count, stop = start, 0, ""
        while va < end:
            try:
                row = decode(read, va)
            except (X.EvidenceError, IndexError, struct.error, KeyError):
                stop = prefix_key(read(va, 16))
                break
            ops[row.op] += 1
            count += 1
            va = row.next
        totals["functions"] += 1
        totals["instructions"] += count
        if stop:
            totals["stopped"] += 1
            stops[stop] += 1
        elif va == end:
            totals["complete"] += 1
        else:
            totals["overran"] += 1
        if index % every == 0:
            rows.append((start, end - start, count, va - start, stop or "-"))
    return totals, ops, stops, rows


def canon_any(row):
    names = ("va", "size", "op", "a", "b", "width", "cc", "target", "next", "imm_at", "imm_size", "rip_at")
    values = [getattr(row, name, None) for name in names]
    values[2] = ALIAS.get(values[2], values[2])
    return tuple(values)


def compare_all_decoders(image):
    """Every tool in tools/ that carries a `decode(read, va)` and a Machine copy: decoded with its own decoder and the shared one on a
    fixed sample of FDE functions. Equality is reported, not assumed: older copies differ in a few operation names and forms."""
    functions = image.starts[::ALL_TOOLS_STRIDE]
    rows = []
    for path in sorted((ROOT / "tools").glob("*.py")):
        text = path.read_text()
        if "def decode(read, va)" not in text or "class Machine" not in text or path.stem in ("x86_115", "re003_x86_115_check"):
            continue
        try:
            module = importlib.import_module(path.stem)
        except Exception as problem:        # noqa: BLE001 - a tool that cannot be imported is listed as such
            rows.append((path.stem, 0, 0, 0, 0, 0, "import failed: " + type(problem).__name__))
            continue
        stats, first = collections.Counter(), "-"
        for start in functions:
            end = image.fde_ends[start]
            read = code_reader(image, start, end)
            va = start
            while va < end:
                got, _ = try_decode(X.decode, read, va)
                try:
                    want = canon_any(module.decode(read, va))
                except Exception:           # noqa: BLE001 - the tool's own EvidenceError class differs per module
                    want = None
                stats["compared"] += 1
                if got is None:
                    if want is None:
                        break
                    stats["shared_narrower"] += 1
                    va = want[8]
                    continue
                if want is None:
                    stats["tool_narrower"] += 1
                elif want == got:
                    stats["same"] += 1
                else:
                    stats["different"] += 1
                    if first == "-":
                        first = "%#x %s/%s" % (va, got[2], want[2])
                va = got[8]
        rows.append((path.stem, stats["compared"], stats["same"], stats["tool_narrower"], stats["shared_narrower"], stats["different"], first))
    return rows


# --------------------------------------------------------------------------------------------------------------------------------
# recording
# --------------------------------------------------------------------------------------------------------------------------------

class Recorder:
    def __init__(self):
        self.writes = hashlib.sha256()
        self.runs = []
        self.machines = {}
        self.run_count = 0
        self.steps = 0


@contextlib.contextmanager
def recording(machine_cls, memory_cls, rec):
    run0, write0, put0 = machine_cls.run, memory_cls.write, memory_cls.put_bytes

    def run(self, entry, args, *rest):
        rec.machines[id(self)] = self
        rec.writes = hashlib.sha256()
        before = self.steps
        problem = None
        try:
            value = run0(self, entry, args, *rest)
            outcome = ("ret", value)
        except BaseException as caught:     # noqa: B902 - re-raised below after the digest is taken
            problem, outcome = caught, (type(caught).__name__, str(caught))
        rec.run_count += 1
        rec.steps += self.steps - before
        rec.runs.append(hashlib.sha256(repr((entry, outcome, tuple(self.regs), tuple(self.xmm), self.steps - before,
                                             rec.writes.hexdigest())).encode()).digest()[:8])
        if problem is not None:
            raise problem
        return value

    def write(self, addr, count, value):
        rec.writes.update(struct.pack("<QQ", addr, count) + (value & ((1 << (8 * count)) - 1)).to_bytes(count, "little"))
        return write0(self, addr, count, value)

    def put_bytes(self, addr, data):
        rec.writes.update(struct.pack("<QQ", addr, len(data)) + bytes(data))
        return put0(self, addr, data)

    machine_cls.run, memory_cls.write, memory_cls.put_bytes = run, write, put_bytes
    try:
        yield rec
    finally:
        machine_cls.run, memory_cls.write, memory_cls.put_bytes = run0, write0, put0


@contextlib.contextmanager
def bound(module, shared):
    """Point a merged tool at the shared interpreter: Machine, Memory, decode and the exception classes it catches."""
    saved = {name: getattr(module, name) for name in SHARED_NAMES}
    old_memory = module.Memory
    swapped = []
    for name, value in list(vars(module).items()):
        if isinstance(value, type) and value is not old_memory and old_memory in value.__bases__:
            swapped.append((value, value.__bases__))
    saved_errors = {name: getattr(shared, name) for name in RAISED}
    for name in RAISED:
        setattr(shared, name, getattr(module, name))
    for name in SHARED_NAMES:
        setattr(module, name, getattr(shared, name))
    for klass, bases in swapped:
        klass.__bases__ = tuple(shared.Memory if base is old_memory else base for base in bases)
    try:
        yield
    finally:
        for klass, bases in swapped:
            klass.__bases__ = bases
        for name, value in saved.items():
            setattr(module, name, value)
        for name, value in saved_errors.items():
            setattr(shared, name, value)


# --------------------------------------------------------------------------------------------------------------------------------
# per-tool adapters: build the cases of the tool and a function that runs one of them and returns (matches the rule list, outcome)
# --------------------------------------------------------------------------------------------------------------------------------

def adapter_gate(m, image, count):
    table, listed = m.read_table(image), m.read_listed(image)
    cases = list(m.all_cases(table, listed))
    gate = m.Gate(image)

    def step(case):
        _, entry, world = case
        got, want = m.run_case(gate, entry, world, table)
        return got == want, got
    return cases, step


def adapter_listed(m, image, count):
    cases = list(m.all_cases())
    run = m.SetRun(image)

    def step(case):
        got, want = m.execute(run, case)
        return got == want, got
    return cases, step


def adapter_snapshot(m, image, count):
    cases = list(m.all_cases())
    lookup = m.Lookup(image)

    def step(case):
        _, entry, world = case
        got, want = m.run_case(lookup, entry, world)
        return got == want, got
    return cases, step


def adapter_funding(spec_name):
    def build(m, image, count):
        k = m.constant_bits(image)
        harness = m.Harness(image)
        cases = m.named_cases() + list(m.random_cases(count))
        spec = getattr(m, spec_name)

        def step(case):
            got, log = m.run_case(harness, case)
            return (got, log) == spec(case, k), (got, log)
        return cases, step
    return build


ADAPTERS = {
    "staking_admission_gate115": adapter_gate, "staking_listed_set115": adapter_listed,
    "staking_validator_snapshot115": adapter_snapshot, "funding_rate115": adapter_funding("spec_rate"),
    "funding_premium115": adapter_funding("spec_premium"),
}


def pick(cases, wanted):
    """At most `wanted` cases spread evenly over the generator order."""
    if len(cases) <= wanted:
        return list(range(len(cases)))
    return sorted({index * len(cases) // wanted for index in range(wanted)})


def run_pass(module, image, adapter, count, chosen=None, limit=None, stop_at=None):
    """Run the chosen cases; returns (case digests, rule list matches, recorder, case count, list of chosen indexes)."""
    rec = Recorder()
    digests, matched = [], 0
    with recording(module.Machine, module.Memory, rec):
        cases, step = adapter(module, image, count)
        indexes = chosen if chosen is not None else (list(range(len(cases))) if limit is None else pick(cases, limit))
        for index in indexes:
            before = len(rec.runs)
            ok, result = step(cases[index])
            digests.append(hashlib.sha256(repr((ok, result, b"".join(rec.runs[before:]))).encode()).digest()[:8])
            matched += bool(ok)
            if stop_at is not None and digests[-1] != stop_at[len(digests) - 1]:
                break
    return digests, matched, rec, len(cases), indexes


# --------------------------------------------------------------------------------------------------------------------------------
# 2. decode equivalence
# --------------------------------------------------------------------------------------------------------------------------------

def decode_executed(module, shared, machines):
    """Compare the tool's decoded rows (its machine caches) with the shared decoder at the same addresses."""
    rows = {}
    for machine in machines.values():
        rows.update(machine.cache)
    stats = collections.Counter()
    reached = {}
    probe = X.Machine(next(iter(machines.values())).image)
    for va in sorted(rows):
        stats["executed"] += 1
        got, error = try_decode(shared.decode, probe.read_code, va)
        want = canon(rows[va])
        reached[va] = want
        if got != want:
            stats["different"] += 1
    return stats, reached, probe


def decode_sweep(module, shared, image, reached):
    """Linear sweep of every FDE function holding a reached instruction, both decoders at every address."""
    stats = collections.Counter()
    functions = sorted({image.fde(va)[0] for va in reached})
    for start in functions:
        end = image.fde_ends[start]
        read = code_reader(image, start, end)
        stats["functions"] += 1
        va = start
        while va < end:
            got, shared_error = try_decode(shared.decode, read, va)
            want, tool_error = try_decode(module.decode, read, va)
            stats["compared"] += 1
            if got is None:
                stats["both_raise" if want is None else "shared_only_raises"] += 1
                if want is not None:
                    stats["different"] += 1
                break
            if want is None:
                stats["tool_only_raises"] += 1
            elif got != want:
                stats["different"] += 1
            va = got[8]
    return stats



# --------------------------------------------------------------------------------------------------------------------------------
# semantic probes: hand assembled routines with results taken from the x86-64 instruction definitions (not from any merged tool)
# --------------------------------------------------------------------------------------------------------------------------------

MARK = X.HEAP_BASE + 0x100
MAXQ = X.MASK[8]
SETB_RESULT = "0F 92 C0 0F B6 C0 C3"
PROBES = (
    # name, code, ((registers, memory {address: (size, value)}, expected {rax, mem, zf, cf}), ...)
    ("setl-signed-compare", "48 39 F7 0F 9C C0 0F B6 C0 C3", (
        ({X.RDI: 1, X.RSI: 2}, {}, {"rax": 1}), ({X.RDI: 2, X.RSI: 1}, {}, {"rax": 0}), ({X.RDI: 1 << 63, X.RSI: 1}, {}, {"rax": 1}),
        ({X.RDI: MAXQ, X.RSI: 1}, {}, {"rax": 1}), ({X.RDI: 5, X.RSI: 5}, {}, {"rax": 0}))),
    ("setb-unsigned-compare", "48 39 F7 " + SETB_RESULT, (
        ({X.RDI: 1, X.RSI: 2}, {}, {"rax": 1}), ({X.RDI: MAXQ, X.RSI: 1}, {}, {"rax": 0}), ({X.RDI: 3, X.RSI: 3}, {}, {"rax": 0}))),
    ("setbe-unsigned-compare", "48 39 F7 0F 96 C0 0F B6 C0 C3", (
        ({X.RDI: 3, X.RSI: 3}, {}, {"rax": 1}), ({X.RDI: 4, X.RSI: 3}, {}, {"rax": 0}), ({X.RDI: 2, X.RSI: 3}, {}, {"rax": 1}))),
    ("add-carry-edge", "48 83 C7 01 " + SETB_RESULT, (
        ({X.RDI: MAXQ - 1}, {}, {"rax": 0}), ({X.RDI: MAXQ}, {}, {"rax": 1}), ({X.RDI: 0}, {}, {"rax": 0}))),
    ("test32-sign", "85 FF 0F 98 C0 0F B6 C0 C3", (
        ({X.RDI: 0x80000000}, {}, {"rax": 1}), ({X.RDI: 0x7FFFFFFF}, {}, {"rax": 0}), ({X.RDI: 0xFFFFFFFF00000000}, {}, {"rax": 0}))),
    ("sub-overflow-flag", "48 39 F7 0F 90 C0 0F B6 C0 C3", (
        ({X.RDI: 1 << 63, X.RSI: 1}, {}, {"rax": 1}), ({X.RDI: 5, X.RSI: 3}, {}, {"rax": 0}), ({X.RDI: (1 << 63) - 1, X.RSI: MAXQ}, {}, {"rax": 1}))),
    ("mov-from-high-byte", "88 E0 C3", (({X.RAX: 0x1234}, {}, {"rax": 0x1212}),)),
    ("shl32-count-mask", "89 F1 D3 E7 89 F8 C3", (
        ({X.RDI: 1, X.RSI: 33}, {}, {"rax": 2}), ({X.RDI: 0x80000001, X.RSI: 1}, {}, {"rax": 2}), ({X.RDI: 3, X.RSI: 32}, {}, {"rax": 3}))),
    ("shl64-count-mask", "48 89 F1 48 D3 E7 48 89 F8 C3", (
        ({X.RDI: 1, X.RSI: 65}, {}, {"rax": 2}), ({X.RDI: 1, X.RSI: 63}, {}, {"rax": 1 << 63}))),
    ("div64-wide-dividend", "48 F7 F1 C3", (
        ({X.RAX: 0, X.RDX: 1, X.RCX: 2}, {}, {"rax": 1 << 63}), ({X.RAX: MAXQ, X.RDX: 0, X.RCX: 1}, {}, {"rax": MAXQ}),
        ({X.RAX: 100, X.RDX: 0, X.RCX: 7}, {}, {"rax": 14}))),
    ("movsx-byte", "48 0F BE C7 C3", (({X.RDI: 0x80}, {}, {"rax": 0xFFFFFFFFFFFFFF80}), ({X.RDI: 0x7F}, {}, {"rax": 0x7F}))),
    ("movsx-word", "48 0F BF C7 C3", (({X.RDI: 0x8000}, {}, {"rax": 0xFFFFFFFFFFFF8000}), ({X.RDI: 0x17FFF}, {}, {"rax": 0x7FFF}))),
    ("movsxd", "48 63 C7 C3", (({X.RDI: 0x80000000}, {}, {"rax": 0xFFFFFFFF80000000}), ({X.RDI: 0x7FFFFFFF}, {}, {"rax": 0x7FFFFFFF}))),
    ("movzx-byte", "40 0F B6 C7 C3", (({X.RDI: 0x1FF}, {}, {"rax": 0xFF}),)),
    ("sar64", "48 D1 FF 48 89 F8 C3", (({X.RDI: 1 << 63}, {}, {"rax": 0xC000000000000000}), ({X.RDI: 6}, {}, {"rax": 3}))),
    ("shr64", "48 D1 EF 48 89 F8 C3", (({X.RDI: 1 << 63}, {}, {"rax": 1 << 62}),)),
    ("cwde", "98 C3", (({X.RAX: 0x8000}, {}, {"rax": 0xFFFF8000}), ({X.RAX: 0x7FFF}, {}, {"rax": 0x7FFF}))),
    ("cdqe", "48 98 C3", (({X.RAX: 0x80000000}, {}, {"rax": 0xFFFFFFFF80000000}), ({X.RAX: 0x7FFFFFFF}, {}, {"rax": 0x7FFFFFFF}))),
    ("inc-keeps-carry", "48 39 F7 48 FF C1 " + SETB_RESULT, (({X.RDI: 1, X.RSI: 2}, {}, {"rax": 1}), ({X.RDI: 2, X.RSI: 1}, {}, {"rax": 0}))),
    ("adc-chain", "48 01 F7 48 83 D2 00 48 89 D0 C3", (
        ({X.RDI: MAXQ, X.RSI: 1, X.RDX: 5}, {}, {"rax": 6}), ({X.RDI: 1, X.RSI: 1, X.RDX: 5}, {}, {"rax": 5}))),
    ("sbb-chain", "48 29 F7 48 83 DA 00 48 89 D0 C3", (
        ({X.RDI: 0, X.RSI: 1, X.RDX: 5}, {}, {"rax": 4}), ({X.RDI: 2, X.RSI: 1, X.RDX: 5}, {}, {"rax": 5}))),
    ("mul64-high", "48 F7 E7 48 89 D0 C3", (
        ({X.RAX: 1 << 63, X.RDI: 4}, {}, {"rax": 2}), ({X.RAX: MAXQ, X.RDI: MAXQ}, {}, {"rax": MAXQ - 1}))),
    ("cmpxchg-store-and-load", "48 0F B1 17 C3", (
        ({X.RDI: MARK, X.RAX: 0x55, X.RDX: 7}, {MARK: (8, 0x55)}, {"rax": 0x55, "mem": {MARK: (8, 7)}, "zf": True}),
        ({X.RDI: MARK, X.RAX: 0x66, X.RDX: 7}, {MARK: (8, 0x55)}, {"rax": 0x55, "mem": {MARK: (8, 0x55)}, "zf": False}))),
    ("bsr", "48 0F BD C7 C3", (({X.RDI: 0x10}, {}, {"rax": 4}), ({X.RDI: MAXQ}, {}, {"rax": 63}), ({X.RDI: 1}, {}, {"rax": 0}))),
    ("tzcnt", "F3 48 0F BC C7 C3", (({X.RDI: 0x18}, {}, {"rax": 3}), ({X.RDI: 0}, {}, {"rax": 64}), ({X.RDI: 1 << 63}, {}, {"rax": 63}))),
    ("ror-by-cl", "48 89 F1 48 D3 CF 48 89 F8 C3", (
        ({X.RDI: 0x10, X.RSI: 4}, {}, {"rax": 1}), ({X.RDI: 1, X.RSI: 65}, {}, {"rax": 1 << 63}), ({X.RDI: 7, X.RSI: 0}, {}, {"rax": 7}))),
    ("stack-top-write", "48 89 3F 48 8B 07 C3", (({X.RDI: X.STACK_TOP - 8}, {}, {"rax": X.STACK_TOP - 8}),)),
    ("xchg", "48 87 F7 48 89 F0 C3", (({X.RDI: 11, X.RSI: 22}, {}, {"rax": 11}),)),
    ("xchg-other-register", "48 87 F7 48 89 F8 C3", (({X.RDI: 11, X.RSI: 22}, {}, {"rax": 22}),)),
    ("lea-scaled-index", "48 8D 04 B7 C3", (({X.RDI: 100, X.RSI: 5}, {}, {"rax": 120}),)),
    ("lea-32-bit-address-stays-64", "48 8D 04 37 C3", (({X.RDI: 1 << 40, X.RSI: 5}, {}, {"rax": (1 << 40) + 5}),)),
    ("cmov-less", "48 39 F7 48 0F 4C C7 C3", (({X.RDI: 1, X.RSI: 2, X.RAX: 9}, {}, {"rax": 1}), ({X.RDI: 3, X.RSI: 2, X.RAX: 9}, {}, {"rax": 9}))),
    ("imul-three-operand", "48 6B C7 FD C3", (({X.RDI: 7}, {}, {"rax": MAXQ - 20}),)),
    ("neg-sets-carry", "48 F7 DF " + SETB_RESULT, (({X.RDI: 0}, {}, {"rax": 0}), ({X.RDI: 5}, {}, {"rax": 1}))),
    ("bswap", "48 0F CF 48 89 F8 C3", (({X.RDI: 0x0102030405060708}, {}, {"rax": 0x0807060504030201}),)),
    ("shld-shrd", "48 0F A4 F7 04 48 89 F8 C3", (({X.RDI: 0x1, X.RSI: 0xF000000000000000}, {}, {"rax": 0x1F}),)),
    ("not-and-xor", "48 F7 D7 48 31 F7 48 89 F8 C3", (({X.RDI: 0xF0, X.RSI: 0xFF}, {}, {"rax": (MAXQ ^ 0xF0) ^ 0xFF}),)),
    ("push-pop-order", "57 56 58 5A C3", (({X.RDI: 3, X.RSI: 4}, {}, {"rax": 4}),)),
    ("ucomisd-below", "66 48 0F 6E C7 66 48 0F 6E CE 66 0F 2E C1 " + SETB_RESULT, (
        ({X.RDI: 0x3FF0000000000000, X.RSI: 0x4000000000000000}, {}, {"rax": 1}),
        ({X.RDI: 0x4000000000000000, X.RSI: 0x3FF0000000000000}, {}, {"rax": 0}),
        ({X.RDI: 0x3FF0000000000000, X.RSI: 0x3FF0000000000000}, {}, {"rax": 0}))),
    ("cvttsd2si", "66 48 0F 6E C7 F2 48 0F 2C C0 C3", (
        ({X.RDI: 0x400C000000000000}, {}, {"rax": 3}), ({X.RDI: 0xC00C000000000000}, {}, {"rax": MAXQ - 2}),
        ({X.RDI: 0x7FF0000000000000}, {}, {"rax": 1 << 63}))),
    ("addsd-quiets-nan", "66 48 0F 6E C7 66 48 0F 6E CE F2 0F 58 C1 66 48 0F 7E C0 C3", (
        ({X.RDI: 0x7FF0000000000001, X.RSI: 0x3FF0000000000000}, {}, {"rax": 0x7FF8000000000001}),
        ({X.RDI: 0x7FF0000000000000, X.RSI: 0xFFF0000000000000}, {}, {"rax": 0xFFF8000000000000}))),
    ("divsd-by-zero", "66 48 0F 6E C7 66 48 0F 6E CE F2 0F 5E C1 66 48 0F 7E C0 C3", (
        ({X.RDI: 0x3FF0000000000000, X.RSI: 0}, {}, {"rax": 0x7FF0000000000000}),
        ({X.RDI: 0xBFF0000000000000, X.RSI: 0}, {}, {"rax": 0xFFF0000000000000}),
        ({X.RDI: 0, X.RSI: 0}, {}, {"rax": 0xFFF8000000000000}))),
    ("or-zero-flag", "48 09 F7 0F 94 C0 0F B6 C0 C3", (({X.RDI: 0, X.RSI: 0}, {}, {"rax": 1}), ({X.RDI: 1, X.RSI: 0}, {}, {"rax": 0}))),
    ("xor-clears", "31 C0 C3", (({X.RAX: 5}, {}, {"rax": 0}),)),
    ("sub-sign-flag", "48 29 F7 0F 98 C0 0F B6 C0 C3", (({X.RDI: 1, X.RSI: 2}, {}, {"rax": 1}), ({X.RDI: 2, X.RSI: 1}, {}, {"rax": 0}))),
    ("jl-taken-and-not", "48 39 F7 7C 06 B8 00 00 00 00 C3 B8 01 00 00 00 C3", (
        ({X.RDI: 1, X.RSI: 2}, {}, {"rax": 1}), ({X.RDI: 2, X.RSI: 1}, {}, {"rax": 0}), ({X.RDI: 1 << 63, X.RSI: 1}, {}, {"rax": 1}))),
    ("ja-unsigned-branch", "48 39 F7 77 06 B8 00 00 00 00 C3 B8 01 00 00 00 C3", (
        ({X.RDI: 2, X.RSI: 1}, {}, {"rax": 1}), ({X.RDI: 1, X.RSI: 2}, {}, {"rax": 0}), ({X.RDI: MAXQ, X.RSI: 1}, {}, {"rax": 1}))),
    ("bt-immediate", "48 0F BA E7 05 " + SETB_RESULT, (({X.RDI: 0x20}, {}, {"rax": 1}), ({X.RDI: 0x1F}, {}, {"rax": 0}))),
    ("bt-register-index", "48 0F A3 F7 " + SETB_RESULT, (
        ({X.RDI: 4, X.RSI: 2}, {}, {"rax": 1}), ({X.RDI: 4, X.RSI: 3}, {}, {"rax": 0}), ({X.RDI: 4, X.RSI: 66}, {}, {"rax": 1}))),
    ("movq-roundtrip", "66 48 0F 6E C7 66 48 0F 7E C0 C3", (({X.RDI: 0x0123456789ABCDEF}, {}, {"rax": 0x0123456789ABCDEF}),)),
    ("movd-roundtrip", "66 0F 6E C7 66 0F 7E C0 C3", (({X.RDI: 0x123456789}, {}, {"rax": 0x23456789}),)),
    ("pshufd-reverse-lanes", "66 48 0F 6E C7 66 48 0F 6E CE 66 0F 6C C1 66 0F 70 C0 1B 66 48 0F 7E C0 C3", (
        ({X.RDI: 0x0000000200000001, X.RSI: 0x0000000400000003}, {}, {"rax": 0x0000000300000004}),
        ({X.RDI: 0xAAAA, X.RSI: 0xBBBB}, {}, {"rax": 0xBBBB << 32}))),
    ("pcmpeqb-pmovmskb", "66 48 0F 6E C7 66 48 0F 6E CE 66 0F 74 C1 66 0F D7 C0 C3", (
        ({X.RDI: 7, X.RSI: 7}, {}, {"rax": 0xFFFF}), ({X.RDI: 1, X.RSI: 2}, {}, {"rax": 0xFFFE}), ({X.RDI: 0x100, X.RSI: 0}, {}, {"rax": 0xFFFD}))),
    ("maxsd", "66 48 0F 6E C7 66 48 0F 6E CE F2 0F 5F C1 66 48 0F 7E C0 C3", (
        ({X.RDI: 0x3FF0000000000000, X.RSI: 0x4000000000000000}, {}, {"rax": 0x4000000000000000}),
        ({X.RDI: 0x4000000000000000, X.RSI: 0x3FF0000000000000}, {}, {"rax": 0x4000000000000000}))),
    ("minsd", "66 48 0F 6E C7 66 48 0F 6E CE F2 0F 5D C1 66 48 0F 7E C0 C3", (
        ({X.RDI: 0x3FF0000000000000, X.RSI: 0x4000000000000000}, {}, {"rax": 0x3FF0000000000000}),
        ({X.RDI: 0x4000000000000000, X.RSI: 0x3FF0000000000000}, {}, {"rax": 0x3FF0000000000000}))),
    ("mulsd", "66 48 0F 6E C7 66 48 0F 6E CE F2 0F 59 C1 66 48 0F 7E C0 C3", (
        ({X.RDI: 0x4000000000000000, X.RSI: 0x4008000000000000}, {}, {"rax": 0x4018000000000000}),)),
    ("subsd", "66 48 0F 6E C7 66 48 0F 6E CE F2 0F 5C C1 66 48 0F 7E C0 C3", (
        ({X.RDI: 0x4008000000000000, X.RSI: 0x4000000000000000}, {}, {"rax": 0x3FF0000000000000}),)),
    ("cvtsi2sd", "F2 48 0F 2A C7 66 48 0F 7E C0 C3", (
        ({X.RDI: 3}, {}, {"rax": 0x4008000000000000}), ({X.RDI: MAXQ}, {}, {"rax": 0xBFF0000000000000}))),
    ("xorps-clear", "66 48 0F 6E C7 0F 57 C0 66 48 0F 7E C0 C3", (({X.RDI: 99}, {}, {"rax": 0}),)),
    ("andpd", "66 48 0F 6E C7 66 48 0F 6E CE 66 0F 54 C1 66 48 0F 7E C0 C3", (({X.RDI: 0xF0F0, X.RSI: 0xFF00}, {}, {"rax": 0xF000}),)),
    ("orpd", "66 48 0F 6E C7 66 48 0F 6E CE 66 0F 56 C1 66 48 0F 7E C0 C3", (({X.RDI: 0xF0F0, X.RSI: 0xFF00}, {}, {"rax": 0xFFF0}),)),
    ("andnpd", "66 48 0F 6E C7 66 48 0F 6E CE 66 0F 55 C1 66 48 0F 7E C0 C3", (({X.RDI: 0xF0F0, X.RSI: 0xFF00}, {}, {"rax": 0x0F00}),)),
    ("rol-by-cl", "48 89 F1 48 D3 C7 48 89 F8 C3", (({X.RDI: 1 << 63, X.RSI: 1}, {}, {"rax": 1}), ({X.RDI: 0x10, X.RSI: 4}, {}, {"rax": 0x100}))),
    ("shr32-by-cl", "89 F1 D3 EF 89 F8 C3", (({X.RDI: 0x80000000, X.RSI: 31}, {}, {"rax": 1}),)),
    ("sar32-by-cl", "89 F1 D3 FF 89 F8 C3", (({X.RDI: 0x80000000, X.RSI: 31}, {}, {"rax": 0xFFFFFFFF}),)),
    ("imul-two-operand", "48 0F AF C7 C3", (({X.RAX: MAXQ - 2, X.RDI: 7}, {}, {"rax": MAXQ - 20}),)),
    ("imul-one-operand-high", "48 F7 EF 48 89 D0 C3", (({X.RAX: MAXQ, X.RDI: 2}, {}, {"rax": MAXQ}), ({X.RAX: 1 << 62, X.RDI: 4}, {}, {"rax": 1}))),
    ("neg32-zero-extends", "F7 DF 89 F8 C3", (({X.RDI: 1}, {}, {"rax": 0xFFFFFFFF}),)),
    ("sub32-wraps", "29 F7 89 F8 C3", (({X.RDI: 0, X.RSI: 1}, {}, {"rax": 0xFFFFFFFF}),)),
    ("dec64", "48 FF CF 48 89 F8 C3", (({X.RDI: 0}, {}, {"rax": MAXQ}),)),
    ("movabs", "48 B8 88 77 66 55 44 33 22 11 C3", (({}, {}, {"rax": 0x1122334455667788}),)),
    ("test-zero-flag", "48 85 FF 0F 94 C0 0F B6 C0 C3", (({X.RDI: 0}, {}, {"rax": 1}), ({X.RDI: 5}, {}, {"rax": 0}))),
    ("cmp-imm8-sign-extended", "48 83 FF FF 0F 94 C0 0F B6 C0 C3", (({X.RDI: MAXQ}, {}, {"rax": 1}), ({X.RDI: 0xFF}, {}, {"rax": 0}))),
    ("mov-imm32-sign-extended", "48 C7 C0 FF FF FF FF C3", (({}, {}, {"rax": MAXQ}),)),
    ("mov-imm32-zero-extended", "B8 FF FF FF FF C3", (({}, {}, {"rax": 0xFFFFFFFF}),)),
    ("movzx-word", "0F B7 C7 C3", (({X.RDI: 0x12345}, {}, {"rax": 0x2345}),)),
    ("push-immediate", "6A FF 58 C3", (({}, {}, {"rax": MAXQ}),)),
)


def run_probes(shared, image, stop=False):
    """Run every probe on `shared.Machine`; returns [(probe, case index, passed, got)] (stops at the first failure when `stop`)."""
    entry = image.named[".text"]["address"]
    rows = []
    for name, code, cases in PROBES:
        raw = bytes.fromhex(code.replace(" ", ""))
        for index, (regs, memory, expect) in enumerate(cases):
            machine = shared.Machine(image, {entry + at: byte for at, byte in enumerate(raw)})
            for address, (size, value) in memory.items():
                machine.memory.write(address, size, value)
            want = expect["rax"]
            try:
                got = machine.run(entry, dict(regs))
                ok = got == want
                for address, (size, value) in expect.get("mem", {}).items():
                    ok = ok and machine.memory.read(address, size) == value
                if "zf" in expect:
                    ok = ok and machine.zf == expect["zf"]
            except Exception as problem:        # noqa: BLE001 - a probe the interpreter cannot run is a failed probe
                got, ok = type(problem).__name__, False
            rows.append((name, index, ok, got if isinstance(got, str) else "%#x" % got))
            if stop and not ok:
                return rows
    return rows


# --------------------------------------------------------------------------------------------------------------------------------
# 4. negative controls
# --------------------------------------------------------------------------------------------------------------------------------

MUTATIONS = (
    ("flag-pf-inverted", "condition", "5: self.pf,", "5: not self.pf,"),
    ("flag-less-equal-sign", "condition", "6: self.sf != self.of,", "6: self.sf == self.of,"),
    ("flag-below-equal-and", "condition", "3: self.cf or self.zf,", "3: self.cf and self.zf,"),
    ("flag-negate-dropped", "condition", "return bool(result) != bool(code & 1)", "return bool(result)"),
    ("flag-sub-borrow-equal", "carry", "self.cf = left < right + carry", "self.cf = left <= right + carry"),
    ("flag-add-carry-edge", "carry", "self.cf = total > mask", "self.cf = total >= mask"),
    ("flag-sub-overflow-sign", "carry", "self.of = bool((left ^ right) & (left ^ result) & SIGN[width])",
     "self.of = bool((left ^ right) & (left ^ result) & 1)"),
    ("flag-logic-sign-width", "carry", "self.sf = bool(result & SIGN[width])\n\n    def add_sub", "self.sf = bool(result & SIGN[8])\n\n    def add_sub"),
    ("flag-add-zero-sign", "carry", "self.zf = result == 0\n        self.sf = bool(result & SIGN[width])\n        return result",
     "self.zf = result != 0\n        self.sf = bool(result & SIGN[width])\n        return result"),
    ("width-write-32-no-zero-extend", "width", "if width >= 4:\n                self.regs[reg] = value", "if width >= 8:\n                self.regs[reg] = value"),
    ("width-high-byte-shift", "width", "return self.regs[operand[1]] >> 8 & 0xFF", "return self.regs[operand[1]] >> 16 & 0xFF"),
    ("width-address-32", "width", "return value & MASK[8]\n\n    def get", "return value & MASK[4]\n\n    def get"),
    ("width-address-scale", "width", "value += self.regs[index] * scale", "value += self.regs[index]"),
    ("width-shift-count-mask", "width", "& (63 if width == 8 else 31)", "& 63"),
    ("width-write-mask", "width", "value & MASK.get(count, (1 << (8 * count)) - 1)", "value & MASK[4]"),
    ("width-div-dividend", "width", "<< (8 * width) | (self.regs[RAX]", "<< (4 * width) | (self.regs[RAX]"),
    ("sign-movsx-dropped", "sign", "self.put(row.a, width, value - (1 << (8 * row.cc)) if value & SIGN[row.cc] else value)",
     "self.put(row.a, width, value)"),
    ("sign-movsxd-dropped", "sign", "self.put(row.a, 8, value - (1 << 32) if value & SIGN[4] else value)", "self.put(row.a, 8, value)"),
    ("sign-sar-logical", "sign", "(value - (1 << (8 * width)) if value & SIGN[width] else value) >> count", "value >> count"),
    ("sign-cdqe-upper", "sign", "(MASK[8] ^ MASK[4] if self.regs[RAX] & SIGN[4] else 0)", "0"),
    ("sign-cwde-bias", "sign", "^ 0x8000) - 0x8000 & MASK[4]", "^ 0x8000) - 0x80 & MASK[4]"),
    ("sign-movzx-width", "sign", "self.put(row.a, width, self.get(row.b, row.cc))\n        elif op == \"set\"",
     "self.put(row.a, width, self.get(row.b, 1))\n        elif op == \"set\""),
    ("carry-adc-as-sbb", "carry", "self.add_sub(self.get(row.a, width), self.get(row.b, width), carry, width, op not in (\"add\", \"adc\"))",
     "self.add_sub(self.get(row.a, width), self.get(row.b, width), carry, width, op not in (\"add\",))"),
    ("carry-inc-clobbers-cf", "carry", "            value = self.add_sub(self.get(row.a, width), 1, 0, width, op == \"dec\")\n            self.cf = carry",
     "            value = self.add_sub(self.get(row.a, width), 1, 0, width, op == \"dec\")"),
    ("carry-mul-high-half", "carry", "self.regs[RDX] = product >> 64", "self.regs[RDX] = product >> 63"),
    ("carry-div-overflow-edge", "carry", "if quotient > MASK[width]:", "if quotient >= MASK[width]:"),
    ("carry-cmpxchg-inverted", "carry", "if wanted == current:", "if wanted != current:"),
    ("carry-ucomisd-below", "carry", "self.cf = unordered or left < right", "self.cf = unordered or left <= right"),
    ("carry-bsr-index", "carry", "self.put(row.a, width, source.bit_length() - 1)", "self.put(row.a, width, source.bit_length())"),
    ("carry-tzcnt-lowest-bit", "carry", "(source & -source).bit_length() - 1 if source", "source.bit_length() - 1 if source"),
    ("carry-cvttsd2si-edge", "carry", "-9223372036854775808.0 <= value <", "-9223372036854775808.0 < value <"),
    ("carry-sse-nan-quiet", "carry", "return bits | QUIET_BIT", "return bits"),
    ("carry-rotate-count-from-register", "carry", "count = self.get(row.b, 1) & (bits - 1)\n            value = self.get(row.a, width)\n            self.put(row.a, width, (value >> count",
     "count = row.b[1] % bits\n            value = self.get(row.a, width)\n            self.put(row.a, width, (value >> count"),
    ("exec-call-pushes-target", "exec", "self.push(row.next)\n            if row.target in self.real:", "self.push(row.target)\n            if row.target in self.real:"),
    ("exec-set-inverted", "exec", "self.put(row.a, 1, int(self.condition(row.cc)))", "self.put(row.a, 1, int(not self.condition(row.cc)))"),
    ("exec-cmov-inverted", "exec", "value if self.condition(row.cc) else self.get(row.a, width)", "value if not self.condition(row.cc) else self.get(row.a, width)"),
    ("exec-stack-balance", "exec", "if self.regs[RSP] != top + 8:", "if self.regs[RSP] != top + 16:"),
    ("exec-stack-top-edge", "exec", "if self.stack_base <= addr and addr + count <= STACK_TOP:", "if self.stack_base <= addr and addr + count < STACK_TOP:"),
    ("exec-pop-order", "exec", "value = self.memory.read(self.regs[RSP], 8)\n        self.regs[RSP] += 8", "value = self.memory.read(self.regs[RSP], 8)\n        self.regs[RSP] += 16"),
    ("exec-xchg-first-only", "exec", "self.put(row.a, width, second)\n            self.put(row.b, width, first)", "self.put(row.a, width, second)"),
    ("decode-sib-scale", "decode", "scale = 1 << (sib >> 6)", "scale = 1 << (sib >> 5)"),
    ("decode-sib-index-rex", "decode", "index = ((sib >> 3) & 7) | ((rex & 2) << 2)", "index = ((sib >> 3) & 7) | ((rex & 2) << 1)"),
    ("decode-immediate-unsigned", "decode", "{1: \"<b\", 2: \"<h\", 4: \"<i\", 8: \"<q\"}", "{1: \"<B\", 2: \"<H\", 4: \"<I\", 8: \"<Q\"}"),
    ("decode-rip-relative", "decode", "return (\"m\", None, None, 1, va + size + operand[4], False)", "return (\"m\", None, None, 1, va + operand[4], False)"),
    ("decode-jcc-condition", "decode", "return finish(\"jcc\", cc=byte & 15, target=va + pos + rel)", "return finish(\"jcc\", cc=byte & 7, target=va + pos + rel)"),
    ("decode-operand-size-prefix", "decode", "width = 8 if wide else (2 if opsize else 4)", "width = 8 if wide else 4"),
    ("decode-rex-base", "decode", "base = rm | ((rex & 1) << 3)", "base = rm"),
    ("decode-group1-direction", "decode", "        if byte & 2:\n            return finish(name, (\"r\", reg), rm, w)", "        if byte & 1:\n            return finish(name, (\"r\", reg), rm, w)"),
    ("decode-disp8-unsigned", "decode", "disp = struct.unpack_from(\"<b\", window, pos)[0]\n            pos += 1", "disp = struct.unpack_from(\"<B\", window, pos)[0]\n            pos += 1"),
    ("decode-setcc-width", "decode", "return finish(\"set\", rm, w=1, cc=two & 15)", "return finish(\"set\", rm, w=4, cc=two & 15)"),
    ("vector-minsd-direction", "vector", "                result = left if left < right else right", "                result = left if left > right else right"),
    ("vector-maxsd-direction", "vector", "                result = left if left > right else right\n            self.set_low", "                result = left if left < right else right\n            self.set_low"),
    ("vector-pshufd-lane-select", "vector", "words[(row.target >> (2 * index)) & 3] << (32 * index)", "words[(row.target >> index) & 3] << (32 * index)"),
    ("vector-andn-operand-order", "vector", "(~self.xmm[row.a[1]] & ((1 << 128) - 1)) & self.vector(row.b)", "(~self.vector(row.b) & ((1 << 128) - 1)) & self.xmm[row.a[1]]"),
    ("vector-cvtsi2sd-unsigned", "vector", "float(value - (1 << 64) if value & SIGN[8] else value)", "float(value)"),
    ("vector-pmovmskb-bit", "vector", "sum((byte >> 7) << index", "sum((byte >> 6) << index"),
    ("carry-imul1-high-half", "carry", "self.regs[RDX] = (product >> 64) & MASK[8]", "self.regs[RDX] = (product >> 63) & MASK[8]"),
    ("carry-rol-wraparound", "carry", "(value << count | value >> (bits - count)) & MASK[width]", "(value << count | value >> count) & MASK[width]"),
    ("decode-movabs-width", "decode", "value = immediate(8 if wide else 2 if opsize else 4)", "value = immediate(8 if wide else 4)"),
)


EQUIVALENT = {
    "carry-cvttsd2si-edge": ("cvttsd2si", "the only input the edited bound changes is exactly -2^63: the exact conversion and the integer indefinite value are both 0x8000000000000000, so the result register is identical"),
}


def build_mutant(source, old, new):
    if source.count(old) != 1:
        raise CheckError("mutation target is not unique: %r" % old[:50])
    module = types.ModuleType("x86_115_mutant")
    module.__file__ = X.__file__
    exec(compile(source.replace(old, new), "x86_115_mutant", "exec"), module.__dict__)      # noqa: S102 - mutated copy of the shared module
    return module


def detect(mutant, modules, images, reference):
    """Run the comparisons with the mutated interpreter; returns (stage, tool, detail) of the first difference or None."""
    failed = [row for row in run_probes(mutant, next(iter(images.values())), stop=True) if not row[2]]
    if failed:
        return ("probe", failed[0][0], "case %d" % failed[0][1])
    for name in DETECT_ORDER:
        module = modules[name]
        ref = reference[name]
        probe = mutant.Machine(images[name])
        for va, want in sorted(ref["rows"].items()):
            try:
                got = canon(mutant.decode(probe.read_code, va))
            except (X.EvidenceError, IndexError, struct.error, KeyError):
                return ("decode", name, "%#x raises" % va)
            if got != want:
                return ("decode", name, "%#x" % va)
    for name in DETECT_ORDER:
        module = modules[name]
        ref = reference[name]
        with bound(module, mutant):
            try:
                digests, _, _, _, _ = run_pass(module, images[name], ADAPTERS[name], ref["count"], chosen=ref["chosen"], stop_at=ref["digests"])
            except Exception as problem:     # noqa: BLE001 - any failure of the mutated interpreter counts as a detection
                return ("execute", name, type(problem).__name__)
        for position, digest in enumerate(digests):
            if digest != ref["digests"][position]:
                return ("execute", name, "case %d" % ref["chosen"][position])
    return None


# --------------------------------------------------------------------------------------------------------------------------------
# driver
# --------------------------------------------------------------------------------------------------------------------------------

def table(header, rows):
    return "\n".join(["\t".join(header)] + ["\t".join(str(item) for item in row) for row in rows]) + "\n"


def analyse():
    image = X.load_image()
    totals, ops, stops, survey_rows = survey(image)
    result = {"image": image, "totals": totals, "ops": ops, "stops": stops, "survey_rows": survey_rows}
    modules, images, reference, tool_rows, decode_rows, case_rows = {}, {}, {}, [], [], []
    executed_ops = collections.Counter()
    for name, count, ordered in TOOLS:
        module = modules[name] = importlib.import_module(name)
        tool_image = images[name] = module.Image(image.blob)       # the digest was checked once by X.load_image; the bytes are shared
        digests, matched, rec, available, indexes = run_pass(module, tool_image, ADAPTERS[name], count, limit=None if ordered else count)
        decode_stats, reached, _ = decode_executed(module, X, rec.machines)
        for want in reached.values():
            executed_ops[want[2]] += 1
        for va in sorted(reached):
            decode_rows.append((name, "%#x" % va, reached[va][2], reached[va][1], hashlib.sha256(repr(reached[va]).encode()).hexdigest()[:12]))
        sweep = decode_sweep(module, X, tool_image, reached)
        with bound(module, X):
            shared_digests, shared_matched, shared_rec, _, _ = run_pass(module, tool_image, ADAPTERS[name], count, chosen=indexes)
        same = sum(1 for a, b in zip(digests, shared_digests) if a == b)
        for position in range(0, len(indexes), CASE_ROW_EVERY):
            case_rows.append((name, indexes[position], digests[position].hex(), shared_digests[position].hex(),
                              int(digests[position] == shared_digests[position])))
        tool_rows.append((name, available, len(indexes), rec.run_count, rec.steps, matched, shared_matched, same, shared_rec.run_count,
                          shared_rec.steps, decode_stats["executed"], decode_stats["different"], sweep["functions"], sweep["compared"],
                          sweep["tool_only_raises"], sweep["different"]))
        battery = list(range(min(BATTERY, len(indexes)))) if ordered else pick(indexes, BATTERY)
        chosen = [indexes[i] for i in battery]
        # the battery is re-run alone with the tool's own machine, so the reference does not depend on the cases skipped between its members
        battery_digests, _, _, _, _ = run_pass(module, tool_image, ADAPTERS[name], count, chosen=chosen)
        reference[name] = {"rows": reached, "chosen": chosen, "digests": battery_digests, "count": count}
    result.update(tool_rows=tool_rows, executed_ops=executed_ops, decode_rows=decode_rows, case_rows=case_rows,
                  all_decoders=compare_all_decoders(image))
    source = pathlib.Path(X.__file__).read_text()
    controls, equivalent, positive = [], [], []
    probe_rows = run_probes(X, image)
    if not all(row[2] for row in probe_rows):
        raise CheckError("a probe fails on the shared interpreter")
    rebuilt = types.ModuleType("x86_115_rebuilt")
    rebuilt.__file__ = X.__file__
    exec(compile(source, "x86_115_rebuilt", "exec"), rebuilt.__dict__)         # noqa: S102 - unmodified copy of the shared module
    for label, candidate in (("shared module", X), ("unmodified rebuilt copy", rebuilt)):
        found = detect(candidate, modules, images, reference)
        positive.append((label, "agrees with every reference" if found is None else "DIFFERS %s" % (found,)))
        if found is not None:
            raise CheckError("positive control failed: %s %s" % (label, found))
    for name, kind, old, new in MUTATIONS:
        mutant = build_mutant(source, old, new)
        found = detect(mutant, modules, images, reference)
        if found is None and name in EQUIVALENT:
            equivalent.append((name, EQUIVALENT[name][0], EQUIVALENT[name][1]))
            continue
        controls.append((name, kind, found))
    result.update(controls=controls, equivalent=equivalent, positive=positive, probes=probe_rows, reference_cases=sum(len(r["chosen"]) for r in reference.values()))
    return result


def render(result):
    files = {}
    totals = result["totals"]
    files["decode-survey-summary.tsv"] = table(("item", "count"), [(k, totals[k]) for k in ("functions", "instructions", "complete", "stopped", "overran")])
    files["decode-survey-ops.tsv"] = table(("op", "survey_count", "reached_by_tools"),
                                         [(op, n, result["executed_ops"].get(op, 0)) for op, n in sorted(result["ops"].items())])
    files["decode-survey-stops.tsv"] = table(("opcode_bytes", "functions"), sorted(result["stops"].items(), key=lambda item: (-item[1], item[0]))[:60])
    files["decode-survey-functions.tsv"] = table(("start", "size", "instructions", "decoded_bytes", "stop_bytes"),
                                                [("%#x" % row[0],) + row[1:] for row in result["survey_rows"]])
    files["tool-equivalence.tsv"] = table(
        ("tool", "cases_available", "cases_run", "tool_machine_runs", "tool_steps", "tool_matches_rules", "shared_matches_rules",
         "identical_cases", "shared_machine_runs", "shared_steps", "executed_instructions", "decode_different", "swept_functions",
         "swept_addresses", "tool_raises_shared_decodes", "sweep_different"), result["tool_rows"])
    files["decode-equivalence-instructions.tsv"] = table(("tool", "address", "operation", "size", "fields_digest"), result["decode_rows"])
    files["execution-equivalence-cases.tsv"] = table(("tool", "case", "tool_digest", "shared_digest", "identical"), result["case_rows"])
    files["all-tools-decode.tsv"] = table(("tool", "compared", "same", "tool_narrower", "shared_narrower", "different", "first_difference"),
                                          result["all_decoders"])
    files["controls.tsv"] = table(("mutation", "kind", "detected_by", "tool", "first_difference"),
                                  [(n, k, f[0] if f else "-", f[1] if f else "-", f[2] if f else "-") for n, k, f in result["controls"]])
    files["probes.tsv"] = table(("probe", "case", "passed", "rax"), [(n, i, int(ok), got) for n, i, ok, got in result["probes"]])
    files["positive-controls.tsv"] = table(("candidate", "result"), result["positive"])
    files["equivalent-mutants.tsv"] = table(("mutation", "address", "reason"), result["equivalent"])
    detected = sum(1 for _, _, f in result["controls"] if f)
    cases = sum(row[2] for row in result["tool_rows"])
    files["measure.json"] = json.dumps({
        "cases": cases, "negative_controls": len(result["controls"]) + len(result["equivalent"]), "negative_detected": detected, "equivalent": len(result["equivalent"]),
        "probes": len(result["probes"]), "decoded_functions": totals["functions"], "decoded_instructions": totals["instructions"],
    }, indent=1, sort_keys=True) + "\n"
    return files


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    result = analyse()
    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    files = render(result)
    for name, text in files.items():
        (out / name).write_text(text)
    print(files["measure.json"], end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
