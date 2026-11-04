#!/usr/bin/env python3
"""Static trace of the arms the node #115 bit-9 cache tests select.

PR #2496 (the RE-002 cache-readback packet) established that only
the first published cache word C0 is ever read back: 102 consumer
bodies load C0 through relocated slot 0x64dfa60, zero-check it,
refresh through slot 0x64dfa68 on the zero arm, and test individual
bits of the word to select between implementations.  The largest
family is the 92 consumers that test bit 9 (CPUID leaf 1 ECX bit 9
in PR #2484's field map).  #2496 stopped at each consumer's first
bit-consuming use and left as its next question: for the 92 bit-9
consumers, what are the two implementations each arm reaches, and
do all 92 bodies select the same pair?

This producer answers that question:

* it re-derives the readback census with the same validated method
  as #2496 (RIP-relative census of the two slots, site validation
  against GNU objdump, CFG may-analysis value tracking per owner
  body) and selects the consumers whose tested-bit set contains
  bit 9 -- the census and the 208 bit-9 mask-test events agree with
  #2496 exactly;
* for each bit-9 mask test it finds the consuming conditional
  branch, resolves trampoline blocks, and pairs the test on the
  loaded word C0 with the test on the refresh return A into one
  selection sequence (the two tests of a sequence must select the
  same ordered pair of arm entries, or the analysis fails closed);
* for each sequence it computes the immediate post-dominator of the
  test block in the body CFG (with a virtual body-exit node) and
  takes each arm's region to be the blocks reachable from the arm
  entry without entering the merge block or the test block again;
  every control transfer inside a region is recorded, and each
  distinct out-of-body target is hash-pinned by its FDE;
* the 92 consumers are grouped by the pair each sequence selects:
  the set arm's target identity (or kind) and the clear arm's class
  (a distinct in-body region, or empty for a guarded call), with the
  clear region of every non-empty clear arm hash-pinned byte by
  byte so the grouping is exact;
* each distinct arm target is identified at entry level only: FDE
  bounds, size, SHA-256, instruction count, its first eight
  instructions, and a normalised instruction stream (internal
  branch/call targets and RIP-relative references rewritten
  self-relative, external references kept absolute) whose hash
  groups targets that are the same instruction stream at different
  placements.  Target bodies are not traced further, and the arms'
  own callees are not followed.

No captured code is executed.  The whole capture is authenticated by
size and SHA-256 before any analysis; GNU tools receive a private
byte-identical snapshot whose path is replaced by
``<authenticated-node115>`` in retained text.
"""

import hashlib
import json
import os
import re
import struct
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "artifacts/node/115/hl-node"
SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
SIZE = 105896032

SLOT_PTR = 0x64DFA60          # relocated slot holding the cache base pointer
SLOT_REFRESH = 0x64DFA68      # relocated slot holding the refresh helper address
CACHE_BASE = 0x6500098        # .bss address of C0
WORD_VAS = (CACHE_BASE, CACHE_BASE + 8, CACHE_BASE + 16)
WORD_NAMES = ("C0", "C1", "C2")
HELPER = (0x5CADD50, 0x5CAE3DA)     # refresh helper / publisher (merged packet)
SELECTOR = (0x160BEE0, 0x160BF68)   # runtime-tag selector (merged packet)
XCR0_LEAF = (0x5CAE3E0, 0x5CAE3ED)

# Field attribution of the bit this packet traces, from PR #2484's
# completed A/B field map through the merged publication equations
# (C0 bit i = A bit i for i < 63): C0 bit 9 is CPUID leaf 1 ECX
# bit 9.
BIT9_DRIVER = "cpuid leaf 1 ecx bit 9"

EXPECTED_FDE_COUNT = 135313


def hx(value):
    return f"0x{value:x}"


# ---------------------------------------------------------------- ELF


def sections(data):
    if data[:6] != b"\x7fELF\x02\x01" or len(data) < 64:
        raise ValueError("Expected ELF64 little-endian input")
    shoff = struct.unpack_from("<Q", data, 40)[0]
    entsize, count, names_index = struct.unpack_from("<HHH", data, 58)
    if entsize < 64 or not count or names_index >= count \
            or shoff + entsize * count > len(data):
        raise ValueError("Invalid or unsupported ELF section table")
    raw = []
    for index in range(count):
        name, typ, flags, addr, off, size = struct.unpack_from(
            "<IIQQQQ", data, shoff + index * entsize)
        if typ != 8 and off + size > len(data):
            raise ValueError("Section outside file")
        raw.append((name, typ, flags, addr, off, size))
    names_off = raw[names_index][4]
    result = []
    for name, typ, flags, addr, off, size in raw:
        end = data.index(b"\x00", names_off + name)
        result.append({
            "name": data[names_off + name:end].decode(),
            "type": typ, "flags": flags, "address": addr,
            "offset": off, "size": size,
        })
    return result


def relocations(data, secs):
    rela = next(s for s in secs if s["name"] == ".rela.dyn")
    rows = []
    for i in range(rela["size"] // 24):
        off, info, add = struct.unpack_from(
            "<QQq", data, rela["offset"] + i * 24)
        rows.append((off, info, add))
    return rows


def readelf_frames(snapshot):
    """FDE ranges and raw readelf -wf lines from the snapshot."""
    native = subprocess.check_output(
        ["readelf", "--debug-dump=frames", str(snapshot)], text=True)
    native = native.replace(str(snapshot), "<authenticated-node115>")
    ranges = []
    lines = {}
    for line in native.splitlines():
        m = re.match(
            r"^[0-9a-f]+ [0-9a-f]+ [0-9a-f]+ FDE cie=[0-9a-f]+ "
            r"pc=([0-9a-f]+)\.\.([0-9a-f]+)\s*$", line)
        if m:
            lo, hi = int(m.group(1), 16), int(m.group(2), 16)
            if hi > lo:
                ranges.append((lo, hi))
                lines[(lo, hi)] = line
    ranges.sort()
    return ranges, lines


# ---------------------------------------------------------------- census


def rip_census(data, secs):
    """Every candidate RIP-relative site in executable sections.

    A modrm byte with mod=00, rm=101 is followed by a disp32; the
    target is (VA after disp32) + disp32.  The scan is prefix
    agnostic, so it covers legacy, REX, 0F-escape and VEX forms.
    Candidates are validated against objdump later; random byte
    patterns cannot survive that validation.
    """
    targets = {SLOT_PTR: "slot_ptr", SLOT_REFRESH: "slot_refresh"}
    for va in WORD_VAS:
        targets[va] = f"word_{WORD_NAMES[WORD_VAS.index(va)]}"
    neighbour_lo, neighbour_hi = CACHE_BASE - 0x20, CACHE_BASE + 0x28
    sites = []
    neighbours = []
    for sec in secs:
        if not (sec["flags"] & 0x4) or sec["size"] == 0:
            continue
        blob = data[sec["offset"]:sec["offset"] + sec["size"]]
        base = sec["address"]
        for p in range(len(blob) - 5):
            if blob[p] & 0xC7 == 0x05:
                disp, = struct.unpack_from("<i", blob, p + 1)
                tgt = base + p + 5 + disp
                if tgt in targets:
                    sites.append({"modrm_va": base + p, "target": tgt,
                                  "kind": targets[tgt]})
                elif neighbour_lo <= tgt < neighbour_hi \
                        and tgt not in WORD_VAS:
                    neighbours.append({"modrm_va": base + p, "target": tgt})
    return sites, neighbours


def movabs_census(data, secs):
    hits = []
    wanted = {SLOT_PTR, SLOT_REFRESH, *WORD_VAS}
    for sec in secs:
        if not (sec["flags"] & 0x4) or sec["size"] == 0:
            continue
        blob = data[sec["offset"]:sec["offset"] + sec["size"]]
        for value in wanted:
            pat = struct.pack("<Q", value)
            i = 0
            while True:
                i = blob.find(pat, i)
                if i < 0:
                    break
                hits.append({"va": sec["address"] + i, "value": value})
                i += 1
    return hits


def direct_call_census(data, secs, callee):
    sites = []
    for sec in secs:
        if not (sec["flags"] & 0x4) or sec["size"] == 0:
            continue
        blob = data[sec["offset"]:sec["offset"] + sec["size"]]
        base = sec["address"]
        for p in range(len(blob) - 5):
            if blob[p] == 0xE8:
                disp, = struct.unpack_from("<i", blob, p + 1)
                if base + p + 5 + disp == callee:
                    sites.append(base + p)
    return sites


# ---------------------------------------------------------------- disassembly

REG64 = {}
for _base, _aliases in {
    "rax": ("rax", "eax", "ax", "al", "ah"),
    "rbx": ("rbx", "ebx", "bx", "bl", "bh"),
    "rcx": ("rcx", "ecx", "cx", "cl", "ch"),
    "rdx": ("rdx", "edx", "dx", "dl", "dh"),
    "rsi": ("rsi", "esi", "si", "sil"),
    "rdi": ("rdi", "edi", "di", "dil"),
    "rbp": ("rbp", "ebp", "bp", "bpl"),
    "rsp": ("rsp", "esp", "sp", "spl"),
}.items():
    for _alias in _aliases:
        REG64[_alias] = _base
for _i in range(8, 16):
    for _alias, _canon in ((f"r{_i}", f"r{_i}"), (f"r{_i}d", f"r{_i}"),
                           (f"r{_i}w", f"r{_i}"), (f"r{_i}b", f"r{_i}")):
        REG64[_alias] = _canon

WIDTH = {}
for _alias in REG64:
    if _alias.startswith("r") and _alias[1:].isdigit():
        WIDTH[_alias] = 64
    elif _alias.endswith("d") and _alias[:-1][1:].isdigit():
        WIDTH[_alias] = 32
    elif _alias.endswith("w") and _alias[:-1][1:].isdigit():
        WIDTH[_alias] = 16
    elif _alias.endswith("b") and _alias[:-1][1:].isdigit():
        WIDTH[_alias] = 8
for _alias, _w in (("rax", 64), ("eax", 32), ("ax", 16), ("al", 8), ("ah", 8),
                   ("rbx", 64), ("ebx", 32), ("bx", 16), ("bl", 8), ("bh", 8),
                   ("rcx", 64), ("ecx", 32), ("cx", 16), ("cl", 8), ("ch", 8),
                   ("rdx", 64), ("edx", 32), ("dx", 16), ("dl", 8), ("dh", 8),
                   ("rsi", 64), ("esi", 32), ("si", 16), ("sil", 8),
                   ("rdi", 64), ("edi", 32), ("di", 16), ("dil", 8),
                   ("rbp", 64), ("ebp", 32), ("bp", 16), ("bpl", 8),
                   ("rsp", 64), ("esp", 32), ("sp", 16), ("spl", 8)):
    WIDTH[_alias] = _w

ARG_REGS = ("rdi", "rsi", "rdx", "rcx", "r8", "r9")
CALLER_SAVED = ("rax", "rcx", "rdx", "rsi", "rdi",
                "r8", "r9", "r10", "r11")

INSN_LINE = re.compile(r"^ ([0-9a-f]+):\t([0-9a-f ]*?)\s*\t(.*)$")


class Insn:
    __slots__ = ("va", "data", "text", "mnemonic", "operands", "comment")

    def __init__(self, va, data, text):
        self.va = va
        self.data = data
        self.text = text
        parts = text.split(None, 1)
        self.mnemonic = parts[0] if parts else ""
        rest = parts[1] if len(parts) > 1 else ""
        if "#" in rest:
            ops, _, comment = rest.partition("#")
            self.operands = ops.strip()
            self.comment = comment.strip()
        else:
            self.operands = rest.strip()
            self.comment = ""

    @property
    def end(self):
        return self.va + len(self.data)

    def comment_target(self):
        m = re.match(r"^([0-9a-f]+)\b", self.comment)
        return int(m.group(1), 16) if m else None


def disassemble(snapshot, lo, hi):
    """objdump one FDE; returns (export_text, [Insn])."""
    native = subprocess.check_output(
        ["objdump", "-d", "-M", "intel",
         f"--start-address={lo:#x}", f"--stop-address={hi:#x}",
         str(snapshot)], text=True)
    native = native.replace(str(snapshot), "<authenticated-node115>")
    insns = []
    current = None
    for line in native.splitlines():
        m = INSN_LINE.match(line)
        if not m:
            continue
        va = int(m.group(1), 16)
        raw = bytes.fromhex(m.group(2).replace(" ", "")) \
            if m.group(2).strip() else b""
        body = m.group(3)
        if body == "":
            if current is not None:
                current.data += raw
            continue
        current = Insn(va, raw, body)
        insns.append(current)
    for insn in insns:
        if not (lo <= insn.va and insn.end <= hi):
            raise ValueError(f"insn {insn.va:#x} escapes FDE {lo:#x}..{hi:#x}")
    if not insns or insns[0].va != lo:
        raise ValueError(f"FDE {lo:#x} does not decode from its start")
    return native, insns


def split_operands(text):
    parts = []
    depth = 0
    current = ""
    for ch in text:
        if ch == "[":
            depth += 1
        elif ch == "]":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append(current.strip())
            current = ""
        else:
            current += ch
    if current.strip():
        parts.append(current.strip())
    return parts


def parse_memory(operand):
    """Parse 'QWORD PTR [base+index*scale+disp]' style operands."""
    m = re.match(r"^(?:(BYTE|WORD|DWORD|QWORD|XMMWORD) PTR )?\[([^]]*)\]$",
                 operand)
    if not m:
        return None
    size = {"BYTE": 8, "WORD": 16, "DWORD": 32, "QWORD": 64,
            "XMMWORD": 128, None: 64}[m.group(1)]
    inside = m.group(2).replace(" ", "")
    base = None
    index = None
    disp = 0
    for term in re.findall(r"[+-]?[^+-]+", inside):
        sign = -1 if term.startswith("-") else 1
        term = term.lstrip("+-")
        if term in REG64:
            if base is None:
                base = REG64[term]
            else:
                index = REG64[term]
        elif "*" in term:
            reg, _, _scale = term.partition("*")
            if reg in REG64:
                index = REG64[reg]
        elif term == "rip":
            base = "rip"
        elif term.startswith("0x"):
            disp += sign * int(term, 16)
        elif term.isdigit():
            disp += sign * int(term)
        else:
            return None
    return {"size": size, "base": base, "index": index, "disp": disp}


def parse_operand(operand):
    operand = operand.strip()
    if operand in REG64:
        return ("reg", REG64[operand], WIDTH[operand], operand)
    mem = parse_memory(operand)
    if mem is not None:
        return ("mem", mem)
    if operand.startswith("0x") or operand.startswith("-0x"):
        return ("imm", int(operand, 16))
    if re.fullmatch(r"-?\d+", operand):
        return ("imm", int(operand))
    m = re.match(r"^([0-9a-f]+)\s*<", operand)
    if m:
        return ("addr", int(m.group(1), 16))
    return ("other", operand)


# ---------------------------------------------------------------- value tracking
#
# A tracked value is a tuple (kind, off, shift, mask):
#   kind: "PTR" | "SLOTADDR" | "REFRESHFN" | "W0" | "W1" | "W2" | "A"
#   off:  for PTR, the byte offset added to the cache base
#   shift: for words/A, net right shift applied since the load
#   mask: for words/A, the set of original bits that may still be
#         nonzero, as a Python int bitmask over original bit numbers
# "A" is the refresh helper's raw return (publication: raw return =
# A, and C0 bit i = A bit i for i < 63; C0 bit 63 is the constant H).
#
# Tracking is a may-analysis over the body's control-flow graph:
# each register and stack cell maps to a SET of possible tracked
# values, joined at block entries, so a use is recorded only when a
# real control path can carry the value to it.  Untracked is the
# empty set.  Events are deduplicated per (site, kind, word, bits).

FULL64 = (1 << 64) - 1
PTR_VALUE = ("PTR", 0, 0, FULL64)
SLOTADDR_VALUE = ("SLOTADDR", 0, 0, FULL64)
REFRESHFN_VALUE = ("REFRESHFN", 0, 0, FULL64)


def word_value(name, cap):
    mask = FULL64 if cap is None else (1 << cap) - 1
    return (name, 0, 0, mask)


def mapped_bits(value, imm, width):
    """Original bit positions selected by an immediate mask applied
    to the value in its current (shifted, width-capped) state."""
    _kind, _off, shift, mask = value
    bits = []
    for b in range(width):
        if imm >> b & 1:
            original = b + shift
            if 0 <= original < 64 and (mask >> original) & 1:
                bits.append(original)
    return bits


def build_blocks(insns, fde):
    """Split the body into basic blocks; returns (blocks, edges).

    blocks: list of lists of Insn.  edges: dict block index ->
    set of successor block indices (fallthrough + direct targets
    inside the FDE).  Calls do not split blocks.
    """
    index = {insn.va: i for i, insn in enumerate(insns)}
    leaders = {insns[0].va}
    for i, insn in enumerate(insns):
        if insn.mnemonic.startswith("j") or insn.mnemonic == "ret":
            ops = split_operands(insn.operands) if insn.operands else []
            if ops:
                target = parse_operand(ops[0])
                if target[0] == "addr" and fde[0] <= target[1] < fde[1]:
                    leaders.add(target[1])
            if i + 1 < len(insns):
                leaders.add(insns[i + 1].va)
    blocks = []
    current = []
    for insn in insns:
        if insn.va in leaders and current:
            blocks.append(current)
            current = []
        current.append(insn)
    if current:
        blocks.append(current)
    block_of = {}
    for bi, block in enumerate(blocks):
        for insn in block:
            block_of[insn.va] = bi
    edges = {bi: set() for bi in range(len(blocks))}
    for bi, block in enumerate(blocks):
        last = block[-1]
        fall = bi + 1 if bi + 1 < len(blocks) else None
        if last.mnemonic == "ret":
            continue
        if last.mnemonic == "jmp":
            ops = split_operands(last.operands) if last.operands else []
            target = parse_operand(ops[0]) if ops else ("other", None)
            if target[0] == "addr" and target[1] in block_of:
                edges[bi].add(block_of[target[1]])
            continue
        if last.mnemonic.startswith("j"):
            if fall is not None:
                edges[bi].add(fall)
            ops = split_operands(last.operands) if last.operands else []
            target = parse_operand(ops[0]) if ops else ("other", None)
            if target[0] == "addr" and target[1] in block_of:
                edges[bi].add(block_of[target[1]])
            continue
        if fall is not None:
            edges[bi].add(fall)
    return blocks, edges


class Tracker:
    def __init__(self, fde):
        self.fde = fde
        self.events = []
        self.loads = []
        self.slot_sites = []
        self.refresh_sites = []
        self._seen_events = set()

    def note(self, site, kind, value, **kw):
        event = {"site": hx(site), "kind": kind,
                 "word": value[0] if value else None}
        event.update(kw)
        key = json.dumps(event, sort_keys=True)
        if key not in self._seen_events:
            self._seen_events.add(key)
            self.events.append(event)

    # state: dict name -> frozenset of values; registers and
    # "stack:<key>" cells share the map.
    @staticmethod
    def join(a, b):
        out = dict(a)
        for key, values in b.items():
            merged = out.get(key, frozenset()) | values
            out[key] = merged if len(merged) <= 4 else frozenset()
        return out

    def run_block(self, block, state, record):
        values = {k: set(v) for k, v in state.items()}
        pushed = []
        defined_here = set()

        def get(name):
            return values.get(name, set())

        def setv(name, new_values):
            values[name] = set(new_values)
            if new_values:
                defined_here.add(name)
            else:
                defined_here.discard(name)

        def kill(name):
            values[name] = set()

        pending = []  # (value, width, kind, site) from test/cmp

        def flush_pending(mnemonic):
            nonlocal pending
            if mnemonic in ("mov", "movabs", "movzx", "movsxd", "movsx",
                            "lea", "nop", "push", "pop"):
                return  # flags survive these; keep the pending test
            current, pending = pending, []
            if not record:
                return
            for value, width, kind, site in current:
                if mnemonic in ("je", "jne"):
                    if kind == "test_self":
                        self.note(site, "zero_check", value, jcc=mnemonic)
                    elif kind == "cmp_imm":
                        self.note(site, "compare", value, jcc=mnemonic)
                elif mnemonic in ("js", "jns") and kind == "test_self":
                    bit = width - 1 + value[2]
                    if 0 <= bit < 64 and (value[3] >> bit) & 1:
                        self.note(site, "sign_test", value, bits=[bit],
                                  jcc=mnemonic)
                    else:
                        self.note(site, "sign_test_constant", value,
                                  jcc=mnemonic)
                elif (mnemonic.startswith("j") and mnemonic != "jmp") \
                        or mnemonic.startswith("set") \
                        or mnemonic.startswith("cmov"):
                    self.note(site, "flags_use", value, jcc=mnemonic)

        for insn in block:
            mn = insn.mnemonic
            ops = split_operands(insn.operands) if insn.operands else []
            parsed = [parse_operand(o) for o in ops]
            flush_pending(mn)

            if mn in ("mov", "movabs") and len(parsed) == 2:
                dst, src = parsed
                if dst[0] == "reg":
                    dreg = dst[1]
                    if src[0] == "reg":
                        setv(dreg, get(src[1]))
                    elif src[0] == "imm":
                        kill(dreg)
                    elif src[0] == "mem":
                        mem = src[1]
                        if mem["base"] == "rip":
                            tgt = insn.comment_target()
                            if tgt == SLOT_PTR:
                                setv(dreg, {PTR_VALUE})
                                if record:
                                    self.slot_sites.append(insn.va)
                            elif tgt == SLOT_REFRESH:
                                setv(dreg, {REFRESHFN_VALUE})
                            elif tgt in WORD_VAS:
                                name = WORD_NAMES[WORD_VAS.index(tgt)]
                                cap = None if mem["size"] >= 64 \
                                    else mem["size"]
                                setv(dreg, {word_value(name, cap)})
                                if record:
                                    self.loads.append(
                                        {"site": hx(insn.va), "word": name,
                                         "width": mem["size"]})
                            else:
                                kill(dreg)
                        else:
                            base_values = get(mem["base"]) \
                                if mem["base"] else set()
                            new_values = set()
                            handled = False
                            for bv in base_values:
                                if bv[0] == "PTR":
                                    handled = True
                                    eff = bv[1] + mem["disp"]
                                    if eff in (0, 8, 16):
                                        name = WORD_NAMES[eff // 8]
                                        cap = None if mem["size"] >= 64 \
                                            else mem["size"]
                                        new_values.add(word_value(name, cap))
                                        if record:
                                            self.loads.append(
                                                {"site": hx(insn.va),
                                                 "word": name,
                                                 "width": mem["size"]})
                                    elif record:
                                        self.note(insn.va,
                                                  "outside_triple_load", bv,
                                                  offset=eff)
                                elif bv[0] == "SLOTADDR":
                                    handled = True
                                    if mem["disp"] == 0:
                                        new_values.add(PTR_VALUE)
                                    elif mem["disp"] == 8:
                                        new_values.add(REFRESHFN_VALUE)
                            if not handled and mem["base"] in ("rsp", "rbp") \
                                    and mem["index"] is None:
                                key = f"stack:{mem['base']}{mem['disp']:+#x}"
                                new_values = set(get(key))
                            setv(dreg, new_values)
                    else:
                        kill(dreg)
                elif dst[0] == "mem":
                    mem = dst[1]
                    src_values = get(src[1]) if src[0] == "reg" else set()
                    if mem["base"] == "rip":
                        if record:
                            for value in src_values:
                                if value[0] != "PTR":
                                    self.note(insn.va, "store_forward",
                                              value,
                                              dest=hx(insn.comment_target()
                                                      or 0))
                    elif mem["base"] in ("rsp", "rbp") \
                            and mem["index"] is None:
                        key = f"stack:{mem['base']}{mem['disp']:+#x}"
                        setv(key, src_values)
                    else:
                        base_values = get(mem["base"]) \
                            if mem["base"] else set()
                        is_cache = False
                        for bv in base_values:
                            if bv[0] == "PTR":
                                is_cache = True
                                if record:
                                    self.note(insn.va, "cache_write", bv,
                                              offset=bv[1] + mem["disp"])
                        if record and not is_cache:
                            for value in src_values:
                                if value[0] != "PTR":
                                    self.note(insn.va, "store_forward",
                                              value,
                                              dest="register-indirect")
                continue

            if mn in ("movzx", "movsxd", "movsx") and len(parsed) == 2:
                dst, src = parsed
                if dst[0] == "reg":
                    if src[0] == "reg":
                        new_values = set()
                        for value in get(src[1]):
                            if value[0] in ("W0", "W1", "W2", "A"):
                                mask = 0
                                for b in range(src[2]):
                                    original = b + value[2]
                                    if 0 <= original < 64 \
                                            and (value[3] >> original) & 1:
                                        mask |= 1 << original
                                new_values.add((value[0], 0, value[2], mask))
                            else:
                                new_values.add(value)
                        setv(dst[1], new_values)
                    elif src[0] == "mem":
                        mem = src[1]
                        new_values = set()
                        for bv in (get(mem["base"]) if mem["base"]
                                   else set()):
                            if bv[0] == "PTR":
                                eff = bv[1] + mem["disp"]
                                if eff in (0, 8, 16):
                                    name = WORD_NAMES[eff // 8]
                                    new_values.add(
                                        word_value(name, mem["size"]))
                                    if record:
                                        self.loads.append(
                                            {"site": hx(insn.va),
                                             "word": name,
                                             "width": mem["size"]})
                        setv(dst[1], new_values)
                    else:
                        kill(dst[1])
                continue

            if mn == "lea" and len(parsed) == 2:
                dst, src = parsed
                if dst[0] == "reg":
                    if src[0] == "mem" and src[1]["base"] == "rip" \
                            and insn.comment_target() == SLOT_PTR:
                        setv(dst[1], {SLOTADDR_VALUE})
                        if record:
                            self.slot_sites.append(insn.va)
                    elif src[0] == "mem":
                        mem = src[1]
                        new_values = set()
                        for bv in (get(mem["base"]) if mem["base"]
                                   else set()):
                            if bv[0] == "PTR" and mem["index"] is None:
                                new_values.add(("PTR", bv[1] + mem["disp"],
                                                0, FULL64))
                        setv(dst[1], new_values)
                    else:
                        kill(dst[1])
                continue

            if mn == "test" and len(parsed) == 2:
                a, b = parsed
                if a[0] == "reg":
                    for value in get(a[1]):
                        if value[0] in ("PTR", "SLOTADDR", "REFRESHFN"):
                            continue
                        if b[0] == "reg" and b[1] == a[1]:
                            pending.append((value, a[2], "test_self",
                                            insn.va))
                        elif b[0] == "imm":
                            bits = mapped_bits(value, b[1], a[2])
                            if record:
                                self.note(insn.va, "mask_test", value,
                                          bits=bits)
                            pending.append((value, a[2], "mask_test",
                                            insn.va))
                        elif record:
                            self.note(insn.va, "other_use", value,
                                      detail="test")
                continue

            if mn == "cmp" and len(parsed) == 2:
                a, b = parsed
                if a[0] == "reg":
                    for value in get(a[1]):
                        if value[0] in ("PTR", "SLOTADDR", "REFRESHFN"):
                            continue
                        if b[0] == "imm" and b[1] == 0:
                            pending.append((value, a[2], "test_self",
                                            insn.va))
                        elif b[0] == "imm":
                            if record:
                                self.note(insn.va, "compare", value,
                                          imm=hx(b[1]))
                            pending.append((value, a[2], "cmp_imm",
                                            insn.va))
                        elif record:
                            self.note(insn.va, "other_use", value,
                                      detail="cmp")
                continue

            if mn == "bt" and len(parsed) == 2:
                a, b = parsed
                if a[0] == "reg" and record:
                    for value in get(a[1]):
                        if value[0] in ("PTR", "SLOTADDR", "REFRESHFN"):
                            continue
                        if b[0] == "imm":
                            bit = b[1] + value[2]
                            if 0 <= bit < 64 and (value[3] >> bit) & 1:
                                self.note(insn.va, "bt_test", value,
                                          bits=[bit])
                            else:
                                self.note(insn.va, "bt_test_constant",
                                          value)
                        else:
                            self.note(insn.va, "bt_test_dynamic", value)
                continue

            if mn == "and" and len(parsed) == 2:
                dst, src = parsed
                if dst[0] == "reg":
                    current = get(dst[1])
                    if src[0] == "imm" and current:
                        new_values = set()
                        for value in current:
                            if value[0] in ("PTR", "SLOTADDR", "REFRESHFN"):
                                new_values.add(value)
                                continue
                            bits = mapped_bits(value, src[1], dst[2])
                            if record:
                                new_values_jcc = False
                                if len(bits) == 1:
                                    self.note(insn.va, "bit_extract",
                                              value, bits=bits, via="and")
                                else:
                                    self.note(insn.va, "mask_use", value,
                                              bits=bits)
                            mask = 0
                            for bit in bits:
                                mask |= 1 << bit
                            new_values.add((value[0], 0, value[2], mask))
                        setv(dst[1], new_values)
                    else:
                        if record:
                            for value in current:
                                if value[0] not in ("PTR", "SLOTADDR",
                                                   "REFRESHFN"):
                                    self.note(insn.va, "other_use", value,
                                              detail="and")
                        kill(dst[1])
                continue

            if mn in ("shr", "shl", "sar") and len(parsed) == 2:
                dst, src = parsed
                if dst[0] == "reg":
                    current = get(dst[1])
                    if src[0] == "imm" and current:
                        new_values = set()
                        for value in current:
                            if value[0] in ("PTR", "SLOTADDR", "REFRESHFN"):
                                new_values.add(value)
                                continue
                            if record:
                                self.note(insn.va, "shift_use", value,
                                          direction=mn, count=src[1])
                            shift = value[2] + src[1] if mn != "shl" \
                                else value[2] - src[1]
                            new_values.add((value[0], 0, shift, value[3]))
                        setv(dst[1], new_values)
                    else:
                        if record:
                            for value in current:
                                if value[0] not in ("PTR", "SLOTADDR",
                                                   "REFRESHFN"):
                                    self.note(insn.va, "other_use", value,
                                              detail=mn)
                        kill(dst[1])
                continue

            if mn in ("or", "xor", "add", "sub", "imul", "inc", "dec",
                      "neg", "not", "rol", "ror", "sal", "shld", "shrd"):
                if mn == "xor" and len(parsed) == 2 \
                        and parsed[0][0] == "reg" \
                        and parsed[1][0] == "reg" \
                        and parsed[0][1] == parsed[1][1]:
                    kill(parsed[0][1])
                    continue
                if record:
                    seen = set()
                    for p in parsed:
                        if p[0] == "reg":
                            for value in get(p[1]):
                                if value[0] in ("PTR", "SLOTADDR",
                                                "REFRESHFN"):
                                    continue
                                if (p[1], value) not in seen:
                                    seen.add((p[1], value))
                                    self.note(insn.va, "other_use", value,
                                              detail=mn)
                if parsed and parsed[0][0] == "reg":
                    kill(parsed[0][1])
                continue

            if mn == "xchg" and len(parsed) == 2:
                a, b = parsed
                if a[0] == "reg" and b[0] == "reg":
                    va_, vb_ = get(a[1]), get(b[1])
                    setv(a[1], vb_)
                    setv(b[1], va_)
                continue

            if mn.startswith("cmov") and len(parsed) == 2:
                dst, src = parsed
                if dst[0] == "reg":
                    if src[0] == "reg" and get(src[1]):
                        if record:
                            for value in get(src[1]):
                                if value[0] not in ("PTR", "SLOTADDR",
                                                    "REFRESHFN"):
                                    self.note(insn.va, "cmov_merge", value,
                                              detail=mn)
                        setv(dst[1], get(dst[1]) | get(src[1]))
                continue

            if mn == "push" and len(parsed) == 1:
                if parsed[0][0] == "reg":
                    pushed.append((parsed[0][1], set(get(parsed[0][1]))))
                continue

            if mn == "pop" and len(parsed) == 1:
                if parsed[0][0] == "reg":
                    reg = parsed[0][1]
                    restored = set()
                    for i in range(len(pushed) - 1, -1, -1):
                        if pushed[i][0] == reg:
                            restored = pushed.pop(i)[1]
                            break
                    setv(reg, restored)
                continue

            if mn == "call" and len(parsed) == 1:
                operand = parsed[0]
                target = None
                if operand[0] == "mem" and operand[1]["base"] == "rip":
                    target = insn.comment_target()
                elif operand[0] == "addr":
                    target = operand[1]
                is_refresh = target == SLOT_REFRESH or (
                    operand[0] == "reg"
                    and any(v[0] == "REFRESHFN" for v in get(operand[1])))
                if record and not is_refresh:
                    for reg in ARG_REGS:
                        for value in get(reg):
                            if reg in defined_here:
                                if value[0] == "PTR":
                                    self.note(insn.va, "ptr_forward",
                                              value,
                                              dest=hx(target) if target
                                              else "indirect")
                                else:
                                    self.note(insn.va, "call_forward",
                                              value,
                                              dest=hx(target) if target
                                              else "indirect")
                            else:
                                self.note(insn.va, "call_live_in", value,
                                          reg=reg,
                                          dest=hx(target) if target
                                          else "indirect")
                if record and operand[0] == "reg":
                    for value in get(operand[1]):
                        if value[0] not in ("PTR", "SLOTADDR", "REFRESHFN"):
                            self.note(insn.va, "call_forward", value,
                                      detail="call target is the tracked "
                                             "word")
                if is_refresh and record:
                    self.refresh_sites.append(insn.va)
                    self.note(insn.va, "refresh_call", None)
                for reg in CALLER_SAVED:
                    kill(reg)
                if is_refresh:
                    setv("rax", {word_value("A", None)})
                continue

            if mn == "jmp" and len(parsed) == 1:
                operand = parsed[0]
                if operand[0] == "reg":
                    reg_values = get(operand[1])
                    if any(v[0] == "REFRESHFN" for v in reg_values):
                        if record:
                            self.refresh_sites.append(insn.va)
                            self.note(insn.va, "refresh_call", None,
                                      via="tail")
                    elif record:
                        for value in reg_values:
                            if value[0] not in ("PTR", "SLOTADDR",
                                                "REFRESHFN"):
                                self.note(insn.va, "other_use", value,
                                          detail="jump target is the "
                                                 "tracked word")
                continue

            if mn == "ret":
                if record:
                    for value in get("rax"):
                        if value[0] not in ("PTR", "SLOTADDR", "REFRESHFN"):
                            self.note(insn.va, "return_forward", value)
                continue

            # generic fallback
            if parsed and parsed[0][0] == "reg":
                kill(parsed[0][1])
            if record:
                for p in parsed[1:]:
                    if p[0] == "reg":
                        for value in get(p[1]):
                            if value[0] not in ("PTR", "SLOTADDR",
                                                "REFRESHFN"):
                                self.note(insn.va, "other_use", value,
                                          detail=mn)
        return {k: frozenset(v) for k, v in values.items()}


def track_fde(insns, fde):
    """CFG may-analysis over one body.  Returns the record dict."""
    blocks, edges = build_blocks(insns, fde)
    tracker = Tracker(fde)
    entry = [dict() for _ in blocks]
    # fixpoint over block entry states (no event recording)
    changed = True
    rounds = 0
    while changed and rounds < 64:
        changed = False
        rounds += 1
        for bi, block in enumerate(blocks):
            state = entry[bi]
            tracker_pass = Tracker(fde)
            exit_state = tracker_pass.run_block(block, state, record=False)
            for succ in edges[bi]:
                merged = Tracker.join(entry[succ], exit_state)
                if merged != entry[succ]:
                    entry[succ] = merged
                    changed = True
    # recording pass with the converged entry states
    for bi, block in enumerate(blocks):
        tracker.run_block(block, entry[bi], record=True)

    bits_tested = {}
    for event in tracker.events:
        if event["kind"] in ("mask_test", "bt_test", "sign_test",
                             "bit_extract") and event.get("bits"):
            bits_tested.setdefault(event["word"], set()).update(
                event["bits"])
    # canonical order: may-analysis value sets iterate in
    # hash-dependent order, so events and loads are sorted by site
    # to keep regeneration byte-identical across processes.
    events = sorted(
        tracker.events,
        key=lambda e: (int(e["site"], 16), e["kind"], e["word"] or "",
                       json.dumps(e, sort_keys=True)))
    loads = sorted(tracker.loads,
                   key=lambda load: (int(load["site"], 16), load["word"]))
    record = {
        "range": f"{hx(fde[0])}..{hx(fde[1])}",
        "bytes": fde[1] - fde[0],
        "cfg_blocks": len(blocks),
        "slot_load_sites": [hx(s) for s in sorted(set(tracker.slot_sites))],
        "refresh_call_sites": [hx(s)
                               for s in sorted(set(tracker.refresh_sites))],
        "loads": loads,
        "words_read": sorted({load["word"] for load in tracker.loads}),
        "events": events,
        "bits_tested": {k: sorted(v) for k, v in sorted(bits_tested.items())},
    }
    return record


# ---------------------------------------------------------------- arm analysis
#
# For every bit-9 mask test in a consumer body, the two arms are the
# successors of the conditional branch that consumes the test's
# flags.  An arm's region is the set of blocks reachable from the
# arm's entry without entering the merge block -- the immediate
# post-dominator of the branch block in a CFG extended with a
# virtual body-exit node -- and without re-entering the branch
# block: exactly the code that can run on that arm before the arms
# rejoin or the body is left.  An entry block that is a single
# unconditional jump is a trampoline and is resolved through, so
# the C0 test and the refresh-arm A test of one selection name the
# same entries even when one path reaches an arm through a jump.

FLAG_PRESERVING = ("mov", "movabs", "movzx", "movsxd", "movsx",
                   "lea", "nop", "push", "pop")


def arm_cfg(insns, fde):
    """Blocks and edges for arm analysis; node len(blocks) is EXIT.

    Block boundaries match build_blocks (the tracker's), so a test
    site belongs to the same block in both analyses.  Edges that
    build_blocks leaves implicit are explicit here: ret, out-of-body
    and indirect jumps, and falling off the body's end lead to the
    virtual EXIT node.
    """
    leaders = {insns[0].va}
    for i, insn in enumerate(insns):
        if insn.mnemonic.startswith("j") or insn.mnemonic == "ret":
            ops = split_operands(insn.operands) if insn.operands else []
            if ops:
                target = parse_operand(ops[0])
                if target[0] == "addr" and fde[0] <= target[1] < fde[1]:
                    leaders.add(target[1])
            if i + 1 < len(insns):
                leaders.add(insns[i + 1].va)
    blocks = []
    current = []
    for insn in insns:
        if insn.va in leaders and current:
            blocks.append(current)
            current = []
        current.append(insn)
    if current:
        blocks.append(current)
    block_of = {}
    for bi, block in enumerate(blocks):
        for insn in block:
            block_of[insn.va] = bi
    exit_node = len(blocks)
    edges = {bi: set() for bi in range(len(blocks) + 1)}
    for bi, block in enumerate(blocks):
        last = block[-1]
        fall = bi + 1 if bi + 1 < len(blocks) else exit_node
        if last.mnemonic == "ret":
            edges[bi].add(exit_node)
            continue
        ops = split_operands(last.operands) if last.operands else []
        target = parse_operand(ops[0]) if ops else ("other", None)
        if last.mnemonic == "jmp":
            if target[0] == "addr" and target[1] in block_of:
                edges[bi].add(block_of[target[1]])
            else:
                edges[bi].add(exit_node)
            continue
        if last.mnemonic.startswith("j"):
            edges[bi].add(fall)
            if target[0] == "addr" and target[1] in block_of:
                edges[bi].add(block_of[target[1]])
            else:
                edges[bi].add(exit_node)
            continue
        edges[bi].add(fall)
    return blocks, block_of, edges, exit_node


def post_dominators(blocks, edges, exit_node):
    nodes = list(range(len(blocks) + 1))
    pdom = {b: set(nodes) for b in nodes}
    pdom[exit_node] = {exit_node}
    changed = True
    while changed:
        changed = False
        for b in nodes:
            if b == exit_node:
                continue
            inter = None
            for s in edges[b]:
                inter = set(pdom[s]) if inter is None \
                    else inter & pdom[s]
            new = {b} | (inter if inter is not None else set())
            if new != pdom[b]:
                pdom[b] = new
                changed = True
    return pdom


def immediate_post_dominator(pdom, block, exit_node):
    strict = pdom[block] - {block}
    if not strict:
        return exit_node
    # the strict post-dominator nearest the block has the largest
    # own post-dominator set
    return max(strict, key=lambda b: len(pdom[b]))


def resolve_entry(blocks, block_of, bi):
    """Follow single-jump trampoline blocks to the real arm entry."""
    seen = set()
    while bi not in seen:
        seen.add(bi)
        block = blocks[bi]
        if len(block) != 1 or block[0].mnemonic != "jmp":
            return bi
        ops = split_operands(block[0].operands) \
            if block[0].operands else []
        target = parse_operand(ops[0]) if ops else ("other", None)
        if target[0] != "addr" or target[1] not in block_of:
            return bi
        bi = block_of[target[1]]
    return bi


def find_branch(insns, insn_index, site):
    """The conditional branch consuming the flags set by the test
    instruction at `site`.

    Scans forward from the test, crossing only flag-preserving
    instructions (the scan is linear, so a fall-through block
    boundary may be crossed).  Any other shape fails closed: the
    bit-9 tests of this binary are all consumed by a je/jne in the
    same block, and an unmodelled flag consumer would invalidate
    the arm pairing.
    """
    i = insn_index[site]
    for step in range(1, 17):
        if i + step >= len(insns):
            break
        insn = insns[i + step]
        if insn.mnemonic.startswith("j") and insn.mnemonic != "jmp":
            return insn
        if insn.mnemonic in FLAG_PRESERVING:
            continue
        break
    raise ValueError(f"no consuming branch found for test at {site:#x}")


def arm_region(edges, entry, merge, branch_block, exit_node):
    seen = set()
    stack = [entry]
    while stack:
        b = stack.pop()
        if b in seen or b == merge or b == branch_block \
                or b == exit_node:
            continue
        seen.add(b)
        stack.extend(edges[b])
    return seen


def describe_arm(blocks, edges, region, entry, branch_block, merge,
                 exit_node, fde, slot_targets):
    transfers = []
    exits = set()
    for bi in sorted(region):
        for insn in blocks[bi]:
            ops = split_operands(insn.operands) if insn.operands else []
            operand = parse_operand(ops[0]) if ops else ("other", None)
            if insn.mnemonic == "call":
                if operand[0] == "addr":
                    transfers.append({
                        "kind": "call", "site": hx(insn.va),
                        "target": hx(operand[1])})
                elif operand[0] == "mem" \
                        and operand[1]["base"] == "rip":
                    slot = insn.comment_target()
                    resolved = slot_targets.get(slot)
                    transfers.append({
                        "kind": "call_slot", "site": hx(insn.va),
                        "slot": hx(slot) if slot is not None else None,
                        "target": hx(resolved)
                        if resolved is not None else None})
                else:
                    transfers.append({
                        "kind": "call_indirect", "site": hx(insn.va),
                        "operand": insn.operands})
            elif insn.mnemonic == "jmp":
                if operand[0] == "addr" \
                        and not (fde[0] <= operand[1] < fde[1]):
                    transfers.append({
                        "kind": "tailjmp", "site": hx(insn.va),
                        "target": hx(operand[1])})
                elif operand[0] != "addr":
                    transfers.append({
                        "kind": "jmp_indirect", "site": hx(insn.va),
                        "operand": insn.operands})
        for succ in edges[bi]:
            if succ == exit_node:
                exits.add("body_exit")
            elif succ == merge:
                exits.add("merge")
            elif succ == branch_block:
                exits.add("test_block")
    blob = b"".join(insn.data for bi in sorted(region)
                    for insn in blocks[bi])
    if not region:
        kind = "empty"
    elif not transfers:
        kind = "inbody"
    elif len(transfers) == 1 and transfers[0]["kind"] == "call":
        kind = "call"
    elif len(transfers) == 1 and transfers[0]["kind"] == "tailjmp":
        kind = "tailjmp"
    else:
        kind = "mixed"
    return {
        "kind": kind,
        "entry": hx(blocks[entry][0].va),
        "blocks": [hx(blocks[bi][0].va) for bi in sorted(region)],
        "block_count": len(region),
        "bytes": len(blob),
        "region_sha256": hashlib.sha256(blob).hexdigest(),
        "transfers": transfers,
        "exits": sorted(exits),
    }


def analyse_consumer_arms(insns, fde, events, slot_targets):
    """Pair a consumer's bit-9 tests into selection sequences and
    describe both arms of each sequence.

    A sequence is the pair of tests (one on the loaded word C0, one
    on the refresh return A) that select the same ordered pair of
    arm entries.  Every sequence must consist of exactly those two
    tests and both tests must yield identical arm descriptions, or
    the analysis fails closed.
    """
    blocks, block_of, edges, exit_node = arm_cfg(insns, fde)
    pdom = post_dominators(blocks, edges, exit_node)
    insn_index = {insn.va: i for i, insn in enumerate(insns)}
    tests = [e for e in events if e["kind"] == "mask_test"
             and 9 in e.get("bits", [])]
    grouped = {}
    for event in tests:
        site = int(event["site"], 16)
        branch = find_branch(insns, insn_index, site)
        ops = split_operands(branch.operands) if branch.operands else []
        target = parse_operand(ops[0]) if ops else ("other", None)
        if target[0] != "addr" or target[1] not in block_of \
                or branch.end not in block_of:
            raise ValueError(
                f"branch at {branch.va:#x} leaves the body or is "
                "not block-aligned")
        taken_b = block_of[target[1]]
        fall_b = block_of[branch.end]
        if branch.mnemonic in ("jne", "jnz"):
            set_b, clear_b = taken_b, fall_b
        elif branch.mnemonic in ("je", "jz"):
            set_b, clear_b = fall_b, taken_b
        else:
            raise ValueError(
                f"unmodelled bit-9 branch {branch.mnemonic} "
                f"at {branch.va:#x}")
        set_b = resolve_entry(blocks, block_of, set_b)
        clear_b = resolve_entry(blocks, block_of, clear_b)
        branch_b = block_of[branch.va]
        merge = immediate_post_dominator(pdom, branch_b, exit_node)
        analysis = {
            "merge": hx(blocks[merge][0].va)
            if merge != exit_node else "EXIT",
            "set_arm": describe_arm(
                blocks, edges,
                arm_region(edges, set_b, merge, branch_b, exit_node),
                set_b, branch_b, merge, exit_node, fde, slot_targets),
            "clear_arm": describe_arm(
                blocks, edges,
                arm_region(edges, clear_b, merge, branch_b, exit_node),
                clear_b, branch_b, merge, exit_node, fde, slot_targets),
        }
        key = (blocks[set_b][0].va, blocks[clear_b][0].va)
        group = grouped.setdefault(key, {"tests": [], "analysis": []})
        group["tests"].append({
            "site": hx(site), "word": event["word"],
            "branch": hx(branch.va), "jcc": branch.mnemonic})
        group["analysis"].append(analysis)
    sequences = []
    for key in sorted(grouped):
        group = grouped[key]
        if len(group["tests"]) != 2 \
                or sorted(t["word"] for t in group["tests"]) != ["A", "C0"]:
            raise ValueError(
                f"bit-9 sequence at {key[0]:#x}/{key[1]:#x} in body "
                f"{fde[0]:#x} is not a C0/A test pair: {group['tests']}")
        first, second = group["analysis"]
        if first != second:
            raise ValueError(
                f"C0 and A tests of the sequence at {key[0]:#x} in "
                f"body {fde[0]:#x} yield different arms")
        sequences.append({
            "tests": sorted(group["tests"],
                            key=lambda t: int(t["site"], 16)),
            "merge": first["merge"],
            "set_arm": first["set_arm"],
            "clear_arm": first["clear_arm"],
        })
    if len(tests) != 2 * len(sequences):
        raise ValueError(
            f"body {fde[0]:#x}: {len(tests)} bit-9 tests do not "
            f"pair into sequences")
    return sequences


def normalised_stream(insns, fde):
    """Instruction stream of a target body with placement removed.

    A lone branch/call operand becomes @self+offset when its target
    is inside the body and @absolute otherwise; a RIP-relative
    operand becomes [rip->self+offset] or [rip->absolute] by its
    computed target.  Two placements of the same instruction stream
    over the same external references hash identically.
    """
    seq = []
    for insn in insns:
        ops = insn.operands
        lone = re.fullmatch(r"([0-9a-f]+)(?:\s*<[^>]*>)?", ops or "")
        if lone:
            va = int(lone.group(1), 16)
            ops = f"@self+0x{va - fde[0]:x}" \
                if fde[0] <= va < fde[1] else f"@{va:#x}"
        elif "rip" in ops:
            target = insn.comment_target()
            if target is not None:
                rep = f"[rip->self+0x{target - fde[0]:x}]" \
                    if fde[0] <= target < fde[1] \
                    else f"[rip->{target:#x}]"
                ops = re.sub(r"\[rip[^\]]*\]", rep, ops)
        seq.append(f"{insn.mnemonic} {ops}".strip())
    return seq


# ---------------------------------------------------------------- analysis


def body_sha256(data, secs, lo, hi):
    text = next(s for s in secs if s["name"] == ".text")
    off = text["offset"] + (lo - text["address"])
    return hashlib.sha256(data[off:off + (hi - lo)]).hexdigest()


def analyse(data):
    secs = sections(data)
    rel = relocations(data, secs)
    slots_for_cache = sorted(o for o, _i, a in rel if a == CACHE_BASE)
    slots_for_helper = sorted(o for o, _i, a in rel if a == HELPER[0])
    slots_for_c1c2 = sorted(o for o, _i, a in rel
                            if a in (CACHE_BASE + 8, CACHE_BASE + 16))
    if slots_for_cache != [SLOT_PTR]:
        raise ValueError(f"cache slot census changed: {slots_for_cache}")
    if slots_for_helper != [SLOT_REFRESH]:
        raise ValueError(f"refresh slot census changed: {slots_for_helper}")
    if slots_for_c1c2:
        raise ValueError(f"unexpected slots at C1/C2: {slots_for_c1c2}")
    slot_targets = {off: add for off, _info, add in rel}

    sites, neighbours = rip_census(data, secs)
    movabs = movabs_census(data, secs)
    direct_helper_calls = direct_call_census(data, secs, HELPER[0])
    direct_selector_calls = direct_call_census(data, secs, SELECTOR[0])

    with tempfile.TemporaryDirectory(dir=ROOT) as directory:
        snapshot = Path(directory) / "node115.elf"
        snapshot.write_bytes(data)
        ranges, frame_lines = readelf_frames(snapshot)
        if len(ranges) != EXPECTED_FDE_COUNT:
            raise ValueError(
                f"FDE count {len(ranges)} != {EXPECTED_FDE_COUNT}")
        starts = [r[0] for r in ranges]

        import bisect

        def owner(va):
            i = bisect.bisect_right(starts, va) - 1
            if i >= 0 and ranges[i][0] <= va < ranges[i][1]:
                return ranges[i]
            return None

        # validate every candidate site against decoded instructions
        owner_sites = {}
        rejected = []
        fde_insns = {}
        fde_exports = {}
        for site in sites:
            fde = owner(site["modrm_va"])
            if fde is None:
                rejected.append({**site, "reason": "no owning FDE"})
                continue
            if fde not in fde_insns:
                export, insns = disassemble(snapshot, fde[0], fde[1])
                fde_insns[fde] = insns
                fde_exports[fde] = export
            insns = fde_insns[fde]
            match = None
            for insn in insns:
                if insn.va <= site["modrm_va"] < insn.end:
                    off = site["modrm_va"] - insn.va
                    disp_bytes = insn.data[off + 1:off + 5]
                    if len(disp_bytes) == 4:
                        disp, = struct.unpack("<i", disp_bytes)
                        if insn.end + disp == site["target"] \
                                and insn.comment_target() == site["target"]:
                            match = insn
                    break
            if match is None:
                rejected.append({**site, "reason":
                                 "no decoded instruction with this target"})
                continue
            owner_sites.setdefault(fde, []).append(
                {**site, "insn_va": match.va})

        records_by_fde = {}
        for fde in sorted(owner_sites):
            record = track_fde(fde_insns[fde], fde)
            record["sha256"] = body_sha256(data, secs, fde[0], fde[1])
            if fde == HELPER:
                record["role"] = "publisher"
            elif fde == SELECTOR:
                record["role"] = "selector"
            else:
                record["role"] = "consumer"
            records_by_fde[fde] = record

        # ---- the bit-9 family and its arms
        bit9_records = []
        bit9_test_events = 0
        for fde in sorted(records_by_fde):
            record = records_by_fde[fde]
            if record["role"] != "consumer" \
                    or 9 not in record["bits_tested"].get("C0", []):
                continue
            bit9_test_events += len([
                e for e in record["events"] if e["kind"] == "mask_test"
                and 9 in e.get("bits", [])])
            sequences = analyse_consumer_arms(
                fde_insns[fde], fde, record["events"], slot_targets)
            bit9_records.append({
                "range": record["range"],
                "bytes": record["bytes"],
                "sha256": record["sha256"],
                "bits_tested": record["bits_tested"],
                "sequences": sequences,
            })

        # ---- hash-pin every distinct out-of-body arm target
        target_vas = set()
        for record in bit9_records:
            for seq in record["sequences"]:
                for arm in (seq["set_arm"], seq["clear_arm"]):
                    for transfer in arm["transfers"]:
                        if transfer["kind"] in ("call", "tailjmp") \
                                and transfer.get("target"):
                            target_vas.add(int(transfer["target"], 16))
        target_records = {}
        target_exports = {}
        for va in sorted(target_vas):
            fde = owner(va)
            if fde is None:
                raise ValueError(f"arm target {va:#x} has no FDE")
            export, insns = disassemble(snapshot, fde[0], fde[1])
            target_exports[fde] = export
            stream = normalised_stream(insns, fde)
            target_records[fde] = {
                "range": f"{hx(fde[0])}..{hx(fde[1])}",
                "bytes": fde[1] - fde[0],
                "sha256": body_sha256(data, secs, fde[0], fde[1]),
                "insns": len(insns),
                "entry": [f"{i.mnemonic} {i.operands}".strip()
                          for i in insns[:8]],
                "normalised_sha256": hashlib.sha256(
                    ("\n".join(stream) + "\n").encode()).hexdigest(),
                "selected_by_sequences": 0,
                "selected_by_bodies": [],
            }
        # stream families: targets sharing a normalised stream hash
        family_of_hash = {}
        for fde in sorted(target_records):
            digest = target_records[fde]["normalised_sha256"]
            if digest not in family_of_hash:
                family_of_hash[digest] = f"F{len(family_of_hash) + 1}"
            target_records[fde]["stream_family"] = family_of_hash[digest]
        for record in bit9_records:
            body_targets = set()
            for seq in record["sequences"]:
                for arm in (seq["set_arm"], seq["clear_arm"]):
                    for transfer in arm["transfers"]:
                        if transfer["kind"] in ("call", "tailjmp") \
                                and transfer.get("target"):
                            fde = owner(int(transfer["target"], 16))
                            target_records[fde]["selected_by_sequences"] \
                                += 1
                            body_targets.add(fde)
            for fde in body_targets:
                target_records[fde]["selected_by_bodies"].append(
                    record["range"])

    # ---- grouping
    def arm_pair_key(seq):
        set_arm = seq["set_arm"]
        if set_arm["kind"] in ("call", "tailjmp"):
            set_id = f"{set_arm['kind']}:{set_arm['transfers'][0]['target']}"
        else:
            set_id = set_arm["kind"]
        return (set_id, seq["clear_arm"]["kind"])

    seq_members = {}
    for record in bit9_records:
        for idx, seq in enumerate(record["sequences"]):
            member = {
                "consumer": record["range"], "sequence": idx,
                "clear_region_sha256":
                    seq["clear_arm"]["region_sha256"]
                    if seq["clear_arm"]["kind"] == "inbody" else None,
            }
            seq_members.setdefault(arm_pair_key(seq), []).append(member)
    sequence_groups = [
        {"set_arm": key[0], "clear_arm": key[1],
         "sequences": len(members), "members": members}
        for key, members in sorted(
            seq_members.items(), key=lambda kv: (-len(kv[1]), kv[0]))]
    body_members = {}
    for record in bit9_records:
        pairs = sorted({arm_pair_key(seq)
                        for seq in record["sequences"]})
        key = json.dumps(pairs)
        body_members.setdefault(key, []).append(record["range"])
    body_groups = [
        {"pairs": [list(p) for p in json.loads(key)],
         "bodies": len(members), "members": members}
        for key, members in sorted(
            body_members.items(), key=lambda kv: (-len(kv[1]), kv[0]))]

    all_sequences = [seq for record in bit9_records
                     for seq in record["sequences"]]
    shapes = {}
    for seq in all_sequences:
        shape = f"{seq['set_arm']['kind']}/{seq['clear_arm']['kind']}"
        shapes[shape] = shapes.get(shape, 0) + 1
    exact_pairs = {
        (arm_pair_key(seq)[0],
         seq["clear_arm"]["region_sha256"]
         if seq["clear_arm"]["kind"] == "inbody" else "empty")
        for seq in all_sequences}
    summary = {
        "owner_fdes": len(records_by_fde),
        "consumers": sum(1 for r in records_by_fde.values()
                         if r["role"] == "consumer"),
        "bit9_bodies": len(bit9_records),
        "bit9_test_events": bit9_test_events,
        "bit9_test_sites": len({
            (r["range"], t["site"])
            for r in bit9_records for seq in r["sequences"]
            for t in seq["tests"]}),
        "sequences": len(all_sequences),
        "distinct_set_targets": len(target_records),
        "sequence_pair_groups": len(sequence_groups),
        "body_pair_groups": len(body_groups),
        "shapes": shapes,
        "distinct_clear_regions": len({
            seq["clear_arm"]["region_sha256"] for seq in all_sequences
            if seq["clear_arm"]["kind"] == "inbody"}),
        "distinct_exact_pairs": len(exact_pairs),
        "target_stream_families": len(family_of_hash),
        "largest_stream_family": max(
            sum(1 for t in target_records.values()
                if t["stream_family"] == fam)
            for fam in set(family_of_hash.values())),
    }

    census = {
        "fde_count": len(ranges),
        "rip_sites_by_kind": {},
        "validated_sites": sum(len(v) for v in owner_sites.values()),
        "candidate_sites": len(sites),
        "rejected_candidates": [
            {"modrm": hx(r["modrm_va"]), "target": hx(r["target"]),
             "kind": r["kind"], "reason": r["reason"]} for r in rejected],
        "movabs_hits": [{"va": hx(h["va"]), "value": hx(h["value"])}
                        for h in movabs],
        "direct_calls_to_refresh_helper": [hx(s)
                                           for s in direct_helper_calls],
        "direct_calls_to_selector": [hx(s)
                                     for s in direct_selector_calls],
        "neighbour_references": len(neighbours),
    }
    for site in sites:
        census["rip_sites_by_kind"][site["kind"]] = \
            census["rip_sites_by_kind"].get(site["kind"], 0) + 1

    records = {
        "target_sha256": hashlib.sha256(data).hexdigest(),
        "target_size": len(data),
        "slots": {
            "cache_ptr_slot": hx(SLOT_PTR),
            "cache_ptr_addend": hx(CACHE_BASE),
            "refresh_slot": hx(SLOT_REFRESH),
            "refresh_addend": hx(HELPER[0]),
            "slots_with_cache_addend": [hx(s) for s in slots_for_cache],
            "slots_pointing_at_C1_C2": [hx(s) for s in slots_for_c1c2],
        },
        "census": census,
        "drivers": {"C09": BIT9_DRIVER},
        "targets": [target_records[fde] for fde in sorted(target_records)],
        "consumers": bit9_records,
        "groups": {"by_sequence": sequence_groups,
                   "by_body": body_groups},
        "summary": summary,
        "captured_code_executed": False,
    }

    involved = sorted(
        {(int(r["range"].split("..")[0], 16),
          int(r["range"].split("..")[1], 16)) for r in bit9_records}
        | set(target_records))
    frames_text = "".join(
        frame_lines[fde] + "\n" for fde in involved if fde in frame_lines)

    def join_exports(exports_by_fde):
        out = []
        first = True
        for fde in sorted(exports_by_fde):
            lines = exports_by_fde[fde].splitlines(keepends=True)
            if not first:
                cut = 0
                for i, line in enumerate(lines):
                    if line.startswith("Disassembly of section"):
                        cut = i + 1
                        break
                lines = lines[cut:]
            out.append("".join(lines))
            first = False
        return "".join(out)

    consumers_exports = join_exports(
        {fde: fde_exports[fde] for fde in
         {(int(r["range"].split("..")[0], 16),
           int(r["range"].split("..")[1], 16)) for r in bit9_records}})
    targets_exports = join_exports(target_exports)
    return records, frames_text, consumers_exports, targets_exports


def authenticate(data):
    if len(data) != SIZE or hashlib.sha256(data).hexdigest() != SHA256:
        raise ValueError("input is not the pinned node #115 capture")


def generate(binary, output):
    data = Path(binary).read_bytes()
    authenticate(data)
    records, frames_text, consumers_text, targets_text = analyse(data)
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    (output / "records.json").write_text(
        json.dumps(records, indent=2) + "\n", encoding="utf-8")
    (output / "frames.txt").write_text(frames_text, encoding="utf-8")
    (output / "consumers.objdump.txt").write_text(
        consumers_text, encoding="utf-8")
    (output / "targets.objdump.txt").write_text(
        targets_text, encoding="utf-8")
    return records


def main(argv=None):
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=TARGET)
    parser.add_argument("--output", type=Path,
                        default=ROOT / "work/bit9-arms-check")
    args = parser.parse_args(argv)
    records = generate(args.binary, args.output)
    summary = records["summary"]
    print(f"bodies={summary['bit9_bodies']} "
          f"sequences={summary['sequences']} "
          f"targets={summary['distinct_set_targets']} "
          f"groups={summary['sequence_pair_groups']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
