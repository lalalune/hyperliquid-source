"""Checker for the RE-001-options-default-init-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-options-default-init-115/verify.py

Checks, in order: the work binary digest against the provenance
entry; MANIFEST.sha256 against every packet file; excerpt
regeneration byte-for-byte against a fresh objdump run; every
excerpt instruction byte-for-byte against the raw binary
(objdump splits a few long instructions across two lines; the
parser accumulates those continuations); spot instructions
byte-for-byte against a fresh objdump run and the raw binary;
the FDE ranges in frames.txt against a fresh frame dump; the
relocation set against a fresh relocation dump (caller C
0x5fa47e0 is installed at two RELATIVE offsets; every other
pinned routine appears in none); the message literals against
the raw binary; census consistency (callers.tsv against a
fresh census run: every pinned routine's direct calls, tail
jumps, stored qwords and RELATIVE addends, and the callers.tsv
caller function against the smallest enclosing FDE range from
a fresh frame dump); the semantic records (re-deriving the
base/main/preset field tables from the excerpts, the pair-site
adjacency, the temp stores and the table-copy prefix); and the
model tests in tests/test_options_default_init_115.py.
Prints ALL CHECKS PASSED on success, else raises.
"""

import hashlib
import importlib.util
import json
import re
import struct
import subprocess
import sys
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]
BINARY = ROOT / "work" / "hl-node-115.bin"
DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

WINDOWS = [
    ("main.txt", 0x60B3FB0, 0x60B44C7),
    ("base.txt", 0x60B3C30, 0x60B3EEB),
    ("preset.txt", 0x606EAD0, 0x606EB0C),
    ("singleton.txt", 0x61BE810, 0x61BE8C8),
    ("table_init.txt", 0x60DB710, 0x60DBD69),
    ("wrapper.txt", 0x60DBD80, 0x60DBDBB),
    ("singleton_stub.txt", 0x61BE8D0, 0x61BE8D9),
    ("caller_a.txt", 0x5E5A8C0, 0x5E5AA63),
    ("site-5e61cdb.txt", 0x5E61C80, 0x5E61E20),
    ("caller_c.txt", 0x5FA47E0, 0x5FA4C5F),
]

# (target, expected direct calls, expected tail jumps)
EXPECTED_CENSUS = {
    0x60B3FB0: (13, 0), 0x60B3C30: (1, 0), 0x606EAD0: (3, 0),
    0x61BE810: (9, 1), 0x60DB710: (3, 0), 0x60DBD80: (3, 0),
    0x61BE8D0: (0, 0), 0x5E5A8C0: (1, 0), 0x5E61AD0: (1, 0),
    0x5FA47E0: (1, 0),
}

EXPECTED_QWORDS = {
    0x5FA47E0: ["0x10d968", "0x10da70"],
}

EXPECTED_RELATIVE = {
    0x5FA47E0: 2,
}

SPOT_BYTES = {
    0x606EAD0: "f30f1efa",
    0x60B3FB0: "f30f1efa",
    0x60B3C30: "f30f1efa",
    0x61BE810: "f30f1efa",
    0x60DB710: "f30f1efa",
    0x60DBD80: "f30f1efa",
    0x5E5A9A1: "e80a962500",
    0x5E5A9A9: "e822412100",
    0x5E61CD3: "e8d8222500",
    0x5E61CDB: "e8f0cd2000",
    0x5FA4A97: "e814f51000",
    0x5FA4A9F: "e82ca00c00",
}

TAB = chr(9)
LINE_RE = re.compile("^ *([0-9a-f]+):" + TAB + "([0-9a-f ]+?)" + TAB + "(.*)$")
CONT_RE = re.compile("^ *([0-9a-f]+):" + TAB + "([0-9a-f ]+?) *$")


def fail(message):
    raise AssertionError(message)


def load_segments(data):
    """(offset, vaddr, filesz) for every PT_LOAD segment."""
    e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
    e_phentsize, e_phnum = struct.unpack_from("<HH", data, 0x36)
    out = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        (p_type, _f, p_offset, p_vaddr, _p, p_filesz,
         _m, _a) = struct.unpack_from("<IIQQQQQQ", data, off)
        if p_type == 1:
            out.append((p_offset, p_vaddr, p_filesz))
    return out


def va_to_off(segments, va):
    for off, vaddr, size in segments:
        if vaddr <= va < vaddr + size:
            return off + (va - vaddr)
    return None


def parse_excerpt(text):
    """[(address, bytes)] for one excerpt, merging objdump
    continuation lines into the previous instruction."""
    ins = []
    for line in text.splitlines():
        m = LINE_RE.match(line)
        if m:
            raw = m.group(2).replace(" ", "")
            ins.append([int(m.group(1), 16), bytes.fromhex(raw)])
            continue
        m = CONT_RE.match(line)
        if m and ins:
            raw = m.group(2).replace(" ", "")
            ins[-1][1] += bytes.fromhex(raw)
            continue
    return [(a, b) for a, b in ins]


def check_digest(data):
    got = hashlib.sha256(data).hexdigest()
    if got != DIGEST:
        fail("binary digest mismatch: %s != %s" % (got, DIGEST))
    print("digest ok")


def check_manifest():
    lines = (PACKET / "MANIFEST.sha256").read_text().splitlines()
    seen = set()
    for line in lines:
        if not line.strip():
            continue
        digest, name = line.split(None, 1)
        name = name.lstrip("*").strip()
        seen.add(name)
        got = hashlib.sha256((PACKET / name).read_bytes()).hexdigest()
        if got != digest:
            fail("manifest mismatch for %s" % name)
    files = {p.name for p in PACKET.iterdir()
             if p.is_file() and p.name != "MANIFEST.sha256"}
    if seen != files:
        fail("manifest file set mismatch: extra=%s missing=%s"
             % (sorted(seen - files), sorted(files - seen)))
    print("manifest ok (%d files)" % len(seen))


def check_excerpts(segments, data):
    for name, start, stop in WINDOWS:
        fresh = subprocess.run(
            ["objdump", "-d", "--start-address=%#x" % start,
             "--stop-address=%#x" % stop, "work/hl-node-115.bin"],
            capture_output=True, text=True, check=True,
            cwd=ROOT).stdout
        stored = (PACKET / name).read_text()
        if fresh != stored:
            fail("excerpt %s does not match a fresh objdump run" % name)
        for addr, raw in parse_excerpt(stored):
            off = va_to_off(segments, addr)
            if off is None:
                fail("excerpt %s: no file offset for %#x" % (name, addr))
            if data[off:off + len(raw)] != raw:
                fail("excerpt %s: bytes mismatch at %#x" % (name, addr))
    print("excerpts ok (%d windows)" % len(WINDOWS))


def check_spots(segments, data):
    for addr, expect in SPOT_BYTES.items():
        fresh = subprocess.run(
            ["objdump", "-d", "--start-address=%#x" % addr,
             "--stop-address=%#x" % (addr + 16),
             "work/hl-node-115.bin"],
            capture_output=True, text=True, check=True,
            cwd=ROOT).stdout
        ins = parse_excerpt(fresh)
        if not ins or ins[0][0] != addr:
            fail("spot %#x: no instruction at that address" % addr)
        raw = ins[0][1]
        if raw.hex() != expect:
            fail("spot %#x: %s != %s" % (addr, raw.hex(), expect))
        off = va_to_off(segments, addr)
        if data[off:off + len(raw)] != raw:
            fail("spot %#x: raw binary mismatch" % addr)
    print("spots ok (%d)" % len(SPOT_BYTES))


def check_frames():
    text = subprocess.run(
        ["readelf", "--debug-dump=frames", str(BINARY)],
        capture_output=True, text=True, check=True).stdout
    fresh = set()
    for m in re.finditer("pc=([0-9a-f]+)[.][.]([0-9a-f]+)", text):
        fresh.add((int(m.group(1), 16), int(m.group(2), 16)))
    for line in (PACKET / "frames.txt").read_text().splitlines():
        m = re.search("pc=([0-9a-f]+)[.][.]([0-9a-f]+)", line)
        if not m:
            fail("frames.txt line has no pc range: %s" % line)
        pair = (int(m.group(1), 16), int(m.group(2), 16))
        if pair not in fresh:
            fail("FDE %#x..%#x not in a fresh frame dump" % pair)
    print("frames ok")


def check_relocations():
    text = subprocess.run(
        ["readelf", "-r", str(BINARY)],
        capture_output=True, text=True, check=True).stdout
    relocs = {}
    for line in text.splitlines():
        m = re.match("[ ]*([0-9a-f]+)[ ]+([0-9a-f]+)[ ]+R_X86_64_([A-Za-z]+)"
                     "(?:[ ]+([0-9a-f]+))?", line)
        if not m or m.group(3) != "RELATIVE" or m.group(4) is None:
            continue
        relocs[int(m.group(1), 16)] = int(m.group(4), 16)
    stored = []
    for line in (PACKET / "relocations.txt").read_text().splitlines():
        if not line.strip():
            continue
        parts = line.split()
        stored.append((int(parts[0], 16), int(parts[3], 16)))
        if relocs.get(int(parts[0], 16)) != int(parts[3], 16):
            fail("relocation %s not in a fresh dump" % line)
    for target, count in EXPECTED_RELATIVE.items():
        got = [o for o, a in relocs.items() if a == target]
        if len(got) != count:
            fail("RELATIVE count for %#x: %d != %d"
                 % (target, len(got), count))
    for target in EXPECTED_CENSUS:
        if target in EXPECTED_RELATIVE:
            continue
        got = [o for o, a in relocs.items() if a == target]
        if got:
            fail("unexpected RELATIVE records for %#x: %s" % (target, got))
    print("relocations ok (%d records)" % len(stored))


def check_literals(segments, data, records):
    for lit in records["literals"]:
        addr = int(lit["address"], 16)
        off = va_to_off(segments, addr)
        if off is None:
            fail("literal %s: no file offset" % lit["address"])
        if "bytes" in lit:
            want = bytes.fromhex(lit["bytes"])
            if data[off:off + len(want)] != want:
                fail("literal bytes mismatch at %s" % lit["address"])
        else:
            want = lit["text"].encode() + b"\x00"
            if data[off:off + len(want)] != want:
                fail("literal text mismatch at %s" % lit["address"])
    print("literals ok (%d)" % len(records["literals"]))

# ----------------------------------------------------------------
# Census re-derivation (imports the packet's census module).
# ----------------------------------------------------------------

def check_census():
    spec = importlib.util.spec_from_file_location(
        "packet_census", PACKET / "census.py")
    census = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(census)
    data = BINARY.read_bytes()
    sites = census.disassembly_sites()
    relocs, _lines = census.relative_records()
    ranges = census.frame_ranges()
    for target, (want_calls, want_jumps) in EXPECTED_CENSUS.items():
        calls, jumps = census.scan(sites, target)
        if len(calls) != want_calls or len(jumps) != want_jumps:
            fail("census for %#x: calls=%d jumps=%d, want %d/%d"
                 % (target, len(calls), len(jumps),
                    want_calls, want_jumps))
        qw = census.qwords(data, target)
        want_qw = [int(x, 16)
                   for x in EXPECTED_QWORDS.get(target, [])]
        if qw != want_qw:
            fail("qwords for %#x: %s != %s" % (target, qw, want_qw))
        rel = sorted(o for o, a in relocs.items() if a == target)
        want_rel = EXPECTED_RELATIVE.get(target, 0)
        if len(rel) != want_rel:
            fail("RELATIVE count for %#x: %d != %d"
                 % (target, len(rel), want_rel))
    rows = []
    for line in (PACKET / "callers.tsv").read_text().splitlines()[1:]:
        if not line.strip():
            continue
        site, target, caller, kind = line.split("\t")
        rows.append((int(site, 16), int(target, 16), caller, kind))
        want = census.enclosing_fde(ranges, int(site, 16))
        if caller != want:
            fail("callers.tsv caller for %s: %s != %s"
                 % (site, caller, want))
    expect_rows = []
    for target in sorted(EXPECTED_CENSUS):
        calls, jumps = census.scan(sites, target)
        for site in calls:
            expect_rows.append((site, target, "call"))
        for site in jumps:
            expect_rows.append((site, target, "tail jump"))
    expect_rows.sort()
    got_rows = sorted((s, t, k) for s, t, _c, k in rows)
    if got_rows != expect_rows:
        fail("callers.tsv rows do not match a fresh census run")
    print("census ok (%d rows)" % len(rows))


# ----------------------------------------------------------------
# Semantic-record re-derivation from the excerpts.
# ----------------------------------------------------------------

REG64 = {"rax": "rax", "eax": "rax", "ax": "rax", "al": "rax",
         "rbx": "rbx", "ebx": "rbx", "bx": "rbx", "bl": "rbx",
         "rcx": "rcx", "ecx": "rcx", "cx": "rcx", "cl": "rcx",
         "rdx": "rdx", "edx": "rdx", "dx": "rdx", "dl": "rdx",
         "rsi": "rsi", "esi": "rsi", "si": "rsi", "sil": "rsi",
         "rdi": "rdi", "edi": "rdi", "di": "rdi", "dil": "rdi",
         "rbp": "rbp", "ebp": "rbp", "bp": "rbp", "bpl": "rbp",
         "rsp": "rsp", "esp": "rsp", "sp": "rsp", "spl": "rsp",
         "r12": "r12", "r12d": "r12", "r12w": "r12", "r12b": "r12",
         "r13": "r13", "r13d": "r13", "r13w": "r13", "r13b": "r13",
         "r14": "r14", "r14d": "r14", "r14w": "r14", "r14b": "r14",
         "r15": "r15", "r15d": "r15", "r15w": "r15", "r15b": "r15"}
REGWIDTH = {"rax": 8, "eax": 4, "ax": 2, "al": 1,
            "rbx": 8, "ebx": 4, "bx": 2, "bl": 1,
            "rcx": 8, "ecx": 4, "cx": 2, "cl": 1,
            "rdx": 8, "edx": 4, "dx": 2, "dl": 1,
            "rsi": 8, "esi": 4, "si": 2, "sil": 1,
            "rdi": 8, "edi": 4, "di": 2, "dil": 1,
            "rbp": 8, "ebp": 4, "bp": 2, "bpl": 1,
            "rsp": 8, "esp": 4, "sp": 2, "spl": 1,
            "r12": 8, "r12d": 4, "r12w": 2, "r12b": 1,
            "r13": 8, "r13d": 4, "r13w": 2, "r13b": 1,
            "r14": 8, "r14d": 4, "r14w": 2, "r14b": 1,
            "r15": 8, "r15d": 4, "r15w": 2, "r15b": 1}


def parse_text_excerpt(text):
    """[(address, mnemonic text)] for one excerpt."""
    out = []
    for line in text.splitlines():
        m = LINE_RE.match(line)
        if m:
            out.append((int(m.group(1), 16), m.group(3).strip()))
    return out


class FieldState:
    """Byte-level model of the options object as the stores land."""

    def __init__(self, segments, data):
        self.segments = segments
        self.data = data
        self.mem = {}
        self.last_size = {}

    def read_qword(self, va):
        off = va_to_off(self.segments, va)
        if off is None:
            fail("no file offset for %#x" % va)
        return struct.unpack_from("<Q", self.data, off)[0]

    def read_bytes(self, va, size):
        off = va_to_off(self.segments, va)
        if off is None:
            fail("no file offset for %#x" % va)
        return self.data[off:off + size]

    def store(self, base_off, raw, size):
        """Write size bytes at base_off; raw is int, bytes, or
        ("ptr", label)."""
        for i in range(size):
            if isinstance(raw, tuple):
                self.mem[base_off + i] = ("ptr", raw[1])
            elif isinstance(raw, bytes):
                self.mem[base_off + i] = ("int", raw[i])
            else:
                self.mem[base_off + i] = ("int", (raw >> (8 * i)) & 0xFF)
        self.last_size[base_off] = size

    def field(self, off, size=None):
        """(value, size) for the field starting at off, using the
        size of the last store that started there, or the given
        size (for a narrower store that only rewrites part of a
        wider field, such as the preset's one-byte store at
        +0x220 inside the main init's two-byte 0xff01 word)."""
        if size is None:
            size = self.last_size.get(off)
        if size is None:
            fail("no store starts at +%#x" % off)
        cells = [self.mem.get(off + i) for i in range(size)]
        if any(c is None for c in cells):
            fail("field +%#x has unwritten bytes" % off)
        if any(c[0] == "ptr" for c in cells):
            labels = {c[1] for c in cells if c[0] == "ptr"}
            if len(labels) != 1:
                fail("field +%#x mixes pointer labels %s" % (off, labels))
            return ("ptr", labels.pop()), size
        value = 0
        for i, c in enumerate(cells):
            value |= c[1] << (8 * i)
        if size == 16:
            return ("bytes", bytes(c[1] for c in cells).hex()), size
        return value, size


def derive_fields(segments, data, names, base_regs):
    """Replay the store instructions of the named excerpts in
    order, starting from an empty object. base_regs maps the
    excerpt file to the object registers (rdi/rbx). Returns a
    FieldState."""
    state = FieldState(segments, data)
    regs = {}
    xmm = {}
    for name in names:
        text = (PACKET / name).read_text()
        for _addr, txt in parse_text_excerpt(text):
            parts = txt.split(None, 1)
            if not parts:
                continue
            mnemonic = parts[0]
            rest = parts[1] if len(parts) > 1 else ""
            if mnemonic == "mov" and "(%rip)" in rest and "#" in rest:
                m = re.match("%([A-Za-z0-9]+),%([A-Za-z0-9]+)[ ]+# ([0-9a-f]+)",
                             rest.replace(" ", "").replace("\t", ""))
                if m:
                    src, dst, va = m.group(1), m.group(2), int(m.group(3), 16)
                    regs[REG64[dst]] = state.read_qword(va)
                    continue
                m = re.match("-?0x[0-9a-f]+[(]%rip[)],%([A-Za-z0-9]+)[ ]+# ([0-9a-f]+)",
                             rest)
                if m:
                    regs[REG64[m.group(1)]] = state.read_qword(
                        int(m.group(2), 16))
                    continue
            if mnemonic in ("movdqa", "movapd") and "(%rip)" in rest:
                m = re.match("-?0x[0-9a-f]+[(]%rip[)],%xmm([0-9])[ ]+# ([0-9a-f]+)",
                             rest)
                if m:
                    xmm["xmm" + m.group(1)] = state.read_bytes(
                        int(m.group(2), 16), 16)
                    continue
            if mnemonic == "pxor":
                m = re.match("%xmm([0-9]),%xmm([0-9])", rest.replace(" ", ""))
                if m and m.group(1) == m.group(2):
                    xmm["xmm" + m.group(1)] = b"\x00" * 16
                    continue
            if mnemonic in ("mov", "movabs") and rest.startswith("$0x"):
                m = re.match("[$]0x([0-9a-f]+),%([A-Za-z0-9]+)$",
                             rest.replace(" ", ""))
                if m:
                    regs[REG64[m.group(2)]] = int(m.group(1), 16)
                    continue
            if mnemonic == "mov" and rest.startswith("%"):
                m = re.match("%([A-Za-z0-9]+),%([A-Za-z0-9]+)$",
                             rest.replace(" ", ""))
                if m and REG64.get(m.group(1)) in regs:
                    regs[REG64[m.group(2)]] = regs[REG64[m.group(1)]]
                    continue
            if mnemonic == "xor":
                m = re.match("%([A-Za-z0-9]+),%([A-Za-z0-9]+)$",
                             rest.replace(" ", ""))
                if m and m.group(1) == m.group(2):
                    regs[REG64[m.group(1)]] = 0
                    continue
            if mnemonic == "lea":
                m = re.match("0x([0-9a-f]+)[(]%([A-Za-z0-9]+)[)],%([A-Za-z0-9]+)$",
                             rest.replace(" ", ""))
                if m:
                    base = regs.get(REG64[m.group(2)])
                    disp = int(m.group(1), 16)
                    if isinstance(base, tuple):
                        regs[REG64[m.group(3)]] = (
                            "ptr", "%s+%#x" % (base[1], disp))
                    continue
                m = re.match("-?0x[0-9a-f]+[(]%rip[)],%([A-Za-z0-9]+)$",
                             rest.replace(" ", ""))
                if m:
                    continue
            if mnemonic == "call":
                target = rest.split()[0] if rest.split() else ""
                if target == "63f0dd0":
                    size = regs.get("rdi", 0)
                    if isinstance(size, int):
                        regs["rax"] = ("ptr", "heap%x" % size)
                    continue
                if target == "61be810":
                    regs["rax"] = ("ptr", "singleton61be810")
                    continue
                if target == "60b3c30":
                    continue
                continue
            if mnemonic in ("movq", "movl", "movb", "mov", "movups"):
                size = {"movq": 8, "movl": 4, "movb": 1,
                        "movups": 16}.get(mnemonic)
                m = re.match("[$]0x([0-9a-f]+),0x([0-9a-f]+)[(]%([A-Za-z0-9]+)[)]$",
                             rest.replace(" ", ""))
                if m and size is not None:
                    base = REG64.get(m.group(3))
                    if base in base_regs:
                        state.store(int(m.group(2), 16),
                                    int(m.group(1), 16), size)
                    continue
                m = re.match("%([A-Za-z0-9]+),0x([0-9a-f]+)[(]%([A-Za-z0-9]+)[)]$",
                             rest.replace(" ", ""))
                if m:
                    base = REG64.get(m.group(3))
                    if base in base_regs:
                        src = m.group(1)
                        off = int(m.group(2), 16)
                        if src.startswith("xmm"):
                            raw = xmm.get(src)
                            if raw is None:
                                fail("xmm %s used before load" % src)
                            state.store(off, raw, 16)
                        else:
                            value = regs.get(REG64.get(src, src))
                            width = REGWIDTH.get(src, 8)
                            if isinstance(value, tuple):
                                state.store(off, value, 8)
                            elif value is None:
                                fail("register %s used before set" % src)
                            else:
                                state.store(off, value & ((1 << (8 * width)) - 1),
                                            width)
                    continue
                m = re.match("%([A-Za-z0-9]+),[(]%([A-Za-z0-9]+)[)]$",
                             rest.replace(" ", ""))
                if m:
                    base = REG64.get(m.group(2))
                    if base in base_regs:
                        src = m.group(1)
                        value = regs.get(REG64.get(src, src))
                        if isinstance(value, tuple):
                            state.store(0, value, 8)
                        elif value is not None:
                            state.store(0, value, 8)
                    continue
    return state


def records_value_matches(rederived, want):
    """Compare one re-derived field (value, size) with the
    records.json spelling."""
    value, _size = rederived

    def norm(label):
        return label.replace("heap18a", "heap18").replace(
            "heap18b", "heap18")

    if want.startswith("ptr:"):
        return isinstance(value, tuple) and value[0] == "ptr" and (
            norm(value[1]) == norm(want[4:]))
    if want.startswith("bytes:"):
        return (isinstance(value, tuple) and value[0] == "bytes"
                and value[1] == want[6:])
    if want.startswith("double:"):
        if not isinstance(value, int):
            return False
        return struct.unpack("<d", struct.pack("<Q", value))[0] == float(
            want[7:])
    if want.startswith("doubles:"):
        if not (isinstance(value, tuple) and value[0] == "bytes"):
            return False
        got = struct.unpack("<dd", bytes.fromhex(value[1]))
        want_pair = tuple(float(x) for x in want[8:].split(","))
        return got == want_pair
    return isinstance(value, int) and value == int(want, 16)


def check_records(segments, data, records):
    base = derive_fields(segments, data, ["base.txt"], {"rdi", "rbx"})
    for off_hex, want in records["base_fields"].items():
        off = int(off_hex, 16)
        if not records_value_matches(base.field(off), want):
            fail("base field %s: re-derived %s != %s"
                 % (off_hex, base.field(off), want))
    main = derive_fields(segments, data, ["base.txt", "main.txt"],
                         {"rdi", "rbx"})
    for off_hex, want in records["main_fields"].items():
        off = int(off_hex, 16)
        if not records_value_matches(main.field(off), want):
            fail("main field %s: re-derived %s != %s"
                 % (off_hex, main.field(off), want))
    preset = derive_fields(segments, data,
                           ["base.txt", "main.txt", "preset.txt"],
                           {"rdi", "rbx"})
    for off_hex, want in records["preset_overrides"].items():
        off = int(off_hex, 16)
        size = None
        if off == 0x220:
            size = main.field(off)[1]
        if not records_value_matches(preset.field(off, size), want):
            fail("preset field %s: re-derived %s != %s"
                 % (off_hex, preset.field(off, size), want))
    # Pair-site adjacency: each init call is followed 8 bytes
    # later by the preset call on the same object register.
    pairs = {"caller_a.txt": (0x5E5A9A1, 0x5E5A9A9),
             "site-5e61cdb.txt": (0x5E61CD3, 0x5E61CDB),
             "caller_c.txt": (0x5FA4A97, 0x5FA4A9F)}
    for name, (init_site, preset_site) in pairs.items():
        ins = dict(parse_text_excerpt((PACKET / name).read_text()))
        if preset_site - init_site != 8:
            fail("pair gap in %s is not 8 bytes" % name)
        for site, target in ((init_site, "60b3fb0"),
                             (preset_site, "606ead0")):
            if site not in ins:
                fail("pair site %#x missing in %s" % (site, name))
            if target not in ins[site]:
                fail("pair site %#x does not call %s" % (site, target))
    print("records ok (base %d, main %d, preset %d fields)"
          % (len(records["base_fields"]), len(records["main_fields"]),
             len(records["preset_overrides"])))


def check_model_tests():
    out = subprocess.run(
        [sys.executable, "tests/test_options_default_init_115.py"],
        capture_output=True, text=True, cwd=ROOT)
    if out.returncode != 0 or "all 74 checks passed" not in out.stdout:
        fail("model tests failed:\n%s\n%s" % (out.stdout, out.stderr))
    print("model tests ok (74 checks)")


def main():
    data = BINARY.read_bytes()
    segments = load_segments(data)
    records = json.loads((PACKET / "records.json").read_text())
    check_digest(data)
    check_manifest()
    check_excerpts(segments, data)
    check_spots(segments, data)
    check_frames()
    check_relocations()
    check_literals(segments, data, records)
    check_census()
    check_records(segments, data, records)
    check_model_tests()
    print("ALL CHECKS PASSED")


if __name__ == "__main__":
    main()
