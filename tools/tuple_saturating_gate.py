#!/usr/bin/env python3
"""Static, digest-locked RE-001 bind of node #94's 0x4d8c270 leaf.

Python 3.10+ stdlib only. No subprocesses, target execution or disassembler.
The decoder deliberately accepts only the instruction forms used by this
function and the explicitly bounded caller/Location excerpts. Unknown forms,
truncation, changed identities, and branches into instructions fail closed.
"""

import argparse
import bisect
from dataclasses import dataclass
import hashlib
import json
import mmap
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import elf_index
import fde_extents

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / "artifacts/node/94/hl-node"
PACKET = ROOT / "research/work-items/RE-001-tuple-saturating-gate-94"
TARGET_SHA256 = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"
START, END, NEXT = 0x4D8C270, 0x4D8C2D8, 0x4D8C2E0
BODY_SHA256 = "eeb533203e237c62866162e4df9e237a0a04deab8028de004d5d941b9184e228"
MASK64 = (1 << 64) - 1
BASE_COMMIT = "e5c9b6436876b2a4a39daef813171f9879317699"
GENERATED = ("records.json", "instructions.txt", "frames.txt", "README.md")
WHITELIST = (*GENERATED, "verify.py", "MANIFEST.sha256")
CALLER_STARTS = (0x4ADEF10, 0x4ADFE30, 0x4C18B40, 0x4C19420)
CALLER_SITES = (0x4ADF597, 0x4AE041D, 0x4C19272, 0x4C19A2F)
# Complete instructions: argument move, call, and first AL consumer (the
# final excerpt also includes the intervening byte OR and SETE).
EXCERPTS = ((0x4ADF594, 0x4ADF59E), (0x4AE041A, 0x4AE0424),
            (0x4C1926F, 0x4C19279), (0x4C19A2C, 0x4C19A3E),
            (0x4C19B52, 0x4C19B62))


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def check_digest(data):
    require(sha(data) == TARGET_SHA256, "target SHA-256 mismatch")


@dataclass(frozen=True)
class Instruction:
    va: int
    raw: bytes
    op: str
    args: tuple

    def text(self):
        a = self.args
        if self.op == "load":
            return f"mov {a[0]}, {'dword' if a[2] == 32 else 'qword'} [rdi+{a[1]:#x}]"
        if self.op == "cmp_mem":
            return f"cmp {a[0]}, {'dword' if a[2] == 32 else 'qword'} [rdi+{a[1]:#x}]"
        if self.op in ("jne", "jae", "jb", "jmp", "call"):
            return f"{self.op} {a[0]:#x}"
        if self.op == "lea_rip":
            return f"lea {a[0]}, [rip -> {a[1]:#x}]"
        if self.op == "call_slot":
            return f"call qword [rip -> {a[0]:#x}]"
        return self.op + (" " + ", ".join(hex(v) if isinstance(v, int) else v for v in a) if a else "")


def decode(raw, start):
    """Decode every byte, with explicit opcode/ModRM forms and operand widths."""
    out, p = [], 0

    def take(n):
        require(p + n <= len(raw), f"truncated instruction at {start + p:#x}")
        return raw[p:p + n]

    while p < len(raw):
        rest = raw[p:]
        op, args, n = None, (), 0
        if rest.startswith(b"\x8b\x47"):
            n = 3
            op, args = "load", ("eax", struct.unpack("b", take(n)[2:])[0], 32)
        elif rest[:3] in (b"\x48\x8b\x4f", b"\x48\x8b\x47"):
            n = 4
            op, args = "load", ("rcx" if rest[2] == 0x4f else "rax",
                                struct.unpack("b", take(n)[3:])[0], 64)
        elif rest.startswith(b"\x3b\x87"):
            n = 6
            op, args = "cmp_mem", ("eax", struct.unpack_from("<i", take(n), 2)[0], 32)
        elif rest.startswith(b"\x48\x3b\x8f"):
            n = 7
            op, args = "cmp_mem", ("rcx", struct.unpack_from("<i", take(n), 3)[0], 64)
        elif rest[:1] in (b"\x75", b"\x73", b"\x72", b"\xeb"):
            n = 2
            op = {0x75: "jne", 0x73: "jae", 0x72: "jb", 0xeb: "jmp"}[rest[0]]
            args = (start + p + n + struct.unpack("b", take(n)[1:])[0],)
        elif rest[:2] in (b"\x48\x3d", b"\x48\x05"):
            n = 6
            op = "cmp" if rest[1] == 0x3d else "add"
            args = ("rax", struct.unpack_from("<i", take(n), 2)[0] & MASK64)
        elif rest.startswith(b"\x48\xc7\xc2"):
            n = 7
            op, args = "mov", ("rdx", struct.unpack_from("<i", take(n), 3)[0] & MASK64)
        elif rest.startswith(b"\xb0"):
            n = 2
            op, args = "mov", ("al", take(n)[1])
        elif rest.startswith(b"\x3c"):
            n = 2
            op, args = "cmp", ("al", take(n)[1])
        elif rest.startswith(b"\xe8"):
            n = 5
            op, args = "call", (start + p + n + struct.unpack_from("<i", take(n), 1)[0],)
        elif rest.startswith(b"\x48\x8d\x15"):
            n = 7
            op, args = "lea_rip", ("rdx", start + p + n + struct.unpack_from("<i", take(n), 3)[0])
        elif rest.startswith(b"\xff\x15"):
            n = 6
            op, args = "call_slot", (start + p + n + struct.unpack_from("<i", take(n), 2)[0],)
        else:
            fixed = {
                b"\x0f\x9c\xc0": ("setl", ("al",)),
                b"\x0f\x92\xc0": ("setb", ("al",)),
                b"\x0f\x93\xc0": ("setae", ("al",)),
                b"\x84\xc0": ("test", ("al", "al")),
                b"\x48\x0f\x42\xc2": ("cmovb", ("rax", "rdx")),
                b"\x48\x39\xc1": ("cmp", ("rcx", "rax")),
                b"\xc3": ("ret", ()),
                b"\x48\x89\xef": ("mov", ("rdi", "rbp")),
                b"\x4c\x89\xf7": ("mov", ("rdi", "r14")),
                b"\x4c\x89\xef": ("mov", ("rdi", "r13")),
                b"\x4c\x89\xe7": ("mov", ("rdi", "r12")),
                b"\x40\x0a\x6c\x24\x0c": ("or", ("bpl", "byte [rsp+0xc]")),
                b"\x0f\x94\xc1": ("sete", ("cl",)),
            }
            for enc, (name, operands) in fixed.items():
                if rest.startswith(enc):
                    n, op, args = len(enc), name, operands
                    break
        require(op is not None, f"unsupported instruction at {start + p:#x}")
        out.append(Instruction(start + p, take(n), op, args))
        p += n
    return out


def check_cfg(insns):
    addresses = {i.va for i in insns}
    require(len(addresses) == len(insns), "duplicate instruction addresses")
    require(insns and insns[0].va == START and insns[-1].va + len(insns[-1].raw) == END,
            "wrong decoded extent")
    for i in insns:
        require(i.op not in ("call", "call_slot"), "leaf unexpectedly has a callee")
        if i.op in ("jne", "jae", "jb", "jmp"):
            require(i.args[0] in addresses, "branch target outside instruction boundaries")
    # All instructions are reachable in the syntactic CFG; paths are forward.
    by_va = {i.va: i for i in insns}
    seen, pending = set(), [START]
    while pending:
        va = pending.pop()
        if va in seen:
            continue
        require(va in by_va, "fallthrough escapes function")
        seen.add(va)
        i = by_va[va]
        if i.op in ("jne", "jae", "jb", "jmp"):
            require(i.args[0] > i.va, "unexpected backward branch")
            pending.append(i.args[0])
        if i.op not in ("ret", "jmp"):
            pending.append(va + len(i.raw))
    require(seen == addresses, "unreachable bytes inside function")


def check_body(raw):
    require(len(raw) == END - START, "body extent mismatch")
    require(sha(raw) == BODY_SHA256, "body SHA-256 mismatch")
    insns = decode(raw, START)
    check_cfg(insns)
    return insns


def signed32(value):
    return value if value < (1 << 31) else value - (1 << 32)


def model(left, right, current, base, limit):
    """Independent high-level rule. Return (AL, full RAX), including stale bits."""
    require(len(left) == len(right) == 3, "tuple must have three fields")
    require(all(type(v) is int and 0 <= v < 1 << 32 for v in (*left, *right)), "u32 tuple input required")
    require(all(type(v) is int and 0 <= v <= MASK64 for v in (current, base, limit)), "u64 input required")
    a, b = (signed32(left[0]), *left[1:]), (signed32(right[0]), *right[1:])
    if a >= b and current >= limit:
        last = next((x for x, y in zip(left, right) if x != y), left[-1])
        return 2, (last & 0xffffff00) | 2
    threshold = min(base + 5000, MASK64)
    result = int(current >= threshold)
    return result, (threshold & ~0xff) | result


def interpret(insns, fields):
    """Execute only the decoded integer subset, never native target bytes.

    Returns full RAX and the field offsets read. This is a static instruction
    model, independently compared with model(), not target execution.
    """
    code = {i.va: i for i in insns}
    registers, reads = {"rax": 0, "rcx": 0, "rdx": 0}, []
    flags = {"cf": False, "zf": False, "sf": False, "of": False}

    def get(reg):
        if reg == "eax":
            return registers["rax"] & 0xffffffff
        if reg == "al":
            return registers["rax"] & 0xff
        return registers[reg]

    def put(reg, value):
        if reg == "eax":
            registers["rax"] = value & 0xffffffff
        elif reg == "al":
            registers["rax"] = (registers["rax"] & ~0xff) | (value & 0xff)
        else:
            registers[reg] = value & MASK64

    def compare(a, b, bits):
        mask, sign = (1 << bits) - 1, 1 << (bits - 1)
        value = (a - b) & mask
        flags.update(cf=a < b, zf=value == 0, sf=bool(value & sign),
                     of=bool((a ^ b) & (a ^ value) & sign))

    pc = START
    for _ in range(len(insns) + 1):
        i = code[pc]
        op, a = i.op, i.args
        nxt = pc + len(i.raw)
        if op in ("load", "cmp_mem"):
            reg, offset, bits = a
            value = fields[offset]
            require(0 <= value < 1 << bits, "field out of range")
            reads.append(offset)
            if op == "load":
                put(reg, value)
            else:
                compare(get(reg), value, bits)
        elif op == "cmp":
            compare(get(a[0]), get(a[1]) if isinstance(a[1], str) else a[1], 64)
        elif op in ("setl", "setb", "setae"):
            value = {"setl": flags["sf"] != flags["of"], "setb": flags["cf"], "setae": not flags["cf"]}[op]
            put(a[0], int(value))
        elif op == "test":
            value = get(a[0]) & get(a[1])
            flags.update(zf=value == 0, sf=bool(value & 0x80), cf=False, of=False)
        elif op == "mov":
            put(a[0], a[1])
        elif op == "add":
            total = get(a[0]) + a[1]
            put(a[0], total)
            flags["cf"] = total > MASK64
        elif op == "cmovb":
            if flags["cf"]:
                put(a[0], get(a[1]))
        elif op in ("jne", "jae", "jb", "jmp"):
            if {"jne": not flags["zf"], "jae": not flags["cf"], "jb": flags["cf"], "jmp": True}[op]:
                nxt = a[0]
        elif op == "ret":
            return registers["rax"], reads
        else:
            raise ValueError(f"unsupported modeled operation: {op}")
        pc = nxt
    raise ValueError("instruction model did not return")


def fields_for(left, right, current, base, limit):
    return dict(zip((0x60, 0x64, 0x68, 0x4524, 0x4528, 0x452c, 0x28, 0x10, 0x4408),
                    (*left, *right, current, base, limit)))


# Expected AL values are authored from the decoded branches, not computed by
# model(). Equality, signedness, priority and carry boundaries are explicit.
VECTORS = (
    ("equal tuple and limit", (0, 0, 0), (0, 0, 0), 100, 0, 100, 2),
    ("limit one below", (0, 0, 0), (0, 0, 0), 99, 0, 100, 0),
    ("signed negative first overrides high later fields", (0xffffffff, 0xffffffff, 0xffffffff), (0, 0, 0), 5000, 0, 0, 1),
    ("signed positive exceeds negative", (0, 0, 0), (0xffffffff, 0xffffffff, 0xffffffff), 0, 0, 0, 2),
    ("signed minimum below maximum", (0x80000000, 9, 9), (0x7fffffff, 0, 0), 4999, 0, 0, 0),
    ("second field unsigned high bit", (1, 0x80000000, 0), (1, 0x7fffffff, 0xffffffff), 0, 0, 0, 2),
    ("second field lower wins over third", (1, 0, 0xffffffff), (1, 1, 0), 5000, 0, 0, 1),
    ("third field unsigned high bit", (1, 1, 0x80000000), (1, 1, 0x7fffffff), 0, 0, 0, 2),
    ("third lower", (1, 1, 0), (1, 1, 1), 5000, 0, 0, 1),
    ("threshold minus one", (0, 0, 0), (1, 0, 0), 5122, 123, 0, 0),
    ("threshold equality", (0, 0, 0), (1, 0, 0), 5123, 123, 0, 1),
    ("threshold plus one", (0, 0, 0), (1, 0, 0), 5124, 123, 0, 1),
    ("last nonoverflowing base", (0, 0, 0), (1, 0, 0), MASK64, MASK64 - 5000, 0, 1),
    ("first overflowing base below saturated threshold", (0, 0, 0), (1, 0, 0), MASK64 - 1, MASK64 - 4999, 0, 0),
    ("first overflowing base at saturated threshold", (0, 0, 0), (1, 0, 0), MASK64, MASK64 - 4999, 0, 1),
    ("maximum base does not wrap", (0, 0, 0), (1, 0, 0), 4999, MASK64, 0, 0),
    ("maximum base maximum current", (0, 0, 0), (1, 0, 0), MASK64, MASK64, 0, 1),
    ("unsigned current limit high bit", (0, 0, 0), (0, 0, 0), 1 << 63, 0, (1 << 63) - 1, 2),
    ("current below unsigned high limit", (0, 0, 0), (0, 0, 0), (1 << 63) - 1, 0, 1 << 63, 1),
    ("early return retains high first-field bits", (0x12345678, 0, 0), (0, 0, 0), 0, MASK64, 0, 2),
    ("early return retains high second-field bits", (0, 0x87654321, 0), (0, 0, 0), 0, MASK64, 0, 2),
    ("equal tuple retains high third-field bits", (0, 0, 0x12345678), (0, 0, 0x12345678), 0, MASK64, 0, 2),
)


class Image:
    def __init__(self, data):
        self.data = data
        self.sections = elf_index.sections(data)
        names = [s["name"] for s in self.sections]
        require(len(set(names)) == len(names), "duplicate ELF section names")
        self.by_name = {s["name"]: s for s in self.sections}

    def offset(self, va, size):
        matches = [s for s in self.sections if s["type"] != 8 and
                   s["address"] <= va and va + size <= s["address"] + s["size"]]
        require(size > 0 and len(matches) == 1, "ambiguous or non-file-backed VA")
        s = matches[0]
        return s["offset"] + va - s["address"]

    def read(self, va, size):
        off = self.offset(va, size)
        return self.data[off:off + size]


def read_frames(image):
    # Parse actual CIE/FDE records, and cross-check the independently encoded
    # unwind index. No next-start-as-function-end substitution.
    _, table = elf_index.unwind_index(image.data)
    cies, frames = fde_extents.eh_frame_records(image.data, image.sections)
    by_fde = {f["fde"]: f for f in frames}
    require(len(by_fde) == len(frames), "duplicate FDE address")
    require(len({f["start"] for f in frames}) == len(frames), "duplicate FDE start")
    for row in table:
        require(row["fde"] in by_fde and by_fde[row["fde"]]["start"] == row["start"], "unwind index/FDE mismatch")
    frame = image.by_name[".eh_frame"]
    header = image.by_name[".eh_frame_hdr"]
    ptr = header["address"] + 4 + struct.unpack_from("<i", image.data, header["offset"] + 4)[0]
    require(ptr == frame["address"], "wrong eh_frame_hdr frame pointer")
    return cies, sorted(frames, key=lambda f: f["start"])


def frame_record(image, f):
    frame = image.by_name[".eh_frame"]
    raw = image.read(f["fde"], 4)
    length = struct.unpack("<I", raw)[0] + 4
    cie_length = struct.unpack("<I", image.read(f["cie"], 4))[0] + 4
    return dict(start=hex(f["start"]), end_exclusive=hex(f["end"]), size=f["end"] - f["start"],
                fde_va=hex(f["fde"]), fde_section_offset=hex(f["fde"] - frame["address"]),
                cie_va=hex(f["cie"]), cie_section_offset=hex(f["cie"] - frame["address"]),
                fde_record_size=length, fde_sha256=sha(image.read(f["fde"], length)),
                cie_sha256=sha(image.read(f["cie"], cie_length)),
                lsda=None if f["lsda"] is None else hex(f["lsda"]))


def scan_callers(image, target):
    """Full .text byte-pattern scan, without making a second .text copy."""
    s = image.by_name[".text"]
    stop = s["offset"] + s["size"]
    rows = []
    for opcode in (0xe8, 0xe9):
        pos = s["offset"]
        while True:
            pos = image.data.find(bytes([opcode]), pos, stop)
            if pos < 0:
                break
            if pos + 5 <= stop:
                va = s["address"] + pos - s["offset"]
                rel = struct.unpack_from("<i", image.data, pos + 1)[0]
                if va + 5 + rel == target:
                    rows.append(dict(site=hex(va), kind="call" if opcode == 0xe8 else "jump", target=hex(target)))
            pos += 1
    return sorted(rows, key=lambda r: int(r["site"], 16))


def check_callsite(raw, site, target=START):
    insns = decode(raw, site)
    require(len(insns) == 1 and insns[0].op == "call" and insns[0].args == (target,), "wrong direct callee target")


def check_primary_frame(record):
    require((record["start"], record["end_exclusive"], record["fde_section_offset"], record["cie_section_offset"])
            == (hex(START), hex(END), "0x267a08", "0x0"), "primary FDE association mismatch")


def location_record(image):
    va = 0x5742320
    raw = image.read(va, 24)
    pointer, length, line, column = struct.unpack("<QQII", raw)
    require((pointer, length, line, column) == (0, 44, 14, 16), "Location layout mismatch")
    rela = image.by_name[".rela.dyn"]
    require(rela["size"] % 24 == 0, "bad RELA section size")
    matches = []
    for off in range(rela["offset"], rela["offset"] + rela["size"], 24):
        target, info, addend = struct.unpack_from("<QQq", image.data, off)
        if target == va:
            matches.append((off, info, addend))
    require(len(matches) == 1, "missing or duplicate Location relocation")
    off, info, addend = matches[0]
    require(info == 8 and addend == 0x1f6ac3, "wrong Location relocation")
    path = image.read(addend, length)
    require(sha(path) == "f97f82aff9dbfa29eab33282e0bcc9c2f0b1ecb4d0b36300a00f29bf212b30f2", "wrong source path identity")
    # Retain the target's source suffix and exact identity without printing a
    # captured build account or an absolute filesystem path in the packet.
    suffix = path.split(b"/code_Mainnet/", 1)[1].decode("ascii")
    return dict(caller=hex(0x4C19420), lea_site=hex(0x4C19B52), location_va=hex(va),
                location_sha256=sha(raw), path_va=hex(addend), path_size=length,
                path_sha256=sha(path), source_suffix=suffix, line=line, column=column,
                relocation_file_offset=hex(off), relocation_type="R_X86_64_RELATIVE",
                relocation_sha256=sha(image.data[off:off + 24]))


def collect(data):
    check_digest(data)
    image = Image(data)
    insns = check_body(image.read(START, END - START))
    cies, frames = read_frames(image)
    starts = [f["start"] for f in frames]
    selected = {a: next(f for f in frames if f["start"] == a) for a in (*CALLER_STARTS, START, NEXT)}
    primary = frame_record(image, selected[START])
    check_primary_frame(primary)
    require(starts[bisect.bisect_right(starts, START)] == NEXT, "wrong following FDE")
    require(all(f["end"] <= START for f in frames if f["start"] < START), "FDE overlap at primary entry")
    padding = image.read(END, NEXT - END)
    require(padding == b"\xcc" * (NEXT - END), "padding is not INT3")
    primary.update(body_sha256=sha(image.read(START, END - START)), file_offset=hex(image.offset(START, END - START)),
                   padding_size=len(padding), padding_hex=padding.hex(), next_fde_start=hex(NEXT))
    incoming = scan_callers(image, START)
    require([r["site"] for r in incoming] == [hex(s) for s in CALLER_SITES] and all(r["kind"] == "call" for r in incoming), "caller census mismatch")
    for row in incoming:
        site = int(row["site"], 16)
        f = frames[bisect.bisect_right(starts, site) - 1]
        require(site + 5 <= f["end"], "call is not contained in FDE")
        check_callsite(image.read(site, 5), site)
        row.update(enclosing_fde=frame_record(image, f), bytes_hex=image.read(site, 5).hex())
    excerpt_records, excerpt_insns = [], []
    for begin, end in EXCERPTS:
        raw = image.read(begin, end - begin)
        parsed = decode(raw, begin)
        excerpt_insns.extend(parsed)
        excerpt_records.append(dict(start=hex(begin), end_exclusive=hex(end), size=end - begin, sha256=sha(raw)))
    require(excerpt_insns[-3].op == "lea_rip" and excerpt_insns[-3].args == ("rdx", 0x5742320), "wrong first-party Location xref")
    loc = location_record(image)
    vectors = []
    for note, left, right, current, base, limit, expected in VECTORS:
        args = (left, right, current, base, limit)
        rax, reads = interpret(insns, fields_for(*args))
        al, model_rax = model(*args)
        require(al == expected == (rax & 0xff) and rax == model_rax, "instruction/model/vector disagreement")
        vectors.append(dict(note=note, left=list(left), right=list(right), current=current, base=base,
                            limit=limit, expected_al=expected, expected_rax=hex(rax), fields_read=[hex(v) for v in reads]))
    by = {i.va: i for i in insns}
    rule = dict(left_offsets=[hex(i.args[1]) for i in insns if i.op == "load" and i.args[0] == "eax"],
                right_offsets=[hex(i.args[1]) for i in insns if i.op == "cmp_mem" and i.args[0] == "eax"],
                comparison_widths=[32, 32, 32], comparison_signedness=["signed", "unsigned", "unsigned"],
                current_offset=hex(by[START + 3].args[1]), base_offset=hex(by[0x4D8C2AC].args[1]),
                limit_offset=hex(by[0x4D8C2A3].args[1]), addend=by[0x4D8C2B8].args[1],
                overflow_precheck=hex(by[0x4D8C2B0].args[1]), saturation=hex(by[0x4D8C2BE].args[1]),
                early_return_al=by[0x4D8C2A1].args[1], return_register="AL", memory_writes=[],
                full_rax_early="(last_loaded_left_u32 & 0xffffff00) | 2",
                full_rax_other="(saturated_threshold & 0xffffffffffffff00) | AL",
                expression="2 if left >= right and current >= limit else int(current >= min(base + 5000, 2**64 - 1))")
    branches = [dict(site=hex(i.va), condition=i.op, target=hex(i.args[0])) for i in insns if i.op in ("jne", "jae", "jb", "jmp")]
    record = dict(task="RE-001", target=dict(release="94", sha256=TARGET_SHA256, file_size=len(data)),
                  source_baseline_commit=BASE_COMMIT, function=primary, next_frame=frame_record(image, selected[NEXT]),
                  callees=[], rule=rule, branches=branches, incoming=incoming,
                  scan=dict(section=".text", start=hex(image.by_name[".text"]["address"]),
                            size=image.by_name[".text"]["size"], opcodes=["e8 rel32", "e9 rel32"],
                            classification="all byte-pattern matches; bounded caller excerpts decoded; caller CFGs not recovered"),
                  first_party_context=loc, excerpts=excerpt_records, vectors=vectors,
                  counts=dict(body_bytes=END - START, padding_bytes=len(padding), instructions=len(insns),
                              callees=0, direct_calls=len(incoming), direct_jumps=0, branches=len(branches),
                              vectors=len(vectors), writes=0, returns=sum(i.op == "ret" for i in insns)))
    disassembly = ["node #94; original ELF virtual addresses; Intel-style operands", "Strict Python decoder; no normalized operands", "", "PRIMARY FUNCTION"]
    for i in insns:
        disassembly.append(f"{i.va:#x}  {i.raw.hex():<24} {i.text()}")
    disassembly.extend([f"{END:#x}  {padding.hex()}  INT3 padding (outside FDE)", "", "BOUNDED CALLER / LOCATION EXCERPTS (not whole caller functions)"])
    for begin, end in EXCERPTS:
        disassembly.append(f"[{begin:#x}, {end:#x})")
        for i in excerpt_insns:
            if begin <= i.va < end:
                disassembly.append(f"{i.va:#x}  {i.raw.hex():<24} {i.text()}")
    frame_text = ["Exact raw CIE/FDE records; addresses are ELF VAs, offsets relative to .eh_frame."]
    for addr in sorted({selected[a]["cie"] for a in selected}):
        length = struct.unpack("<I", image.read(addr, 4))[0] + 4
        frame_text.append(f"CIE {addr:#x} {image.read(addr, length).hex()}")
    for addr in sorted(selected):
        f = frame_record(image, selected[addr])
        frame_text.append(f"FDE {f['fde_va']} offset={f['fde_section_offset']} cie={f['cie_va']} pc={f['start']}..{f['end_exclusive']} {image.read(int(f['fde_va'], 16), f['fde_record_size']).hex()}")
    return record, "\n".join(disassembly) + "\n", "\n".join(frame_text) + "\n"


def metrics_table(r):
    c = r["counts"]
    labels = (("Function bytes", "body_bytes"), ("INT3 padding bytes", "padding_bytes"),
              ("Decoded primary instructions", "instructions"), ("Callees", "callees"),
              ("Direct e8 call patterns", "direct_calls"), ("Direct e9 jump patterns", "direct_jumps"),
              ("Internal branches", "branches"), ("Return instructions", "returns"),
              ("Memory writes", "writes"), ("Target-grounded vectors", "vectors"))
    return "\n".join(["| Metric | Count |", "| --- | ---: |"] + [f"| {label} | {c[key]} |" for label, key in labels])


def render_readme(r):
    f, rule, loc = r["function"], r["rule"], r["first_party_context"]
    caller_table = "\n".join(f"| `{v['site']}` | `{v['enclosing_fde']['start']}..{v['enclosing_fde']['end_exclusive']}` |" for v in r["incoming"])
    return f"""# RE-001: tuple comparison with a saturating threshold (node #94)

Bounded question: what does `{f['start']}` compute from its input object's
comparison fields, including equality, signedness and arithmetic overflow?

Answer: interpret the dwords at `+0x60/+0x64/+0x68` and
`+0x4524/+0x4528/+0x452c` as lexicographic tuples, comparing the first
field as signed and the remaining fields as unsigned. Let `current` be
the qword at `+0x28`, `base` the qword at `+0x10`, and `limit` the qword at
`+0x4408`. Return `{rule['early_return_al']}` in AL if `left >= right` and
`current >= limit`; otherwise return the Boolean `current >= sat_u64(base +
{rule['addend']})` in AL. The function reads fields and returns without calls
or memory writes. RAX is not a canonical integer result: its upper bits
retain the last loaded tuple field on the early path or the saturated
threshold on the arithmetic path.

Task/component: RE-001 function map, with first-party L1 caller context.
This is a complete local integer rule, not recovery of the caller subsystem.
Intended added files: this packet, `tools/tuple_saturating_gate.py`, and
`tests/test_tuple_saturating_gate.py`. No existing files or gates change.

## Identity and extent

Target: `artifacts/node/94/hl-node`, SHA-256
`{r['target']['sha256']}`; file size `{r['target']['file_size']}` bytes.
Source baseline commit: `{r['source_baseline_commit']}`.
No inferred reference source was used to author the model; no reference
revision or source-level function name is claimed.

| Field | Value |
| --- | --- |
| ELF VA interval | `{f['start']}..{f['end_exclusive']}` (end exclusive) |
| File offset | `{f['file_offset']}` |
| Body SHA-256 | `{f['body_sha256']}` |
| FDE VA / section offset | `{f['fde_va']}` / `{f['fde_section_offset']}` |
| CIE VA / section offset | `{f['cie_va']}` / `{f['cie_section_offset']}` |
| Following FDE start | `{f['next_fde_start']}` |
| Padding bytes | `{f['padding_hex']}` |

{metrics_table(r)}

These counts come from `records.json`; tests compare this table and the
entire generated README with the records. The FDE's explicit range, complete
instruction decode, forward CFG with a shared RET, and INT3 gap jointly
support the extent. The following FDE is an extent boundary only; its
behavior is not bound. `frames.txt` retains raw records and CIE associations.

## Instruction argument

`instructions.txt` gives every primary instruction's address, bytes, decoded
operands and the caller excerpts. `records.json` contains semantic records,
not a duplicate per-instruction listing.

The initial MOV loads the first left dword; the following MOV loads `current`
unconditionally. CMP/SETL/JNE implements the signed first-field comparison.
On equality, CMP/SETB/JNE compares the next field unsigned. On equality
again, CMP/JAE compares the final field unsigned. The SET instructions
preserve flags, so the adjacent JNE still tests the preceding CMP.
The shared TEST path selects the tuple-less case. A tuple that is greater
or equal reaches MOV AL,{rule['early_return_al']} and the unsigned qword
limit comparison; JAE returns that value directly.

The remaining paths load `base`. CMP against `{rule['overflow_precheck']}`
selects whether adding `{rule['addend']}` can carry. Below that cutoff,
the addition cannot overflow. At or above it, ADD/CMOVB replaces a carried
sum with `{rule['saturation']}`. MOV RDX does not overwrite carry. The final
CMP/SETAE compares `current` with that saturated threshold and changes only
AL. The decoded instructions therefore prove both the low-byte rule and
the residual upper RAX bits. `model()` independently states the rule;
`interpret()` follows decoded operations and flags. Boundary vectors compare
them, including short-circuit reads and the first overflowing base.

## Callees and incoming references

The callee list is empty, established by decoding the complete function.
There are no external jumps, indirect dispatch, constant-pool reads or
callee-identity/extent gaps for this function.

The census scans every byte of the complete `.text` section, start
`{r['scan']['start']}`, size `{r['scan']['size']}`, for e8/e9 signed rel32
targets. It retains all matches without an alignment filter:

| Call site | Enclosing FDE interval |
| --- | --- |
{caller_table}

All retained sites decode as direct calls in bounded argument/consumer
excerpts. Those excerpts show callers consuming AL, including comparisons
with the early-return value. Caller FDEs are parsed and cross-checked against
the unwind index. This is a complete byte-pattern census, not a proof of
reachability of whole caller CFGs or a census of indirect/data references.
No negative claim about such other references is made.

The caller `{loc['caller']}` also contains a RIP-relative LEA at
`{loc['lea_site']}` referencing the Location at `{loc['location_va']}`.
The Location's relocated path resolves to first-party source suffix
`{loc['source_suffix']}`, line `{loc['line']}`, column `{loc['column']}`.
The path pointer is resolved through its actual R_X86_64_RELATIVE record,
not by treating a zero on-disk pointer as a loaded pointer. The packet
retains hashes and a relative source suffix to omit the captured build
account/path prefix. This is evidence of first-party caller context; it
does not identify the leaf's original source file, name, or field types.

## Novelty before packet creation

At the source baseline above, each command returned exit status `1` with
empty stdout and stderr (no matches):

```sh
rg -i '4d8c270' research/
rg -i '81314416' research/
rg -i '4d8c270|81314416' ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
```

The sibling PR-list copies were byte-compared with the supplied shared
baseline copies. Their SHA-256 identities were:

| List | SHA-256 |
| --- | --- |
| open_prs.txt | `392b5dc45cbf7fd4c0a56640f566edbb28f31f2d5537cb364c99ad10dc62c496` |
| merged_prs.txt | `efc5ab0523e72ecec68136b2c70a64c7c821829180eafe3d51be4bdc11fbe178` |
| closed_unmerged_prs.txt | `297dcbf46c25131b07f912c7b2af552d40f26be941156362395b7b5e3352ffbb` |

There are no callee behavior binds needing a separate novelty search.
The selected entry is in the assigned address band and is not an excluded
address. The research search predates this packet, which now necessarily
contains its own address. This is an address-novelty result, not a claim
that no other function computes an analogous rule.

## Reproduction and controls

From the repository root, Python 3.10+ stdlib only:

```sh
python3 tools/tuple_saturating_gate.py --out research/work-items/RE-001-tuple-saturating-gate-94/
python3 -m unittest tests.test_tuple_saturating_gate -v
python3 research/work-items/RE-001-tuple-saturating-gate-94/verify.py
make verify
make catalogue-check
```

The tool reads a single mmap of the target, verifies the full pinned digest
before parsing, regenerates deterministic evidence, and checks exact
whitelisted packet content. The manifest also covers the tool and tests.
Wrong target/body identities, bad instructions, shifted FDE metadata,
retargeted incoming calls, altered rule/callee records, padding corruption,
and packet/manifest edits must be rejected. Tests compare the independently
authored model with the decoded instruction model across signedness and
saturation boundaries. These are static checks, not runtime differential
tests. No captured executable is run. No normalization masks are applied.

Analysis used CPython 3.13.5 and focused GNU objdump 2.44 inspection during
candidate selection only. The committed tool, verifier, tests and generated
disassembly do not invoke or require objdump. No connected REA provider was
available; make doctor reported static analysis readiness and no Ghidra.
No installation, network, hosted CI or container result is claimed.

Observed validation: packet generation, the targeted unittest suite, packet
verification, `make verify`, and `make catalogue-check` passed. A supplementary
`make test` run reported an existing timeout in
`test_bridge_inventory.ArtifactTests.test_external_artifact_is_portable_and_still_digest_checked`
and was subsequently interrupted. That repository-wide run is failed and
incomplete, not a passing validation result; no unrelated files were changed.

## Assumptions, limitations and next step

The model assumes valid readable memory for every accessed field, stable
field contents during the call, and ordinary x86-64 integer execution.
Invalid pointers may fault; there are no explicit pointer or range checks.
It preserves the observed short-circuit reads; a skipped field need not be
readable on that path. It models the return value and field reads, not all
scratch-register/flag values or machine fault delivery.

No source-level type names, units for the addend, enum/Option interpretation,
or business meaning are established. In particular the byte result must not
be advertised as a canonical full-register integer. The binary's apparent
first-party caller context is not proof of exclusive first-party ownership.
No independently compiled Rust fragment, matched bytes, full-node build,
whole-ELF equivalence or full-scope acceptance gate is claimed.

Next step: follow the caller's object construction and stores to the compared
fields to establish their units and the meaning of the early-return state,
without assigning source names from the arithmetic alone.
"""


def outputs(data):
    record, disassembly, frames = collect(data)
    return {"records.json": (json.dumps(record, indent=2, sort_keys=True) + "\n").encode(),
            "instructions.txt": disassembly.encode(), "frames.txt": frames.encode(),
            "README.md": render_readme(record).encode()}


def manifest_files():
    return (*GENERATED, "verify.py", "../../../tools/tuple_saturating_gate.py",
            "../../../tests/test_tuple_saturating_gate.py", "../../../tools/elf_index.py",
            "../../../tools/fde_extents.py")


def manifest_bytes(packet):
    return "".join(f"{sha((packet / name).read_bytes())}  {name}\n" for name in manifest_files()).encode()


def check_packet(packet, generated):
    require({p.name for p in packet.iterdir()} == set(WHITELIST), "packet whitelist mismatch")
    require(all((packet / n).is_file() and not (packet / n).is_symlink() for n in WHITELIST), "packet entry is not a regular file")
    require((packet / "MANIFEST.sha256").read_bytes() == manifest_bytes(packet), "manifest mismatch")
    for name, content in generated.items():
        require((packet / name).read_bytes() == content, f"regeneration mismatch: {name}")


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--binary", type=Path, default=BINARY)
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument("--out", type=Path)
    group.add_argument("--check", type=Path)
    args = p.parse_args(argv)
    try:
        with args.binary.open("rb") as file, mmap.mmap(file.fileno(), 0, access=mmap.ACCESS_READ) as data:
            generated = outputs(data)
        if args.out:
            args.out.mkdir(parents=True, exist_ok=True)
            require({v.name for v in args.out.iterdir()} <= set(WHITELIST), "unexpected output file")
            for name, content in generated.items():
                (args.out / name).write_bytes(content)
            # verify.py is maintained source, never generated executable text.
            (args.out / "MANIFEST.sha256").write_bytes(manifest_bytes(args.out))
            check_packet(args.out, generated)
        else:
            check_packet(args.check, generated)
    except (ValueError, OSError, KeyError, StopIteration, struct.error) as error:
        print(f"tuple_saturating_gate: {error}", file=sys.stderr)
        return 1
    print("Static tuple/saturating-gate packet reproduces exactly.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
