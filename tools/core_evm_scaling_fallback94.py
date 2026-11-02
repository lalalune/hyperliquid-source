#!/usr/bin/env python3
"""RE-004: the shared core-to-EVM scaling fallback in node #94 (static).

The three handler copies (0x2715320, 0x4d0a6d0, 0x4d0bfa0) that #157
(negative decimals) and #158 (non-negative decimals) mapped share one
fallback path for every scaling failure. The fallback does NOT rejoin the
success flow: it builds an output record of its own, tagged 0xba (186),
and returns directly. The same record-construction tail is also reached
by the flag-error path, tagged 0x14a (330), which skips the float
computation entirely.

Fallback entries, per copy (five jumps plus the remainder fall-through):

    ladder failure (flag bit 0x10 clear, masked value != 0x10, or the
        checked multiply overflowed)          -> fallback
    positive square-and-multiply loop overflow -> fallback
    positive final checked-multiply overflow   -> fallback
    negative exact-division remainder != 0      -> falls through
    (the 32-bit and 64-bit divide paths share one remainder test placed
    immediately before the fallback entry)

At the fallback entry the handler bounds-checks the record index
(index < count, else a shared panic block: lea rdi, [0x56f21f0];
call [GOT 0x576e470]; jmp join), then loads one byte from the record
(array base from the frame, stride 0xe8, byte at record + 0x49) and
computes a double with one SSE sequence shared verbatim by all copies:

    movsd   xmm0, [amount_slot]          ; the u64 core amount
    unpcklps xmm0, [0x203e80]            ; lanes [0x43300000, 0x45300000]
    subpd   xmm0, [0x202ea0]             ; doubles [2^52, 2^84]
    movzx   eax, byte [record + 0x49]
    movapd  xmm1, xmm0
    unpckhpd xmm1, xmm0
    addsd   xmm1, xmm0                   ; horizontal add
    divsd   xmm1, [0x584b08 + rax*8]     ; 256-entry pow10 table
    movapd  [result_slot], xmm1

Traced lane by lane, with amount a u64 and b the record byte, the
stored double is:

    fallback_double = (f64(a mod 2^32) - 2^84) / pow10_table[b]

where pow10_table[b] is the b-th value of the successive IEEE
multiply-by-10 chain starting at 1.0 (table[0] = 1.0,
table[i+1] = table[i] * 10.0 in doubles). The chain matches all 256
table entries exactly, but it is NOT the correctly-rounded power: it
differs from float(10**b) at 195 of the 256 entries (the test
re-verifies the count and the chain). The divisor in the case table is therefore
always the actual table value, never float(10**b).
horizontal add keeps only the low 32 bits of the amount, and the high
lane contributes -2^84, which dominates for every amount. The result is
therefore always a large-magnitude negative double (for b = 0 it is
about -1.93e25), never the scaled amount. Why the sequence computes this
-- whether it is a miscompiled u64-to-double conversion, a deliberate
sentinel, or something else -- is unresolved; the packet reports the
observed formula exactly and does not claim it equals the scaled amount.

The record tail (shared by the 0xba and 0x14a paths) optionally calls
the virtual slot at [object + 0x20] (object from the frame, null-checked)
with (out_ptr, index, count), then copies the input fields into the
output record at [r12]: tag word at +0x0, dword at +0x2, word at +0x6,
double at +0x8 (the computed float on the 0xba path; on the 0x14a path
the slot is never written by this path, so +0x8 carries whatever the
prologue stored there -- the rcx argument for copy-1), 16-byte fields
at +0x10/+0x28/+0x38/+0x48, qword at +0x58. The epilogue (add rsp, 0x618;
pops; ret) returns directly; the success join sits immediately after
the ret and is a different path (result slot zeroed, dl = 1).

This tool never executes the node and never calls a disassembler. It
verifies the target SHA-256, reads FDE bounds from the binary's own
unwind index via the repository shared ELF parser, checks anchor byte
strings at fixed virtual addresses (including every branch target into
the fallback), verifies the pow10 table entry by entry, transcribes the
fallback windows, and computes the case table arithmetically. It writes
only to the directory given by --out.

    python3 tools/core_evm_scaling_fallback94.py --out <dir>
    python3 tools/core_evm_scaling_fallback94.py --out <dir> --binary <path>

--allow-digest-mismatch is test-only: it lets the tamper controls prove
the anchor checks fail on their own, instead of failing at the digest
check. Production runs must never use it.

writes evidence.json, sites.tsv, fallback_cases.tsv and windows.txt.
Only the Python standard library is used.
"""

import argparse
import csv
import hashlib
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import elf_index  # noqa: E402  (repository shared ELF section parser)

DEFAULT_BINARY = ROOT / "artifacts" / "node" / "94" / "hl-node"
SHA256 = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"
CONST_A = 0x203E80
CONST_B = 0x202EA0
TABLE = 0x584B08
PANIC_MSG = 0x56F21F0
PANIC_GOT = 0x576E470

# Per-copy addresses. Every anchor is verified byte-for-byte; the tamper
# controls in the tests flip one byte of each anchor class and must make
# this tool fail. Branch targets are verified arithmetically, not just
# by their opcode bytes.
COPIES = [
    {
        "id": "copy-1",
        "fde": (0x2715320, 0x2716BC0),
        "fallback": 0x271628D,
        "panic": 0x2716954,
        "panic_join": 0x2716B0C,
        "amount_slot": 0x58,
        "result_slot": 0x40,
        "tail_entry": 0x27162E4,
        "ret": 0x27163E7,
        "success_join": 0x27163E8,
        "flag_cmp": 0x2715641,
        "flag_error": 0x2715746,
        "remainder": (0x271627D, 0x271628D),
        "float": (0x27162A8, 0x27162E0),
        "fallback_window": (0x271628D, 0x27163E8),
        "flag_window": (0x2715746, 0x271574F),
        "entries": [0x27156F4, 0x2715713, 0x271571E, 0x2715955, 0x27159F2],
        "anchors": {
            "bound_cmp": (0x271628D, "4c3bbd18020000"),
            "bound_jae": (0x2716294, "0f83ba060000"),
            "movsd": (0x27162A8, "f20f10442458"),
            "unpcklps": (0x27162AE, "0f1405cbdbaefd"),
            "subpd": (0x27162B5, "660f5c05e3cbaefd"),
            "movzx": (0x27162BD, "0fb6440849"),
            "movapd": (0x27162C2, "660f28c8"),
            "unpckhpd": (0x27162C6, "660f15c8"),
            "addsd": (0x27162CA, "f20f58c8"),
            "lea_table": (0x27162CE, "488d0d33e8e6fd"),
            "divsd": (0x27162D5, "f20f5e0cc1"),
            "store": (0x27162DA, "660f294c2440"),
            "tag_ba": (0x27162E0, "66bbba00"),
            "flag_cmp": (0x2715641, "4280bc33bc00000001"),
            "flag_jne": (0x271564A, "0f85f6000000"),
            "tag_14a": (0x2715746, "66bb4a01"),
            "tail_jmp_14a": (0x271574A, "e9950b0000"),
            "vcall": (0x2716309, "ff5020"),
            "tag_store": (0x27163C5, "6641891c24"),
            "double_store": (0x27163CF, "f2410f11442408"),
            "ret": (0x27163E7, "c3"),
            "rem_test": (0x2716284, "4885d2"),
            "rem_je": (0x2716287, "0f845b010000"),
            "e1": (0x27156F4, "0f84930b0000"),
            "e2": (0x2715713, "0f85740b0000"),
            "e3": (0x271571E, "0f85690b0000"),
            "e4": (0x2715955, "e933090000"),
            "e5": (0x27159F2, "0f8595080000"),
            "panic_lea": (0x2716954, "488d3d95b8fd02"),
            "panic_call": (0x271695B, "ff150f7b0503"),
            "panic_jmp": (0x2716961, "e9a6010000"),
        },
    },
    {
        "id": "copy-2",
        "fde": (0x4D0A6D0, 0x4D0BFA0),
        "fallback": 0x4D0B690,
        "panic": 0x4D0BD36,
        "panic_join": 0x4D0BEEB,
        "amount_slot": 0x48,
        "result_slot": 0x30,
        "tail_entry": 0x4D0B6E7,
        "ret": 0x4D0B7E7,
        "success_join": 0x4D0B7E8,
        "flag_cmp": 0x4D0A9F7,
        "flag_error": 0x4D0AAFC,
        "remainder": (0x4D0B680, 0x4D0B690),
        "float": (0x4D0B6AB, 0x4D0B6E3),
        "fallback_window": (0x4D0B690, 0x4D0B7E8),
        "flag_window": (0x4D0AAFC, 0x4D0AB05),
        "entries": [0x4D0AAAA, 0x4D0AAC9, 0x4D0AAD4, 0x4D0AD34, 0x4D0AE0F],
        "anchors": {
            "bound_cmp": (0x4D0B690, "493baf18020000"),
            "bound_jae": (0x4D0B697, "0f8399060000"),
            "movsd": (0x4D0B6AB, "f20f10442448"),
            "unpcklps": (0x4D0B6B1, "0f1405c8874ffb"),
            "subpd": (0x4D0B6B8, "660f5c05e0774ffb"),
            "movzx": (0x4D0B6C0, "0fb6440849"),
            "movapd": (0x4D0B6C5, "660f28c8"),
            "unpckhpd": (0x4D0B6C9, "660f15c8"),
            "addsd": (0x4D0B6CD, "f20f58c8"),
            "lea_table": (0x4D0B6D1, "488d0d309487fb"),
            "divsd": (0x4D0B6D8, "f20f5e0cc1"),
            "store": (0x4D0B6DD, "660f294c2430"),
            "tag_ba": (0x4D0B6E3, "66bbba00"),
            "flag_cmp": (0x4D0A9F7, "4280bc33bc00000001"),
            "flag_jne": (0x4D0AA00, "0f85f6000000"),
            "tag_14a": (0x4D0AAFC, "66bb4a01"),
            "tail_jmp_14a": (0x4D0AB00, "e9e20b0000"),
            "vcall": (0x4D0B70C, "ff5020"),
            "tag_store": (0x4D0B7C5, "6641891c24"),
            "double_store": (0x4D0B7CF, "f2410f11442408"),
            "ret": (0x4D0B7E7, "c3"),
            "rem_test": (0x4D0B687, "4885d2"),
            "rem_je": (0x4D0B68A, "0f8458010000"),
            "e1": (0x4D0AAAA, "0f84e00b0000"),
            "e2": (0x4D0AAC9, "0f85c10b0000"),
            "e3": (0x4D0AAD4, "0f85b60b0000"),
            "e4": (0x4D0AD34, "e957090000"),
            "e5": (0x4D0AE0F, "0f857b080000"),
            "panic_lea": (0x4D0BD36, "488d3db3649e00"),
            "panic_call": (0x4D0BD3D, "ff152d27a600"),
            "panic_jmp": (0x4D0BD43, "e9a3010000"),
        },
    },
    {
        "id": "copy-3",
        "fde": (0x4D0BFA0, 0x4D0D870),
        "fallback": 0x4D0CF60,
        "panic": 0x4D0D606,
        "panic_join": 0x4D0D7BB,
        "amount_slot": 0x48,
        "result_slot": 0x30,
        "tail_entry": 0x4D0CFB7,
        "ret": 0x4D0D0B7,
        "success_join": 0x4D0D0B8,
        "flag_cmp": 0x4D0C2C7,
        "flag_error": 0x4D0C3CC,
        "remainder": (0x4D0CF50, 0x4D0CF60),
        "float": (0x4D0CF7B, 0x4D0CFB3),
        "fallback_window": (0x4D0CF60, 0x4D0D0B8),
        "flag_window": (0x4D0C3CC, 0x4D0C3D5),
        "entries": [0x4D0C37A, 0x4D0C399, 0x4D0C3A4, 0x4D0C604, 0x4D0C6DF],
        "anchors": {
            "bound_cmp": (0x4D0CF60, "493baf18020000"),
            "bound_jae": (0x4D0CF67, "0f8399060000"),
            "movsd": (0x4D0CF7B, "f20f10442448"),
            "unpcklps": (0x4D0CF81, "0f1405f86e4ffb"),
            "subpd": (0x4D0CF88, "660f5c05105f4ffb"),
            "movzx": (0x4D0CF90, "0fb6440849"),
            "movapd": (0x4D0CF95, "660f28c8"),
            "unpckhpd": (0x4D0CF99, "660f15c8"),
            "addsd": (0x4D0CF9D, "f20f58c8"),
            "lea_table": (0x4D0CFA1, "488d0d607b87fb"),
            "divsd": (0x4D0CFA8, "f20f5e0cc1"),
            "store": (0x4D0CFAD, "660f294c2430"),
            "tag_ba": (0x4D0CFB3, "66bbba00"),
            "flag_cmp": (0x4D0C2C7, "4280bc33bc00000001"),
            "flag_jne": (0x4D0C2D0, "0f85f6000000"),
            "tag_14a": (0x4D0C3CC, "66bb4a01"),
            "tail_jmp_14a": (0x4D0C3D0, "e9e20b0000"),
            "vcall": (0x4D0CFDC, "ff5020"),
            "tag_store": (0x4D0D095, "6641891c24"),
            "double_store": (0x4D0D09F, "f2410f11442408"),
            "ret": (0x4D0D0B7, "c3"),
            "rem_test": (0x4D0CF57, "4885d2"),
            "rem_je": (0x4D0CF5A, "0f8458010000"),
            "e1": (0x4D0C37A, "0f84e00b0000"),
            "e2": (0x4D0C399, "0f85c10b0000"),
            "e3": (0x4D0C3A4, "0f85b60b0000"),
            "e4": (0x4D0C604, "e957090000"),
            "e5": (0x4D0C6DF, "0f857b080000"),
            "panic_lea": (0x4D0D606, "488d3de34b9e00"),
            "panic_call": (0x4D0D60D, "ff155d0ea600"),
            "panic_jmp": (0x4D0D613, "e9a3010000"),
        },
    },
]

SHARED_ANCHORS = [
    ("const_lanes", CONST_A, "00003043000030450000000000000000"),
    ("const_bias", CONST_B, "00000000000030430000000000003045"),
]

AMOUNTS = [0, 1, 2, 10 ** 18, (1 << 32) - 1, 1 << 32, (1 << 32) + 1,
           (1 << 64) - 1]
BYTES = [0, 1, 2, 18, 77, 78, 255]


class CheckError(Exception):
    pass


def fail(message):
    raise CheckError(message)


def va_to_offset(data, sections, va):
    for section in sections:
        if section["type"] == 8:
            continue
        start = section["address"]
        end = start + section["size"]
        if start <= va < end:
            return section["offset"] + (va - start)
    fail(f"VA {va:#x} has no file mapping")


def read_at(data, sections, va, size):
    offset = va_to_offset(data, sections, va)
    chunk = data[offset:offset + size]
    if len(chunk) != size:
        fail(f"short read at VA {va:#x}")
    return chunk


def check_anchor(data, sections, va, expected_hex, name):
    actual = read_at(data, sections, va, len(expected_hex) // 2).hex()
    if actual != expected_hex:
        fail(f"anchor {name} at {va:#x}: expected {expected_hex}, got {actual}")


def rel_target(va, size, disp_offset, raw):
    return va + size + struct.unpack_from("<i", raw, disp_offset)[0]


def check_branch(data, sections, name, va, raw_hex, expect):
    raw = bytes.fromhex(raw_hex)
    if raw[0] == 0xE9:
        target = rel_target(va, 5, 1, raw)
    elif raw[0] == 0x0F and raw[1] in (0x83, 0x84, 0x85):
        target = rel_target(va, 6, 2, raw)
    else:
        fail(f"{name} at {va:#x} is not a recognised branch")
    if target != expect:
        fail(f"{name} at {va:#x} targets {target:#x}, expected {expect:#x}")


def check_rip_target(data, sections, name, va, raw_hex, size, disp_offset,
                     expect):
    raw = bytes.fromhex(raw_hex)
    target = rel_target(va, size, disp_offset, raw)
    if target != expect:
        fail(f"{name} at {va:#x} targets {target:#x}, expected {expect:#x}")


def fde_bounds(data):
    _, entries = elf_index.unwind_index(data)
    return {e["start"]: e["next_index_upper_bound"] for e in entries}


def fallback_model(amount, byte, table):
    """The fallback SSE sequence, traced lane by lane in IEEE doubles.

    lo = f64(amount mod 2^32); hi = 0.0 - 2^84; sum = lo + hi (one
    IEEE rounding); result = sum / table[byte] (one IEEE rounding).
    """
    lo = float(amount & 0xFFFFFFFF)
    total = lo + (0.0 - float(1 << 84))
    return total / table[byte]


def double_bits(value):
    return struct.unpack("<Q", struct.pack("<d", value))[0]


def build(binary_path, out_dir, allow_digest_mismatch=False):
    data = Path(binary_path).read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != SHA256 and not allow_digest_mismatch:
        fail(f"target digest mismatch: {digest}")
    sections = elf_index.sections(data)
    bounds = fde_bounds(data)

    for copy in COPIES:
        fde_start, fde_end = copy["fde"]
        if bounds.get(fde_start) != fde_end:
            fail(f"FDE bound mismatch for {copy['id']}: "
                 f"{bounds.get(fde_start)}")
        for name, (va, expected) in copy["anchors"].items():
            check_anchor(data, sections, va, expected,
                         f"{copy['id']}:{name}")
        anchors = copy["anchors"]
        check_branch(data, sections, f"{copy['id']}:bound_jae",
                     anchors["bound_jae"][0], anchors["bound_jae"][1],
                     copy["panic"])
        check_rip_target(data, sections, f"{copy['id']}:unpcklps",
                         anchors["unpcklps"][0], anchors["unpcklps"][1],
                         7, 3, CONST_A)
        check_rip_target(data, sections, f"{copy['id']}:subpd",
                         anchors["subpd"][0], anchors["subpd"][1],
                         8, 4, CONST_B)
        check_rip_target(data, sections, f"{copy['id']}:lea_table",
                         anchors["lea_table"][0], anchors["lea_table"][1],
                         7, 3, TABLE)
        check_branch(data, sections, f"{copy['id']}:flag_jne",
                     anchors["flag_jne"][0], anchors["flag_jne"][1],
                     copy["flag_error"])
        check_branch(data, sections, f"{copy['id']}:tail_jmp_14a",
                     anchors["tail_jmp_14a"][0],
                     anchors["tail_jmp_14a"][1], copy["tail_entry"])
        check_branch(data, sections, f"{copy['id']}:rem_je",
                     anchors["rem_je"][0], anchors["rem_je"][1],
                     copy["success_join"])
        check_rip_target(data, sections, f"{copy['id']}:panic_lea",
                         anchors["panic_lea"][0], anchors["panic_lea"][1],
                         7, 3, PANIC_MSG)
        check_rip_target(data, sections, f"{copy['id']}:panic_call",
                         anchors["panic_call"][0],
                         anchors["panic_call"][1], 6, 2, PANIC_GOT)
        check_branch(data, sections, f"{copy['id']}:panic_jmp",
                     anchors["panic_jmp"][0], anchors["panic_jmp"][1],
                     copy["panic_join"])
        for i, entry_va in enumerate(copy["entries"], 1):
            name = f"e{i}"
            check_branch(data, sections, f"{copy['id']}:{name}",
                         anchors[name][0], anchors[name][1],
                         copy["fallback"])

    for name, va, expected in SHARED_ANCHORS:
        check_anchor(data, sections, va, expected, name)

    table_bytes = read_at(data, sections, TABLE, 256 * 8)
    table = list(struct.unpack("<256d", table_bytes))
    chain = [1.0]
    for _ in range(255):
        chain.append(chain[-1] * 10.0)
    for i, value in enumerate(table):
        if value != chain[i]:
            fail(f"pow10 table entry {i} is {value!r}, not chain value "
                 f"{chain[i]!r}")
    round_mismatch = [i for i in range(256) if table[i] != float(10 ** i)]

    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    def write_text(name, text_content):
        (out_dir / name).write_text(text_content)

    def write_tsv(name, rows, columns):
        with open(out_dir / name, "w", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=columns,
                                    delimiter="\t", lineterminator="\n")
            writer.writeheader()
            writer.writerows(rows)

    windows = {}
    window_lines = []
    for copy in COPIES:
        for kind in ("remainder", "float", "fallback_window", "flag_window"):
            start, end = copy[kind]
            chunk = read_at(data, sections, start, end - start)
            key = f"{copy['id']}:{kind}"
            windows[key] = {
                "start": hex(start),
                "end": hex(end),
                "bytes": len(chunk),
                "sha256": hashlib.sha256(chunk).hexdigest(),
            }
            window_lines.append(f"{key} {start:#x}..{end:#x} {chunk.hex()}")

    sites_rows = []
    for copy in COPIES:
        sites_rows.append({
            "copy": copy["id"],
            "fde_start": hex(copy["fde"][0]),
            "fde_end": hex(copy["fde"][1]),
            "fallback": hex(copy["fallback"]),
            "panic": hex(copy["panic"]),
            "panic_join": hex(copy["panic_join"]),
            "amount_slot": hex(copy["amount_slot"]),
            "result_slot": hex(copy["result_slot"]),
            "tail_entry": hex(copy["tail_entry"]),
            "ret": hex(copy["ret"]),
            "success_join": hex(copy["success_join"]),
            "flag_cmp": hex(copy["flag_cmp"]),
            "flag_error": hex(copy["flag_error"]),
            "entries": ";".join(hex(v) for v in copy["entries"]),
            "remainder_window":
                f"{copy['remainder'][0]:#x}..{copy['remainder'][1]:#x}",
            "float_window": f"{copy['float'][0]:#x}..{copy['float'][1]:#x}",
            "fallback_window":
                f"{copy['fallback_window'][0]:#x}.."
                f"{copy['fallback_window'][1]:#x}",
            "flag_window":
                f"{copy['flag_window'][0]:#x}..{copy['flag_window'][1]:#x}",
        })

    case_rows = []
    for amount in AMOUNTS:
        for byte in BYTES:
            value = fallback_model(amount, byte, table)
            naive = float(amount) / table[byte]
            case_rows.append({
                "amount": amount,
                "amount_hex": f"{amount:#x}",
                "byte": byte,
                "lo32": amount & 0xFFFFFFFF,
                "table_value": repr(table[byte]),
                "fallback_double": repr(value),
                "fallback_double_hex": f"{double_bits(value):#x}",
                "naive_double": repr(naive),
                "naive_double_hex": f"{double_bits(naive):#x}",
                "equal": "1" if value == naive else "0",
            })

    evidence = {
        "target": "node #94",
        "sha256": SHA256,
        "worktree_baseline": "2993e46",
        "constants": {
            "lanes_va": hex(CONST_A),
            "lanes_hex": SHARED_ANCHORS[0][2],
            "lanes_f32": [176.0, 2608.0, 0.0, 0.0],
            "bias_va": hex(CONST_B),
            "bias_hex": SHARED_ANCHORS[1][2],
            "bias_f64": [float(1 << 52), float(1 << 84)],
        },
        "pow10_table": {
            "va": hex(TABLE),
            "entries": 256,
            "bytes": len(table_bytes),
            "sha256": hashlib.sha256(table_bytes).hexdigest(),
            "model": "successive IEEE multiply-by-10 chain from 1.0",
            "exact_chain": True,
            "differs_from_correctly_rounded_pow10": round_mismatch,
            "differs_count": len(round_mismatch),
            "note": "entry b is chain[b], not float(10**b); the case table "
                    "uses the actual table value as the divisor",
        },
        "panic": {
            "message_va": hex(PANIC_MSG),
            "got_va": hex(PANIC_GOT),
            "note": "bound-failure block only; the callee is not identified",
        },
        "copies": {
            copy["id"]: {
                "fde": [hex(copy["fde"][0]), hex(copy["fde"][1])],
                "fallback": hex(copy["fallback"]),
                "panic": hex(copy["panic"]),
                "panic_join": hex(copy["panic_join"]),
                "amount_slot": hex(copy["amount_slot"]),
                "result_slot": hex(copy["result_slot"]),
                "tail_entry": hex(copy["tail_entry"]),
                "ret": hex(copy["ret"]),
                "success_join": hex(copy["success_join"]),
                "flag_cmp": hex(copy["flag_cmp"]),
                "flag_error": hex(copy["flag_error"]),
                "entries": [hex(v) for v in copy["entries"]],
                "record_stride": "0xe8",
                "record_byte_offset": "0x49",
                "record_tag_float": "0xba",
                "record_tag_flag_error": "0x14a",
            }
            for copy in COPIES
        },
        "model": {
            "formula": "(f64(amount mod 2^32) - 2^84) / pow10_table[byte]",
            "diverges_from_naive": True,
            "naive_formula": "f64(amount) / pow10_table[byte]",
            "unresolved": "why the sequence computes this formula "
                          "(miscompiled conversion, sentinel, or other)",
        },
        "windows": windows,
    }

    write_tsv("sites.tsv", sites_rows,
              ["copy", "fde_start", "fde_end", "fallback", "panic",
               "panic_join", "amount_slot", "result_slot", "tail_entry",
               "ret", "success_join", "flag_cmp", "flag_error", "entries",
               "remainder_window", "float_window", "fallback_window",
               "flag_window"])
    write_tsv("fallback_cases.tsv", case_rows,
              ["amount", "amount_hex", "byte", "lo32", "table_value",
               "fallback_double", "fallback_double_hex", "naive_double",
               "naive_double_hex", "equal"])
    write_text("windows.txt", "\n".join(window_lines) + "\n")
    (out_dir / "evidence.json").write_text(json.dumps(evidence, indent=2)
                                           + "\n")
    return evidence


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True)
    parser.add_argument("--binary", default=str(DEFAULT_BINARY))
    parser.add_argument("--allow-digest-mismatch", action="store_true")
    args = parser.parse_args(argv)
    try:
        build(args.binary, args.out, args.allow_digest_mismatch)
    except CheckError as exc:
        print(f"core_evm_scaling_fallback94: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
