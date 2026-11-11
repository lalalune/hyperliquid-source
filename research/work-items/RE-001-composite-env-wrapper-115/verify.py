"""Checker for the RE-001-composite-env-wrapper-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-composite-env-wrapper-115/verify.py

Checks, in order: the work binary digest against the provenance
entry; MANIFEST.sha256 against every packet file; excerpt
regeneration byte-for-byte against a fresh objdump run; every
excerpt instruction byte-for-byte against the raw binary
(objdump splits a few long instructions across two lines; the
parser accumulates those continuations); spot instructions
byte-for-byte against a fresh objdump run and the raw binary
(three random ones among them, seed 115: 0x5fd76aa, 0x5fd72f4,
0x5fd5084); the FDE ranges in frames.txt against a fresh frame
dump; the relocation set against a fresh relocation dump (186
records: the Env header, the CompositeEnv header + slots, the
wrapper header + slots, the Configurable header + slots 0-7,
the FactoryEntry node header + slots, the factory control-block
vtable, the MockEnv header + slot 0); the string literals
against the raw binary; census consistency (callers.tsv against
a fresh census run: every pinned routine's direct calls, tail
jumps, lea references, stored qwords and RELATIVE addends, and
the callers.tsv caller function against the smallest enclosing
FDE range from a fresh frame dump); the semantic records
(re-deriving the census entries, the relocation rows, the
reshipped excerpts, the forwarder forms, the vtable maps and
the model behaviour); and the model tests in
tests/test_composite_env_wrapper_115.py.
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
    ("builder-5fd7360.objdump.txt", 0x5FD7360, 0x5FD7466),
    ("install-5fceb20.objdump.txt", 0x5FCEB20, 0x5FCEBB7),
    ("string-init-5fd5cc0.objdump.txt", 0x5FD5CC0, 0x5FD5CD4),
    ("wrapper-d2-5fd72d0.objdump.txt", 0x5FD72D0, 0x5FD730B),
    ("wrapper-d0-5fd7510.objdump.txt", 0x5FD7510, 0x5FD7558),
    ("basedtor-5fcf4d0.objdump.txt", 0x5FCF4D0, 0x5FCF585),
    ("wslot5-5fd7560.objdump.txt", 0x5FD7560, 0x5FD76B1),
    ("wslot12-5fd5e00.objdump.txt", 0x5FD5E00, 0x5FD5F07),
    ("wslot14-5fd4e60.objdump.txt", 0x5FD4E60, 0x5FD4E6C),
    ("wslot16-5fd6240.objdump.txt", 0x5FD6240, 0x5FD6271),
    ("wslot17-5fd4e70.objdump.txt", 0x5FD4E70, 0x5FD4E79),
    ("holder-init-5fe2860.objdump.txt", 0x5FE2860, 0x5FE2C2F),
    ("node-slot2-5fcc7e0.objdump.txt", 0x5FCC7E0, 0x5FCC7EE),
    ("cb-dispose-6025950.objdump.txt", 0x6025950, 0x6025964),
    ("cb-destroy-6025b90.objdump.txt", 0x6025B90, 0x6025B9E),
    ("helper-5fcf390.objdump.txt", 0x5FCF390, 0x5FCF399),
    ("accessor-5fcf430.objdump.txt", 0x5FCF430, 0x5FCF439),
    ("invoker-composite-5fcf450.objdump.txt", 0x5FCF450, 0x5FCF4CB),
    ("append-6099ce0.objdump.txt", 0x6099CE0, 0x6099E34),
    ("grow-6099790.objdump.txt", 0x6099790, 0x6099CAD),
    ("fwd-45-5fd4e80.objdump.txt", 0x5FD4E80, 0x5FD4EC7),
    ("fwd-46-5fd4ed0.objdump.txt", 0x5FD4ED0, 0x5FD4EE1),
    ("fwd-47-5fd4ef0.objdump.txt", 0x5FD4EF0, 0x5FD4F01),
    ("fwd-48-5fd4f10.objdump.txt", 0x5FD4F10, 0x5FD4F21),
    ("fwd-49-5fd4f30.objdump.txt", 0x5FD4F30, 0x5FD4F41),
    ("fwd-50-5fd4f70.objdump.txt", 0x5FD4F70, 0x5FD4F81),
    ("fwd-51-5fd4f90.objdump.txt", 0x5FD4F90, 0x5FD4FA1),
    ("fwd-52-5fd4f50.objdump.txt", 0x5FD4F50, 0x5FD4F61),
    ("fwd-59-5fd4fb0.objdump.txt", 0x5FD4FB0, 0x5FD4FF7),
    ("fwd-63-5fd5000.objdump.txt", 0x5FD5000, 0x5FD5011),
    ("fwd-64-5fd5020.objdump.txt", 0x5FD5020, 0x5FD5031),
    ("fwd-65-5fd5040.objdump.txt", 0x5FD5040, 0x5FD508A),
    ("fwd-66-5fd5090.objdump.txt", 0x5FD5090, 0x5FD50A1),
    ("fwd-67-5fd50b0.objdump.txt", 0x5FD50B0, 0x5FD50C1),
    ("fwd-68-5fd50f0.objdump.txt", 0x5FD50F0, 0x5FD5137),
    ("fwd-69-5fd50d0.objdump.txt", 0x5FD50D0, 0x5FD50E1),
    ("fwd-71-5fd51d0.objdump.txt", 0x5FD51D0, 0x5FD5217),
    ("fwd-79-5fd5140.objdump.txt", 0x5FD5140, 0x5FD5187),
    ("fwd-80-5fd5190.objdump.txt", 0x5FD5190, 0x5FD51A1),
    ("fwd-81-5fd51b0.objdump.txt", 0x5FD51B0, 0x5FD51C1),
]

# (target, expected direct calls, expected tail jumps, expected leas)
EXPECTED_CENSUS = {
    0x5D35070: (654, 36, 0),
    0x5D350C0: (1273, 25, 0),
    0x5FCC7E0: (0, 0, 0),
    0x5FCEB20: (2, 0, 0),
    0x5FCF390: (14, 0, 0),
    0x5FCF430: (19, 0, 0),
    0x5FCF450: (0, 0, 1),
    0x5FCF4D0: (5, 3, 0),
    0x5FD4E60: (0, 0, 0),
    0x5FD4E70: (0, 0, 0),
    0x5FD4E80: (0, 0, 0),
    0x5FD4ED0: (0, 0, 0),
    0x5FD4EF0: (0, 0, 0),
    0x5FD4F10: (0, 0, 0),
    0x5FD4F30: (0, 0, 0),
    0x5FD4F50: (0, 0, 0),
    0x5FD4F70: (0, 0, 0),
    0x5FD4F90: (0, 0, 0),
    0x5FD4FB0: (0, 0, 0),
    0x5FD5000: (0, 0, 0),
    0x5FD5020: (0, 0, 0),
    0x5FD5040: (0, 0, 0),
    0x5FD5090: (0, 0, 0),
    0x5FD50B0: (0, 0, 0),
    0x5FD50D0: (0, 0, 0),
    0x5FD50F0: (0, 0, 0),
    0x5FD5140: (0, 0, 0),
    0x5FD5190: (0, 0, 0),
    0x5FD51B0: (0, 0, 0),
    0x5FD51D0: (0, 0, 0),
    0x5FD5CC0: (4, 0, 0),
    0x5FD5E00: (0, 0, 0),
    0x5FD6240: (0, 0, 0),
    0x5FD72D0: (0, 0, 0),
    0x5FD7360: (2, 0, 0),
    0x5FD7510: (0, 0, 0),
    0x5FD7560: (0, 0, 0),
    0x5FE2680: (189, 0, 0),
    0x5FE2860: (17, 0, 0),
    0x60029F0: (4, 0, 0),
    0x6025950: (0, 0, 0),
    0x6025B90: (0, 0, 0),
    0x60289F0: (1, 0, 0),
    0x60971C0: (8, 0, 0),
    0x6099790: (1, 0, 0),
    0x6099CE0: (37, 0, 0),
    0x61C21B0: (1, 0, 0),
    0x61D2CA0: (1, 0, 0),
}

# File offsets of 8-byte-aligned qwords equal to the target.
EXPECTED_QWORDS = {
    0x5FCC7E0: ['0x10fa68'],
    0x5FD4E60: ['0x110de8'],
    0x5FD4E70: ['0x110e30', '0x1187b0'],
    0x5FD4E80: ['0x1110d0', '0x118a50'],
    0x5FD4ED0: ['0x1110e8', '0x118a68'],
    0x5FD4EF0: ['0x111100', '0x118a80'],
    0x5FD4F10: ['0x111118', '0x118a98'],
    0x5FD4F30: ['0x111130', '0x118ab0'],
    0x5FD4F50: ['0x111178', '0x118af8'],
    0x5FD4F70: ['0x111148', '0x118ac8'],
    0x5FD4F90: ['0x111160', '0x118ae0'],
    0x5FD4FB0: ['0x111220', '0x118ba0'],
    0x5FD5000: ['0x111280', '0x118c00'],
    0x5FD5020: ['0x111298', '0x118c18'],
    0x5FD5040: ['0x1112b0', '0x118c30'],
    0x5FD5090: ['0x1112c8', '0x118c48'],
    0x5FD50B0: ['0x1112e0', '0x118c60'],
    0x5FD50D0: ['0x111310', '0x118c90'],
    0x5FD50F0: ['0x1112f8', '0x118c78'],
    0x5FD5140: ['0x111400', '0x118d80'],
    0x5FD5190: ['0x111418', '0x118d98'],
    0x5FD51B0: ['0x111430', '0x118db0'],
    0x5FD51D0: ['0x111340', '0x118cc0'],
    0x5FD5E00: ['0x110db8', '0x118738'],
    0x5FD6240: ['0x110e18', '0x118798'],
    0x5FD72D0: ['0x110c98'],
    0x5FD7510: ['0x110cb0'],
    0x5FD7560: ['0x110d10', '0x118690'],
    0x6025950: ['0x119f20'],
    0x6025B90: ['0x119f38'],
}

# Number of RELATIVE records whose addend is the target.
EXPECTED_RELATIVE = {
    0x5FCC7E0: 1,
    0x5FD4E60: 1,
    0x5FD4E70: 2,
    0x5FD4E80: 2,
    0x5FD4ED0: 2,
    0x5FD4EF0: 2,
    0x5FD4F10: 2,
    0x5FD4F30: 2,
    0x5FD4F50: 2,
    0x5FD4F70: 2,
    0x5FD4F90: 2,
    0x5FD4FB0: 2,
    0x5FD5000: 2,
    0x5FD5020: 2,
    0x5FD5040: 2,
    0x5FD5090: 2,
    0x5FD50B0: 2,
    0x5FD50D0: 2,
    0x5FD50F0: 2,
    0x5FD5140: 2,
    0x5FD5190: 2,
    0x5FD51B0: 2,
    0x5FD51D0: 2,
    0x5FD5E00: 2,
    0x5FD6240: 2,
    0x5FD72D0: 1,
    0x5FD7510: 1,
    0x5FD7560: 2,
    0x6025950: 1,
    0x6025B90: 1,
}

# The stored relocations.txt rows: (offset, addend).
EXPECTED_RELOCATIONS = [
    (0x64cdac8, 0x64cd8d0), (0x64cde60, 0x64cd9a0), (0x64cde68, 0x5fcc700), (0x64cde70, 0x5fcd840),
    (0x64cde78, 0x5fcc7e0), (0x64ce2d0, 0x64cdfa8), (0x64ce2e8, 0x609d760), (0x64ce2f0, 0x609dc40),
    (0x64ce2f8, 0x5d32560), (0x64ce300, 0x6095e70), (0x64ce308, 0x6096790), (0x64ce310, 0x5d2e090),
    (0x64ce318, 0x60956f0), (0x64ce320, 0x609d0e0), (0x64ce328, 0x60986b0), (0x64ce330, 0x6095710),
    (0x64ce338, 0x609de80), (0x64ce340, 0x609d980), (0x64ce348, 0x5fcc0d0), (0x64ce350, 0x5d32a30),
    (0x64ce358, 0x5d2e770), (0x64ce360, 0x5d2ca00), (0x64ce368, 0x5d2ca10), (0x64ce370, 0x5fd5a00),
    (0x64ce378, 0x5fd5a80), (0x64ce380, 0x5fdea30), (0x64ce388, 0x5fdedd0), (0x64ce390, 0x5fdf170),
    (0x64ce398, 0x5fdf520), (0x64ce3a0, 0x5fdf820), (0x64ce3a8, 0x5fdfb10), (0x64ce3b0, 0x5fd5980),
    (0x64ce3b8, 0x5fdfe00), (0x64ce3c0, 0x5fdafb0), (0x64ce3c8, 0x5fdad30), (0x64ce3d0, 0x5fdab30),
    (0x64ce3d8, 0x5fda8b0), (0x64ce3e0, 0x5fda6b0), (0x64ce3e8, 0x5fda430), (0x64ce3f0, 0x5fda1b0),
    (0x64ce3f8, 0x5fd9f30), (0x64ce400, 0x5fd9cb0), (0x64ce408, 0x5fd9a30), (0x64ce410, 0x5fd97b0),
    (0x64ce418, 0x5fd95b0), (0x64ce420, 0x5fd93b0), (0x64ce428, 0x5fd91c0), (0x64ce430, 0x5fd8f40),
    (0x64ce438, 0x5fd8cc0), (0x64ce440, 0x5fcce50), (0x64ce450, 0x5fcc120), (0x64ce460, 0x5fcc130),
    (0x64ce468, 0x5fcc140), (0x64ce470, 0x5fcc150), (0x64ce478, 0x5fcc160), (0x64ce480, 0x5fd8a40),
    (0x64ce488, 0x5fd8840), (0x64ce490, 0x5fd5bc0), (0x64ce498, 0x5fd4e20), (0x64ce4a0, 0x5fd4e40),
    (0x64ce4a8, 0x5fd5c40), (0x64ce4b8, 0x5fcd480), (0x64ce4c0, 0x5fd5f10), (0x64ce4c8, 0x5fd85c0),
    (0x64ce4e0, 0x5fccdd0), (0x64ce4f0, 0x5fcc1a0), (0x64ce4f8, 0x5fccd50), (0x64ce500, 0x5fcc1b0),
    (0x64ce508, 0x5fd6190), (0x64ce510, 0x5fccf90), (0x64ce518, 0x5fd7fc0), (0x64ce520, 0x5fd7e40),
    (0x64ce528, 0x5fd7cc0), (0x64ce530, 0x5fd7b40), (0x64ce538, 0x5fd79c0), (0x64ce540, 0x5fd7840),
    (0x64ce548, 0x5fd76c0), (0x64ce550, 0x5fcccd0), (0x64ce558, 0x5fcc1c0), (0x64ce560, 0x5fccf10),
    (0x64ce568, 0x5fd83c0), (0x64ce570, 0x5fd8140), (0x64ce578, 0x5fcc1d0), (0x64ce588, 0x64cdfc0),
    (0x64ce590, 0x5fd72d0), (0x64ce598, 0x5fd7510), (0x64ce5a0, 0x609d760), (0x64ce5a8, 0x609dc40),
    (0x64ce5b0, 0x5d32560), (0x64ce5b8, 0x5fd7560), (0x64ce5c0, 0x6096790), (0x64ce5c8, 0x5d2e090),
    (0x64ce5d0, 0x60956f0), (0x64ce5d8, 0x609d0e0), (0x64ce5e0, 0x60986b0), (0x64ce5e8, 0x6095710),
    (0x64ce5f0, 0x5fd5e00), (0x64ce5f8, 0x609d980), (0x64ce600, 0x5fd4e60), (0x64ce608, 0x5d32a30),
    (0x64ce610, 0x5fd6240), (0x64ce618, 0x5fd4e70), (0x64ce620, 0x5d2ca10), (0x64ce628, 0x5fd5a00),
    (0x64ce630, 0x5fd5a80), (0x64ce638, 0x5fdea30), (0x64ce640, 0x5fdedd0), (0x64ce648, 0x5fdf170),
    (0x64ce650, 0x5fdf520), (0x64ce658, 0x5fdf820), (0x64ce660, 0x5fdfb10), (0x64ce668, 0x5fd5980),
    (0x64ce670, 0x5fdfe00), (0x64ce678, 0x5fdafb0), (0x64ce680, 0x5fdad30), (0x64ce688, 0x5fdab30),
    (0x64ce690, 0x5fda8b0), (0x64ce698, 0x5fda6b0), (0x64ce6a0, 0x5fda430), (0x64ce6a8, 0x5fda1b0),
    (0x64ce6b0, 0x5fd9f30), (0x64ce6b8, 0x5fd9cb0), (0x64ce6c0, 0x5fd9a30), (0x64ce6c8, 0x5fd97b0),
    (0x64ce6d0, 0x5fd95b0), (0x64ce6d8, 0x5fd93b0), (0x64ce6e0, 0x5fd91c0), (0x64ce6e8, 0x5fd8f40),
    (0x64ce6f0, 0x5fd8cc0), (0x64ce6f8, 0x5fd4e80), (0x64ce700, 0x5fd4ed0), (0x64ce708, 0x5fd4ef0),
    (0x64ce710, 0x5fd4f10), (0x64ce718, 0x5fd4f30), (0x64ce720, 0x5fd4f70), (0x64ce728, 0x5fd4f90),
    (0x64ce730, 0x5fd4f50), (0x64ce738, 0x5fd8a40), (0x64ce740, 0x5fd8840), (0x64ce748, 0x5fd5bc0),
    (0x64ce750, 0x5fd4e20), (0x64ce758, 0x5fd4e40), (0x64ce760, 0x5fd5c40), (0x64ce768, 0x5fd4fb0),
    (0x64ce770, 0x5fcd480), (0x64ce778, 0x5fd5f10), (0x64ce780, 0x5fd85c0), (0x64ce788, 0x5fd5000),
    (0x64ce790, 0x5fd5020), (0x64ce798, 0x5fd5040), (0x64ce7a0, 0x5fd5090), (0x64ce7a8, 0x5fd50b0),
    (0x64ce7b0, 0x5fd50f0), (0x64ce7b8, 0x5fd50d0), (0x64ce7c0, 0x5fd6190), (0x64ce7c8, 0x5fd51d0),
    (0x64ce7d0, 0x5fd7fc0), (0x64ce7d8, 0x5fd7e40), (0x64ce7e0, 0x5fd7cc0), (0x64ce7e8, 0x5fd7b40),
    (0x64ce7f0, 0x5fd79c0), (0x64ce7f8, 0x5fd7840), (0x64ce800, 0x5fd76c0), (0x64ce808, 0x5fd5140),
    (0x64ce810, 0x5fd5190), (0x64ce818, 0x5fd51b0), (0x64ce820, 0x5fd83c0), (0x64ce828, 0x5fd8140),
    (0x64ce830, 0x5fcc1d0), (0x64d1390, 0x64d1228), (0x64d1398, 0x6028f90), (0x64d1c30, 0x64d1358),
    (0x64d1c38, 0x6025910), (0x64d1c40, 0x6025a70), (0x64d1c48, 0x6025950), (0x64d1c50, 0x6025b90),
    (0x64d1c58, 0x6026070), (0x64d3428, 0x64d3410), (0x64d3430, 0x60957a0), (0x64d3438, 0x6095830),
    (0x64d3440, 0x6099030), (0x64d3448, 0x60996a0), (0x64d3450, 0x5d32560), (0x64d3458, 0x6095e70),
    (0x64d3460, 0x6096790), (0x64d3468, 0x60958c0),
]

SPOT_BYTES = {
    0x5FD7360: bytes.fromhex("f30f1efa"),
    0x5FCEB20: bytes.fromhex("f30f1efa"),
    0x5FE2860: bytes.fromhex("f30f1efa"),
    0x5FD72D0: bytes.fromhex("f30f1efa"),
    0x5FCF4D0: bytes.fromhex("f30f1efa"),
    0x5FD7560: bytes.fromhex("f30f1efa"),
    0x5FD5E00: bytes.fromhex("f30f1efa"),
    0x5FD75AF: bytes.fromhex("e8bce80b00"),
    0x5FD7306: bytes.fromhex("e9c581ffff"),
    0x5FD4EDB: bytes.fromhex("ffa070010000"),
    0x5FCC7EB: bytes.fromhex("ff6010"),
    0x6025962: bytes.fromhex("ffe0"),
    0x6025B99: bytes.fromhex("e9e2b13c00"),
    0x5D350C4: bytes.fromhex("48b80100000001000000"),
    0x5D3507B: bytes.fromhex("ff5010"),
    0x5FD5CC0: bytes.fromhex("488d4710"),
    0x5FCF430: bytes.fromhex("f30f1efa"),
    0x5FCF390: bytes.fromhex("f30f1efa"),
    0x5FD6244: bytes.fromhex("48837e080c"),
    0x5FD4E64: bytes.fromhex("488d05f79846fa"),
    # Seeded-random gate spots (seed 115).
    0x5FD76AA: bytes.fromhex("ebcb"),
    0x5FD72F4: bytes.fromhex("488d05cd6f4f00"),
    0x5FD5084: bytes.fromhex("c3"),
}
TAB = chr(9)
LINE_RE = re.compile("^ *([0-9a-f]+):" + TAB + "([0-9a-f ]+?)" + TAB + "(.*)$")
CONT_RE = re.compile("^ *([0-9a-f]+):" + TAB + "([0-9a-f ]+?) *$")
DISPATCH_RE = re.compile(r"(jmp|call)\s+\*0x([0-9a-f]+)\(%rax\)")


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
        if raw != expect:
            fail("spot %#x: %s != %s" % (addr, raw.hex(), expect.hex()))
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
            if not line.strip() or line.startswith("start"):
                continue
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
    if len(stored) != len(EXPECTED_RELOCATIONS):
        fail("relocation count %d != %d"
             % (len(stored), len(EXPECTED_RELOCATIONS)))
    if sorted(stored) != sorted(EXPECTED_RELOCATIONS):
        fail("stored relocation set mismatch")
    for target, count in EXPECTED_RELATIVE.items():
        got = [o for o, a in relocs.items() if a == target]
        if len(got) != count:
            fail("RELATIVE count for %#x: %d != %d"
                 % (target, len(got), count))
    print("relocations ok (%d records)" % len(stored))


def check_literals(segments, data, records):
    for lit in records["literals"]:
        addr = lit["addr"]
        off = va_to_off(segments, addr)
        if off is None:
            fail("literal %#x: no file offset" % addr)
        if off != lit["offset"]:
            fail("literal %#x offset %#x != %#x" % (addr, off, lit["offset"]))
        if lit["text"].startswith("<"):
            if addr == 0x459B20:
                want = struct.pack("<Q", 0x100000001)
            elif addr == 0x459E78:
                want = struct.pack("<f", 1.0)
            else:
                fail("unknown special literal %#x" % addr)
        else:
            want = lit["text"].encode() + b"\x00"
        if data[off:off + len(want)] != want:
            fail("literal %#x mismatch" % addr)
    print("literals ok (%d)" % len(records["literals"]))


def check_census():
    spec = importlib.util.spec_from_file_location(
        "packet_census", PACKET / "census.py")
    census = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(census)
    data = BINARY.read_bytes()
    sites = census.disassembly_sites()
    relocs, _lines = census.relative_records()
    ranges = census.frame_ranges()
    ordered = sorted(ranges)
    starts = [a for a, _b in ordered]
    for target, (want_calls, want_jumps, want_leas) in EXPECTED_CENSUS.items():
        calls, jumps = census.scan(sites, target)
        leas = sites.get(target, ([], [], []))[2]
        if (len(calls), len(jumps), len(leas)) != (want_calls, want_jumps, want_leas):
            fail("census for %#x: calls=%d jumps=%d leas=%d, want %d/%d/%d"
                 % (target, len(calls), len(jumps), len(leas),
                    want_calls, want_jumps, want_leas))
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
        want = census.enclosing_fde(ordered, starts, int(site, 16))
        if caller != want:
            fail("callers.tsv caller for %s: %s != %s"
                 % (site, caller, want))
    expect_rows = []
    for target in sorted(EXPECTED_CENSUS):
        calls, jumps = census.scan(sites, target)
        leas = sites.get(target, ([], [], []))[2]
        for site in calls:
            expect_rows.append((site, target, "call"))
        for site in jumps:
            expect_rows.append((site, target, "tail jump"))
        for site in leas:
            expect_rows.append((site, target, "lea"))
    expect_rows.sort()
    got_rows = sorted((s, t, k) for s, t, _c, k in rows)
    if got_rows != expect_rows:
        fail("callers.tsv rows do not match a fresh census run")
    print("census ok (%d rows)" % len(rows))


def check_records(segments, data, records):
    spec = importlib.util.spec_from_file_location(
        "packet_census_rel", PACKET / "census.py")
    census_mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(census_mod)
    full_relocs, _lines = census_mod.relative_records()
    sites = census_mod.disassembly_sites()

    # Census entries re-derive from a fresh run.
    for key, entry in records["census"]["targets"].items():
        target = int(key, 16)
        if target not in EXPECTED_CENSUS:
            fail("records census has an unexpected target %#x" % target)
        want = EXPECTED_CENSUS[target]
        if (entry["calls"], entry["jumps"], entry["leas"]) != want:
            fail("records census for %#x: %s != %s"
                 % (target, (entry["calls"], entry["jumps"], entry["leas"]),
                    want))
        if entry["qwords"] != len(EXPECTED_QWORDS.get(target, [])):
            fail("records qword count for %#x: %d != %d"
                 % (target, entry["qwords"],
                    len(EXPECTED_QWORDS.get(target, []))))
        if entry["relative"] != EXPECTED_RELATIVE.get(target, 0):
            fail("records RELATIVE count for %#x: %d != %d"
                 % (target, entry["relative"],
                    EXPECTED_RELATIVE.get(target, 0)))
    if len(records["census"]["targets"]) != len(EXPECTED_CENSUS):
        fail("records census target count mismatch")
    if records["census"]["relocation_records"] != 186:
        fail("records relocation total != 186")
    if records["census"]["callers_tsv_rows"] != 2297:
        fail("records callers.tsv row count != 2297")
    if records["test_checks"] != 246:
        fail("records test_checks != 246")
    if records["target"]["sha256"] != DIGEST:
        fail("records target digest mismatch")

    # The relocation rows re-derive from a fresh readelf dump.
    for row in records["relocations"]:
        if full_relocs.get(row["offset"]) != row["addend"]:
            fail("records relocation %#x not in a fresh dump"
                 % row["offset"])
    if sorted((r["offset"], r["addend"]) for r in records["relocations"]) \
            != sorted(EXPECTED_RELOCATIONS):
        fail("records relocation set mismatch")

    # The re-shipped excerpts match their pinned SHA-256 values.
    for entry in records["reshipped"]:
        local = hashlib.sha256(
            (PACKET / entry["file"]).read_bytes()).hexdigest()
        if local != entry["sha256"]:
            fail("reshipped excerpt %s hash mismatch" % entry["file"])

    # Builder/install/string-init/holder callers re-derive.
    def call_sites(target):
        return ["%#x" % s for s in
                census_mod.scan(sites, target)[0]]

    if call_sites(0x5FD7360) != ["0x5fcf495", "0x60289f8"]:
        fail("builder caller mismatch")
    if call_sites(0x5FCEB20) != ["0x5fd7388", "0x5fe2900"]:
        fail("install caller mismatch")
    if call_sites(0x5FD5CC0) != ["0x5fd5e63", "0x5fd73c3", "0x5fd73e2",
                                 "0x5fd7408"]:
        fail("string-init caller mismatch")
    if call_sites(0x5FE2860) != records["holder_init"]["callers"]:
        fail("holder-init caller mismatch")
    if call_sites(0x6099CE0)[:3] != ["0x5fd0124", "0x5fd73cb", "0x5fd73f1"]:
        fail("append builder-site order mismatch")
    if "0x5fd7417" not in call_sites(0x6099CE0):
        fail("append third builder site missing")

    # Base D2 reachability re-derives from the fresh census.
    base_d2 = [d for d in records["destructors"]
               if d["addr"] == 0x5FCF4D0][0]
    got_calls = sorted(call_sites(0x5FCF4D0))
    want_calls = sorted(c.split()[0] for c in base_d2["reached_by"]["calls"])
    if got_calls != want_calls:
        fail("base D2 call sites mismatch: %s != %s"
             % (got_calls, want_calls))
    got_jumps = sorted("%#x" % s for s in
                       census_mod.scan(sites, 0x5FCF4D0)[1])
    want_jumps = sorted(j.split()[0]
                        for j in base_d2["reached_by"]["tail_jumps"])
    if got_jumps != want_jumps:
        fail("base D2 tail-jump sites mismatch")

    # The invoker lea site re-derives.
    leas = sites.get(0x5FCF450, ([], [], []))[2]
    if ["%#x" % l for l in leas] != records["invoker"]["lea_sites"]:
        fail("invoker lea sites mismatch")

    # Forwarder forms: each excerpt must contain the right receiver
    # load and the dispatch to wrapped->vtable[slot*8].
    for fwd in records["forwarders"]:
        name = "fwd-%d-%x.objdump.txt" % (fwd["slot"], fwd["addr"])
        text = (PACKET / name).read_text()
        if fwd["form"] == "jmp":
            if "0x48(%rdi),%rdi" not in text:
                fail("forwarder slot %d must load this+0x48"
                     % fwd["slot"])
        else:
            if "0x48(%rsi),%rsi" not in text:
                fail("forwarder slot %d must load arg+0x48"
                     % fwd["slot"])
        m = DISPATCH_RE.search(text)
        if not m or m.group(1) != fwd["form"]:
            fail("forwarder slot %d dispatch form mismatch" % fwd["slot"])
        if int(m.group(2), 16) != fwd["slot"] * 8:
            fail("forwarder slot %d dispatch offset mismatch" % fwd["slot"])
        if fwd["target_offset"] != hex(fwd["slot"] * 8):
            fail("forwarder slot %d target offset mismatch" % fwd["slot"])
    if len(records["forwarders"]) != 20:
        fail("forwarder count != 20")

    # Vtable maps re-derive from a fresh readelf dump.
    def vtable_map(base, nslots):
        return ["0x%x" % full_relocs.get(base + i * 8, 0)
                for i in range(nslots)]

    vt = records["vtables"]
    for name, base, nslots in (
            ("Env", 0x64CDAD0, 85), ("CompositeEnv", 0x64CE2D8, 85),
            ("CompositeEnvWrapper", 0x64CE590, 85),
            ("MockEnv", 0x64D1398, 85),
            ("Configurable", 0x64D3430, 8),
            ("FactoryEntryNode", 0x64CDE68, 3)):
        if vtable_map(base, nslots) != vt[name]["slots"]:
            fail("%s vtable map mismatch" % name)
    if [i for i, v in enumerate(vt["Env"]["slots"]) if v == "0x0"] \
            != vt["Env"]["null_slots"]:
        fail("Env null slots mismatch")
    if [i for i, v in enumerate(vt["CompositeEnv"]["slots"])
            if v == "0x0"] != vt["CompositeEnv"]["null_slots"]:
        fail("CompositeEnv null slots mismatch")
    diffs = vt["diffs"]
    if diffs["composite_env_vs_wrapper"] != \
            [0, 1, 5, 12, 14, 16, 17, 45, 46, 47, 48, 49, 50, 51, 52,
             59, 63, 64, 65, 66, 67, 68, 69, 71, 79, 80, 81]:
        fail("composite_env_vs_wrapper diff mismatch")
    if diffs["wrapper_vs_mock_env"] != [0, 1, 14]:
        fail("wrapper_vs_mock_env diff mismatch")
    if vt["CompositeEnvWrapper"]["slots"][61] != "0x5fd5f10":
        fail("slot 61 must be 0x5fd5f10 in the wrapper")
    if vt["Env"]["slots"][61] != "0x0":
        fail("slot 61 must be null in Env")
    # Control-block slots re-derive.
    cb = records["control_block"]
    if [s["addr"] for s in cb["slots"]] != \
            [0x6025910, 0x6025A70, 0x6025950, 0x6025B90, 0x6026070]:
        fail("control-block slot mismatch")
    if cb["typeinfo"] != ("St23_Sp_counted_ptr_inplace"
                          "IN7rocksdb19EmulatedSystemClockESaIvE"
                          "LN9__gnu_cxx12_Lock_policyE2EE"):
        fail("control-block typeinfo mismatch")

    # Excerpt needles for the pinned semantics.
    def excerpt(name):
        return (PACKET / name).read_text()

    builder = excerpt("builder-5fd7360.objdump.txt")
    for needle in ("call   5fceb20", "# 6504c60", "# 6504c20",
                   "# 6504be0"):
        if needle not in builder:
            fail("builder line missing: %s" % needle)
    if builder.count("call   6099ce0") != 3:
        fail("builder must append three records")
    install = excerpt("install-5fceb20.objdump.txt")
    for needle in ("# 64cdac0", "lock addl", "addl   $0x1,0x8(%rax)"):
        if needle not in install:
            fail("install line missing: %s" % needle)
    slot5 = excerpt("wslot5-5fd7560.objdump.txt")
    for needle in ("call   6095e70", "call   5fcf390", "call   5fcf430",
                   "call   5fe2860"):
        if needle not in slot5:
            fail("slot 5 line missing: %s" % needle)
    slot12 = excerpt("wslot12-5fd5e00.objdump.txt")
    for needle in ("call   609de80", "call   60971c0", "call   5fe2860",
                   "# 4496d1"):
        if needle not in slot12:
            fail("slot 12 line missing: %s" % needle)
    slot14 = excerpt("wslot14-5fd4e60.objdump.txt")
    if "# 43e762" not in slot14:
        fail("slot 14 must lea the CompositeEnv string")
    slot16 = excerpt("wslot16-5fd6240.objdump.txt")
    for needle in ("0x7469736f706d6f43", "0x766e4565", "jmp    5d2e770"):
        if needle not in slot16:
            fail("slot 16 line missing: %s" % needle)
    slot17 = excerpt("wslot17-5fd4e70.objdump.txt")
    if "mov    0x48(%rdi),%rax" not in slot17:
        fail("slot 17 must return this+0x48")
    holder = excerpt("holder-init-5fe2860.objdump.txt")
    for needle in ("call   61d2ca0", "call   61c21b0", "call   5fe2680",
                   "call   60029f0", "call   5fceb20", "call   5d35070",
                   "# 6504ca8", "# 4429a3", "# 459e78"):
        if needle not in holder:
            fail("holder-init line missing: %s" % needle)
    node2 = excerpt("node-slot2-5fcc7e0.objdump.txt")
    if "jmp    *0x10(%rax)" not in node2:
        fail("node slot 2 must forward slot 2")
    dispose = excerpt("cb-dispose-6025950.objdump.txt")
    if "jmp    *%rax" not in dispose:
        fail("cb dispose must tail-jump to the managed D2")
    destroy = excerpt("cb-destroy-6025b90.objdump.txt")
    if "mov    $0x60,%esi" not in destroy:
        fail("cb destroy must delete 0x60 bytes")
    # The append calls grow at capacity.
    append = excerpt("append-6099ce0.objdump.txt")
    if "call   6099790" not in append:
        fail("append must call grow at capacity")
    # The shared_ptr release counts.
    if records["shared_ptr_release"]["calls"] != 1273:
        fail("_M_release call count mismatch")
    if records["shared_ptr_release"]["jumps"] != 25:
        fail("_M_release jump count mismatch")
    if records["shared_ptr_release"]["tail_calls"] != 654:
        fail("dispose-tail call count mismatch")
    if records["shared_ptr_release"]["tail_jumps"] != 36:
        fail("dispose-tail jump count mismatch")

    # The model constants and behaviour.
    sys.path.insert(0, str(ROOT / "tools"))
    import composite_env_wrapper_115 as model
    if model.WRAPPER_VTABLE != 0x64CE590:
        fail("model wrapper vtable mismatch")
    if model.COMPOSITE_ENV_VTABLE != 0x64CE2D8:
        fail("model CompositeEnv vtable mismatch")
    if model.ENV_VTABLE != 0x64CDAD0:
        fail("model Env vtable mismatch")
    if model.FRESH_COUNTS != 0x100000001:
        fail("model fresh counts mismatch")
    if len(model.FORWARDERS) != 20:
        fail("model forwarder count mismatch")
    if sorted(model.FORWARDERS) != sorted(f["slot"] for f in
                                           records["forwarders"]):
        fail("model forwarder slots mismatch")
    for fwd in records["forwarders"]:
        if model.FORWARDERS[fwd["slot"]] != (fwd["addr"], fwd["form"]):
            fail("model forwarder slot %d mismatch" % fwd["slot"])
    ctrl = model.ControlBlock(use=1, weak=1)
    if model.dispose_tail(ctrl) != ["dispose", "weak--", "destroy"]:
        fail("model dispose tail mismatch")
    sp = model.SharedPtr("x", model.ControlBlock(use=1, weak=1))
    if sp.release() != ["dispose", "destroy"]:
        fail("model fast-path release mismatch")
    wrapped = model.Env()
    w = model.CompositeEnvWrapper.builder(
        wrapped, model.SharedPtr("a", model.ControlBlock(1, 1)),
        model.SharedPtr("b", model.ControlBlock(1, 1)))
    if len(w.options.records) != 3:
        fail("model builder record mismatch")
    if [r["ptr2"] for r in w.options.records] != list(model.RECORD_GLOBALS):
        fail("model builder record globals mismatch")
    if "vector-destroy:3" not in w.dtor_d2():
        fail("model wrapper D2 mismatch")
    if w.name() != "CompositeEnv" or w.is_instance_of("CompositeEnv") != 1:
        fail("model slot 14/16 mismatch")
    if w.wrapped_env() is not wrapped:
        fail("model slot 17 mismatch")
    holder_obj = model.DefaultHolder()
    holder_obj.initialize(model.SharedPtr("c", model.ControlBlock(1, 1)),
                          model.SharedPtr("f", model.ControlBlock(1, 1)))
    if len(holder_obj.tsu.field_map()) != 9:
        fail("model TSU field map mismatch")
    print("records ok (census, relocations, reshipped, builder, "
          "install, slots, forwarders, vtables, excerpts, model)")


def check_model_tests():
    out = subprocess.run(
        [sys.executable, "tests/test_composite_env_wrapper_115.py"],
        capture_output=True, text=True, cwd=ROOT)
    if out.returncode != 0 or "ALL CHECKS PASSED (246 checks)" not in out.stdout:
        fail("model tests failed:\n%s\n%s" % (out.stdout, out.stderr))
    print("model tests ok (246 checks)")


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
