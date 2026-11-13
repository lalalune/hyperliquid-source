#!/usr/bin/env python3
"""Verify the node #115 latency-EMA projection packet against the pinned artifact.

Standard library only. Reads bytes; the target is never loaded, executed or
emulated. Every retained instruction row, call edge, relocation, literal and
source-location record is re-derived from the authenticated ELF.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
PACKET = Path(__file__).resolve().parent
TARGET = ROOT / "artifacts/node/115/hl-node"
TARGET_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

sys.path.insert(0, str(ROOT / "tools"))
from elf_index import unwind_index  # noqa: E402
from fde_extents import eh_frame_records  # noqa: E402

# role -> (FDE start, FDE end, instruction count, SHA-256 of the body bytes)
WINDOWS = {
    "row-closure": (0x5A327A0, 0x5A329D8, 145, "5ac7705ebb0b56235f4a8c6e917008ba38561e6bbc253cbfaceb912f1ddccf56"),
    "collector": (0x5B80EA0, 0x5B810CE, 126, "f0a310a1839d5c816c6a82f1266d4901eb1daf28c9e4c2ad781ea90db594dcbc"),
    "sort-build": (0x4D55B50, 0x4D55CB2, 85, "9cd4e38f4730af80b023a772d417621036f7a495433e2ad4c41ee7685cabecd9"),
    "entry": (0x5A71D90, 0x5A71E1D, 35, "9cbb57aae7bc74ecb4e00225028d1b3b3c4ca2129974a47feea3b608c47e1121"),
}

# Instruction anchors: address -> exact bytes. Each one carries a fact used in README.md.
ANCHORS = {
    # row closure: container word 0 is tested for the 0x8000000000000000 sentinel
    0x5A327B4: "488b06",          # mov rax, [rsi]
    0x5A327B7: "4c8b38",          # mov r15, [rax]
    0x5A327BA: "498b1f",          # mov rbx, [r15]
    0x5A327C0: "48f7d8",          # neg rax
    0x5A327C3: "0f81c2000000",    # jno -> ordinary (ring) arm
    # tree arm
    0x5A327C9: "498b4708",        # root = [r15+8]
    0x5A327D0: "0f84d1010000",    # null root -> None
    0x5A327DB: "498b4f10",        # height = [r15+0x10]
    0x5A327EB: "488db080040000",  # keys at node+0x480
    0x5A327F2: "0fb7885e050000",  # u16 count at node+0x55e
    0x5A327FE: "488d58a0",        # value cursor = node-0x60
    0x5A32807: "8d048d00000000",  # count*4
    0x5A3280E: "4c8d3c80",        # *5 -> count*0x14 key bytes
    0x5A32825: "4c8d6e14",        # next key = key+0x14
    0x5A32829: "ba14000000",      # memcmp length 0x14
    0x5A32831: "ffd5",            # call rbp (memcmp slot value)
    0x5A32840: "4883c368",        # value stride 0x68
    0x5A3284E: "3c01",            # search key greater -> next key
    0x5A32857: "7476",            # equal -> found
    0x5A3286A: "4883e901",        # height -= 1
    0x5A32873: "0f8229010000",    # height underflow -> None
    0x5A3287E: "4a8b84e060050000",  # child = [node + idx*8 + 0x560]
    # ordinary arm
    0x5A32898: "a801",            # helper bit 0 set -> None
    0x5A328A0: "493b5718",        # index >= [r15+0x18] -> None
    0x5A328AF: "49035710",        # + head [r15+0x10]
    0x5A328B5: "4839da",          # compare with capacity (word 0)
    0x5A328B8: "480f43c3",        # cmovae: subtract capacity once
    0x5A328C3: "48c1e207",        # element stride 0x80
    0x5A328CB: "4883c318",        # value = element+0x18
    # ratio
    0x5A328CF: "f20f104b18",      # denom = f64 [value+0x18]
    0x5A328D4: "660f57c0",        # +0.0
    0x5A328D8: "660f2ec8",        # ucomisd denom, 0
    0x5A328DC: "7502",            # jne
    0x5A328DE: "7b13",            # jnp -> ordered zero: ratio +0.0, numerator unread
    0x5A328E0: "660f2ec8",
    0x5A328E4: "0f86d5000000",    # jbe -> assertion path (negative or NaN)
    0x5A328EA: "f20f104310",      # num = f64 [value+0x10]
    0x5A328EF: "f20f5ec1",        # divsd num, denom
    # sanitisation network
    0x5A328F3: "66480f7ec1",
    0x5A328F8: "48b8ffffffffffffff7f",
    0x5A32905: "48ba000000000000f0ff",
    0x5A32912: "48c1ea35",
    0x5A32916: "660f57c9",
    0x5A3291D: "7832",
    0x5A32926: "81faff030000",
    0x5A32931: "732e",
    0x5A32933: "48baffffffffffff0f00",
    0x5A32944: "7232",
    0x5A32946: "660f28d1",
    0x5A3294D: "752e",
    0x5A3294F: "eb30",
    0x5A32954: "81faff030000",
    0x5A3295F: "72d2",
    0x5A32961: "660f57c9",
    0x5A32965: "48baffffffffffff0f00",
    0x5A32976: "73ce",
    0x5A3297B: "7404",
    0x5A3297D: "660f28c2",
    # output row
    0x5A32981: "418b4610",        # key bytes 16..19
    0x5A32985: "4189442418",      # -> out+0x18
    0x5A3298A: "410f100e",        # key bytes 0..15
    0x5A3298E: "410f114c2408",    # -> out+8
    0x5A32994: "f2410f11442420",  # ratio -> out+0x20
    0x5A3299B: "b901000000",      # tag 1
    0x5A329A7: "31c9",            # tag 0
    0x5A329A9: "49890c24",        # tag -> out+0
    # assertion
    0x5A329BF: "488d3dfe43a3fa",
    0x5A329C6: "488d156bb29c00",
    0x5A329CD: "be21000000",
    0x5A329D2: "ff1558cdaa00",
    # collector
    0x5B80EB7: "488d4648",        # closure environment = &state[0x48]
    0x5B80EEE: "807c242000",      # tag byte test
    0x5B80F02: "48c70300000000",  # empty: cap 0
    0x5B80F09: "48c7430808000000",  # ptr 8
    0x5B80F11: "48c7431000000000",  # len 0
    0x5B80F1E: "0f10442428",      # row = result+8, 32 bytes
    0x5B80F23: "0f104c2438",
    0x5B80F35: "bf80000000",      # first allocation 0x80 bytes
    0x5B80F60: "48c7042404000000",  # capacity 4
    0x5B80F6D: "48c744241001000000",  # length 1
    0x5B80FEF: "80bc24b000000000",
    0x5B81018: "4c3b3c24",        # len == cap
    0x5B8101E: "ba01000000",      # grow by 1
    0x5B81023: "b908000000",      # align 8
    0x5B81028: "41b820000000",    # element size 0x20
    0x5B81041: "48c1e005",        # index * 0x20
    0x5B81060: "49ffc7",          # len += 1
    # sort-build
    0x4D55BA9: "4883fe02",        # len < 2 skips ordering
    0x4D55C4A: "4883fe15",        # len < 0x15 small path
    0x4D55C55: "ba01000000",
    0x4D55BCC: "4883fa40",        # len <= 0x40 small container
    0x4D55BD2: "48c1e205",        # end = ptr + len*0x20
    0x4D55BFB: "48b80000000000000080",  # large container sentinel
    0x4D55C05: "488903",
    0x4D55C27: "31f6",
    # entry
    0x5A71DB2: "488db348010000",  # container = arg0+0x148
    0x5A71DEE: "4889742450",      # -> iterator state +0x48
}

DIRECT_CALLS = {
    0x5A32891: 0x57F8090,
    0x5B80EC6: 0x5138730,
    0x5B80EE9: 0x5A327A0,
    0x5B80EF8: 0x5138730,
    0x5B80FD3: 0x5138730,
    0x5B80FEA: 0x5A327A0,
    0x5B81034: 0x5963A10,
    0x4D55B90: 0x5B80EA0,
    0x4D55BB8: 0x5B2E730,
    0x4D55BF6: 0x5168480,
    0x4D55C29: 0x5806A40,
    0x4D55C5D: 0x53E5360,
    0x5A71E00: 0x4D55B50,
    0x5A71E10: 0x4E3DFB0,
}

# Direct calls into .plt: site -> (stub, .got.plt slot, JUMP_SLOT symbol)
PLT_CALLS = {
    0x5B810C9: (0x63F0A50, 0x64EE178, "_Unwind_Resume"),
    0x4D55CAD: (0x63F0A50, 0x64EE178, "_Unwind_Resume"),
}
R_X86_64_JUMP_SLOT = 7

# RIP-relative instruction -> referenced address
RIP_REFERENCES = {
    0x5A327E4: 0x64DFB50,
    0x5A329BF: 0x466DC4,
    0x5A329C6: 0x63FDC38,
    0x5A329D2: 0x64DF730,
    0x5B80F3A: 0x64DF480,
    0x5B810A1: 0x64DF498,
    0x5B810C0: 0x64DF4A0,
    0x4D55C6F: 0x64EB270,
    0x4D55CA4: 0x64DF4A0,
}

R_X86_64_GLOB_DAT = 6
R_X86_64_RELATIVE = 8
RELATIVE_SLOTS = {
    0x64DF730: 0x1680E60,
    0x64DF480: 0x6355830,
    0x64DF498: 0x141E264,
    0x64DF4A0: 0x635DE30,
    0x64EB270: 0x4F41090,
    0x64E8718: 0x5A71D90,
    0x63FDC38: 0x443C4F,
}
IMPORT_SLOT = (0x64DFB50, "memcmp")
ASSERT_LITERAL = (0x466DC4, b"assertion failed: self.denom > 0.")
LOCATION = (0x63FDC38, b"base/src/ema_tracker.rs", 58, 13)
LOCATION_LEA_SITES = {0x5A305C8, 0x5A329C6}
DIRECT_CALLERS = {
    0x5A327A0: {0x5B80EE9, 0x5B80FEA},
    0x5B80EA0: {0x4D55B90},
    0x4D55B50: {0x5A71E00},
    0x5A71D90: set(),
}

MASK64 = (1 << 64) - 1


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def section(sections: list[dict], name: str) -> dict:
    return next(row for row in sections if row["name"] == name)


def read(data: bytes, sections: list[dict], name: str, address: int, size: int) -> bytes:
    row = section(sections, name)
    displacement = address - row["address"]
    require(0 <= displacement <= displacement + size <= row["size"], f"{address:#x} outside {name}")
    return data[row["offset"] + displacement:row["offset"] + displacement + size]


def packet_rows() -> list[dict[str, str]]:
    with (PACKET / "instructions.tsv").open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle, delimiter="\t"))


def validate_rows(data: bytes, sections: list[dict], fdes: list[dict],
                  rows: list[dict[str, str]]) -> tuple[dict[int, bytes], dict[str, str]]:
    extents = {(row["start"], row["end"]) for row in fdes}
    spans: dict[int, bytes] = {}
    cursors = {role: start for role, (start, _, _, _) in WINDOWS.items()}
    counts = {role: 0 for role in WINDOWS}
    for row in rows:
        role = row["role"]
        require(role in WINDOWS, f"unknown role {role}")
        start, end, _, _ = WINDOWS[role]
        require((int(row["fde_start"], 16), int(row["fde_end"], 16)) == (start, end), f"row extent differs for {role}")
        require((start, end) in extents, f"{start:#x}..{end:#x} is not an FDE extent")
        address = int(row["va"], 16)
        raw = bytes.fromhex(row["bytes"])
        require(raw, f"empty instruction at {address:#x}")
        require(address == cursors[role], f"row at {address:#x} is not contiguous in {role}")
        require(read(data, sections, ".text", address, len(raw)) == raw, f"instruction bytes differ at {address:#x}")
        cursors[role] = address + len(raw)
        counts[role] += 1
        spans[address] = raw
    digests = {}
    for role, (start, end, expected_count, expected_digest) in WINDOWS.items():
        require(cursors[role] == end, f"{role} rows stop at {cursors[role]:#x}, not {end:#x}")
        require(counts[role] == expected_count, f"{role} has {counts[role]} rows, expected {expected_count}")
        digests[role] = hashlib.sha256(read(data, sections, ".text", start, end - start)).hexdigest()
        require(digests[role] == expected_digest, f"{role} body digest differs")
    for address, raw_hex in ANCHORS.items():
        require(spans.get(address) == bytes.fromhex(raw_hex), f"anchor instruction differs at {address:#x}")
    return spans, digests


def rel32_target(address: int, raw: bytes) -> int:
    return address + len(raw) + struct.unpack_from("<i", raw, len(raw) - 4)[0]


def rip_reference(address: int, raw: bytes) -> int:
    """Target of a RIP-relative operand whose disp32 is last or followed by no immediate."""
    return rel32_target(address, raw)


def validate_edges(spans: dict[int, bytes], fdes: list[dict]) -> None:
    starts = {row["start"] for row in fdes}
    for site, target in DIRECT_CALLS.items():
        raw = spans.get(site)
        require(raw is not None and raw[0] == 0xE8 and len(raw) == 5, f"no direct call at {site:#x}")
        require(rel32_target(site, raw) == target, f"direct call target differs at {site:#x}")
        require(target in starts, f"call target {target:#x} is not an FDE start")
    for site, target in RIP_REFERENCES.items():
        raw = spans.get(site)
        require(raw is not None, f"no instruction at {site:#x}")
        require(rip_reference(site, raw) == target, f"RIP reference differs at {site:#x}")


def symbol_name(data: bytes, sections: list[dict], index: int) -> tuple[str, int, int]:
    dynsym, dynstr = section(sections, ".dynsym"), section(sections, ".dynstr")
    name_offset, _, _, shndx, value, _ = struct.unpack_from("<IBBHQQ", data, dynsym["offset"] + index * 24)
    strings = data[dynstr["offset"]:dynstr["offset"] + dynstr["size"]]
    return strings[name_offset:strings.index(b"\0", name_offset)].decode(), shndx, value


def validate_plt_calls(data: bytes, sections: list[dict], spans: dict[int, bytes]) -> None:
    plt = section(sections, ".rela.plt")
    slots = {slot: info for slot, info, _ in
             struct.iter_unpack("<QQq", data[plt["offset"]:plt["offset"] + plt["size"]])}
    for site, (stub, slot, name) in PLT_CALLS.items():
        raw = spans.get(site)
        require(raw is not None and raw[0] == 0xE8 and rel32_target(site, raw) == stub, f"no PLT call at {site:#x}")
        jump = read(data, sections, ".plt", stub, 6)
        require(jump[:2] == b"\xff\x25" and rel32_target(stub, jump) == slot, f"PLT stub {stub:#x} differs")
        info = slots.get(slot)
        require(info is not None and info & 0xFFFFFFFF == R_X86_64_JUMP_SLOT, f"{slot:#x} is not a JUMP_SLOT")
        require(symbol_name(data, sections, info >> 32) == (name, 0, 0), f"{slot:#x} does not import {name}")


def relocations(data: bytes, sections: list[dict]) -> dict[int, tuple[int, int, int]]:
    rela = section(sections, ".rela.dyn")
    require(rela["size"] % 24 == 0, ".rela.dyn has a partial entry")
    out = {}
    for slot, info, addend in struct.iter_unpack("<QQq", data[rela["offset"]:rela["offset"] + rela["size"]]):
        out[slot] = (info & 0xFFFFFFFF, info >> 32, addend)
    return out


def validate_relocations(data: bytes, sections: list[dict], table: dict[int, tuple[int, int, int]]) -> None:
    for slot, target in RELATIVE_SLOTS.items():
        require(table.get(slot) == (R_X86_64_RELATIVE, 0, target), f"unexpected relocation at {slot:#x}")
    slot, name = IMPORT_SLOT
    kind, symbol, addend = table.get(slot, (None, None, None))
    require(kind == R_X86_64_GLOB_DAT and addend == 0, f"{slot:#x} is not a GLOB_DAT slot")
    found = symbol_name(data, sections, symbol)
    require(found == (name, 0, 0), f"{slot:#x} imports {found[0]!r}, expected undefined {name!r}")


def validate_owner_call(data: bytes, sections: list[dict], table: dict[int, tuple[int, int, int]]) -> dict:
    """Bind the previously recorded owner call to this packet's entry."""
    site, slot = 0x2E0A7F5, 0x64E8718
    require(read(data, sections, ".text", 0x2E0A7D2, 7) == bytes.fromhex("4c8da038050000"),
            "owner argument origin differs")
    setup = read(data, sections, ".text", 0x2E0A7EA, 11)
    require(setup == bytes.fromhex("488db424d00100004c89e7"), "owner call arguments differ")
    raw = read(data, sections, ".text", site, 6)
    require(raw[:2] == b"\xff\x15" and rel32_target(site, raw) == slot, "owner call slot differs")
    require(table.get(slot) == (R_X86_64_RELATIVE, 0, 0x5A71D90), "owner call target differs")
    return {"site": hex(site), "slot": hex(slot), "target": "0x5a71d90",
            "arg0": "r12 (owner + 0x538)", "arg1": "rsp + 0x1d0"}


def validate_literals(data: bytes, sections: list[dict], table: dict[int, tuple[int, int, int]]) -> None:
    address, literal = ASSERT_LITERAL
    require(len(literal) == 0x21, "assertion literal length changed")
    require(read(data, sections, ".rodata", address, len(literal)) == literal, "assertion literal differs")
    slot, path, line, column = LOCATION
    pointer = table[slot][2]
    length, found_line, found_column = struct.unpack("<QII", read(data, sections, ".data.rel.ro", slot + 8, 16))
    require(length == len(path) and (found_line, found_column) == (line, column), "location record differs")
    require(read(data, sections, ".rodata", pointer, length) == path, "location path differs")


def census(data: bytes, sections: list[dict], spans: dict[int, bytes]) -> dict:
    """Whole-.text byte scans. Candidates are raw byte matches, not decoded instructions."""
    text = section(sections, ".text")
    blob = data[text["offset"]:text["offset"] + text["size"]]
    base = text["address"]
    wanted = set(DIRECT_CALLERS)
    callers = {target: set() for target in wanted}
    for match in re.finditer(rb"[\xe8\xe9]", blob):
        position = match.start()
        if position + 5 > len(blob):
            continue
        target = base + position + 5 + struct.unpack_from("<i", blob, position + 1)[0]
        if target in wanted:
            callers[target].add(base + position)
    for target, expected in DIRECT_CALLERS.items():
        require(callers[target] == expected, f"rel32 candidates for {target:#x} differ: {sorted(map(hex, callers[target]))}")
        for site in expected:
            require(site in spans, f"caller {site:#x} is not a retained instruction")
    lea_sites = set()
    slot = LOCATION[0]
    for match in re.finditer(rb"[\x48\x4c]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]", blob, re.S):
        position = match.start()
        if position + 7 <= len(blob) and base + position + 7 + struct.unpack_from("<i", blob, position + 3)[0] == slot:
            lea_sites.add(base + position)
    require(lea_sites == LOCATION_LEA_SITES, f"location LEA candidates differ: {sorted(map(hex, lea_sites))}")
    return {
        "rel32_candidates": {hex(target): sorted(map(hex, sites)) for target, sites in callers.items()},
        "location_lea_candidates": sorted(map(hex, lea_sites)),
    }


def native_sanitize(bits: int) -> int:
    """Branch-for-branch transcription of 0x5a328f3..0x5a32981 on the ratio's raw bits."""
    value = bits                                    # xmm0
    magnitude = bits & 0x7FFFFFFFFFFFFFFF           # rax
    bucket = ((magnitude + 0xFFF0000000000000) & MASK64) >> 53  # rdx; edx compared with 0x3ff
    saved = 0                                       # xmm1 = +0.0
    decremented = (bits - 1) & MASK64               # rcx after dec
    if bits >> 63 == 0:                             # 0x5a3291d js not taken
        saved = value                               # 0x5a3291f
        block = "L61" if bucket >= 0x3FF else "L33"  # 0x5a32931 jae
    else:
        block = "L33" if bucket < 0x3FF else "L61"   # 0x5a3295f jb
    if block == "L61":
        saved = 0                                   # 0x5a32961
        candidate = value                           # 0x5a3296f
        block = "L46" if decremented >= 0xFFFFFFFFFFFFF else "L78"  # 0x5a32976 jae
    else:
        candidate = value                           # 0x5a3293d
        block = "L78" if decremented < 0xFFFFFFFFFFFFF else "L46"   # 0x5a32944 jb
    if block == "L46":
        candidate = saved                           # 0x5a32946
        return candidate if magnitude != 0 else value  # 0x5a3294d jne / 0x5a3294f jmp
    return candidate if magnitude != 0 else value   # 0x5a3297b je


def closed_form_sanitize(bits: int) -> int:
    """Zero of either sign and positive finite values pass; everything else becomes +0.0."""
    magnitude = bits & 0x7FFFFFFFFFFFFFFF
    if magnitude == 0:
        return bits
    if bits >> 63 == 0 and magnitude < 0x7FF0000000000000:
        return bits
    return 0


def sanitize_samples() -> list[int]:
    edges = [
        0x0, 0x1, 0x2, 0xFFFFFFFFFFFFE, 0xFFFFFFFFFFFFF, 0x10000000000000, 0x10000000000001,
        0x3FF0000000000000, 0x7FEFFFFFFFFFFFFF, 0x7FF0000000000000, 0x7FF0000000000001,
        0x7FF8000000000000, 0x7FFFFFFFFFFFFFFF,
    ]
    samples = edges + [bits | (1 << 63) for bits in edges]
    state = 0x9E3779B97F4A7C15
    for _ in range(4096):
        state = (state * 6364136223846793005 + 1442695040888963407) & MASK64
        samples.append(state)
        samples.append(state >> 12)                 # subnormal and small-exponent lanes
        samples.append((state >> 12) | 0x7FF0000000000000)  # infinity/NaN lane
    return samples


def validate_sanitize(closed_form=closed_form_sanitize) -> int:
    samples = sanitize_samples()
    for bits in samples:
        require(native_sanitize(bits) == closed_form(bits), f"sanitisation forms differ for {bits:#018x}")
    return len(samples)


def load():
    data = TARGET.read_bytes()
    require(hashlib.sha256(data).hexdigest() == TARGET_SHA256, "node #115 digest mismatch")
    sections, _ = unwind_index(data)
    _, fdes = eh_frame_records(data, sections)
    return data, sections, fdes


def verify() -> dict:
    data, sections, fdes = load()
    spans, digests = validate_rows(data, sections, fdes, packet_rows())
    validate_edges(spans, fdes)
    validate_plt_calls(data, sections, spans)
    table = relocations(data, sections)
    validate_relocations(data, sections, table)
    owner_call = validate_owner_call(data, sections, table)
    validate_literals(data, sections, table)
    scans = census(data, sections, spans)
    samples = validate_sanitize()
    return {
        "target_sha256": TARGET_SHA256,
        "windows": {
            role: {"start": hex(start), "end": hex(end), "bytes": end - start, "instructions": count,
                   "sha256": digests[role]}
            for role, (start, end, count, _) in WINDOWS.items()
        },
        "authenticated_instruction_rows": len(spans),
        "anchors": len(ANCHORS),
        "direct_calls": len(DIRECT_CALLS),
        "plt_calls": {hex(site): name for site, (_, _, name) in PLT_CALLS.items()},
        "rip_references": len(RIP_REFERENCES),
        "relative_relocations": len(RELATIVE_SLOTS),
        "owner_call": owner_call,
        "import_slot": {"slot": hex(IMPORT_SLOT[0]), "symbol": IMPORT_SLOT[1]},
        "assertion_literal": ASSERT_LITERAL[1].decode(),
        "location": f"{LOCATION[1].decode()}:{LOCATION[2]}:{LOCATION[3]}",
        "byte_scans": scans,
        "sanitize_samples": samples,
        "captured_binary_executed": False,
    }


def expect_rejection(label: str, action) -> str:
    try:
        action()
    except ValueError:
        return label
    raise ValueError(f"corruption accepted: {label}")


def self_test() -> dict:
    result = verify()
    data, sections, fdes = load()
    rows = packet_rows()
    table = relocations(data, sections)

    def with_row(address: int, raw_hex: str):
        changed = [dict(row) for row in rows]
        next(row for row in changed if int(row["va"], 16) == address)["bytes"] = raw_hex
        return lambda: validate_rows(data, sections, fdes, changed)

    def with_relocation(slot: int, entry: tuple[int, int, int]):
        changed = dict(table)
        changed[slot] = entry
        return lambda: (validate_relocations(data, sections, changed), validate_literals(data, sections, changed))

    def with_patched_text(address: int, raw: bytes):
        text = section(sections, ".text")
        offset = text["offset"] + address - text["address"]
        changed = data[:offset] + raw + data[offset + len(raw):]
        spans, _ = validate_rows(data, sections, fdes, rows)
        return lambda: census(changed, sections, spans)

    def with_patched_owner(address: int, raw: bytes):
        text = section(sections, ".text")
        offset = text["offset"] + address - text["address"]
        changed = data[:offset] + raw + data[offset + len(raw):]
        return lambda: validate_owner_call(changed, sections, table)

    def with_literal(address: int, raw: bytes):
        rodata = section(sections, ".rodata")
        offset = rodata["offset"] + address - rodata["address"]
        changed = data[:offset] + raw + data[offset + len(raw):]
        return lambda: validate_literals(changed, sections, table)

    def dropped_row():
        validate_rows(data, sections, fdes, rows[:-1])

    def infinity_kept():
        validate_sanitize(lambda bits: bits if bits == 0x7FF0000000000000 else closed_form_sanitize(bits))

    def negative_zero_cleared():
        validate_sanitize(lambda bits: 0 if bits == 1 << 63 else closed_form_sanitize(bits))

    def subnormal_cleared():
        validate_sanitize(lambda bits: 0 if 0 < bits < 1 << 52 else closed_form_sanitize(bits))

    controls = [
        expect_rejection("denominator offset +0x18 changed to +0x20", with_row(0x5A328CF, "f20f104b20")),
        expect_rejection("numerator offset +0x10 changed to +0x08", with_row(0x5A328EA, "f20f104308")),
        expect_rejection("divsd changed to mulsd", with_row(0x5A328EF, "f20f59c1")),
        expect_rejection("assertion branch jbe changed to jb", with_row(0x5A328E4, "0f82d5000000")),
        expect_rejection("key length 0x14 changed to 0x20", with_row(0x5A32829, "ba20000000")),
        expect_rejection("value stride 0x68 changed to 0x60", with_row(0x5A32840, "4883c360")),
        expect_rejection("ring stride shift 7 changed to 6", with_row(0x5A328C3, "48c1e206")),
        expect_rejection("normal-exponent bound 0x3ff changed to 0x7ff", with_row(0x5A32926, "81faff070000")),
        expect_rejection("row element size 0x20 changed to 0x28", with_row(0x5B81028, "41b828000000")),
        expect_rejection("large-container threshold 0x40 changed to 0x20", with_row(0x4D55BCC, "4883fa20")),
        expect_rejection("container offset +0x148 changed to +0x140", with_row(0x5A71DB2, "488db340010000")),
        expect_rejection("final instruction row dropped", dropped_row),
        expect_rejection("panic slot relocated elsewhere", with_relocation(0x64DF730, (R_X86_64_RELATIVE, 0, 0x1680E61))),
        expect_rejection("memcmp slot turned into a RELATIVE slot", with_relocation(0x64DFB50, (R_X86_64_RELATIVE, 0, 0x1680E60))),
        expect_rejection("location path pointer moved", with_relocation(0x63FDC38, (R_X86_64_RELATIVE, 0, 0x443C50))),
        expect_rejection("assertion literal byte changed", with_literal(0x466DC4 + 29, b"<")),
        expect_rejection("extra rel32 caller of the row closure planted", with_patched_text(
            0x5B80EC6, b"\xe8" + struct.pack("<i", 0x5A327A0 - (0x5B80EC6 + 5)))),
        expect_rejection("owner argument offset changed", with_patched_owner(
            0x2E0A7EA, bytes.fromhex("488db424d8010000"))),
        expect_rejection("owner call slot changed", with_patched_owner(
            0x2E0A7F5, bytes.fromhex("ff1515df6d03"))),
        expect_rejection("closed form that keeps +infinity", infinity_kept),
        expect_rejection("closed form that clears negative zero", negative_zero_cleared),
        expect_rejection("closed form that clears positive subnormals", subnormal_cleared),
    ]
    result["negative_controls"] = controls
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    print(json.dumps(self_test() if args.self_test else verify(), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
