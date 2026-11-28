"""Read the linked width function, the call-site options and its five data objects."""
from bisect import bisect_right
import hashlib
import json
from pathlib import Path
import re
import struct
import sys

import capstone

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "tools"))
import byte_progress
import entry_start_static as elf
from elf_index import sections
from fde_extents import eh_frame_records

TARGET_SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
START = 0x5D01BC0
SLOT = 0x64E1D40
# (instruction, RIP-relative access goes through a RELATIVE slot, full object size)
TABLES = {
    "TABLES_0": (0x5D01BE5, True, 256),
    "TABLES_1": (0x5D01BEC, True, 2432),
    "TABLES_2": (0x5D01BF3, True, 3808),
    "EMOJI_PRESENTATION_LEAVES": (0x5D01BD7, False, 768),
    "TEXT_PRESENTATION_LEAVES": (0x5D01E48, False, 512),
}


def require(ok, message):
    if not ok:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def call_sites(data, fdes):
    text, = [s for s in sections(data) if s["name"] == ".text"]
    start = text["offset"]
    until = start + text["size"]
    shift = text["address"] - start
    sites = []
    owners = {}
    starts = sorted(fdes)
    dis = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    pos = start - 1
    while (pos := data.find(b"\xff\x15", pos + 1, until - 5)) != -1:
        va = pos + shift
        if va + 6 + struct.unpack_from("<i", data, pos + 2)[0] != SLOT:
            continue
        owner = starts[bisect_right(starts, va) - 1]
        require(owner <= va < fdes[owner], "outside FDE")
        if owner not in owners:
            code = elf.read(data, owner, fdes[owner] - owner)[1]
            owners[owner] = {i.address: (i.mnemonic, i.op_str) for i in dis.disasm(code, owner)}
        instructions = owners[owner]
        require(instructions.get(va - 2) == ("xor", "edx, edx")
                and instructions.get(va, ("",))[0] == "call", "changed call-site width policy")
        sites.append({"call": hex(va), "owner": hex(owner)})
    require(len(sites) == 19 and len(owners) == 9, "different call-site population")
    return sites, owners


def capture(tables_source):
    data = (ROOT / "artifacts/node/115/hl-node").read_bytes()
    require(digest(data) == TARGET_SHA, "wrong target")
    fdes = {r["start"]: r["end"] for r in eh_frame_records(data)[1]}
    rel = elf.relocations(data)
    require(rel[SLOT] == (8, START), "width provider changed")
    vendor = ROOT / "research/work-items/RE-002-node115-vendor-overflow-census"
    record, = [r for r in json.loads((vendor / "census.json").read_text())["records"] if r["start"] == START]
    require(record["crate"] == "unicode-width" and record["candidate_versions"] == ["0.1.13"]
            and record["end"] == fdes[START] and "unicode_width9str_width" in record["symbol"], "different function")
    size = fdes[START] - START
    offset = record["source_offset"]
    compiled = (vendor / "bodies.bin").read_bytes()[offset:offset + size]
    body = elf.read(data, START, size)[1]
    require(digest(compiled) == record["source_body_sha256"]
            and digest(body) == record["target_body_sha256"], "changed source or target body")
    matched = byte_progress.compare(compiled, body, record["relocations"])
    require(matched["relocation_qualified"], "source body differs")
    sites, owners = call_sites(data, fdes)
    locations = {}
    for owner, site, suffix in [(0x1648390, 0x164A202, "clap/src/app/help.rs"),
                                (0x165BCD0, 0x165BDCA, "textwrap/src/lib.rs")]:
        require(owners[owner][site][0] == "lea", "source location outside owner instructions")
        location = elf.rip_target(data, site, 3)
        kind, path_va = rel[location]
        length, line, col = struct.unpack("<QII", elf.read(data, location + 8, 16)[1])
        path = elf.read(data, path_va, length)[1].decode()
        require(kind == 8 and path.endswith("/z_vendor/" + suffix), "different caller source")
        locations[hex(owner)] = {"file": suffix, "line": line, "column": col, "load": hex(site)}

    objects, details = {}, {}
    for name, (site, indirect, length) in TABLES.items():
        field = elf.rip_target(data, site, 3)
        if indirect:
            kind, address = rel[field]
            require(kind == 8, "wrong table relocation")
        else:
            address = field
        linked = elf.read(data, address, length)[1]
        initializer = re.search(r"static " + name + r":[^\n]*?= Align\d+\(\[(.*?)\]\);", tables_source, re.S)
        require(initializer is not None, "missing public table " + name)
        published = bytes.fromhex("".join(re.findall(r"0x([0-9A-Fa-f]{2})\b", initializer[1])))
        require(published == linked, "public table bytes differ: " + name)
        objects[name] = linked
        details[name] = {"address": hex(address), "bytes": length, "sha256": digest(linked)}

    # For VS16 the compiler selected a jump table for the first 11 high-bit groups.
    # Its entries are signed displacements from the start of the table.
    jump = elf.rip_target(data, 0x5D01BDE, 3)
    destinations = [jump + x for x in struct.unpack("<11i", elf.read(data, jump, 44)[1])]
    require(destinations == [0x5D01CFF] + [0x5D01D26] * 7 + [0x5D01CD4, 0x5D01CF3, 0x5D01CEC],
            "emoji leaf selector changed")
    return objects, {
        "node115_sha256": TARGET_SHA, "width_fde": [hex(START), hex(START + size)],
        "width_body_sha256": digest(body), "fixed_source_bytes": matched["non_relocation_bytes"],
        "call_slot": hex(SLOT), "narrow_calls": sites, "source_locations": locations,
        "tables": details, "emoji_jump_destinations": [hex(a) for a in destinations],
    }
