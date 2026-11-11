#!/usr/bin/env python3
"""Pin the node #115 owned-db open budget at 0x4524660.

The body looks up one byte key, then passes a cache-size argument and three
fixed immediates to relocated RocksDB option setters. A clear flag bit selects
0x800<<20. The already mapped sibling at 0x57c6530 selects 0x4000<<20. This
tool authenticates the capture and checks those bytes. It does not execute the
capture or open a database.
"""
import hashlib
import json
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from elf_index import sections, unwind_index

ROOT = Path(__file__).resolve().parents[1]
IMAGE = ROOT / "artifacts/node/115/hl-node"
TARGET_SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
TARGET_SIZE = 105_896_032
START = 0x4524660
SIZE = 0x47B
END = START + SIZE
BODY_SHA = "dc1e605f41e2852c1abf20beae609aadff947c84de7f227e46481758a04760bf"
DB_OPTIONS = b"/home/ubuntu/hl/code_Mainnet/z_vendor/rocksdb/src/db_options.rs"

ANCHORS = (
    (0x4524671, "488b4618", "root pointer load changed"),
    (0x4524678, "0f8471030000", "null-root branch changed"),
    (0x4524687, "488b4e20", "height load changed"),
    (0x452468e, "440fb74062", "key count load changed"),
    (0x45246aa, "440fb6543865", "key byte load changed"),
    (0x45246e3, "4883e901", "height decrement changed"),
    (0x45246e7, "0f8202030000", "height borrow branch changed"),
    (0x45246ed, "488b44f870", "child pointer load changed"),
    (0x45246f4, "4c8b64f808", "selected value load changed"),
    (0x45246f9, "f049ff0424", "selected refcount increment changed"),
    (0x45246fe, "0f8ee9020000", "refcount failure branch changed"),
    (0x452470c, "e8af52f4ff", "db_home guard call changed"),
    (0x4524711, "4c89642418", "guard result is no longer ignored"),
    (0x4524732, "4180e601", "flag mask changed"),
    (0x4524739, "48c1e836", "high-bit shift changed"),
    (0x4524740, "49c1e70a", "pre-scale shift changed"),
    (0x4524747, "bf00080000", "cache immediate changed"),
    (0x4524753, "48c1e82c", "saturation shift changed"),
    (0x452476b, "48c1e714", "final scale shift changed"),
    (0x45247f2, "be00400000", "block size immediate changed"),
    (0x4524823, "be01000000", "options flag immediate changed"),
    (0x452482e, "be00000008", "companion immediate changed"),
    (0x452486b, "498b542418", "selected path pointer load changed"),
    (0x4524870, "498b4c2420", "selected path length load changed"),
    (0x4524882, "e889a483ff", "open call changed"),
    (0x4524887, "31c0", "niche compare input changed"),
    (0x4524889, "483b442468", "niche compare address changed"),
    (0x452488e, "0f80ea000000", "error niche branch changed"),
    (0x45248c9, "4c896350", "selected pointer publish changed"),
    (0x45249c6, "48c7c7ffffffff", "saturated budget changed"),
    (0x37BEFDE, "0fb65f10", "caller argument changed"),
    (0x37BEFE9, "80fb030f84dd000000", "caller mode compare changed"),
    (0x37BEFFD, "488b08", "caller argument changed"),
    (0x37BF000, "4c8b4008", "caller argument changed"),
    (0x37BF004, "0fb6d3", "caller argument changed"),
    (0x37BF00C, "e84f56d600", "direct call changed"),
    (0x4469b5d, "488d3d9140fefb", "db_home rejection literal changed"),
    (0x57c661b, "bf00400000", "sibling default changed"),
)

LOCATIONS = (
    (0x646E320, 0x44F3DB, b"db/src/owned_db_home.rs", 72, 37),
    (0x648F260, 0x43D17D, b"db/src/rocks_db.rs", 58, 49),
    (0x64C0F00, 0x43F772, DB_OPTIONS, 3065, 13),
    (0x64C0F30, 0x43F772, DB_OPTIONS, 56, 86),
    (0x64C0F48, 0x43F772, DB_OPTIONS, 650, 9),
)

SLOTS = (
    (0x64EAB28, 0x5D34B20, "block-based options"),
    (0x64EAB30, 0x5D35250, "cache-size builder"),
    (0x64EAB38, 0x5D35AE0, "attach cache budget"),
    (0x64EAB40, 0x5D34C40, "block size"),
    (0x64E6C58, 0x5D35660, "options"),
    (0x64E7378, 0x5D34C50, "options flag"),
    (0x64EAB48, 0x5D34C60, "companion bytes"),
    (0x64EAB50, 0x5D356E0, "attach block options"),
    (0x64DF480, 0x6355830, "box allocation"),
    (0x64DF770, 0x1680BD0, "missing-key panic"),
    (0x64E0D10, 0x5C75B60, "options panic"),
    (0x64DF6A0, 0x1680C30, "unwrap formatter"),
    (0x64DF830, 0x1680C10, "budget-builder panic"),
)

LITERALS = (
    (0x7A0590, b"no entry found for key"),
    (0x944435, b"Could not create RocksDB block based options"),
    (0x4578E0, b"Could not create RocksDB options"),
    (0x7D3CA8, b"called `Result::unwrap()` on an `Err` value"),
    (0x44DBF5, b"$db_home contains db_bundle in path: "),
)


def authenticate(data):
    if len(data) != TARGET_SIZE or hashlib.sha256(data).hexdigest() != TARGET_SHA:
        raise ValueError("digest mismatch")


def load_image(path=IMAGE):
    data = Path(path).read_bytes()
    authenticate(data)
    return data


def _section_map(data):
    rows = sections(data)
    if len({row["name"] for row in rows}) != len(rows):
        raise ValueError("duplicate section name")
    return rows


def read_va(data, rows, va, size):
    matches = [row for row in rows
               if row["type"] != 8 and row["address"] <= va < row["address"] + row["size"]]
    if len(matches) != 1:
        raise ValueError(f"virtual address is not in one loaded section: {va:#x}")
    row = matches[0]
    if va + size > row["address"] + row["size"]:
        raise ValueError(f"read crosses a section: {va:#x}")
    offset = row["offset"] + (va - row["address"])
    return data[offset:offset + size], row["name"]


def _relatives(data, rows):
    section = next(row for row in rows if row["name"] == ".rela.dyn")
    if section["size"] % 24:
        raise ValueError("truncated relocation section")
    found = {}
    for index in range(0, section["size"], 24):
        offset, info, addend = struct.unpack_from("<QQq", data, section["offset"] + index)
        if info & 0xFFFFFFFF == 8:
            if offset in found:
                raise ValueError(f"duplicate relative relocation: {offset:#x}")
            found[offset] = addend
    return found


def _text(data, rows):
    section = next(row for row in rows if row["name"] == ".text")
    return data[section["offset"]:section["offset"] + section["size"]], section["address"]


def _direct_calls(text, base, target):
    found = []
    index = 0
    while True:
        at = text.find(b"\xe8", index)
        if at < 0 or at + 5 > len(text):
            break
        displacement = struct.unpack_from("<i", text, at + 1)[0]
        source = base + at
        if source + 5 + displacement == target:
            found.append(source)
        index = at + 1
    return found


def _fde(data, rows, start):
    _sections, entries = unwind_index(data)
    matches = [row for row in entries if row["start"] == start]
    if len(matches) != 1:
        raise ValueError("fde extent changed")
    entry = matches[0]
    header, _ = read_va(data, rows, entry["fde"], 16)
    relative, extent = struct.unpack_from("<iI", header, 8)
    begin = entry["fde"] + 8 + relative
    if begin != start or extent != SIZE or begin + extent != END:
        raise ValueError("fde extent changed")
    if entry["next_index_upper_bound"] <= END:
        raise ValueError("fde extent changed")
    return entry


def inspect(data, *, authenticated=True):
    """Return the pinned record, or raise ValueError on the first mismatch."""
    if authenticated:
        authenticate(data)
    elif len(data) != TARGET_SIZE:
        raise ValueError("truncated image")
    rows = _section_map(data)
    for va, expected, message in ANCHORS:
        got, _ = read_va(data, rows, va, len(expected) // 2)
        if got.hex() != expected:
            raise ValueError(message)
    body, section = read_va(data, rows, START, SIZE)
    if section != ".text" or hashlib.sha256(body).hexdigest() != BODY_SHA:
        raise ValueError("body digest changed")
    gap, _ = read_va(data, rows, END, 5)
    if gap != b"\xcc" * 5:
        raise ValueError("body digest changed")
    for va, literal in LITERALS:
        got, name = read_va(data, rows, va, len(literal))
        if name != ".rodata" or got != literal:
            raise ValueError("literal changed")
    relatives = _relatives(data, rows)
    locations = []
    for slot, addend, path, line, column in LOCATIONS:
        if relatives.get(slot) != addend:
            raise ValueError("location changed")
        raw, _ = read_va(data, rows, slot, 24)
        pointer, length, got_line, got_column = struct.unpack_from("<QQII", raw)
        text, _ = read_va(data, rows, addend, len(path))
        if pointer != 0 or length != len(path) or (got_line, got_column) != (line, column) or text != path:
            raise ValueError("location changed")
        locations.append({"slot": hex(slot), "file": path.decode(), "line": line, "column": column})
    slots = []
    for slot, addend, role in SLOTS:
        if relatives.get(slot) != addend:
            raise ValueError("slot addend changed")
        slots.append({"slot": hex(slot), "addend": hex(addend), "role": role})
    text, base = _text(data, rows)
    callers = _direct_calls(text, base, START)
    if callers != [0x37BF00C]:
        raise ValueError("direct call changed")
    home_raw = next(raw for va, raw, _message in ANCHORS if va == 0x452470C)
    home = 0x452470C + 5 + struct.unpack_from("<i", bytes.fromhex(home_raw), 1)[0]
    opened = 0x4524882 + 5 + struct.unpack_from("<i", bytes.fromhex("e889a483ff"), 1)[0]
    if home != 0x44699C0 or opened != 0x3D5ED10:
        raise ValueError("open call changed")
    entry = _fde(data, rows, START)
    caller = next(row for row in unwind_index(data)[1] if row["start"] <= 0x37BF00C < row["next_index_upper_bound"])
    return {
        "artifact": "node115",
        "sha256": TARGET_SHA,
        "body": {"start": hex(START), "end": hex(END), "size": SIZE, "sha256": BODY_SHA},
        "fde": hex(entry["fde"]),
        "next_unwind_start": hex(entry["next_index_upper_bound"]),
        "direct_caller": {"site": "0x37bf00c", "function_start": hex(caller["start"]), "skip_byte": 3},
        "cache_default": "0x800<<20",
        "sibling_default": {"site": "0x57c661b", "immediate": "0x4000"},
        "block_size": "0x4000",
        "options_flag": 1,
        "companion_bytes": "0x8000000",
        "error_niche": "0x8000000000000000",
        "calls": {"db_home_guard": hex(home), "open": hex(opened)},
        "locations": locations,
        "slots": slots,
        "literals": [literal.decode() for _, literal in LITERALS],
        "gates_changed": False,
        "target_executed": False,
    }


def produce(path=IMAGE):
    return inspect(load_image(path))


def main():
    record = produce()
    json.dump(record, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, struct.error) as error:
        print(f"owned_db_open_budget_115: {error}", file=sys.stderr)
        raise SystemExit(1)
