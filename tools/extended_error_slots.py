#!/usr/bin/env python3
"""Identify the local slots of the extended io-error vtables.

Work item: RE-005, node #115.  The preceding packet
(``tools/shared_debug_vtables.py``, PR #3141) pinned the 13 extended
vtables of extent 0x58 for the 8-byte tagged std io error value and
recorded their full slot layout, but closed with explicit
boundaries: the local bodies at +0x38, +0x40 and +0x50 were
"recorded as targets; the traits they serve are not identified",
and the two forwarders at +0x30 (0x5ca8760) and +0x48 (0x5ca8730)
were pinned only by their forwarding targets -- "their trait-slot
names are not asserted".

This tool settles those slots.  The answer it re-derives and pins:

* The 11-entry layout is the vtable of the value for the trait
  ``core::error::Error`` (Debug + Display supertraits).  Header:
  drop / size 8 / align 8.  Then +0x18 Debug::fmt (the shared stub
  0x5ca5610), +0x20 Display::fmt (0x5ca84b0), +0x28 a pointer to
  the sibling one-method Display vtable at base-0x20 (the Display
  supertrait upcast entry), and the trait's own five methods in
  declaration order: +0x30 source, +0x38 type_id, +0x40
  description, +0x48 cause, +0x50 provide.
* +0x38 (type_id): all 13 bodies are the same 14-byte shim --
  ``mov rax,rdi; movups xmm0,[rip+const]; movups [rdi],xmm0; ret``
  -- copying one shared 16-byte constant at 0x451540
  (f8dfacffdf56f26d91c0b01aa4986406) into the caller's out slot.
  One constant for all 13 vtables of one Self: the value's TypeId.
* +0x40 (description): all 13 bodies return a &str of length 40
  whose bytes are the trait's deprecated default text,
  "description() is deprecated; use Display" (13 per-crate string
  copies, identical contents).
* +0x50 (provide): all 13 bodies are a single ``ret`` -- the
  trait's only unit-returning method, unimplemented for this
  value.
* +0x30 / +0x48 (source / cause): the two libstd forwarders are
  Option-shaped (they zero rax on every non-custom tag and return
  it), which excludes provide for either.  Their order is pinned
  two ways: (a) the remaining own-method order matches the
  trait's declaration order at every other position (+0x38
  type_id, +0x40 description, +0x50 provide); (b) a wrapper
  vtable at 0x644eb40 shares one body (0x26c67b0) between its
  +0x30 and +0x48 entries; that body inlines the io value's
  source-side forwarder -- the tag dispatch is inlined and the
  final delegation is ``call *0x30(%rax)``, with no ``call
  *0x48(%rax)`` -- i.e. it is a hand-written source that delegates
  through the value's source, with cause reusing the body (the
  default cause is ``self.source()``; a defaulted source would
  have been the None body instead).
* Cross-check census: the same 11-entry shape with a type_id
  shim at +0x38 recurs across the binary -- 108 sane vtables
  (drop with an FDE, sane size/align, +0x28 naming base-0x20)
  found by scanning for type_id shims referenced from a slot at
  +0x38.  Among them, 29 have both Option slots returning None
  (``xor eax,eax; ret`` bodies) and 13 share one body between
  +0x30 and +0x48.

Boundaries kept explicit: trait names rest on the method-set
fingerprint of core::error::Error plus the pinned string and
constant -- the artifact carries no DWARF names.  The Self
attribution (std::io::Error) is inherited from the preceding
packet's pins (drop template, Display string references).  The
TypeId constant is compilation-specific.  Nothing was executed.

Run against the reconstructed #115 artifact only.  ``analyze``
works on bytes; ``generate`` writes the packet under
research/work-items/RE-005-node115-extended-error-slots/.
"""

from __future__ import annotations

import hashlib
import json
import re
import struct
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from elf_index import sections  # noqa: E402
from fde_extents import fde_extents  # noqa: E402

SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
SIZE = 105_896_032
TARGET = Path("artifacts/node/115/hl-node")
PACKET = Path("research/work-items/RE-005-node115-extended-error-slots")

METHOD_STUB = 0x5CA5610
DISPLAY_BODY = 0x5CA84B0
FWD_SOURCE = 0x5CA8760
FWD_CAUSE = 0x5CA8730
FWD_BYTES = 41
FWD_CALL_AT = 0x24
TYPEID_CONST = 0x451540
TYPEID_VALUE = "f8dfacffdf56f26d91c0b01aa4986406"
DESC_TEXT = b"description() is deprecated; use Display"
WRAPPER_VTABLE = 0x644EB40
WRAPPER_BODY = 0x26C67B0

EXPECTED_BASES = [
    0x63F8F58, 0x640D678, 0x640E4E0, 0x64445C0, 0x644E600,
    0x6455A88, 0x645B320, 0x64842F0, 0x6494E90, 0x6496828,
    0x649E030, 0x64C7348, 0x64C74F0,
]

TYPEID_SHIM = re.compile(
    rb"\x48\x89\xf8\x0f\x10\x05(....)\x0f\x11\x07\xc3", re.S)
NONE_BODY = bytes.fromhex("31c0c3")  # xor eax,eax; ret
TAG_MASK = bytes.fromhex("83e603")   # and esi,0x3 (tag dispatch)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def hx(value: int) -> str:
    return f"0x{value:x}"


def read(data: bytes, va: int, size: int) -> bytes:
    for sec in sections(data):
        start = sec["address"]
        if start <= va and va + size <= start + sec["size"]:
            off = sec["offset"] + va - start
            return data[off:off + size]
    raise ValueError(f"unmapped read at {hx(va)}")


def relocations(data: bytes) -> dict:
    secs = {s["name"]: s for s in sections(data)}
    mapping: dict[int, int] = {}
    for name in (".rela.dyn", ".rela.plt"):
        rela = secs[name]
        blob = data[rela["offset"]:rela["offset"] + rela["size"]]
        for off in range(0, len(blob), 24):
            addr, info, addend = struct.unpack_from("<QQq", blob, off)
            if info & 0xFFFFFFFF == 8:  # RELATIVE
                mapping[addr] = addend
    return mapping


def body_map(data: bytes) -> dict[int, dict]:
    _, rows, _ = fde_extents(data)
    return {f["start"]: {"start": f["start"], "end": f["end"],
                         "bytes": f["end"] - f["start"]}
            for f in rows if f["end"] > f["start"]}


def cell(rel: dict, data: bytes, va: int) -> int:
    if va in rel:
        return rel[va]
    return struct.unpack("<Q", read(data, va, 8))[0]


def body_bytes(data: bytes, fdes: dict, start: int) -> bytes:
    fde = fdes.get(start)
    require(fde is not None, f"no FDE at {hx(start)}")
    return read(data, start, fde["bytes"])


def parse_typeid_body(data: bytes, fdes: dict, start: int) -> dict:
    blob = body_bytes(data, fdes, start)
    require(len(blob) >= 14, f"type_id body too short at {hx(start)}")
    require(blob[0:3] == bytes.fromhex("4889f8"),
            f"type_id body prologue mismatch at {hx(start)}")
    require(blob[3:6] == bytes.fromhex("0f1005"),
            f"type_id body movups mismatch at {hx(start)}")
    (rel32,) = struct.unpack_from("<i", blob, 6)
    const_va = start + 10 + rel32
    require(blob[10:13] == bytes.fromhex("0f1107"),
            f"type_id body store mismatch at {hx(start)}")
    require(blob[13] == 0xC3, f"type_id body ret mismatch at {hx(start)}")
    require(all(b == 0xCC for b in blob[14:]),
            f"type_id body padding mismatch at {hx(start)}")
    value = read(data, const_va, 16)
    return {"body": hx(start), "extent": len(blob),
            "const_va": hx(const_va), "const_value": value.hex()}


def parse_description_body(data: bytes, fdes: dict, start: int) -> dict:
    blob = body_bytes(data, fdes, start)
    require(len(blob) >= 13, f"description body too short at {hx(start)}")
    require(blob[0:3] == bytes.fromhex("488d05"),
            f"description body lea mismatch at {hx(start)}")
    (rel32,) = struct.unpack_from("<i", blob, 3)
    str_va = start + 7 + rel32
    require(blob[7:12] == bytes.fromhex("ba28000000"),
            f"description body length mismatch at {hx(start)}")
    require(blob[12] == 0xC3,
            f"description body ret mismatch at {hx(start)}")
    require(all(b == 0xCC for b in blob[13:]),
            f"description body padding mismatch at {hx(start)}")
    text = read(data, str_va, len(DESC_TEXT))
    require(text == DESC_TEXT,
            f"description string mismatch at {hx(str_va)}")
    return {"body": hx(start), "extent": len(blob), "str_va": hx(str_va),
            "length": len(DESC_TEXT), "text": DESC_TEXT.decode()}


def parse_provide_body(data: bytes, fdes: dict, start: int) -> dict:
    blob = body_bytes(data, fdes, start)
    require(len(blob) >= 1 and blob[0] == 0xC3,
            f"provide body is not a bare ret at {hx(start)}")
    require(all(b == 0xCC for b in blob[1:]),
            f"provide body padding mismatch at {hx(start)}")
    return {"body": hx(start), "extent": len(blob)}


def parse_forwarder(data: bytes, fdes: dict, start: int,
                    call_disp: int) -> dict:
    blob = body_bytes(data, fdes, start)
    require(len(blob) == FWD_BYTES,
            f"forwarder extent mismatch at {hx(start)}")
    require(blob[FWD_CALL_AT:FWD_CALL_AT + 3]
            == bytes([0xFF, 0x50, call_disp]),
            f"forwarder call offset mismatch at {hx(start)}")
    require(TAG_MASK in blob, f"forwarder tag dispatch missing at {hx(start)}")
    require(bytes.fromhex("31c0") in blob,
            f"forwarder None prologue missing at {hx(start)}")
    return {"body": hx(start), "extent": len(blob),
            "call_disp": hx(call_disp)}


def typeid_shims(data: bytes) -> dict[int, int]:
    """All 14-byte constant-copy shims in executable sections:
    body va -> constant va."""
    found: dict[int, int] = {}
    for sec in sections(data):
        if not (sec["flags"] & 4 and sec["size"]):
            continue
        blob = data[sec["offset"]:sec["offset"] + sec["size"]]
        for m in TYPEID_SHIM.finditer(blob):
            body = sec["address"] + m.start()
            (rel32,) = struct.unpack_from("<i", m.group(1), 0)
            found[body] = body + 10 + rel32
    return found


def census(data: bytes, rel: dict, fdes: dict) -> dict:
    shims = typeid_shims(data)
    slot_of: dict[int, list[int]] = {}
    for addr, addend in rel.items():
        if addend in shims:
            slot_of.setdefault(addend, []).append(addr)
    text = next(s for s in sections(data) if s["name"] == ".text")
    sane: list[int] = []
    for shim, slots in slot_of.items():
        for slot in slots:
            base = slot - 0x38
            drop = cell(rel, data, base)
            size = cell(rel, data, base + 8)
            align = cell(rel, data, base + 0x10)
            if drop not in fdes:
                continue
            if not (text["address"] <= drop
                    < text["address"] + text["size"]):
                continue
            if not (0 < size <= 0x100000):
                continue
            if not (1 <= align <= 0x1000 and (align & (align - 1)) == 0):
                continue
            if cell(rel, data, base + 0x28) != base - 0x20:
                continue
            if base not in sane:
                sane.append(base)
    both_none = 0
    shared: list[int] = []
    for base in sane:
        t30 = cell(rel, data, base + 0x30)
        t48 = cell(rel, data, base + 0x48)
        if t30 == t48:
            shared.append(base)
        if (read(data, t30, 3) == NONE_BODY
                and read(data, t48, 3) == NONE_BODY):
            both_none += 1
    return {"sane_vtables": len(sane), "both_none": both_none,
            "shared_body": len(shared),
            "shared_bases": [hx(b) for b in sorted(shared)]}


def analyze(data: bytes) -> dict:
    require(len(data) == SIZE, "target size mismatch")
    require(hashlib.sha256(data).hexdigest() == SHA256,
            "target sha256 mismatch")
    rel = relocations(data)
    fdes = body_map(data)

    vtables = []
    desc_addrs: list[int] = []
    for base in EXPECTED_BASES:
        require(cell(rel, data, base + 8) == 8,
                f"size mismatch at {hx(base)}")
        require(cell(rel, data, base + 0x10) == 8,
                f"align mismatch at {hx(base)}")
        slots = {off: cell(rel, data, base + off)
                 for off in (0x18, 0x20, 0x28, 0x30, 0x38, 0x40,
                             0x48, 0x50)}
        require(slots[0x18] == METHOD_STUB,
                f"Debug stub mismatch at {hx(base)}")
        require(slots[0x20] == DISPLAY_BODY,
                f"Display body mismatch at {hx(base)}")
        require(slots[0x28] == base - 0x20,
                f"Display upcast mismatch at {hx(base)}")
        require(slots[0x30] == FWD_SOURCE,
                f"source forwarder mismatch at {hx(base)}")
        require(slots[0x48] == FWD_CAUSE,
                f"cause forwarder mismatch at {hx(base)}")
        tid = parse_typeid_body(data, fdes, slots[0x38])
        require(tid["const_va"] == hx(TYPEID_CONST),
                f"type_id constant address mismatch at {hx(base)}")
        require(tid["const_value"] == TYPEID_VALUE,
                f"type_id constant value mismatch at {hx(base)}")
        desc = parse_description_body(data, fdes, slots[0x40])
        desc_addrs.append(int(desc["str_va"], 16))
        prov = parse_provide_body(data, fdes, slots[0x50])
        vtables.append({
            "base": hx(base),
            "drop": hx(cell(rel, data, base)),
            "slots": {hx(k): hx(v) for k, v in slots.items()},
            "type_id": tid, "description": desc, "provide": prov,
        })

    fwd_source = parse_forwarder(data, fdes, FWD_SOURCE, 0x30)
    fwd_cause = parse_forwarder(data, fdes, FWD_CAUSE, 0x48)

    # Wrapper discriminator: base 0x644eb40 shares one body between
    # its +0x30 and +0x48 entries; the body inlines the value's
    # source-side tag dispatch and delegates via +0x30 only.
    w30 = cell(rel, data, WRAPPER_VTABLE + 0x30)
    w48 = cell(rel, data, WRAPPER_VTABLE + 0x48)
    require(w30 == WRAPPER_BODY and w48 == WRAPPER_BODY,
            "wrapper shared body mismatch")
    wblob = body_bytes(data, fdes, WRAPPER_BODY)
    require(wblob[0:4] == bytes.fromhex("488b4718"),
            "wrapper field load mismatch")
    require(wblob[4:7] == bytes.fromhex("833801"),
            "wrapper field check mismatch")
    require(TAG_MASK in wblob, "wrapper tag dispatch missing")
    require(bytes.fromhex("ff5030") in wblob,
            "wrapper +0x30 delegation missing")
    require(bytes.fromhex("ff5048") not in wblob,
            "wrapper unexpectedly delegates via +0x48")

    cen = census(data, rel, fdes)

    return {
        "artifact": {"sha256": SHA256, "size": SIZE},
        "answers": [
            "+0x38 is Error::type_id: a 14-byte shim returning one "
            "shared 16-byte TypeId constant by sret",
            "+0x40 is Error::description: returns the deprecated "
            "default string \"description() is deprecated; use "
            "Display\" (40 bytes)",
            "+0x50 is Error::provide: a single ret (no-op)",
            "+0x30 is Error::source and +0x48 is Error::cause: "
            "the two Option-shaped libstd forwarders, ordered by "
            "declaration order and the wrapper inline "
            "discriminator at 0x26c67b0",
        ],
        "layout": [
            {"offset": "0x0", "role": "drop_in_place"},
            {"offset": "0x8", "role": "size", "value": 8},
            {"offset": "0x10", "role": "align", "value": 8},
            {"offset": "0x18", "role": "Debug::fmt",
             "target": hx(METHOD_STUB)},
            {"offset": "0x20", "role": "Display::fmt",
             "target": hx(DISPLAY_BODY)},
            {"offset": "0x28", "role": "Display supertrait upcast",
             "target": "base-0x20"},
            {"offset": "0x30", "role": "Error::source",
             "target": hx(FWD_SOURCE)},
            {"offset": "0x38", "role": "Error::type_id"},
            {"offset": "0x40", "role": "Error::description"},
            {"offset": "0x48", "role": "Error::cause",
             "target": hx(FWD_CAUSE)},
            {"offset": "0x50", "role": "Error::provide"},
        ],
        "extended_vtables": vtables,
        "type_id_constant": {"address": hx(TYPEID_CONST),
                             "value": TYPEID_VALUE},
        "description_string": {
            "text": DESC_TEXT.decode(), "length": len(DESC_TEXT),
            "addresses": [hx(a) for a in desc_addrs]},
        "forwarders": {"source": fwd_source, "cause": fwd_cause},
        "discriminator": {
            "wrapper_vtable": hx(WRAPPER_VTABLE),
            "shared_body": hx(WRAPPER_BODY),
            "shared_extent": len(wblob),
            "delegates_via": "0x30", "never_via": "0x48"},
        "census": cen,
        "limitations": [
            "Trait names rest on the method-set fingerprint of "
            "core::error::Error plus the pinned string and "
            "constant; the artifact carries no DWARF names.",
            "The Self attribution (std::io::Error) is inherited "
            "from the preceding packet's pins (drop template, "
            "Display string references), not re-derived here.",
            "The source/cause order is pinned by the declaration "
            "order visible at +0x38/+0x40/+0x50 and by the "
            "wrapper inline discriminator; the swapped reading "
            "would require the wrapper at 0x644eb40 to hand-write "
            "a delegating cause while its source entry shares "
            "that body instead of the None default.",
            "The +0x28 entry is identified as the Display "
            "supertrait upcast pointer by its target (the sibling "
            "one-method Display vtable); no second upcast "
            "pointer, for Debug, exists in this layout.",
            "The TypeId constant is compilation-specific; it is "
            "the value's TypeId because the +0x38 entry of the "
            "value's own vtables returns it.",
            "Static evidence only; no value was executed.",
        ],
    }


def objdump(start: int, size: int) -> bytes:
    out = subprocess.run(
        ["objdump", "-d", "--show-raw-insn",
         f"--start-address={start:#x}",
         f"--stop-address={start + size:#x}", str(TARGET)],
        check=True, capture_output=True)
    return out.stdout


def export_bodies(records: dict) -> dict[str, tuple[int, int]]:
    """filename -> (start, size) for the packet's objdump evidence."""
    first = records["extended_vtables"][0]
    files: dict[str, tuple[int, int]] = {}
    tid = first["type_id"]
    files["slot_38_type_id.objdump.txt"] = (
        int(tid["body"], 16), tid["extent"])
    desc = first["description"]
    files["slot_40_description.objdump.txt"] = (
        int(desc["body"], 16), desc["extent"])
    prov = first["provide"]
    files["slot_50_provide.objdump.txt"] = (
        int(prov["body"], 16), prov["extent"])
    files["forwarder_30_source.objdump.txt"] = (FWD_SOURCE, FWD_BYTES)
    files["forwarder_48_cause.objdump.txt"] = (FWD_CAUSE, FWD_BYTES)
    disc = records["discriminator"]
    files["wrapper_discriminator.objdump.txt"] = (
        int(disc["shared_body"], 16), disc["shared_extent"])
    return files


def manifest(packet: Path) -> str:
    lines = []
    for path in sorted(packet.iterdir()):
        if path.name == "MANIFEST.sha256" or not path.is_file():
            continue
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        lines.append(f"{digest}  {path.name}")
    return "\n".join(lines) + "\n"


def generate() -> dict:
    data = TARGET.read_bytes()
    records = analyze(data)
    PACKET.mkdir(parents=True, exist_ok=True)
    (PACKET / "records.json").write_text(
        json.dumps(records, indent=1, sort_keys=True) + "\n")
    for name, (start, size) in export_bodies(records).items():
        (PACKET / name).write_bytes(objdump(start, size))
    (PACKET / "MANIFEST.sha256").write_text(manifest(PACKET))
    return records


def check() -> None:
    data = TARGET.read_bytes()
    records = analyze(data)
    retained = json.loads((PACKET / "records.json").read_text())
    require(records == retained, "records regeneration mismatch")
    require((PACKET / "MANIFEST.sha256").read_text() == manifest(PACKET),
            "manifest mismatch")
    print("check ok")


def main() -> int:
    if len(sys.argv) != 2 or sys.argv[1] not in ("generate", "check"):
        print("usage: extended_error_slots.py generate|check",
              file=sys.stderr)
        return 2
    if sys.argv[1] == "generate":
        generate()
        print("generated", PACKET)
    else:
        check()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
