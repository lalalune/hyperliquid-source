"""RE-005 node115: the four entries after the tokio Debug vtable.

H15 (RE-005 node115 shared Debug vtables, PR #3141) measured the
io-error Debug vtable at 0x64c6458 with extent 0x40 and recorded
four "local slots" (+0x20/+0x28/+0x30/+0x38) whose trait it could
not name.  This packet settles them.

The compiler vtable at 0x64c6458 is a standalone `dyn Debug`
vtable for the 8-byte tagged io-error value: header (drop
0x5cee460, size 8, align 8) plus the shared Debug stub 0x5ca5610
at +0x18 -- true extent 0x20, like the other 18 standalone-family
members.  H15's extent heuristic (extend while cells resolve to
FDE starts) ran past it because the four following cells are also
RELATIVE pointers to FDE starts: they are a separate static, a
`core::task::RawWakerVTable` at 0x64c6478, in core's field order

    +0x00 clone       0x5cee5a0
    +0x08 wake        0x5cee590
    +0x10 wake_by_ref 0x5cee5c0
    +0x18 drop        0x5cee570

Evidence pinned here, all re-derived from the materialized
artifact (never from the H15 records):

* clone atomically increments the strong count at data-0x80
  (overflow aborts via ud2) and returns the RawWaker pair
  (rax = 0x64c6478, the table's own address; rdx = data).
* wake adjusts data by -0x80 and tail-jumps to the consuming
  body 0x5cfc550, which sets the woken flag at alloc+0x1d0,
  consults a thread-local context, calls the I/O-driver wake
  body 0x5ce09a0 on the sub-object at alloc+0x240 when the
  current context is foreign, and finally decrements the
  strong count (consuming the reference).
* wake_by_ref sets the same flag through data+0x150
  (== alloc+0x1d0) with an xchg, returns early when already
  set or when the thread-local context names this allocation,
  and otherwise tail-calls the same wake body on
  data+0x1c0 (== alloc+0x240).  It never touches the count.
* drop decrements the strong count at data-0x80 and, at zero,
  calls the allocation destroy body 0x5ce86d0, the inner
  type's drop_in_place: allocation size 0x300, weak count at
  +0x08, field drops at +0x100/+0x170/+0x200/+0x210/+0x238/
  +0x240/+0x2e0.

The waker data pointer is the allocation base + 0x80; none of
the four functions dereferences the 8 bytes at the data pointer
itself -- every access is relative (count -0x80, flag +0x150,
wake target +0x1c0).  The allocation is the tokio I/O driver's
shared inner state: the wake body it funnels into is the one
whose expect panics "failed to wake I/O driver"
(tokio/src/runtime/io/driver.rs:272), and that body's panic
formatting is also the only use of the neighbouring Debug
vtable -- the panic helper's format shim (0x1687260) calls
only the vtable's +0x18 slot.

Census: the RawWakerVTable address is referenced exactly once
in the binary (the lea inside clone); the Debug vtable is
referenced exactly at the seven known panic-format sites.

Usage:
    python3 tools/tokio_waker_table.py generate
    python3 tools/tokio_waker_table.py check
"""

from __future__ import annotations

import hashlib
import json
import re
import struct
import subprocess
import sys
from bisect import bisect_right
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from elf_index import sections  # noqa: E402
from fde_extents import fde_extents  # noqa: E402

SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
SIZE = 105_896_032
TARGET = Path("artifacts/node/115/hl-node")
PACKET = Path(
    "research/work-items/RE-005-node115-tokio-waker-table")

RELOC_COUNTS = {"relative": 59_534, "glob_dat": 263,
                "jump_slot": 278, "total": 61_001}

DEBUG_VTABLE = 0x64C6458
DEBUG_DROP = 0x5CEE460
DEBUG_DROP_BYTES = 209
DEBUG_STUB = 0x5CA5610
DEBUG_STUB_GOT = 0x64E1878
DEBUG_BODY = 0x5CA7EA0

WAKER_TABLE = 0x64C6478
CLONE = 0x5CEE5A0
WAKE_FWD = 0x5CEE590
WAKE_BY_REF = 0x5CEE5C0
DROP_SHIM = 0x5CEE570

WAKE_CONSUME = 0x5CFC550
DRIVER_WAKE = 0x5CE09A0
DESTROY = 0x5CE86D0
FIELD_DROP_100 = 0x5CE7E50
FIELD_DROP_240 = 0x5CE7F40

GOT_DESTROY = 0x64DFDB8
GOT_WAKE = 0x64ECC68
GOT_TLS = 0x64E0510
TLS_FN = 0x5CA0D20
TLS_KEY = 0x5CDF410
GOT_PANIC_HELPER = 0x64DF6A0
PANIC_HELPER = 0x1680C30
GOT_PANIC_FMT = 0x64DF6B8
PANIC_FMT = 0x1680E80
FMT_SHIM = 0x1687260
DEALLOC_GOT = 0x64DF4A0

ALLOC_SIZE = 0x300
DATA_OFF = 0x80
FLAG_FROM_DATA = 0x150
TARGET_FROM_DATA = 0x1C0
FLAG_FROM_BASE = 0x1D0
TARGET_FROM_BASE = 0x240
FD_OFF = 0x44

DEBUG_VTABLE_SITES = [0x156F04C, 0x172D07C, 0x2A00AEC, 0x2E74219,
                      0x478118F, 0x59647C9, 0x5CE0A32]
CLONE_LEA_SITE = 0x5CEE5A7
PANIC_MESSAGE = "failed to wake I/O driver"
PANIC_FILE = ("/home/ubuntu/hl/code_Mainnet/z_vendor/tokio/src/"
              "runtime/io/driver.rs")
PANIC_LINE = 272


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
    mapping: dict[int, dict] = {}
    counts = {"relative": 0, "glob_dat": 0, "jump_slot": 0, "total": 0}
    for name in (".rela.dyn", ".rela.plt"):
        rela = secs[name]
        blob = data[rela["offset"]:rela["offset"] + rela["size"]]
        for off in range(0, len(blob), 24):
            addr, info, addend = struct.unpack_from("<QQq", blob, off)
            rtype = info & 0xFFFFFFFF
            counts["total"] += 1
            if rtype == 8:
                counts["relative"] += 1
            elif rtype == 6:
                counts["glob_dat"] += 1
            elif rtype == 7:
                counts["jump_slot"] += 1
            else:
                continue
            mapping[addr] = {"type": rtype, "addend": addend}
    return {"map": mapping, "counts": counts}


def body_map(data: bytes) -> dict[int, dict]:
    _, rows, _ = fde_extents(data)
    return {f["start"]: {"start": f["start"], "end": f["end"],
                         "bytes": f["end"] - f["start"]}
            for f in rows if f["end"] > f["start"]}


def cell(rel: dict, data: bytes, va: int) -> tuple[str, int]:
    entry = rel["map"].get(va)
    if entry and entry["type"] == 8:
        return "RELATIVE", entry["addend"]
    return "raw", struct.unpack("<Q", read(data, va, 8))[0]


def got(rel: dict, va: int) -> int:
    entry = rel["map"].get(va)
    require(entry is not None and entry["type"] == 8,
            f"GOT cell {hx(va)} is not a RELATIVE relocation")
    return entry["addend"]


def body_bytes(data: bytes, fdes: dict, start: int) -> bytes:
    fde = fdes.get(start)
    require(fde is not None, f"no FDE at {hx(start)}")
    return read(data, start, fde["bytes"])


def has(blob: bytes, pattern: bytes) -> bool:
    return pattern in blob


def call_targets(blob: bytes, start: int) -> list[int]:
    out = []
    for m in re.finditer(rb"\xe8(....)", blob, re.S):
        out.append(start + m.start() + 5
                   + struct.unpack("<i", m.group(1))[0])
    for m in re.finditer(rb"\xe9(....)", blob, re.S):
        out.append(start + m.start() + 5
                   + struct.unpack("<i", m.group(1))[0])
    return out


def got_calls(blob: bytes, start: int) -> list[int]:
    out = []
    for m in re.finditer(rb"\xff[\x15\x25](....)", blob, re.S):
        out.append(start + m.start() + 6
                   + struct.unpack("<i", m.group(1))[0])
    return out


def lea_refs(data: bytes, target: int) -> list[int]:
    text = next(s for s in sections(data) if s["name"] == ".text")
    tb = text["address"]
    raw = data[text["offset"]:text["offset"] + text["size"]]
    pat = re.compile(rb"[\x48\x4c]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]"
                     rb"....", re.S)
    sites = []
    for m in pat.finditer(raw):
        disp = struct.unpack_from("<i", raw, m.start() + 3)[0]
        if tb + m.start() + 7 + disp == target:
            sites.append(tb + m.start())
    return sites


def analyze(data: bytes) -> dict:
    require(len(data) == SIZE, "artifact size drifted")
    require(hashlib.sha256(data).hexdigest() == SHA256,
            "artifact sha256 drifted")
    rel = relocations(data)
    require(rel["counts"] == RELOC_COUNTS,
            f"relocation counts drifted: {rel['counts']}")
    fdes = body_map(data)

    # --- the Debug vtable: standalone extent-0x20 shape ----------
    kind, drop = cell(rel, data, DEBUG_VTABLE)
    require(kind == "RELATIVE" and drop == DEBUG_DROP,
            "debug vtable drop pin drifted")
    require(fdes[drop]["bytes"] == DEBUG_DROP_BYTES,
            "debug drop body size drifted")
    require(cell(rel, data, DEBUG_VTABLE + 8) == ("raw", 8),
            "debug vtable size pin drifted")
    require(cell(rel, data, DEBUG_VTABLE + 0x10) == ("raw", 8),
            "debug vtable align pin drifted")
    kind, stub = cell(rel, data, DEBUG_VTABLE + 0x18)
    require(kind == "RELATIVE" and stub == DEBUG_STUB,
            "debug stub pin drifted")
    require(got(rel, DEBUG_STUB_GOT) == DEBUG_BODY,
            "debug stub GOT resolution drifted")

    # --- the adjacent RawWakerVtable ------------------------------
    fields = []
    for i, (name, want) in enumerate(
            (("clone", CLONE), ("wake", WAKE_FWD),
             ("wake_by_ref", WAKE_BY_REF), ("drop", DROP_SHIM))):
        kind, val = cell(rel, data, WAKER_TABLE + 8 * i)
        require(kind == "RELATIVE" and val == want,
                f"waker table field {name} drifted")
        require(want in fdes, f"waker field body {name} has no FDE")
        fields.append({"field": name, "cell": hx(WAKER_TABLE + 8 * i),
                       "kind": kind, "target": hx(val),
                       "body_bytes": fdes[want]["bytes"]})

    clone = body_bytes(data, fdes, CLONE)
    require(has(clone, b"\xf0\x48\xff\x47\x80"),
            "clone: lock incq at data-0x80 not found")
    require(has(clone, b"\x0f\x0b"), "clone: overflow ud2 not found")
    lea_at = clone.find(b"\x48\x8d\x05")
    require(lea_at >= 0, "clone: lea rax not found")
    disp = struct.unpack_from("<i", clone, lea_at + 3)[0]
    require(CLONE + lea_at + 7 + disp == WAKER_TABLE,
            "clone: returned vtable pointer is not the table base")

    wake = body_bytes(data, fdes, WAKE_FWD)
    require(wake[:4] == b"\x48\x83\xc7\x80",
            "wake: data-0x80 adjustment not found")
    require(got_calls(wake, WAKE_FWD) == [GOT_WAKE],
            "wake: indirect jump slot drifted")
    require(got(rel, GOT_WAKE) == WAKE_CONSUME,
            "wake: consume body pin drifted")

    wbr = body_bytes(data, fdes, WAKE_BY_REF)
    require(has(wbr, b"\x86\x87\x50\x01\x00\x00"),
            "wake_by_ref: xchg flag at data+0x150 not found")
    require(has(wbr, b"\x48\x81\xc7\xc0\x01\x00\x00"),
            "wake_by_ref: data+0x1c0 adjustment not found")
    require(DRIVER_WAKE in call_targets(wbr, WAKE_BY_REF),
            "wake_by_ref: driver wake tail call not found")
    require(GOT_TLS in got_calls(wbr, WAKE_BY_REF)
            and got(rel, GOT_TLS) == TLS_FN,
            "wake_by_ref: thread-local consult drifted")
    require(not has(wbr, b"\xf0\x48\xff"),
            "wake_by_ref: unexpected atomic count op")

    dshim = body_bytes(data, fdes, DROP_SHIM)
    require(has(dshim, b"\x48\x8d\x47\x80"),
            "drop shim: lea data-0x80 not found")
    require(has(dshim, b"\xf0\x48\xff\x4f\x80"),
            "drop shim: lock decq at data-0x80 not found")
    require(GOT_DESTROY in got_calls(dshim, DROP_SHIM)
            and got(rel, GOT_DESTROY) == DESTROY,
            "drop shim: destroy call drifted")

    consume = body_bytes(data, fdes, WAKE_CONSUME)
    require(has(consume, b"\x86\x87\xd0\x01\x00\x00"),
            "wake consume: xchg flag at base+0x1d0 not found")
    require(has(consume, b"\x48\x81\xc7\x40\x02\x00\x00"),
            "wake consume: base+0x240 adjustment not found")
    require(DRIVER_WAKE in call_targets(consume, WAKE_CONSUME),
            "wake consume: driver wake call not found")
    require(has(consume, b"\xf0\x48\xff\x08"),
            "wake consume: consuming strong dec not found")
    require(GOT_DESTROY in got_calls(consume, WAKE_CONSUME),
            "wake consume: destroy call not found")
    require(FLAG_FROM_DATA + DATA_OFF == FLAG_FROM_BASE
            and TARGET_FROM_DATA + DATA_OFF == TARGET_FROM_BASE,
            "data/base offset identities broken")

    destroy = body_bytes(data, fdes, DESTROY)
    require(has(destroy, b"\xbe\x00\x03\x00\x00"),
            "destroy: allocation size 0x300 not found")
    require(has(destroy, b"\xf0\x48\xff\x4b\x08"),
            "destroy: weak count dec at +0x08 not found")
    require(FIELD_DROP_100 in call_targets(destroy, DESTROY)
            and FIELD_DROP_240 in call_targets(destroy, DESTROY),
            "destroy: field drop calls drifted")
    require(got_calls(destroy, DESTROY).count(DEALLOC_GOT) >= 3,
            "destroy: dealloc calls drifted")

    driver = body_bytes(data, fdes, DRIVER_WAKE)
    require(has(driver, b"\x83\x7f\x44\xff"),
            "driver wake: fd == -1 check at +0x44 not found")
    require(GOT_PANIC_HELPER in got_calls(driver, DRIVER_WAKE)
            and got(rel, GOT_PANIC_HELPER) == PANIC_HELPER,
            "driver wake: panic helper call drifted")
    require(DEBUG_DROP in call_targets(driver, DRIVER_WAKE),
            "driver wake: landing-pad error drop not found")

    helper = body_bytes(data, fdes, PANIC_HELPER)
    require(GOT_PANIC_FMT in got_calls(helper, PANIC_HELPER)
            and got(rel, GOT_PANIC_FMT) == PANIC_FMT,
            "panic helper: panic_fmt call drifted")
    shim = body_bytes(data, fdes, FMT_SHIM)
    require(has(shim, b"\x48\x8b\x49\x18") and has(shim, b"\xff\xe1"),
            "fmt shim: vtable +0x18 dispatch not found")

    # --- census -----------------------------------------------------
    waker_refs = lea_refs(data, WAKER_TABLE)
    require(waker_refs == [CLONE_LEA_SITE],
            f"waker table reference census drifted: "
            f"{[hx(s) for s in waker_refs]}")
    debug_refs = lea_refs(data, DEBUG_VTABLE)
    require(debug_refs == DEBUG_VTABLE_SITES,
            "debug vtable reference census drifted")
    addend_refs = [a for a, e in rel["map"].items()
                   if e["type"] == 8
                   and e["addend"] in (WAKER_TABLE, DEBUG_VTABLE)]
    require(not addend_refs,
            "a relocation addend names a table base")

    return {
        "answers": {
            "extent_corrected": hx(0x20),
            "h15_measured_extent": hx(0x40),
            "table_at_base_plus_0x20": "core::task::RawWakerVTable",
            "fields": ["clone", "wake", "wake_by_ref", "drop"],
            "waker_owner": "tokio I/O driver shared inner state",
        },
        "artifact": {"sha256": SHA256, "size": SIZE},
        "relocation_counts": rel["counts"],
        "debug_vtable": {
            "base": hx(DEBUG_VTABLE), "drop": hx(DEBUG_DROP),
            "drop_bytes": fdes[DEBUG_DROP]["bytes"],
            "size": 8, "align": 8,
            "debug_slot": {"offset": hx(0x18), "kind": "RELATIVE",
                           "target": hx(DEBUG_STUB),
                           "body": hx(DEBUG_BODY)},
            "references": [hx(s) for s in debug_refs],
            "reference_kind": "panic-format sites only",
        },
        "raw_waker_vtable": {
            "base": hx(WAKER_TABLE), "fields": fields,
            "references": [hx(s) for s in waker_refs],
            "reference_kind": "the lea inside clone only",
            "clone": {
                "strong_inc_at": "data-0x80",
                "overflow": "ud2 abort",
                "returns": {"rax": hx(WAKER_TABLE), "rdx": "data"},
            },
            "wake": {
                "adjusts": "data-0x80",
                "body": hx(WAKE_CONSUME),
                "consumes_strong_ref": True,
            },
            "wake_by_ref": {
                "flag_xchg_at": "data+0x150",
                "wake_target_at": "data+0x1c0",
                "touches_count": False,
            },
            "drop": {"strong_dec_at": "data-0x80",
                     "destroy": hx(DESTROY)},
        },
        "allocation": {
            "size": hx(ALLOC_SIZE), "strong_at": hx(0),
            "weak_at": hx(8), "data_pointer_at": hx(DATA_OFF),
            "woken_flag_at": hx(FLAG_FROM_BASE),
            "wake_target_at": hx(TARGET_FROM_BASE),
            "wake_target_fd_at": hx(TARGET_FROM_BASE + FD_OFF),
            "destroy": hx(DESTROY),
            "destroy_bytes": fdes[DESTROY]["bytes"],
            "field_drops": [hx(FIELD_DROP_100), hx(FIELD_DROP_240)],
        },
        "wake_path": {
            "consume_body": hx(WAKE_CONSUME),
            "consume_bytes": fdes[WAKE_CONSUME]["bytes"],
            "driver_wake_body": hx(DRIVER_WAKE),
            "driver_wake_bytes": fdes[DRIVER_WAKE]["bytes"],
            "thread_local": {"got": hx(GOT_TLS), "fn": hx(TLS_FN),
                             "key": hx(TLS_KEY)},
            "panic": {"message": PANIC_MESSAGE, "file": PANIC_FILE,
                      "line": PANIC_LINE},
        },
        "panic_format_path": {
            "helper": hx(PANIC_HELPER), "panic_fmt": hx(PANIC_FMT),
            "fmt_shim": hx(FMT_SHIM),
            "slot_used": hx(0x18),
        },
        "limitations": [
            "No DWARF type names in the binary: the allocation is "
            "attributed to the tokio I/O driver's inner state from "
            "the wake body's panic location and the field layout, "
            "not from a name.",
            "The thread-local cell (TLS slot -0x1130) is pinned by "
            "its consult pattern and key only; the parker value "
            "object behind it is RE-005 #2935's subject, not "
            "re-identified here.",
            "The 8 bytes at the data pointer (alloc+0x80) are never "
            "dereferenced by the four waker functions; any role "
            "other code gives that field is out of scope.",
            "Static records only; nothing was executed.",
        ],
    }


def objdump(start: int, size: int) -> bytes:
    proc = subprocess.run(
        ["objdump", "-d", f"--start-address={start}",
         f"--stop-address={start + size}", str(TARGET)],
        check=True, capture_output=True)
    return proc.stdout


def export_bodies(records: dict) -> dict[str, tuple[int, int]]:
    fmap = {f["field"]: f for f in records["raw_waker_vtable"]["fields"]}
    out = {
        "clone": (CLONE, fmap["clone"]["body_bytes"]),
        "wake_forwarder": (WAKE_FWD, fmap["wake"]["body_bytes"]),
        "wake_by_ref": (WAKE_BY_REF, fmap["wake_by_ref"]["body_bytes"]),
        "drop_shim": (DROP_SHIM, fmap["drop"]["body_bytes"]),
        "wake_consume": (WAKE_CONSUME,
                         records["wake_path"]["consume_bytes"]),
        "driver_wake": (DRIVER_WAKE,
                        records["wake_path"]["driver_wake_bytes"]),
        "destroy": (DESTROY, records["allocation"]["destroy_bytes"]),
        "fmt_shim": (FMT_SHIM, 16),
        "panic_helper": (PANIC_HELPER, 0x53),
    }
    return out


def generate() -> dict:
    data = TARGET.read_bytes()
    records = analyze(data)
    packet = PACKET
    packet.mkdir(parents=True, exist_ok=True)
    (packet / "records.json").write_text(
        json.dumps(records, indent=2, sort_keys=True) + "\n")
    for role, (start, size) in sorted(export_bodies(records).items()):
        (packet / f"{role}.objdump.txt").write_bytes(
            objdump(start, size))
    digests = []
    for path in sorted(packet.iterdir()):
        if path.name == "MANIFEST.sha256":
            continue
        digests.append(
            f"{hashlib.sha256(path.read_bytes()).hexdigest()}  "
            f"{path.name}")
    (packet / "MANIFEST.sha256").write_text("\n".join(digests) + "\n")
    return records


def main() -> int:
    if sys.argv[1:] == ["generate"]:
        generate()
        print(f"wrote {PACKET}")
        return 0
    if sys.argv[1:] == ["check"]:
        records = analyze(TARGET.read_bytes())
        retained = json.loads((PACKET / "records.json").read_text())
        require(records == retained, "records drifted")
        print("tokio waker table records match the materialized "
              "artifact")
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
