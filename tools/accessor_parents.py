#!/usr/bin/env python3
"""Pin the parent traits/roles of the accessor/store/clone bodies
that the shared-Debug-vtable census (RE-005 node115, PR #3141)
recorded as its closing boundary.

The census catalogued 33 reference sites whose bodies return,
store, or clone the (data, vtable) pair of an error trait object,
but did not say which parent trait or concrete type each body
serves.  This tool re-derives every parent vtable from the binary
(relocation-applied .data.rel.ro headers), names the slot layout
of the shared parent family, and records the identification
evidence (Debug/Display string pins, per-type 16-byte constants,
panic-Location neighbourhoods, construction xrefs) for the five
enum-accessor parents, the six field-accessor parents, the seven
pair-store bodies and the three pair-clone bodies.

Usage:
    python3 tools/accessor_parents.py generate
    python3 tools/accessor_parents.py check
"""

import hashlib
import json
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
PACKET = Path("research/work-items/RE-005-node115-accessor-parent-traits")

DESCRIPTION_TEXT = b"description() is deprecated; use Display"

# The extended io-error vtable (one of the 32 pinned by the census
# packet) and the ErrorStack vtable, both targets of the enum
# accessors' pair returns.
IO_VTABLE = 0x63F8F58
ERRORSTACK_VTABLE = 0x63F8FD0
NONE_BODY = 0x14C5840  # 3-byte `xor eax,eax; ret` pair-null body

# --- pinned identification evidence -------------------------------------

# (string va, expected prefix) pairs read out of the bodies by hand.
# The fmt pieces are (ptr, len) slices into packed string blobs, so
# each va is the start of the named piece, not of a NUL-terminated
# string.
P2_DEBUG_STRINGS = [(0x4645E7, b"Error"), (0x459E80, b"code"),
                    (0x464B87, b"cause")]
P5_DEBUG_STRINGS = [(0x94DFBA, b"Error"), (0x459E80, b"code"),
                    (0x94DFBF, b"cause")]
P1_DISPLAY_STRINGS = [
    (0x7E03F0, b"at least one certificate must be provided"),
    (0x7E042F, b"expected PKCS#8 PEM"),
]
ERRORSTACK_DEBUG_STRINGS = [(0x464B7D, b"ErrorStack"),
                            (0x46E7C4, b"(")]
ERRORSTACK_DISPLAY_STRINGS = [(0x93F86F, b"OpenSSL error"),
                              (0x93F87C, b", ")]

# Enum-accessor parents in census order (P1..P5 of the analysis):
# base -> (identity, basis)
ENUM_IDENTITIES = {
    0x63F9240: (
        "vendored native-tls OpenSSL backend error enum "
        "(imp/openssl.rs Error)",
        "40-byte Self; Debug body 0x475bee0 dispatches through a "
        "4-entry jump table writing the variant names Normal / Ssl "
        "/ EmptyChain / NotPkcs8 in declaration order; Display body "
        "0x475c850 writes the native-tls identity strings and "
        "delegates to the ErrorStack Display; drop 0x14c4a90 "
        "dispatches on the same marker words"),
    0x63F9150: (
        "openssl::ssl::Error",
        "32-byte Self; Debug body 0x14cafa0 writes the struct name "
        "Error with fields code (ErrorCode at +0x18) and cause "
        "(the tagged word at +0); Display is the shared openssl "
        "error Display body 0x5badac0; drop 0x14c4f20 frees the "
        "ErrorStack Vec at +0 or tail-drops the io error at +8 "
        "by the same tag word the accessors read"),
    0x640E648: (
        "vendored native-tls OpenSSL backend error enum "
        "(imp/openssl.rs Error), tokio-side instantiation",
        "same Debug body 0x475bee0 and Display body 0x475c850 as "
        "the 0x63f9240 parent; the surrounding bodies panic in "
        "z_vendor/tokio-native-tls/src/lib.rs (line 124)"),
    0x644E7F8: (
        "vendored native-tls OpenSSL backend error enum "
        "(imp/openssl.rs Error), further instantiation",
        "same Debug body 0x475bee0 and Display body 0x475c850 as "
        "the 0x63f9240 parent; own drop 0x2c954f0 of the same "
        "marker-dispatch template"),
    0x64C7438: (
        "openssl::ssl::Error, further instantiation",
        "Debug body 0x5d01740 writes the same struct name Error "
        "and the same field names code / cause as 0x14cafa0; "
        "Display is the shared openssl error Display body "
        "0x5badac0; drop 0x5d01340"),
}

# Field-accessor parents (Q1..Q5 plus the std-CGU instance): the
# io-returning accessor of the census sits in one of the repeated
# six-method groups of one Error-subtrait vtable per concrete type.
FIELD_PARENTS = [0x6444B60, 0x64845C0, 0x6494F80, 0x6496A80,
                 0x649E3F0, 0x63FA140]
FIELD_ACCESSOR_SLOT = {0x6444B60: 0xF0, 0x64845C0: 0xF0,
                       0x6494F80: 0x90, 0x6496A80: 0xF0,
                       0x649E3F0: 0xF0, 0x63FA140: 0x270}
FIELD_OFFSET = 0x38

# Pair-store bodies: body -> census store sites (from PR #3141).
STORE_BODIES = {
    0x15E12A0: [0x15E143F, 0x15E15DB],
    0x1741D30: [0x1741F47, 0x174201B],
    0x2CCA8D0: [0x2CCA9A6, 0x2CCAA71],
    0x2CCAAF0: [0x2CCABA3, 0x2CCAC83],
    0x2E73C80: [0x2E73D64, 0x2E73E3B],
    0x2E7DB50: [0x2E7DC9E, 0x2E7DD73],
    0x2E86150: [0x2E86177, 0x2E86271],
}
# Pair-clone bodies: body -> census call sites.
CLONE_BODIES = {
    0x15AEA00: [0x15AEBCF],
    0x1750FB0: [0x17511B1],
    0x2B11B80: [0x2B11D64],
}

# Construction xrefs (rip-relative references into the vtable
# bases), measured with a full .text scan of the pinned binary.
XREF_EVIDENCE = [
    {"vtable": "0x6444b60",
     "site": "0x2e7e54a", "inside_body": "0x2e7db50",
     "note": "the hyper-fork connect pair-store body also "
             "constructs this trait object"},
    {"vtable": "0x6444b60",
     "site": "0x2e7e6c2", "inside_body": "0x2e7db50",
     "note": "second construction site in the same body"},
    {"vtable": "0x6444b60",
     "site": "0x2e861ec", "inside_body": "0x2e86150",
     "note": "the 0x2e86150 pair-store body also constructs "
             "this trait object"},
    {"vtable": "0x6444980",
     "site": "0x3f8bd8e", "inside_body": "0x3f8bba0",
     "note": "sibling vtable (same delegation-shim prefix, "
             "80-byte Self) constructed in a body whose panic "
             "Location is z_vendor/tokio-openssl/src/lib.rs:752"},
]

BOUNDARY = [
    "The Error-subtrait behind the six field-accessor parents is "
    "not named anywhere in the binary: no string or panic "
    "Location names it, and its method bodies are generic glue "
    "(delegation shims, a TypeId-keyed field lookup, drop glue). "
    "Its vtable layout, group structure and construction "
    "neighbourhood (vendored hyper/tokio-openssl connect stack) "
    "are pinned; its source-level name is not recoverable.",
    "For the native-tls enum parents the variant-to-arm "
    "correspondence of the source() slots is pinned only at the "
    "level of the observed words: word 0x8000000000000000 yields "
    "(self+8, io vtable), a small/pointer word yields (self+0, "
    "ErrorStack vtable), 0x8000000000000001 and words >= "
    "0x8000000000000002 yield None.  Which named variant owns the "
    "small-word arm is not asserted: the Debug jump table maps "
    "the small-word arm to Ssl (formatting the value at +0x20) "
    "while the accessor returns the word at +0 as an ErrorStack.",
    "The pair-store and pair-clone bodies are large functions "
    "(215-3229 bytes) with no panic Location of their own except "
    "0x2e7db50 (socket2 socket.rs:105 and the hyper-fork HTTP "
    "connect code); their argument/return shapes and the two "
    "construction xrefs into the field-parent family are pinned, "
    "their source-level identities are not.",
    "Three slot bodies are shared between the io vtables of the "
    "census packet and these parents (the +0x38 TypeId writer "
    "0x14c5950, the +0x40 description body 0x14c5750, the +0x50 "
    "provide body 0x14c58a0).  They appear here only as slot-role "
    "evidence for the parents; the io-vtable census itself is "
    "PR #3141's subject and is not re-claimed.",
]


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
    sec = next(s for s in sections(data) if s["name"] == ".rela.dyn")
    out = {"map": {}}
    raw = data[sec["offset"]:sec["offset"] + sec["size"]]
    for i in range(0, len(raw), 24):
        off, info, addend = struct.unpack_from("<QQq", raw, i)
        out["map"][off] = {"type": info & 0xFFFFFFFF, "addend": addend}
    return out


def body_map(data: bytes) -> dict:
    _, rows, _ = fde_extents(data)
    return {f["start"]: {"start": f["start"], "end": f["end"],
                         "bytes": f["end"] - f["start"]}
            for f in rows if f["end"] > f["start"]}


def cell(rel: dict, data: bytes, va: int):
    entry = rel["map"].get(va)
    if entry and entry["type"] == 8:
        return "RELATIVE", entry["addend"]
    return "raw", struct.unpack("<Q", read(data, va, 8))[0]


def is_header(rel: dict, data: bytes, fdes: dict, va: int) -> bool:
    k0, v0 = cell(rel, data, va)
    k1, v1 = cell(rel, data, va + 8)
    k2, v2 = cell(rel, data, va + 0x10)
    return (k0 == "RELATIVE" and v0 in fdes and k1 == "raw"
            and k2 == "raw" and 0 < v1 <= 0x100000
            and v2 in (1, 2, 4, 8, 16, 32, 64, 128))


def header_bases(rel: dict, data: bytes, fdes: dict) -> list:
    sec = next(s for s in sections(data) if s["name"] == ".data.rel.ro")
    return [va for va in range(sec["address"],
                               sec["address"] + sec["size"], 8)
            if is_header(rel, data, fdes, va)]


def extent_of(rel: dict, data: bytes, fdes: dict, bases: list,
              bset: set, base: int) -> int:
    limit = next((b for b in bases if b > base), None)
    ext = 0x18
    while True:
        va = base + ext
        if limit is not None and va >= limit:
            break
        entry = rel["map"].get(va)
        if entry is None:
            break
        if entry["type"] == 8 and entry["addend"] in fdes:
            ext += 8
            continue
        if entry["type"] == 8 and entry["addend"] in bset:
            ext += 8
            continue
        break
    return ext


def slots_of(rel: dict, data: bytes, base: int, extent: int) -> list:
    out = []
    for off in range(0x18, extent, 8):
        kind, val = cell(rel, data, base + off)
        out.append({"offset": hx(off),
                    "target": hx(val) if kind == "RELATIVE"
                    else None})
    return out


def type_id_const(data: bytes, body: int) -> str:
    """The +0x38 slot body is 14 bytes:
    mov rax,rdi ; movups xmm0,[rip+disp] ; movups [rdi],xmm0 ; ret
    It writes the concrete type's 16-byte constant through rdi."""
    raw = read(data, body, 14)
    require(raw[0:3] == b"\x48\x89\xf8" and raw[3:6] == b"\x0f\x10\x05"
            and raw[10:13] == b"\x0f\x11\x07" and raw[13] == 0xC3,
            f"type-id body shape changed at {hx(body)}")
    disp = struct.unpack_from("<i", raw, 6)[0]
    src = body + 10 + disp
    return read(data, src, 16).hex()


def description_string_va(data: bytes, body: int) -> int:
    """The +0x40 slot body is 13 bytes:
    lea rax,[rip+disp] ; mov edx,0x28 ; ret  (a &'static str)."""
    raw = read(data, body, 13)
    require(raw[0:3] == b"\x48\x8d\x05" and raw[7:12]
            == b"\xba\x28\x00\x00\x00" and raw[12] == 0xC3,
            f"description body shape changed at {hx(body)}")
    disp = struct.unpack_from("<i", raw, 3)[0]
    src = body + 7 + disp
    require(read(data, src, len(DESCRIPTION_TEXT)) == DESCRIPTION_TEXT,
            f"description string changed at {hx(body)}")
    return src


def body_bytes(fdes: dict, va: int):
    f = fdes.get(va)
    return f["bytes"] if f else None


def parent_record(rel, data, fdes, bases, bset, base):
    _, drop = cell(rel, data, base)
    _, size = cell(rel, data, base + 8)
    _, align = cell(rel, data, base + 0x10)
    extent = extent_of(rel, data, fdes, bases, bset, base)
    slots = {}
    by_off = {}
    for s in slots_of(rel, data, base, extent):
        by_off[int(s["offset"], 16)] = s["target"]
    for off in (0x18, 0x20, 0x28, 0x30, 0x38, 0x40, 0x48, 0x50):
        tgt = by_off.get(off)
        rec = {"target": tgt}
        if tgt is not None:
            rec["body_bytes"] = body_bytes(fdes, int(tgt, 16))
        slots[hx(off)] = rec
    return {"vtable": hx(base), "drop": hx(drop),
            "drop_body_bytes": body_bytes(fdes, drop),
            "self_size": size, "self_align": align,
            "extent": hx(extent), "slots": slots,
            "slot_targets": by_off}


def analyze(data: bytes) -> dict:
    require(hashlib.sha256(data).hexdigest() == SHA256,
            "binary digest is not the pinned node115 distribution")
    require(len(data) == SIZE, "binary size changed")
    rel = relocations(data)
    fdes = body_map(data)
    bases = header_bases(rel, data, fdes)
    bset = set(bases)

    layout = [
        {"offset": "0x18", "role": "Debug::fmt of the concrete type"},
        {"offset": "0x20", "role": "Display::fmt of the concrete type"},
        {"offset": "0x28",
         "role": "upcast cell: points at the Display-only sibling "
                 "vtable at base-0x20"},
        {"offset": "0x30",
         "role": "Error::source - returns (data, vtable) pair or None"},
        {"offset": "0x38",
         "role": "hidden type_id slot - writes the concrete type's "
                 "16-byte TypeId constant through the out pointer"},
        {"offset": "0x40",
         "role": "deprecated Error::description - every parent uses "
                 "the default body returning the deprecation string"},
        {"offset": "0x48",
         "role": "deprecated Error::cause - same body logic as "
                 "source for these types"},
        {"offset": "0x50",
         "role": "Error::provide - default no-op (1-byte ret) for "
                 "every parent here"},
    ]

    enum_parents = []
    family_consts = {}
    for base in sorted(ENUM_IDENTITIES):
        name, basis = ENUM_IDENTITIES[base]
        rec = parent_record(rel, data, fdes, bases, bset, base)
        by_off = rec.pop("slot_targets")
        require(int(by_off[0x28], 16) == base - 0x20,
                f"sibling rule broken at {hx(base)}")
        tid_body = int(by_off[0x38], 16)
        const = type_id_const(data, tid_body)
        family = ("ssl" if name.startswith("openssl::ssl")
                  else "native-tls")
        if family in family_consts:
            require(family_consts[family] == const,
                    "type-id constant must be a per-type value: "
                    "equal for every vtable of one concrete type")
        else:
            require(const not in family_consts.values(),
                    "type-id constants must differ across types")
            family_consts[family] = const
        desc_va = description_string_va(data, int(by_off[0x40], 16))
        rec["slots"]["0x38"]["type_id_const"] = const
        rec["slots"]["0x40"]["string_va"] = hx(desc_va)
        rec["source_body"] = by_off[0x30]
        rec["cause_body"] = by_off[0x48]
        rec["source_cause_same_body"] = by_off[0x30] == by_off[0x48]
        rec["identity"] = name
        rec["identity_basis"] = basis
        enum_parents.append(rec)

    # The ErrorStack vtable the small-word accessor arm returns.
    es = parent_record(rel, data, fdes, bases, bset, ERRORSTACK_VTABLE)
    es_by = es.pop("slot_targets")
    require(int(es_by[0x30], 16) == NONE_BODY
            and int(es_by[0x48], 16) == NONE_BODY,
            "ErrorStack must be a leaf error (source/cause = None)")
    es["identity"] = "openssl::error::ErrorStack"
    es["identity_basis"] = (
        "24-byte Vec Self; Debug body writes 'ErrorStack(' and "
        "Display body writes 'OpenSSL error' / ', '; source and "
        "cause are the shared 3-byte None body")

    field_parents = []
    for base in FIELD_PARENTS:
        rec = parent_record(rel, data, fdes, bases, bset, base)
        by_off = rec.pop("slot_targets")
        extent = int(rec["extent"], 16)
        require((extent - 0x58) % 0x30 == 0,
                f"group stride broken at {hx(base)}")
        groups = (extent - 0x58) // 0x30
        slot = FIELD_ACCESSOR_SLOT[base]
        acc = by_off[slot]
        require(acc is not None, f"field accessor missing {hx(base)}")
        rec["groups"] = groups
        rec["field_accessor"] = {
            "slot_offset": hx(slot), "body": acc,
            "body_bytes": body_bytes(fdes, int(acc, 16)),
            "field_offset": hx(FIELD_OFFSET),
            "returns_vtable": hx(IO_VTABLE)}
        # The accessor body is the 12-byte pair-return shape:
        # lea rax,[rdi+0x38]; lea rdx,[io vtable]; ret
        raw = read(data, int(acc, 16), 12)
        require(raw[0:4] == b"\x48\x8d\x47\x38",
                f"field accessor shape changed at {hx(base)}")
        rec["identity"] = (
            "one concrete type implementing the shared "
            "Error-subtrait (see big_trait_layout); the trait's "
            "source name is not in the binary")
        field_parents.append(rec)

    big_trait = {
        "prefix": "the std::error::Error vtable layout above "
                  "(offsets 0x18..0x50)",
        "own_method_at_0x58": "one method (114-183 bytes across "
                              "instances) whose body is drop glue "
                              "over the Self layout",
        "group_stride": "0x30",
        "group_slots": [
            "field accessor: returns (self+0x38, per-group vtable)",
            "pair return: returns (self, per-group sibling vtable)",
            "33-byte keyed lookup: compares a 16-byte key against "
            "a per-group constant; returns self+0x38 on equality, "
            "null otherwise",
            "72-141 byte worker body (drop glue)",
            "3-byte body returning 0",
            "72-141 byte worker body (drop glue)",
        ],
        "instances": [{"vtable": r["vtable"], "self_size":
                       r["self_size"], "groups": r["groups"]}
                      for r in field_parents],
        "debug_display": "delegation shims: load Self's first "
                         "word, call through [word+8], then tail-"
                         "dispatch on the third argument's vtable - "
                         "the wrappers forward their Error "
                         "formatting to an inner object",
    }

    stores = []
    for body, sites in sorted(STORE_BODIES.items()):
        stores.append({
            "body": hx(body), "body_bytes": body_bytes(fdes, body),
            "sites": [hx(s) for s in sites],
            "pattern": "saves (rdi, rsi) on the stack, allocates "
                       "8 bytes, then stores the (data, vtable) "
                       "pair with one MOVAPS store; six of the "
                       "seven sites' instruction streams also free "
                       "a previous pair's contents through the "
                       "shared dealloc slot"})
    clones = []
    for body, sites in sorted(CLONE_BODIES.items()):
        clones.append({
            "body": hx(body), "body_bytes": body_bytes(fdes, body),
            "sites": [hx(s) for s in sites],
            "pattern": "takes the destination pair slot and the "
                       "source pair among its first arguments and "
                       "produces a fresh (data, vtable) pair; at "
                       "each census call site the returned pair is "
                       "consumed in rax:rdx"})

    for va, want in (P2_DEBUG_STRINGS + P5_DEBUG_STRINGS
                     + P1_DISPLAY_STRINGS
                     + ERRORSTACK_DEBUG_STRINGS
                     + ERRORSTACK_DISPLAY_STRINGS):
        require(read(data, va, len(want)) == want,
                f"evidence string moved at {hx(va)}")

    return {
        "packet": PACKET.as_posix(),
        "binary": {"path": TARGET.as_posix(), "size": SIZE,
                   "sha256": SHA256},
        "error_vtable_layout": layout,
        "description_text": DESCRIPTION_TEXT.decode(),
        "enum_parents": enum_parents,
        "error_stack_vtable": es,
        "field_parents": field_parents,
        "big_trait_layout": big_trait,
        "store_bodies": stores,
        "clone_bodies": clones,
        "xref_evidence": XREF_EVIDENCE,
        "boundary": BOUNDARY,
    }


def canonical(payload: dict) -> str:
    return json.dumps(payload, indent=1, sort_keys=True) + "\n"


def main(argv):
    if len(argv) != 2 or argv[1] not in ("generate", "check"):
        print(__doc__)
        return 2
    data = TARGET.read_bytes()
    payload = analyze(data)
    out = PACKET / "records.json"
    if argv[1] == "generate":
        out.write_text(canonical(payload))
        print(f"wrote {out}")
    else:
        require(out.read_text() == canonical(payload),
                "records.json differs from the binary-derived "
                "payload")
        print("records.json matches the binary-derived payload")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
