#!/usr/bin/env python3
"""Pin the K six-slot groups of the Error-subtrait vtables that
the accessor-parent packet (RE-005 node115, PR #3171) recorded
structurally but left semantically open.

That packet showed six vtables (plus two further members of the
same family found here) whose layout is a std::error::Error
prefix, one own method at +0x58, and K identical six-slot groups,
but it identified only one slot of one group per vtable (the
io::Error field accessor).  This tool re-derives the whole
family from the binary and records, for every group of every
member, what each of the six slots is: the two trait-object
returns, the 16-byte keyed probe and what its key constant is,
and the two drop shims and the object sizes they free.

Usage:
    python3 tools/subtrait_groups.py generate
    python3 tools/subtrait_groups.py check
"""

import hashlib
import json
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from elf_index import sections  # noqa: E402
from fde_extents import fde_extents  # noqa: E402

SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
SIZE = 105_896_032
TARGET = Path("artifacts/node/115/hl-node")
PACKET = Path("research/work-items/RE-005-node115-subtrait-group-slots")

DESCRIPTION_TEXT = b"description() is deprecated; use Display"
IO_TYPE_ID = "f8dfacffdf56f26d91c0b01aa4986406"

# The family: every vtable in the binary with the Error prefix,
# a method cell at +0x58 and a whole number of six-slot groups.
FAMILY = {
    0x63FA140: 15, 0x6408B48: 1, 0x640A448: 5, 0x6444B60: 8,
    0x64845C0: 4, 0x6494F80: 2, 0x6496A80: 4, 0x649E3F0: 7,
}

# The two group keys that are not the accessor type's own
# TypeId constant.  Both are shared .rodata constants, used by
# every member that carries the role.
KEY_EXCEPTIONS = {
    "6d5dcbd62c50eb637841a657711b8bb9": "0x4503e0",
    "2e6aeecefc4513bb1dec1078a58555b5": "0x454c30",
}

# Measured slot-5 exceptions to the next-pair size rule: none.
# Every non-terminal slot-5 shim either frees exactly the next
# group's pair size or calls that type's own vtable drop body.
SLOT5_EXCEPTIONS = []

BOUNDARY = [
    "The subtrait's source-level name is not in the binary "
    "(PR #3171's boundary stands): no string or panic Location "
    "names it, and the group bodies are generic glue.  What this "
    "packet adds is the per-slot semantics of its groups, not "
    "the name.",
    "Two of the recurring group keys (at .rodata 0x4503e0 and "
    "0x454c30) are not the TypeId constant of the group's "
    "accessor type, nor of any vtable in the binary: the type "
    "they name has no dyn vtable here, so the probe's target "
    "type for those two roles is identified only by its shared "
    "16-byte key constant.",
    "The last group's sixth slot is the vtable's boundary "
    "cell: the measured extent ends there, and the cell holds "
    "the next header's drop pointer, a code address with no "
    "FDE record, or zero, depending on the member.  It is "
    "recorded as a boundary cell, not classified as a group "
    "body.",
    "Virtual call sites of the group slots cannot be "
    "attributed by displacement alone: the offsets 0x60.. are "
    "used by hundreds of unrelated bodies calling through "
    "other vtables, so no caller census is claimed.",
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
    out = {}
    raw = data[sec["offset"]:sec["offset"] + sec["size"]]
    for i in range(0, len(raw), 24):
        off, info, addend = struct.unpack_from("<QQq", raw, i)
        out[off] = {"type": info & 0xFFFFFFFF, "addend": addend}
    return out


def body_map(data: bytes) -> dict:
    _, rows, _ = fde_extents(data)
    return {f["start"]: {"start": f["start"], "end": f["end"],
                         "bytes": f["end"] - f["start"]}
            for f in rows if f["end"] > f["start"]}


def cell(rel: dict, data: bytes, va: int) -> int:
    entry = rel.get(va)
    if entry and entry["type"] == 8:
        return entry["addend"]
    return struct.unpack("<Q", read(data, va, 8))[0]


def cell_is_relative(rel: dict, va: int) -> bool:
    entry = rel.get(va)
    return bool(entry and entry["type"] == 8)


def is_header(rel: dict, data: bytes, fdes: dict, va: int) -> bool:
    entry = rel.get(va)
    if entry and entry["type"] == 8:
        if entry["addend"] not in fdes:
            return False
    elif struct.unpack("<Q", read(data, va, 8))[0] != 0:
        return False
    v1 = cell(rel, data, va + 8)
    v2 = cell(rel, data, va + 0x10)
    return 0 < v1 <= 0x100000 and v2 in (1, 2, 4, 8, 16, 32, 64, 128)


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
        entry = rel.get(va)
        if entry is None:
            break
        if entry["type"] == 8 and (entry["addend"] in fdes
                                   or entry["addend"] in bset):
            ext += 8
            continue
        break
    return ext


def type_id_const(rel: dict, data: bytes, fdes: dict, vt: int):
    """The +0x38 slot body of an Error-family vtable is the
    14-byte writer: mov rax,rdi; movups xmm0,[rip+d];
    movups [rdi],xmm0; ret.  Returns the 16-byte constant it
    writes, or None when the body has another shape."""
    body = cell(rel, data, vt + 0x38)
    if body not in fdes:
        return None
    raw = read(data, body, 14)
    if raw[0:3] == b"\x48\x89\xf8" and raw[3:6] == b"\x0f\x10\x05" \
            and raw[10:13] == b"\x0f\x11\x07" and raw[13] == 0xC3:
        disp = struct.unpack_from("<i", raw, 6)[0]
        return read(data, body + 10 + disp, 16).hex()
    return None


def is_error_vtable(rel: dict, data: bytes, fdes: dict, vt: int) -> bool:
    """Error-family markers: +0x28 upcast cell points at the
    sibling at base-0x20; the +0x38 slot is the 14-byte type-id
    writer; the +0x50 body is the 1-byte ret provide() default.
    (The +0x40 description slot is not a marker: most types use
    the shared default body, but at least one accessor type in
    the family carries a hand-written description().)"""
    if cell(rel, data, vt + 0x28) != vt - 0x20:
        return False
    if type_id_const(rel, data, fdes, vt) is None:
        return False
    provide = cell(rel, data, vt + 0x50)
    return provide in fdes and fdes[provide]["bytes"] == 1 \
        and read(data, provide, 1) == b"\xc3"


def description_is_default(rel: dict, data: bytes, fdes: dict,
                           vt: int) -> bool:
    """True when the +0x40 slot is the shared 13-byte default
    body returning the deprecation string."""
    body = cell(rel, data, vt + 0x40)
    if body not in fdes:
        return False
    raw = read(data, body, 13)
    if not (raw[0:3] == b"\x48\x8d\x05"
            and raw[7:12] == b"\xba\x28\x00\x00\x00"
            and raw[12] == 0xC3):
        return False
    disp = struct.unpack_from("<i", raw, 3)[0]
    return read(data, body + 7 + disp, len(DESCRIPTION_TEXT)) \
        == DESCRIPTION_TEXT


def dec_accessor(data: bytes, body: int):
    """12-byte body: lea rax,[rdi+off]; lea rdx,[vtable]; ret."""
    raw = read(data, body, 12)
    require(raw[0:3] == b"\x48\x8d\x47"
            and raw[4:7] == b"\x48\x8d\x15" and raw[11] == 0xC3,
            f"accessor shape changed at {hx(body)}")
    off = struct.unpack_from("<b", raw, 3)[0]
    disp = struct.unpack_from("<i", raw, 7)[0]
    return off, body + 11 + disp


def dec_pair(data: bytes, body: int) -> int:
    """11-byte body: mov rax,rdi; lea rdx,[vtable]; ret."""
    raw = read(data, body, 11)
    require(raw[0:3] == b"\x48\x89\xf8"
            and raw[3:6] == b"\x48\x8d\x15" and raw[10] == 0xC3,
            f"pair-return shape changed at {hx(body)}")
    disp = struct.unpack_from("<i", raw, 6)[0]
    return body + 10 + disp


def dec_lookup(data: bytes, body: int):
    """33-byte body: movdqu (rsi),xmm0; pcmpeqb [key],xmm0;
    pmovmskb ecx; lea rdx,[rdi+off]; xor eax,eax;
    cmp ecx,0xffff; cmove rax,rdx; ret."""
    raw = read(data, body, 33)
    require(raw[0:4] == b"\xf3\x0f\x6f\x06"
            and raw[4:8] == b"\x66\x0f\x74\x05",
            f"lookup shape changed at {hx(body)}")
    disp = struct.unpack_from("<i", raw, 8)[0]
    cva = body + 12 + disp
    const = read(data, cva, 16).hex()
    require(raw[16:19] == b"\x48\x8d\x57",
            f"lookup lea changed at {hx(body)}")
    off = struct.unpack_from("<b", raw, 19)[0]
    return cva, const, off


def glue_record(data: bytes, fdes: dict, body: int) -> dict:
    f = fdes[body]
    raw = read(data, body, f["bytes"])
    # The self-dealloc size is the last plausible `mov $imm,%esi`
    # in the body (the tail / landing-pad final free).  Fuller
    # variants free a 24-byte fat-pair cell at +0x38 first, so
    # earlier immediates may name that cell instead.
    sizes = []
    for i in range(len(raw) - 5):
        if raw[i] == 0xBE:
            v = struct.unpack_from("<I", raw, i + 1)[0]
            if 0 < v <= 0x100 and v % 8 == 0:
                sizes.append(v)
    require(sizes, f"glue at {hx(body)} has no size immediate")
    called = None
    for i in range(len(raw) - 5):
        if raw[i] == 0xE8:
            disp = struct.unpack_from("<i", raw, i + 1)[0]
            called = body + i + 5 + disp
            break
    return {
        "body": hx(body), "body_bytes": f["bytes"],
        "body_sha256": hashlib.sha256(raw).hexdigest(),
        "dealloc_size": sizes[-1],
        "drops_array_field": b"\x48\x8d\x7b\x10" in raw,
        "checks_second_state": b"\x8b\x43\x30" in raw,
        "frees_buffer_field": b"\x48\x8b\x73\x38" in raw,
        "drops_field_at_0x38": b"\x48\x8d\x7b\x38" in raw,
        "drops_child_fat_pair": b"\xf3\x48\x0f\xbc\xc8" in raw,
        "first_call_target": hx(called) if called is not None
        else None,
    }


def analyze(data: bytes) -> dict:
    require(hashlib.sha256(data).hexdigest() == SHA256,
            "binary digest is not the pinned node115 distribution")
    require(len(data) == SIZE, "binary size changed")
    rel = relocations(data)
    fdes = body_map(data)
    bases = header_bases(rel, data, fdes)
    bset = set(bases)

    # drop bodies per TypeId constant, for the call-form shims
    drops_by_tid: dict = {}
    for b in bases:
        tid = type_id_const(rel, data, fdes, b)
        if tid is not None and cell_is_relative(rel, b):
            drops_by_tid.setdefault(tid, set()).add(
                cell(rel, data, b))

    members = []
    roles: dict = {}
    slot5_checked = 0
    slot5_matched = 0
    slot5_exceptions = []
    for base in sorted(FAMILY):
        want_k = FAMILY[base]
        require(is_error_vtable(rel, data, fdes, base),
                f"family member {hx(base)} lost its Error prefix")
        extent = extent_of(rel, data, fdes, bases, bset, base)
        require((extent - 0x58) % 0x30 == 0,
                f"group stride broken at {hx(base)}")
        k = (extent - 0x58) // 0x30
        require(k == want_k,
                f"family member {hx(base)} has {k} groups, "
                f"expected {want_k}")
        mtid = type_id_const(rel, data, fdes, base)
        require(mtid is not None, f"no type-id at {hx(base)}")

        own = glue_record(data, fdes, cell(rel, data, base + 0x58))
        member = {
            "vtable": hx(base),
            "drop": hx(cell(rel, data, base)),
            "self_size": cell(rel, data, base + 8),
            "self_align": cell(rel, data, base + 0x10),
            "type_id_const": mtid,
            "extent": hx(extent),
            "groups_count": k,
            "own_method_0x58": own,
            "groups": [],
        }
        pair_sizes = []
        pair_tids = []
        parsed = []
        for g in range(k):
            goff = 0x60 + g * 0x30
            s0 = cell(rel, data, base + goff)
            s1 = cell(rel, data, base + goff + 8)
            s2 = cell(rel, data, base + goff + 0x10)
            s3 = cell(rel, data, base + goff + 0x18)
            s4 = cell(rel, data, base + goff + 0x20)
            aoff, avt = dec_accessor(data, s0)
            pvt = dec_pair(data, s1)
            cva, key, loff = dec_lookup(data, s2)
            require(aoff == 0x38 and loff == 0x38,
                    f"field offset moved at {hx(base)} group {g}")
            require(is_error_vtable(rel, data, fdes, avt),
                    f"accessor vtable {hx(avt)} is not Error-family")
            require(is_error_vtable(rel, data, fdes, pvt),
                    f"pair vtable {hx(pvt)} is not Error-family")
            atid = type_id_const(rel, data, fdes, avt)
            ptid = type_id_const(rel, data, fdes, pvt)
            require(atid is not None and ptid is not None,
                    f"missing type-id in group {g} of {hx(base)}")
            raw4 = read(data, s4, 3)
            require(raw4 == b"\x31\xc0\xc3",
                    f"zero slot changed at {hx(base)} group {g}")
            glue3 = glue_record(data, fdes, s3)
            require(glue3["dealloc_size"]
                    == cell(rel, data, pvt + 8),
                    f"slot-3 shim size != pair size at "
                    f"{hx(base)} group {g}")
            role = roles.setdefault(key, {
                "key": key, "key_va": hx(cva),
                "accessor_type_id": atid, "pair_type_id": ptid})
            require(role["accessor_type_id"] == atid
                    and role["pair_type_id"] == ptid
                    and role["key_va"] == hx(cva),
                    f"role for key {key} is inconsistent at "
                    f"{hx(base)} group {g}")
            pair_sizes.append(cell(rel, data, pvt + 8))
            pair_tids.append(ptid)
            parsed.append({
                "index": g,
                "accessor": {
                    "body": hx(s0),
                    "body_bytes": fdes[s0]["bytes"],
                    "field_offset": hx(aoff),
                    "returns_vtable": hx(avt),
                    "returns_size": cell(rel, data, avt + 8),
                    "returns_drop_is_null":
                        not cell_is_relative(rel, avt)
                        and cell(rel, data, avt) == 0,
                    "returns_type_id": atid,
                    "returns_description_default":
                        description_is_default(rel, data, fdes,
                                               avt)},
                "pair_return": {
                    "body": hx(s1),
                    "body_bytes": fdes[s1]["bytes"],
                    "returns_vtable": hx(pvt),
                    "returns_size": cell(rel, data, pvt + 8),
                    "returns_type_id": ptid,
                    "returns_description_default":
                        description_is_default(rel, data, fdes,
                                               pvt),
                    "is_self_vtable": pvt == base},
                "keyed_lookup": {
                    "body": hx(s2),
                    "body_bytes": fdes[s2]["bytes"],
                    "key_va": hx(cva), "key": key,
                    "field_offset": hx(loff),
                    "key_is_accessor_type_id": key == atid},
                "drop_shim_slot3": glue3,
                "zero_slot4": {"body": hx(s4), "body_bytes": 3},
                "_s5": cell(rel, data, base + goff + 0x28),
            })
        # slot-5 shims belong to the next group's pair type; the
        # last group's sixth slot is the boundary cell.
        for g in range(k - 1):
            s5 = parsed[g].pop("_s5")
            glue5 = glue_record(data, fdes, s5)
            parsed[g]["drop_shim_slot5"] = glue5
            slot5_checked += 1
            nxt_tid = pair_tids[g + 1]
            if glue5["first_call_target"] is not None \
                    and not glue5["drops_array_field"] \
                    and glue5["body_bytes"] <= 70:
                called = int(glue5["first_call_target"], 16)
                ok = called in drops_by_tid.get(nxt_tid, set())
                require(ok,
                        f"call-form slot-5 at {hx(base)} group {g} "
                        f"does not call a drop of the next pair "
                        f"type")
                slot5_matched += 1
            elif glue5["dealloc_size"] == pair_sizes[g + 1]:
                slot5_matched += 1
            else:
                slot5_exceptions.append(
                    (base, g, glue5["dealloc_size"],
                     pair_sizes[g + 1]))
        tail_target = parsed[k - 1].pop("_s5")
        for g in range(k):
            if g < k - 1:
                continue
            parsed[g]["drop_shim_slot5"] = None
        member["tail_cell"] = {
            "offset": hx(extent),
            "target": hx(tail_target),
            "target_is_fde_body": tail_target in fdes,
            "target_is_next_header":
                (base + extent) in bset,
        }
        require(own["dealloc_size"] == pair_sizes[0],
                f"+0x58 shim size != first pair size at {hx(base)}")
        self_groups = [g for g in range(k)
                       if pair_tids[g] == mtid]
        require(len(self_groups) == 1,
                f"member {hx(base)} must have exactly one "
                f"self group")
        member["self_group_index"] = self_groups[0]
        member["io_group_indices"] = [
            g for g in range(k)
            if parsed[g]["accessor"]["returns_type_id"]
            == IO_TYPE_ID]
        member["groups"] = parsed
        members.append(member)

    require(slot5_exceptions == SLOT5_EXCEPTIONS,
            f"slot-5 exceptions changed: {slot5_exceptions}")
    for key in roles:
        atid = roles[key]["accessor_type_id"]
        require(key == atid or key in KEY_EXCEPTIONS,
                f"unexpected non-type-id group key {key}")
        if key in KEY_EXCEPTIONS:
            require(roles[key]["key_va"] == KEY_EXCEPTIONS[key],
                    f"exception key {key} moved")

    layout = {
        "prefix": "the std::error::Error vtable layout "
                  "(PR #3171): drop/size/align header, Debug "
                  "+0x18, Display +0x20, upcast cell +0x28, "
                  "source +0x30, type_id +0x38, description "
                  "+0x40, cause +0x48, provide +0x50",
        "own_method_0x58": "a drop shim for the first group's "
                           "pair type: drops the Once-guarded "
                           "array field at +0x10 (and, in the "
                           "fuller variant, frees the "
                           "(size, ptr) buffer at +0x38/+0x40), "
                           "then frees the object with that "
                           "type's size; the freed size equals "
                           "the first pair size in all 8 members",
        "group_stride": "0x30",
        "group_slots": [
            "accessor (12 bytes): returns (self+0x38, the "
            "group's dyn Error vtable A) - the field at +0x38 "
            "viewed as the group's accessor type",
            "pair return (11 bytes): returns (self, the "
            "group's dyn Error vtable B) - self viewed as the "
            "group's pair type; for exactly one group per "
            "member B is the member's own vtable",
            "keyed lookup (33 bytes): byte-compares the "
            "16-byte key pointed to by the second argument "
            "against the group's constant; returns self+0x38 "
            "on equality, null otherwise.  The constant is "
            "the accessor type's TypeId in all but two roles",
            "drop shim: drop-in-place for an object of the "
            "pair type B (Once-guarded array field at +0x10, "
            "element size 0x38) plus dealloc with B's size; "
            "the freed size equals B's size in all 47 groups",
            "zero (3 bytes): xor eax,eax; ret - one shared "
            "body per member returning 0",
            "drop shim for the NEXT group's pair type, in "
            "one of several variants (array-only, second-"
            "state check, buffer free, field drop, fat-pair "
            "drop, or a call to that type's own vtable drop "
            "body); in all 38 non-terminal cases it frees "
            "exactly that type's size or calls its drop.  "
            "The last group's sixth slot is the vtable "
            "boundary cell",
        ],
    }
    return {
        "packet": PACKET.as_posix(),
        "binary": {"path": TARGET.as_posix(), "size": SIZE,
                   "sha256": SHA256},
        "family_layout": layout,
        "members": members,
        "roles": [roles[k] for k in sorted(roles)],
        "slot5_rule": {
            "checked": slot5_checked,
            "conforming": slot5_matched,
            "exceptions": [
                {"member": hx(b), "group": g,
                 "dealloc_size": s, "next_pair_size": n}
                for b, g, s, n in slot5_exceptions]},
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
