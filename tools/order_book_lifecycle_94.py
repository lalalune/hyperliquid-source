#!/usr/bin/env python3
"""RE-006: recover one static order-slot/price-level lifecycle from node #94.

The collector is static and read-only.  It authenticates the captured ELF,
parses its sections, RELATIVE relocations and unwind FDEs, and checks exact
x86-64 bytes for the bounded insertion/removal family.  It never executes the
captured program.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from elf_index import sections
from fde_extents import fde_extents

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "artifacts/node/94/hl-node"
SHA256 = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"


class EvidenceError(Exception):
    """The supplied bytes do not carry the pinned evidence."""


# Labels are deliberately descriptive, not recovered symbols.
FUNCTIONS = (
    ("resting-insert-body", 0x430D610, 0x4311140, 3),
    ("insert-accounting-and-allocation", 0x42E85C0, 0x42E870D, 2),
    ("slab-insert-f8", 0x45A4C90, 0x45A4DC3, 1),
    ("removal-caller-and-unlink", 0x42F7890, 0x42F8834, 4),
    ("slab-remove-f8-and-accounting", 0x42E8BF0, 0x42E8F77, 2),
)

# Each range is kept short enough to have a single local interpretation.  The
# descriptions in the output distinguish observed writes from semantic labels.
ANCHORS = (
    ("side-price-key", 0x430F84B, 0x430F876,
     "488b4c24704889ce48f7de488dbd80000000488d8598000000807c244800480f45f1480f45f8e81a402900",
     "select -price/book+0x80 for side byte 0, +price/book+0x98 otherwise"),
    ("allocation-call", 0x430F9F0, 0x430FA0B,
     "4889ef4c89ea488b8c24800c00004c8b842418020000e8b58bfdff",
     "prepare and call the allocation/accounting helper"),
    ("new-slot-links", 0x430F970, 0x430F98A,
     "410f104424100f298424c005000048c78424d005000000000000",
     "copy the level tail Option into the new slot previous link and clear its next Option"),
    ("level-tail-append", 0x430FA0E, 0x430FA79,
     "41803c2400750d49c70424010000004d8974240841837c2410017541498b4c2418488b8424c0000000483b080f8393140000488b842428010000488b004869c9f8000000833c08020f84771400004801c848c74010010000004c89701849c7442410010000004d89742418",
     "initialize empty head, validate old tail, write old-tail next and new tail"),
    ("insert-total-add", 0x42E866E, 0x42E86D6,
     "4d8b274c89e04c01e8723e4989074989e7baf80000004c89ff4889deff1550594801498b5e204c89f74889de4c89fae8eec52b004889d84881c4680200005b415c415d415e415f5dc3488d35ba42430131ffff15caaa48014d01ec48c7c0ffffffff490f43c4eba3",
     "add the slot +0xc8 qword to the supplied total, overflow diagnostic then u64::MAX"),
    ("insert-size-load", 0x42E85DD, 0x42E8618,
     "8b86f0000000894424480f1086e00000000f11442438488b86d80000000fb68ec2000000488bb6a00000004c8babc800000048c744240800000000",
     "load the inserted slot's unsigned accounting quantity from +0xc8"),
    ("slab-append-or-reuse", 0x45A4CAB, 0x45A4D50,
     "488b4710488b4f1848ffc148c7c2ffffffff480f45d1488957184839c6754c4d3b3e7514488b2b4c8b63504c8b6b584c89f7ff15d5f71c014969fff800000049037e08baf80000004889deff15e4921c0149ffc74d897e104d897e204883c4185b415c415d415e415f5dc37338498b7e084969c7f8000000833c070275274801c7488b470849894620baf80000004889de4883c4185b415c415d415e415f5dff2590921c01",
     "increment occupied count, append at len or replace discriminant-2 free slot"),
    ("remove-key-guard", 0x42E8C04, 0x42E8C2B,
     "483b56107315488b46084869faf80000004c8b24384983fc02750c48c70302000000e9f9020000",
     "key<len and slot discriminant!=2; otherwise return absent discriminant 2"),
    ("slab-free-list-delete", 0x42E8D3C, 0x42E8D5E,
     "48c7000200000048897808488b7e184531c94883ef014c0f43cf4c894e1848895620",
     "write vacant=2, link old free head, decrement count with floor 0, set free head=key"),
    ("remove-size-load", 0x42E8D0A, 0x42E8D24,
     "4c8bb8c80000004c8bb0d8000000448b88f000000044894c2450",
     "load the removed slot's unsigned accounting quantity from +0xc8"),
    ("remove-total-sub", 0x42E8E01, 0x42E8E23,
     "4c8b284d29fd73174531ed488d357d3b430131ffff1575a34801488b4424304c8928",
     "subtract removed slot +0xc8 qword from total, underflow diagnostic then zero"),
    ("remove-side-price-key", 0x42F84B9, 0x42F84F9,
     "488db380000000488d83980000000fb64c240ff6c101480f45f0488b8424a80000004885c00f887b0200004889c248f7daf6c101480f45d04889942428040000",
     "select book+0x80/-price or book+0x98/+price from one-bit side"),
    ("unlink-prev-or-head", 0x42F8590, 0x42F85E4,
     "488d3d294442014c3b4b100f83e8010000488b53084d69c1f800000042833c02020f84d20100004c01c2488b7c246848897a104c8b4424704c8942184885ff752c4c895408f04c894c08f8807c08e000756feb51",
     "validate previous slot then replace its next; absent previous replaces level head"),
    ("unlink-next-or-tail", 0x42F85E4, 0x42F863C,
     "488b7c246848897c08e04c8b4424704c894408e84885ff74d4488d3dd44342014c3b43100f837b010000488b53084d69c0f800000042833c02020f84650100004c01c24c89124c894a08807c08e000751c807c08f0007515",
     "validate next slot then replace its previous; absent next replaces level tail"),
    ("remove-empty-level", 0x42F8635, 0x42F8651,
     "807c08f0007515488dbc24c0000000488d942428040000e80fb06400",
     "when both level option discriminants are zero, call the map removal helper"),
)

# Direct call edges whose instruction boundary was checked with a disassembler.
CALL_EDGES = (
    (0x430FA06, 0x42E85C0, "insert body -> accounting/allocation"),
    (0x42E869D, 0x45A4C90, "accounting/allocation -> slab insert"),
    (0x42F7DE1, 0x42E8BF0, "removal caller -> slab remove/accounting"),
)

# Location records are 24 bytes: relocated path pointer, path length, line, col.
LOCATIONS = (
    (0x571C9A8, "/home/ubuntu/hl/code_Mainnet/l1/src/book/book/mod.rs", 1048, 21),
    (0x571C9C0, "/home/ubuntu/hl/code_Mainnet/l1/src/book/book/mod.rs", 1286, 56),
    (0x571C9D8, "/home/ubuntu/hl/code_Mainnet/l1/src/book/book/mod.rs", 1294, 56),
    (0x571C9F0, "/home/ubuntu/hl/code_Mainnet/l1/src/book/book/impl_insert_order.rs", 514, 43),
    (0x571CA08, "/home/ubuntu/hl/code_Mainnet/l1/src/book/book/impl_insert_order.rs", 517, 59),
    (0x571CA20, "/home/ubuntu/hl/code_Mainnet/l1/src/book/book/impl_insert_order.rs", 445, 56),
    (0x571CA38, "/home/ubuntu/hl/code_Mainnet/l1/src/book/book/impl_insert_order.rs", 768, 85),
    (0x571CA50, "/home/ubuntu/hl/code_Mainnet/l1/src/book/book/impl_insert_order.rs", 167, 17),
    (0x572AFD0, "/home/ubuntu/hl/code_Mainnet/l1/src/slab/slab.rs", 79, 21),
)


def render(value):
    return json.dumps(value, sort_keys=True, indent=2) + "\n"


def file_mapping(data, va, length=1):
    matches = [s for s in sections(data) if s["type"] != 8 and
               s["address"] <= va and va + length <= s["address"] + s["size"]]
    if len(matches) != 1:
        raise EvidenceError(f"{va:#x}+{length:#x} has no unique file mapping")
    sec = matches[0]
    return sec["offset"] + va - sec["address"]


def read_va(data, va, length):
    offset = file_mapping(data, va, length)
    return offset, data[offset:offset + length]


def relative_relocations(data):
    out = {}
    for sec in sections(data):
        if sec["type"] != 4:
            continue
        if sec["size"] % 24:
            raise EvidenceError(f"{sec['name']} has a partial ELF64 Rela entry")
        for off in range(sec["offset"], sec["offset"] + sec["size"], 24):
            slot, info, addend = struct.unpack_from("<QQq", data, off)
            if info == 8:  # R_X86_64_RELATIVE with symbol index zero.
                out[slot] = addend
    return out


def decode_call(data, site):
    _, raw = read_va(data, site, 5)
    if raw[0] != 0xE8:
        raise EvidenceError(f"no direct call at {site:#x}")
    return site + 5 + struct.unpack_from("<i", raw, 1)[0], raw.hex()


def direct_call_sites(text, base, target):
    """Return E8-rel32 byte-pattern hits in .text; this is not a CFG census."""
    result = []
    for match in re.finditer(b"\xe8", text):
        pos = match.start()
        if pos + 5 <= len(text) and base + pos + 5 + struct.unpack_from("<i", text, pos + 1)[0] == target:
            result.append(base + pos)
    return result


def validate_controls(data):
    """Check local byte/call/Location obligations without rescanning all FDEs."""
    anchors = []
    for name, start, end, expected_hex, observation in ANCHORS:
        offset, raw = read_va(data, start, end - start)
        if raw != bytes.fromhex(expected_hex):
            raise EvidenceError(f"{name}: bytes changed at {start:#x}")
        anchors.append({
            "label": name, "start_va": hex(start), "end_va": hex(end),
            "file_offset": hex(offset), "bytes": len(raw), "raw_hex": raw.hex(),
            "sha256": hashlib.sha256(raw).hexdigest(), "observation": observation,
        })

    calls = []
    for site, expected, label in CALL_EDGES:
        target, raw = decode_call(data, site)
        if target != expected:
            raise EvidenceError(f"call at {site:#x} targets {target:#x}, expected {expected:#x}")
        calls.append({"site_va": hex(site), "target_va": hex(target), "bytes": raw, "label": label})

    relocs = relative_relocations(data)
    locations = []
    for slot, path, line, column in LOCATIONS:
        path_va = relocs.get(slot)
        if path_va is None:
            raise EvidenceError(f"Location {slot:#x} has no R_X86_64_RELATIVE relocation")
        _, raw = read_va(data, slot, 24)
        zero_pointer, length, got_line, got_column = struct.unpack("<QQII", raw)
        if zero_pointer != 0:
            raise EvidenceError(f"Location {slot:#x} pointer field is not relocation-zeroed")
        _, path_bytes = read_va(data, path_va, length)
        got_path = path_bytes.decode("utf-8")
        if (got_path, got_line, got_column) != (path, line, column):
            raise EvidenceError(f"Location {slot:#x} changed")
        locations.append({"slot_va": hex(slot), "path_va": hex(path_va), "path": path,
                          "line": line, "column": column})
    return anchors, calls, locations


def scan(data, expected_sha256=SHA256):
    digest = hashlib.sha256(data).hexdigest()
    if digest != expected_sha256:
        raise EvidenceError(f"input SHA-256 {digest} is not pinned node #94 {SHA256}")
    secs = sections(data)
    text_sec = next((s for s in secs if s["name"] == ".text"), None)
    if text_sec is None:
        raise EvidenceError("ELF has no .text")
    text = data[text_sec["offset"]:text_sec["offset"] + text_sec["size"]]

    try:
        fde_summary, fdes, _ = fde_extents(data)
    except ValueError as exc:
        raise EvidenceError(str(exc)) from exc
    by_start = {row["start"]: row for row in fdes}
    functions = []
    for name, start, end, caller_count in FUNCTIONS:
        row = by_start.get(start)
        if row is None or row["end"] != end:
            raise EvidenceError(f"{name}: FDE is not {start:#x}..{end:#x}")
        offset, body = read_va(data, start, end - start)
        sites = direct_call_sites(text, text_sec["address"], start)
        if len(sites) != caller_count:
            raise EvidenceError(f"{name}: {len(sites)} direct-call hits, expected {caller_count}")
        functions.append({
            "label": name, "start_va": hex(start), "end_va": hex(end),
            "file_offset": hex(offset), "bytes": len(body),
            "sha256": hashlib.sha256(body).hexdigest(),
            "direct_call_hits": [hex(site) for site in sites],
        })

    anchors, calls, locations = validate_controls(data)

    return {
        "target": {"path": "artifacts/node/94/hl-node", "sha256": digest, "bytes": len(data)},
        "coordinate_system": "linked ELF virtual addresses; .text file offset = VA - 0x1000",
        "fde_count": fde_summary["fde_records"],
        "functions": functions,
        "anchors": anchors,
        "call_edges": calls,
        "source_locations": locations,
        "captured_binary_executed": False,
        "limits": ("One linked resting-order insertion/removal family only. Labels are inferred roles; "
                   "no external action dispatcher, concurrency contract, duplicate predicate, full matcher, "
                   "or source equivalence is claimed."),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=TARGET)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        result = scan(args.binary.read_bytes())
    except (EvidenceError, ValueError, struct.error, UnicodeDecodeError) as exc:
        print(f"RE-006 evidence error: {exc}", file=sys.stderr)
        raise SystemExit(1)
    text = render(result)
    if args.output:
        args.output.write_text(text)
    else:
        sys.stdout.write(text)


if __name__ == "__main__":
    main()
