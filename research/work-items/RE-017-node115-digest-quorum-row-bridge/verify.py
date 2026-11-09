#!/usr/bin/env python3
"""Verify digest-quorum row bridge witnesses against the pinned node #115 ELF."""
import csv
import hashlib
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "tools"))
from elf_index import sections, unwind_index
from fde_extents import eh_frame_records

TARGET = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
PACKET = Path(__file__).resolve().parent


def load_packet_witnesses(data, packet_dir, minimum=1):
    sec_rows, header = unwind_index(data)
    _, fdes = eh_frame_records(data, sec_rows)
    indexed = {(row["start"], row["fde"]) for row in header}
    extents = {(row["start"], row["end"]) for row in fdes
               if (row["start"], row["fde"]) in indexed}
    text = [row for row in sec_rows if row["name"] == ".text"]
    if len(text) != 1:
        raise ValueError("expected unique .text section")
    text = text[0]
    rows = {}
    with (packet_dir / "instructions.tsv").open(newline="") as stream:
        for row in csv.DictReader(stream, delimiter="\t"):
            address = int(row["va"], 16)
            raw = bytes.fromhex(row["bytes"])
            start, end = (int(row[key], 16) for key in ("fde_start", "fde_end"))
            offset = text["offset"] + address - text["address"]
            if address in rows or (start, end) not in extents:
                raise ValueError(f"duplicate witness or unindexed FDE at {address:#x}")
            if not start <= address < address + len(raw) <= end:
                raise ValueError(f"witness escapes FDE at {address:#x}")
            if not 0 <= offset <= offset + len(raw) <= len(data):
                raise ValueError(f"witness outside file at {address:#x}")
            if data[offset:offset + len(raw)] != raw:
                raise ValueError(f"instruction bytes differ at {address:#x}")
            rows[address] = raw
    if len(rows) < minimum:
        raise ValueError(f"too few selected witnesses in {packet_dir.name}")
    return rows


def load_witnesses(data):
    return load_packet_witnesses(data, PACKET, minimum=35)


def call_target(rows, address):
    raw = rows[address]
    if len(raw) != 5 or raw[0] != 0xE8:
        raise ValueError(f"expected rel32 CALL at {address:#x}")
    return address + 5 + struct.unpack_from("<i", raw, 1)[0]


def indirect_slot(rows, address):
    raw = rows[address]
    if len(raw) != 6 or raw[:2] != b"\xff\x15":
        raise ValueError(f"expected RIP-relative indirect CALL at {address:#x}")
    return address + 6 + struct.unpack_from("<i", raw, 2)[0]


def verify_predecessor_join(data, current_rows):
    work = ROOT / "research/work-items"
    owner = load_packet_witnesses(data, work / "RE-017-node115-digest-quorum-owner", 70)
    history = load_packet_witnesses(data, work / "RE-017-node115-raw-reference-origin", 80)
    comparator = load_packet_witnesses(data, work / "RE-017-node115-compact-digest-reference-lookup", 60)

    # Constructor staging: source descriptor at rsp+0x200 is copied to
    # record base rsp+0x1240 + 0x280 = rsp+0x14c0.
    expected_owner_bytes = {
        0x5A6C55F: "488dbc24c0140000",
        0x5A6C567: "488db42400020000",
        0x5A6C56F: "bab0000000",
        0x5A6C574: "41ffd5",
        0x5A6C5CB: "488db42440120000",
        0x5A6C5D3: "ba38040000",
        0x5A6C5D8: "41ffd5",
        0x5649810: "4c8dbc2400040000",
        0x5649818: "ba70040000",
        0x5649820: "4c89e6",
        0x5649B66: "498dbea8060000",
        0x5649B6D: "488db424f8030000",
        0x5649B7C: "ba78040000",
        0x5649B81: "41ffd7",
    }
    for address, expected in expected_owner_bytes.items():
        if owner.get(address, current_rows.get(address)) != bytes.fromhex(expected):
            raise ValueError(f"owner/context join instruction changed at {address:#x}")

    # The constructor input descriptor is +0x280. The copied context starts
    # eight bytes into the owner's 0x478-byte copy, at owner body +0x6b0.
    staging_offset = 0x14C0 - 0x1240
    owner_context_offset = 0x6A8 + (0x400 - 0x3F8)
    descriptor_owner_offset = owner_context_offset + staging_offset
    if (staging_offset, owner_context_offset, descriptor_owner_offset) != (0x280, 0x6B0, 0x930):
        raise ValueError("descriptor owner offset arithmetic changed")
    if 0x930 + 0x10 != 0x940:
        raise ValueError("returned-allocation prefix offset changed")

    # The raw-reference packet passes owner+0x6b0 into the selected path;
    # the compact packet retains the context and addresses its +0x280 field.
    if history.get(0x4FCAE24) != bytes.fromhex("498d8fb0060000"):
        raise ValueError("raw-reference context offset changed")
    if history.get(0x4FCAE36) != bytes.fromhex("48898c24b0000000"):
        raise ValueError("raw-reference context handoff changed")
    if call_target(history, 0x4FCAE48) != 0x59EC200:
        raise ValueError("raw-reference handoff target changed")
    if comparator.get(0x5A05C14) != bytes.fromhex("498d9c2480020000"):
        raise ValueError("compact comparator context+0x280 use changed")
    if call_target(comparator, 0x5A05C5E) != 0x4E3A020:
        raise ValueError("compact row helper call changed")
    return {"owner_packet_witnesses": len(owner), "history_packet_witnesses": len(history),
            "comparator_packet_witnesses": len(comparator),
            "staging_offset": hex(staging_offset), "owner_context_offset": hex(owner_context_offset),
            "descriptor_owner_offset": hex(descriptor_owner_offset),
            "returned_allocation_offset": "0x940"}


def analyze(data):
    digest = hashlib.sha256(data).hexdigest()
    if digest != TARGET:
        raise ValueError(f"wrong node #115 digest: {digest}")
    rows = load_witnesses(data)
    predecessor_join = verify_predecessor_join(data, rows)
    if call_target(rows, 0x5A05C5E) != 0x4E3A020:
        raise ValueError("compact row loop no longer calls the selected helper")
    if rows[0x5A05C1C] != bytes.fromhex("4c8db42498000000") or rows[0x5A05C2B] != bytes.fromhex("4c8d642410"):
        raise ValueError("temporary or row-record base changed")
    if rows[0x5A05C30] != bytes.fromhex("4c89f7") or rows[0x5A05C33] != bytes.fromhex("41ffd7"):
        raise ValueError("loop temporary initializer call changed")
    if rows[0x5A05C14] != bytes.fromhex("498d9c2480020000"):
        raise ValueError("context +0x280 operand changed")
    if rows[0x5A05C3A] != bytes.fromhex("410f104558") or rows[0x5A05C44] != bytes.fromhex("f3410f6f4548"):
        raise ValueError("candidate lane loads changed")
    if rows[0x5A05C36] != bytes.fromhex("498b4500"):
        raise ValueError("incoming row key load changed")
    if rows[0x4E3A031] != bytes.fromhex("4989d4") or rows[0x4E3A034] != bytes.fromhex("4989f7") or rows[0x4E3A037] != bytes.fromhex("4989fe"):
        raise ValueError("helper argument retention changed")
    if rows[0x4E3A05D] != bytes.fromhex("4c89f6") or indirect_slot(rows, 0x4E3A060) != 0x64E0F80:
        raise ValueError("descriptor is no longer passed to the recorded indirect dispatch")
    if rows[0x4E3A097] != bytes.fromhex("498d5e48"):
        raise ValueError("descriptor subobject offset changed")
    if call_target(rows, 0x4E3A15C) != 0x50E6FE0 or rows[0x50E6FEB] != bytes.fromhex("4889d3"):
        raise ValueError("row-record forwarding to the intermediate builder changed")
    if rows[0x50E702B] != bytes.fromhex("4889df"):
        raise ValueError("row record is no longer passed to the downstream boundary")
    if rows[0x50E702E] != bytes.fromhex("e87d672900") or call_target(rows, 0x50E702E) != 0x537D7B0:
        raise ValueError("downstream insertion boundary changed")
    return {"target_sha256": digest, "witness_count": len(rows),
            "row_helper_call": hex(call_target(rows, 0x5A05C5E)),
            "descriptor_dispatch_slot": hex(indirect_slot(rows, 0x4E3A060)),
            "row_builder_call": hex(call_target(rows, 0x4E3A15C)),
            "downstream_boundary": hex(call_target(rows, 0x50E702E)),
            "predecessor_join": predecessor_join}


def self_test(data):
    original = analyze(data)
    rows = load_witnesses(data)
    changed_call = dict(rows)
    changed_call[0x5A05C5E] = bytes.fromhex("e8be4343ff")
    if call_target(changed_call, 0x5A05C5E) == 0x4E3A020:
        raise AssertionError("altered direct call was accepted")
    sec_rows = sections(data)
    text = [row for row in sec_rows if row["name"] == ".text"]
    if len(text) != 1:
        raise AssertionError("expected unique .text section")
    text = text[0]
    changed_operand = bytearray(data)
    operand_offset = text["offset"] + 0x5A05C14 - text["address"] + 4
    changed_operand[operand_offset] ^= 1
    try:
        load_witnesses(bytes(changed_operand))
    except ValueError:
        pass
    else:
        raise AssertionError("altered descriptor displacement was accepted")
    assert original["witness_count"] >= 35


if __name__ == "__main__":
    image = (ROOT / "artifacts/node/115/hl-node").read_bytes()
    if sys.argv[1:] == ["--self-test"]:
        self_test(image)
    elif sys.argv[1:]:
        raise SystemExit("usage: verify.py [--self-test]")
    print(analyze(image))
