"""Join named #115 checkpoint writer operands to compact root slots, statically."""

import hashlib
import json
from pathlib import Path
import sys

ROOT = Path.cwd()
PACKET = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "tools"))

from abci_hash_slots_115 import builder_pointers, entry_table
from abci_state_fields_115 import EXTRA_NAMES, POOL_NAMES
from foundation_lsda_call_site import TARGET, TARGET_SHA256, parse_sections, walk_eh_frame


STRING_WRITER = 0x57CF860
SHARED_KEY_CALLS = {
    0x5673520: ("0x5673543", "e818c31500"),
    0x56736B0: ("0x56736dd", "e87ec11500"),
    0x56745D0: ("0x56745fd", "e85eb21500"),
    0x5675090: ("0x56750c2", "e899a71500"),
    0x5676BD0: ("0x5676bed", "e86e8c1500"),
    0x5677400: ("0x567741d", "e83e841500"),
    0x5678170: ("0x567819e", "e8bd761500"),
    0x56781F0: ("0x567820d", "e84e761500"),
    0x56783A0: ("0x56783d0", "e88b741500"),
    0x5678670: ("0x56786a3", "e8b8711500"),
    0x5678EA0: ("0x5678ecd", "e88e691500"),
}
COMPACT, EXPANDED = 0x5480950, 0x5481900
OPERANDS = (
    b"\x49\x8d\x97", b"\x4d\x8d\x87", b"\x4d\x8b\x87", b"\x45\x0f\xb6\x87",
    b"\x49\x8d\xb7", b"\xf3\x41\x0f\x7e\x87", b"\x41\x0f\xb6\x97",
    b"\x49\x8b\x8f", b"\x4d\x8b\x8f", b"\x49\x8b\x97", b"\x49\x81\xc7",
)


def source_offset(raw):
    if raw == bytes.fromhex("4c89fe"):
        return 0
    if raw[:-4] not in OPERANDS:
        raise ValueError(f"unsupported state operand {raw.hex()}")
    return int.from_bytes(raw[-4:], "little")


def expanded_offset(offset):
    return offset + 0xB70 if offset >= 0x7C0 else offset


def main():
    assert __debug__, "run without -O"
    data = Path(TARGET).read_bytes()
    assert hashlib.sha256(data).hexdigest() == TARGET_SHA256
    sections = {section["name"]: section for section in parse_sections(data)}

    def at(name, address, size):
        section = sections[name]
        index = address - section["va"]
        assert 0 <= index <= index + size <= section["size"]
        start = section["offset"] + index
        return data[start:start + size]

    frame = sections[".eh_frame"]
    _, fdes = walk_eh_frame(at(".eh_frame", frame["va"], frame["size"]), frame["va"])
    fdes = {row["entry"]: row["end"] for row in fdes}
    reads = set()

    def pin(span, owner):
        address, encoded = span
        site = int(address, 16)
        raw = bytes.fromhex(encoded)
        assert owner <= site < site + len(raw) <= fdes[owner]
        assert at(".text", site, len(raw)) == raw
        reads.add(site)
        return site, raw

    def relative(site, raw, prefixes):
        assert raw[:-4] in prefixes
        return site + len(raw) + int.from_bytes(raw[-4:], "little", signed=True)

    def call(span, owner):
        return relative(*pin(span, owner), (b"\xe8",))

    def key_name(address_pin, length_pin, owner_address, owner_length):
        target = relative(*pin(address_pin, owner_address), (b"H\x8d5", b"H\x8d\x15", b"H\x8d\x05"))
        _, length = pin(length_pin, owner_length)
        assert length[:-4] in (b"\xba", b"\xb9")
        return at(".rodata", target, int.from_bytes(length[-4:], "little")).decode("ascii")

    for writer, headers in (
        (COMPACT, (0x54809F6, 0x5480A58, 0x54809CB, 0x54809D2, 0x5480A2D, 0x5480A34)),
        (EXPANDED, (0x54819A6, 0x5481A08, 0x548197B, 0x5481982, 0x54819DD, 0x54819E4)),
    ):
        count, locus_count, exchange, exchange_len, locus, locus_len = headers
        for address, number in ((count, 59), (locus_count, 17)):
            pin((hex(address), (b"\xba" + number.to_bytes(4, "little")).hex()), writer)
        for address, length, expected in ((exchange, exchange_len, "exchange"), (locus, locus_len, "locus")):
            pointer_pin = (hex(address), at(".text", address, 7).hex())
            size_pin = (hex(length), (b"\xba" + len(expected).to_bytes(4, "little")).hex())
            assert key_name(pointer_pin, size_pin, writer, writer) == expected

    inputs = builder_pointers(data)
    entries = entry_table(data)
    assert len(inputs) == 74 and len(entries) == 59
    assert [index for index, _ in entries] == [None] + list(range(16, 74))
    records = json.loads((PACKET / "records.json").read_text())
    assert [(row["scope"], row["index"]) for row in records] == (
        [("locus", i) for i in range(17)] + [("exchange", i) for i in range(1, 59)]
    )
    names = POOL_NAMES + EXTRA_NAMES
    last = {"compact": COMPACT, "expanded": EXPANDED}
    compact_children = []
    writer_fields = 0
    for row in records:
        scope, index, key = row["scope"], row["index"], row["key"]
        if scope == "exchange":
            assert key == names[index]
        source = {}
        helpers = set()
        for layout, writer in (("compact", COMPACT), ("expanded", EXPANDED)):
            record = row[layout]
            call_site = int(record["value_call"][0], 16)
            assert last[layout] < call_site
            helper = call(record["value_call"], writer)
            helpers.add(helper)
            key_load, key_length, key_call = (record[k] for k in ("key_address", "key_length", "key_call"))
            owners = [writer if writer <= int(span[0], 16) < fdes[writer] else helper
                      for span in (key_load, key_length)]
            assert key_name(key_load, key_length, *owners) == key
            if key_call:
                key_site = int(key_call[0], 16)
                key_owner = writer if writer <= key_site < fdes[writer] else helper
                assert call(key_call, key_owner) == STRING_WRITER
                if key_owner == writer:
                    assert last[layout] < int(key_load[0], 16) < key_site < call_site
            else:
                assert owners == [writer, writer]
                assert call(SHARED_KEY_CALLS[helper], helper) == STRING_WRITER
            if owners[0] == writer:
                assert last[layout] < int(key_load[0], 16) < call_site
            assert all(last[layout] < int(arg[0], 16) < call_site for arg in record["source_args"])
            source[layout] = [source_offset(pin(arg, writer)[1]) for arg in record["source_args"]]
            last[layout] = call_site
        assert len(helpers) == 1
        assert source["expanded"] == [expanded_offset(offset) for offset in source["compact"]]
        if scope == "exchange":
            pointer_index, _ = entries[index]
            assert source["compact"][0] == inputs[pointer_index]
            writer_fields += 1
        elif index < 16:
            assert len(source["compact"]) == 1
            compact_children.extend(source["compact"])
        else:
            assert key == "aux" and helpers == {0x5673860} and not source["compact"]
            pin(("0x56738a2", "31d2"), 0x5673860)
            assert call(("0x56738a4", "e8f7b21500"), 0x5673860) == 0x57CEBA0
    assert compact_children == inputs[:16]
    assert writer_fields == 58 and names[0] == "locus"

    assert source_offset(bytes.fromhex("498d97a00b0000")) == inputs[23]
    assert source_offset(bytes.fromhex("498d97a80b0000")) != inputs[23]
    assert expanded_offset(0x670) == 0x670
    assert 0x670 + 0xB70 != expanded_offset(0x670)
    assert len(compact_children + [0]) != len(inputs[:16])
    print(f"verified {len(reads)} original instruction pins")
    print("59 named Exchange slots, with matching compact and expanded checkpoint writers")
    print("slot 0: 16 shared Locus inputs; on-wire aux adds a constant empty array")
    print("negative controls: shifted Bridge offset, blanket layout shift and fabricated aux slot rejected")


if __name__ == "__main__":
    main()
