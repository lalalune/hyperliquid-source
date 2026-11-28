"""Verify native replica clock serialization and replay clock consumers."""

from argparse import ArgumentParser
import csv
import hashlib
from datetime import datetime, timezone
from pathlib import Path
import struct
import sys

PACKET = Path(__file__).resolve().parent


def require(condition, message):
    if not condition:
        raise ValueError(message)


def verify_native(repo):
    sys.path.insert(0, str(repo / "tools"))
    from foundation_lsda_call_site import TARGET, TARGET_SHA256, parse_sections, walk_eh_frame

    image = (repo / TARGET).read_bytes()
    require(hashlib.sha256(image).hexdigest() == TARGET_SHA256, "wrong target")
    sections = {section["name"]: section for section in parse_sections(image)}

    def read(name, va, n):
        section = sections[name]
        position = va - section["va"]
        require(0 <= position <= position + n <= section["size"], "outside ELF section")
        offset = section["offset"] + position
        return image[offset:offset + n]

    eh = sections[".eh_frame"]
    _, rows = walk_eh_frame(read(".eh_frame", eh["va"], eh["size"]), eh["va"])
    bounds = {(row["entry"], row["end"]) for row in rows}
    spans = {}
    with (PACKET / "anchors.tsv").open() as file:
        for row in csv.DictReader(file, delimiter="\t"):
            start, end, address = (int(row[key], 16) for key in ("start", "end", "address"))
            raw = bytes.fromhex(row["bytes"])
            require((start, end) in bounds and start <= address < address + len(raw) <= end,
                    f"wrong FDE for {address:#x}")
            require(address not in spans and read(".text", address, len(raw)) == raw,
                    f"wrong instruction bytes at {address:#x}")
            spans[address] = raw
            print(f"{start:#x}..{end:#x} {address:#x} {raw.hex()} {row['instruction']}")

    def target(site):
        raw = spans[site]
        return site + len(raw) + struct.unpack("<i", raw[-4:])[0]

    require(read(".rodata", target(0x4d6d5fb), 4) == b"time", "wrong archive field")
    require(spans[0x4fcd889] == spans[0x4fcd8ec] == bytes.fromhex("c6043022"), "wrong JSON quoting")
    require(spans[0x57a6f34][-4:] == struct.pack("<I", ord("T")), "wrong date separator")
    require(spans[0x57a6f4a][-1] == 4, "wrong time offset")
    require(spans[0x1628bd3][-1] == 13, "wrong packed-date extraction")
    require(spans[0x162a789][-4:] == struct.pack("<I", 1_000_000_000), "wrong nanos unit")
    require(spans[0x4ece964][-4:] == struct.pack("<I", 719_163), "wrong CE coordinate offset")
    for site, expected in {
        0x4d6d60c: 0x5076270, 0x5076330: 0x4fcd860, 0x4fcd8b0: 0x57a6f10,
        0x5a04fe9: 0x5483850, 0x5a067ad: 0x5483f50,
    }.items():
        require(target(site) == expected, f"wrong clock edge at {site:#x}")
    rela = sections[".rela.dyn"]
    relocations = {slot: (info, addend) for slot, info, addend in struct.iter_unpack(
        "<QQq", read(".rela.dyn", rela["va"], rela["size"])
    )}
    for site, expected in {
        0x4fcd8d2: 0x1680500, 0x57a6f23: 0x1628bc0,
        0x57a6f5b: 0x162a760, 0x4ece96a: 0x1628f50,
    }.items():
        require(relocations.get(target(site)) == (8, expected), f"wrong clock slot at {site:#x}")
    require(read(".text", 0x5483850, 0x83) == read(".text", 0x5483f50, 0x83),
            "begin clock consumers disagree")
    print(f"Pinned #115 digest {TARGET_SHA256}; {len(spans)} instruction witnesses")


def verify_examples():
    epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
    for text, expected in (
        ("1970-01-01T00:00:00", 0),
        ("1969-12-31T23:59:59", -1),
        ("2000-02-29T12:00:00", 951_825_600),
        ("2025-12-04T08:00:47", 1_764_835_247),
        ("2026-10-21T03:04:05", 1_792_551_845),
        ("2016-12-31T23:59:59", 1_483_228_799),
    ):
        elapsed = datetime.fromisoformat(text).replace(tzinfo=timezone.utc) - epoch
        actual = elapsed.days * 86_400 + elapsed.seconds
        require(actual == expected, f"incorrect civil time fixture at {text}")
        print(f"Civil seconds independently checked {text} -> {actual}")


def main():
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=PACKET.parents[2])
    args = parser.parse_args()
    verify_native(args.repo.resolve())
    verify_examples()


if __name__ == "__main__":
    main()
