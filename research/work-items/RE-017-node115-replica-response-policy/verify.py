"""Verify the selected node #115 replica response lane."""

from argparse import ArgumentParser
import csv
import hashlib
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

    for site, destination in {
        0x5a6ea10: 0x4f122c0, 0x5a6ece8: 0x5a6ee67,
        0x5a6ed0c: 0x4e36af0, 0x5a6f991: 0x595a6b0,
        0x4d6d7b5: 0x506e230, 0x506e30d: 0x4d6d170,
        0x4d6d2f2: 0x502d0d0,
    }.items():
        require(target(site) == destination, f"wrong response lane edge at {site:#x}")
    for site, destination in {0x5a6ec82: 0x5a6eced, 0x5a6f8d2: 0x5a6f916, 0x5a6f914: 0x5a6f949}.items():
        raw = spans[site]
        require(site + len(raw) + struct.unpack("b", raw[-1:])[0] == destination,
                f"wrong short response edge at {site:#x}")
    for site, literal in {0x4d6d1c6: b"Hash", 0x4d6d299: b"Full"}.items():
        require(read(".rodata", target(site), len(literal)) == literal, f"wrong archive label {literal!r}")

    def disp(site):
        return struct.unpack("<I", spans[site][-4:])[0]

    modulus = 1 << 64
    inverse = struct.unpack("<Q", spans[0x5a6ec67][-8:])[0]
    threshold = struct.unpack("<Q", spans[0x5a6ec75][-8:])[0]
    require(inverse * 11 % modulus == 1 and threshold == (modulus - 1) // 11,
            "incorrect height divisibility constants")
    require(spans[0x5a6ec82][0] == 0x76, "wrong unsigned inclusive cadence branch")
    require(disp(0x5a6ea48) == disp(0x5a6ec5c) == disp(0x5a6f981),
            "worked height and published height use different slots")

    require(spans[0x5a6ece6][-1] == spans[0x506e2d6][-1] == 2, "wrong null tag")
    require(spans[0x5a6ee65][-1] == spans[0x4d6d17f][-1] == 1, "wrong Hash tag")
    require(disp(0x5a6eec5) == disp(0x5a6f942), "wrong periodic selection tag reload")
    require(disp(0x5a6f8c3) == 0x6b8 and spans[0x5a6f8cb][-1] == 1, "wrong Full condition")
    require(spans[0x5a6f912] == bytes.fromhex("31c9"), "Full path does not select tag zero")

    full_lo = disp(0x5a6f8dc) + struct.unpack("b", spans[0x5a6f8f0][-1:])[0]
    full_hi = disp(0x5a6f8dc) + struct.unpack("b", spans[0x5a6f8e4][-1:])[0]
    require(disp(0x5a6ea2f) == disp(0x5a6f8e8) == disp(0x5a6ed04)
            and disp(0x5a6f8d4) - disp(0x5a6f8e8) == 16,
            "wrong Full vector source")
    require(full_hi - full_lo == 16, "wrong Full vector carry")
    final_payload = disp(0x5a6f958)
    require(final_payload - 1 == disp(0x5a6f949), "wrong archive variant tag position")
    field_start = disp(0x5a6f989) + spans[0x4d6d7a0][-1]
    require(field_start == disp(0x5a6f949), "wrong record response offset")
    require(final_payload + (full_lo - spans[0x5a6f8f4][-1]) == field_start + spans[0x4d6d2c9][-1],
            "Full vector does not reach the Full JSON writer")

    first_read, second_read = spans[0x5a6f8f4][-1], spans[0x5a6f8f9][-1]
    first_stage, second_stage = disp(0x5a6f8ff), disp(0x5a6f907)
    require(second_read - first_read == second_stage - first_stage == 15,
            "wrong overlapping staging copies")
    require(first_read <= full_lo and full_hi + 8 == second_read + 16,
            "incomplete Full descriptor in the staging windows")
    require(spans[0x5a6f960][-1] == second_stage - first_stage,
            "wrong final descriptor second-lane copy")

    print(f"verified {len(spans)} native response-selection spans and Full vector handoff")
    print("sink lane: mode 1 Full, other modes Hash at H % 11 == 0, otherwise null")


if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    verify_native(parser.parse_args().repo)
