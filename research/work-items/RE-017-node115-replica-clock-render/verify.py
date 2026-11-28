"""Verify the selected node #115 decoded-to-archive clock."""

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
        0x4eff6db: 0x4fb7760, 0x4fb77ff: 0x59d5ea0,
        0x4d6d60c: 0x5076270, 0x5076330: 0x4fcd860, 0x4fcd8b0: 0x57a6f10,
    }.items():
        require(target(site) == destination, f"wrong selected clock edge at {site:#x}")
    require(read(".rodata", target(0x4d6d5fb), 4) == b"time", "wrong archive key")

    def disp(site):
        return struct.unpack("<I", spans[site][-4:])[0]

    for source, load, store, width, relative in (
        (0x59d63ef, 0x4fad644, 0x4fad64b, 8, 0),
        (0x59d63f9, 0x4fad636, 0x4fad641, 4, 8),
    ):
        field = disp(0x4fb77f4) + disp(source)
        begin = disp(0x4fb786f)
        require(begin <= field and field + width <= begin + disp(0x4fb7886), "Header clock span")
        staged = disp(0x4fb7877) + field - begin
        begin = disp(0x4fb78f3)
        require(begin <= staged and staged + width <= begin + disp(0x4fb78ee), "staged clock span")
        block = disp(0x4fb78e6) + staged - begin - disp(0x4fb7ab2)
        require(0 <= block and block + width <= disp(0x4fb7aba), "Block clock span")
        wire = disp(0x4eff6d0) + block
        begin = disp(0x4eff798)
        require(begin <= wire and wire + width <= begin + disp(0x4eff7ad), "wire clock span")
        owner = spans[0x4eff7a0][-1] + wire - begin - spans[0x4eff80f][-1]
        require(owner == disp(load), "owner clock source")
        require(spans[store][-1] == spans[0x4d6d5f7][-1] + relative, "archive clock destination")

    rela = sections[".rela.dyn"]
    relocations = {slot: (info, addend) for slot, info, addend in struct.iter_unpack(
        "<QQq", read(".rela.dyn", rela["va"], rela["size"])
    )}
    for replica_site, checkpoint_site, formatter in (
        (0x57a6f23, 0x5307569, 0x1628bc0),
        (0x57a6f5b, 0x5307599, 0x162a760),
    ):
        require(target(replica_site) == target(checkpoint_site), "clock paths use different slots")
        require(relocations[target(replica_site)] == (8, formatter), "wrong shared formatter")
    require(spans[0x57a6f34] == spans[0x5307581] == bytes.fromhex("be54000000"),
            "wrong common time separator")
    require(spans[0x57a6f4a][-1] == spans[0x530758d][-1] == 4, "wrong date-to-time offset")
    require(disp(0x162a789) == 1_000_000_000, "wrong leap-second threshold")
    print(f"verified {len(spans)} native spans for the decoded-to-archive clock and shared formatter")


if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    verify_native(parser.parse_args().repo)
