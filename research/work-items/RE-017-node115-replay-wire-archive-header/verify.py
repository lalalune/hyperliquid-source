"""Verify the selected node #115 replay-to-archive header projection."""

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

    for site, field in {
        0x4d6d777: b"abci_block", 0x4d6d5fb: b"time", 0x4d6d656: b"round",
        0x4d6d680: b"parent_round", 0x4e0b078: b"hardfork", 0x4e0a658: b"proposer",
    }.items():
        require(read(".rodata", target(site), len(field)) == field, "wrong replica header literal")
    for site, destination in {
        0x4eff6db: 0x4fb7760, 0x4fb77ff: 0x59d5ea0,
        0x5a6ece8: 0x5a6ee67, 0x5a6f991: 0x595a6b0,
        0x595ab43: 0x50e2f80, 0x50e2fce: 0x4d6d740,
        0x4d6d78b: 0x50818f0, 0x50819aa: 0x4d6d5c0,
    }.items():
        require(target(site) == destination, f"wrong replay projection edge at {site:#x}")

    rela = sections[".rela.dyn"]
    relocations = {slot: (info, addend) for slot, info, addend in struct.iter_unpack(
        "<QQq", read(".rela.dyn", rela["va"], rela["size"])
    )}
    require(relocations.get(target(0x5a6e48d)) == (8, 0x4fad300), "wrong converter slot")
    require(target(0x4eff7b2) == target(0x4eff81c) == 0x64df508, "wrong Block owner copy slots")

    def disp(site):
        return struct.unpack("<I", spans[site][-4:])[0]

    for header_site, owner_site, field, width in (
        (0x59d63ef, 0x4fad644, "time_0", 8),
        (0x59d63f9, 0x4fad636, "time_1", 4),
        (0x59d63c5, 0x4fad32f, "proposer_0", 16),
        (0x59d63b7, 0x4fad324, "proposer_1", 4),
    ):
        header_offset = disp(header_site)
        source = disp(0x4fb77f4) + header_offset
        start = disp(0x4fb786f)
        require(start <= source < source + width <= start + disp(0x4fb7886), f"header span {field}")
        staged = disp(0x4fb7877) + source - start
        second_start = disp(0x4fb78f3)
        require(second_start <= staged < staged + width <= second_start + disp(0x4fb78ee),
                f"staged header span {field}")
        block = disp(0x4fb78e6) + staged - second_start - disp(0x4fb7ab2)
        require(0 <= block < block + width <= disp(0x4fb7aba), f"Block copy span {field}")
        wire = disp(0x4eff6d0) + block
        require(disp(0x4eff798) <= wire < wire + width <= disp(0x4eff798) + disp(0x4eff7ad),
                f"wire copy span {field}")
        owner = spans[0x4eff7a0][-1] + wire - disp(0x4eff798) - spans[0x4eff80f][-1]
        require(owner == disp(owner_site), f"decoded owner offset {field}")

    require(spans[0x4fad641][-1] == 0x40 and spans[0x4fad64b][-1] == 0x38, "converter time")
    require(spans[0x4fad66d][-1] == 0x54 and spans[0x4fad675][-1] == 0x44, "converter proposer")
    require(spans[0x4fad67e][-1] == 0x18 and spans[0x4fad687][-1] == 0x20
            and spans[0x4fad690][-1] == 0x28, "converter round and pair displacements")
    require(spans[0x4fad3a3] == spans[0x4fad60c] and spans[0x4fad3a8] == spans[0x4fad611],
            "converter paths disagree on successor and cutoff")
    for source, producer, field in (
        (0x5a6e609, 0x5a6e636, 0x10), (0x5a6e612, 0x5a6e62d, 0x20),
        (0x5a6e61b, 0x5a6e624, 0x30), (0x5a6e5f0, 0x5a6e5f8, 0x40),
        (0x5a6e5e0, 0x5a6e5e8, 0x50),
    ):
        require(disp(source) - disp(0x5a6e47a) == disp(producer) - 0x320 == field,
                "worker temporary changed a header displacement")

    require(disp(0x5a6eafc) == 0x320 + 0x38, "archive clock source")
    staged_base = disp(0x5a6eb07)
    require(staged_base + spans[0x5a6eb15][-1] == 0x1b0 + 0x38, "archive clock staging")
    require(staged_base + spans[0x5a6ec34][-1] == 0x1b0 + 0x44, "archive proposer staging")
    require(disp(0x5a6ec38) - 0x320 == disp(0x5a6ec4a) - 0x1b0 == 0x18, "round staging")
    require(disp(0x5a6ec41) - 0x320 == disp(0x5a6ec53) - 0x1b0 == 0x28, "pair staging")
    require(disp(0x5a6ecc4) - 0x1b0 == disp(0x5a6eccc) - 0x60
            == disp(0x5a6eea3) - disp(0x5a6f989) == 0x30, "clock frame transfer")
    require(disp(0x5a6ec9c) - 0x1b0 == disp(0x5a6eca4) - 0x60
            == disp(0x5a6ee7f) - disp(0x5a6f989) == 0x40, "proposer frame transfer")
    print(f"Pinned #115 SHA-256 {TARGET_SHA256}; {len(spans)} selected header witnesses")
    print("Decoded fields retain clock and proposer bytes through converter and archive staging")


def main():
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=PACKET.parents[2])
    args = parser.parse_args()
    verify_native(args.repo.resolve())


if __name__ == "__main__":
    main()
