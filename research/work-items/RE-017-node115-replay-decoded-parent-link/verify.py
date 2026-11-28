"""Verify the selected node #115 incoming retained Block predecessor."""

from argparse import ArgumentParser
import csv
import hashlib
from pathlib import Path
import re
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
    instructions = {}
    with (PACKET / "anchors.tsv").open() as file:
        for row in csv.DictReader(file, delimiter="\t"):
            start, end, address = (int(row[key], 16) for key in ("start", "end", "address"))
            raw = bytes.fromhex(row["bytes"])
            require((start, end) in bounds and start <= address < address + len(raw) <= end,
                    f"wrong FDE for {address:#x}")
            require(address not in spans and read(".text", address, len(raw)) == raw,
                    f"wrong instruction bytes at {address:#x}")
            spans[address] = raw
            instructions[address] = row['instruction']
            print(f"{start:#x}..{end:#x} {address:#x} {raw.hex()} {row['instruction']}")

    def target(site):
        raw = spans[site]
        return site + len(raw) + struct.unpack("<i", raw[-4:])[0]

    def displacement(site):
        return int(re.search(r"\+ (0x[0-9a-f]+)\]", instructions[site])[1], 16)

    def move(source, loads, stores, widths=None):
        widths = widths or (16,) * len(loads)
        output = []
        for byte in source:
            for load, store, width in zip(loads, stores, widths):
                start = displacement(load)
                if start <= byte < start + width:
                    output.append(displacement(store) + byte - start)
                    break
            else:
                raise ValueError(f"incomplete byte window at {byte:#x}")
        return output

    def block_owner_offset(header_offset):
        def imm(site):
            return struct.unpack("<I", spans[site][-4:])[0]

        source = displacement(0x4fb77f4) + header_offset
        start = displacement(0x4fb786f)
        require(start <= source and source + 32 <= start + imm(0x4fb7886), "Header span")
        staged = displacement(0x4fb7877) + source - start
        second_start = displacement(0x4fb78f3)
        require(second_start <= staged and staged + 32 <= second_start + imm(0x4fb78ee), "staged span")
        block = displacement(0x4fb78e6) + staged - second_start - displacement(0x4fb7ab2)
        require(0 <= block and block + 32 <= imm(0x4fb7aba), "Block span")
        wire = displacement(0x4eff6d0) + block
        wire_start = displacement(0x4eff798)
        require(wire_start <= wire and wire + 32 <= wire_start + imm(0x4eff7ad), "wire span")
        owner_start = displacement(0x4eff80f)
        retained = displacement(0x4eff7a0) + wire - wire_start
        require(owner_start <= retained and retained + 32 <= owner_start + imm(0x4eff814),
                "owner span")
        return retained - owner_start

    for site, destination in {
        0x5968dd8: 0x5821430, 0x5968f50: 0x5968d20,
        0x59d5fb7: 0x5968d20, 0x59d60ec: 0x5968f10,
        0x4e051f6: 0x5968d20, 0x59d6275: 0x4e05180,
        0x4fb77ff: 0x59d5ea0, 0x4eff6db: 0x4fb7760,
    }.items():
        require(target(site) == destination, f"wrong selected decoder edge at {site:#x}")

    source = move(range(0x9, 0x29), (0x5968e7b, 0x5968e80), (0x5968e85, 0x5968e8a))
    qc = move(source, (0x5968ede, 0x5968ee3), (0x5968ee8, 0x5968eec))
    require(qc == list(range(0x48, 0x68)), "wrong native QC raw hash interval")

    direct = [displacement(0x59d5faf) + byte for byte in qc]
    direct = move(direct, (0x59d619a, 0x59d619f), (0x59d61ac, 0x59d61a4))
    direct = move(direct, (0x59d6427, 0x59d642f), (0x59d643b, 0x59d6437))

    timeout_proof = [displacement(0x5968f48) + byte for byte in qc]
    timeout_proof = move(timeout_proof, (0x5968fd7, 0x5968fdc), (0x5968fe9, 0x5968fe1))
    timeout_proof = move(timeout_proof, (0x59690f5, 0x5969105, 0x5969115),
                         (0x59690fd, 0x596910d, 0x596911d), (16, 16, 8))
    timeout_proof = [displacement(0x59d60e4) + byte - displacement(0x5969125)
                     for byte in timeout_proof]
    embedded = move(timeout_proof, (0x59d6203, 0x59d6208), (0x59d6215, 0x59d620d))
    embedded = move(embedded, (0x59d6340, 0x59d6350, 0x59d6360),
                    (0x59d6348, 0x59d6358, 0x59d6368))
    embedded = move(embedded, (0x59d641f, 0x59d6427, 0x59d642f),
                    (0x59d643f, 0x59d643b, 0x59d6437))

    optional = [displacement(0x4e051f1) + byte for byte in qc]
    optional = move(optional, (0x4e052a6, 0x4e052ab), (0x4e052b7, 0x4e052b3))
    optional = [displacement(0x59d626d) + byte for byte in optional]
    optional = move(optional, (0x59d62f3, 0x59d62f8), (0x59d6305, 0x59d62fd))
    optional = move(optional, (0x59d6498, 0x59d64a0), (0x59d64af, 0x59d64a8))

    for label, view, header in (
        ("direct", 0x4fadd18, direct),
        ("embedded timeout", 0x4fadcff, embedded),
        ("optional timeout", 0x4fadd03, optional),
    ):
        require(header == list(range(header[0], header[0] + 32)), "hash bytes reordered")
        owner = block_owner_offset(header[0])
        require(owner == displacement(view) + displacement(0x4fadd3b),
                f"{label} QC copy does not reach the retained predecessor comparison")
        require(owner + 16 == displacement(view) + displacement(0x4fadd40),
                "wrong second-half comparison")
        require(displacement(view) + displacement(0x4fadd24) == owner - 24,
                "wrong paired identity displacement")
        print(f"{label}: header +{header[0]:#x}, owner +{owner:#x}, consecutive 32 bytes")
    print(f"verified {len(spans)} incoming retained-parent instruction spans")


if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    verify_native(parser.parse_args().repo)
