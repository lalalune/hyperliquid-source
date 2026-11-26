"""Resolve the local restore handoff and copy arguments from the retained ELF."""
import csv
import hashlib
from pathlib import Path
import struct
import sys

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]
sys.path.insert(0, str(ROOT / "tools"))
from elf_index import sections


def main():
    data = (ROOT / "artifacts/node/115/hl-node").read_bytes()
    if hashlib.sha256(data).hexdigest() != "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301":
        raise ValueError("node #115 digest mismatch")
    table = {row["name"]: row for row in sections(data)}

    def read(section, va, size):
        row = table[section]
        delta = va - row["address"]
        if not 0 <= delta <= row["size"] - size:
            raise ValueError(f"address outside {section}: {va:#x}")
        start = row["offset"] + delta
        return data[start:start + size]

    spans = {}
    with (PACKET / "trace.tsv").open() as handle:
        for row in csv.DictReader(handle, delimiter="\t"):
            va = int(row["va"], 16)
            raw = bytes.fromhex(row["bytes"])
            if va in spans or read(".text", va, len(raw)) != raw:
                raise ValueError(f"instruction mismatch at {va:#x}")
            spans[va] = raw

    def target(va):
        raw = spans[va]
        return va + len(raw) + struct.unpack("<i", raw[-4:])[0]

    rela = table[".rela.dyn"]
    slots = {slot: (kind, value) for slot, kind, value in struct.iter_unpack(
        "<QQq", data[rela["offset"]:rela["offset"] + rela["size"]])}
    for va, dest in ((0x2cc19ea, 0x3c13610), (0x3c13665, 0x3c2e860),
                     (0x4468328, 0x1696db0), (0x4468379, 0x15028f0),
                     (0x44682ad, 0x1500a60), (0x1502920, 0x1500a60),
                     (0x44682cf, 0x5c8f4c0)):
        if slots[target(va)] != (8, dest):
            raise ValueError(f"relocation at {va:#x}")
    for va, dest in ((0x3c2ec16, 0x434b9f0), (0x434bb32, 0x38b3830),
                     (0x434bb4f, 0x44681e0), (0x4468228, 0x1696d50),
                     (0x4468317, 0x1699c10), (0x1502928, 0x1502aeb)):
        if target(va) != dest:
            raise ValueError(f"relative target at {va:#x}")
    for va, literal in ((0x4468334, b"\xc0\x01/\xc0\x00"), (0x1696de9, b"EvmState"),
                        (0x15029ed, b"-al"), (0x1502a05, b"cp")):
        if read(".rodata", target(va), len(literal)) != literal:
            raise ValueError(f"literal reference at {va:#x}")
    print(f"{len(spans)} instructions; selected row/EvmState -> live home; cp -al")


if __name__ == "__main__":
    main()
