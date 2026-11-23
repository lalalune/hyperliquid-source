#!/usr/bin/env python3
"""Verify one node #115 SendToEvmWithData dispatch-to-digest call path.

The target ELF is read only. This packet joins a selected action-dispatch arm
to the existing EIP-712 wrapper and type builder; it does not resolve the
dynamic data callback or claim a complete digest vector.
"""
from pathlib import Path
import hashlib
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from elf_index import sections  # noqa: E402
from fde_extents import eh_frame_records  # noqa: E402

BINARY = ROOT / "artifacts/node/115/hl-node"
SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
TABLE_BASE = 0x79B120
ACTION_INDEX = 75
ACTION_TAG = 0xD1
ARM = 0x36C3696

EXPECTED_FDES = {
    0x36C3180: (0x36C3180, 0x36C5348),
    0x442D000: (0x442D000, 0x442D480),
    0x46E6D30: (0x46E6D30, 0x46E6F78),
    0x4433F90: (0x4433F90, 0x443431F),
    0x4428520: (0x4428520, 0x44290B4),
    0x44290C0: (0x44290C0, 0x44297EC),
}

ANCHORS = {
    0x36C3180: "4157415641554154534881ecf0080000",
    0x36C319C: "488b06482d86000000bf14000000480f43f8",
    0x36C31B6: "488d05637f0dfd48633cb84801c7ffe7",
    0x36C36AF: "ff159357e202",                  # arm calls relocated slot
    0x442D192: "ff10",                          # unresolved data callback
    0x442D31F: "e80c9a2b00",                    # calls 0x46e6d30
    0x46E6D4C: "e83fd2d4ff",                    # calls 0x4433f90
    0x44340F2: "ff1580680b02",                  # wrapper calls hash slot
    0x4428553: "ff1527240c02",                  # hash calls builder slot
}

RELOCATED_CALLS = {
    0x36C36AF: (0x64E8E48, 0x442D000),
    0x44340F2: (0x64EA978, 0x4428520),
    0x4428553: (0x64EA980, 0x44290C0),
}

DIRECT_CALLS = {
    0x442D31F: 0x46E6D30,
    0x46E6D4C: 0x4433F90,
}


class EvidenceError(ValueError):
    pass


class Image:
    def __init__(self, data):
        self.data = data
        self.sections = sections(data)
        self.file_sections = [s for s in self.sections if s["type"] != 8 and s["address"] and s["size"]]
        self.named = {s["name"]: s for s in self.sections}
        _, records = eh_frame_records(data, self.sections)
        self.fdes = {}
        for row in records:
            self.fdes[row["start"]] = max(self.fdes.get(row["start"], 0), row["end"])

    def offset(self, va, size=1):
        for s in self.file_sections:
            if s["address"] <= va and va + size <= s["address"] + s["size"]:
                return s["offset"] + va - s["address"]
        raise EvidenceError(f"unmapped file-backed VA {va:#x}+{size:#x}")

    def read(self, va, size):
        off = self.offset(va, size)
        return self.data[off:off + size]


def load_image(path=BINARY):
    data = Path(path).read_bytes()
    actual = hashlib.sha256(data).hexdigest()
    if actual != SHA256:
        raise EvidenceError(f"target SHA-256 mismatch: {actual}")
    return Image(data)


def relocation_targets(image):
    rela = image.named.get(".rela.dyn")
    if rela is None or rela["size"] % 24:
        raise EvidenceError("unexpected .rela.dyn layout")
    out = {}
    for at in range(rela["offset"], rela["offset"] + rela["size"], 24):
        slot, info, addend = struct.unpack_from("<QQq", image.data, at)
        if info & 0xFFFFFFFF == 8:
            out.setdefault(slot, []).append(addend)
    return out


def direct_target(image, site):
    raw = image.read(site, 5)
    if raw[0] != 0xE8:
        raise EvidenceError(f"not a direct call at {site:#x}")
    return site + 5 + struct.unpack_from("<i", raw, 1)[0]


def relative_table_target(image):
    entry = TABLE_BASE + ACTION_INDEX * 4
    displacement = struct.unpack("<i", image.read(entry, 4))[0]
    return entry, TABLE_BASE + displacement


def check_image(image):
    for start, expected in EXPECTED_FDES.items():
        if image.fdes.get(start) != expected[1]:
            raise EvidenceError(f"FDE mismatch at {start:#x}: {image.fdes.get(start)}")
    for va, hx in ANCHORS.items():
        if image.read(va, len(bytes.fromhex(hx))) != bytes.fromhex(hx):
            raise EvidenceError(f"instruction bytes changed at {va:#x}")

    entry, target = relative_table_target(image)
    if entry != 0x79B24C or target != ARM:
        raise EvidenceError(f"action index table target mismatch: {entry:#x} -> {target:#x}")
    if direct_target(image, 0x442D31F) != DIRECT_CALLS[0x442D31F]:
        raise EvidenceError("action method direct-call target changed")
    if direct_target(image, 0x46E6D4C) != DIRECT_CALLS[0x46E6D4C]:
        raise EvidenceError("signing caller direct-call target changed")

    relocations = relocation_targets(image)
    for site, (slot, expected_target) in RELOCATED_CALLS.items():
        raw = image.read(site, 6)
        computed_slot = site + 6 + struct.unpack_from("<i", raw, 2)[0]
        if computed_slot != slot or relocations.get(slot) != [expected_target]:
            raise EvidenceError(f"relocated call mismatch at {site:#x}")

    variant_rows = (ROOT / "research/work-items/RE-010-action-serialize-tag-dispatch-115/variants.tsv").read_text().splitlines()
    variants = [line.split("\t") for line in variant_rows[1:] if line.split("\t", 1)[0] == str(ACTION_INDEX)]
    if len(variants) != 1 or variants[0][1:5] != ["SendToEvmWithData", "sendToEvmWithData", "camelCase", "0xd1"]:
        raise EvidenceError("existing Action serializer record does not identify tag 0xd1 as variant index 75")

    rows = (ROOT / "research/work-items/action-wire-typed-data-structs-115/eip712.tsv").read_text().splitlines()
    matches = [line for line in rows if line.startswith("0x44290c0\t")]
    if len(matches) != 1 or "HyperliquidTransaction:SendToEvmWithData(" not in matches[0]:
        raise EvidenceError("existing EIP-712 builder record does not identify SendToEvmWithData")
    return entry, target


def main():
    image = load_image()
    entry, target = check_image(image)
    print(f"target {SHA256}: index {ACTION_INDEX} tag {ACTION_TAG:#x} table {entry:#x}->{target:#x}; 9 anchors, 3 relocated calls, 2 direct calls, 6 FDEs match")
    print("dynamic callback at 0x442d192 is intentionally unresolved; no complete digest is claimed")


if __name__ == "__main__":
    main()
