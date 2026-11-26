#!/usr/bin/env python3
"""Verify the #115 Action serializer-tag to method-dispatch crosswalk."""
from pathlib import Path
import csv
import hashlib
import json
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from elf_index import sections  # noqa: E402
from fde_extents import eh_frame_records  # noqa: E402

BINARY = ROOT / "artifacts/node/115/hl-node"
SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
DISPATCH_FDE = (0x36C3180, 0x36C5348)
TABLE_BASE = 0x79B120
TAG_BASE = 0x86
DEFAULT_INDEX = 20
ENTRY_COUNT = 92
VARIANTS = ROOT / "research/work-items/RE-010-action-serialize-tag-dispatch-115/variants.tsv"
OUT = ROOT / "research/work-items/action-wire-variant-dispatch-crosswalk-115"

ANCHORS = {
    0x36C3180: "4157415641554154534881ecf0080000",
    0x36C319C: "488b06482d86000000bf14000000480f43f8",
    0x36C31B6: "488d05637f0dfd48633cb84801c7ffe7",
}
SPECIAL_TAG_RULE = "<0x86"


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


def read_variants(path=VARIANTS):
    with Path(path).open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle, delimiter="\t"))


def target_for_index(image, table_base, index):
    entry = table_base + index * 4
    displacement = struct.unpack("<i", image.read(entry, 4))[0]
    return entry, table_base + displacement


def check_image(image, variants=None):
    if image.fdes.get(DISPATCH_FDE[0]) != DISPATCH_FDE[1]:
        raise EvidenceError("dispatcher FDE mismatch")
    for va, hex_bytes in ANCHORS.items():
        expected = bytes.fromhex(hex_bytes)
        if image.read(va, len(expected)) != expected:
            raise EvidenceError(f"dispatcher instruction bytes changed at {va:#x}")

    lea = image.read(0x36C31B6, 7)
    table_base = 0x36C31B6 + 7 + struct.unpack_from("<i", lea, 3)[0]
    if table_base != TABLE_BASE:
        raise EvidenceError(f"dispatcher table base mismatch: {table_base:#x}")

    rows = read_variants() if variants is None else variants
    if len(rows) != ENTRY_COUNT:
        raise EvidenceError(f"expected {ENTRY_COUNT} serializer variants, found {len(rows)}")
    output, indices, targets = [], [], []
    for row in rows:
        try:
            index = int(row["index"], 10)
            variant = row["rust_variant"]
            wire_name = row["wire_name"]
            tag_rule = row["tag_word"]
        except (KeyError, TypeError, ValueError) as exc:
            raise EvidenceError("malformed serializer variant row") from exc

        if tag_rule == SPECIAL_TAG_RULE:
            if index != DEFAULT_INDEX or variant != "VoteGlobal":
                raise EvidenceError("below-base tag rule is not the VoteGlobal default row")
            dispatch_rule = f"tag < {TAG_BASE:#x} -> default {DEFAULT_INDEX}"
        else:
            try:
                tag_value = int(tag_rule, 16)
            except ValueError as exc:
                raise EvidenceError(f"invalid serializer tag rule at index {index}") from exc
            if tag_value < TAG_BASE or tag_value >= TAG_BASE + ENTRY_COUNT:
                raise EvidenceError(f"tag outside the 92-entry niche range at index {index}")
            if tag_value - TAG_BASE != index:
                raise EvidenceError(f"tag/index mismatch at index {index}: {tag_rule}")
            dispatch_rule = f"tag {tag_rule} -> index {index}"

        if not variant or not wire_name:
            raise EvidenceError(f"missing variant name at index {index}")
        entry, target = target_for_index(image, table_base, index)
        if not DISPATCH_FDE[0] <= target < DISPATCH_FDE[1]:
            raise EvidenceError(f"table target outside dispatcher FDE at index {index}: {target:#x}")
        prefix = image.read(target, 12).hex()
        indices.append(index)
        targets.append(target)
        output.append({
            "index": index, "tag_rule": tag_rule, "dispatch_rule": dispatch_rule,
            "rust_variant": variant, "serde_wire_name": wire_name,
            "table_entry_va": entry, "target_va": target,
            "target_prefix_12_bytes_hex": prefix,
        })

    if sorted(indices) != list(range(ENTRY_COUNT)):
        raise EvidenceError("serializer indices are not a complete 0..91 set")
    if len(set(targets)) != ENTRY_COUNT:
        raise EvidenceError("dispatcher targets are not unique across the 92 entries")
    output.sort(key=lambda row: row["index"])
    return table_base, output


def write_packet(out=OUT):
    image = load_image()
    table_base, rows = check_image(image)
    out.mkdir(parents=True, exist_ok=True)
    with (out / "crosswalk.tsv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle, delimiter="\t", lineterminator="\n")
        writer.writerow([
            "index", "tag_rule", "dispatch_rule", "rust_variant", "serde_wire_name",
            "table_entry_va", "target_va", "target_prefix_12_bytes_hex",
        ])
        for row in rows:
            writer.writerow([
                row["index"], row["tag_rule"], row["dispatch_rule"], row["rust_variant"],
                row["serde_wire_name"], f"{row['table_entry_va']:#x}",
                f"{row['target_va']:#x}", row["target_prefix_12_bytes_hex"],
            ])
    summary = {
        "target_sha256": SHA256,
        "dispatcher_fde": [f"{DISPATCH_FDE[0]:#x}", f"{DISPATCH_FDE[1]:#x}"],
        "table_base": f"{table_base:#x}", "tag_base": f"{TAG_BASE:#x}",
        "default_index_for_below_base_tags": DEFAULT_INDEX,
        "serializer_variant_rows": len(rows),
        "matched_indices": len({row["index"] for row in rows}),
        "unique_dispatch_targets": len({row["target_va"] for row in rows}),
        "special_below_base_variant": "VoteGlobal",
        "runtime_object_identity_claimed": False,
    }
    (out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    files = [out / "crosswalk.tsv", out / "summary.json"]
    manifest_rows = []
    for path in sorted(files, key=lambda path: path.name):
        try:
            name = path.relative_to(ROOT).as_posix()
        except ValueError:
            name = path.name
        manifest_rows.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {name}\n")
    manifest = "".join(manifest_rows)
    (out / "MANIFEST.sha256").write_text(manifest, encoding="ascii")
    return table_base, rows


def main():
    table_base, rows = write_packet()
    print(
        f"target {SHA256}: joined {len(rows)} Action variant/tag rules to "
        f"{len({row['target_va'] for row in rows})} unique dispatcher arms at {table_base:#x}; "
        f"VoteGlobal below-base default maps to index {DEFAULT_INDEX}"
    )
    print("static crosswalk only; runtime object identity is not claimed")


if __name__ == "__main__":
    main()
