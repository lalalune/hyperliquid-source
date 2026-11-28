"""Verify the #115 named checkpoint coordinate output anchors."""
import csv
import hashlib
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "tools"))
from foundation_lsda_call_site import TARGET, TARGET_SHA256, parse_sections, walk_eh_frame


def main():
    assert __debug__
    data = (ROOT / TARGET).read_bytes()
    assert hashlib.sha256(data).hexdigest() == TARGET_SHA256
    sections = {s["name"]: s for s in parse_sections(data)}
    eh = sections[".eh_frame"]
    _, fdes = walk_eh_frame(data[eh["offset"]:eh["offset"] + eh["size"]], eh["va"])
    bounds = {(row["entry"], row["end"]) for row in fdes}
    text = sections[".text"]
    proof = ROOT / "research/work-items/RE-017-node115-checkpoint-round-source/instructions.tsv"
    selected = {
        0x30d22ae, 0x30d22c5, 0x30d22dc, 0x30d2c01, 0x30d2eee,
        0x30d2ef0, 0x30d2f00, 0x30d31ba, 0x30d31be, 0x332c805,
    }
    observed = set()
    with proof.open() as stream:
        for row in csv.DictReader(stream, delimiter="\t"):
            address = int(row["linked_va"], 16)
            if address not in selected:
                continue
            start, end = (int(row[key], 16) for key in ("fde_start", "fde_end"))
            raw = bytes.fromhex(row["bytes"])
            assert (start, end) in bounds and start <= address < address + len(raw) <= end
            offset = address - text["va"] + text["offset"]
            assert data[offset:offset + len(raw)] == raw
            observed.add(address)
    assert observed == selected
    print(f"PASS: node #115 SHA-256 {TARGET_SHA256}")
    print(f"PASS: {len(observed)} anchors for separate height/round outputs and missing-round default")


if __name__ == "__main__":
    main()
