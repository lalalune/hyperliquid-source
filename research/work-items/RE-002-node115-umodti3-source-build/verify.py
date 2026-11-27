"""Check the retained source-built symbols against the authenticated node ELF."""
import argparse
from hashlib import sha256
import json
from pathlib import Path
import sys

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]
sys.path.insert(0, str(ROOT / "tools"))
from elf_index import sections

START, END = 0x63EFD70, 0x63EFE35
NODE_SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
OLD_SHA = "12f5828bd833666b6023e761036da32c29aeb7d1e7eedbb93d734f730f391e26"


def check_window(node, built, control):
    if sha256(node).hexdigest() != NODE_SHA:
        raise ValueError("unexpected node #115 digest")
    text, = [s for s in sections(node) if s["name"] == ".text" and s["flags"] & 4]
    if not text["address"] <= START < END <= text["address"] + text["size"]:
        raise ValueError("recorded extent outside executable .text")
    offset = text["offset"] + START - text["address"]
    target = node[offset:offset + END - START]
    if built != target:
        raise ValueError("source build differs from the captured function")
    if len(control) != len(target) or sha256(control).hexdigest() != OLD_SHA:
        raise ValueError("incorrect control extent or bytes")
    mismatches = sum(x != y for x, y in zip(target, control))
    if mismatches != 45:
        raise ValueError(f"expected 45 control mismatches, observed {mismatches}")
    return target, offset, mismatches


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("build_dir", nargs="?", type=Path, default=PACKET)
    build_dir = parser.parse_args().build_dir
    built = (build_dir / "umodti3.bin").read_bytes()
    control = (build_dir / "control-1.94.1.bin").read_bytes()
    report = json.loads((build_dir / "build-results.json").read_text())
    if report["target"] != "x86_64-unknown-linux-gnu" or report["symbol"] != "__umodti3":
        raise ValueError("build report identifies a different target or symbol")
    expected = [("build-a", "1.95.0", built), ("build-b", "1.95.0", built), ("control", "1.94.1", control)]
    for row, (label, release, body) in zip(report["builds"], expected, strict=True):
        if (row["label"], row["rust_release"], row["function_sha256"], row["length"],
                row["relocations_in_section"]) != (label, release, sha256(body).hexdigest(), len(body), 0):
            raise ValueError(f"build report disagrees with retained output for {label}")
    node = (ROOT / "artifacts/node/115/hl-node").read_bytes()
    target, offset, mismatches = check_window(node, built, control)
    previous = PACKET.parent / "RE-002-node115-std-census"
    records = json.loads((previous / "census.json").read_text())["records"]
    record, = [r for r in records if r["start"] == START and r["end"] == END]
    if not any(alias["symbol"] == "__umodti3" for alias in record["identical_sources"]):
        raise ValueError("census no longer identifies this public symbol")
    prior_bytes = (previous / "bodies.bin").read_bytes()
    begin = record["source_offset"]
    if prior_bytes[begin:begin + len(target)] != built:
        raise ValueError("published standard library disagrees with the source-built body")
    print(f"node115 VA [{START:#x},{END:#x}), file offset {offset:#x}")
    print(f"Rust 1.95.0: {len(target)}/{len(target)} raw equal, SHA-256 {sha256(target).hexdigest()}")
    print(f"Rust 1.94.1: {mismatches}/{len(target)} positions differ; no masks applied")


if __name__ == "__main__":
    main()
