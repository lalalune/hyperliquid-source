#!/usr/bin/env python3
"""Qualify current registered source comparisons and the previously unowned data island."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
import tarfile
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "tools"))
from byte_progress import load_coverage
from elf_index import sections, unwind_index
from entry_start_static import read, rip_target
from fde_extents import eh_frame_records

ARCHIVES = {
    "0.1.6": "59cbb88c189d6352cc8ae96a39d19c7ecad8f7330b29461187f2587fdc2988d5",
    "0.1.9": "471668161349031e3d415412f996b030c477488eec267cc3cadae3d06c0a367f",
}
FUNCTIONS = {"__KeccakF1600": 0x633A000, "KeccakF1600": 0x633A2E0,
             "KECCAK_ASM_SHA3_absorb": 0x633A380, "KECCAK_ASM_SHA3_squeeze": 0x633A460}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def provider_object(version, archives, root, clang, readelf):
    package = "sha3-asm-" + version
    archive = archives / (package + ".crate")
    assert sha(archive.read_bytes()) == ARCHIVES[version]
    root.mkdir()
    with tarfile.open(archive) as tar:
        # Both independently verified packages ship the generator and its translator together.
        for name in ("keccak1600-x86_64.pl", "x86_64-xlate.pl"):
            with tar.extractfile(f"{package}/cryptogams/x86_64/{name}") as source:
                (root / name).write_bytes(source.read())
    subprocess.run(["perl", "./keccak1600-x86_64.pl", "elf", "keccak.S"], cwd=root, check=True)
    subprocess.run([clang, "--target=x86_64-unknown-linux-gnu", "-c", "keccak.S",
                    "-DSHA3_absorb=KECCAK_ASM_SHA3_absorb", "-DSHA3_squeeze=KECCAK_ASM_SHA3_squeeze",
                    "-o", "keccak.o"], cwd=root, check=True)
    obj = (root / "keccak.o").read_bytes()
    assert struct.unpack_from("<HH", obj, 16) == (1, 62)  # ET_REL, EM_X86_64
    text_index, text = next((i, row) for i, row in enumerate(sections(obj)) if row["name"] == ".text")
    names = set(FUNCTIONS) | {"iotas"}
    symbols = {}
    listing = subprocess.check_output([readelf, "-sW", "keccak.o"], cwd=root, text=True)
    for line in listing.splitlines():
        fields = line.split()
        if len(fields) == 8 and fields[-1] in names:
            name = fields[-1]
            assert name not in symbols and int(fields[6]) == text_index
            assert fields[3] == ("OBJECT" if name == "iotas" else "FUNC")
            if name == "iotas":
                assert fields[4] == "LOCAL"
            symbols[name] = int(fields[1], 16), int(fields[2])
    assert set(symbols) == names
    return obj[text["offset"]:text["offset"] + text["size"]], symbols


def keccak_iota_table():
    # FIPS 202 section 3.2.5. Advance the eight-bit LFSR seven times per round.
    state = 1
    entries = []
    for _ in range(24):
        word = 0
        for j in range(7):
            if state & 1:
                word |= 1 << ((1 << j) - 1)
            state = ((state << 1) ^ (0x71 if state & 0x80 else 0)) & 0xff
        entries.append(word)
    return struct.pack("<24Q", *entries)


def qualify_data(data, fdes, island, build):
    source, symbols = build
    base = FUNCTIONS["KeccakF1600"] - symbols["KeccakF1600"][0]
    for name, address in FUNCTIONS.items():
        offset, size = symbols[name]
        assert base + offset == address and (address, address + size) in fdes
    table, size = symbols["iotas"]
    assert size == 24 * 8 and source[table:table + size] == keccak_iota_table()
    for site in (0x633A311, 0x633A3B9):
        assert read(data, site, 3)[1] == bytes.fromhex("4c8d3d")
        assert rip_target(data, site, 3) == base + table
    start = int(island["start_va"], 16)
    end = int(island["end_va"], 16)
    complete = read(data, start, end - start)[1]
    assert sha(complete) == island["sha256"]
    tail = source[start - base:]
    assert source[table - 64:table] == bytes(64) and start == base + table - 64
    assert complete[:len(tail)] == tail and complete[len(tail):] == b"\xcc"
    credit = source[table + size:]
    assert credit.endswith(b"\0") and b"CRYPTOGAMS" in credit
    return {"source_object_data_start": hex(start - base), "source_text_end": hex(len(source)),
            "target_start": hex(start), "target_data_end_exclusive": hex(start + len(tail)),
            "source_equal_bytes": len(tail), "source_data_sha256": sha(tail), "leading_zero_bytes": 64,
            "iotas_target": hex(base + table), "iotas_size": size, "iotas_sha256": sha(source[table:table + size]),
            "credit_including_terminator_bytes": len(credit), "island_residual_hex": complete[len(tail):].hex()}


def compare(archives, clang, readelf):
    gaps = json.loads((HERE / "node-115-gap-classes.json").read_text())
    data = (ROOT / "artifacts/node/115/hl-node").read_bytes()
    assert sha(data) == gaps["binary_sha256"]
    index = {row["start"] for row in unwind_index(data)[1]}
    fdes = {(row["start"], row["end"]) for row in eh_frame_records(data)[1]}
    assert index == {start for start, end in fdes}
    components = json.loads((ROOT / "research/components.json").read_text())["components"]
    cov = load_coverage(ROOT, "research/byte-windows.json", components)
    rows = [row for row in cov["windows"] if row["target"] == "node115"]
    outside = [row for row in rows if row["start"] not in index]
    islands = []
    for island in gaps["islands"]:
        start, end = int(island["start_va"], 16), int(island["end_va"], 16)
        assert sha(read(data, start, end - start)[1]) == island["sha256"]
        providers = sorted((r for r in outside if start <= r["start"] < end), key=lambda r: r["start"])
        if providers:
            assert providers[0]["start"] == start and providers[-1]["end"] == end
            assert all(a["end"] == b["start"] for a, b in zip(providers, providers[1:]))
            assert [r["start"] for r in providers] == [int(pc, 16) for pc in island["entrypoints"]]
            assert all(r["relocation_qualified"] for r in providers)
            assert all(right <= start or left >= end for left, right in fdes)
        islands.append({"start": hex(start), "end": hex(end), "class": island["class"],
                        "registered_windows": [r["id"] for r in providers],
                        "raw_equal_windows": sum(r["raw_equal"] for r in providers),
                        "relocation_qualified_windows": sum(r["relocation_qualified"] for r in providers),
                        "raw_equal_bytes": sum(r["raw_equal_bytes"] for r in providers),
                        "entrypoints": island["entrypoints"]})
    assert sum(len(item["registered_windows"]) for item in islands) == len(outside)
    prior = next(x for x in gaps["islands"] if x["start_va"] == "0x633a500")
    assert prior["class"] == "pointer_operand_only"
    assert all(b <= 0x633A500 or a >= 0x633A64E for a, b in fdes)
    with tempfile.TemporaryDirectory() as tmp:
        builds = {v: qualify_data(data, fdes, prior, provider_object(v, archives, Path(tmp) / v, clang, readelf))
                  for v in ARCHIVES}
    return {"node_sha256": gaps["binary_sha256"], "aligned_windows": len(rows),
            "indexed_starts": len(index), "compared_indexed_starts": len({r["start"] for r in rows} & index),
            "single_windows_matching_both_fde_ends": sum((r["start"], r["end"]) in fdes for r in rows),
            "outside_index": len(outside), "outside_index_bytes": sum(r["bytes"] for r in outside),
            "gap_islands": islands, "source_archives": ARCHIVES, "keccak_data_builds": builds}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archives", type=Path)
    parser.add_argument("--clang", default="clang")
    parser.add_argument("--readelf", default="readelf")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    report = compare(args.archives.resolve(), args.clang, args.readelf)
    print(json.dumps(report, indent=2))
    if args.check and report != json.loads((HERE / "provider-coverage.json").read_text()):
        raise SystemExit("provider coverage differs from retained evidence")
