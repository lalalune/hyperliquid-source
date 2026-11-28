"""Verify the selected native tree lookup and ordinary projected replay fixtures."""

from argparse import ArgumentParser
import csv
from importlib.util import module_from_spec, spec_from_file_location
import json
from pathlib import Path
import struct
import subprocess
import sys
from tempfile import TemporaryDirectory

from tree_case import require, resolve, sha

PACKET = Path(__file__).resolve().parent
CUSTODY = "bd556b607be44e4f54446e5442edd1db56c41365"
CUSTODY_PACKET = "RE-017-node115-missing-attachment-custody"


def native(repo):
    sys.path.insert(0, str(repo / "tools"))
    from foundation_lsda_call_site import TARGET, TARGET_SHA256, parse_sections, walk_eh_frame
    data = (repo / TARGET).read_bytes()
    require(sha(data) == TARGET_SHA256, "wrong node image")
    sections = {row["name"]: row for row in parse_sections(data)}

    def read(name, address, length):
        region = sections[name]
        relative = address - region["va"]
        require(0 <= relative <= relative + length <= region["size"], "outside ELF section")
        first = region["offset"] + relative
        return data[first:first + length]

    eh = sections[".eh_frame"]
    _, fdes = walk_eh_frame(read(".eh_frame", eh["va"], eh["size"]), eh["va"])
    extents = {(row["entry"], row["end"]) for row in fdes}
    spans = {}
    with (PACKET / "anchors.tsv").open() as stream:
        for row in csv.DictReader(stream, delimiter="\t"):
            entry, end, va = (int(row[key], 16) for key in ("start", "end", "address"))
            raw = bytes.fromhex(row["bytes"])
            require((entry, end) in extents and entry <= va < va + len(raw) <= end
                    and read(".text", va, len(raw)) == raw, f"wrong anchored bytes at {va:#x}")
            spans[va] = raw
            print(f"{entry:#x}..{end:#x} {va:#x} {raw.hex()} {row['instruction']}")

    def displacement(va, length=4):
        return int.from_bytes(spans[va][-length:], "little", signed=True)

    def target(va, length=4):
        return va + len(spans[va]) + displacement(va, length)

    for site, edge, width in (
        (0x4fad7ff, 0x4fad964, 4), (0x4fad8b3, 0x4fad8f0, 1),
        (0x4fad8df, 0x4fad8b0, 1), (0x4fad8e9, 0x4fad910, 1),
        (0x4fad8eb, 0x4fad8f8, 1), (0x4fad8fc, 0x4fadaf0, 4),
        (0x4fad90a, 0x4fad892, 1), (0x4fad85d, 0x4fada64, 4),
        (0x4fad94e, 0x4fad820, 4), (0x4fadaf8, 0x4fadb12, 1),
    ):
        require(target(site, width) == edge, f"selected edge differs at {site:#x}")
    rel = sections[".rela.dyn"]
    imports = {slot: (info, addend) for slot, info, addend in
               struct.iter_unpack("<QQq", read(".rela.dyn", rel["va"], rel["size"]))}
    require(imports[target(0x4fad8c3)] == (0xc00000006, 0), "wrong memcmp import")
    require(displacement(0x4fad892) == 0x1c2 and displacement(0x4fad902) == 0x1c8
            and displacement(0x4fad910) == 0x168, "wrong native tree offsets")
    require(displacement(0x4fad8b9) == 32 and spans[0x4fadb3e][-1] == 0x1c,
            "wrong key or missing result tag")
    print(f"verified {len(spans)} pinned tree lookup spans and selected attachment owner results")


def build(repo, scratch):
    source = scratch / "existing-wire-projection"
    source.mkdir()
    for name in ("verify.py", "objects.py", "probe.rs"):
        data = subprocess.check_output(
            ["git", "show", f"{CUSTODY}:research/work-items/{CUSTODY_PACKET}/{name}"], cwd=repo,
        )
        (source / name).write_bytes(data)
    sys.path.insert(0, str(source))
    spec = spec_from_file_location("existing_owner_wire_projection", source / "verify.py")
    previous = module_from_spec(spec)
    spec.loader.exec_module(previous)
    return previous.build(repo, scratch)


def tests(scratch, probe):
    keys = {label: bytes([value] * 32) for label, value in zip("ABCDEF", (16, 32, 48, 64, 80, 96))}

    def node(entries, children=()):
        return {
            "entries": [["0x" + keys[key].hex(), value] for key, value in entries],
            "children": list(children),
        }

    # Two separator values and three children expose each descent lane.
    tree = {"depth": 1, "root": node((("B", 22), ("D", 44)), (
        node((("A", 11),)), node((("C", 33),)), node((("E", 55),)),
    ))}
    source = scratch / "independent-tree.json"
    source.write_text(json.dumps(tree))

    def observed(order):
        wire = (bytes(10) + bytes([0x31] * 20) + bytes([len(order)])
                + b"".join(keys[key] for key in order)
                + bytes([0, 7, 0, 1, 2, 3, 4, 5]) + bytes([0x71] * 32) + bytes(3))
        origin = scratch / "wire.bin"
        origin.write_bytes(wire)
        result = resolve(origin, sha(wire), source, sha(source.read_bytes()), probe)
        print(json.dumps(result))
        return result

    available = observed("ECBAE")
    rows = available["rows"]
    require(available["status"] == "materialized"
            and [row["child_path"] for row in rows] == [[2], [1], [], [0], [2]]
            and [row["opaque_value"] for row in rows] == [55, 33, 22, 11, 55],
            "wrong tree descent, direct separator result, or input order")
    absent = observed("EFA")
    require(absent["status"] == "missing" and absent["position"] == 1
            and absent["key"] == "0x" + keys["F"].hex() and "rows" not in absent, "wrong first miss")
    print("verified inner-key hits, left/middle/right descent, repeated order and first missing key")


if __name__ == "__main__":
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--wire", type=Path)
    parser.add_argument("--wire-sha")
    parser.add_argument("--tree", type=Path)
    parser.add_argument("--tree-sha")
    args = parser.parse_args()
    supplied = (args.wire, args.wire_sha, args.tree, args.tree_sha)
    if any(supplied) and not all(supplied):
        parser.error("supply the decoded wire and tree observation artifact paths and SHA-256 pins")
    with TemporaryDirectory() as folder:
        scratch = Path(folder)
        native(args.repo.resolve())
        probe = build(args.repo.resolve(), scratch)
        if args.wire:
            result = resolve(*supplied, probe)
            print(json.dumps(result))
            raise SystemExit(0 if result["status"] == "materialized" else 1)
        tests(scratch, probe)
