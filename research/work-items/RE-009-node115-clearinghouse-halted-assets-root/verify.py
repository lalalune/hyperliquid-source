"""Verify the complete named Clearinghouse halted-assets raw subtree."""

import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
from tempfile import TemporaryDirectory

from compare_halted_assets import compare, load_scalars

sys.path.insert(0, str(Path.cwd() / "tools"))
from clearinghouse_fields_115 import bind
from freeze_snapshot_115 import read_va, relative_relocations, rip_target

TARGET = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
DRIVER = "6791575648e65e8ef4fe42536b7327f85c57327cb2423255b598fb2b1d83828f"


def native():
    data = Path("artifacts/node/115/hl-node").read_bytes()
    assert hashlib.sha256(data).hexdigest() == TARGET
    fields = {r["name"]: int(r["offset"], 16) for r in bind(data)["clearinghouse"]["fields"]}
    assert fields["halted_assets"] == 0x4C8
    for va, raw in {
        0x4504363: "488d8fc8040000", 0x450F8B1: "4c8b6f10",
        0x450F943: "488b6f08", 0x450F96E: "4a8d04f34883c008",
        0x450FA70: "498b5d00", 0x450FB61: "4c896c2430",
        0x450FB81: "4c89642450", 0x464A7A1: "488b30",
        0x14199DC: "48890c02",
    }.items():
        raw = bytes.fromhex(raw)
        assert read_va(data, va, len(raw)) == raw, hex(va)
    for va, prefix, target in (
        (0x448243B, "e8", 0x464A630), (0x4504372, "488d0d", 0x648CC78),
        (0x450F986, "488d05", 0x648E380), (0x450FB70, "488d0d", 0x648E1F0),
        (0x450FBA1, "e8", 0x41AE280), (0x3916050, "ff25", 0x64DF538),
        (0x464A7A4, "e8", 0x37BE790),
    ):
        op = bytes.fromhex(prefix)
        assert rip_target(data, va, op, len(op) + 4) == target, hex(va)
    reloc = relative_relocations(data)
    for loc, target in {0x648CC90: 0x450F8A0, 0x648E398: 0x3916050,
                        0x648E208: 0x14199B0, 0x64DF538: 0x14199B0}.items():
        assert reloc[loc] == target, hex(loc)
    print(f"PASS: node #115 SHA-256 {TARGET}")
    print("PASS: halted-assets named U64 array and raw per-row ordered ID and length lanes")


def build_driver(folder, rustc, tmp):
    driver = (folder / "RE-009-node115-context-root-isolation/hash_tree.rs").read_bytes()
    assert hashlib.sha256(driver).hexdigest() == DRIVER
    source = tmp / "hash_tree.rs"
    source.write_bytes(driver)
    library = tmp / "libnode115_abci_blake3.rlib"
    output = tmp / "hash_tree"
    subprocess.run([rustc, "--edition=2024", "--crate-type", "rlib", "--crate-name",
                    "node115_abci_blake3", "src/node115-abci-blake3/src/lib.rs", "-o", library], check=True)
    subprocess.run([rustc, "--edition=2024", source, "--extern", f"node115_abci_blake3={library}",
                    "-o", output], check=True)
    return output


def fixtures(folder, rustc, tmp):
    import msgpack

    scalars = load_scalars(folder)
    kit = scalars.load_helpers(folder)
    tree = kit["tree"]
    helper = build_driver(folder, rustc, tmp)
    height = 905

    def write(name, data):
        path = tmp / name
        path.write_bytes(data)
        return path, hashlib.sha256(data).hexdigest()

    def leaf(data):
        return subprocess.check_output([helper], input=data).decode().strip()

    def make(rows):
        fields = {"ctx": {"height": height}, "cls": [{"halted_assets": row} for row in rows]}
        return write("checkpoint.rmp", msgpack.packb({"exchange": {"locus": fields}}))

    def reference(clearinghouses, sizes, assets=b""):
        cls = [[1, leaf(struct.pack("<Q", clearinghouses))]]
        if clearinghouses:
            selected = [[1, leaf(sizes)]]
            if assets:
                selected.insert(0, [0, leaf(assets)])
            cls.insert(0, [0, [[9, selected]]])
        nodes = [[0, [[0, [[2, leaf(struct.pack("<Q", height))]]], [1, cls]]]]
        return write("raw.json", json.dumps({"height": height, "exchange_abci_hash": nodes,
                                             "abci_digest": tree.digest(helper, tree.decode_tree(nodes))}).encode())

    def run(checkpoint, reference):
        return compare(scalars, kit, helper, height, *checkpoint, *reference)

    checkpoint = make([[5, 41], [], [7, 41, 2**40]])
    sizes = struct.pack("<QQQ", 2, 0, 3)
    assets = struct.pack("<QQQQQ", 5, 41, 7, 41, 2**40)
    assert run(checkpoint, reference(3, sizes, assets))["ordered_halted_assets_match"]
    assert not run(checkpoint, reference(3, struct.pack("<QQQ", 3, 0, 2), assets))["ordered_halted_assets_match"]
    result = run(checkpoint, reference(3, sizes, struct.pack("<QQQQQ", 7, 41, 5, 41, 2**40)))
    assert result["ordered_count_matches"] and not result["ordered_halted_assets_match"]
    assert run(make([[], []]), reference(2, bytes(16)))["ordered_halted_assets_match"]
    assert run(make([]), reference(0, b""))["ordered_halted_assets_match"]
    for rows in ([[4, 2]], [[4, 4]]):
        try:
            run(make(rows), reference(1, struct.pack("<Q", 2), struct.pack("<QQ", *rows[0])))
        except ValueError as error:
            assert "ascending unique" in str(error), error
        else:
            raise AssertionError(rows)
    print(f"PASS: msgpack {msgpack.__version__}; empty nested assets and a complete three-row raw subtree")
    print("PASS: preserve repeated IDs across Clearinghouses, ordered grouping and full U64 asset width")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--helpers", required=True, type=Path)
    parser.add_argument("--rustc", required=True, type=Path)
    args = parser.parse_args()
    native()
    with TemporaryDirectory() as directory:
        fixtures(args.helpers, args.rustc, Path(directory))
