"""Verify the complete named PerpMeta universe raw subtree."""

import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
from tempfile import TemporaryDirectory

from compare_universe import compare, load_scalars

sys.path.insert(0, str(Path.cwd() / "tools"))
from clearinghouse_fields_115 import bind
from freeze_snapshot_115 import read_va, relative_relocations, rip_target

TARGET = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
DRIVER = "6791575648e65e8ef4fe42536b7327f85c57327cb2423255b598fb2b1d83828f"


def native():
    data = Path("artifacts/node/115/hl-node").read_bytes()
    assert hashlib.sha256(data).hexdigest() == TARGET
    fields = {r["name"]: int(r["offset"], 16) for r in bind(data)["perp_meta"]["fields"]}
    assert fields["universe"] == 0
    for va, raw in {
        0x3D6AF51: "488b6f10", 0x3D6AF92: "4d8b6e08", 0x3D6AFD6: "4983c520",
        0x44F5DCA: "488d4f1d48894c2408", 0x44F5DDF: "48897c2418",
        0x44F5DF0: "488d4f1848894c2428", 0x44F5E05: "4883c71c48897c2438",
        0x141964B: "880c0248ffc0", 0x141B49A: "890c024883c004",
        0x141A8E8: "48891c014883c008", 0x3D1DC35: "48c7042401000000",
        0x3D1DC8A: "48c7042400000000", 0x3D1DCD8: "48c7042402000000",
    }.items():
        raw = bytes.fromhex(raw)
        assert read_va(data, va, len(raw)) == raw, hex(va)
    for va, prefix, target in (
        (0x3D1C95F, "488d0d", 0x6478288), (0x3D6AFAE, "4c8d35", 0x647A588),
        (0x3D6B038, "488d0d", 0x6479F20), (0x3D6B069, "e8", 0x41AE280),
        (0x44F5DD3, "488d0d", 0x648DC18), (0x44F5DE4, "488d0d", 0x648DC40),
        (0x44F5DF9, "488d0d", 0x648D628), (0x44F5E0E, "488d0d", 0x648DC68),
        (0x43D0CB0, "ff25", 0x64DF5B0), (0x4303BA7, "e8", 0x141A8C0),
        (0x3D1DD33, "ff15", 0x64DF538),
    ):
        op = bytes.fromhex(prefix)
        assert rip_target(data, va, op, len(op) + 4) == target, hex(va)
    for va, name in ((0x2D3B204, b"szDecimals"), (0x2D3B22E, b"name"),
                     (0x2D3B25F, b"marginTableId"), (0x2D3B285, b"marginMode")):
        ptr = rip_target(data, va, bytes.fromhex("488d35"), 7)
        assert read_va(data, ptr, len(name)) == name
    reloc = relative_relocations(data)
    for loc, target in {0x64782A0: 0x3D6AF40, 0x647A5A0: 0x44F5DC0,
                        0x6479F38: 0x14199B0, 0x648DC30: 0x1419620,
                        0x648DC58: 0x4303B90, 0x648D640: 0x43D0CB0,
                        0x648DC80: 0x3D1DC20, 0x64DF5B0: 0x141B470}.items():
        assert reloc[loc] == target, hex(loc)
    print(f"PASS: node #115 SHA-256 {TARGET}")
    print("PASS: native PerpAssetInfo four-stream order, 32-byte row stride and per-universe length lane")


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
        fields = {"ctx": {"height": height}, "cls": [{"meta": {"universe": row}} for row in rows]}
        return write("checkpoint.rmp", msgpack.packb({"exchange": {"locus": fields}}))

    def reference(count, sizes, parts=()):
        cls = [[1, leaf(struct.pack("<Q", count))]]
        if count:
            universe = [[1, leaf(sizes)]]
            if parts:
                universe.insert(0, [0, [[slot, leaf(raw)] for slot, raw in enumerate(parts)]])
            cls.insert(0, [0, [[0, [[0, universe]]]]])
        nodes = [[0, [[0, [[2, leaf(struct.pack("<Q", height))]]], [1, cls]]]]
        return write("raw.json", json.dumps({"height": height, "exchange_abci_hash": nodes,
                                             "abci_digest": tree.digest(helper, tree.decode_tree(nodes))}).encode())

    def run(checkpoint, reference):
        return compare(scalars, kit, helper, height, *checkpoint, *reference)

    first = {"szDecimals": 3, "name": "例", "marginTableId": 253, "marginMode": "noCross"}
    second = {"szDecimals": 5, "name": "A", "marginTableId": 77777, "marginMode": "normal"}
    third = {"szDecimals": 4, "name": "", "marginTableId": 0, "marginMode": "strictIsolated"}
    checkpoint = make([[first, second], [], [third]])
    sizes = struct.pack("<QQQ", 2, 0, 1)
    parts = (bytes([3, 5, 4]), struct.pack("<Q", 3) + "例".encode() + struct.pack("<Q", 1) + b"A" + bytes(8),
             struct.pack("<III", 253, 77777, 0), struct.pack("<QQQ", 1, 0, 2))
    assert run(checkpoint, reference(3, sizes, parts))["ordered_universe_matches"]
    for bad_sizes, bad_parts in (
        (struct.pack("<QQQ", 1, 0, 2), parts),
        (sizes, (*parts[:3], struct.pack("<QQQ", 0, 1, 2))),
        (sizes, (*parts[:2], struct.pack("<QQQ", 253, 77777, 0), parts[3])),
    ):
        result = run(checkpoint, reference(3, bad_sizes, bad_parts))
        assert result["ordered_count_matches"] and not result["ordered_universe_matches"]
    assert run(make([[], []]), reference(2, bytes(16)))["ordered_universe_matches"]
    assert run(make([]), reference(0, b""))["ordered_universe_matches"]
    print(f"PASS: msgpack {msgpack.__version__}; one ordered universe subtree spanning unequal row groups")
    print("PASS: empty outer and inner sequence; isolate regrouped counts, wrong mode order and wrong integer width")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--helpers", required=True, type=Path)
    parser.add_argument("--rustc", required=True, type=Path)
    args = parser.parse_args()
    native()
    with TemporaryDirectory() as directory:
        fixtures(args.helpers, args.rustc, Path(directory))
