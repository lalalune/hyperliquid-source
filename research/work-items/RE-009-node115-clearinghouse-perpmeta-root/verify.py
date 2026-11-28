"""Verify named PerpMeta numeric and length-prefixed string root streams."""

import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
from tempfile import TemporaryDirectory

from compare_perpmeta import compare, load_scalars

sys.path.insert(0, str(Path.cwd() / "tools"))
from clearinghouse_fields_115 import bind
from freeze_snapshot_115 import read_va, relative_relocations, rip_target

TARGET = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
DRIVER = "6791575648e65e8ef4fe42536b7327f85c57327cb2423255b598fb2b1d83828f"


def native():
    data = Path("artifacts/node/115/hl-node").read_bytes()
    assert hashlib.sha256(data).hexdigest() == TARGET
    fields = {r["name"]: int(r["offset"], 16) for r in bind(data)["perp_meta"]["fields"]}
    assert {key: fields[key] for key in ("pdi", "collateralToken", "collateralTokenName")} == {
        "pdi": 0x50, "collateralToken": 0x58, "collateralTokenName": 0x18}
    for va, raw in {
        0x3D1C96B: "488d4f5048894c2418", 0x3D1C995: "488d4f5848894c2438",
        0x3D1C9AA: "4883c71848897c2448", 0x3C404CF: "488b7350",
        0x46468D9: "498b3e", 0x4303B9C: "488b7708488b5710",
        0x14199DC: "48890c02", 0x141A8E8: "48891c014883c008", 0x141A90A: "4889da",
        0x141A913: "4901df4d897e10",
    }.items():
        raw = bytes.fromhex(raw)
        assert read_va(data, va, len(raw)) == raw, hex(va)
    for va, prefix, target in (
        (0x3D1C974, "488d0d", 0x6473FD0), (0x3D1C99E, "488d0d", 0x6474020),
        (0x3D1C9B3, "488d0d", 0x6477DE0), (0x457D480, "ff25", 0x64DF538),
        (0x4302E70, "ff25", 0x64DF538), (0x4303BA7, "e8", 0x141A8C0),
        (0x141A90D, "ff15", 0x64DF508),
    ):
        op = bytes.fromhex(prefix)
        assert rip_target(data, va, op, len(op) + 4) == target, hex(va)
    reloc = relative_relocations(data)
    for loc, target in {0x6473FE8: 0x457D480, 0x6474038: 0x4302E70,
                        0x6477DF8: 0x4303B90, 0x64DF538: 0x14199B0}.items():
        assert reloc[loc] == target, hex(loc)
    print(f"PASS: node #115 SHA-256 {TARGET}")
    print("PASS: pdi and collateral token share U64 appender; name has a U64 byte-size prefix per row")


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
        fields = {"ctx": {"height": height}, "cls": [{"meta": row} for row in rows]}
        return write("checkpoint.rmp", msgpack.packb({"exchange": {"locus": fields}}))

    def reference(count, parts):
        cls = [[1, leaf(struct.pack("<Q", count))]]
        if count:
            cls.insert(0, [0, [[0, [[slot, leaf(raw)] for slot, raw in parts]]]])
        nodes = [[0, [[0, [[2, leaf(struct.pack("<Q", height))]]], [1, cls]]]]
        return write("raw.json", json.dumps({"height": height, "exchange_abci_hash": nodes,
                                             "abci_digest": tree.digest(helper, tree.decode_tree(nodes))}).encode())

    rows = [{"pdi": 7, "collateralToken": 8000, "collateralTokenName": "例A"},
            {"pdi": 2, "collateralToken": 0, "collateralTokenName": ""}]
    checkpoint = make(rows)
    good_parts = [(1, struct.pack("<QQ", 7, 2)), (3, struct.pack("<QQ", 8000, 0)),
                  (4, struct.pack("<Q", 4) + "例A".encode() + bytes(8))]
    result = compare(scalars, kit, helper, height, *checkpoint, *reference(2, good_parts))
    assert result["ordered_count_matches"] and all(result["streams_match"].values())
    for slot, key, wrong in (
        (1, "pdi", struct.pack("<QQ", 2, 7)),
        (3, "collateralToken", struct.pack("<QQ", 0, 8000)),
        (4, "collateralTokenName", struct.pack("<Q", 2) + "例A".encode() + bytes(8)),
    ):
        parts = [(i, wrong if i == slot else payload) for i, payload in good_parts]
        result = compare(scalars, kit, helper, height, *checkpoint, *reference(2, parts))
        assert result["ordered_count_matches"] and [k for k, v in result["streams_match"].items() if not v] == [key]
    assert all(compare(scalars, kit, helper, height, *make([]), *reference(0, []))["streams_match"].values())
    print(f"PASS: msgpack {msgpack.__version__}; independently encoded named PerpMeta two-row and empty fixtures")
    print("PASS: isolated wrong PDI order, collateral token order and Unicode character-count length")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--helpers", required=True, type=Path)
    parser.add_argument("--rustc", required=True, type=Path)
    args = parser.parse_args()
    native()
    with TemporaryDirectory() as directory:
        fixtures(args.helpers, args.rustc, Path(directory))
