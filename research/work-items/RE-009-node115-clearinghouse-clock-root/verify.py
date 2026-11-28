"""Verify named Clearinghouse clock root streams."""

import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
from tempfile import TemporaryDirectory

from compare_clocks import compare, load_scalars

sys.path.insert(0, str(Path.cwd() / "tools"))
from clearinghouse_fields_115 import bind
from freeze_snapshot_115 import read_va, relative_relocations, rip_target

TARGET = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
DRIVER = "6791575648e65e8ef4fe42536b7327f85c57327cb2423255b598fb2b1d83828f"


def native():
    data = Path("artifacts/node/115/hl-node").read_bytes()
    assert hashlib.sha256(data).hexdigest() == TARGET
    fields = {r["name"]: int(r["offset"], 16) for r in bind(data)["clearinghouse"]["fields"]}
    assert {key: fields[key] for key in ("last_set_global_time", "lnsgt")} == {
        "last_set_global_time": 0x4F0, "lnsgt": 0x4FC}
    for va, raw in {
        0x45043BD: "488d97f004000048899424f8000000",
        0x45043DB: "4c8d87fc0400004c898424080100004889942410010000",
        0x141B1F1: "488b17", 0x141B296: "4889040a4883c108",
        0x141B2A2: "896c2410", 0x141B2BA: "892c014883c004",
    }.items():
        raw = bytes.fromhex(raw)
        assert read_va(data, va, len(raw)) == raw, hex(va)
    for va, prefix, target in (
        (0x44824AF, "e8", 0x4658BF0), (0x44824DD, "e8", 0x4658BF0),
        (0x45043CC, "488d15", 0x648C850), (0x3D5E950, "ff25", 0x64DF5A0),
    ):
        op = bytes.fromhex(prefix)
        assert rip_target(data, va, op, len(op) + 4) == target, hex(va)
    reloc = relative_relocations(data)
    assert reloc[0x648C868] == 0x3D5E950 and reloc[0x64DF5A0] == 0x141B1E0
    print(f"PASS: node #115 SHA-256 {TARGET}")
    print("PASS: both named clocks bind to one canonical Time leaf encoder at distinct raw slots")


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
        fields = {"ctx": {"height": height}, "cls": rows}
        return write("checkpoint.rmp", msgpack.packb({"exchange": {"locus": fields}}))

    def reference(count, parts):
        cls = [[1, leaf(struct.pack("<Q", count))]]
        if count:
            cls.insert(0, [0, [[slot, leaf(raw)] for slot, raw in parts]])
        nodes = [[0, [[0, [[2, leaf(struct.pack("<Q", height))]]], [1, cls]]]]
        return write("raw.json", json.dumps({"height": height, "exchange_abci_hash": nodes,
                                             "abci_digest": tree.digest(helper, tree.decode_tree(nodes))}).encode())

    rows = [
        {"last_set_global_time": "1969-12-31T23:59:58.000000009", "lnsgt": "1970-01-01T00:00:07"},
        {"last_set_global_time": "1970-01-01T00:00:03.123456789", "lnsgt": "1970-01-01T00:00:01.900"},
    ]
    checkpoint = make(rows)
    global_time = struct.pack("<qIqI", -2, 9, 3, 123456789)
    second_clock = struct.pack("<qIqI", 7, 0, 1, 900000000)
    result = compare(scalars, kit, helper, height, *checkpoint, *reference(2, [(12, global_time), (13, second_clock)]))
    assert result["ordered_count_matches"] and all(result["streams_match"].values())
    for changed, expected in (
        ([(12, global_time[12:] + global_time[:12]), (13, second_clock)], "last_set_global_time"),
        ([(12, global_time), (13, struct.pack("<qIqI", 7, 0, 1, 9))], "lnsgt"),
    ):
        result = compare(scalars, kit, helper, height, *checkpoint, *reference(2, changed))
        assert result["ordered_count_matches"] and [k for k, v in result["streams_match"].items() if not v] == [expected]
    assert all(compare(scalars, kit, helper, height, *make([]), *reference(0, []))["streams_match"].values())
    print(f"PASS: msgpack {msgpack.__version__}; empty and two-row signed-second and nanosecond clocks")
    print("PASS: isolate rows reordered only for global time and incorrectly scaled nanos only for lnsgt")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--helpers", required=True, type=Path)
    parser.add_argument("--rustc", required=True, type=Path)
    args = parser.parse_args()
    native()
    with TemporaryDirectory() as directory:
        fixtures(args.helpers, args.rustc, Path(directory))
