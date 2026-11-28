"""Authenticate three packed Time paths and test same-height raw root comparison."""

import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
from tempfile import TemporaryDirectory

from compare_times import TIMES, compare, load_helpers, read_times

sys.path.insert(0, str(Path.cwd() / "tools"))
from abci_hash_slots_115 import bind
from elf_index import unwind_index
from fde_extents import eh_frame_records
from freeze_snapshot_115 import read_va, relative_relocations, rip_target

TARGET = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
DRIVER_SHA = "6791575648e65e8ef4fe42536b7327f85c57327cb2423255b598fb2b1d83828f"


def native():
    data = Path("artifacts/node/115/hl-node").read_bytes()
    assert hashlib.sha256(data).hexdigest() == TARGET
    slots = bind(data)["slots"]
    sections, header = unwind_index(data)
    _, frames = eh_frame_records(data, sections)
    indexed = {(row["start"], row["fde"]) for row in header}
    extents = [(row["start"], row["end"]) for row in frames
               if (row["start"], row["fde"]) in indexed]

    def check(va, expected):
        raw = bytes.fromhex(expected)
        assert any(start <= va and va + len(raw) <= end for start, end in extents), hex(va)
        assert read_va(data, va, len(raw)) == raw, hex(va)

    sites = {"last_hlp_cancel_time": (0x4288, 0x5481007), "post_only_until_time": (0x4294, 0x5481032),
             "lvt": (0x42A0, 0x5481460)}
    for name, (offset, load) in sites.items():
        row = slots[TIMES[name]]
        assert (int(row["box_field"], 16), row["type_size"], int(row["vtable"], 16),
                int(row["method_0"], 16)) == (offset, 12, 0x64A8368, 0x3D5E950)
        check(load, "4d8d87" + offset.to_bytes(4, "little").hex())
        key = rip_target(data, load + 7, b"\x48\x8d\x15", 7)
        assert read_va(data, key, len(name)) == name.encode("ascii")
        check(load + 17, "b9" + len(name).to_bytes(4, "little").hex())
        assert rip_target(data, load + 25, b"\xe8", 5) == 0x5676BD0

    assert read_va(data, rip_target(data, 0x5676C06, b"\x48\x8d\x15", 7), 4) == b"Time"
    assert rip_target(data, 0x5676C12, b"\xe9", 5) == 0x52FD6D0
    assert rip_target(data, 0x52FD711, b"\xe8", 5) == 0x5307510
    assert rip_target(data, 0x4E0DA83, b"\xe8", 5) == 0x5307510
    assert rip_target(data, 0x53075B8, b"\xe8", 5) == 0x57CF860
    assert rip_target(data, 0x3D5E950, b"\xff\x25", 6) == 0x64DF5A0
    for va, raw in {
        0x5676C0D: "b904000000", 0x52FD6DA: "4883f90a", 0x5307581: "be54000000",
        0x141B1F1: "488b17", 0x141B234: "8b6f08", 0x141B273: "4869c080510100",
        0x141B27A: "4801c8", 0x141B296: "4889040a", 0x141B29A: "4883c108",
        0x141B2BA: "892c01", 0x141B2BD: "4883c004",
    }.items():
        check(va, raw)
    relocs = relative_relocations(data)
    assert relocs[0x64A8380] == 0x3D5E950 and relocs[0x64DF5A0] == 0x141B1E0
    print(f"PASS: node #115 SHA-256 {TARGET}")
    print("PASS: three named Time writers share the Context formatter and twelve-byte raw visitor")


def driver(folder, rustc, temp):
    source = folder / "RE-009-node115-context-root-isolation/hash_tree.rs"
    data = source.read_bytes()
    assert hashlib.sha256(data).hexdigest() == DRIVER_SHA
    saved = temp / source.name
    saved.write_bytes(data)
    library = temp / "libnode115_abci_blake3.rlib"
    executable = temp / "hash_tree"
    subprocess.run([rustc, "--edition=2024", "--crate-name", "node115_abci_blake3",
                    "--crate-type", "rlib", "src/node115-abci-blake3/src/lib.rs",
                    "-o", library], check=True)
    subprocess.run([rustc, "--edition=2024", saved, "--extern",
                    f"node115_abci_blake3={library}", "-o", executable], check=True)
    return executable


def controls(folder, rustc, temp):
    import msgpack

    kit = load_helpers(folder)
    helper = driver(folder, rustc, temp)

    def hashed(raw):
        return subprocess.check_output([helper], input=raw).decode().strip()

    height = 701
    fields = {"last_hlp_cancel_time": "1969-12-31T23:59:59.999999999",
              "post_only_until_time": "1970-01-01T00:00:00.123",
              "lvt": "2000-02-29T00:00:00.090012"}
    expected = {15: struct.pack("<qI", -1, 999_999_999), 16: struct.pack("<qI", 0, 123_000_000),
                45: struct.pack("<qI", 951_782_400, 90_012_000)}

    def save(name, data):
        path = temp / name
        path.write_bytes(data)
        return path, hashlib.sha256(data).hexdigest()

    def checkpoint(name, state, h=height):
        return save(name, msgpack.packb({"exchange": {"locus": {"ctx": {"height": h}}, **state}}))

    def reference(name, raw, bad_digest=False):
        tree = kit["tree"]
        rows = [[0, [[4, hashed(b"other")]]], *[[slot, hashed(data)] for slot, data in raw.items()]]
        digest = hashed(b"stale") if bad_digest else tree.digest(helper, tree.decode_tree(rows))
        return save(name, json.dumps({"height": height, "abci_digest": digest,
                                      "exchange_abci_hash": rows}).encode())

    source = checkpoint("synthetic.rmp", fields)
    assert read_times(kit, *source, height) == expected
    exact = reference("same.json", expected)
    assert compare(kit, helper, height, *source, *exact)["all_time_leaves_match"]
    wrong_nanos = reference("different.json", expected | {45: struct.pack("<qI", 951_782_400, 90_012_001)})
    result = compare(kit, helper, height, *source, *wrong_nanos)
    assert not result["all_time_leaves_match"]
    assert [name for name, row in result["times"].items() if not row["leaf_matches"]] == ["lvt"]

    no_fraction = checkpoint("no-fraction.rmp", fields | {"lvt": "2000-02-29T00:00:00"})
    assert read_times(kit, *no_fraction, height)[45] == struct.pack("<qI", 951_782_400, 0)
    noncanonical = checkpoint("short-fraction.rmp", fields | {"lvt": "2000-02-29T00:00:00.1"})
    shifted = checkpoint("height.rmp", fields, height + 1)
    stale = reference("stale.json", expected, bad_digest=True)
    for candidate, ref, reason in ((noncanonical, exact, "canonical checkpoint clock"),
                                   (shifted, exact, "Context height"),
                                   (source, stale, "stated raw ABCI digest")):
        try:
            compare(kit, helper, height, *candidate, *ref)
        except ValueError as error:
            assert reason in str(error), error
        else:
            raise AssertionError(reason)
    cmd = [sys.executable, "-B", Path(__file__).with_name("compare_times.py"), folder, helper,
           str(height), *source, *wrong_nanos]
    run = subprocess.run(cmd, check=False, capture_output=True)
    assert run.returncode == 1 and json.loads(run.stdout) == result
    print(f"PASS: msgpack {msgpack.__version__}; same-height signed Time leaves and 0/3/6/9-digit precision")
    print("PASS: one-nanosecond lvt divergence isolated; noncanonical time, height and stale digest rejected")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--helpers", required=True, type=Path)
    parser.add_argument("--rustc", required=True, type=Path)
    args = parser.parse_args()
    native()
    with TemporaryDirectory() as tmp:
        controls(args.helpers, args.rustc, Path(tmp))
