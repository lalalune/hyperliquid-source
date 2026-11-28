"""Authenticate the three native raw guard members and check pinned synthetic fixtures."""

import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
from tempfile import TemporaryDirectory

from compare_guard import GUARD, SLOT, compare, load_helpers

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
    row = bind(data)["slots"][SLOT]
    assert (int(row["box_field"], 16), row["type_size"],
            int(row["method_0"], 16)) == (0x4200, 32, 0x15B4950)
    sections, header = unwind_index(data)
    _, frames = eh_frame_records(data, sections)
    indexed = {(row["start"], row["fde"]) for row in header}
    extents = [(row["start"], row["end"]) for row in frames
               if (row["start"], row["fde"]) in indexed]
    for va, encoding in {
        0x5480F5E: "498d9700420000", 0x4D9CB11: "f2410f1007",
        0x4D9CB49: "498d4708", 0x4D9CB4D: "833800", 0x4D9CBB6: "c60430c0",
        0x4D9CBF2: "4983c714", 0x4D9CBF6: "41833f00", 0x52F00B4: "c60431c0",
        0x15B4968: "488d4f08", 0x15B497D: "4883c714", 0x14BBF2B: "48837f1003",
        0x15D1553: "833f00", 0x15D15BA: "4883c318", 0x15D1607: "488d5818",
        0x141992E: "f20f110401", 0x141B296: "4889040a", 0x141B2BA: "892c01",
    }.items():
        raw = bytes.fromhex(encoding)
        # The shared visitor's argument guard precedes its frame setup.
        if va != 0x14BBF2B:
            assert any(start <= va and va + len(raw) <= end for start, end in extents), hex(va)
        assert read_va(data, va, len(raw)) == raw, hex(va)
    for va, prefix, literal in (
        (0x5673751, b"\x48\x8d\x35", GUARD.encode()),
        (0x4D9CAF7, b"\x48\x8d\x35", b"err_duration"),
        (0x4D9CB2B, b"\x48\x8d\x35", b"first_err_time"),
        (0x4D9CBD8, b"\x48\x8d\x35", b"last_err_time"),
        (0x15D15E6, b"\x48\x8d\x3d", b"\x01" + bytes(7)),
        (0x15D1634, b"\x48\x8d\x3d", bytes(8)),
    ):
        assert read_va(data, rip_target(data, va, prefix, 7), len(literal)) == literal
    for va, prefix, target in (
        (0x5480F6B, b"\xe8", 0x5673740), (0x567377C, b"\xe9", 0x4D9CA80),
        (0x4D9CB19, b"\xe8", 0x4E380C0), (0x4D9CB6B, b"\xe8", 0x5307510),
        (0x4D9CC16, b"\xe8", 0x5307510), (0x4D9CC50, b"\xe8", 0x52F0080),
        (0x15B49CC, b"\xe8", 0x14BBF10), (0x1603EC0, b"\xff\x25", 0x64DF4D0),
        (0x15D15AC, b"\xff\x15", 0x64E12D8), (0x156F3A0, b"\xff\x25", 0x64DF5A0),
        (0x15D163E, b"\xff\x15", 0x64DF538),
    ):
        assert rip_target(data, va, prefix, len(prefix) + 4) == target
    for va, descriptor in ((0x15B495C, 0x6400110), (0x15B4971, 0x6400138)):
        assert rip_target(data, va, b"\x48\x8d\x0d", 7) == descriptor
    relocs = relative_relocations(data)
    for slot, target in {0x6400128: 0x1603EC0, 0x6400150: 0x15D1540,
                         0x64DF4D0: 0x1419900, 0x64E12D8: 0x156F3A0,
                         0x64DF5A0: 0x141B1E0, 0x64DF538: 0x14199B0}.items():
        assert relocs[slot] == target
    print(f"PASS: node #115 SHA-256 {TARGET}")
    print("PASS: three native guard writer-to-root fields, independently tagged optional timestamps")


def build_driver(folder, rustc, directory):
    source = folder / "RE-009-node115-context-root-isolation/hash_tree.rs"
    data = source.read_bytes()
    assert hashlib.sha256(data).hexdigest() == DRIVER_SHA
    staged = directory / source.name
    staged.write_bytes(data)
    library = directory / "libnode115_abci_blake3.rlib"
    executable = directory / "hash_tree"
    subprocess.run([rustc, "--edition=2024", "--crate-name", "node115_abci_blake3",
                    "--crate-type", "rlib", "src/node115-abci-blake3/src/lib.rs",
                    "-o", library], check=True)
    subprocess.run([rustc, "--edition=2024", staged, "--extern",
                    f"node115_abci_blake3={library}", "-o", executable], check=True)
    return executable


def controls(folder, rustc, directory):
    import msgpack

    kit = load_helpers(folder)
    helper = build_driver(folder, rustc, directory)
    tree = kit["tree"]

    def leaf(raw):
        return subprocess.check_output([helper], input=raw).decode().strip()

    height = 250

    def save(name, raw):
        path = directory / name
        path.write_bytes(raw)
        return path, hashlib.sha256(raw).hexdigest()

    def checkpoint(name, values, single=False):
        return save(name, msgpack.packb({"exchange": {"locus": {"ctx": {"height": height}},
                                                     GUARD: values}}, use_single_float=single))

    nil = [[1, leaf(bytes(8))]]
    some = [[0, leaf(struct.pack("<qI", -1, 999_999_999))], [1, leaf(b"\x01" + bytes(7))]]
    epoch = [[0, leaf(bytes(12))], [1, leaf(b"\x01" + bytes(7))]]
    duration = leaf(bytes.fromhex("000000000000f83f"))
    values = {"last_err_time": None, "err_duration": 1.5, "first_err_time": "1969-12-31T23:59:59.999999999"}

    def reference(name, first, last, reverse=False, stale=False):
        branch = [[0, duration], [1, first], [2, last]]
        rows = [[11, branch[::-1] if reverse else branch], [12, leaf(b"unrelated")]]
        digest = leaf(b"stale") if stale else tree.digest(helper, tree.decode_tree(rows))
        return save(name, json.dumps({"height": height, "abci_digest": digest,
                                      "exchange_abci_hash": rows}).encode())

    source = checkpoint("first.rmp", values)
    exact = reference("correct.json", some, nil)
    assert compare(kit, helper, height, *source, *exact)["ordered_guard_subtree_matches"]
    other = checkpoint("last.rmp", values | {"first_err_time": None, "last_err_time": "1970-01-01T00:00:00"})
    assert compare(kit, helper, height, *other, *reference("last.json", nil, epoch))["ordered_guard_subtree_matches"]
    mismatch = reference("nil-versus-epoch.json", some, epoch)
    result = compare(kit, helper, height, *source, *mismatch)
    assert not result["ordered_guard_subtree_matches"]
    assert result["fields"] == {"err_duration": True, "first_err_time": True, "last_err_time": False}
    reordered = compare(kit, helper, height, *source, *reference("reordered.json", some, nil, reverse=True))
    assert not reordered["ordered_guard_subtree_matches"] and all(reordered["fields"].values())

    missing = checkpoint("omitted.rmp", {k: v for k, v in values.items() if k != "last_err_time"})
    short_float = checkpoint("binary32.rmp", values, single=True)
    wrong_hash = reference("wrong-hash.json", some, nil, stale=True)
    for supplied, ref, reason in ((missing, exact, "all three named"), (short_float, exact, "binary64"),
                                  (source, wrong_hash, "stated raw ABCI digest")):
        try:
            compare(kit, helper, height, *supplied, *ref)
        except ValueError as error:
            assert reason in str(error), error
        else:
            raise AssertionError(reason)
    command = [sys.executable, "-B", Path(__file__).with_name("compare_guard.py"), folder, helper,
               str(height), *source, *mismatch]
    run = subprocess.run(command, check=False, capture_output=True)
    assert run.returncode == 1 and json.loads(run.stdout) == result
    print(f"PASS: msgpack {msgpack.__version__}; duration and independently optional clock subtrees match")
    print("PASS: nil versus epoch and order-only divergence isolated; width, missing clock and stale digest rejected")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--helpers", required=True, type=Path)
    parser.add_argument("--rustc", required=True, type=Path)
    args = parser.parse_args()
    native()
    with TemporaryDirectory() as directory:
        controls(args.helpers, args.rustc, Path(directory))
