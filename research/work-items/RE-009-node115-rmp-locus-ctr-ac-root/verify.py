"""Verify all 23 named Locus ctr.ac leaves and the defaults omitted by the writer."""

import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
from types import ModuleType
from tempfile import TemporaryDirectory

from compare_locus_activity import compare, load_helpers

sys.path.insert(0, str(Path.cwd() / "tools"))
from elf_index import unwind_index
from fde_extents import eh_frame_records
from freeze_snapshot_115 import read_va, relative_relocations, rip_target

TARGET = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
DRIVER_SHA = "6791575648e65e8ef4fe42536b7327f85c57327cb2423255b598fb2b1d83828f"


def native(folder):
    data = Path("artifacts/node/115/hl-node").read_bytes()
    assert hashlib.sha256(data).hexdigest() == TARGET
    witness = folder / "RE-009-node115-locus-context-root-captures/verify.py"
    raw = witness.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == "19cc80a8e20a68b6ad9e471b2d92ea61dec0c2451a0b2414563e1808faabf993"
    capture = ModuleType("locus_capture")
    capture.__file__ = str(witness)
    exec(compile(raw, str(witness), "exec"), capture.__dict__)
    by_name = {row[1]: row for row in capture.first_fields(data)}
    assert by_name["ctr"] == ("0.10", "ctr", "0xa78", "0x64794c0", "0x3d2e000", "0x3d251d0")
    assert by_name["height"] == ("0.0.2", "height", "0x28", "0x64828c8", "0x14199b0", "0x14196d0")

    sections, header = unwind_index(data)
    _, frames = eh_frame_records(data, sections)
    indexed = {(row["start"], row["fde"]) for row in header}
    extents = [(row["start"], row["end"]) for row in frames
               if (row["start"], row["fde"]) in indexed]

    def verify_bytes(va, raw):
        assert any(start <= va and va + len(raw) <= end for start, end in extents), hex(va)
        assert read_va(data, va, len(raw)) == raw, hex(va)

    for va, prefix, key in (
        (0x5679439, "488d35", "ac"),
        (0x4D95A1E, "488d35", "p"), (0x4D95A71, "488d35", "m"),
        (0x4D95ABF, "488d35", "l"), (0x4D95B0B, "488d35", "L"),
        (0x4D95B5D, "488d15", "M"), (0x4D95B94, "488d15", "b"), (0x4D95BCE, "488d15", "c"),
        (0x4D95C0A, "488d35", "s"), (0x4D95C59, "488d15", "t"),
        (0x4E0BC21, "488d35", "t"), (0x4E0BC71, "488d35", "s"),
        (0x4E0BCB7, "488d35", "c"), (0x4E0BD02, "488d35", "u"), (0x4E0BD40, "488d35", "l"),
        (0x5184ACD, "488d35", "n"), (0x5184B18, "488d35", "t"),
    ):
        assert read_va(data, rip_target(data, va, bytes.fromhex(prefix), 7), len(key)) == key.encode()
    for va, raw in {
        0x567942E: "84c0", 0x4E44ED9: "837f24007507837f28000f94c0",
        0x4D95861: "4c8b6630488b6e38", 0x4D95878: "488b4e40", 0x4D95888: "488b4e48",
        0x4D95B59: "498d4e50", 0x4D95B90: "498d4e78", 0x4D95BC7: "498d8ea0000000",
        0x4D95C55: "4983c618", 0x4E0BB8D: "4d8b3c24498b6c2408", 0x4E0BBA5: "4d8b6c2410",
        0x4E0BBB1: "498b4c2418", 0x4E0BBC2: "4d8b642420", 0x5184A51: "4c8b26b81a40f6003346080b460c",
        0x3D2E077: "48897c2468", 0x3B8328A: "488d4f30", 0x3B8329F: "488d5738", 0x3B832AD: "488d5740",
        0x3B832BB: "488d5748", 0x3B832C9: "488d4f50", 0x3B832DE: "488d5778", 0x3B832EC: "488d97a0000000",
        0x3B832FD: "48897c2478", 0x3B83311: "4883c718", 0x3B834AB: "488d5708", 0x3B834B9: "488d5710",
        0x3B834C7: "488d5718", 0x3B834D5: "4883c720", 0x4306A48: "4883c708", 0x14199DC: "48890c02",
        0x141B296: "4889040a", 0x141B2BA: "892c01",
    }.items():
        verify_bytes(va, bytes.fromhex(raw))
    epoch = bytes.fromhex("1a40f60000000000000000001a40f600")
    assert read_va(data, rip_target(data, 0x4E44E4D, bytes.fromhex("660f7605"), 8), 16) == epoch
    for va, prefix, target in (
        (0x5679429, "e8", 0x4E44E10), (0x5679462, "e8", 0x4D95850),
        (0x4D95A47, "e8", 0x57D00B0), (0x4D95A9A, "e8", 0x57D00B0),
        (0x4D95AE8, "e8", 0x57D00B0), (0x4D95B36, "e8", 0x57D00B0),
        (0x4D95B6C, "e8", 0x4E0BB40), (0x4D95BA3, "e8", 0x4E0BB40), (0x4D95BDD, "e8", 0x4E0BB40),
        (0x4D95C33, "e8", 0x5184A30), (0x4D95C6B, "e8", 0x4E0DBF0), (0x4E0DC2B, "e9", 0x5184A30),
        (0x5184AF6, "e8", 0x57D00B0), (0x5184B52, "e8", 0x5307510),
        (0x3D2E07C, "488d15", 0x6479650), (0x3B83293, "488d0d", 0x6473FF8),
        (0x3B832D2, "488d0d", 0x6474178), (0x3B83302, "488d0d", 0x64741A0),
        (0x3B83414, "e8", 0x41AD3C0), (0x3B83559, "e8", 0x41AD070),
        (0x4306A3C, "488d0d", 0x6482968), (0x4306A51, "488d0d", 0x6482708),
        (0x4306A8B, "e8", 0x41AE280), (0x3D5E950, "ff25", 0x64DF5A0),
    ):
        op = bytes.fromhex(prefix)
        assert rip_target(data, va, op, len(op) + 4) == target, hex(va)
    reloc = relative_relocations(data)
    for site, method in {
        0x6479668: 0x3B83280, 0x6474010: 0x14199B0, 0x6474190: 0x3B83490, 0x64741B8: 0x4306A30,
        0x6482980: 0x14199B0, 0x6482720: 0x3D5E950, 0x64DF5A0: 0x141B1E0,
    }.items():
        assert reloc[site] == method
    print(f"PASS: node #115 SHA-256 {TARGET}")
    print("PASS: four named words, three five-word branches, two clock pairs and native omission predicate")


def driver(folder, rustc, tmp):
    source = folder / "RE-009-node115-context-root-isolation/hash_tree.rs"
    data = source.read_bytes()
    assert hashlib.sha256(data).hexdigest() == DRIVER_SHA
    staged = tmp / source.name
    staged.write_bytes(data)
    library = tmp / "libnode115_abci_blake3.rlib"
    executable = tmp / "hash_tree"
    subprocess.run([rustc, "--edition=2024", "--crate-name", "node115_abci_blake3",
                    "--crate-type", "rlib", "src/node115-abci-blake3/src/lib.rs", "-o", library], check=True)
    subprocess.run([rustc, "--edition=2024", staged, "--extern",
                    f"node115_abci_blake3={library}", "-o", executable], check=True)
    return executable


def controls(folder, rustc, tmp):
    import msgpack

    kit = load_helpers(folder)
    helper = driver(folder, rustc, tmp)
    tree = kit["tree"]
    height = 900

    def leaf(raw):
        return subprocess.check_output([helper], input=raw).decode().strip()

    def word(value):
        return leaf(value.to_bytes(8, "little"))

    def words(*values):
        return [[i, word(n)] for i, n in enumerate(values)]

    def clock(n, seconds, nanos):
        return [[0, word(n)], [1, leaf(struct.pack("<qI", seconds, nanos))]]

    def save(name, raw):
        path = tmp / name
        path.write_bytes(raw)
        return path, hashlib.sha256(raw).hexdigest()

    def checkpoint(name, activity=None):
        ctr = {} if activity is None else {"ac": activity}
        source = {"exchange": {"locus": {"ctx": {"height": height}, "ctr": ctr}}}
        return save(name, msgpack.packb(source))

    def reference(name, selected, root_height=height, stale=False):
        slots = [[0, [[0, [[2, word(root_height)]]], [10, [[0, word(15)], [6, selected], [7, word(25)]]]]]]
        digest = leaf(b"stale") if stale else tree.digest(helper, tree.decode_tree(slots))
        return save(name, json.dumps({"height": height, "abci_digest": digest,
                                      "exchange_abci_hash": slots}).encode())

    maximum = (1 << 64) - 1
    activity = {"p": 2, "m": maximum, "L": 6, "M": {"t": 10, "s": 11, "c": 12, "u": 13, "l": 14},
                "b": {"u": 19}, "c": {"l": 20}, "s": {"n": 7, "t": "1969-12-31T23:59:59.999999999"},
                "t": {"t": "1970-01-01T00:00:00.001"}}
    raw = words(2, maximum, 0, 6) + [
        [4, words(10, 11, 12, 13, 14)], [5, words(0, 0, 0, 19, 0)], [6, words(0, 0, 0, 0, 20)],
        [7, clock(7, -1, 999_999_999)], [8, clock(0, 0, 1_000_000)],
    ]
    source, exact = checkpoint("explicit.rmp", activity), reference("exact.json", raw)
    assert compare(kit, helper, height, *source, *exact)["ordered_activity_matches"]
    zero = words(0, 0, 0, 0) + [[i, words(0, 0, 0, 0, 0)] for i in (4, 5, 6)] + [
        [7, clock(0, 0, 0)], [8, clock(0, 0, 0)],
    ]
    zero_ref = reference("zero.json", zero)
    for name, value in (("omitted.rmp", None), ("empty.rmp", {}), ("explicit-zero.rmp", {"b": {"u": 0},
                         "s": {"n": 0, "t": "1970-01-01T00:00:00"}})):
        assert compare(kit, helper, height, *checkpoint(name, value), *zero_ref)["ordered_activity_matches"]

    mismatched = raw[:5] + [[5, words(0, 0, 0, 20, 0)]] + raw[6:8] + [[8, clock(0, 0, 0)]]
    wrong = reference("mismatch.json", mismatched)
    mismatch = compare(kit, helper, height, *source, *wrong)
    assert [name for name, ok in mismatch["fields"].items() if not ok] == ["b", "t"]
    for candidate, ref, reason in (
        (checkpoint("not-u64.rmp", activity | {"p": True}), exact, "unsigned 64-bit p"),
        (source, reference("wrong-inner-h.json", raw, root_height=height + 1), "inner Context height"),
        (source, reference("stale.json", raw, stale=True), "stated raw ABCI digest"),
    ):
        try:
            compare(kit, helper, height, *candidate, *ref)
        except ValueError as error:
            assert reason in str(error), error
        else:
            raise AssertionError(reason)
    cmd = [sys.executable, "-B", Path(__file__).with_name("compare_locus_activity.py"), folder, helper,
           str(height), *source, *wrong]
    run = subprocess.run(cmd, check=False, capture_output=True)
    assert run.returncode == 1 and json.loads(run.stdout) == mismatch
    print(f"PASS: msgpack {msgpack.__version__}; all 23 leaves, signed seconds and omitted epoch defaults")
    print("PASS: nested counter and clock mismatches isolated at verified H")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--helpers", required=True, type=Path)
    parser.add_argument("--rustc", required=True, type=Path)
    args = parser.parse_args()
    native(args.helpers)
    with TemporaryDirectory() as directory:
        controls(args.helpers, args.rustc, Path(directory))
