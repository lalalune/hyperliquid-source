"""Verify the entire named Locus msc raw subtree and same-height binding."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from types import ModuleType
from tempfile import TemporaryDirectory

from compare_locus_misc import compare, load_helpers

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
    assert by_name["msc"] == ("0.15", "msc", "0xa38", "0x6479560", "0x3d24cb0", "0x3d1da10")
    assert by_name["height"] == ("0.0.2", "height", "0x28", "0x64828c8", "0x14199b0", "0x14196d0")

    sections, header = unwind_index(data)
    _, frames = eh_frame_records(data, sections)
    indexed = {(row["start"], row["fde"]) for row in header}
    extents = [(row["start"], row["end"]) for row in frames
               if (row["start"], row["fde"]) in indexed]

    def verify_bytes(va, raw):
        assert any(start <= va and va + len(raw) <= end for start, end in extents), hex(va)
        assert read_va(data, va, len(raw)) == raw, hex(va)

    for va, prefix, name in (
        (0x5677AF2, "488d35", b"apw"), (0x5677B34, "488d35", b"ape"), (0x5677BA4, "488d35", b"tse"),
        (0x5677C0E, "488d35", b"mts"), (0x5677C56, "488d35", b"nts"), (0x5679C0E, "488d05", b"uts"),
        (0x5677CB6, "488d15", b"scr"),
    ):
        assert read_va(data, rip_target(data, va, bytes.fromhex(prefix), 7), len(name)) == name
    for va, raw in {
        0x5480D2D: "498d97380a0000", 0x5677A9A: "ba07000000",
        0x5677B10: "f2410f104720", 0x5677B28: "450fb66f38", 0x5677B98: "450fb66f39",
        0x5677C03: "4d8b6728", 0x5677C4B: "4d8b6730", 0x5677CB1: "450fb6473a",
        0x528B4EB: "488d4520", 0x528B4F7: "488d5518", 0x528B5B3: "c6043092", 0x3C57CE9: "498d4520",
        0x3C57CF2: "498d6d18", 0x3D24CBA: "488d4f20", 0x3D24CCF: "488d4f38", 0x3D24CE4: "488d5739",
        0x3D24CF2: "488d5728", 0x3D24D07: "488d7730", 0x3D24D15: "48897c2458", 0x3D24D26: "4883c73a",
        0x141992E: "f20f110401", 0x1419D6B: "880c02", 0x14199DC: "48890c02",
        0x141B9E6: "89740a100f10070f11040a4883c114",
    }.items():
        verify_bytes(va, bytes.fromhex(raw))
    for va, prefix, target in (
        (0x5480D3A, "e8", 0x5677A50), (0x5677B19, "e8", 0x4E380C0), (0x5677B74, "e8", 0x57D0B20),
        (0x5677BDF, "e8", 0x57D0B20), (0x5677C37, "e8", 0x57D00B0), (0x5677C7B, "e8", 0x57D00B0),
        (0x5677CA0, "e8", 0x5679BF0), (0x5677CCA, "e8", 0x56783A0), (0x5679CF7, "e8", 0x528B320),
        (0x528B3AD, "e8", 0x57CEBA0), (0x528B5F7, "e8", 0x531FE80), (0x528B8CC, "e8", 0x57D00B0),
        (0x3D24CC3, "488d0d", 0x64788E0), (0x3D24CD8, "488d0d", 0x6474380), (0x3D24CFB, "488d15", 0x6473FF8),
        (0x3D24D1A, "488d15", 0x6478908), (0x3D24DE8, "e8", 0x41AE3E0), (0x1603EC0, "ff25", 0x64DF4D0),
        (0x3C57C7A, "4c8d3d", 0x6476BC0), (0x3C57C81, "488d1d", 0x6473FF8), (0x3C57DCB, "e8", 0x41ADC70),
        (0x41F8050, "ff25", 0x64DF600),
    ):
        op = bytes.fromhex(prefix)
        assert rip_target(data, va, op, len(op) + 4) == target, hex(va)
    reloc = relative_relocations(data)
    for site, method in {0x64788F8: 0x1603EC0, 0x6474398: 0x1419D40, 0x6474010: 0x14199B0,
                         0x6478920: 0x3C57AD0, 0x6476BD8: 0x41F8050,
                         0x64DF4D0: 0x1419900, 0x64DF600: 0x141B9B0}.items():
        assert reloc[site] == method
    print(f"PASS: node #115 SHA-256 {TARGET}")
    print("PASS: seven named Locus misc fields, ordered uts key/value/count and native scalar visitors")


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
    height = 899

    def leaf(raw):
        return subprocess.check_output([helper], input=raw).decode().strip()

    def word(value):
        return leaf(value.to_bytes(8, "little"))

    def save(name, raw):
        path = tmp / name
        path.write_bytes(raw)
        return path, hashlib.sha256(raw).hexdigest()

    def checkpoint(name, fields, **packing):
        source = {"exchange": {"locus": {"ctx": {"height": height}, "msc": fields}}}
        return save(name, msgpack.packb(source, **packing))

    def reference(name, selected, root_height=height, stale=False):
        slots = [[0, [[0, [[2, word(root_height)], [4, word(321)]]], [15, selected]]]]
        digest = leaf(b"stale") if stale else tree.digest(helper, tree.decode_tree(slots))
        return save(name, json.dumps({"height": height, "abci_digest": digest,
                                      "exchange_abci_hash": slots}).encode())

    first, second = bytes.fromhex("11" * 20), bytes.fromhex("22" * 20)
    maximum = (1 << 64) - 1
    fields = {"uts": [["0x" + first.hex(), 0], [list(second), maximum]],
              "apw": -0.0, "ape": True, "tse": False, "mts": maximum, "nts": 15, "scr": True}
    collection = [[0, leaf(first + second)], [1, leaf(bytes(8) + bytes.fromhex("ff" * 8))], [2, word(2)]]
    expected = [[0, leaf(bytes.fromhex("0000000000000080"))], [1, leaf(b"\x01")], [2, leaf(b"\x00")],
                [3, word(maximum)], [4, word(15)], [5, collection], [6, leaf(b"\x01")]]
    source, exact = checkpoint("ordinary.rmp", fields), reference("ordinary.json", expected)
    assert compare(kit, helper, height, *source, *exact)["ordered_locus_misc_matches"]
    empty_ref = reference("empty.json", expected[:5] + [[5, [[2, word(0)]]]] + expected[6:])
    empty = checkpoint("empty.rmp", fields | {"uts": []})
    assert compare(kit, helper, height, *empty, *empty_ref)["ordered_locus_misc_matches"]

    wrong = expected[:5] + [[5, [collection[1], collection[0], collection[2]]]] + expected[6:]
    mismatch_ref = reference("mismatch.json", wrong)
    mismatch = compare(kit, helper, height, *source, *mismatch_ref)
    assert [name for name, ok in mismatch["fields"].items() if not ok] == ["uts"]
    changed = compare(kit, helper, height, *checkpoint("changed.rmp", fields | {"apw": 0.0, "tse": True}), *exact)
    assert [name for name, ok in changed["fields"].items() if not ok] == ["apw", "tse"]
    for candidate, ref, reason in (
        (checkpoint("binary32.rmp", fields, use_single_float=True), exact, "binary64 apw"),
        (checkpoint("duplicate.rmp", fields | {"uts": [["0x" + first.hex(), 1], [list(first), 2]]}),
         exact, "duplicate uts Address"),
        (source, reference("wrong-h.json", expected, root_height=height + 1), "inner Context height"),
        (source, reference("stale.json", expected, stale=True), "stated raw ABCI digest"),
    ):
        try:
            compare(kit, helper, height, *candidate, *ref)
        except ValueError as error:
            assert reason in str(error), error
        else:
            raise AssertionError(reason)
    cmd = [sys.executable, "-B", Path(__file__).with_name("compare_locus_misc.py"), folder, helper,
           str(height), *source, *mismatch_ref]
    run = subprocess.run(cmd, check=False, capture_output=True)
    assert run.returncode == 1 and json.loads(run.stdout) == mismatch
    print(f"PASS: msgpack {msgpack.__version__}; complete empty and populated misc subtrees")
    print("PASS: exact float sign, scoped bool, ordered map, counted keys and inner H distinguished")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--helpers", required=True, type=Path)
    parser.add_argument("--rustc", required=True, type=Path)
    args = parser.parse_args()
    native(args.helpers)
    with TemporaryDirectory() as directory:
        controls(args.helpers, args.rustc, Path(directory))
