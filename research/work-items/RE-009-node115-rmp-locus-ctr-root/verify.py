"""Verify seven direct Locus counters and their omitted-zero ABI."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from types import ModuleType
from tempfile import TemporaryDirectory

from compare_locus_counters import compare, load_helpers

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

    key_sites = (0x5679265, 0x56792B1, 0x56792FF, 0x567934B, 0x5679399, 0x56793E7, 0x5679486)
    for va, key in zip(key_sites, ("tn", "vn", "tc", "sc", "to", "so", "ad")):
        assert read_va(data, rip_target(data, va, bytes.fromhex("488d35"), 7), 2) == key.encode()
    for va, raw in {
        0x5480C85: "498d97780a0000",
        0x5679165: "498b9fc8000000498bafd0000000", 0x5679185: "498b87d8000000",
        0x5679199: "498b87e0000000", 0x56791AD: "498b87e8000000",
        0x56791C1: "498b87f0000000", 0x56791E5: "4d8ba7f8000000",
        0x567924F: "4885db", 0x567925C: "7444", 0x56792A2: "4885ed", 0x56792A8: "7444",
        0x56792F3: "4d85ed7444", 0x567933C: "48837c2438007446",
        0x567938A: "48837c2430007446", 0x56793D8: "48837c2428007446", 0x5679477: "48837c242000743e",
        0x3D2E00A: "488d8fc8000000", 0x3D2E022: "488d97d0000000",
        0x3D2E033: "488d97d8000000", 0x3D2E044: "488d97e0000000",
        0x3D2E055: "488d97e8000000", 0x3D2E066: "488d97f0000000",
        0x3D2E077: "48897c2468", 0x3D2E088: "4881c7f8000000",
        0x41AE87C: "48837f1008", 0x14199DC: "48890c024883c008",
    }.items():
        verify_bytes(va, bytes.fromhex(raw))
    for va, prefix, target in (
        (0x5480C92, "e8", 0x5679120), (0x567928E, "e8", 0x57D00B0),
        (0x56792DA, "e8", 0x57D00B0), (0x5679328, "e8", 0x57D00B0),
        (0x5679376, "e8", 0x57D00B0), (0x56793C4, "e8", 0x57D00B0),
        (0x5679412, "e8", 0x57D00B0), (0x56794AD, "e8", 0x57D00B0),
        (0x3D2E016, "488d0d", 0x6473FF8), (0x3D2E07C, "488d15", 0x6479650), (0x3D2E16F, "e8", 0x41AE850),
    ):
        op = bytes.fromhex(prefix)
        assert rip_target(data, va, op, len(op) + 4) == target, hex(va)
    reloc = relative_relocations(data)
    assert reloc[0x6474010] == 0x14199B0 and reloc[0x6479668] == 0x3B83280
    print(f"PASS: node #115 SHA-256 {TARGET}")
    print("PASS: seven named counter zero skips and the matching native qword positions")


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

    def checkpoint(name, counters):
        source = {"exchange": {"locus": {"ctx": {"height": height}, "ctr": counters}}}
        return save(name, msgpack.packb(source))

    def reference(name, selected, root_height=height, stale=False, ac=b"opaque"):
        ctr = selected[:6] + [[6, [[0, leaf(ac)]]]] + selected[6:]
        slots = [[0, [[0, [[2, word(root_height)], [4, word(321)]]], [10, ctr]]]]
        digest = leaf(b"stale") if stale else tree.digest(helper, tree.decode_tree(slots))
        return save(name, json.dumps({"height": height, "abci_digest": digest,
                                      "exchange_abci_hash": slots}).encode())

    maximum = (1 << 64) - 1
    fields = {"vn": 0, "tn": maximum, "tc": 73, "sc": 11, "so": 40,
              "ac": {"unchecked-nested-field": 17}, "ad": 13}
    expected = [[0, word(maximum)], [1, word(0)], [2, word(73)], [3, word(11)],
                [4, word(0)], [5, word(40)], [7, word(13)]]
    source, exact = checkpoint("ordinary.rmp", fields), reference("ordinary.json", expected)
    assert compare(kit, helper, height, *source, *exact)["all_direct_counters_match"]
    changed_ac = reference("alternate-ac.json", expected, ac=b"different unmeasured child")
    change = compare(kit, helper, height, *source, *changed_ac)
    assert change["all_direct_counters_match"]
    assert change["reference_raw_digest"] != compare(kit, helper, height, *source, *exact)["reference_raw_digest"]
    all_omitted = checkpoint("all-omitted.rmp", {})
    zeros = reference("zeros.json", [[i, word(0)] for i in (0, 1, 2, 3, 4, 5, 7)])
    assert compare(kit, helper, height, *all_omitted, *zeros)["all_direct_counters_match"]

    wrong = expected[:2] + [[2, expected[3][1]], [3, expected[2][1]]] + expected[4:6] + [[7, word(0)]]
    mismatch_ref = reference("mismatch.json", wrong)
    mismatch = compare(kit, helper, height, *source, *mismatch_ref)
    assert [name for name, ok in mismatch["fields"].items() if not ok] == ["tc", "sc", "ad"]

    for candidate, ref, reason in (
        (checkpoint("not-u64.rmp", fields | {"tn": True}), exact, "unsigned 64-bit tn"),
        (source, reference("wrong-inner-h.json", expected, root_height=height + 1), "inner Context height"),
        (source, reference("stale.json", expected, stale=True), "stated raw ABCI digest"),
    ):
        try:
            compare(kit, helper, height, *candidate, *ref)
        except ValueError as error:
            assert reason in str(error), error
        else:
            raise AssertionError(reason)
    cmd = [sys.executable, "-B", Path(__file__).with_name("compare_locus_counters.py"), folder, helper,
           str(height), *source, *mismatch_ref]
    run = subprocess.run(cmd, check=False, capture_output=True)
    assert run.returncode == 1 and json.loads(run.stdout) == mismatch
    print(f"PASS: msgpack {msgpack.__version__}; all omitted, explicit zero and populated uint64 counters")
    print("PASS: swapped counters and different ad isolated, opaque sibling excluded, inner H checked")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--helpers", required=True, type=Path)
    parser.add_argument("--rustc", required=True, type=Path)
    args = parser.parse_args()
    native(args.helpers)
    with TemporaryDirectory() as directory:
        controls(args.helpers, args.rustc, Path(directory))
