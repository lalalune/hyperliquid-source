"""Verify named Oracle-history ordered timestamp and count parity."""

import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
from tempfile import TemporaryDirectory

from compare_history import SLOT, compare, load_helpers

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
    assert (int(row["box_field"], 16), int(row["method_0"], 16)) == (0x3D78, 0x57B9EA0)
    sections, header = unwind_index(data)
    _, frames = eh_frame_records(data, sections)
    indexed = {(row["start"], row["fde"]) for row in header}
    extents = [(row["start"], row["end"]) for row in frames
               if (row["start"], row["fde"]) in indexed]

    def verify_bytes(va, raw):
        assert any(start <= va and va + len(raw) <= end for start, end in extents), hex(va)
        assert read_va(data, va, len(raw)) == raw, hex(va)

    name = rip_target(data, 0x5673ADF, bytes.fromhex("488d05"), 7)
    assert read_va(data, name, 2) == b"oh"
    for va, raw in {
        0x5481577: "498d97783d0000", 0x52CF784: "488b4218", 0x52CF791: "4c8b224c8b7a10",
        0x52CF7C4: "488b6a08", 0x530696F: "c6040192", 0x5306A7B: "4983c510",
        0x53071E1: "be54000000", 0x57B9EBB: "4c8b6718", 0x57B9F33: "488b0f488b4710",
        0x57B9F99: "4983c428", 0x57BA000: "4889442420", 0x57BA024: "48837a1002",
        0x57BA02F: "4c8b7208498d4618", 0x57BA07A: "4c89f6ff5318",
        0x4E1A9D8: "48837e1002", 0x4E1A9E3: "488b5e08", 0x4E1AA25: "4c8d6b18",
        0x4E1AA91: "4883c710", 0x141B1F1: "488b17", 0x141B234: "8b6f08",
        0x141B296: "4889040a4883c108", 0x141B2BA: "892c014883c004", 0x14199DC: "48890c02",
    }.items():
        verify_bytes(va, bytes.fromhex(raw))
    for va, prefix, target in (
        (0x5481584, "e8", 0x5673AD0), (0x5673B14, "0f84", 0x52CF770), (0x52CF811, "e8", 0x57CEBA0),
        (0x52CF8D0, "e8", 0x53067A0), (0x52CF92E, "e8", 0x53067A0),
        (0x53069AE, "e8", 0x5321780), (0x5321866, "e8", 0x5307170),
        (0x5307218, "e8", 0x57CF5D0), (0x5306A8A, "e8", 0x517FEB0),
        (0x57B9F9D, "488d0d", 0x64B0310), (0x4E1AA17, "ff15", 0x64DF5A0),
        (0x4E1AAD0, "e8", 0x3D6B420), (0x57BA0CA, "ff15", 0x64DF538),
    ):
        op = bytes.fromhex(prefix)
        assert rip_target(data, va, op, len(op) + 4) == target, hex(va)
    reloc = relative_relocations(data)
    assert (reloc[0x64B0328], reloc[0x64DF5A0], reloc[0x64DF538]) == (0x4E1A9B0, 0x141B1E0, 0x14199B0)
    print(f"PASS: node #115 SHA-256 {TARGET}")
    print("PASS: named oh logical order, two-child row visitor, shared Time stream and final count writer")


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
    height = 110

    def leaf(raw):
        return subprocess.check_output([helper], input=raw).decode().strip()

    def save(name, raw):
        path = tmp / name
        path.write_bytes(raw)
        return path, hashlib.sha256(raw).hexdigest()

    choices = [
        ["1970-01-01T00:00:02.001", {"pxs2": []}],
        ["1969-12-31T23:59:59.999999999", {"pxs2": [["synthetic"]]}],
        ["1970-01-01T00:00:04", {"pxs2": []}],
    ]
    def checkpoint(name, values):
        body = {"exchange": {"locus": {"ctx": {"height": height}}, "oh": values}}
        return save(name, msgpack.packb(body))

    def reference(name, times, count=3, stale=False):
        slots = [[0, [[4, leaf(b"outside-scope")]]], [52, [
            [0, [[0, leaf(times)], [1, [[0, leaf(b"payload stream supplied independently")]]]]],
            [1, leaf(count.to_bytes(8, "little"))],
        ]]]
        digest = leaf(b"stale") if stale else tree.digest(helper, tree.decode_tree(slots))
        return save(name, json.dumps({"height": height, "abci_digest": digest,
                                      "exchange_abci_hash": slots}).encode())

    time_rows = (struct.pack("<qI", 2, 1_000_000), struct.pack("<qI", -1, 999_999_999),
                 struct.pack("<qI", 4, 0))
    expected = b"".join(time_rows)
    exact = reference("exact.json", expected)
    source = checkpoint("actual.rmp", choices)
    good = compare(kit, helper, height, *source, *exact)
    assert good["scoped_match"] and good["row_count"] == 3
    reordered = compare(kit, helper, height, *source, *reference("reordered.json", b"".join(time_rows[::-1])))
    assert not reordered["ordered_time_stream_matches"] and reordered["row_count_matches"]
    wrong = reference("wrong.json", expected, count=2)
    count_only = compare(kit, helper, height, *source, *wrong)
    assert not count_only["row_count_matches"] and count_only["ordered_time_stream_matches"]
    for candidate, ref, reason in (
        (checkpoint("unscoped-empty.rmp", []), exact, "nonempty"),
        (checkpoint("wrong-shape.rmp", [choices[0][:1]]), exact, "pair at row"),
        (source, reference("stale.json", expected, stale=True), "stated raw ABCI digest"),
    ):
        try:
            compare(kit, helper, height, *candidate, *ref)
        except ValueError as error:
            assert reason in str(error), error
        else:
            raise AssertionError(reason)
    cmd = [sys.executable, "-B", Path(__file__).with_name("compare_history.py"), folder, helper,
           str(height), *source, *wrong]
    run = subprocess.run(cmd, check=False, capture_output=True)
    assert run.returncode == 1 and json.loads(run.stdout) == count_only
    print(f"PASS: msgpack {msgpack.__version__}; three logical times compose one ordered raw leaf")
    print("PASS: reordered stream, independent count difference and stale root distinguished")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--helpers", required=True, type=Path)
    parser.add_argument("--rustc", required=True, type=Path)
    args = parser.parse_args()
    native()
    with TemporaryDirectory() as directory:
        controls(args.helpers, args.rustc, Path(directory))
