"""Verify ordered Locus uac multi-row hashing and independent compact count."""

import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
from types import ModuleType
from tempfile import TemporaryDirectory

from compare_uac import compare, load_helpers

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
    assert by_name["uac"] == ("0.11", "uac", "0x9b0", "0x64794e8", "0x46a5870", "0x46a0fb0")
    assert by_name["height"] == ("0.0.2", "height", "0x28", "0x64828c8", "0x14199b0", "0x14196d0")

    sections, header = unwind_index(data)
    _, frames = eh_frame_records(data, sections)
    indexed = {(row["start"], row["fde"]) for row in header}
    extents = [(row["start"], row["end"]) for row in frames
               if (row["start"], row["fde"]) in indexed]

    def verify_bytes(va, raw):
        assert any(start <= va and va + len(raw) <= end for start, end in extents), hex(va)
        assert read_va(data, va, len(raw)) == raw, hex(va)

    for va, raw in {
        0x5480CA4: "498d97b0090000", 0x52D4CAC: "4c8b7208488b5a10", 0x52D4D5E: "4869c3e8000000",
        0x52D4DBD: "4981c6e8000000", 0x52D4DD2: "4d8daed0000000",
        0x46A5881: "4c8b6f30", 0x46A5940: "488b4f10", 0x46A594D: "4c896c2430",
        0x46A5957: "4c8b6f084869e9e8000000", 0x46A598C: "4c892c084981c5e8000000",
        0x46A59BD: "498d85d0000000", 0x46A5A0A: "4c8b6c2430", 0x46A5A16: "4c896c2440",
        0x41ADD8D: "41ff56184983c7f0", 0x3B8328A: "488d4f30", 0x3B83311: "4883c718",
        0x14199DC: "48890c02", 0x141B9F1: "4883c114", 0x141B296: "4889040a",
    }.items():
        verify_bytes(va, bytes.fromhex(raw))
    for va, prefix, target in (
        (0x5678CB4, "0f84", 0x52D4C90), (0x52D4CC7, "e8", 0x57CEBA0),
        (0x52D4E7A, "e8", 0x531FE80), (0x52D4F24, "e8", 0x4D95850),
        (0x46A5969, "4c8d25", 0x648F6F8), (0x46A5970, "4c8d35", 0x6493520),
        (0x46A5A25, "488d15", 0x648F680), (0x46A5A63, "e8", 0x41ADC70),
        (0x3B83414, "e8", 0x41AD3C0), (0x41F8050, "ff25", 0x64DF600),
    ):
        op = bytes.fromhex(prefix)
        assert rip_target(data, va, op, len(op) + 4) == target, hex(va)
    reloc = relative_relocations(data)
    for site, method in {0x648F710: 0x41F8050, 0x6493538: 0x3B83280, 0x648F698: 0x14199B0,
                         0x64DF600: 0x141B9B0}.items():
        assert reloc[site] == method
    print(f"PASS: node #115 SHA-256 {TARGET}")
    print("PASS: named and raw 232-byte row geometry, reused 23-leaf visitor, separate compact count")


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

    activity, kit = load_helpers(folder)
    helper = driver(folder, rustc, tmp)
    tree = kit["tree"]
    height = 900

    def leaf(raw):
        return subprocess.check_output([helper], input=raw).decode().strip()

    def words(*values):
        return leaf(b"".join(value.to_bytes(8, "little") for value in values))

    def save(name, raw):
        path = tmp / name
        path.write_bytes(raw)
        return path, hashlib.sha256(raw).hexdigest()

    def checkpoint(name, rows):
        source = {"exchange": {"locus": {"ctx": {"height": height}, "uac": rows}}}
        return save(name, msgpack.packb(source))

    def witness(name, source, count, bound_height=height):
        return save(name, json.dumps({"height": bound_height, "checkpoint_sha256": source,
                                      "uac_compact_count": count}).encode())

    def reference(name, selected, root_height=height, stale=False):
        slots = [[0, [[0, [[2, words(root_height)]]], [11, selected]]]]
        digest = leaf(b"stale") if stale else tree.digest(helper, tree.decode_tree(slots))
        return save(name, json.dumps({"height": height, "abci_digest": digest,
                                      "exchange_abci_hash": slots}).encode())

    first, second = bytes.fromhex("11" * 20), bytes.fromhex("22" * 20)
    rows = [
        ["0x" + first.hex(), {"p": 3, "M": {"u": 9}, "t": {"t": "1970-01-01T00:00:02"}}],
        [list(second), {"p": 7, "L": 5, "b": {"s": 10}, "s": {"n": 19}}],
    ]
    source = checkpoint("rows.rmp", rows)
    zero = words(0, 0)
    values = [[0, words(3, 7)], [1, zero], [2, zero], [3, words(0, 5)],
              [4, [[0, zero], [1, zero], [2, zero], [3, words(9, 0)], [4, zero]]],
              [5, [[0, zero], [1, words(0, 10)], [2, zero], [3, zero], [4, zero]]],
              [6, [[i, zero] for i in range(5)]],
              [7, [[0, words(0, 19)], [1, leaf(bytes(24))]]],
              [8, [[0, zero], [1, leaf(struct.pack("<qIqI", 2, 0, 0, 0))]]]]
    exact = [[0, leaf(first + second)], [1, values], [2, words(2)]]
    exact_ref = reference("exact.json", exact)
    matching = witness("count.json", source[1], 2)
    result = compare(activity, kit, helper, height, *source, *exact_ref, *matching)
    assert result["ordered_uac_matches"] and result["compact_count"] == result["named_row_count"] == 2
    other_count = witness("other-count.json", source[1], 9)
    result = compare(activity, kit, helper, height, *source, *exact_ref, *other_count)
    assert not result["compact_count_matches"] and result["ordered_values_match"]
    assert (result["named_row_count"], result["compact_count"]) == (2, 9)

    wrong_values = exact[:1] + [[1, [[0, words(7, 3)], *values[1:]]]] + exact[2:]
    wrong = reference("wrong-values.json", wrong_values)
    mismatch = compare(activity, kit, helper, height, *source, *wrong, *matching)
    assert not mismatch["ordered_values_match"] and mismatch["address_stream_matches"] and mismatch["compact_count_matches"]
    empty = checkpoint("empty.rmp", [])
    assert compare(activity, kit, helper, height, *empty, *reference("empty.json", [[2, words(0)]]),
                   *witness("empty-count.json", empty[1], 0))["ordered_uac_matches"]
    for ref, saved, reason in (
        (exact_ref, witness("wrong-source.json", "0" * 64, 2), "different checkpoint"),
        (exact_ref, witness("wrong-height.json", source[1], 2, height + 1), "different checkpoint"),
        (exact_ref, (matching[0], "0" * 64), "witness SHA-256"),
        (reference("stale.json", exact, stale=True), matching, "stated raw ABCI digest"),
    ):
        try:
            compare(activity, kit, helper, height, *source, *ref, *saved)
        except ValueError as error:
            assert reason in str(error), error
        else:
            raise AssertionError(reason)
    cmd = [sys.executable, "-B", Path(__file__).with_name("compare_uac.py"), folder, helper,
           str(height), *source, *wrong, *matching]
    run = subprocess.run(cmd, check=False, capture_output=True)
    assert run.returncode == 1 and json.loads(run.stdout) == mismatch
    print(f"PASS: msgpack {msgpack.__version__}; two ordered Address rows across all 23 activity streams")
    print("PASS: compact count witness independent of named row count; empty, mismatch and wrong binding tested")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--helpers", required=True, type=Path)
    parser.add_argument("--rustc", required=True, type=Path)
    args = parser.parse_args()
    native(args.helpers)
    with TemporaryDirectory() as directory:
        controls(args.helpers, args.rustc, Path(directory))
