"""Authenticate and verify the complete named hil to raw root comparison."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory

from compare_hil import FIELD, SLOT, compare, load_helpers

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
    assert (int(row["box_field"], 16), int(row["method_0"], 16)) == (0x3830, 0x44F3030)
    sections, header = unwind_index(data)
    _, frames = eh_frame_records(data, sections)
    indexed = {(row["start"], row["fde"]) for row in header}
    extents = [(row["start"], row["end"]) for row in frames
               if (row["start"], row["fde"]) in indexed]

    def verify_bytes(va, raw):
        assert any(start <= va and va + len(raw) <= end for start, end in extents), hex(va)
        assert read_va(data, va, len(raw)) == raw, hex(va)

    for va, literal in ((0x567762D, b"hil"), (0x56776B7, b"m"), (0x56776DE, b"x"),
                        (0x56776E7, b"e"), (0x56776F0, b"d"), (0x5677715, b"half_life"),
                        (0x5677799, b"max_slippage"), (0x56777EA, b"max_n_depositors")):
        assert read_va(data, rip_target(data, va, b"\x48\x8d\x35", 7), len(literal)) == literal
    for va, raw in {
        0x5481558: "498d9730380000", 0x567765A: "ba04000000", 0x56776AB: "410fb66f20",
        0x56776D5: "85ed740e83fd017512", 0x5677733: "41833f017527", 0x5677739: "f2410f104708",
        0x5677783: "c60430c0", 0x567778C: "f2410f104710", 0x56777DF: "4d8b7f18",
        0x44F303A: "488d4f20", 0x44F304F: "48897c2418", 0x44F3060: "488d4f10",
        0x44F3075: "4883c718", 0x44F3094: "48c744245001000000", 0x44F30A7: "48c744246001000000",
        0x44F30BA: "48c744247001000000", 0x44F30CD: "48c784248000000001000000",
        0x44EBE75: "0fb60785c0745e", 0x44EBE85: "48c7042401000000", 0x44EBEDA: "48c7042400000000",
        0x44EBF28: "48c7042402000000", 0x4514D77: "833f0175314883c708",
        0x4514D9B: "48c744241001000000", 0x4514DB6: "48c744241000000000",
        0x4514DCB: "48c744242001000000", 0x141992E: "f20f110401", 0x14199DC: "48890c02",
    }.items():
        verify_bytes(va, bytes.fromhex(raw))
    for va, prefix, target in (
        (0x5481565, "e8", 0x5677610), (0x5677742, "e8", 0x4E380C0), (0x56777C6, "e8", 0x4E380C0),
        (0x567780F, "e8", 0x57D00B0), (0x44F30E1, "e8", 0x41AD9A0), (0x4514DDC, "e8", 0x41AE280),
        (0x44EBF83, "ff15", 0x64DF538), (0x1603EC0, "ff25", 0x64DF4D0),
        (0x44F3043, "488d0d", 0x648DA38), (0x44F3054, "488d0d", 0x648DA60),
        (0x44F3069, "488d0d", 0x648C8A0), (0x44F307E, "488d0d", 0x6488138),
        (0x4514D85, "488d0d", 0x648EE90), (0x4514DA4, "488d0d", 0x648E5D8), (0x4514DBF, "488d0d", 0x648E5E8),
    ):
        op = bytes.fromhex(prefix)
        assert rip_target(data, va, op, len(op) + 4) == target, hex(va)
    reloc = relative_relocations(data)
    for at, target in {0x648DA50: 0x44EBE70, 0x648DA78: 0x4514D70, 0x648C8B8: 0x1419900,
                       0x6488150: 0x14199B0, 0x648EEA8: 0x1603EC0, 0x64DF538: 0x14199B0,
                       0x64DF4D0: 0x1419900, 0x648E5E0: 0x648E1F0, 0x648E5F0: 0x648E1F0,
                       0x648E208: 0x14199B0}.items():
        assert reloc[at] == target
    assert read_va(data, reloc[0x648E5D8], 8) == bytes.fromhex("0100000000000000")
    assert read_va(data, reloc[0x648E5E8], 8) == bytes(8)
    print(f"PASS: node #115 SHA-256 {TARGET}")
    print("PASS: slot 51 four-field writer, mode tags, optional child, binary64 and word visitor")


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
        return subprocess.check_output([helper], input=bytes.fromhex(raw)).decode().strip()

    def save(name, raw):
        path = tmp / name
        path.write_bytes(raw)
        return path, hashlib.sha256(raw).hexdigest()

    def checkpoint(name, mode, duration, slip=0.125, depositors=(1 << 64) - 1, **packing):
        source = {"exchange": {"locus": {"ctx": {"height": height}}, FIELD: {
            "max_n_depositors": depositors, "max_slippage": slip, "half_life": duration, "m": mode,
        }}}
        return save(name, msgpack.packb(source, **packing))

    def reference(name, selected, stale=False):
        slots = [[0, [[4, leaf("8403000000000000")]]], [51, selected]]
        digest = leaf("00") if stale else tree.digest(helper, tree.decode_tree(slots))
        return save(name, json.dumps({"height": height, "abci_digest": digest,
                                      "exchange_abci_hash": slots}).encode())

    zero, one, two = map(leaf, ("0000000000000000", "0100000000000000", "0200000000000000"))
    max_slip = leaf("000000000000c03f")
    max_depositors = leaf("ffffffffffffffff")
    for mode, encoded in (("e", zero), ("x", one), ("d", two)):
        for duration, optional in ((None, [[1, zero]]),
                                   (-0.0, [[0, leaf("0000000000000080")], [1, one]])):
            exact = [[0, [[0, encoded]]], [1, optional], [2, max_slip], [3, max_depositors]]
            source = checkpoint("ordinary.rmp", mode, duration)
            good = compare(kit, helper, height, *source, *reference("ordinary.json", exact))
            assert good["ordered_hil_slot_matches"] and all(good["fields"].values())

    wrong = exact[:2] + [[2, zero], exact[3]]
    mismatch = compare(kit, helper, height, *source, *reference("mismatch.json", wrong))
    assert not mismatch["ordered_hil_slot_matches"]
    assert [key for key, ok in mismatch["fields"].items() if not ok] == ["max_slippage"]
    reversed_rows = compare(kit, helper, height, *source, *reference("reversed.json", exact[::-1]))
    assert not reversed_rows["ordered_hil_slot_matches"] and all(reversed_rows["fields"].values())
    correct = reference("correct.json", exact)
    for candidate, raw, expected in (
        (checkpoint("binary32.rmp", "d", -0.0, use_single_float=True), correct, "binary64"),
        (checkpoint("bad-mode.rmp", "other", -0.0), correct, "unknown hil mode"),
        (source, reference("stale.json", exact, stale=True), "stated raw ABCI digest"),
    ):
        try:
            compare(kit, helper, height, *candidate, *raw)
        except ValueError as error:
            assert expected in str(error), error
        else:
            raise AssertionError(expected)
    cmd = [sys.executable, "-B", Path(__file__).with_name("compare_hil.py"), folder, helper,
           str(height), *source, *reference("cli.json", wrong)]
    run = subprocess.run(cmd, check=False, capture_output=True)
    assert run.returncode == 1 and json.loads(run.stdout) == mismatch
    print(f"PASS: msgpack {msgpack.__version__}; all three modes × nil or signed binary64 zero")
    print("PASS: complete ordered subtree, one-field mismatch, binary32 rejection and stale digest rejection")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--helpers", required=True, type=Path)
    parser.add_argument("--rustc", required=True, type=Path)
    args = parser.parse_args()
    native()
    with TemporaryDirectory() as directory:
        controls(args.helpers, args.rustc, Path(directory))
