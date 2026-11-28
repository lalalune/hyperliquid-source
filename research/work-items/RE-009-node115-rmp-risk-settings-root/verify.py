"""Authenticate two named risk settings and test their complete raw subtree comparison."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory

from compare_settings import COOLDOWN, LIMIT_KEYS, LIMITS, SLOTS, compare, load_helpers

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
    rows = bind(data)["slots"]
    for field, offset, method in ((COOLDOWN, 0x37E0, 0x4D3F5C0), (LIMITS, 0x41A8, 0x44E7560)):
        row = rows[SLOTS[field]]
        assert (int(row["box_field"], 16), int(row["method_0"], 16)) == (offset, method)
    sections, header = unwind_index(data)
    _, frames = eh_frame_records(data, sections)
    indexed = {(row["start"], row["fde"]) for row in header}
    extents = [(row["start"], row["end"]) for row in frames
               if (row["start"], row["fde"]) in indexed]

    def verify_bytes(va, raw):
        assert any(start <= va and va + len(raw) <= end for start, end in extents), hex(va)
        assert read_va(data, va, len(raw)) == raw, hex(va)

    key_sites = (0x549C3D0, 0x549C418, 0x549C460, 0x549C4A8, 0x549C4E8, 0x549C521)
    for i, (site, name) in enumerate(zip(key_sites, LIMIT_KEYS)):
        tag = b"\x48\x8d\x35" if i != 5 else b"\x48\x8d\x15"
        assert read_va(data, rip_target(data, site, tag, 7), len(name)) == name.encode()
    for va, prefix, literal in ((0x548134A, b"\x48\x8d\x15", COOLDOWN.encode()),
                                (0x5679BA1, b"\x48\x8d\x35", LIMITS.encode()),
                                (0x4D3F66A, b"\x48\x8d\x3d", b"\x01" + bytes(7)),
                                (0x4D3F6B8, b"\x48\x8d\x3d", bytes(8))):
        assert read_va(data, rip_target(data, va, prefix, 7), len(literal)) == literal
    for va, raw in {
        0x548133A: "4d8b87e0370000", 0x5481341: "f3410f7e87e8370000",
        0x54813F7: "498d97a8410000", 0x56786B4: "4983ff01", 0x56786EA: "c60430c0",
        0x549C3C5: "4d8b6708", 0x549C40D: "4d8b6710", 0x549C455: "4d8b6718",
        0x549C49D: "4d8b6720", 0x549C502: "498b17", 0x549C51D: "4d8b4728",
        0x44E756A: "488d4f08", 0x44E757F: "488d5710", 0x44E758D: "488d5718",
        0x44E759B: "488d5720", 0x44E75A9: "48897c2448", 0x44E75BA: "4883c728",
        0x4D3F5D3: "833f01", 0x4D3F63E: "4883c318", 0x4D3F68B: "488d5818",
        0x141992E: "f20f110401", 0x14199DC: "48890c02", 0x141B3EC: "48890c02",
    }.items():
        verify_bytes(va, bytes.fromhex(raw))
    for va, prefix, width, target in (
        (0x548135C, b"\xe8", 5, 0x5678670), (0x56786BD, b"\xe8", 5, 0x4E380C0),
        (0x5481404, b"\xe8", 5, 0x5679B90), (0x5679BCC, b"\xe9", 5, 0x549C350),
        (0x549C3F9, b"\xe8", 5, 0x57D00B0), (0x549C441, b"\xe8", 5, 0x57D00B0),
        (0x549C489, b"\xe8", 5, 0x57D00B0), (0x549C4D1, b"\xe8", 5, 0x57D00B0),
        (0x549C50D, b"\xe8", 5, 0x57D00B0), (0x549C535, b"\xe8", 5, 0x56736B0),
        (0x44E7664, b"\xe8", 5, 0x41ADE90), (0x4D3F630, b"\xff\x15", 6, 0x64E1530),
        (0x1603EC0, b"\xff\x25", 6, 0x64DF4D0), (0x4D3F6C2, b"\xff\x15", 6, 0x64DF538),
        (0x44E7573, b"\x48\x8d\x0d", 7, 0x648CB38), (0x44E75AE, b"\x48\x8d\x0d", 7, 0x648CB88),
        (0x44E75C3, b"\x48\x8d\x0d", 7, 0x6488138),
    ):
        assert rip_target(data, va, prefix, width) == target, hex(va)
    reloc = relative_relocations(data)
    for at, target in {0x648CB50: 0x14199B0, 0x648CBA0: 0x141B3C0, 0x6488150: 0x14199B0,
                       0x64E1530: 0x1603EC0, 0x64DF4D0: 0x1419900, 0x64DF538: 0x14199B0}.items():
        assert reloc[at] == target
    print(f"PASS: node #115 SHA-256 {TARGET}")
    print("PASS: named optional cooldown and six HIP-3 source-to-root coordinates")


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
    quantities = (27, 4, 2500, 500, 11, (1 << 64) - 1)
    named = dict(zip(LIMIT_KEYS[::-1], quantities[::-1]))

    def leaf(raw):
        return subprocess.check_output([helper], input=raw).decode().strip()

    def word(value):
        return leaf(value.to_bytes(8, "little"))

    def save(name, raw):
        path = tmp / name
        path.write_bytes(raw)
        return path, hashlib.sha256(raw).hexdigest()

    def checkpoint(name, duration, values=named, binary32=False):
        source = {"exchange": {"locus": {"ctx": {"height": height}}, COOLDOWN: duration, LIMITS: values}}
        return save(name, msgpack.packb(source, use_single_float=binary32))

    def reference(name, option, limits, stale=False):
        slots = [[0, [[4, word(600)]]], [37, option], [42, limits]]
        digest = word(0) if stale else tree.digest(helper, tree.decode_tree(slots))
        return save(name, json.dumps({"height": height, "abci_digest": digest,
                                      "exchange_abci_hash": slots}).encode())

    negatives = [[0, leaf(bytes.fromhex("0000000000000080"))], [1, word(1)]]
    absent = [[1, word(0)]]
    limits = [[i, word(value)] for i, value in enumerate(quantities)]
    exact = reference("signed-zero.json", negatives, limits)
    source = checkpoint("negative-zero.rmp", -0.0)
    good = compare(kit, helper, height, *source, *exact)
    assert good["ordered_limits_slot_matches"] and good["cooldown_slot_matches"]
    nil_ref = reference("nil.json", absent, limits)
    assert compare(kit, helper, height, *checkpoint("nil.rmp", None), *nil_ref)["cooldown_slot_matches"]

    reordered = reference("bad.json", absent, limits[::-1])
    mismatch = compare(kit, helper, height, *source, *reordered)
    assert not mismatch["ordered_limits_slot_matches"] and not mismatch["cooldown_slot_matches"]
    assert all(mismatch["limits"].values())
    twisted = reference("twisted.json", negatives, limits[:4] + [[4, word(12)], limits[5]])
    mismatch = compare(kit, helper, height, *source, *twisted)
    assert mismatch["cooldown_slot_matches"] and not mismatch["ordered_limits_slot_matches"]
    assert [name for name, match in mismatch["limits"].items() if not match] == ["daily_px_range"]

    missing = checkpoint("missing.rmp", -0.0, {k: v for k, v in named.items() if k != "daily_px_range"})
    single = checkpoint("single.rmp", -0.0, binary32=True)
    stale = reference("stale.json", negatives, limits, stale=True)
    for candidate, raw, reason in ((missing, exact, "all six"), (single, exact, "binary64"),
                                    (source, stale, "stated raw ABCI digest")):
        try:
            compare(kit, helper, height, *candidate, *raw)
        except ValueError as error:
            assert reason in str(error), error
        else:
            raise AssertionError(reason)
    cmd = [sys.executable, "-B", Path(__file__).with_name("compare_settings.py"), folder, helper,
           str(height), *source, *twisted]
    run = subprocess.run(cmd, check=False, capture_output=True)
    assert run.returncode == 1 and json.loads(run.stdout) == mismatch
    print(f"PASS: msgpack {msgpack.__version__}; complete cooldown and six-field HIP-3 branches")
    print("PASS: nil versus signed zero, ordered child slots, field-level mismatch and stale digest checks")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--helpers", required=True, type=Path)
    parser.add_argument("--rustc", required=True, type=Path)
    args = parser.parse_args()
    native()
    with TemporaryDirectory() as directory:
        controls(args.helpers, args.rustc, Path(directory))
