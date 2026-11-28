"""Check named checkpoint and raw-root scalar joins without executing the node."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory

from compare_auctions import SLOTS, compare, load_helpers

sys.path.insert(0, str(Path.cwd() / "tools"))
from abci_hash_slots_115 import bind
from elf_index import unwind_index
from fde_extents import eh_frame_records
from freeze_snapshot_115 import read_va, relative_relocations, rip_target

TARGET = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
RUST_SOURCE_SHA = "6791575648e65e8ef4fe42536b7327f85c57327cb2423255b598fb2b1d83828f"


def native():
    data = Path("artifacts/node/115/hl-node").read_bytes()
    assert hashlib.sha256(data).hexdigest() == TARGET
    slots = bind(data)["slots"]
    sections, header = unwind_index(data)
    _, fdes = eh_frame_records(data, sections)
    indexed = {(item["start"], item["fde"]) for item in header}
    extents = [(item["start"], item["end"]) for item in fdes
               if (item["start"], item["fde"]) in indexed]

    def check(va, raw):
        assert any(start <= va and va + len(raw) <= end for start, end in extents), hex(va)
        assert read_va(data, va, len(raw)) == raw, hex(va)

    for index, (name, slot) in enumerate(SLOTS.items()):
        field = 0x3A00 + 0x40 * index
        entry = slots[slot]
        assert (int(entry["box_field"], 16), int(entry["vtable"], 16),
                int(entry["method_0"], 16)) == (field, 0x64A84F8, 0x4D3E9B0)
        site = 0x54811FA + 0x2B * index
        check(site - 7, b"\x4d\x8d\x87" + field.to_bytes(4, "little"))
        name_bytes = name.encode("ascii")
        check(site + 10, b"\xb9" + len(name_bytes).to_bytes(4, "little"))
        assert read_va(data, rip_target(data, site, b"\x48\x8d\x15", 7), len(name_bytes)) == name_bytes
        assert rip_target(data, site + 18, b"\xe8", 5) == 0x5673520

    for va, label, prefix in (
        (0x5A0162D, b"bucket_guard", b"\x48\x8d\x35"),
        (0x5A01672, b"start_gas_wei", b"\x48\x8d\x35"),
        (0x5A0175D, b"token", b"\x48\x8d\x35"),
        (0x5A0179E, b"initial_gas_to_last_auction_gas_ratio", b"\x48\x8d\x35"),
        (0x5A017D8, b"min_gas", b"\x48\x8d\x15"),
        (0x561709A, b"last_bucket", b"\x48\x8d\x35"),
        (0x56170D3, b"bucket_millis", b"\x48\x8d\x35"),
    ):
        assert read_va(data, rip_target(data, va, prefix, 7), len(label)) == label

    for va, target in {
        0x5A01657: 0x5617020, 0x5A0169C: 0x57D00B0, 0x5A01787: 0x57D00B0,
        0x5A017C4: 0x57D00B0, 0x5A017EC: 0x5AAE2C0, 0x5AAE303: 0x57D00B0,
        0x56170BD: 0x57D00B0, 0x56170F6: 0x57D00B0,
        0x43C6AAB: 0x41AE280,
    }.items():
        assert rip_target(data, va, b"\xe8", 5) == target

    for va, raw in {
        0x567354E: "41833f02", 0x567357A: "c60430c0",
        0x5A0164B: "498d7710", 0x5A01690: "498b5728",
        0x5A0177B: "498b5730", 0x5A017B8: "498b5720", 0x5A017D4: "4d8b4738",
        0x561708F: "4d8b6708", 0x56170ED: "498b17",
        0x46F4590: "4c8d7708", 0x46F45CC: "4883c318",
        0x43C6A57: "48897c2408", 0x43C6A68: "4883c708",
        0x14199DC: "48890c02", 0x141B3EC: "48890c02",
    }.items():
        check(va, bytes.fromhex(raw))

    assert rip_target(data, 0x567359F, b"\xe9", 5) == 0x5A015B0
    assert rip_target(data, 0x4302E70, b"\xff\x25", 6) == 0x64DF538
    relocs = relative_relocations(data)
    for slot, target in {
        0x6478790: 0x46F4560, 0x6476F70: 0x43C6A50, 0x6487B20: 0x14199B0,
        0x6474038: 0x4302E70, 0x64741E0: 0x141B3C0, 0x64DF538: 0x14199B0,
        0x64DF530: 0x14199B0, 0x64DF5D0: 0x141B3C0,
    }.items():
        assert relocs[slot] == target, hex(slot)

    print(f"PASS: node #115 SHA-256 {TARGET}")
    print("PASS: three named slot bindings, six scalar writer/preimage joins and named nil gate")


def compile_helper(folder, rustc, directory):
    source = folder / "RE-009-node115-context-root-isolation/hash_tree.rs"
    data = source.read_bytes()
    assert hashlib.sha256(data).hexdigest() == RUST_SOURCE_SHA
    saved = directory / source.name
    saved.write_bytes(data)
    library = directory / "libnode115_abci_blake3.rlib"
    executable = directory / "hash_tree"
    subprocess.run([rustc, "--edition=2024", "--crate-name", "node115_abci_blake3",
                    "--crate-type", "rlib", "src/node115-abci-blake3/src/lib.rs",
                    "-o", library], check=True)
    subprocess.run([rustc, "--edition=2024", saved, "--extern",
                    f"node115_abci_blake3={library}", "-o", executable], check=True)
    return executable


def controls(folder, rustc, directory):
    import msgpack

    helpers = load_helpers(folder)
    helper = compile_helper(folder, rustc, directory)

    def leaf(value):
        return subprocess.check_output([helper], input=value.to_bytes(8, "little")).decode().strip()

    height = 30
    cap = (1 << 64) - 1
    names = list(SLOTS)
    common = {"bucket_guard": {"last_bucket": 17, "bucket_millis": 900},
              "start_gas_wei": 123_456, "end_gas_wei": None, "token": 7,
              "initial_gas_to_last_auction_gas_ratio": cap, "min_gas": 0}
    changed = {**common, "token": 29, "end_gas_wei": 2000}
    checkpoint_values = {names[0]: common, names[1]: None, names[2]: changed}

    def save(name, raw):
        path = directory / name
        path.write_bytes(raw)
        return path, hashlib.sha256(raw).hexdigest()

    def rmp(name, fields):
        return save(name, msgpack.packb({"exchange": {"locus": {"ctx": {"height": height}},
                                                     **fields}}, use_bin_type=True))

    def raw(name, token_last, wrong_root=False):
        branch_28 = [[0, [[0, [[0, leaf(17)], [1, leaf(900)]]], [1, [[0, leaf(123_456)]]],
                          [2, [[0, leaf(734)]]], [3, leaf(7)], [4, leaf(cap)], [5, [[0, leaf(0)]]]]],
                     [1, leaf(1)]]
        branch_30 = [[0, [[0, [[0, leaf(17)], [1, leaf(900)]]], [1, [[0, leaf(123_456)]]],
                          [2, [[1, leaf(82)]]], [3, leaf(token_last)], [4, leaf(cap)],
                          [5, [[0, leaf(0)]]]]], [1, leaf(1)]]
        ordered = [[0, [[4, leaf(600)]]], [28, branch_28], [29, [[1, leaf(0)]]], [30, branch_30]]
        tree = helpers["tree"]
        digest = leaf(0) if wrong_root else tree.digest(helper, tree.decode_tree(ordered))
        return save(name, json.dumps({"height": height, "abci_digest": digest,
                                      "exchange_abci_hash": ordered}).encode())

    checkpoint = rmp("named.rmp", checkpoint_values)
    reference = raw("reference.json", 29)
    good = compare(helpers, helper, height, *checkpoint, *reference)
    assert good["selected_checks_pass"]
    assert [len(row["leaves"]) for row in good["auctions"].values()] == [7, 1, 7]
    assert good["auctions"][names[1]]["leaves"] == {"presence": True}

    wrong_token = raw("wrong-token.json", 7)
    mismatch = compare(helpers, helper, height, *checkpoint, *wrong_token)
    assert not mismatch["selected_checks_pass"]
    bad_fields = [(name, field) for name, row in mismatch["auctions"].items()
                  for field, agrees in row["leaves"].items() if not agrees]
    assert bad_fields == [(names[2], "token")]
    missing = rmp("omitted.rmp", {names[0]: common, names[2]: changed})
    stale = raw("wrong-digest.json", 29, wrong_root=True)
    wrong_type = rmp("bad-width.rmp", checkpoint_values | {names[2]: changed | {"token": -1}})
    for source, export, reason in ((missing, reference, "omits"), (checkpoint, stale, "stated raw"),
                                   (wrong_type, reference, "unsigned 64-bit token")):
        try:
            compare(helpers, helper, height, *source, *export)
        except ValueError as error:
            assert reason in str(error), error
        else:
            raise AssertionError(reason)

    cli = Path(__file__).with_name("compare_auctions.py")
    cmd = [sys.executable, "-B", cli, folder, helper, str(height), *checkpoint, *wrong_token]
    result = subprocess.run(cmd, capture_output=True, check=False)
    assert result.returncode == 1 and json.loads(result.stdout) == mismatch
    print(f"PASS: msgpack {msgpack.__version__}; mixed presence and six scalar leaves per present slot")
    print("PASS: single slot-30 token mismatch localized; omitted field, invalid u64 and stale root rejected")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--helpers", required=True, type=Path)
    parser.add_argument("--rustc", required=True, type=Path)
    options = parser.parse_args()
    native()
    with TemporaryDirectory() as directory:
        controls(options.helpers, options.rustc, Path(directory))
