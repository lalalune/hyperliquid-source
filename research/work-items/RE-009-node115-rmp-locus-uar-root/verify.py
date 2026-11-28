"""Verify complete named Locus uaR and its three levels of ordered raw streams."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from types import ModuleType
from tempfile import TemporaryDirectory

from compare_uar import compare, load_helpers

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
    assert by_name["uaR"] == ("0.7", "uaR", "0x9f8", "0x6479470", "0x3c52840", "0x3b83660")
    assert by_name["height"] == ("0.0.2", "height", "0x28", "0x64828c8", "0x14199b0", "0x14196d0")

    sections, header = unwind_index(data)
    _, frames = eh_frame_records(data, sections)
    indexed = {(row["start"], row["fde"]) for row in header}
    extents = [(row["start"], row["end"]) for row in frames
               if (row["start"], row["fde"]) in indexed]

    def verify_bytes(va, raw):
        assert any(start <= va and va + len(raw) <= end for start, end in extents), hex(va)
        assert read_va(data, va, len(raw)) == raw, hex(va)

    raw_table = rip_target(data, 0x3B82F1C, bytes.fromhex("488d0d"), 7)
    named_table = rip_target(data, 0x4D955A4, bytes.fromhex("488d0d"), 7)
    raw_arms = (0x3B82F2C, 0x3B82FEE, 0x3B82FAE, 0x3B82FCE, 0x3B82F4F, 0x3B83046, 0x3B83096)
    named_arms = (
        (0x4D955B4, 0x4D955E2, b"Perp"), (0x4D95704, 0x4D95724, b"Spot"),
        (0x4D9561A, 0x4D95648, b"Token"), (0x4D9568C, 0x4D956B0, b"Pdi"),
        (0x4D95604, 0x4D9560E, b"ActivateDexAbstraction"),
        (0x4D95794, 0x4D9579E, b"ActivateUnifiedAccount"), (0x4D957BE, 0x4D957C8, b"AllBoleTokens"),
    )
    for tag, (arm, literal, name) in enumerate(named_arms):
        for table, dst in ((raw_table, raw_arms[tag]), (named_table, arm)):
            delta = int.from_bytes(read_va(data, table + tag * 4, 4), "little", signed=True)
            assert table + delta == dst
        assert read_va(data, rip_target(data, literal, bytes.fromhex("488d35"), 7), len(name)) == name
        verify_bytes(raw_arms[tag], bytes.fromhex("48c7442408") + tag.to_bytes(4, "little"))

    for va, raw in {
        0x5480C1C: "498d97f8090000", 0x52BADA1: "4d8d6618", 0x52BB029: "c6040192",
        0x4D94190: "c6040181", 0x4D941C3: "c7040750657270", 0x4D941E3: "c60431b6", 0x4D94320: "488b4608",
        0x4510BA1: "48891c08", 0x4510D80: "498d6e01", 0x4510DD5: "4c896c2430",
        0x4510DEB: "48894c2440", 0x41AE2EA: "41ff5518", 0x41ADD8D: "41ff5618",
        0x45070B4: "48b9010000000000008048890848894818", 0x3B82F15: "488b074883c708",
        0x3B82F35: "48c744241000000000", 0x3B82FF7: "48c744241001000000",
        0x3B82FB7: "48c744241002000000", 0x3B82FD7: "48c744241003000000",
        0x3B83011: "48c744242804000000", 0x3B82ED1: "48894818488948304889484848894860",
        0x3B82EEC: "48c7431005000000", 0x3B82F80: "488d5960",
        0x3B8306F: "488d5960", 0x3B830BF: "488d5960",
        0x14199DC: "48890c02", 0x141B9F1: "4883c114",
    }.items():
        verify_bytes(va, bytes.fromhex(raw))
    for va, prefix, target in (
        (0x5480C29, "e8", 0x5678AE0), (0x5678BF9, "e8", 0x52BAB90), (0x52BAC2F, "e8", 0x57CEBA0), (0x52BAE96, "e8", 0x531FE80),
        (0x52BAFDE, "e8", 0x57CEBA0), (0x52BB49D, "e8", 0x5138950), (0x52BB4CC, "e8", 0x4D94160),
        (0x4D9432D, "e8", 0x57CFD20), (0x4D9566F, "e8", 0x57D00B0), (0x4D956E4, "e8", 0x57D00B0), (0x4D9574E, "e8", 0x57D00B0),
        (0x3C529EE, "4c8d35", 0x6476BC0), (0x3C529F5, "4c8d3d", 0x6476FD0),
        (0x3C52B04, "488d05", 0x6473FF8), (0x3C52B40, "e8", 0x41ADC70),
        (0x4510BA5, "488d15", 0x648E448), (0x4510DE4, "488d0d", 0x648E1F0), (0x4510E15, "e8", 0x41AE280),
        (0x3B82F43, "488d05", 0x6474048), (0x3B83005, "488d05", 0x6474070),
        (0x3B82FC5, "488d05", 0x6474020), (0x3B82FE5, "488d05", 0x6473FD0),
        (0x3B83024, "488d05", 0x6473FF8), (0x3B8303B, "e8", 0x41AED60), (0x3B830FD, "ff15", 0x64DF538),
        (0x3916050, "ff25", 0x64DF538), (0x4302E70, "ff25", 0x64DF538),
        (0x457D480, "ff25", 0x64DF538), (0x41F8050, "ff25", 0x64DF600),
    ):
        op = bytes.fromhex(prefix)
        assert rip_target(data, va, op, len(op) + 4) == target, hex(va)
    reloc = relative_relocations(data)
    for site, method in {
        0x6476BD8: 0x41F8050, 0x6476FE8: 0x4510AC0, 0x6476FF0: 0x45070A0, 0x6474010: 0x14199B0,
        0x648E460: 0x3B82F10, 0x648E468: 0x3B82EB0, 0x648E208: 0x14199B0,
        0x6474060: 0x3916050, 0x6474088: 0x457D480, 0x6474038: 0x4302E70, 0x6473FE8: 0x457D480,
        0x64DF538: 0x14199B0, 0x64DF600: 0x141B9B0,
    }.items():
        assert reloc[site] == method, hex(site)
    print(f"PASS: node #115 SHA-256 {TARGET}")
    print("PASS: seven serialized variants, four native numeric streams, shared tags and nested counts")


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

    def words(*values):
        return leaf(b"".join(value.to_bytes(8, "little") for value in values))

    def save(name, raw):
        path = tmp / name
        path.write_bytes(raw)
        return path, hashlib.sha256(raw).hexdigest()

    def checkpoint(name, rows):
        source = {"exchange": {"locus": {"ctx": {"height": height}, "uaR": rows}}}
        return save(name, msgpack.packb(source))

    def reference(name, selected, root_height=height, stale=False):
        slots = [[0, [[0, [[2, words(root_height)], [4, words(321)]]], [7, selected]]]]
        digest = leaf(b"stale") if stale else tree.digest(helper, tree.decode_tree(slots))
        return save(name, json.dumps({"height": height, "abci_digest": digest,
                                      "exchange_abci_hash": slots}).encode())

    first, second, third = (bytes([value]) * 20 for value in (1, 2, 3))
    rows = [
        ["0x" + first.hex(), [{"Perp": 9}, {"Spot": 12}, "ActivateDexAbstraction"]],
        [list(second), [{"Perp": 100}, {"Token": (1 << 64) - 1}, {"Pdi": 2},
                        "ActivateUnifiedAccount", "AllBoleTokens"]],
        ["0x" + third.hex(), []],
    ]
    source = checkpoint("ordinary.rmp", rows)
    tags = [0, 1, 4, 0, 2, 3, 5, 6]
    variants = [[0, words(9, 100)], [1, words(12)], [2, words((1 << 64) - 1)], [3, words(2)], [4, words(*tags)]]
    expected = [[0, leaf(first + second + third)], [1, [[0, variants], [1, words(3, 5, 0)]]], [2, words(3)]]
    exact = reference("ordinary.json", expected)
    assert compare(kit, helper, height, *source, *exact)["ordered_uar_matches"]

    units = checkpoint("units.rmp", [[rows[0][0], ["AllBoleTokens"]]])
    unit_ref = reference("units.json", [[0, leaf(first)], [1, [[0, [[4, words(6)]]], [1, words(1)]]], [2, words(1)]])
    assert compare(kit, helper, height, *units, *unit_ref)["ordered_uar_matches"]
    empty_users = checkpoint("empty-users.rmp", [[rows[0][0], []], [rows[1][0], []]])
    empty_users_ref = reference("empty-users.json", [[0, leaf(first + second)], [1, [[1, words(0, 0)]]], [2, words(2)]])
    assert compare(kit, helper, height, *empty_users, *empty_users_ref)["ordered_uar_matches"]
    assert compare(kit, helper, height, *checkpoint("empty.rmp", []),
                   *reference("empty.json", [[2, words(0)]]))["ordered_uar_matches"]

    wrong = expected[:1] + [[1, [[0, variants[:4] + [[4, words(*tags[::-1])]]], [1, words(3, 5, 0)]]]] + expected[2:]
    mismatch_ref = reference("mismatch.json", wrong)
    mismatch = compare(kit, helper, height, *source, *mismatch_ref)
    assert not mismatch["ordered_value_streams_match"] and mismatch["address_stream_matches"]
    assert mismatch["user_count_matches"]
    count_bad = reference("counts.json", expected[:1] + [[1, [[0, variants], [1, words(5, 3, 0)]]]] + expected[2:])
    assert not compare(kit, helper, height, *source, *count_bad)["ordered_value_streams_match"]

    for candidate, ref, reason in (
        (checkpoint("duplicate-variant.rmp", [[rows[0][0], [{"Perp": 1}, {"Perp": 1}]]]), exact, "duplicate uaR variant"),
        (checkpoint("unit-as-map.rmp", [[rows[0][0], [{"ActivateDexAbstraction": None}]]]), exact, "uaR variant"),
        (source, reference("wrong-inner-h.json", expected, root_height=height + 1), "inner Context height"),
        (source, reference("stale.json", expected, stale=True), "stated raw ABCI digest"),
    ):
        try:
            compare(kit, helper, height, *candidate, *ref)
        except ValueError as error:
            assert reason in str(error), error
        else:
            raise AssertionError(reason)
    cmd = [sys.executable, "-B", Path(__file__).with_name("compare_uar.py"), folder, helper,
           str(height), *source, *mismatch_ref]
    run = subprocess.run(cmd, check=False, capture_output=True)
    assert run.returncode == 1 and json.loads(run.stdout) == mismatch
    print(f"PASS: msgpack {msgpack.__version__}; full seven-variant, unit-only and empty controls")
    print("PASS: type order and per-user count mismatches isolated at a verified inner H")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--helpers", required=True, type=Path)
    parser.add_argument("--rustc", required=True, type=Path)
    args = parser.parse_args()
    native(args.helpers)
    with TemporaryDirectory() as directory:
        controls(args.helpers, args.rustc, Path(directory))
