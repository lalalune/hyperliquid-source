"""Authenticate staking-link writer and variant streams, then compare synthetic raw trees."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory

from compare_links import FIELD, LINKS, SLOT, compare, load_helpers

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
    assert (int(row["box_field"], 16), int(row["method_0"], 16)) == (0x40A0, 0x472EA70)
    sections, header = unwind_index(data)
    _, frames = eh_frame_records(data, sections)
    indexed = {(row["start"], row["fde"]) for row in header}
    spans = {row["start"]: row["end"] for row in frames if (row["start"], row["fde"]) in indexed}
    writers = (0x37CA6C0, 0x5139600)
    assert all(spans[start] - start == 0x21B for start in writers)
    assert read_va(data, writers[0], 0x1FF) == read_va(data, writers[1], 0x1FF)
    for va, encoding in {
        0x54813B9: "498d97a0400000", 0x5363E5C: "ba01000000", 0x5363EB1: "ba15000000",
        0x5299185: "488d4329", 0x5299191: "4c8d6314",
        0x5364614: "48b954726164696e6755", 0x5364622: "c744300755736572",
        0x5364674: "48b95265717565737465", 0x5364682: "c644300864",
        0x5364719: "48b95374616b696e6755", 0x5364727: "c744300755736572",
        0x472EA82: "48837e1001", 0x3C560A1: "488b5718", 0x3C560D5: "4889542438",
        0x3C562A9: "498d4529", 0x3C562B2: "498d6d14", 0x3C56337: "488b442438",
        0x471542D: "48c70304000000", 0x4715438: "48c7431004000000",
        0x4715467: "0fb60f", 0x471546A: "48ffc7", 0x471546F: "7418", 0x4715474: "7526",
        0x4715476: "48c7042401000000", 0x471547E: "48c744240801000000",
        0x4715489: "48c7042400000000", 0x4715491: "48c744240800000000",
        0x471549C: "48c7042402000000", 0x47154A4: "48c744240802000000",
        0x47154BE: "48c744242003000000", 0x41AEDCB: "488d0449",
        0x41AEE22: "488b442418", 0x141B9F1: "4883c114", 0x14199DC: "48890c02",
    }.items():
        raw = bytes.fromhex(encoding)
        assert any(begin <= va and va + len(raw) <= end for begin, end in spans.items()), hex(va)
        assert read_va(data, va, len(raw)) == raw, hex(va)
    for va, prefix, width, target in (
        (0x54813C6, b"\xe8", 5, 0x5675030), (0x567506C, b"\xe9", 5, 0x5363E30),
        (0x5363E61, b"\xe8", 5, 0x57CE100), (0x5363FA4, b"\xe8", 5, 0x5298FB0),
        (0x5299047, b"\xe8", 5, 0x57CEBA0), (0x52991B8, b"\xe8", 5, writers[1]),
        (0x52993FB, b"\xe8", 5, 0x5320910), (0x52994E3, b"\xe8", 5, 0x53645B0),
        (0x472EACE, b"\xe8", 5, 0x3C56090), (0x3C562C5, b"\xe8", 5, writers[0]),
        (0x3C56390, b"\xe8", 5, 0x41ADC70), (0x47154E3, b"\xe8", 5, 0x41AED60),
        (0x3C5623E, b"\x4c\x8d\x35", 7, 0x6476BC0), (0x3C56245, b"\x4c\x8d\x3d", 7, 0x64772A0),
        (0x3C56354, b"\x48\x8d\x05", 7, 0x6473FF8), (0x47154B2, b"\x48\x8d\x0d", 7, 0x648F6F8),
        (0x47154CF, b"\x48\x8d\x0d", 7, 0x648F680),
    ):
        assert rip_target(data, va, prefix, width) == target, hex(va)
    for va, prefix, literal in (
        (0x5675041, b"\x48\x8d\x35", FIELD.encode()), (0x5363EAA, b"\x48\x8d\x35", LINKS.encode()),
        (0x53646C9, b"\x48\x8d\x15", b"staking_user"), (0x5364771, b"\x48\x8d\x15", b"trading_user"),
    ):
        assert read_va(data, rip_target(data, va, prefix, 7), len(literal)) == literal
    relocs = relative_relocations(data)
    for at, target in {
        0x64772B8: 0x4715460, 0x64772C0: 0x4715400, 0x6476BD8: 0x41F8050,
        0x648F710: 0x41F8050, 0x64DF600: 0x141B9B0, 0x648F698: 0x14199B0,
        0x6474010: 0x14199B0,
    }.items():
        assert relocs[at] == target, hex(at)
    print(f"PASS: node #115 SHA-256 {TARGET}")
    print("PASS: native staking-link shape, matching iterator bodies and separate variant stream bindings")


def driver(folder, rustc, temp):
    source = folder / "RE-009-node115-context-root-isolation/hash_tree.rs"
    data = source.read_bytes()
    assert hashlib.sha256(data).hexdigest() == DRIVER_SHA
    staged = temp / source.name
    staged.write_bytes(data)
    library = temp / "libnode115_abci_blake3.rlib"
    executable = temp / "hash_tree"
    subprocess.run([rustc, "--edition=2024", "--crate-name", "node115_abci_blake3",
                    "--crate-type", "rlib", "src/node115-abci-blake3/src/lib.rs",
                    "-o", library], check=True)
    subprocess.run([rustc, "--edition=2024", staged, "--extern",
                    f"node115_abci_blake3={library}", "-o", executable], check=True)
    return executable


def controls(folder, rustc, temp):
    import msgpack

    kit = load_helpers(folder)
    helper = driver(folder, rustc, temp)
    tree = kit["tree"]
    height = 710
    keys = [bytes([i]) * 20 for i in range(1, 5)]
    payloads = [bytes([i]) * 20 for i in range(51, 55)]

    def address(key):
        return "0x" + key.hex()

    labels = [("Requested", "staking_user"), ("TradingUser", "staking_user"),
              ("Requested", "staking_user"), ("StakingUser", "trading_user")]
    rows = [[address(key), {variant: {name: address(payload)}}]
            for key, (variant, name), payload in zip(keys, labels, payloads)]

    def leaf(raw):
        return subprocess.check_output([helper], input=raw).decode().strip()

    def qwords(*values):
        return b"".join(value.to_bytes(8, "little") for value in values)

    def save(name, raw):
        path = temp / name
        path.write_bytes(raw)
        return path, hashlib.sha256(raw).hexdigest()

    def checkpoint(name, links):
        return save(name, msgpack.packb({"exchange": {"locus": {"ctx": {"height": height}}, FIELD: {LINKS: links}}}))

    def reference(name, subtree, stale=False):
        entries = [[0, [[4, leaf(b"other")]]], [40, [[0, subtree]]]]
        digest = leaf(b"wrong") if stale else tree.digest(helper, tree.decode_tree(entries))
        return save(name, json.dumps({"height": height, "abci_digest": digest,
                                      "exchange_abci_hash": entries}).encode())

    variants = [[0, leaf(payloads[0] + payloads[2])], [1, leaf(payloads[1])], [2, leaf(payloads[3])],
                [3, leaf(qwords(0, 1, 0, 2))]]
    expected = [[0, leaf(b"".join(keys))], [1, variants], [2, leaf(qwords(4))]]
    checkpoint_all = checkpoint("native.rmp", rows)
    exact = reference("exact.json", expected)
    assert compare(kit, helper, height, *checkpoint_all, *exact)["ordered_subtree_matches"]
    assert compare(kit, helper, height, *checkpoint("empty.rmp", []),
                   *reference("empty.json", [[2, leaf(qwords(0))]]))["ordered_subtree_matches"]

    one_variant = [[0, leaf(keys[1])], [1, [[1, leaf(payloads[1])], [3, leaf(qwords(1))]]], [2, leaf(qwords(1))]]
    assert compare(kit, helper, height, *checkpoint("one.rmp", [rows[1]]),
                   *reference("one.json", one_variant))["ordered_subtree_matches"]

    wrong_tags = [expected[0], [1, variants[:3] + [[3, leaf(qwords(0, 0, 1, 2))]]], expected[2]]
    wrong = reference("wrong-tags.json", wrong_tags)
    result = compare(kit, helper, height, *checkpoint_all, *wrong)
    assert not result["ordered_subtree_matches"] and not result["variant_subtree_matches"]
    assert result["key_stream_matches"] and result["count_leaf_matches"]
    swapped = compare(kit, helper, height, *checkpoint("swapped.rmp", [rows[2], rows[1], rows[0], rows[3]]), *exact)
    assert not swapped["key_stream_matches"] and not swapped["variant_subtree_matches"]
    assert swapped["count_leaf_matches"]

    unsupported = checkpoint("wrong-variant.rmp", [[address(keys[0]), {"Other": {"staking_user": address(payloads[0])}}]])
    stale = reference("stale.json", expected, stale=True)
    for candidate, ref, reason in ((unsupported, exact, "unknown named"), (checkpoint_all, stale, "stated raw")):
        try:
            compare(kit, helper, height, *candidate, *ref)
        except ValueError as error:
            assert reason in str(error), error
        else:
            raise AssertionError(reason)
    cmd = [sys.executable, "-B", Path(__file__).with_name("compare_links.py"), folder, helper,
           str(height), *checkpoint_all, *wrong]
    run = subprocess.run(cmd, check=False, capture_output=True)
    assert run.returncode == 1 and json.loads(run.stdout) == result
    print(f"PASS: msgpack {msgpack.__version__}; all three variants, sparse variant streams and empty collection")
    print("PASS: type order, same-variant payload order, unknown variant and stale digest controls")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--helpers", required=True, type=Path)
    parser.add_argument("--rustc", required=True, type=Path)
    args = parser.parse_args()
    native()
    with TemporaryDirectory() as temp:
        controls(args.helpers, args.rustc, Path(temp))
