"""Verify ordered display-name streams and test the full slot with pinned fixtures."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory

from compare_display_names import FIELD, SLOT, compare, load_helpers

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
    assert (int(row["box_field"], 16), int(row["method_0"], 16),
            int(row["method_1"], 16)) == (0x3F88, 0x4D9E710, 0x4D9DB00)
    sections, header = unwind_index(data)
    _, frames = eh_frame_records(data, sections)
    indexed = {(row["start"], row["fde"]) for row in header}
    extents = [(row["start"], row["end"]) for row in frames
               if (row["start"], row["fde"]) in indexed]
    for va, encoding in {
        0x54810A2: "498d97883f0000", 0x56761C5: "ba14000000",
        0x52D835B: "488d4830", 0x52D8367: "488d4818", 0x53065BD: "c6040192",
        0x53209FB: "be2a000000", 0x5320A00: "b914000000", 0x5320A05: "4531c0",
        0x5322C7F: "488b7208", 0x5322C83: "488b5210",
        0x4D9E721: "488b5718", 0x4D9E755: "4889542438", 0x4D9E929: "498d4530",
        0x4D9E932: "498d6d18", 0x4D9E974: "4c892c08", 0x4D9E8DC: "48892c08",
        0x4D9E9B7: "488b442438", 0x4D9DB1E: "4889084889481848894830",
        0x4E1BEBB: "48837f1003", 0x4E1BF10: "4883c510", 0x4E1BF90: "4983c710",
        0x141B620: "488b5710", 0x141A8E8: "48891c01", 0x141A90A: "4889da",
        0x141B9F1: "4883c114", 0x14199DC: "48890c02",
    }.items():
        raw = bytes.fromhex(encoding)
        if va != 0x4E1BEBB:
            assert any(start <= va and va + len(raw) <= end for start, end in extents), hex(va)
        assert read_va(data, va, len(raw)) == raw, hex(va)
    for va, prefix, target in (
        (0x54810AF, b"\xe8", 0x56761A0), (0x56762B9, b"\xe8", 0x52D81D0),
        (0x52D8279, b"\xe8", 0x57CEBA0), (0x52D8383, b"\xe8", 0x5133D90),
        (0x52D8399, b"\xe8", 0x5306490), (0x53065F4, b"\xe8", 0x5320910),
        (0x530660A, b"\xe8", 0x5322BB0), (0x5320A08, b"\xff\x15", 0x64E4D08),
        (0x5320A14, b"\xe8", 0x57CF5D0), (0x5322C8A, b"\xe8", 0x57CF5D0),
        (0x4D9E945, b"\xe8", 0x5133D90), (0x4D9EA10, b"\xe8", 0x4E1BEA0),
        (0x41F8050, b"\xff\x25", 0x64DF600), (0x141B627, b"\xe8", 0x141A8C0),
    ):
        assert rip_target(data, va, prefix, len(prefix) + 4) == target, hex(va)
    key = rip_target(data, 0x56761BE, b"\x48\x8d\x05", 7)
    assert read_va(data, key, len(FIELD)) == FIELD.encode()
    for site, desc in ((0x4D9E8BE, 0x649A790), (0x4D9E8C5, 0x649C830), (0x4D9E9D4, 0x649A6F0)):
        assert rip_target(data, site, read_va(data, site, 3), 7) == desc
    reloc = relative_relocations(data)
    for at, target in {
        0x649A7A8: 0x41F8050, 0x649C848: 0x141B610, 0x649A708: 0x14199B0,
        0x64DF600: 0x141B9B0, 0x64E4D08: 0x2EABB50,
    }.items():
        assert reloc[at] == target
    print(f"PASS: node #115 SHA-256 {TARGET}")
    print("PASS: shared row order iterator, named pair array, address/name/count raw streams and empty slots")


def driver(folder, rustc, temp):
    source = folder / "RE-009-node115-context-root-isolation/hash_tree.rs"
    data = source.read_bytes()
    assert hashlib.sha256(data).hexdigest() == DRIVER_SHA
    staged = temp / source.name
    staged.write_bytes(data)
    library = temp / "libnode115_abci_blake3.rlib"
    program = temp / "hash_tree"
    subprocess.run([rustc, "--edition=2024", "--crate-name", "node115_abci_blake3",
                    "--crate-type", "rlib", "src/node115-abci-blake3/src/lib.rs",
                    "-o", library], check=True)
    subprocess.run([rustc, "--edition=2024", staged, "--extern",
                    f"node115_abci_blake3={library}", "-o", program], check=True)
    return program


def controls(folder, rustc, temp):
    import msgpack

    kit = load_helpers(folder)
    tree = kit["tree"]
    helper = driver(folder, rustc, temp)
    height = 512
    addr_a = "0x" + "0123456789abcdef0123456789abcdef01234567"
    addr_b = "0x" + "ab" * 20
    rows = [[addr_a, ""], [addr_b, "é水"]]

    def hash_raw(raw):
        return subprocess.check_output([helper], input=raw).decode().strip()

    def save(name, raw):
        path = temp / name
        path.write_bytes(raw)
        return path, hashlib.sha256(raw).hexdigest()

    def checkpoint(name, pairs):
        return save(name, msgpack.packb({"exchange": {"locus": {"ctx": {"height": height}}, FIELD: pairs}}))

    def raw_reference(name, branch, wrong_digest=False):
        entries = [[0, [[4, hash_raw(b"unrelated")]]], [19, branch]]
        digest = hash_raw(b"stale") if wrong_digest else tree.digest(helper, tree.decode_tree(entries))
        return save(name, json.dumps({"height": height, "abci_digest": digest,
                                      "exchange_abci_hash": entries}).encode())

    keys = bytes.fromhex(addr_a[2:] + addr_b[2:])
    names = bytes.fromhex("00000000000000000500000000000000c3a9e6b0b4")
    count = bytes.fromhex("0200000000000000")
    branch = [[0, hash_raw(keys)], [1, hash_raw(names)], [2, hash_raw(count)]]
    named = checkpoint("native.rmp", rows)
    exact = raw_reference("exact.json", branch)
    assert compare(kit, helper, height, *named, *exact)["ordered_subtree_matches"]
    empty = checkpoint("empty.rmp", [])
    empty_ref = raw_reference("empty.json", [[2, hash_raw(bytes(8))]])
    assert compare(kit, helper, height, *empty, *empty_ref)["ordered_subtree_matches"]

    wrong_length = [[0, hash_raw(keys)], [1, hash_raw(bytes(8) + b"\x02" + bytes(7) + names[16:])], [2, hash_raw(count)]]
    wrong_name_ref = raw_reference("codepoint-count.json", wrong_length)
    result = compare(kit, helper, height, *named, *wrong_name_ref)
    assert not result["ordered_subtree_matches"]
    assert result["streams"] == {"address_bytes": True, "length_prefixed_utf8": False, "entry_count": True}
    reversed_rows = checkpoint("reversed.rmp", rows[::-1])
    result = compare(kit, helper, height, *reversed_rows, *exact)
    assert result["streams"] == {"address_bytes": False, "length_prefixed_utf8": False, "entry_count": True}

    dup = checkpoint("duplicate.rmp", [[addr_a, "a"], [addr_a, "b"]])
    stale = raw_reference("stale.json", branch, wrong_digest=True)
    for source, ref, reason in ((dup, exact, "duplicate display-name Address"),
                                (named, stale, "stated raw ABCI digest")):
        try:
            compare(kit, helper, height, *source, *ref)
        except ValueError as error:
            assert reason in str(error), error
        else:
            raise AssertionError(reason)
    cmd = [sys.executable, "-B", Path(__file__).with_name("compare_display_names.py"), folder, helper,
           str(height), *reversed_rows, *exact]
    run = subprocess.run(cmd, check=False, capture_output=True)
    assert run.returncode == 1 and json.loads(run.stdout) == result
    print(f"PASS: msgpack {msgpack.__version__}; empty and populated native pair shapes match")
    print("PASS: UTF-8 byte length, stored row order and separate count; duplicate Address and stale digest rejected")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--helpers", required=True, type=Path)
    parser.add_argument("--rustc", required=True, type=Path)
    args = parser.parse_args()
    native()
    with TemporaryDirectory() as temp:
        controls(args.helpers, args.rustc, Path(temp))
