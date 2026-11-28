"""Verify native quantity wrappers and execute full subtree checks on offline fixtures."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory

from compare_quantities import AMOUNT, BALANCE, SLOTS, compare, load_helpers

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
    slots = bind(data)["slots"]
    for name, (field, method) in {AMOUNT: (0x10F8, 0x4D3F3A0), "pvs": (0x4240, 0x35C31A0),
                                 BALANCE: (0x4268, 0x43C6A50)}.items():
        row = slots[SLOTS[name]]
        assert (int(row["box_field"], 16), int(row["method_0"], 16)) == (field, method)

    sections, header = unwind_index(data)
    _, frames = eh_frame_records(data, sections)
    indexed = {(row["start"], row["fde"]) for row in header}
    extents = [(row["start"], row["end"]) for row in frames
               if (row["start"], row["fde"]) in indexed]
    no_stack = {0x4D3F7F0, 0x430B920, 0x41D6980}
    for va, encoding in {
        0x54811AE: "498b97f8100000", 0x54811B5: "498b8f00110000", 0x54811D4: "498d9740420000",
        0x54814B7: "4d8b8768420000", 0x56774ED: "ba1e000000", 0x5677509: "4983ff01",
        0x5677555: "c60430c0", 0x5B06674: "498b17", 0x5B066B0: "498b5708",
        0x4D3F3B3: "833f01", 0x4D3F3D8: "4883c708", 0x4D3F46D: "4c397818",
        0x5106AF7: "4983c618", 0x35C31B8: "4883c708", 0x43C6A68: "4883c708",
        0x4D3F7F0: "31c0483b060f90c0c0e002c3", 0x430B920: "31c0483b060f90c0c0e002c3",
        0x41D6980: "31c0483b060f90c0c0e002c3", 0x141A14A: "48c7431000000000",
        0x141A2BF: "4d85ed7414", 0x14199DC: "48890c02",
    }.items():
        raw = bytes.fromhex(encoding)
        if va not in no_stack:
            assert any(start <= va and va + len(raw) <= end for start, end in extents), hex(va)
        assert read_va(data, va, len(raw)) == raw, hex(va)
    for va, prefix, target in (
        (0x56774E6, b"\x48\x8d\x05", AMOUNT.encode()), (0x5673F41, b"\x48\x8d\x35", b"pvs"),
        (0x54814BE, b"\x48\x8d\x15", BALANCE.encode()), (0x5B0665A, b"\x48\x8d\x35", b"mptc"),
        (0x5B06696, b"\x48\x8d\x35", b"ptc"), (0x4D3F448, b"\x48\x8d\x3d", b"\x01" + bytes(7)),
        (0x4D3F496, b"\x48\x8d\x3d", bytes(8)),
    ):
        assert read_va(data, rip_target(data, va, prefix, 7), len(target)) == target
    for va, target in {
        0x54811C2: 0x56774C0, 0x54811E1: 0x5673F30, 0x54814D0: 0x56745D0,
        0x5677517: 0x57D00B0, 0x5B0667F: 0x57D00B0, 0x5B066BC: 0x57D00B0,
        0x5674613: 0x57D00B0, 0x4D3F40F: 0x5106A90,
        0x5106B08: 0x57BA3E0, 0x5106B25: 0x4D3F7F0,
        0x35C31F4: 0x41AE280, 0x46F54EB: 0x41AE280, 0x43C6AAB: 0x41AE280,
    }.items():
        assert rip_target(data, va, b"\xe8", 5) == target, hex(va)
    assert rip_target(data, 0x5673F6C, b"\xe9", 5) == 0x5B065E0
    assert rip_target(data, 0x57BA3E0, b"\xff\x25", 6) == 0x64DF4F8
    assert rip_target(data, 0x4D3F4A0, b"\xff\x15", 6) == 0x64DF538
    for va, descriptor in ((0x35C31AC, 0x6465368), (0x46F549C, 0x64828C8),
                           (0x46F54B1, 0x6484B28), (0x43C6A71, 0x6487B30)):
        assert rip_target(data, va, b"\x48\x8d\x0d", 7) == descriptor
    reloc = relative_relocations(data)
    for at, target in {
        0x6465380: 0x46F5490, 0x64828E0: 0x14199B0, 0x6484B40: 0x41D6980,
        0x6484B48: 0x41AD060, 0x6487B48: 0x430B920, 0x6487B50: 0x41AD060,
        0x64DF4F8: 0x141A020, 0x64DF530: 0x14199B0, 0x64DF538: 0x14199B0,
    }.items():
        assert reloc[at] == target, hex(at)
    print(f"PASS: node #115 SHA-256 {TARGET}")
    print("PASS: three named quantities bound to native option, paired wrappers and empty leaves")


def driver(folder, rustc, tmp):
    source = folder / "RE-009-node115-context-root-isolation/hash_tree.rs"
    raw = source.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == DRIVER_SHA
    fixed_source = tmp / source.name
    fixed_source.write_bytes(raw)
    library = tmp / "libnode115_abci_blake3.rlib"
    executable = tmp / "hash_tree"
    subprocess.run([rustc, "--edition=2024", "--crate-name", "node115_abci_blake3",
                    "--crate-type", "rlib", "src/node115-abci-blake3/src/lib.rs",
                    "-o", library], check=True)
    subprocess.run([rustc, "--edition=2024", fixed_source, "--extern",
                    f"node115_abci_blake3={library}", "-o", executable], check=True)
    return executable


def controls(folder, rustc, tmp):
    import msgpack

    kit = load_helpers(folder)
    helper = driver(folder, rustc, tmp)

    def leaf(raw):
        return subprocess.check_output([helper], input=raw).decode().strip()

    def word(value):
        return leaf(value.to_bytes(8, "little"))

    empty = "0xaf1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
    assert leaf(b"") == empty

    def quantity(value):
        return [[0, word(value)], [1, empty]]

    max_word = (1 << 64) - 1
    h = 882
    named = {AMOUNT: 0, "pvs": {"ptc": max_word, "mptc": 303}, BALANCE: 17_003}

    def save(name, raw):
        path = tmp / name
        path.write_bytes(raw)
        return path, hashlib.sha256(raw).hexdigest()

    def checkpoint(name, fields, height=h):
        return save(name, msgpack.packb({"exchange": {"locus": {"ctx": {"height": height}}, **fields}}))

    present = [[0, quantity(0)], [1, word(1)]]
    absent = [[1, word(0)]]
    pvs = [[0, quantity(303)], [1, quantity(max_word)]]

    def reference(name, amount=present, pair=pvs, balance=None, wrong_digest=False):
        tree = kit["tree"]
        entries = [[0, [[4, word(30)]]], [26, amount], [27, pair],
                   [47, quantity(17_003) if balance is None else balance]]
        digest = word(0) if wrong_digest else tree.digest(helper, tree.decode_tree(entries))
        return save(name, json.dumps({"height": h, "abci_digest": digest,
                                      "exchange_abci_hash": entries}).encode())

    explicit_zero = checkpoint("named.rmp", named)
    good = reference("good.json")
    assert compare(kit, helper, h, *explicit_zero, *good)["all_quantity_subtrees_match"]
    nil = checkpoint("nil.rmp", named | {AMOUNT: None})
    assert compare(kit, helper, h, *nil, *reference("nil.json", amount=absent))["all_quantity_subtrees_match"]

    bad = reference("wrong.json", amount=absent, pair=pvs[::-1], balance=[[0, word(17_003)], [1, word(0)]])
    result = compare(kit, helper, h, *explicit_zero, *bad)
    assert not result["all_quantity_subtrees_match"] and all(not row["matches"] for row in result["fields"].values())

    missing = checkpoint("missing.rmp", named | {"pvs": {"mptc": 303}})
    wrong_height = checkpoint("later.rmp", named, h + 1)
    stale = reference("stale.json", wrong_digest=True)
    for source, ref, reason in ((missing, good, "pvs.ptc"), (wrong_height, good, "Context height"),
                                (explicit_zero, stale, "stated raw ABCI digest")):
        try:
            compare(kit, helper, h, *source, *ref)
        except ValueError as error:
            assert reason in str(error), error
        else:
            raise AssertionError(reason)
    command = [sys.executable, "-B", Path(__file__).with_name("compare_quantities.py"), folder, helper,
               str(h), *explicit_zero, *bad]
    cli = subprocess.run(command, check=False, capture_output=True)
    assert cli.returncode == 1 and json.loads(cli.stdout) == result
    print(f"PASS: msgpack {msgpack.__version__}; complete matching HLP, pvs and initial USDC subtrees")
    print("PASS: nil versus zero, order and phantom mismatch controls; input and stale digest rejection")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--helpers", required=True, type=Path)
    parser.add_argument("--rustc", required=True, type=Path)
    args = parser.parse_args()
    native()
    with TemporaryDirectory() as tmp:
        controls(args.helpers, args.rustc, Path(tmp))
