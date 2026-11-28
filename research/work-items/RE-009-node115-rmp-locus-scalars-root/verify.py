"""Verify ordinary named Locus scalars and exact inner raw Context height."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from types import ModuleType
from tempfile import TemporaryDirectory

from compare_locus_scalars import compare, load_helpers

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
    for name, expected in {
        "chn": ("0.5", "chn", "0xb9a", "0x6479448", "0x141b650", "0x141b640"),
        "pdl": ("0.6", "pdl", "0xb98", "0x6474380", "0x1419d40", "0x14193f0"),
        "hcm": ("0.13", "hcm", "0xb99", "0x6479538", "0x44ebe70", "0x44ebfc0"),
        "pmu": ("0.14", "pmu", "0xb90", "0x6473ff8", "0x14199b0", "0x14196d0"),
        "height": ("0.0.2", "height", "0x28", "0x64828c8", "0x14199b0", "0x14196d0"),
    }.items():
        assert by_name[name] == expected

    sections, header = unwind_index(data)
    _, frames = eh_frame_records(data, sections)
    indexed = {(row["start"], row["fde"]) for row in header}
    extents = [(row["start"], row["end"]) for row in frames
               if (row["start"], row["fde"]) in indexed]

    def verify_bytes(va, raw):
        assert any(start <= va and va + len(raw) <= end for start, end in extents), hex(va)
        assert read_va(data, va, len(raw)) == raw, hex(va)

    table = rip_target(data, 0x567642D, bytes.fromhex("488d0d"), 7)
    assert table == 0x928BDC
    for tag, (site, name) in enumerate(((0x567643D, b"Local"), (0x567647C, b"Sandbox"),
                                        (0x567646A, b"Testnet"), (0x5676473, b"Mainnet"))):
        entry = int.from_bytes(read_va(data, table + tag * 4, 4), "little", signed=True)
        assert table + entry == site
        assert read_va(data, rip_target(data, site, bytes.fromhex("488d35"), 7), len(name)) == name
    for site, name in ((0x5676521, b"disabled"), (0x56764F7, b"reduceOnly"), (0x5676568, b"enabled")):
        assert read_va(data, rip_target(data, site, bytes.fromhex("488d35"), 7), len(name)) == name

    for va, raw in {
        0x5676429: "400fb6c5", 0x5676434: "486304814801c8ffe0", 0x56764DF: "4084ed7433",
        0x56764F2: "83f8017571", 0x56783EA: "4080cdc2",
        0x141B655: "0fb60f", 0x141B67B: "880c0248ffc0",
        0x1419D45: "0fb60f", 0x1419D6B: "880c0248ffc0",
        0x44EBE75: "0fb60785c0745e", 0x44EBE85: "48c7042401000000", 0x44EBEDA: "48c7042400000000",
        0x44EBF28: "48c7042402000000", 0x44EBFC4: "bf18000000", 0x44EBFE1: "48c70301000000",
        0x44EBFEC: "48c7431001000000", 0x14199DC: "48890c024883c008",
    }.items():
        verify_bytes(va, bytes.fromhex(raw))
    for va, prefix, target in (
        (0x5480BDE, "e8", 0x56763F0), (0x5480C0A, "e8", 0x56783A0),
        (0x5480CF0, "e8", 0x56764B0), (0x5480D1B, "e8", 0x56736B0),
        (0x44EBF83, "ff15", 0x64DF538), (0x141B640, "ff25", 0x64DF4F8),
    ):
        op = bytes.fromhex(prefix)
        assert rip_target(data, va, op, len(op) + 4) == target, hex(va)
    reloc = relative_relocations(data)
    assert reloc[0x64DF538] == 0x14199B0 and reloc[0x64DF4F8] == 0x141A020
    print(f"PASS: node #115 SHA-256 {TARGET}")
    print("PASS: named chn and hcm enum tables, pdl byte, pmu qword and Locus raw child bindings")


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

    def checkpoint(name, fields):
        source = {"exchange": {"locus": {"ctx": {"height": height}, **fields}}}
        return save(name, msgpack.packb(source))

    def reference(name, selected, root_height=height, stale=False):
        slots = [[0, [[0, [[2, word(root_height)], [4, word(321)]]], *selected]], [38, leaf(b"unrelated")]]
        digest = leaf(b"stale") if stale else tree.digest(helper, tree.decode_tree(slots))
        return save(name, json.dumps({"height": height, "abci_digest": digest,
                                      "exchange_abci_hash": slots}).encode())

    pmu = (1 << 64) - 1
    for chain, chain_tag in (("Local", 0), ("Sandbox", 1), ("Testnet", 2), ("Mainnet", 3)):
        for mode, tag in (("disabled", 0), ("reduceOnly", 1), ("enabled", 2)):
            flag = (chain_tag + tag) % 2 == 1
            fields = {"pdl": flag, "pmu": pmu, "chn": chain, "hcm": mode}
            expected = [[5, leaf(bytes([chain_tag]))], [6, leaf(bytes([flag]))],
                        [13, [[0, word(tag)]]], [14, word(pmu)]]
            source = checkpoint("ordinary.rmp", fields)
            assert compare(kit, helper, height, *source,
                           *reference("ordinary.json", expected))["all_locus_scalars_match"]
    wrong = expected[:2] + [[13, word(2)], [14, word(pmu - 1)]]
    mismatch_ref = reference("mismatch.json", wrong)
    mismatch = compare(kit, helper, height, *source, *mismatch_ref)
    assert mismatch["fields"] == {"chn": True, "pdl": True, "hcm": False, "pmu": False}
    wrong_width = [[5, word(3)], *expected[1:]]
    width_result = compare(kit, helper, height, *source, *reference("wrong-width.json", wrong_width))
    assert width_result["fields"] == {"chn": False, "pdl": True, "hcm": True, "pmu": True}
    correct = reference("correct.json", expected)
    for candidate, ref, reason in (
        (checkpoint("invalid-pdl.rmp", fields | {"pdl": 1}), correct, "native Locus pdl boolean"),
        (checkpoint("invalid-chain.rmp", fields | {"chn": "mainnet"}), correct, "native named Locus chn"),
        (source, reference("wrong-inner-height.json", expected, root_height=height + 1), "inner Context height"),
        (source, reference("stale.json", expected, stale=True), "stated raw ABCI digest"),
    ):
        try:
            compare(kit, helper, height, *candidate, *ref)
        except ValueError as error:
            assert reason in str(error), error
        else:
            raise AssertionError(reason)
    cmd = [sys.executable, "-B", Path(__file__).with_name("compare_locus_scalars.py"), folder, helper,
           str(height), *source, *mismatch_ref]
    run = subprocess.run(cmd, check=False, capture_output=True)
    assert run.returncode == 1 and json.loads(run.stdout) == mismatch
    print(f"PASS: msgpack {msgpack.__version__}; 12 named enum combinations with both bool values")
    print("PASS: full raw rehash and actual inner H leaf verified; wrong width, branch and value distinguished")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--helpers", required=True, type=Path)
    parser.add_argument("--rustc", required=True, type=Path)
    args = parser.parse_args()
    native(args.helpers)
    with TemporaryDirectory() as directory:
        controls(args.helpers, args.rustc, Path(directory))
