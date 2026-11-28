"""Check native Context captures and build an offline leaf projector."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import sys

from compare import compare

sys.path.insert(0, str(Path.cwd() / "tools"))
from elf_index import unwind_index
from fde_extents import eh_frame_records
from freeze_snapshot_115 import read_va, relative_relocations, rip_target

SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
PACKET = Path(__file__).resolve().parent
RUST_LIBRARY = Path("src/node115-abci-blake3/src/lib.rs")


def verify_elf():
    data = Path("artifacts/node/115/hl-node").read_bytes()
    assert hashlib.sha256(data).hexdigest() == SHA
    sections, header = unwind_index(data)
    _, frames = eh_frame_records(data, sections)
    indexed = {(row["start"], row["fde"]) for row in header}
    bounds = {(row["start"], row["end"]) for row in frames if (row["start"], row["fde"]) in indexed}
    assert {(0x4306E30, 0x4306E95), (0x45146F0, 0x4514766), (0x41AE280, 0x41AE3DB),
            (0x4305CF0, 0x4305D3D), (0x45127D0, 0x451281D)} <= bounds
    relocations = relative_relocations(data)
    for address, expected in {
        0x6484738: 0x4306E30, 0x64827A0: 0x45146F0,
        0x6484740: 0x4305CF0, 0x64827A8: 0x45127D0,
        0x64828E0: 0x14199B0, 0x6484760: 0x457D610, 0x64DF530: 0x14199B0,
        0x648E208: 0x14199B0, 0x648E5D8: 0x459280, 0x648E5E8: 0x459348,
        0x648E5E0: 0x648E1F0, 0x648E5F0: 0x648E1F0,
    }.items():
        assert relocations[address] == expected, hex(address)
    for address, prefix, target in (
        (0x430380E, b"\x48\x8d\x0d", 0x6482788),
        (0x43037EF, b"\x48\x8d\x0d", 0x6484720),
        (0x4306E3C, b"\x48\x8d\x0d", 0x64828C8),
        (0x4306E51, b"\x48\x8d\x0d", 0x6484748),
        (0x4514705, b"\x48\x8d\x0d", 0x648E1F0),
        (0x4514724, b"\x48\x8d\x0d", 0x648E5D8),
        (0x451473F, b"\x48\x8d\x0d", 0x648E5E8),
        (0x4306E8B, b"\xe8", 0x41AE280),
        (0x451475C, b"\xe8", 0x41AE280),
        (0x457D610, b"\xff\x25", 0x64DF530),
    ):
        assert rip_target(data, address, prefix, len(prefix) + 4) == target, hex(address)
    for address, raw in {
        0x43037E6: "488d4f18", 0x4303809: "48897c2468",
        0x4306E37: "48897c2408", 0x4306E48: "4883c708",
        0x4306E67: "48c744243001000000", 0x4306E7A: "48c744244001000000",
        0x45146F7: "833f01", 0x45146FC: "4883c708",
        0x451471B: "48c744241001000000", 0x4514736: "48c744241000000000",
        0x41AE2A9: "48837f1002", 0x41AE2D0: "498d6e18",
        0x41AE2FA: "4885db", 0x41AE2FD: "743e",
        0x4305CF4: "bf30000000", 0x4305D11: "48894818",
        0x45127D4: "bf30000000", 0x45127F1: "48894818",
        0x14199B5: "488b0f", 0x14199DC: "48890c02", 0x14199E0: "4883c008",
    }.items():
        expected = bytes.fromhex(raw)
        assert read_va(data, address, len(expected)) == expected, hex(address)
    assert read_va(data, 0x459348, 8) == (0).to_bytes(8, "little")
    assert read_va(data, 0x459280, 8) == (1).to_bytes(8, "little")
    print(f"PASS: node #115 SHA-256 {SHA}")
    print("PASS: native hardfork pair, optional tx index branches, descriptors, and qword leaf writes")


def build(rustc, directory):
    library = directory / "libnode115_abci_blake3.rlib"
    projector = directory / "project"
    subprocess.run([rustc, "--edition=2024", "--crate-name", "node115_abci_blake3", "--crate-type",
                    "rlib", RUST_LIBRARY, "-o", library], check=True)
    subprocess.run([rustc, "--edition=2024", PACKET / "project.rs", "--extern",
                    f"node115_abci_blake3={library}", "-o", projector], check=True)
    vectors = directory / "blake3_vectors"
    subprocess.run([rustc, "--edition=2024", "--test",
                    Path("src/node115-abci-blake3/tests/blake3_vectors.rs"), "--extern",
                    f"node115_abci_blake3={library}", "-o", vectors], check=True)
    subprocess.run([vectors], check=True)
    return projector


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--rustc", default="rustc")
    args = parser.parse_args()
    verify_elf()
    subprocess.run([args.rustc, "--version"], check=True)
    with tempfile.TemporaryDirectory() as directory:
        projector = build(args.rustc, Path(directory))

        def run(*values):
            return json.loads(subprocess.check_output([projector, *values], text=True))

        first = run("66051", "7", "none")
        swapped = run("7", "66051", "none")
        present_zero = run("66051", "7", "0")
        assert first["hardfork"][0][1] == swapped["hardfork"][1][1]
        assert first["hardfork"][1][1] == swapped["hardfork"][0][1]
        assert first["hardfork"][0][1] != first["hardfork"][1][1]
        assert [row[0] for row in first["tx_index"]] == [1]
        assert [row[0] for row in present_zero["tx_index"]] == [0, 1]
        assert first["tx_index"][0][1] == present_zero["tx_index"][0][1]
        assert first["tx_index"][0][1] != present_zero["tx_index"][1][1]
        row = {"height": 30, "abci_digest": "0x" + "ab" * 32,
               "exchange_abci_hash": [[0, [[0, [[1, first["hardfork"]], [3, first["tx_index"]]]]]]]}
        assert compare(first, row, 30) == {"height": 30, "hardfork": True, "tx_index": True}
        assert compare(swapped, row, 30) == {"height": 30, "hardfork": False, "tx_index": True}
        assert compare(present_zero, row, 30) == {"height": 30, "hardfork": True, "tx_index": False}
        line = Path(directory) / "selected.jsonl"
        data = (json.dumps(row) + "\n").encode()
        line.write_bytes(data)
        complete = subprocess.run(
            [sys.executable, "-B", PACKET / "compare.py", projector, line,
             hashlib.sha256(data).hexdigest(), "30", "66051", "7", "none"],
            check=True, capture_output=True, text=True,
        )
        assert json.loads(complete.stdout) == {"height": 30, "hardfork": True, "tx_index": True}
        row["exchange_abci_hash"][0][1][0][1][1][1][0][0] = True
        try:
            compare(first, row, 30)
        except ValueError as error:
            assert "invalid or repeated child index" in str(error)
        else:
            raise AssertionError("accepted boolean index as ordinal 1")

    print("PASS: trusted Rust projection built offline; synthetic pair order and absent/present-zero controls")


if __name__ == "__main__":
    main()
