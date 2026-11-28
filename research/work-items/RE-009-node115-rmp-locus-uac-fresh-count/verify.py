"""Check fresh named uac count initialization and offline raw reference agreement."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
from types import ModuleType

from derive_uac_count import derive, load_uac, MAX_RESERVED_ROWS

sys.path.insert(0, str(Path.cwd() / "tools"))
from elf_index import unwind_index
from fde_extents import eh_frame_records
from freeze_snapshot_115 import read_va, rip_target

TARGET = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
UAC_VERIFIER_SHA = "e32abee3f144a88b390796bde7d7fef6a14eeb79da504b8b316fdc0b0e133b21"


def native():
    data = Path("artifacts/node/115/hl-node").read_bytes()
    assert hashlib.sha256(data).hexdigest() == TARGET
    sections, header = unwind_index(data)
    _, frames = eh_frame_records(data, sections)
    indexed = {(row["start"], row["fde"]) for row in header}
    extents = [(row["start"], row["end"]) for row in frames
               if (row["start"], row["fde"]) in indexed]

    def exact(va, raw):
        assert any(start <= va and va + len(raw) <= end for start, end in extents), hex(va)
        assert read_va(data, va, len(raw)) == raw, hex(va)

    for va, raw in {
        0x332CAA2: "488dbc24700c00004c89fe31d2",
        0x3292B21: "48898424980000004c898c24a0000000",
        0x47027C4: "4c8b364c8b7e084c89f84c29f0",
        0x47027D1: "483d49120000bb49120000480f42d8",
        0x4702827: "4c69ebe8000000",
        0x4702848: "0f108c24b00000000f114c2450",
        0x4702864: "48c744243800000000",
        0x47028B4: "48c744243800000000",
        0x47028D0: "0f11442450",
        0x3EE624D: "48c7471800000000",
        0x470298C: "488d742428",
        0x4715501: "4989f6",
        0x471565F: "4c89f6",
        0x3ECB5DC: "488b7e30",
        0x3ECB5EA: "48ffc748897e30",
        0x3ECB5FC: "4c8b7e104c3b3e",
        0x3ECB71A: "4989f4",
        0x3ECB749: "49ffc74d897c2410",
        0x3ECB75E: "41c7461000000000",
        0x47029A9: "83bc24b000000000",
        0x47029CB: "48b963617465206b6579",
        0x47029D9: "48b96475706c69636174",
        0x4702A41: "0f104c2438",
        0x4702A4B: "0f105c24580f115b30",
        0x4702A58: "0f114b10",
    }.items():
        exact(va, bytes.fromhex(raw))
    for va, prefix, target in (
        (0x332CAAF, "e8", 0x3292600), (0x3292B48, "e8", 0x47027B0),
        (0x4702822, "e8", 0x3EE6130), (0x47028C9, "0f1005", 0x648F9D8),
        (0x47028F3, "0f84", 0x4702A2E), (0x47028FC, "0f84", 0x4702A2E),
        (0x4702912, "e8", 0x3808B10), (0x4702942, "0f84", 0x4702A64),
        (0x470299E, "e8", 0x47154F0), (0x4715665, "e8", 0x3ECB420),
        (0x47029B1, "0f84", 0x47028F0), (0x3ECB513, "e9", 0x3ECB6A0),
    ):
        op = bytes.fromhex(prefix)
        assert rip_target(data, va, op, len(op) + 4) == target, hex(va)
    assert read_va(data, 0x648F9D8, 16) == bytes(16)
    print(f"PASS: node #115 SHA-256 {TARGET}")
    print("PASS: fresh selected named reader initializes both count qwords and increments each on accepted row")
    print("PASS: selected success copies both count qwords; duplicate status does not return a fresh state")


def build_driver(folder, rustc, tmp):
    path = folder / "RE-009-node115-rmp-locus-uac-root/verify.py"
    source = path.read_bytes()
    assert hashlib.sha256(source).hexdigest() == UAC_VERIFIER_SHA
    sys.path.insert(0, str(path.parent))
    try:
        verifier = ModuleType("node115_uac_verifier")
        exec(compile(source, str(path), "exec"), verifier.__dict__)
        return verifier.driver(folder, rustc, tmp)
    finally:
        sys.path.pop(0)


def fixtures(folder, rustc, tmp):
    import msgpack

    uac = load_uac(folder)
    activity, kit = uac.load_helpers(folder)
    helper = build_driver(folder, rustc, tmp)
    tree = kit["tree"]
    height = 903
    addr = bytes.fromhex("af" * 20)
    rows = [["0x" + addr.hex(), {"p": 3}]]

    def save(name, data):
        path = tmp / name
        path.write_bytes(data)
        return path, hashlib.sha256(data).hexdigest()

    def checkpoint(name, items):
        data = msgpack.packb({"exchange": {"locus": {"ctx": {"height": height}, "uac": items}}})
        return save(name, data)

    def leaf(data):
        return subprocess.check_output([helper], input=data).decode().strip()

    def word(value):
        return leaf(value.to_bytes(8, "little"))

    def reference(name, uac_tree):
        nodes = [[0, [[0, [[2, word(height)]]], [11, uac_tree]]]]
        record = {"height": height, "abci_digest": tree.digest(helper, tree.decode_tree(nodes)),
                  "exchange_abci_hash": nodes}
        return save(name, json.dumps(record).encode())

    def cli(case, checkpoint_height=height):
        return subprocess.run([sys.executable, "-B", Path(__file__).with_name("derive_uac_count.py"),
                               folder, str(checkpoint_height), *case], capture_output=True, check=False)

    single = checkpoint("single.rmp", rows)
    result = cli(single)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == derive(uac, activity, kit, height, *single) == {
        "height": height, "checkpoint_sha256": single[1], "uac_compact_count": 1}
    witness = save("single-count.json", result.stdout)
    zero = leaf(bytes(8))
    clocks = [[0, zero], [1, leaf(bytes(12))]]
    five = [[i, zero] for i in range(5)]
    selected = [[0, leaf(addr)], [1, [[0, word(3)], [1, zero], [2, zero], [3, zero],
                                    [4, five], [5, five], [6, five], [7, clocks], [8, clocks]]], [2, word(1)]]
    assert uac.compare(activity, kit, helper, height, *single, *reference("match.json", selected),
                       *witness)["ordered_uac_matches"]
    different = uac.compare(activity, kit, helper, height, *single,
                            *reference("different.json", [*selected[:2], [2, word(2)]]), *witness)
    assert different["ordered_values_match"] and not different["compact_count_matches"]

    empty = checkpoint("empty.rmp", [])
    result = cli(empty)
    assert result.returncode == 0 and json.loads(result.stdout)["uac_compact_count"] == 0
    assert uac.compare(activity, kit, helper, height, *empty, *reference("empty.json", [[2, word(0)]]),
                       *save("empty-count.json", result.stdout))["ordered_uac_matches"]

    limit_rows = [[list(row.to_bytes(20, "big")), {}] for row in range(MAX_RESERVED_ROWS + 1)]
    exact = checkpoint("exact-limit.rmp", limit_rows[:-1])
    assert derive(uac, activity, kit, height, *exact)["uac_compact_count"] == MAX_RESERVED_ROWS
    for case, selected_height, expected in (
        (checkpoint("duplicate.rmp", [*rows, [list(addr), {}]]), height, "duplicate uac Address"),
        (single, height + 1, "checkpoint Context height mismatch"),
        ((single[0], "0" * 64), height, "checkpoint SHA-256 mismatch"),
        (checkpoint("above-limit.rmp", limit_rows), height, "fresh reservation scope"),
    ):
        result = cli(case, selected_height)
        assert result.returncode == 2 and not result.stdout and expected.encode() in result.stderr, result
    print(f"PASS: msgpack {msgpack.__version__}; fresh zero and one differ correctly in the raw uac comparison")
    print("PASS: reservation boundary, duplicate Address, wrong checkpoint height and wrong byte pin")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--helpers", required=True, type=Path)
    parser.add_argument("--rustc", required=True, type=Path)
    args = parser.parse_args()
    native()
    with TemporaryDirectory() as directory:
        fixtures(args.helpers, args.rustc, Path(directory))
