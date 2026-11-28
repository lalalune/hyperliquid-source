"""Localize named Clearinghouse raw slots and verify the count and ordered boolean stream."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
from types import ModuleType

from compare_cls import compare, load_scalars

sys.path.insert(0, str(Path.cwd() / "tools"))
from clearinghouse_fields_115 import bind
from elf_index import unwind_index
from fde_extents import eh_frame_records
from freeze_snapshot_115 import read_va, relative_relocations, rip_target

TARGET = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
DRIVER_SHA = "6791575648e65e8ef4fe42536b7327f85c57327cb2423255b598fb2b1d83828f"


def native(folder):
    data = Path("artifacts/node/115/hl-node").read_bytes()
    assert hashlib.sha256(data).hexdigest() == TARGET
    path = folder / "RE-009-node115-locus-context-root-captures/verify.py"
    source = path.read_bytes()
    assert hashlib.sha256(source).hexdigest() == "19cc80a8e20a68b6ad9e471b2d92ea61dec0c2451a0b2414563e1808faabf993"
    capture = ModuleType("cls_locus_capture")
    capture.__file__ = str(path)
    exec(compile(source, str(path), "exec"), capture.__dict__)
    root_parts = {row[1]: row for row in capture.first_fields(data)}
    assert root_parts["cls"] == ("0.1", "cls", "0x7c0", "0x64793a8", "0x43cfeb0", "0x43cfe60")
    assert root_parts["height"] == ("0.0.2", "height", "0x28", "0x64828c8", "0x14199b0", "0x14196d0")

    sections, header = unwind_index(data)
    _, frames = eh_frame_records(data, sections)
    indexed = {(row["start"], row["fde"]) for row in header}
    extents = [(row["start"], row["end"]) for row in frames
               if (row["start"], row["fde"]) in indexed]

    def exact(va, raw):
        assert any(start <= va and va + len(raw) <= end for start, end in extents), hex(va)
        assert read_va(data, va, len(raw)) == raw, hex(va)

    for va, raw in {
        0x3D676A1: "488b5f10", 0x3D676E2: "4d8b6e08", 0x3D676EB: "4869eb10050000",
        0x3D67715: "4c896c18f84c893418", 0x3D67726: "4981c5100500004883c310",
        0x3D6775C: "48c744240800000000", 0x3D6777C: "4531ff",
        0x3D6777F: "48895c2430", 0x3D6779F: "4c897c2450",
        0x3D677AE: "48c744246001000000",
        0x41AE2A9: "48837f1002", 0x41AE2D0: "498d6e18",
        0x41AE2E4: "4c89e74c89f641ff5518", 0x41AE36A: "4889eeff5318",
        0x43D1034: "bfc8010000", 0x4504482: "48837e1013",
        0x45046E7: "4c89f6ff5318", 0x4504735: "4881f9c8010000",
        0x4504743: "4c8d34084883c118", 0x14199DC: "48890c02",
        0x1419D45: "0fb60f", 0x1419D6B: "880c02",
        0x464985D: "0fb62b", 0x464988C: "40f6c501", 0x46498A6: "c7043074727565",
    }.items():
        exact(va, bytes.fromhex(raw))
    for va, prefix, target in (
        (0x43CFEB0, "e9", 0x3D67690), (0x3D67701, "4c8d35", 0x647A010),
        (0x3D6778E, "488d0d", 0x6479F20), (0x3D677BF, "e8", 0x41AE280),
        (0x3D1CA35, "e8", 0x41AD070), (0x4482399, "e8", 0x4649840),
    ):
        op = bytes.fromhex(prefix)
        assert rip_target(data, va, op, len(op) + 4) == target, hex(va)

    reloc = relative_relocations(data)
    for loc, target in {0x647A028: 0x4504270, 0x647A030: 0x43D1030,
                        0x6479F38: 0x14199B0}.items():
        assert reloc[loc] == target
    known = bind(data)
    # (source offset, source instruction, result descriptor)
    fields = (
        (0, 0x4504281, 0x648DEE8), (0x60, 0x4504292, 0x648DF10),
        (0x148, 0x45042A7, 0x648DF38), (0x4A8, 0x45042BF, 0x648CDE0),
        (0x4B0, 0x45042D7, 0x648CD90), (0x508, 0x45042F2, 0x64884F8),
        (0x4B8, 0x4504310, 0x648CD90), (0x4C0, 0x4504327, 0x648CB10),
        (0x2F8, 0x4504345, 0x648DF60), (0x4C8, 0x4504363, 0x648CC78),
        (0x318, 0x4504381, 0x648DF88), (0x509, 0x450439F, 0x648DFB0),
        (0x4F0, 0x45043BD, 0x648C850), (0x4FC, 0x45043DB, 0x648C850),
        (0x4E0, 0x45043F2, 0x648DFD8), (0x338, 0x4504410, 0x648DF88),
        (0x358, 0x4504427, 0x648DF88), (0x378, 0x450443E, 0x648E000),
        (0x4E8, 0x450445C, 0x648CD90),
    )
    metadata = ((0, 0x3D1C95A, 0x6478288), (0x50, 0x3D1C96B, 0x6473FD0),
                (0x30, 0x3D1C980, 0x64782B0), (0x58, 0x3D1C995, 0x6474020),
                (0x18, 0x3D1C9AA, 0x6477DE0))

    def recover_streams(slots, named, prefix, start):
        out = []
        by_offset = {int(row["offset"], 16): row["name"] for row in named}
        assert len(by_offset) == len(slots)
        for index, (offset, va, desc) in enumerate(slots):
            op = read_va(data, va, 3)
            if offset == 0:
                assert op == b"\x48\x89\x7c"
                store_at = va
            elif op in (b"\x48\x83\xc7", b"\x48\x8d\x47", b"\x48\x8d\x4f"):
                assert read_va(data, va + 3, 1)[0] == offset
                store_at = va + 4
            else:
                assert op in (b"\x48\x8d\x87", b"\x48\x8d\x8f", b"\x48\x8d\x97",
                              b"\x4c\x8d\x87", b"\x48\x81\xc7")
                assert int.from_bytes(read_va(data, va + 3, 4), "little") == offset
                store_at = va + 7
            store = read_va(data, store_at, 8)
            assert store[0] in (0x48, 0x4C) and store[1] == 0x89 and store[3] == 0x24
            assert store[2] & 0xC0 in (0x40, 0x80)
            size = 1 if store[2] & 0xC0 == 0x40 else 4
            destination = int.from_bytes(store[4:4 + size], "little")
            assert destination == start + index * 16
            next_at = store_at + 4 + size
            next_op = read_va(data, next_at, 3)
            if next_op[1] == 0x8D:
                assert rip_target(data, next_at, next_op, 7) == desc
                desc_store = next_at + 7
            else:
                # Repeated descriptors stay resident in these registers.
                assert (va, next_op, desc) in reused
                desc_store = next_at
            store = read_va(data, desc_store, 8)
            assert store[1] == 0x89 and store[3] == 0x24
            size = 1 if store[2] & 0xC0 == 0x40 else 4
            assert int.from_bytes(store[4:4 + size], "little") == destination + 8
            out.append(f"{prefix}.{index}\t{by_offset[offset]}\t{offset:#x}\t{desc:#x}\t{reloc[desc+24]:#x}")
        return out

    reused = {(0x4504310, b"\x48\x89\x84", 0x648CD90),
              (0x45043DB, b"\x48\x89\x94", 0x648C850),
              (0x4504410, b"\x48\x89\x8c", 0x648DF88),
              (0x4504427, b"\x48\x89\x8c", 0x648DF88),
              (0x450445C, b"\x48\x89\x84", 0x648CD90)}
    rows = ["path\tname\toffset\tdescriptor\tvisitor",
            "0.1.1\tcls.count\t0x10\t0x6479f20\t0x14199b0"]
    rows += recover_streams(fields, known["clearinghouse"]["fields"], "0.1.0", 0x38)
    rows += recover_streams(metadata, known["perp_meta"]["fields"], "0.1.0.0", 8)
    assert reloc[0x64884F8 + 24] == 0x1419D40 and reloc[0x648DEE8 + 24] == 0x3D1C950
    print(f"PASS: node #115 SHA-256 {TARGET}")
    print("PASS: ordered row pointer stride, shared Clearinghouse subtree, independent count")
    print("PASS: authenticated named offsets mapped into 19 Clearinghouse and five PerpMeta slots")
    return "\n".join(rows) + "\n"


def driver(folder, rustc, tmp):
    source = folder / "RE-009-node115-context-root-isolation/hash_tree.rs"
    data = source.read_bytes()
    assert hashlib.sha256(data).hexdigest() == DRIVER_SHA
    staged = tmp / source.name
    staged.write_bytes(data)
    library = tmp / "libnode115_abci_blake3.rlib"
    binary = tmp / "hash_tree"
    subprocess.run([rustc, "--edition=2024", "--crate-name", "node115_abci_blake3", "--crate-type",
                    "rlib", "src/node115-abci-blake3/src/lib.rs", "-o", library], check=True)
    subprocess.run([rustc, "--edition=2024", staged, "--extern",
                    f"node115_abci_blake3={library}", "-o", binary], check=True)
    return binary


def fixtures(folder, rustc, tmp):
    import msgpack
    scalars = load_scalars(folder)
    kit = scalars.load_helpers(folder)
    tree = kit["tree"]
    helper = driver(folder, rustc, tmp)
    height = 904

    def save(name, data):
        file = tmp / name
        file.write_bytes(data)
        return file, hashlib.sha256(data).hexdigest()

    def leaf(data):
        return subprocess.check_output([helper], input=data).decode().strip()

    def word(value):
        return leaf(value.to_bytes(8, "little"))

    def case(name, flags):
        rows = [{"perform_auto_deleveraging": flag} for flag in flags]
        return save(name, msgpack.packb({"exchange": {"locus": {"ctx": {"height": height}, "cls": rows}}}))

    def ref(name, children, inner=height):
        nodes = [[0, [[0, [[2, word(inner)]]], [1, children]]]]
        record = {"height": height, "abci_digest": tree.digest(helper, tree.decode_tree(nodes)),
                  "exchange_abci_hash": nodes}
        return save(name, json.dumps(record).encode())

    def run(source, reference):
        return compare(scalars, kit, helper, height, *source, *reference)

    source = case("named.rmp", [False, True])
    flat = [[i, leaf(bytes([i]))] for i in range(19)]
    flat[0][1] = [[i, word(i)] for i in range(5)]
    flat[5][1] = leaf(b"\x00\x01")
    match = ref("match.json", [[0, flat], [1, word(2)]])
    result = run(source, match)
    assert all(v for k, v in result.items() if k.endswith("_matches"))
    changed_order = ref("flags.json", [[0, [*flat[:5], [5, leaf(b"\x01\x00")], *flat[6:]]], [1, word(2)]])
    result = run(source, changed_order)
    assert result["ordered_count_matches"] and result["field_stream_layout_matches"]
    assert not result["perform_auto_deleveraging_stream_matches"]
    result = run(source, ref("count.json", [[0, flat], [1, word(1)]]))
    assert result["perform_auto_deleveraging_stream_matches"] and not result["ordered_count_matches"]
    result = run(source, ref("short.json", [[0, flat[:-1]], [1, word(2)]]))
    assert not result["field_stream_layout_matches"]
    result = run(case("empty.rmp", []), ref("empty.json", [[1, word(0)]]))
    assert all(v for k, v in result.items() if k.endswith("_matches"))

    for bad_source, bad_ref, reason in (
        (case("not-bool.rmp", [1]), match, "expected a boolean"),
        (source, ref("wrong-height.json", [[0, flat], [1, word(2)]], height + 1), "inner Context height"),
    ):
        try:
            run(bad_source, bad_ref)
        except ValueError as error:
            assert reason in str(error), error
        else:
            raise AssertionError(reason)
    cmd = [sys.executable, "-B", Path(__file__).with_name("compare_cls.py"), folder, helper,
           str(height), *source, *changed_order]
    cli = subprocess.run(cmd, check=False, capture_output=True)
    assert cli.returncode == 1 and json.loads(cli.stdout) == run(source, changed_order)
    print(f"PASS: msgpack {msgpack.__version__}; empty and ordered two-row cls fixtures")
    print("PASS: distinguish reordered boolean stream, wrong count, missing field slot and wrong inner height")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--helpers", required=True, type=Path)
    parser.add_argument("--rustc", required=True, type=Path)
    parser.add_argument("--write-layout", action="store_true")
    args = parser.parse_args()
    layout = native(args.helpers)
    table = Path(__file__).with_name("root-layout.tsv")
    if args.write_layout:
        table.write_text(layout)
    else:
        assert table.read_text() == layout
    with TemporaryDirectory() as directory:
        fixtures(args.helpers, args.rustc, Path(directory))
