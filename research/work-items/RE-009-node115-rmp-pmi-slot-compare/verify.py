"""Authenticate the native PMI writer and test checkpoint-to-root comparison offline."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory

from compare_pmi import compare, load_helpers

sys.path.insert(0, str(Path.cwd() / "tools"))
from abci_hash_slots_115 import bind
from elf_index import unwind_index
from fde_extents import eh_frame_records
from freeze_snapshot_115 import read_va, relative_relocations, rip_target

TARGET = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
HASH_HELPER_SHA = "6791575648e65e8ef4fe42536b7327f85c57327cb2423255b598fb2b1d83828f"


def native():
    data = Path("artifacts/node/115/hl-node").read_bytes()
    assert hashlib.sha256(data).hexdigest() == TARGET
    row = bind(data)["slots"][54]
    assert (int(row["box_field"], 16), int(row["vtable"], 16),
            row["type_size"], int(row["method_0"], 16)) == (0x42B0, 0x64A87C8, 21, 0x4D3F050)
    sections, header = unwind_index(data)
    _, extents = eh_frame_records(data, sections)
    indexed = {(row["start"], row["fde"]) for row in header}
    spans = [(row["start"], row["end"]) for row in extents
             if (row["start"], row["fde"]) in indexed]
    for va, encoding in {
        0x54815B5: "498d97b0420000", 0x5677FDE: "ba03000000",
        0x5677FFA: "41803e01", 0x5678000: "49ffc6", 0x567800A: "b907000000",
        0x567804B: "c60430c0", 0x52F7C40: "be2a000000", 0x52F7C45: "b914000000",
        0x52F7C4D: "4531c0", 0x2EABB62: "66c7073078",
        0x2EABB87: "7514", 0x2EABC29: "420fb6041a", 0x2EABC5A: "75c4",
        0x57CF883: "89d081fa00010000", 0x57CF88D: "b3d9",
        0x4D3F063: "803f01", 0x4D3F088: "48ffc7", 0x4D3F0CD: "4883c318",
        0x141B9E3: "8b771089740a100f10070f11040a",
    }.items():
        raw = bytes.fromhex(encoding)
        assert any(start <= va and va + len(raw) <= end for start, end in spans), hex(va)
        assert read_va(data, va, len(raw)) == raw, hex(va)
    for va, prefix, width, expected in (
        (0x54815C2, b"\xe8", 5, 0x5677FC0), (0x5678020, b"\xe9", 5, 0x52F7BF0),
        (0x52F7C50, b"\xff\x15", 6, 0x64E4D08), (0x52F7C5C, b"\xe8", 5, 0x57CF860),
    ):
        assert rip_target(data, va, prefix, width) == expected, hex(va)
    assert relative_relocations(data)[0x64E4D08] == 0x2EABB50
    for va, prefix, literal in (
        (0x5677FD7, b"\x48\x8d\x05", b"pmi"),
        (0x5678003, b"\x48\x8d\x15", b"Address"),
        (0x2EABBAA, b"\x4c\x8d\x15", b"0123456789abcdef"),
        (0x4D3F0F9, b"\x48\x8d\x3d", b"\x01" + bytes(7)),
        (0x4D3F147, b"\x48\x8d\x3d", bytes(8)),
    ):
        assert read_va(data, rip_target(data, va, prefix, 7), len(literal)) == literal
    print(f"PASS: node #115 SHA-256 {TARGET}")
    print("PASS: native named PMI nil and Address encoding; raw exchange slot 54 payload and tag")


def rust_helper(folder, rustc, directory):
    source = folder / "RE-009-node115-context-root-isolation/hash_tree.rs"
    data = source.read_bytes()
    assert hashlib.sha256(data).hexdigest() == HASH_HELPER_SHA
    saved_source = directory / source.name
    saved_source.write_bytes(data)
    library = directory / "libnode115_abci_blake3.rlib"
    executable = directory / "hash_tree"
    subprocess.run([rustc, "--edition=2024", "--crate-name", "node115_abci_blake3",
                    "--crate-type", "rlib", "src/node115-abci-blake3/src/lib.rs",
                    "-o", library], check=True)
    subprocess.run([rustc, "--edition=2024", saved_source, "--extern",
                    f"node115_abci_blake3={library}", "-o", executable], check=True)
    return executable


def controls(folder, rustc, temp):
    import msgpack

    helpers = load_helpers(folder)
    hash_ = rust_helper(folder, rustc, temp)

    def blake3(raw):
        return subprocess.check_output([hash_], input=raw).decode("ascii").strip()

    assert blake3(b"abc") == "0x6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85"
    height = 30

    def save(name, data):
        path = temp / name
        path.write_bytes(data)
        return path, hashlib.sha256(data).hexdigest()

    def checkpoint(name, field):
        packed = msgpack.packb({"exchange": {"locus": {"ctx": {"height": height}},
                                            "unrelated": [b"skip", [3, 9]], **field}},
                               use_bin_type=True)
        return save(name, packed)

    tag_0 = blake3(bytes(8))
    tag_1 = blake3(b"\x01" + bytes(7))
    address = "0x0123456789abcdef0123456789abcdef01234567"
    digest = blake3(bytes.fromhex(address[2:]))
    zero_digest = blake3(bytes(20))
    nil_branch = [[1, tag_0]]
    address_branch = [[0, digest], [1, tag_1]]
    zero_branch = [[0, zero_digest], [1, tag_1]]

    def reference(name, branch, declare=None):
        full = [[0, [[7, blake3(b"other state")]]], [54, branch]]
        declared = declare or helpers["tree"].digest(hash_, helpers["tree"].decode_tree(full))
        return save(name, json.dumps({"height": height, "abci_digest": declared,
                                      "exchange_abci_hash": full}).encode())

    source_nil = checkpoint("nil.rmp", {"pmi": None})
    source_address = checkpoint("address.rmp", {"pmi": address})
    source_zero = checkpoint("zero.rmp", {"pmi": "0x" + "00" * 20})
    ref_nil = reference("ref-nil.json", nil_branch)
    ref_address = reference("ref-address.json", address_branch)
    ref_zero = reference("ref-zero.json", zero_branch)
    for source, ref in ((source_nil, ref_nil), (source_address, ref_address), (source_zero, ref_zero)):
        assert compare(helpers, hash_, height, *source, *ref)["pmi_slot_matches"]
    detail = compare(helpers, hash_, height, *source_address, *ref_zero)
    assert detail["discriminant_leaf_matches"] and not detail["payload_leaf_matches"]
    assert not detail["pmi_slot_matches"]
    detail = compare(helpers, hash_, height, *source_nil, *ref_zero)
    assert not detail["discriminant_leaf_matches"] and not detail["ordered_child_slots_match"]
    reordered = reference("reordered.json", list(reversed(address_branch)))
    detail = compare(helpers, hash_, height, *source_address, *reordered)
    assert detail["payload_leaf_matches"] and detail["discriminant_leaf_matches"]
    assert not detail["ordered_child_slots_match"] and not detail["pmi_slot_matches"]
    omitted = checkpoint("omitted.rmp", {})
    invalid = checkpoint("invalid-address.rmp", {"pmi": bytes(20)})
    wrong_root = reference("wrong-root.json", address_branch, tag_0)
    for source, ref, needle in ((omitted, ref_nil, "omits"), (invalid, ref_zero, "writer-shaped"),
                                ((source_zero[0], "0" * 64), ref_zero, "SHA-256"),
                                (source_address, wrong_root, "declared raw")):
        try:
            compare(helpers, hash_, height, *source, *ref)
        except ValueError as error:
            assert needle in str(error), error
        else:
            raise AssertionError(needle)
    cli = Path(__file__).with_name("compare_pmi.py")
    run = subprocess.run([sys.executable, "-B", cli, folder, hash_, str(height),
                          *source_address, *ref_zero], capture_output=True, check=False)
    assert run.returncode == 1 and json.loads(run.stdout)["discriminant_leaf_matches"]
    print(f"PASS: msgpack {msgpack.__version__}; nil, zero Address and nonzero Address match their exact slot trees")
    print("PASS: payload-only divergence, absent/present divergence, child order, supplied pins and export rehash")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--helpers", required=True, type=Path)
    parser.add_argument("--rustc", required=True, type=Path)
    args = parser.parse_args()
    native()
    with TemporaryDirectory() as directory:
        controls(args.helpers, args.rustc, Path(directory))


if __name__ == "__main__":
    main()
