"""Verify the native tree encoding and run the paired root-substitution controls."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory

from isolate import append_preimage, decode_tree, digest, isolate
from abci_hash_tree_encoding_115 import enc_tree

PACKET = Path(__file__).resolve().parent
TARGET = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"


def build(rustc, directory):
    library = directory / "libnode115_abci_blake3.rlib"
    helper = directory / "hash_tree"
    subprocess.run([rustc, "--edition=2024", "--crate-name", "node115_abci_blake3", "--crate-type",
                    "rlib", "src/node115-abci-blake3/src/lib.rs", "-o", library], check=True)
    subprocess.run([rustc, "--edition=2024", PACKET / "hash_tree.rs",
                    "--extern", f"node115_abci_blake3={library}", "-o", helper], check=True)
    vector = subprocess.check_output([helper], input=b"abc").decode("ascii").strip()
    assert vector == "0x6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85"
    return helper


def controls(helper, directory):
    unchanged = "0x" + "11" * 32
    successor = "0x" + "22" * 32
    other = "0x" + "33" * 32
    context = [[3, unchanged], [255, other]]
    changed_context = [[3, successor], [255, other]]
    prefix = [[0, [[0, context], [2, other]]], [58, unchanged]]
    only_context = [[0, [[0, changed_context], [2, other]]], [58, unchanged]]
    both = [[0, [[0, changed_context], [2, other]]], [58, other]]
    reordered = [[58, unchanged], [0, [[0, changed_context], [2, other]]]]
    only_outside = [[0, [[0, context], [2, other]]], [58, other]]
    native_example = decode_tree(prefix)
    preimage = bytearray()
    append_preimage(native_example, preimage)
    assert preimage == enc_tree(native_example)

    def save(name, raw_tree, height=42, stated=None):
        root = stated or digest(helper, decode_tree(raw_tree))
        row = {"height": height, "abci_digest": root, "exchange_abci_hash": raw_tree}
        data = (json.dumps(row) + "\n").encode()
        file = directory / name
        file.write_bytes(data)
        return file, hashlib.sha256(data).hexdigest()

    ref = save("reference.jsonl", prefix)

    def run(tree):
        observed = save("observed.jsonl", tree)
        return isolate(helper, 42, *ref, *observed)

    no_change = run(prefix)
    assert not no_change["context_changed"] and no_change["outside_context_equal"]
    changed = run(only_context)
    assert changed["context_changed"] and changed["outside_context_equal"]
    assert changed["substitution_matches_observed_digest"]
    for changed_elsewhere in (only_outside, both, reordered):
        result = run(changed_elsewhere)
        assert not result["outside_context_equal"] and not result["substitution_matches_observed_digest"]
    cases = (
        (*save("wrong-height.jsonl", only_context, height=43), "export height"),
        (*save("stale-root.jsonl", only_context, stated="0x" + "00" * 32), "own raw digest"),
        (*save("missing-context.jsonl", [[0, [[1, unchanged]]]]), "missing native Context"),
        (ref[0], "0" * 64, "export SHA-256 mismatch"),
    )
    for path, sha, expected in cases:
        try:
            isolate(helper, 42, *ref, path, sha)
        except ValueError as error:
            assert expected in str(error)
        else:
            raise AssertionError(expected)
    observed = save("both.jsonl", both)
    result = subprocess.run([sys.executable, "-B", PACKET / "isolate.py", helper, "42",
                             *ref, *observed], text=True, capture_output=True)
    assert result.returncode == 1 and not json.loads(result.stdout)["outside_context_equal"]
    print("PASS: Context-only, outside-only, mixed, unchanged and reordered tree controls")
    print("PASS: stale raw digest, missing Context, SHA, height and CLI controls")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--rustc", default="rustc")
    args = parser.parse_args()
    assert hashlib.sha256(Path("artifacts/node/115/hl-node").read_bytes()).hexdigest() == TARGET
    print(f"PASS: node #115 SHA-256 {TARGET}", flush=True)
    for tool in ("abci_hashes_tree_json_115", "abci_hash_tree_encoding_115"):
        subprocess.run([sys.executable, "-B", f"tools/{tool}.py", "--check"], check=True)
    subprocess.run([args.rustc, "--version"], check=True)
    with TemporaryDirectory() as tempdir:
        directory = Path(tempdir)
        controls(build(args.rustc, directory), directory)


if __name__ == "__main__":
    main()
