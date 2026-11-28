"""Recheck native roles and exercise typed, pinned artifact comparisons offline."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory

from compare import compare

TARGET = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
PACKET = Path(__file__).resolve().parent
RAW = bytes(range(32))
VECTORS = (
    (bytes.fromhex("81a66865696768742a"),
     "d8a7c4db836db4daa5e30be798f805105be429bf48500183554cc74aba4e1127",
     "08347eacd591cca8d88e87cda875d7613bd1335081a915bf83f22a0379c288f9"),
    (bytes(index % 251 for index in range(1025)),
     "d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444",
     "5ae7252aa7cc0999668e1472bdb0a274e02b75c0c9ca53e7c3cffb67030cc71c"),
)


def build(rustc, directory):
    lib = directory / "libnode115_abci_blake3.rlib"
    exe = directory / "linked"
    subprocess.run([rustc, "--edition=2024", "--crate-name", "node115_abci_blake3", "--crate-type",
                    "rlib", "src/node115-abci-blake3/src/lib.rs", "-o", lib], check=True)
    subprocess.run([rustc, "--edition=2024", PACKET / "linked.rs",
                    "--extern", f"node115_abci_blake3={lib}", "-o", exe], check=True)
    return exe


def controls(exe, directory):
    def save(name, contents):
        path = directory / name
        path.write_bytes(contents)
        return (path, hashlib.sha256(contents).hexdigest())

    def export_row(height, digest):
        return json.dumps({"height": height, "abci_digest": "0x" + digest.hex(),
                           "exchange_abci_hash": []}).encode() + b"\n"

    def message(height, linked):
        return height.to_bytes(8, "little") + bytes.fromhex(linked)

    height = 42
    for i, (state_bytes, inner, linked) in enumerate(VECTORS):
        state = save(f"synthetic-{i}.rmp", state_bytes)
        raw = save(f"synthetic-{i}.jsonl", export_row(height, RAW))
        capture = save(f"synthetic-{i}.message", message(height, linked))
        result = compare(exe, height, *state, *raw, *capture)
        assert result["linked_match"] and result["serialized_state_blake3"] == "0x" + inner
        assert result["serialized_state_bytes"] == len(state_bytes)
    new_state = save("extended.rmp", state_bytes + height.to_bytes(8, "little"))
    altered_raw = save("different-raw.jsonl", export_row(height, RAW[::-1]))
    assert not compare(exe, height, *new_state, *raw, *capture)["linked_match"]
    assert not compare(exe, height, *state, *altered_raw, *capture)["linked_match"]

    failures = (
        (*state, *save("different-height.jsonl", export_row(43, RAW)), *capture, "raw ABCI record height"),
        (*state, *raw, *save("different-height.message", message(43, linked)), "message height"),
        (*state, *raw, *save("long.message", message(height, linked) + b"x"), "40-byte"),
        (state[0], "0" * 64, *raw, *capture, "serialized state SHA-256"),
        (*state, raw[0], "0" * 64, *capture, "SHA-256 mismatch"),
        (*state, *raw, capture[0], "0" * 64, "SHA-256 mismatch"),
    )
    for *inputs, reason in failures:
        try:
            compare(exe, height, *inputs)
        except ValueError as error:
            assert reason in str(error)
        else:
            raise AssertionError(reason)

    command = [sys.executable, "-B", PACKET / "compare.py", exe, str(height)]
    match = subprocess.run(command + [*state, *raw, *capture],
                           check=True, capture_output=True, text=True)
    mismatch = subprocess.run(command + [*new_state, *raw, *capture], capture_output=True, text=True)
    assert json.loads(match.stdout)["linked_match"]
    assert mismatch.returncode == 1 and not json.loads(mismatch.stdout)["linked_match"]
    print("PASS: two published independent vectors, including a 1025-byte BLAKE3 boundary")
    print("PASS: same-height typed artifacts, exact state extent, three SHA pins and mismatch CLI codes")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--rustc", default="rustc")
    args = parser.parse_args()
    assert hashlib.sha256(Path("artifacts/node/115/hl-node").read_bytes()).hexdigest() == TARGET
    print(f"PASS: node #115 SHA-256 {TARGET}", flush=True)
    for tool in ("hardfork_hashes_115", "l1_hash_input_115", "abci_hashes_log_115"):
        subprocess.run([sys.executable, "-B", f"tools/{tool}.py", "--check"], check=True)
    subprocess.run([args.rustc, "--version"], check=True)
    with TemporaryDirectory() as tempdir:
        directory = Path(tempdir)
        controls(build(args.rustc, directory), directory)


if __name__ == "__main__":
    main()
