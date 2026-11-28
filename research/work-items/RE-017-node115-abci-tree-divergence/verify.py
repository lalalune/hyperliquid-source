"""Validate native writer anchors and deterministic offline mismatch localization."""

import hashlib
import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory

from compare import compare

TARGET = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
A = "0x" + "12" * 32
B = "0x" + "34" * 32


def main():
    for tool in ("abci_hashes_log_115", "abci_hashes_tree_json_115"):
        subprocess.run([sys.executable, "-B", f"tools/{tool}.py", "--check"], check=True)
    print(f"PASS: authenticated native row and tree writers for #115 SHA-256 {TARGET}")

    with TemporaryDirectory() as directory:
        reference = Path(directory) / "reference.jsonl"
        observation = Path(directory) / "observation.jsonl"

        def write(path, tree, digest, height=30):
            data = (json.dumps({"height": height, "abci_digest": digest,
                                "exchange_abci_hash": tree}) + "\n").encode()
            path.write_bytes(data)
            return hashlib.sha256(data).hexdigest()

        ref_sha = write(reference, [[3, [[7, A], [9, B]]], [4, []]], A)

        def run(tree, digest=A):
            return compare(reference, ref_sha, observation, write(observation, tree, digest), 30)

        exact = [[3, [[7, A], [9, B]]], [4, []]]
        assert run(exact) == {"height": 30, "raw_digest_equal": True, "first_tree_difference": None}
        assert run(exact, B) == {"height": 30, "raw_digest_equal": False, "first_tree_difference": None}
        assert run([[3, [[7, B], [9, B]]], [4, []]], B)["first_tree_difference"] == {
            "path": (3, 7), "kind": "leaf_digest",
        }
        assert run([[3, [[9, B], [7, A]]], [4, []]])["first_tree_difference"] == {
            "path": (3,), "kind": "child_order", "ordinal": 0,
            "reference_index": 7, "observation_index": 9,
        }
        assert run([[3, [[6, A], [9, B]]], [4, []]])["first_tree_difference"]["kind"] == "child_index"
        assert run([[3, [[7, A]]], [4, []]])["first_tree_difference"] == {
            "path": (3,), "kind": "child_count", "reference_count": 2, "observation_count": 1,
        }
        assert run([[3, [[7, A], [9, B]]], [4, A]])["first_tree_difference"] == {
            "path": (4,), "kind": "leaf_vs_branch",
        }
        assert run(A)["first_tree_difference"] == {"path": (), "kind": "leaf_vs_branch"}
        print("PASS: synthetic equality, independent raw-root flag, nested leaf, order, index, count and shape controls")

        def rejects(sha, reason):
            try:
                compare(reference, ref_sha, observation, sha, 30)
            except ValueError as error:
                assert reason in str(error), error
            else:
                raise AssertionError(f"accepted invalid input: {reason}")

        rejects(write(observation, exact, A, height=31), "row height")
        rejects(write(observation, [[3, A], [3, B]], A), "unique unsigned")
        rejects(write(observation, [[True, A]], A), "unique unsigned")
        rejects(write(observation, [[0, "0x00"]], A), "32-byte digest")
        rejects(write(observation, exact, "0x00"), "invalid raw")
        rejects("0" * 64, "artifact digest mismatch")
        digest = write(observation, exact, B)
        completed = subprocess.run(
            [sys.executable, "-B", str(Path(__file__).with_name("compare.py")),
             "30", str(reference), ref_sha, str(observation), digest],
            check=False, capture_output=True, text=True,
        )
        assert completed.returncode == 1 and not completed.stderr
        assert json.loads(completed.stdout) == {
            "height": 30, "raw_digest_equal": False, "first_tree_difference": None,
        }
        print("PASS: synthetic input controls reject wrong height, duplicate or boolean index, width and input SHA")


if __name__ == "__main__":
    main()
