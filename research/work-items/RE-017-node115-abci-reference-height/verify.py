"""Reproduce the abci_hashes writer witnesses and reference-selection checks."""
import json
from pathlib import Path
import subprocess
import sys

from references import read_references

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]


def main():
    assert __debug__, "run without -O"
    subprocess.run(
        [sys.executable, "-B", str(ROOT / "tools/abci_hashes_log_115.py"), "--check"],
        cwd=ROOT,
        check=True,
    )
    print("PASS: #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301")
    records = (HERE / "synthetic.jsonl").read_text().splitlines()
    assert read_references(records, [42, 43]) == {
        42: b"\x12" * 32,
        43: b"\x34" * 32,
    }
    for changed, expected in (
        (records[:1], "no raw ABCI reference"),
        (records + records[-1:], "duplicate reference"),
        ([records[0], records[1].replace("abci_digest", "l1_digest")], "invalid raw"),
        ([json.dumps(json.loads(records[0]) | {"abci_digest": "0x00"}), records[1]],
         "invalid raw"),
    ):
        try:
            read_references(changed, [42, 43])
        except ValueError as error:
            assert expected in str(error)
        else:
            raise AssertionError("accepted a changed reference")
    print("PASS: exact H/H+1 selection and digest-kind, width, duplicate and absence controls")


if __name__ == "__main__":
    main()
