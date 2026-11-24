"""Compare the Rust test input with lookup and writer references in node #115."""
import csv
import hashlib
from pathlib import Path
import sys

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]
sys.path.insert(0, str(ROOT / "tools"))
import output_flags_115 as flags


def main():
    image = flags.TARGET.read_bytes()
    if hashlib.sha256(image).hexdigest() != flags.SHA256:
        raise ValueError("node #115 digest mismatch")
    evidence = flags.bind(image)
    gates = {int(row["setter_byte"], 16) - 1: row["writer_name"] for row in evidence["setter"]["gates"]}
    with (PACKET / "lookups.tsv").open() as handle:
        fixture = list(csv.DictReader(handle, delimiter="\t"))
    expected = []
    for row in evidence["reader"]["lookups"]:
        present = row["lookup"] == "0x4e4c8e0"
        offset = int(row["offset"], 16) if present else None
        expected.append(dict(kind="presence" if present else "value", name=row["name"],
                             reader_offset=str(offset) if present else "-", writer=gates.get(offset, "-")))
    if fixture != expected:
        raise ValueError("lookup fixture differs from the decoded writer/option mapping")
    print(f"node #115: {len(expected)} lookups, {len(gates)} named writer gates match lookups.tsv")


if __name__ == "__main__":
    main()
