"""Reframe two pre-Rust fixture sets; contains no Rust or captured execution."""
import csv
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
PRIOR = HERE.parent / "RE-008-qc-fd-group-success-94"
PROTOCOL_SHA = "c2dc886f45e9484a164ad6bba3d6f33b6b8a7f8db65c71433d1263ce3f89c1fa"


def need(ok, message):
    if not ok:
        raise ValueError(message)


def rows(path):
    with path.open() as file:
        return list(csv.DictReader(file, delimiter="\t"))


def streams():
    raw = (HERE / "RUST-PROTOCOL-FREEZE.json").read_bytes()
    need(hashlib.sha256(raw).hexdigest() == PROTOCOL_SHA, "pre-source protocol freeze")
    pin = json.loads(raw)
    need(hashlib.sha256((HERE / "PRE-RUST-FREEZE.json").read_bytes()).hexdigest() == pin["short_freeze_sha256"], "native short freeze")
    inputs = ["id\tcharge\tlimit\twire_hex"]
    expected = ["id\tcharge\tpointer_advance\tremaining\tsuffix_hex\tgroup_tag\tgroup_kind_byte\tgroup_need_u64\trow_tag\trow_kind_byte\trow_need_u64\twords_le_hex"]
    for i, e in zip(rows(HERE / "inputs.tsv"), rows(HERE / "expected.tsv"), strict=True):
        inputs.append("\t".join(i[k] for k in ("id", "charge", "limit", "wire_hex")))
        expected.append("\t".join(e.values()) + "\t-")
    for i, e in zip(rows(PRIOR / "inputs.tsv"), rows(PRIOR / "expected.tsv"), strict=True):
        need(e["output_hex"][:16] == "0" * 16, "prior success tag")
        inputs.append("\t".join(i[k] for k in ("id", "charge", "limit", "wire_hex")))
        expected.append("\t".join([i["id"], e["charge"], e["consumed"], str(len(bytes.fromhex(i["wire_hex"])) - 36),
                                   e["suffix_hex"], "0", "-", "-", "-", "-", "-", e["output_hex"][16:]]))
    result = {"inputs.tsv": ("\n".join(inputs) + "\n").encode(),
              "expected.tsv": ("\n".join(expected) + "\n").encode()}
    need(len(inputs) == len(expected) == 45, "frozen protocol row count")
    need({k: hashlib.sha256(v).hexdigest() for k, v in result.items()} == pin["streams"], "frozen protocol streams")
    return result
