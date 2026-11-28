"""Compare a supplied #115 abci_hashes row with its exported tree preimage."""
from dataclasses import dataclass
import json
import re

import blake3
import msgpack

HEX32 = re.compile(r"0x[0-9a-f]{64}")


@dataclass(frozen=True)
class Comparison:
    height: int
    expected: str
    computed: str

    @property
    def matches(self):
        return self.computed == self.expected


def parse_unique_pairs(pairs):
    output = {}
    for name, value in pairs:
        if name in output:
            raise ValueError(f"duplicate key: {name}")
        output[name] = value
    return output


def valid_height(value):
    return type(value) is int and 0 <= value < 2**64


def require_digest(value):
    if not isinstance(value, str) or HEX32.fullmatch(value) is None:
        raise ValueError("expected a canonical 32-byte digest string")


def validate_tree(value):
    pending = [value]
    while pending:
        node = pending.pop()
        if isinstance(node, list):
            for child in node:
                if not isinstance(child, list) or len(child) != 2 or not valid_height(child[0]):
                    raise ValueError("expected each tree row to be [u64, child]")
                pending.append(child[1])
        else:
            require_digest(node)


def audit_line(line):
    row = json.loads(line, object_pairs_hook=parse_unique_pairs)
    if not isinstance(row, dict) or not valid_height(row.get("height")):
        raise ValueError("expected an abci_hashes row with an unsigned height")
    expected = row.get("abci_digest")
    require_digest(expected)
    tree = row.get("exchange_abci_hash")
    validate_tree(tree)
    preimage = msgpack.packb(tree, use_bin_type=True)
    return Comparison(row["height"], expected, "0x" + blake3.blake3(preimage).hexdigest())


if __name__ == "__main__":
    import sys
    from dataclasses import asdict

    try:
        comparison = audit_line(sys.stdin.read())
    except ValueError as error:
        raise SystemExit(str(error)) from error
    print(json.dumps({**asdict(comparison), "matches": comparison.matches}, sort_keys=True))
    raise SystemExit(0 if comparison.matches else 1)
