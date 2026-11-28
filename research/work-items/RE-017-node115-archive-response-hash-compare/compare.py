"""Compare selected local Full outcome rows with an archived response Hash."""

from argparse import ArgumentParser
from dataclasses import dataclass
import json
from pathlib import Path
import re
import sys

TOOLS = Path(__file__).resolve().parents[3] / "tools"
if TOOLS.is_dir():
    sys.path.insert(0, str(TOOLS))

from abci_res_variants115 import encode_subset
from re11_selfdestruct_keccak115 import keccak256


class UnsupportedOutcome(ValueError):
    """A response cannot be encoded by the selected outcome subset."""


@dataclass(frozen=True)
class Comparison:
    expected: str
    actual: str
    rows: int
    entries: int

    @property
    def matches(self):
        return self.expected == self.actual


def fixed_hex(value, width):
    if not isinstance(value, str) or re.fullmatch(r"0x[0-9a-f]{%d}" % (2 * width), value) is None:
        raise ValueError(f"expected {width} lowercase hex bytes")
    return value.encode("ascii")


def array_header(length):
    if length < 16:
        return bytes([0x90 | length])
    if length < 1 << 16:
        return b"\xdc" + length.to_bytes(2, "big")
    if length < 1 << 32:
        return b"\xdd" + length.to_bytes(4, "big")
    raise ValueError("response count exceeds the MessagePack array range")


def encode_result(result):
    if not isinstance(result, dict) or set(result) != {"status", "response"}:
        raise UnsupportedOutcome("expected a status and response")
    response = result["response"]
    if result["status"] == "err" and isinstance(response, str):
        payload = response.encode("utf-8")
        if len(payload) <= 255:
            return encode_subset(1, 15, payload)
    if result["status"] == "ok" and isinstance(response, dict):
        if response == {"type": "default"}:
            return encode_subset(1, 14)
        if set(response) == {"type", "data"} and response["type"] == "cancel":
            data = response["data"]
            if isinstance(data, dict) and set(data) == {"statuses"}:
                states = data["statuses"]
                if isinstance(states, list) and len(states) < 16:
                    values = []
                    for state in states:
                        if state == "success":
                            values.append(None)
                        elif (isinstance(state, dict) and set(state) == {"error"}
                              and isinstance(state["error"], str)
                              and len(state["error"].encode("utf-8")) <= 255):
                            values.append(state["error"].encode("utf-8"))
                        else:
                            raise UnsupportedOutcome("unmodeled cancel status")
                    return encode_subset(1, 1, tuple(values))
    raise UnsupportedOutcome("unmodeled outcome")


def encode_entry(entry):
    if not isinstance(entry, dict) or set(entry) != {"user", "res"}:
        raise UnsupportedOutcome("expected user and res")
    user = entry["user"]
    user_value = b"\xc0" if user is None else b"\xd9\x2a" + fixed_hex(user, 20)
    return b"\x82\xa4user" + user_value + b"\xa3res" + encode_result(entry["res"])


def encode_rows(rows):
    if not isinstance(rows, list):
        raise ValueError("expected Full response rows")
    output = bytearray(array_header(len(rows)))
    entries = 0
    for row_number, row in enumerate(rows):
        if not isinstance(row, list) or len(row) != 2 or not isinstance(row[1], list):
            raise ValueError(f"expected a digest and result array at row {row_number}")
        output.extend(b"\x92\xd9\x42" + fixed_hex(row[0], 32))
        output.extend(array_header(len(row[1])))
        for entry_number, entry in enumerate(row[1]):
            try:
                output.extend(encode_entry(entry))
            except UnsupportedOutcome as error:
                raise UnsupportedOutcome(f"row {row_number}, entry {entry_number}: {error}") from error
            entries += 1
    return bytes(output), entries


def compare(archived_response, local_response):
    """Check ordered local results against the supplied same-block response hash."""
    if not isinstance(archived_response, dict) or set(archived_response) != {"Hash"}:
        raise ValueError("expected an archived Hash response")
    if not isinstance(local_response, dict) or set(local_response) != {"Full"}:
        raise ValueError("expected separately produced Full results")
    expected = fixed_hex(archived_response["Hash"], 32).decode("ascii")
    rows = local_response["Full"]
    preimage, entries = encode_rows(rows)
    return Comparison(expected, "0x" + keccak256(preimage).hex(), len(rows), entries)


def unique_object(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError(f"duplicate JSON key {key}")
        obj[key] = value
    return obj


def main():
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("archive_row", type=Path, help="one local JSONL row with resps.Hash")
    parser.add_argument("local_response", type=Path, help="one JSON object with Full results")
    options = parser.parse_args()
    try:
        archived = json.loads(options.archive_row.read_text(encoding="utf-8"), object_pairs_hook=unique_object)
        if not isinstance(archived, dict) or "resps" not in archived:
            raise ValueError("archive row has no resps field")
        local = json.loads(options.local_response.read_text(encoding="utf-8"), object_pairs_hook=unique_object)
        result = compare(archived["resps"], local)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    print(json.dumps({**vars(result), "matches": result.matches}, sort_keys=True))
    return 0 if result.matches else 1


if __name__ == "__main__":
    sys.exit(main())
