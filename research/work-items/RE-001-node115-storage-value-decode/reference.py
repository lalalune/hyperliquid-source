#!/usr/bin/env python3
"""Reproduce synthetic storage-word fixtures without running captured code.

The reference uses struct length decoding, Python's independent UTF-8 codec,
and a single arbitrary-precision integer before extracting little-order limbs.
It is a cross-language grammar check, not a target runtime differential test.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path

HEADERS = {0xC4: ">B", 0xC5: ">H", 0xC6: ">I", 0xD9: ">B", 0xDA: ">H", 0xDB: ">I"}


def expected(wire, mutation=None):
    marker = wire[0]
    format_ = HEADERS[marker]
    width = struct.calcsize(format_)
    length, = struct.unpack(format_, wire[1:1 + width])
    payload = wire[1 + width:1 + width + length]
    if len(payload) != length or length != 32:
        return "reject"
    if marker >= 0xD9:
        try:
            payload.decode("utf-8", errors="strict")
            valid = True
        except UnicodeDecodeError:
            valid = False
        if mutation == "invert-utf8":
            valid = not valid
        if mutation == "reject-all-strings" or (valid and mutation != "accept-valid-strings"):
            return "reject"
    integer = int.from_bytes(payload, "big")
    limbs = [(integer >> (64 * index)) & ((1 << 64) - 1) for index in range(4)]
    if mutation == "reverse-limb-order":
        limbs.reverse()
    consumed = 1 + width + length
    if mutation == "require-eof" and consumed != len(wire):
        return "reject"
    return ",".join([*(f"{limb:016x}" for limb in limbs), str(consumed)])


def inputs():
    payloads = []
    for position in (0, 15, 31):
        for byte in range(256):
            payload = bytearray(b"a" * 32)
            payload[position] = byte
            payloads.append(bytes(payload))
    # Overlong encodings, surrogate boundaries, max-code-point boundaries,
    # truncated sequences and valid 2/3/4-byte UTF-8 at the end of a 32-byte row.
    for suffix in (
        b"\xc0\x80", b"\xc1\xbf", b"\xc2\x80", b"\xdf\xbf",
        b"\xe0\x9f\xbf", b"\xe0\xa0\x80", b"\xed\x9f\xbf", b"\xed\xa0\x80",
        b"\xef\xbf\xbf", b"\xf0\x8f\xbf\xbf", b"\xf0\x90\x80\x80",
        b"\xf4\x8f\xbf\xbf", b"\xf4\x90\x80\x80", b"\xf5\x80\x80\x80",
        b"\xc2", b"\xe0\xa0", b"\xf0\x90\x80", b"\x80",
    ):
        payloads.append(b"a" * (32 - len(suffix)) + suffix)
    assert len(payloads) == 786
    for marker, format_ in HEADERS.items():
        for payload in payloads:
            # The final reserved marker must remain unconsumed on success.
            yield bytes([marker]) + struct.pack(format_, 32) + payload + b"\xc1"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    here = Path(__file__).resolve().parent
    root = here.parents[2]
    fixture = root / "src/node115-storage-value-decode/tests/reference-vectors.txt"
    lines = ["# wire_hex expected_le_limbs_and_consumed_or_reject"]
    controls = {name: 0 for name in (
        "reject-all-strings", "accept-valid-strings", "invert-utf8", "reverse-limb-order", "require-eof"
    )}
    accepted = 0
    for wire in inputs():
        result = expected(wire)
        accepted += result != "reject"
        lines.append(wire.hex() + " " + result)
        for name in controls:
            controls[name] += expected(wire, name) != result
    assert len(lines) - 1 == 4716 and all(controls.values())
    contents = "\n".join(lines) + "\n"
    summary = {
        "method": "struct + Python strict UTF-8 codec + arbitrary precision integer; synthetic reference only",
        "cases": 4716,
        "accepted": accepted,
        "rejected": 4716 - accepted,
        "fixture_sha256": hashlib.sha256(contents.encode()).hexdigest(),
        "negative_controls_differing_cases": controls,
        "limits": ["not a target execution/emulation", "native error text and failure consumption not reproduced"],
    }
    summary_text = json.dumps(summary, indent=2) + "\n"
    report = here / "reference-results.json"
    if args.write:
        fixture.write_text(contents)
        report.write_text(summary_text)
    else:
        assert fixture.read_text() == contents
        assert report.read_text() == summary_text
    print(summary_text, end="")


if __name__ == "__main__":
    main()
