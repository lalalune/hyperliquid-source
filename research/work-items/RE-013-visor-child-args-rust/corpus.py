#!/usr/bin/env python3
"""Independent scalar-language oracle, authored before production Rust.

No host Unicode decoder, native instruction evaluator or candidate imports.
Canonical encodings are generated from scalar integers and compiled into a trie.
"""

import argparse
from collections import Counter
import gzip
import hashlib
import itertools
import json
from pathlib import Path

from bind import HERE, REPO, authenticate, read_json, require, sha, write_json

MAX_SIGNED = (1 << 63) - 1


def encode_scalar(value):
    require(0 <= value <= 0x10ffff and not 0xd800 <= value <= 0xdfff, "not a scalar")
    if value < 0x80:
        return bytes([value])
    if value < 0x800:
        return bytes([0xc0 | (value >> 6), 0x80 | (value & 63)])
    if value < 0x10000:
        return bytes([0xe0 | (value >> 12), 0x80 | ((value >> 6) & 63), 0x80 | (value & 63)])
    return bytes([0xf0 | (value >> 18), 0x80 | ((value >> 12) & 63),
                  0x80 | ((value >> 6) & 63), 0x80 | (value & 63)])


class ScalarLanguage:
    def __init__(self):
        self.next = {}
        self.width = [0] * 256
        self.counts = Counter()
        encoded = hashlib.sha256()
        for value in range(0x110000):
            if 0xd800 <= value <= 0xdfff:
                continue
            word = encode_scalar(value)
            encoded.update(word)
            self.counts[len(word)] += 1
            first = word[0]
            require(self.width[first] in (0, len(word)), "ambiguous canonical width")
            self.width[first] = len(word)
            for used, byte in enumerate(word):
                prefix = word[:used]
                self.next[prefix] = self.next.get(prefix, 0) | (1 << byte)
        self.scalar_stream_sha256 = encoded.hexdigest()
        require(self.counts == {1: 128, 2: 1920, 3: 61440, 4: 1048576}, "scalar count differs")
        require(len(self.next) == 17652, "prefix count differs")

    def classify(self, data):
        """None iff a concatenation of canonical encodings.

        Failure tuple is (sequence start, invalid length or None for EOF).
        The failure projection follows the credited validator protocol; this
        structure is not exposed as a recovered collection error API.
        """
        index = 0
        while index < len(data):
            width = self.width[data[index]]
            if width == 0:
                return index, 1
            prefix = b""
            for used in range(width):
                if index + used == len(data):
                    return index, None
                byte = data[index + used]
                if not (self.next[prefix] >> byte) & 1:
                    return index, max(1, used)
                prefix += bytes([byte])
            index += width
        return None


def cell(data):
    if data is None:
        return "~"
    return data.hex() if data else "-"


def cells(items):
    return ",".join(cell(x) for x in items) if items else "."


def expectation(language, items):
    result = []
    for index, data in enumerate(items):
        if data is None:
            break
        if language.classify(data) is not None:
            return "INVALID\t" + str(index)
        result.append(data)
    return "OK\t" + cells(result)


def cases(language):
    yield "empty-descriptors", []
    for value in range(256):
        yield "all-one-byte", [bytes([value])]
    for value in range(65536):
        yield "all-two-byte", [value.to_bytes(2, "big")]
    # Every proper canonical multibyte prefix: incomplete and first bad byte.
    for prefix in sorted(language.next):
        if not prefix:
            continue
        yield "proper-prefix-eof", [prefix]
        yield "proper-prefix-invalid-ascii", [prefix + b"\0"]
    boundaries = {0, 1, 0x7e, 0x7f, 0x80, 0x81, 0x7fe, 0x7ff, 0x800, 0x801,
                  0xd7fe, 0xd7ff, 0xe000, 0xe001, 0xfffe, 0xffff, 0x10000,
                  0x10001, 0x10fffe, 0x10ffff}
    for pivot in range(0, 0x110000, 1024):
        boundaries.update(x for x in [pivot - 1, pivot, pivot + 1]
                          if 0 <= x <= 0x10ffff and not 0xd800 <= x <= 0xdfff)
    for value in sorted(boundaries):
        yield "scalar-boundary", [encode_scalar(value)]
    examples = [b"", b"\0", b"a", b" a\t", b"child-args", b"'\"^/",
                encode_scalar(0x80), encode_scalar(0x800), encode_scalar(0xd7ff),
                encode_scalar(0x10000), encode_scalar(0x10ffff), b"\xff", b"\xe0\xa0",
                b"\xed\xa0\x80", None]
    for count in range(1, 4):
        for items in itertools.product(examples, repeat=count):
            yield "small-list-product", list(items)
    for count in [0, 1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 63, 64, 65, 257]:
        ordered = [bytes([65 + (i % 26)]) + str(i).encode("ascii") for i in range(count)]
        yield "ordered-list", ordered
        yield "all-empty-list", [b""] * count
        yield "duplicate-list", [b"same"] * count
        for stop in sorted({0, count // 2, count}):
            yield "stop-before-invalid-suffix", ordered[:stop] + [None, b"\xff", b"\0"]
        for bad in sorted({0, count // 2, count}):
            yield "invalid-index", ordered[:bad] + [b"\xff", None, b"ok"]
    for size in list(range(0, 34)) + [63, 64, 65, 127, 128, 129, 255, 256, 257, 4095, 4096]:
        prefix = b"A" * size
        for suffix in [b"", b"\0", b"\xff", b"\xc2", b"\xc2\x80", b"\xe0\x80",
                       b"\xe0\xa0", b"\xe0\xa0\x80", b"\xf4\x8f\xbf", b"\xf4\x8f\xbf\xbf"]:
            yield "long-prefix", [prefix + suffix, b"tail"]
    for width in [1, 2, 3, 4]:
        cp = {1: 0x7f, 2: 0x7ff, 3: 0xffff, 4: 0x10ffff}[width]
        word = encode_scalar(cp)
        for count in [1, 3, 4, 15, 16, 17, 31, 32, 33, 257]:
            yield "repeated-scalar", [word * count + b"\0", b"", word]


def handwritten(language):
    # Literal hand-derived values, not populated from the classifier.
    grammar = [
        ("", None), ("00", None), ("c280", None), ("e0a080", None),
        ("eda080", (0, 1)), ("f48fbfbf", None), ("f4908080", (0, 1)),
        ("e080", (0, 1)), ("e0a0", (0, None)), ("e0a000", (0, 2)),
        ("f0908080", None), ("f0908000", (0, 3)), ("f09080", (0, None)),
        ("61c080", (1, 1)), ("61c2", (1, None)), ("61c200", (1, 1)),
        ("7f80", (1, 1)), ("c280ff", (2, 1)), ("f5808080", (0, 1)),
    ]
    for encoded, expected in grammar:
        require(language.classify(bytes.fromhex(encoded)) == expected,
                "hand grammar witness differs: " + encoded)
    values = [
        ([], "OK\t."), ([None, b"\xff"], "OK\t."), ([b""], "OK\t-"),
        ([b"a", None, b"\xff"], "OK\t61"), ([b"\0", b""], "OK\t00,-"),
        ([b"b", b"a", b"b"], "OK\t62,61,62"), ([b" a\t"], "OK\t206109"),
        ([b"a", b"\xe0\xa0"], "INVALID\t1"),
        ([b"a", b"\xe0\x80"], "INVALID\t1"),
        ([b"", b"", b"\xff", None], "INVALID\t2"),
        ([b"\xf4\x8f\xbf\xbf"], "OK\tf48fbfbf"),
        ([b"\xed\xa0\x80"], "INVALID\t0"),
    ]
    for items, expected in values:
        require(expectation(language, items) == expected, "hand collection witness differs")
    return dict(grammar=[dict(hex=x, expected=y) for x, y in grammar],
                values=[dict(input=cells(x), expected=y) for x, y in values])


def put_gzip(directory, name, data):
    compressed = gzip.compress(data, mtime=0)
    (directory / name).write_bytes(compressed)
    return dict(path=name, sha256=sha(compressed), bytes=len(compressed),
                raw_sha256=sha(data), raw_bytes=len(data))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, default=REPO)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    pins = read_json(HERE / "BASIS-PINS.json")
    image = authenticate(args.repo, pins)
    language = ScalarLanguage()
    native_widths = image.at(int(pins["lead_table"]["va"], 16), 256)
    require(bytes(language.width) == native_widths, "canonical/native lead widths disagree")
    witnesses = handwritten(language)
    args.out.mkdir(parents=True, exist_ok=False)
    inputs, expected = [], []
    categories, outcomes = Counter(), Counter()
    for index, (category, items) in enumerate(cases(language)):
        case_id = f"c{index:06d}"
        result = expectation(language, items)
        inputs.append(case_id + "\t" + cells(items) + "\n")
        expected.append(case_id + "\t" + result + "\n")
        categories[category] += 1
        outcomes[result.split("\t")[0]] += 1
    counts = set(range(0, 10))
    boundary = MAX_SIGNED // 24
    counts.update([boundary - 2, boundary - 1, boundary, boundary + 1, boundary + 2,
                   MAX_SIGNED - 1, MAX_SIGNED, MAX_SIGNED + 1, (1 << 64) - 1])
    for bit in range(64):
        counts.update(x for x in [(1 << bit) - 1, 1 << bit, (1 << bit) + 1]
                      if 0 <= x < (1 << 64))
    integer_inputs, integer_expected = [], []
    for index, count in enumerate(sorted(counts)):
        case_id = f"n{index:03d}"
        integer_inputs.append(f"{case_id}\t{count}\n")
        product = 24 * count
        result = f"OK\t{product}" if product <= MAX_SIGNED else "DOMAIN"
        integer_expected.append(f"{case_id}\t{result}\n")
    streams = [
        put_gzip(args.out, "inputs.tsv.gz", "".join(inputs).encode()),
        put_gzip(args.out, "expected.tsv.gz", "".join(expected).encode()),
        put_gzip(args.out, "length-inputs.tsv.gz", "".join(integer_inputs).encode()),
        put_gzip(args.out, "length-expected.tsv.gz", "".join(integer_expected).encode()),
    ]
    trie = b"".join(prefix.hex().encode() + b":" + f"{mask:064x}".encode() + b"\n"
                    for prefix, mask in sorted(language.next.items()))
    certificate = dict(scalar_count=sum(language.counts.values()),
                       scalar_count_by_width=dict(language.counts),
                       scalar_encoding_stream_sha256=language.scalar_stream_sha256,
                       proper_prefix_count=len(language.next) - 1,
                       proper_prefix_count_by_length=dict(Counter(len(x) for x in language.next if x)),
                       complete_prefix_relation_sha256=sha(trie),
                       native_lead_widths_sha256=sha(native_widths),
                       all_256_lead_widths_match=True,
                       scope="Finite canonical scalar-language certificate, not instruction execution or full native proof")
    write_json(args.out / "grammar.json", certificate)
    write_json(args.out / "handwritten.json", witnesses)
    write_json(args.out / "corpus.json", dict(cases=len(inputs), length_cases=len(integer_inputs),
                                              categories=dict(categories), outcomes=dict(outcomes),
                                              streams=streams, target=pins["target"],
                                              generator_sha256=sha(Path(__file__).read_bytes()),
                                              basis_pins_sha256=sha((HERE / "BASIS-PINS.json").read_bytes()),
                                              origin="Pre-Rust independent canonical scalar-language oracle; no target execution"))
    print(json.dumps(dict(status="PASS: pre-code mathematical corpus", cases=len(inputs),
                          length_cases=len(integer_inputs), scalar_count=sum(language.counts.values()),
                          proper_prefixes=len(language.next) - 1)))


if __name__ == "__main__":
    main()
