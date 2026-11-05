#!/usr/bin/env python3
"""Independent linear specification; never imports or runs reconstructed code."""
import hashlib
import itertools
import json
from pathlib import Path
import random
import sys

MAX = (1 << 64) - 1


def row(key, offset, divisor, salt=0):
    value = bytearray((salt + i * 13) % 256 for i in range(40))
    value[:8] = key.to_bytes(8, "little")
    value[24:32] = offset.to_bytes(8, "little")
    value[32] = divisor
    return bytes(value)


def key(value):
    return int.from_bytes(value[:8], "little")


def reference(rows, head, live, query):
    capacity = len(rows)
    if live > capacity or (head >= capacity if capacity else head != 0):
        return "bounds"
    logical = [(head + i) % capacity for i in range(live)]
    if any(key(rows[a]) > key(rows[b]) for a, b in zip(logical, logical[1:])):
        return "order"
    selected = []
    for physical in logical:
        if key(rows[physical]) > query:
            break
        selected.append(physical)
    first = []
    second = []
    for physical in selected:
        (first if physical >= head else second).append(rows[physical])
    last = None
    if selected:
        physical = selected[-1]
        value = rows[physical]
        last = [len(selected) - 1, physical, key(value),
                int.from_bytes(value[24:32], "little"), value[32]]
    return first, second, last


def packed(rows):
    return ",".join(value.hex() for value in rows) or "-"


def output(identifier, result):
    if isinstance(result, str):
        return f"{identifier}\terr\t{result}\n"
    first, second, last = result
    fields = [identifier, "ok", len(first) + len(second), len(first), len(second)]
    fields += last if last is not None else ["-"] * 5
    fields += [packed(first), packed(second)]
    return "\t".join(map(str, fields)) + "\n"


def main(directory):
    directory.mkdir()
    cases = []
    # Literal indices/field projections specified before generated expectations.
    manual = [
        ([], 0, 0, 0, None),
        ([row(9, 2, 0)], 0, 1, 9, [0, 0, 9, 2, 0]),
        ([row(9, 2, 255)], 0, 1, 8, None),
        ([row(9, 2, 255)], 0, 0, MAX, None),
        ([row(5, 11, 1), row(5, 22, 2), row(99, 99, 0),
          row(1, 33, 3), row(5, 44, 4)], 3, 4, 5, [3, 1, 5, 22, 2]),
        ([row(5, 11, 1), row(5, 22, 2), row(99, 99, 0),
          row(1, 33, 3), row(5, 44, 4)], 3, 4, 4, [0, 3, 1, 33, 3]),
        ([row(MAX, MAX, 255), row(0, 0, 0), row(1 << 63, 17, 128)],
         1, 3, MAX, [2, 0, MAX, MAX, 255]),
        ([row(MAX, MAX, 255), row(0, 0, 0), row(1 << 63, 17, 128)],
         1, 3, (1 << 63) - 1, [0, 1, 0, 0, 0]),
        ([row(7, 1, 1), row(3, 2, 2)], 0, 2, MAX, "order"),
        ([row(7, 1, 1), row(3, 2, 2)], 2, 3, MAX, "bounds"),
        ([], 1, 0, MAX, "bounds"),
        ([row(3, 1, 1), row(1, 2, 2)], 1, 0, MAX, None),
    ]
    # Independent literal physical-index lists also bind the actual two slices.
    segments = [([], []), ([0], []), ([], []), ([], []),
                ([3, 4], [0, 1]), ([3], []), ([1, 2], [0]), ([1], []),
                None, None, None, ([], [])]
    manual_records = []
    for i, (rows, head, live, query, wanted) in enumerate(manual):
        result = reference(rows, head, live, query)
        observed = result if isinstance(result, str) else result[2]
        if observed != wanted:
            raise ValueError((i, observed, wanted))
        if segments[i] is not None:
            first_indices, second_indices = segments[i]
            if result[:2] != ([rows[j] for j in first_indices],
                              [rows[j] for j in second_indices]):
                raise ValueError((i, "manual segment mismatch"))
        manual_records.append({"id": f"M{i:02}", "projection": wanted,
                               "physical_segments": segments[i]})
        cases.append((f"M{i:02}", rows, head, live, query))
    # Exhaust all rotations/live lengths/nondecreasing tiny keys through capacity6.
    serial = 0
    for capacity in range(7):
        for head in range(max(1, capacity)):
            for live in range(capacity + 1):
                for keys in itertools.combinations_with_replacement([0, 1, 3], live):
                    rows = [row(MAX - i, 1000 + i, i, i * 17) for i in range(capacity)]
                    for i, value in enumerate(keys):
                        rows[(head + i) % capacity] = row(value, 10 + i, (i * 71) % 256, i)
                    for query in [0, 1, 2, 3, 4, 1 << 63, MAX]:
                        cases.append((f"E{serial}", rows, head, live, query))
                        serial += 1
    rng = random.Random(1154550)
    for i in range(512):
        capacity = rng.randrange(1, 33)
        head = rng.randrange(capacity)
        live = rng.randrange(capacity + 1)
        keys = sorted(rng.choice([0, MAX, 1 << 63, rng.getrandbits(64)]) for _ in range(live))
        rows = [row(rng.getrandbits(64), rng.getrandbits(64), rng.randrange(256), j)
                for j in range(capacity)]
        for j, value in enumerate(keys):
            rows[(head + j) % capacity] = row(value, rng.getrandbits(64), rng.randrange(256), j)
        query = rng.choice(keys + [0, MAX, rng.getrandbits(64)])
        cases.append((f"R{i}", rows, head, live, query))
    # Invalid views and live-key disorder are host admission outcomes only.
    for i in range(24):
        rows = [row(3, i, 0), row(1, MAX - i, 255), row(2, i, 1)]
        cases.append((f"B{i}", rows, i + 3, 4, MAX))
        cases.append((f"O{i}", rows, 0, 3, i))
    inputs = "".join(f"{name}\t{head}\t{live}\t{query}\t{packed(rows)}\n"
                     for name, rows, head, live, query in cases).encode()
    expected = "".join(output(name, reference(rows, head, live, query))
                       for name, rows, head, live, query in cases).encode()
    (directory / "inputs.tsv").write_bytes(inputs)
    (directory / "expected.tsv").write_bytes(expected)
    (directory / "manual.json").write_text(json.dumps(manual_records, indent=2) + "\n")
    summary = {"cases": len(cases), "manual_cases": len(manual),
               "generated_exhaustive_cases": serial, "seeded_cases": 512,
               "additional_host_rejections": 48, "inputs_bytes": len(inputs),
               "expected_bytes": len(expected),
               "files": {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                         for p in sorted(directory.iterdir())}}
    (directory / "CORPUS.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary))


if __name__ == "__main__":
    main(Path(sys.argv[1]))
