#!/usr/bin/env python3
"""Draft deterministic scalar-input corpus builder; execution is separately gated.

Only stdlib and the exact qualified mathematical reference buffer are used.
No target files, subprocesses, network, project models or Rust files are read.
The output directory must be fresh. Input and expected output remain separate.
"""

import argparse
from collections import Counter
import hashlib
from itertools import combinations_with_replacement
import json
from pathlib import Path
import random
import re
import types

REFERENCE_SHA256 = "3bc9d4e1474b475b0a1b8911cabe59c60d85fa64de5c8dfe7c86ffe3d82c079b"
MANUAL_FREEZE_SHA256 = "eec1e900dd60abb77deda2d5aaabcf54ee87fb1f1d790ea5013aedce77a4f40f"
QUALIFICATION_SHA256 = "777f00994e2a85ef285c34341203d2e42d2b24a8bd505df65060f17fc8342291"
HOST_SHA256 = "4bb6a164423609b2310b7952351be5e88f8583d205b1ec144e9393cfde92a28e"
U64_MAX = 18446744073709551615
SEED = 0x5354414B455F3230
REQUESTS = 8026
MAX_BYTES = 16777216
MAX_RECORDS = 8192
ID = re.compile(r"[A-Za-z0-9_-]{1,64}\Z", re.ASCII)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def key(value):
    return value.to_bytes(20, "big")


def physical(logical, capacity, head):
    rows = [(key(0) if i % 2 else bytes([255]) * 20, U64_MAX)
            for i in range(capacity)]
    for i, row in enumerate(logical):
        rows[(head + i) % capacity] = row
    return rows


class Corpus:
    def __init__(self, reference):
        self.reference = reference
        self.inputs = []
        self.expected = []
        self.index = []
        self.aliases = []
        self.seen = {}
        self.ids = set()
        self.requested = Counter()
        self.retained = Counter()
        self.statuses = Counter()
        self.input_bytes = 0

    def add(self, family, rows, head, live, selected, manual=None):
        request_number = sum(self.requested.values()) + 1
        identity = manual["id"] if manual else f"G{request_number:05d}"
        require(ID.fullmatch(identity) is not None and identity not in self.ids,
                "bad or duplicate request ID")
        self.ids.add(identity)
        require(len(rows) <= 4096 and len(selected) <= 4096, "row/query limit exceeded")
        require(type(head) is int and type(live) is int
                and 0 <= head <= U64_MAX and 0 <= live <= U64_MAX,
                "head/live outside transport u64 domain")
        require(all(type(k) is bytes and len(k) == 20 and type(w) is int
                    and 0 <= w <= U64_MAX for k, w in rows), "bad physical row")
        require(all(type(k) is bytes and len(k) == 20 for k in selected), "bad key")
        row_text = ",".join(k.hex() + ":" + str(w) for k, w in rows) or "-"
        selected_text = ",".join(k.hex() for k in selected) or "-"
        body = "\t".join([str(len(rows)), str(head), str(live), row_text, selected_text])
        self.requested[family] += 1
        if body in self.seen:
            require(manual is None, "manual fixture unexpectedly deduplicated")
            self.aliases.append({"request_id": identity, "family": family,
                                 "canonical_id": self.seen[body],
                                 "input_body_sha256": digest(body.encode("ascii"))})
            return
        result = self.reference.observe(rows, head, live, selected)
        fields = [identity, *map(str, result)]
        if manual is not None:
            require(fields == manual["expected_fields"],
                    "manual expectation mismatch; preserve evidence, do not adjust it")
        line = (identity + "\t" + body + "\n").encode("ascii")
        output = ("\t".join(fields) + "\n").encode("ascii")
        require(len(self.inputs) < MAX_RECORDS, "record limit exceeded; no truncation")
        require(self.input_bytes + len(line) <= MAX_BYTES,
                "byte limit exceeded; no truncation")
        self.seen[body] = identity
        self.inputs.append(line)
        self.expected.append(output)
        self.input_bytes += len(line)
        self.retained[family] += 1
        self.statuses[result[0]] += 1
        self.index.append({"id": identity, "family": family,
                           "expected_provenance": "manual-literal-qualified-reference"
                           if manual else "qualified-mathematical-reference",
                           "input_sha256": digest(line), "expected_sha256": digest(output)})


def populate(corpus, cases):
    for case in cases:
        value = case["input"]
        rows = [(bytes.fromhex(r["key_hex"]), int(r["weight"]))
                for r in value["physical_rows"]]
        require(int(value["capacity"]) == len(rows), "manual capacity mismatch")
        corpus.add("manual", rows, int(value["head"]), int(value["live"]),
                   [bytes.fromhex(k) for k in value["selected_keys"]], manual=case)

    # Complete small ring geometry and every sorted three-key multiset.
    alphabet = [key(1), key(2), key(3)]
    probes = [[], *[[key(i)] for i in range(5)],
              [key(i) for i in (3, 0, 1, 2, 1, 4)]]
    for capacity in range(7):
        for head in range(capacity) if capacity else [0]:
            for live in range(capacity + 1):
                for keys in combinations_with_replacement(alphabet, live):
                    rows = physical([(k, i + 1) for i, k in enumerate(keys)], capacity, head)
                    for selected in probes:
                        corpus.add("small_geometry", rows, head, live, selected)

    # Binary search sizes and both contiguous/wrapped/partially live layouts.
    lengths = (7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65,
               127, 128, 129, 255, 256, 257, 4095, 4096)
    for live in lengths:
        logical = [(key(i + 1), (i * 17 + 3) % 29) for i in range(live)]
        layouts = [(live, 0), (live, live // 2)]
        if live < 4096:
            layouts.append((live + 1, live))
        queries = [[key(max(1, live // 2))],
                   [key(i) for i in (live, 0, 1, max(1, live // 2), live, live + 1)]]
        for capacity, head in layouts:
            for selected in queries:
                corpus.add("search_length", physical(logical, capacity, head),
                           head, live, selected)

    for count in (0, 1, 2, 7, 8, 9, 63, 64, 65, 255, 256, 257, 4095, 4096):
        rows = [(key(1), 1 << 63), (key(2), 1)]
        corpus.add("selected_length", rows, 0, 2, [key(1)] * count)
        corpus.add("selected_length", rows, 0, 2,
                   [key((1, 2, 3, 1)[i % 4]) for i in range(count)])

    # Every key byte position independently determines unsigned ordering.
    for position in range(20):
        def byte_key(value):
            return bytes(position) + bytes([value]) + bytes(19 - position)
        logical = [(byte_key(127), 2), (byte_key(128), 5), (byte_key(255), 9)]
        for head in (0, 2):
            rows = physical(logical, 3, head)
            corpus.add("each_key_byte", rows, head, 3, [byte_key(128)])
            corpus.add("each_key_byte", rows, head, 3,
                       [byte_key(v) for v in (255, 128, 127, 128, 129)])

    weights = (0, 1, 2, U64_MAX // 3, 2 * (U64_MAX // 3),
               2 * (U64_MAX // 3) + 1, (1 << 63) - 1, 1 << 63, U64_MAX - 1, U64_MAX)
    for left in weights:
        for right in weights:
            for selection in ((), (1,), (2,), (1, 1), (1, 2), (2, 1, 2)):
                corpus.add("arithmetic", [(key(1), left), (key(2), right)],
                           0, 2, [key(i) for i in selection])

    for capacity in range(7):
        rows = [(key(capacity - i), i + 1) for i in range(capacity)]
        for head, live in ((capacity or 1, capacity), (U64_MAX, capacity),
                           (0, capacity + 1), (0, U64_MAX)):
            corpus.add("bounds_priority", rows, head, live, [key(1)])
        if capacity >= 2:
            corpus.add("order_refusal", rows, 0, capacity, [key(1)])

    rng = random.Random(SEED)
    for _ in range(64):
        capacity = rng.randrange(1, 32)
        head = rng.randrange(capacity)
        live = rng.randrange(capacity + 1)
        pool = [key(rng.getrandbits(160)) for _ in range(max(1, live // 2))]
        keys = sorted(rng.choice(pool) for _ in range(live))
        logical = [(k, rng.choice((0, 1, U64_MAX, rng.getrandbits(64)))) for k in keys]
        rows = physical(logical, capacity, head)
        selected = [rng.choice(keys) if keys and i % 3 else key(rng.getrandbits(160))
                    for i in range(16)]
        corpus.add("seeded_bit_patterns", rows, head, live, selected)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manual", type=Path, required=True)
    parser.add_argument("--qualification", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    require(not args.output.exists(), "output must not exist")
    reference_path = Path(__file__).with_name("reference_math.py")
    source = reference_path.read_bytes()
    require(digest(source) == REFERENCE_SHA256, "reference identity mismatch")
    freeze_bytes = (args.manual / "MANUAL-FREEZE.json").read_bytes()
    require(digest(freeze_bytes) == MANUAL_FREEZE_SHA256, "manual freeze mismatch")
    freeze = json.loads(freeze_bytes)
    manual = {}
    for entry in freeze["entries"]:
        name = entry["path"]
        require(Path(name).name == name, "manual entry must be a local filename")
        data = (args.manual / name).read_bytes()
        require(len(data) == entry["bytes"] and digest(data) == entry["sha256"],
                "manual bytes changed: " + name)
        manual[name] = data
    qualification_bytes = args.qualification.read_bytes()
    require(digest(qualification_bytes) == QUALIFICATION_SHA256, "qualification identity mismatch")
    qualification = json.loads(qualification_bytes)
    require(qualification["cases"] == 40 and qualification["mismatches"] == 0
            and qualification["reference_sha256"] == REFERENCE_SHA256
            and qualification["manual_freeze_sha256"] == MANUAL_FREEZE_SHA256,
            "reference has not passed the pinned manual qualification")
    reference = types.ModuleType("stake_math_reference")
    reference.__file__ = str(reference_path)
    exec(compile(source, str(reference_path), "exec"), reference.__dict__)
    corpus = Corpus(reference)
    cases = json.loads(manual["cases.json"])["cases"]
    require(len(cases) == 40, "manual case count mismatch")
    populate(corpus, cases)
    require(sum(corpus.requested.values()) == REQUESTS, "planned request count mismatch")
    require(b"".join(corpus.inputs[:40]) == manual["inputs.tsv"], "manual input prefix changed")
    require(b"".join(corpus.expected[:40]) == manual["expected.tsv"], "manual expected prefix changed")
    require(len(corpus.inputs) + len(corpus.aliases) == REQUESTS, "dedup accounting mismatch")

    provenance = {"schema": "stake-corpus-v1", "reference_sha256": REFERENCE_SHA256,
                  "generator_sha256": digest(Path(__file__).read_bytes()),
                  "manual_freeze_sha256": MANUAL_FREEZE_SHA256,
                  "manual_qualification_sha256": QUALIFICATION_SHA256,
                  "host_contract_sha256": HOST_SHA256, "seed": SEED,
                  "manual_entries": freeze["entries"],
                  "limits": "finite conditional value corpus; no native execution or effect trace",
                  "early_stop_limit": "B/S/P cannot distinguish every pure equivalent early stop"}
    encode_json = lambda value: (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
    outputs = {"inputs.tsv": b"".join(corpus.inputs),
               "expected.tsv": b"".join(corpus.expected),
               "index.jsonl": b"".join((json.dumps(row, sort_keys=True) + "\n").encode()
                                          for row in corpus.index),
               "aliases.json": encode_json(corpus.aliases),
               "manual-cases.json": manual["cases.json"],
               "manual-derivations.md": manual["DERIVATIONS.md"],
               "PROVENANCE.json": encode_json(provenance)}
    summary = {"requested": REQUESTS, "retained": len(corpus.inputs),
               "aliases": len(corpus.aliases), "input_bytes": corpus.input_bytes,
               "requested_by_family": dict(corpus.requested),
               "retained_by_family": dict(corpus.retained), "statuses": dict(corpus.statuses),
               "outputs": {name: {"bytes": len(data), "sha256": digest(data)}
                           for name, data in outputs.items()}}
    outputs["SUMMARY.json"] = encode_json(summary)
    args.output.mkdir(parents=True, exist_ok=False)
    for name, data in outputs.items():
        (args.output / name).write_bytes(data)
    print(json.dumps({"requested": REQUESTS, "retained": len(corpus.inputs),
                      "aliases": len(corpus.aliases), "input_bytes": corpus.input_bytes},
                     sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
