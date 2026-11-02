#!/usr/bin/env python3
"""Independent finite oracle for the conditional value/effect projection.

The fold expectation uses the first index in a terminal set, rather than
executing the native loop. No target instruction evaluator is imported.
"""
import gzip
import hashlib
import itertools
import json
from pathlib import Path
import random

HERE = Path(__file__).resolve().parent
SUCCESS = (1 << 63) + 42
STOP = SUCCESS + 1
MASK = (1 << 64) - 1


def record(tag, salt, size=80):
    return tag.to_bytes(8, "little") + bytes(
        (salt * 29 + i * 73 + (i * i >> 2)) & 255 for i in range(size - 8))


def tag(data):
    return int.from_bytes(data[:8], "little")


def expected_fold(folder, initial_flag, observations):
    if not observations:
        return f"F {folder.hex()} {initial_flag} 0 0 0 0 -"
    old = tag(folder)
    # Once either an incoming error or a preexisting error is consumed, this
    # local fold cannot execute another verifier call. A STOP result exits
    # before any reduction, byte store or byte read.
    terminal = {i for i, (value, flag) in enumerate(observations)
                if tag(value) == STOP or old != SUCCESS
                or tag(value) != SUCCESS or flag != 0}
    last = min(terminal) if terminal else len(observations) - 1
    value, flag = observations[last]
    value_tag = tag(value)
    marker = value_tag == STOP
    local_error = not marker and (old != SUCCESS or value_tag != SUCCESS)
    reads = last + (0 if marker or local_error else 1)
    drops = value.hex() if local_error and old != SUCCESS and value_tag != SUCCESS else "-"
    new_record = value if local_error and old == SUCCESS else folder[:80]
    result = new_record + folder[80:]
    stop_reason = 1 if marker else 2 if local_error else 3 if flag != 0 else 0
    return f"F {result.hex()} {1 if local_error else flag} {last + 1} {reads} {int(local_error)} {stop_reason} {drops}"


def expected_merge(out, left, right):
    # Truth-table projection: TT writes only the tag, FT/FF select left,
    # TF selects right. The second error is delegated to drop only for FF.
    key = (tag(left) == SUCCESS, tag(right) == SUCCESS)
    selected = {(False, False): left, (False, True): left, (True, False): right}
    if key == (True, True):
        result = SUCCESS.to_bytes(8, "little") + out[8:]
        width = 8
    else:
        result = selected[key]
        width = 80
    drop = right.hex() if key == (False, False) else "-"
    return f"M {result.hex()} {width} {drop}"


def expected_plan(length, producer, minimum, splits, migrated, cancel, threads):
    # Four disjoint regions over unbounded integers. This is one bridge step,
    # not a prediction of task scheduling, TLS or worker-pool state.
    half = length // 2
    eligible = half >= minimum
    splitting = eligible and (migrated != 0 or splits != 0)
    worker_read = int(cancel == 0 and eligible and migrated != 0)
    next_splits = max(threads, splits // 2) if migrated else splits // 2
    if cancel:
        return "P 0 0 0 0 0 0"
    if not splitting:
        return f"P 1 0 0 0 {(184 * producer) % (1 << 64)} 0"
    if half > producer:
        return f"P 3 {half} 0 {next_splits} 0 {worker_read}"
    return f"P 2 {half} {producer - half} {next_splits} {(184 * half) % (1 << 64)} {worker_read}"


def cases():
    serial = 0
    for old in [SUCCESS, 0, (1 << 63) + 1, STOP]:
        for n in range(5):
            for sequence in itertools.product([SUCCESS, (1 << 63) + 1, STOP], repeat=n):
                for flag_pattern in [0, 1, 255]:
                    folder = record(old, serial, 96)
                    obs = [(record(t, serial + j + 1), flag_pattern if j == n // 2 else 0)
                           for j, t in enumerate(sequence)]
                    initial = serial % 256
                    fields = " ".join(f"{v.hex()} {f}" for v, f in obs)
                    line = f"F {folder.hex()} {initial} {n}" + (" " + fields if fields else "")
                    yield f"fold-enumerated-{serial}", line, expected_fold(folder, initial, obs)
                    serial += 1
    rng = random.Random(0x94_4768F80)
    tags = [0, 1, (1 << 63) - 1, 1 << 63, (1 << 63) + 1,
            (1 << 63) + 39, (1 << 63) + 40, (1 << 63) + 41,
            SUCCESS, STOP, STOP + 1, MASK]
    for i in range(2048):
        folder = record(rng.choice(tags + [SUCCESS] * 30), rng.getrandbits(16), 96)
        n = rng.randrange(65)
        obs = [(record(rng.choice(tags + [SUCCESS] * 40), rng.getrandbits(16)),
                rng.choice([0] * 50 + [1, 2, 127, 128, 255])) for _ in range(n)]
        initial = rng.randrange(256)
        fields = " ".join(f"{v.hex()} {f}" for v, f in obs)
        line = f"F {folder.hex()} {initial} {n}" + (" " + fields if fields else "")
        yield f"fold-wide-{i}", line, expected_fold(folder, initial, obs)
    for i, (a, b) in enumerate(itertools.product(tags, repeat=2)):
        out, left, right = record(0x1234, i), record(a, i + 1), record(b, i + 2)
        yield f"merge-{i}", f"M {out.hex()} {left.hex()} {right.hex()}", expected_merge(out, left, right)
    lengths = [0, 1, 2, 3, 4, 7, 8, 31, 32, (1 << 32) - 1, 1 << 32, 1 << 63, MASK]
    for i, values in enumerate(itertools.product(lengths, [0, 1, 2, MASK], [0, 1, 3, MASK], [0, 1, 2, 255])):
        length, minimum, splits, byte = values
        producer = length
        params = (length, producer, minimum, splits, byte, 0, 7)
        yield f"plan-grid-{i}", "P " + " ".join(map(str, params)), expected_plan(*params)
    for flag in range(256):
        params = (MASK, 0, 0, MASK, 255, flag, MASK)
        yield f"plan-flag-{flag}", "P " + " ".join(map(str, params)), expected_plan(*params)
    for i in range(2048):
        length = rng.getrandbits(64)
        producer = rng.choice([length, length // 2, max(0, length // 2 - 1), rng.getrandbits(64)])
        params = (length, producer, rng.choice([0, 1, length // 2, length // 2 + 1]),
                  rng.choice([0, 1, rng.getrandbits(64)]), rng.randrange(256),
                  rng.choice([0] * 20 + [1, 2, 255]), rng.getrandbits(64))
        yield f"plan-wide-{i}", "P " + " ".join(map(str, params)), expected_plan(*params)


def freeze():
    if (HERE / "rust").exists():
        raise ValueError("pre-source freeze refuses an existing Rust directory")
    out = HERE / "frozen"
    out.mkdir(exist_ok=False)
    rows = list(cases())
    files = {
        "inputs.txt.gz": "".join(r[1] + "\n" for r in rows).encode(),
        "expected.txt.gz": "".join(r[2] + "\n" for r in rows).encode(),
        "labels.json.gz": (json.dumps([r[0] for r in rows]) + "\n").encode(),
    }
    manifest = []
    for name, raw in files.items():
        encoded = gzip.compress(raw, compresslevel=9, mtime=0)
        (out / name).write_bytes(encoded)
        manifest.append({"path": name, "bytes": len(encoded),
                         "sha256": hashlib.sha256(encoded).hexdigest(),
                         "raw_bytes": len(raw), "raw_sha256": hashlib.sha256(raw).hexdigest()})
    pins = ["oracle.py", "static.py", "static/records.json", "sources/acquisition.json",
            "sources/try_reduce.rs", "sources/plumbing.rs"]
    record = {"cases": len(rows), "operations": {k: sum(r[1][0] == k for r in rows) for k in "FMP"},
              "rust_absent_at_freeze": True, "files": manifest,
              "pins": {p: hashlib.sha256((HERE / p).read_bytes()).hexdigest() for p in pins},
              "scope": "Independent conditional supplied-outcome/observed-byte oracle; no cryptography, scheduler or captured execution."}
    (out / "freeze.json").write_text(json.dumps(record, indent=2) + "\n")
    print(json.dumps(record))


if __name__ == "__main__":
    freeze()
