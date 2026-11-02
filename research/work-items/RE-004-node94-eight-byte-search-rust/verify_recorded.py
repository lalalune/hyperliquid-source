"""Recheck the retained raw native streams, source bindings, and comparisons."""
import base64
import gzip
import hashlib
import json
import oracle


def check():
    packet = oracle.PACKET
    observed = packet / "observed"
    read = lambda path: json.loads(path.read_text())
    frozen = read(packet / "frozen/ORACLE-FREEZE.json")
    results = read(observed / "results.json")
    commands = read(observed / "commands.json")
    archive = json.loads(gzip.decompress((observed / "raw-streams.json.gz").read_bytes()))
    sha = lambda raw: hashlib.sha256(raw).hexdigest()
    oracle.require(oracle.digest(packet / "oracle.py") == frozen["oracle_source_sha256"], "Oracle changed")
    for field, filename in (("validator_sha256", "validate.py"),
                            ("static_verifier_sha256", "verify_static.py"),
                            ("oracle_freeze_sha256", "frozen/ORACLE-FREEZE.json")):
        oracle.require(oracle.digest(packet / filename) == results[field], f"Changed {filename}")
    for name, digest in results["source_sha256"].items():
        oracle.require(oracle.digest(oracle.ROOT / "src/node94-eight-byte-search" / name) == digest,
                       f"Changed Rust source {name}")
    streams = {}
    for record in archive["streams"]:
        key = record["label"], record["stream"]
        raw = base64.b64decode(record["base64"], validate=True)
        oracle.require(key not in streams and sha(raw) == record["sha256"], "Raw stream changed/duplicated")
        streams[key] = raw
    expected_keys = set()
    for command in commands:
        if command["label"] == "target-frames":
            continue  # This very large upstream stdout is explicitly excerpted.
        for stream in ("stdout", "stderr"):
            key = command["label"], stream
            expected_keys.add(key)
            oracle.require(sha(streams[key]) == command[stream + "_sha256"], "Command stream differs")
        oracle.require(command["returncode"] == 0, "Recorded command failed")
    oracle.require(set(streams) == expected_keys, "Archive coverage changed")
    truth_raw = gzip.decompress((packet / "frozen/expected.txt.gz").read_bytes())
    input_raw = gzip.decompress((packet / "frozen/inputs.tsv.gz").read_bytes())
    oracle.require(sha(truth_raw) == frozen["expected_sha256"] and
                   sha(input_raw) == frozen["inputs_sha256"], "Frozen streams changed")
    truth = truth_raw.splitlines()
    for label, record in list(results["builds"].items()) + [
        ("mutant-" + name, record) for name, record in results["compiled_controls"].items()
    ]:
        raw = streams[label + "-run", "stdout"]
        lines = raw.splitlines()
        oracle.require(sha(raw) == record["output_sha256"] and len(lines) == record["cases"] == len(truth),
                       "Native output binding/count changed")
        oracle.require(sum(a != b for a, b in zip(lines, truth)) == record["mismatches"],
                       "Native mismatch count changed")
    return {"verified_streams": len(streams), "cases_per_run": len(truth),
            "native_runs": len(results["builds"]) + len(results["compiled_controls"])}


if __name__ == "__main__":
    print(json.dumps(check(), indent=2))
