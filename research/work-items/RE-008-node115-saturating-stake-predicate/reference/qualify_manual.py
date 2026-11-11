#!/usr/bin/env python3
"""Qualify the reviewed mathematical reference against pre-reference literals.

Reads only the pinned local reference and pinned manual files. Writes a fresh
result directory. No subprocess, network, target input or project-model import.
Execution requires the separate parent review/admission; this is only a draft.
"""

import argparse
import hashlib
import json
from pathlib import Path
import types

REFERENCE_SHA256 = "3bc9d4e1474b475b0a1b8911cabe59c60d85fa64de5c8dfe7c86ffe3d82c079b"
MANUAL_FREEZE_SHA256 = "eec1e900dd60abb77deda2d5aaabcf54ee87fb1f1d790ea5013aedce77a4f40f"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manual", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    reference_path = Path(__file__).with_name("reference_math.py")
    source = reference_path.read_bytes()
    require(digest(source) == REFERENCE_SHA256, "reference identity mismatch")
    freeze_bytes = (args.manual / "MANUAL-FREEZE.json").read_bytes()
    require(digest(freeze_bytes) == MANUAL_FREEZE_SHA256, "manual freeze mismatch")
    freeze = json.loads(freeze_bytes)
    buffers = {}
    for entry in freeze["entries"]:
        name = entry["path"]
        require(Path(name).name == name, "manual entry must be a local filename")
        data = (args.manual / name).read_bytes()
        require(len(data) == entry["bytes"] and digest(data) == entry["sha256"],
                "manual entry mismatch: " + name)
        buffers[name] = data
    cases = json.loads(buffers["cases.json"])["cases"]
    require(len(cases) == freeze["case_count"] == 40, "manual case count changed")

    # Compile exactly the authenticated source buffer; no cached bytecode loader.
    reference = types.ModuleType("stake_math_reference")
    reference.__file__ = str(reference_path)
    exec(compile(source, str(reference_path), "exec"), reference.__dict__)

    results = []
    reconstructed_inputs = []
    reconstructed_expected = []
    for case in cases:
        value = case["input"]
        rows = [(bytes.fromhex(r["key_hex"]), int(r["weight"]))
                for r in value["physical_rows"]]
        require(int(value["capacity"]) == len(rows), "manual capacity mismatch")
        selected = [bytes.fromhex(key) for key in value["selected_keys"]]
        result = reference.observe(rows, int(value["head"]), int(value["live"]), selected)
        actual = [case["id"], *map(str, result)]
        results.append({"id": case["id"], "expected_fields": case["expected_fields"],
                        "actual_fields": actual, "match": actual == case["expected_fields"]})
        row_text = ",".join(r["key_hex"] + ":" + r["weight"]
                            for r in value["physical_rows"]) or "-"
        selected_text = ",".join(value["selected_keys"]) or "-"
        reconstructed_inputs.append("\t".join([case["id"], value["capacity"],
                                    value["head"], value["live"], row_text, selected_text]) + "\n")
        reconstructed_expected.append("\t".join(case["expected_fields"]) + "\n")
    require("".join(reconstructed_inputs).encode("ascii") == buffers["inputs.tsv"],
            "manual input serialization differs")
    require("".join(reconstructed_expected).encode("ascii") == buffers["expected.tsv"],
            "manual expected serialization differs")
    mismatches = sum(not row["match"] for row in results)
    output = {"scope": "mathematical reference against frozen manual value examples only",
              "reference_sha256": REFERENCE_SHA256,
              "manual_freeze_sha256": MANUAL_FREEZE_SHA256,
              "cases": len(results), "mismatches": mismatches, "results": results,
              "captured_execution_or_emulation": False,
              "transport_or_rust_qualification": False}
    args.output.mkdir(parents=True, exist_ok=False)
    (args.output / "RESULT.json").write_text(json.dumps(output, indent=2) + "\n")
    print(json.dumps({"cases": len(results), "mismatches": mismatches,
                      "passed": mismatches == 0}, sort_keys=True))
    return 1 if mismatches else 0


if __name__ == "__main__":
    raise SystemExit(main())
