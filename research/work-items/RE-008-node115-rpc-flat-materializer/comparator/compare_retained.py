"""Compare already captured RPC child results; this program launches nothing.

Unexecuted draft pending source/effects admission. Parent must pin this module
and value_compare before import. All raw files and process receipt must already
exist, be retained, and be hash-bound by an actual external parent harness.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re

from value_compare import AdmissionError, MAX_BYTES, compare_prepared, prepare

HASH_RE = re.compile(r"[0-9a-f]{64}")
EXIT_CODES = {"match": 0, "semantic_mismatch": 1, "admission_failure": 2,
              "process_failure": 3, "protocol_failure": 4}


def pinned_file(path, expected_hash, retain_limit):
    """Hash all raw bytes with bounded memory, including oversized failed output."""
    if not HASH_RE.fullmatch(expected_hash):
        raise AdmissionError("noncanonical SHA256 argument")
    digest = hashlib.sha256()
    size = 0
    retained = bytearray()
    with path.open("rb") as handle:
        while True:
            block = handle.read(1 << 20)
            if not block:
                break
            digest.update(block)
            size += len(block)
            if retained is not None:
                if size <= retain_limit:
                    retained.extend(block)
                else:
                    retained = None
    actual = digest.hexdigest()
    if actual != expected_hash:
        raise AdmissionError("retained file SHA256 mismatch: " + path.name)
    return (bytes(retained) if retained is not None else None,
            {"bytes": size, "sha256": actual})


def admit_process(raw, identities):
    if raw is None:
        raise AdmissionError("process receipt exceeds64KiB")
    try:
        receipt = json.loads(raw)
    except ValueError as exc:
        raise AdmissionError("invalid process receipt JSON") from exc
    if type(receipt) is not dict or type(receipt.get("schema")) is not int or receipt["schema"] != 1:
        raise AdmissionError("process receipt schema mismatch")
    if receipt.get("captured_before_comparison") is not True:
        raise AdmissionError("raw capture chronology is not declared")
    status = receipt.get("process_status")
    returncode = receipt.get("returncode")
    if status not in ("completed", "timeout", "launch_error"):
        raise AdmissionError("process receipt status invalid")
    if status == "completed" and type(returncode) is not int:
        raise AdmissionError("completed child requires integer returncode")
    if status != "completed" and returncode is not None and type(returncode) is not int:
        raise AdmissionError("failed child returncode must be integer or null")
    executable_hash = receipt.get("executable_sha256")
    if type(executable_hash) is not str or not HASH_RE.fullmatch(executable_hash):
        raise AdmissionError("missing canonical executable identity")
    for field, label in (("stdin_sha256", "inputs"), ("stdout_sha256", "stdout"), ("stderr_sha256", "stderr")):
        if receipt.get(field) != identities[label]["sha256"]:
            raise AdmissionError("process receipt/raw binding mismatch: " + field)
    return {"process_status": status, "returncode": returncode,
            "executable_sha256": executable_hash,
            "chronology_limit": "Receipt declaration is not independent execution proof; actual parent capture/launch records remain required."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for label in ("inputs", "expected", "stdout", "stderr", "process_receipt"):
        option = label.replace("_", "-")
        parser.add_argument("--" + option, type=Path, required=True)
        parser.add_argument("--" + option + "-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output must be a fresh directory")
    identities = {}
    process = None
    try:
        data = {}
        for label, limit in (("inputs", MAX_BYTES), ("expected", MAX_BYTES),
                             ("stdout", MAX_BYTES), ("stderr", 0), ("process_receipt", 65536)):
            data[label], identities[label] = pinned_file(
                getattr(args, label), getattr(args, label + "_sha256"), limit)
        process = admit_process(data["process_receipt"], identities)
        if data["inputs"] is None or data["expected"] is None:
            raise AdmissionError("input/expected file exceeds admitted bound")
        frames, expected = prepare(data["inputs"], data["expected"])
        if process["process_status"] != "completed" or process["returncode"] != 0:
            result = {"classification": "process_failure", "semantic_mismatch_count": None,
                      "semantic_mismatches": [], "reason": "No value detection is counted for child failure."}
        elif data["stdout"] is None:
            result = {"classification": "protocol_failure", "semantic_mismatch_count": None,
                      "semantic_mismatches": [], "protocol_error": "actual stdout exceeds admitted stream bound"}
        else:
            result = compare_prepared(frames, expected, data["stdout"])
    except (AdmissionError, OSError) as exc:
        result = {"classification": "admission_failure", "semantic_mismatch_count": None,
                  "semantic_mismatches": [], "admission_error": str(exc)}
    sources = {name: hashlib.sha256((Path(__file__).parent / name).read_bytes()).hexdigest()
               for name in ("value_compare.py", "compare_retained.py")}
    result.update({"schema": 1, "retained_files": identities, "process": process,
                   "source_sha256": sources,
                   "limits": ["No executable was launched by this comparator.",
                              "Expected data are parent-only, not supplied to the child.",
                              "Native, lifetime, allocation and execution-trace equivalence are not tested.",
                              "Actual launch/raw capture and source pre-import admission remain external requirements."]})
    args.output.mkdir(parents=True, exist_ok=False)
    encoded = (json.dumps(result, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode("ascii")
    with (args.output / "result.json").open("xb") as handle:
        handle.write(encoded)
    print(json.dumps({"classification": result["classification"],
                      "semantic_mismatch_count": result["semantic_mismatch_count"],
                      "result_sha256": hashlib.sha256(encoded).hexdigest()}, sort_keys=True))
    return EXIT_CODES[result["classification"]]


if __name__ == "__main__":
    raise SystemExit(main())
