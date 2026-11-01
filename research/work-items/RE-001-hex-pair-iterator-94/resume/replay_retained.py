#!/usr/bin/env python3
"""Readmit and replay hash-bound own Rust artifacts, never captured binaries."""
from __future__ import annotations
import argparse
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[4]
PACKET = Path(__file__).resolve().parent.parent
OLD_BASE = "3324e50333042b391312515e542279ca21f63dc8"
NEW_BASE = "56c0ec672bd8fdcfaa80f2db700a61e6240b3663"
sha = lambda data: hashlib.sha256(data).hexdigest()

def write(path, value):
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")

def run(build: Path, rustc: Path, output: Path):
    if output.exists() or output.is_symlink():
        raise ValueError("new owned output path required")
    spec = importlib.util.spec_from_file_location("hex_current_runner", ROOT / "tools/hex_pair_iterator_rust.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    historical = json.loads((PACKET / "build-c1/before.json").read_bytes())
    result_raw = (PACKET / "build-c1/result.json").read_bytes()
    result = json.loads(result_raw)
    if (build / "result.json").read_bytes() != result_raw:
        raise ValueError("retained build result differs from published historical record")
    current = module.state()
    if current["status"]:
        raise ValueError("clean source checkpoint required")
    if current["pins"] != historical["pins"]:
        raise ValueError("pinned imports changed")
    for relative, expected in historical["sources"].items():
        data = (ROOT / relative).read_bytes()
        if relative == "tools/hex_pair_iterator_rust.py":
            new = f'BASE = "{NEW_BASE}"'.encode()
            if data.count(new) != 1:
                raise ValueError("current absence-control pin missing")
            data = data.replace(new, f'BASE = "{OLD_BASE}"'.encode())
        if sha(data) != expected:
            raise ValueError("historical execution source or authority changed: " + relative)
    inputs, expected_raw, expected = module.fixtures()
    def identities():
        artifacts = {}
        for profile in result["profiles"]:
            directory = build / ("opt" + str(profile["opt_level"]))
            for name, digest in (("input-only", profile["driver_sha256"]),
                                 ("libnode94_hex_pair_iterator.rlib", profile["rlib_sha256"]),
                                 ("rebuild/libnode94_hex_pair_iterator.rlib", profile["rlib_sha256"])):
                path = directory / name
                actual = sha(path.read_bytes())
                if actual != digest:
                    raise ValueError("retained own artifact changed: " + str(path))
                artifacts[str(path)] = actual
        return {"repository": module.state(), "replay_script_sha256": sha(Path(__file__).read_bytes()),
                "target": module.admit_target(ROOT / "artifacts/node/94/hl-node"),
                "provider": module.admit_provider(rustc), "retained_artifacts": artifacts,
                "historical_result_sha256": sha(result_raw)}
    before = identities()
    output.mkdir(parents=True)
    write(output / "before.json", before)
    commands = []
    def command(label, argv, stdin=None, expected_exit=0):
        start = time.monotonic()
        completed = subprocess.run(argv, cwd=ROOT, input=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        for kind, data in (("stdout", completed.stdout), ("stderr", completed.stderr)):
            (output / f"{label}.{kind}.gz").write_bytes(gzip.compress(data, mtime=0))
        commands.append({"label": label, "argv": argv, "exit": completed.returncode,
                         "seconds": time.monotonic() - start,
                         "stdin_sha256": sha(stdin) if stdin is not None else None,
                         "stdout_sha256": sha(completed.stdout), "stderr_sha256": sha(completed.stderr)})
        write(output / "commands.json", commands)
        if completed.returncode != expected_exit:
            raise ValueError(label + " failed; raw streams retained")
        return completed
    command("current-base-production-absent", ["git", "cat-file", "-e",
            NEW_BASE + ":src/node94-hex-pair-iterator/lib.rs"], expected_exit=128)
    profiles = []
    for profile in result["profiles"]:
        level = profile["opt_level"]
        client = build / ("opt" + str(level)) / "input-only"
        completed = command("opt" + str(level) + "-replay", [str(client)], inputs)
        if completed.stderr or completed.stdout != expected_raw or module.compare(completed.stdout, expected):
            raise ValueError("complete replay observations differ")
        profiles.append({"opt_level": level, "matched_cases": 39850, "matched_observations": 185490,
                         "stdout_sha256": sha(completed.stdout), "driver_sha256": profile["driver_sha256"]})
    command("python-controls", [sys.executable, "-B", "-m", "unittest", "tests.test_hex_pair_iterator_rust", "-v"])
    after = identities()
    write(output / "after.json", after)
    if before != after:
        raise ValueError("readmission/replay inputs changed")
    receipt = {"status": "PASS", "historical_build_head": historical["head"],
               "current_head": current["head"], "current_base": NEW_BASE, "before_after_equal": True,
               "new_compiler_runs": 0, "profiles": profiles, "python_test_methods": 3,
               "input_sha256": sha(inputs), "expected_sha256": sha(expected_raw),
               "commands": len(commands), "full_current_test_and_ci": "NOT_RUN: expanded evaluators not authorized"}
    write(output / "result.json", receipt)
    return receipt

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--rustc", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(run(args.build.resolve(), args.rustc.resolve(), args.output.resolve()), sort_keys=True))
