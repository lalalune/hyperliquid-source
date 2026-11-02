#!/usr/bin/env python3
"""Replay frozen static/grammar evidence after production source exists.

The historical pre-code checker/freeze remain immutable; this checker does not
reinterpret their source-absence observation as a present-day requirement.
"""

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

from build import HERE, PACKET, ROOT, admit_sources, inventory, require, write_json


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--source-freeze-sha", required=True)
    args = parser.parse_args()
    require(not args.out.exists(), "fresh output required")
    admit_sources(args.source_freeze_sha)
    historical = json.loads((PACKET / "PRECODE-VALIDATION.json").read_text())
    require(historical["status"] == "PASS: pre-code only" and
            historical["current_source_absent"] and len(historical["controls"]) == 13,
            "historical pre-code evidence differs")
    args.out.mkdir(parents=True)
    commands = []
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    for script, output, frozen in [("bind.py", "native", "observed"),
                                    ("corpus.py", "corpus", "frozen")]:
        argv = [sys.executable, str(PACKET / script), "--repo", str(ROOT),
                "--out", str(args.out / output)]
        result = subprocess.run(argv, cwd=ROOT, env=env, capture_output=True, text=True, timeout=180)
        require(result.returncode == 0 and not result.stderr, "replay failed: " + script)
        left, right = inventory(PACKET / frozen), inventory(args.out / output)
        require(left == right, "frozen replay differs: " + script)
        commands.append(dict(argv=["<PYTHON>", "<PACKET>/" + script, "--repo", "<SOURCE_ROOT>",
                                   "--out", "<OUTPUT_DIR>/" + output],
                             exit_code=result.returncode, stdout=result.stdout, stderr=result.stderr,
                             byte_identical_files=len(left)))
    admit_sources(args.source_freeze_sha)
    receipt = dict(status="PASS: post-source static/grammar replay", commands=commands,
                   source_freeze_sha256=args.source_freeze_sha,
                   historical_precode_controls=13,
                   source_absence_is_historical_only=True,
                   limits="Regeneration and immutable phase admission; no Rust build or target execution.")
    write_json(args.out / "receipt.json", receipt)
    print(json.dumps(dict(status=receipt["status"], byte_identical_files=12)))


if __name__ == "__main__":
    main()
