#!/usr/bin/env python3
"""Independently compare selected Capstone partitions/FDEs with GNU tools."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

import extract

P = Path(__file__).resolve().parent


def main():
    a = argparse.ArgumentParser(description=__doc__)
    a.add_argument("--binary", type=Path, default=extract.ROOT / "artifacts/node/115/hl-node")
    a.add_argument("--objdump", default="objdump")
    a.add_argument("--readelf", default="readelf")
    args = a.parse_args()
    data = args.binary.read_bytes()
    extract.identity(data)
    report = extract.analyze(data)
    expected = json.loads((P / "field-layout.json").read_text(encoding="utf-8"))
    extract.need(report == expected, "Retained report drift")
    contexts = [report["outer"], *report["directCalleeContexts"]]
    versions = {}
    for name in ("objdump", "readelf"):
        value = getattr(args, name)
        p = subprocess.run([value, "--version"], capture_output=True, text=True,
                           encoding="utf-8", timeout=10, check=True)
        versions[name] = p.stdout.splitlines()[0]
    raw = []
    total_instructions = 0
    for ordinal, record in enumerate(contexts, 1):
        print(f"$ GNU partition {ordinal}/{len(contexts)} {record['start']}", flush=True)
        command = [args.objdump, "-d", "-w", "--insn-width=16", "-Mintel",
                   "--start-address=" + record["start"], "--stop-address=" + record["end"],
                   str(args.binary)]
        p = subprocess.run(command, capture_output=True, text=True, encoding="utf-8",
                           timeout=30, check=True)
        # Preserve exact decoded lines; replace only the local artifact path banner.
        text = p.stdout.replace(str(args.binary), "<authenticated-node115>")
        rows = []
        for line in text.splitlines():
            match = re.match(r"\s*([0-9a-f]+):\s+((?:[0-9a-f]{2} )*[0-9a-f]{2})(?:\s|\t)", line)
            if match:
                rows.append((hex(int(match[1], 16)), match[2].replace(" ", "")))
        want = [(x["va"], x["bytes"]) for x in record["instructions"]]
        extract.need(rows == want, f"GNU/Capstone partition mismatch at {record['start']}")
        total_instructions += len(rows)
        raw.append("$ objdump -d -w --insn-width=16 -Mintel --start-address="
                   + record["start"] + " --stop-address=" + record["end"]
                   + " <authenticated-node115>\n" + text)
    (P / "gnu-contexts.txt").write_text("\n".join(raw), encoding="utf-8", newline="\n")
    print("$ GNU readelf independently checks selected actual FDE extents", flush=True)
    p = subprocess.run([args.readelf, "--debug-dump=frames", str(args.binary)],
                       capture_output=True, timeout=120, check=True)
    frames = p.stdout.decode("utf-8")
    wanted = {(int(x["start"], 16), int(x["end"], 16)) for x in contexts}
    retained = []
    found = set()
    for block in re.split(r"\n\s*\n", frames):
        match = re.search(r"FDE .*pc=([0-9a-fA-F]+)\.\.([0-9a-fA-F]+)", block)
        if match:
            pair = (int(match[1], 16), int(match[2], 16))
            if pair in wanted:
                extract.need(pair not in found, "Duplicate GNU selected FDE")
                found.add(pair)
                retained.append(block)
    extract.need(found == wanted, "GNU FDE extent mismatch/missing range")
    (P / "gnu-frames.txt").write_text("\n\n".join(retained) + "\n", encoding="utf-8", newline="\n")
    result = {"targetSha256": extract.TARGET_SHA, "versions": versions,
              "capstone": extract.capstone.__version__, "selectedFdes": len(contexts),
              "selectedBytes": sum(x["size"] for x in contexts),
              "partitionInstructions": total_instructions, "partitionMismatches": 0,
              "gnuFdeExtentMismatches": 0,
              "fullReadelfStdoutSha256": hashlib.sha256(p.stdout).hexdigest(),
              "targetExecuted": False, "targetEmulated": False,
              "denominator": "One outer serializer plus62 direct-callee contexts; no deep helper closure, compiled Rust comparison or whole-component coverage"}
    (P / "static-validation.json").write_text(json.dumps(result, indent=2) + "\n",
                                              encoding="utf-8", newline="\n")
    print(json.dumps(result), flush=True)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        print(f"state-encoder-contexts: {error}", file=sys.stderr)
        sys.exit(1)
