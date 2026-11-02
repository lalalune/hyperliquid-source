#!/usr/bin/env python3
"""Cross-check complete retained instruction boundaries with two static tools."""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import re
import subprocess

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gnu", type=Path, required=True)
    parser.add_argument("--llvm", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    records = json.loads((HERE / "static/records.json").read_bytes())
    target = ROOT / "artifacts/node/94/hl-node"
    if hashlib.sha256(target.read_bytes()).hexdigest() != records["target_sha256"]:
        raise ValueError("target mismatch")
    outputs, commands, results = {}, [], []
    for kind, executable in [("gnu", args.gnu), ("llvm", args.llvm)]:
        version = subprocess.run([str(executable), "--version"], capture_output=True, check=True)
        outputs[kind + "-version.stdout"] = version.stdout.decode()
        outputs[kind + "-version.stderr"] = version.stderr.decode()
        for body in records["bodies"]:
            options = ["-d", "-M", "intel", "--insn-width=15"] if kind == "gnu" else ["-d", "--x86-asm-syntax=intel"]
            command = [str(executable), *options, "--start-address=" + body["start"],
                       "--stop-address=" + body["end"], "artifacts/node/94/hl-node"]
            result = subprocess.run(command, cwd=ROOT, capture_output=True)
            name = kind + "-" + body["start"]
            outputs[name + ".stdout"] = result.stdout.decode()
            outputs[name + ".stderr"] = result.stderr.decode()
            commands.append({"argv": ["@" + kind.upper() + "@", *command[1:]], "exit": result.returncode})
            if result.returncode:
                raise ValueError("disassembler failed")
            rows = []
            for line in result.stdout.decode().splitlines():
                match = re.match(r"\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}(?:\s+|$))+)", line)
                if match:
                    rows.append((int(match[1], 16), bytes.fromhex(match[2]).hex()))
            expected = [(int(row["va"], 16), row["hex"]) for row in body["instructions"]]
            # GNU prints LOCK as its own pseudo-instruction in some versions;
            # only combine that literal one-byte prefix with the next row.
            normalized = []
            index = 0
            while index < len(rows):
                address, code = rows[index]
                if code == "f0" and index + 1 < len(rows) and rows[index + 1][0] == address + 1:
                    normalized.append((address, code + rows[index + 1][1]))
                    index += 2
                else:
                    normalized.append((address, code))
                    index += 1
            if normalized != expected:
                (args.out / (name + "-mismatch.json")).write_text(json.dumps({"actual": normalized, "expected": expected}, indent=2))
                raise ValueError("instruction boundary disagreement: " + name)
            results.append({"tool": kind, "start": body["start"], "end": body["end"],
                            "bytes": body["bytes"], "instructions": len(expected)})
    raw = (json.dumps(outputs, sort_keys=True) + "\n").encode()
    archive = gzip.compress(raw, compresslevel=9, mtime=0)
    (args.out / "raw-disassembly.json.gz").write_bytes(archive)
    summary = {"commands": commands, "results": results,
               "archive_sha256": hashlib.sha256(archive).hexdigest(),
               "archive_raw_sha256": hashlib.sha256(raw).hexdigest(),
               "normalization": "Only standalone f0 prefix rows joined; no bytes removed or changed."}
    (args.out / "result.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps({"bodies": len(records["bodies"]), "tools": 2,
                      "bytes_per_tool": sum(b["bytes"] for b in records["bodies"]),
                      "instructions_per_tool": sum(len(b["instructions"]) for b in records["bodies"])}))


if __name__ == "__main__":
    main()
