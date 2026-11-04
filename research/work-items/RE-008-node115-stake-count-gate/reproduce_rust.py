#!/usr/bin/env python3
"""Run only independently authored Rust and four compiled wrong programs."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[3]
PACKET = Path(__file__).resolve().parent
CHANGES = {
    "wrong-second-map": ("second_keys.iter().copied()", "first_keys.iter().copied()"),
    "wrapping-sums": ("saturating_add", "wrapping_add"),
    "inclusive-count": ("(matches as f64) > fraction", "(matches as f64) >= fraction"),
    "missing-zero-shortcut": ("if fraction == 0.0 {", "if false {"),
}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--cargo", default="cargo")
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    if any(out.iterdir()):
        raise ValueError("Use a new empty output directory; do not overwrite old controls")
    component = ROOT / "src/node115-stake-count-gate"
    original = (component / "lib.rs").read_text()
    records = []
    environment = dict(os.environ, CARGO_TARGET_DIR=str(out / "target"),
                       CARGO_NET_OFFLINE="true")
    def run(label, argv, expected, cwd):
        result = subprocess.run(argv, cwd=cwd, env=environment,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                timeout=120)
        (out / (label + ".log")).write_bytes(result.stdout)
        records.append({"label":label, "command":argv, "exitCode":result.returncode,
                        "expected":expected,
                        "outputSha256":hashlib.sha256(result.stdout).hexdigest()})
        if result.returncode != expected:
            raise ValueError("Unexpected result: " + label)
    for release in (False, True):
        argv = [args.cargo, "test", "--offline", "--locked", "--manifest-path",
                str(component / "Cargo.toml")]
        if release:
            argv.append("--release")
        run("release" if release else "debug", argv, 0, ROOT)
    for name, (old, new) in CHANGES.items():
        if old not in original:
            raise ValueError("Mutation anchor missing: " + name)
        base = out / name
        dest = base / "src/node115-stake-count-gate"
        shutil.copytree(component, dest)
        (dest / "lib.rs").write_text(original.replace(old,new))
        fixture = base / "research/work-items/RE-008-node115-stake-count-gate"
        fixture.mkdir(parents=True)
        shutil.copyfile(PACKET / "predictions.tsv", fixture / "predictions.tsv")
        argv = [args.cargo, "test", "--offline", "--locked", "--manifest-path",
                str(dest / "Cargo.toml")]
        run(name + "-compiles", argv + ["--no-run"], 0, base)
        run(name + "-rejected", argv, 101, base)
    (out / "results.json").write_text(json.dumps(records, indent=2)+"\n")
    print(json.dumps({"checks":len(records),"allExpected":True}))

if __name__ == "__main__":
    main()
