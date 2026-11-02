#!/usr/bin/env python3
"""Compare compiled safe Rust row-copy output with pre-model native vectors."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
MANIFEST = ROOT / "src/node94-consensus-admission/Cargo.toml"
LOCK = ROOT / "src/node94-consensus-admission/Cargo.lock"
COMPONENT = ROOT / "src/node94-consensus-admission"


def need(test, message):
    if not test:
        raise ValueError(message)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def command(argv, env):
    result = subprocess.run(argv, cwd=ROOT, env=env, text=True,
                            capture_output=True, check=False)
    need(result.returncode == 0, f"command failed {argv}: {result.stderr[:1500]}")
    return {"argv": [str(item) for item in argv], "exit": result.returncode,
            "stdout": result.stdout, "stderr": result.stderr}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cargo", type=Path, required=True)
    parser.add_argument("--rustc", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    freeze = json.loads((HERE / "freeze.json").read_text())
    selected_example = COMPONENT / "examples/qc_row_success_input_only.rs"
    names = [MANIFEST, LOCK, *sorted((COMPONENT / "src").rglob("*.rs")),
             selected_example]
    pins_before = {str(p.relative_to(ROOT)): sha(p) for p in names}
    tool_pins = {str(p): sha(p) for p in (args.rustc, args.cargo)}
    need(not args.out.exists(), "refuse a preexisting result directory")
    args.out.mkdir(parents=True, exist_ok=True)
    compiler = command([args.rustc, "--version", "--verbose"], os.environ.copy())
    need("rustc 1.94.1 " in compiler["stdout"], "unexpected compiler version")
    cargo_version = command([args.cargo, "--version", "--verbose"], os.environ.copy())
    report = {"target_sha256": freeze["target_sha256"],
              "freeze_sha256": sha(HERE / "freeze.json"),
              "project_sources_sha256": pins_before,
              "compiler": compiler, "cargo": cargo_version,
              "tool_sha256": tool_pins,
              "profiles": [], "captured_binary_executed": False,
              "scope": "Only prior successful QC-row fields; tag and recovery supplied as context"}
    for profile in ("debug", "release"):
        target_dir = args.out / f"target-{profile}"
        env = os.environ.copy()
        env.update({"RUSTC": str(args.rustc), "CARGO_TARGET_DIR": str(target_dir),
                    "CARGO_NET_OFFLINE": "true", "RUSTFLAGS": "-D warnings -C overflow-checks=on"})
        build = [args.cargo, "build", "--offline", "--locked", "--manifest-path", MANIFEST,
                 "--example", "qc_row_success_input_only"]
        if profile == "release":
            build.append("--release")
        build_result = command(build, env)
        binary = target_dir / profile / "examples/qc_row_success_input_only"
        need(binary.is_file(), "built example missing")
        dependencies = set()
        pattern = re.escape(str(COMPONENT)) + r"/[^\s\\]+\.rs"
        for dep_info in target_dir.rglob("*.d"):
            dependencies.update(re.findall(pattern, dep_info.read_text()))
        wanted = {str(p) for p in names if p.suffix == ".rs"}
        need(dependencies == wanted, "Cargo project-source closure differs from pinned source set")
        rows = []
        for vector in freeze["vectors"]:
            argv = [binary, vector["source_raw20_hex"], vector["source_group1_hex"],
                    vector["source_group2_hex"], vector["source_recovery_hex"],
                    vector["prefill_byte_hex"]]
            result = command(argv, env)
            actual = result["stdout"].strip()
            need(actual == vector["expected_output_104_hex"],
                 f"Rust output differs for {profile}/{vector['id']}")
            rows.append({"id": vector["id"], "actual_sha256":
                         hashlib.sha256(bytes.fromhex(actual)).hexdigest(),
                         "actual_output_104_hex": actual,
                         "run": result, "passed": True})
        report["profiles"].append({"name": profile, "build": build_result,
                                   "binary_sha256": sha(binary),
                                   "compiler_project_sources": sorted(dependencies),
                                   "vectors": rows})
    pins_after = {str(p.relative_to(ROOT)): sha(p) for p in names}
    need(pins_after == pins_before, "project source changed during comparison")
    need({str(p): sha(p) for p in (args.rustc, args.cargo)} == tool_pins,
         "compiler or Cargo changed during comparison")
    report["project_sources_after_sha256"] = pins_after
    output = args.out / "RUST-RESULTS.json"
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"profiles": [(p["name"], len(p["vectors"])) for p in report["profiles"]],
                      "source_unchanged": True, "captured_binary_executed": False},
                     sort_keys=True))


if __name__ == "__main__":
    main()
