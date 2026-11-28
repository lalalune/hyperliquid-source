#!/usr/bin/env python3
"""Build published Decimal sources in fresh directories and replay the #115 comparison."""
import argparse
from decimal import Decimal
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import tomllib

from compare import ROOT, TARGET_SHA, capture, compare, digest, require

HERE = Path(__file__).resolve().parent
REFERENCE = HERE / "reference"
VECTORS = ROOT / "src/node115-quantity-preparation/target-vectors.tsv"
TARGET = "x86_64-unknown-linux-gnu"
VERSION = "1.95.0"


def rust_tool(tool):
    return subprocess.check_output(["rustup", "which", "--toolchain", VERSION, tool], text=True).strip()


def build(work, label, lock, checked, ar, fetch, captured):
    project = work / label
    shutil.copytree(REFERENCE, project)
    shutil.copyfile(REFERENCE / lock, project / "Cargo.lock")
    packages = tomllib.loads((project / "Cargo.lock").read_text())["package"]
    decimal, = [p for p in packages if p["name"] == "rust_decimal"]
    env = os.environ.copy()
    for key in ("CARGO_ENCODED_RUSTFLAGS", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER"):
        env.pop(key, None)
    env.update(RUSTC=rust_tool("rustc"), RUSTDOC=rust_tool("rustdoc"), RUSTFLAGS="",
               CARGO_TARGET_DIR=str(project / "target"), CARGO_PROFILE_RELEASE_OPT_LEVEL="3",
               CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS=str(checked).lower())
    cargo = rust_tool("cargo")
    if fetch:
        subprocess.run([cargo, "fetch", "--locked"], cwd=project, env=env, check=True)
    subprocess.run([cargo, "build", "--release", "--frozen", "--target", TARGET, "-p", "rust_decimal"],
                   env=env, cwd=project, check=True)
    archive, = (project / "target" / TARGET / "release/deps").glob("librust_decimal-*.rlib")
    compared = compare(ar, archive, captured)
    summary = {"crate": decimal["name"], "version": decimal["version"],
               "crate_sha256": decimal["checksum"], "overflow_checks": checked}
    if label in ("primary", "other-release"):
        # Execute only the authored comparator and published crates on the host.
        corpus = VECTORS.read_bytes()
        rendered = subprocess.check_output([cargo, "run", "--frozen", "--release", "--quiet"],
                                           input=corpus, env=env, cwd=project)
        expected = bytearray()
        for row in corpus.splitlines():
            raw = int(row.split(b"\t", 1)[0])
            exact = format(Decimal(raw).scaleb(-8).normalize(), "f")
            expected.extend(f"{raw}\t{exact}\n".encode("ascii"))
        require(rendered == expected, "public Decimal differs from the independent scalar model")
        summary.update(corpus_sha256=digest(corpus), rendered_rows=len(corpus.splitlines()),
                       rendered_tsv_sha256=digest(rendered))
    return compared, summary


def replay(work, ar, fetch):
    captured = capture()
    jobs = [
        ("primary", "Cargo.lock", True),
        ("repeat", "Cargo.lock", True),
        ("other-release", "control-1.39.lock", True),
        ("unchecked", "Cargo.lock", False),
    ]
    runs, comparisons = {}, {}
    for label, lock, checked in jobs:
        compared, summary = build(work, label, lock, checked, ar, fetch, captured)
        comparison_id = "checked" if checked else "unchecked"
        if comparison_id in comparisons:
            require(compared == comparisons[comparison_id], f"{label} differs from the primary source build")
        else:
            comparisons[comparison_id] = compared
        runs[label] = dict(summary, comparison=comparison_id)
    return {"node115_sha256": TARGET_SHA, "captured_node_executed": False,
            "rustc": subprocess.check_output([rust_tool("rustc"), "-V"], text=True).strip(),
            "linux_target": TARGET, "runs": runs, "comparisons": comparisons}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ar", default=shutil.which("llvm-ar") or "ar", help="GNU ar or LLVM ar executable")
    parser.add_argument("--fetch", action="store_true", help="provision locked public packages before offline builds")
    parser.add_argument("--record", action="store_true", help="print fresh JSON for review")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="decimal-display-") as tmp:
        report = replay(Path(tmp), args.ar, args.fetch)
    if args.record:
        print(json.dumps(report, sort_keys=True, indent=2))
        return
    require(report == json.loads((HERE / "results.json").read_text()), "recorded evidence differs from replay")
    checked = report["comparisons"]["checked"]["digits"]
    print(f"Both releases: {checked['raw_equal_bytes']}/{checked['target_bytes']} raw bytes equal; "
          f"{checked['bytes_outside_relocations']} bytes outside {len(checked['relocations'])} relocations, "
          f"{checked['unmasked_difference_count']} differences.")
    print("Reproduced repeat build, neighboring wrapper, unchecked profile and both 2,540-row text comparisons.")


if __name__ == "__main__":
    main()
