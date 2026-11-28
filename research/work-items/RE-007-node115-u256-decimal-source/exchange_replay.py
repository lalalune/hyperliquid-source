#!/usr/bin/env python3
"""Compare the public exchange scaler before and after the ownership correction."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BASE = "2da45cb0a761cff6b478e40421699857d87a94df"
TOOLCHAIN = "1.95.0"


def rust_tool(name):
    return subprocess.check_output(["rustup", "which", "--toolchain", TOOLCHAIN, name],
                                   text=True).strip()


def replay(root, work, corpus):
    """Build the ordinary path dependency, then feed its public API the frozen corpus."""
    client = work / "client"
    client.mkdir(parents=True)
    lib = json.dumps(str(root / "src/exchange"))
    (client / "Cargo.toml").write_text(
        '[package]\nname = "exchange-scaler-replay"\nversion = "0.0.0"\nedition = "2021"\n'
        f'[[bin]]\nname = "exchange-scaler-replay"\npath = "client.rs"\n'
        f'[dependencies]\nexchange = {{ path = {lib} }}\n[workspace]\n'
    )
    (client / "client.rs").write_bytes((HERE / "exchange_client.rs").read_bytes())
    env = dict(os.environ, RUSTC=rust_tool("rustc"), CARGO_TARGET_DIR=str(work / "target"))
    cargo = rust_tool("cargo")
    subprocess.run([cargo, "generate-lockfile", "--offline", "--quiet"], cwd=client, env=env, check=True)
    output = []
    for profile in ([], ["--release"]):
        raw = subprocess.check_output([cargo, "run", "--frozen", "--quiet", *profile],
                                      input=corpus, cwd=client, env=env)
        output.append(json.loads(raw))
    if output[0] != output[1]:
        raise ValueError("debug and release exchange outputs differ")
    return output[0]


def main():
    oracle = ROOT / "src/node115-u256-decimal-scale/tests/reference.py"
    corpus = subprocess.check_output([sys.executable, str(oracle)])
    with tempfile.TemporaryDirectory(prefix="exchange-scaler-") as directory:
        work = Path(directory)
        baseline = work / "baseline"
        baseline.mkdir()
        archive = work / "sources.tar"
        subprocess.run(["git", "-C", ROOT, "archive", "--format=tar", "-o", archive, BASE, "src"],
                       check=True)
        with tarfile.open(archive) as sources:
            sources.extractall(baseline, filter="data")
        before = replay(baseline, work / "before", corpus)
        after = replay(ROOT, work / "after", corpus)
    report = {
        "base_commit": BASE,
        "corpus_sha256": hashlib.sha256(corpus).hexdigest(),
        "profiles": ["debug", "release"],
        "before": before,
        "after": after,
    }
    expected = json.loads((HERE / "exchange-results.json").read_text())
    if report != expected:
        raise ValueError(f"recorded results differ\n{json.dumps(report, indent=2)}")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
