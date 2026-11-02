#!/usr/bin/env python3
"""Replay retained static/oracle/native evidence, without recompiling or network."""
import base64
import gzip
import hashlib
import importlib.util
import json
import lzma
from pathlib import Path

HERE = Path(__file__).resolve().parent


def sha(data):
    return hashlib.sha256(data).hexdigest()


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    obj = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(obj)
    return obj


def check():
    manifest = {}
    for line in (HERE / "MANIFEST.sha256").read_text().splitlines():
        digest, name = line.split("  ", 1)
        path = Path(name)
        if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest) or path.is_absolute() or ".." in path.parts or name in manifest:
            raise ValueError("invalid manifest row")
        candidate = HERE / path
        if not candidate.is_file() or candidate.is_symlink():
            raise ValueError("manifest path is not a plain file")
        manifest[name] = digest
    actual = {str(p.relative_to(HERE)) for p in HERE.rglob("*") if p.is_file()
              and p.name != "MANIFEST.sha256" and "__pycache__" not in p.parts}
    if set(manifest) != actual:
        raise ValueError("manifest file set differs")
    for name, digest in manifest.items():
        if sha((HERE / name).read_bytes()) != digest:
            raise ValueError("manifest hash differs: " + name)
    static = module("tc_static_replay", HERE / "static.py")
    target = (HERE.parents[2] / "artifacts/node/94/hl-node").read_bytes()
    current = static.collect(target)
    for row in json.loads((HERE / "sources/target-path-strings.json").read_bytes()):
        start = int(row["file_offset"], 16)
        wanted = bytes.fromhex(row["bytes_hex"])
        if target[start:start + len(wanted)] != wanted or wanted.decode() != row["text"]:
            raise ValueError("target source-path string differs")
    if current != json.loads((HERE / "static/records.json").read_bytes()):
        raise ValueError("static replay differs")
    frozen = json.loads((HERE / "frozen/freeze.json").read_bytes())
    for path, expected in frozen["pins"].items():
        if sha((HERE / path).read_bytes()) != expected:
            raise ValueError("frozen pin differs: " + path)
    raw = {}
    for row in frozen["files"]:
        data = (HERE / "frozen" / row["path"]).read_bytes()
        decoded = gzip.decompress(data)
        if sha(data) != row["sha256"] or sha(decoded) != row["raw_sha256"]:
            raise ValueError("frozen stream differs")
        raw[row["path"]] = decoded
    oracle = module("tc_independent_oracle", HERE / "oracle.py")
    cases = list(oracle.cases())
    if len(cases) != frozen["cases"]:
        raise ValueError("oracle case count differs")
    for filename, index in [("inputs.txt.gz", 1), ("expected.txt.gz", 2)]:
        if "".join(c[index] + "\n" for c in cases).encode() != raw[filename]:
            raise ValueError("independent oracle regeneration differs")
    native = json.loads((HERE / "native/result.json").read_bytes())
    if native["status"] != "pass" or native["source_sha256"] != sha((HERE / "rust/lib.rs").read_bytes()) or native["driver_sha256"] != sha((HERE / "rust/driver.rs").read_bytes()):
        raise ValueError("native source identity differs")
    repack = json.loads((HERE / "native/repack.json").read_bytes())
    compressed = (HERE / "native" / repack["output_path"]).read_bytes()
    decoded = lzma.decompress(compressed)
    if sha(compressed) != repack["output_sha256"] or sha(decoded) != native["archive"]["raw_sha256"]:
        raise ValueError("lossless archive identity differs")
    if repack["input_sha256"] != native["archive"]["sha256"]:
        raise ValueError("original archive identity differs")
    archive = json.loads(decoded)
    if len(archive) != native["archive"]["streams"]:
        raise ValueError("stream count differs")
    streams = {}
    for name, row in archive.items():
        value = base64.b64decode(row["base64"], validate=True)
        if sha(value) != row["sha256"]:
            raise ValueError("stream digest differs")
        streams[name] = value
    referenced = []
    for command in native["commands"]:
        for stream in command["streams"]:
            value = streams[stream["stream"]]
            if len(value) != stream["bytes"] or sha(value) != stream["sha256"]:
                raise ValueError("command stream differs")
            referenced.append(stream["stream"])
    if len(set(referenced)) != len(referenced) or set(referenced) != set(streams):
        raise ValueError("command/archive closure differs")
    expected = raw["expected.txt.gz"]
    for opt in [0, 3]:
        for repeat in [0, 1]:
            if streams[f"good-opt{opt}-repeat{repeat}-run.stdout"] != expected:
                raise ValueError("normal native stream differs")
    for row in native["mutants"]:
        lines = streams["mutant-" + row["name"] + "-run.stdout"].splitlines()
        wanted = expected.splitlines()
        differences = [i for i, (a, b) in enumerate(zip(lines, wanted)) if a != b]
        if len(lines) != len(wanted) or len(differences) != row["mismatches"] or not differences or differences[0] != row["first_index"]:
            raise ValueError("compiled mutant mismatch record differs")
    return {"status": "pass", "frozen_cases": len(cases), "normal_runs": 4,
            "compiled_mutants": len(native["mutants"]), "retained_streams": len(streams)}


if __name__ == "__main__":
    print(json.dumps(check()))
