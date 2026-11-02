#!/usr/bin/env python3
"""Build/run only this packet's newly authored Rust; never run captured code."""
import argparse
import base64
import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess

HERE = Path(__file__).resolve().parent


def sha(data):
    return hashlib.sha256(data).hexdigest()


MUTANTS = [
    ("leaf-prechecks-flag", "for item in items {", "for item in items { if out.flag != 0 { out.stop = 3; break; }"),
    ("ignore-extra-marker", "if incoming == STOP {", "if false {"),
    ("last-error-wins", "out.dropped = Some(item.result);", "out.dropped = Some(item.result); out.folder[..80].copy_from_slice(&item.result);"),
    ("omit-leaf-drop", "out.dropped = Some(item.result);", "out.dropped = None;"),
    ("overwrite-success-payload", "} else if incoming != SUCCESS {", "} else {"),
    ("lose-opaque-state", "let previous = tag(&out.folder);", "out.folder[80..].fill(0); let previous = tag(&out.folder);"),
    ("no-flag-store", "out.flag = 1;", "out.flag = 0;"),
    ("ignore-post-call-byte", "out.flag = item.flag_after_call;", "out.flag = 0;"),
    ("only-one-cancels", "if out.flag != 0 {", "if out.flag == 1 {"),
    ("read-byte-on-local-error", "out.stop = 2;", "out.flag_reads += 1; out.stop = 2;"),
    ("merge-right-error-wins", "output = if left_ok { right } else { left };", "output = if right_ok { left } else { right };"),
    ("merge-overwrites-inactive-payload", "output[..8].copy_from_slice(&SUCCESS.to_le_bytes());", "output = left;"),
    ("merge-drops-left", "Some(right)", "Some(left)"),
    ("merge-omits-drop", "Some(right)", "None"),
    ("entry-only-one-cancels", "if input.observed_cancel != 0 {", "if input.observed_cancel == 1 {"),
    ("minimum-exclusive", "mid < input.minimum", "mid <= input.minimum"),
    ("zero-budget-still-splits", "input.splits == 0", "false"),
    ("migration-minimum", "next_splits.max(input.observed_threads)", "next_splits.min(input.observed_threads)"),
    ("wrong-leaf-stride", "input.producer_len.wrapping_mul(184)", "input.producer_len.wrapping_mul(183)"),
    ("wrong-split-stride", "mid.wrapping_mul(184)", "mid.wrapping_mul(183)"),
    ("underflow-wraps", "input.producer_len.checked_sub(mid)", "Some(input.producer_len.wrapping_sub(mid))"),
    ("wrong-midpoint", "input.logical_len >> 1", "input.logical_len / 3"),
]


def compare(actual, expected):
    a, e = actual.splitlines(), expected.splitlines()
    if len(a) != len(e) or actual.endswith(b"\n") != expected.endswith(b"\n"):
        raise ValueError("output shape mismatch")
    return [i for i, (x, y) in enumerate(zip(a, e)) if x != y]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--toolchain-bin", type=Path, required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    streams, commands = {}, []
    result = {"status": "running", "commands": commands, "builds": [], "mutants": []}
    inputs = gzip.decompress((HERE / "frozen/inputs.txt.gz").read_bytes())
    expected = gzip.decompress((HERE / "frozen/expected.txt.gz").read_bytes())
    freeze = json.loads((HERE / "frozen/freeze.json").read_bytes())
    for name, digest in freeze["pins"].items():
        if sha((HERE / name).read_bytes()) != digest:
            raise ValueError("pre-source pin mismatch: " + name)
    for row in freeze["files"]:
        compressed = (HERE / "frozen" / row["path"]).read_bytes()
        if sha(compressed) != row["sha256"] or sha(gzip.decompress(compressed)) != row["raw_sha256"]:
            raise ValueError("frozen fixture mismatch")
    source = (HERE / "rust/lib.rs").read_text()
    driver = (HERE / "rust/driver.rs").read_bytes()
    result["source_sha256"] = sha(source.encode())
    result["driver_sha256"] = sha(driver)
    result["cases"] = freeze["cases"]
    result["input_sha256"] = sha(inputs)
    result["expected_sha256"] = sha(expected)
    compiler = args.toolchain_bin.resolve() / "rustc"
    result["compiler_sha256"] = sha(compiler.read_bytes())
    env = dict(os.environ)
    env.update(RUSTC=str(compiler), RUSTDOC=str(compiler.parent / "rustdoc"),
               PATH=str(compiler.parent) + os.pathsep + env.get("PATH", ""))

    def run(label, command, stdin=b""):
        completed = subprocess.run(command, input=stdin, capture_output=True, env=env, cwd=out)
        names = []
        for suffix, data in [("stdout", completed.stdout), ("stderr", completed.stderr)]:
            name = label + "." + suffix
            (out / name).write_bytes(data)
            streams[name] = data
            names.append({"stream": name, "bytes": len(data), "sha256": sha(data)})
        commands.append({"label": label,
                         "argv": [str(x).replace(str(out), "@OUT@").replace(str(HERE), "@PACKET@").replace(str(compiler.parent), "@TOOLCHAIN@") for x in command],
                         "exit": completed.returncode, "stdin_sha256": sha(stdin),
                         "streams": names})
        checkpoint()
        return completed

    def checkpoint():
        (out / "result.json").write_text(json.dumps(result, indent=2) + "\n")

    def build(label, text, opt):
        directory = out / label
        directory.mkdir()
        (directory / "lib.rs").write_text(text)
        (directory / "driver.rs").write_bytes(driver)
        library, client = directory / "libnode94_tc_abort_projection.rlib", directory / "input-only"
        common = [str(compiler), "--edition=2021", "-C", f"opt-level={opt}", "-C", "codegen-units=1",
                  "-C", "overflow-checks=yes", "-C", "debuginfo=0", "-C", "metadata=tc_abort_94",
                  "--remap-path-prefix", f"{directory}=/tc-abort-build"]
        a = run(label + "-library", common + ["--crate-name", "node94_tc_abort_projection", "--crate-type", "rlib", str(directory / "lib.rs"), "-o", str(library)])
        if a.returncode:
            raise ValueError("library failed: " + label)
        b = run(label + "-client", common + [str(directory / "driver.rs"), "--extern", f"node94_tc_abort_projection={library}", "-o", str(client)])
        if b.returncode:
            raise ValueError("client failed: " + label)
        artifacts = {p.name: {"bytes": p.stat().st_size, "sha256": sha(p.read_bytes())} for p in [library, client]}
        result["builds"].append({"label": label, "optimization": opt, "source_sha256": sha(text.encode()), "artifacts": artifacts})
        return client, artifacts

    try:
        version = run("rustc-version", [str(compiler), "-vV"])
        if version.returncode or b"release: 1.94.1\n" not in version.stdout:
            raise ValueError("expected rustc 1.94.1")
        artifacts = {}
        for opt in [0, 3]:
            for repetition in [0, 1]:
                label = f"good-opt{opt}-repeat{repetition}"
                client, built = build(label, source, opt)
                if repetition and artifacts[opt] != built:
                    raise ValueError("compiled same-profile repeat differs")
                artifacts[opt] = built
                child = run(label + "-run", [str(client)], inputs)
                differences = compare(child.stdout, expected)
                if child.returncode or differences:
                    result["first_mismatches"] = differences[:20]
                    raise ValueError("production mismatch: " + label)
        for name, old, new in MUTANTS:
            if source.count(old) != 1:
                raise ValueError("ambiguous mutant edit: " + name)
            mutant = source.replace(old, new)
            client, _ = build("mutant-" + name, mutant, 3)
            child = run("mutant-" + name + "-run", [str(client)], inputs)
            if child.returncode:
                raise ValueError("mutant must run normally: " + name)
            differences = compare(child.stdout, expected)
            if not differences:
                raise ValueError("surviving mutant: " + name)
            result["mutants"].append({"name": name, "mismatches": len(differences), "first_index": differences[0]})
        # Comparator corruptions use a real normal stream, not a synthetic
        # comparator success label.
        good = streams["good-opt3-repeat1-run.stdout"]
        comparator_controls = [good[:-1], good + b"x\n", b"X" + good[1:], good.replace(b"F ", b"M ", 1)]
        for altered in comparator_controls:
            try:
                rejected = bool(compare(altered, expected))
            except ValueError:
                rejected = True
            if not rejected:
                raise ValueError("comparator corruption accepted")
        result["comparator_controls"] = len(comparator_controls)
        client = out / "good-opt3-repeat1/input-only"
        invalid = [b"", b"Q\n", b"P 1 2\n", b"P 1 2 3 4 256 0 1\n", b"P 1 2 3 4 0 0 1 extra\n",
                   b"F 00 0 0\n", b"P -1 2 3 4 0 0 1\n", b"P 18446744073709551616 2 3 4 0 0 1\n"]
        for i, data in enumerate(invalid):
            child = run("parser-" + str(i), [str(client)], data)
            wanted = 0 if not data else 2
            if child.returncode != wanted or child.stdout:
                raise ValueError("parser control failed")
        child = run("extra-argument", [str(client), "extra"])
        if child.returncode != 2:
            raise ValueError("extra argument accepted")
        result["parser_controls"] = len(invalid) + 1
        result["status"] = "pass"
    except Exception as exc:
        result["status"] = "failed"
        result["failure"] = str(exc)
        raise
    finally:
        archive = {name: {"base64": base64.b64encode(data).decode(), "sha256": sha(data)} for name, data in streams.items()}
        raw = (json.dumps(archive, sort_keys=True, separators=(",", ":")) + "\n").encode()
        encoded = gzip.compress(raw, compresslevel=9, mtime=0)
        (out / "raw-streams.json.gz").write_bytes(encoded)
        decoded = json.loads(gzip.decompress(encoded))
        if any(base64.b64decode(decoded[n]["base64"]) != data for n, data in streams.items()):
            raise ValueError("archive round trip failed")
        result["archive"] = {"path": "raw-streams.json.gz", "sha256": sha(encoded), "raw_sha256": sha(raw), "streams": len(streams)}
        checkpoint()
    print(json.dumps({k: result[k] for k in ["status", "cases", "source_sha256", "driver_sha256"]}))


if __name__ == "__main__":
    main()
