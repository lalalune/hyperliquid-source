#!/usr/bin/env python3
"""Compile qualified FD success/short-input projections against frozen data."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
from corpus import streams

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
COMPONENT = ROOT / "src/node94-consensus-admission"
FIELD = "src/qc_fd_group.rs"
EXAMPLE = "qc_fd_group_short_input_only"
DRIVER = f"examples/{EXAMPLE}.rs"


def need(ok, message):
    if not ok:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def recipes():
    result = {}
    stop = "            return FdGroupOutcome::Incomplete { needed };"
    for index in range(3):
        result[f"continue-after-short-{index + 1}"] = (FIELD, stop,
            f"            if index == {index} {{ continue; }}\n" + stop)
    result["fourth-short-becomes-success"] = (FIELD, stop,
        "            if index == 3 { words[index] = needed; return FdGroupOutcome::Complete(words); }\n" + stop)
    result.update({
        "shortfall-minus-one": (FIELD, "let needed = (9 - input.len()) as u64;", "let needed = (8 - input.len()) as u64;"),
        "consume-short-payload": (FIELD, "*input = &input[1..];", "*input = &input[input.len()..];"),
        "retain-charge-minus-eight": (FIELD, "*charge = reserved_charge;", "*charge = reserved_charge - 8;"),
        "lose-group-need": (FIELD, "Some((1, 0, *needed))", "Some((1, 0, needed.wrapping_sub(*needed)))"),
        "lose-row-need": (DRIVER, "let row_need = need;", "let row_need = 0u64;"),
    })
    return result


def command(argv, cwd, stem, *, env=None, stdin=None):
    p = subprocess.run(list(map(str, argv)), cwd=cwd, env=env, input=stdin, capture_output=True, timeout=90)
    stem.with_suffix(".stdout").write_bytes(p.stdout)
    stem.with_suffix(".stderr").write_bytes(p.stderr)
    record = {"argv": list(map(str, argv)), "exit": p.returncode,
              "stdout_sha256": sha(p.stdout), "stderr_sha256": sha(p.stderr)}
    need(p.returncode == 0, f"command failed: {record}; {p.stderr.decode(errors='replace')}")
    return p, record


def read_result(line):
    fields = line.decode("ascii").split("\t")
    need(len(fields) == 12, "active result shape")
    numeric = []
    for i in (1, 2, 3, 5, 6, 7, 8, 9, 10):
        n = None if fields[i] == "-" else int(fields[i])
        need(n is None or 0 <= n < 1 << (8 if i in (6, 9) else 64), "active field width")
        numeric.append(n)
    suffix = b"" if fields[4] == "-" else bytes.fromhex(fields[4])
    values = None if fields[11] == "-" else bytes.fromhex(fields[11])
    need(values is None or len(values) == 32, "complete successful value width")
    return fields[0], tuple(numeric), suffix, values


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rustc", type=Path, required=True)
    parser.add_argument("--cargo", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    rustc = args.rustc.resolve(strict=True)
    cargo = (args.cargo or rustc.with_name("cargo")).resolve(strict=True)
    output = args.out.resolve()
    need(not output.exists(), "refuse existing output")
    output.mkdir(parents=True)
    tool_pins = {str(p): sha(p.read_bytes()) for p in (rustc, cargo)}
    comparator_pins = {p.name: sha(p.read_bytes()) for p in (Path(__file__), HERE / "corpus.py")}
    version, _ = command([rustc, "-vV"], output, output / "rustc-version")
    need(b"release: 1.94.1\n" in version.stdout and b"host: x86_64-unknown-linux-gnu\n" in version.stdout, "reviewed compiler/host")
    cargo_version, _ = command([cargo, "-vV"], output, output / "cargo-version")
    corpus = streams()
    inputs, expected = corpus["inputs.tsv"], corpus["expected.tsv"]
    wanted = [read_result(line) for line in expected.splitlines()[1:]]
    need(len(wanted) == 44, "frozen case count")
    for name, content in corpus.items():
        (output / name).write_bytes(content)
        (output / name).chmod(0o444)
    names = ["Cargo.toml", "Cargo.lock", DRIVER]
    names += sorted(p.relative_to(COMPONENT).as_posix() for p in (COMPONENT / "src").rglob("*.rs"))
    sources = {name: (COMPONENT / name).read_bytes() for name in names}
    library = sources[FIELD]
    old_start = library.index(b"pub fn read_mode1_fd_group(")
    old_end = library.index(b"\n\n/// A chosen safe result type")
    need(sha(library[old_start:old_end] + b"\n") == "6550a8bfdfca51027a202188ecb459e1c7bee638cf09e1d482e03fa382e2e3c7",
         "prior bool API must remain byte-identical")
    variants = {"baseline": sources}
    for name, (path, old, new) in recipes().items():
        original = sources[path].decode()
        need(original.count(old) == 1 and old != new, "unique operative source site " + name)
        variants[name] = sources | {path: original.replace(old, new, 1).encode()}
    snapshots = {}
    for name, contents in variants.items():
        for relative, content in contents.items():
            p = output / "sources" / name / relative
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(content)
            p.chmod(0o444)
        snapshots[name] = {relative: sha(content) for relative, content in contents.items()}
    freeze = {"source_snapshots": snapshots, "fixtures": {name: sha(content) for name, content in corpus.items()},
              "comparator_pins": comparator_pins}
    frozen = (json.dumps(freeze, indent=2, sort_keys=True) + "\n").encode()
    (output / "freeze.json").write_bytes(frozen)
    results = []
    for name, contents in variants.items():
        location = output / "sources" / name
        for opt in (0, 3):
            run = output / f"{name}-opt{opt}"
            run.mkdir()
            env = os.environ.copy()
            env.update({"RUSTC": str(rustc), "RUSTDOC": str(rustc.with_name("rustdoc")),
                        "RUSTC_WRAPPER": "", "RUSTC_WORKSPACE_WRAPPER": "", "CARGO_HOME": str(output / "cargo-home"),
                        "CARGO_TARGET_DIR": str(run / "target"), "CARGO_NET_OFFLINE": "true",
                        "RUSTFLAGS": "-D warnings -C overflow-checks=yes"})
            argv = [cargo, "build", "--offline", "--locked", "--manifest-path", location / "Cargo.toml", "--example", EXAMPLE]
            if opt == 3:
                argv.append("--release")
            _, build = command(argv, run, run / "compile", env=env)
            binary = run / "target" / ("release" if opt == 3 else "debug") / "examples" / EXAMPLE
            executable = sha(binary.read_bytes())
            project, dep_info = set(), {}
            pattern = re.escape(str(location)) + r"/[^\s\\:]+"
            for p in (run / "target").rglob("*.d"):
                project.update(re.findall(pattern, p.read_text()))
                dep_info[str(p.relative_to(run))] = sha(p.read_bytes())
            need(project == {str(location / p) for p in contents if p.endswith(".rs")}, "exact compiler-read project closure")
            actual, executed = command([binary], run, run / "run", env=env, stdin=inputs)
            need(not actual.stderr and sha(binary.read_bytes()) == executable, "run diagnostic/executable drift")
            got = list(map(read_result, actual.stdout.splitlines()))
            need(len(got) == 44, "output count")
            different = [i for i, (a, b) in enumerate(zip(got, wanted, strict=True)) if a != b]
            need(bool(different) == (name != "baseline"), "unexpected semantic comparison " + name)
            need(all(sha((location / p).read_bytes()) == h for p, h in snapshots[name].items()), "compiled source drift")
            results.append({"source": name, "opt": opt, "compile": build, "run": executed,
                            "binary_sha256": executable, "dep_info": dep_info, "compiler_project_sources": len(project),
                            "matched": 44 - len(different), "different": len(different),
                            "witnesses": [wanted[i][0] for i in different[:3]]})
            print(f"{name} opt{opt}: compile/run0; {len(different)}/44 different", flush=True)
    need(all(sha((COMPONENT / p).read_bytes()) == sha(v) for p, v in sources.items()), "working sources changed")
    need(all(sha(Path(p).read_bytes()) == h for p, h in tool_pins.items()), "tool drift")
    need(all(sha((HERE / p).read_bytes()) == h for p, h in comparator_pins.items()), "comparator drift")
    need(streams() == corpus, "fixture drift")
    report = {"rustc": version.stdout.decode(), "cargo": cargo_version.stdout.decode(), "tools": tool_pins,
              "source_pins": snapshots["baseline"], "source_freeze_sha256": sha(frozen), "comparator_pins": comparator_pins,
              "fixture_pins": {n: sha(v) for n, v in corpus.items()}, "cases": 44, "short_cases": 36,
              "prior_success_cases": 8, "compiled_mutants": 9, "results": results, "captured_execution": False,
              "limits": "Static-derived qualified group state/active fields and row forwarding projection; no inactive error image, native ABI or full QC reachability"}
    (output / "results.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
