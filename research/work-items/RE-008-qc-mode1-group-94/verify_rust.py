#!/usr/bin/env python3
"""Compile the qualified mode1 group against the independent pre-source freeze."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
COMPONENT = ROOT / "src/node94-consensus-admission"
FIELD = "src/qc_mode1_group.rs"
EXAMPLE = "qc_mode1_group_input_only"
DRIVER = f"examples/{EXAMPLE}.rs"
FREEZE = "5fa1a8a08792fda65f42923033315ed16533ce8d51755bd01fd67c945c97e209"
RESERVE = 300 * 1024 * 1024
START_RESERVE = RESERVE + 16 * 1024 * 1024


def need(ok, message):
    if not ok:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def corpus():
    raw = (HERE / "pre-rust/PRE-MODE1-RUST-FREEZE.json").read_bytes()
    need(sha(raw) == FREEZE, "pre-mode1-Rust identity")
    frozen = json.loads(raw)
    result = {name: (HERE / "pre-rust" / name).read_bytes() for name in ("inputs.tsv", "expected.tsv")}
    need(all(sha(v) == frozen["fixtures"][name] for name, v in result.items()), "frozen fixtures")
    return frozen, result


def recipes():
    result = {
        "threshold-rejects-equality": ("    let Some(reserved_charge) = charge.checked_add(32) else {",
            "    if *charge == u64::MAX - 32 { return Mode1GroupOutcome::BudgetDenied; }\n    let Some(reserved_charge) = charge.checked_add(32) else {"),
        "limit-rejects-equality": ("    if reserved_charge > limit {", "    if reserved_charge >= limit {"),
        "omit-reserve-charge-store": (
            "    if reserved_charge > limit {\n        *charge = reserved_charge;\n        return Mode1GroupOutcome::BudgetDenied;\n    }",
            "    if reserved_charge > limit {\n        return Mode1GroupOutcome::BudgetDenied;\n    }"),
        "reserve-increment31": ("charge.checked_add(32)", "charge.checked_add(31)"),
        "initial-charge23": ("    *charge = reserved_charge;\n    *input = suffix;",
            "    *charge = reserved_charge - 1;\n    *input = suffix;"),
        "denial-kind0": ("Self::BudgetDenied => Some((1, 2, None))", "Self::BudgetDenied => Some((1, 0, None))"),
        "denial-tag2": ("Self::BudgetDenied => Some((1, 2, None))", "Self::BudgetDenied => Some((2, 2, None))"),
    }
    # Qualified counterparts of omitted native refunds: model only the branch
    # where the next scalar's extra8 fits but exceeds L, after k complete reads.
    # Full-corpus counts are Rust countermodel counts, not patched-native traces.
    for index, name in enumerate(("first", "second", "third"), 1):
        block = f"""    if let Some(extra_charge) = reserved_charge.checked_add(8) {{
        if extra_charge > limit {{
            let mut probe = *input;
            let mut complete = 0;
            for _ in 0..{index} {{
                let Some(&marker) = probe.first() else {{ break; }};
                let width = match marker {{ 0..=0xfa => 1, 0xfb => 3, 0xfc => 5, 0xfd => 9, _ => break }};
                if probe.len() < width {{ break; }}
                probe = &probe[width..];
                complete += 1;
            }}
            if complete == {index} {{
                *charge = extra_charge;
                *input = probe;
                return Mode1GroupOutcome::BudgetDenied;
            }}
        }}
    }}
"""
        result[f"omit-{name}-refund"] = ("    let mut suffix = *input;", block + "    let mut suffix = *input;")
    return result


def read_result(line):
    f = line.decode("ascii").split("\t")
    need(len(f) == 13, "result shape")
    for index in (1, 2, 3, 5, 6, 7, 8, 9, 10):
        need(f[index] == "-" or 0 <= int(f[index]) < 1 << (8 if index in (6, 9) else 64), "field width")
    suffix = b"" if f[4] == "-" else bytes.fromhex(f[4])
    words = None if f[11] == "-" else bytes.fromhex(f[11])
    memory = None if f[12] == "-" else bytes.fromhex(f[12])
    need(words is None or len(words) == 32, "four value words")
    need(memory is None or len(memory) == 40, "raw helper view width")
    if f[5] == "0":
        need(words is not None and memory is not None, "success requires values and memory")
    return f, suffix, words, memory


def verify_control(control, actual):
    f, _, _, _ = actual
    fields = {"charge": 1, "advance": 2, "group_tag": 5, "kind": 6}
    for key, expected in control["predicted_difference"].items():
        need(key in fields, "known native witness predicate")
        need(f[fields[key]] != "-" and int(f[fields[key]]) == expected, "required native witness " + key)


def command(argv, cwd, stem, *, env=None, stdin=None):
    p = subprocess.run(list(map(str, argv)), cwd=cwd, env=env, input=stdin, capture_output=True, timeout=90)
    stem.with_suffix(".stdout").write_bytes(p.stdout)
    stem.with_suffix(".stderr").write_bytes(p.stderr)
    record = {"argv": list(map(str, argv)), "exit": p.returncode,
              "stdout_sha256": sha(p.stdout), "stderr_sha256": sha(p.stderr)}
    need(p.returncode == 0, f"command failed: {record}; {p.stderr.decode(errors='replace')}")
    return p, record


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
    need(shutil.disk_usage(output.parent).free >= RESERVE, "reserve before writes")
    output.mkdir(parents=True)
    tools = {str(p): sha(p.read_bytes()) for p in (rustc, cargo)}
    comparator = {Path(__file__).name: sha(Path(__file__).read_bytes())}
    version, _ = command([rustc, "-vV"], output, output / "rustc-version")
    need(b"release: 1.94.1\n" in version.stdout and b"host: x86_64-unknown-linux-gnu\n" in version.stdout, "pinned compiler/host")
    cargo_version, _ = command([cargo, "-vV"], output, output / "cargo-version")
    frozen, fixtures = corpus()
    wanted = [read_result(line) for line in fixtures["expected.tsv"].splitlines()[1:]]
    need(len(wanted) == 128, "case count")
    for name, data in fixtures.items():
        (output / name).write_bytes(data)
        (output / name).chmod(0o444)
    names = ["Cargo.toml", "Cargo.lock", DRIVER]
    names += sorted(p.relative_to(COMPONENT).as_posix() for p in (COMPONENT / "src").rglob("*.rs"))
    sources = {name: (COMPONENT / name).read_bytes() for name in names}
    variants = {"baseline": sources}
    for name, (old, new) in recipes().items():
        original = sources[FIELD].decode()
        need(original.count(old) == 1 and old != new, "unique source mutation " + name)
        variants[name] = sources | {FIELD: original.replace(old, new, 1).encode()}
    controls = {c["name"]: c for c in frozen["native_controls"]}
    need(set(variants) - {"baseline"} == set(controls), "native/source counterpart names")
    snapshots = {}
    for name, contents in variants.items():
        for relative, data in contents.items():
            path = output / "sources" / name / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            path.chmod(0o444)
        snapshots[name] = {n: sha(data) for n, data in contents.items()}
    source_freeze = (json.dumps({"source_snapshots": snapshots, "fixtures": {n: sha(v) for n, v in fixtures.items()},
                                "comparator_pins": comparator}, indent=2, sort_keys=True) + "\n").encode()
    (output / "freeze.json").write_bytes(source_freeze)
    results = []
    for name, contents in variants.items():
        location = output / "sources" / name
        for opt in (0, 3):
            free = shutil.disk_usage(output).free
            need(free >= START_RESERVE, "reserve plus transient-build margin")
            run = output / f"{name}-opt{opt}"
            run.mkdir()
            env = os.environ.copy()
            env.update({"RUSTC": str(rustc), "RUSTDOC": str(rustc.with_name("rustdoc")), "RUSTC_WRAPPER": "", "RUSTC_WORKSPACE_WRAPPER": "",
                        "CARGO_HOME": str(output / "cargo-home"), "CARGO_TARGET_DIR": str(run / "target"), "CARGO_NET_OFFLINE": "true",
                        "CARGO_INCREMENTAL": "0", "RUSTFLAGS": "-D warnings -C overflow-checks=yes -C debuginfo=0 -C strip=symbols",
                        "CARGO_PROFILE_DEV_OPT_LEVEL": "0", "CARGO_PROFILE_RELEASE_OPT_LEVEL": "3"})
            argv = [cargo, "build", "--offline", "--locked", "--manifest-path", location / "Cargo.toml", "--example", EXAMPLE]
            if opt == 3:
                argv.append("--release")
            _, build = command(argv, run, run / "compile", env=env)
            need("Compiling node94-consensus-admission v0.1.0 (" + str(location) + ")" in (run / "compile.stderr").read_text(), "fresh rustc source root")
            built = run / "target" / ("release" if opt == 3 else "debug") / "examples" / EXAMPLE
            binary = run / EXAMPLE
            shutil.copy2(built, binary)
            executable = sha(binary.read_bytes())
            project, dep_info = set(), {}
            pattern = re.escape(str(location)) + r"/[^\s\\:]+"
            for path in (run / "target").rglob("*.d"):
                matches = re.findall(pattern, path.read_text())
                if not matches:
                    continue
                project.update(matches)
                relative = path.relative_to(run / "target")
                saved = run / "dep-info" / relative
                saved.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(path, saved)
                dep_info[relative.as_posix()] = sha(saved.read_bytes())
            need(project == {str(location / p) for p in contents if p.endswith(".rs")}, "exact compiler-read source closure")
            actual, executed = command([binary], run, run / "run", env=env, stdin=fixtures["inputs.tsv"])
            need(not actual.stderr and sha(binary.read_bytes()) == executable, "diagnostic/executable drift")
            got = [read_result(line) for line in actual.stdout.splitlines()]
            need(len(got) == 128, "actual count")
            different = [i for i, (a, b) in enumerate(zip(got, wanted, strict=True)) if a != b]
            need(bool(different) == (name != "baseline"), "countermodel comparison " + name)
            if name != "baseline":
                control = controls[name]
                index = next(i for i, e in enumerate(wanted) if e[0][0] == control["witness"])
                need(index in different, "named native witness differs")
                verify_control(control, got[index])
            need(all(sha((location / p).read_bytes()) == digest for p, digest in snapshots[name].items()), "compiled source drift")
            results.append({"source": name, "opt": opt, "compile": build, "run": executed,
                            "binary_sha256": executable, "dep_info": dep_info, "compiler_project_sources": len(project),
                            "matched": 128 - len(different), "different": len(different),
                            "witness": None if name == "baseline" else controls[name]["witness"], "free_before": free})
            target = run / "target"
            need(not target.is_symlink() and target.parent == run, "own terminal target cleanup")
            shutil.rmtree(target)
            results[-1]["cache_removed_after_archival"] = str(target)
            results[-1]["free_after"] = shutil.disk_usage(output).free
            need(results[-1]["free_after"] >= RESERVE, "reserve after terminal archival")
            print(f"{name} opt{opt}: compile/run0; {len(different)}/128 different; free={results[-1]['free_after']}", flush=True)
    need(all(sha((COMPONENT / p).read_bytes()) == sha(v) for p, v in sources.items()), "current source drift")
    need(all(sha(Path(p).read_bytes()) == digest for p, digest in tools.items()), "tool drift")
    need(sha(Path(__file__).read_bytes()) == comparator[Path(__file__).name], "comparator drift")
    need(corpus()[1] == fixtures, "fixture drift")
    report = {"rustc": version.stdout.decode(), "cargo": cargo_version.stdout.decode(), "tools": tools,
              "source_pins": snapshots["baseline"], "source_freeze_sha256": sha(source_freeze), "comparator_pins": comparator,
              "fixture_pins": {n: sha(v) for n, v in fixtures.items()}, "pre_rust_freeze": FREEZE,
              "cases": 128, "compiled_countermodels": 10, "results": results, "captured_execution": False,
              "limits": "qualified final fields;denial memory only with supplied prefill;no inactive need/ABI/fullQC;countermodel counts not patched-native predictions"}
    (output / "results.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
