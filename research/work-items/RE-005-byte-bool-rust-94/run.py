#!/usr/bin/env python3
"""Run only the independently written 197-byte decoder reconstruction experiment."""

import argparse
import hashlib
import json
import os
import pathlib
import stat
import subprocess
import sys
import zlib

PACKET = pathlib.Path(__file__).resolve().parent
ROOT = PACKET.parents[2]
COMPONENT = ROOT / "src/node94-byte-decoders"
PREFIX = pathlib.Path("/tmp/hl-resume-20261101/toolchain/prefix")
RUSTC = PREFIX / "bin/rustc"
CARGO = pathlib.Path("/workspace/mayhem-build-repeat/toolchain/rust/bin/cargo")
PROVIDER = PREFIX.parent / "PROVIDER-AUDIT.json"
PROVIDER_SHA = "56969b4e39acf17cf6f60f7c94d840a06bb37feb89cc577d0dcadfed7a71fdd6"
BASE = "56c0ec672bd8fdcfaa80f2db700a61e6240b3663"
COUNT = 5628
CLEAN_ENV = {"PATH": "/usr/local/bin:/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "PYTHONDONTWRITEBYTECODE": "1"}


def require(value, message):
    if not value:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def file_record(path):
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
            size += len(block)
    return {"bytes": size, "sha256": digest.hexdigest()}


def physical_record(path):
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode):
        raw = os.fsencode(os.readlink(path))
        return {"mode": metadata.st_mode, "bytes": len(raw), "sha256": sha(raw), "kind": "symlink"}
    require(stat.S_ISREG(metadata.st_mode), "not a regular physical input: " + str(path))
    return {"mode": metadata.st_mode, "kind": "file", **file_record(path)}


def save(path, value):
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")


def git(*args, cwd=ROOT):
    return subprocess.check_output(["/usr/bin/git", *args], cwd=cwd, env=CLEAN_ENV)


def audit():
    for directory in [COMPONENT, ROOT, *ROOT.parents]:
        for name in ["config", "config.toml"]:
            require(not (directory / ".cargo" / name).exists(), "unaudited Cargo configuration: " + str(directory / ".cargo" / name))
    files = {}
    pins = []
    for raw in git("ls-files", "--cached", "--others", "--exclude-standard", "-z").split(b"\0"):
        if not raw:
            continue
        name = raw.decode()
        path = ROOT / name
        if path.is_dir():
            pin = git("rev-parse", "HEAD", cwd=path).decode().strip()
            expected = git("ls-tree", "HEAD", "--", name).decode().split()[2]
            status = git("status", "--porcelain=v1", "--untracked-files=all", cwd=path).decode()
            require(pin == expected and not status, "pinned view changed: " + name)
            physical = {}
            for leaf in git("ls-files", "-z", cwd=path).split(b"\0"):
                if leaf:
                    physical[leaf.decode()] = physical_record(path / leaf.decode())
            pins.append({"path": name, "head": pin, "status": status, "tracked_physical_files": physical})
        else:
            require(path.is_file(), "missing physical input: " + name)
            files[name] = physical_record(path)
    require(len(pins) == 7, "expected seven genuine pinned views")
    provider_raw = PROVIDER.read_bytes()
    require(sha(provider_raw) == PROVIDER_SHA, "provider audit changed")
    provider = json.loads(provider_raw)
    payloads = {}
    for item in provider["payloads"]:
        record = file_record(PREFIX / item["path"])
        require(record == {"bytes": item["bytes"], "sha256": item["sha256"]}, "provider payload changed: " + item["path"])
        payloads[item["path"]] = record
    require(len(payloads) == 103, "provider payload count changed")
    manifests = {}
    for name, digest in provider["installed_manifest_sha256"].items():
        record = file_record(PREFIX / "lib/rustlib" / name)
        require(record["sha256"] == digest, "installed provider manifest changed: " + name)
        manifests[name] = record
    require(len(manifests) == 2, "expected two provider component manifests")
    return {"head": git("rev-parse", "HEAD").decode().strip(),
            "status": git("status", "--porcelain=v1", "--untracked-files=all").decode(),
            "files": files, "pins": pins, "provider_audit_sha256": PROVIDER_SHA,
            "provider_payloads": payloads, "provider_manifests": manifests,
            "host_tools": {str(path): {"resolved": str(path.resolve()), **file_record(path.resolve())}
                           for path in [CARGO, pathlib.Path("/usr/bin/gcc"), pathlib.Path("/usr/bin/ld.bfd"), pathlib.Path("/usr/bin/objdump")]}}


def freeze():
    require(sha((PACKET / "FREEZE.json").read_bytes()) == "47ed92d67d59b3ff8067fab7cf9f20a50c418599695d0fcee28e7f57329f4e03", "pre-source seal changed")
    sealed = json.loads((PACKET / "FREEZE.json").read_bytes())
    for name, record in sealed["files"].items():
        raw = (zlib.decompress((PACKET / "authority.json.zlib").read_bytes())
               if name == "authority.json" else (PACKET / name).read_bytes())
        require({"bytes": len(raw), "sha256": sha(raw)} == record, "frozen input changed: " + name)
    require(sha((PACKET / "PROOF.md").read_bytes()) == sealed["proof_sha256"], "pre-source proof changed")
    inputs = (PACKET / "inputs.tsv").read_bytes()
    expected = (PACKET / "expected.jsonl").read_bytes()
    require(len(inputs.splitlines()) == len(expected.splitlines()) == COUNT, "frozen denominator changed")
    return inputs, expected


class Experiment:
    def __init__(self, out):
        self.out = out
        self.commands = []
        (out / "cargo-home").mkdir()
        (out / "tmp").mkdir()
        self.declared_env = {**CLEAN_ENV, "TMPDIR": str(out / "tmp"), "CARGO_HOME": str(out / "cargo-home"),
                             "CARGO_TARGET_DIR": str(out / "cargo-target"), "CARGO_NET_OFFLINE": "true",
                             "RUSTC": str(RUSTC), "RUSTDOC": str(PREFIX / "bin/rustdoc"),
                             "RUSTFLAGS": "-C debuginfo=0 -C linker=/usr/bin/gcc -C link-arg=-B/usr/bin/ -C link-arg=-fuse-ld=bfd"}
        self.env = self.declared_env

    def command(self, label, argv, *, stdin=None, expected_exit=0):
        stdout = self.out / (label + ".stdout")
        stderr = self.out / (label + ".stderr")
        with stdout.open("wb") as output, stderr.open("wb") as errors:
            result = subprocess.run([str(arg) for arg in argv], cwd=ROOT, env=self.env,
                                    input=stdin, stdout=output, stderr=errors, check=False)
        record = {"label": label, "argv": [str(arg) for arg in argv], "cwd": str(ROOT),
                  "declared_environment": self.declared_env,
                  "stdin_sha256": None if stdin is None else sha(stdin),
                  "exit_code": result.returncode,
                  "stdout": {"path": stdout.name, **file_record(stdout)},
                  "stderr": {"path": stderr.name, **file_record(stderr)}}
        self.commands.append(record)
        save(self.out / "COMMANDS.json", self.commands)
        if expected_exit == "nonzero":
            require(result.returncode > 0, "negative control did not fail normally: " + label)
        else:
            require(result.returncode == expected_exit, "command failed: " + label)
        return stdout.read_bytes()

    def build(self, label, source, opt, inputs, expected, *, mutant=False):
        folder = self.out / label
        folder.mkdir()
        library = folder / "libhyperliquid_node94_byte_decoders.rlib"
        common = [RUSTC, "--edition=2024", "--target=x86_64-unknown-linux-gnu", "-Dwarnings",
                  "-C", "opt-level=" + str(opt), "-C", "codegen-units=1", "-C", "debuginfo=0",
                  "-C", "linker=/usr/bin/gcc", "-C", "link-arg=-B/usr/bin/", "-C", "link-arg=-fuse-ld=bfd"]
        self.command(label + "-library", common + ["--crate-name", "hyperliquid_node94_byte_decoders", "--crate-type=rlib", source, "-o", library])
        client = folder / "compare"
        self.command(label + "-client", common + ["--crate-name", "compare", COMPONENT / "examples/compare.rs", "--extern", "hyperliquid_node94_byte_decoders=" + str(library), "-o", client])
        actual = self.command(label + "-cases", [client], stdin=inputs)
        mismatch = compare(actual, expected)
        require((mismatch > 0) if mutant else (actual == expected), "unexpected case relation: " + label)
        tests = folder / "relations"
        self.command(label + "-test-build", common + ["--test", COMPONENT / "tests/relations.rs", "--extern", "hyperliquid_node94_byte_decoders=" + str(library), "-o", tests])
        self.command(label + "-tests", [tests, "--test-threads=1"], expected_exit="nonzero" if mutant else 0)
        return {"cases": COUNT, "mismatches": mismatch, "library": file_record(library),
                "client": file_record(client), "tests": file_record(tests), "output": {"bytes": len(actual), "sha256": sha(actual)},
                "optimization": opt, "semantic_mutant": mutant}


def compare(actual, expected):
    actual_rows, expected_rows = actual.splitlines(), expected.splitlines()
    require(actual.endswith(b"\n") and len(actual_rows) == len(expected_rows) == COUNT, "incomplete normal case output")
    # Exact canonical bytes compare every field, including absent native writes and full suffix.
    for row in actual_rows:
        value = json.loads(row)
        require(json.dumps(value, sort_keys=True, separators=(",", ":")).encode() == row, "noncanonical result")
    return sum(a != b for a, b in zip(actual_rows, expected_rows))


def comparator_controls(expected):
    rows = expected.splitlines(keepends=True)
    first = json.loads(rows[0])
    first["tag"] = 255
    changed = json.dumps(first, sort_keys=True, separators=(",", ":")).encode() + b"\n" + b"".join(rows[1:])
    require(compare(changed, expected) == 1, "altered-content comparator control failed")
    result = {"changed_content_mismatches": 1}
    for label, raw in [("missing_row", b"".join(rows[1:])), ("extra_row", expected + rows[-1])]:
        try:
            compare(raw, expected)
        except ValueError:
            result[label] = "rejected"
        else:
            raise ValueError("row-count comparator control failed: " + label)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=pathlib.Path, required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    require(not out.exists() and out.is_relative_to(ROOT / "work"), "output must be a fresh ignored ROOT/work child")
    require(not git("status", "--porcelain=v1", "--untracked-files=all"), "commit the reviewed source checkpoint first")
    require(git("merge-base", BASE, "HEAD").decode().strip() == BASE, "task-start base is not an ancestor")
    require(not git("ls-tree", BASE, "--", "src/node94-byte-decoders"), "baseline already contains this component")
    inputs, expected = freeze()
    out.mkdir(parents=True)
    experiment = Experiment(out)
    before = audit()
    save(out / "AUDIT-BEFORE.json", before)
    try:
        provider = json.loads(PROVIDER.read_bytes())
        version = experiment.command("rustc-version", [RUSTC, "-vV"])
        require(version.decode() == provider["rustc_vV"], "compiler version changed")
        cargo_version = experiment.command("cargo-version", [CARGO, "--version"])
        require(cargo_version.startswith(b"cargo 1.89.0 "), "owned Cargo version changed")
        experiment.command("gcc-version", ["/usr/bin/gcc", "--version"])
        experiment.command("ld-version", ["/usr/bin/ld.bfd", "--version"])
        selected = experiment.command("gcc-selected-linker", ["/usr/bin/gcc", "-B/usr/bin/", "-fuse-ld=bfd", "-print-prog-name=ld.bfd"])
        require(selected.decode().strip() == "/usr/bin/ld.bfd", "gcc did not select the audited linker")
        controls = comparator_controls(expected)
        save(out / "COMPARATOR-CONTROLS.json", controls)
        experiment.command("native", [sys.executable, PACKET / "collect.py", "--out", out / "native"])
        experiment.command("native-controls", [sys.executable, "-m", "unittest", "discover", "-s", PACKET, "-p", "test_static.py", "-v"])
        results = {}
        source = COMPONENT / "src/lib.rs"
        for opt in [0, 3]:
            results["O" + str(opt)] = experiment.build("O" + str(opt), source, opt, inputs, expected)
        repeat = out / "repeat"
        repeat.mkdir()
        repeat_lib = repeat / "libhyperliquid_node94_byte_decoders.rlib"
        original_argv = next(item["argv"] for item in experiment.commands if item["label"] == "O3-library")
        experiment.command("O3-repeat-library", original_argv[:-1] + [repeat_lib])
        require(file_record(repeat_lib) == results["O3"]["library"], "own optimized rlib repeat differs")
        for label, release in [("cargo-debug", []), ("cargo-release", ["--release"])]:
            experiment.command(label, [CARGO, "test", "--offline", "--locked", "--manifest-path", COMPONENT / "Cargo.toml", *release, "--", "--test-threads=1"])
        text = source.read_text()
        replacements = {
            "mode-nonzero": ("budget.mode_word == 1", "budget.mode_word != 0"),
            "rollback-limit": ("if before >= budget.limit {", "if before >= budget.limit {\n            budget.counter = before;"),
            "omit-bool-word": ("charge_one(budget, Some(1))?;", "charge_one(budget, None)?;"),
            "accept-bool-two": ("1 => Ok(true),", "1 | 2 => Ok(true),"),
            "restore-invalid": ("found => Err(DecodeError::InvalidBooleanByte { found }),", "found => {\n            *input = original;\n            Err(DecodeError::InvalidBooleanByte { found })\n        },"),
        }
        for label, (old, new) in replacements.items():
            require(text.count(old) == 1, "mutant replacement is not unique: " + label)
            changed = text.replace(old, new)
            if label == "restore-invalid":
                site = "    match take_one(input)? {"
                require(changed.count(site) == 1, "mutant slice checkpoint ambiguous")
                changed = changed.replace(site, "    let original = *input;\n" + site)
            mutant = out / (label + ".rs")
            mutant.write_text(changed)
            results[label] = experiment.build(label, mutant, 3, inputs, expected, mutant=True)
        save(out / "RESULT.json", {"scope": "197B/64-row no-call u8/bool relation; independent Rust only",
                                  "base": BASE, "source_checkpoint": before["head"], "cases": COUNT,
                                  "results": results, "own_optimized_rlib_repeat_equal": True,
                                  "comparator_controls": controls,
                                  "captured_execution_or_instruction_evaluator": False,
                                  "expanded_current_suite": "NOT_RUN", "CI": "NOT_RUN", "component_gates": False})
    finally:
        after = audit()
        save(out / "AUDIT-AFTER.json", after)
        require(before == after, "physical inputs/provider/host tools/head/status changed during experiment")
    print("PASS: complete197B/64rows; O0/O3 each5628 exact cases; 5 compiled semantic mutants; own Cargo debug/release; immutable inputs")


if __name__ == "__main__":
    main()
