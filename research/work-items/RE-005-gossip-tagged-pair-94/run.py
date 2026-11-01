#!/usr/bin/env python3
"""Qualify only the defined normal-return selector/two-field reconstruction."""

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
COMPONENT = ROOT / "src/node94-gossip-tagged-pair"
PREFIX = pathlib.Path("/tmp/hl-resume-20261101/toolchain/prefix")
RUSTC = PREFIX / "bin/rustc"
CARGO = pathlib.Path("/workspace/mayhem-build-repeat/toolchain/rust/bin/cargo")
PROVIDER = PREFIX.parent / "PROVIDER-AUDIT.json"
PROVIDER_SHA = "56969b4e39acf17cf6f60f7c94d840a06bb37feb89cc577d0dcadfed7a71fdd6"
BASE = "56c0ec672bd8fdcfaa80f2db700a61e6240b3663"
COUNTS = {"wire": 29858}
CLEAN_ENV = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "PYTHONDONTWRITEBYTECODE": "1"}


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
    tracked = git("ls-files", "--stage", "-z").split(b"\0")
    for raw in tracked:
        if not raw:
            continue
        meta, rawname = raw.split(b"\t", 1)
        mode, expected, stage = meta.decode().split()
        require(stage == "0", "unmerged physical input")
        name = rawname.decode()
        path = ROOT / name
        if mode == "160000":
            pin = git("rev-parse", "HEAD", cwd=path).decode().strip()
            status = git("status", "--porcelain=v1", "--untracked-files=all", cwd=path).decode()
            require(pin == expected and not status, "pinned view changed: " + name)
            physical = {}
            for leaf in git("ls-files", "--stage", "-z", cwd=path).split(b"\0"):
                if leaf:
                    childmeta, childraw = leaf.split(b"\t", 1)
                    childmode, _, childstage = childmeta.decode().split()
                    require(childmode != "160000" and childstage == "0", "unexpected nested gitlink/conflict")
                    physical[childraw.decode()] = {"git_mode": childmode, **physical_record(path / childraw.decode())}
            pins.append({"path": name, "head": pin, "status": status, "tracked_physical_files": physical})
        else:
            files[name] = {"git_mode": mode, **physical_record(path)}
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
                           for path in [CARGO, pathlib.Path("/usr/bin/gcc"), pathlib.Path("/usr/bin/ld.bfd"), pathlib.Path("/usr/bin/objdump"), pathlib.Path(sys.executable)]}}


def authority_bytes(name):
    path = PACKET / "independent" / name
    return path.read_bytes() if path.exists() else zlib.decompress(path.with_name(name + ".zlib").read_bytes())


def freeze():
    sealraw = (PACKET / "independent/FREEZE.json").read_bytes()
    require(sha(sealraw) == "257baf59658d80e3c9cae121fed1af2379f26d2a8d65936a64b35384f4bbecaa", "pre-source seal differs")
    seal = json.loads(sealraw)
    for name, wanted in seal["files"].items():
        raw = authority_bytes(name)
        require({"bytes": len(raw), "sha256": sha(raw)} == wanted, "frozen authority differs: " + name)
    for name, wanted in seal["independent_source_peer_native_proof"].items():
        require(file_record(PACKET / name) == wanted, "pre-source native theorem differs: " + name)
    subset = json.loads((PACKET / "UNIT-FIXTURE-FREEZE.json").read_bytes())
    require(subset["source_existed"] is False and subset["parent_authority_sha256"] == sha(sealraw), "unit subset chronology differs")
    for name, wanted in subset["files"].items():
        require(file_record(COMPONENT / name) == wanted, "unit subset differs")
    inputs, expected = authority_bytes("inputs.tsv"), authority_bytes("expected.jsonl")
    fields = [line.split(b"\t") for line in inputs.splitlines()]
    require(inputs.endswith(b"\n") and len(fields) == COUNTS["wire"] and all(len(f) == 5 for f in fields), "input protocol denominator differs")
    require(len({f[0] for f in fields}) == len({tuple(f[1:]) for f in fields}) == COUNTS["wire"], "complete input/ID uniqueness differs")
    compare(expected, expected, "wire")
    require([f[0].decode() for f in fields] == [json.loads(r)["id"] for r in expected.splitlines()], "input/output IDs differ")
    return {"wire": (inputs, expected)}


def compare(actual, expected, mode):
    rows, wanted = actual.splitlines(), expected.splitlines()
    require(actual.endswith(b"\n") and len(rows) == len(wanted) == COUNTS[mode], "incomplete normal case output")
    fields = {"allowed_tags", "consumed", "counter_after", "counter_writes", "expected", "first", "found", "id", "needed", "option_tag", "phase", "remaining", "second", "tag", "tail_hex", "type_name"}
    for raw in rows:
        value = json.loads(raw)
        require(type(value) is dict and set(value) == fields, "result fields differ")
        require(json.dumps(value, sort_keys=True, separators=(",", ":")).encode() == raw, "noncanonical result")
        require(all(type(v) is not bool for v in value.values()), "boolean substituted for logical integer")
        stores = value["counter_writes"]
        require(type(stores) is list and len(stores) <= 3 and all(type(n) is int and 0 <= n < 1 << 64 for n in stores), "counter store protocol differs")
        require(value["allowed_tags"] is None or (value["allowed_tags"] == [0, 1] and all(type(n) is int for n in value["allowed_tags"])), "allowed tag protocol differs")
    return sum(a != b for a, b in zip(rows, wanted))


def comparator_controls(expected):
    rows = expected.splitlines(keepends=True)
    changed = json.loads(rows[0]); changed["tag"] = 255
    raw = json.dumps(changed, sort_keys=True, separators=(",", ":")).encode() + b"\n" + b"".join(rows[1:])
    require(compare(raw, expected, "wire") == 1, "changed field control failed")
    result = {"changed_field_mismatches": 1}
    changed["tag"] = True
    boolean = json.dumps(changed, sort_keys=True, separators=(",", ":")).encode() + b"\n" + b"".join(rows[1:])
    for label, value in [("missing", b"".join(rows[1:])), ("extra", expected + rows[-1]), ("whitespace", b" " + expected),
                         ("duplicate_key", rows[0].replace(b'{', b'{"tag":255,', 1) + b"".join(rows[1:])), ("bool_integer", boolean)]:
        try:
            compare(value, expected, "wire")
        except ValueError:
            result[label] = "rejected"
        else:
            raise ValueError("comparator control accepted: " + label)
    require(compare(rows[1] + rows[0] + b"".join(rows[2:]), expected, "wire") == 2, "order control failed")
    result["swapped_row_mismatches"] = 2
    return result

class Experiment:
    def __init__(self, out, cases):
        self.out, self.cases, self.commands = out, cases, []
        (out / "cargo-home").mkdir()
        (out / "tmp").mkdir()
        self.env = {**CLEAN_ENV, "TMPDIR": str(out / "tmp"), "CARGO_HOME": str(out / "cargo-home"),
                    "CARGO_TARGET_DIR": str(out / "cargo-target"), "CARGO_NET_OFFLINE": "true",
                    "RUSTC": str(RUSTC), "RUSTDOC": str(PREFIX / "bin/rustdoc"),
                    "RUSTFLAGS": "-Dwarnings -C debuginfo=0 -C linker=/usr/bin/gcc -C link-arg=-B/usr/bin/ -C link-arg=-fuse-ld=bfd"}

    def command(self, label, argv, *, stdin=None, expected_exit=0):
        stdout, stderr = self.out / (label + ".stdout"), self.out / (label + ".stderr")
        with stdout.open("wb") as output, stderr.open("wb") as errors:
            result = subprocess.run([str(arg) for arg in argv], cwd=ROOT, env=self.env,
                                    input=stdin, stdout=output, stderr=errors, check=False)
        record = {"label": label, "argv": [str(arg) for arg in argv], "cwd": str(ROOT),
                  "declared_environment": self.env,
                  "stdin_sha256": None if stdin is None else sha(stdin), "exit_code": result.returncode,
                  "stdout": {"path": stdout.name, **file_record(stdout)}, "stderr": {"path": stderr.name, **file_record(stderr)}}
        self.commands.append(record)
        save(self.out / "COMMANDS.json", self.commands)
        require(result.returncode == expected_exit, "command failed: " + label)
        return stdout.read_bytes()

    def common(self, opt):
        return [RUSTC, "--edition=2024", "--target=x86_64-unknown-linux-gnu", "-Dwarnings",
                "-C", "opt-level=" + str(opt), "-C", "codegen-units=1", "-C", "debuginfo=0",
                "-C", "linker=/usr/bin/gcc", "-C", "link-arg=-B/usr/bin/", "-C", "link-arg=-fuse-ld=bfd"]

    def dependency(self, opt):
        folder = self.out / ("dependency-O" + str(opt))
        folder.mkdir()
        library = folder / "libhl_bincode_varint.rlib"
        self.command("dependency-O" + str(opt), self.common(opt) + ["--crate-name", "hl_bincode_varint", "--crate-type=rlib",
                     ROOT / "src/bincode-varint/src/lib.rs", "-o", library])
        return library

    def build(self, label, source, opt, dependency, modes, *, mutant=False):
        folder = self.out / label
        folder.mkdir()
        library = folder / "libnode94_gossip_tagged_pair.rlib"
        common = self.common(opt) + ["-L", "dependency=" + str(dependency.parent)]
        self.command(label + "-library", common + ["--crate-name", "node94_gossip_tagged_pair", "--crate-type=rlib",
                     source, "--extern", "hl_bincode_varint=" + str(dependency), "--emit=link,llvm-ir", "--out-dir", folder])
        ir = folder / "node94_gossip_tagged_pair.ll"
        client = folder / "compare"
        self.command(label + "-client", common + ["--crate-name", "compare", COMPONENT / "examples/compare.rs", "--extern",
                     "node94_gossip_tagged_pair=" + str(library), "-o", client])
        relations = {}
        for mode in modes:
            inputs, expected = self.cases[mode]
            actual = self.command(label + "-" + mode, [client], stdin=inputs)
            mismatch = compare(actual, expected, mode)
            require((mismatch > 0) if mutant else actual == expected, "unexpected full-output relation: " + label + "/" + mode)
            relations[mode] = {"rows": COUNTS[mode], "mismatches": mismatch, "output": {"bytes": len(actual), "sha256": sha(actual)}}
        tests = folder / "relations"
        self.command(label + "-test-build", common + ["--test", COMPONENT / "tests/relations.rs", "--extern",
                     "node94_gossip_tagged_pair=" + str(library), "-o", tests])
        self.command(label + "-tests", [tests, "--test-threads=1"], expected_exit=101 if mutant else 0)
        return {"cases": relations, "library": file_record(library), "client": file_record(client), "tests": file_record(tests),
                "own_IR": file_record(ir), "optimization": opt, "semantic_mutant": mutant}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=pathlib.Path, required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    require(not os.path.lexists(out) and out.is_relative_to(ROOT / 'work'), 'Use fresh ignored output, preserve old logs')
    require(not git('status', '--porcelain=v1', '--untracked-files=all'), 'Commit reviewed source checkpoint first')
    require(git('merge-base', BASE, 'HEAD').decode().strip() == BASE, 'Task base is not an ancestor')
    require(not git('ls-tree', BASE, '--', 'src/node94-gossip-tagged-pair'), 'Baseline already contains component')
    require(file_record(ROOT / 'src/bincode-varint/src/lib.rs')['sha256'] == '96a4b43f42ff54524bf36279e24e0ee30771223de4486f189c77b6a86dd0a279', 'Real accepted dependency differs')
    cases = freeze()
    out.mkdir(parents=True)
    experiment = Experiment(out, cases)
    before = audit()
    require(not before['status'], 'Physical snapshot is not clean')
    save(out / 'AUDIT-BEFORE.json', before)
    try:
        provider = json.loads(PROVIDER.read_bytes())
        require(experiment.command('rustc-version', [RUSTC, '-vV']).decode() == provider['rustc_vV'], 'Compiler identity differs')
        require(experiment.command('cargo-version', [CARGO, '--version']).startswith(b'cargo 1.89.0 '), 'Cargo identity differs')
        experiment.command('python-version', [sys.executable, '--version'])
        experiment.command('gcc-version', ['/usr/bin/gcc', '--version'])
        experiment.command('ld-version', ['/usr/bin/ld.bfd', '--version'])
        selected = experiment.command('gcc-selected-linker', ['/usr/bin/gcc', '-B/usr/bin/', '-fuse-ld=bfd', '-print-prog-name=ld.bfd'])
        require(pathlib.Path(selected.decode().strip()).resolve() == pathlib.Path('/usr/bin/ld.bfd').resolve(), 'Selected BFD differs')
        controls = comparator_controls(cases['wire'][1])
        save(out / 'COMPARATOR-CONTROLS.json', controls)
        experiment.command('native', [sys.executable, '-B', PACKET / 'collect.py', '--out', out / 'native'])
        experiment.command('native-controls', [sys.executable, '-B', '-m', 'unittest', 'discover', '-s', PACKET, '-p', 'test_static.py', '-v'])
        source = COMPONENT / 'src/lib.rs'
        results, dependencies = {}, {}
        for opt in [0, 3]:
            dependencies[opt] = experiment.dependency(opt)
            results['O' + str(opt)] = experiment.build('O' + str(opt), source, opt, dependencies[opt], ['wire'])
        repeat = out / 'repeat'; repeat.mkdir()
        argv = next(c['argv'] for c in experiment.commands if c['label'] == 'O3-library')
        experiment.command('O3-repeat-library', argv[:-1] + [repeat])
        require(file_record(repeat / 'libnode94_gossip_tagged_pair.rlib') == results['O3']['library'], 'Own O3 raw repeat differs')
        for label, release in [('cargo-debug', []), ('cargo-release', ['--release'])]:
            experiment.command(label, [CARGO, 'test', '--offline', '--locked', '--manifest-path', COMPONENT / 'Cargo.toml', *release, '--', '--test-threads=1'])
        text = source.read_text()
        replacements = {
            'mode-full-qword': ('budget.mode_word as u32 == 1', 'budget.mode_word == 1'),
            'omit-selector-cost': ('charge(budget, stores, 1).map_err', 'charge(budget, stores, 0).map_err'),
            'empty-before-budget': ('    charge(budget, stores, 1).map_err(Failure::Selector)?;', '    if input.is_empty() { return Err(Failure::Selector(ScalarFault::Need { additional: 1 })); }\n    charge(budget, stores, 1).map_err(Failure::Selector)?;'),
            'invalid-selector-rollback': ('found => Err(Failure::InvalidSelector { found }),', 'found => { *input = before_selector; Err(Failure::InvalidSelector { found }) },'),
            'swap-fields': ('Ok(Decoded::TagOne { first, second })', 'Ok(Decoded::TagOne { first: second, second: first })'),
            'rollback-second-error': ('            let second = scalar(input, budget, stores).map_err(Failure::Second)?;', '            let checkpoint = *input;\n            let second = scalar(input, budget, stores).map_err(|error| { *input = checkpoint; Failure::Second(error) })?;'),
            'continue-after-first-error': ('            let first = scalar(input, budget, stores).map_err(Failure::First)?;', '            let first = match scalar(input, budget, stores) { Ok(value) => value, Err(error) => { let _ = scalar(input, budget, stores); return Err(Failure::First(error)); } };'),
            'accept-selector-two': ('        0 => Ok(Decoded::TagZero),', '        0 | 2 => Ok(Decoded::TagZero),'),
        }
        for label, (old, new) in replacements.items():
            require(text.count(old) == 1, 'Mutant replacement is not unique: ' + label)
            path = out / (label + '.rs'); path.write_text(text.replace(old, new))
            results[label] = experiment.build(label, path, 3, dependencies[3], ['wire'], mutant=True)
        save(out / 'RESULT.json', {'scope': '318B/86-row normal-return selector/two-u64-field relation', 'base': BASE,
             'source_checkpoint': before['head'], 'counts': COUNTS, 'results': results,
             'dependency_artifacts': {str(k): file_record(v) for k, v in dependencies.items()},
             'own_optimized_rlib_repeat_equal': True, 'comparator_controls': controls,
             'native_type_ABI_or_inactive_bytes_compared': False,
             'captured_execution_or_instruction_evaluator': False, 'expanded_current_suite': 'NOT_RUN', 'CI': 'NOT_RUN', 'component_gates': False})
    finally:
        after = audit(); save(out / 'AUDIT-AFTER.json', after)
        require(before == after, 'Physical inputs/provider/host tools/head/status changed')
    print('PASS:318B/86 rows; O0/O3 each29858 exact rows;8normal compiled mutants;7relations; genuine accepted dependency; stable inputs')


if __name__ == '__main__':
    main()
