#!/usr/bin/env python3
"""Offline RPC value reproduction; never executes a captured target.

Default: admit fixed files, qualify the independent manual examples, regenerate
the mathematical corpus twice, and compare all ten raw outputs. Optional
--driver/--driver-sha256 runs a caller-reviewed authored binary on inputs only.
--mutations additionally requires explicitly admitted cargo/rustc paths/hashes
and builds twelve release controls. Review this script before running it.

Example:
  python3 -B -S reproduce.py --out /tmp/rpc-reproduction-fresh
  python3 -B -S reproduce.py --out /tmp/rpc-driver-fresh \
    --driver /absolute/authored/driver --driver-sha256 SHA256
  python3 -B -S reproduce.py --out /tmp/rpc-mutants-fresh --mutations \
    --cargo /absolute/toolchain/bin/cargo --cargo-sha256 SHA256 \
    --rustc /absolute/toolchain/bin/rustc --rustc-sha256 SHA256

The output directory must be fresh and outside the repository. This is not a
sandbox: executable hashes do not establish provenance. The caller must admit
the authored driver and installed toolchain; captured-code execution is outside
this interface. All child statuses/raw streams are retained before comparison.
"""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time

CAPTURE_SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
MANIFEST_SHA = "2243a0e6a26a5e951b6173673c9b31c735d4ae8bcb8dce72d38d227ef675fd31"
QUALIFICATION_SHA = "cc4680b2c319ca6dd885de9b046271db361fd0d610375fe557fb75abf77fdb9e"
COMPANION_SHA = "b4b1266fef02352089fd88c702dd8ce44572fcb5771062e7290ef219a5373cb0"
SOURCE_PINS = {
    "Cargo.toml": "c936a44663b7c0289a8dfffba5cd3cb457204d4a54c3457a57c11bcf3542d0ca",
    "Cargo.lock": "e40ce88aad1cd1958b5fbb70728e88cc8ea1bf4f5c6ad2bf741ea61df894881c",
    "src/lib.rs": "8da06fda6977268c7495b3387272aacbaa3eb35bb1ce72026ac317a8db4a4d9f",
    "src/bin/driver.rs": "2b046ee9f26290bd08f10577ae9647a02b4ae4438f663d783dbffa528c06a36f",
}
MODULE_PINS = {
    "reference/reference_math.py": "ebeff5fc0d45f57547ef6b46faa463df90c3056cedeaa04802f780e1462b0a4b",
    "reference/qualify_handcases.py": "368c757808e0438dddebf58eb4ea860451404269eaecedf0ddde72024e898cfb",
    "reference/generate_corpus.py": "4314bf6b5ddcceb7dd81ef8df6b7a56b2618c38b389c852e169ed3fb2bd71c9f",
    "reference/GENERATOR-SPEC.md": "a77707b4ff2e5dc01c5a12d5924f46befad15ceb4cadbd182b896761a88857e3",
    "comparator/value_compare.py": "77ee170e2bd45e5afc0b1fe07d6be4f909b943ea42de261f554a333eba923f0c",
    "comparator/compare_retained.py": "cf81ac8a1a86c10440a757e66a1fbc6c4cb26b87dfb1b40d545c616f38f32289",
    "controls/generate_controls.py": "43a1c879add0bb23b7fc0d933aa052ca9d34bb1e4bddb84baa0988310fe9e69e",
    "controls/PLAN.md": "f9fd6079d269c7b925a88f8bc9419b2db0b6fc9bc549e3ca126c2d805ef1dd19",
}
CORPUS_NAMES = {
    "aliases.jsonl", "case-metadata.jsonl", "coverage.json", "expected.tsv",
    "inputs.tsv", "manual-freeze.json", "manual-handcases.json",
    "manual-host-invalid.json", "reference-qualification.json",
}
COMPRESSED = {"inputs.tsv", "expected.tsv", "case-metadata.jsonl"}
HASH_RE = re.compile(r"[0-9a-f]{64}")


class Session:
    def __init__(self, args):
        self.packet = Path(__file__).resolve().parent
        self.out = args.out.absolute()
        self.timeout = args.timeout
        self.executables = {}
        self.commands = []
        self.out.mkdir(parents=True, exist_ok=False)
        self.data = self.out / "data"
        self.snapshots = self.out / "sources"
        self.python = self.admit_executable(Path(sys.executable), self.file_identity(Path(sys.executable))["sha256"])
        self.json(self.out / "INVOCATION.json", {
            "argv": sys.argv, "python": str(self.python),
            "python_identity": self.file_identity(self.python),
            "python_version": sys.version, "packet": str(self.packet),
            "authored_driver_admission": bool(args.driver),
            "mutations_requested": args.mutations,
            "notice": "Caller admits authored executable/toolchain. Hashes and known-target rejection are not a sandbox or provenance proof.",
        })

    @staticmethod
    def sha(raw):
        return hashlib.sha256(raw).hexdigest()

    @staticmethod
    def file_identity(path):
        digest = hashlib.sha256()
        count = 0
        with path.open("rb") as handle:
            for block in iter(lambda: handle.read(1 << 20), b""):
                count += len(block)
                digest.update(block)
        return {"bytes": count, "sha256": digest.hexdigest()}

    @staticmethod
    def write(path, raw):
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("xb") as handle:
            handle.write(raw)

    def json(self, path, value):
        self.write(path, (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8"))

    def pin(self, path, digest):
        if not HASH_RE.fullmatch(digest) or path.is_symlink() or not path.is_file():
            raise ValueError("nonregular input or invalid digest: " + str(path))
        raw = path.read_bytes()
        if self.sha(raw) != digest:
            raise ValueError("SHA256 mismatch: " + str(path))
        return raw

    def admit_executable(self, path, digest):
        if path is None or not HASH_RE.fullmatch(digest or ""):
            raise ValueError("explicit executable path and canonical SHA256 required")
        # Direct toolchain binaries are preferred; resolving a symlink records
        # the actual admitted object and still binds every subsequent launch.
        actual = path.resolve(strict=True)
        self.pin(actual, digest)
        if digest == CAPTURE_SHA:
            raise ValueError("known node115 capture is forbidden as an executable")
        if not os.access(actual, os.X_OK):
            raise ValueError("admitted executable is not executable")
        self.executables[str(actual)] = digest
        return actual

    def clean_env(self):
        return {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C",
                "PYTHONDONTWRITEBYTECODE": "1", "PYTHONHASHSEED": "0"}

    def command(self, label, argv, stdin=b"", cwd=None, env=None):
        if not re.fullmatch(r"[a-zA-Z0-9-]+", label):
            raise ValueError("unsafe internal command label")
        executable = Path(argv[0]).resolve(strict=True)
        digest = self.executables.get(str(executable))
        if digest is None:
            raise ValueError("unadmitted executable")
        self.pin(executable, digest)
        directory = self.out / "commands" / label
        directory.mkdir(parents=True, exist_ok=False)
        if cwd is None:
            cwd = directory / "empty-cwd"
            cwd.mkdir()
        env = self.clean_env() if env is None else env
        started = time.time()
        launch = {"argv": argv, "cwd": str(cwd), "env": env,
                  "executable_sha256": digest, "stdin": {"bytes": len(stdin), "sha256": self.sha(stdin)},
                  "timeout_seconds": self.timeout, "started_unix": started}
        self.json(directory / "LAUNCH.json", launch)
        stdout, stderr = directory / "stdout.raw", directory / "stderr.raw"
        status, code, error = "launch_error", None, None
        with stdout.open("xb") as out_handle, stderr.open("xb") as err_handle:
            try:
                child = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=out_handle,
                                         stderr=err_handle, cwd=cwd, env=env, start_new_session=True)
                try:
                    child.communicate(stdin, timeout=self.timeout)
                    status = "completed"
                except subprocess.TimeoutExpired:
                    status = "timeout"
                    os.killpg(child.pid, signal.SIGKILL)
                    child.communicate()
                code = child.returncode
            except OSError as exc:
                error = repr(exc)
        # Raw bytes/status are made durable before any value/comparator call.
        record = {
            "label": label, "process_status": status, "returncode": code,
            "launch_error": error, "elapsed_seconds": time.time() - started,
            "launch": self.file_identity(directory / "LAUNCH.json"),
            "executable_sha256": digest, "stdin": launch["stdin"],
            "stdout_path": str(stdout), "stdout": self.file_identity(stdout),
            "stderr_path": str(stderr), "stderr": self.file_identity(stderr),
        }
        self.json(directory / "COMMAND.json", record)
        self.commands.append(record)
        self.pin(executable, digest)
        return record

    @staticmethod
    def require_exit(record, expected):
        if record["process_status"] != "completed" or record["returncode"] != expected:
            raise ValueError("retained command did not complete with expected exit: " + record["label"])

    def recheck_modules(self):
        for name, digest in MODULE_PINS.items():
            self.pin(self.snapshots / name, digest)

    def python_command(self, label, script, arguments):
        self.recheck_modules()
        command = self.command(label, [str(self.python), "-B", "-S",
                                      str(self.snapshots / script), *map(str, arguments)])
        self.recheck_modules()
        return command

    def driver(self, label, path, digest):
        executable = self.admit_executable(path, digest)
        inputs = self.data / "inputs.tsv"
        expected = self.data / "expected.tsv"
        child = self.command(label, [str(executable)], inputs.read_bytes())
        process = {
            "schema": 1, "captured_before_comparison": True,
            "process_status": child["process_status"], "returncode": child["returncode"],
            "executable_sha256": digest, "stdin_sha256": child["stdin"]["sha256"],
            "stdout_sha256": child["stdout"]["sha256"], "stderr_sha256": child["stderr"]["sha256"],
            "actual_parent_command": str(self.out / "commands" / label / "COMMAND.json"),
        }
        process_path = self.out / "process-bindings" / (label + ".json")
        self.json(process_path, process)
        arguments = []
        for name, file in (("inputs", inputs), ("expected", expected),
                           ("stdout", Path(child["stdout_path"])), ("stderr", Path(child["stderr_path"])),
                           ("process-receipt", process_path)):
            arguments += ["--" + name, file, "--" + name + "-sha256", self.file_identity(file)["sha256"]]
        result_dir = self.out / "comparisons" / label
        arguments += ["--output", result_dir]
        comparison = self.python_command("compare-" + label, "comparator/compare_retained.py", arguments)
        # Even a failed child has been bound and classified by the comparator.
        if comparison["process_status"] != "completed":
            raise ValueError("comparator process failure; retained output is inconclusive")
        result = json.loads((result_dir / "result.json").read_bytes())
        return result, child, comparison


def unpack_and_admit(session, args):
    manifest_raw = session.pin(session.packet / "corpus/manifest.json", MANIFEST_SHA)
    manifest = json.loads(manifest_raw)
    if set(manifest["outputs"]) != CORPUS_NAMES:
        raise ValueError("corpus output-name set differs")
    session.write(session.data / "manifest.json", manifest_raw)
    for name in sorted(CORPUS_NAMES):
        expected = manifest["outputs"][name]
        if name in COMPRESSED:
            path = session.packet / "corpus" / (name + ".gz")
            if path.is_symlink() or not path.is_file():
                raise ValueError("nonregular compressed input")
            with gzip.open(path, "rb") as handle:
                raw = handle.read(expected["bytes"] + 1)
        else:
            raw = session.pin(session.packet / "corpus" / name, expected["sha256"])
        if len(raw) != expected["bytes"] or session.sha(raw) != expected["sha256"]:
            raise ValueError("decompressed corpus identity mismatch: " + name)
        session.write(session.data / name, raw)
        (session.data / name).chmod(0o400)
    for name, digest in MODULE_PINS.items():
        raw = session.pin(session.packet / name, digest)
        session.write(session.snapshots / name, raw)
        (session.snapshots / name).chmod(0o400)
    for name, digest in SOURCE_PINS.items():
        session.pin(args.repo / "src/node115-rpc-flat-materializer" / name, digest)
    return manifest


def reproduce_data(session, manifest):
    manual = [
        "--handcases", session.data / "manual-handcases.json",
        "--host-invalid", session.data / "manual-host-invalid.json",
        "--manual-freeze", session.data / "manual-freeze.json",
    ]
    qualification = session.out / "manual-qualification"
    command = session.python_command("manual-qualification", "reference/qualify_handcases.py",
                                     manual + ["--output", qualification])
    session.require_exit(command, 0)
    session.pin(qualification / "result.json", QUALIFICATION_SHA)
    compared = []
    for label in ("one", "two"):
        generated = session.out / ("regenerated-" + label)
        command = session.python_command("generate-" + label, "reference/generate_corpus.py",
            manual + ["--qualification", qualification / "result.json", "--output", generated])
        session.require_exit(command, 0)
        if {p.name for p in generated.iterdir()} != CORPUS_NAMES | {"manifest.json"}:
            raise ValueError("regenerated file set differs")
        for name in sorted(CORPUS_NAMES | {"manifest.json"}):
            if (generated / name).read_bytes() != (session.data / name).read_bytes():
                raise ValueError("regenerated bytes differ: " + label + "/" + name)
            compared.append({"run": label, "file": name, **session.file_identity(generated / name)})
    return {"manual_qualification_sha256": QUALIFICATION_SHA, "regenerated_runs": 2,
            "raw_files_compared_per_run": 10, "comparisons": compared,
            "records": 13957, "manifest_sha256": MANIFEST_SHA}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[3])
    parser.add_argument("--timeout", type=int, default=300, help="per child, 1..3600 seconds")
    parser.add_argument("--driver", type=Path)
    parser.add_argument("--driver-sha256")
    parser.add_argument("--mutations", action="store_true")
    parser.add_argument("--cargo", type=Path)
    parser.add_argument("--cargo-sha256")
    parser.add_argument("--rustc", type=Path)
    parser.add_argument("--rustc-sha256")
    args = parser.parse_args()
    args.repo = args.repo.resolve(strict=True)
    if os.name != "posix":
        parser.error("this process-retention implementation requires POSIX")
    if not 1 <= args.timeout <= 3600:
        parser.error("timeout must be in 1..3600")
    if bool(args.driver) != bool(args.driver_sha256):
        parser.error("--driver and --driver-sha256 are required together")
    compiler = (args.cargo, args.cargo_sha256, args.rustc, args.rustc_sha256)
    if (args.mutations and not all(compiler)) or (not args.mutations and any(compiler)):
        parser.error("all four compiler path/hash options are required only with --mutations")
    if args.out.exists() or args.out.is_symlink():
        parser.error("--out must be fresh")
    if args.out.resolve().is_relative_to(args.repo):
        parser.error("--out must be outside the repository")
    session = None
    try:
        session = Session(args)
        manifest = unpack_and_admit(session, args)
        result = {"schema": 1, "result": "PASS", "data": reproduce_data(session, manifest)}
        if args.driver:
            values, child, comparison = session.driver("authored-driver", args.driver, args.driver_sha256)
            session.require_exit(child, 0)
            session.require_exit(comparison, 0)
            if values["classification"] != "match" or values.get("records") != 13957:
                raise ValueError("authored driver did not match the complete frozen corpus")
            result["driver"] = {"records": 13957, "child": child, "comparison": comparison}
        if args.mutations:
            raw = session.pin(session.packet / "reproduce_mutations.py", COMPANION_SHA)
            companion = session.snapshots / "reproduce_mutations.py"
            session.write(companion, raw)
            companion.chmod(0o400)
            admitted_bytes = session.pin(companion, COMPANION_SHA)
            namespace = {"__name__": "rpc_reproduction_mutations", "__file__": str(companion)}
            exec(compile(admitted_bytes, str(companion), "exec"), namespace)
            result["mutations"] = namespace["run"](session, args)
            session.pin(companion, COMPANION_SHA)
        session.recheck_modules()
        for name, digest in SOURCE_PINS.items():
            session.pin(args.repo / "src/node115-rpc-flat-materializer" / name, digest)
        result["limits"] = [
            "Default replay runs only authored mathematical/reference programs, not a captured target.",
            "A driver is caller-admitted authored code. SHA256 rejection of one known capture is only an accidental-target guard.",
            "No process sandbox or general executable provenance verification is provided.",
            "Expected files remain parent-only; the authored value child receives stdin inputs and no path arguments.",
            "This helper does not replay the separate static native-byte checker, transport suite, unit tests, debug or Linux builds.",
            "Reference-derived corpus agreement is not native execution, lifetime, allocator, or whole-RPC equivalence.",
            "Runtime output and compiled payloads may contain local paths; review before publication.",
        ]
        result["commands"] = session.commands
        session.json(session.out / "RESULT.json", result)
        print(json.dumps({"result": "PASS", "records": 13957,
                          "driver_requested": bool(args.driver), "mutations_requested": args.mutations}))
        return 0
    except Exception as exc:
        if session is not None:
            session.json(session.out / "FAILURE.json", {
                "result": "FAIL", "error_type": type(exc).__name__, "error": str(exc),
                "commands": session.commands,
                "limit": "No failed compiler/process/protocol outcome is a semantic detection.",
            })
        print("reproduction failed; retained receipts are authoritative: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

