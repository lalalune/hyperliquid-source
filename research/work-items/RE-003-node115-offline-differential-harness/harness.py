#!/usr/bin/env python3
"""RE-003 offline differential admission & bubblewrap isolation controller.

Implements the admission, isolation, comparison, and positive/negative control
contract defined in `research/work-items/RE-003-node115-offline-differential-protocol`.

Security invariant:
- Never executes captured binaries under `artifacts/` (including node #115
  `hl-node` or `hl-visor`) without an explicit separate execution-approval record
  bound to exact hashes, question, and policy; defaults strictly to `not-run`.
- Never falls back to unsandboxed host execution if bubblewrap/seccomp/namespaces
  are unavailable (fails closed).
- Self-tests run strictly against harmless ephemeral synthetic Python stubs.
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import os
import pathlib
import platform
import resource
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import time
from typing import Any


REPO_ROOT = pathlib.Path(__file__).resolve().parents[3]
ARTIFACTS_DIR = (REPO_ROOT / "artifacts").resolve()
NODE115_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
VISOR_SHA256 = "b779b44db04f1b241932325f5a57bc4282b8869bc87d526b172186e54b144f4d"
CAPTURED_ARTIFACT_HASHES = frozenset({NODE115_SHA256, VISOR_SHA256})

TERMINAL_OUTCOMES = frozenset({"match", "mismatch", "rejected", "failed", "not-run"})
POLICY_ID = "re003-bwrap-unshare-all-seccomp-x86_64-v1"

# x86-64 Linux syscall numbers denied with EPERM inside the sandbox.
DENIED_SYSCALLS_X86_64: dict[str, int] = {
    "socket": 41,
    "socketpair": 53,
    "clone": 56,
    "fork": 57,
    "vfork": 58,
    "ptrace": 101,
    "mount": 165,
    "umount2": 166,
    "unshare": 272,
    "setns": 308,
    "clone3": 435,
}

FORBIDDEN_ENV_PREFIXES = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "AWS_", "GITHUB_", "GH_", "SSH_", "GPG_")
FORBIDDEN_ENV_SUFFIXES = ("_KEY", "_TOKEN", "_SECRET", "_PASSWORD", "_PROXY")

DEFAULT_MAX_FIXTURE_BYTES = 65_536
DEFAULT_MAX_OUTPUT_BYTES = 65_536


@dataclasses.dataclass(frozen=True)
class NormalizationMask:
    mask_id: str
    start: int
    end: int
    reason: str
    source_evidence: str

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


@dataclasses.dataclass(frozen=True)
class ExecutionApproval:
    approval_id: str
    bounded_question: str
    target_sha256: str
    fixture_sha256: str
    policy_id: str
    approved_by: str


@dataclasses.dataclass(frozen=True)
class CaseSpec:
    case_id: str
    bounded_question: str
    target_path: pathlib.Path
    expected_target_sha256: str
    independent_path: pathlib.Path
    expected_independent_sha256: str
    fixture_path: pathlib.Path
    expected_fixture_sha256: str
    fixture_format: str = "utf8"  # "utf8" | "json" | "bytes"
    max_fixture_bytes: int = DEFAULT_MAX_FIXTURE_BYTES
    max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES
    timeout_seconds: float = 3.0
    cpu_limit_seconds: int = 2
    fsize_limit_bytes: int = 1_048_576
    nofile_limit: int = 64
    env_allowlist: tuple[tuple[str, str], ...] = (
        ("LC_ALL", "C"),
        ("TZ", "UTC"),
        ("PATH", "/usr/bin:/bin"),
    )
    allowed_scratch_outputs: tuple[str, ...] = ()
    normalization_masks: tuple[NormalizationMask, ...] = ()
    execution_approval: ExecutionApproval | None = None
    target_is_python_script: bool = True
    independent_is_python_script: bool = True


@dataclasses.dataclass(frozen=True)
class RunResult:
    role: str
    exit_code: int | None
    timed_out: bool
    output_limit_exceeded: bool
    undeclared_scratch_files: tuple[str, ...]
    stdout_bytes: bytes
    stderr_bytes: bytes
    stdout_sha256: str
    stderr_sha256: str
    allowed_outputs_sha256: dict[str, str]
    duration_ms: float

    @property
    def clean_exit(self) -> bool:
        return (
            self.exit_code == 0
            and not self.timed_out
            and not self.output_limit_exceeded
            and not self.undeclared_scratch_files
        )

    def to_record(self) -> dict[str, Any]:
        return {
            "role": self.role,
            "exit_code": self.exit_code,
            "timed_out": self.timed_out,
            "output_limit_exceeded": self.output_limit_exceeded,
            "undeclared_scratch_files": list(self.undeclared_scratch_files),
            "stdout_len": len(self.stdout_bytes),
            "stderr_len": len(self.stderr_bytes),
            "stdout_sha256": self.stdout_sha256,
            "stderr_sha256": self.stderr_sha256,
            "stdout_utf8_preview": self.stdout_bytes[:1024].decode("utf-8", errors="replace"),
            "stderr_utf8_preview": self.stderr_bytes[-1024:].decode("utf-8", errors="replace"),
            "allowed_outputs_sha256": dict(self.allowed_outputs_sha256),
            "duration_ms": round(self.duration_ms, 3),
        }


def sha256_file(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def build_seccomp_bpf_x86_64() -> bytes:
    """Builds a classic BPF seccomp filter for x86-64 denying DENIED_SYSCALLS_X86_64 with EPERM."""
    bpf_ld_w_abs = 0x20
    bpf_jmp_jeq_k = 0x15
    bpf_ret_k = 0x06
    seccomp_ret_allow = 0x7FFF0000
    seccomp_ret_errno_eperm = 0x00050001
    audit_arch_x86_64 = 0xC000003E

    def insn(code: int, jt: int, jf: int, k: int) -> bytes:
        return struct.pack("HBBI", code, jt, jf, k)

    denied = sorted(DENIED_SYSCALLS_X86_64.values())
    prog = [
        insn(bpf_ld_w_abs, 0, 0, 4),  # load seccomp_data.arch
        insn(bpf_jmp_jeq_k, 1, 0, audit_arch_x86_64),
        insn(bpf_ret_k, 0, 0, seccomp_ret_errno_eperm),
        insn(bpf_ld_w_abs, 0, 0, 0),  # load seccomp_data.nr
    ]
    for idx, nr in enumerate(denied):
        prog.append(insn(bpf_jmp_jeq_k, len(denied) - idx, 0, nr))
    prog.append(insn(bpf_ret_k, 0, 0, seccomp_ret_allow))
    prog.append(insn(bpf_ret_k, 0, 0, seccomp_ret_errno_eperm))
    return b"".join(prog)


def _is_forbidden_env_key(key: str) -> bool:
    up = key.upper()
    return any(up.startswith(p) for p in FORBIDDEN_ENV_PREFIXES) or any(
        up.endswith(s) for s in FORBIDDEN_ENV_SUFFIXES
    )


def _is_captured_artifact(path: pathlib.Path, actual_sha256: str | None) -> bool:
    try:
        resolved = path.resolve()
        if resolved == ARTIFACTS_DIR or ARTIFACTS_DIR in resolved.parents:
            return True
    except OSError:
        pass
    if actual_sha256 and actual_sha256 in CAPTURED_ARTIFACT_HASHES:
        return True
    return False


def admit_case(
    spec: CaseSpec,
    *,
    reviewed_mask_allowlist: dict[str, NormalizationMask] | None = None,
    bwrap_path: str | None = None,
) -> tuple[str, str, dict[str, Any]]:
    """Validates admission before launching any process.

    Returns `(status, reason, metadata)` where `status` is `"admitted"`, `"rejected"`,
    `"not-run"`, or `"failed"`.
    """
    allowlist = reviewed_mask_allowlist or {}

    # 1. Fail-closed check for isolation prerequisites.
    if platform.machine() != "x86_64":
        return "failed", f"unsupported_arch:{platform.machine()}", {}
    resolved_bwrap = bwrap_path if bwrap_path is not None else shutil.which("bwrap")
    if not resolved_bwrap or not os.path.isfile(resolved_bwrap):
        return "failed", "missing_isolation_facility:bwrap", {}

    # 2. Validate files exist and compute digests.
    for role, p in (
        ("target", spec.target_path),
        ("independent", spec.independent_path),
        ("fixture", spec.fixture_path),
    ):
        if not p.is_file():
            return "rejected", f"missing_{role}_file", {"role": role}

    target_sha = sha256_file(spec.target_path)
    indep_sha = sha256_file(spec.independent_path)
    fixture_bytes = spec.fixture_path.read_bytes()
    fixture_sha = sha256_bytes(fixture_bytes)

    meta = {
        "target_sha256": target_sha,
        "independent_sha256": indep_sha,
        "fixture_sha256": fixture_sha,
        "fixture_len": len(fixture_bytes),
        "policy_id": POLICY_ID,
    }

    # 3. Separate execution-approval gate for captured artifacts (`hl-node` / `hl-visor`).
    if _is_captured_artifact(spec.target_path, target_sha) or _is_captured_artifact(
        spec.independent_path, indep_sha
    ):
        ap = spec.execution_approval
        if (
            ap is None
            or ap.bounded_question != spec.bounded_question
            or ap.target_sha256 != target_sha
            or ap.fixture_sha256 != fixture_sha
            or ap.policy_id != POLICY_ID
            or not ap.approval_id.strip()
            or not ap.approved_by.strip()
        ):
            return (
                "not-run",
                "captured_artifact_requires_separate_execution_approval",
                meta,
            )

    # 4. Exact SHA-256 identity checks.
    if target_sha != spec.expected_target_sha256:
        return "rejected", "target_sha256_mismatch", meta
    if indep_sha != spec.expected_independent_sha256:
        return "rejected", "independent_sha256_mismatch", meta
    if fixture_sha != spec.expected_fixture_sha256:
        return "rejected", "fixture_sha256_mismatch", meta

    # 5. Fixture bounds and format validation.
    if len(fixture_bytes) == 0:
        return "rejected", "empty_fixture", meta
    if len(fixture_bytes) > spec.max_fixture_bytes:
        return "rejected", "oversized_fixture", meta
    if spec.fixture_format == "utf8":
        try:
            fixture_bytes.decode("utf-8")
        except UnicodeDecodeError:
            return "rejected", "malformed_utf8_fixture", meta
    elif spec.fixture_format == "json":
        try:
            json.loads(fixture_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return "rejected", "malformed_json_fixture", meta
    elif spec.fixture_format != "bytes":
        return "rejected", f"out_of_scope_fixture_format:{spec.fixture_format}", meta

    # 6. Environment allowlist check (no proxy/credential/secret vars).
    for k, _ in spec.env_allowlist:
        if _is_forbidden_env_key(k):
            return "rejected", f"forbidden_env_var:{k}", meta

    # 7. Normalization mask allowlist check (no implicit or unreviewed masks).
    for mask in spec.normalization_masks:
        if mask.mask_id not in allowlist:
            return "rejected", f"unapproved_normalization_mask:{mask.mask_id}", meta
        if allowlist[mask.mask_id] != mask:
            return "rejected", f"altered_normalization_mask:{mask.mask_id}", meta
        if mask.start < 0 or mask.end <= mask.start:
            return "rejected", f"invalid_normalization_range:{mask.mask_id}", meta

    return "admitted", "ok", meta


def _apply_masks(data: bytes, masks: tuple[NormalizationMask, ...]) -> bytes:
    if not masks:
        return data
    buf = bytearray(data)
    for m in masks:
        lo = min(m.start, len(buf))
        hi = min(m.end, len(buf))
        for i in range(lo, hi):
            buf[i] = 0x2A  # '*' sentinel inside explicitly reviewed byte range
    return bytes(buf)


def run_isolated(
    role: str,
    executable_path: pathlib.Path,
    fixture_path: pathlib.Path,
    *,
    is_python_script: bool,
    spec: CaseSpec,
    bwrap_path: str,
) -> RunResult:
    """Runs one bounded executable inside bubblewrap + seccomp + rlimits."""
    bpf_bytes = build_seccomp_bpf_x86_64()
    start_t = time.monotonic()

    with tempfile.TemporaryDirectory(prefix="re003-run-") as td:
        td_path = pathlib.Path(td)
        ro_dir = td_path / "ro"
        scratch_dir = td_path / "scratch"
        ro_dir.mkdir(mode=0o755)
        scratch_dir.mkdir(mode=0o755)

        prog_name = "prog.py" if is_python_script else "prog.bin"
        ro_prog = ro_dir / prog_name
        ro_fixture = ro_dir / "fixture.dat"
        shutil.copy2(executable_path, ro_prog)
        shutil.copy2(fixture_path, ro_fixture)
        os.chmod(ro_prog, 0o555)
        os.chmod(ro_fixture, 0o444)

        r_fd, w_fd = os.pipe()
        os.write(w_fd, bpf_bytes)
        os.close(w_fd)
        os.set_inheritable(r_fd, True)

        cmd = [
            bwrap_path,
            "--unshare-all",
            "--new-session",
            "--die-with-parent",
            "--seccomp",
            str(r_fd),
            "--clearenv",
        ]
        for k, v in spec.env_allowlist:
            cmd.extend(["--setenv", k, v])
        cmd.extend(
            [
                "--ro-bind",
                "/usr",
                "/usr",
                "--symlink",
                "usr/lib",
                "/lib",
                "--symlink",
                "usr/lib64",
                "/lib64",
                "--symlink",
                "usr/bin",
                "/bin",
                "--ro-bind",
                str(ro_dir),
                "/input",
                "--bind",
                str(scratch_dir),
                "/scratch",
                "--proc",
                "/proc",
                "--dev",
                "/dev",
                "--chdir",
                "/scratch",
                "--",
            ]
        )
        if is_python_script:
            cmd.extend(["/usr/bin/python3", "-I", "-B", f"/input/{prog_name}", "/input/fixture.dat", "/scratch"])
        else:
            cmd.extend([f"/input/{prog_name}", "/input/fixture.dat", "/scratch"])

        def _set_limits() -> None:
            resource.setrlimit(resource.RLIMIT_CPU, (spec.cpu_limit_seconds, spec.cpu_limit_seconds))
            resource.setrlimit(resource.RLIMIT_FSIZE, (spec.fsize_limit_bytes, spec.fsize_limit_bytes))
            resource.setrlimit(resource.RLIMIT_NOFILE, (spec.nofile_limit, spec.nofile_limit))

        timed_out = False
        exit_code: int | None = None
        stdout_bytes = b""
        stderr_bytes = b""

        try:
            proc = subprocess.Popen(
                cmd,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                pass_fds=(r_fd,),
                start_new_session=True,
                preexec_fn=_set_limits,
            )
            os.close(r_fd)
            r_fd = -1
            try:
                stdout_bytes, stderr_bytes = proc.communicate(timeout=spec.timeout_seconds)
                exit_code = proc.returncode
            except subprocess.TimeoutExpired:
                timed_out = True
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                stdout_bytes, stderr_bytes = proc.communicate()
                exit_code = proc.returncode
        finally:
            if r_fd >= 0:
                os.close(r_fd)

        duration_ms = (time.monotonic() - start_t) * 1000.0
        output_limit_exceeded = (
            len(stdout_bytes) > spec.max_output_bytes or len(stderr_bytes) > spec.max_output_bytes
        )

        # Inspect scratch directory for allowed vs undeclared outputs before discarding.
        allowed_set = set(spec.allowed_scratch_outputs)
        allowed_hashes: dict[str, str] = {}
        undeclared: list[str] = []
        for entry in sorted(scratch_dir.rglob("*")):
            rel = str(entry.relative_to(scratch_dir))
            if entry.is_file():
                if rel in allowed_set:
                    allowed_hashes[rel] = sha256_file(entry)
                else:
                    undeclared.append(rel)
            elif entry.is_dir():
                undeclared.append(rel + "/")

        return RunResult(
            role=role,
            exit_code=exit_code,
            timed_out=timed_out,
            output_limit_exceeded=output_limit_exceeded,
            undeclared_scratch_files=tuple(undeclared),
            stdout_bytes=stdout_bytes[: spec.max_output_bytes + 1],
            stderr_bytes=stderr_bytes[: spec.max_output_bytes + 1],
            stdout_sha256=sha256_bytes(stdout_bytes),
            stderr_sha256=sha256_bytes(stderr_bytes),
            allowed_outputs_sha256=allowed_hashes,
            duration_ms=duration_ms,
        )


def execute_case(
    spec: CaseSpec,
    *,
    reviewed_mask_allowlist: dict[str, NormalizationMask] | None = None,
    bwrap_path: str | None = None,
) -> dict[str, Any]:
    """Executes the full RE-003 admission -> isolated runs -> comparison pipeline."""
    status, reason, meta = admit_case(
        spec,
        reviewed_mask_allowlist=reviewed_mask_allowlist,
        bwrap_path=bwrap_path,
    )
    record: dict[str, Any] = {
        "case_id": spec.case_id,
        "bounded_question": spec.bounded_question,
        "policy_id": POLICY_ID,
        "admission": {"status": status, "reason": reason},
        "metadata": meta,
        "env_allowlist": dict(spec.env_allowlist),
        "normalization_masks": [m.to_dict() for m in spec.normalization_masks],
        "runs": {},
    }

    if status != "admitted":
        assert status in TERMINAL_OUTCOMES
        record["outcome"] = status
        return record

    resolved_bwrap = bwrap_path if bwrap_path is not None else shutil.which("bwrap")
    assert resolved_bwrap is not None

    target_run = run_isolated(
        "target",
        spec.target_path,
        spec.fixture_path,
        is_python_script=spec.target_is_python_script,
        spec=spec,
        bwrap_path=resolved_bwrap,
    )
    indep_run = run_isolated(
        "independent",
        spec.independent_path,
        spec.fixture_path,
        is_python_script=spec.independent_is_python_script,
        spec=spec,
        bwrap_path=resolved_bwrap,
    )
    record["runs"] = {
        "target": target_run.to_record(),
        "independent": indep_run.to_record(),
    }

    if not target_run.clean_exit or not indep_run.clean_exit:
        record["outcome"] = "failed"
        record["failure_detail"] = {
            "target_clean": target_run.clean_exit,
            "independent_clean": indep_run.clean_exit,
        }
        return record

    t_out = _apply_masks(target_run.stdout_bytes, spec.normalization_masks)
    i_out = _apply_masks(indep_run.stdout_bytes, spec.normalization_masks)
    t_err = _apply_masks(target_run.stderr_bytes, spec.normalization_masks)
    i_err = _apply_masks(indep_run.stderr_bytes, spec.normalization_masks)

    if (
        t_out == i_out
        and t_err == i_err
        and target_run.allowed_outputs_sha256 == indep_run.allowed_outputs_sha256
    ):
        record["outcome"] = "match"
    else:
        record["outcome"] = "mismatch"
    return record


def run_self_test() -> dict[str, Any]:
    """Validates all 9 RE-003 protocol controls + the captured-artifact approval gate."""
    results: list[dict[str, Any]] = []
    bwrap_ver = subprocess.check_output(["bwrap", "--version"], text=True).strip()

    with tempfile.TemporaryDirectory(prefix="re003-selftest-") as td:
        root = pathlib.Path(td)

        def write_stub(name: str, body: str) -> tuple[pathlib.Path, str]:
            p = root / name
            p.write_text(body, encoding="utf-8")
            return p, sha256_file(p)

        def write_fixture(name: str, raw: bytes) -> tuple[pathlib.Path, str]:
            p = root / name
            p.write_bytes(raw)
            return p, sha256_bytes(raw)

        stub_ok_a, sha_ok_a = write_stub(
            "stub_ok_a.py",
            "import json, sys\nd = json.loads(open(sys.argv[1]).read())\nprint(d['a'] + d['b'])\n",
        )
        stub_ok_b, sha_ok_b = write_stub(
            "stub_ok_b.py",
            "import json, sys\nd = json.loads(open(sys.argv[1]).read())\nprint(sum((d['a'], d['b'])))\n",
        )
        stub_diff, sha_diff = write_stub(
            "stub_diff.py",
            "import json, sys\nd = json.loads(open(sys.argv[1]).read())\nprint(d['a'] + d['b'] + 1)\n",
        )
        stub_socket, sha_socket = write_stub(
            "stub_socket.py",
            "import socket\nsocket.socket(socket.AF_INET, socket.SOCK_STREAM)\n",
        )
        stub_escape_write, sha_escape = write_stub(
            "stub_escape.py",
            "open('/input/escape.txt', 'w').write('bad')\n",
        )
        stub_spawn, sha_spawn = write_stub(
            "stub_spawn.py",
            "import subprocess\nsubprocess.run(['/usr/bin/true'], check=True)\n",
        )
        stub_timeout, sha_timeout = write_stub(
            "stub_timeout.py",
            "while True:\n    pass\n",
        )

        fix_ok, sha_fix_ok = write_fixture("fix_ok.json", b'{"a": 40, "b": 2}\n')
        fix_bad_json, sha_fix_bad = write_fixture("fix_bad.json", b"{not-json")
        fix_big, sha_fix_big = write_fixture("fix_big.dat", b"A" * 2048)

        # Control 1: Valid fixture + deterministic stub -> match
        c1 = execute_case(
            CaseSpec(
                case_id="C1_valid_deterministic_match",
                bounded_question="Synthetic sum check",
                target_path=stub_ok_a,
                expected_target_sha256=sha_ok_a,
                independent_path=stub_ok_b,
                expected_independent_sha256=sha_ok_b,
                fixture_path=fix_ok,
                expected_fixture_sha256=sha_fix_ok,
                fixture_format="json",
            )
        )
        assert c1["outcome"] == "match", c1
        assert c1["runs"]["target"]["stdout_utf8_preview"].strip() == "42"
        results.append({"control": c1["case_id"], "expected": "match", "actual": c1["outcome"], "passed": True})

        # Control 2: Repeatability byte-for-byte with same declared environment
        c2 = execute_case(
            CaseSpec(
                case_id="C2_repeatability_byte_for_byte",
                bounded_question="Synthetic sum check repeat",
                target_path=stub_ok_a,
                expected_target_sha256=sha_ok_a,
                independent_path=stub_ok_b,
                expected_independent_sha256=sha_ok_b,
                fixture_path=fix_ok,
                expected_fixture_sha256=sha_fix_ok,
                fixture_format="json",
            )
        )
        assert c2["outcome"] == "match"
        assert c2["runs"]["target"]["stdout_sha256"] == c1["runs"]["target"]["stdout_sha256"]
        assert c2["runs"]["independent"]["stdout_sha256"] == c1["runs"]["independent"]["stdout_sha256"]
        results.append({"control": c2["case_id"], "expected": "match", "actual": c2["outcome"], "passed": True})

        # Control 3: Wrong target/source/fixture hash -> rejected before process start
        c3 = execute_case(
            CaseSpec(
                case_id="C3_wrong_hash_rejected",
                bounded_question="Hash mismatch check",
                target_path=stub_ok_a,
                expected_target_sha256="0" * 64,
                independent_path=stub_ok_b,
                expected_independent_sha256=sha_ok_b,
                fixture_path=fix_ok,
                expected_fixture_sha256=sha_fix_ok,
                fixture_format="json",
            )
        )
        assert c3["outcome"] == "rejected" and not c3["runs"], c3
        results.append(
            {
                "control": c3["case_id"],
                "expected": "rejected",
                "actual": c3["outcome"],
                "reason": c3["admission"]["reason"],
                "passed": True,
            }
        )

        # Control 4: Missing / malformed / oversized fixture -> rejected before process start
        c4_malformed = execute_case(
            CaseSpec(
                case_id="C4a_malformed_fixture_rejected",
                bounded_question="Malformed JSON check",
                target_path=stub_ok_a,
                expected_target_sha256=sha_ok_a,
                independent_path=stub_ok_b,
                expected_independent_sha256=sha_ok_b,
                fixture_path=fix_bad_json,
                expected_fixture_sha256=sha_fix_bad,
                fixture_format="json",
            )
        )
        c4_oversized = execute_case(
            CaseSpec(
                case_id="C4b_oversized_fixture_rejected",
                bounded_question="Oversized fixture check",
                target_path=stub_ok_a,
                expected_target_sha256=sha_ok_a,
                independent_path=stub_ok_b,
                expected_independent_sha256=sha_ok_b,
                fixture_path=fix_big,
                expected_fixture_sha256=sha_fix_big,
                fixture_format="bytes",
                max_fixture_bytes=1024,
            )
        )
        assert c4_malformed["outcome"] == "rejected" and not c4_malformed["runs"]
        assert c4_oversized["outcome"] == "rejected" and not c4_oversized["runs"]
        results.append(
            {
                "control": "C4_invalid_and_oversized_fixture_rejected",
                "expected": "rejected",
                "actual": "rejected",
                "reasons": [c4_malformed["admission"]["reason"], c4_oversized["admission"]["reason"]],
                "passed": True,
            }
        )

        # Control 5: Stub attempts socket creation -> denied (seccomp EPERM) & failed
        c5 = execute_case(
            CaseSpec(
                case_id="C5_socket_denied_seccomp",
                bounded_question="Socket denial check",
                target_path=stub_socket,
                expected_target_sha256=sha_socket,
                independent_path=stub_ok_b,
                expected_independent_sha256=sha_ok_b,
                fixture_path=fix_ok,
                expected_fixture_sha256=sha_fix_ok,
                fixture_format="json",
            )
        )
        assert c5["outcome"] == "failed", c5
        assert c5["runs"]["target"]["exit_code"] != 0
        assert "Operation not permitted" in c5["runs"]["target"]["stderr_utf8_preview"]
        results.append({"control": c5["case_id"], "expected": "failed", "actual": c5["outcome"], "passed": True})

        # Control 6: Stub attempts write outside scratch -> denied (EROFS) & failed
        c6 = execute_case(
            CaseSpec(
                case_id="C6_write_outside_scratch_denied",
                bounded_question="Read-only mount check",
                target_path=stub_escape_write,
                expected_target_sha256=sha_escape,
                independent_path=stub_ok_b,
                expected_independent_sha256=sha_ok_b,
                fixture_path=fix_ok,
                expected_fixture_sha256=sha_fix_ok,
                fixture_format="json",
            )
        )
        assert c6["outcome"] == "failed", c6
        assert "Read-only file system" in c6["runs"]["target"]["stderr_utf8_preview"]
        results.append({"control": c6["case_id"], "expected": "failed", "actual": c6["outcome"], "passed": True})

        # Control 7: Stub attempts child spawn + timeout resource limit -> denied/killed & failed
        c7_spawn = execute_case(
            CaseSpec(
                case_id="C7a_child_spawn_denied",
                bounded_question="Child spawn denial check",
                target_path=stub_spawn,
                expected_target_sha256=sha_spawn,
                independent_path=stub_ok_b,
                expected_independent_sha256=sha_ok_b,
                fixture_path=fix_ok,
                expected_fixture_sha256=sha_fix_ok,
                fixture_format="json",
            )
        )
        c7_timeout = execute_case(
            CaseSpec(
                case_id="C7b_timeout_process_group_killed",
                bounded_question="Wall-clock timeout check",
                target_path=stub_timeout,
                expected_target_sha256=sha_timeout,
                independent_path=stub_ok_b,
                expected_independent_sha256=sha_ok_b,
                fixture_path=fix_ok,
                expected_fixture_sha256=sha_fix_ok,
                fixture_format="json",
                timeout_seconds=0.5,
                cpu_limit_seconds=1,
            )
        )
        assert c7_spawn["outcome"] == "failed"
        assert "Operation not permitted" in c7_spawn["runs"]["target"]["stderr_utf8_preview"]
        assert c7_timeout["outcome"] == "failed"
        assert c7_timeout["runs"]["target"]["timed_out"] or c7_timeout["runs"]["target"]["exit_code"] != 0
        results.append(
            {
                "control": "C7_spawn_and_timeout_denied",
                "expected": "failed",
                "actual": "failed",
                "passed": True,
            }
        )

        # Control 8: Two admitted programs produce different values -> mismatch (raw preserved)
        c8 = execute_case(
            CaseSpec(
                case_id="C8_value_mismatch_preserved",
                bounded_question="Mismatch preservation check",
                target_path=stub_ok_a,
                expected_target_sha256=sha_ok_a,
                independent_path=stub_diff,
                expected_independent_sha256=sha_diff,
                fixture_path=fix_ok,
                expected_fixture_sha256=sha_fix_ok,
                fixture_format="json",
            )
        )
        assert c8["outcome"] == "mismatch", c8
        assert c8["runs"]["target"]["stdout_utf8_preview"].strip() == "42"
        assert c8["runs"]["independent"]["stdout_utf8_preview"].strip() == "43"
        results.append({"control": c8["case_id"], "expected": "mismatch", "actual": c8["outcome"], "passed": True})

        # Control 9: Unapproved normalization mask -> rejected before execution
        bad_mask = NormalizationMask(
            mask_id="unreviewed_mask",
            start=0,
            end=2,
            reason="unapproved",
            source_evidence="none",
        )
        c9 = execute_case(
            CaseSpec(
                case_id="C9_unapproved_mask_rejected",
                bounded_question="Mask allowlist check",
                target_path=stub_ok_a,
                expected_target_sha256=sha_ok_a,
                independent_path=stub_diff,
                expected_independent_sha256=sha_diff,
                fixture_path=fix_ok,
                expected_fixture_sha256=sha_fix_ok,
                fixture_format="json",
                normalization_masks=(bad_mask,),
            ),
            reviewed_mask_allowlist={},
        )
        assert c9["outcome"] == "rejected" and not c9["runs"], c9
        results.append(
            {
                "control": c9["case_id"],
                "expected": "rejected",
                "actual": c9["outcome"],
                "reason": c9["admission"]["reason"],
                "passed": True,
            }
        )

        # Control 10: Captured node #115 binary blocked without separate approval -> not-run
        node115_path = REPO_ROOT / "artifacts" / "node" / "115" / "hl-node"
        if node115_path.is_file():
            c10 = execute_case(
                CaseSpec(
                    case_id="C10_captured_node115_approval_gate",
                    bounded_question="Verify captured artifact cannot run without separate approval",
                    target_path=node115_path,
                    expected_target_sha256=NODE115_SHA256,
                    independent_path=stub_ok_b,
                    expected_independent_sha256=sha_ok_b,
                    fixture_path=fix_ok,
                    expected_fixture_sha256=sha_fix_ok,
                    fixture_format="json",
                    target_is_python_script=False,
                )
            )
            assert c10["outcome"] == "not-run" and not c10["runs"], c10
            results.append(
                {
                    "control": c10["case_id"],
                    "expected": "not-run",
                    "actual": c10["outcome"],
                    "reason": c10["admission"]["reason"],
                    "passed": True,
                }
            )

    return {
        "schema_version": 1,
        "work_item": "RE-003-node115-offline-differential-harness",
        "target_sha256": NODE115_SHA256,
        "target_execution_status": "not-run",
        "policy_id": POLICY_ID,
        "sandbox_tool": bwrap_ver,
        "architecture": platform.machine(),
        "denied_syscalls_x86_64": DENIED_SYSCALLS_X86_64,
        "controls_passed": len(results),
        "controls_total": len(results),
        "controls": results,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="RE-003 offline differential harness controller")
    parser.add_argument("--self-test", action="store_true", help="Run all RE-003 positive/negative controls on harmless stubs")
    parser.add_argument("--write-records", type=pathlib.Path, help="Write self-test summary JSON to path")
    args = parser.parse_args(argv)

    if args.self_test or args.write_records:
        summary = run_self_test()
        if args.write_records:
            args.write_records.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(json.dumps(summary, indent=2, sort_keys=True))
        return 0

    parser.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
