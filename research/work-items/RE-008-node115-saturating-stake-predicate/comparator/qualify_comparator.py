#!/usr/bin/env python3
"""Finite synthetic qualification for the parent result comparator.

This does not generate or use stake inputs, target expectations or a driver.
No subprocess is launched. Run only after the paired sources are admitted.
"""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import types

HOST_CONTRACT_SHA256 = "4bb6a164423609b2310b7952351be5e88f8583d205b1ec144e9393cfde92a28e"
MAX = b"18446744073709551615"
BASE = (
    b"A\tok\t0\t0\t0\n"
    b"b\tok\t" + MAX + b"\t1\t1\n"
    b"C\tbounds\n"
    b"d\torder\n"
    b"E\tok\t1\t" + MAX + b"\t0\n"
)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_exact(path: Path, pin: str):
    raw = path.read_bytes()
    if sha(raw) != pin:
        raise ValueError("comparator source digest mismatch")
    module = types.ModuleType("stake_comparator_synthetic_qualification")
    module.__file__ = str(path)
    # Execute exactly the hashed source buffer; never load a cached .pyc.
    exec(compile(raw, str(path), "exec"), module.__dict__)
    if module.HOST_CONTRACT_SHA256 != HOST_CONTRACT_SHA256:
        raise ValueError("host contract identity mismatch")
    return module


def run_controls(module, scratch: Path) -> tuple[list[dict], dict | None]:
    records: list[dict] = []

    def check(name: str, actual: dict, kind: str, reason: str | None = None,
              mismatch_count: int | None = None, format_reason: str | None = None):
        good = actual.get("kind") == kind
        if reason is not None:
            good = good and actual.get("reason") == reason
        if mismatch_count is not None:
            good = good and actual.get("mismatch_count") == mismatch_count
        if format_reason is not None:
            good = good and actual.get("format_reason") == format_reason
        row = {"name": name, "passed": bool(good), "observed": actual}
        records.append(row)
        if not good:
            raise ControlFailure(row)

    def compare(actual: bytes, expected: bytes = BASE, exit_code: int = 0,
                stderr: bytes = b"") -> dict:
        return module.compare_bytes(expected, actual, exit_code, stderr)

    def grammar(name: str, raw: bytes, reason: str):
        check(name, compare(raw, b"x\tok\t1\t2\t0\n"),
              "qualification_failure", "actual_format", format_reason=reason)

    try:
        check("equal_mixed_statuses_and_B_greater_than_S", compare(BASE), "match", mismatch_count=0)
        check("empty_completed_stream", compare(b"", b""), "match", mismatch_count=0)
        arbitrary = b"x\tok\t" + MAX + b"\t0\t0\n"
        check("no_predicate_or_B_le_S_recomputation",
              compare(arbitrary, arbitrary), "match", mismatch_count=0)
        case_ids = b"A\tbounds\na\torder\n"
        check("case_distinct_ids", compare(case_ids, case_ids), "match", mismatch_count=0)

        for name, old, new in [
            ("selected_only_changes", b"E\tok\t1\t", b"E\tok\t2\t"),
            ("total_only_changes", b"b\tok\t" + MAX + b"\t1\t",
             b"b\tok\t" + MAX + b"\t2\t"),
            ("boolean_only_changes", b"A\tok\t0\t0\t0\n", b"A\tok\t0\t0\t1\n"),
            ("last_row_value_not_ignored", b"E\tok\t1\t" + MAX + b"\t0\n",
             b"E\tok\t1\t" + MAX + b"\t1\n"),
            ("bounds_to_order_is_value_difference", b"C\tbounds\n", b"C\torder\n"),
            ("order_to_ok_is_value_difference", b"d\torder\n", b"d\tok\t1\t2\t0\n"),
            ("ok_to_bounds_is_value_difference", b"A\tok\t0\t0\t0\n", b"A\tbounds\n"),
        ]:
            check(name, compare(BASE.replace(old, new)), "value_mismatch",
                  "different_values", mismatch_count=1)
        all_changed = (
            b"A\torder\nb\tbounds\nC\torder\nd\tbounds\nE\tbounds\n"
        )
        check("count_all_value_mismatches", compare(all_changed),
              "value_mismatch", "different_values", mismatch_count=5)

        rows = BASE.splitlines(keepends=True)
        check("missing_last_row", compare(b"".join(rows[:-1])),
              "qualification_failure", "missing_rows")
        check("missing_middle_row", compare(b"".join(rows[:2] + rows[3:])),
              "qualification_failure", "missing_rows")
        check("missing_all_rows", compare(b""), "qualification_failure", "missing_rows")
        check("extra_unique_row", compare(BASE + b"extra\torder\n"),
              "qualification_failure", "extra_rows")
        check("unexpected_row_for_empty", compare(b"x\torder\n", b""),
              "qualification_failure", "extra_rows")
        check("duplicate_existing_extra_row", compare(BASE + rows[0]),
              "qualification_failure", "duplicate_rows", format_reason="duplicate_id")
        check("duplicate_existing_same_count", compare(BASE.replace(b"E\t", b"A\t")),
              "qualification_failure", "duplicate_rows", format_reason="duplicate_id")
        check("same_ids_wrong_order", compare(b"".join([rows[1], rows[0], *rows[2:]])),
              "qualification_failure", "id_order")
        check("unknown_id_same_count", compare(BASE.replace(b"E\t", b"Z\t")),
              "qualification_failure", "id_identity")
        check("id_case_not_folded", compare(BASE.replace(b"A\t", b"a\t")),
              "qualification_failure", "id_identity")

        for name, raw, reason in [
            ("missing_final_lf", b"x\tok\t1\t2\t0", "missing_final_lf"),
            ("crlf", b"x\tok\t1\t2\t0\r\n", "forbidden_byte"),
            ("nul", b"x\x00\tok\t1\t2\t0\n", "forbidden_byte"),
            ("non_ascii", b"x\tok\t1\t2\t0\xff\n", "non_ascii"),
            ("utf8_bom", b"\xef\xbb\xbfx\tok\t1\t2\t0\n", "non_ascii"),
            ("blank_line", b"\n", "blank_line"),
            ("extra_final_lf", b"x\tok\t1\t2\t0\n\n", "blank_line"),
            ("blank_middle", b"x\torder\n\ny\tbounds\n", "blank_line"),
            ("empty_id", b"\tok\t1\t2\t0\n", "invalid_id"),
            ("space_id", b"x y\tok\t1\t2\t0\n", "invalid_id"),
            ("slash_id", b"x/y\tok\t1\t2\t0\n", "invalid_id"),
            ("overlong_id", b"x" * 65 + b"\tok\t1\t2\t0\n", "invalid_id"),
            ("no_status", b"x\n", "field_count"),
            ("unknown_status", b"x\tsuccess\t1\t2\t0\n", "invalid_status"),
            ("uppercase_status", b"x\tOK\t1\t2\t0\n", "invalid_status"),
            ("status_space", b"x\torder \n", "invalid_status"),
            ("ok_missing_field", b"x\tok\t1\t2\n", "field_count"),
            ("ok_extra_field", b"x\tok\t1\t2\t0\t0\n", "field_count"),
            ("bounds_extra_field", b"x\tbounds\t0\n", "field_count"),
            ("order_extra_field", b"x\torder\t0\n", "field_count"),
        ]:
            grammar(name, raw, reason)
        for column in (2, 3):
            for label, raw in [
                ("sign_plus", b"+1"), ("negative", b"-1"), ("leading_zero", b"01"),
                ("empty", b""), ("space", b" 1"), ("hex", b"0x1"),
                ("overflow", b"18446744073709551616"), ("too_long", b"1" * 21),
            ]:
                fields = [b"x", b"ok", b"1", b"2", b"0"]
                fields[column] = raw
                grammar(f"sum{column}_{label}", b"\t".join(fields) + b"\n",
                        "u64_overflow" if label == "overflow" else "noncanonical_u64")
        for label, raw in [("word", b"true"), ("two", b"2"), ("double_zero", b"00"),
                           ("empty", b""), ("space", b" 0")]:
            grammar("boolean_" + label, b"x\tok\t1\t2\t" + raw + b"\n",
                    "invalid_boolean")

        check("invalid_expected_not_a_mismatch", compare(BASE, b"x\tbogus\n"),
              "qualification_failure", "expected_format", format_reason="invalid_status")
        check("duplicate_expected_not_a_mismatch", compare(BASE, b"x\torder\nx\torder\n"),
              "qualification_failure", "expected_format", format_reason="duplicate_id")
        check("matching_output_nonzero_child_exit", compare(BASE, exit_code=2),
              "qualification_failure", "process_failure")
        check("matching_output_signal_exit", compare(BASE, exit_code=-9),
              "qualification_failure", "process_failure")
        check("matching_output_unexpected_stderr", compare(BASE, stderr=b"diagnostic"),
              "qualification_failure", "process_failure")
        check("process_failure_precedes_actual_grammar",
              compare(b"bad", exit_code=1), "qualification_failure", "process_failure")
        check("expected_grammar_precedes_process_failure",
              compare(b"bad", b"bad", exit_code=1),
              "qualification_failure", "expected_format")
        check("boolean_is_not_exit_integer", compare(BASE, exit_code=False),
              "qualification_failure", "invalid_process_exit")

        maximum_rows = b"".join(
            f"r{i:04d}\torder\n".encode("ascii") for i in range(module.MAX_ROWS)
        )
        check("exact_output_record_limit", compare(maximum_rows, maximum_rows), "match")
        check("over_output_record_limit",
              compare(maximum_rows + b"overflow\torder\n", maximum_rows),
              "qualification_failure", "actual_format", format_reason="record_limit")
        maximum_bytes = b"".join(
            b"r" + f"{i:04d}".encode("ascii") + b"x" * 59
            + b"\tok\t" + MAX + b"\t" + MAX + b"\t1\n"
            for i in range(module.MAX_ROWS)
        )
        if len(maximum_bytes) != module.MAX_OUTPUT_BYTES:
            raise ControlFailure({"name": "derived_output_limit_length", "passed": False})
        check("exact_derived_output_byte_limit",
              compare(maximum_bytes, maximum_bytes), "match")
        check("over_output_byte_limit",
              compare(maximum_bytes + b"\n", maximum_bytes),
              "qualification_failure", "actual_format", format_reason="output_byte_limit")

        for name, data, pin, should_pass in [
            ("right_digest", BASE, sha(BASE), True),
            ("modified_buffer_below_file_name", BASE + b"x", sha(BASE), False),
            ("wrong_digest", BASE, "0" * 64, False),
            ("noncanonical_digest", BASE, sha(BASE).upper(), False),
        ]:
            admitted = True
            try:
                module.verify_digest(data, pin, "synthetic")
            except module.ArtifactError:
                admitted = False
            row = {"name": name, "passed": admitted == should_pass,
                   "admitted": admitted, "expected_admitted": should_pass}
            records.append(row)
            if not row["passed"]:
                raise ControlFailure(row)

        # Parent CLI and readback controls use only fresh synthetic regular files.
        with tempfile.TemporaryDirectory(prefix="synthetic-", dir=scratch) as temp:
            root = Path(temp)
            expected_file, actual_file, stderr_file = (
                root / "expected.tsv", root / "stdout.bin", root / "stderr.bin"
            )
            expected_file.write_bytes(BASE)
            actual_file.write_bytes(BASE)
            stderr_file.write_bytes(b"")

            def cli(name, wanted_kind, wanted_code, *, actual=BASE, stderr=b"",
                    exit_code=0, wrong_pin_role=None, extra_arg=False,
                    missing_actual=False):
                actual_file.write_bytes(actual)
                stderr_file.write_bytes(stderr)
                args = [
                    "--expected", str(expected_file), "--expected-sha256",
                    "0" * 64 if wrong_pin_role == "expected" else sha(BASE),
                    "--actual", str(root / "missing.bin" if missing_actual else actual_file),
                    "--actual-sha256",
                    "0" * 64 if wrong_pin_role == "actual" else sha(actual),
                    "--stderr", str(stderr_file), "--stderr-sha256",
                    "0" * 64 if wrong_pin_role == "stderr" else sha(stderr),
                    "--exit-code", str(exit_code),
                ]
                if extra_arg:
                    args.append("--unexpected")
                out, err = io.StringIO(), io.StringIO()
                with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                    try:
                        code = module.main(args)
                    except SystemExit as failure:
                        code = failure.code
                if extra_arg:
                    good = code == wanted_code and not out.getvalue() and bool(err.getvalue())
                    observed = {"code": code, "stdout_empty": not out.getvalue(),
                                "stderr_nonempty": bool(err.getvalue())}
                else:
                    parsed = json.loads(out.getvalue())
                    good = code == wanted_code and parsed.get("kind") == wanted_kind
                    good = good and not err.getvalue()
                    if wrong_pin_role is not None:
                        good = good and parsed.get("reason") == "artifact_admission"
                        good = good and parsed.get("artifact") == wrong_pin_role
                        good = good and parsed.get("detail") == "digest_mismatch"
                    if missing_actual:
                        good = good and parsed.get("reason") == "artifact_io"
                    if wrong_pin_role is None and not missing_actual:
                        good = good and parsed["artifacts"]["actual"]["bytes"] == len(actual)
                        good = good and parsed["artifacts"]["stderr"]["bytes"] == len(stderr)
                    observed = {"code": code, "result": parsed, "stderr_empty": not err.getvalue()}
                row = {"name": name, "passed": bool(good), "observed": observed}
                records.append(row)
                if not good:
                    raise ControlFailure(row)

            cli("cli_exact_match", "match", 0)
            cli("cli_value_mismatch_exit1", "value_mismatch", 1,
                actual=BASE.replace(b"C\tbounds", b"C\torder"))
            cli("cli_duplicate_is_failure_exit2", "qualification_failure", 2,
                actual=BASE + BASE.splitlines(keepends=True)[0])
            cli("cli_bad_expected_pin", "qualification_failure", 2,
                wrong_pin_role="expected")
            cli("cli_bad_actual_pin", "qualification_failure", 2,
                wrong_pin_role="actual")
            cli("cli_bad_stderr_pin", "qualification_failure", 2,
                wrong_pin_role="stderr")
            cli("cli_missing_artifact_is_io_failure", "qualification_failure", 2,
                missing_actual=True)
            cli("cli_nonzero_recorded_process_exit", "qualification_failure", 2, exit_code=7)
            cli("cli_stderr_hashes_complete_raw_file", "qualification_failure", 2,
                stderr=b"synthetic-child-diagnostic\n")
            cli("cli_unknown_argument_refuses", None, 2, extra_arg=True)
            prefix, metadata = module.read_pinned(actual_file, sha(actual_file.read_bytes()),
                                                  "actual", 3)
            good = prefix == actual_file.read_bytes()[:3]
            good = good and metadata["bytes"] == actual_file.stat().st_size
            row = {"name": "read_prefix_does_not_truncate_hash_or_length",
                   "passed": bool(good), "observed": metadata}
            records.append(row)
            if not good:
                raise ControlFailure(row)
    except ControlFailure as error:
        return records, error.record
    return records, None


class ControlFailure(Exception):
    def __init__(self, record: dict):
        super().__init__(record["name"])
        self.record = record


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--comparator", type=Path, required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--scratch", type=Path, required=True,
                        help="fresh private directory for synthetic files")
    args = parser.parse_args(argv)
    try:
        module = load_exact(args.comparator, args.sha256)
        args.scratch.mkdir(mode=0o700, exist_ok=False)
        controls, failed = run_controls(module, args.scratch)
    except (OSError, ValueError, SyntaxError, KeyError, TypeError) as error:
        print(json.dumps({"kind": "qualification_error",
                          "exception": type(error).__name__}, sort_keys=True))
        return 2
    report = {
        "schema": "stake-comparator-synthetic-qualification-v1",
        "comparator_sha256": args.sha256,
        "host_contract_sha256": HOST_CONTRACT_SHA256,
        "synthetic_only": True,
        "target_cases_or_driver_used": False,
        "subprocesses_launched": 0,
        "controls": controls,
        "passed": sum(row["passed"] for row in controls),
        "failed": failed,
    }
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

