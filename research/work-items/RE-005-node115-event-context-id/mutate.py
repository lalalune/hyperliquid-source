#!/usr/bin/env python3
"""Mutation check for the node115-event-context-id crate tests.

Every variant is a private copy of the crate (plus the permutation source it reuses)
under a NEW output directory; the crate in the repository is only read. Build and run
are separate steps, so a mutant that fails to compile is reported as such and never
counted as caught by a test. A run that fails without naming a failed test is an
environment error and stops the tool with exit status 2.

Usage: mutate.py --outdir NEW_DIRECTORY [--selftest]
Exit status: 0 all mutants caught by an expected test, 1 a mutant survived / mis-caught /
did not compile, 2 environment error or invalid mutant definition.
"""
import argparse
import json
import re
import shutil
import subprocess
import sys

from tool_common import CRATE, ROOT, fresh_outdir

CORPUS = "function_level_corpus_matches_spec_derived_expectations"
BRANCH = "branch_choice_at_every_threshold"
SPOT = ["spot_deploy_context_is_zero_unless_the_tag_is_one", "spot_deploy_call_site_passes_third_value_zero"]

# (name, old text (must occur exactly once), new text, tests of which at least one must fail)
MUTANTS = [
    ("mode2-packed-from-strict", "a >= MODE2_PACKED_FROM", "a > MODE2_PACKED_FROM", [BRANCH, CORPUS]),
    ("mode2-arith-above-inclusive", "if a > MODE2_ARITH_ABOVE {", "if a >= MODE2_ARITH_ABOVE {", [BRANCH, CORPUS]),
    ("later-abi-up-to-strict", "a <= LATER_ABI_UP_TO", "a < LATER_ABI_UP_TO", [BRANCH, CORPUS]),
    ("later-arith-above-inclusive", "a > LATER_ARITH_ABOVE", "a >= LATER_ARITH_ABOVE", [BRANCH, CORPUS]),
    ("mode-2-treated-as-arithmetic", "if mode < 2 {", "if mode <= 2 {", [BRANCH, CORPUS]),
    ("later-modes-use-mode-2-rules", "if mode == 2 {", "if mode >= 2 {", [BRANCH, CORPUS]),
    ("multiplier-last-digit", "0xf135_7aea_2e62_a9c5", "0xf135_7aea_2e62_a9c4", [CORPUS]),
    ("seed2-last-digit", "0xb182_5c50_e63c_e358", "0xb182_5c50_e63c_e359", [CORPUS]),
    ("rotate-19", "const WORD_ROTATE: u32 = 20;", "const WORD_ROTATE: u32 = 19;", [CORPUS]),
    ("arith-words-little-endian", "chunk.copy_from_slice(&word.to_be_bytes());", "chunk.copy_from_slice(&word.to_le_bytes());", [CORPUS]),
    ("arith-ignores-c", ".wrapping_add(c)", ".wrapping_add(0)", [CORPUS]),
    ("abi-word-little-endian", "word[24..].copy_from_slice(&value.to_be_bytes());", "word[24..].copy_from_slice(&value.to_le_bytes());",
     ["abi_words_are_big_endian_in_the_last_eight_bytes", CORPUS]),
    ("pack-array-of-two", "out.push(&[0x90 | 3]);", "out.push(&[0x90 | 2]);", ["message_pack_width_boundaries", CORPUS]),
    ("pack-fixint-includes-0x80", "if value < 0x80 {", "if value <= 0x80 {", ["message_pack_width_boundaries", CORPUS]),
    ("pack-u8-marker", "self.push(&[0xcc, value as u8]);", "self.push(&[0xcd, value as u8]);", ["message_pack_width_boundaries", CORPUS]),
    ("pack-u16-includes-0x10000", "} else if value < 0x1_0000 {", "} else if value <= 0x1_0000 {", ["message_pack_width_boundaries", CORPUS]),
    ("pack-u32-limit-too-wide", "} else if value >> 32 == 0 {", "} else if value >> 33 == 0 {", ["message_pack_width_boundaries", CORPUS]),
    ("keccak-sha3-delimiter", "const KECCAK_DELIMITER: u8 = 0x01;", "const KECCAK_DELIMITER: u8 = 0x06;", ["keccak_short_matches_published_vectors", CORPUS]),
    ("keccak-final-bit-position", "block[RATE - 1] ^= 0x80;", "block[RATE - 2] ^= 0x80;", ["keccak_short_matches_published_vectors", CORPUS]),
    ("keccak-big-endian-lanes", "u64::from_le_bytes(bytes.try_into()", "u64::from_be_bytes(bytes.try_into()", ["keccak_short_matches_published_vectors", CORPUS]),
    ("overlay-starts-at-11", "const OVERLAY_START: usize = 10;", "const OVERLAY_START: usize = 11;",
     ["overlay_keeps_unwritten_bytes_and_drops_leading_zeros", CORPUS]),
    ("overlay-c-fit-strict", "if za + zb + 4 >= 9 - zc {", "if za + zb + 4 > 9 - zc {", ["overlay_skips_a_third_field_that_does_not_fit", CORPUS]),
    ("overlay-c-fit-one-short", "if za + zb + 4 >= 9 - zc {", "if za + zb + 3 >= 9 - zc {", ["overlay_skips_a_third_field_that_does_not_fit", CORPUS]),
    ("overlay-c-uses-b-zero-count", "put_length_prefixed(digest, after_b, c, zc);", "put_length_prefixed(digest, after_b, c, zb);", [CORPUS]),
    ("zero-keeps-one-byte", "(value.leading_zeros() / 8) as usize", "((value.leading_zeros() / 8) as usize).min(7)",
     ["overlay_keeps_unwritten_bytes_and_drops_leading_zeros", CORPUS]),
    ("spot-tag-nonzero", "if state_tag == 1 {", "if state_tag != 0 {", SPOT),
    ("spot-third-value-one", "        event_context(mode, word_28, word_08, 0)\n", "        event_context(mode, word_28, word_08, 1)\n", SPOT),
    ("spot-swaps-words", "        event_context(mode, word_28, word_08, 0)\n", "        event_context(mode, word_08, word_28, 0)\n", SPOT),
    ("spot-else-not-zero", "        [0; 32]\n", "        [1; 32]\n", SPOT),
]

# selftest controls: an equivalent edit must survive, a broken edit must not compile.
EQUIVALENT = ("equivalent-comment", "const RATE: usize = 136;", "const RATE: usize = 136; // same value", [])
BROKEN = ("does-not-compile", "fn leading_zero_bytes(value: u64) -> usize {", "fn leading_zero_bytes(value: u64) -> u32 {", [])


def stage(outdir, name):
    base = outdir / name
    crate = base / "src" / "node115-event-context-id"
    shutil.copytree(CRATE, crate, ignore=shutil.ignore_patterns("target"))
    (base / "src" / "node115-sponge-permutation").mkdir(parents=True)
    shutil.copy(ROOT / "src" / "node115-sponge-permutation" / "lib.rs", base / "src" / "node115-sponge-permutation" / "lib.rs")
    return base, crate


def cargo(base, crate, *extra):
    try:
        return subprocess.run(
            ["cargo", "test", "--offline", "--locked", "--manifest-path", str(crate / "Cargo.toml"),
             "--target-dir", str(base / "target"), *extra],
            cwd=base, capture_output=True, text=True, check=False)
    except FileNotFoundError:
        sys.exit("cargo not found on PATH")


def run_variant(outdir, name, edit):
    """Returns (status, failed_tests); status in baseline-pass|killed|survived|compile-error."""
    base, crate = stage(outdir, name)
    if edit:
        kind, old, new = edit
        path = crate / ("lib.rs" if kind == "lib" else "tests/cases.tsv")
        text = path.read_text()
        if text.count(old) != 1:
            sys.exit(f"invalid mutant {name}: pattern occurs {text.count(old)} times")
        path.write_text(text.replace(old, new))
    build = cargo(base, crate, "--no-run")
    if build.returncode != 0:
        return "compile-error", []
    run = cargo(base, crate, "--no-fail-fast")
    failed = sorted(t.rsplit("::", 1)[-1] for t in re.findall(r"^test (\S+) \.\.\. FAILED$", run.stdout, re.M))
    if run.returncode == 0:
        return "survived", []
    if not failed:
        sys.exit(f"{name}: test run failed without a failed test (environment error):\n{run.stderr[-800:]}")
    return "killed", failed


def flip_digit(row_prefix, column):
    """A one-hex-digit corruption of one corpus column in the first row with the given group."""
    text = (CRATE / "tests" / "cases.tsv").read_text()
    for line in text.splitlines():
        fields = line.split("\t")
        if len(fields) == 10 and fields[1] == row_prefix and fields[column] != "-":
            digit = fields[column][0]
            fields[column] = ("1" if digit == "0" else "0") + fields[column][1:]
            return line, "\t".join(fields)
    sys.exit(f"no corpus row for {row_prefix}")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--outdir", required=True)
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args()
    outdir = fresh_outdir(args.outdir)

    status, _ = run_variant(outdir, "baseline", None)
    if status != "survived":
        print(f"baseline is not green ({status}); mutation results would be meaningless")
        return 2
    results, problems = [{"name": "baseline", "status": "all tests pass"}], []

    def record(name, status, failed, expect, wanted):
        ok = status == wanted and (wanted != "killed" or any(t in failed for t in expect))
        results.append({"name": name, "status": status, "failed_tests": failed, "as_expected": ok})
        print(f"{'ok  ' if ok else 'FAIL'} {name}: {status} {failed}")
        if not ok:
            problems.append(name)

    name, old, new, expect = EQUIVALENT
    status, failed = run_variant(outdir, name, ("lib", old, new))
    record(name, status, failed, expect, "survived")
    name, old, new, expect = BROKEN
    status, failed = run_variant(outdir, name, ("lib", old, new))
    record(name, status, failed, expect, "compile-error")
    for label, group, column in (("corpus-bit-flip-context", "overlay-fit", 9), ("corpus-bit-flip-preimage", "msgpack-width", 7)):
        old, new = flip_digit(group, column)
        status, failed = run_variant(outdir, label, ("corpus", old, new))
        record(label, status, failed, [CORPUS], "killed")

    for name, old, new, expect in (MUTANTS[20:21] if args.selftest else MUTANTS):
        status, failed = run_variant(outdir, name, ("lib", old, new))
        record(name, status, failed, expect, "killed")

    (outdir / "mutation.json").write_text(json.dumps(results, indent=1) + "\n")
    mutants = [r for r in results if r["name"] in {m[0] for m in MUTANTS}]
    print(f"{len(mutants)} mutants run, {sum(r['as_expected'] for r in mutants)} caught by an expected test, "
          f"{len(problems)} problem(s) in total")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
