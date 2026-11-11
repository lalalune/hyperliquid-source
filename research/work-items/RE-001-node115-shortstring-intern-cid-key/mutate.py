#!/usr/bin/env python3
"""Mutation check for the crate's tests: one edit per copy, build then run.

For every mutant the crate is copied into a new directory, one exact-once text replacement is applied
to lib.rs, `cargo test --no-run` must succeed (a compile error is a tooling error, exit 2, never a
"kill"), then the tests run and the named test(s) must be among the failures. The baseline must pass
first. The original crate and corpus are never written.

usage: mutate.py --corpus FILE --outdir NEW_DIR
NEW_DIR must not exist (its parent must) and must not be inside this packet or the crate directory.
Exit 0 only if the baseline passes and every mutant is killed by its named test(s); 1 if one survives.
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.realpath(__file__))
CRATE = os.path.realpath(os.path.join(HERE, "..", "..", "..", "src", "node115-shortstring-intern"))

SIP = "sip13_zero_key_matches_corpus_for_whole_byte_by_byte_and_split_writes"
KEY = "name_to_key_and_generated_letters_match_corpus_on_a_fresh_cache"
CACHE = "cache_paths_and_sizes_match_corpus_around_the_99999_100000_limit"
ROWS = "rows_intern_each_name_before_the_standin_parse_matches_corpus"
SCOUT = "three_scouting_values_computed_by_cpython_siphash13"
SHORT = "short_names_never_touch_the_cache_and_length_counts_bytes"
FOLD = "fold_overflow_domain_is_the_prior_packets_rule"
N_TESTS = 9

# name: (old text, new text, tests that must fail)
MUTANTS = {
    "short_cutoff_lt16": ("bytes.len() <= SHORT_MAX_LEN", "bytes.len() < SHORT_MAX_LEN", [KEY, SCOUT, SHORT]),
    "short_cutoff_17": ("SHORT_MAX_LEN: usize = 16;", "SHORT_MAX_LEN: usize = 17;", [KEY, SCOUT]),
    "terminator_zero": ("TERMINATOR: u8 = 0xff;", "TERMINATOR: u8 = 0x00;", [KEY, SCOUT]),
    "index_eight_bytes": ("h.write(&(i as i32).to_le_bytes()[..INDEX_WIDTH]);", "h.write(&(i as u64).to_le_bytes());", [KEY, SCOUT]),
    "index_big_endian": ("(i as i32).to_le_bytes()", "(i as i32).to_be_bytes()", [KEY, SCOUT]),
    "index_from_one": ("(i as i32).to_le_bytes()", "(i as i32 + 1).to_le_bytes()", [KEY, SCOUT]),
    "alphabet_25": ("ALPHABET_LEN: u64 = 26;", "ALPHABET_LEN: u64 = 25;", [KEY, SCOUT]),
    "alphabet_lowercase": ("ALPHABET_BASE: u8 = 0x41;", "ALPHABET_BASE: u8 = 0x61;", [KEY, SCOUT]),
    "generated_last_letter_missing": ("out.iter_mut().enumerate()", "out.iter_mut().enumerate().take(GENERATED_LEN - 1)", [KEY, SCOUT]),
    "fold_big_endian": ("for &b in bytes.iter().rev() {", "for &b in bytes.iter() {", [KEY, FOLD]),
    "fold_overflow_check_dropped": ("if acc >> 120 != 0 {", "if false {", [FOLD]),
    "sip_two_compression_rounds": ("SIP_C_ROUNDS: u32 = 1;", "SIP_C_ROUNDS: u32 = 2;", [SIP, KEY]),
    "sip_four_finalization_rounds": ("SIP_D_ROUNDS: u32 = 3;", "SIP_D_ROUNDS: u32 = 4;", [SIP, KEY]),
    "sip_length_byte_dropped": ("let b = (self.length << 56) | u64::from_le_bytes(tail);", "let b = u64::from_le_bytes(tail);", [SIP]),
    "sip_final_xor_0xfe": ("v[2] ^= 0xff;", "v[2] ^= 0xfe;", [SIP]),
    "sip_init_words_unswapped": ("let [v0, v2, v1, v3] = SIP_INIT;", "let [v0, v1, v2, v3] = SIP_INIT;", [SIP]),
    "sip_tail_big_endian": ("u64::from_le_bytes(tail)", "u64::from_be_bytes(tail)", [SIP]),
    "sip_block_big_endian": ("u64::from_le_bytes(self.pending)", "u64::from_be_bytes(self.pending)", [SIP]),
    "cache_cap_one_more": ("self.map.len() <= CACHE_INSERT_MAX_LEN {", "self.map.len() <= CACHE_INSERT_MAX_LEN + 1 {", [CACHE]),
    "cache_cap_one_fewer": ("self.map.len() <= CACHE_INSERT_MAX_LEN {", "self.map.len() < CACHE_INSERT_MAX_LEN {", [CACHE]),
    "cache_stores_short_names": ("return Keyed { key, path: Path::Short };",
                                 "self.map.insert(bytes.to_vec(), key); return Keyed { key, path: Path::Short };", [SHORT, CACHE]),
    "cache_never_hits": ("self.map.get(bytes) {", "self.map.get(bytes).filter(|_| false) {", [CACHE]),
    "cache_keyed_by_generated_letters": ("self.map.insert(bytes.to_vec(), key);",
                                         "self.map.insert(generated_name(bytes).to_vec(), key);", [CACHE]),
    "rows_parse_before_key": ("        let key = cache.key_for(name).key;\n        match parse20(text) {\n            Ok(value) => rows.push(CidRow { key, value }),\n",
                              "        match parse20(text) {\n            Ok(value) => rows.push(CidRow { key: cache.key_for(name).key, value }),\n", [ROWS]),
    "rows_error_index_off_by_one": ("return Err(RowError { index, source })", "return Err(RowError { index: index + 1, source })", [ROWS]),
}


def check_outdir(path):
    p = os.path.realpath(path)
    if os.path.lexists(path):
        sys.exit("refusing: %s already exists" % path)
    if not os.path.isdir(os.path.dirname(p)):
        sys.exit("refusing: parent directory of --outdir must exist")
    for guard in (HERE, CRATE):
        if p == guard or p.startswith(guard + os.sep):
            sys.exit("refusing: --outdir is inside the packet or the crate")


def cargo(args, manifest, target, env):
    return subprocess.run(["cargo"] + args + ["--offline", "--manifest-path", manifest, "--target-dir", target],
                          capture_output=True, text=True, env=env)


def one(name, outdir, corpus, edit):
    d = os.path.join(outdir, name)
    shutil.copytree(CRATE, d, ignore=shutil.ignore_patterns("target"))
    if edit:
        lib = os.path.join(d, "lib.rs")
        s = open(lib).read()
        if s.count(edit[0]) != 1:
            sys.exit("tool error: mutant %s: pattern occurs %d times" % (name, s.count(edit[0])))
        open(lib, "w").write(s.replace(edit[0], edit[1]))
    env = dict(os.environ, SHORTSTRING_CORPUS=corpus)
    manifest, target = os.path.join(d, "Cargo.toml"), os.path.join(outdir, "target-" + name)
    b = cargo(["test", "--no-run"], manifest, target, env)
    if b.returncode != 0:
        print("tool error: %s does not build:\n%s" % (name, b.stderr[-1500:]), file=sys.stderr)
        sys.exit(2)
    r = cargo(["test", "--no-fail-fast"], manifest, target, env)
    failed = sorted(set(re.findall(r"^test (\w+) \.\.\. FAILED", r.stdout, re.M)))
    passed = len(re.findall(r"^test \w+ \.\.\. ok", r.stdout, re.M))
    shutil.rmtree(target, ignore_errors=True)
    return r.returncode, failed, passed


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", required=True)
    ap.add_argument("--outdir", required=True)
    a = ap.parse_args()
    check_outdir(a.outdir)
    os.mkdir(a.outdir)
    corpus = os.path.realpath(a.corpus)
    rc, failed, passed = one("baseline", a.outdir, corpus, None)
    if rc != 0 or failed or passed != N_TESTS:
        print("baseline does not pass (rc %d, failed %s, passed %d)" % (rc, failed, passed), file=sys.stderr)
        sys.exit(2)
    results = [{"mutant": "baseline", "tests_passed": passed, "failed": []}]
    survivors = 0
    for name, edit in MUTANTS.items():
        rc, failed, passed = one(name, a.outdir, corpus, edit)
        killed = rc != 0 and all(t in failed for t in edit[2])
        survivors += not killed
        results.append({"mutant": name, "expected_to_fail": edit[2], "failed": failed, "killed_by_expected": killed})
        print("%-36s %s %s" % (name, "KILLED  " if killed else "SURVIVED", ",".join(failed)))
    summary = {"mutants": len(MUTANTS), "killed_by_expected_tests": len(MUTANTS) - survivors, "survivors": survivors}
    with open(os.path.join(a.outdir, "mutation.json"), "w", newline="\n") as f:
        json.dump({"summary": summary, "results": results}, f, indent=1)
        f.write("\n")
    print(json.dumps(summary))
    sys.exit(1 if survivors else 0)


if __name__ == "__main__":
    main()
