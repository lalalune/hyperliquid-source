#!/usr/bin/env python3
"""Mutation run for src/node115-peers-response-set.

Copies the crate and the path-dependency closure it needs into a new --outdir,
edits only those copies, builds each mutant and runs its tests. Inputs are
never changed (their hashes are compared before and after). The directory must
not exist and must not be inside this packet or the crate.

Outcome classes, each decided from cargo's own output:
  KILLED      the mutant built and at least one expected test reported FAILED
  SURVIVED    the mutant built and every test passed
  BUILD_ERROR the mutant did not compile (the mutant is invalid, run fails)
  NOT_APPLIED the text to replace was missing, repeated or unchanged (run fails)
  ENV_ERROR   cargo could not run (run fails with a different exit code)
A mutant marked `equivalent` must SURVIVE; every other mutant must be KILLED by
a test named in its `tests` list, not merely by any failure.

The baseline (no mutation) must pass first, otherwise nothing else is run.
"""
import argparse
import hashlib
import os
import re
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.realpath(__file__))
ROOT = os.path.realpath(os.path.join(HERE, "..", "..", ".."))
CRATE = "node115-peers-response-set"
CLOSURE = [
    "src/node115-peers-response-set",
    "src/node115-gossip-response-composed",
    "src/node115-gossip-address-vector",
    "src/node115-gossip-response-v2-envelope",
    "src/node115-gossip-response-record",
    "src/node115-client-blocks-error",
    "src/node115-u32-varint",
    "src/node115-u64-reader-state",
    "src/node115-lz4-decode",
    "src/node115-tcp-frame-plan",
    "src/node115-tcp-stream-frame-lz4",
    "research/imported/node115-reader-45e91f8499f1a78460407d235f580c1625f44d1a",
]
LIB = f"src/{CRATE}/src/lib.rs"
CORPUS = f"src/{CRATE}/tests/corpus.tsv"
CORPUS_TEST = "every_corpus_case_matches_the_oracle"

# (id, description, file, old, new, tests expected to fail | None when equivalent)
SORT_LINE = "rows.sort_by(|a, b| -> Ordering { key_of(a).cmp(&key_of(b)) });"
MUTANTS = [
    ("M01", "long sort made unstable", LIB, SORT_LINE,
     "rows.sort_unstable_by(|a, b| -> Ordering { key_of(a).cmp(&key_of(b)) });", [CORPUS_TEST]),
    ("M02", "long sort compares the key as a little-endian number", LIB, SORT_LINE,
     "rows.sort_by(|a, b| u32::from_le_bytes(key_of(a)).cmp(&u32::from_le_bytes(key_of(b))));", [CORPUS_TEST]),
    ("M03", "insertion sort moves on equal keys (<= instead of <)", LIB,
     "while j > 0 && key_of(&cur) < key_of(&rows[j - 1]) {", "while j > 0 && key_of(&cur) <= key_of(&rows[j - 1]) {",
     [CORPUS_TEST]),
    ("M04", "insertion sort entry test compares little-endian numbers", LIB,
     "if key_of(&rows[i]) < key_of(&rows[i - 1]) {",
     "if u32::from_le_bytes(key_of(&rows[i])) < u32::from_le_bytes(key_of(&rows[i - 1])) {",
     [CORPUS_TEST, "key_order_is_byte_order_not_little_endian_number_order"]),
    ("M05", "first equal pair keeps the earlier row", LIB, "    rows.swap(first, first - 1);\n", "", [CORPUS_TEST]),
    ("M06", "later equal rows keep the earlier row", LIB, "            rows.swap(idx, kept - 1);\n", "", [CORPUS_TEST]),
    ("M07", "equal keys compared with != so only distinct keys collapse", LIB,
     "if key_of(&rows[idx]) != key_of(&rows[kept - 1]) {", "if key_of(&rows[idx]) == key_of(&rows[kept - 1]) {", [CORPUS_TEST]),
    ("M08", "first duplicate search skips index 1", LIB, "(1..len).find(", "(2..len).find(", [CORPUS_TEST]),
    ("M09", "insertion sort skips the first pair", LIB, "    for i in 1..rows.len() {", "    for i in 2..rows.len() {", [CORPUS_TEST]),
    ("M10", "two rows are not sorted", LIB, "if rows.len() >= 2 {", "if rows.len() > 2 {", [CORPUS_TEST]),
    ("M11", "small set limit 65", LIB, "pub const SMALL_SET_MAX: usize = 64;", "pub const SMALL_SET_MAX: usize = 65;",
     [CORPUS_TEST, "replacement_and_storage_follow_the_thresholds"]),
    ("M12", "small set limit 63", LIB, "pub const SMALL_SET_MAX: usize = 64;", "pub const SMALL_SET_MAX: usize = 63;",
     [CORPUS_TEST, "replacement_and_storage_follow_the_thresholds"]),
    ("M13", "request limit raised to 10,100", LIB, "pub const PEERS_LIMIT: u64 = 10_000;", "pub const PEERS_LIMIT: u64 = 10_100;", [CORPUS_TEST]),
    ("M14", "frame payload gate one too high", LIB, "frame_payload: PEERS_LIMIT,", "frame_payload: PEERS_LIMIT + 1,", [CORPUS_TEST]),
    ("M15", "LZ4 capacity gate one too high", LIB, "decoded_capacity: PEERS_LIMIT,", "decoded_capacity: PEERS_LIMIT + 1,", [CORPUS_TEST]),
    ("M16", "nested success boundary accepted as an empty peer set", LIB,
     "Err(Error::NotPeers(OtherResponse::ResultSuccessBoundary))", "Ok((normalize(&[]), 0, out.charged, out.remaining.len()))", [CORPUS_TEST]),
    ("M17", "bytes after the frame dropped", LIB, "Ok((decoded, &bytes[used..]))", "Ok((decoded, &bytes[..0]))", [CORPUS_TEST]),
    ("M18", "payload bytes after the vector reported as zero", LIB, "            out.remaining.len(),\n        )),", "            0,\n        )),",
     [CORPUS_TEST]),
    ("M19", "boolean inverted in the output", LIB, "flag: r.record.flag,", "flag: !r.record.flag,", [CORPUS_TEST, "scout_frame_gives_two_rows_in_byte_order_and_charge_51"]),
    ("M20", "source index off by one", LIB, "winners: rows.iter().map(|r| r.index).collect(),", "winners: rows.iter().map(|r| r.index + 1).collect(),",
     [CORPUS_TEST, "scout_frame_gives_two_rows_in_byte_order_and_charge_51"]),
    ("M21", "key reported byte-reversed", LIB, "(row.record.fixed as u32).to_le_bytes()", "(row.record.fixed as u32).to_be_bytes()",
     [CORPUS_TEST, "scout_frame_gives_two_rows_in_byte_order_and_charge_51"]),
    ("E01", "insertion-sort length bound 20 -> 19 (equivalent: both branches give the same order)", LIB,
     "pub const INSERTION_SORT_MAX: usize = 20;", "pub const INSERTION_SORT_MAX: usize = 19;", None),
    ("E02", "insertion-sort branch removed (equivalent: std stable sort gives the same order)", LIB,
     "if rows.len() <= INSERTION_SORT_MAX {", "if false {", None),
]
# corpus controls: corrupt one expectation or frame bit, the corpus test must fail
CONTROLS = [
    ("C01", "kept count in one expectation changed", "kept=2;", "kept=3;"),
    ("C02", "a winners list changed", "winners=1,2", "winners=2,1"),
    ("C03", "storage word changed", "storage=small", "storage=tree"),
    ("C04", "a frame hex digit flipped", None, None),
]


def sha256(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def tree_hashes(root):
    out = {}
    for rel in CLOSURE:
        for dp, dn, fn in os.walk(os.path.join(root, rel)):
            dn[:] = [d for d in dn if d != "target"]
            for f in fn:
                p = os.path.join(dp, f)
                out[os.path.relpath(p, root)] = sha256(p)
    return out


def cargo(tree, target, extra, cargo_bin="cargo"):
    cmd = [cargo_bin, "test", "--offline", "--locked", "--no-fail-fast", "--target-dir", target,
           "--manifest-path", os.path.join(tree, "src", CRATE, "Cargo.toml")] + extra
    try:
        p = subprocess.run(cmd, capture_output=True, text=True)
    except OSError as e:
        return "ENV_ERROR", str(e), []
    text = p.stdout + p.stderr
    failed = re.findall(r"^test (\S+) \.\.\. FAILED$", p.stdout, re.M)
    if "could not compile" in text:
        return "BUILD_ERROR", text[-600:], []
    if "test result:" not in p.stdout:
        return "ENV_ERROR", text[-600:], []
    return ("FAIL" if failed or p.returncode != 0 else "PASS"), text[-300:], failed


def replace_once(path, old, new):
    with open(path) as fh:
        text = fh.read()
    if old == new or text.count(old) != 1:
        return False
    with open(path, "w") as fh:
        fh.write(text.replace(old, new))
    return True


def restore(tree, root, rel):
    shutil.copyfile(os.path.join(root, rel), os.path.join(tree, rel))


def run_one(tree, target, root, mid, file, old, new, expected, cargo_bin="cargo"):
    if not replace_once(os.path.join(tree, file), old, new):
        restore(tree, root, file)
        return "NOT_APPLIED", []
    status, _, failed = cargo(tree, target, [], cargo_bin)
    restore(tree, root, file)
    if status == "FAIL":
        return "KILLED", failed
    return {"PASS": "SURVIVED"}.get(status, status), failed


def selftest(root, work):
    tree = os.path.join(work, "tree")
    target = os.path.join(work, "target")
    base, tail, _ = cargo(tree, target, [])
    if base != "PASS":
        print("selftest: baseline did not pass:", base, tail)
        return 3
    print("selftest: baseline passes")
    ok = True
    checks = [
        ("an edit that does not compile is BUILD_ERROR, not KILLED",
         run_one(tree, target, root, "S1", LIB, "pub const PEERS_LIMIT: u64 = 10_000;", "pub const PEERS_LIMIT: u64 = ;", None)[0], "BUILD_ERROR"),
        ("text that is not in the file is NOT_APPLIED",
         run_one(tree, target, root, "S2", LIB, "no such text", "x", None)[0], "NOT_APPLIED"),
        ("an unchanged replacement is NOT_APPLIED",
         run_one(tree, target, root, "S3", LIB, "pub const PEERS_LIMIT: u64 = 10_000;", "pub const PEERS_LIMIT: u64 = 10_000;", None)[0], "NOT_APPLIED"),
        ("a comment-only edit SURVIVES",
         run_one(tree, target, root, "S4", LIB, "pub const PEERS_LIMIT: u64 = 10_000;", "pub const PEERS_LIMIT: u64 = 10_000; // x", None)[0], "SURVIVED"),
        ("a real behaviour change is KILLED",
         run_one(tree, target, root, "S5", LIB, "pub const SMALL_SET_MAX: usize = 64;", "pub const SMALL_SET_MAX: usize = 63;", None)[0], "KILLED"),
        ("a missing cargo binary is ENV_ERROR",
         run_one(tree, target, root, "S6", LIB, "pub const SMALL_SET_MAX: usize = 64;", "pub const SMALL_SET_MAX: usize = 63;", None, "cargo-does-not-exist")[0], "ENV_ERROR"),
    ]
    for label, got, want in checks:
        good = got == want
        ok &= good
        print(f"selftest: {label}: {got} {'ok' if good else 'EXPECTED ' + want}")
    return 0 if ok else 1


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--outdir", required=True, help="new working directory; must not exist")
    ap.add_argument("--repo", default=ROOT, help="repository root holding the crate (read only)")
    ap.add_argument("--selftest", action="store_true", help="baseline and tool controls only")
    args = ap.parse_args(argv)

    root = os.path.realpath(args.repo)
    out = os.path.abspath(args.outdir)
    real_out = os.path.join(os.path.realpath(os.path.dirname(out)), os.path.basename(out))
    if os.path.lexists(out):
        print("refusing: outdir already exists", file=sys.stderr)
        return 2
    for forbidden in (HERE, os.path.join(root, "src", CRATE)):
        if real_out == forbidden or real_out.startswith(forbidden + os.sep):
            print("refusing: outdir is inside the packet or the crate", file=sys.stderr)
            return 2
    before = tree_hashes(root)
    os.mkdir(out)
    tree = os.path.join(out, "tree")
    for rel in CLOSURE:
        shutil.copytree(os.path.join(root, rel), os.path.join(tree, rel), ignore=shutil.ignore_patterns("target"))
    target = os.path.join(out, "target")

    if args.selftest:
        code = selftest(root, out)
    else:
        code = run_all(root, out, tree, target)
    if tree_hashes(root) != before:
        print("INPUT CHANGED: the source tree differs after the run", file=sys.stderr)
        return 5
    return code


def run_all(root, out, tree, target):
    base, tail, _ = cargo(tree, target, [])
    if base != "PASS":
        print("baseline did not pass:", base, tail)
        return 3
    rows = []
    bad = 0
    for mid, desc, file, old, new, tests in MUTANTS:
        outcome, failed = run_one(tree, target, root, mid, file, old, new, tests)
        if tests is None:
            good = outcome == "SURVIVED"
        else:
            good = outcome == "KILLED" and all(t in failed for t in tests)
        rows.append((mid, "mutant", desc, outcome, ",".join(sorted(set(failed))), "ok" if good else "UNEXPECTED"))
        bad += not good
    corpus_rel = CORPUS
    with open(os.path.join(root, corpus_rel)) as fh:
        corpus = fh.read()
    for cid, desc, old, new in CONTROLS:
        if old is None:
            # flip one hex digit of the first success frame
            lines = corpus.split("\n")
            i = next(k for k, l in enumerate(lines) if l and not l.startswith("#") and "\tok;" in l)
            parts = lines[i].split("\t")
            parts[1] = parts[1][:12] + ("1" if parts[1][12] != "1" else "2") + parts[1][13:]
            lines[i] = "\t".join(parts)
            mutated = "\n".join(lines)
        else:
            if corpus.count(old) < 1:
                print("control text not found:", cid)
                return 4
            mutated = corpus.replace(old, new, 1)
        path = os.path.join(tree, corpus_rel)
        with open(path, "w") as fh:
            fh.write(mutated)
        status, _, failed = cargo(tree, target, [])
        restore(tree, root, corpus_rel)
        outcome = {"FAIL": "KILLED", "PASS": "SURVIVED"}.get(status, status)
        good = outcome == "KILLED" and CORPUS_TEST in failed
        rows.append((cid, "control", desc, outcome, ",".join(sorted(set(failed))), "ok" if good else "UNEXPECTED"))
        bad += not good
    with open(os.path.join(out, "results.tsv"), "w") as fh:
        fh.write("id\tkind\tdescription\toutcome\tfailing_tests\tstatus\n")
        for r in rows:
            fh.write("\t".join(r) + "\n")
    killed = sum(1 for r in rows if r[1] == "mutant" and r[3] == "KILLED")
    mutants = sum(1 for r in rows if r[1] == "mutant")
    print(f"baseline passes; {mutants} mutants: {killed} killed, {sum(1 for r in rows if r[1]=='mutant' and r[3]=='SURVIVED')} survived; "
          f"{sum(1 for r in rows if r[1]=='control' and r[3]=='KILLED')}/{len(CONTROLS)} corpus controls detected; {bad} unexpected")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
